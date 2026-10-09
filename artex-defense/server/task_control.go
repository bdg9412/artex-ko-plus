package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

const maxBatchControlIDs = 100

// 사용자에게 노출되는 작업·의도 제어 오류 문구(한국어화, F3b). 식별자·enum(paused 등)·
// %w 래핑은 원문 그대로 둔다. applyTaskControlWithCause 의 문구는 단건(controlTask)·
// 배치(controlTasksBatch) 제어 응답이 주 용도이며, 오케스트레이터 pause 도구
// (orchestration.go)가 err.Error() 를 재참조할 때도 같은 문구가 쓰인다.
const (
	errTaskCtrlDeleting      = "작업을 삭제하는 중이라 제어할 수 없습니다"
	errTaskCtrlTerminalPause = "종료된 작업은 일시정지할 수 없습니다"
	errTaskCtrlAlreadyPaused = "작업이 이미 일시정지되어 있습니다"
	errTaskCtrlBatchSizeFmt  = "task_ids 개수는 1~%d개여야 합니다"

	errIntentCtrlInheritedReadonly = "상속된 의도는 읽기 전용이라 제어할 수 없습니다"
	errIntentCtrlOnlyRunningPause  = "실행 중인 의도만 일시정지할 수 있습니다"
	errIntentCtrlOnlyPausedResume  = "일시정지된 의도만 재개할 수 있습니다"
	errIntentCtrlStateConflictFmt  = "%w: 의도가 더 이상 paused 상태가 아닙니다"
	errIntentCtrlOnlyDeletable     = "대기 중·실행 중·일시정지 상태의 의도만 삭제할 수 있습니다"
	errIntentCtrlReasonRequired    = "삭제 사유를 입력하세요"
)

type taskControlResult struct {
	ID     string `json:"id"`
	Paused bool   `json:"paused"`
	Queued bool   `json:"queued"`
	Status string `json:"status"`
}

type intentControlResult struct {
	ID      int64             `json:"id"`
	State   string            `json:"state"`
	Deleted *db.IntentCleanup `json:"deleted,omitempty"`
}

// parsedTaskID carries one requested batch id together with whether it parsed.
// Invalid ids are kept rather than dropped so the response can name them.
type parsedTaskID struct {
	id    string
	valid bool
}

// normalizeBatchTaskIDs trims, canonicalizes and de-duplicates the ids of one
// batch request while preserving the caller's order. Shared by every batch
// endpoint so they agree on what counts as a duplicate.
func normalizeBatchTaskIDs(raw []string) []parsedTaskID {
	seen := map[string]bool{}
	seenInvalid := map[string]bool{}
	taskIDs := make([]parsedTaskID, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		id, valid := canonicalTaskID(trimmed)
		if !valid {
			if seenInvalid[trimmed] {
				continue
			}
			seenInvalid[trimmed] = true
			taskIDs = append(taskIDs, parsedTaskID{id: trimmed})
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		taskIDs = append(taskIDs, parsedTaskID{id: id, valid: true})
	}
	return taskIDs
}

type batchControlItem struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Status string `json:"status,omitempty"`
	Queued bool   `json:"queued,omitempty"`
	Error  string `json:"error,omitempty"`
}

func (s *Server) resumeAdmissionMode(t *Task) string {
	if t == nil {
		return "resume"
	}
	lifecycle := t.lifecycleSnapshot()
	if lifecycle.QueueMode == "bootstrap" {
		return "bootstrap"
	}
	if lifecycle.FirstRunAt == 0 {
		goals, err := t.Store.ListByKind(db.KindGoal, 1)
		if err == nil && len(goals) == 0 {
			return "bootstrap"
		}
	}
	return "resume"
}

// applyTaskControl is shared by the single and batch endpoints. Task resume is
// deliberately limited to paused tasks; reruns and finding follow-ups use
// admitTask directly when they need to revive a terminal task.
func (s *Server) applyTaskControl(t *Task, action string) (taskControlResult, error) {
	return s.applyTaskControlWithCause(t, action, agent.AbortPausedByUser)
}

func (s *Server) applyTaskControlWithCause(t *Task, action string, pauseCause error) (taskControlResult, error) {
	if t == nil {
		return taskControlResult{}, fmt.Errorf("task not found")
	}
	out := taskControlResult{ID: t.ID}
	switch action {
	case "pause":
		s.concMu.Lock()
		defer s.concMu.Unlock()
		current, exists := s.m.Task(t.ID)
		if !exists || current != t || s.engine.IsDeleting(t.ID) {
			return out, fmt.Errorf(errTaskCtrlDeleting)
		}
		if !s.engine.beginTaskOperation(t.ID) {
			return out, fmt.Errorf(errTaskCtrlDeleting)
		}
		defer s.engine.decInflight(t.ID)
		lifecycle := t.lifecycleSnapshot()
		if isTerminalStatus(lifecycle.Status) {
			return out, fmt.Errorf(errTaskCtrlTerminalPause)
		}
		if lifecycle.Paused {
			return out, fmt.Errorf(errTaskCtrlAlreadyPaused)
		}
		wasQueued := lifecycle.Queued
		wasEnginePaused := s.engine.IsPaused(t.ID)
		if pauseCause == nil {
			pauseCause = agent.AbortPausedByUser
		}
		s.engine.Pause(t.ID, pauseCause)
		if err := s.m.ApplyTaskPause(t.ID); err != nil {
			if !wasEnginePaused && !wasQueued {
				s.engine.Resume(t)
			}
			return out, err
		}
		// Main Agent is independently cancellable. Only cancel its current turn
		// after the persistent pause commits, so a failed control request is fully
		// compensated and does not lose an otherwise valid conversation turn.
		s.cancelTaskChat(t.ID, agent.AbortChatPausedWithTask)
		out.Paused, out.Status = true, "paused"
		go s.reconcileConcurrency()
	case "resume":
		queued, err := s.admitPausedTask(t)
		if err != nil {
			return out, err
		}
		out.Queued = queued
		out.Status = map[bool]string{true: "queued", false: "running"}[queued]
	default:
		return out, fmt.Errorf("action must be pause|resume")
	}
	log.Printf("[task] #%s %s", t.ID, map[string]string{"pause": "일시정지됨", "resume": "재개됨"}[action])
	return out, nil
}

// intentSummaryOf 는 의도 payload 에서 summary 를 꺼낸다. 하드 삭제로 의도 노드가
// 사라지기 전에 삭제 알림이 그 값을 보관해 둘 수 있게 한다.
func intentSummaryOf(n *db.Node) string {
	if n == nil {
		return ""
	}
	var p map[string]any
	if json.Unmarshal(n.Payload, &p) == nil {
		if s, ok := p["summary"].(string); ok {
			return s
		}
	}
	return ""
}

func (s *Server) applyIntentControl(ctx context.Context, t *Task, iid int64, action, reason, mode string) (intentControlResult, error) {
	out := intentControlResult{ID: iid}
	node, err := t.Store.GetNode(iid)
	if err != nil {
		return out, err
	}
	if node == nil {
		if inherited, sourceErr := t.Store.GetNodeWithSources(iid); sourceErr == nil && inherited != nil && inherited.Inherited {
			return out, fmt.Errorf(errIntentCtrlInheritedReadonly)
		}
		return out, fmt.Errorf("intent not found")
	}
	if node.Kind != db.KindIntent {
		return out, fmt.Errorf("node is not an intent")
	}
	switch action {
	case "pause":
		if node.State != "running" {
			return out, fmt.Errorf(errIntentCtrlOnlyRunningPause)
		}
		if err := s.engine.ControlWork(ctx, iid, "pause"); err != nil {
			return out, err
		}
		out.State = "paused"
	case "resume":
		if node.State != "paused" {
			return out, fmt.Errorf(errIntentCtrlOnlyPausedResume)
		}
		changed, err := t.Store.CompareAndSetIntentState(iid, "paused", "open")
		if err != nil {
			return out, err
		}
		if !changed {
			return out, fmt.Errorf(errIntentCtrlStateConflictFmt, db.ErrIntentStateConflict)
		}
		t.Notify()
		out.State = "open"
	case "cancel":
		// 삭제는 두 가지 모드를 지원한다:
		//   soft(기본값, 소프트 삭제): 의도를 state='deleted' 로 멈추고 삭제 사유를 delete_reason
		//     필드에 기록하며, 의도 노드와 모든 산출물·혈통(lineage)을 보존하고 그래프에 fact 를 따로 달지 않는다.
		//   hard(하드 삭제): 해당 의도와 "그 의도만이 지탱하는" 전용 자손 노드를 물리적으로 삭제하며(잎까지
		//     연쇄), 고아 데이터가 남지 않게 한다. 공유 노드·goal·작업 루트 사실은 보존한다.
		// 두 모드 모두 cancelled 로 planner 에게 알려(의도 내용 + 삭제 사유), 그에 따라 다시 계획하게 한다.
		if node.State != "running" && node.State != "paused" && node.State != "open" {
			return out, fmt.Errorf(errIntentCtrlOnlyDeletable)
		}
		reason = strings.TrimSpace(reason)
		if reason == "" {
			return out, fmt.Errorf(errIntentCtrlReasonRequired)
		}
		if node.State == "running" {
			if err := s.engine.ControlWork(ctx, iid, "cancel"); err != nil {
				return out, err
			}
		}
		summary := intentSummaryOf(node)
		if mode == "hard" {
			cleanup, err := t.Store.CancelIntent(iid)
			if err != nil {
				return out, err
			}
			s.cancelWorkerSide(t.ID, t.ExpID, iid)
			t.NotifyCancelled(iid, summary, reason)
			out.Deleted = &cleanup
			out.State = "" // 노드가 삭제됨. 프런트엔드는 Deleted 를 보고 목록에서 제거한다.
		} else {
			if _, err := t.Store.SoftDeleteIntent(iid, reason); err != nil {
				return out, err
			}
			s.cancelWorkerSide(t.ID, t.ExpID, iid)
			t.NotifyCancelled(iid, summary, reason)
			out.State = db.StateIntentDeleted
		}
	default:
		return out, fmt.Errorf("action must be pause|resume|cancel")
	}
	return out, nil
}

func (s *Server) controlTasksBatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var req struct {
		TaskIDs []string `json:"task_ids"`
		Action  string   `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if req.Action != "pause" && req.Action != "resume" {
		writeErr(w, 400, "action must be pause|resume")
		return
	}
	taskIDs := normalizeBatchTaskIDs(req.TaskIDs)
	if len(taskIDs) == 0 || len(taskIDs) > maxBatchControlIDs {
		writeErr(w, 400, fmt.Sprintf(errTaskCtrlBatchSizeFmt, maxBatchControlIDs))
		return
	}
	items := make([]batchControlItem, 0, len(taskIDs))
	for _, parsed := range taskIDs {
		item := batchControlItem{ID: parsed.id}
		if !parsed.valid {
			item.Error = "bad task id"
			items = append(items, item)
			continue
		}
		t, ok := s.m.Task(parsed.id)
		if !ok {
			item.Error = "task not found"
			items = append(items, item)
			continue
		}
		result, err := s.applyTaskControl(t, req.Action)
		if err != nil {
			item.Error = err.Error()
		} else {
			item.OK, item.Status, item.Queued = true, result.Status, result.Queued
		}
		items = append(items, item)
	}
	writeJSON(w, 200, map[string]any{"items": items})
}
