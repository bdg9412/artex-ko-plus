package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// 总览「约束管理」的人工 CRUD 接口 + 注入范围开关的解析。操作约束(allow/deny)与 agent 侧的
// set_constraints 工具写同一张 task_constraints 表;这里是人类在 UI 上直接增删改。约束仅是
// 提示上下文——增删改后【不】通知 planner,下一轮规划自然读库生效(按产品决策)。每个变更 handler
// 都走 beginTaskOperation/decInflight,避免与任务删除竞态(与目标/意图 CRUD 一致)。

// 注入范围开关的 settings key,默认都开(GetBool 第二参数 = true)。
const (
	settingConstraintsInjectPlanner = "constraints_inject_planner"
	settingConstraintsInjectWorker  = "constraints_inject_worker"
)

// 约束 CRUD 핸들러의 사용자 노출 에러 응답(한국어). writeErr 로 그대로 UI 토스트에 노출된다.
// 用語: 约束→제약(ko.json 의 약속/제약 표기와 정합), 任务→작업. 추가/수정/삭제 문구는
// goals_api.go 의 errGoalTaskDeleting* 와 같은 문형이고, kind 검증은 intercept.go 의
// "값은 … 중 하나여야 합니다" 패턴을 따른다.
const (
	errConstraintTaskDeletingAdd    = "작업을 삭제하는 중이라 제약을 추가할 수 없습니다"
	errConstraintTaskDeletingEdit   = "작업을 삭제하는 중이라 제약을 수정할 수 없습니다"
	errConstraintTaskDeletingDelete = "작업을 삭제하는 중이라 제약을 삭제할 수 없습니다"
	errConstraintTextEmpty          = "제약 내용은 비워 둘 수 없습니다"
	errConstraintKindInvalid        = "kind 값은 allow 또는 deny 중 하나여야 합니다"
)

// constraintInjectPlanner / constraintInjectWorker 报告是否把操作约束注入对应 agent 的
// 系统提示(默认开)。作为 resolver 传给 planner/worker,每轮读 → 改开关即时生效。
func (s *Server) constraintInjectPlanner() bool {
	return s.m.pg.GetBool(settingConstraintsInjectPlanner, true)
}

func (s *Server) constraintInjectWorker() bool {
	return s.m.pg.GetBool(settingConstraintsInjectWorker, true)
}

// listConstraints 返回本任务的全部操作约束(allow 在前、deny 在后)。
func (s *Server) listConstraints(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	rows, err := t.Store.ListConstraints()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"constraints": constraintDTOs(rows)})
}

// addConstraint 人工新增一条操作约束(kind=allow|deny)。不通知 planner。
func (s *Server) addConstraint(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errConstraintTaskDeletingAdd)
		return
	}
	defer s.engine.decInflight(t.ID)

	var body struct {
		Text string `json:"text"`
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, 400, errConstraintTextEmpty)
		return
	}
	kind := normalizeConstraintKind(body.Kind)
	if kind == "" {
		writeErr(w, 400, errConstraintKindInvalid)
		return
	}
	id, err := t.Store.AddConstraint(kind, text, "human")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ConstraintDTO{ID: strconv.FormatInt(id, 10), Kind: kind, Text: text, Origin: "human"})
}

// editConstraint 人工修改一条约束(kind + text)。不通知 planner。
func (s *Server) editConstraint(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errConstraintTaskDeletingEdit)
		return
	}
	defer s.engine.decInflight(t.ID)

	cid, err := strconv.ParseInt(r.PathValue("cid"), 10, 64)
	if err != nil || cid <= 0 {
		writeErr(w, 400, "bad constraint id")
		return
	}
	var body struct {
		Text string `json:"text"`
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, 400, errConstraintTextEmpty)
		return
	}
	kind := normalizeConstraintKind(body.Kind)
	if kind == "" {
		writeErr(w, 400, errConstraintKindInvalid)
		return
	}
	if err := t.Store.UpdateConstraint(cid, kind, text); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ConstraintDTO{ID: strconv.FormatInt(cid, 10), Kind: kind, Text: text})
}

// deleteConstraint 人工删除一条约束。不通知 planner。
func (s *Server) deleteConstraint(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, errConstraintTaskDeletingDelete)
		return
	}
	defer s.engine.decInflight(t.ID)

	cid, err := strconv.ParseInt(r.PathValue("cid"), 10, 64)
	if err != nil || cid <= 0 {
		writeErr(w, 400, "bad constraint id")
		return
	}
	if err := t.Store.DeleteConstraint(cid); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// normalizeConstraintKind lowercases + validates the kind; "" on invalid.
func normalizeConstraintKind(k string) string {
	k = strings.TrimSpace(strings.ToLower(k))
	if k == "allow" || k == "deny" {
		return k
	}
	return ""
}

// constraintDTOs converts db rows to the frontend shape.
func constraintDTOs(in []db.Constraint) []ConstraintDTO {
	out := make([]ConstraintDTO, 0, len(in))
	for _, c := range in {
		out = append(out, ConstraintDTO{
			ID:     strconv.FormatInt(c.ID, 10),
			Kind:   c.Kind,
			Text:   c.Text,
			Origin: c.Origin,
			TS:     rfc3339(c.CreatedAt),
		})
	}
	return out
}
