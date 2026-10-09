package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// task_control.go 의 작업·의도 제어 API 에러 응답을 한국어로 유지하는 회귀 방어 테스트다.
// 한국어 판정은 F3a 의 assertKoreanError(한글 포함·중국어 한자 0)를, 응답 본문 추출은
// task_categories 테스트의 decodeErrorField 를 재사용한다(같은 package server).

// TestTaskControlErrorConstantsLocalized 는 제어 응답 상수 10종이 전부 한국어임을
// 단언한다. 의도 제어 경로(applyIntentControl)는 첫 줄에서 t.Store.GetNode(DB)를 거쳐야
// 도달하므로 DB 없는 이 호스트에서 끝까지 못 몰아, 그 6종은 상수 자체를 단언한다
// (intent_intervention·goals_api 선례). 작업 제어·배치 경로는 아래 두 테스트가 실제
// 함수 실행과 HTTP 응답 본문까지 확인한다.
func TestTaskControlErrorConstantsLocalized(t *testing.T) {
	cases := map[string]string{
		"task_deleting":          errTaskCtrlDeleting,
		"task_terminal_pause":    errTaskCtrlTerminalPause,
		"task_already_paused":    errTaskCtrlAlreadyPaused,
		"batch_size":             errTaskCtrlBatchSizeFmt,
		"intent_inherited":       errIntentCtrlInheritedReadonly,
		"intent_only_running":    errIntentCtrlOnlyRunningPause,
		"intent_only_paused":     errIntentCtrlOnlyPausedResume,
		"intent_state_conflict":  errIntentCtrlStateConflictFmt,
		"intent_only_deletable":  errIntentCtrlOnlyDeletable,
		"intent_reason_required": errIntentCtrlReasonRequired,
	}
	for label, msg := range cases {
		assertKoreanError(t, label, msg)
	}
}

// TestTaskControlApplyResponsesLocalized 는 DB·엔진 상태를 거치지 않고 끝나는 pause 제어
// 경로를 applyTaskControl 로 실제 실행해, 상수가 반환 오류에 실제로 실리는 연결을
// 확인한다. 세 분기 모두 s.m.Task(맵 조회) → 삭제 장벽 → t.lifecycleSnapshot()(인메모리
// 필드 Status/Paused 직접 읽기) 순이라, tasks 맵에 작업 하나와 빈 Engine 만 있으면
// Store·DB 없이 돌아간다. 성공 경로(실제 일시정지)는 ApplyTaskPause(DB)를 거치므로
// 여기서 몰지 않는다 — 오류 분기는 모두 그 전에 반환한다.
func TestTaskControlApplyResponsesLocalized(t *testing.T) {
	// 종료 상태 작업: isTerminalStatus(done) 분기.
	terminalServer := func() (*Server, *Task) {
		tk := &Task{ID: "1", Status: "done"}
		return &Server{m: &Manager{tasks: map[string]*Task{"1": tk}}, engine: &Engine{}}, tk
	}
	// 이미 일시정지된 실행 작업: lifecycle.Paused 분기.
	pausedServer := func() (*Server, *Task) {
		tk := &Task{ID: "1", Status: "running", Paused: true}
		return &Server{m: &Manager{tasks: map[string]*Task{"1": tk}}, engine: &Engine{}}, tk
	}
	// 삭제 장벽이 세워진 작업: IsDeleting 분기.
	deletingServer := func() (*Server, *Task) {
		tk := &Task{ID: "1", Status: "running"}
		s := &Server{m: &Manager{tasks: map[string]*Task{"1": tk}}, engine: &Engine{}}
		s.engine.deleting.Store("1", true)
		return s, tk
	}

	cases := []struct {
		name  string
		setup func() (*Server, *Task)
		want  string
	}{
		{"terminal", terminalServer, errTaskCtrlTerminalPause},
		{"already-paused", pausedServer, errTaskCtrlAlreadyPaused},
		{"deleting", deletingServer, errTaskCtrlDeleting},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, tk := c.setup()
			_, err := s.applyTaskControl(tk, "pause")
			if err == nil {
				t.Fatalf("오류를 기대했으나 nil 이 반환되었습니다")
			}
			if err.Error() != c.want {
				t.Fatalf("반환 오류 = %q, 기대 = %q", err.Error(), c.want)
			}
			assertKoreanError(t, c.name, err.Error())
		})
	}
}

// TestControlTasksBatchResponsesLocalized 는 배치 제어 엔드포인트의 응답 본문을 실제
// HTTP 로 검사한다. ① 빈 task_ids 는 s.m 접근 전에 writeErr 로 400 + 크기 오류를 내므로
// &Server{} 로도 도달한다. ② 종료 상태 작업 하나를 배치 pause 하면 200 items[].error 로
// 작업 제어 오류가 그대로 실려, applyTaskControl 오류가 배치 JSON 까지 전파되는 연결을
// 확인한다.
func TestControlTasksBatchResponsesLocalized(t *testing.T) {
	t.Run("size-error", func(t *testing.T) {
		s := &Server{}
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/control",
			strings.NewReader(`{"task_ids":[],"action":"pause"}`))
		rec := httptest.NewRecorder()
		s.controlTasksBatch(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("상태 코드 = %d, 기대 = 400 (본문 %q)", rec.Code, rec.Body.String())
		}
		got := decodeErrorField(t, rec.Body.Bytes())
		want := fmt.Sprintf(errTaskCtrlBatchSizeFmt, maxBatchControlIDs)
		if got != want {
			t.Fatalf("응답 문구 = %q, 기대 = %q", got, want)
		}
		if !strings.Contains(got, "100") {
			t.Fatalf("크기 상한 100 이 문구에 반영되지 않았습니다: %q", got)
		}
		assertKoreanError(t, "size-error", got)
	})

	t.Run("item-error-surfaces", func(t *testing.T) {
		tk := &Task{ID: "1", Status: "done"}
		s := &Server{m: &Manager{tasks: map[string]*Task{"1": tk}}, engine: &Engine{}}
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/control",
			strings.NewReader(`{"task_ids":["1"],"action":"pause"}`))
		rec := httptest.NewRecorder()
		s.controlTasksBatch(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("상태 코드 = %d, 기대 = 200 (본문 %q)", rec.Code, rec.Body.String())
		}
		var out struct {
			Items []struct {
				ID    string `json:"id"`
				OK    bool   `json:"ok"`
				Error string `json:"error"`
			} `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("응답 JSON 파싱 실패: %v (본문 %q)", err, rec.Body.String())
		}
		if len(out.Items) != 1 {
			t.Fatalf("items 개수 = %d, 기대 = 1", len(out.Items))
		}
		if out.Items[0].OK || out.Items[0].Error != errTaskCtrlTerminalPause {
			t.Fatalf("items[0] = %+v, error 기대 = %q", out.Items[0], errTaskCtrlTerminalPause)
		}
		assertKoreanError(t, "item-error", out.Items[0].Error)
	})
}

// TestIntentStateConflictWrapsSentinel 은 의도 상태 충돌 문구가 한국어이면서도 %w 로
// db.ErrIntentStateConflict 를 그대로 감싸, errors.Is 식별이 깨지지 않음을 확인한다.
// enum 값 paused 는 원문대로 보존되어야 한다.
func TestIntentStateConflictWrapsSentinel(t *testing.T) {
	err := fmt.Errorf(errIntentCtrlStateConflictFmt, db.ErrIntentStateConflict)
	if !errors.Is(err, db.ErrIntentStateConflict) {
		t.Fatalf("errors.Is(.., ErrIntentStateConflict) = false, %%w 래핑이 깨졌습니다: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "paused") {
		t.Fatalf("enum paused 가 문구에 보존되지 않았습니다: %q", err.Error())
	}
	assertKoreanError(t, "state-conflict", err.Error())
}
