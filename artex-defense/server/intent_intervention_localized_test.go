package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// intent_intervention.go 의 Worker 개입 API 에러 응답을 한국어로 유지하는 회귀 방어
// 테스트다. 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어 한자 0)를 재사용한다.

// TestIntentInterventionErrorConstantsLocalized 는 응답 상수 11종이 전부 한국어임을 단언한다.
// 수명주기·의도 상태 경로는 s.engine·Store 설정이 필요해 DB 없는 이 호스트에서 끝까지 못
// 도므로, 그 문구들은 상수 자체를 단언한다(conversations.go 선례). 입력 검증 경로 4종은
// 아래 HTTP 테스트가 응답 본문까지 확인한다.
func TestIntentInterventionErrorConstantsLocalized(t *testing.T) {
	cases := []struct {
		name string
		msg  string
	}{
		{"request_too_large", errIntentRequestTooLarge},
		{"message_empty", errIntentMessageEmpty},
		{"message_too_long", errIntentMessageTooLong},
		{"bad_request_id", errIntentBadRequestID},
		{"task_deleting", errIntentTaskDeleting},
		{"task_paused", errIntentTaskPaused},
		{"task_queued", errIntentTaskQueued},
		{"task_terminal", errIntentTaskTerminal},
		{"task_settling", errIntentTaskSettling},
		{"inherited_readonly", errIntentInheritedReadonly},
		{"not_paused", errIntentNotPaused},
	}
	for _, c := range cases {
		assertKoreanError(t, c.name, c.msg)
	}
}

// TestSendWorkerMessageInputValidationLocalized 는 입력 검증 경로 4종을 실제 HTTP 응답
// 본문까지 검사한다. sendWorkerMessage 의 이 4경로는 s.m.Task(맵 조회)와 요청 본문만 보고
// s.engine·Store·DB 를 거치지 않으므로, tasks 맵에 작업 하나만 넣으면 DB 없이 끝까지 돈다.
// 상수가 응답에 실제로 실리는 연결까지 확인한다.
func TestSendWorkerMessageInputValidationLocalized(t *testing.T) {
	s := &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}}

	call := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/t1/intents/1/message", strings.NewReader(body))
		req.SetPathValue("id", "t1")
		req.SetPathValue("iid", "1")
		rec := httptest.NewRecorder()
		s.sendWorkerMessage(rec, req)
		return rec
	}
	errBody := func(t *testing.T, rec *httptest.ResponseRecorder) string {
		t.Helper()
		var resp struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("응답 JSON 파싱 실패: %v (본문 %q)", err, rec.Body.String())
		}
		return resp.Error
	}

	cases := []struct {
		name string
		body string
		code int
		want string
	}{
		// 64KB 한도를 넘기는 유효 JSON 본문. MaxBytesReader 가 읽기 도중 한도 초과를 돌려준다.
		{"request_too_large", `{"message":"` + strings.Repeat("a", maxWorkerMessageBytes+1024) + `"}`, http.StatusRequestEntityTooLarge, errIntentRequestTooLarge},
		{"message_empty", `{"message":"  "}`, http.StatusBadRequest, errIntentMessageEmpty},
		{"message_too_long", `{"message":"` + strings.Repeat("가", 4001) + `"}`, http.StatusBadRequest, errIntentMessageTooLong},
		{"bad_request_id", `{"message":"안녕","request_id":"공백 포함"}`, http.StatusBadRequest, errIntentBadRequestID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := call(c.body)
			if rec.Code != c.code {
				t.Fatalf("상태 코드 = %d, 기대 = %d (본문 %q)", rec.Code, c.code, rec.Body.String())
			}
			if got := errBody(t, rec); got != c.want {
				t.Fatalf("응답 문구 = %q, 기대 = %q", got, c.want)
			}
			assertKoreanError(t, c.name, errBody(t, rec))
		})
	}
}
