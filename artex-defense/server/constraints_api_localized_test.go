package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// constraints_api.go 의 제약(约束) 관리 API 에러 응답을 한국어로 유지하는 회귀 방어
// 테스트다. 한국어 판정은 F3a 의 assertKoreanError(한글 포함·중국어 한자 0)를, 응답 본문
// 추출은 task_categories 테스트의 decodeErrorField 를 재사용한다(같은 package server).

// TestConstraintErrorConstantsLocalized 는 응답 상수 5종이 전부 한국어임을 단언한다.
func TestConstraintErrorConstantsLocalized(t *testing.T) {
	cases := map[string]string{
		"task_deleting_add":    errConstraintTaskDeletingAdd,
		"task_deleting_edit":   errConstraintTaskDeletingEdit,
		"task_deleting_delete": errConstraintTaskDeletingDelete,
		"text_empty":           errConstraintTextEmpty,
		"kind_invalid":         errConstraintKindInvalid,
	}
	for label, msg := range cases {
		assertKoreanError(t, label, msg)
	}
}

// TestConstraintHandlersResponsesLocalized 는 DB 를 건드리지 않고 끝나는 핸들러 경로를
// 실제 HTTP 응답 본문까지 검사해, 상수가 응답에 실제로 실리는 연결을 확인한다. 세 핸들러
// 모두 s.m.Task(맵 조회) → s.engine.beginTaskOperation(sync.Map 기반 삭제 장벽) → 요청
// 본문·필드 검증 순이라, tasks 맵에 작업 하나와 빈 Engine 만 있으면 Store·DB 없이 돈다.
func TestConstraintHandlersResponsesLocalized(t *testing.T) {
	// deleting 장벽이 세워진 서버: beginTaskOperation 이 false 를 돌려 409 를 낸다.
	deletingServer := func() *Server {
		s := &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}, engine: &Engine{}}
		s.engine.deleting.Store("t1", true)
		return s
	}
	// 장벽이 없는 서버: beginTaskOperation 이 true 를 돌려 입력 검증까지 진행한다.
	liveServer := func() *Server {
		return &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}, engine: &Engine{}}
	}

	newReq := func(body, cid string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/t1/constraints", strings.NewReader(body))
		req.SetPathValue("id", "t1")
		if cid != "" {
			req.SetPathValue("cid", cid)
		}
		return req
	}

	cases := []struct {
		name    string
		handler func(*Server) http.HandlerFunc
		server  func() *Server
		body    string
		cid     string
		code    int
		want    string
	}{
		{
			name:    "add/task-deleting",
			handler: func(s *Server) http.HandlerFunc { return s.addConstraint },
			server:  deletingServer,
			body:    `{"text":"현재 포트만 테스트","kind":"allow"}`,
			code:    http.StatusConflict,
			want:    errConstraintTaskDeletingAdd,
		},
		{
			name:    "add/text-empty",
			handler: func(s *Server) http.HandlerFunc { return s.addConstraint },
			server:  liveServer,
			body:    `{"text":"   ","kind":"allow"}`,
			code:    http.StatusBadRequest,
			want:    errConstraintTextEmpty,
		},
		{
			name:    "add/kind-invalid",
			handler: func(s *Server) http.HandlerFunc { return s.addConstraint },
			server:  liveServer,
			body:    `{"text":"다른 포트 스캔 금지","kind":"maybe"}`,
			code:    http.StatusBadRequest,
			want:    errConstraintKindInvalid,
		},
		{
			name:    "edit/task-deleting",
			handler: func(s *Server) http.HandlerFunc { return s.editConstraint },
			server:  deletingServer,
			body:    `{"text":"수정된 제약","kind":"deny"}`,
			cid:     "5",
			code:    http.StatusConflict,
			want:    errConstraintTaskDeletingEdit,
		},
		{
			name:    "edit/text-empty",
			handler: func(s *Server) http.HandlerFunc { return s.editConstraint },
			server:  liveServer,
			body:    `{"text":"  ","kind":"deny"}`,
			cid:     "5",
			code:    http.StatusBadRequest,
			want:    errConstraintTextEmpty,
		},
		{
			name:    "edit/kind-invalid",
			handler: func(s *Server) http.HandlerFunc { return s.editConstraint },
			server:  liveServer,
			body:    `{"text":"수정된 제약","kind":"nope"}`,
			cid:     "5",
			code:    http.StatusBadRequest,
			want:    errConstraintKindInvalid,
		},
		{
			name:    "delete/task-deleting",
			handler: func(s *Server) http.HandlerFunc { return s.deleteConstraint },
			server:  deletingServer,
			body:    ``,
			cid:     "5",
			code:    http.StatusConflict,
			want:    errConstraintTaskDeletingDelete,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := c.server()
			rec := httptest.NewRecorder()
			c.handler(s)(rec, newReq(c.body, c.cid))
			if rec.Code != c.code {
				t.Fatalf("상태 코드 = %d, 기대 = %d (본문 %q)", rec.Code, c.code, rec.Body.String())
			}
			got := decodeErrorField(t, rec.Body.Bytes())
			if got != c.want {
				t.Fatalf("응답 문구 = %q, 기대 = %q", got, c.want)
			}
			assertKoreanError(t, c.name, got)
		})
	}
}
