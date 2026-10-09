package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// goals_api.go 의 목표 관리 API 에러 응답을 한국어로 유지하는 회귀 방어 테스트다.
// 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어 한자 0)를, 응답 본문
// 추출은 task_categories 테스트의 decodeErrorField 를 재사용한다(같은 package server).

// TestGoalErrorConstantsLocalized 는 응답 상수 7종이 전부 한국어임을 단언한다. 목표
// 조회·저장(目标不存在·읽기 실패)은 Store·DB 를 거쳐야 도달하므로 DB 없는 이 호스트에서
// 끝까지 못 몰아, 그 문구들은 상수 자체를 단언한다(intent_intervention 선례). 입력 검증·
// 삭제 장벽 경로는 아래 HTTP 테스트가 응답 본문까지 확인한다.
func TestGoalErrorConstantsLocalized(t *testing.T) {
	cases := map[string]string{
		"task_deleting_add":    errGoalTaskDeletingAdd,
		"task_deleting_edit":   errGoalTaskDeletingEdit,
		"task_deleting_delete": errGoalTaskDeletingDelete,
		"text_empty":           errGoalTextEmpty,
		"not_found":            errGoalNotFound,
		"read_after_add":       errGoalReadAfterAdd,
		"read_after_edit":      errGoalReadAfterEdit,
	}
	for label, msg := range cases {
		assertKoreanError(t, label, msg)
	}
}

// TestGoalHandlersResponsesLocalized 는 DB 를 건드리지 않고 끝나는 핸들러 경로를 실제
// HTTP 응답 본문까지 검사해, 상수가 응답에 실제로 실리는 연결을 확인한다. 세 핸들러 모두
// s.m.Task(맵 조회) → s.engine.beginTaskOperation(sync.Map 기반 삭제 장벽) → 요청 본문
// 검증 순이라, tasks 맵에 작업 하나와 빈 Engine 만 있으면 Store·DB 없이 돌아간다.
func TestGoalHandlersResponsesLocalized(t *testing.T) {
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

	newReq := func(body, gid string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/t1/goals", strings.NewReader(body))
		req.SetPathValue("id", "t1")
		if gid != "" {
			req.SetPathValue("gid", gid)
		}
		return req
	}

	cases := []struct {
		name    string
		handler func(*Server) http.HandlerFunc
		server  func() *Server
		body    string
		gid     string
		code    int
		want    string
	}{
		{
			name:    "add/task-deleting",
			handler: func(s *Server) http.HandlerFunc { return s.addGoal },
			server:  deletingServer,
			body:    `{"text":"SQL 인젝션 입증"}`,
			code:    http.StatusConflict,
			want:    errGoalTaskDeletingAdd,
		},
		{
			name:    "add/text-empty",
			handler: func(s *Server) http.HandlerFunc { return s.addGoal },
			server:  liveServer,
			body:    `{"text":"   "}`,
			code:    http.StatusBadRequest,
			want:    errGoalTextEmpty,
		},
		{
			name:    "edit/task-deleting",
			handler: func(s *Server) http.HandlerFunc { return s.editGoal },
			server:  deletingServer,
			body:    `{"text":"수정된 목표"}`,
			gid:     "5",
			code:    http.StatusConflict,
			want:    errGoalTaskDeletingEdit,
		},
		{
			name:    "edit/text-empty",
			handler: func(s *Server) http.HandlerFunc { return s.editGoal },
			server:  liveServer,
			body:    `{"text":"  "}`,
			gid:     "5",
			code:    http.StatusBadRequest,
			want:    errGoalTextEmpty,
		},
		{
			name:    "delete/task-deleting",
			handler: func(s *Server) http.HandlerFunc { return s.deleteGoal },
			server:  deletingServer,
			body:    ``,
			gid:     "5",
			code:    http.StatusConflict,
			want:    errGoalTaskDeletingDelete,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := c.server()
			rec := httptest.NewRecorder()
			c.handler(s)(rec, newReq(c.body, c.gid))
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
