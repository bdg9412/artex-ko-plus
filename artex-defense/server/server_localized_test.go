package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// server.go 의 사용자 노출 응답을 한국어로 유지하는 회귀 방어 테스트다(F3b-server.go +
// F34). 한국어 판정은 F3a 의 assertKoreanError(한글 포함·중국어 한자 0)를, 응답 본문
// 추출은 task_categories 테스트의 decodeErrorField 를 재사용한다(같은 package server).
// 범위는 ① F3b: writeErr 24곳 + validateTaskProfileIDs 가 writeErr 로 노출하는
// fmt.Errorf 2곳, ② F34: writeErr 를 거치지 않는 사용자 노출 5곳(chatUnavailableReason
// 의 return 3종 + testLLM·웹 검색 프로브의 writeJSON error 2종), ③ F34(d): 규칙 모드
// 채팅 fallbackChat 의 응답 3종(확인 2종 + 현황 요약)과 한국어 트리거 별칭(의도/힌트) 인식
// 이다. 에이전트에 전달되는 프롬프트·도구 설명·seed 의도 요약·기본 제목(未命名任务)·로그는
// 원문 보존이라 이 테스트의 대상이 아니다.

// TestServerErrorConstantsLocalized 는 응답 상수 전부가 한국어임을 단언한다. 형식 문자열
// 상수(%d 포함)는 실제 포매팅한 결과로도 함께 검사해, 치환값이 들어가도 한국어가 깨지지
// 않음을 확인한다.
func TestServerErrorConstantsLocalized(t *testing.T) {
	plain := map[string]string{
		"intent_control":        errTaskDeletingIntentControl,
		"intent_rerun":          errTaskDeletingIntentRerun,
		"intent_not_rerunnable": errIntentNotRerunnable,
		"source_invalid":        errCreateTaskSourceInvalid,
		"intercept_rules":       errCreateTaskInterceptRules,
		"category_invalid":      errCreateTaskCategoryInvalid,
		"company_invalid":       errCreateTaskCompanyInvalid,
		"llm_profile_invalid":   errLLMProfileInvalid,
		"asset_store_disabled":  errAssetStoreDisabled,
		"asset_id_required":     errAssetIDRequired,
		"python_not_detected":   errPythonNotDetected,
		"notify_base_url":       errNotifyBaseURLScheme,
		"notify_digest":         errNotifyDigestRange,
		"new_session":           errTaskDeletingNewSession,
		"new_message":           errTaskDeletingNewMessage,
		"main_agent_busy":       errMainAgentBusy,
		// F34: writeErr 를 거치지 않는 사용자 노출 응답
		"chat_no_profile":       errChatNoLLMProfile,
		"chat_no_active":        errChatNoActiveLLMProfile,
		"chat_not_ready":        errChatLLMNotReady,
		"llm_test_no_api_key":   errLLMTestNoAPIKey,
		"web_search_no_results": errWebSearchProbeNoResults,
		// F34(d): 규칙 모드 채팅 fallbackChat 의 두 확인 응답(뒤에 입력 텍스트를 이어 붙인다)
		"fallback_intent": fallbackIntentInjected,
		"fallback_hint":   fallbackHintRecorded,
	}
	for label, msg := range plain {
		assertKoreanError(t, label, msg)
	}

	formatted := map[string]string{
		"source_limit":     fmt.Sprintf(errCreateTaskSourceLimit, 8),
		"source_not_found": fmt.Sprintf(errCreateTaskSourceNotFound, 999),
		"company_limit":    fmt.Sprintf(errCreateTaskCompanyLimit, 32),
		"llm_profile_404":  fmt.Sprintf(errLLMProfileNotFound, 7),
		// F34(d): 규칙 모드 현황 요약(자산·대기 의도·확인된 취약점 개수 치환)
		"fallback_status": fmt.Sprintf(fallbackChatStatus, 3, 2, 1),
	}
	for label, msg := range formatted {
		assertKoreanError(t, label, msg)
	}
}

// TestServerHandlersResponsesLocalized 는 DB 를 건드리지 않고 끝나는 핸들러 경로를 실제
// HTTP 응답 본문까지 검사해, 상수가 응답에 실제로 실리는 연결을 확인한다(상수를 중국어로
// 되돌리면 이 테스트가 깨진다 = 적대적 비공허성). DB·엔진·자산 저장소가 필요한 경로
// (분류/기업 무효·LLM 설정 미존재·파이썬 미탐지·알림 설정·메인 에이전트 점유)는 위
// 상수 단언으로 핀 고정한다.
func TestServerHandlersResponsesLocalized(t *testing.T) {
	// 삭제 장벽이 세워진 서버: beginTaskOperation / IsDeleting 이 "삭제 중"으로 판정한다.
	deletingServer := func() *Server {
		s := &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}, engine: &Engine{}}
		s.engine.deleting.Store("t1", true)
		return s
	}
	// 장벽이 없는 서버: 입력 검증까지 진행한다.
	liveServer := func() *Server {
		return &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}, engine: &Engine{}}
	}

	cases := []struct {
		name    string
		req     func() *http.Request
		handler func(*Server) http.HandlerFunc
		server  func() *Server
		code    int
		want    string
	}{
		{
			name: "controlIntent/task-deleting",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/tasks/t1/intents/5/control", strings.NewReader(`{"action":"pause"}`))
				r.SetPathValue("id", "t1")
				r.SetPathValue("iid", "5")
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.controlIntent },
			server:  deletingServer,
			code:    http.StatusConflict,
			want:    errTaskDeletingIntentControl,
		},
		{
			name: "rerunIntent/task-deleting",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/tasks/t1/intents/5/rerun", nil)
				r.SetPathValue("id", "t1")
				r.SetPathValue("iid", "5")
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.rerunIntent },
			server:  deletingServer,
			code:    http.StatusConflict,
			want:    errTaskDeletingIntentRerun,
		},
		{
			name: "rerunBlocked/task-deleting",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/tasks/t1/intents/rerun-blocked", nil)
				r.SetPathValue("id", "t1")
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.rerunBlocked },
			server:  deletingServer,
			code:    http.StatusConflict,
			want:    errTaskDeletingIntentRerun,
		},
		{
			name: "createTask/source-limit",
			req: func() *http.Request {
				// MaxTaskSourceCount=8 → 9개는 한도 초과(루프 전에 반환).
				r := httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(
					`{"goal":"목표","source_task_ids":["1","2","3","4","5","6","7","8","9"]}`))
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.createTask },
			server:  liveServer,
			code:    http.StatusBadRequest,
			want:    fmt.Sprintf(errCreateTaskSourceLimit, 8),
		},
		{
			name: "createTask/source-invalid",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(
					`{"goal":"목표","source_task_ids":["abc"]}`))
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.createTask },
			server:  liveServer,
			code:    http.StatusBadRequest,
			want:    errCreateTaskSourceInvalid,
		},
		{
			name: "createTask/source-not-found",
			req: func() *http.Request {
				// 999 는 tasks 맵에 없음 → 찾을 수 없음(DB 미접근, 맵 조회).
				r := httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(
					`{"goal":"목표","source_task_ids":["999"]}`))
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.createTask },
			server:  liveServer,
			code:    http.StatusBadRequest,
			want:    fmt.Sprintf(errCreateTaskSourceNotFound, 999),
		},
		{
			name: "createTask/company-limit",
			req: func() *http.Request {
				// MaxTaskCompanyCount=32 → 33개는 NormalizeTaskCompanyIDs(순수 함수)에서 오류.
				ids := make([]string, 33)
				for i := range ids {
					ids[i] = fmt.Sprintf("%d", i+1)
				}
				body := `{"goal":"목표","company_ids":[` + strings.Join(ids, ",") + `]}`
				return httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(body))
			},
			handler: func(s *Server) http.HandlerFunc { return s.createTask },
			server:  liveServer,
			code:    http.StatusBadRequest,
			want:    fmt.Sprintf(errCreateTaskCompanyLimit, 32),
		},
		{
			name: "createTask/llm-profile-invalid",
			req: func() *http.Request {
				// llm_profile_ids:[0] → validateTaskProfileIDs 가 loadProfileConfig(DB) 전에 반환.
				r := httptest.NewRequest(http.MethodPost, "/api/tasks", strings.NewReader(
					`{"goal":"목표","llm_profile_ids":[0]}`))
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.createTask },
			server:  liveServer,
			code:    http.StatusBadRequest,
			want:    errLLMProfileInvalid,
		},
		{
			name: "taskCoverageGraph/asset-store-disabled",
			req: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/api/tasks/t1/coverage-graph", nil)
				r.SetPathValue("id", "t1")
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.taskCoverageGraph },
			server:  liveServer, // Manager.assets==nil → Assets()==nil → 503
			code:    http.StatusServiceUnavailable,
			want:    errAssetStoreDisabled,
		},
		{
			name: "taskAssetRefs/asset-id-required",
			req: func() *http.Request {
				// asset_id 쿼리 없음 → ParseInt("")=0 → <=0 → 400(Assets() 호출 전).
				r := httptest.NewRequest(http.MethodGet, "/api/tasks/t1/asset-refs", nil)
				r.SetPathValue("id", "t1")
				return r
			},
			handler: func(s *Server) http.HandlerFunc { return s.taskAssetRefs },
			server:  liveServer,
			code:    http.StatusBadRequest,
			want:    errAssetIDRequired,
		},
		{
			// F34(b): profile_id 를 비우고(=DB 미조회) api_key 도 비우면 TestConnection
			// 전에 writeJSON{ok:false,error}로 반환한다(status 200). liveServer 는
			// llmCfg.APIKey 도 "" 라 전역 폴백 키도 없다.
			name: "testLLM/no-api-key",
			req: func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/api/llm/test", strings.NewReader(`{}`))
			},
			handler: func(s *Server) http.HandlerFunc { return s.testLLM },
			server:  liveServer,
			code:    http.StatusOK,
			want:    errLLMTestNoAPIKey,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := c.server()
			rec := httptest.NewRecorder()
			c.handler(s)(rec, c.req())
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

// TestChatUnavailableReasonLocalized 는 F34(a)의 chatUnavailableReason() 이 사용자에게
// 실제로 돌려주는 사유가 한국어 상수에 연결되어 있음을 확인한다. pg 가 nil 이면(테스트에
// DB 없음) "준비 안 됨" 경로로 바로 떨어지므로, 그 return 이 errChatLLMNotReady 임을
// 단언한다(상수를 중국어로 되돌리면 깨짐 = 적대적 비공허성). 나머지 두 사유(설정 없음·활성
// 설정 없음)는 pg(DB)가 필요한 분기라 위 상수 단언으로 핀 고정한다.
func TestChatUnavailableReasonLocalized(t *testing.T) {
	s := &Server{m: &Manager{}} // m.pg == nil → 세 번째 return 경로
	got := s.chatUnavailableReason()
	if got != errChatLLMNotReady {
		t.Fatalf("chatUnavailableReason() = %q, 기대 = %q", got, errChatLLMNotReady)
	}
	assertKoreanError(t, "chat_not_ready", got)
}

// TestFallbackCommandParsing 은 규칙 모드 채팅의 트리거 키워드 파싱(fallbackCommand)이 한국어
// 별칭(의도/힌트)을 인식하면서도 기존 중국어·영어 트리거를 그대로 받고, 키워드만 벗겨 낸
// 인자를 돌려줌을 확인한다. Store·DB 를 건드리지 않는 순수 입력 파싱이라 DB 없이 돌아간다.
// 한국어 별칭을 지우면 korean-* 케이스가, 중국어·영어를 지우면 그 케이스가 깨진다(비공허성).
func TestFallbackCommandParsing(t *testing.T) {
	cases := []struct {
		name, in, cmd, text string
	}{
		{"korean-intent", "의도 SQLi 주입점 먼저 확인", "intent", "SQLi 주입점 먼저 확인"},
		{"korean-hint", "힌트 로그인 폼부터 보라", "hint", "로그인 폼부터 보라"},
		{"chinese-intent", "意图 扫描端口", "intent", "扫描端口"}, // 하위 호환 보존
		{"chinese-hint", "提示 看登录", "hint", "看登录"},       // 하위 호환 보존
		{"english-intent", "intent scan ports", "intent", "scan ports"},
		{"english-hint", "hint try admin:admin", "hint", "try admin:admin"},
		{"status-korean", "지금 상황 알려줘", "", "지금 상황 알려줘"},
		{"status-empty", "   ", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cmd, text := fallbackCommand(c.in)
			if cmd != c.cmd || text != c.text {
				t.Fatalf("fallbackCommand(%q) = (%q, %q), 기대 = (%q, %q)", c.in, cmd, text, c.cmd, c.text)
			}
		})
	}
}
