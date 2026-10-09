package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// customtool.go 의 사용자 지정 도구 CRUD·시험 실행 엔드포인트가 writeErr 로 돌려주는
// 검증 오류 응답을 한국어로 유지하는 회귀 방어 테스트다. 한국어 판정은 F3a 의
// assertKoreanError(한글 포함·중국어 한자 0), 응답 본문 추출은 task_categories 테스트의
// decodeErrorField 를 재사용한다(같은 package server). 에이전트가 읽는 actool.Errorf 도구
// 결과와 도구 스키마 description 은 두뇌 경계라 번역 대상이 아니며 이 테스트도 건드리지 않는다.

// TestCustomToolErrorConstantsLocalized 는 writeErr 로 노출되는 상수 8종이 전부 한국어임을
// 단언한다. 이 중 둘(errCustomToolKeyExists·errCustomToolEditCustomOnly)은 핸들러가 먼저
// pg.GetTool(DB)을 거쳐야 도달하므로 아래 실제 HTTP 테스트로는 닿지 않는다. 상수 단언으로
// 핀 고정하고, "어느 분기에서 이 상수가 쓰이는지"는 코드 경로 추적으로 확인했다
// (goals_api·task_control 의 DB 경로 검증 밀도와 동일).
func TestCustomToolErrorConstantsLocalized(t *testing.T) {
	for _, c := range []struct{ name, msg string }{
		{"keyFormat", errCustomToolKeyFormat},
		{"kindInvalid", errCustomToolKindInvalid},
		{"httpSchemaRequired", errCustomToolHTTPSchemaRequired},
		{"keyExists", errCustomToolKeyExists},
		{"editCustomOnly", errCustomToolEditCustomOnly},
		{"badBody", errCustomToolBadBody},
		{"shellNoExec", errCustomToolShellNoExec},
		{"unknownKindPrefix", errCustomToolUnknownKindPrefix},
	} {
		assertKoreanError(t, "customtool."+c.name, c.msg)
	}
}

// newCustomToolServer 는 pg 게이트(s.pg)를 통과시키되 실제 DB 연결은 없는 Server 를 만든다.
// &db.DB{} 는 임베드된 *sql.DB 가 nil 이지만 포인터 자체는 non-nil 이라 pg() 가 503 을 쓰지
// 않고 그대로 반환한다. 아래 검증 분기들은 전부 pg.GetTool 같은 실제 DB 호출 "이전"에
// 반환하므로 nil DB 를 역참조하지 않는다(코드 경로로 확인).
func newCustomToolServer() *Server {
	return &Server{m: &Manager{pg: &db.DB{}}}
}

// TestCustomToolCreateValidationLocalized 는 pgCreateCustomTool 의 입력 검증 3경로를
// 실제 HTTP 로 돌려 응답 본문이 한국어임을 확인한다. 세 경로 모두 pg.GetTool(68행) 전에
// 반환한다.
func TestCustomToolCreateValidationLocalized(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"bad-key", `{"key":"BadKey","kind":"command"}`, errCustomToolKeyFormat},
		{"bad-kind", `{"key":"goodkey","kind":"bogus"}`, errCustomToolKindInvalid},
		{"http-no-schema", `{"key":"goodkey","kind":"http"}`, errCustomToolHTTPSchemaRequired},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newCustomToolServer()
			req := httptest.NewRequest(http.MethodPost, "/api/tools/custom", strings.NewReader(c.body))
			rec := httptest.NewRecorder()
			s.pgCreateCustomTool(rec, req)
			if rec.Code != 400 && rec.Code != 409 {
				t.Fatalf("검증 오류 상태 코드를 기대했으나 %d (본문 %q)", rec.Code, rec.Body.String())
			}
			got := decodeErrorField(t, rec.Body.Bytes())
			if got != c.want {
				t.Fatalf("응답 본문 불일치: got %q want %q", got, c.want)
			}
			assertKoreanError(t, "customtool.create."+c.name, got)
		})
	}
}

// TestCustomToolTestRunValidationLocalized 는 pgTestCustomTool 의 입력 검증 3경로를
// 실제 HTTP 로 돌려 응답 본문이 한국어임을 확인한다. 셋 다 DB 호출이 없다.
func TestCustomToolTestRunValidationLocalized(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"bad-body", `not-json`, errCustomToolBadBody},
		{"shell", `{"kind":"shell"}`, errCustomToolShellNoExec},
		{"unknown-kind", `{"kind":"bogus"}`, errCustomToolUnknownKindPrefix + "bogus"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newCustomToolServer()
			req := httptest.NewRequest(http.MethodPost, "/api/tools/custom/test", strings.NewReader(c.body))
			rec := httptest.NewRecorder()
			s.pgTestCustomTool(rec, req)
			if rec.Code != 400 {
				t.Fatalf("상태 코드 400 을 기대했으나 %d (본문 %q)", rec.Code, rec.Body.String())
			}
			got := decodeErrorField(t, rec.Body.Bytes())
			if got != c.want {
				t.Fatalf("응답 본문 불일치: got %q want %q", got, c.want)
			}
			// unknown-kind 는 뒤에 req.Kind("bogus") 라틴 꼬리표가 붙으므로 한자 0 만 확인한다.
			assertKoreanError(t, "customtool.test."+c.name, errCustomToolUnknownKindPrefix)
		})
	}
}
