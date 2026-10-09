//go:build !embedui

package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWebUIStubErrorLocalized guards the no-embed stub's HTTP response: a request
// served by the default (!embedui) build must get a Korean 404 body, not the old
// Chinese one. This is the last user-facing HTTP error response in server/ that the
// earlier `writeErr(`-only sweeps missed (it uses http.Error, not writeErr). If an
// upstream re-sync reintroduces the Chinese literal, this test fails.
func TestWebUIStubErrorLocalized(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	(&Server{}).webuiHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("상태 코드가 404 가 아닙니다: %d", rec.Code)
	}
	body := strings.TrimSpace(rec.Body.String())
	assertKoreanError(t, "webui.stub", body)
	// 명령 참조는 원문 그대로 보존되어야 한다(번역 대상 아님).
	for _, want := range []string{"next dev", "-tags embedui"} {
		if !strings.Contains(body, want) {
			t.Fatalf("명령 참조 %q 가 응답에 없습니다: %q", want, body)
		}
	}
}
