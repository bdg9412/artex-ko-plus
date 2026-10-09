package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestWorkspaceErrorConstantsLocalized guards F3b (workspace.go): every user-facing
// error string the workspace file manager hands back must be Korean (Hangul present,
// no Chinese Han). Reverting any literal to Chinese fails this test. The constants
// are DB-independent, so this always runs (no postgres needed).
func TestWorkspaceErrorConstantsLocalized(t *testing.T) {
	for label, msg := range map[string]string{
		"illegalPath":      errWsIllegalPath,
		"pathNotFound":     errWsPathNotFound,
		"notDir":           errWsNotDir,
		"fileNotFound":     errWsFileNotFound,
		"isDir":            errWsIsDir,
		"targetIsDir":      errWsTargetIsDir,
		"cannotDeleteRoot": errWsCannotDeleteRoot,
		"uploadDirMissing": errWsUploadDirMissing,
		"uploadParse":      errWsUploadParse,
		"noUploadFile":     errWsNoUploadFile,
	} {
		assertKoreanError(t, label, msg)
	}
}

// wsErrBody pulls the {"error": "..."} string writeErr produces.
func wsErrBody(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("응답 JSON 파싱 실패: %v (본문 %q)", err, rec.Body.String())
	}
	return out.Error
}

// TestWorkspaceHandlerResponsesLocalized drives the workspace file-manager handlers
// over real HTTP. They only touch s.m.dir and the filesystem (never s.m.pg), so a
// temp-dir Manager is enough — no DB. This proves the Korean constants actually land
// in the HTTP response body, not just that the constants are Korean.
func TestWorkspaceHandlerResponsesLocalized(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: &Manager{dir: dir}}

	cases := []struct {
		name    string
		handler http.HandlerFunc
		req     *http.Request
		code    int
		want    string
	}{
		{"read-missing", s.wsRead, httptest.NewRequest(http.MethodGet, "/api/workspace/read?path=nope.txt", nil), 404, errWsFileNotFound},
		{"read-dir", s.wsRead, httptest.NewRequest(http.MethodGet, "/api/workspace/read?path=sub", nil), 400, errWsIsDir},
		{"list-missing", s.wsList, httptest.NewRequest(http.MethodGet, "/api/workspace/list?path=nope", nil), 404, errWsPathNotFound},
		{"list-not-dir", s.wsList, nil, 400, errWsNotDir}, // req built below (needs a real file)
		{"delete-root", s.wsDelete, httptest.NewRequest(http.MethodDelete, "/api/workspace/delete?path=", nil), 400, errWsCannotDeleteRoot},
	}

	// list-not-dir needs an actual file to point at.
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases[3].req = httptest.NewRequest(http.MethodGet, "/api/workspace/list?path=a.txt", nil)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c.handler(rec, c.req)
			if rec.Code != c.code {
				t.Fatalf("status = %d, want %d (본문 %q)", rec.Code, c.code, rec.Body.String())
			}
			got := wsErrBody(t, rec)
			if got != c.want {
				t.Fatalf("error = %q, want %q", got, c.want)
			}
			assertKoreanError(t, c.name, got)
		})
	}
}
