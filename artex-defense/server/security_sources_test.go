package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/securitysource"
)

func TestPurpleSecuritySourceEncryptionAndTamper(t *testing.T) {
	s := &Server{jwtKey: []byte("source-test-key")}
	auth := securitysource.Credentials{Username: "reader", Password: "never-expose-this"}
	c, e := s.encryptSourceCredentials(auth)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(c), auth.Password) {
		t.Fatal("credential stored as plaintext")
	}
	out, e := s.securitySourceCredentials(&db.SecuritySource{SecretCipher: c})
	if e != nil || out != auth {
		t.Fatalf("roundtrip: %v", e)
	}
	c[len(c)-1] ^= 1
	if _, e := s.securitySourceCredentials(&db.SecuritySource{SecretCipher: c}); e == nil {
		t.Fatal("tampered credentials accepted")
	}
}
func TestPurpleSecuritySourceAPISecretRedactionAndRevisions(t *testing.T) {
	s, _, request := purpleAPIFixture(t)
	cfg := securitysource.Config{BaseURL: "https://siem.example.test:8089", Index: "security", AuditSourcetype: "audit", AlertSourcetype: "alert", CorrelationField: "artex_verification_id", ActionField: "action"}
	in := map[string]any{"name": "test-read-only", "config": cfg, "enabled": true, "expected_revision": 0, "username": "reader", "password": "source-secret-not-in-output"}
	post := func(method, path string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(in)
		return request(method, path, string(b))
	}
	w := post("POST", "/api/purple/sources")
	if w.Code != 201 || strings.Contains(w.Body.String(), "source-secret") || strings.Contains(w.Body.String(), "secret_cipher") {
		t.Fatalf("save: %d %s", w.Code, w.Body)
	}
	var source db.SecuritySource
	if e := json.Unmarshal(w.Body.Bytes(), &source); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID) })
	stored, e := s.m.pg.GetSecuritySource(t.Context(), source.ID)
	if e != nil {
		t.Fatal(e)
	}
	if len(stored.SecretCipher) == 0 || !source.CredentialSet {
		t.Fatal("encrypted credentials not stored")
	}
	if w = request("GET", "/api/purple/sources", ""); w.Code != 200 || strings.Contains(w.Body.String(), "source-secret") {
		t.Fatal("list disclosed credentials")
	}
	delete(in, "username")
	delete(in, "password")
	in["expected_revision"] = source.Revision
	in["name"] = "renamed"
	path := fmt.Sprintf("/api/purple/sources/%d", source.ID)
	w = post("PUT", path)
	if w.Code != 200 {
		t.Fatalf("preserve secret: %d %s", w.Code, w.Body)
	}
	after, _ := s.m.pg.GetSecuritySource(t.Context(), source.ID)
	if string(after.SecretCipher) != string(stored.SecretCipher) || after.Revision != 2 {
		t.Fatal("update lost credentials or revision")
	}
	if w = post("PUT", path); w.Code != 409 {
		t.Fatal("stale source edit accepted")
	}
	in["expected_revision"] = 2
	cfg.BaseURL = "https://other.example.test"
	in["config"] = cfg
	if w = post("PUT", path); w.Code != 400 {
		t.Fatal("credential silently forwarded to new endpoint")
	}
}
func TestPurpleSecuritySourceAuthentication(t *testing.T) {
	s := &Server{jwtKey: []byte("key")}
	for _, r := range []struct{ method, path string }{{"GET", "/api/purple/sources"}, {"POST", "/api/purple/sources"}, {"PUT", "/api/purple/sources/1"}, {"POST", "/api/purple/sources/1/test"}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(r.method, r.path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatalf("unprotected %s", r.path)
		}
	}
}
