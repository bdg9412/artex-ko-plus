package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func purpleAPIFixture(t *testing.T) (*Server, int64, func(string, string, string) *httptest.ResponseRecorder) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN is required for isolated PostgreSQL integration tests")
	}
	pg, err := db.Open(dsn)
	if err != nil {
		t.Fatalf("initialize configured purple test database: %v", err)
	}
	t.Cleanup(func() { pg.Close() })
	id, err := pg.AddFinding(0, 0, "PURPLE_API", "API fixture", "medium", "source", "source evidence", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pg.DeleteFinding(id); err != nil {
			t.Error(err)
		}
	})
	s := &Server{m: &Manager{pg: pg}, jwtKey: []byte("purple-test-only-signing-key-32-bytes")}
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.Handler()
	request := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	return s, id, request
}

func TestPurpleAPIRequiresAuthentication(t *testing.T) {
	s := &Server{jwtKey: []byte("purple-test-only-signing-key-32-bytes")}
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/purple/overview"}, {"GET", "/api/exploration/findings/1/defense"},
		{"PUT", "/api/exploration/findings/1/defense"}, {"POST", "/api/exploration/findings/1/defense/validations"},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: %d", route.method, route.path, w.Code)
		}
	}
}

func TestPurpleAPIContractsAndErrors(t *testing.T) {
	s, id, request := purpleAPIFixture(t)
	path := fmt.Sprintf("/api/exploration/findings/%d/defense", id)
	parse := func(r *httptest.ResponseRecorder, code int) db.FindingDefense {
		t.Helper()
		if r.Code != code {
			t.Fatalf("response %d: %s", r.Code, r.Body)
		}
		var out db.FindingDefense
		if err := json.Unmarshal(r.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	initial := parse(request("GET", path, ""), 200)
	if initial.State != "unplanned" || initial.Validations == nil || len(initial.SourceFingerprint) != 32 {
		t.Fatalf("initial bundle: %+v", initial)
	}
	for _, body := range []string{`{`, `null`, `[]`, `{} {}`, `{"hypothesis":"x","rule_format":"bad"}`, `{"hypothesis":"x","rule_format":"query","unknown":1}`, `{"hypothesis":" ","rule_format":"query"}`} {
		if r := request("PUT", path, body); r.Code != 400 {
			t.Fatalf("bad body accepted (%s): %d %s", body, r.Code, r.Body)
		}
	}
	if r := request("PUT", path, `{"hypothesis":"`+strings.Repeat("x", maxPurpleRequestBytes)+`","rule_format":"query"}`); r.Code != 413 {
		t.Fatalf("oversized body: %d %s", r.Code, r.Body)
	}
	if r := request("PUT", path, `{"hypothesis":"`+strings.Repeat("x", 4001)+`","rule_format":"query"}`); r.Code != 400 {
		t.Fatalf("oversized field: %d %s", r.Code, r.Body)
	}
	for _, query := range []string{"?limit=101", "?page=-1", "?page=huge", "?page=1000001", "?limit=0"} {
		if r := request("GET", "/api/purple/overview"+query, ""); r.Code != 400 {
			t.Fatalf("bad pagination accepted: %s %d", query, r.Code)
		}
	}
	state := parse(request("PUT", path, `{"hypothesis":"local event should alert","rule_format":"query","rule_text":"test = true","expected_revision":0}`), 200)
	if state.Plan == nil || state.Plan.Revision != 1 || state.State != "untested" {
		t.Fatalf("plan bundle: %+v", state)
	}
	if r := request("PUT", path, `{"hypothesis":"stale edit","rule_format":"query"}`); r.Code != 409 {
		t.Fatalf("optimistic conflict: %d %s", r.Code, r.Body)
	}
	makeObservation := func() map[string]any {
		return map[string]any{"plan_revision": state.Plan.Revision, "expected_evidence_version": state.EvidenceVersion, "expected_source_fingerprint": state.SourceFingerprint, "detection": "detected", "prevention": "not_tested", "evidence": "alert #7", "observed_at": time.Now().UTC().Add(-time.Minute).Format(time.RFC3339), "notes": "manually observed"}
	}
	post := func(in map[string]any) *httptest.ResponseRecorder {
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		return request("POST", path+"/validations", string(raw))
	}
	for _, field := range []string{"expected_evidence_version", "expected_source_fingerprint", "observed_at", "evidence"} {
		in := makeObservation()
		delete(in, field)
		if r := post(in); r.Code != 400 {
			t.Fatalf("missing %s: %d %s", field, r.Code, r.Body)
		}
	}
	for _, mutation := range []map[string]any{{"detection": "unknown"}, {"prevention": "unknown"}, {"detection": "not_tested"}, {"evidence": " "}, {"observed_at": "not-a-date"}, {"observed_at": time.Now().Add(time.Hour).Format(time.RFC3339)}} {
		in := makeObservation()
		for k, v := range mutation {
			in[k] = v
		}
		if r := post(in); r.Code != 400 {
			t.Fatalf("invalid observation %v: %d %s", mutation, r.Code, r.Body)
		}
	}
	state = parse(post(makeObservation()), 201)
	if state.State != "current" || len(state.Validations) != 1 || state.Validations[0].PlanSnapshot.Revision != 1 {
		t.Fatalf("validation bundle: %+v", state)
	}
	stale := makeObservation()
	if _, err := s.m.pg.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if r := post(stale); r.Code != 409 {
		t.Fatalf("stale source conflict: %d %s", r.Code, r.Body)
	}
	state = parse(request("GET", path, ""), 200)
	if state.State != "stale" {
		t.Fatalf("staleness: %+v", state)
	}
	missing := "/api/exploration/findings/9223372036854775807/defense"
	if r := request("GET", missing, ""); r.Code != 404 {
		t.Fatalf("missing GET: %d %s", r.Code, r.Body)
	}
	if r := request("PUT", missing, `{"hypothesis":"valid","rule_format":"query"}`); r.Code != 404 {
		t.Fatalf("missing PUT: %d %s", r.Code, r.Body)
	}
	raw, _ := json.Marshal(makeObservation())
	if r := request("POST", missing+"/validations", string(raw)); r.Code != 404 {
		t.Fatalf("missing POST: %d %s", r.Code, r.Body)
	}
	for _, invalidID := range []string{"0", "-1", "abc"} {
		if r := request("GET", "/api/exploration/findings/"+invalidID+"/defense", ""); r.Code != 400 {
			t.Fatalf("bad id %s: %d", invalidID, r.Code)
		}
	}
	if r := request("GET", "/api/purple/overview?limit=1", ""); r.Code != 200 {
		t.Fatalf("overview: %d %s", r.Code, r.Body)
	}
}
