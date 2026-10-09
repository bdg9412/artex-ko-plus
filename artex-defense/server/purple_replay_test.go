package server

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestPurpleReplayAPIRejectsNULRuleFields(t *testing.T) {
	s, id, request := purpleAPIFixture(t)
	state, err := s.m.pg.SaveDefensePlan(t.Context(), id, db.DefensePlanInput{
		Hypothesis: "invalid field fixture", RuleFormat: "event_filter",
		RuleText: `{"version":1,"all":[{"field":"actor\u0000id","op":"eq","value":"alice"}]}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(db.DefenseReplayInput{
		PlanRevision: state.Plan.Revision, ExpectedEvidenceVersion: &state.EvidenceVersion,
		ExpectedSourceFingerprint: state.SourceFingerprint, TargetLogs: `{}`, ControlLogs: `{}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := request("POST", fmt.Sprintf("/api/exploration/findings/%d/defense/replays", id), string(raw))
	if w.Code != 400 {
		t.Fatalf("NUL rule field should be rejected before JSONB persistence: %d %s", w.Code, w.Body)
	}
}

func TestPurpleReplayAPIAuthentication(t *testing.T) {
	s := &Server{jwtKey: []byte("purple-replay-test-key")}
	for _, route := range []struct{ method, path string }{{"GET", "/api/exploration/findings/1/defense/replays"}, {"POST", "/api/exploration/findings/1/defense/replays"}, {"GET", "/api/exploration/findings/1/defense/replays/1/export"}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatalf("unauthenticated %s: %d", route.path, w.Code)
		}
	}
}

func TestPurpleReplayAPIResultsAndExport(t *testing.T) {
	s, id, request := purpleAPIFixture(t)
	plan, err := s.m.pg.SaveDefensePlan(t.Context(), id, db.DefensePlanInput{Hypothesis: "local sample", RuleFormat: "event_filter", RuleText: `{"version":1,"all":[{"field":"action","op":"eq","value":"denied"}]}`})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/exploration/findings/%d/defense/replays", id)
	in := map[string]any{"plan_revision": plan.Plan.Revision, "expected_evidence_version": plan.EvidenceVersion, "expected_source_fingerprint": plan.SourceFingerprint, "target_logs": "{\"action\":\"denied\"}\n", "control_logs": `{"action":"allowed"}`, "notes": "API replay fixture"}
	post := func(input map[string]any) *httptest.ResponseRecorder {
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return request("POST", path, string(raw))
	}
	w := post(in)
	if w.Code != 201 {
		t.Fatalf("run: %d %s", w.Code, w.Body)
	}
	var run db.DefenseReplay
	if err = json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run.Result.Verdict != "pass" || run.State != "current" || strings.Contains(w.Body.String(), "target_logs") {
		t.Fatalf("run response: %s", w.Body)
	}
	if w = request("GET", path, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"runs":[`) || strings.Contains(w.Body.String(), "target_logs") {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	exportPath := fmt.Sprintf("%s/%d/export", path, run.ID)
	w = request("GET", exportPath, "")
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("export headers: %d %v", w.Code, w.Header())
	}
	var exported db.DefenseReplayExport
	if err = json.Unmarshal(w.Body.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if exported.TargetLogs != in["target_logs"] || exported.ControlLogs != in["control_logs"] || exported.ID != run.ID {
		t.Fatal("export lost input/run association")
	}
	if w = request("GET", fmt.Sprintf("/api/exploration/findings/%d/defense/replays/%d/export", id+1000000, run.ID), ""); w.Code != 404 {
		t.Fatalf("foreign run export: %d %s", w.Code, w.Body)
	}
	if w = request("GET", path+"/9223372036854775807/export", ""); w.Code != 404 {
		t.Fatalf("unknown run: %d %s", w.Code, w.Body)
	}
	if w = request("GET", path+"/no/export", ""); w.Code != 400 {
		t.Fatalf("invalid run id: %d %s", w.Code, w.Body)
	}
	if w = request("GET", "/api/exploration/findings/9223372036854775807/defense/replays", ""); w.Code != 404 {
		t.Fatalf("unknown finding list: %d %s", w.Code, w.Body)
	}
	// Client verdict and rule injection are not fields of this API.
	in["verdict"] = "pass"
	if w = post(in); w.Code != 400 {
		t.Fatalf("client verdict accepted: %d", w.Code)
	}
	delete(in, "verdict")
	in["rule_text"] = "replacement"
	if w = post(in); w.Code != 400 {
		t.Fatalf("client rule accepted: %d", w.Code)
	}
	delete(in, "rule_text")
	for _, field := range []string{"expected_source_fingerprint", "expected_evidence_version", "plan_revision"} {
		old := in[field]
		delete(in, field)
		if w = post(in); w.Code != 400 {
			t.Fatalf("missing %s: %d %s", field, w.Code, w.Body)
		}
		in[field] = old
	}
	in["target_logs"] = "not JSON"
	if w = post(in); w.Code != 400 {
		t.Fatalf("invalid logs: %d %s", w.Code, w.Body)
	}
	in["target_logs"] = strings.Repeat("x", (1<<20)+1)
	if w = post(in); w.Code != 400 {
		t.Fatalf("decoded bytes bound: %d %s", w.Code, w.Body)
	}
	if w = request("POST", path, `{"target_logs":"`+strings.Repeat("x", maxPurpleReplayRequestBytes)+`"}`); w.Code != 413 {
		t.Fatalf("body bound: %d %s", w.Code, w.Body)
	}
	in["target_logs"] = `{"action":"denied"}`
	if _, err = s.m.pg.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if w = post(in); w.Code != 409 {
		t.Fatalf("stale evidence: %d %s", w.Code, w.Body)
	}
	if w = request("GET", path, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"stale"`) {
		t.Fatalf("stale history: %d %s", w.Code, w.Body)
	}
}
