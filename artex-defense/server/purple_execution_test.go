package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/securitysource"
	"github.com/Autumn-27/norma/llm"
)

func TestPurpleExecutionAuthentication(t *testing.T) {
	s := &Server{jwtKey: []byte("purple-execution-test-key")}
	base := "/api/exploration/findings/1/defense/executions"
	for _, route := range []struct{ method, path string }{{"GET", base}, {"POST", base}, {"GET", base + "/compare?baseline_id=1&current_id=2"}, {"GET", base + "/1/export"}, {"POST", base + "/1/collect"}, {"POST", base + "/1/upload"}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s: %d", route.method, route.path, w.Code)
		}
	}
}

func TestPurpleExecutionObservationWindow(t *testing.T) {
	now := time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC)
	start, finish := now.Add(-2*time.Minute), now.Add(-20*time.Second)
	e := &db.DefenseExecution{CorrelationID: "run-correlation-id", CreatedAt: start.Add(-time.Second), Retest: &db.FindingRetest{Status: "completed", StartedAt: &start, FinishedAt: &finish}}
	q, complete, err := defenseExecutionWindow(e, now)
	if err != nil || complete || !q.Start.Equal(start.Add(-30*time.Second)) || !q.End.Equal(now) || q.CorrelationID != e.CorrelationID {
		t.Fatalf("early: %+v %t %v", q, complete, err)
	}
	q, complete, err = defenseExecutionWindow(e, now.Add(time.Minute))
	if err != nil || !complete || !q.End.Equal(finish.Add(time.Minute)) {
		t.Fatalf("settled: %+v %t %v", q, complete, err)
	}
	e.Retest.StartedAt = nil
	e.Retest.CreatedAt = e.CreatedAt.Add(-time.Millisecond)
	q, _, err = defenseExecutionWindow(e, now)
	if err != nil || !q.Start.Equal(e.Retest.CreatedAt.Add(-30*time.Second)) {
		t.Fatal("created-at fallback", q, err)
	}
	for _, status := range []string{"pending", "running"} {
		e.Retest.Status = status
		if _, _, err := defenseExecutionWindow(e, now); err == nil {
			t.Fatalf("queried %s run", status)
		}
	}
	e.Retest.Status = "completed"
	e.Retest.FinishedAt = nil
	if _, _, err := defenseExecutionWindow(e, now); err == nil {
		t.Fatal("queried without terminal timestamp")
	}
}

func executionAPISource(t *testing.T, s *Server, findingID int64, cfg securitysource.Config) (db.DefenseExecutionInput, *db.SecuritySource) {
	t.Helper()
	state, err := s.m.pg.SaveDefensePlan(t.Context(), findingID, db.DefensePlanInput{Hypothesis: "Original ARTEX retest produces a correlated security alert", RuleFormat: "query", RuleText: "Existing deployed detector"})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := s.encryptSourceCredentials(securitysource.Credentials{Token: "test-source-token"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := s.m.pg.SaveSecuritySource(t.Context(), 0, 0, "test SIEM connector", cfg, true, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = s.m.pg.Exec(`DELETE FROM conversations WHERE id IN (SELECT conversation_id FROM finding_retests WHERE finding_id=$1)`, findingID)
		_, _ = s.m.pg.DeleteFinding(findingID)
		_, _ = s.m.pg.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID)
	})
	return db.DefenseExecutionInput{SourceID: source.ID, PlanRevision: state.Plan.Revision, ExpectedEvidenceVersion: &state.EvidenceVersion, ExpectedSourceFingerprint: state.SourceFingerprint}, source
}

func TestPurpleExecutionAPICollectExportAndSourceConflict(t *testing.T) {
	s, fid, request := purpleAPIFixture(t)
	var execution *db.DefenseExecution
	var calls atomic.Int32
	var fail atomic.Bool
	eventTime := time.Now().UTC().Add(-90 * time.Second)
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			http.Error(w, "private upstream details", http.StatusInternalServerError)
			return
		}
		if r.URL.Path != "/services/search/v2/jobs/export" || r.Header.Get("Authorization") != "Bearer test-source-token" {
			t.Error("incorrect connector route/auth")
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if !strings.Contains(r.Form.Get("search"), execution.CorrelationID) {
			t.Error("query lacks execution correlation")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": map[string]any{"_time": eventTime.Format(time.RFC3339Nano), "verification_id": execution.CorrelationID, "action": "blocked", "_cd": "evidence-1"}})
	}))
	defer remote.Close()
	sum := sha256.Sum256(remote.Certificate().Raw)
	in, source := executionAPISource(t, s, fid, securitysource.Config{BaseURL: remote.URL, Index: "main", AuditSourcetype: "audit", AlertSourcetype: "alert", CorrelationField: "verification_id", ActionField: "action", TLSFingerprint: hex.EncodeToString(sum[:])})
	retest, conv, createdExecution, _, err := s.m.pg.CreateFindingRetestWithDefense(t.Context(), fid, "test only", in)
	if err != nil {
		t.Fatal(err)
	}
	execution = createdExecution
	base := fmt.Sprintf("/api/exploration/findings/%d/defense/executions", fid)
	collect := fmt.Sprintf("%s/%d/collect", base, execution.ID)
	if w := request("POST", collect, ""); w.Code != 409 || calls.Load() != 0 {
		t.Fatalf("pending queried remote: %d %s calls=%d", w.Code, w.Body, calls.Load())
	}
	if _, err := s.m.pg.StartFindingRetest(t.Context(), retest.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.m.pg.RecordFindingRetestResult(t.Context(), conv.ID, "reproduced", "diagnostic result", "diagnostic evidence"); err != nil {
		t.Fatal(err)
	}
	// Test-only timestamps make the observation interval settled without sleeping.
	if _, err := s.m.pg.Exec(`UPDATE finding_retests SET status='completed',started_at=$2,finished_at=$3 WHERE id=$1`, retest.ID, eventTime.Add(-time.Second), eventTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	w := request("POST", collect, "")
	if w.Code != 200 {
		t.Fatalf("collect: %d %s", w.Code, w.Body)
	}
	var assessment db.DefenseAssessment
	if err := json.Unmarshal(w.Body.Bytes(), &assessment); err != nil {
		t.Fatal(err)
	}
	if assessment.Detection != "detected" || assessment.Prevention != "blocked" || assessment.Evidence == nil || len(assessment.Evidence.Events) != 2 || calls.Load() != 2 {
		t.Fatalf("assessment: %+v calls=%d", assessment, calls.Load())
	}
	if w = request("POST", collect, ""); w.Code != 200 {
		t.Fatalf("recollect: %d %s", w.Code, w.Body)
	}
	w = request("GET", fmt.Sprintf("%s/%d/export", base, execution.ID), "")
	var exported db.DefenseExecution
	if err := json.Unmarshal(w.Body.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") || w.Header().Get("Cache-Control") != "no-store" || len(exported.Assessments) != 2 || exported.CorrelationID != execution.CorrelationID {
		t.Fatalf("export: %d %+v %s", w.Code, w.Header(), w.Body)
	}
	if strings.Contains(w.Body.String(), "test-source-token") || strings.Contains(w.Body.String(), "secret_cipher") {
		t.Fatal("credentials exposed")
	}
	if w = request("GET", fmt.Sprintf("/api/exploration/findings/%d/defense/executions/%d/export", fid+1000000, execution.ID), ""); w.Code != 404 {
		t.Fatalf("cross-finding export: %d", w.Code)
	}
	fail.Store(true)
	w = request("POST", collect, "")
	if w.Code != 502 || strings.Contains(w.Body.String(), "private upstream") || strings.Contains(w.Body.String(), remote.URL) {
		t.Fatalf("remote failure: %d %s", w.Code, w.Body)
	}
	got, err := s.m.pg.GetDefenseExecution(t.Context(), fid, execution.ID)
	if err != nil || len(got.Assessments) != 2 {
		t.Fatalf("failure created proof: %+v %v", got, err)
	}
	// An archive may be restored into a database with a reused source ID and
	// revision. Different config must be rejected before making any request.
	changedConfig := source.Config
	changedConfig.Index = "unrelated_restored_index"
	changedRaw, err := json.Marshal(changedConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec(`UPDATE security_sources SET config=$2 WHERE id=$1`, source.ID, changedRaw); err != nil {
		t.Fatal(err)
	}
	beforeConfigConflict := calls.Load()
	if w = request("POST", collect, ""); w.Code != 409 || calls.Load() != beforeConfigConflict {
		t.Fatalf("same revision changed config queried remote: %d calls=%d", w.Code, calls.Load())
	}
	originalRaw, err := json.Marshal(source.Config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.Exec(`UPDATE security_sources SET config=$2 WHERE id=$1`, source.ID, originalRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := s.m.pg.SaveSecuritySource(t.Context(), source.ID, source.Revision, "changed source", source.Config, true, nil); err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	if w = request("POST", collect, ""); w.Code != 409 || calls.Load() != before {
		t.Fatalf("changed source queried: %d calls=%d", w.Code, calls.Load())
	}
	for _, body := range []string{`{"verdict":"detected"}`, `{"notes":"x","unknown":true}`, `[]`, `{`} {
		if w = request("POST", base, body); w.Code != 400 {
			t.Fatalf("unsupported body accepted: %d %s", w.Code, w.Body)
		}
	}
}

func TestPurpleExecutionPreflightAndContext(t *testing.T) {
	s, fid := newRetestServer(t)
	s.jwtKey = []byte("test-execution-context-key")
	if w := retestRequest(s.startDefenseExecution, "POST", fid, `{}`); w.Code != 503 {
		t.Fatalf("missing provider preflight: %d %s", w.Code, w.Body)
	}
	rows, err := s.m.pg.ListDefenseExecutions(t.Context(), fid)
	if err != nil || len(rows) != 0 {
		t.Fatalf("preflight created state: %+v %v", rows, err)
	}
	in, _ := executionAPISource(t, s, fid, securitysource.Config{BaseURL: "https://siem.invalid", Index: "main", AuditSourcetype: "audit", AlertSourcetype: "alert", CorrelationField: "verification_id", ActionField: "action"})
	r, c, e, _, err := s.m.pg.CreateFindingRetestWithDefense(t.Context(), fid, "context association", in)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.findingRetestTools()[0].Call(intercept.WithConvID(t.Context(), c.ID), json.RawMessage(`{}`), nil)
	raw, _ := json.Marshal(res)
	if err != nil || res.IsError || !strings.Contains(string(raw), e.CorrelationID) || !strings.Contains(string(raw), "X-ARTEX-Verification-ID") {
		t.Fatalf("tool context: %s %v", raw, err)
	}
	if r.ID != e.RetestID {
		t.Fatal("wrong retest association")
	}
	other, err := s.m.pg.CreateConversation("test", "ordinary conversation", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteConversation(other.ID) })
	res, err = s.findingRetestTools()[0].Call(intercept.WithConvID(t.Context(), other.ID), json.RawMessage(`{}`), nil)
	if err != nil || !res.IsError {
		t.Fatalf("unassociated context: %+v %v", res, err)
	}
}

func TestPurpleExecutionPOSTDispatchHasCommittedCorrelation(t *testing.T) {
	s, fid := newRetestServer(t)
	s.jwtKey = []byte("test-execution-dispatch-key")
	in, _ := executionAPISource(t, s, fid, securitysource.Config{BaseURL: "https://siem.invalid", Index: "main", AuditSourcetype: "audit", AlertSourcetype: "alert", CorrelationField: "verification_id", ActionField: "action"})
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	var calls atomic.Int32
	setRetestProvider(s, retestProvider{complete: func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		n := calls.Add(1)
		executions, err := s.m.pg.ListDefenseExecutions(ctx, fid)
		if err != nil || len(executions) != 1 {
			t.Errorf("dispatch preceded committed execution: %+v %v", executions, err)
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("missing committed execution")
		}
		messages, _ := json.Marshal(req.Messages)
		if !strings.Contains(string(messages), executions[0].CorrelationID) {
			t.Error("agent request lacks immutable execution UUID")
		}
		if n == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return llm.Message{}, "", llm.Usage{}, ctx.Err()
			}
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "context", Name: "get_finding_retest_context", Input: json.RawMessage(`{}`)}}}, "tool_use", llm.Usage{}, nil
		}
		if n == 2 {
			if !strings.Contains(string(messages), "defense_execution") || !strings.Contains(string(messages), "header_value") {
				t.Error("agent did not receive defense tool context")
			}
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "result", Name: "record_finding_retest_result", Input: json.RawMessage(`{"verdict":"inconclusive","summary":"Authorized retest needs valid credentials","evidence":"No security control outcome asserted"}`)}}}, "tool_use", llm.Usage{}, nil
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("Diagnostic result saved")}}, "end_turn", llm.Usage{}, nil
	}})
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	w := retestRequest(s.startDefenseExecution, "POST", fid, string(raw))
	if w.Code != 202 || !strings.Contains(w.Body.String(), `"created":true`) {
		t.Fatalf("start: %d %s", w.Code, w.Body)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("retet agent was not dispatched")
	}
	if duplicate := retestRequest(s.startDefenseExecution, "POST", fid, string(raw)); duplicate.Code != 409 {
		t.Fatalf("duplicate dispatched: %d %s", duplicate.Code, duplicate.Body)
	}
	unblock()
	waitRetestIdle(t, s)
	executions, err := s.m.pg.ListDefenseExecutions(t.Context(), fid)
	if err != nil || len(executions) != 1 || executions[0].Retest.Status != "completed" || calls.Load() != 3 {
		t.Fatalf("finished execution: %+v calls=%d err=%v", executions, calls.Load(), err)
	}
	if len(executions[0].Assessments) != 0 {
		t.Fatal("agent diagnostic result fabricated defense evidence")
	}
}
