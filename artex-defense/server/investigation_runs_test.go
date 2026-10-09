package server

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
)

type investigationHTTPProvider struct {
	calls   atomic.Int32
	block   bool
	started chan struct{}
}

func (p *investigationHTTPProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	n := p.calls.Add(1)
	if p.block {
		if n == 1 {
			close(p.started)
		}
		<-ctx.Done()
		return llm.Message{}, "", llm.Usage{}, ctx.Err()
	}
	if n == 1 {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "plan-stop", Name: "plan_investigation", Input: json.RawMessage(`{"action":"insufficient_data","reason":"인증 로그가 필요합니다.","needed_logs":["해당 계정의 인증 감사 로그"],"next_steps":["승인된 계정 활동과 대조"]}`)}}}, "tool_use", llm.Usage{InputTokens: 20, OutputTokens: 30}, nil
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("필요 자료를 기록했습니다.")}}, "end_turn", llm.Usage{InputTokens: 30, OutputTokens: 10}, nil
}
func (p *investigationHTTPProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		_, _, _, err := p.Complete(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}

func investigationRunFixture(t *testing.T) (*Server, *db.FindingInvestigation, func(string, string, string) *httptest.ResponseRecorder, string) {
	t.Helper()
	s, id, request := purpleAPIFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	s.ctx = ctx
	t.Cleanup(func() {
		cancel()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			s.investigationMu.Lock()
			n := len(s.investigationCancel)
			s.investigationMu.Unlock()
			if n == 0 {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Error("investigator did not stop")
	})
	in := investigationAPIInput(t, s, id)
	raw, _ := json.Marshal(in)
	w := request("POST", fmt.Sprintf("/api/exploration/findings/%d/investigations", id), string(raw))
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var base db.FindingInvestigation
	if err := json.Unmarshal(w.Body.Bytes(), &base); err != nil {
		t.Fatal(err)
	}
	return s, &base, request, fmt.Sprintf("/api/exploration/findings/%d/investigations/%d/agent-runs", id, base.ID)
}

func waitInvestigationRun(t *testing.T, s *Server, run *db.InvestigationRun) *db.InvestigationRun {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		current, err := s.m.pg.GetInvestigationRun(t.Context(), run.FindingID, run.ID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status != "queued" && current.Status != "running" {
			return current
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("agent run did not settle")
	return nil
}

func TestInvestigationRunAPINoLLMNoExecution(t *testing.T) {
	s, base, request, path := investigationRunFixture(t)
	w := request("POST", path, `{"question":"과거 사용 여부"}`)
	if w.Code != 503 {
		t.Fatal(w.Code, w.Body.String())
	}
	runs, err := s.m.pg.ListInvestigationRuns(t.Context(), base.FindingID, base.ID)
	if err != nil || len(runs) != 0 {
		t.Fatal("unready model created run", err)
	}
	for _, route := range []string{path, path + "/1", path + "/1/export", path + "/1/cancel"} {
		unauth := httptest.NewRecorder()
		s.Handler().ServeHTTP(unauth, httptest.NewRequest("GET", route, nil))
		if unauth.Code != 401 {
			t.Fatal("unprotected agent route", route, unauth.Code)
		}
	}
}

func TestInvestigationRunAPIAsyncHistoryExportAndNoRetest(t *testing.T) {
	s, base, request, path := investigationRunFixture(t)
	p := &investigationHTTPProvider{}
	s.llmProv = p
	s.llmOn = true
	s.llmCfg = agent.Config{Model: "local-mock", Stream: false}
	s.llmProf = "test"
	w := request("POST", path, `{"question":"인증 자료가 충분한가?"}`)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var run db.InvestigationRun
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	done := waitInvestigationRun(t, s, &run)
	if done.Status != "insufficient_data" || done.Usage.ModelCalls != 2 || len(done.Events) < 2 || !strings.Contains(string(done.Result), "인증 로그") {
		t.Fatalf("unexpected finished run: %+v", done)
	}
	w = request("GET", fmt.Sprintf("%s/%d/export", path, done.ID), "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "historical-no-uuid") || w.Header().Get("Content-Disposition") == "" {
		t.Fatal("incomplete export", w.Code)
	}
	w = request("GET", path, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "historical-no-uuid") {
		t.Fatal("run history leaked raw", w.Code)
	}
	var count int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM finding_retests WHERE finding_id=$1`, base.FindingID).Scan(&count); err != nil || count != 0 {
		t.Fatal("agent started retest", err)
	}
	if w = request("GET", fmt.Sprintf("/api/exploration/findings/%d/investigations/%d/agent-runs/%d", base.FindingID, base.ID+999, done.ID), ""); w.Code != 404 {
		t.Fatal("cross evidence accepted", w.Code)
	}
}

func TestInvestigationRunAPICancelAndDuplicateStart(t *testing.T) {
	s, _, request, path := investigationRunFixture(t)
	p := &investigationHTTPProvider{block: true, started: make(chan struct{})}
	s.llmProv = p
	s.llmOn = true
	s.llmCfg = agent.Config{Model: "local-mock"}
	w := request("POST", path, `{}`)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var run, duplicate db.InvestigationRun
	_ = json.Unmarshal(w.Body.Bytes(), &run)
	select {
	case <-p.started:
	case <-time.After(3 * time.Second):
		t.Fatal("provider did not start")
	}
	w = request("POST", path, `{}`)
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	_ = json.Unmarshal(w.Body.Bytes(), &duplicate)
	if duplicate.ID != run.ID || p.calls.Load() != 1 {
		t.Fatal("duplicate run started")
	}
	// Deterministically check the ordering at the exact point the running
	// worker is released; polling the terminal state alone can miss the race.
	var cancellationSealed atomic.Bool
	s.investigationMu.Lock()
	originalCancel := s.investigationCancel[run.ID]
	if originalCancel == nil {
		s.investigationMu.Unlock()
		t.Fatal("running investigation has no cancellation callback")
	}
	s.investigationCancel[run.ID] = func() {
		current, err := s.m.pg.GetInvestigationRun(t.Context(), run.FindingID, run.ID)
		if err != nil {
			t.Errorf("read durable state before cancellation: %v", err)
		} else if current.Status != "cancelled" {
			t.Errorf("worker cancelled before durable state was sealed: %s", current.Status)
		} else {
			cancellationSealed.Store(true)
		}
		originalCancel()
	}
	s.investigationMu.Unlock()
	w = request("POST", fmt.Sprintf("%s/%d/cancel", path, run.ID), `{}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if !cancellationSealed.Load() {
		t.Fatal("cancellation did not observe a previously sealed cancelled state")
	}
	done := waitInvestigationRun(t, s, &run)
	if done.Status != "cancelled" || len(done.Events) == 0 {
		t.Fatal("cancellation lost partial trace", done)
	}
}

func TestInvestigationRunPivotScopeBoundaries(t *testing.T) {
	s, base, _, _ := investigationRunFixture(t)
	_ = s
	query := agent.InvestigationSearch{Scope: base.Scope, Remote: true}
	if err := validateInvestigationPivot(base.Scope, query); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*agent.InvestigationSearch){func(q *agent.InvestigationSearch) { q.Scope.Target = "other.example" }, func(q *agent.InvestigationSearch) { q.Scope.PathPrefix = "/" }, func(q *agent.InvestigationSearch) { q.Scope.Start = q.Scope.Start.Add(-time.Second) }, func(q *agent.InvestigationSearch) { q.Offset = 20 }} {
		bad := query
		change(&bad)
		if err := validateInvestigationPivot(base.Scope, bad); err == nil {
			t.Fatal("scope escape accepted", bad)
		}
	}
}
