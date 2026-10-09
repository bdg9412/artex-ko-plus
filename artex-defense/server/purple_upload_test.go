package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/securitysource"
	"github.com/Autumn-27/norma/llm"
)

func fileExecutionAPIInput(t *testing.T, s *Server, fid int64) db.DefenseExecutionInput {
	t.Helper()
	state, err := s.m.pg.SaveDefensePlan(t.Context(), fid, db.DefensePlanInput{Hypothesis: "Correlate uploaded actual audit and alert exports", RuleFormat: "query", RuleText: "Existing detector configuration"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := securitysource.ValidateFileConfig(securitysource.FileConfig{Label: "API test uploaded logs"})
	if err != nil {
		t.Fatal(err)
	}
	return db.DefenseExecutionInput{SourceKind: "file", FileConfig: &cfg, PlanRevision: state.Plan.Revision, ExpectedEvidenceVersion: &state.EvidenceVersion, ExpectedSourceFingerprint: state.SourceFingerprint}
}

func TestPurpleFileExecutionPOSTWithoutSIEM(t *testing.T) {
	s, fid := newRetestServer(t)
	s.jwtKey = []byte("file-execution-dispatch-test-key")
	in := fileExecutionAPIInput(t, s, fid)
	var sourceCount int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM security_sources`).Scan(&sourceCount); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	setRetestProvider(s, retestProvider{complete: func(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
		rows, err := s.m.pg.ListDefenseExecutions(ctx, fid)
		if err != nil || len(rows) != 1 || rows[0].SourceKind != "file" || rows[0].SourceID != 0 {
			t.Errorf("file run was not committed before dispatch: %+v %v", rows, err)
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("missing file execution")
		}
		messages, _ := json.Marshal(req.Messages)
		if !strings.Contains(string(messages), rows[0].CorrelationID) {
			t.Error("agent lacks immutable file execution UUID")
		}
		if calls.Add(1) == 1 {
			return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "result", Name: "record_finding_retest_result", Input: json.RawMessage(`{"verdict":"inconclusive","summary":"Test-only diagnostic result","evidence":"No live target was contacted"}`)}}}, "tool_use", llm.Usage{}, nil
		}
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("Finished")}}, "end_turn", llm.Usage{}, nil
	}})
	raw, _ := json.Marshal(in)
	w := retestRequest(s.startDefenseExecution, "POST", fid, string(raw))
	if w.Code != http.StatusAccepted {
		t.Fatalf("file start without SIEM: %d %s", w.Code, w.Body)
	}
	waitRetestIdle(t, s)
	rows, err := s.m.pg.ListDefenseExecutions(t.Context(), fid)
	if err != nil || len(rows) != 1 || rows[0].Retest.Status != "completed" || len(rows[0].Assessments) != 0 {
		t.Fatalf("diagnostic completion fabricated file proof: %+v %v", rows, err)
	}
	var after int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM security_sources`).Scan(&after); err != nil || after != sourceCount {
		t.Fatal("file execution created a SIEM credential/source", err)
	}
}

func TestPurpleUploadAPIEvidenceDiagnosisHistoryAndExport(t *testing.T) {
	s, fid, request := purpleAPIFixture(t)
	in := fileExecutionAPIInput(t, s, fid)
	r, c, e, _, err := s.m.pg.CreateFindingRetestWithDefense(t.Context(), fid, "test only, no dispatch", in)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.m.pg.DeleteConversation(c.ID) })
	base := fmt.Sprintf("/api/exploration/findings/%d/defense/executions", fid)
	path := fmt.Sprintf("%s/%d/upload", base, e.ID)
	if w := request("POST", path, `{}`); w.Code != http.StatusConflict {
		t.Fatalf("pending upload accepted: %d %s", w.Code, w.Body)
	}
	start, finish := time.Now().UTC().Add(-3*time.Minute), time.Now().UTC().Add(-2*time.Minute)
	if _, err := s.m.pg.Exec(`UPDATE finding_retests SET status='completed',started_at=$2,finished_at=$3 WHERE id=$1`, r.ID, start, finish); err != nil {
		t.Fatal(err)
	}
	e, err = s.m.pg.GetDefenseExecution(t.Context(), fid, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	// PostgreSQL stores microseconds; use the persisted execution boundaries.
	start, finish = *e.Retest.StartedAt, *e.Retest.FinishedAt
	eventTime := start.Add(5 * time.Second).Format(time.RFC3339Nano)
	auditRaw := fmt.Sprintf(`{"id":"audit-1","timestamp":%q,"artex_verification_id":%q,"action":"allowed","large_number":9007199254740993}`, eventTime, e.CorrelationID)
	alertRaw := fmt.Sprintf(`[{"id":"alert-1","timestamp":%q,"artex_verification_id":%q,"rule_id":"test-detector"}]`, eventTime, e.CorrelationID)
	input := securitysource.FileUpload{AuditFile: securitysource.UploadFile{Name: "audit.jsonl", Content: auditRaw}, AlertFile: &securitysource.UploadFile{Name: "alerts.json", Content: alertRaw}, CoverageStart: start.Add(-30 * time.Second), CoverageEnd: finish.Add(time.Minute), CoverageComplete: true}
	post := func(input securitysource.FileUpload) db.DefenseAssessment {
		t.Helper()
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		w := request("POST", path, string(raw))
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("upload: %d %s", w.Code, w.Body)
		}
		var a db.DefenseAssessment
		if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		return a
	}
	a := post(input)
	if a.Detection != "detected" || a.Prevention != "not_blocked" || a.EventCount != 2 || a.Evidence.Upload == nil {
		t.Fatalf("actual correlated file evidence: %+v", a)
	}
	sum := sha256.Sum256([]byte(auditRaw))
	if a.Evidence.Upload.Files[0].SHA256 != hex.EncodeToString(sum[:]) || a.Evidence.Upload.Files[0].Content != auditRaw {
		t.Fatal("file evidence hash/bytes changed")
	}
	input.AlertFile, input.NoAlerts = nil, true
	a = post(input)
	if a.Detection != "missed" || len(a.Diagnostics) == 0 {
		t.Fatalf("complete no-alert export lacks missed diagnosis: %+v", a)
	}
	input.CoverageComplete = false
	a = post(input)
	if a.Detection != "inconclusive" {
		t.Fatal("unconfirmed coverage became a missed detection")
	}
	input.CoverageComplete, input.NoAlerts = true, false
	a = post(input)
	if a.Detection != "inconclusive" {
		t.Fatal("missing alert export became a missed detection")
	}
	input.NoAlerts = true
	input.AuditFile.Content = strings.ReplaceAll(auditRaw, e.CorrelationID, "00000000-0000-0000-0000-000000000000")
	a = post(input)
	if a.Detection != "inconclusive" || a.AuditCount != 0 {
		t.Fatal("foreign run data supported a conclusion")
	}
	// Invalid uploads must not add a new assessment or trigger any SIEM lookup.
	for _, body := range []string{`{"verdict":"detected"}`, `{"audit_file":{"name":"a.json","content":"not json"},"coverage_start":"x"}`, `{}`, `[]`} {
		if w := request("POST", path, body); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid upload: %d %s", w.Code, w.Body)
		}
	}
	if w := request("POST", fmt.Sprintf("%s/%d/collect", base, e.ID), ""); w.Code != http.StatusConflict {
		t.Fatal("file execution tried the Splunk collection path")
	}
	foreign := fmt.Sprintf("/api/exploration/findings/%d/defense/executions/%d/upload", fid+100000, e.ID)
	if w := request("POST", foreign, `{}`); w.Code != http.StatusNotFound {
		t.Fatal("cross-finding upload accepted")
	}
	w := request("GET", base, "")
	var history struct {
		Executions []*db.DefenseExecution `json:"executions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &history); err != nil || len(history.Executions) != 1 || len(history.Executions[0].Assessments) != 5 {
		t.Fatalf("history: %d %s %v", w.Code, w.Body, err)
	}
	for _, a := range history.Executions[0].Assessments {
		for _, f := range a.Evidence.Upload.Files {
			if f.Content != "" {
				t.Fatal("list includes full uploaded files")
			}
		}
	}
	w = request("GET", fmt.Sprintf("%s/%d/export", base, e.ID), "")
	var exported db.DefenseExecution
	if err := json.Unmarshal(w.Body.Bytes(), &exported); err != nil || w.Code != http.StatusOK || len(exported.Assessments) != 5 {
		t.Fatalf("export: %d %s %v", w.Code, w.Body, err)
	}
	if exported.Assessments[4].Evidence.Upload.Files[0].Content != auditRaw || !strings.Contains(w.Body.String(), "9007199254740993") {
		t.Fatal("full export lost original evidence or number precision")
	}
}

func TestPurpleUploadRejectsSIEMExecution(t *testing.T) {
	s, fid, request := purpleAPIFixture(t)
	in, _ := executionAPISource(t, s, fid, securitysource.Config{BaseURL: "https://siem.invalid", Index: "main", AuditSourcetype: "audit", AlertSourcetype: "alert", CorrelationField: "id", ActionField: "action"})
	_, _, e, _, err := s.m.pg.CreateFindingRetestWithDefense(t.Context(), fid, "test only", in)
	if err != nil {
		t.Fatal(err)
	}
	w := request("POST", fmt.Sprintf("/api/exploration/findings/%d/defense/executions/%d/upload", fid, e.ID), `{}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("SIEM provenance replaced: %d %s", w.Code, w.Body)
	}
}
