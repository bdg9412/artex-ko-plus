package db

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/securitysource"
	"github.com/google/uuid"
)

func fileExecutionInput(t *testing.T, d *DB, fid int64) DefenseExecutionInput {
	t.Helper()
	in := defenseExecutionInput(t, d, fid, 0)
	in.SourceKind = "file"
	in.FileConfig = &securitysource.FileConfig{Label: "authorized gateway export"}
	return in
}

func fileExecutionEvidence(t *testing.T, e *DefenseExecution, alert bool, action string) *securitysource.Evidence {
	t.Helper()
	config, err := defenseExecutionFileConfig(e)
	if err != nil {
		t.Fatal(err)
	}
	query := securitysource.Query{CorrelationID: e.CorrelationID, Start: e.Retest.StartedAt.Add(-30 * time.Second), End: e.Retest.FinishedAt.Add(time.Minute)}
	content := func(id string) string {
		b, err := json.Marshal(map[string]any{config.EventIDField: id, config.TimestampField: e.Retest.StartedAt.Add(10 * time.Second).Format(time.RFC3339Nano), config.CorrelationField: e.CorrelationID, config.ActionField: action, "literal_text": `literal \u0000 remains text`})
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	in := securitysource.FileUpload{AuditFile: securitysource.UploadFile{Name: "audit.jsonl", Content: content("audit-1")}, NoAlerts: !alert, CoverageStart: query.Start, CoverageEnd: query.End, CoverageComplete: true}
	if alert {
		in.AlertFile = &securitysource.UploadFile{Name: "alert.jsonl", Content: content("alert-1")}
	}
	proof, err := securitysource.ParseUpload(config, in, query)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func hasDefenseDiagnostic(a *DefenseAssessment, code, certainty string) bool {
	for _, d := range a.Diagnostics {
		if d.Code == code && d.Certainty == certainty {
			return true
		}
	}
	return false
}

func TestPurpleFileExecutionPersistenceAndSourceSeparation(t *testing.T) {
	d, fid := purpleDB(t)
	ctx := t.Context()
	if _, err := d.SaveDefensePlan(ctx, fid, purplePlan()); err != nil {
		t.Fatal(err)
	}
	var sourcesBefore, sourcesAfter int
	if err := d.QueryRow(`SELECT count(*) FROM security_sources`).Scan(&sourcesBefore); err != nil {
		t.Fatal(err)
	}
	in := fileExecutionInput(t, d, fid)
	for _, invalid := range []DefenseExecutionInput{
		{SourceKind: "file", SourceID: 1, FileConfig: in.FileConfig, PlanRevision: in.PlanRevision, ExpectedEvidenceVersion: in.ExpectedEvidenceVersion, ExpectedSourceFingerprint: in.ExpectedSourceFingerprint},
		{SourceKind: "file", PlanRevision: in.PlanRevision, ExpectedEvidenceVersion: in.ExpectedEvidenceVersion, ExpectedSourceFingerprint: in.ExpectedSourceFingerprint},
		{SourceKind: "unknown", PlanRevision: in.PlanRevision, ExpectedEvidenceVersion: in.ExpectedEvidenceVersion, ExpectedSourceFingerprint: in.ExpectedSourceFingerprint},
	} {
		if _, _, _, _, err := d.CreateFindingRetestWithDefense(ctx, fid, "", invalid); !errors.Is(err, ErrDefenseInvalid) {
			t.Fatalf("invalid file source accepted: %v", err)
		}
	}
	e := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, in))
	if e.SourceKind != "file" || e.SourceID != 0 || e.SourceRevision != 1 || e.State != "current" {
		t.Fatalf("file execution needs a connector: %+v", e)
	}
	if err := d.QueryRow(`SELECT count(*) FROM security_sources`).Scan(&sourcesAfter); err != nil || sourcesAfter != sourcesBefore {
		t.Fatalf("file execution created a SIEM source: %d -> %d, %v", sourcesBefore, sourcesAfter, err)
	}
	proof := fileExecutionEvidence(t, e, false, "allowed")
	a, err := d.SaveDefenseAssessment(ctx, fid, e.ID, proof)
	if err != nil {
		t.Fatal(err)
	}
	if a.Detection != "missed" || a.Prevention != "not_blocked" || !hasDefenseDiagnostic(a, "file_coverage_attested", "observed") || !hasDefenseDiagnostic(a, "alert_absent", "observed") || !hasDefenseDiagnostic(a, "rule_gap", "hypothesis") {
		t.Fatalf("unsupported file conclusion or missing diagnostic: %+v", a)
	}
	countDefenseEvidence(a)
	countDefenseEvidence(a)
	if a.EventCount != 1 || a.AuditCount != 1 || a.AlertCount != 0 {
		t.Fatalf("recount accumulated events: %+v", a)
	}
	list, err := d.ListDefenseExecutions(ctx, fid)
	if err != nil {
		t.Fatal(err)
	}
	preview := list[0].Assessments[0]
	if !preview.EvidenceTruncated || preview.Evidence.Upload.Files[0].Content != "" || preview.Evidence.Upload.Files[0].SHA256 != proof.Upload.Files[0].SHA256 {
		t.Fatal("preview leaked content or lost provenance")
	}
	full, err := d.GetDefenseExecution(ctx, fid, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if full.Assessments[0].Evidence.Upload.Files[0].Content != proof.Upload.Files[0].Content || len(full.Assessments[0].Diagnostics) == 0 {
		t.Fatal("export lost raw upload or diagnostics")
	}
	metadata, err := d.GetDefenseExecutionForCollection(ctx, fid, e.ID)
	if err != nil || len(metadata.Assessments) != 0 || metadata.CorrelationID != e.CorrelationID {
		t.Fatalf("collection loaded prior raw files: %+v %v", metadata, err)
	}
	if _, err := d.SaveDefenseAssessment(ctx, fid, e.ID, defenseExecutionEvidence(e, true, "blocked")); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatalf("file accepted SIEM evidence without provenance: %v", err)
	}
	tampered := fileExecutionEvidence(t, e, true, "blocked")
	tampered.Upload.Config.Label = "different source"
	if _, err := d.SaveDefenseAssessment(ctx, fid, e.ID, tampered); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatalf("changed upload source accepted: %v", err)
	}
	tampered = fileExecutionEvidence(t, e, true, "blocked")
	tampered.Upload.Files[0].Content += "modified"
	if _, err := d.SaveDefenseAssessment(ctx, fid, e.ID, tampered); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatalf("wrong original hash accepted: %v", err)
	}
	s := defenseExecutionSource(t, d)
	splunk := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, defenseExecutionInput(t, d, fid, s.ID)))
	if splunk.SourceKind != "splunk" {
		t.Fatal("legacy empty source kind did not default to Splunk")
	}
	if _, err := d.SaveDefenseAssessment(ctx, fid, splunk.ID, proof); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatalf("Splunk execution accepted an uploaded file: %v", err)
	}
}

func TestPurpleFileEvidenceCoverageAndConcreteDiagnostics(t *testing.T) {
	now := time.Now().UTC()
	start, finish := now.Add(-3*time.Minute), now.Add(-2*time.Minute)
	config, err := securitysource.ValidateFileConfig(securitysource.FileConfig{Label: "gateway export"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := json.Marshal(map[string]any{"kind": "file", "name": config.Label, "config": config, "revision": 1})
	e := &DefenseExecution{ID: 1, SourceKind: "file", SourceRevision: 1, SourceSnapshot: snapshot, CorrelationID: uuid.NewString(), Retest: &FindingRetest{Status: "completed", CreatedAt: start, StartedAt: &start, FinishedAt: &finish}}
	for _, tc := range []struct {
		name   string
		mutate func(*securitysource.Evidence)
		code   string
	}{
		{"coverage not confirmed", func(p *securitysource.Evidence) { p.Upload.CoverageComplete = false }, "file_coverage_unconfirmed"},
		{"alert query absent", func(p *securitysource.Evidence) { p.Upload.NoAlerts = false }, "alert_export_unconfirmed"},
		{"no correlated audit", func(p *securitysource.Evidence) { p.Events = nil }, "audit_missing"},
		{"partial export", func(p *securitysource.Evidence) { p.Complete = false }, "evidence_incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := fileExecutionEvidence(t, e, false, "allowed")
			tc.mutate(proof)
			a, err := assessDefenseEvidence(e, proof)
			if err != nil || a.Detection != "inconclusive" || a.Prevention != "inconclusive" || !hasDefenseDiagnostic(a, tc.code, "observed") || hasDefenseDiagnostic(a, "alert_absent", "observed") {
				t.Fatalf("partial evidence claimed missed/blocked: %+v %v", a, err)
			}
		})
	}
	proof := fileExecutionEvidence(t, e, true, "blocked")
	a, err := assessDefenseEvidence(e, proof)
	if err != nil || a.Detection != "detected" || a.Prevention != "blocked" || !hasDefenseDiagnostic(a, "file_coverage_attested", "observed") {
		t.Fatalf("file provenance notice incorrectly invalidated proof: %+v %v", a, err)
	}
	proof.Upload.NoAlerts = true
	if _, err := assessDefenseEvidence(e, proof); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatalf("contradictory no-alert assertion accepted: %v", err)
	}
	if defenseJSONContainsNUL(json.RawMessage(`{"value":"literal \\u0000"}`)) || !defenseJSONContainsNUL(json.RawMessage(`{"value":"actual \u0000"}`)) {
		t.Fatal("literal escape and decoded NUL were confused")
	}
}

func TestPurpleFileExecutionBeforeAfterSourceComparability(t *testing.T) {
	d, fid := purpleDB(t)
	ctx := t.Context()
	if _, err := d.SaveDefensePlan(ctx, fid, purplePlan()); err != nil {
		t.Fatal(err)
	}
	baseline := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, fileExecutionInput(t, d, fid)))
	if _, err := d.SaveDefenseAssessment(ctx, fid, baseline.ID, fileExecutionEvidence(t, baseline, false, "allowed")); err != nil {
		t.Fatal(err)
	}
	in := fileExecutionInput(t, d, fid)
	in.BaselineID, in.RemediationNote = &baseline.ID, "Applied authorization control"
	current := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, in))
	if _, err := d.SaveDefenseAssessment(ctx, fid, current.ID, fileExecutionEvidence(t, current, true, "blocked")); err != nil {
		t.Fatal(err)
	}
	comparison, err := d.CompareDefenseExecutions(ctx, fid, baseline.ID, current.ID)
	if err != nil || !comparison.Comparable || comparison.Current.Assessments[0].Evidence.Upload.Files[0].Content != "" {
		t.Fatalf("matching file before/after comparison or preview failed: %+v %v", comparison, err)
	}
	in.FileConfig.Label = "a different gateway export"
	other := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, in))
	if _, err := d.SaveDefenseAssessment(ctx, fid, other.ID, fileExecutionEvidence(t, other, true, "blocked")); err != nil {
		t.Fatal(err)
	}
	comparison, err = d.CompareDefenseExecutions(ctx, fid, baseline.ID, other.ID)
	if err != nil || comparison.Comparable || !strings.Contains(strings.Join(comparison.Reasons, " "), "파일 로그 출처") {
		t.Fatalf("different file source comparable: %+v %v", comparison, err)
	}
	source := defenseExecutionSource(t, d)
	splunkInput := defenseExecutionInput(t, d, fid, source.ID)
	splunkInput.BaselineID, splunkInput.RemediationNote = &baseline.ID, "Applied same control"
	splunk := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, splunkInput))
	if _, err := d.SaveDefenseAssessment(ctx, fid, splunk.ID, defenseExecutionEvidence(splunk, true, "blocked")); err != nil {
		t.Fatal(err)
	}
	comparison, err = d.CompareDefenseExecutions(ctx, fid, baseline.ID, splunk.ID)
	if err != nil || comparison.Comparable {
		t.Fatalf("file and Splunk evidence comparable: %+v %v", comparison, err)
	}
}
