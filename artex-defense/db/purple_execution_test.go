package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/securitysource"
	"github.com/google/uuid"
)

func defenseExecutionSource(t *testing.T, d *DB) *SecuritySource {
	t.Helper()
	s, err := d.SaveSecuritySource(t.Context(), 0, 0, "isolated source", securitysource.Config{BaseURL: "https://security.example.invalid:8089", Index: "test", AuditSourcetype: "test:audit", AlertSourcetype: "test:alert", CorrelationField: "verification_id", ActionField: "action"}, true, []byte("isolated-cipher-placeholder"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM security_sources WHERE id=$1`, s.ID) })
	return s
}

func defenseExecutionInput(t *testing.T, d *DB, findingID, sourceID int64) DefenseExecutionInput {
	t.Helper()
	state, err := d.GetFindingDefense(t.Context(), findingID)
	if err != nil {
		t.Fatal(err)
	}
	return DefenseExecutionInput{SourceID: sourceID, PlanRevision: state.Plan.Revision, ExpectedEvidenceVersion: &state.EvidenceVersion, ExpectedSourceFingerprint: state.SourceFingerprint}
}

func createDefenseExecutionFixture(t *testing.T, d *DB, findingID int64, input DefenseExecutionInput) *DefenseExecution {
	t.Helper()
	r, c, e, created, err := d.CreateFindingRetestWithDefense(t.Context(), findingID, "isolated fixture, no agent dispatch", input)
	if err != nil || !created {
		t.Fatalf("create execution: created=%v err=%v", created, err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM conversations WHERE id=$1`, c.ID) })
	if e.RetestID != r.ID || e.Retest == nil || len(e.Retest.Snapshot) != 0 {
		t.Fatalf("retst association or private snapshot: %+v", e)
	}
	return e
}

func completeDefenseExecutionFixture(t *testing.T, d *DB, e *DefenseExecution) *DefenseExecution {
	t.Helper()
	createdSeconds, startSeconds, finishSeconds := 240, 180, 120
	if e.BaselineID != nil {
		createdSeconds, startSeconds, finishSeconds = 100, 90, 70
	}
	_, err := d.Exec(`UPDATE finding_retests SET created_at=clock_timestamp()-($2::bigint*interval '1 second'),started_at=clock_timestamp()-($3::bigint*interval '1 second'),finished_at=clock_timestamp()-($4::bigint*interval '1 second'),status='completed',verdict='fixed',summary='fixture conclusion',evidence='fixture reproduction evidence' WHERE id=$1`, e.RetestID, createdSeconds, startSeconds, finishSeconds)
	if err != nil {
		t.Fatal(err)
	}
	e, err = d.GetDefenseExecution(t.Context(), e.FindingID, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func defenseExecutionEvidence(e *DefenseExecution, alert bool, action string) *securitysource.Evidence {
	start := *e.Retest.StartedAt
	evidence := &securitysource.Evidence{Complete: true, CollectedAt: time.Now().UTC(), WindowStart: start.Add(-30 * time.Second), WindowEnd: e.Retest.FinishedAt.Add(60 * time.Second), Warnings: []string{}, Events: []securitysource.Event{
		{ID: "audit-1", Kind: "audit", CorrelationID: e.CorrelationID, OccurredAt: start.Add(10 * time.Second), Action: action, Raw: json.RawMessage(`{"source":"audit"}`)},
	}}
	if alert {
		evidence.Events = append(evidence.Events, securitysource.Event{ID: "alert-1", Kind: "alert", CorrelationID: e.CorrelationID, OccurredAt: start.Add(15 * time.Second), Action: "unknown", Raw: json.RawMessage(`{"source":"alert"}`)})
	}
	return evidence
}

func TestPurpleExecutionEvidenceTruthTable(t *testing.T) {
	now := time.Now().UTC()
	start := now.Add(-3 * time.Minute)
	finish := now.Add(-2 * time.Minute)
	base := &DefenseExecution{ID: 1, CorrelationID: uuid.NewString(), Retest: &FindingRetest{Status: "completed", Verdict: "fixed", CreatedAt: start.Add(-time.Minute), StartedAt: &start, FinishedAt: &finish}}
	for _, tc := range []struct {
		name                  string
		mutate                func(*DefenseExecution, *securitysource.Evidence)
		detection, prevention string
	}{
		{"positive", func(_ *DefenseExecution, _ *securitysource.Evidence) {}, "detected", "blocked"},
		{"missed", func(_ *DefenseExecution, e *securitysource.Evidence) { e.Events = e.Events[:1] }, "missed", "blocked"},
		{"allowed despite fixed LLM verdict", func(_ *DefenseExecution, e *securitysource.Evidence) { e.Events[0].Action = "allowed" }, "detected", "not_blocked"},
		{"mixed actions", func(_ *DefenseExecution, e *securitysource.Evidence) {
			v := e.Events[0]
			v.ID = "audit-2"
			v.Action = "allowed"
			e.Events = append(e.Events, v)
		}, "detected", "inconclusive"},
		{"unknown action", func(_ *DefenseExecution, e *securitysource.Evidence) { e.Events[0].Action = "unknown" }, "detected", "inconclusive"},
		{"no audit", func(_ *DefenseExecution, e *securitysource.Evidence) { e.Events = e.Events[1:] }, "inconclusive", "inconclusive"},
		{"partial", func(_ *DefenseExecution, e *securitysource.Evidence) { e.Complete = false }, "inconclusive", "inconclusive"},
		{"warning", func(_ *DefenseExecution, e *securitysource.Evidence) {
			e.Warnings = []string{"source search truncated"}
		}, "inconclusive", "inconclusive"},
		{"pending", func(e *DefenseExecution, _ *securitysource.Evidence) {
			e.Retest.Status = "pending"
			e.Retest.FinishedAt = nil
		}, "inconclusive", "inconclusive"},
		{"failed", func(e *DefenseExecution, _ *securitysource.Evidence) { e.Retest.Status = "failed" }, "inconclusive", "inconclusive"},
		{"wrong correlation", func(_ *DefenseExecution, e *securitysource.Evidence) { e.Events[1].CorrelationID = uuid.NewString() }, "inconclusive", "inconclusive"},
		{"outside window", func(_ *DefenseExecution, e *securitysource.Evidence) {
			e.Events[1].OccurredAt = e.WindowEnd.Add(time.Second)
		}, "inconclusive", "inconclusive"},
		{"duplicate event", func(_ *DefenseExecution, e *securitysource.Evidence) { e.Events = append(e.Events, e.Events[0]) }, "inconclusive", "inconclusive"},
		{"settling", func(_ *DefenseExecution, e *securitysource.Evidence) {
			e.Events = e.Events[:1]
			e.WindowEnd = finish.Add(30 * time.Second)
			e.CollectedAt = e.WindowEnd
		}, "inconclusive", "blocked"},
		{"short coverage", func(_ *DefenseExecution, e *securitysource.Evidence) { e.WindowStart = start }, "inconclusive", "inconclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := *base
			r := *base.Retest
			e.Retest = &r
			proof := defenseExecutionEvidence(&e, true, "blocked")
			tc.mutate(&e, proof)
			got, err := assessDefenseEvidence(&e, proof)
			if err != nil {
				t.Fatal(err)
			}
			if got.Detection != tc.detection || got.Prevention != tc.prevention {
				t.Fatalf("got %s/%s want %s/%s", got.Detection, got.Prevention, tc.detection, tc.prevention)
			}
			if (got.Detection == "inconclusive" || got.Prevention == "inconclusive" || got.Detection == "missed" || got.Prevention == "not_blocked") && len(got.Recommendations) == 0 {
				t.Fatal("evidence gap has no actionable recommendation")
			}
		})
	}
}

func TestPurpleExecutionPersistenceVersionsAndSnapshots(t *testing.T) {
	d, fid := purpleDB(t)
	ctx := t.Context()
	s := defenseExecutionSource(t, d)
	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type,url,method,auth) VALUES('endpoint',$1,'GET',ARRAY[$2::jsonb]) RETURNING id`, "https://target.example.invalid/"+uuid.NewString(), `{"password":"MUST_NOT_ENTER_DIAGNOSIS"}`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM assets WHERE id=$1`, assetID) })
	if _, err := d.Exec(`UPDATE findings SET asset_ids=jsonb_build_array($2::bigint) WHERE id=$1`, fid, assetID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveDefensePlan(ctx, fid, purplePlan()); err != nil {
		t.Fatal(err)
	}
	in := defenseExecutionInput(t, d, fid, s.ID)
	e := createDefenseExecutionFixture(t, d, fid, in)
	if e.State != "current" || strings.Contains(string(e.SourceSnapshot), "isolated-cipher") || strings.Contains(string(e.SourceSnapshot), "secret_cipher") {
		t.Fatalf("snapshot leaked credentials or stale: %s", e.SourceSnapshot)
	}
	if !strings.Contains(string(e.DiagnosisSnapshot), "source evidence") || !strings.Contains(string(e.DiagnosisSnapshot), "target.example.invalid") || strings.Contains(string(e.DiagnosisSnapshot), "MUST_NOT_ENTER_DIAGNOSIS") || strings.Contains(string(e.DiagnosisSnapshot), `"auth"`) {
		t.Fatal("diagnosis lost original proof or copied asset authentication")
	}
	if _, err := uuid.Parse(e.CorrelationID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := d.CreateFindingRetestWithDefense(ctx, fid, "", in); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("active retest acquired extra execution: %v", err)
	}
	e = completeDefenseExecutionFixture(t, d, e)
	a, err := d.SaveDefenseAssessment(ctx, fid, e.ID, defenseExecutionEvidence(e, false, "allowed"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Detection != "missed" || a.Prevention != "not_blocked" || a.EventCount != 1 {
		t.Fatalf("assessment: %+v", a)
	}
	before, _ := json.Marshal(e.Retest)
	if _, err = d.Exec(`DELETE FROM finding_retests WHERE id=$1`, e.RetestID); err != nil {
		t.Fatal(err)
	}
	read, err := d.GetDefenseExecution(ctx, fid, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(read.Retest)
	if string(before) != string(after) || len(read.Assessments) != 1 {
		t.Fatal("terminal result or assessment lost after retest deletion")
	}
	if string(read.DiagnosisSnapshot) != string(e.DiagnosisSnapshot) {
		t.Fatal("original diagnosis changed after retest deletion")
	}
	if _, err = d.Exec(`UPDATE security_sources SET revision=revision+1 WHERE id=$1`, s.ID); err != nil {
		t.Fatal(err)
	}
	read, err = d.GetDefenseExecution(ctx, fid, e.ID)
	if err != nil || read.State != "stale" {
		t.Fatalf("source edit state: %+v %v", read, err)
	}
	if _, err = d.SaveDefenseAssessment(ctx, fid, e.ID, defenseExecutionEvidence(e, true, "blocked")); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("changed source accepted evidence: %v", err)
	}
	if _, err = d.GetDefenseExecution(ctx, fid+1000000, e.ID); !errors.Is(err, ErrDefenseExecutionNotFound) {
		t.Fatalf("cross-finding read: %v", err)
	}
}

func TestPurpleExecutionBeforeAfterComparison(t *testing.T) {
	d, fid := purpleDB(t)
	ctx := t.Context()
	s := defenseExecutionSource(t, d)
	if _, err := d.SaveDefensePlan(ctx, fid, purplePlan()); err != nil {
		t.Fatal(err)
	}
	baseline := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, defenseExecutionInput(t, d, fid, s.ID)))
	if _, err := d.SaveDefenseAssessment(ctx, fid, baseline.ID, defenseExecutionEvidence(baseline, false, "allowed")); err != nil {
		t.Fatal(err)
	}
	plan := purplePlan()
	plan.ExpectedRevision = 1
	plan.RuleText = "corrected rule"
	if _, err := d.SaveDefensePlan(ctx, fid, plan); err != nil {
		t.Fatal(err)
	}
	in := defenseExecutionInput(t, d, fid, s.ID)
	in.BaselineID = &baseline.ID
	if _, _, _, _, err := d.CreateFindingRetestWithDefense(ctx, fid, "", in); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatalf("missing remediation accepted: %v", err)
	}
	in.RemediationNote = "Corrected detection field and applied authorization policy"
	current := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, in))
	if _, err := d.SaveDefenseAssessment(ctx, fid, current.ID, defenseExecutionEvidence(current, true, "blocked")); err != nil {
		t.Fatal(err)
	}
	comparison, err := d.CompareDefenseExecutions(ctx, fid, baseline.ID, current.ID)
	if err != nil || !comparison.Comparable || comparison.Baseline.Assessments[0].Detection != "missed" || comparison.Current.Assessments[0].Detection != "detected" {
		t.Fatalf("before/after: %+v %v", comparison, err)
	}
	if comparison.Baseline.CorrelationID == comparison.Current.CorrelationID {
		t.Fatal("two executions reused UUID")
	}
	if _, err := d.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, fid); err != nil {
		t.Fatal(err)
	}
	comparison, err = d.CompareDefenseExecutions(ctx, fid, baseline.ID, current.ID)
	if err != nil || comparison.Comparable {
		t.Fatalf("stale current comparable: %+v %v", comparison, err)
	}
	if _, err = d.CompareDefenseExecutions(ctx, fid+1000000, baseline.ID, current.ID); !errors.Is(err, ErrDefenseExecutionNotFound) {
		t.Fatalf("cross-finding comparison: %v", err)
	}
}

func TestPurpleExecutionPreviewPreservesFullEvidence(t *testing.T) {
	d, fid := purpleDB(t)
	ctx := t.Context()
	s := defenseExecutionSource(t, d)
	if _, err := d.SaveDefensePlan(ctx, fid, purplePlan()); err != nil {
		t.Fatal(err)
	}
	e := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, defenseExecutionInput(t, d, fid, s.ID)))
	proof := defenseExecutionEvidence(e, true, "blocked")
	for i := 0; i < 30; i++ {
		v := proof.Events[0]
		v.ID = fmt.Sprintf("audit-extra-%d", i)
		proof.Events = append(proof.Events, v)
	}
	for range 7 {
		if _, err := d.SaveDefenseAssessment(ctx, fid, e.ID, proof); err != nil {
			t.Fatal(err)
		}
	}
	list, err := d.ListDefenseExecutions(ctx, fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || len(list[0].Assessments) != 5 || !list[0].AssessmentsTruncated {
		t.Fatalf("assessment history preview: %+v", list)
	}
	if len(list[0].DiagnosisSnapshot) != 0 {
		t.Fatal("list included original diagnostic payload")
	}
	a := list[0].Assessments[0]
	if !a.EvidenceTruncated || a.EventCount != 32 || a.AuditCount != 31 || a.AlertCount != 1 || len(a.Evidence.Events) != 20 {
		t.Fatalf("event preview counts: %+v", a)
	}
	for _, event := range a.Evidence.Events {
		if len(event.Raw) != 0 {
			t.Fatal("list leaked raw event")
		}
	}
	full, err := d.GetDefenseExecution(ctx, fid, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Assessments) != 7 || full.AssessmentsTruncated || len(full.Assessments[0].Evidence.Events) != 32 || len(full.Assessments[0].Evidence.Events[0].Raw) == 0 {
		t.Fatal("preview modified stored evidence")
	}
}

func TestPurpleExecutionOverviewLatestAndStale(t *testing.T) {
	d, fid := purpleDB(t)
	ctx := t.Context()
	s := defenseExecutionSource(t, d)
	if _, err := d.SaveDefensePlan(ctx, fid, purplePlan()); err != nil {
		t.Fatal(err)
	}
	base, err := d.GetPurpleOverview(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	e := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, defenseExecutionInput(t, d, fid, s.ID)))
	if _, err := d.SaveDefenseAssessment(ctx, fid, e.ID, defenseExecutionEvidence(e, true, "blocked")); err != nil {
		t.Fatal(err)
	}
	got, err := d.GetPurpleOverview(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stats.ExecutionTotal != base.Stats.ExecutionTotal+1 || got.Stats.ExecutionDetected != base.Stats.ExecutionDetected+1 || got.Stats.ExecutionBlocked != base.Stats.ExecutionBlocked+1 || got.Stats.Detected != base.Stats.Detected || got.Stats.Replayed != base.Stats.Replayed {
		t.Fatalf("actual execution counts: %+v", got.Stats)
	}
	if _, err := d.SaveDefenseAssessment(ctx, fid, e.ID, defenseExecutionEvidence(e, false, "allowed")); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetPurpleOverview(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stats.ExecutionDetected != base.Stats.ExecutionDetected || got.Stats.ExecutionMissed != base.Stats.ExecutionMissed+1 || got.Stats.ExecutionBlocked != base.Stats.ExecutionBlocked {
		t.Fatalf("latest assessment did not supersede: %+v", got.Stats)
	}
	current := createDefenseExecutionFixture(t, d, fid, defenseExecutionInput(t, d, fid, s.ID))
	got, err = d.GetPurpleOverview(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stats.ExecutionMissed != base.Stats.ExecutionMissed || got.Stats.ExecutionInconclusive != base.Stats.ExecutionInconclusive+1 {
		t.Fatalf("pending execution inherited previous success: %+v", got.Stats)
	}
	for _, item := range got.Items {
		if item.FindingID == fid && (item.ExecutionID != fmt.Sprint(current.ID) || item.ExecutionStatus != "pending" || item.ExecutionState != "current") {
			t.Fatalf("latest execution item: %+v", item)
		}
	}
	if _, err := d.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, fid); err != nil {
		t.Fatal(err)
	}
	got, err = d.GetPurpleOverview(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stats.ExecutionTotal != base.Stats.ExecutionTotal+1 || got.Stats.ExecutionInconclusive != base.Stats.ExecutionInconclusive {
		t.Fatalf("stale execution counted current: %+v", got.Stats)
	}
}

func TestPurpleExecutionRejectsStaleAndForeignBaseline(t *testing.T) {
	d, fid := purpleDB(t)
	ctx := t.Context()
	s := defenseExecutionSource(t, d)
	if _, err := d.SaveDefensePlan(ctx, fid, purplePlan()); err != nil {
		t.Fatal(err)
	}
	in := defenseExecutionInput(t, d, fid, s.ID)
	if _, err := d.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, fid); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := d.CreateFindingRetestWithDefense(ctx, fid, "", in); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("stale create: %v", err)
	}
	in = defenseExecutionInput(t, d, fid, s.ID)
	if _, err := d.Exec(`UPDATE security_sources SET enabled=false WHERE id=$1`, s.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := d.CreateFindingRetestWithDefense(ctx, fid, "", in); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatalf("disabled create: %v", err)
	}
	if _, err := d.Exec(`UPDATE security_sources SET enabled=true WHERE id=$1`, s.ID); err != nil {
		t.Fatal(err)
	}
	baseline := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, in))
	if _, err := d.SaveDefenseAssessment(ctx, fid, baseline.ID, defenseExecutionEvidence(baseline, true, "blocked")); err != nil {
		t.Fatal(err)
	}
	other, err := d.AddFinding(0, 0, "OTHER", "other", "low", "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteFinding(other) })
	if _, err := d.SaveDefensePlan(ctx, other, purplePlan()); err != nil {
		t.Fatal(err)
	}
	foreign := defenseExecutionInput(t, d, other, s.ID)
	foreign.BaselineID = &baseline.ID
	foreign.RemediationNote = "changed"
	if _, _, _, _, err := d.CreateFindingRetestWithDefense(ctx, other, "", foreign); !errors.Is(err, ErrDefenseExecutionNotFound) {
		t.Fatalf("foreign baseline accepted: %v", err)
	}
	if _, err := d.SaveDefenseAssessment(ctx, other, baseline.ID, defenseExecutionEvidence(baseline, true, "blocked")); !errors.Is(err, ErrDefenseExecutionNotFound) {
		t.Fatalf("foreign assessment accepted: %v", err)
	}
}

func TestPurpleExecutionTargetAndConstraintFreshness(t *testing.T) {
	d, fid := purpleDB(t)
	ctx := t.Context()
	source := defenseExecutionSource(t, d)
	task, err := d.CreateTask("execution scope fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteTask(task.ID) })
	var assetID int64
	if err := d.QueryRow(`INSERT INTO assets(type,url,method,ip) VALUES('endpoint',$1,'GET','192.0.2.10') RETURNING id`, "https://scope.example.invalid/"+uuid.NewString()).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Assets().DeleteByIDs([]int64{assetID}) })
	if _, err := d.Exec(`UPDATE findings SET task_id=$2,asset_ids=jsonb_build_array($3::bigint) WHERE id=$1`, fid, task.ID, assetID); err != nil {
		t.Fatal(err)
	}
	constraints := d.Exploration(task.ExplorationID)
	for _, c := range []struct{ kind, text string }{{"deny", "No destructive operations"}, {"allow", "Only the authorized original target"}} {
		if _, err := constraints.AddConstraint(c.kind, c.text, "human"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.SaveDefensePlan(ctx, fid, purplePlan()); err != nil {
		t.Fatal(err)
	}
	baseCounts, err := d.GetPurpleOverview(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	baseline := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, defenseExecutionInput(t, d, fid, source.ID)))
	if _, err := d.SaveDefenseAssessment(ctx, fid, baseline.ID, defenseExecutionEvidence(baseline, false, "allowed")); err != nil {
		t.Fatal(err)
	}
	// Recreate semantically identical constraints in a different order and with
	// different IDs/provenance. Neither discovery metadata nor row order is scope.
	if _, err := d.Exec(`DELETE FROM task_constraints WHERE exploration_id=$1`, task.ExplorationID); err != nil {
		t.Fatal(err)
	}
	var denyID int64
	for _, c := range []struct{ kind, text string }{{"allow", "Only the authorized original target"}, {"deny", "No destructive operations"}} {
		id, err := constraints.AddConstraint(c.kind, c.text, "system")
		if err != nil {
			t.Fatal(err)
		}
		if c.kind == "deny" {
			denyID = id
		}
	}
	if _, err := d.Exec(`UPDATE assets SET last_seen=clock_timestamp(),page_title='New discovery metadata' WHERE id=$1`, assetID); err != nil {
		t.Fatal(err)
	}
	in := defenseExecutionInput(t, d, fid, source.ID)
	in.BaselineID, in.RemediationNote = &baseline.ID, "Applied the reviewed policy"
	current := completeDefenseExecutionFixture(t, d, createDefenseExecutionFixture(t, d, fid, in))
	if _, err := d.SaveDefenseAssessment(ctx, fid, current.ID, defenseExecutionEvidence(current, true, "blocked")); err != nil {
		t.Fatal(err)
	}
	assertState := func(want string) {
		t.Helper()
		full, err := d.GetDefenseExecution(ctx, fid, current.ID)
		if err != nil || full.State != want {
			t.Fatalf("full execution state=%v want %s err=%v", full, want, err)
		}
		if string(full.DiagnosisSnapshot) != string(current.DiagnosisSnapshot) {
			t.Fatal("scope freshness rewrote historical diagnostic proof")
		}
		list, err := d.ListDefenseExecutions(ctx, fid)
		if err != nil || len(list) != 2 || list[0].State != want {
			t.Fatalf("list scope state=%v want %s err=%v", list, want, err)
		}
		comparison, err := d.CompareDefenseExecutions(ctx, fid, baseline.ID, current.ID)
		if err != nil || comparison.Comparable != (want == "current") {
			t.Fatalf("scope comparison=%+v want state %s err=%v", comparison, want, err)
		}
		overview, err := d.GetPurpleOverview(ctx, 1, 100)
		if err != nil {
			t.Fatal(err)
		}
		increment := int64(0)
		if want == "current" {
			increment = 1
		}
		if overview.Stats.ExecutionDetected != baseCounts.Stats.ExecutionDetected+increment || overview.Stats.ExecutionBlocked != baseCounts.Stats.ExecutionBlocked+increment {
			t.Fatalf("scope freshness disagrees with overview: %+v", overview.Stats)
		}
		found := false
		for _, item := range overview.Items {
			if item.FindingID == fid {
				found = true
				if item.ExecutionState != want {
					t.Fatalf("overview item state=%s want %s", item.ExecutionState, want)
				}
			}
		}
		if !found {
			t.Fatal("scope fixture missing from overview")
		}
	}
	assertState("current")
	// UpsertEndpoint updates the IP on this same asset ID. The finding's own
	// evidence version and asset ID list remain unchanged by that supported edit.
	if _, err := d.Exec(`UPDATE assets SET ip='192.0.2.11' WHERE id=$1`, assetID); err != nil {
		t.Fatal(err)
	}
	assertState("stale")
	if _, err := d.Exec(`UPDATE assets SET ip='192.0.2.10' WHERE id=$1`, assetID); err != nil {
		t.Fatal(err)
	}
	assertState("current")
	if err := constraints.UpdateConstraint(denyID, "deny", "No requests to the previous target"); err != nil {
		t.Fatal(err)
	}
	assertState("stale")
	if err := constraints.UpdateConstraint(denyID, "deny", "No destructive operations"); err != nil {
		t.Fatal(err)
	}
	assertState("current")
	if _, err := d.Assets().DeleteByIDs([]int64{assetID}); err != nil {
		t.Fatal(err)
	}
	assertState("stale")
}

func TestPurpleExecutionScopeNormalization(t *testing.T) {
	a := json.RawMessage(`{"finding":{"vulnclass":"IDOR"},"assets":[{"id":2,"type":"endpoint","url":"https://b.invalid","method":"GET","last_seen":"old"},{"id":1,"type":"endpoint","url":"https://a.invalid","method":"GET","ip":null}],"constraints":[{"id":1,"kind":"deny","text":"No delete","created_at":"old"},{"id":2,"kind":"allow","text":"Read only"}]}`)
	b := json.RawMessage(`{"finding":{"vulnclass":"IDOR","summary":"changed evidence"},"assets":[{"id":1,"type":"endpoint","url":"https://a.invalid","method":"GET"},{"id":2,"type":"endpoint","url":"https://b.invalid","method":"GET","last_seen":"new"}],"constraints":[{"id":8,"kind":"allow","text":"Read only","origin":"human"},{"id":9,"kind":"deny","text":"No delete","created_at":"new"}]}`)
	left, ok := defenseDiagnosisScope(a)
	right, otherOK := defenseDiagnosisScope(b)
	if !ok || !otherOK || left != right {
		t.Fatalf("equivalent scope differs: %s / %s", left, right)
	}
	changed := json.RawMessage(strings.Replace(string(b), "https://a.invalid", "https://other.invalid", 1))
	if scope, valid := defenseDiagnosisScope(changed); !valid || scope == left {
		t.Fatal("changed target normalized to the original scope")
	}
	if _, valid := defenseDiagnosisScope(json.RawMessage(`{}`)); valid {
		t.Fatal("legacy missing scope accepted as comparable")
	}
}
