package db

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/defenseeval"
)

func purpleReplayPlan() DefensePlanInput {
	return DefensePlanInput{Hypothesis: "Uploaded target events should match while controls do not", RuleFormat: "event_filter", RuleText: `{"version":1,"all":[{"field":"event.action","op":"eq","value":"denied"}]}`}
}

func purpleReplayInput(state *FindingDefense) DefenseReplayInput {
	version := state.EvidenceVersion
	return DefenseReplayInput{PlanRevision: state.Plan.Revision, ExpectedEvidenceVersion: &version, ExpectedSourceFingerprint: state.SourceFingerprint,
		TargetLogs: "{\"event\":{\"action\":\"denied\"}}\n", ControlLogs: `[{"event.action":"allowed"}]`, Notes: "fixture logs only"}
}

func TestPurpleReplayResultsSnapshotsAndManualSeparation(t *testing.T) {
	d, id := purpleDB(t)
	ctx := t.Context()
	state, err := d.SaveDefensePlan(ctx, id, purpleReplayPlan())
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := d.GetPurpleOverview(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	in := purpleReplayInput(state)
	first, err := d.RunDefenseReplay(ctx, id, in)
	if err != nil || first.Result.Verdict != "pass" || first.State != "current" {
		t.Fatalf("first replay: %+v %v", first, err)
	}
	if first.EvaluatorVersion != defenseeval.EngineVersion || first.RuleSHA256 != replayHash(state.Plan.RuleText) || first.TargetSHA256 != replayHash(in.TargetLogs) || first.ControlSHA256 != replayHash(in.ControlLogs) {
		t.Fatalf("reproducibility metadata missing: %+v", first)
	}
	exported, err := d.ExportDefenseReplay(ctx, id, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if exported.TargetLogs != in.TargetLogs || exported.ControlLogs != in.ControlLogs {
		t.Fatal("export modified original uploaded bytes")
	}
	replayed, err := defenseeval.Evaluate(exported.PlanSnapshot.RuleText, exported.TargetLogs, exported.ControlLogs)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(first.Result)
	got, _ := json.Marshal(replayed)
	if string(want) != string(got) {
		t.Fatalf("export did not reproduce result: %s / %s", want, got)
	}
	list, err := d.ListDefenseReplays(ctx, id)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}
	raw, _ := json.Marshal(list)
	if strings.Contains(string(raw), "target_logs") || strings.Contains(string(raw), "control_logs") {
		t.Fatal("history list exposed raw logs")
	}
	overview, err := d.GetPurpleOverview(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if overview.Stats.Replayed != baseline.Stats.Replayed+1 || overview.Stats.ReplayPassed != baseline.Stats.ReplayPassed+1 || overview.Stats.Detected != baseline.Stats.Detected || overview.Stats.Blocked != baseline.Stats.Blocked || overview.Stats.Validated != baseline.Stats.Validated {
		t.Fatalf("replay affected manual counts: %+v", overview.Stats)
	}
	manual, err := d.GetFindingDefense(ctx, id)
	if err != nil || manual.State != "untested" || len(manual.Validations) != 0 {
		t.Fatalf("replay became live observation: %+v %v", manual, err)
	}
	// A newer failed replay supersedes the earlier pass in replay-only stats.
	in.TargetLogs = `{"event.action":"allowed"}`
	second, err := d.RunDefenseReplay(ctx, id, in)
	if err != nil || second.Result.Verdict != "fail" {
		t.Fatalf("failed replay: %+v %v", second, err)
	}
	overview, err = d.GetPurpleOverview(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if overview.Stats.Replayed != baseline.Stats.Replayed+1 || overview.Stats.ReplayPassed != baseline.Stats.ReplayPassed {
		t.Fatalf("historical pass still counted: %+v", overview.Stats)
	}
	list, err = d.ListDefenseReplays(ctx, id)
	if err != nil || list[0].ID != second.ID {
		t.Fatalf("latest replay order: %+v %v", list, err)
	}
	plan := purpleReplayPlan()
	plan.ExpectedRevision = 1
	plan.RuleText = `{"version":1,"all":[{"field":"event.action","op":"eq","value":"allowed"}]}`
	state, err = d.SaveDefensePlan(ctx, id, plan)
	if err != nil {
		t.Fatal(err)
	}
	list, err = d.ListDefenseReplays(ctx, id)
	if err != nil || list[0].State != "stale" || list[1].PlanSnapshot.RuleText != first.PlanSnapshot.RuleText {
		t.Fatalf("old replay snapshot changed: %+v %v", list, err)
	}
	if _, err = d.RunDefenseReplay(ctx, id, in); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("old revision accepted: %v", err)
	}
	overview, err = d.GetPurpleOverview(ctx, 1, 100)
	if err != nil || overview.Stats.ReplayNeedsRevalidation != baseline.Stats.ReplayNeedsRevalidation+1 {
		t.Fatalf("stale replay stats: %+v %v", overview, err)
	}
	in = purpleReplayInput(state)
	in.ControlLogs = ""
	third, err := d.RunDefenseReplay(ctx, id, in)
	if err != nil || third.Result.Verdict != "inconclusive" {
		t.Fatalf("empty controls: %+v %v", third, err)
	}
	if _, err = d.Exec(`UPDATE findings SET vulnclass='REPLAY_SOURCE_CHANGED' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RunDefenseReplay(ctx, id, in); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("changed source accepted: %v", err)
	}
	list, err = d.ListDefenseReplays(ctx, id)
	if err != nil || list[0].State != "stale" {
		t.Fatalf("source edit should stale replay: %+v %v", list, err)
	}
	if _, err = d.DeleteFinding(id); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ExportDefenseReplay(ctx, id, first.ID); !errors.Is(err, ErrDefenseReplayNotFound) {
		t.Fatalf("deleted replay accessible: %v", err)
	}
	var count int
	if err = d.QueryRow(`SELECT count(*) FROM finding_defense_replays WHERE finding_id=$1`, id).Scan(&count); err != nil || count != 0 {
		t.Fatalf("replay cascade: %d %v", count, err)
	}
}

func TestPurpleReplayRechecksAfterEvaluation(t *testing.T) {
	d, id := purpleDB(t)
	ctx := t.Context()
	state, err := d.SaveDefensePlan(ctx, id, purpleReplayPlan())
	if err != nil {
		t.Fatal(err)
	}
	in := purpleReplayInput(state)
	result, err := defenseeval.Evaluate(state.Plan.RuleText, in.TargetLogs, in.ControlLogs)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the boundary between pure evaluation and the locked commit.
	plan := purpleReplayPlan()
	plan.ExpectedRevision = 1
	plan.Hypothesis = "Edited while replay evaluated"
	if _, err = d.SaveDefensePlan(ctx, id, plan); err != nil {
		t.Fatal(err)
	}
	if _, err = d.saveDefenseReplay(ctx, id, in, state.Plan, result); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("plan changed during evaluation: %v", err)
	}
	state, err = d.GetFindingDefense(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	in = purpleReplayInput(state)
	if _, err = d.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if _, err = d.saveDefenseReplay(ctx, id, in, state.Plan, result); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("evidence changed during evaluation: %v", err)
	}
	list, err := d.ListDefenseReplays(ctx, id)
	if err != nil || len(list) != 0 {
		t.Fatalf("rejected replay persisted: %+v %v", list, err)
	}
}

func TestPurpleReplayPreviewPreservesCompleteExport(t *testing.T) {
	d, id := purpleDB(t)
	ctx := t.Context()
	state, err := d.SaveDefensePlan(ctx, id, purpleReplayPlan())
	if err != nil {
		t.Fatal(err)
	}
	in := purpleReplayInput(state)
	in.TargetLogs = strings.Repeat("{\"event.action\":\"denied\"}\n", 75)
	run, err := d.RunDefenseReplay(ctx, id, in)
	if err != nil {
		t.Fatal(err)
	}
	if !run.EvaluationsTruncated || len(run.Result.Evaluations) != 50 || run.Result.Target.Total != 75 || run.Result.Control.Total != 1 {
		t.Fatalf("POST preview/counts: %+v", run)
	}
	list, err := d.ListDefenseReplays(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if !list[0].EvaluationsTruncated || len(list[0].Result.Evaluations) != 50 || list[0].TargetSHA256 != run.TargetSHA256 {
		t.Fatal("list preview changed counts or hash")
	}
	exported, err := d.ExportDefenseReplay(ctx, id, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if exported.EvaluationsTruncated || len(exported.Result.Evaluations) != 76 || exported.Result.Target.Total != 75 || exported.TargetSHA256 != run.TargetSHA256 || exported.TargetLogs != in.TargetLogs {
		t.Fatal("stored export lost full evaluation history")
	}
}

func TestPurpleReplayRejectsDraftsMalformedAndOversizedInputs(t *testing.T) {
	d, id := purpleDB(t)
	ctx := t.Context()
	state, err := d.SaveDefensePlan(ctx, id, purplePlan())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RunDefenseReplay(ctx, id, purpleReplayInput(state)); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatalf("query draft executed: %v", err)
	}
	plan := purpleReplayPlan()
	plan.ExpectedRevision = 1
	state, err = d.SaveDefensePlan(ctx, id, plan)
	if err != nil {
		t.Fatal(err)
	}
	valid := purpleReplayInput(state)
	for _, tc := range []struct {
		name   string
		mutate func(*DefenseReplayInput)
	}{
		{"no evidence version", func(in *DefenseReplayInput) { in.ExpectedEvidenceVersion = nil }},
		{"no fingerprint", func(in *DefenseReplayInput) { in.ExpectedSourceFingerprint = "" }},
		{"malformed logs", func(in *DefenseReplayInput) { in.TargetLogs = `{"broken"` }},
		{"file path", func(in *DefenseReplayInput) { in.TargetLogs = "/etc/passwd" }},
		{"external URL", func(in *DefenseReplayInput) { in.TargetLogs = "https://example.invalid/logs" }},
		{"decoded byte limit", func(in *DefenseReplayInput) { in.TargetLogs = strings.Repeat("x", defenseeval.MaxCombinedLogBytes+1) }},
		{"event limit", func(in *DefenseReplayInput) { in.TargetLogs = strings.Repeat("{}\n", defenseeval.MaxEvents+1) }},
		{"notes limit", func(in *DefenseReplayInput) { in.Notes = strings.Repeat("x", 4001) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mutate(&in)
			if _, err := d.RunDefenseReplay(ctx, id, in); !errors.Is(err, ErrDefenseInvalid) {
				t.Fatalf("invalid input: %v", err)
			}
		})
	}
	plan.ExpectedRevision = 2
	plan.RuleText = `{"version":1,"all":[{"field":"event.action","op":"shell","value":"test"}]}`
	state, err = d.SaveDefensePlan(ctx, id, plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.RunDefenseReplay(ctx, id, purpleReplayInput(state)); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatalf("unsupported rule executed: %v", err)
	}
	list, err := d.ListDefenseReplays(ctx, id)
	if err != nil || len(list) != 0 {
		t.Fatalf("invalid attempts persisted: %+v %v", list, err)
	}
}

func TestPurpleReplayHistoryBoundAndForeignOwnership(t *testing.T) {
	d, id := purpleDB(t)
	ctx := t.Context()
	state, err := d.SaveDefensePlan(ctx, id, purpleReplayPlan())
	if err != nil {
		t.Fatal(err)
	}
	in := purpleReplayInput(state)
	first, err := d.RunDefenseReplay(ctx, id, in)
	if err != nil {
		t.Fatal(err)
	}
	// Duplicate stored fixtures to exercise the history bound without 50 evaluations.
	if _, err = d.Exec(`INSERT INTO finding_defense_replays(finding_id,plan_revision,evidence_version,source_fingerprint,plan_snapshot,target_logs,control_logs,rule_sha256,target_sha256,control_sha256,evaluator_version,result,notes)
	SELECT r.finding_id,r.plan_revision,r.evidence_version,r.source_fingerprint,r.plan_snapshot,r.target_logs,r.control_logs,r.rule_sha256,r.target_sha256,r.control_sha256,r.evaluator_version,r.result,r.notes FROM finding_defense_replays r CROSS JOIN generate_series(1,54) WHERE r.id=$1`, first.ID); err != nil {
		t.Fatal(err)
	}
	list, err := d.ListDefenseReplays(ctx, id)
	if err != nil || len(list) != 50 || list[49].ID <= first.ID {
		t.Fatalf("bounded newest history: %d %v", len(list), err)
	}
	if _, err = d.ExportDefenseReplay(ctx, id+1000000, first.ID); !errors.Is(err, ErrDefenseReplayNotFound) {
		t.Fatalf("foreign finding read replay: %v", err)
	}
	if _, err = d.ListDefenseReplays(ctx, id+1000000); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("unknown finding list: %v", err)
	}
	if _, err = d.ExportDefenseReplay(ctx, id, first.ID+1000000); !errors.Is(err, ErrDefenseReplayNotFound) {
		t.Fatalf("unknown replay export: %v", err)
	}
}

func TestPurpleReplayFormatUpgradePreservesPlans(t *testing.T) {
	d, id := purpleDB(t)
	ctx := t.Context()
	state, err := d.SaveDefensePlan(ctx, id, purplePlan())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// Reconstruct only the original restrictive CHECK, then apply the real
	// idempotent startup schema. Roll back all test DDL after the assertions.
	if _, err = tx.Exec(`ALTER TABLE finding_defense_plans DROP CONSTRAINT finding_defense_plans_rule_format_v2_check;
	ALTER TABLE finding_defense_plans ADD CONSTRAINT finding_defense_plans_rule_format_check CHECK(rule_format IN ('query','sigma','other'))`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(schemaSQL); err != nil {
		t.Fatal(err)
	}
	var hypothesis, format string
	var revision int64
	if err = tx.QueryRow(`SELECT hypothesis,rule_format,revision FROM finding_defense_plans WHERE finding_id=$1`, id).Scan(&hypothesis, &format, &revision); err != nil {
		t.Fatal(err)
	}
	if hypothesis != state.Plan.Hypothesis || format != "query" || revision != state.Plan.Revision {
		t.Fatal("format migration changed existing plan")
	}
	if _, err = tx.Exec(`UPDATE finding_defense_plans SET rule_format='event_filter' WHERE finding_id=$1`, id); err != nil {
		t.Fatal("upgraded constraint rejected event filter", err)
	}
}
