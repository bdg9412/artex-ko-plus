package db

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func purpleDB(t *testing.T) (*DB, int64) {
	t.Helper()
	dsn := os.Getenv("ARTEX_PG_DSN")
	if dsn == "" {
		t.Skip("ARTEX_PG_DSN is required for isolated PostgreSQL integration tests")
	}
	d, err := Open(dsn)
	if err != nil {
		t.Fatalf("initialize configured purple test database: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	id, err := d.AddFinding(0, 0, "PURPLE_TEST", "Local finding", "high", "source summary", "source evidence", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := d.DeleteFinding(id); err != nil {
			t.Error(err)
		}
	})
	return d, id
}

func purplePlan() DefensePlanInput {
	return DefensePlanInput{Hypothesis: "Check that the local test event creates an alert", LogSource: "test events", RuleFormat: "query", RuleText: "event.type = test", Remediation: "Review local control"}
}

func purpleObservation(state *FindingDefense) DefenseValidationInput {
	version := state.EvidenceVersion
	return DefenseValidationInput{PlanRevision: state.Plan.Revision, ExpectedEvidenceVersion: &version, ExpectedSourceFingerprint: state.SourceFingerprint,
		Detection: "detected", Prevention: "not_tested", Evidence: "Manual test event #42 produced alert #7", ObservedAt: time.Now().UTC().Add(-time.Minute)}
}

func TestPurpleLifecycleSnapshotsAndCounts(t *testing.T) {
	d, id := purpleDB(t)
	ctx := t.Context()
	initial, err := d.GetFindingDefense(ctx, id)
	if err != nil || initial.State != "unplanned" || initial.Plan != nil || len(initial.Validations) != 0 {
		t.Fatalf("initial: %+v %v", initial, err)
	}
	baseline, err := d.GetPurpleOverview(ctx, 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	plan := purplePlan()
	state, err := d.SaveDefensePlan(ctx, id, plan)
	if err != nil || state.State != "untested" || state.Plan.Revision != 1 {
		t.Fatalf("save: %+v %v", state, err)
	}
	observation := purpleObservation(state)
	state, err = d.AddDefenseValidation(ctx, id, observation)
	if err != nil || state.State != "current" || len(state.Validations) != 1 {
		t.Fatalf("validate: %+v %v", state, err)
	}
	first := *state.Validations[0]
	plan.ExpectedRevision = 1
	unchanged, err := d.SaveDefensePlan(ctx, id, plan)
	if err != nil || unchanged.Plan.Revision != 1 || !unchanged.Plan.UpdatedAt.Equal(state.Plan.UpdatedAt) || unchanged.State != "current" {
		t.Fatalf("no-op edit invalidated: %+v %v", unchanged, err)
	}
	plan.RuleText = "event.type = updated_test"
	state, err = d.SaveDefensePlan(ctx, id, plan)
	if err != nil || state.State != "stale" || state.Plan.Revision != 2 {
		t.Fatalf("plan edit: %+v %v", state, err)
	}
	if state.Validations[0].PlanSnapshot.RuleText != first.PlanSnapshot.RuleText || state.Validations[0].Evidence != first.Evidence {
		t.Fatal("historical snapshot mutated")
	}
	if _, err = d.AddDefenseValidation(ctx, id, observation); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("obsolete revision accepted: %v", err)
	}
	if _, err = d.SaveDefensePlan(ctx, id, plan); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("lost update accepted: %v", err)
	}
	state, err = d.AddDefenseValidation(ctx, id, purpleObservation(state))
	if err != nil {
		t.Fatal(err)
	}
	oldSource := purpleObservation(state)
	if _, err = d.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	state, err = d.GetFindingDefense(ctx, id)
	if err != nil || state.State != "stale" {
		t.Fatalf("traffic edit not stale: %+v %v", state, err)
	}
	if _, err = d.AddDefenseValidation(ctx, id, oldSource); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("old traffic version accepted: %v", err)
	}
	state, err = d.AddDefenseValidation(ctx, id, purpleObservation(state))
	if err != nil {
		t.Fatal(err)
	}
	oldSource = purpleObservation(state)
	if _, err = d.Exec(`UPDATE findings SET vulnclass='CHANGED_CLASS' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	state, err = d.GetFindingDefense(ctx, id)
	if err != nil || state.State != "stale" {
		t.Fatalf("source edit not stale: %+v %v", state, err)
	}
	if _, err = d.AddDefenseValidation(ctx, id, oldSource); !errors.Is(err, ErrDefenseConflict) {
		t.Fatalf("old source fingerprint accepted: %v", err)
	}
	staleStats, err := d.GetPurpleOverview(ctx, 1, 20)
	if err != nil || staleStats.Stats.Detected != baseline.Stats.Detected || staleStats.Stats.Validated != baseline.Stats.Validated || staleStats.Stats.NeedsRevalidation != baseline.Stats.NeedsRevalidation+1 {
		t.Fatalf("stale outcomes counted: %+v %v", staleStats, err)
	}
	latest := purpleObservation(state)
	latest.Detection, latest.Prevention = "missed", "blocked"
	latest.ObservedAt = first.ObservedAt.Add(-time.Hour) // insertion order, not observed_at
	state, err = d.AddDefenseValidation(ctx, id, latest)
	if err != nil || state.State != "current" || state.Validations[0].Detection != "missed" {
		t.Fatalf("latest observation: %+v %v", state, err)
	}
	overview, err := d.GetPurpleOverview(ctx, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if overview.Stats.Detected != baseline.Stats.Detected || overview.Stats.Missed != baseline.Stats.Missed+1 || overview.Stats.Blocked != baseline.Stats.Blocked+1 || overview.Stats.Validated != baseline.Stats.Validated+1 || overview.Stats.Planned != baseline.Stats.Planned+1 || overview.Total != baseline.Total || len(overview.Items) != 1 {
		t.Fatalf("global counts or pagination: %+v", overview)
	}
	f, err := d.GetFinding(id)
	if err != nil || f.Status != FindingPending {
		t.Fatalf("defense observation changed finding status: %+v %v", f, err)
	}
	if _, err := d.DeleteFinding(id); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"finding_defense_plans", "finding_defense_validations"} {
		var count int
		if err := d.QueryRow(`SELECT count(*) FROM `+table+` WHERE finding_id=$1`, id).Scan(&count); err != nil || count != 0 {
			t.Fatalf("cascade %s: %d %v", table, count, err)
		}
	}
	if _, err := d.GetFindingDefense(ctx, id); !errors.Is(err, ErrFindingNotFound) {
		t.Fatalf("deleted finding: %v", err)
	}
}

func TestPurpleConcurrentCreatesAndEvidenceEdits(t *testing.T) {
	d, id := purpleDB(t)
	ctx := t.Context()
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, err := d.SaveDefensePlan(ctx, id, purplePlan()); results <- err })
	}
	wg.Wait()
	close(results)
	created, conflicts := 0, 0
	for err := range results {
		if err == nil {
			created++
		} else if errors.Is(err, ErrDefenseConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if created != 1 || conflicts != 7 {
		t.Fatalf("creates=%d conflicts=%d", created, conflicts)
	}
	state, err := d.GetFindingDefense(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	observation := purpleObservation(state)
	start := make(chan struct{})
	writeResult := make(chan error, 1)
	editResult := make(chan error, 1)
	go func() { <-start; _, err := d.AddDefenseValidation(ctx, id, observation); writeResult <- err }()
	go func() {
		<-start
		_, err := d.Exec(`UPDATE findings SET evidence_version=evidence_version+1 WHERE id=$1`, id)
		editResult <- err
	}()
	close(start)
	if err = <-editResult; err != nil {
		t.Fatal(err)
	}
	validationErr := <-writeResult
	if validationErr != nil && !errors.Is(validationErr, ErrDefenseConflict) {
		t.Fatal(validationErr)
	}
	state, err = d.GetFindingDefense(ctx, id)
	if err != nil || state.State == "current" {
		t.Fatalf("concurrent edit yielded falsely current validation: %+v %v", state, err)
	}
	if validationErr == nil && state.State != "stale" {
		t.Fatalf("committed pre-edit observation must be stale: %+v", state)
	}
	if validationErr != nil && len(state.Validations) != 0 {
		t.Fatal("conflicted validation persisted")
	}
}

func TestPurpleConcurrentPlanEditAndValidation(t *testing.T) {
	d, id := purpleDB(t)
	ctx := t.Context()
	state, err := d.SaveDefensePlan(ctx, id, purplePlan())
	if err != nil {
		t.Fatal(err)
	}
	observation := purpleObservation(state)
	plan := purplePlan()
	plan.ExpectedRevision = 1
	plan.RuleText = "replacement"
	start := make(chan struct{})
	validationResult := make(chan error, 1)
	planResult := make(chan error, 1)
	go func() { <-start; _, err := d.AddDefenseValidation(ctx, id, observation); validationResult <- err }()
	go func() { <-start; _, err := d.SaveDefensePlan(ctx, id, plan); planResult <- err }()
	close(start)
	if err := <-planResult; err != nil {
		t.Fatal(err)
	}
	validationErr := <-validationResult
	if validationErr != nil && !errors.Is(validationErr, ErrDefenseConflict) {
		t.Fatal(validationErr)
	}
	state, err = d.GetFindingDefense(ctx, id)
	if err != nil || state.Plan.Revision != 2 || state.State == "current" {
		t.Fatalf("plan race: %+v %v", state, err)
	}
}

func TestPurpleInputValidation(t *testing.T) {
	plan := purplePlan()
	plan.Hypothesis = strings.Repeat("검", 4000)
	if _, err := normalizeDefensePlan(plan); err != nil {
		t.Fatal("valid unicode rejected", err)
	}
	plan.Hypothesis += "증"
	if _, err := normalizeDefensePlan(plan); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatal("oversized hypothesis accepted", err)
	}
	zero := int64(0)
	now := time.Now().UTC()
	valid := DefenseValidationInput{PlanRevision: 1, ExpectedEvidenceVersion: &zero, ExpectedSourceFingerprint: strings.Repeat("a", 32), Detection: "detected", Prevention: "not_tested", Evidence: "alert #1", ObservedAt: now}
	cases := []struct {
		name   string
		mutate func(*DefenseValidationInput)
	}{
		{"no version", func(v *DefenseValidationInput) { v.ExpectedEvidenceVersion = nil }},
		{"no fingerprint", func(v *DefenseValidationInput) { v.ExpectedSourceFingerprint = "" }},
		{"unrun", func(v *DefenseValidationInput) { v.Detection = "not_tested" }},
		{"invalid detection", func(v *DefenseValidationInput) { v.Detection = "pass" }},
		{"invalid prevention", func(v *DefenseValidationInput) { v.Prevention = "prevented" }},
		{"blank evidence", func(v *DefenseValidationInput) { v.Evidence = " \t " }},
		{"large evidence", func(v *DefenseValidationInput) { v.Evidence = strings.Repeat("e", 32001) }},
		{"null byte", func(v *DefenseValidationInput) { v.Evidence = "a\x00b" }},
		{"zero timestamp", func(v *DefenseValidationInput) { v.ObservedAt = time.Time{} }},
		{"future timestamp", func(v *DefenseValidationInput) { v.ObservedAt = now.Add(6 * time.Minute) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := valid
			tc.mutate(&v)
			if _, err := normalizeDefenseValidation(v, now); !errors.Is(err, ErrDefenseInvalid) {
				t.Fatalf("accepted invalid input: %v", err)
			}
		})
	}
	if _, err := normalizeDefenseValidation(valid, now); err != nil {
		t.Fatal(err)
	}
}
