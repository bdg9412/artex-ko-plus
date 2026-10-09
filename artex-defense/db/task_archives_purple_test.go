package db

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPurpleTaskArchiveDefenseLegacyTablesOptional(t *testing.T) {
	// Packages created before defense records were added have neither key.
	for _, tables := range []map[string]json.RawMessage{nil, {
		"finding_defense_plans":       json.RawMessage(`[]`),
		"finding_defense_validations": json.RawMessage(`[]`),
	}, {
		"finding_defense_plans":       json.RawMessage(`[]`),
		"finding_defense_validations": json.RawMessage(`[]`),
		"finding_defense_replays":     json.RawMessage(`[]`),
	}} {
		if err := restoreFindingDefenseTx(nil, &TaskArchiveSnapshot{Tables: tables}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPurpleReplayLegacyManualArchiveRoundTrip(t *testing.T) {
	d, _ := purpleDB(t)
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("legacy manual defense archive", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID); d.DeleteTask(task.ID) })
	finding, err := d.Exploration(task.ExplorationID).RecordFinding(t.Context(), RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Summary: "legacy manual record", Severity: SeverityLow})
	if err != nil {
		t.Fatal(err)
	}
	state, err := d.SaveDefensePlan(t.Context(), finding.FindingID, purplePlan())
	if err != nil {
		t.Fatal(err)
	}
	state, err = d.AddDefenseValidation(t.Context(), finding.FindingID, purpleObservation(state))
	if err != nil {
		t.Fatal(err)
	}
	if err = d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	delete(snapshot.Tables, "finding_defense_replays")
	delete(snapshot.DataCounts, "finding_defense_replays")
	if err = d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/legacy-manual-defense.tar.zst", "fixture", 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	after, err := d.GetFindingDefense(t.Context(), finding.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(state)
	got, _ := json.Marshal(after)
	if !bytes.Equal(want, got) {
		t.Fatal("legacy manual archive lost its plan or observation")
	}
	replays, err := d.ListDefenseReplays(t.Context(), finding.FindingID)
	if err != nil || len(replays) != 0 {
		t.Fatalf("legacy archive acquired replay history: %+v %v", replays, err)
	}
}

func TestPurpleTaskArchiveDefenseRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("defense archive roundtrip", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID)
		d.DeleteTask(task.ID)
	}()
	finding, err := d.Exploration(task.ExplorationID).RecordFinding(t.Context(), RecordFindingInput{
		TaskID: task.ID, ExplorationID: task.ExplorationID, Summary: "private order access", Severity: SeverityLow,
	})
	if err != nil {
		t.Fatal(err)
	}
	var before *FindingDefense
	var replaysBefore []*DefenseReplayExport
	for revision := int64(1); revision <= 2; revision++ {
		before, err = d.SaveDefensePlan(t.Context(), finding.FindingID, DefensePlanInput{
			ExpectedRevision: revision - 1, Hypothesis: fmt.Sprintf("hypothesis %d", revision),
			LogSource: "fixture audit", RuleFormat: "event_filter", RuleText: fmt.Sprintf(`{"version":1,"all":[{"field":"revision","op":"eq","value":%d}]}`, revision),
		})
		if err != nil {
			t.Fatal(err)
		}
		before, err = d.AddDefenseValidation(t.Context(), finding.FindingID, DefenseValidationInput{
			PlanRevision: before.Plan.Revision, ExpectedEvidenceVersion: &before.EvidenceVersion,
			ExpectedSourceFingerprint: before.SourceFingerprint,
			Detection:                 "missed", Prevention: "not_blocked", Evidence: fmt.Sprintf("observation %d", revision),
			ObservedAt: time.Now().UTC().Add(-time.Minute),
		})
		if err != nil {
			t.Fatal(err)
		}
		replay, err := d.RunDefenseReplay(t.Context(), finding.FindingID, DefenseReplayInput{
			PlanRevision: before.Plan.Revision, ExpectedEvidenceVersion: &before.EvidenceVersion, ExpectedSourceFingerprint: before.SourceFingerprint,
			TargetLogs: fmt.Sprintf(`{"revision":%d}`, revision), ControlLogs: `{"revision":0}`,
		})
		if err != nil {
			t.Fatal(err)
		}
		exported, err := d.ExportDefenseReplay(t.Context(), finding.FindingID, replay.ID)
		if err != nil {
			t.Fatal(err)
		}
		replaysBefore = append(replaysBefore, exported)
	}
	// Refresh only derived state after the second plan revision, preserving raw history.
	for i, replay := range replaysBefore {
		replaysBefore[i], err = d.ExportDefenseReplay(t.Context(), finding.FindingID, replay.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	// No defense writes may slip in after the archive barrier and disappear
	// between the repeatable snapshot and the final cascading deletion.
	if _, err := d.SaveDefensePlan(t.Context(), finding.FindingID, DefensePlanInput{
		ExpectedRevision: 2, Hypothesis: "late plan", RuleFormat: "query",
	}); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatalf("plan write during archive returned %v", err)
	}
	if _, err := d.AddDefenseValidation(t.Context(), finding.FindingID, DefenseValidationInput{
		PlanRevision: before.Plan.Revision, ExpectedEvidenceVersion: &before.EvidenceVersion,
		ExpectedSourceFingerprint: before.SourceFingerprint,
		Detection:                 "detected", Prevention: "not_tested", Evidence: "late observation", ObservedAt: time.Now().UTC(),
	}); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatalf("validation write during archive returned %v", err)
	}
	if _, err := d.RunDefenseReplay(t.Context(), finding.FindingID, DefenseReplayInput{
		PlanRevision: before.Plan.Revision, ExpectedEvidenceVersion: &before.EvidenceVersion, ExpectedSourceFingerprint: before.SourceFingerprint,
		TargetLogs: `{"revision":2}`, ControlLogs: `{"revision":0}`,
	}); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatalf("replay write during archive returned %v", err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DataCounts["finding_defense_plans"] != 1 || snapshot.DataCounts["finding_defense_validations"] != 2 || snapshot.DataCounts["finding_defense_replays"] != 2 {
		t.Fatalf("defense archive counts: %#v", snapshot.DataCounts)
	}
	if err := d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/defense-roundtrip.tar.zst", "fixture", 1, 1); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"finding_defense_plans", "finding_defense_validations", "finding_defense_replays"} {
		var count int
		if err := d.QueryRow(`SELECT count(*) FROM `+table+` WHERE finding_id=$1`, finding.FindingID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("%s was not compacted", table)
		}
	}
	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	after, err := d.GetFindingDefense(t.Context(), finding.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("defense plan/history changed across archive restore\nbefore: %s\nafter: %s", want, got)
	}
	for _, beforeReplay := range replaysBefore {
		afterReplay, err := d.ExportDefenseReplay(t.Context(), finding.FindingID, beforeReplay.ID)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := json.Marshal(beforeReplay)
		got, _ := json.Marshal(afterReplay)
		if !bytes.Equal(want, got) {
			t.Fatal("replay input, result or metadata changed across archive restore")
		}
	}
}

func TestPurpleTaskArchiveDefenseRejectsForeignFinding(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	id, err := d.AddFinding(0, 0, "fixture", "foreign finding", SeverityLow, "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.DeleteFinding(id)
	tx, err := d.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, table := range []string{"finding_defense_plans", "finding_defense_validations", "finding_defense_replays"} {
		err := restoreFindingDefenseTx(tx, &TaskArchiveSnapshot{TaskID: 1, Tables: map[string]json.RawMessage{
			table: json.RawMessage(fmt.Sprintf(`[{"finding_id":%d}]`, id)),
		}})
		if err == nil || !strings.Contains(err.Error(), "outside archived task") {
			t.Fatalf("%s accepted a foreign finding: %v", table, err)
		}
	}
}
