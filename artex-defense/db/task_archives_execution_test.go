package db

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestPurpleExecutionArchivePreservesEvidenceWithoutLiveSourceOrRetest(t *testing.T) {
	testDefenseExecutionArchive(t, false, false)
}

func TestPurpleExecutionLegacyArchiveDiagnosisDefaults(t *testing.T) {
	testDefenseExecutionArchive(t, true, false)
}

func TestPurpleFileExecutionArchivePreservesRawUploadsAndDiagnostics(t *testing.T) {
	testDefenseExecutionArchive(t, false, true)
}

func testDefenseExecutionArchive(t *testing.T, legacyDiagnosis, fileMode bool) {
	t.Helper()
	d, _ := purpleDB(t)
	ctx := t.Context()
	var source *SecuritySource
	if !fileMode {
		source = defenseExecutionSource(t, d)
	}
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("execution archive fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID); d.DeleteTask(task.ID) })
	finding, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Summary: "archive execution", Severity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveDefensePlan(ctx, finding.FindingID, purplePlan()); err != nil {
		t.Fatal(err)
	}
	input := fileExecutionInput(t, d, finding.FindingID)
	if source != nil {
		input = defenseExecutionInput(t, d, finding.FindingID, source.ID)
	}
	execution := createDefenseExecutionFixture(t, d, finding.FindingID, input)
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.QueueTaskArchive(task.ID); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatalf("active execution archived: %v", err)
	}
	if _, err := d.SnapshotTaskArchive(task.ID); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatalf("active execution snapshotted: %v", err)
	}
	execution = completeDefenseExecutionFixture(t, d, execution)
	proof := defenseExecutionEvidence(execution, true, "blocked")
	if fileMode {
		proof = fileExecutionEvidence(t, execution, true, "blocked")
	}
	if _, err := d.SaveDefenseAssessment(ctx, finding.FindingID, execution.ID, proof); err != nil {
		t.Fatal(err)
	}
	before, err := d.GetDefenseExecution(ctx, finding.FindingID, execution.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.SaveDefenseAssessment(ctx, finding.FindingID, execution.ID, proof); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatalf("assessment during archive: %v", err)
	}
	if _, err := d.ClaimTaskArchiveJob(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DataCounts["finding_defense_executions"] != 1 || snapshot.DataCounts["finding_defense_assessments"] != 1 {
		t.Fatalf("missing archive tables: %+v", snapshot.DataCounts)
	}
	if legacyDiagnosis {
		rows, err := decodeArchiveRows(snapshot.Tables["finding_defense_executions"])
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			delete(row, "diagnosis_snapshot")
			delete(row, "source_kind")
		}
		snapshot.Tables["finding_defense_executions"], err = json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		before.DiagnosisSnapshot = json.RawMessage(`{}`)
		assessments, err := decodeArchiveRows(snapshot.Tables["finding_defense_assessments"])
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range assessments {
			delete(row, "diagnostics")
		}
		snapshot.Tables["finding_defense_assessments"], err = json.Marshal(assessments)
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/defense-execution-fixture.tar.zst", "fixture", 1, 1); err != nil {
		t.Fatal(err)
	}
	// Historical source snapshots have no dependency on a current connector or
	// retest row. Restore must not import credentials or manufacture a connector.
	if source != nil {
		if _, err := d.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.ClaimTaskArchiveJob(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	after, err := d.GetDefenseExecution(ctx, finding.FindingID, execution.ID)
	if err != nil {
		t.Fatal(err)
	}
	wantState := "stale"
	if fileMode {
		wantState = "current"
	}
	if after.State != wantState || after.Retest == nil || after.Retest.Status != "completed" {
		t.Fatalf("restored current source/retest dependence: %+v", after)
	}
	before.State = wantState
	want, _ := json.Marshal(before)
	got, _ := json.Marshal(after)
	if string(want) != string(got) {
		t.Fatal("archive changed frozen retest, plan, source, correlation or assessment evidence")
	}
}

func TestPurpleExecutionLegacyArchiveTablesOptional(t *testing.T) {
	for _, tables := range []map[string]json.RawMessage{nil, {"finding_defense_plans": json.RawMessage(`[]`), "finding_defense_validations": json.RawMessage(`[]`), "finding_defense_replays": json.RawMessage(`[]`)}} {
		if err := restoreFindingDefenseTx(nil, &TaskArchiveSnapshot{Tables: tables}); err != nil {
			t.Fatal(err)
		}
	}
}
