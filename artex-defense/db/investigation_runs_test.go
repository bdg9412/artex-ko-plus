package db

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func investigationRunFixture(t *testing.T, d *DB, findingID int64) *FindingInvestigation {
	t.Helper()
	base, err := d.SaveFindingInvestigation(t.Context(), findingID, investigationFixture(t, d, findingID))
	if err != nil {
		t.Fatal(err)
	}
	return base
}

func TestInvestigationRunLifecycleAndImmutableBase(t *testing.T) {
	d, findingID := purpleDB(t)
	ctx := t.Context()
	base := investigationRunFixture(t, d, findingID)
	run, created, err := d.CreateInvestigationRun(ctx, findingID, base.ID, json.RawMessage(`{"question":"Trace file access"}`))
	if err != nil || !created || run.Status != "queued" || run.StartedAt != nil || run.FinishedAt != nil {
		t.Fatalf("create: %+v %t %v", run, created, err)
	}
	duplicate, created, err := d.CreateInvestigationRun(ctx, findingID, base.ID, json.RawMessage(`{"question":"must not replace"}`))
	if err != nil || created || duplicate.ID != run.ID || !strings.Contains(string(duplicate.Options), "Trace file access") {
		t.Fatalf("duplicate: %+v %t %v", duplicate, created, err)
	}
	otherBase := investigationRunFixture(t, d, findingID)
	if _, _, err = d.CreateInvestigationRun(ctx, findingID, otherBase.ID, nil); !errors.Is(err, ErrDefenseConflict) {
		t.Fatal("second evidence base started while first active", err)
	}
	if _, _, err = d.CreateInvestigationRun(ctx, findingID, base.ID+99999, nil); !errors.Is(err, ErrInvestigationNotFound) {
		t.Fatal("missing base accepted", err)
	}
	if _, err = d.AppendInvestigationRunEvent(ctx, run.ID, "query", json.RawMessage(`{}`), InvestigationRunUsage{}); !errors.Is(err, ErrInvestigationRunInactive) {
		t.Fatal("queued run accepted event", err)
	}
	if started, err := d.StartInvestigationRun(ctx, run.ID); err != nil || !started {
		t.Fatal("start failed", started, err)
	}
	if started, err := d.StartInvestigationRun(ctx, run.ID); err != nil || started {
		t.Fatal("double start accepted", started, err)
	}
	usage := InvestigationRunUsage{Rounds: 1, ModelCalls: 1, ToolCalls: 1, Queries: 1, InputTokens: 123, OutputTokens: 15}
	event, err := d.AppendInvestigationRunEvent(ctx, run.ID, "query_evidence", json.RawMessage(`{"evidence_ref":"q1:e1","raw":"original response\nbytes","query":"index=local earliest=1 latest=2"}`), usage)
	if err != nil || event.Sequence != 1 || event.CreatedAt.IsZero() {
		t.Fatalf("append: %+v %v", event, err)
	}
	if _, err = d.AppendInvestigationRunEvent(ctx, run.ID, "erase_usage", json.RawMessage(`{}`), InvestigationRunUsage{}); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatal("usage could decrease", err)
	}
	if _, err = d.FinishInvestigationRun(ctx, run.ID, "running", nil, "", usage); !errors.Is(err, ErrDefenseInvalid) {
		t.Fatal("nonterminal completion accepted", err)
	}
	result := json.RawMessage(`{"observed":[{"evidence_refs":["q1:e1"],"statement":"Request observed"}],"inferred":[],"limitations":["No host logs"]}`)
	if finished, err := d.FinishInvestigationRun(ctx, run.ID, "insufficient_data", result, "", usage); err != nil || !finished {
		t.Fatal("finish failed", finished, err)
	}
	if finished, err := d.FinishInvestigationRun(ctx, run.ID, "completed", json.RawMessage(`{"forged":"overwrite"}`), "", usage); err != nil || finished {
		t.Fatal("terminal result overwritten", finished, err)
	}
	if _, err = d.AppendInvestigationRunEvent(ctx, run.ID, "late", nil, usage); !errors.Is(err, ErrInvestigationRunInactive) {
		t.Fatal("terminal evidence overwritten", err)
	}
	finished, err := d.GetInvestigationRun(ctx, findingID, run.ID)
	if err != nil || finished.Status != "insufficient_data" || finished.StartedAt == nil || finished.FinishedAt == nil || len(finished.Events) != 1 || finished.Usage != usage || !strings.Contains(string(finished.Events[0].Payload), "original response") {
		t.Fatalf("saved run: %+v %v", finished, err)
	}
	if _, err = d.GetInvestigationRun(ctx, findingID+99999, run.ID); !errors.Is(err, ErrInvestigationRunNotFound) {
		t.Fatal("cross-finding read accepted", err)
	}
	summaries, err := d.ListInvestigationRuns(ctx, findingID, base.ID)
	if err != nil || len(summaries) != 1 || summaries[0].Usage != usage {
		t.Fatalf("history: %+v %v", summaries, err)
	}
	raw, _ := json.Marshal(summaries)
	if strings.Contains(string(raw), "original response") || strings.Contains(string(raw), "Trace file access") {
		t.Fatal("history includes raw investigation content")
	}
	unchanged, err := d.GetFindingInvestigation(ctx, findingID, base.ID)
	beforeJSON, _ := json.Marshal(base)
	afterJSON, _ := json.Marshal(unchanged)
	if err != nil || string(beforeJSON) != string(afterJSON) {
		t.Fatal("agent run mutated original evidence", err)
	}
	if _, err = d.Exec(`UPDATE findings SET evidence='changed during next investigation' WHERE id=$1`, findingID); err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.CreateInvestigationRun(ctx, findingID, base.ID, nil); !errors.Is(err, ErrDefenseConflict) {
		t.Fatal("stale evidence accepted", err)
	}
}

func TestInvestigationRunCancellationAndRestartPreservePartialEvidence(t *testing.T) {
	d, findingID := purpleDB(t)
	ctx := t.Context()
	base := investigationRunFixture(t, d, findingID)
	run, _, err := d.CreateInvestigationRun(ctx, findingID, base.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.StartInvestigationRun(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	usage := InvestigationRunUsage{Rounds: 1, ModelCalls: 1, ToolCalls: 1, InputTokens: 20}
	if _, err = d.AppendInvestigationRunEvent(ctx, run.ID, "observation", json.RawMessage(`{"evidence_refs":["file:1"],"observation":"Access observed"}`), usage); err != nil {
		t.Fatal(err)
	}
	if _, err = d.CancelInvestigationRun(ctx, findingID+99999, run.ID); !errors.Is(err, ErrInvestigationRunNotFound) {
		t.Fatal("cross-finding cancellation accepted", err)
	}
	cancelled, err := d.CancelInvestigationRun(ctx, findingID, run.ID)
	if err != nil || cancelled.Status != "cancelled" || len(cancelled.Events) != 1 || cancelled.Usage != usage {
		t.Fatalf("cancel: %+v %v", cancelled, err)
	}
	if finished, err := d.FinishInvestigationRun(ctx, run.ID, "completed", nil, "", usage); err != nil || finished {
		t.Fatal("late worker overwrote cancellation", finished, err)
	}
	running, _, err := d.CreateInvestigationRun(ctx, findingID, base.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.StartInvestigationRun(ctx, running.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.AppendInvestigationRunEvent(ctx, running.ID, "partial", json.RawMessage(`{"preserved":true}`), usage); err != nil {
		t.Fatal(err)
	}
	otherFinding, err := d.AddFinding(0, 0, "CERT_RESTART_TEST", "Other finding", "low", "summary", "evidence", "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.DeleteFinding(otherFinding) })
	otherBase := investigationRunFixture(t, d, otherFinding)
	queued, _, err := d.CreateInvestigationRun(ctx, otherFinding, otherBase.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if recovered, err := d.RecoverInvestigationRuns(ctx); err != nil || recovered != 2 {
		t.Fatal("recovery failed", recovered, err)
	}
	for _, item := range []struct{ findingID, runID int64 }{{findingID, running.ID}, {otherFinding, queued.ID}} {
		interrupted, err := d.GetInvestigationRun(ctx, item.findingID, item.runID)
		if err != nil || interrupted.Status != "interrupted" || interrupted.FinishedAt == nil {
			t.Fatalf("recovered: %+v %v", interrupted, err)
		}
		if item.runID == running.ID && (len(interrupted.Events) != 1 || interrupted.Usage != usage) {
			t.Fatal("restart discarded partial evidence")
		}
	}
	after, err := d.GetInvestigationRun(ctx, findingID, run.ID)
	if err != nil || !reflect.DeepEqual(cancelled, after) {
		t.Fatal("restart modified prior terminal result", err)
	}
}

func TestInvestigationRunConcurrentCreationDeduplicates(t *testing.T) {
	d, findingID := purpleDB(t)
	base := investigationRunFixture(t, d, findingID)
	const count = 6
	var wg sync.WaitGroup
	var mu sync.Mutex
	createdCount := 0
	ids := map[int64]bool{}
	for range count {
		wg.Go(func() {
			run, created, err := d.CreateInvestigationRun(t.Context(), findingID, base.ID, nil)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			ids[run.ID] = true
			if created {
				createdCount++
			}
		})
	}
	wg.Wait()
	if len(ids) != 1 || createdCount != 1 {
		t.Fatalf("created %d runs across %d IDs", createdCount, len(ids))
	}
}

func TestInvestigationRunArchiveBarrierAndRoundTrip(t *testing.T) {
	d, _ := purpleDB(t)
	ctx := t.Context()
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}
	task, err := d.CreateTask("CERT agent archive fixture", "fixture", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID); d.DeleteTask(task.ID) })
	finding, err := d.Exploration(task.ExplorationID).RecordFinding(ctx, RecordFindingInput{TaskID: task.ID, ExplorationID: task.ExplorationID, Summary: "CERT archive", Severity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	base := investigationRunFixture(t, d, finding.FindingID)
	run, _, err := d.CreateInvestigationRun(ctx, finding.FindingID, base.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.SetPaused(task.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchive(task.ID); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatal("queued agent run did not block archive", err)
	}
	if _, err = d.StartInvestigationRun(ctx, run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchive(task.ID); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatal("running agent run did not block archive", err)
	}
	usage := InvestigationRunUsage{Rounds: 1, ModelCalls: 1, ToolCalls: 1, InputTokens: 8}
	if _, err = d.AppendInvestigationRunEvent(ctx, run.ID, "query", json.RawMessage(`{"reference":"query:1","raw":"unaltered original bytes"}`), usage); err != nil {
		t.Fatal(err)
	}
	if _, err = d.FinishInvestigationRun(ctx, run.ID, "completed", json.RawMessage(`{"observed":["query:1"]}`), "", usage); err != nil {
		t.Fatal(err)
	}
	before, err := d.GetInvestigationRun(ctx, finding.FindingID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = d.CreateInvestigationRun(ctx, finding.FindingID, base.ID, nil); !errors.Is(err, ErrTaskArchiveState) {
		t.Fatal("new agent run crossed archive barrier", err)
	}
	if _, err = d.ClaimTaskArchiveJob(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot, err := d.SnapshotTaskArchive(task.ID)
	if err != nil || snapshot.DataCounts["finding_investigation_runs"] != 1 {
		t.Fatal("run missing from archive", err)
	}
	if err = d.CompleteTaskArchive(archive.ID, snapshot, "/tmp/cert-agent-test-only.tar.zst", "fixture", 1, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = d.ClaimTaskArchiveJob(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RestoreTaskArchive(archive.ID, snapshot, 0); err != nil {
		t.Fatal(err)
	}
	after, err := d.GetInvestigationRun(ctx, finding.FindingID, run.ID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("archive changed agent result or raw query evidence", err)
	}
}
