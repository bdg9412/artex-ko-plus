package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestPlannerCannotReportFindingBeforeIntentProducesFact(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("planner finding guard", "verify local evidence", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	store := d.Exploration(task.ExplorationID)
	intentID, err := store.AddIntent(map[string]any{"summary": "verify candidate"}, 5, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	planner := NewToolSet(store, "planner")
	planner.SetTaskID(task.ID)
	input := json.RawMessage(fmt.Sprintf(`{"intent_id":%d,"vulnclass":"TEST","severity":"low","summary":"unverified candidate","evidence":"fabricated HTTP response"}`, intentID))
	call := func() (bool, string) {
		t.Helper()
		result, err := planner.addFinding().Call(context.Background(), input, nil)
		if err != nil {
			t.Fatal(err)
		}
		return result.IsError, result.Flatten()
	}
	if isError, body := call(); !isError || !strings.Contains(body, "尚无已确认事实") {
		t.Fatalf("unverified planner report was accepted: is_error=%v body=%q", isError, body)
	}
	if findings, err := store.ListByKind(db.KindFinding, 10); err != nil || len(findings) != 0 {
		t.Fatalf("unverified report wrote a finding: findings=%v err=%v", findings, err)
	}
	factID, err := store.AddNode(db.KindFact, map[string]any{"summary": "observed candidate", "evidence": "actual fixture observation"}, 0, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Link(intentID, db.RelYields, factID); err != nil {
		t.Fatal(err)
	}
	if isError, body := call(); isError || !strings.HasPrefix(body, "finding recorded: ") {
		t.Fatalf("evidence-backed planner report was rejected: is_error=%v body=%q", isError, body)
	}
}
