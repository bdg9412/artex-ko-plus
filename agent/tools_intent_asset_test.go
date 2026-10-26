package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestAddIntentRejectsUnknownAssetIDWithoutCreatingIntent(t *testing.T) {
	d := testDB(t)
	defer d.Close()
	task, err := d.CreateTask("unknown asset id", "verify intent input", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	store := d.Exploration(task.ExplorationID)
	tools := NewToolSet(store, "planner")
	tools.SetTaskID(task.ID)
	tools.SetAssetStore(d.Assets(), d.Companies())
	before, err := store.ListByKind(db.KindIntent, 100)
	if err != nil {
		t.Fatal(err)
	}
	input := json.RawMessage(`{"intents":[{"summary":"verify lab target","asset_ids":[9223372036854775807]}]}`)
	result, err := tools.addIntent().Call(context.Background(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || !strings.Contains(result.Flatten(), "asset_ids 必须使用 list_assets") {
		t.Fatalf("missing actionable asset ID error: is_error=%v result=%q", result.IsError, result.Flatten())
	}
	after, err := store.ListByKind(db.KindIntent, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("unknown asset id created an intent: before=%d after=%d", len(before), len(after))
	}
}
