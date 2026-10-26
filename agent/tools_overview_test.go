package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
)

func TestOverviewTextBudgetIsFairAndUTF8Safe(t *testing.T) {
	if got := relatedOverviewBudgetForSources(1); got != relatedOverviewMaxTextPerSource {
		t.Fatalf("single source budget=%d want=%d", got, relatedOverviewMaxTextPerSource)
	}
	perSource := relatedOverviewBudgetForSources(db.MaxTaskSourceCount)
	if perSource*db.MaxTaskSourceCount > relatedOverviewTotalTextRunes {
		t.Fatalf("aggregate budget exceeded: per_source=%d", perSource)
	}

	budget := overviewTextBudget{remaining: 5}
	got := budget.take(strings.Repeat("中", 10), 20)
	if !utf8.ValidString(got) {
		t.Fatalf("budget truncation produced invalid UTF-8: %q", got)
	}
	if utf8.RuneCountInString(got) != 5 || !budget.truncated || budget.remaining != 0 {
		t.Fatalf("unexpected truncation: got=%q budget=%+v", got, budget)
	}
	if tail := budget.take("more", 20); tail != "" {
		t.Fatalf("exhausted budget returned more text: %q", tail)
	}
}

func TestBoundGraphOverviewKeepsReferencesAndSharesBudget(t *testing.T) {
	long := strings.Repeat("긴 진단 근거와 다음 단계 ", 1000)
	makeEntries := func(n int, field string) []map[string]any {
		entries := make([]map[string]any, n)
		for i := range entries {
			entries[i] = map[string]any{"id": int64(i + 1), "state": "open", field: long}
		}
		return entries
	}
	related := []map[string]any{
		{
			"source_task_id": int64(11),
			"task":           map[string]any{"goal": long, "description": long, "status": "running"},
			"recent_facts":   makeEntries(5, "summary"),
			"cold_digests":   makeEntries(3, "body"),
			"asset_scope":    []map[string]any{{"value": "lab.example", "source": long}},
		},
		{
			"source_task_id": int64(12),
			"task":           map[string]any{"goal": long, "description": long, "status": "running"},
			"recent_facts":   makeEntries(5, "summary"),
			"cold_digests":   makeEntries(3, "body"),
		},
	}
	overview := map[string]any{
		"task":                map[string]any{"description": long, "goal": long},
		"goals":               makeEntries(10, "text"),
		"open_intents":        makeEntries(30, "summary"),
		"running_intents":     makeEntries(4, "summary"),
		"finding_list":        makeEntries(10, "summary"),
		"recent_facts":        makeEntries(20, "summary"),
		"recent_done_intents": makeEntries(12, "summary"),
		"hints":               makeEntries(10, "text"),
		"cold_digests":        makeEntries(15, "body"),
		"related_tasks":       related,
		"frontier_open":       30,
		"coverage":            map[string]any{"pct": 40},
	}
	boundGraphOverview(overview)
	encoded, err := json.Marshal(overview)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 32_000 {
		t.Fatalf("overview remains too large: %d bytes", len(encoded))
	}
	if overview["summary_truncated"] != true || overview["frontier_open"] != 30 {
		t.Fatalf("missing truncation marker or count: %#v", overview)
	}
	if got := overview["coverage"].(map[string]any)["pct"]; got != 40 {
		t.Fatalf("coverage changed: %v", got)
	}
	open := overview["open_intents"].([]map[string]any)
	if open[0]["id"] != int64(1) || open[len(open)-1]["id"] != int64(30) {
		t.Fatalf("intent ids changed: first=%v last=%v", open[0]["id"], open[len(open)-1]["id"])
	}
	if open[len(open)-1]["summary"] == "" {
		t.Fatal("later intents lost their fair share of the summary budget")
	}
	if !utf8.Valid(encoded) {
		t.Fatal("overview is not valid UTF-8")
	}
	if related[0]["asset_scope"].([]map[string]any)[0]["value"] != "lab.example" {
		t.Fatal("exact scope value changed")
	}
	if related[0]["summary_truncated"] != true || related[1]["summary_truncated"] != true {
		t.Fatal("related task truncation is not marked")
	}
}
