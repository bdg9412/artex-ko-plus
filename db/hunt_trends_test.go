package db

import (
	"testing"
	"time"

	"github.com/Autumn-27/artex/hunting"
)

func TestHuntTrendCollectionLeaseAndReportPersistence(t *testing.T) {
	d := defensiveDB(t)
	ctx := t.Context()
	_, _ = d.ExecContext(ctx, `UPDATE defensive_hunt_trend_collection SET lease_until='-infinity',last_attempt=NULL WHERE singleton=true`)
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM defensive_hunt_trend_collection WHERE singleton=true`) })
	acquired, err := d.AcquireHuntTrendCollection(ctx)
	if err != nil || !acquired {
		t.Fatal("first collection lease", acquired, err)
	}
	acquired, err = d.AcquireHuntTrendCollection(ctx)
	if err != nil || acquired {
		t.Fatal("overlapping collection admitted", acquired, err)
	}
	report := hunting.TrendReport{
		TopicKey: "CVE-2099-12345", Term: "CVE-2099-12345", Title: "Fixture KEV report",
		Summary: "Source claim for review", Reason: "Review asset exposure", Priority: "high", Kind: "kev",
		PublishedAt: time.Now().UTC(), References: []hunting.TrendReference{{Source: "fixture", URL: "https://example.org/advisory", Title: "advisory"}},
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM defensive_hunt_trends WHERE topic_key=$1`, report.TopicKey) })
	if err := d.FinishHuntTrendCollection(ctx, []hunting.TrendReport{report}, ""); err != nil {
		t.Fatal(err)
	}
	reports, state, err := d.ListHuntTrends(ctx)
	if err != nil || state.Busy || state.LastSuccess == nil {
		t.Fatal("collection state", state, err)
	}
	found := false
	for _, item := range reports {
		if item.TopicKey == report.TopicKey {
			found = item.Term == report.Term && len(item.References) == 1
		}
	}
	if !found {
		t.Fatal("report was not listed")
	}
	// A completed run remains rate limited until the cooldown passes.
	acquired, err = d.AcquireHuntTrendCollection(ctx)
	if err != nil || acquired {
		t.Fatal("collection cooldown was bypassed", acquired, err)
	}
	_, err = d.ExecContext(ctx, `UPDATE defensive_hunt_trend_collection SET last_attempt=clock_timestamp()-interval '6 minutes' WHERE singleton=true`)
	if err != nil {
		t.Fatal(err)
	}
	acquired, err = d.AcquireHuntTrendCollection(ctx)
	if err != nil || !acquired {
		t.Fatal("collection lease was not released", acquired, err)
	}
	if err := d.FinishHuntTrendCollection(ctx, nil, "fixture upstream error"); err != nil {
		t.Fatal(err)
	}
	_, state, err = d.ListHuntTrends(ctx)
	if err != nil || state.LastError != "fixture upstream error" {
		t.Fatal("source failure was not recorded", state, err)
	}
}
