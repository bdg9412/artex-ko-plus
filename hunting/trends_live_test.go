package hunting

import (
	"os"
	"testing"
)

// Opt-in smoke test for the fixed public feeds. Unit tests remain offline and
// deterministic; this checks real TLS, redirects, formats, and current dates.
func TestTrendLiveFeeds(t *testing.T) {
	if os.Getenv("ARTEX_HUNT_TREND_LIVE") != "1" {
		t.Skip("set ARTEX_HUNT_TREND_LIVE=1 to check public feeds")
	}
	reports, warnings := (TrendCollector{}).Collect(t.Context())
	if len(reports) == 0 || len(warnings) == len(trendFeeds)+1 {
		t.Fatalf("no usable live trend source: reports=%d warnings=%v", len(reports), warnings)
	}
	t.Logf("live reports=%d warnings=%v", len(reports), warnings)
}
