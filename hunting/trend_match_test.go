package hunting

import (
	"testing"
	"time"
)

func TestMatchTrendAssetsUsesKEVProductAndKeepsVersionUnverified(t *testing.T) {
	seen := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	reports := []TrendReport{
		{TopicKey: "CVE-2026-12345", Kind: "kev", Product: "Connect Secure", Vendor: "Ivanti", Priority: "high"},
		{TopicKey: "CVE-2026-67890", Kind: "kev", Product: "Secure Connect", Priority: "high"},
	}
	assets := []TrendAsset{
		{ID: "7", Label: "lab.example:443", Target: "lab.example:443", Technologies: []string{"Ivanti Connect Secure 22.7"}, LastSeen: seen},
		{ID: "8", Label: "other.example", Technologies: []string{"HTTPS"}, LastSeen: seen},
	}
	matched := MatchTrendAssets(reports, assets)
	if matched[0].TopicKey != "CVE-2026-12345" || matched[0].AssetMatchCount != 1 || len(matched[0].AssetMatches) != 1 {
		t.Fatalf("product clue missing: %+v", matched)
	}
	got := matched[0].AssetMatches[0]
	if got.Basis != "kev_product" || got.Observed != "Ivanti Connect Secure 22.7" || got.Target != "lab.example:443" {
		t.Fatalf("match evidence incorrect: %+v", got)
	}
	if matched[1].AssetMatchCount != 0 || reports[0].AssetMatchCount != 0 {
		t.Fatalf("false match or input mutation: matched=%+v source=%+v", matched, reports)
	}
}

func TestMatchTrendAssetsHeadlineIsOnlyAProductNameClue(t *testing.T) {
	reports := []TrendReport{{TopicKey: "NEWS-1", Kind: "news", Title: "Nginx 취약점 보도"}, {TopicKey: "NEWS-2", Kind: "news", Title: "SecureConnect incident"}}
	assets := []TrendAsset{{ID: "1", Label: "web.lab", Technologies: []string{"nginx/1.25", "HTTPS"}}, {ID: "2", Label: "other.lab", Technologies: []string{"Connect Secure"}}}
	matched := MatchTrendAssets(reports, assets)
	if matched[0].AssetMatchCount != 1 || matched[0].AssetMatches[0].Basis != "headline_technology" || matched[0].AssetMatches[0].Observed != "nginx/1.25" {
		t.Fatalf("headline product clue missing: %+v", matched[0])
	}
	if matched[1].AssetMatchCount != 0 {
		t.Fatalf("substring-only match admitted: %+v", matched[1])
	}
}
