package hunting

import (
	"sort"
	"strings"
	"time"
	"unicode"
)

// TrendAsset contains only inventory fields safe to display in a lead report.
// Auth, arbitrary extra metadata, and log contents are never loaded here.
type TrendAsset struct {
	ID           string
	Label        string
	Target       string
	AppName      string
	Technologies []string
	LastSeen     time.Time
}

type TrendAssetMatch struct {
	AssetID  string    `json:"asset_id"`
	Label    string    `json:"label"`
	Target   string    `json:"target,omitempty"`
	Observed string    `json:"observed"`
	Basis    string    `json:"basis"` // kev_product or headline_technology
	LastSeen time.Time `json:"last_seen"`
}

func trendWords(s string) []string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	return strings.Fields(b.String())
}

func trendHasWords(haystack, needle []string) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		matched := true
		for j, word := range needle {
			if haystack[i+j] != word {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func trendUsefulProduct(words []string) bool {
	if len(words) == 0 || len(strings.Join(words, "")) < 3 {
		return false
	}
	if len(words) == 1 {
		switch words[0] {
		case "software", "product", "products", "multiple", "unknown", "server", "service", "web", "http", "https":
			return false
		}
	}
	return true
}

// A technology fingerprint may contain a version (e.g. nginx/1.25). The
// headline check uses the product prefix only; it cannot verify that version.
func trendTechnologyName(raw string) []string {
	words := trendWords(raw)
	out := make([]string, 0, 4)
	for _, word := range words {
		if len(out) >= 4 || len(word) == 0 || word[0] >= '0' && word[0] <= '9' {
			break
		}
		out = append(out, word)
	}
	if !trendUsefulProduct(out) {
		return nil
	}
	return out
}

func trendMatch(report TrendReport, asset TrendAsset) (TrendAssetMatch, bool) {
	fields := append([]string(nil), asset.Technologies...)
	if asset.AppName != "" {
		fields = append(fields, asset.AppName)
	}
	for _, observed := range fields {
		if observed == "" {
			continue
		}
		basis := ""
		if report.Product != "" {
			product := trendWords(report.Product)
			if trendUsefulProduct(product) && trendHasWords(trendWords(observed), product) {
				basis = "kev_product"
			}
		} else if report.Kind == "news" {
			name := trendTechnologyName(observed)
			if trendHasWords(trendWords(report.Title), name) {
				basis = "headline_technology"
			}
		}
		if basis != "" {
			return TrendAssetMatch{AssetID: asset.ID, Label: asset.Label, Target: asset.Target, Observed: trendClean(observed, 160), Basis: basis, LastSeen: asset.LastSeen}, true
		}
	}
	return TrendAssetMatch{}, false
}

// MatchTrendAssets decorates saved source reports at read time so an inventory
// update changes recommendations without rewriting the original feed record.
// A match is a product-name clue, never a vulnerable-version verdict.
func MatchTrendAssets(reports []TrendReport, assets []TrendAsset) []TrendReport {
	out := make([]TrendReport, len(reports))
	copy(out, reports)
	for i := range out {
		out[i].AssetMatches = nil
		out[i].AssetMatchCount = 0
		for _, asset := range assets {
			match, ok := trendMatch(out[i], asset)
			if !ok {
				continue
			}
			out[i].AssetMatchCount++
			if len(out[i].AssetMatches) < 5 {
				out[i].AssetMatches = append(out[i].AssetMatches, match)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return (out[i].AssetMatchCount > 0) && out[j].AssetMatchCount == 0
	})
	return out
}
