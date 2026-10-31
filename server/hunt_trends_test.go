package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/hunting"
)

func TestHuntTrendCollectToAuthenticatedAssetReport(t *testing.T) {
	s, request := defensiveAPIFixture(t)
	_, _ = s.m.pg.Exec(`DELETE FROM defensive_hunt_trend_collection WHERE singleton=true`)
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM defensive_hunt_trend_collection WHERE singleton=true`) })
	var assetID int64
	if err := s.m.pg.QueryRowContext(t.Context(), `INSERT INTO assets(type,domain,port,url,service_type,technologies,auth,extra) VALUES('service','hunt-trend-test.lab',443,'https://hunt-trend-test.lab','http',ARRAY['Ivanti Connect Secure 22.7'],ARRAY['{"token":"must-not-leak"}'::jsonb],'{"secret":"must-not-leak"}'::jsonb) RETURNING id`).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM assets WHERE id=$1`, assetID) })
	const cve = "CVE-2099-87654"
	t.Cleanup(func() { _, _ = s.m.pg.Exec(`DELETE FROM defensive_hunt_trends WHERE topic_key=$1`, cve) })
	now := time.Now().UTC()
	s.huntTrendCollector = &hunting.TrendCollector{Now: func() time.Time { return now }, HTTPClient: &http.Client{Transport: huntTransportFunc(func(r *http.Request) (*http.Response, error) {
		body := fmt.Sprintf(`<rss><channel><item><title>%s 취약점 보도</title><link>https://www.boannews.com/news/fixture</link><description>최근 보안 업데이트</description><pubDate>%s</pubDate></item></channel></rss>`, cve, now.Format(time.RFC1123Z))
		if r.URL.Host == "raw.githubusercontent.com" {
			body = fmt.Sprintf(`{"vulnerabilities":[{"cveID":%q,"vendorProject":"Ivanti","product":"Connect Secure","vulnerabilityName":"Ivanti Connect Secure Vulnerability","dateAdded":%q,"shortDescription":"Known exploitation reported."}]}`, cve, now.Format("2006-01-02"))
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})}}
	started := request("POST", "/api/defensive/hunts/trends/collect", "")
	if started.Code != 202 {
		t.Fatalf("collection did not start: %d %s", started.Code, started.Body.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response := request("GET", "/api/defensive/hunts/trends", "")
		if response.Code != 200 {
			t.Fatalf("report endpoint: %d %s", response.Code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "must-not-leak") {
			t.Fatal("asset credentials or arbitrary metadata leaked in trend report")
		}
		var payload struct {
			Reports   []hunting.TrendReport `json:"reports"`
			Inventory struct {
				Available     bool `json:"available"`
				ScannedAssets int  `json:"scanned_assets"`
			} `json:"inventory"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		for _, report := range payload.Reports {
			if report.TopicKey != cve {
				continue
			}
			if report.Product != "Connect Secure" || report.AssetMatchCount != 1 || report.AssetMatches[0].Target != "hunt-trend-test.lab:443" || !payload.Inventory.Available || payload.Inventory.ScannedAssets < 1 {
				t.Fatalf("stored report lost product or asset evidence: %+v inventory=%+v", report, payload.Inventory)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("collected report did not appear")
}
