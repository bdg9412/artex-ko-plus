package hunting

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type trendRoundTrip func(*http.Request) (*http.Response, error)

func (f trendRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestTrendCollectorMakesSourceBackedReportsWithoutLogAccess(t *testing.T) {
	now := time.Date(2026, 10, 31, 4, 0, 0, 0, time.UTC)
	client := &http.Client{Transport: trendRoundTrip(func(req *http.Request) (*http.Response, error) {
		body := `<rss><channel><item><title>보안 업데이트</title><link>https://www.boannews.com/news/cve</link><description>CVE-2026-12345 취약점 공격 보도</description><pubDate>Sat, 31 Oct 2026 09:00:00</pubDate></item><item><title>오래된 보안 기사</title><link>https://www.boannews.com/old</link><description>CVE-2025-9999</description><pubDate>Mon, 01 Sep 2025 09:00:00 +0900</pubDate></item><item><title>악성 링크</title><link>javascript:alert(1)</link><description>취약점 공격</description><pubDate>Sat, 31 Oct 2026 09:00:00 +0900</pubDate></item></channel></rss>`
		if req.URL.String() == trendKEVURL {
			body = `{"vulnerabilities":[{"cveID":"CVE-2026-12345","vulnerabilityName":"Example vulnerability","dateAdded":"2026-10-30","shortDescription":"Known exploitation reported."}]}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: req}, nil
	})}
	reports, warnings := (TrendCollector{HTTPClient: client, Now: func() time.Time { return now }}).Collect(context.Background())
	if len(warnings) != 0 || len(reports) != 1 {
		t.Fatalf("reports=%+v warnings=%v", reports, warnings)
	}
	r := reports[0]
	if r.TopicKey != "CVE-2026-12345" || r.Kind != "kev" || r.Priority != "high" || len(r.References) < 2 {
		t.Fatalf("wrong merged report: %+v", r)
	}
	if r.PublishedAt != time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("KST date was not normalized: %v", r.PublishedAt)
	}
}

func TestTrendCollectorKeepsPartialReportsWhenSourceFails(t *testing.T) {
	now := time.Date(2026, 10, 31, 4, 0, 0, 0, time.UTC)
	client := &http.Client{Transport: trendRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == trendKEVURL {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"vulnerabilities":[{"cveID":"CVE-2026-12345","vulnerabilityName":"Example","dateAdded":"2026-10-30","shortDescription":"Known exploitation."}]}`)), Header: make(http.Header), Request: req}, nil
		}
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable")), Header: make(http.Header), Request: req}, nil
	})}
	reports, warnings := (TrendCollector{HTTPClient: client, Now: func() time.Time { return now }}).Collect(context.Background())
	if len(reports) != 1 || len(warnings) != len(trendFeeds) {
		t.Fatalf("reports=%+v warnings=%v", reports, warnings)
	}
}
