package securitysource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/investigation"
)

func historicalScope() investigation.Scope {
	end := time.Now().UTC().Add(-time.Hour)
	return investigation.Scope{Target: "juice-shop:3000", PathPrefix: "/ftp", Start: end.Add(-24 * time.Hour), End: end}
}

func historicalLine(at time.Time, last bool, id string) string {
	event := map[string]any{
		"_time": at.Format(time.RFC3339Nano), "_cd": "1:2", "splunk_server": "indexer-test",
		"_raw":         fmt.Sprintf(`{"id":%q,"target":"http://juice-shop:3000/","path":"/ftp/acquisitions.md","action":"allowed","status":200,"bytes":123,"response_complete":true}`, id),
		"large_number": json.Number("9007199254740993"),
	}
	encoded, _ := json.Marshal(event)
	return fmt.Sprintf("{\"preview\":false,\"lastrow\":%t,\"result\":%s}\n", last, encoded)
}

func TestInvestigationSourceHistoricalReadOnlyQuery(t *testing.T) {
	scope := historicalScope()
	calls := 0
	c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/services/search/v2/jobs/export" {
			t.Errorf("unexpected operation: %s %s", r.Method, r.URL.Path)
		}
		if username, password, ok := r.BasicAuth(); !ok || username != "reader" || password != "test-only" {
			t.Error("missing search credentials")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		search := r.Form.Get("search")
		if !strings.HasPrefix(search, `search index="security" (sourcetype="app:audit" OR sourcetype="waf:alert") | spath | where `) || !strings.HasSuffix(search, " | head 10001") || strings.Contains(search, "artex_verification_id") {
			t.Errorf("unbounded or UUID-dependent search: %s", search)
		}
		if r.Form.Get("earliest_time") != investigationEpoch(scope.Start) || r.Form.Get("latest_time") != investigationEpoch(scope.End) || r.Form.Get("preview") != "false" {
			t.Error("missing exact historical time bounds")
		}
		_, _ = w.Write([]byte(historicalLine(scope.Start.Add(time.Hour), true, "real-source-event")))
	})
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:1")
	out, err := FetchInvestigation(t.Context(), c, auth, scope, investigation.DefaultMapping(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || out.SourceKind != "splunk" || !out.Complete || !out.CoverageConfirmed || len(out.Events) != 1 || len(out.Files) != 2 || out.Query == "" || out.Mapping.Timestamp != "_time" {
		t.Fatalf("unexpected collection: %+v", out)
	}
	if out.Events[0].ID != "real-source-event" || out.Events[0].KnownARTEX || out.Events[0].VerificationID != "" || !strings.Contains(out.Events[0].Raw, "9007199254740993") {
		t.Fatalf("unmarked historical event or numeric evidence altered: %+v", out.Events[0])
	}
	if out.Files[1].Name != "splunk-export.jsonl" || out.Files[1].SHA256 == "" || !strings.Contains(out.Files[1].Content, `"lastrow":true`) {
		t.Fatal("exact stream provenance missing")
	}
	if strings.Contains(strings.Join(out.Warnings, " "), "업로더") {
		t.Fatal("actual Splunk query incorrectly described as uploader attestation")
	}
}

func TestInvestigationSourceValidationBeforeNetwork(t *testing.T) {
	c, auth := sourceFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid request reached network") })
	scope, mapping := historicalScope(), investigation.DefaultMapping()
	badMapping := mapping
	badMapping.Target = `host' | delete`
	if _, err := FetchInvestigation(t.Context(), c, auth, scope, badMapping, nil, nil); err == nil {
		t.Fatal("unsafe field accepted")
	}
	for _, bad := range []investigation.Mapping{
		{Timestamp: "timestamp", Path: "path"},
		{Timestamp: "timestamp", Target: "host"},
		{Timestamp: "timestamp", Target: "host", Path: "path", User: "_time"},
	} {
		if _, err := FetchInvestigation(t.Context(), c, auth, scope, bad, nil, nil); err == nil {
			t.Fatal("missing scope mapping or conflicting canonical timestamp accepted")
		}
	}
	for _, sourcetypes := range [][]string{{`audit" | delete`}, {"audit", "audit"}, {"*"}, {"1", "2", "3", "4", "5", "6", "7", "8", "9"}} {
		if _, err := FetchInvestigation(t.Context(), c, auth, scope, mapping, sourcetypes, nil); err == nil {
			t.Fatalf("unsafe sourcetypes accepted: %v", sourcetypes)
		}
	}
	badScope := scope
	badScope.Target = `example.test" | delete`
	if _, err := FetchInvestigation(t.Context(), c, auth, badScope, mapping, nil, nil); err == nil {
		t.Fatal("unsafe target accepted")
	}
	badScope = scope
	badScope.End = time.Now().Add(time.Hour)
	if _, err := FetchInvestigation(t.Context(), c, auth, badScope, mapping, nil, nil); err == nil {
		t.Fatal("future time bound accepted")
	}
	if _, err := FetchInvestigation(t.Context(), c, Credentials{}, scope, mapping, nil, nil); err == nil {
		t.Fatal("missing credentials accepted")
	}
}

func TestInvestigationSearchLiteralPathAndTarget(t *testing.T) {
	c, _ := sourceFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("builder reached network") })
	scope := historicalScope()
	scope.Target = "Example.test"
	scope.PathPrefix = `/file_*_name`
	search, err := BuildInvestigationSearch(c, scope, investigation.DefaultMapping(), []string{"http:access"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(search, "like(") || !strings.Contains(search, ` = "/file_*_name"`) || !strings.Contains(search, `"/file_*_name/"`) || !strings.Contains(search, `example\\.test`) || strings.Contains(search, "artex_verification_id") {
		t.Fatalf("literal boundary semantics lost: %s", search)
	}
	scope.PathPrefix = "/"
	search, err = BuildInvestigationSearch(c, scope, investigation.DefaultMapping(), nil)
	if err != nil || strings.Contains(search, "substr(") {
		t.Fatalf("root path should retain every target path: %s, %v", search, err)
	}
}

func TestInvestigationSourceIgnoresOtherTargetAndTime(t *testing.T) {
	scope := historicalScope()
	for _, body := range []string{
		strings.Replace(historicalLine(scope.Start.Add(time.Hour), true, "other-target"), "juice-shop:3000", "other-target:3000", 1),
		historicalLine(scope.Start.Add(-time.Hour), true, "outside-window"),
		strings.Replace(historicalLine(scope.Start.Add(time.Hour), true, "other-path"), "/ftp/acquisitions.md", "/ftp-not-related/acquisitions.md", 1),
	} {
		c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
		out, err := FetchInvestigation(t.Context(), c, auth, scope, investigation.DefaultMapping(), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Events) != 0 {
			t.Fatal("server-side query was trusted without validating actual event scope")
		}
	}
}

func TestInvestigationSearchTargetSemanticsMatchDomain(t *testing.T) {
	c, _ := sourceFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("builder reached network") })
	for _, target := range []string{"example.test", "example.test:80", "example.test:443", "example.test:3000", "example.test:00080", "[::1]:3000"} {
		scope := historicalScope()
		scope.Target = target
		search, err := BuildInvestigationSearch(c, scope, investigation.DefaultMapping(), nil)
		if err != nil {
			t.Fatal(err)
		}
		start := strings.Index(search, `match(trim(tostring('target')), `) + len(`match(trim(tostring('target')), `)
		end := strings.Index(search[start:], ") | where") + start
		var pattern string
		if err = json.Unmarshal([]byte(search[start:end]), &pattern); err != nil {
			t.Fatal(err)
		}
		matcher := regexp.MustCompile(pattern)
		for _, eventTarget := range []string{"example.test", "example.test:80", "example.test:00080", "example.test:443", "example.test:3000", "http://example.test/", "https://example.test/?a=1", "https://EXAMPLE.test.:3000/x", "http://example.test.evil.test/", "http://evil-example.test/", "http://example.test@evil.test/", "http://[::1]:3000/path", "[::1]:3000"} {
			if got, want := matcher.MatchString(eventTarget), investigation.MatchTarget(eventTarget, target); got != want {
				t.Errorf("query/domain scope mismatch for scope=%q event=%q: query=%v domain=%v", target, eventTarget, got, want)
			}
		}
	}
}

func TestInvestigationSourceZeroResultsIsNotCompromiseVerdict(t *testing.T) {
	c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	out, err := FetchInvestigation(t.Context(), c, auth, historicalScope(), investigation.DefaultMapping(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !out.Complete || !out.CoverageConfirmed || len(out.Events) != 0 || len(out.Files) != 2 {
		t.Fatalf("zero-result query lost provenance: %+v", out)
	}
}

func TestInvestigationExportIncompleteStreams(t *testing.T) {
	at := historicalScope().Start.Add(time.Hour)
	for name, body := range map[string]string{
		"preview":              `{"preview":true,"lastrow":true,"result":{"id":"preview"}}` + "\n",
		"warning":              `{"messages":[{"type":"WARN","text":"private server internals"}]}` + "\n" + historicalLine(at, true, "1"),
		"missing final marker": historicalLine(at, false, "1"),
		"unknown envelope":     `{"unexpected":true}`,
		"unknown diagnostic":   `{"messages":[{"type":"INCOMPLETE"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, complete, warnings, err := parseInvestigationExport([]byte(body))
			if err != nil || complete || len(warnings) == 0 {
				t.Fatalf("incomplete stream accepted: complete=%v warnings=%v error=%v", complete, warnings, err)
			}
			if strings.Contains(strings.Join(warnings, " "), "private server internals") {
				t.Fatal("upstream diagnostic disclosed")
			}
		})
	}
}

func TestInvestigationExportRejectsMalformedAndFatal(t *testing.T) {
	for _, body := range []string{
		`{"messages":[{"type":"ERROR","text":"secret"}]}`,
		`{"messages":[{"type":"FATAL"}]}`,
		`{"error":"secret"}`,
		`{"result":{}`, `{"result":[]} `,
		`{"result":{},"result":{"id":"ambiguous"}}`,
		`{"result":{}} {"result":{}}`,
	} {
		if _, _, _, _, err := parseInvestigationExport([]byte(body)); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatalf("malformed response or diagnostic accepted/disclosed: %v", err)
		}
	}
}

func TestInvestigationExportBoundedSentinel(t *testing.T) {
	var body strings.Builder
	for i := 0; i <= investigation.MaxRows; i++ {
		fmt.Fprintf(&body, "{\"lastrow\":%t,\"result\":{\"id\":%s}}\n", i == investigation.MaxRows, strconv.Itoa(i))
	}
	results, rows, complete, warnings, err := parseInvestigationExport([]byte(body.String()))
	if err != nil || complete || rows != investigation.MaxRows+1 || len(warnings) == 0 || bytesLines(results) != investigation.MaxRows {
		t.Fatalf("sentinel lost or silently truncated: rows=%d complete=%v warnings=%v error=%v", rows, complete, warnings, err)
	}
}

func bytesLines(data []byte) int { return strings.Count(string(data), "\n") }

func TestInvestigationSourceRefusesRedirectCertificateAndLargeResponse(t *testing.T) {
	scope, mapping := historicalScope(), investigation.DefaultMapping()
	c, auth := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/secret", http.StatusFound)
	})
	if _, err := FetchInvestigation(t.Context(), c, auth, scope, mapping, nil, nil); err == nil {
		t.Fatal("redirect followed")
	}
	c.TLSFingerprint = strings.Repeat("0", 64)
	if _, err := FetchInvestigation(t.Context(), c, auth, scope, mapping, nil, nil); err == nil {
		t.Fatal("wrong certificate accepted")
	}
	c, auth = sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat(" ", maxResponseBytes+1)))
	})
	if _, err := FetchInvestigation(t.Context(), c, auth, scope, mapping, nil, nil); err == nil {
		t.Fatal("unbounded response accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := FetchInvestigation(ctx, c, auth, scope, mapping, nil, nil); err == nil {
		t.Fatal("cancelled request succeeded")
	}
}
