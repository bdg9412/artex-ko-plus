package securitysource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sourceFixture(t *testing.T, h http.HandlerFunc) (Config, Credentials) {
	t.Helper()
	s := httptest.NewTLSServer(h)
	t.Cleanup(s.Close)
	fp := sha256.Sum256(s.Certificate().Raw)
	return Config{BaseURL: s.URL, Index: "security", AuditSourcetype: "app:audit", AlertSourcetype: "waf:alert", CorrelationField: "artex_verification_id", ActionField: "action", TLSFingerprint: hex.EncodeToString(fp[:])}, Credentials{Username: "reader", Password: "test-only"}
}

const testCorrelation = "bbbbbbbb-aaaa-cccc-dddd-eeeeeeeeeeee"

func sourceQuery() Query {
	end := time.Now().UTC().Add(-time.Second)
	return Query{CorrelationID: testCorrelation, Start: end.Add(-time.Minute), End: end}
}
func resultLine(t time.Time, correlation, action string) string {
	raw, _ := json.Marshal(map[string]any{"_time": t.Format(time.RFC3339Nano), "_cd": "1:2", "_raw": fmt.Sprintf(`{"artex_verification_id":%q,"action":%q}`, correlation, action)})
	return `{"preview":false,"lastrow":true,"result":` + string(raw) + "}\n"
}

func TestPurpleSourceFetchPinnedTLSAndRealQuery(t *testing.T) {
	q := sourceQuery()
	calls := 0
	c, a := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/search/v2/jobs/export" || r.Method != "POST" {
			t.Errorf("unexpected operation %s %s", r.Method, r.URL.Path)
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "reader" || p != "test-only" {
			t.Error("credentials not scoped to configured endpoint")
		}
		_ = r.ParseForm()
		search := r.Form.Get("search")
		if !strings.Contains(search, `where 'artex_verification_id' = "`+testCorrelation+`"`) || r.Form.Get("earliest_time") == "" || r.Form.Get("latest_time") == "" || strings.Contains(search, "collect ") {
			t.Errorf("unbounded or wrong query %s", search)
		}
		calls++
		_, _ = w.Write([]byte(resultLine(q.Start.Add(time.Second), testCorrelation, "blocked")))
	})
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:1")
	out, e := Fetch(t.Context(), c, a, q)
	if e != nil {
		t.Fatal(e)
	}
	if calls != 2 || !out.Complete || len(out.Events) != 2 || out.Events[0].Kind != "audit" || out.Events[1].Kind != "alert" || out.Events[0].Action != "blocked" || len(out.Events[0].Raw) == 0 || out.CollectedAt.IsZero() {
		t.Fatalf("evidence: %+v", out)
	}
	if out.Events[0].CorrelationID != testCorrelation || out.WindowStart != q.Start || out.WindowEnd != q.End {
		t.Fatal("correlation window changed")
	}
}
func TestPurpleSourceRejectsInvalidSettingsAndQueries(t *testing.T) {
	c, a := sourceFixture(t, func(http.ResponseWriter, *http.Request) { t.Error("invalid request reached network") })
	for _, mutate := range []func(*Config){func(x *Config) { x.BaseURL = "http://example.test" }, func(x *Config) { x.BaseURL = "https://user:pass@example.test" }, func(x *Config) { x.Index = `main | delete` }, func(x *Config) { x.CorrelationField = `x' | delete` }, func(x *Config) { x.AlertSourcetype = x.AuditSourcetype }, func(x *Config) { x.TLSFingerprint = "bad" }} {
		bad := c
		mutate(&bad)
		if _, e := Fetch(t.Context(), bad, a, sourceQuery()); e == nil {
			t.Fatal("invalid config accepted")
		}
	}
	q := sourceQuery()
	q.CorrelationID = `x" | delete`
	if _, e := Fetch(t.Context(), c, a, q); e == nil {
		t.Fatal("query injection accepted")
	}
	q = sourceQuery()
	q.Start = q.End.Add(-25 * time.Hour)
	if _, e := Fetch(t.Context(), c, a, q); e == nil {
		t.Fatal("unbounded window accepted")
	}
	if _, e := Fetch(t.Context(), c, Credentials{Token: "a", Username: "b", Password: "c"}, sourceQuery()); e == nil {
		t.Fatal("ambiguous auth accepted")
	}
}
func TestPurpleSourceRefusesWrongCertificateAndRedirects(t *testing.T) {
	c, a := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.invalid/credentials", 302)
	})
	if _, e := Fetch(t.Context(), c, a, sourceQuery()); e == nil {
		t.Fatal("redirect accepted")
	}
	c.TLSFingerprint = strings.Repeat("0", 64)
	if _, e := Fetch(t.Context(), c, a, sourceQuery()); e == nil {
		t.Fatal("wrong certificate accepted")
	}
}
func TestPurpleSourceIncompleteAndUncorrelatedEvidence(t *testing.T) {
	q := sourceQuery()
	c := Config{Index: "x", CorrelationField: "artex_verification_id", ActionField: "action"}
	for _, body := range []string{resultLine(q.Start.Add(time.Second), "other-execution", "blocked"), resultLine(q.Start.Add(-time.Second), testCorrelation, "blocked"), `{"preview":true,"result":{}}` + "\n", `{"messages":[{"type":"WARN","text":"private internal details"}]}` + "\n"} {
		out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
		if e := parseExport([]byte(body), "audit", c, q, out); e != nil {
			t.Fatal(e)
		}
		if out.Complete || len(out.Events) != 0 {
			t.Fatal("incomplete or foreign event accepted")
		}
		for _, warning := range out.Warnings {
			if strings.Contains(warning, "private internal") {
				t.Fatal("remote error leaked")
			}
		}
	}
	for _, body := range []string{"{not json", `{"messages":[{"type":"FATAL","text":"secret"}]}`} {
		if e := parseExport([]byte(body), "audit", c, q, &Evidence{}); e == nil {
			t.Fatal("invalid response accepted")
		}
	}
}
func TestPurpleSourceUnknownActionDoesNotInferFromHTTPStatus(t *testing.T) {
	q := sourceQuery()
	c := Config{Index: "x", CorrelationField: "artex_verification_id", ActionField: "action"}
	out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
	if e := parseExport([]byte(resultLine(q.Start.Add(time.Second), testCorrelation, "403")), "audit", c, q, out); e != nil {
		t.Fatal(e)
	}
	if len(out.Events) != 1 || out.Events[0].Action != "unknown" {
		t.Fatal("HTTP status was treated as policy action")
	}
	q.CorrelationID = "no-such-event-correlated"
	if e := parseExport(nil, "alert", c, q, out); e != nil {
		t.Fatal(e)
	}
}
func TestPurpleSourceLimitsAndRedactedFailures(t *testing.T) {
	c, a := sourceFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = w.Write([]byte("secret private detail"))
	})
	_, e := Fetch(t.Context(), c, a, sourceQuery())
	if e == nil || strings.Contains(e.Error(), "secret") || strings.Contains(e.Error(), c.BaseURL) {
		t.Fatalf("remote error disclosure: %v", e)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := Fetch(ctx, c, a, sourceQuery()); e == nil {
		t.Fatal("cancelled fetch succeeded")
	}
	q := sourceQuery()
	cfg := Config{Index: "x", CorrelationField: "artex_verification_id", ActionField: "action"}
	out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
	if e := parseExport([]byte(strings.Repeat(resultLine(q.Start.Add(time.Second), testCorrelation, "allowed"), 201)), "audit", cfg, q, out); e != nil {
		t.Fatal(e)
	}
	if out.Complete {
		t.Fatal("truncated search counted complete")
	}
}

func TestPurpleSourceConflictingIdentityAndExactNumbers(t *testing.T) {
	q := sourceQuery()
	c := Config{Index: "x", CorrelationField: "artex_verification_id", ActionField: "action"}
	out := &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
	stream := resultLine(q.Start.Add(time.Second), testCorrelation, "blocked") + resultLine(q.Start.Add(time.Second), testCorrelation, "allowed")
	if e := parseExport([]byte(stream), "audit", c, q, out); e != nil {
		t.Fatal(e)
	}
	if out.Complete || len(out.Warnings) == 0 {
		t.Fatal("conflicting duplicate was accepted as blocked-only")
	}
	line := strings.Replace(resultLine(q.Start.Add(time.Second), testCorrelation, "blocked"), `"_cd":"1:2"`, `"_cd":"1:2","large":9007199254740993`, 1)
	out = &Evidence{Events: []Event{}, Complete: true, Warnings: []string{}}
	if e := parseExport([]byte(line), "audit", c, q, out); e != nil {
		t.Fatal(e)
	}
	if len(out.Events) != 1 || !strings.Contains(string(out.Events[0].Raw), "9007199254740993") {
		t.Fatal("original numeric evidence was rounded")
	}
}
