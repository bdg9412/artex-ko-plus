package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/artex/securitysource"
)

func investigationAPIInput(t *testing.T, s *Server, id int64) investigationRequest {
	t.Helper()
	state, err := s.m.pg.GetInvestigationOverview(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	scope := investigation.Scope{Target: "app.example", PathPrefix: "/ftp", Start: time.Now().UTC().Add(-time.Hour), End: time.Now().UTC().Add(-time.Minute)}
	return investigationRequest{Title: "Historical access investigation", SourceKind: "file", FileLabel: "original web logs", Scope: scope, Mapping: investigation.DefaultMapping(), Files: []investigation.InputFile{{Name: "prior.jsonl", Content: fmt.Sprintf(`{"timestamp":%q,"id":"historical-no-uuid","target":"app.example","path":"/ftp/file.txt","status":200}`, scope.Start.Add(time.Minute).Format(time.RFC3339Nano))}}, CoverageConfirmed: true, ExpectedEvidenceVersion: &state.EvidenceVersion, ExpectedSourceFingerprint: state.SourceFingerprint}
}
func TestInvestigationAPIAuth(t *testing.T) {
	s := &Server{jwtKey: []byte("investigation-test-key")}
	for _, route := range []struct{ method, path string }{{"GET", "/api/exploration/findings/1/investigations"}, {"POST", "/api/exploration/findings/1/investigations"}, {"POST", "/api/exploration/findings/1/investigations/preview"}, {"GET", "/api/exploration/findings/1/investigations/2/export"}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatalf("%s: %d", route.path, w.Code)
		}
	}
}
func TestInvestigationAPIFileHistoryWithoutRetest(t *testing.T) {
	s, id, request := purpleAPIFixture(t)
	path := fmt.Sprintf("/api/exploration/findings/%d/investigations", id)
	in := investigationAPIInput(t, s, id)
	raw, _ := json.Marshal(in)
	w := request("POST", path, string(raw))
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var result db.FindingInvestigation
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Analysis.ObservedCount != 1 || len(result.Collection.Files) != 1 || result.Collection.Files[0].Content != "" {
		t.Fatalf("unexpected preview %+v", result)
	}
	detail := fmt.Sprintf("%s/%d", path, result.ID)
	w = request("GET", detail+"/export", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "historical-no-uuid") || w.Header().Get("Content-Disposition") == "" {
		t.Fatal("missing original export", w.Code)
	}
	w = request("GET", path, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "historical-no-uuid") {
		t.Fatal("history raw leakage")
	}
	var retests int
	if err := s.m.pg.QueryRow(`SELECT count(*) FROM finding_retests WHERE finding_id=$1`, id).Scan(&retests); err != nil || retests != 0 {
		t.Fatal("investigation started a scan", err)
	}
	in.CoverageConfirmed = false
	raw, _ = json.Marshal(in)
	w = request("POST", path, string(raw))
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result.Collection.Complete {
		t.Fatal("unconfirmed coverage treated complete")
	}
	if _, err := s.m.pg.Exec(`UPDATE findings SET evidence='changed' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if w = request("POST", path, string(raw)); w.Code != 409 {
		t.Fatal("stale snapshot accepted", w.Code, w.Body.String())
	}
}
func TestInvestigationSplunkAPIReadOnlyPreviewAndExport(t *testing.T) {
	s, id, request := purpleAPIFixture(t)
	path := fmt.Sprintf("/api/exploration/findings/%d/investigations", id)
	in := investigationAPIInput(t, s, id)
	var calls atomic.Int32
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/services/search/v2/jobs/export" || r.Method != "POST" {
			t.Error("unexpected Splunk endpoint", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-only-token" {
			t.Error("missing encrypted credentials")
		}
		_ = r.ParseForm()
		query := r.FormValue("search")
		if strings.Contains(query, "delete") || !strings.Contains(query, `app\\.example`) {
			t.Error("unsafe or unscoped query", query)
		}
		fmt.Fprintf(w, `{"preview":false,"lastrow":true,"result":{"_time":%q,"id":"historical-splunk","target":"app.example","path":"/ftp/file.txt"}}`+"\n", in.Scope.Start.Add(time.Minute).Format(time.RFC3339Nano))
	}))
	defer endpoint.Close()
	pin := sha256.Sum256(endpoint.Certificate().Raw)
	cfg := securitysource.Config{BaseURL: endpoint.URL, Index: "test_index", AuditSourcetype: "web", AlertSourcetype: "alerts", CorrelationField: "artex_verification_id", ActionField: "action", TLSFingerprint: hex.EncodeToString(pin[:])}
	encrypted, err := s.encryptSourceCredentials(securitysource.Credentials{Token: "test-only-token"})
	if err != nil {
		t.Fatal(err)
	}
	source, err := s.m.pg.SaveSecuritySource(t.Context(), 0, 0, "local mocked Splunk", cfg, true, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID) })
	in.SourceKind = "splunk"
	in.SourceID = source.ID
	in.ExpectedSourceRevision = source.Revision
	in.Files = nil
	in.Sourcetypes = []string{"web"}
	raw, _ := json.Marshal(in)
	w := request("POST", path+"/preview", string(raw))
	if w.Code != 200 || calls.Load() != 0 {
		t.Fatalf("preview searched remotely: %d %s", w.Code, w.Body)
	}
	w = request("POST", path, string(raw))
	if w.Code != 201 || calls.Load() != 1 {
		t.Fatalf("query: %d %s calls=%d", w.Code, w.Body, calls.Load())
	}
	var result db.FindingInvestigation
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	if result.SourceKind != "splunk" || result.Analysis.ObservedCount != 1 || result.Collection.Query == "" {
		t.Fatalf("missing live-query evidence %+v", result)
	}
	w = request("GET", fmt.Sprintf("%s/%d/export", path, result.ID), "")
	if strings.Contains(w.Body.String(), "test-only-token") || strings.Contains(w.Body.String(), "secret_cipher") {
		t.Fatal("credentials exposed")
	}
	if _, err = s.m.pg.SaveSecuritySource(t.Context(), source.ID, source.Revision, "changed", cfg, true, nil); err != nil {
		t.Fatal(err)
	}
	if w = request("POST", path, string(raw)); w.Code != 409 || calls.Load() != 1 {
		t.Fatal("stale source queried", w.Code, calls.Load())
	}
}

func TestInvestigationMarkerWindow(t *testing.T) {
	start := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)
	end := start.Add(time.Minute)
	const marker = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	collection := investigation.Collection{
		Events: []investigation.Event{
			{ID: "at-start", Timestamp: start, VerificationID: strings.ToUpper(marker), KnownARTEX: true, Raw: "source-at-start"},
			{ID: "before", Timestamp: start.Add(-time.Nanosecond), VerificationID: marker, KnownARTEX: true, Raw: "source-before"},
			{ID: "at-end", Timestamp: end, VerificationID: marker, KnownARTEX: true, Raw: "source-at-end"},
			{ID: "after", Timestamp: end.Add(time.Hour), VerificationID: marker, KnownARTEX: true, Raw: "source-after"},
			{ID: "untrusted", Timestamp: start.Add(time.Second), VerificationID: marker, KnownARTEX: false, Raw: "source-untrusted"},
		},
		Stats:    investigation.Stats{KnownARTEX: 4, UnrecognizedMarkers: 1},
		Warnings: []string{"existing source limitation"},
	}
	boundInvestigationMarkers(&collection, []db.InvestigationVerification{{ID: marker, Start: start, End: end}})
	if !collection.Events[0].KnownARTEX || collection.Stats.KnownARTEX != 1 || collection.Stats.UnrecognizedMarkers != 4 {
		t.Fatalf("registered interval was not applied: %+v", collection)
	}
	for _, event := range collection.Events[1:] {
		if event.KnownARTEX {
			t.Errorf("outside or previously untrusted event was excluded: %s", event.ID)
		}
	}
	if collection.Events[1].Raw != "source-before" || collection.Events[2].Timestamp != end || len(collection.Events) != 5 || len(collection.Warnings) != 2 || collection.Warnings[0] != "existing source limitation" {
		t.Fatal("marker bounding changed evidence or discarded source limitations")
	}
	if !strings.Contains(collection.Warnings[1], "인증 수단이 아니므로") {
		t.Fatal("known marker was presented as authenticated source identity")
	}
	// No evidence or runs should remain an empty collection, not manufacture
	// marker matches, warnings, or empty provenance documents.
	empty := investigation.Collection{}
	boundInvestigationMarkers(&empty, nil)
	if empty.Events != nil || empty.Files != nil || empty.Warnings != nil || empty.Stats != (investigation.Stats{}) {
		t.Fatalf("empty collection mutated: %+v", empty)
	}
	withoutRuns := investigation.Collection{Events: []investigation.Event{{VerificationID: marker, KnownARTEX: true}}, Stats: investigation.Stats{KnownARTEX: 1}}
	boundInvestigationMarkers(&withoutRuns, nil)
	if withoutRuns.Events[0].KnownARTEX || withoutRuns.Stats.KnownARTEX != 0 || withoutRuns.Stats.UnrecognizedMarkers != 1 {
		t.Fatal("marker remained excluded without an actual registered run window")
	}
}
