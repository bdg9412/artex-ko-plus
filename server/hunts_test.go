package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/hunting"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/artex/securitysource"
	"github.com/Autumn-27/norma/llm"
)

type huntResolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f huntResolverFunc) LookupIPAddr(c context.Context, h string) ([]net.IPAddr, error) {
	return f(c, h)
}

type huntTransportFunc func(*http.Request) (*http.Response, error)

func (f huntTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Synthetic literature and telemetry exercise the real product adapters. They
// are not an exploit reproduction or a claim about production PHP traffic.
func huntTestResearcher() *hunting.Researcher {
	return &hunting.Researcher{Resolver: huntResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}), HTTPClient: &http.Client{Transport: huntTransportFunc(func(r *http.Request) (*http.Response, error) {
		body := `<title>PHP2Shell fixture advisory</title><p>PHP2Shell groups CVE-2026-109618 and CVE-2026-109619 involving PHP out-of-memory request state handling. A web request or server error alone does not demonstrate remote code execution. Host process evidence and affected configuration must be independently verified.</p>`
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}}
}

type huntScriptProvider struct {
	design atomic.Bool
	script investigationSplunkRunProvider
}

func (p *huntScriptProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if !p.design.Swap(true) {
		var input struct {
			Research hunting.Research `json:"research"`
		}
		if len(req.Messages) == 0 || len(req.Messages[0].Content) == 0 || json.Unmarshal([]byte(req.Messages[0].Content[0].Text), &input) != nil || len(input.Research.Sources) == 0 {
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("design did not receive real research")
		}
		if len(input.Research.CVEs) != 2 {
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("PHP2Shell multi-CVE literature was lost")
		}
		source := input.Research.Sources[0].ID
		d := hunting.Design{Title: "PHP2Shell 독립 헌팅", Summary: "웹 접근과 호스트 영향은 분리하여 조사합니다", Stages: []hunting.Stage{
			{ID: "web", AttackDescription: "가정: 취약한 PHP 서비스에 관련 요청이 도달했을 수 있습니다", DetectionQuestion: "출발지의 후속 요청이 원문으로 관측되는가?", RequiredFields: []string{"timestamp", "target", "path", "source_ip"}, SuccessCriteria: "요청 원문을 확인하며 HTTP 상태만으로 악용 성공을 판정하지 않습니다", BenignAlternatives: []string{"정상 사용자 접근"}, SourceIDs: []string{source}},
			{ID: "impact", AttackDescription: "가정: 실제 호스트 코드 실행 영향이 있었을 수 있습니다", DetectionQuestion: "호스트 프로세스 직접 근거가 있는가?", RequiredFields: []string{"timestamp", "target", "process_command"}, SuccessCriteria: "취약 요청과 연결한 호스트 프로세스 원문 필요", BenignAlternatives: []string{"운영자 실행"}, SourceIDs: []string{source}, DependsOn: []string{"web"}},
		}}
		raw, _ := json.Marshal(d)
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock(string(raw))}}, "end_turn", llm.Usage{InputTokens: 10, OutputTokens: 20}, nil
	}
	if p.script.calls.Load() >= 5 {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: "impact-insufficient", Name: "plan_investigation", Input: json.RawMessage(`{"action":"insufficient_data","reason":"호스트 프로세스 로그가 없습니다.","needed_logs":["호스트 프로세스 생성 원문"]}`)}}}, "tool_use", llm.Usage{InputTokens: 4, OutputTokens: 6}, nil
	}
	return p.script.Complete(ctx, req)
}
func (p *huntScriptProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return p.script.Stream(ctx, req)
}

func waitHunt(t *testing.T, s *Server, id int64) *db.Hunt {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		h, err := s.m.pg.GetHunt(t.Context(), id)
		if err != nil {
			t.Fatal(err)
		}
		if h.Status != "queued" && h.Status != "running" {
			return h
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("hunt did not terminate")
	return nil
}
func TestHuntPHP2ShellResearchToSplunkEvidenceIndependent(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprintf("source_revoked_%t", revoke), func(t *testing.T) {
			s, request := defensiveAPIFixture(t)
			s.huntResearch = huntTestResearcher()
			s.m.webSearchOn = true
			var searchCalls atomic.Int32
			s.huntResearch.Search = func(ctx context.Context, q string) ([]string, error) {
				searchCalls.Add(1)
				if !strings.Contains(strings.ToLower(q), "php2shell") && !strings.Contains(q, "CVE-2026-109618") {
					t.Error("research lost original question", q)
				}
				return []string{"https://research.example.com/php2shell"}, nil
			}
			scope := investigation.Scope{Target: "app.example", PathPrefix: "/ftp", Start: time.Now().UTC().Add(-time.Hour), End: time.Now().UTC().Add(-time.Minute)}
			var calls atomic.Int32
			const token = "hunting-fixture-secret-token"
			remoteBody := fmt.Sprintf(`{"preview":false,"lastrow":true,"result":{"_time":%q,"id":"remote-followup","target":"app.example","path":"/ftp/followup.txt","source_ip":"192.0.2.44","message":"original-remote-evidence-marker","large_value":9007199254740993}}`+"\n", scope.Start.Add(2*time.Minute).Format(time.RFC3339Nano))
			endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if r.Method != "POST" || r.URL.Path != "/services/search/v2/jobs/export" {
					t.Error("unexpected write endpoint", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("credential not resolved")
				}
				_ = r.ParseForm()
				q := r.FormValue("search")
				if !strings.Contains(q, `index="hunt_fixture"`) || !strings.Contains(q, `sourcetype="web"`) || strings.Contains(q, "delete") || strings.Contains(q, "outputlookup") || strings.Contains(q, `sourcetype="alerts"`) {
					t.Error("scope/write bypass", q)
				}
				if n == 1 {
					fmt.Fprintf(w, `{"preview":false,"lastrow":true,"result":{"_time":%q,"id":"seed-splunk","target":"app.example","path":"/ftp/initial.txt"}}`+"\n", scope.Start.Add(time.Minute).Format(time.RFC3339Nano))
					return
				}
				if n != 2 || !strings.Contains(q, `tostring('source_ip') = "192.0.2.44"`) {
					t.Error("missing autonomous typed pivot", n, q)
				}
				fmt.Fprint(w, remoteBody)
			}))
			defer endpoint.Close()
			pin := sha256.Sum256(endpoint.Certificate().Raw)
			config := securitysource.Config{BaseURL: endpoint.URL, Index: "hunt_fixture", AuditSourcetype: "web", AlertSourcetype: "alerts", CorrelationField: "artex_verification_id", ActionField: "action", TLSFingerprint: hex.EncodeToString(pin[:])}
			cipher, err := s.encryptSourceCredentials(securitysource.Credentials{Token: token})
			if err != nil {
				t.Fatal(err)
			}
			source, err := s.m.pg.SaveSecuritySource(t.Context(), 0, 0, "hunting fixture", config, true, cipher)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID) })
			p := &huntScriptProvider{}
			p.script.revoked = revoke
			if revoke {
				p.script.beforeSearch = func() error {
					_, err := s.m.pg.SaveSecuritySource(t.Context(), source.ID, source.Revision, "revoked during hunt", config, true, nil)
					return err
				}
			}
			s.llmOn = true
			s.llmProv = p
			s.llmCfg = agent.Config{Model: "scripted-mock", Stream: false}
			in := huntRequest{Request: hunting.Request{Term: "php2shell", SourceID: source.ID, ExpectedSourceRevision: source.Revision, Scope: scope, Mapping: investigation.DefaultMapping(), Sourcetypes: []string{"web"}}, ScopeConfirmed: true}
			var scenariosBefore, scenariosAfter int
			if err = s.m.pg.QueryRow(`SELECT count(*) FROM finding_defense_scenarios`).Scan(&scenariosBefore); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(in)
			w := request("POST", "/api/defensive/hunts", string(raw))
			if w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			var started db.Hunt
			if err = json.Unmarshal(w.Body.Bytes(), &started); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM defensive_hunts WHERE id=$1`, started.ID) })
			done := waitHunt(t, s, started.ID)
			var result hunting.Result
			if err = json.Unmarshal(done.Result, &result); err != nil {
				t.Fatal(err)
			}
			if err = s.m.pg.QueryRow(`SELECT count(*) FROM finding_defense_scenarios`).Scan(&scenariosAfter); err != nil || scenariosBefore != scenariosAfter {
				t.Fatal("existing scenario generation was changed", err)
			}
			if len(result.Research.CVEs) != 2 || len(result.Design.Stages) != 2 || len(result.Verification.Stages) != 2 {
				t.Fatalf("pipeline incomplete: %s", done.Result)
			}
			if searchCalls.Load() != 3 {
				t.Fatal("name-only input did not invoke bounded research searches", searchCalls.Load())
			}
			if result.Verification.ImpactConfirmed {
				t.Fatal("HTTP evidence promoted to impact")
			}
			if revoke {
				if calls.Load() != 1 || result.Verification.Stages[0].Status == "evidence_observed" {
					t.Fatalf("revoked source still queried: %d %s", calls.Load(), done.Result)
				}
				return
			}
			if calls.Load() != 2 || result.Verification.Stages[0].Status != "evidence_observed" || result.Verification.Stages[1].Status != "insufficient_data" {
				t.Fatalf("evidence/impact separation lost: calls %d %s", calls.Load(), done.Result)
			}
			if result.Investigation.Usage.RemoteQueries != 2 || result.Investigation.Usage.ModelCalls != 7 {
				t.Fatalf("cumulative budget lost: %+v", result.Investigation.Usage)
			}
			found := false
			for _, event := range done.Events {
				if event.Kind == "evidence_collection" {
					var proof investigationQueryProof
					_ = json.Unmarshal(event.Payload, &proof)
					for _, file := range proof.Collection.Files {
						if file.Name == "splunk-export.jsonl" && file.Content == remoteBody {
							found = true
						}
					}
				}
			}
			if !found {
				t.Fatal("exact query response was not preserved")
			}
			preview := request("GET", fmt.Sprintf("/api/defensive/hunts/%d", done.ID), "")
			if preview.Code != 200 || strings.Contains(preview.Body.String(), `"content":"{`) {
				t.Fatal("preview file contents leak", preview.Code)
			}
			exported := request("GET", fmt.Sprintf("/api/defensive/hunts/%d/export", done.ID), "")
			if exported.Code != 200 || exported.Header().Get("Content-Disposition") == "" || strings.Contains(exported.Body.String(), token) {
				t.Fatal("export failed or secret leaked", exported.Code)
			}
		})
	}
}
func TestHuntRoutesRequireAuthentication(t *testing.T) {
	s := &Server{jwtKey: []byte("fixture-key")}
	for _, route := range []struct{ method, path string }{{"GET", "/api/defensive/hunts"}, {"POST", "/api/defensive/hunts"}, {"GET", "/api/defensive/hunts/trends"}, {"POST", "/api/defensive/hunts/trends/collect"}, {"GET", "/api/defensive/hunts/1"}, {"GET", "/api/defensive/hunts/1/export"}, {"POST", "/api/defensive/hunts/1/cancel"}} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`)))
		if w.Code != 401 {
			t.Fatal(route, w.Code)
		}
	}
}
func TestHuntProviderBudgetSpansStagesAndFailures(t *testing.T) {
	base := &huntScriptProvider{}
	base.design.Store(true)
	p := &huntProvider{base: base}
	for i := 0; i < huntProviderMaxCalls; i++ {
		_, _, _, _ = p.Complete(t.Context(), llm.CompletionRequest{MaxTokens: 1})
	}
	before, _, _ := p.snapshot()
	_, _, _, err := p.Complete(t.Context(), llm.CompletionRequest{MaxTokens: 1})
	after, _, _ := p.snapshot()
	if err == nil || before != huntProviderMaxCalls || after != huntProviderMaxCalls || !p.exhausted() {
		t.Fatal("paid call cap reset", before, after, err)
	}
}

func TestHuntProviderBudgetCarriesEvidenceAcrossStages(t *testing.T) {
	p := &huntProvider{}
	req := llm.CompletionRequest{Messages: []llm.Message{{Role: llm.RoleUser, Content: []llm.ContentBlock{llm.TextBlock(strings.Repeat("x", 32<<10))}}}, MaxTokens: 2048}
	for i := 0; i < 12; i++ {
		if err := p.reserve(&req); err != nil {
			t.Fatalf("bounded multi-stage context rejected at call %d: %v", i+1, err)
		}
	}
	if calls, _, _ := p.snapshot(); calls != 12 || p.reserved > huntProviderReservedBytes {
		t.Fatalf("shared budget not bounded: calls=%d reserved=%d", calls, p.reserved)
	}
}

func TestHuntAdmissionScopeIdempotencyAndEarlyCancellation(t *testing.T) {
	s, request := defensiveAPIFixture(t)
	s.m.webSearchOn = true
	researchStarted := make(chan struct{})
	s.huntResearch = &hunting.Researcher{Search: func(ctx context.Context, _ string) ([]string, error) {
		select {
		case <-researchStarted:
		default:
			close(researchStarted)
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	p := &huntScriptProvider{}
	s.llmOn = true
	s.llmProv = p
	cipher, err := s.encryptSourceCredentials(securitysource.Credentials{Token: "admission-test-only"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := securitysource.Config{BaseURL: "https://splunk.example.com:8089", Index: "authorized", AuditSourcetype: "web", AlertSourcetype: "alerts", CorrelationField: "artex_verification_id", ActionField: "action"}
	source, err := s.m.pg.SaveSecuritySource(t.Context(), 0, 0, "admission fixture", cfg, true, cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM security_sources WHERE id=$1`, source.ID) })
	in := huntRequest{Request: hunting.Request{Term: "php2shell", SourceID: source.ID, ExpectedSourceRevision: source.Revision, Scope: investigation.Scope{Target: "fixture.lab", Start: time.Now().UTC().Add(-time.Hour), End: time.Now().UTC().Add(-time.Minute)}, Mapping: investigation.DefaultMapping(), Sourcetypes: []string{"web"}}}
	raw, _ := json.Marshal(in)
	if w := request("POST", "/api/defensive/hunts", string(raw)); w.Code != 400 {
		t.Fatal("scope confirmation bypass", w.Code)
	}
	in.ScopeConfirmed = true
	in.ExpectedSourceRevision++
	raw, _ = json.Marshal(in)
	if w := request("POST", "/api/defensive/hunts", string(raw)); w.Code != 409 {
		t.Fatal("stale revision admitted", w.Code)
	}
	in.ExpectedSourceRevision = source.Revision
	in.Sourcetypes = []string{"unconfigured"}
	raw, _ = json.Marshal(in)
	if w := request("POST", "/api/defensive/hunts", string(raw)); w.Code != 400 {
		t.Fatal("unconfigured stream admitted", w.Code)
	}
	in.Sourcetypes = []string{"web"}
	raw, _ = json.Marshal(in)
	w := request("POST", "/api/defensive/hunts", string(raw))
	if w.Code != 202 {
		t.Fatal(w.Code, w.Body.String())
	}
	var h db.Hunt
	_ = json.Unmarshal(w.Body.Bytes(), &h)
	t.Cleanup(func() { s.m.pg.Exec(`DELETE FROM defensive_hunts WHERE id=$1`, h.ID) })
	select {
	case <-researchStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("research not started")
	}
	w = request("POST", "/api/defensive/hunts", string(raw))
	var duplicate db.Hunt
	_ = json.Unmarshal(w.Body.Bytes(), &duplicate)
	if w.Code != 202 || duplicate.ID != h.ID {
		t.Fatal("duplicate research admitted", w.Code, w.Body.String())
	}
	w = request("POST", fmt.Sprintf("/api/defensive/hunts/%d/cancel", h.ID), "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		s.huntMu.Lock()
		active := len(s.huntCancel)
		s.huntMu.Unlock()
		if active == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancel did not stop research")
		}
		time.Sleep(5 * time.Millisecond)
	}
	sealed, err := s.m.pg.GetHunt(t.Context(), h.ID)
	if err != nil || sealed.Status != "cancelled" || p.design.Load() {
		t.Fatal("cancel lost or paid generation continued", sealed, err)
	}
}

type huntCaptureProvider struct {
	base         llm.Provider
	requestBytes int
}

func (p *huntCaptureProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	raw, _ := json.Marshal(req)
	p.requestBytes = len(raw)
	return p.base.Complete(ctx, req)
}
func (p *huntCaptureProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return p.base.Stream(ctx, req)
}
func TestHuntLargeLiteratureUsesBoundedModelViewWithoutChangingEvidence(t *testing.T) {
	research := hunting.Research{Term: "php2shell", Summary: "제품·조건·복수 CVE는 각각 확인해야 합니다", CVEs: []string{"CVE-2026-109618", "CVE-2026-109619"}}
	excerpt := strings.Repeat("PHP2Shell 문헌의 영향 조건을 확인합니다. ", 250)
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("source-%d", i)
		sum := sha256.Sum256([]byte(excerpt))
		research.Sources = append(research.Sources, hunting.ResearchSource{ID: id, URL: fmt.Sprintf("https://research.example.com/%d", i), Title: "문헌 발췌", Excerpt: excerpt, SHA256: hex.EncodeToString(sum[:]), FetchedAt: time.Now().UTC()})
		research.Claims = append(research.Claims, hunting.ResearchClaim{Text: "문헌 주장만으로 실제 침해를 확정하지 않습니다", SourceIDs: []string{id}})
	}
	capture := &huntCaptureProvider{base: &huntScriptProvider{}}
	p := &huntProvider{base: capture}
	_, err := generateHuntDesign(t.Context(), p, hunting.Request{Term: "php2shell", Mapping: investigation.DefaultMapping()}, research)
	if err != nil || capture.requestBytes > 64000 || capture.requestBytes < 10000 || p.exhausted() {
		t.Fatal("valid long literature cannot reach designer", capture.requestBytes, err)
	}
	if research.Sources[0].Excerpt != excerpt || research.Sources[7].Excerpt != excerpt {
		t.Fatal("model projection changed archived source text")
	}
}

func TestHuntModelViewRetainsIdentifiedCVEsBeyondNavigation(t *testing.T) {
	raw := strings.Repeat("일반 사이트 안내 ", 500) + "CVE-2026-109618: prerequisite condition A. " + strings.Repeat("background ", 250) + "CVE-2026-109619: distinct prerequisite condition B. " + strings.Repeat("footer ", 500)
	view := huntResearchView(raw, []string{"CVE-2026-109618", "CVE-2026-109619"})
	if len(view) > 3000 || !strings.Contains(view, "CVE-2026-109618") || !strings.Contains(view, "CVE-2026-109619") || !strings.Contains(view, "distinct prerequisite") {
		t.Fatal("model view lost identity/conditions", len(view), view)
	}
}
