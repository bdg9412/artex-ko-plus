package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/securitysource"
	"github.com/Autumn-27/norma/llm"
)

// These responses exercise the real planner/worker harness and server callback;
// neither the model provider nor the Splunk endpoint makes an external call.
type investigationSplunkRunProvider struct {
	calls        atomic.Int32
	beforeSearch func() error
	revoked      bool
	ref          string
}

func (p *investigationSplunkRunProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if err := ctx.Err(); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	n := p.calls.Add(1)
	tool, input := "", ""
	switch n {
	case 1:
		tool, input = "plan_investigation", `{"action":"investigate","reason":"추가 원본 로그를 확인합니다.","hypothesis":"공개 파일에 대한 후속 접근이 있을 수 있습니다.","objective":"지정한 출발지의 후속 파일 요청을 확인합니다."}`
	case 2:
	case 3:
		if p.beforeSearch != nil {
			if err := p.beforeSearch(); err != nil {
				return llm.Message{}, "", llm.Usage{}, err
			}
		}
		tool, input = "search_evidence", `{"remote":true,"source_ip":"192.0.2.44","path_contains":"followup.txt"}`
	case 4:
		if p.revoked {
			tool, input = "record_observation", `{"kind":"insufficient_data","summary":"연결 설정 변경으로 후속 로그를 조회하지 못했습니다.","next_steps":["최신 연결로 로그 근거를 다시 준비하세요."]}`
		} else {
			body, err := json.Marshal(req.Messages)
			if err != nil {
				return llm.Message{}, "", llm.Usage{}, err
			}
			var value any
			if err = json.Unmarshal(body, &value); err != nil {
				return llm.Message{}, "", llm.Usage{}, err
			}
			p.ref = investigationSplunkRunRef(value)
			if p.ref == "" {
				return llm.Message{}, "", llm.Usage{}, fmt.Errorf("remote event missing from worker search result")
			}
			tool, input = "read_evidence", fmt.Sprintf(`{"refs":[%q]}`, p.ref)
		}
	case 5:
		if !p.revoked {
			body, _ := json.Marshal(req.Messages)
			if !strings.Contains(string(body), "original-remote-evidence-marker") {
				return llm.Message{}, "", llm.Usage{}, fmt.Errorf("worker did not read original remote event")
			}
			tool, input = "record_observation", fmt.Sprintf(`{"kind":"observed","summary":"지정한 출발지의 파일 요청이 기록되었습니다. 실제 내용 탈취 여부는 확인되지 않습니다.","evidence_refs":[%q],"alternatives":["승인된 정상 접근일 수 있습니다."],"next_steps":["인증 기록을 대조하세요."]}`, p.ref)
		}
	case 6:
		if p.revoked {
			tool, input = "plan_investigation", `{"action":"insufficient_data","reason":"연결 변경으로 후속 로그 확인을 완료하지 못했습니다.","needed_logs":["최신 연결에서 다시 수집한 원본 로그"]}`
		}
	case 7:
		if !p.revoked {
			tool, input = "plan_investigation", fmt.Sprintf(`{"action":"complete","reason":"허용된 범위의 후속 접근을 원본으로 확인했습니다.","evidence_refs":[%q]}`, p.ref)
		}
	case 8:
		if p.revoked {
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("unexpected revoked-provider call")
		}
	default:
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("unexpected provider call %d", n)
	}
	usage := llm.Usage{InputTokens: 12, OutputTokens: 8}
	if tool == "" {
		return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("단계를 마쳤습니다.")}}, "end_turn", usage, nil
	}
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{{Type: llm.BlockToolUse, ID: fmt.Sprintf("remote-step-%d", n), Name: tool, Input: json.RawMessage(input)}}}, "tool_use", usage, nil
}
func (p *investigationSplunkRunProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{}, fmt.Errorf("test provider requires non-streaming configuration"))
	}
}

// Tool outputs are JSON strings nested inside provider message content. Recover
// only the actual returned event ref rather than inventing a citation in tests.
func investigationSplunkRunRef(value any) string {
	switch v := value.(type) {
	case map[string]any:
		if v["id"] == "remote-followup" {
			if ref, ok := v["ref"].(string); ok {
				return ref
			}
		}
		for _, child := range v {
			if ref := investigationSplunkRunRef(child); ref != "" {
				return ref
			}
		}
	case []any:
		for _, child := range v {
			if ref := investigationSplunkRunRef(child); ref != "" {
				return ref
			}
		}
	case string:
		var nested any
		if len(v) > 0 && (v[0] == '{' || v[0] == '[') && json.Unmarshal([]byte(v), &nested) == nil {
			return investigationSplunkRunRef(nested)
		}
	}
	return ""
}

func TestInvestigationRunSplunkCallbackEvidenceAndRevision(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprintf("revision_changed_%t", revoke), func(t *testing.T) {
			s, seed, request, _ := investigationRunFixture(t)
			in := investigationAPIInput(t, s, seed.FindingID)
			var calls atomic.Int32
			const token = "test-only-investigation-run-token"
			remoteBody := fmt.Sprintf(`{"preview":false,"lastrow":true,"result":{"_time":%q,"id":"remote-followup","target":"app.example","path":"/ftp/followup.txt","source_ip":"192.0.2.44","message":"original-remote-evidence-marker","large_value":9007199254740993}}`+"\n", in.Scope.Start.Add(2*time.Minute).Format(time.RFC3339Nano))
			endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if r.Method != "POST" || r.URL.Path != "/services/search/v2/jobs/export" {
					t.Errorf("unexpected writable or non-export endpoint: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("missing saved encrypted credential")
				}
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					return
				}
				query := r.FormValue("search")
				for _, part := range []string{`index="test_index"`, `sourcetype="web"`, `app\\.example`, `"/ftp"`} {
					if !strings.Contains(query, part) {
						t.Errorf("query missing authorized scope %q: %s", part, query)
					}
				}
				if strings.Contains(query, `sourcetype="alerts"`) || strings.Contains(query, "delete") {
					t.Errorf("query broadened source or became writable: %s", query)
				}
				for key, value := range map[string]string{"earliest_time": fmt.Sprintf("%d.%09d", in.Scope.Start.Unix(), in.Scope.Start.Nanosecond()), "latest_time": fmt.Sprintf("%d.%09d", in.Scope.End.Unix(), in.Scope.End.Nanosecond()), "preview": "false"} {
					if r.FormValue(key) != value {
						t.Errorf("wrong %s: %s", key, r.FormValue(key))
					}
				}
				if n == 1 {
					fmt.Fprintf(w, `{"preview":false,"lastrow":true,"result":{"_time":%q,"id":"seed-splunk","target":"app.example","path":"/ftp/initial.txt"}}`+"\n", in.Scope.Start.Add(time.Minute).Format(time.RFC3339Nano))
					return
				}
				if n != 2 {
					t.Errorf("unbounded remote calls: %d", n)
				}
				if !strings.Contains(query, `tostring('source_ip') = "192.0.2.44"`) || !strings.Contains(query, `followup\\.txt`) {
					t.Errorf("missing literal follow-up filters: %s", query)
				}
				fmt.Fprint(w, remoteBody)
			}))
			defer endpoint.Close()
			pin := sha256.Sum256(endpoint.Certificate().Raw)
			cfg := securitysource.Config{BaseURL: endpoint.URL, Index: "test_index", AuditSourcetype: "web", AlertSourcetype: "alerts", CorrelationField: "artex_verification_id", ActionField: "action", TLSFingerprint: hex.EncodeToString(pin[:])}
			cipher, err := s.encryptSourceCredentials(securitysource.Credentials{Token: token})
			if err != nil {
				t.Fatal(err)
			}
			source, err := s.m.pg.SaveSecuritySource(t.Context(), 0, 0, "mocked investigation source", cfg, true, cipher)
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
			basePath := fmt.Sprintf("/api/exploration/findings/%d/investigations", seed.FindingID)
			w := request("POST", basePath, string(raw))
			if w.Code != 201 {
				t.Fatal(w.Code, w.Body.String())
			}
			var base db.FindingInvestigation
			if err = json.Unmarshal(w.Body.Bytes(), &base); err != nil {
				t.Fatal(err)
			}
			p := &investigationSplunkRunProvider{revoked: revoke}
			if revoke {
				p.beforeSearch = func() error {
					_, err := s.m.pg.SaveSecuritySource(t.Context(), source.ID, source.Revision, "changed during active run", cfg, true, nil)
					return err
				}
			}
			s.llmProv = p
			s.llmOn = true
			s.llmCfg = agent.Config{Model: "local-scripted-mock", Stream: false}
			path := fmt.Sprintf("%s/%d/agent-runs", basePath, base.ID)
			w = request("POST", path, `{"question":"원격 후속 로그로 파일 요청을 확인하세요."}`)
			if w.Code != 202 {
				t.Fatal(w.Code, w.Body.String())
			}
			var started db.InvestigationRun
			if err = json.Unmarshal(w.Body.Bytes(), &started); err != nil {
				t.Fatal(err)
			}
			done := waitInvestigationRun(t, s, &started)
			var report agent.InvestigatorReport
			if err = json.Unmarshal(done.Result, &report); err != nil {
				t.Fatal(err)
			}
			proofs := []investigationQueryProof{}
			for _, event := range done.Events {
				if event.Kind == "evidence_collection" {
					var proof investigationQueryProof
					if err = json.Unmarshal(event.Payload, &proof); err != nil {
						t.Fatal(err)
					}
					proofs = append(proofs, proof)
				}
			}
			if revoke {
				if done.Status != "insufficient_data" || calls.Load() != 1 || len(proofs) != 0 || len(report.Observations) != 1 || report.Observations[0].Kind != "insufficient_data" {
					t.Fatalf("revoked source still queried or not recorded: status=%s calls=%d proofs=%d result=%s", done.Status, calls.Load(), len(proofs), done.Result)
				}
				return
			}
			if done.Status != "completed" || calls.Load() != 2 || len(proofs) != 1 || len(report.Observations) != 1 || report.Observations[0].Kind != "observed" || p.calls.Load() != 8 {
				t.Fatalf("server callback did not finish actual agent loop: status=%s calls=%d modelcalls=%d proofs=%d result=%s", done.Status, calls.Load(), p.calls.Load(), len(proofs), done.Result)
			}
			proof := proofs[0]
			if !proof.Search.Remote || proof.Search.SourceIP != "192.0.2.44" || len(proof.Collection.Events) != 1 || proof.Collection.Events[0].Ref != report.Observations[0].EvidenceRefs[0] || !strings.Contains(proof.Collection.Events[0].Raw, "9007199254740993") {
				t.Fatalf("remote evidence linkage/original numeric value lost: %+v", proof)
			}
			wantHash := sha256.Sum256([]byte(remoteBody))
			foundOriginal := false
			for _, file := range proof.Collection.Files {
				if file.Name == "splunk-export.jsonl" {
					foundOriginal = file.Content == remoteBody && file.SHA256 == hex.EncodeToString(wantHash[:])
				}
			}
			if !foundOriginal {
				t.Fatal("exact export stream and hash not preserved in evidence event")
			}
			w = request("GET", fmt.Sprintf("%s/%d", path, done.ID), "")
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body.String())
			}
			var preview db.InvestigationRun
			if err = json.Unmarshal(w.Body.Bytes(), &preview); err != nil {
				t.Fatal(err)
			}
			for _, event := range preview.Events {
				if event.Kind == "evidence_collection" {
					var item investigationQueryProof
					_ = json.Unmarshal(event.Payload, &item)
					for _, file := range item.Collection.Files {
						if file.Content != "" {
							t.Fatal("poll response leaked whole source file")
						}
					}
					if len(item.Collection.Events) != 1 || item.Collection.Events[0].Raw == "" || item.Collection.Query == "" {
						t.Fatal("poll response omitted citation raw or source query")
					}
				}
			}
			w = request("GET", fmt.Sprintf("%s/%d/export", path, done.ID), "")
			if w.Code != 200 || w.Header().Get("Content-Disposition") == "" {
				t.Fatal("export failed", w.Code)
			}
			if strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), "secret_cipher") || strings.Contains(w.Body.String(), string(cipher)) {
				t.Fatal("credential leaked into agent export")
			}
			var exported struct {
				Run db.InvestigationRun `json:"run"`
			}
			if err = json.Unmarshal(w.Body.Bytes(), &exported); err != nil {
				t.Fatal(err)
			}
			foundOriginal = false
			for _, event := range exported.Run.Events {
				if event.Kind == "evidence_collection" {
					var item investigationQueryProof
					_ = json.Unmarshal(event.Payload, &item)
					for _, file := range item.Collection.Files {
						if file.Name == "splunk-export.jsonl" && file.Content == remoteBody {
							foundOriginal = true
						}
					}
				}
			}
			if !foundOriginal {
				t.Fatal("download omitted full remote query proof")
			}
		})
	}
}
