package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
)

// TestConfigFromOpenAIResponses locks the openai-responses format wiring:
// ConfigFrom resolves the Responses format, strips a full /responses endpoint
// back to the API base, and Provider() round-trips the short name. NewProvider
// must build a working provider for it.
func TestConfigFromOpenAIResponses(t *testing.T) {
	c := ConfigFrom("openai-responses", "gpt-5", "https://gw.example/v1/responses", "sk-x", "")
	if c.Format != llm.FormatOpenAIResponses {
		t.Fatalf("format=%v, want FormatOpenAIResponses", c.Format)
	}
	if c.BaseURL != "https://gw.example/v1" {
		t.Fatalf("base_url=%q, want the /responses suffix stripped", c.BaseURL)
	}
	if c.Provider() != "openai-responses" {
		t.Fatalf("Provider()=%q", c.Provider())
	}
	if !c.Stream { // default streaming preserved
		t.Fatal("Stream should default true")
	}
	if _, err := c.NewProvider(); err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
}

func TestResponsesCyberAccessProgramWireOptIn(t *testing.T) {
	for _, tc := range []struct {
		name, program string
	}{
		{name: "default-off"},
		{name: "daybreak-blue", program: "daybreak_blue"},
		{name: "explicit-standard", program: "standard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wire []byte
			var path string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				path = r.URL.Path
				wire, _ = io.ReadAll(r.Body)
				w.WriteHeader(http.StatusBadRequest) // Test only the outgoing wire request.
				_, _ = io.WriteString(w, `{"error":{"message":"test endpoint"}}`)
			}))
			defer srv.Close()

			cfg := ConfigFrom("openai-responses", "gpt-6-sol", srv.URL+"/v1", "test-key", "")
			cfg.CyberAccessProgram = tc.program
			provider, err := cfg.NewProvider()
			if err != nil {
				t.Fatalf("NewProvider: %v", err)
			}
			ctx, capture := llmrec.NewCapture(context.Background())
			_, _, _, _ = provider.Complete(ctx, llm.CompletionRequest{
				Messages:  []llm.Message{{Role: "user", Content: []llm.ContentBlock{{Type: "text", Text: "ping"}}}},
				MaxTokens: 128,
			})
			if path != "/v1/responses" || len(wire) == 0 {
				t.Fatalf("request path=%q body=%q", path, wire)
			}
			if capture.RawRequest() != string(wire) {
				t.Fatal("capture must contain the exact outgoing request after Daybreak injection")
			}
			var body map[string]json.RawMessage
			if err := json.Unmarshal(wire, &body); err != nil {
				t.Fatalf("request JSON: %v", err)
			}
			programs, hasPrograms := body["access_programs"]
			if tc.program == "" {
				if hasPrograms {
					t.Fatalf("default-off request unexpectedly has access_programs: %s", programs)
				}
				return
			}
			if !hasPrograms {
				t.Fatal("explicit cyber selection missing access_programs")
			}
			var selection struct {
				Cyber string `json:"cyber"`
			}
			if err := json.Unmarshal(programs, &selection); err != nil || selection.Cyber != tc.program {
				t.Fatalf("access_programs=%s, err=%v", programs, err)
			}
		})
	}
}

func TestResponsesCyberAccessProgramStreamingWire(t *testing.T) {
	var wire []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":{"message":"test endpoint"}}`)
	}))
	defer srv.Close()

	cfg := ConfigFrom("openai-responses", "gpt-6-sol", srv.URL+"/v1", "test-key", "")
	cfg.CyberAccessProgram = "daybreak_blue"
	provider, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	for range provider.Stream(context.Background(), llm.CompletionRequest{
		Messages:  []llm.Message{{Role: "user", Content: []llm.ContentBlock{{Type: "text", Text: "ping"}}}},
		MaxTokens: 128,
	}) {
	}
	var body struct {
		AccessPrograms struct {
			Cyber string `json:"cyber"`
		} `json:"access_programs"`
	}
	if err := json.Unmarshal(wire, &body); err != nil || body.AccessPrograms.Cyber != "daybreak_blue" {
		t.Fatalf("stream request body=%s err=%v", wire, err)
	}
}

func TestCyberAccessProgramRejectsUnsupportedConfiguration(t *testing.T) {
	for _, tc := range []struct {
		provider, program string
	}{
		{provider: "openai-responses", program: "unknown"},
		{provider: "openai", program: "daybreak_blue"},
		{provider: "ollama", program: "daybreak_blue"},
	} {
		cfg := ConfigFrom(tc.provider, "model", "", "test-key", "")
		cfg.CyberAccessProgram = tc.program
		if _, err := cfg.NewProvider(); err == nil {
			t.Errorf("provider=%q program=%q: expected validation error", tc.provider, tc.program)
		}
	}
}

func TestCyberAccessProgramPreservesOtherResponseFields(t *testing.T) {
	const original = `{"model":"gpt-6-sol","input":"ping","access_programs":{"future_flag":"keep"}}`
	req, err := http.NewRequest(http.MethodPost, "https://example.test/v1/responses", strings.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	modified, err := withCyberAccessProgram(req.Clone(req.Context()), "daybreak_blue")
	if err != nil {
		t.Fatal(err)
	}
	if got := requestBodySnapshot(req); got != original {
		t.Fatalf("original request mutated: %q", got)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(requestBodySnapshot(modified)), &body); err != nil {
		t.Fatal(err)
	}
	if body["model"] != "gpt-6-sol" || body["input"] != "ping" {
		t.Fatalf("request fields were lost: %#v", body)
	}
	programs, ok := body["access_programs"].(map[string]any)
	if !ok || programs["future_flag"] != "keep" || programs["cyber"] != "daybreak_blue" {
		t.Fatalf("access_programs=%#v", body["access_programs"])
	}
	if modified.ContentLength != int64(len(requestBodySnapshot(modified))) {
		t.Fatal("rewritten request content length is stale")
	}
}
