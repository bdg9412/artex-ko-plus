package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestConfigFromOllamaUsesLocalOpenAIEndpointWithoutKey(t *testing.T) {
	c := ConfigFrom("ollama", "qwen3:8b", "http://127.0.0.1:11434/v1/chat/completions/", "real-old-key", "")
	if c.Provider() != "ollama" {
		t.Fatalf("provider=%q, want ollama", c.Provider())
	}
	if c.Format != llm.FormatOpenAI {
		t.Fatalf("format=%v, want OpenAI-compatible wire format", c.Format)
	}
	if c.BaseURL != "http://127.0.0.1:11434/v1" {
		t.Fatalf("base URL=%q, want normalized /v1 root", c.BaseURL)
	}
	if c.APIKey != "" {
		t.Fatalf("Ollama should ignore an old cloud API key, got %q", c.APIKey)
	}
	if got := c.CompactionWindow(); got != 32_000 {
		t.Fatalf("Ollama compaction window=%d, want 32000", got)
	}
	if _, err := c.NewProvider(); err != nil {
		t.Fatalf("NewProvider() with no key: %v", err)
	}
}

func TestFromEnvOllamaDoesNotRequireCloudCredentials(t *testing.T) {
	t.Setenv("ARTEX_LLM_PROVIDER", "ollama")
	t.Setenv("ARTEX_LLM_MODEL", "qwen3:8b")
	t.Setenv("ARTEX_LLM_BASE_URL", "http://127.0.0.1:11434/v1")
	t.Setenv("OPENAI_API_KEY", "unrelated-cloud-key")
	t.Setenv("ANTHROPIC_API_KEY", "")

	c, ok := FromEnv()
	if !ok {
		t.Fatal("explicit Ollama provider should work with no cloud credentials")
	}
	if c.Provider() != "ollama" || c.Model != "qwen3:8b" || c.BaseURL != "http://127.0.0.1:11434/v1" {
		t.Fatalf("unexpected environment config: provider=%q model=%q base=%q", c.Provider(), c.Model, c.BaseURL)
	}
	if c.APIKey != "" {
		t.Fatalf("Ollama must ignore cloud credentials, got %q", c.APIKey)
	}
}

func TestFromEnvOllamaDefaults(t *testing.T) {
	t.Setenv("ARTEX_LLM_PROVIDER", "ollama")
	t.Setenv("ARTEX_LLM_MODEL", "")
	t.Setenv("ARTEX_LLM_BASE_URL", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	c, ok := FromEnv()
	if !ok || c.Provider() != "ollama" || c.Model != "qwen3:8b" || c.BaseURL != "http://127.0.0.1:11434/v1" {
		t.Fatalf("unexpected defaults: ok=%v provider=%q model=%q base=%q", ok, c.Provider(), c.Model, c.BaseURL)
	}
}

func TestOllamaProviderCallsConfiguredLocalEndpoint(t *testing.T) {
	var gotPath, gotModel, gotAuth, gotAPIKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r) // this mock does not implement Ollama metadata APIs
			return
		}
		gotPath = r.URL.Path
		gotAuth, gotAPIKey = r.Header.Get("Authorization"), r.Header.Get("X-API-Key")
		var request struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		gotModel = request.Model
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-local","object":"chat.completion","created":1,"model":"qwen3:8b","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer srv.Close()

	c := ConfigFrom("ollama", "qwen3:8b", srv.URL+"/v1", "cloud-test-key", "")
	p, err := c.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	msg, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{
		Messages:  []llm.Message{llm.UserText("ping")},
		MaxTokens: 64,
	})
	if err != nil {
		t.Fatalf("Complete(): %v", err)
	}
	if gotPath != "/v1/chat/completions" || gotModel != "qwen3:8b" {
		t.Fatalf("request path=%q model=%q", gotPath, gotModel)
	}
	if gotAuth != "" || gotAPIKey != "" {
		t.Fatalf("local Ollama request unexpectedly has auth headers: Authorization=%q X-API-Key=%q", gotAuth, gotAPIKey)
	}
	if msg.Text() != "OK" {
		t.Fatalf("completion text=%q, want OK", msg.Text())
	}
}

func TestOllamaProviderStreamsFromLocalEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r) // this mock does not implement Ollama metadata APIs
			return
		}
		var request struct {
			Stream bool `json:"stream"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if !request.Stream {
			t.Error("streaming request did not set stream=true")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		frames := []string{
			`{"id":"chatcmpl-local","object":"chat.completion.chunk","created":1,"model":"qwen3:8b","choices":[{"index":0,"delta":{"role":"assistant","content":"OK"},"finish_reason":null}]}`,
			`{"id":"chatcmpl-local","object":"chat.completion.chunk","created":1,"model":"qwen3:8b","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
			`[DONE]`,
		}
		for _, frame := range frames {
			_, _ = io.WriteString(w, "data: "+frame+"\n\n")
		}
	}))
	defer srv.Close()

	p, err := ConfigFrom("ollama", "qwen3:8b", srv.URL+"/v1", "", "").NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	var reply strings.Builder
	for event, err := range p.Stream(context.Background(), llm.CompletionRequest{
		Messages:  []llm.Message{llm.UserText("ping")},
		MaxTokens: 64,
	}) {
		if err != nil {
			t.Fatalf("Stream(): %v", err)
		}
		if event.Type == llm.SETextDelta {
			reply.WriteString(event.Text)
		}
	}
	if reply.String() != "OK" {
		t.Fatalf("streamed text=%q, want OK", reply.String())
	}
}
