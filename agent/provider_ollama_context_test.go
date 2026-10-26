package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestOllamaContextPreflightPrefersLoadedContext(t *testing.T) {
	var completions, shows atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[{"name":"artex-qwen3:32k","context_length":4096}]}`))
		case "/api/show":
			shows.Add(1)
			_, _ = w.Write([]byte(`{"parameters":"num_ctx 32768"}`))
		case "/v1/chat/completions":
			completions.Add(1)
			writeOllamaTestCompletion(w)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newOllamaTestProvider(t, srv.URL, "artex-qwen3:32k")
	for range 2 {
		_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}, MaxTokens: 64})
		var mismatch *OllamaContextMismatchError
		if !errors.As(err, &mismatch) {
			t.Fatalf("expected OllamaContextMismatchError, got %v", err)
		}
		if mismatch.ModelTokens != 4096 || mismatch.ConfiguredTokens != 32000 || mismatch.Source != "/api/ps context_length" {
			t.Fatalf("unexpected mismatch: %+v", mismatch)
		}
	}
	if completions.Load() != 0 || shows.Load() != 0 {
		t.Fatalf("mismatch must stop model call and prefer /api/ps: completions=%d shows=%d", completions.Load(), shows.Load())
	}
}

func TestOllamaContextPreflightUsesModelNumCtxWhenNotLoaded(t *testing.T) {
	var completions atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		case "/api/show":
			_, _ = w.Write([]byte(`{"parameters":"temperature 0.7\nnum_ctx 4096"}`))
		case "/v1/chat/completions":
			completions.Add(1)
			writeOllamaTestCompletion(w)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newOllamaTestProvider(t, srv.URL, "deepseek-r1:8b")
	_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}, MaxTokens: 64})
	var mismatch *OllamaContextMismatchError
	if !errors.As(err, &mismatch) || mismatch.Source != "/api/show parameters num_ctx" || mismatch.ModelTokens != 4096 {
		t.Fatalf("expected configured num_ctx mismatch, got %v", err)
	}
	if completions.Load() != 0 {
		t.Fatalf("model was called despite context mismatch: %d", completions.Load())
	}
}

func TestOllamaContextPreflightAllowsMatchingAlias(t *testing.T) {
	var completions atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[{"name":"other:latest","context_length":4096}]}`))
		case "/api/show":
			_, _ = w.Write([]byte(`{"parameters":"num_ctx 32768"}`))
		case "/v1/chat/completions":
			completions.Add(1)
			writeOllamaTestCompletion(w)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newOllamaTestProvider(t, srv.URL, "artex-qwen3:32k")
	msg, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}, MaxTokens: 64})
	if err != nil || msg.Text() != "OK" || completions.Load() != 1 {
		t.Fatalf("matching alias must call model: reply=%q err=%v calls=%d", msg.Text(), err, completions.Load())
	}
}

func TestOllamaContextPreflightUnknownMetadataPreservesExistingEndpoint(t *testing.T) {
	var probes, completions atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ps", "/api/show":
			probes.Add(1)
			http.NotFound(w, r)
		case "/v1/chat/completions":
			completions.Add(1)
			writeOllamaTestCompletion(w)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newOllamaTestProvider(t, srv.URL, "artex-qwen3:32k")
	for range 2 {
		_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}, MaxTokens: 64})
		if err != nil {
			t.Fatalf("unavailable metadata must not block existing endpoint: %v", err)
		}
	}
	if probes.Load() != 2 || completions.Load() != 2 {
		t.Fatalf("unexpected probe/cache or model counts: probes=%d completions=%d", probes.Load(), completions.Load())
	}
}

func TestOllamaContextPreflightBlocksStreamingCall(t *testing.T) {
	var completions atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[{"name":"artex-qwen3:32k:latest","context_length":4096}]}`))
		case "/api/show":
			_, _ = w.Write([]byte(`{"parameters":"num_ctx 4096"}`))
		case "/v1/chat/completions":
			completions.Add(1)
			writeOllamaTestCompletion(w)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	p := newOllamaTestProvider(t, srv.URL, "artex-qwen3:32k")
	var got error
	for _, err := range p.Stream(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}, MaxTokens: 64}) {
		got = err
	}
	var mismatch *OllamaContextMismatchError
	if !errors.As(got, &mismatch) || completions.Load() != 0 {
		t.Fatalf("streaming mismatch must stop before model call: err=%v calls=%d", got, completions.Load())
	}
}

func TestOllamaContextPreflightMatchesImplicitLatestTag(t *testing.T) {
	if !sameOllamaModel("qwen3:latest", "qwen3") || sameOllamaModel("other:latest", "qwen3") || sameOllamaModel("", "") {
		t.Fatal("Ollama model name matching is incorrect")
	}
}

func newOllamaTestProvider(t *testing.T, serverURL, model string) llm.Provider {
	t.Helper()
	cfg := ConfigFrom("ollama", model, serverURL+"/v1", "", "")
	p, err := cfg.NewProvider()
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

func writeOllamaTestCompletion(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"id":"chatcmpl-local","object":"chat.completion","created":1,"model":"artex-qwen3:32k","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
}

func TestOllamaContextMismatchMessageIsActionable(t *testing.T) {
	err := (&OllamaContextMismatchError{Model: "deepseek-r1:8b", Source: "/api/ps context_length", ModelTokens: 4096, ConfiguredTokens: 32000}).Error()
	for _, want := range []string{"context mismatch", "4096", "32000", "PARAMETER num_ctx", "ollama ps"} {
		if !strings.Contains(err, want) {
			t.Fatalf("missing %q from %q", want, err)
		}
	}
}
