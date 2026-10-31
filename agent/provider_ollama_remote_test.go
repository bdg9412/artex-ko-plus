package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/ollamaendpoint"
	"github.com/Autumn-27/norma/llm"
)

func TestRemoteOllamaUsesSameAuthForMetadataAndInference(t *testing.T) {
	for _, mode := range []string{"none", "bearer"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				want := ""
				if mode == "bearer" {
					want = "Bearer fixture-gateway-token"
				}
				if r.Header.Get("Authorization") != want || r.Header.Get("X-Api-Key") != "" {
					t.Errorf("wrong auth for %s", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/prefix/api/tags":
					_, _ = w.Write([]byte(`{"models":[{"name":"qwen3:8b"}]}`))
				case "/prefix/api/ps":
					_, _ = w.Write([]byte(`{"models":[{"name":"qwen3:8b","context_length":32768}]}`))
				case "/prefix/v1/chat/completions":
					calls.Add(1)
					writeOllamaTestCompletion(w)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()
			cfg := ConfigFrom(ollamaendpoint.Remote, "qwen3:8b", srv.URL+"/prefix/v1", "fixture-gateway-token", "")
			cfg.OllamaRemote.AuthMode = mode
			status, err := CheckOllamaStatus(context.Background(), cfg)
			if err != nil || !status.Reachable || !status.ModelAvailable || !status.ModelLoaded || status.ContextTokens != 32768 {
				t.Fatalf("status=%+v err=%v", status, err)
			}
			if calls.Load() != 0 {
				t.Fatal("status check invoked inference")
			}
			provider, err := cfg.NewProvider()
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, err = provider.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}, MaxTokens: 32})
			if err != nil || calls.Load() != 1 {
				t.Fatalf("inference count=%d err=%v", calls.Load(), err)
			}
			if cfg.Provider() != ollamaendpoint.Remote || cfg.CompactionWindow() != 32000 {
				t.Fatal("remote identity/context was lost")
			}
		})
	}
}

func TestRemoteOllamaRejectsMissingDestinationAndToken(t *testing.T) {
	cfg := ConfigFrom(ollamaendpoint.Remote, "qwen3:8b", "", "", "")
	if _, err := cfg.NewProvider(); err == nil {
		t.Fatal("remote mode fell back to localhost")
	}
	cfg.BaseURL = "https://model.example/v1"
	cfg.OllamaRemote.AuthMode = "bearer"
	if _, err := cfg.NewProvider(); err == nil {
		t.Fatal("missing Bearer token accepted")
	}
	t.Setenv("ARTEX_LLM_PROVIDER", ollamaendpoint.Remote)
	t.Setenv("ARTEX_LLM_BASE_URL", "https://model.example/v1")
	t.Setenv("OPENAI_API_KEY", "must-not-leak")
	t.Setenv("ARTEX_OLLAMA_REMOTE_TOKEN", "")
	fromEnv, ok := FromEnv()
	if !ok || fromEnv.APIKey != "" || fromEnv.Provider() != ollamaendpoint.Remote {
		t.Fatal("remote env reused cloud credentials")
	}
}

func TestRemoteOllamaStatusDoesNotFollowRedirectOrTrustInvalidTLS(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { leaked.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL+r.URL.Path, 307) }))
	defer redirect.Close()
	cfg := ConfigFrom(ollamaendpoint.Remote, "x", redirect.URL+"/v1", "token", "")
	cfg.OllamaRemote.AuthMode = "bearer"
	if _, err := CheckOllamaStatus(context.Background(), cfg); err == nil || leaked.Load() != 0 {
		t.Fatal("followed redirect")
	}
	tls := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS reached handler") }))
	defer tls.Close()
	cfg.BaseURL = tls.URL + "/v1"
	if _, err := CheckOllamaStatus(context.Background(), cfg); err == nil {
		t.Fatal("accepted untrusted certificate")
	}
}

type remoteBlockingProvider struct {
	llm.Provider
	entered chan struct{}
	release chan struct{}
}

func (p *remoteBlockingProvider) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.entered <- struct{}{}
	select {
	case <-ctx.Done():
		return llm.Message{}, "", llm.Usage{}, ctx.Err()
	case <-p.release:
		return llm.Message{}, "stop", llm.Usage{}, nil
	}
}
func (p *remoteBlockingProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.entered <- struct{}{}
		if !yield(llm.StreamEvent{}, nil) {
			return
		}
		<-ctx.Done()
	}
}

func TestRemoteOllamaProfilesShareQueueAndCancellationReleasesSlot(t *testing.T) {
	base := &remoteBlockingProvider{entered: make(chan struct{}, 4), release: make(chan struct{})}
	cfg := ConfigFrom(ollamaendpoint.Remote, "one", "http://queue-fixture.invalid:11434/v1", "", "")
	first := newRemoteOllamaProvider(base, cfg)
	cfg.Model = "two"
	second := newRemoteOllamaProvider(base, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, _, _, err := first.Complete(ctx, llm.CompletionRequest{}); done <- err }()
	<-base.entered
	waitCtx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	_, _, _, err := second.Complete(waitCtx, llm.CompletionRequest{})
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "queue") {
		t.Fatalf("expected queue timeout, got %v", err)
	}
	select {
	case <-base.entered:
		t.Fatal("second profile bypassed shared limit")
	default:
	}
	cancel()
	if !errors.Is(<-done, context.Canceled) {
		t.Fatal("request cancellation lost")
	}
	close(base.release)
	if _, _, _, err := second.Complete(context.Background(), llm.CompletionRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteOllamaGateFIFOAndConservativeMixedLimits(t *testing.T) {
	g := &remoteOllamaGate{active: make(map[*remoteOllamaTicket]bool), changed: make(chan struct{})}
	release, err := g.acquire(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = g.acquire(ctx, 8); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("higher limit bypassed active limit: %v", err)
	}
	release()
	release, err = g.acquire(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	release()
	release()
}

func TestRemoteOllamaStreamingBreakReleasesSlotAndHasDeadline(t *testing.T) {
	base := &remoteBlockingProvider{entered: make(chan struct{}, 2), release: make(chan struct{})}
	close(base.release)
	cfg := ConfigFrom(ollamaendpoint.Remote, "fixture", "http://stream-fixture.invalid/v1", "", "")
	cfg.OllamaRemote.RequestTimeoutSeconds = 5
	p := newRemoteOllamaProvider(base, cfg).(*remoteOllamaProvider)
	ctx, finish, err := p.begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 5*time.Second {
		t.Fatal("request timeout not applied")
	}
	finish()
	for range p.Stream(context.Background(), llm.CompletionRequest{}) {
		break
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, _, _, err = p.Complete(ctx, llm.CompletionRequest{}); err != nil {
		t.Fatalf("stream break leaked slot: %v", err)
	}
}

func TestRemoteOllamaStreamingPreservesToolsAndGatewayAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer streaming-fixture" {
			t.Error("missing streaming/metadata gateway auth")
		}
		if r.URL.Path != "/v1/chat/completions" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Stream bool              `json:"stream"`
			Tools  []json.RawMessage `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if !body.Stream || len(body.Tools) != 1 {
			t.Error("stream/tool request settings lost")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: "+`{"id":"fixture","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_fixture","type":"function","function":{"name":"inspect_fixture","arguments":"{}"}}]},"finish_reason":null}]}`+"\n\n")
		_, _ = io.WriteString(w, "data: "+`{"id":"fixture","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`+"\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()
	cfg := ConfigFrom(ollamaendpoint.Remote, "fixture", srv.URL+"/v1", "streaming-fixture", "")
	cfg.OllamaRemote.AuthMode = "bearer"
	p, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	sawTool := false
	for event, err := range p.Stream(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("inspect")}, Tools: []llm.ToolSchema{{Name: "inspect_fixture", InputSchema: map[string]any{"type": "object", "properties": map[string]any{}}}}, MaxTokens: 64}) {
		if err != nil {
			t.Fatal(err)
		}
		if event.Type == llm.SEToolUseStart && event.ToolName == "inspect_fixture" {
			sawTool = true
		}
	}
	if !sawTool {
		t.Fatal("streamed tool call was lost")
	}
}
