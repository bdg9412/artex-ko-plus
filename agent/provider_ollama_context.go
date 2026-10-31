package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// OllamaContextMismatchError means Ollama advertises a smaller context than
// ARTEX uses for session compaction. The source identifies whether the value is
// the loaded runner's effective context or the model's configured num_ctx.
type OllamaContextMismatchError struct {
	Model            string
	Source           string
	ModelTokens      int
	ConfiguredTokens int
}

func (e *OllamaContextMismatchError) Error() string {
	return fmt.Sprintf("ollama context mismatch: model %q %s=%d tokens, ARTEX context_window_k=%d (%d tokens); configure a model alias with PARAMETER num_ctx >= %d and verify it with ollama ps",
		e.Model, e.Source, e.ModelTokens, e.ConfiguredTokens/1000, e.ConfiguredTokens, e.ConfiguredTokens)
}

type ollamaContextObservation struct {
	tokens int
	source string
}

// ollamaContextProvider validates a known mismatch immediately before a model
// call. An inaccessible or unsupported metadata endpoint leaves the normal
// request path intact, which also keeps OpenAI-compatible Ollama test servers
// and gateway deployments usable.
type ollamaContextProvider struct {
	llm.Provider
	model      string
	baseURL    string
	wantTokens int
	client     *http.Client

	mu        sync.Mutex
	checkedAt time.Time
	observed  ollamaContextObservation
}

const (
	ollamaContextProbeTimeout = 2 * time.Second
	ollamaKnownContextTTL     = 30 * time.Second
	ollamaUnknownContextTTL   = 10 * time.Second
	ollamaProbeBodyLimit      = 1 << 20
)

func newOllamaContextProvider(base llm.Provider, cfg Config, llmClient *http.Client) llm.Provider {
	// The LLM transport also captures raw requests for audit. Metadata probes
	// are not model calls and must not overwrite those captures.
	probeTransport := llmClient.Transport
	if transport, ok := probeTransport.(quotaAwareTransport); ok {
		probeTransport = ollamaAuthTransport{base: transport.base, token: cfg.ollamaBearerToken()}
	}
	return &ollamaContextProvider{
		Provider:   base,
		model:      cfg.Model,
		baseURL:    cfg.BaseURL,
		wantTokens: cfg.CompactionWindow(),
		client: &http.Client{
			Transport: probeTransport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (p *ollamaContextProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if err := p.checkContext(ctx); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	return p.Provider.Complete(ctx, req)
}

func (p *ollamaContextProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if err := p.checkContext(ctx); err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		for event, err := range p.Provider.Stream(ctx, req) {
			if !yield(event, err) {
				return
			}
		}
	}
}

func (p *ollamaContextProvider) checkContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	ttl := ollamaKnownContextTTL
	if p.observed.tokens == 0 {
		ttl = ollamaUnknownContextTTL
	}
	if p.checkedAt.IsZero() || time.Since(p.checkedAt) >= ttl {
		probeCtx, cancel := context.WithTimeout(ctx, ollamaContextProbeTimeout)
		p.observed = p.probeContext(probeCtx)
		cancel()
		p.checkedAt = time.Now()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.observed.tokens > 0 && p.observed.tokens < p.wantTokens {
		return &OllamaContextMismatchError{
			Model: p.model, Source: p.observed.source,
			ModelTokens: p.observed.tokens, ConfiguredTokens: p.wantTokens,
		}
	}
	return nil
}

func (p *ollamaContextProvider) probeContext(ctx context.Context) ollamaContextObservation {
	apiBase, ok := ollamaNativeAPIBase(p.baseURL)
	if !ok {
		return ollamaContextObservation{}
	}
	if value := p.runningContext(ctx, apiBase); value.tokens > 0 {
		return value
	}
	return p.configuredContext(ctx, apiBase)
}

func ollamaNativeAPIBase(baseURL string) (string, bool) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	if !strings.HasSuffix(u.Path, "/v1") {
		return "", false
	}
	u.Path = strings.TrimSuffix(u.Path, "/v1")
	return strings.TrimRight(u.String(), "/"), true
}

func (p *ollamaContextProvider) runningContext(ctx context.Context, apiBase string) ollamaContextObservation {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/ps", nil)
	if err != nil {
		return ollamaContextObservation{}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return ollamaContextObservation{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ollamaContextObservation{}
	}
	var result struct {
		Models []struct {
			Name          string `json:"name"`
			Model         string `json:"model"`
			ContextLength int    `json:"context_length"`
		} `json:"models"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, ollamaProbeBodyLimit)).Decode(&result) != nil {
		return ollamaContextObservation{}
	}
	for _, item := range result.Models {
		if (sameOllamaModel(item.Name, p.model) || sameOllamaModel(item.Model, p.model)) && item.ContextLength > 0 {
			return ollamaContextObservation{tokens: item.ContextLength, source: "/api/ps context_length"}
		}
	}
	return ollamaContextObservation{}
}

func sameOllamaModel(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, ":latest"), strings.TrimSuffix(b, ":latest")) && a != "" && b != ""
}

func (p *ollamaContextProvider) configuredContext(ctx context.Context, apiBase string) ollamaContextObservation {
	body, _ := json.Marshal(struct {
		Model string `json:"model"`
	}{Model: p.model})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/show", bytes.NewReader(body))
	if err != nil {
		return ollamaContextObservation{}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return ollamaContextObservation{}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ollamaContextObservation{}
	}
	var result struct {
		Parameters string `json:"parameters"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, ollamaProbeBodyLimit)).Decode(&result) != nil {
		return ollamaContextObservation{}
	}
	var numCtx int
	for _, line := range strings.Split(result.Parameters, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "num_ctx" {
			continue
		}
		if value, err := strconv.Atoi(fields[1]); err == nil && value > 0 {
			numCtx = value
		}
	}
	if numCtx > 0 {
		return ollamaContextObservation{tokens: numCtx, source: "/api/show parameters num_ctx"}
	}
	return ollamaContextObservation{}
}
