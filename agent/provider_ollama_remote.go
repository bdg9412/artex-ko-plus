package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"sync"
	"time"

	"github.com/Autumn-27/artex/ollamaendpoint"
	"github.com/Autumn-27/norma/llm"
)

func (c Config) ValidateRemoteOllama() error {
	if _, err := ollamaendpoint.NormalizeURL(c.BaseURL); err != nil {
		return err
	}
	if err := c.OllamaRemote.Validate(); err != nil {
		return err
	}
	if c.OllamaRemote.Resolved().AuthMode == "bearer" && c.APIKey == "" {
		return fmt.Errorf("remote Ollama Bearer token is required")
	}
	return nil
}

func (c Config) ollamaBearerToken() string {
	if c.IsRemoteOllama() && c.OllamaRemote.Resolved().AuthMode == "bearer" {
		return c.APIKey
	}
	return ""
}

func noOllamaRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

type ollamaAuthTransport struct {
	base  http.RoundTripper
	token string
}

func (t ollamaAuthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Del("Authorization")
	r.Header.Del("X-Api-Key")
	if t.token != "" {
		r.Header.Set("Authorization", "Bearer "+t.token)
	}
	return t.base.RoundTrip(r)
}

// OllamaHTTPClient is shared by explicit metadata checks and the automatic
// context preflight. It uses the same endpoint authentication as inference,
// without recording metadata as a model response or following redirects.
func OllamaHTTPClient(c Config) (*http.Client, error) {
	if !c.IsOllama() {
		return nil, fmt.Errorf("Ollama profile required")
	}
	if c.IsRemoteOllama() {
		if err := c.ValidateRemoteOllama(); err != nil {
			return nil, err
		}
	}
	client, err := quotaAwareHTTPClient(c.Proxy, "")
	if err != nil {
		return nil, err
	}
	base := client.Transport.(quotaAwareTransport).base
	return &http.Client{Transport: ollamaAuthTransport{base: base, token: c.ollamaBearerToken()}, CheckRedirect: noOllamaRedirect, Timeout: 30 * time.Second}, nil
}

type OllamaStatus struct {
	CheckedAt      time.Time `json:"checked_at"`
	Reachable      bool      `json:"reachable"`
	ModelAvailable bool      `json:"model_available"`
	ModelLoaded    bool      `json:"model_loaded"`
	RunningKnown   bool      `json:"running_known"`
	ContextTokens  int       `json:"context_tokens,omitempty"`
	Models         []string  `json:"models"`
}

// CheckOllamaStatus never generates text, pulls a model, or changes load state.
func CheckOllamaStatus(ctx context.Context, c Config) (OllamaStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	status := OllamaStatus{CheckedAt: time.Now().UTC(), Models: []string{}}
	client, err := OllamaHTTPClient(c)
	if err != nil {
		return status, err
	}
	baseURL := c.BaseURL
	if c.IsRemoteOllama() {
		baseURL, _ = ollamaendpoint.NormalizeURL(baseURL)
	}
	base, ok := ollamaNativeAPIBase(baseURL)
	if !ok {
		return status, fmt.Errorf("Ollama URL must end with /v1")
	}
	read := func(path string, into any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("Ollama %s: HTTP %d", path, resp.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, ollamaProbeBodyLimit)).Decode(into)
	}
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := read("/api/tags", &tags); err != nil {
		return status, err
	}
	status.Reachable = true
	for _, m := range tags.Models {
		status.Models = append(status.Models, m.Name)
		if sameOllamaModel(m.Name, c.Model) {
			status.ModelAvailable = true
		}
	}
	var running struct {
		Models []struct {
			Name          string `json:"name"`
			Model         string `json:"model"`
			ContextLength int    `json:"context_length"`
		} `json:"models"`
	}
	if err := read("/api/ps", &running); err == nil {
		status.RunningKnown = true
		for _, m := range running.Models {
			if sameOllamaModel(m.Name, c.Model) || sameOllamaModel(m.Model, c.Model) {
				status.ModelLoaded, status.ContextTokens = true, m.ContextLength
			}
		}
	}
	return status, nil
}

// A process-wide gate is keyed by server URL, not by model/profile, so separate
// agents and profiles cannot each consume an independent GPU concurrency limit.
var remoteOllamaGates = struct {
	sync.Mutex
	servers map[string]*remoteOllamaGate
}{servers: make(map[string]*remoteOllamaGate)}

type remoteOllamaTicket struct{ limit int }
type remoteOllamaGate struct {
	mu      sync.Mutex
	active  map[*remoteOllamaTicket]bool
	waiting []*remoteOllamaTicket
	changed chan struct{}
}

func (g *remoteOllamaGate) signal() { close(g.changed); g.changed = make(chan struct{}) }
func (g *remoteOllamaGate) acquire(ctx context.Context, limit int) (func(), error) {
	ticket := &remoteOllamaTicket{limit: limit}
	g.mu.Lock()
	g.waiting = append(g.waiting, ticket)
	for {
		if err := ctx.Err(); err != nil {
			for i, t := range g.waiting {
				if t == ticket {
					g.waiting = append(g.waiting[:i], g.waiting[i+1:]...)
					break
				}
			}
			g.signal()
			g.mu.Unlock()
			return nil, fmt.Errorf("remote Ollama queue: %w", err)
		}
		capacity := limit
		for t := range g.active {
			if t.limit < capacity {
				capacity = t.limit
			}
		}
		if g.waiting[0] == ticket && len(g.active) < capacity {
			g.waiting = g.waiting[1:]
			g.active[ticket] = true
			g.signal()
			g.mu.Unlock()
			var once sync.Once
			return func() { once.Do(func() { g.mu.Lock(); delete(g.active, ticket); g.signal(); g.mu.Unlock() }) }, nil
		}
		changed := g.changed
		g.mu.Unlock()
		select {
		case <-ctx.Done():
		case <-changed:
		}
		g.mu.Lock()
	}
}

type remoteOllamaProvider struct {
	llm.Provider
	gate    *remoteOllamaGate
	options ollamaendpoint.Options
}

func newRemoteOllamaProvider(p llm.Provider, c Config) llm.Provider {
	key, _ := ollamaendpoint.NormalizeURL(c.BaseURL)
	remoteOllamaGates.Lock()
	gate := remoteOllamaGates.servers[key]
	if gate == nil {
		gate = &remoteOllamaGate{active: make(map[*remoteOllamaTicket]bool), changed: make(chan struct{})}
		remoteOllamaGates.servers[key] = gate
	}
	remoteOllamaGates.Unlock()
	return &remoteOllamaProvider{Provider: p, gate: gate, options: c.OllamaRemote.Resolved()}
}
func (p *remoteOllamaProvider) begin(ctx context.Context) (context.Context, func(), error) {
	wait, cancelWait := context.WithTimeout(ctx, time.Duration(p.options.QueueTimeoutSeconds)*time.Second)
	release, err := p.gate.acquire(wait, p.options.MaxConcurrent)
	cancelWait()
	if err != nil {
		return nil, nil, err
	}
	call, cancel := context.WithTimeout(ctx, time.Duration(p.options.RequestTimeoutSeconds)*time.Second)
	return call, func() { cancel(); release() }, nil
}
func (p *remoteOllamaProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	ctx, finish, err := p.begin(ctx)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	defer finish()
	return p.Provider.Complete(ctx, req)
}
func (p *remoteOllamaProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		ctx, finish, err := p.begin(ctx)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		defer finish()
		for event, err := range p.Provider.Stream(ctx, req) {
			if !yield(event, err) {
				return
			}
		}
	}
}
