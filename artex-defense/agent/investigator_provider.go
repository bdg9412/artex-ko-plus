package agent

import (
	"context"
	"encoding/json"
	"iter"
	"sync"

	"github.com/Autumn-27/norma/llm"
)

// Reserve a conservative UTF-8 byte/token envelope before every request, not
// just after usage arrives. This also bounds gateways that omit token usage.
// The model output cap is part of every request. No automatic retry is added by
// this wrapper; the caller's existing provider policy remains in effect.
type investigatorProvider struct {
	mu        sync.Mutex
	base      llm.Provider
	budget    InvestigatorBudget
	maxOutput int
	usage     InvestigatorUsage
	limit     bool
}

func (p *investigatorProvider) reserve(req *llm.CompletionRequest) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if req.MaxTokens <= 0 || req.MaxTokens > p.maxOutput {
		req.MaxTokens = p.maxOutput
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	reserved := len(b) + req.MaxTokens + 256
	if p.limit || len(b) > 64000 || p.usage.ModelCalls >= p.budget.MaxModelCalls || p.usage.ReservedTokens+reserved > p.budget.MaxTokens {
		p.limit = true
		return ErrInvestigationBudget
	}
	p.usage.ModelCalls++
	p.usage.ReservedTokens += reserved
	return nil
}
func (p *investigatorProvider) addUsage(u llm.Usage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.usage.InputTokens += u.InputTokens + u.CacheReadTokens + u.CacheWriteTokens
	p.usage.OutputTokens += u.OutputTokens
}
func (p *investigatorProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if err := ctx.Err(); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	if err := p.reserve(&req); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	m, stop, u, err := p.base.Complete(ctx, req)
	p.addUsage(u)
	return m, stop, u, err
}
func (p *investigatorProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if err := ctx.Err(); err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		if err := p.reserve(&req); err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		acc := llm.NewAccumulator()
		defer func() { p.addUsage(acc.Usage) }()
		for ev, err := range p.base.Stream(ctx, req) {
			if err == nil {
				acc.Add(ev)
			}
			if !yield(ev, err) {
				return
			}
		}
	}
}
func (p *investigatorProvider) snapshot() InvestigatorUsage {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.usage
}
func (p *investigatorProvider) exhausted() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.limit }
func (p *investigatorProvider) query() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.usage.Queries >= p.budget.MaxQueries {
		p.limit = true
		return ErrInvestigationBudget
	}
	p.usage.Queries++
	return nil
}
