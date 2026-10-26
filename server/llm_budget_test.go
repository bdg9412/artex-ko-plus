package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/llm"
)

func TestCheckOllamaContextBudget(t *testing.T) {
	t.Parallel()
	cfg := agent.Config{ProviderID: "ollama", ContextWindowK: 32}
	small := llm.CompletionRequest{
		System:    []string{"Follow the assigned intent."},
		Messages:  []llm.Message{llm.UserText("Inspect the authorized fixture.")},
		Tools:     []llm.ToolSchema{{Name: "read_fact", Description: "Read one fact", InputSchema: map[string]any{"type": "object"}}},
		MaxTokens: 4096,
	}
	if err := checkOllamaContextBudget(cfg, small); err != nil {
		t.Fatalf("small request rejected: %v", err)
	}
	// A substantial request below the 32K estimate must still pass. This guard
	// is for clear overflows, not an arbitrary low prompt-size limit.
	moderate := llm.CompletionRequest{Messages: []llm.Message{llm.UserText(strings.Repeat("a", 80000))}, MaxTokens: 4096}
	if err := checkOllamaContextBudget(cfg, moderate); err != nil {
		t.Fatalf("moderate request rejected: %v", err)
	}

	secret := "sensitive-value-must-not-appear"
	cases := []struct {
		name string
		req  llm.CompletionRequest
	}{
		{"system", llm.CompletionRequest{System: []string{strings.Repeat(secret, 5000)}, MaxTokens: 4096}},
		{"messages", llm.CompletionRequest{Messages: []llm.Message{llm.UserText(strings.Repeat(secret, 5000))}, MaxTokens: 4096}},
		{"tools", llm.CompletionRequest{Tools: []llm.ToolSchema{{Name: "lookup", Description: strings.Repeat(secret, 5000), InputSchema: map[string]any{"type": "object"}}}, MaxTokens: 4096}},
		{"output", llm.CompletionRequest{Messages: []llm.Message{llm.UserText("short")}, MaxTokens: 33000}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkOllamaContextBudget(cfg, tc.req)
			if err == nil || !strings.Contains(err.Error(), "context length budget exceeded") {
				t.Fatalf("expected clear budget error, got %v", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("budget error disclosed request content: %v", err)
			}
		})
	}
}

func TestCheckOllamaContextBudgetOnlyAppliesToOllama(t *testing.T) {
	t.Parallel()
	large := llm.CompletionRequest{Messages: []llm.Message{llm.UserText(strings.Repeat("large", 100000))}}
	if err := checkOllamaContextBudget(agent.Config{ProviderID: "openai", ContextWindowK: 32}, large); err != nil {
		t.Fatalf("non-Ollama request was rejected: %v", err)
	}
}
