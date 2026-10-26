package agent

import (
	"context"
	"iter"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

func TestBedrockConfigUsesAnthropicMessagesEndpoint(t *testing.T) {
	tests := []struct {
		endpoint string
		base     string
	}{
		{"https://bedrock-runtime.us-east-1.amazonaws.com/anthropic/v1/messages/", "https://bedrock-runtime.us-east-1.amazonaws.com/anthropic"},
		{"https://bedrock-mantle.ap-northeast-2.api.aws/anthropic", "https://bedrock-mantle.ap-northeast-2.api.aws/anthropic"},
	}
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			c := ConfigFrom("bedrock", "us.anthropic.claude-sonnet-4-6", tt.endpoint, "bedrock-test-key", "")
			if c.Provider() != "bedrock" || c.Format != llm.FormatAnthropic || c.BaseURL != tt.base || c.MaxTokens != defaultBedrockMaxTokens {
				t.Fatalf("unexpected Bedrock config: provider=%q format=%q base=%q max=%d", c.Provider(), c.Format, c.BaseURL, c.MaxTokens)
			}
			provider, err := c.NewProvider()
			if err != nil {
				t.Fatalf("NewProvider: %v", err)
			}
			if _, ok := provider.(bedrockMaxTokensProvider); !ok {
				t.Fatalf("provider type %T does not enforce Bedrock max_tokens", provider)
			}
		})
	}
}

func TestBedrockRequiresAWSURLClaudeModelAndKey(t *testing.T) {
	tests := []struct {
		name, model, endpoint, key string
	}{
		{"missing endpoint", "anthropic.claude-sonnet-4-6", "", "key"},
		{"missing model", "", "https://bedrock-runtime.us-east-1.amazonaws.com/anthropic", "key"},
		{"missing key", "anthropic.claude-sonnet-4-6", "https://bedrock-runtime.us-east-1.amazonaws.com/anthropic", ""},
		{"non Claude model", "amazon.nova-pro-v1:0", "https://bedrock-runtime.us-east-1.amazonaws.com/anthropic", "key"},
		{"http endpoint", "anthropic.claude-sonnet-4-6", "http://bedrock-runtime.us-east-1.amazonaws.com/anthropic", "key"},
		{"lookalike host", "anthropic.claude-sonnet-4-6", "https://bedrock-runtime.us-east-1.amazonaws.com.evil.test/anthropic", "key"},
		{"user info", "anthropic.claude-sonnet-4-6", "https://user@bedrock-runtime.us-east-1.amazonaws.com/anthropic", "key"},
		{"unexpected path", "anthropic.claude-sonnet-4-6", "https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1", "key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ConfigFrom("bedrock", tt.model, tt.endpoint, tt.key, "")
			if _, err := c.NewProvider(); err == nil {
				t.Fatalf("accepted invalid Bedrock config: %+v", c)
			}
		})
	}
	if !validBedrockClaudeModel("arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6") {
		t.Fatal("rejected Claude inference-profile ARN")
	}
	if validBedrockClaudeModel("arn:aws:bedrock:us-east-1:123456789012:inference-profile/amazon.nova-pro-v1:0") {
		t.Fatal("accepted non-Claude inference-profile ARN")
	}
}

func TestFromEnvBedrockUsesDedicatedAPIKey(t *testing.T) {
	t.Setenv("ARTEX_LLM_PROVIDER", "bedrock")
	t.Setenv("ARTEX_LLM_MODEL", "anthropic.claude-sonnet-4-6")
	t.Setenv("ARTEX_LLM_BASE_URL", "https://bedrock-mantle.us-east-1.api.aws/anthropic/v1/messages")
	t.Setenv("ANTHROPIC_API_KEY", "unrelated-anthropic-key")
	t.Setenv("BEDROCK_API_KEY", "bedrock-key")
	t.Setenv("AWS_BEARER_TOKEN_BEDROCK", "fallback-key")
	c, ok := FromEnv()
	if !ok || c.APIKey != "bedrock-key" || c.Provider() != "bedrock" || c.BaseURL != "https://bedrock-mantle.us-east-1.api.aws/anthropic" {
		t.Fatalf("unexpected Bedrock env config: ok=%t provider=%q base=%q key=%q", ok, c.Provider(), c.BaseURL, c.APIKey)
	}
	t.Setenv("BEDROCK_API_KEY", "")
	c, ok = FromEnv()
	if !ok || c.APIKey != "fallback-key" {
		t.Fatalf("AWS_BEARER_TOKEN_BEDROCK fallback failed: ok=%t key=%q", ok, c.APIKey)
	}
	t.Setenv("AWS_BEARER_TOKEN_BEDROCK", "")
	if _, ok := FromEnv(); ok {
		t.Fatal("Bedrock used the unrelated Anthropic API key")
	}
}

type bedrockCaptureProvider struct {
	last llm.CompletionRequest
}

func (p *bedrockCaptureProvider) Complete(_ context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	p.last = req
	return llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{llm.TextBlock("OK")}}, "end_turn", llm.Usage{}, nil
}

func (p *bedrockCaptureProvider) Stream(_ context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	p.last = req
	return func(yield func(llm.StreamEvent, error) bool) {
		yield(llm.StreamEvent{Type: llm.SETextDelta, Text: "OK"}, nil)
	}
}

func TestBedrockProviderSuppliesMaxTokensForCompleteAndStream(t *testing.T) {
	base := &bedrockCaptureProvider{}
	p := bedrockMaxTokensProvider{Provider: base, maxTokens: defaultBedrockMaxTokens}
	if _, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}}); err != nil {
		t.Fatal(err)
	}
	if base.last.MaxTokens != defaultBedrockMaxTokens {
		t.Fatalf("Complete max tokens=%d", base.last.MaxTokens)
	}
	for range p.Stream(context.Background(), llm.CompletionRequest{}) {
	}
	if base.last.MaxTokens != defaultBedrockMaxTokens {
		t.Fatalf("Stream max tokens=%d", base.last.MaxTokens)
	}
	if _, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{MaxTokens: 512}); err != nil {
		t.Fatal(err)
	}
	if base.last.MaxTokens != 512 {
		t.Fatalf("explicit max tokens changed to %d", base.last.MaxTokens)
	}
}

func TestBedrockDoesNotInferFromAPIKeyAlone(t *testing.T) {
	t.Setenv("ARTEX_LLM_PROVIDER", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("BEDROCK_API_KEY", strings.Repeat("b", 20))
	if _, ok := FromEnv(); ok {
		t.Fatal("Bedrock must be selected explicitly")
	}
}
