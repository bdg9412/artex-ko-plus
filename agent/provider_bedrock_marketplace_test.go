package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

const marketplaceTestARN = "arn:aws:sagemaker:us-east-1:123456789012:endpoint/deepseek-r1"
const marketplaceTestURL = "https://bedrock-runtime.us-east-1.amazonaws.com"

func marketplaceTestConfig() Config {
	c := ConfigFrom("bedrock-marketplace", marketplaceTestARN, marketplaceTestURL, "test-bedrock-key", "")
	c.InvokeSchema = "tgi"
	c.PromptStyle = "raw"
	return c
}

func TestMarketplaceDefaultsTo32KContextWindow(t *testing.T) {
	c := marketplaceTestConfig()
	if c.ContextWindowK != 32 || c.CompactionWindow() != 32000 {
		t.Fatalf("ConfigFrom context window=%d compaction=%d", c.ContextWindowK, c.CompactionWindow())
	}
	t.Setenv("ARTEX_LLM_PROVIDER", "bedrock-marketplace")
	t.Setenv("ARTEX_LLM_MODEL", marketplaceTestARN)
	t.Setenv("ARTEX_LLM_BASE_URL", marketplaceTestURL)
	t.Setenv("BEDROCK_API_KEY", "test-bedrock-key")
	fromEnv, ok := FromEnv()
	if !ok || fromEnv.ContextWindowK != 32 || fromEnv.CompactionWindow() != 32000 {
		t.Fatalf("FromEnv context window=%d compaction=%d ok=%t", fromEnv.ContextWindowK, fromEnv.CompactionWindow(), ok)
	}
}

func TestMarketplaceConfigRejectsWrongDestinationAndIdentifier(t *testing.T) {
	tests := []struct{ name, model, baseURL, key, proxy string }{
		{"wrong region", marketplaceTestARN, "https://bedrock-runtime.us-west-2.amazonaws.com", "key", ""},
		{"lookalike host", marketplaceTestARN, marketplaceTestURL + ".evil.example", "key", ""},
		{"http", marketplaceTestARN, "http://bedrock-runtime.us-east-1.amazonaws.com", "key", ""},
		{"wrong path", marketplaceTestARN, marketplaceTestURL + "/anthropic", "key", ""},
		{"userinfo", marketplaceTestARN, "https://attacker@bedrock-runtime.us-east-1.amazonaws.com", "key", ""},
		{"port", marketplaceTestARN, marketplaceTestURL + ":443", "key", ""},
		{"not endpoint ARN", "arn:aws:bedrock:us-east-1:123456789012:inference-profile/deepseek", marketplaceTestURL, "key", ""},
		{"missing key", marketplaceTestARN, marketplaceTestURL, "", ""},
		{"proxy", marketplaceTestARN, marketplaceTestURL, "key", "http://localhost:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ConfigFrom("bedrock-marketplace", tt.model, tt.baseURL, tt.key, tt.proxy)
			if _, err := c.NewProvider(); err == nil {
				t.Fatal("accepted invalid Marketplace config")
			}
		})
	}
	if _, err := marketplaceTestConfig().NewProvider(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}

type marketplaceRoundTrip func(*http.Request) (*http.Response, error)

func (f marketplaceRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMarketplaceInvokeTGIMapsARNKeyCapAndToolCall(t *testing.T) {
	provider, err := newBedrockMarketplaceProvider(marketplaceTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	p := provider.(*marketplaceProvider)
	p.client.Transport = marketplaceRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.URL.Host != "bedrock-runtime.us-east-1.amazonaws.com" ||
			!strings.Contains(r.URL.EscapedPath(), "endpoint%2Fdeepseek-r1") ||
			r.Header.Get("Authorization") != "Bearer test-bedrock-key" {
			t.Errorf("wrong InvokeModel request: %s %s auth=%q", r.Method, r.URL, r.Header.Get("Authorization"))
		}
		var body struct {
			Inputs     string `json:"inputs"`
			Parameters struct {
				MaxNewTokens int `json:"max_new_tokens"`
			} `json:"parameters"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Parameters.MaxNewTokens != 256 || !strings.Contains(body.Inputs, "Available tools") {
			t.Errorf("request body=%+v", body)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`[{"generated_text":"{\"kind\":\"tool_call\",\"name\":\"lookup\",\"arguments\":{\"item\":\"one\"}}"}]`)), Header: http.Header{}}, nil
	})
	message, stop, _, err := p.Complete(context.Background(), llm.CompletionRequest{
		Messages:  []llm.Message{llm.UserText("find one")},
		Tools:     []llm.ToolSchema{{Name: "lookup", InputSchema: map[string]any{"type": "object"}}},
		MaxTokens: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stop != "tool_use" || len(message.Content) != 1 || message.Content[0].Type != llm.BlockToolUse ||
		message.Content[0].Name != "lookup" || message.Content[0].ID == "" || string(message.Content[0].Input) != `{"item":"one"}` {
		t.Fatalf("parsed tool call: stop=%q message=%+v", stop, message)
	}
}

func TestMarketplaceNativeResponseAndStrictToolEnvelope(t *testing.T) {
	for _, shape := range []string{`{"choices":[{"text":"hello"}]}`, `[{"generated_text":"hello"}]`, `{"generated_text":"hello"}`} {
		text, err := marketplaceGeneratedText([]byte(shape))
		if err != nil || text != "hello" {
			t.Fatalf("response %s: text=%q err=%v", shape, text, err)
		}
	}
	tools := []llm.ToolSchema{{Name: "lookup"}}
	for _, bad := range []string{
		`{"kind":"tool_call","name":"unknown","arguments":{}}`,
		`{"kind":"tool_call","name":"lookup","arguments":[]}`,
		`{"kind":"tool_call","name":"lookup","arguments":{}} trailing`,
		`<think>unfinished`,
		`plain text`,
	} {
		if _, _, _, err := marketplaceMessage(bad, tools); err == nil {
			t.Fatalf("accepted invalid tool response %q", bad)
		}
	}
	message, stop, _, err := marketplaceMessage(`<think>reasoning</think>{"kind":"final","text":"done"}`, tools)
	if err != nil || stop != "end_turn" || message.Content[0].Text != "done" {
		t.Fatalf("final: %+v %q %v", message, stop, err)
	}
}

func TestMarketplaceEndpointRefusesRedirect(t *testing.T) {
	provider, err := newBedrockMarketplaceProvider(marketplaceTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	p := provider.(*marketplaceProvider)
	p.client.Transport = marketplaceRoundTrip(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://evil.example/steal"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	if _, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{Messages: []llm.Message{llm.UserText("ping")}}); err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("redirect should be refused: %v", err)
	}
}
