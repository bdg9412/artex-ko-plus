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

type converseRoundTripFunc func(*http.Request) (*http.Response, error)

func (f converseRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func converseTestResponse(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}
}

func TestBedrockConverseConfigAcceptsAnyModelFamilyAndRestrictsHost(t *testing.T) {
	for _, model := range []string{
		"zai.glm-4.7", "global.zai.glm-5.3", "amazon.nova-lite-v1:0",
		"arn:aws:bedrock:ap-northeast-2:123456789012:inference-profile/global.zai.glm-5.3",
	} {
		c := ConfigFrom("bedrock-converse", model, "https://bedrock-runtime.ap-northeast-2.amazonaws.com/", "key", "")
		if c.Provider() != "bedrock-converse" || c.Format != llm.Format("bedrock-converse") || c.MaxTokens != defaultBedrockMaxTokens {
			t.Fatalf("bad config for %q: %+v", model, c)
		}
		if _, err := c.NewProvider(); err != nil {
			t.Fatalf("model %q: %v", model, err)
		}
	}
	for _, tc := range []struct{ model, baseURL, key string }{
		{"", "https://bedrock-runtime.ap-northeast-2.amazonaws.com", "key"},
		{"zai.glm-4.7", "", "key"},
		{"zai.glm-4.7", "https://bedrock-runtime.ap-northeast-2.amazonaws.com", ""},
		{"zai.glm-4.7", "http://bedrock-runtime.ap-northeast-2.amazonaws.com", "key"},
		{"zai.glm-4.7", "https://bedrock-runtime.ap-northeast-2.amazonaws.com.evil.test", "key"},
		{"zai.glm-4.7", "https://user@bedrock-runtime.ap-northeast-2.amazonaws.com", "key"},
		{"zai.glm-4.7", "https://bedrock-runtime.ap-northeast-2.amazonaws.com:443", "key"},
		{"zai.glm-4.7", "https://bedrock-runtime.ap-northeast-2.amazonaws.com/openai/v1", "key"},
		{"zai.glm-4.7", "https://bedrock-runtime.ap-northeast-2.amazonaws.com?x=1", "key"},
		{"zai.glm-4.7/../escape", "https://bedrock-runtime.ap-northeast-2.amazonaws.com", "key"},
	} {
		c := ConfigFrom("bedrock-converse", tc.model, tc.baseURL, tc.key, "")
		if _, err := c.NewProvider(); err == nil {
			t.Fatalf("accepted invalid Converse config: model=%q base=%q hasKey=%t", tc.model, tc.baseURL, tc.key != "")
		}
	}
}

func TestBedrockConverseNativeToolRoundTrip(t *testing.T) {
	model := "arn:aws:bedrock:ap-northeast-2:123456789012:inference-profile/global.zai.glm-5.3"
	c := ConfigFrom("bedrock-converse", model, "https://bedrock-runtime.ap-northeast-2.amazonaws.com", "test-bedrock-key", "")
	base, err := c.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	p := base.(*bedrockConverseProvider)
	calls := 0
	p.client.Transport = converseRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.Host != "bedrock-runtime.ap-northeast-2.amazonaws.com" ||
			r.Header.Get("Authorization") != "Bearer test-bedrock-key" ||
			!strings.Contains(r.URL.EscapedPath(), "inference-profile%2Fglobal.zai.glm-5.3") ||
			!strings.HasSuffix(r.URL.EscapedPath(), "/converse") {
			t.Errorf("unexpected request method=%s host=%s path=%s authorization_valid=%t", r.Method, r.Host, r.URL.EscapedPath(), r.Header.Get("Authorization") == "Bearer test-bedrock-key")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatal(err)
		}
		inference := wire["inferenceConfig"].(map[string]any)
		if inference["maxTokens"] != float64(defaultBedrockMaxTokens) {
			t.Fatalf("missing bounded default maxTokens: %s", body)
		}
		messages := wire["messages"].([]any)
		if calls == 1 {
			if len(messages) != 1 || len(wire["system"].([]any)) != 1 {
				t.Fatalf("missing first-turn messages or system prompt: %s", body)
			}
			tools := wire["toolConfig"].(map[string]any)["tools"].([]any)
			spec := tools[0].(map[string]any)["toolSpec"].(map[string]any)
			if spec["name"] != "lookup" || spec["inputSchema"].(map[string]any)["json"].(map[string]any)["type"] != "object" {
				t.Fatalf("wrong native tool schema: %s", body)
			}
			return converseTestResponse(`{"output":{"message":{"role":"assistant","content":[{"text":"Checking."},{"toolUse":{"toolUseId":"tooluse_123","name":"lookup","input":{"host":"fixture.local"}}}]}},"stopReason":"tool_use","usage":{"inputTokens":25,"outputTokens":9}}`), nil
		}
		if len(messages) != 3 {
			t.Fatalf("missing tool history: %s", body)
		}
		assistant := messages[1].(map[string]any)["content"].([]any)[0].(map[string]any)["toolUse"].(map[string]any)
		result := messages[2].(map[string]any)["content"].([]any)[0].(map[string]any)["toolResult"].(map[string]any)
		if assistant["toolUseId"] != "tooluse_123" || result["toolUseId"] != "tooluse_123" {
			t.Fatalf("tool call/result ID lost: %s", body)
		}
		return converseTestResponse(`{"output":{"message":{"role":"assistant","content":[{"text":"Found one result."}]}},"stopReason":"end_turn","usage":{"inputTokens":40,"outputTokens":7}}`), nil
	})

	request := llm.CompletionRequest{
		System:   []string{"You are an analyst."},
		Messages: []llm.Message{llm.UserText("Look up the lab host")},
		Tools: []llm.ToolSchema{{Name: "lookup", Description: "Look up a lab host", InputSchema: map[string]any{
			"type": "object", "properties": map[string]any{"host": map[string]any{"type": "string"}},
		}}},
	}
	message, stop, usage, err := p.Complete(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if stop != "tool_use" || usage.InputTokens != 25 || usage.OutputTokens != 9 ||
		len(message.Content) != 2 || message.Content[1].Type != llm.BlockToolUse ||
		message.Content[1].ID != "tooluse_123" || message.Content[1].Name != "lookup" {
		t.Fatalf("native tool response lost: message=%+v stop=%q usage=%+v", message, stop, usage)
	}
	request.Messages = append(request.Messages, llm.Message{Role: llm.RoleAssistant, Content: []llm.ContentBlock{message.Content[1]}})
	request.Messages = append(request.Messages, llm.Message{Role: llm.RoleUser, Content: []llm.ContentBlock{{
		Type: llm.BlockToolResult, ToolUseID: "tooluse_123", Content: []llm.ContentBlock{llm.TextBlock("one result")},
	}}})
	message, stop, usage, err = p.Complete(context.Background(), request)
	if err != nil || stop != "end_turn" || message.Text() != "Found one result." || usage.InputTokens != 40 || calls != 2 {
		t.Fatalf("tool result follow-up: message=%+v stop=%q usage=%+v err=%v calls=%d", message, stop, usage, err, calls)
	}
}

func TestBedrockConverseStreamNormalizesCompletedToolResponse(t *testing.T) {
	c := ConfigFrom("bedrock-converse", "zai.glm-4.7", "https://bedrock-runtime.ap-northeast-2.amazonaws.com", "key", "")
	base, err := c.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	p := base.(*bedrockConverseProvider)
	p.client.Transport = converseRoundTripFunc(func(*http.Request) (*http.Response, error) {
		return converseTestResponse(`{"output":{"message":{"role":"assistant","content":[{"toolUse":{"toolUseId":"tooluse_456","name":"lookup","input":{"host":"lab"}}}]}},"stopReason":"tool_use","usage":{"inputTokens":10,"outputTokens":5}}`), nil
	})
	var got []llm.StreamEvent
	for event, err := range p.Stream(context.Background(), llm.CompletionRequest{
		Messages: []llm.Message{llm.UserText("ping")},
		Tools:    []llm.ToolSchema{{Name: "lookup", InputSchema: map[string]any{"type": "object"}}},
	}) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, event)
	}
	if len(got) != 5 || got[0].Type != llm.SEMessageStart || got[1].Type != llm.SEToolUseStart ||
		got[2].Type != llm.SEToolInputJSON || got[3].StopReason != "tool_use" || got[4].Type != llm.SEMessageStop {
		t.Fatalf("wrong normalized stream events: %+v", got)
	}
}
