package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// Converse accepts Bedrock model IDs, inference profile IDs, and model ARNs.
// Keep this independent of model vendors: Bedrock decides whether the selected
// model supports Converse and whether the account may invoke it.
var (
	converseHost    = regexp.MustCompile(`^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$`)
	converseModelID = regexp.MustCompile(`^[A-Za-z0-9_.:/-]+$`)
)

const converseMaxOutputTokens = 65536

func (c Config) validateBedrockConverse() error {
	if c.Format != llm.Format("bedrock-converse") {
		return errors.New("llm: Bedrock Converse requires its own provider format")
	}
	if c.APIKey == "" {
		return errors.New("llm: Amazon Bedrock API key required for Converse")
	}
	if len(c.Model) == 0 || len(c.Model) > 2048 || !converseModelID.MatchString(c.Model) {
		return errors.New("llm: Bedrock Converse requires an explicit model ID or ARN")
	}
	if strings.Contains(c.Model, "/") && !strings.HasPrefix(c.Model, "arn:aws") {
		return errors.New("llm: Bedrock Converse resource paths require a model ARN")
	}
	for _, segment := range strings.Split(c.Model, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("llm: Bedrock Converse model ARN contains an invalid path segment")
		}
	}
	if c.CyberAccessProgram != "" || c.ThinkingType != "" || c.ReasoningEffort != "" || c.MaxTokensField != "" ||
		c.InvokeSchema != "" || c.PromptStyle != "" {
		return errors.New("llm: Bedrock Converse does not support provider-specific request options")
	}
	if c.MaxTokens < 0 || c.MaxTokens > converseMaxOutputTokens {
		return fmt.Errorf("llm: Bedrock Converse max_tokens must be between 0 and %d", converseMaxOutputTokens)
	}
	if math.IsNaN(c.RatePerSecond) || math.IsInf(c.RatePerSecond, 0) || c.RatePerSecond < 0 ||
		math.IsNaN(c.RatePerMinute) || math.IsInf(c.RatePerMinute, 0) || c.RatePerMinute < 0 {
		return errors.New("llm: Bedrock Converse rate limits must be finite and nonnegative")
	}
	if (c.RatePerSecond > 0 && c.RatePerSecond < 1e-6) || (c.RatePerMinute > 0 && c.RatePerMinute < 1e-6) {
		return errors.New("llm: Bedrock Converse positive rate limits must be at least 0.000001")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") ||
		!converseHost.MatchString(strings.ToLower(u.Hostname())) {
		return errors.New("llm: Bedrock Converse base URL must be an HTTPS AWS Bedrock Runtime host")
	}
	return nil
}

type bedrockConverseProvider struct {
	config      Config
	client      *http.Client
	mu          sync.Mutex
	lastRequest time.Time
	semaphore   chan struct{}
}

func newBedrockConverseProvider(c Config) (llm.Provider, error) {
	if err := c.validateBedrockConverse(); err != nil {
		return nil, err
	}
	client, err := quotaAwareHTTPClient(c.Proxy, c.SessionHeaderKey)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("llm: Bedrock Converse endpoint redirect refused")
	}
	return &bedrockConverseProvider{config: c, client: client, semaphore: make(chan struct{}, 4)}, nil
}

// A provider is shared by planner and workers; enforce both a concurrency
// ceiling and the profile's request rate before each model call.
func (p *bedrockConverseProvider) reserve(ctx context.Context) error {
	select {
	case p.semaphore <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	for {
		p.mu.Lock()
		wait := time.Duration(0)
		if p.config.RatePerMinute > 0 {
			wait = time.Until(p.lastRequest.Add(time.Duration(float64(time.Minute) / p.config.RatePerMinute)))
		}
		if p.config.RatePerSecond > 0 {
			gap := time.Until(p.lastRequest.Add(time.Duration(float64(time.Second) / p.config.RatePerSecond)))
			if gap > wait {
				wait = gap
			}
		}
		if wait <= 0 {
			p.lastRequest = time.Now()
			p.mu.Unlock()
			return nil
		}
		p.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			<-p.semaphore
			return ctx.Err()
		}
	}
}

func (p *bedrockConverseProvider) Complete(ctx context.Context, request llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	if err := p.reserve(ctx); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	defer func() { <-p.semaphore }()

	body, err := converseRequestBody(request, p.config.MaxTokens)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	endpoint := strings.TrimRight(p.config.BaseURL, "/") + "/model/" + url.PathEscape(p.config.Model) + "/converse"
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	response, err := p.client.Do(httpRequest)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("bedrock-converse: %w", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("bedrock-converse: read response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("bedrock-converse: status %d: %s", response.StatusCode, truncateMarketplaceError(raw))
	}
	message, stop, usage, err := converseResponse(raw)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	allowed := make(map[string]bool, len(request.Tools))
	for _, tool := range request.Tools {
		allowed[tool.Name] = true
	}
	for _, block := range message.Content {
		if block.Type == llm.BlockToolUse && !allowed[block.Name] {
			return llm.Message{}, "", llm.Usage{}, fmt.Errorf("bedrock-converse: tool %q was not offered in the request", block.Name)
		}
	}
	return message, stop, usage, nil
}

func converseRequestBody(request llm.CompletionRequest, profileMaxTokens int) ([]byte, error) {
	maxTokens := request.MaxTokens
	if maxTokens <= 0 {
		maxTokens = profileMaxTokens
	}
	if maxTokens <= 0 {
		maxTokens = defaultBedrockMaxTokens
	}
	if maxTokens > converseMaxOutputTokens {
		return nil, fmt.Errorf("bedrock-converse: max_tokens exceeds %d", converseMaxOutputTokens)
	}
	body := map[string]any{
		"messages":        make([]any, 0, len(request.Messages)),
		"inferenceConfig": map[string]any{"maxTokens": maxTokens},
	}
	if len(request.System) > 0 {
		system := make([]any, 0, len(request.System))
		for _, text := range request.System {
			if text != "" {
				system = append(system, map[string]any{"text": text})
			}
		}
		if len(system) > 0 {
			body["system"] = system
		}
	}
	messages := body["messages"].([]any)
	for _, message := range request.Messages {
		role := string(message.Role)
		if role != "user" && role != "assistant" {
			return nil, fmt.Errorf("bedrock-converse: unsupported message role %q", role)
		}
		content := make([]any, 0, len(message.Content))
		for _, block := range message.Content {
			switch block.Type {
			case llm.BlockText:
				if block.Text != "" {
					content = append(content, map[string]any{"text": block.Text})
				}
			case llm.BlockToolUse:
				if role != "assistant" || block.ID == "" || block.Name == "" {
					return nil, errors.New("bedrock-converse: invalid assistant tool use")
				}
				input := map[string]any{}
				if len(block.Input) > 0 {
					if err := json.Unmarshal(block.Input, &input); err != nil || input == nil {
						return nil, errors.New("bedrock-converse: tool input must be a JSON object")
					}
				}
				content = append(content, map[string]any{"toolUse": map[string]any{
					"toolUseId": block.ID, "name": block.Name, "input": input,
				}})
			case llm.BlockToolResult:
				if role != "user" || block.ToolUseID == "" {
					return nil, errors.New("bedrock-converse: invalid user tool result")
				}
				resultContent := make([]any, 0, len(block.Content))
				for i, resultBlock := range block.Content {
					if resultBlock.Type != llm.BlockText {
						return nil, fmt.Errorf("bedrock-converse: unsupported tool result block %q", resultBlock.Type)
					}
					text := resultBlock.Text
					if block.IsError && i == 0 {
						// The status field is not supported by every Converse model.
						// Keep the error signal in portable text instead.
						text = "Tool error: " + text
					}
					resultContent = append(resultContent, map[string]any{"text": text})
				}
				if len(resultContent) == 0 {
					text := block.Text
					if block.IsError {
						text = "Tool error: " + text
					}
					resultContent = append(resultContent, map[string]any{"text": text})
				}
				content = append(content, map[string]any{"toolResult": map[string]any{
					"toolUseId": block.ToolUseID, "content": resultContent,
				}})
			default:
				return nil, fmt.Errorf("bedrock-converse: unsupported content block %q", block.Type)
			}
		}
		if len(content) == 0 {
			return nil, errors.New("bedrock-converse: message has no supported content")
		}
		messages = append(messages, map[string]any{"role": role, "content": content})
	}
	if len(messages) == 0 {
		return nil, errors.New("bedrock-converse: at least one message is required")
	}
	body["messages"] = messages
	if len(request.Tools) > 0 {
		tools := make([]any, 0, len(request.Tools))
		for _, tool := range request.Tools {
			if tool.Name == "" {
				return nil, errors.New("bedrock-converse: tool name is required")
			}
			schema := tool.InputSchema
			if schema == nil {
				schema = map[string]any{"type": "object", "properties": map[string]any{}}
			}
			tools = append(tools, map[string]any{"toolSpec": map[string]any{
				"name": tool.Name, "description": tool.Description,
				"inputSchema": map[string]any{"json": schema},
			}})
		}
		body["toolConfig"] = map[string]any{"tools": tools}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("bedrock-converse: encode request: %w", err)
	}
	return encoded, nil
}

func converseResponse(raw []byte) (llm.Message, string, llm.Usage, error) {
	var response struct {
		Output struct {
			Message struct {
				Role    string                       `json:"role"`
				Content []map[string]json.RawMessage `json:"content"`
			} `json:"message"`
		} `json:"output"`
		StopReason string `json:"stopReason"`
		Usage      struct {
			InputTokens           int `json:"inputTokens"`
			OutputTokens          int `json:"outputTokens"`
			CacheReadInputTokens  int `json:"cacheReadInputTokens"`
			CacheWriteInputTokens int `json:"cacheWriteInputTokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return llm.Message{}, "", llm.Usage{}, fmt.Errorf("bedrock-converse: decode response: %w", err)
	}
	if response.Output.Message.Role != "assistant" || response.StopReason == "" {
		return llm.Message{}, "", llm.Usage{}, errors.New("bedrock-converse: invalid response role or stop reason")
	}
	message := llm.Message{Role: llm.RoleAssistant}
	hasToolUse := false
	for _, block := range response.Output.Message.Content {
		if value, ok := block["text"]; ok {
			var text string
			if err := json.Unmarshal(value, &text); err != nil {
				return llm.Message{}, "", llm.Usage{}, fmt.Errorf("bedrock-converse: invalid text block: %w", err)
			}
			message.Content = append(message.Content, llm.TextBlock(text))
			continue
		}
		if value, ok := block["toolUse"]; ok {
			var tool struct {
				ID    string          `json:"toolUseId"`
				Name  string          `json:"name"`
				Input json.RawMessage `json:"input"`
			}
			if err := json.Unmarshal(value, &tool); err != nil || tool.ID == "" || tool.Name == "" {
				return llm.Message{}, "", llm.Usage{}, errors.New("bedrock-converse: invalid tool use block")
			}
			var input map[string]any
			if err := json.Unmarshal(tool.Input, &input); err != nil || input == nil {
				return llm.Message{}, "", llm.Usage{}, errors.New("bedrock-converse: invalid tool use block")
			}
			message.Content = append(message.Content, llm.ContentBlock{
				Type: llm.BlockToolUse, ID: tool.ID, Name: tool.Name, Input: tool.Input,
			})
			hasToolUse = true
			continue
		}
		if _, ok := block["reasoningContent"]; ok {
			// Reasoning is not a user-facing message or executable tool call.
			continue
		}
		return llm.Message{}, "", llm.Usage{}, errors.New("bedrock-converse: unsupported response content block")
	}
	if len(message.Content) == 0 && response.StopReason != "max_tokens" {
		return llm.Message{}, "", llm.Usage{}, errors.New("bedrock-converse: empty response")
	}
	if (response.StopReason == "tool_use") != hasToolUse {
		return llm.Message{}, "", llm.Usage{}, errors.New("bedrock-converse: tool use and stop reason disagree")
	}
	usage := llm.Usage{
		InputTokens: response.Usage.InputTokens, OutputTokens: response.Usage.OutputTokens,
		CacheReadTokens: response.Usage.CacheReadInputTokens, CacheWriteTokens: response.Usage.CacheWriteInputTokens,
	}
	return message, response.StopReason, usage, nil
}

// ConverseStream has AWS event-stream framing. Until that path is implemented,
// the non-streaming Converse response is normalized into Norma stream events.
// The UI keeps this profile in non-streaming mode so it does not promise live
// token delivery.
func (p *bedrockConverseProvider) Stream(ctx context.Context, request llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		message, stop, usage, err := p.Complete(ctx, request)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageStart, Usage: llm.Usage{
			InputTokens: usage.InputTokens, CacheReadTokens: usage.CacheReadTokens,
		}}, nil) {
			return
		}
		for _, block := range message.Content {
			if block.Type == llm.BlockToolUse {
				if !yield(llm.StreamEvent{Type: llm.SEToolUseStart, ToolID: block.ID, ToolName: block.Name}, nil) {
					return
				}
				if !yield(llm.StreamEvent{Type: llm.SEToolInputJSON, Text: string(block.Input)}, nil) {
					return
				}
			} else if !yield(llm.StreamEvent{Type: llm.SETextDelta, Text: block.Text}, nil) {
				return
			}
		}
		if !yield(llm.StreamEvent{Type: llm.SEMessageDelta, StopReason: stop, Usage: llm.Usage{
			OutputTokens: usage.OutputTokens, CacheWriteTokens: usage.CacheWriteTokens,
		}}, nil) {
			return
		}
		yield(llm.StreamEvent{Type: llm.SEMessageStop}, nil)
	}
}
