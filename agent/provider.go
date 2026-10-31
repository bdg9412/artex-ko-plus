// Package agent wires real LLM-driven planner and work agents (on top of the
// agent-core SDK) to the dual SQLite graph. See docs/ARTEX-架构设计.md
// §4.3 (planner) and §4.4 (work agent).
//
// Provider configuration is read from the environment so the system runs with
// Anthropic, OpenAI-compatible, Amazon Bedrock, or local Ollama endpoints.
// Cloud providers need a key; explicit Ollama configuration can run without one.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/ollamaendpoint"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/compaction"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/transcript"
)

// Config describes the LLM backend resolved from the environment.
type Config struct {
	Format llm.Format
	// ProviderID preserves the UI/environment provider name when multiple
	// backends share the same wire format. Ollama uses OpenAI chat completions;
	// Bedrock's legacy Claude Messages endpoint uses the Anthropic wire format.
	ProviderID   string
	OllamaRemote ollamaendpoint.Options
	BaseURL      string
	APIKey       string
	Model        string
	// Marketplace text endpoints use InvokeModel with a model-specific body.
	// Empty values select the conservative TGI/raw defaults.
	InvokeSchema string
	PromptStyle  string
	// CyberAccessProgram opts an OpenAI Responses profile into an approved
	// cybersecurity access program. Empty leaves the wire request unchanged.
	// Supported values are standard, daybreak_blue, and daybreak_red; the API
	// decides whether the selected model and project may use that program.
	CyberAccessProgram string
	// Proxy routes all LLM requests through the given proxy URL (http/https/socks5,
	// optionally with user:pass@ credentials). Empty means direct — it does NOT
	// fall back to the standard *_PROXY environment variables.
	Proxy string
	// RatePerSecond / RatePerMinute cap the shared request rate across ALL agents
	// using the provider (0 = that window unlimited).
	RatePerSecond float64
	RatePerMinute float64
	// ContextWindowK is the model's context window in K tokens (user-configured),
	// used to size compaction thresholds. 0 = default; see CompactionWindow.
	ContextWindowK int
	// ThinkingType 独立控制思考「开关」字段(thinking.type):
	//   "" = 不发送(默认,兼容不支持该字段的模型); "disabled" = 显式关闭;
	//   "enabled" = 开启. 与 ReasoningEffort 完全解耦——有些接口没有 thinking 字段、
	//   只靠强度参数就能激活思考,故两者可各自单独设置.
	ThinkingType string
	// ReasoningEffort 独立控制思考「强度」字段:
	//   "" = 不发送(默认); "low"/"medium"/"high"/"xhigh"/"max" = 对应强度.
	//   OpenAI 映射为顶层 reasoning_effort;Anthropic 映射为 output_config.effort.
	ReasoningEffort string
	// Stream 控制该 profile 是否使用流式(SSE)接口。true(默认)= 流式;false = 真·
	// 非流式(发 stream:false,一次性拿完整 JSON,走 Provider.Complete)。非流式可绕开
	// 某些网关糟糕的 SSE 实现(空帧、思考字段丢帧),代价是失去运行中的实时进度/实时
	// token 计数。映射为 agentcore.Options.NonStreaming = !Stream。
	Stream bool
	// MaxTokens 是单次回复的输出上限(token)。0 = 不发送该字段,由服务端默认值决定
	// (历史行为)。与 ContextWindowK 不同:后者是模型总容量,只在本地用来算压缩阈值,
	// 不出现在请求里;本值随每次请求发出。映射为 agentcore.Options.MaxTokens。
	MaxTokens int
	// MaxTokensField 选择 MaxTokens 用哪个请求字段名,仅对 format=openai 生效:
	//   "" = max_tokens(默认); "max_completion_tokens" = 新字段。
	// OpenAI 推理模型(o 系列/GPT-5)只认后者,收到 max_tokens 会直接报
	// unsupported_parameter;而多数兼容网关只认前者,故不做自动推断,交由用户按端点选。
	MaxTokensField string
	// SessionHeaderKey,非空时,让每次 LLM 请求带上一个自定义 HTTP 头,头名为该值、
	// 头值为【当前会话的 session id】(chat 会话=conv-<id>,worker=exp<x>-worker-i<intent>
	// 等,见 WorkerSessionID)。用于某些按 session-id 头做提示缓存/粘性路由的网关。
	// 空 = 不发送。值由 transcript.WithSessionID 挂在请求 context 上,由 RoundTripper
	// 读取填入,因此同一共享 provider 也能按会话发出不同的头值。
	SessionHeaderKey string
	// Retry 是该配置解析后的重试参数(profile 覆盖 → 全局策略 → 内置默认,由
	// server 侧解析)。三层的含义见 RetryConfig;零值 = 完全沿用内置默认。
	Retry RetryConfig
}

// RetryConfig 是随一个 LLM 配置走的重试参数。每层的「次数」统一语义:
// 0 = 用内置默认次数;负数 = 关闭该层重试;>0 = 用该值。每层的「间隔」:
// 0 = 用该层原本的指数退避;>0 = 改用这个固定间隔。
type RetryConfig struct {
	// ConnectAttempts/ConnectInterval:SDK 建连重试(连接重置/超时/429/5xx,流开始前),
	// 直接映射为 llm.Config.MaxRetries / RetryInterval。默认 3 次、0.5s 起指数(封顶 8s)。
	ConnectAttempts int
	ConnectInterval time.Duration
	// EmptyAttempts/EmptyInterval:SDK 空响应重试(完成但无 content block,仅 openai
	// 格式),映射为 llm.Config.EmptyResponseRetries / EmptyResponseInterval。
	// 默认 2 次、同一条指数梯度。
	EmptyAttempts int
	EmptyInterval time.Duration
	// StreamAttempts/StreamInterval:同 provider 安全窗口重试——本项目在 SDK 之上补的
	// 一层,只在「还没向调用方交付任何输出」时重放断流/过载/流内 429。SDK 看不到它,
	// 由 server/task_llm.go 消费。默认 2 次、0.5s 起指数(封顶 4s)。
	StreamAttempts int
	StreamInterval time.Duration
}

// compaction window resolution bounds (in K tokens). Below the floor the
// threshold math (window − summary reserve − buffer) would go non-positive and
// compaction would fire every turn; above the cap it would never fire.
const (
	defaultWindowK              = 200  // unset → assume a 200K window (Claude default)
	minWindowK                  = 32   // floor so effectiveWindow stays comfortably positive
	maxWindowK                  = 1000 // cap at 1M tokens (user request)
	defaultOllamaURL            = "http://127.0.0.1:11434/v1"
	defaultOllamaModel          = "qwen3:8b"
	defaultBedrockMaxTokens     = 4096
	defaultMarketplaceMaxTokens = 2048
)

var bedrockEndpointHost = regexp.MustCompile(`^(?:bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com|bedrock-mantle\.[a-z0-9-]+\.api\.aws)$`)

// CompactionWindow returns the model context window in TOKENS for compaction
// thresholds, resolved from the user-configured size (ContextWindowK). 0/unset →
// a 200K default; otherwise clamped to [32K, 1M] so compaction stays effective.
func (c Config) CompactionWindow() int {
	k := c.ContextWindowK
	if k <= 0 {
		k = defaultWindowK
	}
	if k < minWindowK {
		k = minWindowK
	}
	if k > maxWindowK {
		k = maxWindowK
	}
	return k * 1000
}

// compactionConfig builds the agent-core compaction config for a context window
// in tokens. agentcore.NewSession wires the summarizer (same provider) when this
// is set on Options.Compaction.
func compactionConfig(windowTokens int) *compaction.Config {
	if windowTokens <= 0 {
		windowTokens = defaultWindowK * 1000
	}
	return &compaction.Config{ContextWindow: windowTokens}
}

// FromEnv resolves the LLM provider config:
//
//	ARTEX_LLM_PROVIDER = anthropic|openai|openai-responses|ollama|ollama-remote|bedrock|bedrock-converse (default: inferred from keys)
//	ARTEX_LLM_MODEL    = model id        (default: per provider)
//	ARTEX_LLM_BASE_URL = endpoint        (optional)
//	ARTEX_LLM_PROXY    = proxy URL        (optional; http/https/socks5)
//	ANTHROPIC_API_KEY / OPENAI_API_KEY / BEDROCK_API_KEY = credentials
//	ARTEX_OLLAMA_REMOTE_TOKEN = optional remote gateway token (never inherits cloud keys)
func FromEnv() (Config, bool) {
	prov := strings.ToLower(strings.TrimSpace(os.Getenv("ARTEX_LLM_PROVIDER")))
	anthKey := os.Getenv("ANTHROPIC_API_KEY")
	oaiKey := os.Getenv("OPENAI_API_KEY")

	if prov == "" {
		switch {
		case anthKey != "":
			prov = "anthropic"
		case oaiKey != "":
			prov = "openai"
		default:
			return Config{}, false
		}
	}

	c := Config{
		ProviderID: prov,
		BaseURL:    os.Getenv("ARTEX_LLM_BASE_URL"),
		Model:      os.Getenv("ARTEX_LLM_MODEL"),
		Proxy:      strings.TrimSpace(os.Getenv("ARTEX_LLM_PROXY")),
		// 默认流式;ARTEX_LLM_STREAM=false/0/off 显式关闭走非流式。
		Stream: !isFalsy(os.Getenv("ARTEX_LLM_STREAM")),
	}
	switch prov {
	case "bedrock-converse":
		c.Format = llm.Format("bedrock-converse")
		c.Model = strings.TrimSpace(c.Model)
		c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
		c.MaxTokens = defaultBedrockMaxTokens
		c.APIKey = strings.TrimSpace(os.Getenv("BEDROCK_API_KEY"))
		if c.APIKey == "" {
			c.APIKey = strings.TrimSpace(os.Getenv("AWS_BEARER_TOKEN_BEDROCK"))
		}
	case "bedrock-marketplace":
		c.Format = llm.Format("bedrock-marketplace")
		c.ContextWindowK = minWindowK
		c.Model = strings.TrimSpace(c.Model)
		c.APIKey = strings.TrimSpace(os.Getenv("BEDROCK_API_KEY"))
		if c.APIKey == "" {
			c.APIKey = strings.TrimSpace(os.Getenv("AWS_BEARER_TOKEN_BEDROCK"))
		}
		c.InvokeSchema = strings.TrimSpace(os.Getenv("ARTEX_LLM_INVOKE_SCHEMA"))
		c.PromptStyle = strings.TrimSpace(os.Getenv("ARTEX_LLM_PROMPT_STYLE"))
		c.MaxTokens = defaultMarketplaceMaxTokens
	case "bedrock":
		c.Format = llm.FormatAnthropic
		c.Model = strings.TrimSpace(c.Model)
		c.BaseURL = bedrockBaseURL(c.BaseURL)
		c.MaxTokens = defaultBedrockMaxTokens
		c.APIKey = strings.TrimSpace(os.Getenv("BEDROCK_API_KEY"))
		if c.APIKey == "" {
			c.APIKey = strings.TrimSpace(os.Getenv("AWS_BEARER_TOKEN_BEDROCK"))
		}
	case "ollama-remote":
		c.Format = llm.FormatOpenAI
		c.ContextWindowK = minWindowK
		c.APIKey = strings.TrimSpace(os.Getenv("ARTEX_OLLAMA_REMOTE_TOKEN"))
		if c.APIKey != "" {
			c.OllamaRemote.AuthMode = "bearer"
		}
		if c.Model == "" {
			c.Model = defaultOllamaModel
		}
		if _, err := ollamaendpoint.NormalizeURL(c.BaseURL); err != nil {
			return Config{}, false
		}
		c.BaseURL, _ = ollamaendpoint.NormalizeURL(c.BaseURL)
	case "ollama":
		c.Format = llm.FormatOpenAI
		c.ContextWindowK = minWindowK
		// A local Ollama server does not require an API key. Never reuse an
		// OpenAI key from the process environment for this backend.
		if strings.TrimSpace(c.BaseURL) == "" {
			c.BaseURL = defaultOllamaURL
		}
		c.BaseURL = openAIChatBaseURL(c.BaseURL)
		if strings.TrimSpace(c.Model) == "" {
			c.Model = defaultOllamaModel
		}
	case "openai":
		c.Format = llm.FormatOpenAI
		c.APIKey = oaiKey
		if c.Model == "" {
			c.Model = "gpt-4o"
		}
	case "openai-responses":
		c.Format = llm.FormatOpenAIResponses
		c.APIKey = oaiKey
		if c.Model == "" {
			c.Model = "gpt-5"
		}
	default:
		c.Format = llm.FormatAnthropic
		c.APIKey = anthKey
		if c.Model == "" {
			c.Model = "claude-opus-4-8"
		}
	}
	if c.APIKey == "" && !c.IsOllama() {
		return Config{}, false
	}
	if c.IsBedrock() {
		if err := c.validateBedrock(); err != nil {
			return Config{}, false
		}
	}
	if c.IsBedrockMarketplace() {
		if err := c.validateBedrockMarketplace(); err != nil {
			return Config{}, false
		}
	}
	if c.IsBedrockConverse() {
		if err := c.validateBedrockConverse(); err != nil {
			return Config{}, false
		}
	}
	return c, true
}

// ConfigFrom builds a Config from UI-provided strings (provider defaults to
// anthropic; model defaults per provider). Inputs are trimmed and the base URL
// is normalized to the API base the provider expects (the provider appends the
// endpoint path itself), so a full endpoint URL is tolerated.
func ConfigFrom(provider, model, baseURL, apiKey, proxy string) Config {
	c := Config{
		ProviderID: strings.ToLower(strings.TrimSpace(provider)),
		Model:      strings.TrimSpace(model),
		BaseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		APIKey:     strings.TrimSpace(apiKey),
		Proxy:      strings.TrimSpace(proxy),
		Stream:     true, // 默认流式;调用方按 profile 覆盖
	}
	switch c.ProviderID {
	case "bedrock-converse":
		c.Format = llm.Format("bedrock-converse")
		c.MaxTokens = defaultBedrockMaxTokens
	case "bedrock-marketplace":
		c.Format = llm.Format("bedrock-marketplace")
		c.ContextWindowK = minWindowK
		c.MaxTokens = defaultMarketplaceMaxTokens
	case "bedrock":
		c.Format = llm.FormatAnthropic
		c.BaseURL = bedrockBaseURL(c.BaseURL)
		c.MaxTokens = defaultBedrockMaxTokens
	case "ollama-remote":
		c.Format = llm.FormatOpenAI
		c.ContextWindowK = minWindowK
		if normalized, err := ollamaendpoint.NormalizeURL(c.BaseURL); err == nil {
			c.BaseURL = normalized
		}
		if c.Model == "" {
			c.Model = defaultOllamaModel
		}
	case "ollama":
		c.Format = llm.FormatOpenAI
		c.ContextWindowK = minWindowK
		// Ignore even a supplied key: switching a saved OpenAI profile to
		// Ollama must not send its previous credential to the local server.
		c.APIKey = ""
		if c.BaseURL == "" {
			c.BaseURL = defaultOllamaURL
		}
		c.BaseURL = openAIChatBaseURL(c.BaseURL)
		if c.Model == "" {
			c.Model = defaultOllamaModel
		}
	case "openai":
		c.Format = llm.FormatOpenAI
		// provider appends "/chat/completions"; tolerate a full endpoint URL.
		c.BaseURL = openAIChatBaseURL(c.BaseURL)
		if c.Model == "" {
			c.Model = "gpt-4o"
		}
	case "openai-responses":
		c.Format = llm.FormatOpenAIResponses
		// provider appends "/responses"; tolerate a full endpoint URL.
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/responses"), "/")
		if c.Model == "" {
			c.Model = "gpt-5"
		}
	default:
		c.Format = llm.FormatAnthropic
		// provider appends "/v1/messages".
		c.BaseURL = strings.TrimRight(strings.TrimSuffix(c.BaseURL, "/v1/messages"), "/")
		if c.Model == "" {
			c.Model = "claude-opus-4-8"
		}
	}
	return c
}

func openAIChatBaseURL(baseURL string) string {
	return strings.TrimRight(strings.TrimSuffix(strings.TrimRight(strings.TrimSpace(baseURL), "/"), "/chat/completions"), "/")
}

// Norma appends /v1/messages to an Anthropic-format base URL. Both Bedrock
// endpoint families expose that path below /anthropic.
func bedrockBaseURL(baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	return strings.TrimRight(strings.TrimSuffix(baseURL, "/v1/messages"), "/")
}

func validBedrockClaudeModel(model string) bool {
	if strings.HasPrefix(model, "arn:") {
		parts := strings.SplitN(model, ":", 6)
		if len(parts) != 6 || (parts[1] != "aws" && parts[1] != "aws-us-gov" && parts[1] != "aws-cn") ||
			parts[2] != "bedrock" || parts[3] == "" {
			return false
		}
		resource := strings.SplitN(parts[5], "/", 2)
		if len(resource) != 2 {
			return false
		}
		switch resource[0] {
		case "foundation-model", "inference-profile", "application-inference-profile":
			model = resource[1]
		default:
			return false
		}
	}
	for _, prefix := range []string{"anthropic.", "us.anthropic.", "eu.anthropic.", "apac.anthropic.", "global.anthropic."} {
		if strings.HasPrefix(model, prefix) && len(model) > len(prefix) {
			return !strings.ContainsAny(model, " \t\r\n/?#")
		}
	}
	return false
}

func (c Config) validateBedrock() error {
	if c.Format != llm.FormatAnthropic {
		return fmt.Errorf("llm: Bedrock requires Anthropic Messages format")
	}
	if c.APIKey == "" {
		return fmt.Errorf("llm: Bedrock API key required")
	}
	if !validBedrockClaudeModel(c.Model) {
		return fmt.Errorf("llm: Bedrock requires an explicit Claude model ID or inference-profile ARN")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Path != "/anthropic" ||
		!bedrockEndpointHost.MatchString(strings.ToLower(u.Hostname())) {
		return fmt.Errorf("llm: Bedrock base URL must be an HTTPS AWS Bedrock /anthropic endpoint")
	}
	return nil
}

// isFalsy reports whether an env-var string explicitly requests "off". Empty or
// unrecognized → false (so an unset var keeps the streaming default).
func isFalsy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0", "false", "off", "no":
		return true
	}
	return false
}

// IsOllama identifies both local and remote Ollama protocol behavior.
func (c Config) IsOllama() bool       { return c.ProviderID == "ollama" || c.IsRemoteOllama() }
func (c Config) IsRemoteOllama() bool { return c.ProviderID == ollamaendpoint.Remote }

// IsBedrock reports whether this config uses the Bedrock Claude Messages API.
func (c Config) IsBedrock() bool { return c.ProviderID == "bedrock" }

// IsBedrockConverse reports whether this config uses Bedrock's model-neutral Converse API.
func (c Config) IsBedrockConverse() bool { return c.ProviderID == "bedrock-converse" }

// IsBedrockMarketplace reports whether this config invokes a Marketplace endpoint.
func (c Config) IsBedrockMarketplace() bool { return c.ProviderID == "bedrock-marketplace" }

// Provider returns the short provider name.
func (c Config) Provider() string {
	if c.IsOllama() {
		return c.ProviderID
	}
	if c.IsBedrock() {
		return "bedrock"
	}
	if c.IsBedrockConverse() {
		return "bedrock-converse"
	}
	if c.IsBedrockMarketplace() {
		return "bedrock-marketplace"
	}
	switch c.Format {
	case llm.FormatOpenAI:
		return "openai"
	case llm.FormatOpenAIResponses:
		return "openai-responses"
	}
	return "anthropic"
}

// NewProvider builds an llm.Provider from the config. When a rate is set, the
// limiter lives on the single provider instance — so planner + all workers +
// main agent (which share this provider) are bounded by one shared rate limit.
func (c Config) NewProvider() (llm.Provider, error) {
	if c.IsRemoteOllama() {
		if err := c.ValidateRemoteOllama(); err != nil {
			return nil, err
		}
		c.BaseURL, _ = ollamaendpoint.NormalizeURL(c.BaseURL)
	}
	if c.IsBedrockConverse() {
		return newBedrockConverseProvider(c)
	}
	if c.IsBedrockMarketplace() {
		return newBedrockMarketplaceProvider(c)
	}
	if c.IsBedrock() {
		if err := c.validateBedrock(); err != nil {
			return nil, err
		}
	}
	cyberProgram := strings.ToLower(strings.TrimSpace(c.CyberAccessProgram))
	if cyberProgram != "" {
		if c.Format != llm.FormatOpenAIResponses || c.IsOllama() {
			return nil, fmt.Errorf("llm: cyber access program is only supported for openai-responses profiles")
		}
		switch cyberProgram {
		case "standard", "daybreak_blue", "daybreak_red":
		default:
			return nil, fmt.Errorf("llm: unsupported cyber access program %q", c.CyberAccessProgram)
		}
	}
	client, err := quotaAwareHTTPClient(c.Proxy, c.SessionHeaderKey, providerTransportOptions{
		stripAuth: c.IsOllama(), bearerToken: c.ollamaBearerToken(), cyberAccessProgram: cyberProgram,
	})
	if err != nil {
		return nil, err
	}
	if c.IsRemoteOllama() {
		client.CheckRedirect = noOllamaRedirect
	}
	lc := llm.Config{
		Format:     c.Format,
		BaseURL:    c.BaseURL,
		APIKey:     c.APIKey,
		Model:      c.Model,
		HTTPClient: client,
	}
	if c.IsOllama() {
		// Norma's OpenAI client may require a non-empty key while building a
		// provider. The transport below removes its placeholder auth header
		// before the request reaches Ollama.
		lc.Format = llm.FormatOpenAI
		lc.APIKey = "ollama"
	}
	// 思考开关与强度两个字段各自透传(空 = 该字段不发送)。二者解耦:
	// 可只发 thinking.type、只发 effort、都发、或都不发。
	lc.ThinkingType = c.ThinkingType
	lc.ReasoningEffort = c.ReasoningEffort
	// 输出上限的字段名选择(空 = 用 max_tokens)。上限的「值」不在这里:它每轮随
	// agentcore.Options.MaxTokens 走,provider 只决定把它塞进哪个键。
	lc.MaxTokensField = c.MaxTokensField
	if c.IsOllama() {
		// These are provider-specific request fields; a profile converted from
		// OpenAI may still carry them, but the Ollama chat endpoint does not
		// need them for basic completion and tool calls.
		lc.ThinkingType = ""
		lc.ReasoningEffort = ""
		lc.MaxTokensField = ""
	}
	// 重试参数与 SDK 同语义(次数 0=默认/负=关闭,间隔 0=指数退避/>0=固定),原样透传。
	lc.MaxRetries = c.Retry.ConnectAttempts
	lc.RetryInterval = c.Retry.ConnectInterval
	lc.EmptyResponseRetries = c.Retry.EmptyAttempts
	lc.EmptyResponseInterval = c.Retry.EmptyInterval
	if c.RatePerSecond > 0 || c.RatePerMinute > 0 {
		lc.RateLimit = &llm.RateLimit{PerSecond: c.RatePerSecond, PerMinute: c.RatePerMinute}
	}
	provider, err := llm.NewProvider(lc)
	if err != nil {
		return provider, err
	}
	if c.IsOllama() {
		provider = newOllamaContextProvider(provider, c, client)
		if c.IsRemoteOllama() {
			provider = newRemoteOllamaProvider(provider, c)
		}
		return provider, nil
	}
	if c.IsBedrock() {
		maxTokens := c.MaxTokens
		if maxTokens <= 0 {
			maxTokens = defaultBedrockMaxTokens
		}
		return bedrockMaxTokensProvider{Provider: provider, maxTokens: maxTokens}, nil
	}
	return provider, nil
}

// Bedrock Messages requires max_tokens. Some direct callers bypass agentcore's
// MaxTokens option, so supply a bounded value on both completion paths.
type bedrockMaxTokensProvider struct {
	llm.Provider
	maxTokens int
}

func (p bedrockMaxTokensProvider) withMaxTokens(req llm.CompletionRequest) llm.CompletionRequest {
	if req.MaxTokens <= 0 {
		req.MaxTokens = p.maxTokens
	}
	return req
}

func (p bedrockMaxTokensProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return p.Provider.Complete(ctx, p.withMaxTokens(req))
}

func (p bedrockMaxTokensProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return p.Provider.Stream(ctx, p.withMaxTokens(req))
}

// IsQuotaExhaustedMessage deliberately recognizes only explicit balance,
// billing, credit, or quota-exhaustion signals. Generic 429/rate-limit text,
// authentication failures, network errors, and server failures are excluded.
var nonFailoverHTTPStatus = regexp.MustCompile(`(?:status(?:\s+code)?|http(?:\s+status)?)\s*[=:]?\s*(?:401|403|5\d\d)\b`)
var transientQuotaLimit = regexp.MustCompile(`(?i)(?:\b(?:rpm|tpm|rpd|qps)\b|quota[_\s-]*metric|rate[_\s-]*limit|too many requests|(?:requests?|tokens?)\s+(?:per|/)\s*(?:second|minute)|(?:per|/)\s*(?:second|minute)\s+(?:requests?|tokens?)|generate[_\s-]*requests[_\s-]*per[_\s-]*(?:minute|second)|tokens?[_\s-]*per[_\s-]*(?:minute|second))`)

func IsQuotaExhaustedMessage(message string) bool {
	message = strings.ToLower(message)
	// Authentication/authorization and provider-side 5xx failures never rotate,
	// even when a gateway happens to echo a quota-looking phrase in the body.
	if nonFailoverHTTPStatus.MatchString(message) {
		return false
	}
	// Provider APIs frequently describe an ordinary rate limit as "quota
	// exceeded", especially Google-style responses containing a quota metric.
	// These limits recover with time and must stay on the current provider.
	if transientQuotaLimit.MatchString(message) {
		return false
	}
	markers := []string{
		"insufficient_quota", "quota_exceeded", "quota exceeded", "quota exhausted",
		"exceeded your current quota", "billing_hard_limit_reached",
		"billing hard limit", "billing_not_active", "credit balance", "insufficient credit",
		"insufficient balance", "balance is too low", "payment required", "status 402",
		"余额不足", "额度不足", "额度已用尽", "欠费",
	}
	for _, marker := range markers {
		if strings.Contains(message, marker) {
			return true
		}
	}
	// gRPC RESOURCE_EXHAUSTED is overloaded for both account quota and ordinary
	// request-rate limiting. Preserve it as an explicit exhaustion signal only
	// when the same error does not identify a transient rate limit.
	return strings.Contains(message, "resource_exhausted") &&
		!strings.Contains(message, "rate limit") &&
		!strings.Contains(message, "too many requests")
}

// quotaAwareTransport preserves Norma's normal retry behavior except for a 429
// whose body explicitly says the account quota/balance is exhausted. Norma's
// retry loop treats every 429 as transient; normalizing only that response to
// 402 lets a task router fail over immediately while retaining the original
// response body for provider-specific classification and audit logs.
type quotaAwareTransport struct {
	base http.RoundTripper
	// stripAuth prevents OpenAI credentials or the internal placeholder from
	// reaching Ollama. Only enabled for an explicit Ollama configuration.
	stripAuth   bool
	bearerToken string
	// sessionHeaderKey, when non-empty, is the HTTP header name each request
	// carries; its value is the session id read from the request context. Empty
	// disables it. See Config.SessionHeaderKey.
	sessionHeaderKey string
	// cyberAccessProgram is injected into Responses API JSON only when explicitly
	// selected by this provider's profile. Empty does not touch the request body.
	cyberAccessProgram string
}

func (t quotaAwareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.stripAuth || t.bearerToken != "" || t.cyberAccessProgram != "" {
		// Clone before mutating so a shared caller request is left untouched.
		req = req.Clone(req.Context())
	}
	if t.cyberAccessProgram != "" && req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/responses") {
		var err error
		req, err = withCyberAccessProgram(req, t.cyberAccessProgram)
		if err != nil {
			return nil, err
		}
	}
	// Custom session-id header: name is user-configured, value is THIS run's
	// session id (norma stashes it on the context via transcript.WithSessionID).
	// Stable across a session's turns and distinct across sessions — exactly what
	// a session-keyed prompt cache wants. Skipped when no session id is present.
	if t.sessionHeaderKey != "" {
		if sid := transcript.SessionIDFrom(req.Context()); sid != "" {
			req.Header.Set(t.sessionHeaderKey, sid)
		}
	}
	if t.stripAuth {
		req.Header.Del("Authorization")
		req.Header.Del("X-Api-Key")
	}
	if t.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+t.bearerToken)
	}
	// When LLM recording is on, the Recorder puts a Capture on the context so the
	// raw wire bodies can be persisted. This is the only layer that still sees
	// them: norma builds the request body internally and decodes the SSE response
	// before either reaches the recorder.
	capt := llmrec.CaptureFrom(req.Context())
	capt.SetRequest(requestBodySnapshot(req))

	resp, err := t.base.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	// Tee rather than read: a 200 is an SSE stream that must keep streaming. The
	// 429 branch below reads through this wrapper, so its body lands in the
	// capture before being replaced.
	resp.Body = capt.TeeResponse(resp.StatusCode, resp.Body)

	if resp.StatusCode != http.StatusTooManyRequests {
		return resp, nil
	}
	body, readErr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if readErr != nil {
		return resp, nil
	}
	if IsQuotaExhaustedMessage(string(body)) {
		resp.StatusCode = http.StatusPaymentRequired
		resp.Status = "402 Payment Required"
	}
	return resp, nil
}

// withCyberAccessProgram adds the documented Responses API request field while
// preserving all other JSON fields. Norma constructs requests with GetBody, so
// this transport can read the body without consuming the original or breaking
// retries. It runs before llmrec captures the outgoing wire bytes.
func withCyberAccessProgram(req *http.Request, program string) (*http.Request, error) {
	if req.GetBody == nil {
		return nil, fmt.Errorf("llm: cannot set cyber access program on request without replayable JSON body")
	}
	bodyReader, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("llm: read Responses request body: %w", err)
	}
	raw, readErr := io.ReadAll(bodyReader)
	closeErr := bodyReader.Close()
	if readErr != nil {
		return nil, fmt.Errorf("llm: read Responses request body: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("llm: close Responses request body: %w", closeErr)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("llm: invalid Responses request JSON: %v", err)
	}
	if body == nil {
		return nil, fmt.Errorf("llm: Responses request body must be a JSON object")
	}
	programs := make(map[string]json.RawMessage)
	if existing, ok := body["access_programs"]; ok && !bytes.Equal(bytes.TrimSpace(existing), []byte("null")) {
		if err := json.Unmarshal(existing, &programs); err != nil {
			return nil, fmt.Errorf("llm: invalid Responses access_programs JSON: %v", err)
		}
		if programs == nil {
			return nil, fmt.Errorf("llm: Responses access_programs must be a JSON object")
		}
	}
	programs["cyber"], _ = json.Marshal(program)
	body["access_programs"], err = json.Marshal(programs)
	if err != nil {
		return nil, fmt.Errorf("llm: encode Responses access_programs: %w", err)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("llm: encode Responses request: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(encoded))
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(encoded)), nil }
	req.ContentLength = int64(len(encoded))
	return req, nil
}

// requestBodySnapshot copies an outgoing request body without consuming it.
// norma builds every model request from a *bytes.Reader, so net/http populates
// GetBody and the copy has no effect on what gets sent.
func requestBodySnapshot(req *http.Request) string {
	if req.GetBody == nil {
		return ""
	}
	rc, err := req.GetBody()
	if err != nil {
		return ""
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}
	return string(b)
}

type providerTransportOptions struct {
	stripAuth          bool
	bearerToken        string
	cyberAccessProgram string
}

func quotaAwareHTTPClient(proxy, sessionHeaderKey string, opts ...providerTransportOptions) (*http.Client, error) {
	var option providerTransportOptions
	if len(opts) > 0 {
		option = opts[0]
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		transport.Proxy = nil // 留空=直连,不回退 HTTP_PROXY/HTTPS_PROXY 环境变量
	} else {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("llm: invalid proxy %q: %w", proxy, err)
		}
		switch proxyURL.Scheme {
		case "http", "https", "socks5":
		case "":
			return nil, fmt.Errorf("llm: proxy %q missing scheme (use http://, https:// or socks5://)", proxy)
		default:
			return nil, fmt.Errorf("llm: unsupported proxy scheme %q (use http, https or socks5)", proxyURL.Scheme)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	return &http.Client{Transport: quotaAwareTransport{
		base: transport, stripAuth: option.stripAuth,
		bearerToken:        option.bearerToken,
		sessionHeaderKey:   strings.TrimSpace(sessionHeaderKey),
		cyberAccessProgram: option.cyberAccessProgram,
	}}, nil
}

// logTestConnection prints the raw HTTP status code(s) and response body of a
// connection test to the server log, so "点击测试" leaves a diagnosable trail of
// exactly what the gateway returned — 401 bodies, quota text, empty frames — not
// just the collapsed ok/err the UI shows. Bodies are clipped to keep a chatty
// SSE stream from flooding the log.
func logTestConnection(c Config, capt *llmrec.Capture) {
	attempts := capt.Attempts()
	if len(attempts) == 0 {
		log.Printf("[llm-test] %s / %s @ %s — 未发出任何 HTTP 请求(配置解析或建连即失败)",
			c.Provider(), c.Model, c.BaseURL)
		return
	}
	for i, a := range attempts {
		log.Printf("[llm-test] %s / %s @ %s — 尝试 %d/%d HTTP %d\n响应体: %s",
			c.Provider(), c.Model, c.BaseURL, i+1, len(attempts), a.Status, clipBody(a.Body))
	}
}

// clipBody trims a wire body for logging. 4K is plenty to show an error JSON or
// the head of an SSE stream while bounding a runaway response.
func clipBody(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(空)"
	}
	const max = 4096
	if len(s) > max {
		return s[:max] + fmt.Sprintf("…(截断,共 %d 字节)", len(s))
	}
	return s
}

// TestConnection makes a minimal real completion to verify the provider/model/
// endpoint/key actually work. Returns the round-trip latency and the model's
// reply text.
func TestConnection(ctx context.Context, c Config) (time.Duration, string, error) {
	prov, err := c.NewProvider()
	if err != nil {
		return 0, "", err
	}
	timeout := 30 * time.Second
	if c.IsOllama() {
		// A local model may need to load its weights on the first request.
		timeout = 90 * time.Second
	}
	if c.IsRemoteOllama() {
		o := c.OllamaRemote.Resolved()
		timeout = time.Duration(o.QueueTimeoutSeconds+o.RequestTimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// 抓取原始 wire 报文:连接测试最需要看到的就是网关到底回了什么(状态码+响应体),
	// 而 norma 把响应解码成 StreamEvent 后这些就没了。quotaAwareTransport 会在
	// context 里找到这个 Capture 并填入每次 HTTP 尝试的状态码与 body。
	ctx, capt := llmrec.NewCapture(ctx)
	defer logTestConnection(c, capt)
	// 连接测试是一条单发路径,不经过 agentcore 的会话循环,因此没人往 context 上挂
	// session id。对配了 SessionHeaderKey 的端点(如 opencode zen 强制要求
	// x-opencode-session 头,缺了直接 400 MissingSessionID),这会导致"对话正常、
	// 点击测试却 400"的落差。这里补挂一个一次性随机 session id,让测试与真实对话走同
	// 一套发头逻辑;未配 SessionHeaderKey 的端点不读它,无副作用。
	ctx = transcript.WithSessionID(ctx, "conntest-"+transcript.NewSessionID())
	start := time.Now()
	testMaxTokens := 8192
	if c.IsRemoteOllama() && c.MaxTokens > 0 {
		testMaxTokens = c.MaxTokens
	}
	if c.IsBedrockMarketplace() || c.IsBedrockConverse() {
		testMaxTokens = c.MaxTokens
		if testMaxTokens <= 0 {
			if c.IsBedrockConverse() {
				testMaxTokens = defaultBedrockMaxTokens
			} else {
				testMaxTokens = defaultMarketplaceMaxTokens
			}
		}
	}
	// MaxTokens 要给足：推理模型(如 deepseek-v4-pro)在给出答案前会先产出一大段
	// 思考(实测对一句 "ping" 也能烧 ~2900 token)。若只给 32,模型会一直卡在"思考阶段"
	// 就撞到输出上限(finish=length)、被截断,连接测试虽仍算通(err=nil)但显示成
	// "已中断/length/resume" 一团糟。给足预算让它把 OK 干净吐完(finish=stop)。
	// EscalateMaxTokens 保持 false:不因截断而抬额重试,避免 resume 循环空烧。
	reply, err := agentcore.Run(ctx, agentcore.Options{
		Provider:       prov,
		SystemPrompt:   []string{"你是连接测试。直接输出两个字符 OK 即可，不要思考、不要解释、不要别的。"},
		PermissionMode: acperm.ModeBypass,
		MaxTurns:       1,
		MaxTokens:      testMaxTokens,
		NonStreaming:   !c.Stream, // 用该 profile 的真实收发模式做连接测试
	}, "ping")
	lat := time.Since(start)
	if err != nil {
		return lat, "", err
	}
	// err==nil 还不够：请求通了但模型一个字都不吐的情况真实存在(思考把预算烧光、
	// 正文被安全策略吞掉、兼容层把 content 丢了)。这种配置在会话里就是"不回话",
	// 测试却报成功——正是本项要消除的落差。没有可见正文一律判失败。
	reply = strings.TrimSpace(reply)
	if reply == "" {
		return lat, "", fmt.Errorf("模型无回复内容（请求已通，但未返回任何文本）")
	}
	return lat, reply, nil
}
