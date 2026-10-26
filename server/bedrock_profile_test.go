package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestBedrockModelListRequiresManualModelID(t *testing.T) {
	for _, provider := range []string{"bedrock", "bedrock-converse", "bedrock-marketplace"} {
		t.Run(provider, func(t *testing.T) {
			rec := httptest.NewRecorder()
			(&Server{}).pgListModels(rec, httptest.NewRequest(http.MethodPost, "/api/llm/models",
				strings.NewReader(`{"provider":"`+provider+`","api_key":"test-only"}`)))
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var result struct {
				OK    bool   `json:"ok"`
				Error string `json:"error"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.OK || !strings.Contains(result.Error, "모델 ID") {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestSetLLMDoesNotReuseAnotherProvidersKeyForBedrock(t *testing.T) {
	s := &Server{llmCfg: agent.ConfigFrom("openai", "gpt-4o", "", "openai-test-secret", "")}
	rec := httptest.NewRecorder()
	s.setLLM(rec, httptest.NewRequest(http.MethodPost, "/api/llm", strings.NewReader(`{
		"provider":"bedrock",
		"model":"us.anthropic.claude-sonnet-4-6",
		"base_url":"https://bedrock-runtime.us-east-1.amazonaws.com/anthropic"
	}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "api_key required") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMarketplaceDoesNotReuseAnotherProvidersKey(t *testing.T) {
	s := &Server{llmCfg: agent.ConfigFrom("openai", "gpt-4o", "", "openai-test-secret", "")}
	rec := httptest.NewRecorder()
	s.setLLM(rec, httptest.NewRequest(http.MethodPost, "/api/llm", strings.NewReader(`{
		"provider":"bedrock-marketplace",
		"model":"arn:aws:sagemaker:us-east-1:123456789012:endpoint/deepseek-r1",
		"base_url":"https://bedrock-runtime.us-east-1.amazonaws.com"
	}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "api_key required") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConverseDoesNotReuseAnotherProvidersKey(t *testing.T) {
	s := &Server{llmCfg: agent.ConfigFrom("openai", "gpt-4o", "", "openai-test-secret", "")}
	rec := httptest.NewRecorder()
	s.setLLM(rec, httptest.NewRequest(http.MethodPost, "/api/llm", strings.NewReader(`{
		"provider":"bedrock-converse",
		"model":"zai.glm-4.7",
		"base_url":"https://bedrock-runtime.ap-northeast-2.amazonaws.com"
	}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "api_key required") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestConverseTestIgnoresMarketplaceRequestOptions(t *testing.T) {
	cfg := agent.ConfigFrom("bedrock-converse", "zai.glm-5.3",
		"https://bedrock-runtime.ap-northeast-2.amazonaws.com", "test-key", "")
	applyMarketplaceInvokeOptions(&cfg, "tgi", "raw")
	if cfg.InvokeSchema != "" || cfg.PromptStyle != "" {
		t.Fatalf("Marketplace options leaked to Converse: schema=%q style=%q", cfg.InvokeSchema, cfg.PromptStyle)
	}
	if _, err := cfg.NewProvider(); err != nil {
		t.Fatalf("Converse provider rejected normalized test options: %v", err)
	}

	marketplace := agent.ConfigFrom("bedrock-marketplace",
		"arn:aws:sagemaker:us-east-1:123456789012:endpoint/deepseek-r1",
		"https://bedrock-runtime.us-east-1.amazonaws.com", "test-key", "")
	applyMarketplaceInvokeOptions(&marketplace, "deepseek", "qwen")
	if marketplace.InvokeSchema != "deepseek" || marketplace.PromptStyle != "qwen" {
		t.Fatalf("Marketplace request options were not retained: schema=%q style=%q", marketplace.InvokeSchema, marketplace.PromptStyle)
	}
}

func TestMarketplaceProfileContextWindowDefaultAndOverride(t *testing.T) {
	cfg := agent.ConfigFrom("bedrock-marketplace", "arn:aws:sagemaker:us-east-1:123456789012:endpoint/deepseek-r1", "https://bedrock-runtime.us-east-1.amazonaws.com", "test-key", "")
	applyProfileContextWindow(&cfg, 0)
	if cfg.ContextWindowK != 32 || cfg.CompactionWindow() != 32000 {
		t.Fatalf("unset profile context window=%d compaction=%d", cfg.ContextWindowK, cfg.CompactionWindow())
	}
	applyProfileContextWindow(&cfg, 64)
	if cfg.ContextWindowK != 64 || cfg.CompactionWindow() != 64000 {
		t.Fatalf("explicit profile context window=%d compaction=%d", cfg.ContextWindowK, cfg.CompactionWindow())
	}
}
