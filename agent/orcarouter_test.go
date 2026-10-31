package agent

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// catalogFixture mirrors the shape returned by GET /models?capability=chat on
// OrcaRouter, including records the chat adapter cannot serve.
const catalogFixture = `{
  "data": [
    {"id":"deepseek/deepseek-v4-pro","supported_endpoint_types":["openai","anthropic"],"architecture":{"input_modalities":["text"]},"context_length":128000},
    {"id":"deepseek/deepseek-v4-flash-vision-exp","supported_endpoint_types":["openai","openai-response"],"architecture":{"input_modalities":["text","image"]}},
    {"id":"vendor/text-embedding-3","supported_endpoint_types":["embeddings"],"architecture":{"input_modalities":["text"]}},
    {"id":"vendor/flux-pro","supported_endpoint_types":["image-generation"],"architecture":{"input_modalities":[]}},
    {"id":"vendor/video-1","supported_endpoint_types":["openai-video"],"architecture":{"input_modalities":[]}},
    {"id":"vendor/jina-reranker","supported_endpoint_types":["jina-rerank"],"architecture":{"input_modalities":[]}},
    {"id":"vendor/mystery"},
    {"id":"bad id","supported_endpoint_types":["openai"]},
    {"id":"orcarouter/auto","supported_endpoint_types":["openai","anthropic","gemini","openai-response"],"architecture":{"input_modalities":["text","image"]}},
    {"id":"orcarouter/auto","supported_endpoint_types":["openai"]}
  ]
}`

func TestParseOrcaRouterCatalogFiltersChatModels(t *testing.T) {
	ids, err := ParseOrcaRouterCatalog([]byte(catalogFixture))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		"deepseek/deepseek-v4-pro",
		"deepseek/deepseek-v4-flash-vision-exp",
		"orcarouter/auto",
	}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("chat model IDs = %v, want %v", ids, want)
	}
}

func TestParseOrcaRouterCatalogRejectsMalformedEnvelope(t *testing.T) {
	if _, err := ParseOrcaRouterCatalog([]byte(`{"data":`)); err == nil {
		t.Fatal("expected an error for a truncated catalog envelope")
	}
}

func TestParseOrcaRouterCatalogEmptyIsNotAnError(t *testing.T) {
	ids, err := ParseOrcaRouterCatalog([]byte(`{"data":[]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected no IDs, got %v", ids)
	}
}

func TestOrcaRouterModelsURL(t *testing.T) {
	cases := []struct{ base, capability, want string }{
		{"", "", "https://api.orcarouter.ai/v1/models?capability=chat"},
		{"https://api.orcarouter.ai/v1/", "chat", "https://api.orcarouter.ai/v1/models?capability=chat"},
		{" https://self-hosted.example/v1 ", "chat", "https://self-hosted.example/v1/models?capability=chat"},
	}
	for _, tc := range cases {
		if got := OrcaRouterModelsURL(tc.base, tc.capability); got != tc.want {
			t.Errorf("OrcaRouterModelsURL(%q, %q) = %q, want %q", tc.base, tc.capability, got, tc.want)
		}
	}
}

// setEnvForTest sets one variable and restores the previous state.
func setEnvForTest(t *testing.T, name, value string) {
	t.Helper()
	previous, hadPrevious := os.LookupEnv(name)
	if err := os.Setenv(name, value); err != nil {
		t.Skipf("cannot set %s: %v", name, err)
	}
	t.Cleanup(func() {
		if hadPrevious {
			_ = os.Setenv(name, previous)
			return
		}
		_ = os.Unsetenv(name)
	})
}

func TestOrcaRouterConfigDefaults(t *testing.T) {
	setEnvForTest(t, OrcaRouterAPIKeyEnv, "sk-orca-test-value")

	cfg := ConfigFrom(OrcaRouterProviderID, "", "", "", "")
	if cfg.ProviderID != OrcaRouterProviderID {
		t.Fatalf("ProviderID = %q, want %q", cfg.ProviderID, OrcaRouterProviderID)
	}
	if cfg.BaseURL != OrcaRouterAPIBase {
		t.Fatalf("BaseURL = %q, want %q", cfg.BaseURL, OrcaRouterAPIBase)
	}
	if cfg.Model != OrcaRouterDefaultModel {
		t.Fatalf("Model = %q, want %q", cfg.Model, OrcaRouterDefaultModel)
	}
	if !cfg.IsOrcaRouter() {
		t.Fatal("IsOrcaRouter() = false for the orcarouter provider")
	}
	if cfg.Provider() != OrcaRouterProviderID {
		t.Fatalf("Provider() = %q, want %q", cfg.Provider(), OrcaRouterProviderID)
	}

	// Explicit values win over the defaults; a full endpoint URL is trimmed back
	// to the base because the adapter appends /chat/completions itself.
	custom := ConfigFrom(OrcaRouterProviderID, OrcaRouterFallback, "https://self-hosted.example/v1/chat/completions", "sk-orca-explicit", "")
	if custom.BaseURL != "https://self-hosted.example/v1" {
		t.Fatalf("explicit BaseURL was not honoured: %q", custom.BaseURL)
	}
	if custom.Model != OrcaRouterFallback {
		t.Fatalf("explicit Model was not honoured: %q", custom.Model)
	}
	if custom.APIKey != "sk-orca-explicit" {
		t.Fatal("explicit API key was not honoured")
	}
}

func TestOrcaRouterConfigReadsDedicatedEnvKey(t *testing.T) {
	setEnvForTest(t, OrcaRouterAPIKeyEnv, "sk-orca-from-env")
	setEnvForTest(t, "ARTEX_LLM_PROVIDER", OrcaRouterProviderID)

	cfg, ok := FromEnv()
	if !ok {
		t.Fatal("FromEnv reported no configuration for the orcarouter provider")
	}
	if cfg.APIKey != "sk-orca-from-env" {
		t.Fatal("API key was not read from the dedicated environment variable")
	}
	if cfg.BaseURL != OrcaRouterAPIBase || cfg.Model != OrcaRouterDefaultModel {
		t.Fatalf("unexpected defaults: base=%q model=%q", cfg.BaseURL, cfg.Model)
	}
	if cfg.Format != llm.FormatOpenAI {
		t.Fatalf("Format = %q, want the OpenAI chat wire format", cfg.Format)
	}
}

func TestOrcaRouterConfigDoesNotAffectOtherProviders(t *testing.T) {
	setEnvForTest(t, OrcaRouterAPIKeyEnv, "sk-orca-test-value")

	openai := ConfigFrom("openai", "", "", "sk-openai-value", "")
	if openai.IsOrcaRouter() {
		t.Fatal("openai config reports itself as OrcaRouter")
	}
	if openai.Provider() == OrcaRouterProviderID {
		t.Fatal("openai config resolved to the OrcaRouter provider id")
	}
	if openai.APIKey != "sk-openai-value" {
		t.Fatalf("openai config API key = %q, want its own key", openai.APIKey)
	}
	if openai.BaseURL == OrcaRouterAPIBase || openai.Model == OrcaRouterDefaultModel {
		t.Fatal("openai config inherited OrcaRouter defaults")
	}
}

func TestOrcaRouterDisplayNameIsBranded(t *testing.T) {
	if OrcaRouterDisplayName != "OrcaRouter Cyber Inference" {
		t.Fatalf("display name = %q", OrcaRouterDisplayName)
	}
	if !strings.Contains(OrcaRouterProviderID, "orcarouter") {
		t.Fatalf("provider id lost the brand keyword: %q", OrcaRouterProviderID)
	}
	payload, err := json.Marshal(map[string]string{
		"provider": OrcaRouterProviderID,
		"name":     OrcaRouterDisplayName,
		"base_url": OrcaRouterAPIBase,
	})
	if err != nil || !strings.Contains(string(payload), "api.orcarouter.ai") {
		t.Fatalf("serialized provider metadata lost the OrcaRouter origin: %s (%v)", payload, err)
	}
}
