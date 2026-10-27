package agent

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// OrcaRouter Cyber Inference is a named, first-class provider: inference and
// model discovery live on the API origin, while credential issuance lives on
// the auth origin. Keep both constants here; never derive one from the other.
//
// It speaks the OpenAI chat-completions wire format, so it reuses the existing
// OpenAI adapter and only adds its own defaults, catalog filtering and
// credential handling.
const (
	OrcaRouterProviderID   = "orcarouter"
	OrcaRouterDisplayName  = "OrcaRouter Cyber Inference"
	OrcaRouterAPIBase      = "https://api.orcarouter.ai/v1"
	OrcaRouterAuthBase     = "https://www.orcarouter.ai"
	OrcaRouterAPIKeyEnv    = "ORCAROUTER_API_KEY"
	OrcaRouterDefaultModel = "orcarouter/auto"
	OrcaRouterFallback     = "orcarouter/fusion"
	// OrcaRouterCyberUltra / OrcaRouterCyberZero are the dedicated cyber models
	// recommended to verified security teams. They are recommendations only: the
	// account's own catalog decides whether they are callable.
	OrcaRouterCyberUltra = "orcacyber-ultra-1.0"
	OrcaRouterCyberZero  = "orcacyber-zero-1.5"
)

// orcaRouterTextEndpointTypes are the endpoint families the chat adapter can
// actually speak. A model that advertises none of them is not offered.
var orcaRouterTextEndpointTypes = []string{"openai", "anthropic", "gemini", "openai-response"}

// orcaRouterNonTextEndpoints mark records that are not chat models even when a
// chat-tagged catalog page returns them.
var orcaRouterNonTextEndpoints = map[string]bool{
	"image-generation": true,
	"openai-video":     true,
	"jina-rerank":      true,
	"embeddings":       true,
}

// OrcaRouterModelsURL is the authoritative discovery endpoint for one origin.
// The capability filter is part of the request so a non-chat model never has to
// be filtered out of the authoritative answer.
func OrcaRouterModelsURL(baseURL, capability string) string {
	base := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if base == "" {
		base = OrcaRouterAPIBase
	}
	if capability == "" {
		capability = "chat"
	}
	return base + "/models?capability=" + url.QueryEscape(capability)
}

// orcaRouterCatalogRecord is the subset of GET /models the client depends on.
// Unknown fields are ignored; unknown endpoint families are dropped rather than
// guessed at, and a model without declared capabilities fails closed.
type orcaRouterCatalogRecord struct {
	ID                    string   `json:"id"`
	SupportedEndpointType []string `json:"supported_endpoint_types"`
	Architecture          struct {
		InputModalities []string `json:"input_modalities"`
	} `json:"architecture"`
	ContextLength int `json:"context_length"`
}

// ParseOrcaRouterCatalog returns the text-capable chat model IDs from a catalog
// response, in catalog order, with duplicates removed. It errors on a malformed
// envelope so the caller can fall back to its verified seed instead of showing
// an empty selector.
func ParseOrcaRouterCatalog(payload []byte) ([]string, error) {
	var envelope struct {
		Data []orcaRouterCatalogRecord `json:"data"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("orcarouter: invalid model catalog JSON: %w", err)
	}
	seen := make(map[string]bool, len(envelope.Data))
	out := make([]string, 0, len(envelope.Data))
	for _, record := range envelope.Data {
		if !orcaRouterChatModel(record) || seen[record.ID] {
			continue
		}
		seen[record.ID] = true
		out = append(out, record.ID)
	}
	return out, nil
}

// orcaRouterChatModel applies the same rule as the UI: at least one text
// endpoint family, and not a non-text-only record.
func orcaRouterChatModel(record orcaRouterCatalogRecord) bool {
	id := strings.TrimSpace(record.ID)
	if id == "" || strings.ContainsAny(id, " \t\r\n") {
		return false
	}
	if len(record.SupportedEndpointType) == 0 {
		return false
	}
	speaksText := false
	for _, endpoint := range record.SupportedEndpointType {
		for _, textEndpoint := range orcaRouterTextEndpointTypes {
			if endpoint == textEndpoint {
				speaksText = true
				break
			}
		}
	}
	if !speaksText {
		return false
	}
	onlyNonText := true
	for _, endpoint := range record.SupportedEndpointType {
		if !orcaRouterNonTextEndpoints[endpoint] {
			onlyNonText = false
			break
		}
	}
	return !onlyNonText
}
