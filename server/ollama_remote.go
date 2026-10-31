package server

import (
	"fmt"
	"net/http"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/ollamaendpoint"
)

func (s *Server) resolveRemoteOllamaKey(cfg *agent.Config, profileID *int64) error {
	if cfg.OllamaRemote.Resolved().AuthMode == "none" {
		cfg.APIKey = ""
	}
	if cfg.APIKey == "" && cfg.OllamaRemote.Resolved().AuthMode == "bearer" && profileID != nil && s.m != nil && s.m.pg != nil {
		if p, err := s.m.pg.ProfileByID(*profileID); err == nil && p != nil && ollamaendpoint.ReuseKey(p.Format, p.BaseURL, p.OllamaRemote, cfg.BaseURL, cfg.OllamaRemote) {
			cfg.APIKey = p.APIKey
		}
	}
	return cfg.ValidateRemoteOllama()
}

func (s *Server) ollamaStatus(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Provider     string                 `json:"provider"`
		BaseURL      string                 `json:"base_url"`
		Model        string                 `json:"model"`
		Proxy        string                 `json:"proxy"`
		APIKey       string                 `json:"api_key"`
		ProfileID    *int64                 `json:"profile_id"`
		OllamaRemote ollamaendpoint.Options `json:"ollama_remote"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cfg := agent.ConfigFrom(req.Provider, req.Model, req.BaseURL, req.APIKey, req.Proxy)
	cfg.OllamaRemote = req.OllamaRemote
	if !cfg.IsRemoteOllama() {
		writeErr(w, 400, fmt.Sprintf("provider must be %s", ollamaendpoint.Remote))
		return
	}
	if err := s.resolveRemoteOllamaKey(&cfg, req.ProfileID); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	status, err := agent.CheckOllamaStatus(r.Context(), cfg)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "status": status})
}
