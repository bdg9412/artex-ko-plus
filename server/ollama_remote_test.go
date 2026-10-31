package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestRemoteOllamaStatusAndModelsNeverGenerate(t *testing.T) {
	var reads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-gateway-token" {
			t.Errorf("unexpected metadata request %s %s", r.Method, r.URL.Path)
		}
		reads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"fixture:latest"}]}`))
		case "/api/ps":
			_, _ = w.Write([]byte(`{"models":[]}`))
		default:
			t.Errorf("state-changing/unknown endpoint %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	s := &Server{}
	body := `{"provider":"ollama-remote","model":"fixture:latest","base_url":"` + srv.URL + `/v1","api_key":"test-gateway-token","ollama_remote":{"auth_mode":"bearer"}}`
	for _, handler := range []http.HandlerFunc{s.ollamaStatus, s.pgListModels} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodPost, "/api/llm/ollama/status", strings.NewReader(body)))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) {
			t.Fatalf("status=%d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "test-gateway-token") {
			t.Fatal("credential leaked in response")
		}
	}
	if reads.Load() != 4 {
		t.Fatalf("metadata requests=%d", reads.Load())
	}
}

func TestRemoteOllamaCannotBorrowGlobalCloudCredential(t *testing.T) {
	s := &Server{llmCfg: agent.ConfigFrom("openai", "cloud", "https://cloud.example/v1", "cloud-secret", "")}
	for _, handler := range []http.HandlerFunc{s.ollamaStatus, s.pgListModels, s.testLLM} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodPost, "/api/llm/test", strings.NewReader(`{"provider":"ollama-remote","model":"fixture","base_url":"https://model.example/v1","ollama_remote":{"auth_mode":"bearer"}}`)))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":false`) || strings.Contains(rec.Body.String(), "cloud-secret") {
			t.Fatalf("unsafe key resolution: %d %s", rec.Code, rec.Body.String())
		}
	}
}

func TestRemoteOllamaExplicitResponseTestUsesGateway(t *testing.T) {
	var generated atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("gateway token missing")
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/ps" {
			_, _ = w.Write([]byte(`{"models":[{"name":"fixture","context_length":32768}]}`))
			return
		}
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		var request struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.Model != "fixture" {
			t.Errorf("model=%s", request.Model)
		}
		generated.Add(1)
		_, _ = w.Write([]byte(`{"id":"fixture","object":"chat.completion","model":"fixture","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer srv.Close()
	body := `{"provider":"ollama-remote","model":"fixture","base_url":"` + srv.URL + `/v1","api_key":"fixture-token","streaming":false,"ollama_remote":{"auth_mode":"bearer","max_concurrent":1}}`
	rec := httptest.NewRecorder()
	(&Server{}).testLLM(rec, httptest.NewRequest(http.MethodPost, "/api/llm/test", strings.NewReader(body)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) || generated.Load() != 1 {
		t.Fatalf("status=%d %s generated=%d", rec.Code, rec.Body.String(), generated.Load())
	}
}
