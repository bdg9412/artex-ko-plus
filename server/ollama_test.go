package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOllamaModelListNeedsNoKeyAndSendsNoAuthorization(t *testing.T) {
	var gotPath, gotAuth string
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"fixture-local:latest"}]}`))
	}))
	t.Cleanup(endpoint.Close)

	s := &Server{}
	request := `{"provider":"ollama","base_url":"` + endpoint.URL + `/v1","api_key":"must-not-leak"}`
	rec := httptest.NewRecorder()
	s.pgListModels(rec, httptest.NewRequest(http.MethodPost, "/api/llm/models", strings.NewReader(request)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		OK     bool     `json:"ok"`
		Models []string `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || len(response.Models) != 1 || response.Models[0] != "fixture-local:latest" {
		t.Fatalf("response=%+v", response)
	}
	if gotPath != "/v1/models" || gotAuth != "" {
		t.Fatalf("request path=%q authorization=%q", gotPath, gotAuth)
	}
}
