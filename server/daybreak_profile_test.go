package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A profile's Daybreak choice must reach the connection-test request too: a
// test without the same access_programs body could pass while the real run
// fails (or the other way around).
func TestLLMConnectionTestSendsOptionalDaybreakProgram(t *testing.T) {
	for _, tc := range []struct {
		name      string
		program   string
		sendField bool
	}{
		{name: "off-explicit", sendField: true},
		{name: "off-omitted"},
		{name: "blue", program: "daybreak_blue", sendField: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var received map[string]json.RawMessage
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/responses" || r.Method != http.MethodPost {
					t.Errorf("request %s %s, want POST /v1/responses", r.Method, r.URL.Path)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read request: %v", err)
				} else if err := json.Unmarshal(body, &received); err != nil {
					t.Errorf("decode request: %v", err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"id":"resp_test","object":"response","created_at":1,"status":"completed","model":"gpt-6-sol","output":[{"id":"msg_test","type":"message","role":"assistant","status":"completed","content":[{"type":"output_text","text":"OK","annotations":[]}]}],"usage":{"input_tokens":4,"output_tokens":2,"total_tokens":6}}`)
			}))
			t.Cleanup(upstream.Close)

			request := map[string]any{
				"provider":  "openai-responses",
				"model":     "gpt-6-sol",
				"base_url":  upstream.URL + "/v1",
				"api_key":   "test-only",
				"streaming": false,
			}
			if tc.sendField {
				request["cyber_access_program"] = tc.program
			}
			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			rec := httptest.NewRecorder()
			(&Server{}).testLLM(rec, httptest.NewRequest(http.MethodPost, "/api/llm/test", strings.NewReader(string(payload))))
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
			if !result.OK {
				t.Fatalf("connection test failed: %s", result.Error)
			}
			if received == nil {
				t.Fatal("no request received by upstream")
			}
			program, present := received["access_programs"]
			if tc.program == "" {
				if present {
					t.Fatalf("Daybreak off still sent access_programs: %s", program)
				}
				return
			}
			var access struct {
				Cyber string `json:"cyber"`
			}
			if !present || json.Unmarshal(program, &access) != nil || access.Cyber != tc.program {
				t.Fatalf("access_programs=%s, want cyber=%q", program, tc.program)
			}
		})
	}
}
