package server

import (
	"encoding/json"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestLLMProfileDTORestoresCyberProgramWithoutKey(t *testing.T) {
	p := &db.LLMProfile{
		ID: 17, Format: "openai-responses", Model: "gpt-6-sol",
		CyberAccessProgram: "daybreak_blue", APIKey: "private-test-key",
	}
	dto := llmProfileDTO(p)
	if dto.CyberAccessProgram != "daybreak_blue" {
		t.Fatalf("cyber program=%q, want daybreak_blue", dto.CyberAccessProgram)
	}
	b, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["cyber_access_program"] != "daybreak_blue" {
		t.Fatalf("DTO omits saved program: %s", b)
	}
	if _, present := decoded["api_key"]; present {
		t.Fatalf("DTO exposed an API key: %s", b)
	}
}
