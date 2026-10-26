package db

import (
	"fmt"
	"testing"
	"time"
)

func TestValidCyberAccessProgram(t *testing.T) {
	for _, tc := range []struct {
		format, program string
		want            bool
	}{
		{"openai-responses", "", true},
		{"openai-responses", "standard", true},
		{"openai-responses", "daybreak_blue", true},
		{"openai-responses", "daybreak_red", true},
		{"openai-responses", "unknown", false},
		{"openai", "daybreak_blue", false},
		{"ollama", "daybreak_blue", false},
		{"anthropic", "daybreak_blue", false},
		{"ollama", "", true},
	} {
		if got := ValidCyberAccessProgram(tc.format, tc.program); got != tc.want {
			t.Errorf("ValidCyberAccessProgram(%q,%q)=%v, want %v", tc.format, tc.program, got, tc.want)
		}
	}
	var d DB
	if _, err := d.SaveProfile(&LLMProfile{Format: "ollama", CyberAccessProgram: "daybreak_blue"}); err == nil {
		t.Fatal("SaveProfile accepted a Daybreak program for Ollama")
	}
}

func TestProfileCyberAccessProgramRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { d.Close() })

	id, err := d.SaveProfile(&LLMProfile{
		Name: fmt.Sprintf("t-cyber-%d", time.Now().UnixNano()), Format: "openai-responses",
		Model: "gpt-6-sol", APIKey: "test-key", CyberAccessProgram: "daybreak_blue",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })

	check := func(want string) *LLMProfile {
		t.Helper()
		p, err := d.ProfileByID(id)
		if err != nil || p == nil || p.CyberAccessProgram != want {
			t.Fatalf("keyed load: profile=%+v err=%v, want program %q", p, err, want)
		}
		profiles, err := d.ListProfiles()
		if err != nil {
			t.Fatal(err)
		}
		for _, listed := range profiles {
			if listed.ID == id {
				if listed.CyberAccessProgram != want {
					t.Fatalf("list load: program=%q, want %q", listed.CyberAccessProgram, want)
				}
				return p
			}
		}
		t.Fatal("profile missing from ListProfiles")
		return nil
	}

	p := check("daybreak_blue")
	p.APIKey = "" // editing an existing profile leaves its key intact
	p.CyberAccessProgram = "daybreak_red"
	if _, err := d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	if got := check("daybreak_red"); got.APIKey != "test-key" {
		t.Fatalf("blank API key update changed stored key: %q", got.APIKey)
	}
	p.APIKey = "new-key"
	p.CyberAccessProgram = "standard"
	if _, err := d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	check("standard")
	p.APIKey = ""
	p.CyberAccessProgram = "" // switch off must remove the explicit request option
	if _, err := d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	check("")
}
