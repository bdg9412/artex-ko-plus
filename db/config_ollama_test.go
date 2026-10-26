package db

import (
	"fmt"
	"testing"
	"time"
)

func TestOllamaProfileCanBeSavedAndUsedWithoutKey(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	id, err := d.SaveProfile(&LLMProfile{
		Name:    fmt.Sprintf("t-ollama-%d", time.Now().UnixNano()),
		Format:  "ollama",
		Model:   "qwen3:8b",
		BaseURL: "http://host.docker.internal:11434/v1",
	})
	if err != nil {
		t.Fatalf("SaveProfile with no key: %v", err)
	}
	defer d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id)

	p, err := d.ProfileByID(id)
	if err != nil || p == nil {
		t.Fatalf("ProfileByID: profile=%v err=%v", p, err)
	}
	if p.Format != "ollama" || p.APIKey != "" {
		t.Fatalf("saved profile format=%q key=%q", p.Format, p.APIKey)
	}

	chain, err := d.PoolProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range chain {
		if candidate.ID == id {
			return
		}
	}
	t.Fatal("keyless Ollama profile was excluded from the LLM pool")
}

func TestSwitchingHostedProfileToOllamaClearsCredential(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	id, err := d.SaveProfile(&LLMProfile{
		Name:   fmt.Sprintf("t-ollama-switch-%d", time.Now().UnixNano()),
		Format: "openai", Model: "hosted", APIKey: "old-hosted-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id)
	p, err := d.ProfileByID(id)
	if err != nil || p == nil {
		t.Fatalf("ProfileByID: %v", err)
	}
	p.Format = "ollama"
	p.Model = "fixture-local:latest"
	p.BaseURL = "http://127.0.0.1:11434/v1"
	if _, err := d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	stored, err := d.ProfileByID(id)
	if err != nil || stored == nil {
		t.Fatalf("ProfileByID after switch: %v", err)
	}
	if stored.Format != "ollama" || stored.APIKey != "" {
		t.Fatalf("old credential retained after switch: format=%q key=%q", stored.Format, stored.APIKey)
	}
	listed, err := d.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range listed {
		if item.ID == id && item.APIKeyHint != "" {
			t.Fatalf("old credential hint retained after switch: %q", item.APIKeyHint)
		}
	}
}
