package db

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestBedrockProfileRequiresItsOwnKey(t *testing.T) {
	var d DB
	_, err := d.SaveProfile(&LLMProfile{Format: "bedrock", Model: "us.anthropic.claude-sonnet-4-6"})
	if !errors.Is(err, ErrBedrockAPIKeyRequired) {
		t.Fatalf("missing Bedrock key: got %v", err)
	}
	_, err = d.SaveProfile(&LLMProfile{Format: "bedrock-marketplace", Model: "arn:aws:sagemaker:us-east-1:123456789012:endpoint/deepseek-r1"})
	if !errors.Is(err, ErrBedrockAPIKeyRequired) {
		t.Fatalf("missing Marketplace key: got %v", err)
	}
	_, err = d.SaveProfile(&LLMProfile{Format: "bedrock-converse", Model: "zai.glm-4.7"})
	if !errors.Is(err, ErrBedrockAPIKeyRequired) {
		t.Fatalf("missing Converse key: got %v", err)
	}
}

func TestBedrockProfileKeyCannotCrossProviderBoundary(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	id, err := d.SaveProfile(&LLMProfile{
		Name: fmt.Sprintf("t-bedrock-%d", time.Now().UnixNano()), Format: "bedrock",
		Model: "us.anthropic.claude-sonnet-4-6", BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com/anthropic",
		APIKey: "bedrock-test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id)

	p, err := d.ProfileByID(id)
	if err != nil || p == nil {
		t.Fatalf("ProfileByID: profile=%v err=%v", p, err)
	}
	p.APIKey = ""
	if _, err := d.SaveProfile(p); err != nil {
		t.Fatalf("same-provider blank-key update: %v", err)
	}
	stored, err := d.ProfileByID(id)
	if err != nil || stored == nil || stored.APIKey != "bedrock-test-key" {
		t.Fatalf("Bedrock key was not retained on same-provider update: profile=%v err=%v", stored, err)
	}

	chain, err := d.PoolProfiles()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, candidate := range chain {
		if candidate.ID == id {
			found = true
		}
	}
	if !found {
		t.Fatal("keyed Bedrock profile missing from failover pool")
	}
	stored.Format = "bedrock-converse"
	stored.APIKey = ""
	if _, err := d.SaveProfile(stored); !errors.Is(err, ErrBedrockAPIKeyRequired) {
		t.Fatalf("switch from Claude Bedrock to Converse without a new key: got %v", err)
	}
	stored.Format = "bedrock-marketplace"
	stored.APIKey = ""
	if _, err := d.SaveProfile(stored); !errors.Is(err, ErrBedrockAPIKeyRequired) {
		t.Fatalf("switch from Claude Bedrock to Marketplace without a new key: got %v", err)
	}

	stored.Format = "openai"
	stored.APIKey = ""
	if _, err := d.SaveProfile(stored); !errors.Is(err, ErrBedrockAPIKeyRequired) {
		t.Fatalf("switch away from Bedrock without a new key: got %v", err)
	}
	check, err := d.ProfileByID(id)
	if err != nil || check == nil || check.Format != "bedrock" {
		t.Fatalf("rejected switch changed the profile: profile=%v err=%v", check, err)
	}
}

func TestBedrockConverseProfilePersistsWithoutLeakingKeyAcrossFormats(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	id, err := d.SaveProfile(&LLMProfile{
		Name: fmt.Sprintf("t-converse-%d", time.Now().UnixNano()), Format: "bedrock-converse",
		Model: "zai.glm-4.7", BaseURL: "https://bedrock-runtime.ap-northeast-2.amazonaws.com",
		APIKey: "converse-test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id)

	stored, err := d.ProfileByID(id)
	if err != nil || stored == nil || stored.Format != "bedrock-converse" || stored.APIKey != "converse-test-key" {
		t.Fatalf("Converse profile was not persisted: profile=%v err=%v", stored, err)
	}
	stored.APIKey = ""
	if _, err := d.SaveProfile(stored); err != nil {
		t.Fatalf("same-format blank-key update: %v", err)
	}
	stored, err = d.ProfileByID(id)
	if err != nil || stored == nil || stored.APIKey != "converse-test-key" {
		t.Fatalf("same-format key was not retained: profile=%v err=%v", stored, err)
	}
	stored.Format = "openai"
	stored.APIKey = ""
	if _, err := d.SaveProfile(stored); !errors.Is(err, ErrBedrockAPIKeyRequired) {
		t.Fatalf("switch away from Converse without a new key: %v", err)
	}
}
