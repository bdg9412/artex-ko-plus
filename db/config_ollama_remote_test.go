package db

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/ollamaendpoint"
	_ "modernc.org/sqlite"
)

func TestRemoteOllamaValidationBeforeDatabaseWrite(t *testing.T) {
	for _, p := range []LLMProfile{
		{Format: ollamaendpoint.Remote},
		{Format: ollamaendpoint.Remote, BaseURL: "https://model.example/v1", OllamaRemote: ollamaendpoint.Options{AuthMode: "bearer"}},
		{Format: ollamaendpoint.Remote, BaseURL: "https://model.example/v1", OllamaRemote: ollamaendpoint.Options{MaxConcurrent: 9}},
	} {
		if _, err := (&DB{}).SaveProfile(&p); !errors.Is(err, ErrRemoteOllamaProfile) {
			t.Fatalf("invalid remote profile was not rejected before DB access: %v", err)
		}
	}
	for _, format := range []string{"ollama", ollamaendpoint.Remote} {
		if !(&LLMProfile{Format: format}).KeylessOllama() {
			t.Fatalf("keyless %s cannot be selected", format)
		}
	}
	if (&LLMProfile{Format: ollamaendpoint.Remote, OllamaRemote: ollamaendpoint.Options{AuthMode: "bearer"}}).KeylessOllama() {
		t.Fatal("Bearer profile treated as keyless")
	}
}

// Exercise the actual profile SQL against an in-memory SQL database without
// starting PostgreSQL or touching the developer's configured database. Only
// PostgreSQL-specific column types/defaults are adapted; save/read SQL is shared.
func TestRemoteOllamaProfileSQLRoundTrip(t *testing.T) {
	conn, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetMaxOpenConns(1)
	ddl := strings.Split(strings.Split(schemaSQL, "CREATE TABLE IF NOT EXISTS llm_profiles (")[1], "CREATE UNIQUE INDEX IF NOT EXISTS uq_llm_one_default")[0]
	ddl = "CREATE TABLE llm_profiles (" + ddl
	ddl = strings.NewReplacer("BIGSERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT", "JSONB", "TEXT", "'{}'::jsonb", "'{}'", "DEFAULT now()", "DEFAULT CURRENT_TIMESTAMP").Replace(ddl)
	if _, err = conn.Exec(ddl); err != nil {
		t.Fatal(err)
	}
	d := &DB{conn}
	p := &LLMProfile{Name: "remote", Format: ollamaendpoint.Remote, Model: "fixture", BaseURL: "https://model.example/v1", APIKey: "gateway-fixture", OllamaRemote: ollamaendpoint.Options{AuthMode: "bearer", MaxConcurrent: 2, QueueTimeoutSeconds: 15, RequestTimeoutSeconds: 60}}
	id, err := d.SaveProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ID = id
	stored, err := d.ProfileByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.APIKey != "gateway-fixture" || stored.OllamaRemote != p.OllamaRemote {
		t.Fatalf("round trip=%+v", stored.OllamaRemote)
	}
	p.APIKey = ""
	p.Name = "renamed"
	if _, err = d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	p.APIKey = ""
	p.BaseURL = "https://different.example/v1"
	if _, err = d.SaveProfile(p); !errors.Is(err, ErrRemoteOllamaProfile) {
		t.Fatalf("moved server retained token: %v", err)
	}
	p.APIKey = "new-gateway-fixture"
	if _, err = d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	p.APIKey = ""
	p.OllamaRemote.AuthMode = "none"
	if _, err = d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	stored, err = d.ProfileByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.APIKey != "" {
		t.Fatal("disabling authentication retained token")
	}
	listed, err := d.ListProfiles()
	if err != nil || len(listed) != 1 || listed[0].APIKeyHint != "" {
		t.Fatal("credential hint remained after disabling authentication")
	}
	pool, err := d.PoolProfiles()
	if err != nil || len(pool) != 1 || pool[0].ID != id {
		t.Fatalf("keyless remote excluded: %v", err)
	}
	p.Format = "ollama"
	p.APIKey = "unrelated-cloud-fixture"
	if _, err = d.SaveProfile(p); err != nil {
		t.Fatal(err)
	}
	stored, err = d.ProfileByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Format != "ollama" || stored.APIKey != "" || stored.OllamaRemote != (ollamaendpoint.Options{}) {
		t.Fatal("local profile behavior changed")
	}
}
