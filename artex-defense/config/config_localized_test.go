package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hasHan reports whether s contains a CJK Han ideograph (the Chinese source text
// we are replacing). Hangul and ASCII identifiers must survive; Han must not.
func hasHan(s string) bool {
	for _, r := range s {
		if r >= 0x4e00 && r <= 0x9fff {
			return true
		}
	}
	return false
}

func hasHangul(s string) bool {
	for _, r := range s {
		if r >= 0xac00 && r <= 0xd7a3 {
			return true
		}
	}
	return false
}

func assertKorean(t *testing.T, label, s string) {
	t.Helper()
	if hasHan(s) {
		t.Errorf("%s: Chinese Han ideograph remains: %q", label, s)
	}
	if !hasHangul(s) {
		t.Errorf("%s: no Hangul found (expected Korean): %q", label, s)
	}
}

// TestPostgresDSNErrorLocalized pins the install-path startup message to Korean.
// When neither ARTEX_PG_DSN nor a config file supplies a database, PostgresDSN
// returns an error that propagates verbatim (db.DSN → server.NewManager → the
// `log.Fatalf("open stores: %v", err)` in cmd/artex/main.go). An operator who
// boots with missing config sees it first, so it must read as Korean.
func TestPostgresDSNErrorLocalized(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ARTEX_PG_DSN", "")
	t.Setenv("ARTEX_CONFIG", filepath.Join(dir, "nope.json"))

	_, _, err := PostgresDSN()
	if err == nil {
		t.Fatal("missing config should error")
	}
	assertKorean(t, "startup error", err.Error())

	// The identifiers an operator must act on stay verbatim (not translated).
	for _, want := range []string{"ARTEX_PG_DSN", "database", "dsn", "host/user/dbname"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("startup error should keep identifier %q verbatim: %q", want, err.Error())
		}
	}

	// What the operator actually sees after propagation (no %w wrapping anywhere
	// on the path), recorded so the message can be eyeballed in context.
	t.Logf("open stores: %v", err)
}

// TestPostgresDSNSourceLocalized pins the three source labels (logged at
// server/manager.go:361) to Korean. They live in the same function as the
// startup error, so they are localized together to avoid a mixed-language file.
func TestPostgresDSNSourceLocalized(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")

	// env source
	t.Setenv("ARTEX_CONFIG", filepath.Join(dir, "nope.json"))
	t.Setenv("ARTEX_PG_DSN", "postgres://envwins/x")
	if _, source, err := PostgresDSN(); err != nil {
		t.Fatalf("env source: %v", err)
	} else {
		assertKorean(t, "env source", source)
	}

	// config file dsn source
	t.Setenv("ARTEX_PG_DSN", "")
	if err := os.WriteFile(cfgPath, []byte(`{"database":{"dsn":"postgres://full/dsn"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARTEX_CONFIG", cfgPath)
	if _, source, err := PostgresDSN(); err != nil {
		t.Fatalf("dsn source: %v", err)
	} else {
		assertKorean(t, "dsn source", source)
	}

	// config file fields source
	if err := os.WriteFile(cfgPath, []byte(`{"database":{"host":"10.1.2.3","dbname":"d","user":"u"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, source, err := PostgresDSN(); err != nil {
		t.Fatalf("fields source: %v", err)
	} else {
		assertKorean(t, "fields source", source)
	}
}
