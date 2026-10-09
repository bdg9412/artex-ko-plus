package server

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestTaskLLMResolutionLocalized guards F18: every user-facing reason/label that
// GET /api/tasks/{id}/llm/resolution returns (rendered in the task LLM settings
// chain / system/llm UI via resolutionLabel / the chain editor) must be Korean —
// Hangul present, no Chinese Han. Source enum values and English fmt.Errorf wraps
// are out of scope and are not asserted here.
func TestTaskLLMResolutionLocalized(t *testing.T) {
	// 1) Every localized constant is Korean. Reverting any to Chinese fails this.
	for _, c := range []struct{ label, msg string }{
		{"reasonLLMProfileMissing", reasonLLMProfileMissing},
		{"reasonLLMProfileNoAPIKey", reasonLLMProfileNoAPIKey},
		{"reasonLLMProfileInvalid", reasonLLMProfileInvalid},
		{"reasonTaskLLMChainExhausted", reasonTaskLLMChainExhausted},
		{"reasonNoLLMAvailable", reasonNoLLMAvailable},
		{"sourceNameGlobalConfig", sourceNameGlobalConfig},
	} {
		assertKoreanError(t, c.label, c.msg)
	}

	// 2) Pin the two reasons reachable with no DB. resolutionFromProfile returns
	// before touching providerForProfile for a nil profile and for a profile with
	// a blank API key, so a zero-value Server exercises the real code path.
	s := &Server{}

	missing := s.resolutionFromProfile(nil, "task_chain")
	if missing.Available {
		t.Fatalf("nil profile must be unavailable, got %+v", missing)
	}
	if missing.Reason != reasonLLMProfileMissing {
		t.Fatalf("nil profile reason = %q, want %q", missing.Reason, reasonLLMProfileMissing)
	}
	assertKoreanError(t, "resolutionFromProfile(nil).Reason", missing.Reason)

	noKey := s.resolutionFromProfile(&db.LLMProfile{Name: "p", Format: "openai", Model: "m"}, "task_chain")
	if noKey.Available {
		t.Fatalf("blank API key must be unavailable, got %+v", noKey)
	}
	if noKey.Reason != reasonLLMProfileNoAPIKey {
		t.Fatalf("blank-key reason = %q, want %q", noKey.Reason, reasonLLMProfileNoAPIKey)
	}
	assertKoreanError(t, "resolutionFromProfile(noKey).Reason", noKey.Reason)
}
