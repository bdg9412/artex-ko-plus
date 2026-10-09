package llmpool

import (
	"context"
	"errors"
	"strings"
	"testing"
	"unicode"

	"github.com/Autumn-27/norma/llm"
)

// hasHangul reports whether s contains any Hangul character.
func hasHangul(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Hangul, r) {
			return true
		}
	}
	return false
}

// hasHanzi reports whether s contains any CJK (Han) character.
func hasHanzi(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// assertSurfacedExhaustion checks the error an exhausted chain hands back: it must
// still wrap the ErrExhausted sentinel (callers rely on errors.Is), read as a
// Korean message (no Han characters, no full-width colon), and lead with the
// localized sentinel text. failProv's body is ASCII ("anthropic: status 402:
// nope"), so the whole surfaced string must be Han-free.
func assertSurfacedExhaustion(t *testing.T, label string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: exhausted chain returned nil error", label)
	}
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("%s: surfaced error no longer wraps ErrExhausted: %v", label, err)
	}
	msg := err.Error()
	if hasHanzi(msg) {
		t.Errorf("%s: surfaced error still carries Chinese characters: %q", label, msg)
	}
	if strings.ContainsRune(msg, '：') {
		t.Errorf("%s: surfaced error still uses a full-width colon: %q", label, msg)
	}
	if !strings.HasPrefix(msg, ErrExhausted.Error()) {
		t.Errorf("%s: surfaced error does not lead with the localized sentinel: %q", label, msg)
	}
}

// The chain-exhaustion error is user-facing: a worker whose whole LLM chain fails
// records it through agent/capture.go as a "result" activity shown in the run
// transcript. So its text must be Korean, while its identity (errors.Is) must be
// preserved for callers that branch on the sentinel.
func TestExhaustedErrorLocalized(t *testing.T) {
	assertKoreanErrText(t, "ErrExhausted", ErrExhausted.Error())

	// Drive both surfaced paths so a future edit to either wrap site is caught.
	streamChain := New([]*Member{
		member(1, "a", 10, failProv("a", 402)),
		member(2, "b", 5, failProv("b", 402)),
	}, NewRegistry(nil, nil))
	_, serr := drain(streamChain.Stream(context.Background(), llm.CompletionRequest{}))
	assertSurfacedExhaustion(t, "Stream", serr)

	completeChain := New([]*Member{
		member(1, "a", 10, failProv("a", 402)),
		member(2, "b", 5, failProv("b", 402)),
	}, NewRegistry(nil, nil))
	_, _, _, cerr := completeChain.Complete(context.Background(), llm.CompletionRequest{})
	assertSurfacedExhaustion(t, "Complete", cerr)
}

// assertKoreanErrText fails unless s contains Hangul and no Han character.
func assertKoreanErrText(t *testing.T, label, s string) {
	t.Helper()
	if !hasHangul(s) {
		t.Errorf("%s: 한글이 없습니다: %q", label, s)
	}
	if hasHanzi(s) {
		t.Errorf("%s: 중국어 한자가 남아 있습니다: %q", label, s)
	}
}
