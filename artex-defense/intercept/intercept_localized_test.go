package intercept

import (
	"fmt"
	"strings"
	"testing"
	"unicode"
)

// hasHangul reports whether s contains any Hangul syllable.
func hasHangul(s string) bool {
	for _, r := range s {
		if r >= 0xAC00 && r <= 0xD7A3 {
			return true
		}
	}
	return false
}

// hasHan reports whether s contains any CJK Han ideograph.
func hasHan(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// assertKorean fails if s lacks Hangul or still carries Han ideographs. Reverting
// any localized message back to Chinese trips hasHan, so the test is not vacuous.
func assertKorean(t *testing.T, label, s string) {
	t.Helper()
	if !hasHangul(s) {
		t.Errorf("%s: 한글이 없습니다: %q", label, s)
	}
	if hasHan(s) {
		t.Errorf("%s: 한자가 남아 있습니다: %q", label, s)
	}
}

// TestInterceptMessagesLocalized pins the user-facing judge/approval messages to
// Korean. These surface in the approval record reason, the activity stream, and
// the 409 response for an already-decided request.
func TestInterceptMessagesLocalized(t *testing.T) {
	for _, c := range []struct{ name, s string }{
		{"msgReviewContextIncomplete", msgReviewContextIncomplete},
		{"msgModelApprovalFailed", msgModelApprovalFailed},
		{"msgModelOutputUnparsable", msgModelOutputUnparsable},
		{"reasonWorkCanceled", reasonWorkCanceled},
		{"reasonWorkCanceledPreExec", reasonWorkCanceledPreExec},
		{"reasonApprovalTimeout", reasonApprovalTimeout},
		{"reasonManualDeny", reasonManualDeny},
		{"reasonManualAllow", reasonManualAllow},
		{"ErrAlreadyDecided", ErrAlreadyDecided.Error()},
	} {
		assertKorean(t, c.name, c.s)
	}
}

// TestJudgeActionLabelLocalized checks the three judge verdict labels are Korean
// (허용 / 차단 / 확인 요청, per the glossary) and that an unknown action still
// passes through untranslated.
func TestJudgeActionLabelLocalized(t *testing.T) {
	for _, action := range []string{"allow", "deny", "ask"} {
		assertKorean(t, "judgeActionLabel("+action+")", judgeActionLabel(action))
	}
	if got := judgeActionLabel("weird"); got != "weird" {
		t.Errorf("judgeActionLabel(weird) = %q, want passthrough", got)
	}
}

// TestDefaultMessageLocalized checks the rule-derived deny/ask messages are Korean
// and still embed the rule name, while allow stays empty.
func TestDefaultMessageLocalized(t *testing.T) {
	for _, action := range []string{"deny", "ask"} {
		msg := defaultMessage(action, "R1")
		assertKorean(t, "defaultMessage("+action+")", msg)
		if !strings.Contains(msg, "R1") {
			t.Errorf("defaultMessage(%s) dropped rule name: %q", action, msg)
		}
	}
	if got := defaultMessage("allow", "R1"); got != "" {
		t.Errorf("defaultMessage(allow) = %q, want empty", got)
	}
}

// TestToolApprovalSummaryLocalized checks the activity summary is Korean and stays
// parseable by transcript.tsx, which extracts the pending id via /\(#(\d+)\)/ and
// the tool name via /도구\s+(\S+)\s+승인/.
func TestToolApprovalSummaryLocalized(t *testing.T) {
	s := fmt.Sprintf(msgToolApprovalRequestFmt, "Bash", 42)
	assertKorean(t, "msgToolApprovalRequestFmt", s)
	if !strings.Contains(s, "(#42)") {
		t.Errorf("summary lost the (#N) marker (transcript.tsx pending_id regex): %q", s)
	}
	if !strings.Contains(s, "도구 Bash 승인") {
		t.Errorf("summary lost the '도구 X 승인' shape (transcript.tsx toolName regex): %q", s)
	}
}
