package db

import (
	"testing"
	"unicode"
)

// assertRetestReasonKorean 은 재검증 사유 상수가 한글을 포함하고 중국어 한자가 없음을
// 단언한다(F9). FinishFindingRetest·RecoverFindingRetests 의 SQL 리터럴 자리에 상수로
// 이어 붙이므로, 상수를 핀 고정하면 패널에 노출되는 사용자 문구도 함께 보호된다.
func assertRetestReasonKorean(t *testing.T, name, s string) {
	t.Helper()
	if s == "" {
		t.Fatalf("%s: 빈 문자열", name)
	}
	hasHangul := false
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			t.Fatalf("%s: 중국어 한자가 남아 있습니다: %q", name, s)
		}
		if unicode.Is(unicode.Hangul, r) {
			hasHangul = true
		}
	}
	if !hasHangul {
		t.Fatalf("%s: 한글이 없습니다: %q", name, s)
	}
}

// TestFindingRetestReasonsLocalized 는 finding_retests.error 컬럼에 저장돼 재검증 패널
// (finding-retest-panel) 의 item.error 로 노출되는 종결 사유 두 상수가 한국어임을 단언한다.
// server/conversations.go 의 형제 사유(convRetest*)와 같은 컬럼·패널이라, 둘 중 하나만
// 한국어면 같은 패널에서 언어가 섞인다.
func TestFindingRetestReasonsLocalized(t *testing.T) {
	assertRetestReasonKorean(t, "retestNoConclusionReason", retestNoConclusionReason)
	assertRetestReasonKorean(t, "retestServiceRestartReason", retestServiceRestartReason)
}
