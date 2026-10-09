package notify

import (
	"strings"
	"testing"
)

// hasHan 은 문자열에 CJK 통합 한자가 하나라도 있으면 true 를 반환한다.
// 번역한 라벨이 중국어로 되돌아가면(회귀) 이 판정이 잡아낸다.
func hasHan(s string) bool {
	for _, r := range s {
		if r >= 0x4E00 && r <= 0x9FFF {
			return true
		}
	}
	return false
}

// hasHangul 은 문자열에 한글 음절이 하나라도 있으면 true 를 반환한다.
func hasHangul(s string) bool {
	for _, r := range s {
		if r >= 0xAC00 && r <= 0xD7A3 {
			return true
		}
	}
	return false
}

// assertKorean 은 라벨이 한글을 포함하고 중국어 한자는 없음을 단언한다.
func assertKorean(t *testing.T, where, got string) {
	t.Helper()
	if hasHan(got) {
		t.Errorf("%s: 중국어 한자가 남아 있습니다: %q", where, got)
	}
	if !hasHangul(got) {
		t.Errorf("%s: 한글이 없습니다: %q", where, got)
	}
}

// TestSeverityLabelLocalized 는 모든 심각도 enum 이 한국어 라벨로 나오는지 검사한다.
// 라벨은 모든 알림 채널(telegram·email·html·markdown·webhook·feishu·dingtalk·wecom)이
// 공유하므로, 하나라도 중국어로 되돌아가면 전 채널 메시지가 혼재된다.
func TestSeverityLabelLocalized(t *testing.T) {
	// 중국어 라벨(严重/高危/中危/低危) → 한국어(심각/높음/중간/낮음), UI status.severity 정합.
	want := map[string]string{
		"critical": "심각",
		"high":     "높음",
		"medium":   "중간",
		"low":      "낮음",
	}
	for sev, label := range want {
		got := SeverityLabel(sev)
		assertKorean(t, "SeverityLabel("+sev+")", got)
		if !strings.Contains(got, label) {
			t.Errorf("SeverityLabel(%q)=%q, %q 를 포함해야 합니다", sev, got, label)
		}
	}
	// 알 수 없는 심각도는 원문을 그대로 돌려준다(없는 값을 지어내지 않는다).
	if got := SeverityLabel("made_up"); got != "made_up" {
		t.Errorf("알 수 없는 심각도는 원문 유지여야 합니다, 받은 값 %q", got)
	}
}

// TestStatusLabelLocalized 는 처치 상태 9종이 전부 한국어로 나오는지 검사한다.
// UI status.finding 네임스페이스(B4a)와 동일 표기여야 상태 변경 알림과 화면이 어긋나지 않는다.
func TestStatusLabelLocalized(t *testing.T) {
	want := map[string]string{
		"pending":        "처리 대기",
		"in_progress":    "처리 중",
		"confirmed":      "확인됨",
		"resolved":       "처리됨",
		"fixed":          "수정됨",
		"false_positive": "오탐",
		"ignored":        "무시",
		"duplicate":      "중복",
		"risk_accepted":  "위험 수용",
	}
	for status, label := range want {
		got := StatusLabel(status)
		assertKorean(t, "StatusLabel("+status+")", got)
		if got != label {
			t.Errorf("StatusLabel(%q)=%q, %q 를 기대했습니다", status, got, label)
		}
	}
	// 알 수 없는 상태는 원문 그대로 회신(없는 라벨을 지어내지 않는다).
	if got := StatusLabel("weird_status"); got != "weird_status" {
		t.Errorf("알 수 없는 상태는 원문 유지여야 합니다, 받은 값 %q", got)
	}
}

// TestItemTitlePlaceholderLocalized 는 이름·유형이 모두 빈 항목의 대체 제목이
// 한국어 자리표시자(이름 없는 취약점)인지 검사한다. 절대 빈 제목을 내보내지 않는다.
func TestItemTitlePlaceholderLocalized(t *testing.T) {
	got := Item{}.Title()
	assertKorean(t, "Item{}.Title()", got)
	// 이름이 있으면 그 이름을, 유형만 있으면 유형을 우선한다(대체 로직 미회귀 확인).
	if n := (Item{Name: "로그인 SQLi"}).Title(); n != "로그인 SQLi" {
		t.Errorf("이름 우선 로직이 깨졌습니다, 받은 값 %q", n)
	}
	if v := (Item{VulnClass: "XSS"}).Title(); v != "XSS" {
		t.Errorf("유형 대체 로직이 깨졌습니다, 받은 값 %q", v)
	}
}

// TestAssetLineLocalized 는 자산 나열 문구의 구분자·총수 표기가 한국어/ASCII 인지 검사한다.
// 중국어 구두점(、)·等·个 가 되돌아오면 알림 본문에 혼재가 생긴다.
func TestAssetLineLocalized(t *testing.T) {
	// 상한 이하: 전부 나열, ASCII 쉼표 구분자.
	if got := assetLine([]string{"a.example.com", "b.example.com"}, 3); got != "a.example.com, b.example.com" {
		t.Errorf("구분자가 ASCII 쉼표여야 합니다, 받은 값 %q", got)
	}
	// 상한 초과: 앞 limit 개 + 한국어 "등 N개"(N 은 전체 개수).
	got := assetLine([]string{"a", "b", "c", "d", "e"}, 2)
	if hasHan(got) {
		t.Errorf("자산 나열에 중국어 한자가 남았습니다: %q", got)
	}
	if !strings.Contains(got, "등 5개") {
		t.Errorf("전체 개수 5 를 '등 5개'로 표기해야 합니다, 받은 값 %q", got)
	}
}
