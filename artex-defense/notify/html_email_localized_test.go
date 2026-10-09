package notify

import (
	"strings"
	"testing"
)

// 이 파일은 F4 ③(이메일 본문·HTML 템플릿) 한국어화를 회귀로부터 지킨다.
// html.go 의 라벨과 email.go 의 검증 오류가 중국어로 되돌아가면 잡아낸다.
// 헬퍼 hasHan·hasHangul·assertKorean 은 notify_localized_test.go 에 있다(같은 패키지).
//
// 데이터(제목·유형·자산·개요)는 전부 ASCII 로 둔다. 그래야 "출력 전체에 한자 0"
// 이라는 단언이 콘텐츠가 아니라 골격 라벨의 회귀만 정확히 포착한다. 심각도·상태
// 라벨은 F4 ①에서 이미 한국어라 출력에 한글로 나오며(한자 아님) 단언을 통과한다.

// TestHTMLItemLabelsLocalized 는 단건 이메일 본문의 모든 라벨 분기를 켠 뒤
// 골격이 한국어이고 중국어 한자가 없음을 확인한다.
func TestHTMLItemLabelsLocalized(t *testing.T) {
	m := Message{
		HomeURL: "https://example.com/panel",
		Items: []Item{{
			Name:       "sqli-login", // Title() = Name
			VulnClass:  "injection",  // Title() 과 달라야 유형 줄이 렌더됨
			Severity:   "high",       // SeverityLabel → 높음(한글)
			Summary:    "login form is injectable",
			Assets:     []string{"host-a.example.com"},
			DetailURL:  "https://example.com/f/1",
			FromStatus: "pending", // IsStatusChange()=true → 상태 변경 줄
			ToStatus:   "fixed",
		}},
	}
	out := htmlBody(m, 0)
	if hasHan(out) {
		t.Errorf("이메일 본문에 중국어 한자가 남아 있습니다:\n%s", out)
	}
	for _, want := range []string{
		"상태 변경", "유형", "자산", "개요", "상세 보기", "플랫폼에서 전체 보기",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("이메일 본문에 %q 라벨이 없습니다:\n%s", want, out)
		}
	}
}

// TestHTMLBatchIntroLocalized 는 다건(digest) 머리말의 두 분기(시간창 유무)가
// 한국어로 렌더되는지 확인한다.
func TestHTMLBatchIntroLocalized(t *testing.T) {
	items := []Item{{Name: "a", Severity: "high"}, {Name: "b", Severity: "low"}}

	withWindow := htmlBatchIntro(Message{Batch: true, WindowMinutes: 30, Items: items})
	assertKorean(t, "htmlBatchIntro(시간창)", withWindow)
	for _, want := range []string{"최근 30분간", "신규 취약점", "2건"} {
		if !strings.Contains(withWindow, want) {
			t.Errorf("시간창 머리말에 %q 가 없습니다: %q", want, withWindow)
		}
	}

	noWindow := htmlBatchIntro(Message{Batch: true, WindowMinutes: 0, Items: items})
	assertKorean(t, "htmlBatchIntro(시간창 없음)", noWindow)
	if !strings.Contains(noWindow, "신규 취약점 2건") {
		t.Errorf("시간창 없는 머리말이 %q 를 포함해야 합니다: %q", "신규 취약점 2건", noWindow)
	}
	if strings.Contains(noWindow, "분간") {
		t.Errorf("시간창이 없는데 '분간' 이 들어갔습니다: %q", noWindow)
	}
}

// TestEmailValidateLocalized 는 SMTP 설정 검증 오류 네 가지가 한국어이고,
// 각 오류가 어떤 필드가 문제인지 알려 주는지 확인한다. 이 메시지는 알림 채널을
// 설정하는 사용자에게 그대로 표시된다.
func TestEmailValidateLocalized(t *testing.T) {
	cases := []struct {
		name   string
		cfg    map[string]any
		substr string
	}{
		{"서버 주소 누락", map[string]any{"port": float64(25), "from": "a@b.c", "to": []any{"d@e.f"}}, "SMTP"},
		{"포트 범위 벗어남", map[string]any{"host": "h"}, "포트"},
		{"발신자 누락", map[string]any{"host": "h", "port": float64(25), "to": []any{"d@e.f"}}, "발신자"},
		{"수신자 누락", map[string]any{"host": "h", "port": float64(25), "from": "a@b.c"}, "수신자"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := (emailChannel{}).Validate(tc.cfg)
			if err == nil {
				t.Fatalf("검증이 실패해야 합니다: %v", tc.cfg)
			}
			assertKorean(t, "Validate("+tc.name+")", err.Error())
			if !strings.Contains(err.Error(), tc.substr) {
				t.Errorf("오류 메시지에 %q 가 있어야 합니다, 받은 값 %q", tc.substr, err.Error())
			}
		})
	}
}
