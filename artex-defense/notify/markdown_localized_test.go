package notify

import (
	"strings"
	"testing"
)

// hanFreeItems 는 CJK 한자가 없는 항목(ASCII 제목·유형·요약)만 만든다.
// 라벨이 중국어로 되돌아가면 렌더 결과 전체에 한자가 생기므로, 데이터가
// 한자 0 일 때만 "출력 전체에 한자 0" 단언이 라벨 회귀를 정확히 잡아낸다.
func hanFreeItems(n int) []Item {
	items := make([]Item, 0, n)
	for i := 0; i < n; i++ {
		items = append(items, Item{
			FindingID: int64(i + 1),
			Name:      "login-flaw",
			VulnClass: "SQLi",
			Severity:  "high",
			Summary:   "SQL injection via q param",
			Assets:    []string{"a.example.com"},
		})
	}
	return items
}

// TestMarkdownTitleLocalized 는 markdown 계열 채널(dingtalk·wecom)과 제목을
// 공유하는 feishu·html·telegram·webhook 이 함께 쓰는 markdownTitle 이 한국어인지
// 검사한다. 하나라도 중국어로 되돌아가면 이 다섯 채널의 제목이 전부 혼재된다.
func TestMarkdownTitleLocalized(t *testing.T) {
	// 다건(汇总): "취약점 요약 · 총 N건"
	got := markdownTitle(Message{Batch: true, Items: hanFreeItems(3)})
	assertKorean(t, "markdownTitle(batch)", got)
	if !strings.Contains(got, "취약점 요약") || !strings.Contains(got, "총 3건") {
		t.Errorf("다건 제목이 '취약점 요약 · 총 3건' 형태여야 합니다, 받은 값 %q", got)
	}
	// 항목 없음: "취약점 알림"
	empty := markdownTitle(Message{})
	assertKorean(t, "markdownTitle(empty)", empty)
	if empty != "취약점 알림" {
		t.Errorf("빈 메시지 제목은 '취약점 알림' 이어야 합니다, 받은 값 %q", empty)
	}
}

// TestMarkdownBatchIntroLocalized 는 다이제스트 머리말(시간창·건수·초과 안내)이
// 한국어인지 검사한다. 항목 데이터가 한자 0 이므로 출력에 한자가 보이면 머리말
// 문구가 중국어로 회귀한 것이다.
func TestMarkdownBatchIntroLocalized(t *testing.T) {
	items := hanFreeItems(3)

	// 시간창 있음: "최근 N분간 신규 취약점 N건"
	win := markdownBatchIntro(Message{Batch: true, WindowMinutes: 30}, items, 3)
	if hasHan(win) {
		t.Errorf("시간창 머리말에 중국어 한자가 남았습니다: %q", win)
	}
	if !strings.Contains(win, "최근 30분간") || !strings.Contains(win, "신규 취약점 3건") {
		t.Errorf("시간창 머리말이 '최근 30분간 신규 취약점 3건' 형태여야 합니다, 받은 값 %q", win)
	}

	// 시간창 없음: "신규 취약점 N건"(분간 표기 없음)
	noWin := markdownBatchIntro(Message{Batch: true}, items, 3)
	if hasHan(noWin) {
		t.Errorf("머리말에 중국어 한자가 남았습니다: %q", noWin)
	}
	if !strings.Contains(noWin, "신규 취약점 3건") || strings.Contains(noWin, "분간") {
		t.Errorf("시간창 없는 머리말은 '신규 취약점 3건'(분간 표기 없음)이어야 합니다, 받은 값 %q", noWin)
	}

	// 일부만 담겼을 때: "(이 메시지에는 앞 N건만 … 나머지 N건은 다음 메시지에서 …)"
	trunc := markdownBatchIntro(Message{Batch: true, WindowMinutes: 30}, items, 5)
	if hasHan(trunc) {
		t.Errorf("초과 안내에 중국어 한자가 남았습니다: %q", trunc)
	}
	for _, want := range []string{"앞 3건만", "나머지 2건", "다음 메시지에서"} {
		if !strings.Contains(trunc, want) {
			t.Errorf("초과 안내에 %q 가 있어야 합니다, 받은 값 %q", want, trunc)
		}
	}
}

// TestWriteItemLabelsLocalized 는 단건 상세 렌더(markdown 3채널 공유 경로)의
// 필드 라벨(상태 변경·유형·자산·개요)과 상세 링크가 한국어인지 검사한다.
func TestWriteItemLabelsLocalized(t *testing.T) {
	it := Item{
		Name:       "login-flaw",
		VulnClass:  "SQLi",
		Severity:   "high",
		Summary:    "SQL injection via q param",
		Assets:     []string{"a.example.com"},
		DetailURL:  "https://platform.example/finding/1",
		FromStatus: "pending",
		ToStatus:   "fixed",
	}
	var b strings.Builder
	writeItem(&b, it, "", true)
	got := b.String()

	assertKorean(t, "writeItem(single)", got)
	for _, want := range []string{
		"**상태 변경**: 처리 대기 → 수정됨",
		"**유형**: SQLi",
		"**자산**: a.example.com",
		"**개요**: SQL injection via q param",
		"[상세 보기](https://platform.example/finding/1)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("단건 렌더에 %q 가 있어야 합니다:\n%s", want, got)
		}
	}
}

// TestMarkdownBodyFooterLocalized 는 다건 본문 끝의 플랫폼 입구 링크가
// 한국어인지 검사한다(HomeURL 이 있을 때만 붙는다).
func TestMarkdownBodyFooterLocalized(t *testing.T) {
	m := Message{Batch: true, HomeURL: "https://platform.example", Items: hanFreeItems(2)}
	body, kept := markdownBody(m, 0)
	if kept != 2 {
		t.Fatalf("한도 없음(0)이면 2건 모두 담겨야 합니다, 받은 값 %d", kept)
	}
	if !strings.Contains(body, "[플랫폼에서 전체 보기](https://platform.example)") {
		t.Errorf("본문 끝에 '플랫폼에서 전체 보기' 링크가 있어야 합니다:\n%s", body)
	}
}
