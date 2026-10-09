package notify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// 이 파일은 F4 ④⑤(telegram·webhook·공용 HTTP 전송 계층) 한국어화를 회귀로부터
// 지킨다. telegram.go 의 메시지 라벨·배치 제목, webhook.go 의 설정 검증 오류,
// http.go 의 전송 오류, 그리고 다섯 채널이 공유하는 validateHTTPURL 이 중국어로
// 되돌아가면 잡아낸다. 헬퍼 hasHan·hasHangul·assertKorean 은
// notify_localized_test.go 에 있다(같은 패키지).
//
// 데이터(제목·유형·자산·개요)는 전부 ASCII 로 둔다. 그래야 "출력 전체에 한자 0"
// 이라는 단언이 콘텐츠가 아니라 골격 라벨의 회귀만 정확히 포착한다. 심각도·상태
// 라벨은 F4 ①에서 이미 한국어라 출력에 한글로 나오며(한자 아님) 단언을 통과한다.

// TestTelegramItemLabelsLocalized 는 단건 Telegram 메시지의 모든 라벨 분기를 켠 뒤
// 골격이 한국어이고 중국어 한자가 없음을 확인한다.
func TestTelegramItemLabelsLocalized(t *testing.T) {
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
	out, kept := telegramHTML(m)
	if kept != 1 {
		t.Fatalf("단건 메시지는 1 을 보고해야 합니다, 받은 값 %d", kept)
	}
	if hasHan(out) {
		t.Errorf("Telegram 본문에 중국어 한자가 남아 있습니다:\n%s", out)
	}
	for _, want := range []string{"상태 변경", "유형", "자산", "개요", "상세 보기"} {
		if !strings.Contains(out, want) {
			t.Errorf("Telegram 본문에 %q 라벨이 없습니다:\n%s", want, out)
		}
	}
}

// TestTelegramBatchTitleLocalized 는 배치(digest) 제목의 넘침·시간창 분기가
// 한국어로 렌더되는지 확인한다. markdownTitle 과 글자까지 맞춰야 채널 간 혼재가
// 생기지 않는다.
func TestTelegramBatchTitleLocalized(t *testing.T) {
	items := []Item{{Name: "a", Severity: "high"}, {Name: "b", Severity: "low"}}

	// 넘침 있음 + 시간창: 요약·총건수·앞 N건·나머지·다음 메시지·최근 N분간.
	over := telegramBatchTitle(Message{WindowMinutes: 30}, items, 5)
	assertKorean(t, "telegramBatchTitle(넘침)", over)
	for _, want := range []string{"취약점 요약 · 총 5건", "앞 2건만 표시", "나머지 3건", "다음 메시지", "최근 30분간"} {
		if !strings.Contains(over, want) {
			t.Errorf("넘침 제목에 %q 가 없습니다: %q", want, over)
		}
	}

	// 넘침 없음 + 시간창 없음: 다음 메시지 안내가 없어야 한다.
	full := telegramBatchTitle(Message{}, items, 2)
	assertKorean(t, "telegramBatchTitle(전량)", full)
	if !strings.Contains(full, "취약점 요약 · 총 2건") {
		t.Errorf("전량 제목에 '취약점 요약 · 총 2건' 이 있어야 합니다: %q", full)
	}
	if strings.Contains(full, "다음 메시지") {
		t.Errorf("넘치지 않았는데 '다음 메시지' 안내가 들어갔습니다: %q", full)
	}
}

// TestTelegramValidateLocalized 는 필수 필드 누락 오류가 한국어이고 어떤 필드가
// 비었는지 알려 주는지 확인한다. 기술 용어 Bot Token·Chat ID 는 그대로 보존한다.
func TestTelegramValidateLocalized(t *testing.T) {
	if err := (telegramChannel{}).Validate(map[string]any{}); err == nil {
		t.Fatal("bot_token 누락은 검증 실패여야 합니다")
	} else {
		assertKorean(t, "telegram Validate(bot_token)", err.Error())
		if !strings.Contains(err.Error(), "Bot Token") {
			t.Errorf("Bot Token 누락을 알려줘야 합니다: %q", err.Error())
		}
	}
	if err := (telegramChannel{}).Validate(map[string]any{"bot_token": "t"}); err == nil {
		t.Fatal("chat_id 누락은 검증 실패여야 합니다")
	} else {
		assertKorean(t, "telegram Validate(chat_id)", err.Error())
		if !strings.Contains(err.Error(), "Chat ID") {
			t.Errorf("Chat ID 누락을 알려줘야 합니다: %q", err.Error())
		}
	}
}

// TestWebhookValidateLocalized 는 범용 Webhook 설정 검증 오류 세 가지가 한국어이고
// 각 오류가 문제의 원인을 알려 주는지 확인한다.
func TestWebhookValidateLocalized(t *testing.T) {
	if err := (webhookChannel{}).Validate(map[string]any{}); err == nil {
		t.Fatal("url 누락은 검증 실패여야 합니다")
	} else {
		assertKorean(t, "webhook Validate(url)", err.Error())
		if !strings.Contains(err.Error(), "대상 URL") {
			t.Errorf("대상 URL 누락을 알려줘야 합니다: %q", err.Error())
		}
	}
	// 지원하지 않는 메서드: 한국어 + 허용 목록 노출.
	if err := (webhookChannel{}).Validate(map[string]any{"url": "https://example.com/hook", "method": "DELETE"}); err == nil {
		t.Fatal("DELETE 는 검증 실패여야 합니다")
	} else {
		assertKorean(t, "webhook Validate(method)", err.Error())
		if !strings.Contains(err.Error(), "GET/POST/PUT/PATCH") {
			t.Errorf("허용 메서드 목록을 알려줘야 합니다: %q", err.Error())
		}
	}
	// 템플릿 문법 오류: 한국어(래핑된 원인은 Go 템플릿 오류라 한자가 없다).
	if err := (webhookChannel{}).Validate(map[string]any{"url": "https://example.com/hook", "body_template": "{{"}); err == nil {
		t.Fatal("깨진 템플릿은 검증 실패여야 합니다")
	} else {
		assertKorean(t, "webhook Validate(template)", err.Error())
		if !strings.Contains(err.Error(), "템플릿") {
			t.Errorf("템플릿 오류임을 알려줘야 합니다: %q", err.Error())
		}
	}
}

// TestValidateHTTPURLLocalized 는 다섯 채널(telegram·webhook·dingtalk·feishu·wecom)이
// 공유하는 URL 검증 헬퍼의 오류가 한국어인지 확인한다. 이 헬퍼가 중국어로 남아 있으면
// 한국어 접두("API 주소가 올바르지 않습니다: ...")와 섞여 반한반중이 된다.
func TestValidateHTTPURLLocalized(t *testing.T) {
	// 지원하지 않는 스킴.
	if err := validateHTTPURL("ftp://example.com/x"); err == nil {
		t.Fatal("ftp 스킴은 거부되어야 합니다")
	} else {
		assertKorean(t, "validateHTTPURL(scheme)", err.Error())
		if !strings.Contains(err.Error(), "http") {
			t.Errorf("지원 스킴(http/https)을 알려줘야 합니다: %q", err.Error())
		}
	}
	// 호스트 이름 없음.
	if err := validateHTTPURL("http://"); err == nil {
		t.Fatal("호스트 없는 주소는 거부되어야 합니다")
	} else {
		assertKorean(t, "validateHTTPURL(host)", err.Error())
	}
}

// TestHTTPLocalTargetBlockedLocalized 는 로컬/링크 로컬 주소 차단 오류가 한국어이고
// 우회 방법(환경 변수)을 알려 주는지 확인한다.
func TestHTTPLocalTargetBlockedLocalized(t *testing.T) {
	t.Setenv(AllowLocalTargetsEnv, "") // 명시적으로 꺼서 차단 경로를 탄다
	err := blockInternalDial("tcp", "127.0.0.1:25", nil)
	if err == nil {
		t.Fatal("로컬 주소는 기본적으로 차단되어야 합니다")
	}
	assertKorean(t, "blockInternalDial", err.Error())
	if !strings.Contains(err.Error(), AllowLocalTargetsEnv) {
		t.Errorf("차단 오류는 우회 방법(%s)을 알려줘야 합니다: %q", AllowLocalTargetsEnv, err.Error())
	}
}

// TestHTTPRedactHelpersLocalized 는 주소 탈감(redact) 자리표시자와 전송 오류의
// "알 수 없는 오류" 분기가 한국어인지 확인한다.
func TestHTTPRedactHelpersLocalized(t *testing.T) {
	if got := redactRequestTarget(""); !strings.Contains(got, "해석할 수 없") {
		t.Errorf("해석 불가 주소는 한국어 자리표시자여야 합니다, 받은 값 %q", got)
	}
	// *url.Error 의 Err 가 nil 인 분기.
	got := redactTransportError(&url.Error{Op: "Get", URL: "http://api.example", Err: nil})
	if hasHan(got) {
		t.Errorf("전송 오류 탈감 결과에 한자가 남았습니다: %q", got)
	}
	if !strings.Contains(got, "알 수 없는 오류") {
		t.Errorf("Err 가 nil 이면 '알 수 없는 오류' 여야 합니다, 받은 값 %q", got)
	}
}

// TestHTTPStatusErrorsLocalized 는 실제 doJSON 왕복으로 상태코드 분류(거부/서버
// 오류/제한)의 사용자 노출 오류가 한국어인지 확인한다. 127.0.0.1 httptest 로의
// 전송은 기본 차단이라 이 테스트에서만 명시적으로 허용한다.
func TestHTTPStatusErrorsLocalized(t *testing.T) {
	t.Setenv(AllowLocalTargetsEnv, "1")
	cases := []struct {
		code int
		want string
	}{
		{http.StatusForbidden, "요청을 거부했습니다"},
		{http.StatusInternalServerError, "오류가 발생했습니다"},
		{http.StatusTooManyRequests, "요청을 제한하거나"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.code)
			_, _ = w.Write([]byte("body"))
		}))
		_, err := doJSON(context.Background(), http.MethodPost, srv.URL, nil, map[string]any{"a": 1})
		srv.Close()
		if err == nil {
			t.Fatalf("HTTP %d 는 오류여야 합니다", tc.code)
		}
		assertKorean(t, "doJSON(HTTP status)", err.Error())
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("HTTP %d 오류에 %q 가 있어야 합니다, 받은 값 %q", tc.code, tc.want, err.Error())
		}
	}
}
