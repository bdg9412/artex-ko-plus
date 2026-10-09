package server

import (
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// notify_api.go 의 알림 설정 API 응답 문구와 테스트 메시지를 한국어로 유지하는 회귀 방어
// 테스트다. 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어 한자 0)를 재사용한다.

// TestNotifyErrorConstantsLocalized 는 응답 상수 10종과 테스트 메시지 상수 3종이 전부
// 한국어임을 단언한다. 어느 하나라도 중국어로 되돌리면 이 테스트가 실패한다.
func TestNotifyErrorConstantsLocalized(t *testing.T) {
	cases := map[string]string{
		"notifyErrBadJSON":         notifyErrBadJSON,
		"notifyErrKindInvalidFmt":  fmt.Sprintf(notifyErrKindInvalidFmt, "email / webhook"),
		"notifyErrNameMissing":     notifyErrNameMissing,
		"notifyErrNameEmpty":       notifyErrNameEmpty,
		"notifyErrModeInvalid":     notifyErrModeInvalid,
		"notifyErrRateNegative":    notifyErrRateNegative,
		"notifyErrChannelID":       notifyErrChannelID,
		"notifyErrKindUnregFmt":    fmt.Sprintf(notifyErrKindUnregFmt, "bogus"),
		"notifyErrDeliveryID":      notifyErrDeliveryID,
		"notifyErrChannelNotFound": notifyErrChannelNotFound,
		"notifyTestName":           notifyTestName,
		"notifyTestClass":          notifyTestClass,
		"notifyTestSummary":        notifyTestSummary,
	}
	for label, msg := range cases {
		assertKoreanError(t, label, msg)
	}
}

// TestNotifyChannelLookupErrLocalized 는 「채널 없음 → 404」 경로를 실제 코드로 검사한다.
// notifyChannelLookupErr 는 Server/DB 없이 w 와 err 만으로 도는 패키지 함수라, 센티넬
// 오류를 그대로 넘기면 404 응답 본문에 한국어 상수가 실리는 연결까지 DB 없이 확인된다.
func TestNotifyChannelLookupErrLocalized(t *testing.T) {
	rec := httptest.NewRecorder()
	notifyChannelLookupErr(rec, db.ErrNotificationChannelNotFound)
	if rec.Code != 404 {
		t.Fatalf("상태 코드 = %d, 기대 = 404 (본문 %q)", rec.Code, rec.Body.String())
	}
	got := decodeErrorField(t, rec.Body.Bytes())
	if got != notifyErrChannelNotFound {
		t.Fatalf("응답 문구 = %q, 기대 = %q", got, notifyErrChannelNotFound)
	}
	assertKoreanError(t, "channel_not_found", got)
}

// TestNotifyTestMessageLocalized 는 채널 연결 점검용 테스트 메시지를 순수 함수로 조립해
// 사용자에게 발송되는 본문(제목·분류·요약)이 한국어임을 검사한다. DB·네트워크가 필요 없다.
func TestNotifyTestMessageLocalized(t *testing.T) {
	const base = "https://artex.example.test"
	msg := notifyTestMessage(base)
	if len(msg.Items) != 1 {
		t.Fatalf("테스트 메시지 항목 수 = %d, 기대 = 1", len(msg.Items))
	}
	item := msg.Items[0]
	assertKoreanError(t, "test.name", item.Name)
	assertKoreanError(t, "test.class", item.VulnClass)
	assertKoreanError(t, "test.summary", item.Summary)
	if msg.HomeURL != base || item.DetailURL != base {
		t.Fatalf("링크 보존 실패: HomeURL=%q DetailURL=%q (기대 %q)", msg.HomeURL, item.DetailURL, base)
	}
}
