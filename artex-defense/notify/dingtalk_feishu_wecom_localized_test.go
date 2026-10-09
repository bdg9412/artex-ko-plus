package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// asciiStatusChangeItem 은 한자가 없는(ASCII) 상태 변경 항목을 만든다.
// 라벨이 중국어로 되돌아가면 렌더 결과에 한자가 생기므로, 데이터가 한자 0 일 때만
// "출력 전체 한자 0" 단언이 라벨 회귀를 정확히 잡아낸다.
func asciiStatusChangeItem() Item {
	return Item{
		FindingID:  7,
		Name:       "login-flaw",
		VulnClass:  "SQLi",
		Severity:   "high",
		Summary:    "SQL injection via q param",
		Assets:     []string{"a.example.com"},
		DetailURL:  "https://platform.example/finding/7",
		FromStatus: "pending",
		ToStatus:   "fixed",
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("카드 직렬화 실패: %v", err)
	}
	return string(b)
}

// TestFeishuItemLinesLocalized 는 飞书 카드 단건 본문의 필드 라벨(상태 변경·유형·
// 자산·개요)이 한국어이고 markdown.go(F4②)와 글자까지 같은지 검사한다. feishu.go 는
// 이 라벨의 자기 복사본(markdown 3채널 공유 함수가 아님)을 쓰므로, 공유 함수 회귀와
// 별개로 이 핀이 있어야 飞书 본문만 중국어로 되돌아가는 회귀를 잡는다.
func TestFeishuItemLinesLocalized(t *testing.T) {
	got := feishuItemLines(asciiStatusChangeItem())
	assertKorean(t, "feishuItemLines", got)
	for _, want := range []string{
		"**상태 변경**: 처리 대기 → 수정됨",
		"**유형**: SQLi",
		"**자산**: a.example.com",
		"**개요**: SQL injection via q param",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("飞书 단건 본문에 %q 가 있어야 합니다:\n%s", want, got)
		}
	}
}

// TestFeishuCardButtonsLocalized 는 飞书 카드 버튼 라벨(상세 보기·플랫폼에서 전체 보기)이
// 한국어인지, 카드 전체에 중국어 한자가 없는지(ASCII 데이터 기준) 검사한다.
func TestFeishuCardButtonsLocalized(t *testing.T) {
	// 단건: "상세 보기" 버튼(DetailURL 있을 때)
	single, _ := feishuCard(Message{Items: []Item{asciiStatusChangeItem()}})
	singleJSON := mustJSON(t, single)
	if hasHan(singleJSON) {
		t.Errorf("단건 飞书 카드에 중국어 한자가 남았습니다:\n%s", singleJSON)
	}
	if !strings.Contains(singleJSON, "상세 보기") {
		t.Errorf("단건 飞书 카드에 '상세 보기' 버튼이 있어야 합니다:\n%s", singleJSON)
	}

	// 다건: "플랫폼에서 전체 보기" 버튼(HomeURL 있을 때)
	batch, _ := feishuCard(Message{Batch: true, HomeURL: "https://platform.example", Items: hanFreeItems(2)})
	batchJSON := mustJSON(t, batch)
	if hasHan(batchJSON) {
		t.Errorf("다건 飞书 카드에 중국어 한자가 남았습니다:\n%s", batchJSON)
	}
	if !strings.Contains(batchJSON, "플랫폼에서 전체 보기") {
		t.Errorf("다건 飞书 카드에 '플랫폼에서 전체 보기' 버튼이 있어야 합니다:\n%s", batchJSON)
	}
}

// TestDingTalkActionCardButtonLocalized 는 钉钉 ActionCard 의 "상세 보기" 버튼(singleTitle)이
// 한국어인지 실제 Send 경로(가짜 수신단)로 검사한다.
func TestDingTalkActionCardButtonLocalized(t *testing.T) {
	var singleTitle string
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(_ *testing.T, body map[string]any, _ *http.Request) {
		card, _ := body["actionCard"].(map[string]any)
		singleTitle, _ = card["singleTitle"].(string)
	})
	m := Message{Items: []Item{asciiStatusChangeItem()}}
	if _, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, m); err != nil {
		t.Fatalf("투递 실패: %v", err)
	}
	if singleTitle != "상세 보기" {
		t.Errorf("钉钉 ActionCard singleTitle 은 '상세 보기' 여야 합니다, 받은 값 %q", singleTitle)
	}
}

// TestChinaPlatformValidateLocalized 는 钉钉·飞书·企业微信 설정 검증 오류가 한국어이고
// "Webhook" 표기를 유지하는지 검사한다(알림 설정 저장·테스트 API 가 사용자에게 노출).
func TestChinaPlatformValidateLocalized(t *testing.T) {
	for _, kind := range []string{KindDingTalk, KindFeishu, KindWeCom} {
		ch, ok := Get(kind)
		if !ok {
			t.Fatalf("%s 채널이 등록되어 있지 않습니다", kind)
		}

		// 빈 설정: "Webhook 주소가 없습니다"
		missing := ch.Validate(map[string]any{})
		if missing == nil {
			t.Fatalf("%s: 빈 설정은 검증에 실패해야 합니다", kind)
		}
		assertKorean(t, kind+" missing", missing.Error())
		if !strings.Contains(missing.Error(), "Webhook") || !strings.Contains(missing.Error(), "없습니다") {
			t.Errorf("%s: 누락 오류는 'Webhook 주소가 없습니다' 여야 합니다, 받은 값 %q", kind, missing)
		}

		// 잘못된 주소(ftp): "Webhook 주소가 올바르지 않습니다: …"
		bad := ch.Validate(map[string]any{"webhook": "ftp://x"})
		if bad == nil {
			t.Fatalf("%s: ftp 주소는 검증에 실패해야 합니다", kind)
		}
		if hasHan(bad.Error()) {
			t.Errorf("%s: 잘못된 주소 오류에 중국어 한자가 남았습니다: %q", kind, bad)
		}
		if !strings.Contains(bad.Error(), "Webhook 주소가 올바르지 않습니다") {
			t.Errorf("%s: 잘못된 주소 오류는 'Webhook 주소가 올바르지 않습니다' 로 시작해야 합니다, 받은 값 %q", kind, bad)
		}
	}
}

// TestChinaPlatformSendErrorsLocalized 는 钉钉·飞书·企业微信 발송 실패 사유가 한국어로
// 투递 이력(last_error)에 남는지 검사한다. 플랫폼 이름은 UI 채널 라벨(DingTalk/Feishu/
// WeCom)과 맞춘다. 서버 errmsg 는 ASCII 이므로 오류에 한자가 보이면 골격 문구가
// 중국어로 회귀한 것이다.
func TestChinaPlatformSendErrorsLocalized(t *testing.T) {
	// 업무 오류 코드(HTTP 200 + body 의 errcode/code != 0) 경로.
	bizCases := []struct {
		kind     string
		resp     string
		wantSubs []string
	}{
		{KindDingTalk, `{"errcode":310000,"errmsg":"keyword not matched"}`, []string{"DingTalk에서 오류가 발생했습니다", "310000"}},
		{KindFeishu, `{"code":19021,"msg":"sign error"}`, []string{"Feishu에서 오류가 발생했습니다", "19021"}},
		{KindWeCom, `{"errcode":45009,"errmsg":"freq out of limit"}`, []string{"WeCom 요청이 제한되었습니다", "45009"}},
		{KindWeCom, `{"errcode":93000,"errmsg":"invalid webhook"}`, []string{"WeCom에서 오류가 발생했습니다", "93000"}},
	}
	for _, tc := range bizCases {
		srv := capturePost(t, tc.resp, nil)
		ch, ok := Get(tc.kind)
		if !ok {
			t.Fatalf("%s 채널이 등록되어 있지 않습니다", tc.kind)
		}
		_, err := ch.Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg())
		if err == nil {
			t.Fatalf("%s: %s 응답은 오류여야 합니다", tc.kind, tc.resp)
		}
		if hasHan(err.Error()) {
			t.Errorf("%s: 발송 오류에 중국어 한자가 남았습니다: %q", tc.kind, err)
		}
		for _, sub := range tc.wantSubs {
			if !strings.Contains(err.Error(), sub) {
				t.Errorf("%s: 발송 오류에 %q 가 있어야 합니다, 받은 값 %q", tc.kind, sub, err)
			}
		}
	}

	// 응답이 JSON 이 아닐 때의 파싱 실패 경로: "<플랫폼> 응답을 해석하지 못했습니다".
	parseCases := []struct {
		kind     string
		platform string
	}{
		{KindDingTalk, "DingTalk"},
		{KindFeishu, "Feishu"},
		{KindWeCom, "WeCom"},
	}
	for _, pc := range parseCases {
		srv := capturePost(t, `not-json`, nil)
		ch, ok := Get(pc.kind)
		if !ok {
			t.Fatalf("%s 채널이 등록되어 있지 않습니다", pc.kind)
		}
		_, err := ch.Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg())
		if err == nil {
			t.Fatalf("%s: JSON 이 아닌 응답은 오류여야 합니다", pc.kind)
		}
		want := pc.platform + " 응답을 해석하지 못했습니다"
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: 파싱 실패 오류에 %q 가 있어야 합니다, 받은 값 %q", pc.kind, want, err)
		}
	}
}
