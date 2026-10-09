package notify

import (
	"errors"
	"strings"
	"testing"
)

// F4 ⑥: notify/mask.go·filter.go 의 사용자 노출 문구(알림 채널 설정을 저장·갱신할 때
// server/notify_api.go 가 writeErr(400) 로 그대로 돌려주는 검증 오류)가 한국어이고
// 한자가 없음을 핀 고정한다. channel.go 는 사용자 노출 문구가 없어(전부 주석) 대상이
// 아니다. hasHan / hasHangul / assertKorean 은 notify_localized_test.go 에 정의돼 있다.

// TestFilterValidateLocalized 는 min_severity 를 잘못 넣었을 때의 검증 오류를 검사한다.
// 이 오류는 저장·갱신 경로(server/notify_api.go:264·369)에서 400 으로 노출된다.
func TestFilterValidateLocalized(t *testing.T) {
	err := Filter{MinSeverity: "hgih"}.Validate()
	if err == nil {
		t.Fatal("잘못된 최소 심각도인데 오류가 없습니다")
	}
	assertKorean(t, "Filter.Validate", err.Error())
	// low/medium/high/critical 는 설정 enum 이라 원문 그대로 남아야 한다.
	for _, tok := range []string{"low", "medium", "high", "critical"} {
		if !strings.Contains(err.Error(), tok) {
			t.Errorf("심각도 토큰 %q 가 사라졌습니다: %q", tok, err.Error())
		}
	}
	// 올바른 값과 빈 값은 통과해야 한다.
	if err := (Filter{MinSeverity: "high"}).Validate(); err != nil {
		t.Errorf("high 는 유효한데 오류가 났습니다: %v", err)
	}
	if err := (Filter{}).Validate(); err != nil {
		t.Errorf("빈 최소 심각도는 유효한데 오류가 났습니다: %v", err)
	}
}

// TestPrepareConfigUpdateUnknownKindLocalized 는 등록되지 않은 채널 유형으로 설정을
// 갱신할 때의 오류(server/notify_api.go:326 에서 400)를 검사한다.
func TestPrepareConfigUpdateUnknownKindLocalized(t *testing.T) {
	_, err := PrepareConfigUpdate("definitely-not-a-channel", map[string]any{}, map[string]any{})
	if err == nil {
		t.Fatal("미등록 채널 유형인데 오류가 없습니다")
	}
	assertKorean(t, "PrepareConfigUpdate unknown kind", err.Error())
}

// TestDestinationChangedErrorLocalized 는 실제 경로로 ErrDestinationChangedWithoutCredentials
// 를 유발한다: webhook 의 대상 주소(url)만 새 값으로 바꾸고 자격 증명(headers)에는
// 아무 표태도 하지 않는 PATCH 다. 서버는 이를 400 으로 돌려준다.
func TestDestinationChangedErrorLocalized(t *testing.T) {
	_, err := PrepareConfigUpdate("webhook",
		map[string]any{
			"url":     "https://old.example.com/hook",
			"headers": map[string]any{"Authorization": "Bearer real-token"},
		},
		map[string]any{"url": "https://attacker.example.com/hook"},
	)
	if err == nil {
		t.Fatal("대상 주소를 바꾸고 자격 증명을 표태하지 않았는데 오류가 없습니다")
	}
	var de *ErrDestinationChangedWithoutCredentials
	if !errors.As(err, &de) {
		t.Fatalf("예상한 오류 유형이 아닙니다: %T", err)
	}
	assertKorean(t, "ErrDestinationChangedWithoutCredentials", err.Error())
	// 바뀐 대상 키·누락된 자격 증명 키 이름은 설정 필드명이라 메시지에 그대로 들어가야 한다.
	if !strings.Contains(err.Error(), "url") || !strings.Contains(err.Error(), "headers") {
		t.Errorf("필드 키 이름이 누락됐습니다: %q", err.Error())
	}
}

// TestRejectMaskedInContainersLocalized 는 실제 경로로 구조체 내부 마스킹 센티넬 거부를
// 유발한다: headers(객체이자 자격 증명 필드) 안에 마스킹 센티넬 값을 끼워 넣은 PATCH 다.
func TestRejectMaskedInContainersLocalized(t *testing.T) {
	_, err := PrepareConfigUpdate("webhook",
		map[string]any{},
		map[string]any{"headers": map[string]any{"Authorization": MaskedPrefix + ":…abc123"}},
	)
	if err == nil {
		t.Fatal("구조체 내부에 마스킹 센티넬을 끼워 넣었는데 오류가 없습니다")
	}
	assertKorean(t, "rejectMaskedInContainers", err.Error())
	// 센티넬 리터럴(__masked__)은 운영자가 어느 값이 문제인지 알 수 있게 메시지에 표시된다.
	if !strings.Contains(err.Error(), MaskedPrefix) {
		t.Errorf("마스킹 센티넬이 메시지에 없습니다: %q", err.Error())
	}
}
