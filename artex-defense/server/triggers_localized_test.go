package server

import "testing"

// triggers.go 의 트리거 설정 검증 오류 문구를 한국어로 유지하는 회귀 방어 테스트다.
// 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어 한자 0)를 재사용한다.

// TestTriggerErrorConstantsLocalized 는 오류 상수 3종이 전부 한국어임을 단언한다.
func TestTriggerErrorConstantsLocalized(t *testing.T) {
	cases := []struct {
		name string
		msg  string
	}{
		{"no_condition", errTriggerNoCondition},
		{"tool_set_empty", errTriggerToolSetEmpty},
		{"custom_only", errTriggerCustomOnly},
	}
	for _, c := range cases {
		assertKoreanError(t, c.name, c.msg)
	}
}

// TestValidateTriggerLocalized 는 validateTrigger 순수 함수를 실제로 호출해, 조건 누락·도구
// 미선택 경로가 한국어 상수를 돌려주고 유효 입력은 빈 문자열을 돌려줌을 확인한다. 이 반환값은
// pgCreateTrigger·pgUpdateTrigger 가 writeErr(400, msg) 로 사용자에게 그대로 노출한다.
func TestValidateTriggerLocalized(t *testing.T) {
	if msg := validateTrigger(&triggerReq{}); msg != errTriggerNoCondition {
		t.Fatalf("조건 누락 문구 = %q, 기대 = %q", msg, errTriggerNoCondition)
	}
	if msg := validateTrigger(&triggerReq{OnToolCall: true}); msg != errTriggerToolSetEmpty {
		t.Fatalf("도구 미선택 문구 = %q, 기대 = %q", msg, errTriggerToolSetEmpty)
	}
	if msg := validateTrigger(&triggerReq{OnFinding: true}); msg != "" {
		t.Fatalf("유효 입력 문구 = %q, 기대 = 빈 문자열", msg)
	}
	if msg := validateTrigger(&triggerReq{OnToolCall: true, ToolNames: []string{"nmap"}}); msg != "" {
		t.Fatalf("유효 도구 호출 문구 = %q, 기대 = 빈 문자열", msg)
	}
}
