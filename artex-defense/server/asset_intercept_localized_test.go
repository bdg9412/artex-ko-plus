package server

import "testing"

// asset_intercept.go·task_intercept.go 의 가로채기 규칙 검증기가 돌려주는 사용자 노출
// 오류 문구를 한국어로 유지하는 회귀 방어 테스트다. 두 검증기
// (validateAssetInterceptRuleReq·validateTaskInterceptRuleReq)는 DB 를 쓰지 않는 순수
// 함수라, 상수 핀 고정에 더해 실제 오류 경로를 직접 호출해 반환 문구까지 검증한다.
// 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어 한자 0)를 재사용한다.
// 필드명·열거값(pattern·exact_ip·cidr·kind·action·block·allow)은 와이어 식별자라 ASCII 로
// 남으며 한자 판정에서 걸리지 않는다. 누군가 둘러싼 설명을 중국어로 되돌리면 실패한다.
func TestAssetInterceptErrorsLocalized(t *testing.T) {
	// 상수 핀 고정
	for _, c := range []struct{ label, msg string }{
		{"pattern_empty", errAssetInterceptPatternEmpty},
		{"bad_exact_ip", errAssetInterceptInvalidExactIPFmt},
		{"bad_cidr", errAssetInterceptInvalidCIDRFmt},
		{"bad_kind", errAssetInterceptInvalidKindFmt},
		{"bad_action", errTaskInterceptInvalidAction},
	} {
		assertKoreanError(t, c.label, c.msg)
	}

	// 실제 경로: validateAssetInterceptRuleReq 의 네 거부 분기
	for _, c := range []struct {
		label string
		req   assetInterceptRuleReq
	}{
		{"empty_pattern", assetInterceptRuleReq{Kind: "exact_ip", Pattern: "   "}},
		{"invalid_exact_ip", assetInterceptRuleReq{Kind: "exact_ip", Pattern: "not-an-ip"}},
		{"invalid_cidr", assetInterceptRuleReq{Kind: "cidr", Pattern: "nonsense"}},
		{"invalid_kind", assetInterceptRuleReq{Kind: "nope", Pattern: "example.com"}},
	} {
		req := c.req
		err := validateAssetInterceptRuleReq(&req)
		if err == nil {
			t.Fatalf("%s: 오류가 없습니다(검증을 통과함)", c.label)
		}
		assertKoreanError(t, c.label, err.Error())
	}

	// 유효 입력은 거부되지 않는다
	okReq := assetInterceptRuleReq{Kind: "cidr", Pattern: "192.168.0.0/16"}
	if err := validateAssetInterceptRuleReq(&okReq); err != nil {
		t.Fatalf("유효한 CIDR 가 거부되었습니다: %v", err)
	}

	// 실제 경로: validateTaskInterceptRuleReq 의 action 거부 분기
	badAction := taskInterceptRuleReq{Action: "nope", Kind: "exact_domain", Pattern: "example.com"}
	if err := validateTaskInterceptRuleReq(&badAction); err == nil {
		t.Fatalf("bad_action_path: 오류가 없습니다(검증을 통과함)")
	} else {
		assertKoreanError(t, "bad_action_path", err.Error())
	}

	// action 공란은 block 기본값으로 정규화되어 통과한다
	defaultAction := taskInterceptRuleReq{Action: "", Kind: "exact_domain", Pattern: "example.com"}
	if err := validateTaskInterceptRuleReq(&defaultAction); err != nil {
		t.Fatalf("기본 action 정규화에 실패했습니다: %v", err)
	}
	if defaultAction.Action != "block" {
		t.Fatalf("기본 action 이 block 으로 정규화되지 않았습니다: %q", defaultAction.Action)
	}
}
