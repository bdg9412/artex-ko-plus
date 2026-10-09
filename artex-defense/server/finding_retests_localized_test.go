package server

import "testing"

// finding_retests.go 의 사용자 노출 HTTP 에러 응답 문구를 한국어로 유지하는 회귀 방어
// 테스트다. 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어 한자 0)를
// 재사용한다. 네 문구를 반환하는 startFindingRetest 핸들러는 맨 앞에서 s.pg(w)(DB)
// 게이트를 지나므로 DB 없는 이 호스트에서 끝까지 돌 수 없어, 상수 자체를 핀 고정한다
// (finding_traffic·goals_api·notify_api 의 DB 게이트 경로와 같은 방식). 누군가 이
// 리터럴을 중국어로 되돌리면 이 테스트가 실패한다.
//
// 도구 설명(get_finding_retest_context·record_finding_retest_result)·파라미터 설명·
// actool.Errorf(회차 미연결 안내)와 seedFindingRetester 의 DB 시드 에이전트 이름·
// 프로필·note 는 에이전트가 읽는 두뇌 입력이거나 시드라 의도적으로 원문(중국어)을
// 보존하며, 이 테스트의 단언 대상이 아니다(finding_retests.go 상수 블록 주석 참조).
func TestFindingRetestErrorsLocalized(t *testing.T) {
	for _, c := range []struct {
		label, msg string
	}{
		{"notes_too_long", errFindingRetestNotesTooLong},
		{"agent_missing", errFindingRetestAgentMissing},
		{"tool_required", errFindingRetestToolRequired},
		{"service_stopping", errFindingRetestServiceStopping},
	} {
		assertKoreanError(t, c.label, c.msg)
	}
}
