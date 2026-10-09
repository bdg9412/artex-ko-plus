package server

import "testing"

// goals.go 의 작업 재개(admitPausedTask) 사전 조건 검증 오류 문구를 한국어로 유지하는
// 회귀 방어 테스트다. 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어
// 한자 0)를 재사용한다. 두 문구를 반환하는 admitTaskWhen(requirePaused=true) 경로는
// s.concMu 잠금 뒤 s.m.Task()·s.engine.IsDeleting()·beginTaskOperation() 엔진 게이트를
// 지나므로 DB·엔진 없는 이 호스트에서 끝까지 돌 수 없어, 상수 자체를 핀 고정한다
// (finding_retests·finding_traffic 의 게이트 뒤 경로와 같은 방식). 누군가 이 리터럴을
// 중국어로 되돌리면 이 테스트가 실패한다.
//
// 호출 그래프 판정(goals.go 상수 블록 주석 참조): 두 문구는 단건(server.go:1194 →
// writeErr 409)·배치(task_control.go:298 → items[].error) 작업 제어 응답으로만 노출되는
// 사용자 전용이다. 오케스트레이터 경로(orchestration.go:343)는 action="pause" 로 고정이라
// 재개 검증에 닿지 않으므로 두뇌 입력이 아니다.
func TestGoalResumeErrorsLocalized(t *testing.T) {
	for _, c := range []struct {
		label, msg string
	}{
		{"resume_terminal", errGoalResumeTerminal},
		{"resume_not_paused", errGoalResumeNotPaused},
	} {
		assertKoreanError(t, c.label, c.msg)
	}
}
