package server

import "testing"

// TestReporterSeedLabelsLocalized 는 시드되는 reporter 에이전트의 표시 전용 라벨
// (reporterAgentName·reporterAgentDescription)이 한국어로 유지되는지 지키는 회귀 방어
// 테스트다. 이 두 문자열은 `agentDTO`(server_mgmt.go)로 system/agents UI 에만 렌더되고,
// 어떤 에이전트 system 프롬프트에도(renderSystem 은 key→段[A] agent.ReporterDefaultPrompt
// 로만 조립) 모델 기반 에이전트 선택에도(reporter 트리거는 report_finding 도구 호출 기반
// OnToolCall·결정적) 들어가지 않는 순수 UI 라벨이다. 그래서 한국어화가 BRIEF 경계 #1
// (두뇌 미번역)을 건드리지 않는다. 반대로 reporter 의 두뇌 본문(agent.ReporterDefaultPrompt)
// 과 트리거 주입 메시지(reporterToolCallMessage)는 모델 입력이라 중국어 원문을 보존하므로
// 이 테스트 대상이 아니다. 한국어 판정은 assertKoreanError(한글 포함·중국어 한자 0,
// intercept_archive_localized_test.go)를 재사용한다. [[F35]] [[G133]]
func TestReporterSeedLabelsLocalized(t *testing.T) {
	assertKoreanError(t, "reporter_name", reporterAgentName)
	assertKoreanError(t, "reporter_description", reporterAgentDescription)
}
