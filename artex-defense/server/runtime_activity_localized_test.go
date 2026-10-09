package server

import (
	"fmt"
	"strings"
	"testing"
)

// engine.go·engine_timeout.go·goals.go 의 "표시 전용" 런타임 활동 요약 상수를 한국어로
// 유지하는 회귀 방어 테스트다. 이 요약들은 대시보드 전사(activity transcript)에 노출되지만
// node_id 를 달지 않아(작업 단위) 어떤 에이전트 컨텍스트로도 되읽히지 않는다 — 되먹임
// 경로(planner.workerOutput·get_worker_output 도구)는 intent 범위(node_id)에서 'result'/
// 'text' 활동만 고르기 때문이다. 그래서 한국어화가 두뇌 입력(BRIEF 경계 #1)을 건드리지
// 않는다. 반대로 두뇌로 되먹여지는 요약(seed 의도 요약 `完成任务目标…`·기본 설명 `未命名任务`
// 등)은 원문을 보존하므로 이 테스트 대상이 아니다. 한국어 판정은 assertKoreanError(한글
// 포함·중국어 한자 0, intercept_archive_localized_test.go)를 재사용한다. [[G132]]
func TestRuntimeActivitySummariesLocalized(t *testing.T) {
	// 포맷 인자 없는 고정 요약: 그대로 한국어여야 한다.
	plain := map[string]string{
		"goalless_task_done": goallessTaskDoneSummary,
		"goal_breakdown_r0":  goalBreakdownRound0Summary,
		"queued_no_llm":      queuedNoLLMSummary,
		"queued_fifo":        queuedFIFOSummary,
	}
	for label, msg := range plain {
		assertKoreanError(t, label, msg)
	}

	// %d 포맷 문자열: 포맷 인자가 살아 있고, 포맷한 결과도 한국어이며 숫자가 실제로
	// 반영되는지 확인한다.
	fmtCases := map[string]string{
		"planner_round":       plannerRoundSummaryFmt,
		"timeout_final_round": timeoutFinalRoundSummaryFmt,
		"queued_conc_limit":   queuedConcurrencyLimitSummaryFmt,
	}
	for label, f := range fmtCases {
		if !strings.Contains(f, "%d") {
			t.Fatalf("%s: 포맷 인자 %%d 가 사라졌습니다: %q", label, f)
		}
		got := fmt.Sprintf(f, 7)
		assertKoreanError(t, label, got)
		if !strings.Contains(got, "7") {
			t.Fatalf("%s: 포맷 인자가 결과에 반영되지 않았습니다: %q", label, got)
		}
	}
}
