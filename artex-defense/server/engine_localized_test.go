package server

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// engine.go 의 작업 제어·의도 개입 오류 중 "사용자 노출" 문구를 한국어로 유지하는 회귀
// 방어 테스트다. 한국어 판정은 F3a 가 만든 assertKoreanError(한글 포함·중국어 한자 0)를
// 재사용한다.
//
// 호출 그래프 판정(engine.go 상수 블록 주석 참조):
//   - ControlWork 의 네 오류(실행 중 work 없음·이미 제어 중·마무리 대기 취소·마무리 대기
//     타임아웃) → applyIntentControl(task_control.go) → controlIntent(server.go:1236) →
//     writeErr 409. 사용자 전용이며 에이전트 도구(actool) 경로에 닿지 않는다.
//   - runDetachedIntent 의 두 오류(Worker 미준비·재개 CAS 충돌) →
//     sendWorkerMessage(intent_intervention.go:147) → writeErr. 사용자 전용이다.
//   - 반대로 SteerWork·KillWork(steer_work·kill_work 도구 actool.Errorf)·
//     transitionIntentState(내부 상태 전이 로그)의 중국어는 두뇌 입력·로그라 보존하며 이
//     테스트의 대상이 아니다.

// TestControlWorkNoRunningWorkErrorLocalized 는 실행 중 work 가 없을 때 ControlWork 가
// 실제로 한국어 오류를 반환하는지 DB·엔진 없이 직접 구동한다. run==nil 분기는 e.work 맵만
// 보므로 NewEngine(nil) 로 끝까지 도달한다. %w 로 errWorkControlConflict 센티넬을 감싸므로
// errors.Is 관계가 함께 보존되는지도 확인한다. 누군가 이 리터럴을 중국어로 되돌리면 실패한다.
func TestControlWorkNoRunningWorkErrorLocalized(t *testing.T) {
	e := NewEngine(nil)
	err := e.ControlWork(context.Background(), 42, "pause")
	if err == nil {
		t.Fatal("실행 중 work 가 없는데 ControlWork 가 nil 을 반환했습니다")
	}
	if !errors.Is(err, errWorkControlConflict) {
		t.Fatalf("errors.Is(err, errWorkControlConflict) = false, err=%v", err)
	}
	assertKoreanError(t, "control_work_no_running", err.Error())
}

// TestEngineUserFacingErrorsLocalized 는 엔진/DB 게이트나 고루틴 타이밍 뒤에 있어 끝까지
// 구동하기 어려운 나머지 사용자 노출 형식 문자열을 핀 고정한다(finding_retests·
// finding_traffic 의 게이트 뒤 경로와 같은 방식). 형식 문자열은 대표 인자로 채운 뒤 판정한다.
func TestEngineUserFacingErrorsLocalized(t *testing.T) {
	for _, c := range []struct {
		label, msg string
	}{
		{"work_control_busy", fmt.Errorf(errWorkControlBusyFmt, errWorkControlConflict, int64(42), "pause").Error()},
		{"work_control_wait", fmt.Errorf(errWorkControlWaitFmt, int64(42), "pause", context.DeadlineExceeded).Error()},
		{"detached_worker_not_ready", errDetachedWorkerNotReady},
		{"detached_state_conflict", fmt.Errorf(errIntentCtrlStateConflictFmt, db.ErrIntentStateConflict).Error()},
	} {
		assertKoreanError(t, c.label, c.msg)
	}
}
