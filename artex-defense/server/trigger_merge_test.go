package server

import (
	"strings"
	"testing"
)

// A long task goal repeated per event was the dominant bloat. These tests pin the
// fix: the task-context header (description + goal) is rendered ONCE per task, no
// matter how many same-task fires are merged.

const longGoal = "拿到题目 f2-05 的受保护 flag 并通过 submit_flag 提交；本题密文已高度收敛，flag 只能由二进制内嵌数据派生……" // 代表那段几千字的继承事实

func sameTaskFires(n int) []triggeredRun {
	items := make([]triggeredRun, n)
	for i := range items {
		items[i] = triggeredRun{
			agentKey: "tec_benchmark", taskID: 72, taskDesc: "f2-05 逆向", taskGoal: longGoal,
			message: "【本次由工具调用触发】\n工具: submit_flag\n入参: {...}\n返回: {correct:false}", mergeable: true,
		}
	}
	return items
}

func TestMergeAllRunsWritesTaskGoalOnce(t *testing.T) {
	out := mergeAllRuns(sameTaskFires(39))
	if got := strings.Count(out.message, longGoal); got != 1 {
		t.Fatalf("same-task goal should appear exactly once in a merged-all run, got %d", got)
	}
	if strings.Count(out.message, "── 触发 ") < 1 || !strings.Contains(out.message, "触发 39") {
		t.Fatalf("all 39 event bodies should be present: %q", out.message)
	}
	// A merged run embeds its header inline, so finalTriggerMessage must not re-add it.
	if out.taskDesc != "" || out.taskGoal != "" {
		t.Fatalf("merged run must clear taskDesc/taskGoal to avoid a duplicate header")
	}
	if finalTriggerMessage(out) != out.message {
		t.Fatalf("finalTriggerMessage must not prepend another header for a merged run")
	}
}

func TestMergeAllRunsGroupsInterleavedTasks(t *testing.T) {
	// Fires from two tasks arriving interleaved (A,B,A,B) must still carry each
	// task's context exactly once — grouping, not per-event repetition.
	mk := func(id int64, goal string) triggeredRun {
		return triggeredRun{agentKey: "a", taskID: id, taskDesc: "d", taskGoal: goal, message: "body", mergeable: true}
	}
	out := mergeAllRuns([]triggeredRun{mk(1, "GOAL_A"), mk(2, "GOAL_B"), mk(1, "GOAL_A"), mk(2, "GOAL_B")})
	if got := strings.Count(out.message, "GOAL_A"); got != 1 {
		t.Fatalf("task #1 goal should appear once despite interleaving, got %d", got)
	}
	if got := strings.Count(out.message, "GOAL_B"); got != 1 {
		t.Fatalf("task #2 goal should appear once despite interleaving, got %d", got)
	}
	if !strings.Contains(out.message, "共 2 个任务") {
		t.Fatalf("header should report 2 tasks: %q", out.message)
	}
	if got := strings.Count(out.message, "── 触发 "); got != 4 {
		t.Fatalf("all 4 event bodies should be present, got %d", got)
	}
}

func TestMergeTriggeredRunsWritesTaskGoalOnce(t *testing.T) {
	out := mergeTriggeredRuns(sameTaskFires(5))
	if got := strings.Count(out.message, longGoal); got != 1 {
		t.Fatalf("same-task goal should appear exactly once in a by-task merge, got %d", got)
	}
}

func TestFinalTriggerMessageSingleFirePrependsHeaderOnce(t *testing.T) {
	item := sameTaskFires(1)[0]
	msg := finalTriggerMessage(item)
	if got := strings.Count(msg, longGoal); got != 1 {
		t.Fatalf("single fire should carry the task goal exactly once, got %d", got)
	}
	if !strings.HasPrefix(msg, "【任务 #72") {
		t.Fatalf("single fire should be prefixed with the task-context header: %q", msg)
	}
}

func TestTaskContextHeaderEmptyForIntervalFire(t *testing.T) {
	if h := taskContextHeader(0, "", ""); h != "" {
		t.Fatalf("interval/none trigger (no task) must produce no header, got %q", h)
	}
	// An interval fire's message must pass through untouched.
	item := triggeredRun{message: "定时触发正文"}
	if finalTriggerMessage(item) != "定时触发正文" {
		t.Fatalf("interval fire message must pass through unchanged")
	}
}

func TestTaskContextHeaderTruncatesLongGoal(t *testing.T) {
	huge := strings.Repeat("很", 5000)
	h := taskContextHeader(72, "d", huge)
	if len([]rune(h)) > 800 { // 200 desc + 500 goal + 截断标记/装饰，远小于 5000
		t.Fatalf("header should be bounded even for a huge goal, got %d runes", len([]rune(h)))
	}
}

// TestTriggerSynthesisChineseFramingPreserved 는 P3 트리거 메시지 합성부가 만드는 중국어
// 프레이밍을 보존 대상(에이전트 두뇌 입력)으로 명시 고정한다(F10/F19 경계 판정). 이 문구들은
// finalTriggerMessage → runTriggeredRun → ca.Chat 의 user 메시지로 들어가는 에이전트 입력이자
// 전사에 노출되는 이중 용도라, BRIEF 경계 #1(두뇌는 번역하지 않는다 — 벤치마크 동작 보존)에
// 따라 번역하면 안 된다. 위 머지/헤더 동작 테스트가 `【任务 #`·`── 触发 `·`共 N 个任务` 를
// 이미 핀하지만, 작업 컨텍스트 헤더의 목표 프레이밍과 by-task 머지 안내는 아직 미핀이라
// 여기서 보강한다(우발 한국어화 역회귀 가드 · conversations.go 보존 주석과 짝).
func TestTriggerSynthesisChineseFramingPreserved(t *testing.T) {
	// 작업 컨텍스트 헤더의 목표 프레이밍(（目标：…）) 보존 — 입력에 CJK 를 안 넣어 프레이밍만 검증.
	if h := taskContextHeader(7, "d", "g"); !strings.Contains(h, "（目标：") {
		t.Fatalf("작업 컨텍스트 헤더의 목표 프레이밍이 바뀌었습니다(두뇌 입력 번역 금지): %q", h)
	}
	// by-task 머지 안내 프레이밍 보존.
	if out := mergeTriggeredRuns(sameTaskFires(3)); !strings.Contains(out.message, "【本会话合并了") {
		t.Fatalf("by-task 머지 안내 프레이밍이 바뀌었습니다(두뇌 입력 번역 금지): %q", out.message)
	}
}
