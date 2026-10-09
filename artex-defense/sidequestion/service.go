package sidequestion

import (
	"context"
	"errors"
	"strings"

	"github.com/Autumn-27/norma/llm"
)

// User-facing side-question outputs are Korean. The agent-brain prompts
// (request.go:instruction, context.go:summaryInstruction) stay in their
// benchmarked Chinese; only text and errors shown to the user are localized
// (BRIEF 현지화 방침: 출력 언어만 한국어, 프롬프트 본문은 보존).
var (
	errSideModelInterrupted = errors.New("모델 응답이 중단되었습니다. 다시 질문해 주세요.")
	errSideNoAnswer         = errors.New("모델이 답변을 반환하지 않았습니다.")
)

// msgSideToolUnavailable is the answer text shown when a side question tries to
// trigger a tool call: side questions cannot run tools.
const msgSideToolUnavailable = "현재 곁질문에서는 도구 작업을 실행할 수 없습니다. 작업 요청은 메인 대화에서 보내 주세요."

// SideQuestionService has no harness, tool executor, transcript writer or model
// failover chain. Answer is one completion; Respond adds bounded preparation
// and at most one context-overflow recovery around that completion.
type SideQuestionService struct{ Provider llm.Provider }

type Answer struct {
	Text    string
	Usage   llm.Usage
	ToolUse bool
}

func (s SideQuestionService) Answer(ctx context.Context, req llm.CompletionRequest, streaming bool, update func(Answer)) (out Answer, err error) {
	if streaming {
		complete := false
		for ev, streamErr := range s.Provider.Stream(ctx, req) {
			if streamErr != nil {
				err = streamErr
				break
			}
			switch ev.Type {
			case llm.SETextDelta:
				out.Text += ev.Text
			case llm.SEToolUseStart:
				out.ToolUse = true
			case llm.SEMessageStart, llm.SEMessageDelta:
				out.Usage.Add(ev.Usage)
			case llm.SEMessageStop:
				complete = true
			}
			if update != nil {
				update(out)
			}
			if ctx.Err() != nil {
				err = ctx.Err()
				break
			}
		}
		if err == nil && !complete {
			err = errSideModelInterrupted
		}
	} else {
		var msg llm.Message
		msg, _, out.Usage, err = s.Provider.Complete(ctx, req)
		out.Text, out.ToolUse = msg.Text(), len(msg.ToolUses()) > 0
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err == nil && strings.TrimSpace(out.Text) == "" {
		if out.ToolUse {
			out.Text = msgSideToolUnavailable
		} else {
			err = errSideNoAnswer
		}
	}
	return out, err
}
