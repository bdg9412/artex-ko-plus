package server

import (
	"encoding/json"
	"fmt"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/norma/llm"
)

// ollamaBudgetEstimate is deliberately approximate. Norma's request has already
// been compacted when it reaches the task runtime, but its compactor does not
// account for the system prompt, tool schemas, or the next reply's token budget.
type ollamaBudgetEstimate struct {
	system   int
	messages int
	tools    int
	overhead int
	output   int
}

func (e ollamaBudgetEstimate) input() int {
	return e.system + e.messages + e.tools + e.overhead
}

// estimateOllamaBudget uses the JSON form of the actual request components. Four
// ASCII bytes per token and two non-ASCII UTF-8 bytes per token are cautious
// approximations, not a model tokenizer. Small fixed framing costs cover the
// OpenAI-compatible wire format. An unset max_tokens gets a modest reply reserve;
// the server's true default is unknown, so this is only a preflight safeguard.
func estimateOllamaBudget(req llm.CompletionRequest) (ollamaBudgetEstimate, error) {
	var e ollamaBudgetEstimate
	var err error
	if e.system, err = estimatedJSONTokens(req.System); err != nil {
		return e, fmt.Errorf("cannot estimate Ollama system prompt size")
	}
	if e.messages, err = estimatedJSONTokens(req.Messages); err != nil {
		return e, fmt.Errorf("cannot estimate Ollama message size")
	}
	if e.tools, err = estimatedJSONTokens(req.Tools); err != nil {
		return e, fmt.Errorf("cannot estimate Ollama tool schema size")
	}
	e.overhead = 256 + 4*len(req.Messages) + 8*len(req.Tools)
	e.output = req.MaxTokens
	if e.output <= 0 {
		e.output = 1024
	}
	return e, nil
}

func estimatedJSONTokens(value any) (int, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return 0, err
	}
	var ascii, nonASCII int
	for _, b := range raw {
		if b < 0x80 {
			ascii++
		} else {
			nonASCII++
		}
	}
	return (ascii+3)/4 + (nonASCII+1)/2, nil
}

// checkOllamaContextBudget rejects only a request whose estimated total is
// already beyond ARTEX's configured window. The window must separately match
// Ollama's num_ctx; this function cannot discover the server's live setting.
// Errors contain counts only, never prompt text, tool inputs, or credentials.
func checkOllamaContextBudget(cfg agent.Config, req llm.CompletionRequest) error {
	if !cfg.IsOllama() {
		return nil
	}
	estimate, err := estimateOllamaBudget(req)
	if err != nil {
		return err
	}
	window := cfg.CompactionWindow()
	if estimate.output <= window && estimate.input() <= window-estimate.output {
		return nil
	}
	return fmt.Errorf("Ollama context length budget exceeded (conservative estimate): input %d tokens (system %d, messages %d, tools %d, framing %d) + reserved output %d > configured context %d; reduce request size or align Ollama num_ctx and ARTEX context_window_k",
		estimate.input(), estimate.system, estimate.messages, estimate.tools, estimate.overhead, estimate.output, window)
}
