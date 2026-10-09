package agent

import (
	"context"
	"time"

	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

const InvestigatorVersion = "cert-agent-v1"

// InvestigationSearch is deliberately data, not SPL or a shell command. The
// server callback must enforce the configured source/index and field mapping.
type InvestigationSearch struct {
	Scope        investigation.Scope `json:"scope"`
	SourceIP     string              `json:"source_ip,omitempty"`
	User         string              `json:"user,omitempty"`
	Session      string              `json:"session,omitempty"`
	EventKind    string              `json:"event_kind,omitempty"`
	PathContains string              `json:"path_contains,omitempty"`
	Remote       bool                `json:"remote"`
	Offset       int                 `json:"offset,omitempty"`
}

type InvestigatorBudget struct {
	MaxRounds      int `json:"max_rounds"`
	MaxModelCalls  int `json:"max_model_calls"`
	MaxQueries     int `json:"max_queries"`
	MaxTokens      int `json:"max_tokens"`
	TimeoutSeconds int `json:"timeout_seconds"`
}

type InvestigatorOptions struct {
	Provider     llm.Provider
	NonStreaming bool
	MaxTokens    int // per reply, additionally capped at 2048
	SessionID    string
	Transcript   *transcript.Store
	Finding      investigation.FindingContext
	Question     string
	Collection   investigation.Collection
	Search       func(context.Context, InvestigationSearch) (investigation.Collection, error)
	Emit         func(InvestigatorProgress)
	Budget       InvestigatorBudget // zero values use the bounded defaults
}

type InvestigatorIntent struct {
	ID           string   `json:"id"`
	Round        int      `json:"round"`
	Hypothesis   string   `json:"hypothesis"`
	Objective    string   `json:"objective"`
	Reason       string   `json:"reason"`
	EvidenceRefs []string `json:"evidence_refs"`
	State        string   `json:"state"`
}

type InvestigatorObservation struct {
	ID           string   `json:"id"`
	IntentID     string   `json:"intent_id"`
	Kind         string   `json:"kind"` // observed, inferred, or insufficient_data
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs"`
	Alternatives []string `json:"alternatives"`
	NextSteps    []string `json:"next_steps"`
	KnownARTEX   bool     `json:"known_artex"`
}

type InvestigatorDecision struct {
	Round        int      `json:"round"`
	Action       string   `json:"action"` // investigate, complete, insufficient_data
	Reason       string   `json:"reason"`
	EvidenceRefs []string `json:"evidence_refs"`
}

type InvestigatorProgress struct {
	At           time.Time                `json:"at"`
	Stage        string                   `json:"stage"`
	Round        int                      `json:"round"`
	Kind         string                   `json:"kind"`
	Tool         string                   `json:"tool,omitempty"`
	Summary      string                   `json:"summary"`
	Detail       string                   `json:"detail,omitempty"`
	IsError      bool                     `json:"is_error,omitempty"`
	Usage        InvestigatorUsage        `json:"usage"`
	EvidenceRefs []string                 `json:"evidence_refs,omitempty"`
	Intent       *InvestigatorIntent      `json:"intent,omitempty"`
	Observation  *InvestigatorObservation `json:"observation,omitempty"`
	Decision     *InvestigatorDecision    `json:"decision,omitempty"`
}

type InvestigatorUsage struct {
	ModelCalls     int `json:"model_calls"`
	Queries        int `json:"queries"`
	InputTokens    int `json:"input_tokens"`
	OutputTokens   int `json:"output_tokens"`
	ReservedTokens int `json:"reserved_tokens"`
}

type InvestigatorReport struct {
	Version      string                    `json:"version"`
	Status       string                    `json:"status"`
	Summary      string                    `json:"summary"`
	StartedAt    time.Time                 `json:"started_at"`
	FinishedAt   time.Time                 `json:"finished_at"`
	Scope        investigation.Scope       `json:"scope"`
	Budget       InvestigatorBudget        `json:"budget"`
	Usage        InvestigatorUsage         `json:"usage"`
	Decisions    []InvestigatorDecision    `json:"decisions"`
	Intents      []InvestigatorIntent      `json:"intents"`
	Observations []InvestigatorObservation `json:"observations"`
	Gaps         []string                  `json:"gaps"`
	NextSteps    []string                  `json:"next_steps"`
	Trace        []InvestigatorProgress    `json:"trace"`
	Searches     []InvestigationSearch     `json:"searches"`
	// Additional evidence retains original bytes locally for audit/export; it is
	// never inserted wholesale into the LLM prompt.
	Collections []investigation.Collection `json:"collections"`
}
