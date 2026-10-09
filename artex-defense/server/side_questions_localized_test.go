package server

import "testing"

// TestSideQuestionAPIErrorsLocalized guards F21: every user-facing side-question
// (곁질문) message surfaced by the HTTP wrapper (writeErr responses) and by the
// exchange status (e.Error) must be Korean — Hangul present, no Chinese Han.
// These reach the chat 곁질문 panel alongside the sidequestion package errors, so
// both layers are localized together to avoid a mixed-language panel. Reuses
// assertKoreanError (F3a).
func TestSideQuestionAPIErrorsLocalized(t *testing.T) {
	for _, c := range []struct{ label, msg string }{
		{"ctx_not_saved", sideErrCtxNotSaved},
		{"model_config_changed", sideErrModelConfigChanged},
		{"service_unavailable", sideErrServiceUnavailable},
		{"task_archived", sideErrTaskArchived},
		{"worker_deleted", sideErrWorkerDeleted},
		{"bad_question", sideErrBadQuestion},
		{"task_archiving", sideErrTaskArchiving},
		{"request_id_reused", sideErrRequestIDReused},
		{"no_snapshot", sideErrNoSnapshot},
		{"concurrency_limit", sideErrConcurrencyLimit},
		{"answer_stopped", sideErrAnswerStopped},
		{"answer_timeout", sideErrAnswerTimeout},
	} {
		assertKoreanError(t, c.label, c.msg)
	}
}
