package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestTaskTemplateErrorConstantsLocalized guards the F3b task-template bundle:
// every user-facing string the task-template API returns must be Korean with no
// leftover Chinese Han characters. The format constant is checked after
// formatting so the %s/%d verbs resolve to a concrete message.
func TestTaskTemplateErrorConstantsLocalized(t *testing.T) {
	assertKoreanError(t, "request-too-large", errTaskTemplateRequestTooLarge)
	assertKoreanError(t, "name-conflict", errTaskTemplateNameConflict)
	assertKoreanError(t, "rule-invalid", errTaskTemplateRuleInvalid)
	assertKoreanError(t, "no-fields", errTaskTemplateNoFields)
	assertKoreanError(t, "field-too-long",
		fmt.Sprintf(errTaskTemplateFieldTooLongFmt, "name", db.MaxTaskTemplateNameRunes))
}

// TestTaskTemplateResponsesLocalized drives the real response paths that do not
// touch the database: the body decoder rejects an oversized request, the field
// validator rejects an over-length name, and writeTaskTemplateErr maps the
// name-conflict sentinel to the Korean 409 body.
func TestTaskTemplateResponsesLocalized(t *testing.T) {
	// decodeTaskTemplateRequest — MaxBytesReader errors on an oversized body
	// before any DB access, so the 413 message is produced on its own.
	body := `{"name":"` + strings.Repeat("a", maxTaskTemplateRequestBytes+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/task-templates", strings.NewReader(body))
	rec := httptest.NewRecorder()
	var decoded taskTemplateRequest
	if _, ok := decodeTaskTemplateRequest(rec, req, &decoded); ok {
		t.Fatalf("too-large: 디코딩이 통과해서는 안 됩니다 (status=%d)", rec.Code)
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too-large status=%d, want 413", rec.Code)
	}
	assertKoreanError(t, "too-large", decodeErrorField(t, rec.Body.Bytes()))

	// validateTaskTemplateRequest — a name past the rune limit returns the
	// Korean field-too-long error (surfaced via writeErr in the handlers).
	longName := strings.Repeat("가", db.MaxTaskTemplateNameRunes+1)
	err := validateTaskTemplateRequest(taskTemplateRequest{Name: &longName})
	if err == nil {
		t.Fatal("name-too-long: 검증이 통과해서는 안 됩니다")
	}
	assertKoreanError(t, "name-too-long", err.Error())

	// writeTaskTemplateErr — the name-conflict sentinel maps to the Korean 409.
	rec = httptest.NewRecorder()
	writeTaskTemplateErr(rec, db.ErrTaskTemplateNameConflict)
	if rec.Code != http.StatusConflict {
		t.Fatalf("name-conflict status=%d, want 409", rec.Code)
	}
	assertKoreanError(t, "name-conflict-response", decodeErrorField(t, rec.Body.Bytes()))
}
