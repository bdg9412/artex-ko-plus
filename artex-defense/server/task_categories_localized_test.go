package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// decodeErrorField pulls the "error" string out of a writeErr JSON body so the
// Korean-ness of the user-facing message can be asserted.
func decodeErrorField(t *testing.T, body []byte) string {
	t.Helper()
	var resp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("응답 JSON 파싱 실패: %v (본문 %s)", err, body)
	}
	return resp.Error
}

// TestTaskCategoryErrorConstantsLocalized pins that every user-facing error
// literal in task_categories.go is Korean (Hangul present, no Chinese Han). If
// anyone reverts one to Chinese, this fails.
func TestTaskCategoryErrorConstantsLocalized(t *testing.T) {
	cases := map[string]string{
		"errTaskCatRequestTooLarge": errTaskCatRequestTooLarge,
		"errTaskCatNameEmpty":       errTaskCatNameEmpty,
		"errTaskCatNameTooLong":     errTaskCatNameTooLong,
		"errTaskCatNameConflict":    errTaskCatNameConflict,
		"errTaskCatInvalidID":       errTaskCatInvalidID,
		"errTaskCatBatchSizeFmt":    fmt.Sprintf(errTaskCatBatchSizeFmt, db.MaxTaskCategoryBatchSize),
	}
	for label, msg := range cases {
		assertKoreanError(t, label, msg)
	}
}

// TestTaskCategoryResponsesLocalized drives the validators that never touch the
// database and confirms the Korean message actually lands in the HTTP body. The
// request decoder and id parser work on the body alone, writeTaskCategoryError
// maps a db sentinel, and the batch-size guard returns before s.m is read.
func TestTaskCategoryResponsesLocalized(t *testing.T) {
	// decodeTaskCategoryRequest — body-only validation, no DB.
	decodeCase := func(name, body string) string {
		req := httptest.NewRequest(http.MethodPost, "/api/task-categories", strings.NewReader(body))
		rec := httptest.NewRecorder()
		if _, ok := decodeTaskCategoryRequest(rec, req); ok {
			t.Fatalf("%s: 검증이 통과해서는 안 됩니다 (status=%d)", name, rec.Code)
		}
		return decodeErrorField(t, rec.Body.Bytes())
	}
	assertKoreanError(t, "name-empty", decodeCase("name-empty", `{"name":"   "}`))
	assertKoreanError(t, "name-too-long",
		decodeCase("name-too-long", `{"name":"`+strings.Repeat("가", db.MaxTaskCategoryNameRunes+1)+`"}`))
	// The body exceeds maxTaskCategoryRequestBytes, so MaxBytesReader errors mid-decode.
	assertKoreanError(t, "too-large",
		decodeCase("too-large", `{"name":"`+strings.Repeat("a", maxTaskCategoryRequestBytes+1)+`"}`))

	// parseCategoryIDField — a zero/negative category_id is rejected.
	rec := httptest.NewRecorder()
	if _, ok := parseCategoryIDField(rec, json.RawMessage("0")); ok {
		t.Fatal("invalid id 가 통과해서는 안 됩니다")
	}
	assertKoreanError(t, "invalid-id", decodeErrorField(t, rec.Body.Bytes()))

	// writeTaskCategoryError — the name-conflict sentinel maps to the Korean 409.
	rec = httptest.NewRecorder()
	writeTaskCategoryError(rec, db.ErrTaskCategoryNameConflict)
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d, want 409", rec.Code)
	}
	assertKoreanError(t, "name-conflict", decodeErrorField(t, rec.Body.Bytes()))

	// Batch move — an empty selection is rejected before any DB access, so a
	// zero-value Server reaches the guard without dereferencing s.m.
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/category/batch",
		strings.NewReader(`{"task_ids":[],"category_id":null}`))
	rec = httptest.NewRecorder()
	(&Server{}).updateTasksCategoryBatch(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty batch status=%d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	assertKoreanError(t, "batch-size", decodeErrorField(t, rec.Body.Bytes()))
}
