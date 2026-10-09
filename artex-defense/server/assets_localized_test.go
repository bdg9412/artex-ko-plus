package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAssetErrorConstantsLocalized pins that every user-facing writeErr literal
// in task_assets.go and assets.go is Korean (Hangul present, no Chinese Han). If
// anyone reverts one to Chinese, this fails.
func TestAssetErrorConstantsLocalized(t *testing.T) {
	cases := map[string]string{
		"errTaskAssetRequestTooLarge": errTaskAssetRequestTooLarge,
		"errTaskAssetScopeConflict":   errTaskAssetScopeConflict,
		"errCompanyRequestTooLarge":   errCompanyRequestTooLarge,
		"errCompanyNameConflict":      errCompanyNameConflict,
	}
	for label, msg := range cases {
		assertKoreanError(t, label, msg)
	}
}

// TestTaskAssetProvenanceLocalized pins the asset-provenance summary labels that
// get stored in task_asset_links.source_summary and rendered verbatim on the task
// detail sessions/assets tabs. Reverting either to Chinese fails here. The manual
// variant lives in the db package (db.manualTaskScopeSummary) and is pinned there.
func TestTaskAssetProvenanceLocalized(t *testing.T) {
	cases := map[string]string{
		"taskAssetSourceAPISummary":  taskAssetSourceAPISummary,
		"taskAssetSourceTaskSummary": taskAssetSourceTaskSummary,
	}
	for label, msg := range cases {
		assertKoreanError(t, label, msg)
	}
}

// TestAssetResponsesLocalized drives the request validators that return before
// any database access and confirms the Korean message actually lands in the HTTP
// body. The scope/asset_ids conflict guard returns before s.m.Assets() is read,
// MaxBytesReader trips mid-decode, and decodeCompanyMutationRequest works on the
// body alone, so a Manager holding only the task map reaches every path.
func TestAssetResponsesLocalized(t *testing.T) {
	s := &Server{m: &Manager{tasks: map[string]*Task{"1": {ID: "1"}}}}

	// attachTaskAssets — scope and asset_ids may not be submitted together.
	conflictReq := httptest.NewRequest(http.MethodPost, "/api/tasks/1/assets",
		strings.NewReader(`{"scope":["example.com"],"asset_ids":[1]}`))
	conflictReq.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	s.attachTaskAssets(rec, conflictReq)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("scope+asset_ids status=%d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	assertKoreanError(t, "scope-conflict", decodeErrorField(t, rec.Body.Bytes()))

	// attachTaskAssets — an oversized body trips MaxBytesReader during decode.
	bigReq := httptest.NewRequest(http.MethodPost, "/api/tasks/1/assets",
		strings.NewReader(`{"source_summary":"`+strings.Repeat("a", maxTaskAssetRequestBytes+1)+`"}`))
	bigReq.SetPathValue("id", "1")
	rec = httptest.NewRecorder()
	s.attachTaskAssets(rec, bigReq)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("task asset too-large status=%d, want 413 (body %s)", rec.Code, rec.Body.String())
	}
	assertKoreanError(t, "task-asset-too-large", decodeErrorField(t, rec.Body.Bytes()))

	// decodeCompanyMutationRequest — a body-only helper, no DB or Server state.
	compReq := httptest.NewRequest(http.MethodPost, "/api/companies",
		strings.NewReader(`{"name":"`+strings.Repeat("a", maxCompanyMutationBodyBytes+1)+`"}`))
	rec = httptest.NewRecorder()
	var dst map[string]any
	if ok := decodeCompanyMutationRequest(rec, compReq, &dst); ok {
		t.Fatalf("company too-large body should not decode (status=%d)", rec.Code)
	}
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("company too-large status=%d, want 413 (body %s)", rec.Code, rec.Body.String())
	}
	assertKoreanError(t, "company-too-large", decodeErrorField(t, rec.Body.Bytes()))
}
