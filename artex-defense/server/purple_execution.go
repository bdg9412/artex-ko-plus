package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/securitysource"
)

// Bound outbound SIEM work across requests and Server instances in this process.
var defenseCollectSlots = make(chan struct{}, 2)

func (s *Server) registerPurpleExecutions(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/exploration/findings/{id}/defense/executions", s.listDefenseExecutions)
	mux.HandleFunc("POST /api/exploration/findings/{id}/defense/executions", s.startDefenseExecution)
	mux.HandleFunc("GET /api/exploration/findings/{id}/defense/executions/compare", s.compareDefenseExecutions)
	mux.HandleFunc("GET /api/exploration/findings/{id}/defense/executions/{executionID}/export", s.exportDefenseExecution)
	mux.HandleFunc("POST /api/exploration/findings/{id}/defense/executions/{executionID}/collect", s.collectDefenseExecution)
	mux.HandleFunc("POST /api/exploration/findings/{id}/defense/executions/{executionID}/upload", s.uploadDefenseExecution)
}

func (s *Server) startDefenseExecution(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	var in struct {
		db.DefenseExecutionInput
		Notes string `json:"notes"`
	}
	if !decodePurpleRequest(w, r, &in) {
		return
	}
	in.Notes = strings.TrimSpace(in.Notes)
	if !utf8.ValidString(in.Notes) || strings.ContainsRune(in.Notes, 0) || utf8.RuneCountInString(in.Notes) > 4000 {
		writeErr(w, http.StatusBadRequest, errFindingRetestNotesTooLong)
		return
	}
	pg := s.pg(w)
	if pg == nil || !s.findingRetestReady(w, r, pg, id) {
		return
	}
	retest, conv, execution, created, err := pg.CreateFindingRetestWithDefense(r.Context(), id, in.Notes, in.DefenseExecutionInput)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	if created {
		s.dispatchFindingRetest(retest, conv)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusAccepted, map[string]any{"execution": execution, "retest": retest, "created": created})
}

func (s *Server) listDefenseExecutions(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	executions, err := pg.ListDefenseExecutions(r.Context(), id)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"executions": executions})
}

func defenseExecutionID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, ok := pathInt(r, "executionID")
	if !ok || id <= 0 {
		writeErr(w, http.StatusBadRequest, "올바른 검증 실행 ID를 입력해 주세요")
		return 0, false
	}
	return id, true
}

func (s *Server) exportDefenseExecution(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	executionID, ok := defenseExecutionID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	execution, err := pg.GetDefenseExecution(r.Context(), id, executionID)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="defense-execution-%d.json"`, executionID))
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, execution)
}

// A completed observation window is required even when an early query finds an
// alert: delayed audit records may still alter the independent prevention result.
func defenseExecutionWindow(execution *db.DefenseExecution, now time.Time) (securitysource.Query, bool, error) {
	if execution == nil || execution.Retest == nil || execution.Retest.FinishedAt == nil {
		return securitysource.Query{}, false, errors.New("진단 실행이 종료된 뒤 증거를 수집해 주세요")
	}
	switch execution.Retest.Status {
	case "completed", "failed", "stopped":
	default:
		return securitysource.Query{}, false, errors.New("진단 실행이 종료된 뒤 증거를 수집해 주세요")
	}
	start := execution.CreatedAt
	if !execution.Retest.CreatedAt.IsZero() {
		start = execution.Retest.CreatedAt
	}
	if execution.Retest.StartedAt != nil {
		start = *execution.Retest.StartedAt
	}
	end := execution.Retest.FinishedAt.Add(time.Minute)
	complete := !now.Before(end)
	if !complete {
		end = now
	}
	start = start.Add(-30 * time.Second)
	if !end.After(start) || end.Sub(start) > 24*time.Hour {
		return securitysource.Query{}, false, errors.New("실행의 수집 시간 범위가 지원 범위를 벗어났습니다. 새 검증 실행을 시작해 주세요")
	}
	return securitysource.Query{CorrelationID: execution.CorrelationID, Start: start, End: end}, complete, nil
}

func (s *Server) collectDefenseExecution(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	executionID, ok := defenseExecutionID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	execution, err := pg.GetDefenseExecutionForCollection(r.Context(), id, executionID)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	if execution.SourceKind == "file" {
		writeErr(w, http.StatusConflict, "파일 연결 실행입니다. 감사·경보 로그 파일을 업로드해 주세요")
		return
	}
	query, windowComplete, err := defenseExecutionWindow(execution, time.Now().UTC())
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	source, err := pg.GetSecuritySource(r.Context(), execution.SourceID)
	if errors.Is(err, db.ErrSecuritySourceNotFound) {
		writePurpleError(w, db.ErrDefenseConflict)
		return
	}
	if err != nil {
		writePurpleError(w, err)
		return
	}
	var sourceSnapshot db.SecuritySource
	if json.Unmarshal(execution.SourceSnapshot, &sourceSnapshot) != nil || sourceSnapshot.ID != source.ID || sourceSnapshot.Revision != source.Revision || sourceSnapshot.Config != source.Config || source.Revision != execution.SourceRevision || !source.Enabled {
		writeErr(w, http.StatusConflict, "보안 로그 연결이 변경됐습니다. 현재 설정으로 새 검증 실행을 시작해 주세요")
		return
	}
	credentials, err := s.securitySourceCredentials(source)
	if err != nil {
		writeErr(w, http.StatusConflict, "저장된 보안 로그 인증 정보를 확인해 주세요")
		return
	}
	select {
	case defenseCollectSlots <- struct{}{}:
		defer func() { <-defenseCollectSlots }()
	default:
		writeErr(w, http.StatusTooManyRequests, "다른 증거 수집이 진행 중입니다. 잠시 후 다시 시도해 주세요")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	evidence, err := securitysource.Fetch(ctx, source.Config, credentials, query)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "보안 로그 증거를 수집하지 못했습니다. 연결 설정과 소스 상태를 확인해 주세요")
		return
	}
	if !windowComplete {
		evidence.Complete = false
		evidence.Warnings = append(evidence.Warnings, "진단 종료 후 60초의 관측 기간이 아직 끝나지 않았습니다. 이후 다시 수집해 주세요")
	}
	assessment, err := pg.SaveDefenseAssessment(ctx, id, executionID, evidence)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, assessment)
}

func (s *Server) compareDefenseExecutions(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	baselineID, baselineErr := strconv.ParseInt(r.URL.Query().Get("baseline_id"), 10, 64)
	currentID, currentErr := strconv.ParseInt(r.URL.Query().Get("current_id"), 10, 64)
	if baselineErr != nil || currentErr != nil || baselineID <= 0 || currentID <= 0 || baselineID == currentID {
		writeErr(w, http.StatusBadRequest, "서로 다른 기준 실행과 개선 후 실행 ID를 입력해 주세요")
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	comparison, err := pg.CompareDefenseExecutions(r.Context(), id, baselineID, currentID)
	if err != nil {
		writePurpleError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, comparison)
}
