package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/artex/securitysource"
)

type investigationRequest struct {
	Title                     string                    `json:"title"`
	Question                  string                    `json:"question"`
	Scope                     investigation.Scope       `json:"scope"`
	Mapping                   investigation.Mapping     `json:"mapping"`
	SourceKind                string                    `json:"source_kind"`
	FileLabel                 string                    `json:"file_label"`
	Files                     []investigation.InputFile `json:"files"`
	SourceID                  int64                     `json:"source_id,string"`
	ExpectedSourceRevision    int64                     `json:"expected_source_revision"`
	Sourcetypes               []string                  `json:"sourcetypes"`
	CoverageConfirmed         bool                      `json:"coverage_confirmed"`
	TargetScopeConfirmed      bool                      `json:"target_scope_confirmed"`
	ExpectedEvidenceVersion   *int64                    `json:"expected_evidence_version"`
	ExpectedSourceFingerprint string                    `json:"expected_source_fingerprint"`
}

func (s *Server) registerInvestigations(mux *http.ServeMux) {
	s.registerInvestigationRuns(mux)
	mux.HandleFunc("GET /api/exploration/findings/{id}/investigations", s.listFindingInvestigations)
	mux.HandleFunc("POST /api/exploration/findings/{id}/investigations/preview", s.previewFindingInvestigation)
	mux.HandleFunc("POST /api/exploration/findings/{id}/investigations", s.runFindingInvestigation)
	mux.HandleFunc("GET /api/exploration/findings/{id}/investigations/{investigationID}", s.getFindingInvestigation)
	mux.HandleFunc("GET /api/exploration/findings/{id}/investigations/{investigationID}/export", s.exportFindingInvestigation)
}
func investigationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrInvestigationRunNotFound), errors.Is(err, db.ErrInvestigationNotFound), errors.Is(err, db.ErrFindingNotFound), errors.Is(err, db.ErrSecuritySourceNotFound):
		writeErr(w, 404, err.Error())
	case errors.Is(err, db.ErrInvestigationRunInactive), errors.Is(err, db.ErrDefenseConflict), errors.Is(err, db.ErrTaskArchiveState):
		writeErr(w, 409, "취약점 근거·로그 연결 또는 작업 상태가 변경됐습니다. 새로고침 후 다시 조사해 주세요")
	case errors.Is(err, db.ErrDefenseInvalid), errors.Is(err, securitysource.ErrInvalid):
		writeErr(w, 400, err.Error())
	default:
		log.Printf("[investigation] operation failed: %v", err)
		writeErr(w, 500, "침해 조사 기록을 처리하지 못했습니다")
	}
}
func (s *Server) listFindingInvestigations(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	out, err := pg.GetInvestigationOverview(r.Context(), id)
	if err != nil {
		investigationError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, out)
}
func validateInvestigationRequest(in investigationRequest) error {
	if in.SourceKind != "file" && in.SourceKind != "splunk" {
		return fmt.Errorf("로그 연결 방식을 선택해 주세요")
	}
	if err := investigation.ValidateScope(in.Scope, time.Now()); err != nil {
		return err
	}
	if err := investigation.ValidateMapping(in.Mapping); err != nil {
		return err
	}
	if in.ExpectedEvidenceVersion == nil || *in.ExpectedEvidenceVersion < 0 || len(in.ExpectedSourceFingerprint) != 32 {
		return fmt.Errorf("취약점 근거를 새로고침해 주세요")
	}
	if len([]rune(in.Title)) > 200 || len([]rune(in.Question)) > 4000 || strings.ContainsRune(in.Title+in.Question, 0) {
		return fmt.Errorf("제목은 200자, 조사 질문은 4000자 이내로 입력해 주세요")
	}
	if in.SourceKind == "file" {
		if in.SourceID != 0 || in.ExpectedSourceRevision != 0 || len(in.Sourcetypes) > 0 {
			return fmt.Errorf("파일 조사에는 Splunk 연결을 지정하지 않습니다")
		}
		if len([]rune(strings.TrimSpace(in.FileLabel))) < 1 || len([]rune(in.FileLabel)) > 120 || strings.ContainsRune(in.FileLabel, 0) {
			return fmt.Errorf("파일 로그 출처 이름을 1~120자로 입력해 주세요")
		}
	} else if in.SourceID <= 0 || in.ExpectedSourceRevision <= 0 || len(in.Files) > 0 {
		return fmt.Errorf("활성 Splunk 연결을 선택하고 파일은 별도로 조사해 주세요")
	}
	return nil
}
func checkInvestigationFreshness(in investigationRequest, overview *db.InvestigationOverview) bool {
	return in.ExpectedEvidenceVersion != nil && *in.ExpectedEvidenceVersion == overview.EvidenceVersion && in.ExpectedSourceFingerprint == overview.SourceFingerprint
}
func (s *Server) investigationSource(ctx context.Context, pg *db.DB, in investigationRequest) (*db.SecuritySource, error) {
	source, err := pg.GetSecuritySource(ctx, in.SourceID)
	if err != nil {
		return nil, err
	}
	if !source.Enabled || !source.CredentialSet {
		return nil, fmt.Errorf("%w: 인증 정보가 있는 활성 연결을 선택해 주세요", securitysource.ErrInvalid)
	}
	if source.Revision != in.ExpectedSourceRevision {
		return nil, db.ErrDefenseConflict
	}
	return source, nil
}
func (s *Server) previewFindingInvestigation(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	var in investigationRequest
	if !decodePurpleRequestLimit(w, r, &in, 128<<10) {
		return
	}
	if err := validateInvestigationRequest(in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	overview, err := pg.GetInvestigationOverview(r.Context(), id)
	if err != nil {
		investigationError(w, err)
		return
	}
	if !checkInvestigationFreshness(in, overview) {
		investigationError(w, db.ErrDefenseConflict)
		return
	}
	if in.SourceKind != "splunk" {
		writeErr(w, 400, "검색 미리보기는 Splunk 연결에서 사용할 수 있습니다")
		return
	}
	source, err := s.investigationSource(r.Context(), pg, in)
	if err != nil {
		investigationError(w, err)
		return
	}
	query, err := securitysource.BuildInvestigationSearch(source.Config, in.Scope, in.Mapping, in.Sourcetypes)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"query": query, "source_revision": source.Revision, "scope": in.Scope, "limits": map[string]any{"max_days": 31, "max_bytes": investigation.MaxUploadBytes, "max_response_bytes": 4 << 20, "max_rows": investigation.MaxRows, "max_events": investigation.MaxEvents}})
}
func (s *Server) runFindingInvestigation(w http.ResponseWriter, r *http.Request) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return
	}
	var in investigationRequest
	if !decodePurpleRequestLimit(w, r, &in, 32<<20) {
		return
	}
	if err := validateInvestigationRequest(in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	overview, err := pg.GetInvestigationOverview(r.Context(), id)
	if err != nil {
		investigationError(w, err)
		return
	}
	if !checkInvestigationFreshness(in, overview) {
		investigationError(w, db.ErrDefenseConflict)
		return
	}
	knownRuns, err := pg.KnownInvestigationVerifications(r.Context(), id)
	if err != nil {
		investigationError(w, err)
		return
	}
	known := make([]string, 0, len(knownRuns))
	for _, run := range knownRuns {
		known = append(known, run.ID)
	}
	title := strings.TrimSpace(in.Title)
	if title == "" {
		title = "과거 로그 침해 조사"
	}
	out := db.FindingInvestigation{Title: title, Question: in.Question, Scope: in.Scope, Mapping: in.Mapping, SourceKind: in.SourceKind, SourceID: in.SourceID, SourceRevision: in.ExpectedSourceRevision, EvidenceVersion: overview.EvidenceVersion, SourceFingerprint: overview.SourceFingerprint}
	if in.SourceKind == "file" {
		out.Collection, err = investigation.ParseFiles(in.Files, in.Scope, in.Mapping, in.CoverageConfirmed, in.TargetScopeConfirmed, known)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		out.SourceSnapshot, _ = json.Marshal(map[string]any{"kind": "file", "name": in.FileLabel})
	} else {
		source, e := s.investigationSource(r.Context(), pg, in)
		if e != nil {
			investigationError(w, e)
			return
		}
		credentials, e := s.securitySourceCredentials(source)
		if e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 75*time.Second)
		defer cancel()
		out.Collection, err = securitysource.FetchInvestigation(ctx, source.Config, credentials, in.Scope, in.Mapping, in.Sourcetypes, known)
		if err != nil {
			code := 502
			if errors.Is(err, investigation.ErrInvalid) || errors.Is(err, securitysource.ErrInvalid) {
				code = 400
			}
			writeErr(w, code, err.Error())
			return
		}
		out.SourceSnapshot, _ = json.Marshal(struct {
			*db.SecuritySource
			InvestigationSourcetypes []string `json:"investigation_sourcetypes"`
		}{source, in.Sourcetypes})
	}
	boundInvestigationMarkers(&out.Collection, knownRuns)
	out.Mapping = out.Collection.Mapping
	saved, err := pg.SaveFindingInvestigation(r.Context(), id, out)
	if err != nil {
		investigationError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, investigationPreview(saved))
}
func boundInvestigationMarkers(c *investigation.Collection, runs []db.InvestigationVerification) {
	for i := range c.Events {
		event := &c.Events[i]
		if !event.KnownARTEX {
			continue
		}
		matched := false
		for _, run := range runs {
			if strings.EqualFold(run.ID, event.VerificationID) && !event.Timestamp.Before(run.Start) && event.Timestamp.Before(run.End) {
				matched = true
				break
			}
		}
		if !matched {
			event.KnownARTEX = false
			c.Stats.KnownARTEX--
			c.Stats.UnrecognizedMarkers++
		}
	}
	if c.Stats.KnownARTEX > 0 {
		c.Warnings = append(c.Warnings, "ARTEX 구분은 같은 취약점의 등록 실행 ID와 시간 구간 일치에 근거합니다. 표식은 인증 수단이 아니므로 원본 요청·점검 일정과 대조하세요.")
	}
}
func investigationPreview(out *db.FindingInvestigation) *db.FindingInvestigation {
	// Original file contents are exported explicitly, not echoed into routine UI responses.
	copied := *out
	copied.Collection = out.Collection
	copied.Collection.Files = append([]investigation.FileEvidence{}, out.Collection.Files...)
	for i := range copied.Collection.Files {
		copied.Collection.Files[i].Content = ""
	}
	return &copied
}
func (s *Server) readInvestigation(w http.ResponseWriter, r *http.Request) (*db.FindingInvestigation, bool) {
	id, ok := purpleFindingID(w, r)
	if !ok {
		return nil, false
	}
	iid, ok := pathInt(r, "investigationID")
	if !ok || iid <= 0 {
		writeErr(w, 400, "조사 ID를 확인해 주세요")
		return nil, false
	}
	pg := s.pg(w)
	if pg == nil {
		return nil, false
	}
	out, err := pg.GetFindingInvestigation(r.Context(), id, iid)
	if err != nil {
		investigationError(w, err)
		return nil, false
	}
	return out, true
}
func (s *Server) getFindingInvestigation(w http.ResponseWriter, r *http.Request) {
	out, ok := s.readInvestigation(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, investigationPreview(out))
}
func (s *Server) exportFindingInvestigation(w http.ResponseWriter, r *http.Request) {
	out, ok := s.readInvestigation(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="finding-%d-investigation-%d.json"`, out.FindingID, out.ID))
	writeJSON(w, 200, out)
}
