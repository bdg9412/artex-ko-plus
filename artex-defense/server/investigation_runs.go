package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/artex/securitysource"
	"github.com/Autumn-27/norma/transcript"
)

func (s *Server) registerInvestigationRuns(mux *http.ServeMux) {
	const route = "/api/exploration/findings/{id}/investigations/{investigationID}/agent-runs"
	mux.HandleFunc("GET "+route, s.listInvestigationRuns)
	mux.HandleFunc("POST "+route, s.startInvestigationRun)
	mux.HandleFunc("GET "+route+"/{runID}", s.getInvestigationRun)
	mux.HandleFunc("GET "+route+"/{runID}/export", s.exportInvestigationRun)
	mux.HandleFunc("POST "+route+"/{runID}/cancel", s.cancelInvestigationRun)
}

func (s *Server) investigationRunBase(w http.ResponseWriter, r *http.Request) (*db.FindingInvestigation, bool) {
	return s.readInvestigation(w, r)
}

func (s *Server) listInvestigationRuns(w http.ResponseWriter, r *http.Request) {
	base, ok := s.investigationRunBase(w, r)
	if !ok {
		return
	}
	runs, err := s.m.pg.ListInvestigationRuns(r.Context(), base.FindingID, base.ID)
	if err != nil {
		investigationError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"runs": runs})
}

func (s *Server) readInvestigationRun(w http.ResponseWriter, r *http.Request) (*db.FindingInvestigation, *db.InvestigationRun, bool) {
	base, ok := s.investigationRunBase(w, r)
	if !ok {
		return nil, nil, false
	}
	id, ok := pathInt(r, "runID")
	if !ok || id <= 0 {
		writeErr(w, 400, "조사 실행 ID를 확인해 주세요")
		return nil, nil, false
	}
	run, err := s.m.pg.GetInvestigationRun(r.Context(), base.FindingID, id)
	if err == nil && run.InvestigationID != base.ID {
		err = db.ErrInvestigationRunNotFound
	}
	if err != nil {
		investigationError(w, err)
		return nil, nil, false
	}
	return base, run, true
}

// Ordinary polling returns selected evidence, never whole uploaded files.
func investigationRunPreview(run *db.InvestigationRun) *db.InvestigationRun {
	out := *run
	out.Events = append([]db.InvestigationRunEvent{}, run.Events...)
	for i := range out.Events {
		if out.Events[i].Kind != "evidence_collection" {
			continue
		}
		var proof investigationQueryProof
		if json.Unmarshal(out.Events[i].Payload, &proof) != nil {
			continue
		}
		for j := range proof.Collection.Files {
			proof.Collection.Files[j].Content = ""
		}
		out.Events[i].Payload, _ = json.Marshal(proof)
	}
	return &out
}

func (s *Server) getInvestigationRun(w http.ResponseWriter, r *http.Request) {
	_, run, ok := s.readInvestigationRun(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, investigationRunPreview(run))
}

func (s *Server) exportInvestigationRun(w http.ResponseWriter, r *http.Request) {
	base, run, ok := s.readInvestigationRun(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="finding-%d-investigation-agent-%d.json"`, base.FindingID, run.ID))
	writeJSON(w, 200, map[string]any{"investigation": base, "run": run})
}

func (s *Server) cancelInvestigationRun(w http.ResponseWriter, r *http.Request) {
	base, run, ok := s.readInvestigationRun(w, r)
	if !ok {
		return
	}
	s.investigationMu.Lock()
	run, err := s.m.pg.CancelInvestigationRun(r.Context(), base.FindingID, run.ID)
	// Seal the durable state before waking the worker. Otherwise its cancelled
	// progress write can fail and race to seal this run as interrupted instead.
	if err == nil {
		if cancel := s.investigationCancel[run.ID]; cancel != nil {
			cancel()
		}
	}
	s.investigationMu.Unlock()
	if err != nil {
		investigationError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, investigationRunPreview(run))
}

func (s *Server) startInvestigationRun(w http.ResponseWriter, r *http.Request) {
	base, ok := s.investigationRunBase(w, r)
	if !ok {
		return
	}
	var in struct {
		Question string `json:"question"`
	}
	if !decodePurpleRequestLimit(w, r, &in, 32<<10) {
		return
	}
	in.Question = strings.TrimSpace(in.Question)
	if utf8.RuneCountInString(in.Question) > 4000 || strings.ContainsRune(in.Question, 0) {
		writeErr(w, 400, "조사 질문은 NUL 문자 없이 4000자 이내로 입력해 주세요")
		return
	}
	if in.Question == "" {
		in.Question = base.Question
	}
	if base.State != "current" {
		investigationError(w, db.ErrDefenseConflict)
		return
	}
	s.cfgMu.Lock()
	provider, cfg, profile := s.llmProv, s.llmCfg, s.llmProf
	ready := s.llmOn && provider != nil
	s.cfgMu.Unlock()
	if !ready {
		writeErr(w, 503, "AI 조사에는 활성 LLM 연결이 필요합니다. 시스템 → LLM 설정을 확인해 주세요")
		return
	}
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	if parent.Err() != nil {
		writeErr(w, 503, "서비스가 종료 중입니다")
		return
	}
	// Resolve query scope before creating a paid model run. Credentials never
	// enter the model options, prompt, result, or exported source snapshot.
	var source *db.SecuritySource
	var sourcetypes []string
	if base.SourceKind == "splunk" {
		var err error
		source, sourcetypes, err = s.investigationRunSource(r.Context(), base)
		if err != nil {
			investigationError(w, err)
			return
		}
	}
	options, _ := json.Marshal(map[string]any{"question": in.Question, "model": cfg.Model, "profile": profile, "source_kind": base.SourceKind, "remote_enabled": source != nil, "budget": map[string]int{"max_rounds": 3, "max_model_calls": 18, "max_queries": 12, "max_remote_queries": 3, "max_tokens": 180000, "timeout_seconds": 240}})
	s.investigationMu.Lock()
	if s.investigationCancel == nil {
		s.investigationCancel = map[int64]context.CancelFunc{}
	}
	if len(s.investigationCancel) > 0 {
		// Repeated clicks on the same active run are idempotent.
		for activeID := range s.investigationCancel {
			if active, err := s.m.pg.GetInvestigationRun(r.Context(), base.FindingID, activeID); err == nil && active.InvestigationID == base.ID && (active.Status == "running" || active.Status == "queued") {
				s.investigationMu.Unlock()
				writeJSON(w, 202, investigationRunPreview(active))
				return
			}
		}
		s.investigationMu.Unlock()
		writeErr(w, 409, "다른 AI 조사가 진행 중입니다. 완료하거나 중지한 뒤 시작해 주세요")
		return
	}
	run, created, err := s.m.pg.CreateInvestigationRun(r.Context(), base.FindingID, base.ID, options)
	if err != nil {
		s.investigationMu.Unlock()
		investigationError(w, err)
		return
	}
	if created {
		// Include persistence waits in the same deadline as model and log work.
		ctx, cancel := context.WithTimeout(parent, 4*time.Minute)
		s.investigationCancel[run.ID] = cancel
		var transcripts *transcript.Store
		if s.m.dir != "" {
			transcripts = transcript.NewStore(filepath.Join(s.m.dir, "transcripts"))
		}
		opts := agent.InvestigatorOptions{Provider: provider, NonStreaming: !cfg.Stream, MaxTokens: cfg.MaxTokens, Transcript: transcripts, SessionID: fmt.Sprintf("cert-investigation-%d", run.ID), Finding: base.FindingSnapshot, Question: in.Question, Collection: base.Collection}
		if finding, e := s.m.pg.GetFinding(base.FindingID); e == nil && finding != nil && finding.TaskID != nil {
			ctx = llmrec.WithTaskID(ctx, strconv.FormatInt(*finding.TaskID, 10))
		}
		go s.executeInvestigationRun(ctx, cancel, run, base, source, sourcetypes, opts)
	}
	s.investigationMu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 202, investigationRunPreview(run))
}

func (s *Server) investigationRunSource(ctx context.Context, base *db.FindingInvestigation) (*db.SecuritySource, []string, error) {
	source, err := s.m.pg.GetSecuritySource(ctx, base.SourceID)
	if err != nil {
		return nil, nil, err
	}
	if !source.Enabled || !source.CredentialSet || source.Revision != base.SourceRevision {
		return nil, nil, db.ErrDefenseConflict
	}
	var snapshot struct {
		InvestigationSourcetypes []string `json:"investigation_sourcetypes"`
	}
	if err = json.Unmarshal(base.SourceSnapshot, &snapshot); err != nil {
		return nil, nil, err
	}
	query, err := securitysource.BuildInvestigationSearch(source.Config, base.Scope, base.Mapping, snapshot.InvestigationSourcetypes)
	if err != nil {
		return nil, nil, err
	}
	// Old default-source records are compatible. Old custom selections need a
	// new evidence collection because their authorization isn't separately stored.
	if query != base.Collection.Query {
		return nil, nil, fmt.Errorf("%w: 저장된 조회 범위가 달라졌습니다. Splunk 근거를 다시 수집해 주세요", db.ErrDefenseInvalid)
	}
	return source, snapshot.InvestigationSourcetypes, nil
}

type investigationQueryProof struct {
	Search     agent.InvestigationSearch `json:"search"`
	Collection investigation.Collection  `json:"collection"`
}

func validateInvestigationPivot(base investigation.Scope, query agent.InvestigationSearch) error {
	if err := investigation.ValidateScope(query.Scope, time.Now()); err != nil {
		return err
	}
	if query.Scope.Target != base.Target || query.Scope.Start.Before(base.Start) || query.Scope.End.After(base.End) {
		return fmt.Errorf("조사 대상 또는 시간 범위를 넓힐 수 없습니다")
	}
	if base.PathPrefix != "" && base.PathPrefix != "/" && !investigation.MatchPath(query.Scope.PathPrefix, base.PathPrefix) {
		return fmt.Errorf("조사 경로 범위를 넓힐 수 없습니다")
	}
	if !query.Remote || query.Offset != 0 {
		return fmt.Errorf("원격 조회는 첫 페이지의 범위 제한 검색만 지원합니다")
	}
	return nil
}

func (s *Server) executeInvestigationRun(ctx context.Context, cancel context.CancelFunc, run *db.InvestigationRun, base *db.FindingInvestigation, source *db.SecuritySource, sourcetypes []string, opts agent.InvestigatorOptions) {
	defer cancel()
	defer func() { s.investigationMu.Lock(); delete(s.investigationCancel, run.ID); s.investigationMu.Unlock() }()
	started, err := s.m.pg.StartInvestigationRun(ctx, run.ID)
	if err != nil {
		finishCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
		_, finishErr := s.m.pg.FinishInvestigationRun(finishCtx, run.ID, "interrupted", json.RawMessage(`{}`), "조사 실행을 시작하지 못했습니다. 다시 실행해 주세요", db.InvestigationRunUsage{})
		done()
		if finishErr != nil {
			log.Printf("[investigation] run %d start cleanup failed: %v", run.ID, finishErr)
		}
		return
	}
	if !started {
		return
	}
	var mu sync.Mutex
	var usage db.InvestigationRunUsage
	var persistErr error
	storedBytes, remoteCalls := 0, 0
	appendEvent := func(kind string, payload any) error {
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if storedBytes+len(raw) > 20<<20 {
			return fmt.Errorf("조사 증거 보존 한도에 도달했습니다")
		}
		_, err = s.m.pg.AppendInvestigationRunEvent(ctx, run.ID, kind, raw, usage)
		if err == nil {
			storedBytes += len(raw)
		}
		return err
	}
	opts.Emit = func(progress agent.InvestigatorProgress) {
		if progress.Kind == "thinking" {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if persistErr != nil {
			return
		}
		usage.Rounds = max(usage.Rounds, int64(progress.Round))
		usage.ModelCalls = max(usage.ModelCalls, int64(progress.Usage.ModelCalls))
		usage.Queries = max(usage.Queries, int64(progress.Usage.Queries))
		usage.InputTokens = max(usage.InputTokens, int64(progress.Usage.InputTokens))
		usage.OutputTokens = max(usage.OutputTokens, int64(progress.Usage.OutputTokens))
		if progress.Kind == "tool_use" {
			usage.ToolCalls++
		}
		if err := appendEvent(progress.Kind, progress); err != nil {
			persistErr = err
			cancel()
		}
	}
	if source != nil {
		opts.Search = func(queryCtx context.Context, query agent.InvestigationSearch) (investigation.Collection, error) {
			var empty investigation.Collection
			if err := queryCtx.Err(); err != nil {
				return empty, err
			}
			active, err := s.m.pg.GetInvestigationRun(queryCtx, base.FindingID, run.ID)
			if err != nil {
				return empty, err
			}
			if active.Status != "running" {
				return empty, db.ErrInvestigationRunInactive
			}
			if err := validateInvestigationPivot(base.Scope, query); err != nil {
				return empty, err
			}
			mu.Lock()
			if persistErr != nil || remoteCalls >= 3 {
				mu.Unlock()
				return empty, fmt.Errorf("Splunk 후속 조회 한도에 도달했습니다")
			}
			remoteCalls++
			mu.Unlock()
			// Re-read revision immediately before each request; revoked/changed
			// credentials or source scope stop later pivots.
			current, _, err := s.investigationRunSource(queryCtx, base)
			if err != nil {
				return empty, err
			}
			auth, err := s.securitySourceCredentials(current)
			if err != nil {
				return empty, err
			}
			runs, err := s.m.pg.KnownInvestigationVerifications(queryCtx, base.FindingID)
			if err != nil {
				return empty, err
			}
			ids := []string{}
			for _, known := range runs {
				ids = append(ids, known.ID)
			}
			collection, err := securitysource.FetchInvestigationFiltered(queryCtx, current.Config, auth, query.Scope, base.Mapping, sourcetypes, ids, securitysource.InvestigationFilters{SourceIP: query.SourceIP, User: query.User, Session: query.Session, EventKind: query.EventKind, PathContains: query.PathContains})
			if err != nil {
				return empty, err
			}
			boundInvestigationMarkers(&collection, runs)
			mu.Lock()
			defer mu.Unlock()
			if err := appendEvent("evidence_collection", investigationQueryProof{query, collection}); err != nil {
				persistErr = err
				cancel()
				return empty, err
			}
			return collection, nil
		}
	}
	report, runErr := agent.RunInvestigation(ctx, opts)
	mu.Lock()
	usage.ModelCalls = max(usage.ModelCalls, int64(report.Usage.ModelCalls))
	usage.Queries = max(usage.Queries, int64(report.Usage.Queries))
	usage.InputTokens = max(usage.InputTokens, int64(report.Usage.InputTokens))
	usage.OutputTokens = max(usage.OutputTokens, int64(report.Usage.OutputTokens))
	// Progress and evidence are already persisted once in ordered events.
	report.Trace = nil
	report.Collections = nil
	message := ""
	if persistErr != nil && !errors.Is(persistErr, db.ErrInvestigationRunInactive) {
		report.Status = "interrupted"
		message = "조사 과정 저장에 실패하여 추가 조회와 모델 호출을 중단했습니다"
	} else if runErr != nil && report.Status == "model_error" {
		message = "LLM 호출을 완료하지 못했습니다. 저장된 진행 과정과 LLM 연결·한도를 확인해 주세요"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		report.Status = "budget_exhausted"
		message = "조사 제한시간에 도달했습니다. 그전에 저장된 진행 과정과 근거를 확인하세요"
	}
	if s.ctx != nil && s.ctx.Err() != nil {
		report.Status = "interrupted"
		message = "서비스 종료로 조사가 중단되었습니다. 저장된 근거를 확인한 뒤 새 실행을 시작하세요"
	}
	raw, err := json.Marshal(report)
	if err != nil {
		raw = json.RawMessage(`{}`)
		report.Status = "interrupted"
		message = "조사 결과를 직렬화하지 못했습니다"
	}
	finishCtx, done := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = s.m.pg.FinishInvestigationRun(finishCtx, run.ID, report.Status, raw, message, usage)
	if err != nil { // Preserve a terminal state even when the final report is too large.
		_, err = s.m.pg.FinishInvestigationRun(finishCtx, run.ID, "interrupted", json.RawMessage(`{"summary":"결과 저장 한도에 도달했습니다. 보존된 조사 과정과 근거를 확인하세요."}`), "최종 결과 저장 한도", usage)
	}
	done()
	mu.Unlock()
	if err != nil {
		log.Printf("[investigation] run %d finish failed: %v", run.ID, err)
	}
}
