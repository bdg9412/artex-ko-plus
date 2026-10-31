package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/hunting"
	"github.com/Autumn-27/artex/investigation"
	"github.com/Autumn-27/artex/securitysource"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

type huntRequest struct {
	hunting.Request
	ScopeConfirmed bool `json:"scope_confirmed"`
}

func (s *Server) registerHunts(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/defensive/hunts/trends", s.listHuntTrends)
	mux.HandleFunc("POST /api/defensive/hunts/trends/collect", s.collectHuntTrends)
	mux.HandleFunc("GET /api/defensive/hunts", s.listHunts)
	mux.HandleFunc("POST /api/defensive/hunts", s.createHunt)
	mux.HandleFunc("GET /api/defensive/hunts/{id}", s.getHunt)
	mux.HandleFunc("GET /api/defensive/hunts/{id}/export", s.exportHunt)
	mux.HandleFunc("POST /api/defensive/hunts/{id}/cancel", s.cancelHunt)
}
func huntError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrHuntNotFound):
		writeErr(w, 404, err.Error())
	case errors.Is(err, db.ErrHuntActive), errors.Is(err, db.ErrHuntInactive), errors.Is(err, db.ErrDefenseConflict):
		writeErr(w, 409, err.Error())
	default:
		writeErr(w, 400, "헌팅 입력·로그 연결·허용 범위를 확인해 주세요")
	}
}
func huntID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "헌팅 ID가 올바르지 않습니다")
		return 0, false
	}
	return id, true
}
func (s *Server) listHunts(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	out, err := pg.ListHunts(r.Context())
	if err != nil {
		writeErr(w, 500, "헌팅 목록을 읽지 못했습니다")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"hunts": out})
}
func (s *Server) readHunt(w http.ResponseWriter, r *http.Request) (*db.Hunt, bool) {
	id, ok := huntID(w, r)
	if !ok {
		return nil, false
	}
	pg := s.pg(w)
	if pg == nil {
		return nil, false
	}
	h, err := pg.GetHunt(r.Context(), id)
	if err != nil {
		huntError(w, err)
		return nil, false
	}
	w.Header().Set("Cache-Control", "no-store")
	return h, true
}

// Polling retains bounded raw excerpts; export includes original source bytes.
func huntPreview(h *db.Hunt) *db.Hunt {
	out := *h
	var result hunting.Result
	if json.Unmarshal(h.Result, &result) == nil && result.EngineVersion != "" {
		for i := range result.Investigation.Collections {
			for j := range result.Investigation.Collections[i].Files {
				result.Investigation.Collections[i].Files[j].Content = ""
			}
			for j := range result.Investigation.Collections[i].Events {
				result.Investigation.Collections[i].Events[j].Raw = huntRawExcerpt(result.Investigation.Collections[i].Events[j].Raw)
			}
		}
		result.Events = nil
		out.Result, _ = json.Marshal(result)
	}
	out.Events = make([]db.HuntEvent, len(h.Events))
	for i, e := range h.Events {
		out.Events[i] = e
		if e.Kind == "evidence_collection" {
			var proof investigationQueryProof
			if json.Unmarshal(e.Payload, &proof) == nil {
				for j := range proof.Collection.Files {
					proof.Collection.Files[j].Content = ""
				}
				for j := range proof.Collection.Events {
					proof.Collection.Events[j].Raw = huntRawExcerpt(proof.Collection.Events[j].Raw)
				}
				out.Events[i].Payload, _ = json.Marshal(proof)
			}
		}
	}
	return &out
}
func huntRawExcerpt(raw string) string {
	return huntTextBytes(raw, 4096)
}
func huntTextBytes(raw string, limit int) string {
	if len(raw) <= limit {
		return raw
	}
	end := limit
	for end > 0 && !utf8.RuneStart(raw[end]) {
		end--
	}
	return raw[:end]
}
func (s *Server) getHunt(w http.ResponseWriter, r *http.Request) {
	h, ok := s.readHunt(w, r)
	if ok {
		writeJSON(w, 200, huntPreview(h))
	}
}
func (s *Server) exportHunt(w http.ResponseWriter, r *http.Request) {
	h, ok := s.readHunt(w, r)
	if ok {
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="defensive-hunt-%d.json"`, h.ID))
		writeJSON(w, 200, h)
	}
}
func (s *Server) cancelHunt(w http.ResponseWriter, r *http.Request) {
	id, ok := huntID(w, r)
	if !ok {
		return
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	h, err := pg.CancelHunt(r.Context(), id)
	if err != nil {
		huntError(w, err)
		return
	}
	s.huntMu.Lock()
	cancel := s.huntCancel[id]
	s.huntMu.Unlock()
	if cancel != nil {
		cancel()
	}
	writeJSON(w, 200, huntPreview(h))
}

// Re-check the immutable source revision and explicit stream pairs before every
// query. A saved connection is not itself authorization to query every asset.
func (s *Server) huntSource(ctx context.Context, in hunting.Request) (*db.SecuritySource, error) {
	source, err := s.m.pg.GetSecuritySource(ctx, in.SourceID)
	if err != nil {
		return nil, err
	}
	if !source.Enabled || !source.CredentialSet || source.Revision != in.ExpectedSourceRevision {
		return nil, db.ErrDefenseConflict
	}
	if len(in.Sourcetypes) > 8 {
		return nil, hunting.ErrInvalid
	}
	allowed := map[string]bool{}
	for _, stream := range securitysource.EffectiveStreams(source.Config) {
		allowed[stream.Sourcetype] = true
	}
	seen := map[string]bool{}
	for _, st := range in.Sourcetypes {
		if !allowed[st] || seen[st] {
			return nil, hunting.ErrInvalid
		}
		seen[st] = true
	}
	if _, err = securitysource.BuildInvestigationSearch(source.Config, in.Scope, in.Mapping, in.Sourcetypes); err != nil {
		return nil, err
	}
	return source, nil
}
func (s *Server) createHunt(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var in huntRequest
	if !decodePurpleRequestLimit(w, r, &in, 64<<10) {
		return
	}
	in.Term = strings.TrimSpace(in.Term)
	if !in.ScopeConfirmed || in.SourceID <= 0 || in.ExpectedSourceRevision <= 0 || len([]rune(in.Term)) < 2 || len([]rune(in.Term)) > 200 || strings.ContainsAny(in.Term, "\x00\r\n") {
		writeErr(w, 400, "취약점과 허용한 로그 조회 범위를 확인해 주세요")
		return
	}
	if len(in.ResearchURLs) > 8 {
		writeErr(w, 400, "리서치 출처는 최대 8개입니다")
		return
	}
	if in.Mapping == (investigation.Mapping{}) {
		in.Mapping = investigation.DefaultMapping()
	}
	if normalized, err := hunting.NormalizeRequest(in.Request); err != nil {
		huntError(w, err)
		return
	} else {
		in.Request = normalized
	}
	source, sourceErr := s.huntSource(r.Context(), in.Request)
	if sourceErr != nil {
		huntError(w, sourceErr)
		return
	}
	s.cfgMu.Lock()
	provider, cfg := s.llmProv, s.llmCfg
	ready := s.llmOn && provider != nil
	s.cfgMu.Unlock()
	if !ready {
		writeErr(w, 503, "자율 헌팅에는 활성 LLM 연결이 필요합니다")
		return
	}
	on, _, _, _, _ := s.m.WebSearch()
	if !on && len(in.ResearchURLs) == 0 {
		writeErr(w, 400, "웹 검색을 켜거나 공개 리서치 출처 URL을 입력해 주세요")
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
	// Keep selected stream identity even if the saved connection later changes.
	// Credentials and provider endpoints never enter this immutable snapshot.
	document, _ := json.Marshal(in)
	var contract map[string]any
	_ = json.Unmarshal(document, &contract)
	streams := []securitysource.LogStream{}
	for _, stream := range securitysource.EffectiveStreams(source.Config) {
		if len(in.Sourcetypes) == 0 {
			streams = append(streams, stream)
			continue
		}
		for _, selected := range in.Sourcetypes {
			if stream.Sourcetype == selected {
				streams = append(streams, stream)
			}
		}
	}
	contract["source_snapshot"] = map[string]any{"id": strconv.FormatInt(source.ID, 10), "name": source.Name, "revision": source.Revision, "streams": streams}
	contract["budget"] = map[string]int{"timeout_seconds": int(hunting.RunTimeout.Seconds()), "stage_timeout_seconds": huntStageTimeoutSeconds, "max_model_calls": huntProviderMaxCalls, "max_reserved_bytes": huntProviderReservedBytes, "max_remote_queries": 6, "max_queries": 12, "max_research_queries": 3}
	raw, _ := json.Marshal(contract)
	s.huntMu.Lock()
	defer s.huntMu.Unlock()
	h, created, err := pg.CreateHunt(r.Context(), raw)
	if err != nil {
		huntError(w, err)
		return
	}
	if created {
		ctx, cancel := context.WithTimeout(parent, hunting.RunTimeout)
		if s.huntCancel == nil {
			s.huntCancel = map[int64]context.CancelFunc{}
		}
		s.huntCancel[h.ID] = cancel
		go s.executeHunt(ctx, cancel, h, in.Request, provider, cfg)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 202, huntPreview(h))
}
func (s *Server) huntResearcher() hunting.Researcher {
	if s.huntResearch != nil {
		return *s.huntResearch
	}
	on, backend, brave, tavily, proxy := s.m.WebSearch()
	r := hunting.Researcher{}
	if on {
		cfg := actool.WebSearchConfig{Backend: backend, BraveAPIKey: brave, TavilyAPIKey: tavily, Proxy: proxy}
		if backend == deepSeekWebSearchBackend {
			cfg.DeepSeekBaseURL, cfg.DeepSeekAPIKey, cfg.DeepSeekModel = s.m.deepSeekSearchCreds()
		}
		r.Search = func(ctx context.Context, q string) ([]string, error) {
			results, err := actool.WebSearchProbe(ctx, cfg, q, 4)
			if err != nil {
				return nil, errors.New("웹 검색을 완료하지 못했습니다")
			}
			urls := []string{}
			for _, result := range results {
				urls = append(urls, result.URL)
			}
			return urls, nil
		}
	}
	return r
}
func (s *Server) executeHunt(ctx context.Context, cancel context.CancelFunc, h *db.Hunt, in hunting.Request, base llm.Provider, cfg agent.Config) {
	defer cancel()
	defer func() { s.huntMu.Lock(); delete(s.huntCancel, h.ID); s.huntMu.Unlock() }()
	started, err := s.m.pg.StartHunt(ctx, h.ID)
	if err != nil || !started {
		if err != nil {
			s.finishHunt(h.ID, "interrupted", hunting.Result{}, "헌팅 실행을 시작하지 못했습니다")
		}
		return
	}
	provider := &huntProvider{base: base}
	var persistErr error
	emit := func(e hunting.Event) error {
		if persistErr != nil {
			return persistErr
		}
		payload, _ := json.Marshal(e)
		if e.Kind == "evidence_collection" && len(e.Payload) > 0 {
			payload = e.Payload
		}
		persistErr = s.m.pg.AppendHuntEvent(ctx, h.ID, e.Kind, payload)
		if persistErr != nil {
			cancel()
		}
		return persistErr
	}
	researcher := s.huntResearcher()
	deps := hunting.Dependencies{Research: researcher.Run, Design: func(ctx context.Context, r hunting.Request, research hunting.Research) (hunting.Design, error) {
		return generateHuntDesign(ctx, provider, r, research)
	}, Investigate: func(ctx context.Context, r hunting.Request, d hunting.Design, emit func(hunting.Event) error) (hunting.InvestigationResult, error) {
		return s.investigateHunt(ctx, h.ID, r, d, provider, cfg, emit)
	}, Emit: emit}
	result, runErr := hunting.Run(ctx, in, deps)
	result.Investigation.Usage.ModelCalls, result.Investigation.Usage.InputTokens, result.Investigation.Usage.OutputTokens = provider.snapshot()
	var serviceErr error
	if s.ctx != nil {
		serviceErr = s.ctx.Err()
	}
	message := huntExecutionFailure(&result, runErr, persistErr, provider.exhausted(), ctx.Err(), serviceErr)
	s.finishHunt(h.ID, result.Status, result, message)
}

// Keep the existing persistence/budget/shutdown precedence while making a
// provider failure distinguishable from invalid research or scenario output.
func huntExecutionFailure(result *hunting.Result, runErr, persistErr error, exhausted bool, runContextErr, serviceErr error) string {
	message := ""
	if runErr != nil {
		message = "헌팅을 완료하지 못했습니다. 보존된 조사 단계와 근거를 확인해 주세요"
	}
	var providerErr *huntProviderCallError
	modelFailure := runContextErr == nil && errors.As(runErr, &providerErr)
	if modelFailure {
		result.Status = "model_error"
		message = providerErr.Error()
	}
	if persistErr != nil {
		result.Status = "interrupted"
		message = "근거 저장에 실패하여 추가 실행을 중단했습니다"
	}
	if exhausted {
		result.Status = "budget_exhausted"
		message = "누적 모델 호출·토큰 한도에 도달했습니다"
	}
	if errors.Is(runContextErr, context.DeadlineExceeded) {
		result.Status = "budget_exhausted"
		message = "헌팅 제한시간에 도달했습니다"
	}
	if serviceErr != nil {
		result.Status = "interrupted"
		message = "서비스 종료로 헌팅이 중단되었습니다"
	}
	if modelFailure {
		result.Error = message
	}
	return message
}
func (s *Server) finishHunt(id int64, status string, result hunting.Result, message string) {
	result.Events = nil // already persisted as ordered events, including raw receipts
	raw, err := json.Marshal(result)
	if err != nil {
		raw = json.RawMessage(`{}`)
		status = "interrupted"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err = s.m.pg.FinishHunt(ctx, id, status, raw, message); err != nil {
		_, err = s.m.pg.FinishHunt(ctx, id, "interrupted", json.RawMessage(`{}`), "결과 저장 한도에 도달했습니다. 보존된 이벤트를 확인하세요")
	}
	if err != nil {
		log.Printf("[hunting] %d terminal persistence failed", id)
	}
}
