package server

import (
	"fmt"
	"net/http"

	"github.com/Autumn-27/artex/db"
)

type taskLLMResolution struct {
	ProfileID *int64 `json:"profile_id,omitempty"`
	Name      string `json:"name"`
	Format    string `json:"format"`
	Model     string `json:"model"`
	Source    string `json:"source"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// 사용자 노출 사유·소스 이름(GET /api/tasks/{id}/llm/resolution 응답). 작업 LLM 설정 체인·
// system/llm 화면에 그대로 렌더되므로 ko.json 의 taskDetail.llm 네임스페이스 표기(설정·전역·
// 할당량·설정 체인)에 맞춘다. Source enum 값과 영어 오류 문구는 번역 대상이 아니다.
const (
	reasonLLMProfileMissing     = "LLM 설정을 찾을 수 없습니다"
	reasonLLMProfileNoAPIKey    = "LLM 설정에 API Key 가 지정되지 않았습니다"
	reasonLLMProfileInvalid     = "LLM 설정 형식 또는 매개변수가 올바르지 않습니다"
	reasonTaskLLMChainExhausted = "작업 LLM 설정 체인의 할당량을 모두 소진했습니다"
	reasonNoLLMAvailable        = "사용 가능한 LLM 설정이 없습니다"
	sourceNameGlobalConfig      = "전역 설정"
)

func (s *Server) resolutionFromProfile(p *db.LLMProfile, source string) taskLLMResolution {
	if p == nil {
		return taskLLMResolution{Source: source, Reason: reasonLLMProfileMissing}
	}
	id := p.ID
	result := taskLLMResolution{
		ProfileID: &id,
		Name:      p.Name,
		Format:    p.Format,
		Model:     p.Model,
		Source:    source,
	}
	if p.APIKey == "" {
		result.Reason = reasonLLMProfileNoAPIKey
		return result
	}
	if _, _, ok := s.providerForProfile(p.ID); !ok {
		result.Reason = reasonLLMProfileInvalid
		return result
	}
	result.Available = true
	return result
}

// resolveTaskRoleLLM mirrors taskLLMRuntime.current without creating a provider:
// role Agent binding -> explicit task chain -> active/global environment config.
// Database failures are returned rather than represented as an unavailable model.
func (s *Server) resolveTaskRoleLLM(t *Task, agentKey string) (taskLLMResolution, error) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return taskLLMResolution{}, fmt.Errorf("database unavailable")
	}
	a, err := s.m.pg.GetAgentByKey(agentKey)
	if err != nil {
		return taskLLMResolution{}, fmt.Errorf("load agent %q: %w", agentKey, err)
	}
	if a != nil && a.LLMProfileID != nil {
		p, err := s.m.pg.ProfileByID(*a.LLMProfileID)
		if err != nil {
			return taskLLMResolution{}, fmt.Errorf("load agent LLM profile: %w", err)
		}
		if p != nil {
			resolved := s.resolutionFromProfile(p, "agent_binding")
			if resolved.Available {
				return resolved, nil
			}
		}
	}
	state := t.llmStateSnapshot()
	if len(state.ProfileIDs) > 0 {
		if state.ActiveID == nil {
			return taskLLMResolution{Source: "task_chain", Reason: reasonTaskLLMChainExhausted}, nil
		}
		p, err := s.m.pg.ProfileByID(*state.ActiveID)
		if err != nil {
			return taskLLMResolution{}, fmt.Errorf("load task LLM profile: %w", err)
		}
		return s.resolutionFromProfile(p, "task_chain"), nil
	}
	p, err := s.m.pg.ActiveProfile()
	if err != nil {
		return taskLLMResolution{}, fmt.Errorf("load global LLM profile: %w", err)
	}
	if p != nil {
		resolved := s.resolutionFromProfile(p, "global_profile")
		if resolved.Available {
			return resolved, nil
		}
	}
	s.cfgMu.Lock()
	on, name, cfg := s.llmOn, s.llmProf, s.llmCfg
	s.cfgMu.Unlock()
	if on {
		if name == "" {
			name = sourceNameGlobalConfig
		}
		return taskLLMResolution{
			Name: name, Format: cfg.Provider(), Model: cfg.Model,
			Source: "environment", Available: true,
		}, nil
	}
	return taskLLMResolution{Source: "global", Reason: reasonNoLLMAvailable}, nil
}

func (s *Server) taskLLMResolutionHandler(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	roles := map[string]taskLLMResolution{}
	for responseKey, agentKey := range map[string]string{
		"mainagent": "mainagent",
		"planner":   "planner",
		"worker":    "worker",
	} {
		resolved, err := s.resolveTaskRoleLLM(t, agentKey)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		roles[responseKey] = resolved
	}
	writeJSON(w, http.StatusOK, roles)
}
