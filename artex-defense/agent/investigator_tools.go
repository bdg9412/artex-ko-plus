package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/investigation"
	actool "github.com/Autumn-27/norma/tool"
)

type investigatorPlanInput struct {
	Action       string   `json:"action"`
	Reason       string   `json:"reason"`
	Hypothesis   string   `json:"hypothesis"`
	Objective    string   `json:"objective"`
	EvidenceRefs []string `json:"evidence_refs"`
	NeededLogs   []string `json:"needed_logs"`
	NextSteps    []string `json:"next_steps"`
}

func certDecode(in json.RawMessage, out any) error {
	if len(in) > 16000 {
		return investigation.ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(in))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return investigation.ErrInvalid
	}
	return nil
}
func certArray(desc string) map[string]any {
	return map[string]any{"type": "array", "description": desc, "items": map[string]any{"type": "string"}}
}
func certObject(props map[string]any, required ...string) map[string]any {
	return map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
}
func (r *investigatorRun) validateRefs(refs []string, require bool) error {
	if (require && len(refs) == 0) || len(refs) > 10 {
		return fmt.Errorf("1~10개의 실제 근거 ref가 필요합니다")
	}
	for _, ref := range refs {
		if !r.seen[ref] {
			return fmt.Errorf("이번 실행에서 읽지 않은 근거 ref입니다")
		}
	}
	return nil
}

func (r *investigatorRun) planTool() actool.CoreTool {
	return writeTool("plan_investigation", "조사 가설과 다음 작업 하나를 결정하거나 증거 부족·조사 완료로 중단합니다. 근거가 바뀌면 재계획하고 기존 작업은 반복하지 마세요.", certObject(map[string]any{
		"action": map[string]any{"type": "string", "enum": []string{"investigate", "complete", "insufficient_data"}}, "reason": str("현재 증거로 이 결정을 내린 이유"), "hypothesis": str("아직 확인되지 않은 조건부 가설"), "objective": str("작업자가 로그로 확인할 구체적인 행동"), "evidence_refs": certArray("이미 확인한 원본 근거 ref; 첫 계획에는 비워두세요"), "needed_logs": certArray("부족한 로그와 필요한 필드"), "next_steps": certArray("남은 조사 및 탐지 개선 제안"),
	}, "action", "reason"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if err := ctx.Err(); err != nil {
			return actool.Errorf("조사가 종료되었습니다"), nil
		}
		var a investigatorPlanInput
		if err := certDecode(in, &a); err != nil {
			return actool.Errorf("계획 입력 형식이 올바르지 않습니다"), nil
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.decision != nil {
			return actool.Errorf("이번 회차의 계획은 이미 제출되었습니다. 새 계획은 다음 회차에서 제출하세요"), nil
		}
		if a.Action != "investigate" && a.Action != "complete" && a.Action != "insufficient_data" {
			return actool.Errorf("지원하지 않는 계획 상태입니다"), nil
		}
		if strings.TrimSpace(a.Reason) == "" || len(a.Reason) > 1600 || len(a.Hypothesis) > 1200 || len(a.Objective) > 1200 || certStrings(a.NeededLogs, 8, 500) != nil || certStrings(a.NextSteps, 8, 500) != nil {
			return actool.Errorf("계획 내용이 비어 있거나 한도를 초과했습니다"), nil
		}
		if err := r.validateRefs(a.EvidenceRefs, false); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if a.Action == "investigate" {
			if strings.TrimSpace(a.Hypothesis) == "" || strings.TrimSpace(a.Objective) == "" {
				return actool.Errorf("가설과 구체적 조사 작업이 필요합니다"), nil
			}
			for _, intent := range r.report.Intents {
				if strings.EqualFold(strings.TrimSpace(intent.Objective), strings.TrimSpace(a.Objective)) {
					return actool.Errorf("이미 실행한 작업입니다. 새 증거를 따라가거나 필요한 로그를 남기고 중단하세요"), nil
				}
			}
		}
		if a.Action == "complete" && (len(r.report.Intents) == 0 || len(r.report.Observations) == 0) {
			return actool.Errorf("로그를 조사하기 전에는 완료할 수 없습니다. 조사하거나 자료 부족으로 중단하세요"), nil
		}
		r.decision = &a
		d := InvestigatorDecision{Round: r.round, Action: a.Action, Reason: a.Reason, EvidenceRefs: a.EvidenceRefs}
		r.report.Decisions = append(r.report.Decisions, d)
		r.report.Gaps = append(r.report.Gaps, a.NeededLogs...)
		r.report.NextSteps = append(r.report.NextSteps, a.NextSteps...)
		r.emitLocked(InvestigatorProgress{Kind: "decision", Summary: a.Reason, Decision: &d, EvidenceRefs: a.EvidenceRefs})
		return jsonResult(map[string]any{"saved": true, "action": a.Action, "instruction": "이번 회차의 계획이 저장되었습니다. 간단히 종료하세요. 호스트가 작업자를 실행합니다."})
	})
}

// ValidateInvestigationSearch is shared with callers for defense in depth. No
// wildcard target, widened time window, or escape from the original path is
// possible through the typed query tool.
func ValidateInvestigationSearch(base investigation.Scope, q InvestigationSearch) error {
	if err := investigation.ValidateScope(q.Scope, time.Now()); err != nil {
		return err
	}
	if !strings.EqualFold(q.Scope.Target, base.Target) || q.Scope.Start.Before(base.Start) || q.Scope.End.After(base.End) || !q.Scope.Start.Before(q.Scope.End) {
		return fmt.Errorf("조회는 최초 대상과 시간 범위를 벗어날 수 없습니다")
	}
	if base.PathPrefix != "" && (q.Scope.PathPrefix == "" || !investigation.MatchPath(q.Scope.PathPrefix, base.PathPrefix)) {
		return fmt.Errorf("조회 경로는 최초 경로 범위 안에 있어야 합니다")
	}
	if q.Offset < 0 || q.Offset > investigation.MaxEvents || q.Remote && q.Offset != 0 {
		return investigation.ErrInvalid
	}
	for _, s := range []string{q.SourceIP, q.User, q.Session, q.EventKind, q.PathContains} {
		if len(s) > 256 || !utf8.ValidString(s) || strings.ContainsAny(s, "\r\n\x00") {
			return investigation.ErrInvalid
		}
	}
	return nil
}

func (r *investigatorRun) searchTool() actool.CoreTool {
	scopeSchema := certObject(map[string]any{"target": str("최초 대상 유지"), "path_prefix": str("최초 범위 안의 경로 접두어"), "start": str("RFC3339; 최초 시작 이후"), "end": str("RFC3339; 최초 종료 이전")})
	return readTool("search_evidence", "구조화된 조건으로 로그를 조회합니다. 기본은 수집된 파일/로그에서 검색합니다. remote=true일 때만 연결된 Splunk에 읽기 전용 추가 조회합니다. 결과는 20개씩, 원문은 read_evidence로 확인하세요. 같은 조건 반복 대신 offset으로 다음 페이지를 요청하세요.", certObject(map[string]any{
		"scope": scopeSchema, "source_ip": str("정확히 일치하는 출발 IP"), "user": str("정확히 일치하는 계정"), "session": str("정확히 일치하는 세션"), "event_kind": str("정확히 일치하는 이벤트 종류"), "path_contains": str("경로에 포함될 리터럴 문자열"), "remote": map[string]any{"type": "boolean"}, "offset": map[string]any{"type": "integer", "minimum": 0},
	}), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		var q InvestigationSearch
		if err := certDecode(in, &q); err != nil {
			return actool.Errorf("조회 입력 형식이 올바르지 않습니다"), nil
		}
		base := r.report.Scope
		if q.Scope.Target == "" {
			q.Scope.Target = base.Target
		}
		if q.Scope.Start.IsZero() {
			q.Scope.Start = base.Start
		}
		if q.Scope.End.IsZero() {
			q.Scope.End = base.End
		}
		if q.Scope.PathPrefix == "" {
			q.Scope.PathPrefix = base.PathPrefix
		}
		if err := ValidateInvestigationSearch(base, q); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if err := ctx.Err(); err != nil {
			return actool.Errorf("조사가 종료되었습니다"), nil
		}
		r.mu.Lock()
		key, _ := json.Marshal(q)
		if r.queryKeys[string(key)] {
			r.mu.Unlock()
			return actool.Errorf("동일한 조회는 이미 수행했습니다. 기존 근거나 다음 페이지를 확인하세요"), nil
		}
		if q.Remote && (r.opts.Search == nil || r.remoteQueries >= 3) {
			r.mu.Unlock()
			return actool.Errorf("Splunk 추가 조회를 사용할 수 없거나 3회 한도를 소진했습니다. 필요한 로그를 기록하세요"), nil
		}
		if err := r.provider.query(); err != nil {
			r.mu.Unlock()
			return actool.Errorf(err.Error()), nil
		}
		r.queryKeys[string(key)] = true
		r.report.Searches = append(r.report.Searches, q)
		if q.Remote {
			r.remoteQueries++
		}
		r.mu.Unlock()
		var selected []investigation.Event
		if q.Remote {
			c, err := r.opts.Search(ctx, q)
			if err != nil {
				return actool.Errorf("Splunk 조회에 실패했습니다. 연결 상태·로그 필드·허용 범위를 확인하세요"), nil
			}
			body, err := json.Marshal(c)
			r.mu.Lock()
			defer r.mu.Unlock()
			if err != nil || len(c.Events) > investigation.MaxEvents || len(body)+r.evidenceBytes > 24<<20 {
				return actool.Errorf("추가 증거 저장 한도를 초과했습니다. 더 좁은 범위가 필요합니다"), nil
			}
			if err := ValidateInvestigationSearch(q.Scope, InvestigationSearch{Scope: c.Scope}); err != nil {
				return actool.Errorf("조회 응답이 요청 범위를 벗어났습니다"), nil
			}
			for _, e := range c.Events {
				if e.Ref == "" || !r.inScope(e, q.Scope) {
					continue
				}
				if old, ok := r.events[e.Ref]; ok && (old.Raw != e.Raw || old.FileName != e.FileName || old.Line != e.Line) {
					return actool.Errorf("추가 증거의 근거 식별자가 기존 증거와 충돌합니다"), nil
				}
			}
			r.report.Collections = append(r.report.Collections, c)
			r.evidenceBytes += len(body)
			r.report.Gaps = append(r.report.Gaps, c.Warnings...)
			if !c.Complete {
				r.report.Gaps = append(r.report.Gaps, "추가 Splunk 조회 결과에 수집 범위 또는 절단 경고가 있습니다.")
			}
			for _, e := range c.Events {
				if e.Ref != "" && r.inScope(e, q.Scope) {
					r.events[e.Ref] = e
					if certMatch(e, q) {
						selected = append(selected, e)
					}
				}
			}
			return r.searchResultLocked(q, selected)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, e := range r.events {
			if r.inScope(e, q.Scope) && certMatch(e, q) {
				selected = append(selected, e)
			}
		}
		return r.searchResultLocked(q, selected)
	})
}

func certMatch(e investigation.Event, q InvestigationSearch) bool {
	return (q.SourceIP == "" || e.SourceIP == q.SourceIP) && (q.User == "" || e.User == q.User) && (q.Session == "" || e.Session == q.Session) && (q.EventKind == "" || e.EventKind == q.EventKind) && (q.PathContains == "" || strings.Contains(e.Path, q.PathContains))
}
func (r *investigatorRun) searchResultLocked(q InvestigationSearch, selected []investigation.Event) (actool.Result, error) {
	sort.Slice(selected, func(i, j int) bool {
		if selected[i].Timestamp.Equal(selected[j].Timestamp) {
			return selected[i].Ref < selected[j].Ref
		}
		return selected[i].Timestamp.Before(selected[j].Timestamp)
	})
	total := len(selected)
	start := min(q.Offset, total)
	end := min(start+20, total)
	rows := make([]investigation.Event, 0, end-start)
	refs := make([]string, 0, end-start)
	for _, e := range selected[start:end] {
		r.seen[e.Ref] = true
		refs = append(refs, e.Ref)
		e.Raw = ""
		e.Path = certClip(e.Path, 400)
		e.User = certClip(e.User, 160)
		e.Session = certClip(e.Session, 160)
		e.Action = certClip(e.Action, 160)
		rows = append(rows, e)
	}
	r.emitLocked(InvestigatorProgress{Kind: "query", Summary: fmt.Sprintf("조회 결과 %d개 중 %d개를 확인했습니다.", total, len(rows)), EvidenceRefs: refs})
	return jsonResult(map[string]any{"events": rows, "total_matches": total, "next_offset": end, "has_more": end < total, "scope": q.Scope, "warning": "조회한 증거의 일부분입니다. 관측 없음은 침해 없음이 아닙니다. raw는 read_evidence로 확인하세요."})
}

func (r *investigatorRun) readTool() actool.CoreTool {
	return readTool("read_evidence", "원본 근거 최대 5개를 확인합니다. ref는 search_evidence에서 제공된 실제 식별자여야 합니다. 원문이 길면 4096바이트까지만 표시하며 전체 원문은 로컬 증거에 보존됩니다.", certObject(map[string]any{"refs": certArray("확인할 근거 ref 목록")}, "refs"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if ctx.Err() != nil {
			return actool.Errorf("조사가 종료되었습니다"), nil
		}
		var a struct {
			Refs []string `json:"refs"`
		}
		if certDecode(in, &a) != nil || len(a.Refs) == 0 || len(a.Refs) > 5 {
			return actool.Errorf("1~5개의 ref가 필요합니다"), nil
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if err := r.validateRefs(a.Refs, true); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		rows := make([]map[string]any, 0, len(a.Refs))
		for _, ref := range a.Refs {
			e := r.events[ref]
			r.rawSeen[ref] = true
			rows = append(rows, map[string]any{"ref": ref, "file_name": e.FileName, "line": e.Line, "known_artex": e.KnownARTEX, "raw_excerpt": certClip(e.Raw, 4096), "raw_truncated": len(e.Raw) > 4096, "timestamp": e.Timestamp})
		}
		return jsonResult(rows)
	})
}

func (r *investigatorRun) observationTool() actool.CoreTool {
	return writeTool("record_observation", "AI 관측·추론·자료 부족을 기록합니다. observed는 직접 로그 행동에만 사용하고 실제 원문을 먼저 읽으세요. inferred는 정상 대안과 검증 방법이 필요합니다. 존재하지 않거나 이번 실행에서 읽지 않은 근거를 인용할 수 없습니다.", certObject(map[string]any{"kind": map[string]any{"type": "string", "enum": []string{"observed", "inferred", "insufficient_data"}}, "summary": str("근거가 직접 말하는 내용과 해석 범위"), "evidence_refs": certArray("실제로 확인한 이벤트 ref"), "alternatives": certArray("정상 행위·다른 해석 및 반증 가능성"), "next_steps": certArray("부족한 로그 및 다음 조사·탐지 개선")}, "kind", "summary"), func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if ctx.Err() != nil {
			return actool.Errorf("조사가 종료되었습니다"), nil
		}
		var a struct {
			Kind         string   `json:"kind"`
			Summary      string   `json:"summary"`
			EvidenceRefs []string `json:"evidence_refs"`
			Alternatives []string `json:"alternatives"`
			NextSteps    []string `json:"next_steps"`
		}
		if certDecode(in, &a) != nil {
			return actool.Errorf("관측 입력 형식이 올바르지 않습니다"), nil
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if len(r.report.Observations) >= 24 {
			return actool.Errorf("관측 기록 한도에 도달했습니다"), nil
		}
		if a.Kind != "observed" && a.Kind != "inferred" && a.Kind != "insufficient_data" {
			return actool.Errorf("지원하지 않는 관측 유형입니다"), nil
		}
		if strings.TrimSpace(a.Summary) == "" || len(a.Summary) > 1600 || certStrings(a.Alternatives, 6, 500) != nil || certStrings(a.NextSteps, 6, 500) != nil {
			return actool.Errorf("관측 내용이 비어 있거나 한도를 초과했습니다"), nil
		}
		if err := r.validateRefs(a.EvidenceRefs, a.Kind != "insufficient_data"); err != nil {
			return actool.Errorf(err.Error()), nil
		}
		if a.Kind == "inferred" && len(a.Alternatives) == 0 {
			return actool.Errorf("추론에는 정상 대안이나 다른 해석을 남겨야 합니다"), nil
		}
		if a.Kind == "insufficient_data" && len(a.NextSteps) == 0 {
			return actool.Errorf("자료 부족에는 필요한 로그 또는 다음 조사 항목을 남겨야 합니다"), nil
		}
		known := false
		for _, ref := range a.EvidenceRefs {
			if a.Kind == "observed" && !r.rawSeen[ref] {
				return actool.Errorf("관측 근거 원문을 read_evidence로 먼저 확인하세요"), nil
			}
			known = known || r.events[ref].KnownARTEX
		}
		if known {
			a.Alternatives = append(a.Alternatives, "인용한 근거에 ARTEX 재현 트래픽이 포함됩니다. 이 요청 자체를 외부 침해로 분류할 수 없습니다.")
		}
		o := InvestigatorObservation{ID: fmt.Sprintf("observation-%d", len(r.report.Observations)+1), IntentID: r.intentID, Kind: a.Kind, Summary: a.Summary, EvidenceRefs: a.EvidenceRefs, Alternatives: a.Alternatives, NextSteps: a.NextSteps, KnownARTEX: known}
		r.report.Observations = append(r.report.Observations, o)
		r.report.NextSteps = append(r.report.NextSteps, a.NextSteps...)
		if a.Kind == "insufficient_data" {
			r.report.Gaps = append(r.report.Gaps, a.Summary)
		}
		r.emitLocked(InvestigatorProgress{Kind: "observation", Summary: o.Summary, Observation: &o, EvidenceRefs: o.EvidenceRefs})
		return jsonResult(map[string]any{"saved": true, "observation": o, "assessment": "AI interpretation; references validated, semantic claim not independently verified"})
	})
}
