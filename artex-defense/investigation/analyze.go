package investigation

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Analyze links every observation to selected evidence. Follow-on hypotheses
// require domain-specific evidence and remain manual review in this version.
func Analyze(plan Plan, scope Scope, c Collection) Analysis {
	a := Analysis{EngineVersion: EngineVersion, Hypotheses: []HypothesisResult{}, Timeline: []TimelineEntry{}, Signals: []Signal{}, Limitations: append([]string{}, c.Warnings...), NextSteps: []string{}}
	a.Limitations = append(a.Limitations, "관측된 이벤트는 침해 확정이 아닙니다. 검색 결과가 없어도 조사 범위 밖의 공격을 배제할 수 없습니다.", "HTTP 상태 코드·허용 조치만으로 파일 전달, 코드 실행, 계정 탈취 또는 차단 성공을 판정하지 않습니다.")
	events := append([]Event{}, c.Events...)
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].Ref < events[j].Ref
		}
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	pathRefs := []string{}
	groups := map[string][]Event{}
	missingIdentity, missingCompletion := 0, 0
	for _, e := range events {
		label := "기록된 경로: " + e.Path
		if e.Path == "" {
			label = "경로가 없는 대상 관련 이벤트 — 추가 필드 검토 필요"
		}
		if e.KnownARTEX {
			label = "알려진 ARTEX 검증 표식 · " + label
			a.KnownARTEXCount++
		}
		a.Timeline = append(a.Timeline, TimelineEntry{Timestamp: e.Timestamp, EvidenceRef: e.Ref, EventID: e.ID, Summary: label, KnownARTEX: e.KnownARTEX})
		if e.KnownARTEX {
			continue
		}
		a.ObservedCount++
		if e.Session == "" && e.SourceIP == "" {
			missingIdentity++
		}
		if e.ResponseComplete == nil || e.Bytes == nil {
			missingCompletion++
		}
		if e.Path == "" {
			continue
		}
		pathRefs = append(pathRefs, e.Ref)
		if e.EventKind == "alert" || e.EventKind == "경보" {
			continue
		}
		identity := ""
		if e.Session != "" {
			identity = "session=" + e.Session
		} else if e.SourceIP != "" {
			identity = "source_ip=" + e.SourceIP
		}
		if identity == "" {
			continue
		}
		source := e.Source
		if source == "" {
			source = e.FileName
		}
		target := strings.ToLower(e.Target)
		if target == "" {
			target = scope.Target
		}
		// Source and target are separate from identity; a repeated IP in two
		// sources is never treated as a common actor or causal chain.
		keyBytes, _ := json.Marshal([]string{source, target, identity})
		key := string(keyBytes)
		groups[key] = append(groups[key], e)
	}
	if missingIdentity > 0 {
		a.Limitations = append(a.Limitations, fmt.Sprintf("이벤트 %d건에 세션·출발지가 없어 요청 흐름을 묶을 수 없습니다.", missingIdentity))
	}
	if missingCompletion > 0 {
		a.Limitations = append(a.Limitations, fmt.Sprintf("이벤트 %d건에 응답 완료·전송 바이트 자료가 모두 갖춰지지 않아 실제 전달 범위를 판단할 수 없습니다.", missingCompletion))
	}
	if a.KnownARTEXCount > 0 {
		a.Limitations = append(a.Limitations, "저장된 ARTEX 실행 UUID와 일치한 표식은 타임라인에 별도 표시하고 의심 흐름에서 제외했습니다. 헤더 표식 자체는 요청자의 신원을 인증하지 않습니다.")
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sequenceRefs := []string{}
	signalOverflow := false
	for _, key := range keys {
		g := groups[key]
		found := false
		for start := 0; start < len(g) && !found; start++ {
			paths := map[string]bool{}
			refs := []string{}
			ids := map[string]bool{}
			for end := start; end < len(g) && !g[end].Timestamp.After(g[start].Timestamp.Add(10*time.Minute)); end++ {
				e := g[end]
				p, _ := normalizedPath(e.Path)
				base := strings.TrimRight(scope.PathPrefix, "/")
				if p == base || p == base+"/" {
					continue
				}
				if ids[e.ID] {
					continue
				}
				ids[e.ID] = true
				paths[p] = true
				refs = append(refs, e.Ref)
			}
			if len(paths) >= 2 {
				if len(a.Signals) >= 50 {
					signalOverflow = true
					found = true
					continue
				}
				var keyParts []string
				_ = json.Unmarshal([]byte(key), &keyParts)
				shownKey := strings.Join(keyParts, " · ")
				a.Signals = append(a.Signals, Signal{Kind: "multi_path_requests", Key: shownKey, Summary: fmt.Sprintf("동일 로그 출처·대상·세션 또는 출발지에서 10분 이내 서로 다른 경로 %d개에 대한 이벤트가 관측됐습니다. 정상 리소스 로딩·공유 IP도 가능한 설명입니다.", len(paths)), EvidenceRefs: refs})
				sequenceRefs = append(sequenceRefs, refs...)
				found = true
			}
		}
	}
	if signalOverflow {
		a.Limitations = append(a.Limitations, "요청 흐름 표시 한도 50개를 초과했습니다. 기간·경로를 좁혀 추가 조사하세요.")
	}
	for _, h := range plan.Hypotheses {
		r := HypothesisResult{HypothesisID: h.ID, Status: "manual_review", Summary: "이 후속 가설은 별도 로그와 성립 조건을 확인해야 합니다. 현재 자동 분석으로 검증하지 않았습니다.", EvidenceRefs: []string{}, NextSteps: append([]string{}, h.NextSteps...)}
		switch h.ID {
		case "path_access":
			if len(pathRefs) > 0 {
				r.Status = "observed"
				r.Summary = fmt.Sprintf("선택한 자산·기간·경로 범위에서 이벤트 %d건을 관측했습니다. 경로 기록만으로 악용 성공을 판단하지 않습니다.", len(pathRefs))
				r.EvidenceRefs = pathRefs
			} else if !c.Complete {
				r.Status = "insufficient_data"
				r.Summary = "수집 범위 또는 파싱에 공백이 있어 미관측 결론을 내릴 수 없습니다."
			} else if a.ObservedCount > 0 {
				r.Status = "insufficient_data"
				r.Summary = "대상 이벤트는 있으나 요청 경로가 없어 취약 경로 접근 여부를 확인할 수 없습니다."
			} else {
				r.Status = "not_observed"
				r.Summary = "확인된 조사 범위에서 알려진 ARTEX 표식을 제외한 관련 경로 이벤트를 관측하지 못했습니다. 침해가 없었다는 뜻은 아닙니다."
			}
		case "multi_path":
			if len(sequenceRefs) > 0 {
				r.Status = "suspicious"
				r.Summary = "짧은 시간의 여러 경로 요청 흐름이 있어 검토가 필요합니다. 파일 수집 성공이나 동일 공격자를 확인한 것은 아닙니다."
				r.EvidenceRefs = sequenceRefs
			} else if !c.Complete || missingIdentity > 0 || a.ObservedCount > len(pathRefs) {
				r.Status = "insufficient_data"
				r.Summary = "수집 공백 또는 세션·출발지·경로 부족으로 다중 경로 요청 흐름을 충분히 평가할 수 없습니다."
			} else {
				r.Status = "not_observed"
				r.Summary = "현재 범위에서 동일 로그 출처·대상·세션 또는 출발지의 10분 내 다중 경로 흐름을 관측하지 못했습니다."
			}
		}
		a.Hypotheses = append(a.Hypotheses, r)
	}
	if scope.PathPrefix == "" || scope.PathPrefix == "/" {
		a.Limitations = append(a.Limitations, "특정 취약 경로가 지정되지 않았습니다. 자산 전체의 경로 관측이며 취약점과의 관련성은 별도 확인해야 합니다.")
	}
	a.Summary = fmt.Sprintf("조사 범위의 이벤트 %d건과 알려진 ARTEX 검증 표식 %d건을 분리했습니다. 침해 여부는 관측 근거와 추가 조사로 판단합니다.", a.ObservedCount, a.KnownARTEXCount)
	if !c.Complete {
		a.Summary += " 수집에 공백이 있어 미관측을 확정할 수 없습니다."
		a.NextSteps = append(a.NextSteps, "수집 경고를 해결하고 같은 자산·기간의 증거를 다시 제출하세요.")
	}
	if len(a.Signals) > 0 {
		a.NextSteps = append(a.NextSteps, "다중 경로 흐름의 정상 사용·승인된 점검 여부를 원본 로그와 운영 이력으로 대조하세요.")
	}
	a.NextSteps = append(a.NextSteps, "가설별 성립 조건과 필요한 추가 로그를 확인하세요.", "확인된 행동에 맞는 탐지 규칙을 검토한 뒤 기존 방어 검증에서 효과를 확인하세요.")
	return a
}
