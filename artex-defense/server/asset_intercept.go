package server

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// 자산 가로채기 규칙 검증기(validateAssetInterceptRuleReq)가 돌려주는 사용자 노출
// 오류 네 가지다. 호출처는 전역 규칙 CRUD 핸들러(assetInterceptCreateRule·
// assetInterceptUpdateRule)와 작업 수준 검증기(validateTaskInterceptRuleReq)뿐이고,
// 모두 writeErr 로 HTTP 400 을 돌려주는 사용자 전용 경로다(에이전트 도구를 거치지
// 않는다). 필드명과 kind 열거값(pattern·exact_ip·cidr·kind)은 클라이언트가 그대로
// 주고받는 와이어 식별자라 번역하지 않고 원문을 유지한다.
const (
	errAssetInterceptPatternEmpty      = "패턴을 입력하세요"
	errAssetInterceptInvalidExactIPFmt = "exact_ip 는 올바른 IP 주소여야 합니다: %s"
	errAssetInterceptInvalidCIDRFmt    = "cidr 는 올바른 네트워크 대역이어야 합니다(예: 192.168.0.0/16): %s"
	errAssetInterceptInvalidKindFmt    = "kind 값이 올바르지 않습니다: %s"
)

// --- asset intercept rule CRUD ---
//
// Global asset blocklist: exact/fuzzy domain·ip·url + CIDR. This layer only
// persists rules; the actual match/enforcement logic lives elsewhere.

func (s *Server) assetInterceptListRules(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	rules, err := pg.ListAssetInterceptRules()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if rules == nil {
		rules = []db.AssetInterceptRule{}
	}
	writeJSON(w, 200, map[string]any{"rules": rules})
}

func (s *Server) assetInterceptCreateRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req assetInterceptRuleReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validateAssetInterceptRuleReq(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rule, err := pg.CreateAssetInterceptRule(req.Kind, req.Pattern, req.Note, req.Enabled)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rule)
}

func (s *Server) assetInterceptUpdateRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad rule id")
		return
	}
	var req assetInterceptRuleReq
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := validateAssetInterceptRuleReq(&req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rule, err := pg.UpdateAssetInterceptRule(id, req.Kind, req.Pattern, req.Note, req.Enabled)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, rule)
}

func (s *Server) assetInterceptDeleteRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad rule id")
		return
	}
	if err := pg.DeleteAssetInterceptRule(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": id})
}

func (s *Server) assetInterceptToggleRule(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad rule id")
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := pg.ToggleAssetInterceptRule(id, req.Enabled); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": req.Enabled})
}

// --- helpers ---

type assetInterceptRuleReq struct {
	Enabled bool   `json:"enabled"`
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Note    string `json:"note"`
}

// validateAssetInterceptRuleReq normalizes and validates a rule. It trims the
// pattern and, for the strictly-formatted kinds (exact_ip / cidr), rejects
// malformed values; fuzzy kinds and domain/url patterns are left as free text
// (the enforcement layer decides how to interpret them).
func validateAssetInterceptRuleReq(req *assetInterceptRuleReq) error {
	req.Pattern = strings.TrimSpace(req.Pattern)
	if req.Pattern == "" {
		return errors.New(errAssetInterceptPatternEmpty)
	}
	switch req.Kind {
	case "exact_domain", "exact_url", "fuzzy_domain", "fuzzy_ip", "fuzzy_url":
		// free-form, no format check
	case "exact_ip":
		if net.ParseIP(req.Pattern) == nil {
			return fmt.Errorf(errAssetInterceptInvalidExactIPFmt, req.Pattern)
		}
	case "cidr":
		if _, _, err := net.ParseCIDR(req.Pattern); err != nil {
			return fmt.Errorf(errAssetInterceptInvalidCIDRFmt, req.Pattern)
		}
	default:
		return fmt.Errorf(errAssetInterceptInvalidKindFmt, req.Kind)
	}
	return nil
}
