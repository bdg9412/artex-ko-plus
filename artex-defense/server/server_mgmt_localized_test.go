package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestServerMgmtConstantsLocalized pins that every user-facing error/response
// literal extracted from server_mgmt.go is Korean (Hangul present, no Chinese
// Han). Reverting any one to Chinese makes assertKoreanError fail on the Han
// ideograph. assertKoreanError / decodeErrorField are reused from the F3 suite
// (same package server).
func TestServerMgmtConstantsLocalized(t *testing.T) {
	cases := map[string]string{
		"errMgmtPGUnavailable":      errMgmtPGUnavailable,
		"errMgmtTaskIDInvalid":      errMgmtTaskIDInvalid,
		"errMgmtTaskDeleting":       errMgmtTaskDeleting,
		"errMgmtTaskHasAgents":      errMgmtTaskHasAgents,
		"errMgmtAgentKeyFormat":     errMgmtAgentKeyFormat,
		"errMgmtNameEmpty":          errMgmtNameEmpty,
		"errMgmtAgentKeyExists":     errMgmtAgentKeyExists,
		"errMgmtBuiltinNoEditMeta":  errMgmtBuiltinNoEditMeta,
		"errMgmtBuiltinNoDelete":    errMgmtBuiltinNoDelete,
		"errMgmtLLMProfileIDFormat": errMgmtLLMProfileIDFormat,
		"errMgmtLLMProfileInvalid":  errMgmtLLMProfileInvalid,
		"errMgmtNoBuiltinPrompt":    errMgmtNoBuiltinPrompt,
		"errMgmtToolNotFound":       errMgmtToolNotFound,
		"errMgmtNotBuiltinTool":     errMgmtNotBuiltinTool,
		"errMgmtMCPNotFound":        errMgmtMCPNotFound,
		"errMgmtToolDiscoverFail":   errMgmtToolDiscoverFail,
		"errMgmtSkillNameInvalid":   errMgmtSkillNameInvalid,
		"errMgmtSkillNoFile":        errMgmtSkillNoFile,
		"errMgmtSkillNoMDInZip":     errMgmtSkillNoMDInZip,
		"errMgmtSkillReadMDFail":    errMgmtSkillReadMDFail,
		"errMgmtSkillNamePre":       errMgmtSkillNamePre,
		"errMgmtSkillNamePost":      errMgmtSkillNamePost,
		"errMgmtSkillExistsPre":     errMgmtSkillExistsPre,
		"errMgmtSkillExistsPost":    errMgmtSkillExistsPost,
		"errMgmtSkillZipBadPath":    errMgmtSkillZipBadPath,
		"errMgmtSkillZipTooMany":    errMgmtSkillZipTooMany,
		"errMgmtSkillFileTooLarge":  errMgmtSkillFileTooLarge,
		"errMgmtSkillZipTooLarge":   errMgmtSkillZipTooLarge,
		"errMgmtSkillNoMDAfter":     errMgmtSkillNoMDAfter,
		"errMgmtSkillInstallFail":   errMgmtSkillInstallFail,
		"errMgmtLLMActiveDelete":    errMgmtLLMActiveDelete,
		"errMgmtLLMRefChanged":      errMgmtLLMRefChanged,
		"errMgmtLLMRefTimeout":      errMgmtLLMRefTimeout,
		"errMgmtNoAPIKey":           errMgmtNoAPIKey,
		"errMgmtBuildReqFail":       errMgmtBuildReqFail,
		"errMgmtReqFail":            errMgmtReqFail,
		"errMgmtParseRespFail":      errMgmtParseRespFail,
		"errMgmtNoModelList":        errMgmtNoModelList,
		"errMgmtTmplSyntax":         errMgmtTmplSyntax,
		"errMgmtTmplVarPre":         errMgmtTmplVarPre,
		"errMgmtTmplVarPost":        errMgmtTmplVarPost,
		// 형식 문자열은 실제 포매팅 결과로 검사한다(한국어 + verb 보존).
		"errMgmtAPIReturned": fmt.Sprintf(errMgmtAPIReturned, 404, "detail"),
	}
	for label, msg := range cases {
		assertKoreanError(t, label, msg)
	}
}

// TestServerMgmtAPIReturnedFormat guards that the model-list probe format string
// keeps its status-code and body placeholders (a %d→wrong-verb edit would drop
// them).
func TestServerMgmtAPIReturnedFormat(t *testing.T) {
	msg := fmt.Sprintf(errMgmtAPIReturned, 404, "boom-body")
	assertKoreanError(t, "errMgmtAPIReturned", msg)
	if !strings.Contains(msg, "404") || !strings.Contains(msg, "boom-body") {
		t.Fatalf("형식 문자열이 상태 코드와 본문을 보존해야 합니다: %q", msg)
	}
}

// TestServerMgmtSkillExistsSentinel guards the cross-stack contract: the server's
// duplicate-skill message must carry the "이미 존재" marker that
// web/src/app/(main)/system/skills/page.tsx greps (msg.includes("이미 존재")) to
// switch into the overwrite-confirm flow. Drift here silently disables overwrite.
func TestServerMgmtSkillExistsSentinel(t *testing.T) {
	msg := errMgmtSkillExistsPre + "my-skill" + errMgmtSkillExistsPost
	assertKoreanError(t, "skillExists", msg)
	if !strings.Contains(msg, "이미 존재") {
		t.Fatalf("프론트 미러 마커 '이미 존재' 가 없습니다: %q", msg)
	}
	if !strings.Contains(msg, "my-skill") {
		t.Fatalf("스킬 이름이 메시지에 포함돼야 합니다: %q", msg)
	}
}

// TestServerMgmtPGGate503Localized exercises the real shared DB gate every
// management handler passes through: with no PostgreSQL handle, pg() writes 503
// and returns nil. The 503 body must be Korean.
func TestServerMgmtPGGate503Localized(t *testing.T) {
	s := &Server{m: &Manager{}} // pg == nil
	rec := httptest.NewRecorder()
	if got := s.pg(rec); got != nil {
		t.Fatal("pg() 는 DB 핸들이 없으면 nil 을 반환해야 합니다")
	}
	if rec.Code != 503 {
		t.Fatalf("상태 코드 503 을 기대했으나 %d", rec.Code)
	}
	assertKoreanError(t, "pg.503", decodeErrorField(t, rec.Body.Bytes()))
}

// TestServerMgmtDeleteTaskBadIDLocalized drives pgDeleteTask through its first
// guard (non-numeric id → 400) without any DB or engine.
func TestServerMgmtDeleteTaskBadIDLocalized(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodDelete, "/api/tasks/abc", nil)
	req.SetPathValue("id", "abc")
	rec := httptest.NewRecorder()
	s.pgDeleteTask(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("상태 코드 400 을 기대했으나 %d (본문 %s)", rec.Code, rec.Body.Bytes())
	}
	got := decodeErrorField(t, rec.Body.Bytes())
	assertKoreanError(t, "deleteTask.badID", got)
	if got != errMgmtTaskIDInvalid {
		t.Fatalf("errMgmtTaskIDInvalid 와 일치해야 합니다: %q", got)
	}
}

// TestServerMgmtListModelsNoKeyLocalized drives pgListModels with no api key and
// no profile id, so it returns {"ok":false,"error":...} before touching the DB.
func TestServerMgmtListModelsNoKeyLocalized(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodPost, "/api/llm/models", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	s.pgListModels(rec, req)
	if rec.Code != 200 {
		t.Fatalf("상태 코드 200 을 기대했으나 %d", rec.Code)
	}
	got := decodeErrorField(t, rec.Body.Bytes())
	assertKoreanError(t, "listModels.noKey", got)
	if got != errMgmtNoAPIKey {
		t.Fatalf("errMgmtNoAPIKey 와 일치해야 합니다: %q", got)
	}
}

// TestServerMgmtValidateTemplateLocalized exercises the prompt-template editor
// validator (pure function, no DB): both the parse-error and the
// disallowed-variable branches must return Korean.
func TestServerMgmtValidateTemplateLocalized(t *testing.T) {
	if msg := validateTemplate("{{", nil); msg == "" {
		t.Fatal("깨진 템플릿은 오류 문구를 반환해야 합니다")
	} else {
		assertKoreanError(t, "validateTemplate.syntax", msg)
	}
	msg := validateTemplate("{{.Bogus}}", nil)
	if msg == "" {
		t.Fatal("허용 목록에 없는 변수는 오류 문구를 반환해야 합니다")
	}
	assertKoreanError(t, "validateTemplate.var", msg)
	if !strings.Contains(msg, "Bogus") {
		t.Fatalf("변수 이름이 메시지에 포함돼야 합니다: %q", msg)
	}
}

// TestServerMgmtGlobalPromptVarsLocalized pins the template-variable catalog help
// text (rendered in the prompt editor's variable palette) as Korean.
func TestServerMgmtGlobalPromptVarsLocalized(t *testing.T) {
	if len(globalPromptVars) == 0 {
		t.Fatal("globalPromptVars 가 비어 있습니다")
	}
	for _, v := range globalPromptVars {
		assertKoreanError(t, "globalPromptVar."+v.Name, v.Description)
	}
}
