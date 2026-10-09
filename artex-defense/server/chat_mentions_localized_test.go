package server

import (
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestChatMentionErrorsLocalized guards F3b chat_mentions.go: every user-facing
// @멘션(인용) error response must be Korean (Hangul present, no Chinese Han). The
// wire token labels (chatMentionPattern·chatMentionKinds), the agent-input
// snapshot header, and the truncation markers fed into that snapshot stay in the
// original language by design and are intentionally not checked here.
func TestChatMentionErrorsLocalized(t *testing.T) {
	// Fixed user-facing literals.
	for label, msg := range map[string]string{
		"badID":       errChatMentionBadID,
		"tooMany":     errChatMentionTooMany,
		"badSearch":   errChatMentionBadSearch,
		"dataUnavail": errChatMentionDataUnavail,
		"tooLarge":    errChatMentionTooLarge,
	} {
		assertKoreanError(t, label, msg)
	}

	// parseChatMentions — a non-positive id inside a valid wire token.
	if _, err := parseChatMentions("@[漏洞#0]"); err == nil {
		t.Fatal("잘못된 인용 ID 가 통과해서는 안 됩니다")
	} else {
		assertKoreanError(t, "parse.badID", err.Error())
	}

	// parseChatMentions — exceeding the per-message mention cap (11 distinct ids).
	var b strings.Builder
	for i := 1; i <= 11; i++ {
		fmt.Fprintf(&b, "@[漏洞#%d] ", i)
	}
	if _, err := parseChatMentions(b.String()); err == nil {
		t.Fatal("인용 상한 초과가 통과해서는 안 됩니다")
	} else {
		assertKoreanError(t, "parse.tooMany", err.Error())
	}

	// composeChatMentionMessage — a mention is present but the database is nil.
	if _, err := composeChatMentionMessage(nil, "@[漏洞#1]"); err == nil {
		t.Fatal("DB 없이 인용 해석이 통과해서는 안 됩니다")
	} else {
		assertKoreanError(t, "compose.dataUnavail", err.Error())
	}

	// searchChatMentions — invalid kind and over-long query are rejected before
	// the database handle is touched, so &Server{} is enough to reach the branch.
	for _, q := range []string{"kind=unsupported", "q=" + url.QueryEscape(strings.Repeat("字", 201))} {
		w := httptest.NewRecorder()
		(&Server{}).searchChatMentions(w, httptest.NewRequest("GET", "/api/chat/mentions?"+q, nil))
		if w.Code != 400 {
			t.Fatalf("검증 실패(400)를 기대했으나 %d 가 반환되었습니다 (%s)", w.Code, q)
		}
		assertKoreanError(t, "search."+q, decodeErrorField(t, w.Body.Bytes()))
	}

	// The display label map mirrors the UI mention kinds, and the not-found
	// template resolves to a fully Korean message for a known kind.
	for _, kind := range []string{"finding", "asset", "company", "endpoint", "ip", "app", "root_domain", "subdomain", "service"} {
		if chatMentionKindLabel[kind] == "" {
			t.Fatalf("종류 라벨이 누락되었습니다: %s", kind)
		}
	}
	assertKoreanError(t, "notFound", fmt.Sprintf(errChatMentionNotFoundFmt, chatMentionKindLabel["finding"], 7))
}
