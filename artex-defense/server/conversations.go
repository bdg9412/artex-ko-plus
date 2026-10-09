package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/intercept"
	"github.com/Autumn-27/artex/sidequestion"
)

const (
	maxConversationRequestBytes  = 64 << 10
	maxConversationAgentKeyRunes = 120
	maxConversationTitleRunes    = 200
)

// 대화(채팅) 엔드포인트가 HTTP 응답으로 돌려주는 사용자 노출 문구다. 한국어 UI 에서
// 요청이 실패하면 이 문구가 그대로 토스트로 뜨므로 한국어로 둔다. 요청 필드명
// (agent_key·title·pinned·ids·id)·식별자(LLM·API Key·token)는 사용자가 요청을 고치는 데
// 쓰는 값이라 원문 그대로 둔다. 用語: 配置→설정(B4c-5), agent→에이전트. %d 가 든 상수는
// fmt.Sprintf 형식 문자열이다. 기본 대화 제목·센티넬은 아래 convDefaultTitle·
// convAttachmentTitle 로 분리했고(F8), 재검증 사유·트랜스크립트 오류 문구는 아래
// convRetest* 상수·transcriptErrorSummary 로 분리했다(F9). 트리거 메시지 골격은 아직
// 이 묶음 밖이다(F10·저널 참조). 로그·주석은 BRIEF 방침상 최하위.
const (
	convErrRequestTooLarge = "요청 본문이 너무 큽니다"
	convErrAgentKeyEmpty   = "agent_key 는 비어 있을 수 없습니다"
	convErrAgentKeyTooLong = "agent_key 는 최대 %d자까지 입력할 수 있습니다"
	convErrAgentNotFound   = "에이전트를 찾을 수 없습니다"
	convErrLLMProfile      = "지정한 LLM 설정이 존재하지 않거나 API Key 가 설정되지 않았습니다"
	convErrTitleTooLong    = "제목은 최대 %d자까지 입력할 수 있습니다"
	convErrTitleOrPinned   = "title 또는 pinned 중 하나 이상을 제공해야 합니다"
	convErrTitleEmpty      = "제목은 비어 있을 수 없습니다"
	convErrBadConvID       = "대화 id 가 올바르지 않습니다"
	convErrIDsCount        = "ids 개수는 1에서 %d 사이여야 합니다"
	convErrMessageEmpty    = "메시지는 비어 있을 수 없습니다"
	convErrBusy            = "이 대화가 이전 메시지를 처리하고 있습니다. 잠시 기다려 주세요"
)

// 대화 기본 제목. convDefaultTitle 은 표시 문구이자 센티넬이다. 대화를 만들 때 제목으로
// 쓰고, 첫 사용자 메시지가 오면 제목이 비었거나 이 값일 때만 자동 제목으로 덮어쓴다
// (sendConversationMessage). 대입하는 쪽과 비교하는 쪽이 어긋나면 자동 제목 분기가
// 깨지므로 한 상수로 묶는다. convAttachmentTitle 은 첨부만 보낸 첫 메시지의 기본 제목이다.
const (
	convDefaultTitle    = "새 대화"
	convAttachmentTitle = "첨부 메시지"
)

// 재검증(finding_retest) 종결 사유. runConversationTurn 이 재검증 대화를 봉인할 때 쓰고,
// finding_retests.error 컬럼에 저장돼 재검증 패널(finding-retest-panel) 의 item.error 로
// 그대로 노출된다(사용자 노출). db/finding_retests.go 의 형제 사유(결론 미저장·서비스 재시작)도
// 같은 컬럼·패널이라 그 파일에서 함께 한국어로 둔다. 종결 상태 값("failed"/"stopped"/
// "completed")은 StatusLabel 로 한국어 라벨에 매핑되는 센티넬이라 ASCII 로 유지한다(F9).
const (
	convRetestFailedToStart    = "재검증을 시작하지 못했습니다"
	convRetestStatusReadFailed = "재검증 상태를 읽지 못했습니다. 다시 시작해 주세요"
	convRetestStoppedOrClosed  = "재검증이 중지되었거나 서비스가 종료되었습니다"
)

// isDefaultConversationTitle 은 대화가 아직 자동 생성된 기본 제목(빈 값 또는
// convDefaultTitle)을 달고 있는지 알려준다. 이 경우 첫 사용자 메시지가 제목을 자동으로
// 덮어쓴다. 생성 기본값과 이 판정이 같은 상수를 쓰므로 둘이 어긋날 수 없다.
func isDefaultConversationTitle(title string) bool {
	return title == "" || title == convDefaultTitle
}

func decodeConversationRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxConversationRequestBytes)
	if err := decode(r, value); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, convErrRequestTooLarge)
		} else {
			writeErr(w, http.StatusBadRequest, err.Error())
		}
		return false
	}
	return true
}

// ---------- conversations (chat page) ----------
//
// A conversation is a ChatGPT-style thread bound to an agent key, independent of
// the pentest task graph. Turns run on ChatAgent; steps persist to
// conversation_activities and the browser POLLS ?since=cursor for live updates
// (no per-conversation SSE broadcaster needed).

type conversationListItem struct {
	*db.Conversation
	Running bool `json:"running"`
}

func (s *Server) pgListConversations(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	cs, err := pg.ListConversations()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	items := make([]conversationListItem, 0, len(cs))
	s.chatMu.Lock()
	for _, c := range cs {
		items = append(items, conversationListItem{Conversation: c, Running: s.chatBusy[s.convBusyKey(c.ID)]})
	}
	s.chatMu.Unlock()
	writeJSON(w, 200, map[string]any{"conversations": items})
}

func (s *Server) pgCreateConversation(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		AgentKey     string `json:"agent_key"`
		Title        string `json:"title"`
		LLMProfileID *int64 `json:"llm_profile_id"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	req.AgentKey = strings.TrimSpace(req.AgentKey)
	if req.AgentKey == "" {
		writeErr(w, 400, convErrAgentKeyEmpty)
		return
	}
	if utf8.RuneCountInString(req.AgentKey) > maxConversationAgentKeyRunes {
		writeErr(w, 400, fmt.Sprintf(convErrAgentKeyTooLong, maxConversationAgentKeyRunes))
		return
	}
	a, err := pg.GetAgentByKey(req.AgentKey)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if a == nil {
		writeErr(w, 404, convErrAgentNotFound)
		return
	}
	if req.LLMProfileID != nil {
		if _, ok := s.loadProfileConfig(*req.LLMProfileID); !ok {
			writeErr(w, 400, convErrLLMProfile)
			return
		}
	}
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = convDefaultTitle
	}
	if utf8.RuneCountInString(title) > maxConversationTitleRunes {
		writeErr(w, 400, fmt.Sprintf(convErrTitleTooLong, maxConversationTitleRunes))
		return
	}
	c, err := pg.CreateConversation(req.AgentKey, title, req.LLMProfileID)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, c)
}

func (s *Server) pgUpdateConversation(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	var req struct {
		LLMProfileID *int64 `json:"llm_profile_id"` // null clears the override
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	if req.LLMProfileID != nil {
		if _, ok := s.loadProfileConfig(*req.LLMProfileID); !ok {
			writeErr(w, 400, convErrLLMProfile)
			return
		}
	}
	if err := pg.UpdateConversationProfile(c.ID, req.LLMProfileID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// convByID resolves the {id} path value to a conversation (404 if absent).
func (s *Server) convByID(w http.ResponseWriter, r *http.Request) (*db.DB, *db.Conversation, bool) {
	pg := s.pg(w)
	if pg == nil {
		return nil, nil, false
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, "bad conversation id")
		return nil, nil, false
	}
	c, err := pg.GetConversation(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return nil, nil, false
	}
	if c == nil {
		writeErr(w, 404, "conversation not found")
		return nil, nil, false
	}
	return pg, c, true
}

func (s *Server) pgRenameConversation(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	var req struct {
		Title  *string `json:"title"`
		Pinned *bool   `json:"pinned"`
	}
	if !decodeConversationRequest(w, r, &req) {
		return
	}
	if req.Title == nil && req.Pinned == nil {
		writeErr(w, 400, convErrTitleOrPinned)
		return
	}
	if req.Title != nil {
		title := strings.TrimSpace(*req.Title)
		if title == "" {
			writeErr(w, 400, convErrTitleEmpty)
			return
		}
		if utf8.RuneCountInString(title) > maxConversationTitleRunes {
			writeErr(w, 400, fmt.Sprintf(convErrTitleTooLong, maxConversationTitleRunes))
			return
		}
		req.Title = &title
	}
	updated, err := pg.UpdateConversation(c.ID, db.ConversationPatch{Title: req.Title, Pinned: req.Pinned})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if updated == nil {
		writeErr(w, 404, "conversation not found")
		return
	}
	writeJSON(w, 200, updated)
}

func (s *Server) pgDeleteConversation(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	s.cancelConversation(c.ID)
	s.cancelSideWhere(func(p sidequestion.Parent) bool { return p.ConversationID == c.ID })
	if err := pg.DeleteConversation(c.ID); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": c.ID})
}

const maxConversationDeleteBatch = 100

type conversationDeleteItem struct {
	ID    int64  `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (s *Server) cancelConversation(id int64) {
	busyKey := s.convBusyKey(id)
	s.chatMu.Lock()
	cancel := s.chatCancel[busyKey]
	s.chatMu.Unlock()
	if cancel != nil {
		cancel(agent.AbortChatStoppedByUser)
	}
}

// pgDeleteConversationsBatch deletes up to 100 selected conversations in one
// database statement. Missing ids are reported per item so a stale list does not
// hide what was actually removed.
func (s *Server) pgDeleteConversationsBatch(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var request struct {
		IDs []int64 `json:"ids"`
	}
	if !decodeConversationRequest(w, r, &request) {
		return
	}
	ids := make([]int64, 0, len(request.IDs))
	seen := make(map[int64]struct{}, len(request.IDs))
	for _, id := range request.IDs {
		if id <= 0 {
			writeErr(w, http.StatusBadRequest, convErrBadConvID)
			return
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	if len(ids) == 0 || len(ids) > maxConversationDeleteBatch {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf(convErrIDsCount, maxConversationDeleteBatch))
		return
	}
	for _, id := range ids {
		s.cancelConversation(id)
		s.cancelSideWhere(func(p sidequestion.Parent) bool { return p.ConversationID == id })
	}
	deleted, err := pg.DeleteConversations(ids)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	deletedSet := make(map[int64]struct{}, len(deleted))
	for _, id := range deleted {
		deletedSet[id] = struct{}{}
	}
	items := make([]conversationDeleteItem, 0, len(ids))
	for _, id := range ids {
		_, ok := deletedSet[id]
		item := conversationDeleteItem{ID: id, OK: ok}
		if !ok {
			item.Error = "conversation not found"
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) convBusyKey(id int64) string { return "conv-" + strconv.FormatInt(id, 10) }

// pgConversationMessages returns steps after ?since=cursor plus whether a turn is
// still running (so the client knows to keep polling). Same item shape as the task
// activity stream, so the frontend transcript renderer is reused verbatim.
func (s *Server) pgConversationMessages(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit := atoiDefault(q.Get("limit"), 200)
	s.chatMu.Lock()
	running := s.chatBusy[s.convBusyKey(c.ID)]
	s.chatMu.Unlock()

	// Incremental tail: ?since=N returns steps after id N (ASC) — used by the live
	// poll and the post-send fetch. A generous cap so a burst is never dropped.
	if sv := q.Get("since"); sv != "" {
		since, _ := strconv.ParseInt(sv, 10, 64)
		items, cursor, err := pg.ConvActivityList(c.ID, since, max(limit, 1000))
		if err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"items": activityDTOs(items), "cursor": cursor, "running": running, "hasMore": false})
		return
	}

	// History page (reverse pagination): no ?since → the latest page; ?before=N →
	// the page of older steps ending before id N. hasMore lets the client stop
	// loading earlier history once the top of the thread is reached.
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	items, hasMore, err := pg.ConvActivityPage(c.ID, before, limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	cursor := before
	if n := len(items); n > 0 {
		cursor = items[n-1].ID
	}
	writeJSON(w, 200, map[string]any{"items": activityDTOs(items), "cursor": cursor, "running": running, "hasMore": hasMore})
}

// pgConversationMsgDetail lazily returns one step's full detail blob.
func (s *Server) pgConversationMsgDetail(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	seq, ok := pathInt(r, "seq")
	if !ok {
		writeErr(w, 400, "bad seq")
		return
	}
	detail, err := pg.ConvActivityDetail(c.ID, seq)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"detail": detail})
}

// pgStopConversation aborts the in-flight run for one conversation (manual stop —
// the run/stop button in the chat UI). It cancels only THIS session's agent run;
// the P3 trigger queue is untouched, so the agent's next queued fire still starts.
func (s *Server) pgStopConversation(w http.ResponseWriter, r *http.Request) {
	_, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	busyKey := s.convBusyKey(c.ID)
	s.chatMu.Lock()
	cancel := s.chatCancel[busyKey]
	s.chatMu.Unlock()
	if cancel == nil {
		writeJSON(w, 200, map[string]any{"status": "idle"}) // nothing running
		return
	}
	cancel(agent.AbortChatStoppedByUser)
	writeJSON(w, 200, map[string]any{"status": "stopping"})
}

// pgSendConversationMessage persists the human turn, then runs the agent in the
// background (steps stream to conversation_activities, polled by the client). One
// in-flight turn per conversation.
func (s *Server) pgSendConversationMessage(w http.ResponseWriter, r *http.Request) {
	pg, c, ok := s.convByID(w, r)
	if !ok {
		return
	}
	var req struct {
		Message     string           `json:"message"`
		Attachments []chatAttachment `json:"attachments,omitempty"` // 方式1 上传的文件(路径相对会话工作目录)
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	msg := strings.TrimSpace(req.Message)
	if msg == "" && len(req.Attachments) == 0 {
		writeErr(w, 400, convErrMessageEmpty)
		return
	}
	agentMessage, ok := s.prepareChatMentionMessage(w, msg)
	if !ok {
		return
	}
	// Same resolution as the background runner: honour the agent binding / this
	// conversation's chosen profile before falling back to the global config, so a
	// conversation that picked a valid LLM is not rejected just because no global
	// config is active.
	if s.resolveChatAgent(c) == nil {
		writeErr(w, 503, s.chatUnavailableReason())
		return
	}

	busyKey := s.convBusyKey(c.ID)
	s.chatMu.Lock()
	if s.chatBusy[busyKey] {
		s.chatMu.Unlock()
		writeErr(w, 409, convErrBusy)
		return
	}
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()

	// persist + float the human turn; auto-title the thread from the first message.
	// Worker is the agent key (not "user") so the transcript stays a single lane
	// (no worker chips) — the kind='user' already right-aligns it as a human bubble.
	// With attachments, Detail carries {text, attachments} JSON so the transcript
	// renders attachment cards; without, Detail is the full text (Summary is truncated,
	// so the transcript lazy-loads Detail to show the message untruncated).
	ua := userActivityWithAttachments(c.AgentKey, msg, req.Attachments)
	ua.Summary = firstLine(msg, 200)
	if ua.Detail == "" {
		ua.Detail = msg
	}
	if _, err := pg.AppendConvActivity(c.ID, ua); err != nil {
		log.Printf("[conv %d] append user msg failed: %v", c.ID, err)
	}
	if isDefaultConversationTitle(c.Title) {
		title := firstLine(msg, 40)
		if title == "" {
			title = convAttachmentTitle
		}
		_ = pg.RenameConversation(c.ID, title)
	}
	_ = pg.TouchConversation(c.ID)

	// Append the uploaded files' ABSOLUTE paths so the ChatAgent opens them with its
	// Read/Bash tools. baseDir = the agent's per-session CWD (<workDir>/sessions/
	// conv-<id>/), matching chatUpload's landing dir and agent/chat.go's sessionWorkDir
	// — busyKey == convBusyKey(c.ID) == "conv-<id>" == that session id.
	baseDir := filepath.Join(s.m.dir, "sessions", busyKey)
	s.runConversation(c, composeAgentMessage(agentMessage, req.Attachments, baseDir), busyKey, msg)
	writeJSON(w, 202, map[string]any{"status": "accepted"})
}

// runConversation runs ONE agent turn on a conversation in a background goroutine
// (each conversation is independent → parallel). Steps stream to
// conversation_activities. Shared by the chat HTTP handler and the P3 scheduler.
// busyKey clears when the run ends (best-effort in-flight marker).
func (s *Server) runConversation(c *db.Conversation, msg, busyKey string, userMessage ...string) {
	ctx, cancel := s.conversationRunContext(c.ID, busyKey)
	// Only the human-message handler supplies this field, before adding the
	// attachment manifest. Scheduler/retest prompts must not be labelled as users.
	if len(userMessage) == 1 {
		ctx = intercept.WithReviewContext(ctx, "", intercept.ReviewBackground{Source: intercept.BackgroundUserMessage, Text: userMessage[0]})
	}
	go s.runConversationTurn(ctx, cancel, c, msg, busyKey)
}

// runConversationSync runs ONE agent turn on a conversation and BLOCKS until the
// run ends (clearing busyKey). runConversation wraps it in a goroutine for the
// fire-and-forget chat path; the P3 trigger queue calls it directly so it can wait
// for completion before starting the next queued fire for the same agent.
func (s *Server) runConversationSync(c *db.Conversation, msg, busyKey string) {
	ctx, cancel := s.conversationRunContext(c.ID, busyKey)
	s.runConversationTurn(ctx, cancel, c, msg, busyKey)
}

// Register cancellation before returning 202, so an immediate stop/delete cannot
// miss a background goroutine which has not started yet.
func (s *Server) conversationRunContext(id int64, busyKey string) (context.Context, context.CancelCauseFunc) {
	// Per-run cancellable context so a manual stop (pgStopConversation) can abort
	// just this session. Registered under chatMu so the stop handler can find it.
	ctx, cancel := context.WithCancelCause(intercept.WithConvID(s.ctx, id))
	s.chatMu.Lock()
	s.chatCancel[busyKey] = cancel
	s.chatMu.Unlock()
	return ctx, cancel
}

// transcriptErrorSummary 는 실행이 실패했을 때 활동 전사(transcript)에 남기는 오류 요약을
// 만든다. label 은 실패한 주체를 가리키며, 채팅 턴은 빈 문자열, 작업 메인 에이전트는
// "메인 에이전트"를 넣는다. 두 전사 모두 "(…오류: …)" 형태로 같게 렌더되도록 한 곳에 모은다.
// err 원문은 그대로 보존하고 바깥 라벨만 한국어로 둔다(F9).
func transcriptErrorSummary(label, errMsg string) string {
	if label != "" {
		label += " "
	}
	return "(" + label + "오류: " + errMsg + ")"
}

func (s *Server) runConversationTurn(ctx context.Context, cancel context.CancelCauseFunc, c *db.Conversation, msg, busyKey string) {
	defer func() {
		cancel(agent.AbortChatTurnFinished)
		s.chatMu.Lock()
		delete(s.chatBusy, busyKey)
		delete(s.chatCancel, busyKey)
		s.chatMu.Unlock()
	}()
	// Only the first turn executes a historical retest. Follow-up conversation
	// turns may explain the sealed result; the result tool refuses to overwrite it.
	finishStatus, finishReason := "failed", convRetestFailedToStart
	if c.AgentKey == db.FindingRetestAgentKey {
		// Read without the run cancellation so an immediate stop still seals pending.
		r, err := s.m.pg.FindingRetestForConversation(context.Background(), c.ID)
		if err != nil {
			// The sealing defer below needs r.ID, which we do not have here. Seal by
			// conversation instead, otherwise the row stays 'pending' forever.
			log.Printf("[conv %d] load retest: %v", c.ID, err)
			if err := s.m.pg.FailPendingRetestForConversation(c.ID, convRetestStatusReadFailed); err != nil {
				log.Printf("[conv %d] seal retest: %v", c.ID, err)
			}
			return
		}
		if r != nil && r.Status == "pending" {
			defer func() {
				if ctx.Err() != nil {
					finishStatus, finishReason = "stopped", convRetestStoppedOrClosed
				}
				s.finishRetest(r.ID, finishStatus, finishReason)
			}()
			if ctx.Err() != nil {
				return
			}
			started, err := s.m.pg.StartFindingRetest(ctx, r.ID)
			if err != nil {
				finishReason = err.Error()
				return
			}
			if !started {
				return
			}
		}
	}
	if ctx.Err() != nil {
		return
	}
	// precedence: the conversation agent's own binding → this conversation's pin → global.
	ca := s.resolveChatAgent(c)
	if ca == nil {
		finishReason = s.chatUnavailableReason()
		return
	}
	pg := s.m.pg
	maxTurns := s.agentMaxTurns(c.AgentKey)
	maxDuration := time.Duration(s.agentRunSeconds(c.AgentKey)) * time.Second
	webSearch := false
	if a, err := pg.GetAgentByKey(c.AgentKey); err == nil && a != nil {
		webSearch = a.WebSearch
	}
	sessionID := s.convBusyKey(c.ID) // "conv-<id>" transcript session
	emit := func(rec db.Activity) {
		if _, err := pg.AppendConvActivity(c.ID, rec); err != nil {
			log.Printf("[conv %d] append activity failed: %v", c.ID, err)
		}
	}
	// On a manual stop ctx is cancelled; Chat already emits a clean "已手动停止"
	// step, so skip the raw-error entry — only surface genuine failures.
	if _, err := ca.Chat(ctx, c.AgentKey, sessionID, msg, maxTurns, maxDuration, webSearch, emit); err != nil {
		finishReason = err.Error()
		if ctx.Err() == nil {
			_, _ = pg.AppendConvActivity(c.ID, db.Activity{Worker: c.AgentKey, Kind: "text", IsError: true,
				Summary: transcriptErrorSummary("", err.Error()), Detail: err.Error()})
		}
	} else {
		finishStatus, finishReason = "completed", ""
	}
	_ = pg.TouchConversation(c.ID)
}

// triggerBehavior is an agent's cached P3 trigger post-processing策略 (see the
// agents table trigger_* columns). Read once per fire in StartTriggeredRun so the
// pump never touches the DB while holding queueMu.
type triggerBehavior struct {
	runMode     string // serial | parallel
	mergeMode   string // by_task | all | none (serial 用;parallel 忽略,每条各自一个会话)
	maxParallel int    // parallel 用的每 agent 并发上限;<=0=不限
}

// readTriggerBehavior loads an agent's策略, falling back to safe defaults
// (serial / all / 5) on any error or unknown enum value.
func (s *Server) readTriggerBehavior(agentKey string) triggerBehavior {
	b := triggerBehavior{runMode: "serial", mergeMode: "all", maxParallel: 5}
	if s.m.pg == nil {
		return b
	}
	a, err := s.m.pg.GetAgentByKey(agentKey)
	if err != nil || a == nil {
		return b
	}
	if a.TriggerRunMode == "parallel" {
		b.runMode = "parallel"
	}
	switch a.TriggerMergeMode {
	case "by_task", "all", "none":
		b.mergeMode = a.TriggerMergeMode
	}
	b.maxParallel = a.TriggerMaxParallel
	return b
}

// StartTriggeredRun enqueues a P3 trigger fire for agentKey and pumps the queue. The
// agent's策略 decides concurrency + merge: serial → run one at a time (optionally
// merging by task / all / none); parallel → run each fire in its own concurrent
// conversation up to trigger_max_parallel. Distinct agents always run concurrently.
func (s *Server) StartTriggeredRun(agentKey, title, message string, taskID int64, mergeable bool, taskDesc, taskGoal string) {
	if s.m.pg == nil || s.chatAgentRef() == nil {
		return
	}
	cfg := s.readTriggerBehavior(agentKey) // DB read BEFORE the lock (never under queueMu)
	s.queueMu.Lock()
	s.triggerCfg[agentKey] = cfg
	s.triggerQ[agentKey] = append(s.triggerQ[agentKey], triggeredRun{agentKey: agentKey, title: title, message: message, taskID: taskID, taskDesc: taskDesc, taskGoal: taskGoal, mergeable: mergeable})
	s.pumpLocked(agentKey)
	s.queueMu.Unlock()
}

// pumpLocked launches queued fires for one agent up to its concurrency limit, then
// returns. Serial → limit 1; parallel → limit = maxParallel (<=0 → unlimited). Each
// launched run re-pumps on completion (runAndPump) to fill the freed slot. Caller
// holds queueMu.
func (s *Server) pumpLocked(agentKey string) {
	if s.ctx.Err() != nil {
		return
	}
	cfg := s.triggerCfg[agentKey]
	limit := 1
	if cfg.runMode == "parallel" {
		if cfg.maxParallel <= 0 {
			limit = math.MaxInt
		} else {
			limit = cfg.maxParallel
		}
	}
	for s.triggerActive[agentKey] < limit && len(s.triggerQ[agentKey]) > 0 {
		item := s.nextTriggerRun(agentKey, cfg)
		s.triggerActive[agentKey]++
		go s.runAndPump(agentKey, item)
	}
}

// runAndPump runs one fire to completion, then decrements the active counter and
// re-pumps to fill the freed slot (cleaning up the agent's maps when fully idle).
func (s *Server) runAndPump(agentKey string, item triggeredRun) {
	s.runTriggeredRun(item)
	s.queueMu.Lock()
	s.triggerActive[agentKey]--
	if s.triggerActive[agentKey] <= 0 && len(s.triggerQ[agentKey]) == 0 {
		delete(s.triggerActive, agentKey)
		delete(s.triggerQ, agentKey)
		delete(s.triggerCfg, agentKey)
	} else {
		s.pumpLocked(agentKey)
	}
	s.queueMu.Unlock()
}

// nextTriggerRun pops the next run from the agent's queue per the merge mode:
//
//	parallel / none → one head item, no merge
//	by_task         → head + all queued same-task mergeable fires merged into one
//	all             → the ENTIRE queue merged into one run (regardless of task/type)
//
// Caller holds queueMu.
func (s *Server) nextTriggerRun(agentKey string, cfg triggerBehavior) triggeredRun {
	q := s.triggerQ[agentKey]
	if cfg.runMode == "parallel" || cfg.mergeMode == "none" {
		s.triggerQ[agentKey] = q[1:]
		return q[0]
	}
	if cfg.mergeMode == "all" {
		s.triggerQ[agentKey] = q[:0:0]
		return mergeAllRuns(q)
	}
	// by_task: head + same-task mergeable fires.
	head := q[0]
	if !head.mergeable || head.taskID == 0 {
		s.triggerQ[agentKey] = q[1:]
		return head
	}
	group := []triggeredRun{head}
	rest := q[:0:0] // keep non-matching items in order
	for _, it := range q[1:] {
		if it.mergeable && it.taskID == head.taskID {
			group = append(group, it)
		} else {
			rest = append(rest, it)
		}
	}
	s.triggerQ[agentKey] = rest
	return mergeTriggeredRuns(group)
}

// [F10/F19 경계 판정 · 두뇌 입력 보존] 아래 P3 트리거 메시지 합성부(taskContextHeader·
// finalTriggerMessage·mergeTriggeredRuns·mergeAllRuns)가 만드는 중국어 문구는 번역하지 않고
// 원문을 보존한다. 조립된 message 는 runTriggeredRun 에서 finalTriggerMessage(item) →
// ca.Chat 의 user 메시지로 들어가는 에이전트 입력(두뇌)이자, 동시에 AppendConvActivity
// (kind="user")로 전사에 노출되는 이중 용도 문자열이다. 대상: `【任务 …】`(작업 컨텍스트
// 헤더)·`【本会话合并了…请一并处理】`(합병 안내)·`── 触发 N ──`(구분선). BRIEF 경계 #1
// (에이전트 두뇌는 번역하지 않는다 — TSecBench 벤치마크 동작 보존)에 해당하고, 표시만
// 한국어로 가르려면 두뇌용·전사용 두 문자열을 따로 나르도록 구조를 바꿔야 해(F16 동형)
// 고위험·저가치라 보류한다. 합병 run 의 conversation 제목(`合并触发 · …`)은 ca.Chat 에
// 안 들어가는 표시 전용이지만, 그 본문(위 보존 대상)이 중국어로 고정되므로 제목만 바꾸면
// 한 대화에서 제목=한국어·본문=중국어로 섞인다(F7·F8·F12 혼재 금지) — 가치도 낮아 함께 보존.
// 회귀 가드: trigger_merge_test.go 가 `【任务 #`·`── 触发 `·`共 N 个任务`·`【本会话合并了`·
// `（目标：` 프레이밍을 핀한다(우발 한국어화 시 FAIL).
//
// taskContextHeader renders a task's description/goal once. Same-task fires share
// this block, so the scheduler no longer repeats it per event (a long task goal
// times N fires was the dominant bloat). Returns "" for interval/none triggers
// (taskID==0, no task context). desc/goal are truncated to keep even a single copy
// bounded.
func taskContextHeader(taskID int64, desc, goal string) string {
	if desc == "" && goal == "" {
		// No task context to show (interval/none fire, or a merged run that already
		// embedded its per-task headers and cleared these fields).
		return ""
	}
	if goal != "" {
		return fmt.Sprintf("【任务 #%d %s（目标：%s）】", taskID, trunc(desc, 200), trunc(goal, 500))
	}
	return fmt.Sprintf("【任务 #%d %s】", taskID, trunc(desc, 200))
}

// finalTriggerMessage renders the message actually sent to the agent for a single
// (non-merged) fire: the task-context header (written once) followed by the event
// body. Merged runs embed their per-task headers inline and clear taskDesc/taskGoal,
// so this returns their message unchanged.
func finalTriggerMessage(item triggeredRun) string {
	if h := taskContextHeader(item.taskID, item.taskDesc, item.taskGoal); h != "" {
		return h + "\n" + item.message
	}
	return item.message
}

// mergeTriggeredRuns folds several same-task event fires into one run: the shared
// task-context header written ONCE, then each fire's event body, so the agent handles
// the task's burst in a single conversation without repeating the (possibly long)
// task description/goal per event.
func mergeTriggeredRuns(items []triggeredRun) triggeredRun {
	if len(items) == 1 {
		return items[0]
	}
	first := items[0]
	var b strings.Builder
	fmt.Fprintf(&b, "【本会话合并了任务 #%d 的 %d 条触发事件，请一并处理】\n", first.taskID, len(items))
	if h := taskContextHeader(first.taskID, first.taskDesc, first.taskGoal); h != "" {
		fmt.Fprintf(&b, "%s\n", h) // same task → task context appears once
	}
	for i, it := range items {
		fmt.Fprintf(&b, "\n── 触发 %d ──\n%s\n", i+1, it.message)
	}
	return triggeredRun{
		agentKey:  first.agentKey,
		title:     fmt.Sprintf("合并触发 · task#%d · %d 条", first.taskID, len(items)),
		message:   b.String(),
		taskID:    first.taskID,
		mergeable: true,
		// taskDesc/taskGoal left empty: header already embedded above.
	}
}

// mergeAllRuns folds the ENTIRE queued burst into one run (merge_mode='all'),
// regardless of type. Events are grouped by task (tasks in first-appearance order,
// events in their original order within a task), so each task's context header — and
// its possibly long description/goal — is written exactly ONCE even when fires from
// different tasks interleave in the queue. Cross-task chronology is not preserved
// (event bodies carry no timestamps, so per-task grouping reads better for the agent).
func mergeAllRuns(items []triggeredRun) triggeredRun {
	if len(items) == 1 {
		return items[0]
	}
	first := items[0]
	order := []int64{}
	groups := map[int64][]triggeredRun{}
	for _, it := range items {
		if _, seen := groups[it.taskID]; !seen {
			order = append(order, it.taskID)
		}
		groups[it.taskID] = append(groups[it.taskID], it)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "【本会话合并了队列中的 %d 条触发事件（共 %d 个任务），请一并处理】\n", len(items), len(order))
	seq := 0
	for _, tid := range order {
		g := groups[tid]
		if h := taskContextHeader(tid, g[0].taskDesc, g[0].taskGoal); h != "" {
			fmt.Fprintf(&b, "\n%s\n", h) // same task → context appears once, even if interleaved
		}
		for _, it := range g {
			seq++
			fmt.Fprintf(&b, "\n── 触发 %d（task#%d）──\n%s\n", seq, tid, it.message)
		}
	}
	return triggeredRun{
		agentKey:  first.agentKey,
		title:     fmt.Sprintf("合并触发 · 全部 · %d 条", len(items)),
		message:   b.String(),
		taskID:    first.taskID,
		mergeable: true,
		// taskDesc/taskGoal left empty: per-task headers already embedded above.
	}
}

// runTriggeredRun creates the conversation for one queued fire, records the human
// turn, and runs it synchronously (blocks until the run ends). recover keeps a
// panic from killing the drain loop and wedging the agent's queue.
func (s *Server) runTriggeredRun(item triggeredRun) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[trigger] run for %s panicked: %v", item.agentKey, r)
		}
	}()
	pg := s.m.pg
	c, err := pg.CreateConversation(item.agentKey, firstLine(item.title, 60), nil)
	if err != nil {
		log.Printf("[trigger] create conversation for %s failed: %v", item.agentKey, err)
		return
	}
	msg := finalTriggerMessage(item) // prepend the task-context header for single (non-merged) fires
	if _, err := pg.AppendConvActivity(c.ID, db.Activity{Worker: item.agentKey, Kind: "user", Summary: firstLine(msg, 200), Detail: msg}); err != nil {
		log.Printf("[trigger] append msg failed: %v", err)
	}
	busyKey := s.convBusyKey(c.ID)
	s.chatMu.Lock()
	s.chatBusy[busyKey] = true
	s.chatMu.Unlock()
	s.runConversationSync(c, msg, busyKey)
}

// firstLine returns a single-line, length-capped preview (shared with summaries).
func firstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len([]rune(s)) > max {
		s = string([]rune(s)[:max]) + "…"
	}
	return s
}
