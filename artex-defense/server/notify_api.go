package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/notify"
)

// 本文件是推送功能的 HTTP 接口。全部路由挂在 requireAuth 之后（见 Handler()），
// 与其它管理接口一致。

// notify_api.go 가 HTTP 응답으로 돌려주는 사용자 노출 오류 문구다. 한국어 UI 에서 알림
// 설정 요청이 실패하면 이 문구가 그대로 토스트로 뜨므로 한국어로 둔다. 식별자(id)·JSON
// 필드명·enum 값(realtime·digest)·채널 종류 키는 사용자가 설정을 고치는 데 쓰는 값이라
// 원문 그대로 둔다. %s·%q 가 든 상수는 fmt.Sprintf 형식 문자열이다. 用語: 渠道→채널,
// 通知推送→알림(크롬 nav "알림 발송"), 投递→전송, 推送模式→발송 모드. 로그·주석은 BRIEF
// 방침상 최하위라 이 묶음 밖이다.
const (
	notifyErrBadJSON         = "요청 본문이 올바른 JSON 형식이 아닙니다: "
	notifyErrKindInvalidFmt  = "채널 유형이 올바르지 않습니다. 가능한 값: %s"
	notifyErrNameMissing     = "채널 이름을 입력하세요"
	notifyErrNameEmpty       = "채널 이름은 비워 둘 수 없습니다"
	notifyErrModeInvalid     = "발송 모드가 올바르지 않습니다. 가능한 값: realtime / digest"
	notifyErrRateNegative    = "전송 제한 값은 음수일 수 없습니다"
	notifyErrChannelID       = "채널 id 가 올바르지 않습니다"
	notifyErrKindUnregFmt    = "채널 유형 %q 는 등록되어 있지 않습니다"
	notifyErrDeliveryID      = "전송 id 가 올바르지 않습니다"
	notifyErrChannelNotFound = "알림 채널을 찾을 수 없습니다"
)

// 채널 연결을 점검할 때 보내는 테스트 메시지 본문이다. 사용자가 등록한 채널로 실제 발송되므로
// 한국어로 두되, 받는 사람이 실제 취약점으로 오해하지 않도록 한눈에 테스트임이 드러나게 한다.
const (
	notifyTestName    = "테스트 메시지 · 채널 설정 정상"
	notifyTestClass   = "연결 테스트"
	notifyTestSummary = "ARTEX 알림 채널 테스트 메시지입니다. 이 메시지를 받으셨다면 채널 설정이 정상입니다."
)

// notifyChannelDTO 是渠道的对外表述。
//
// Config 是**掩码后**的配置：凭据字段被替换成 notify.MaskedPrefix 开头的值。
// 前端把掩码值原样提交回来即表示「这个字段没改」，服务端据此保留库中原值
// （见 notify.MergeConfig）。
type notifyChannelDTO struct {
	ID         int64          `json:"id"`
	Name       string         `json:"name"`
	Kind       string         `json:"kind"`
	Enabled    bool           `json:"enabled"`
	Mode       string         `json:"mode"`
	Config     map[string]any `json:"config"`
	Filter     notify.Filter  `json:"filter"`
	RatePerMin int            `json:"rate_per_min"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
	// SecretKeys 告知前端哪些字段是凭据，据此渲染密码框与「留空即不改」的提示。
	// 由渠道自己声明（notify.Channel.SecretKeys），前端不硬编码渠道知识。
	SecretKeys []string `json:"secret_keys"`
}

// notifyDeliveryDTO 是投递历史的对外表述。
type notifyDeliveryDTO struct {
	ID          int64      `json:"id"`
	FindingID   int64      `json:"finding_id,string"`
	EventKind   string     `json:"event_kind"`
	ChannelID   int64      `json:"channel_id"`
	ChannelName string     `json:"channel_name"`
	ChannelKind string     `json:"channel_kind"`
	State       string     `json:"state"`
	Attempts    int        `json:"attempts"`
	LastError   string     `json:"last_error"`
	BatchID     *int64     `json:"batch_id,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	SentAt      *time.Time `json:"sent_at,omitempty"`
	NextAttempt time.Time  `json:"next_attempt_at"`
	// 消息标题摘要，让历史列表不必展开就能看出这条推的是什么。
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

func toNotifyChannelDTO(ch *db.NotificationChannel) notifyChannelDTO {
	var cfg map[string]any
	if len(ch.Config) > 0 {
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	secrets := []string{}
	if c, ok := notify.Get(ch.Kind); ok {
		secrets = c.SecretKeys()
	}
	return notifyChannelDTO{
		ID:         ch.ID,
		Name:       ch.Name,
		Kind:       ch.Kind,
		Enabled:    ch.IsEnabled(),
		Mode:       ch.Mode,
		Config:     notify.MaskConfig(ch.Kind, cfg),
		Filter:     notify.ParseFilter(ch.Filter),
		RatePerMin: ch.RatePerMin,
		CreatedAt:  ch.CreatedAt,
		UpdatedAt:  ch.UpdatedAt,
		SecretKeys: secrets,
	}
}

func toNotifyDeliveryDTO(dl *db.NotificationDelivery) notifyDeliveryDTO {
	snap, _ := parseSnapshot(dl)
	dto := notifyDeliveryDTO{
		ID:          dl.ID,
		FindingID:   dl.FindingID,
		EventKind:   dl.EventKind,
		ChannelID:   dl.ChannelID,
		ChannelName: dl.ChannelName,
		ChannelKind: dl.ChannelKind,
		State:       dl.State,
		Attempts:    dl.Attempts,
		LastError:   dl.LastError,
		BatchID:     dl.BatchID,
		CreatedAt:   dl.CreatedAt,
		SentAt:      dl.SentAt,
		NextAttempt: dl.NextAttemptAt,
		Severity:    snap.Severity,
	}
	if snap.Name != "" {
		dto.Title = snap.Name
	} else {
		dto.Title = snap.VulnClass
	}
	return dto
}

// notifyMeta 返回通知页需要的静态元数据与全局设置，一次请求拿全，
// 避免前端为了渲染一个下拉框发三次请求。
func (s *Server) notifyMeta(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	kinds := make([]map[string]any, 0, len(notify.Kinds()))
	for _, k := range notify.Kinds() {
		ch, _ := notify.Get(k)
		kinds = append(kinds, map[string]any{
			"kind":                 k,
			"default_rate_per_min": ch.DefaultRatePerMin(),
			"secret_keys":          ch.SecretKeys(),
		})
	}
	baseURL, _, _ := pg.GetSetting(settingNotifyPublicBaseURL)
	digest, _, _ := pg.GetSetting(settingNotifyDigestMinutes)
	stats, err := pg.NotificationStatsSnapshot(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"kinds":               kinds,
		"enabled":             pg.GetBool(settingNotifyEnabled, true),
		"public_base_url":     baseURL,
		"digest_interval_min": digest,
		"defaults": map[string]any{
			"digest_interval_min": notifyDefaultDigestMinutes,
		},
		"stats": stats,
	})
}

func (s *Server) notifyListChannels(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	channels, err := pg.ListNotificationChannels(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]notifyChannelDTO, 0, len(channels))
	for _, ch := range channels {
		out = append(out, toNotifyChannelDTO(ch))
	}
	writeJSON(w, 200, map[string]any{"channels": out})
}

// notifyChannelRequest 是新建/更新渠道的请求体。
//
// 全部业务字段用指针，以便区分「没传」与「传了零值」：PATCH 语义下，
// 没传的字段必须保留库中原值。
type notifyChannelRequest struct {
	Name       *string        `json:"name"`
	Kind       *string        `json:"kind"`
	Enabled    *bool          `json:"enabled"`
	Mode       *string        `json:"mode"`
	Config     map[string]any `json:"config"`
	Filter     *notify.Filter `json:"filter"`
	RatePerMin *int           `json:"rate_per_min"`
}

func (s *Server) notifyCreateChannel(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req notifyChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, notifyErrBadJSON+err.Error())
		return
	}
	if req.Kind == nil || !notify.ValidKind(*req.Kind) {
		writeErr(w, 400, fmt.Sprintf(notifyErrKindInvalidFmt, strings.Join(notify.Kinds(), " / ")))
		return
	}
	name := ""
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if name == "" {
		writeErr(w, 400, notifyErrNameMissing)
		return
	}
	channel, _ := notify.Get(*req.Kind)
	if err := channel.Validate(req.Config); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ch := &db.NotificationChannel{
		Name:       name,
		Kind:       *req.Kind,
		Enabled:    req.Enabled,
		Mode:       db.NotifyModeRealtime,
		RatePerMin: channel.DefaultRatePerMin(),
	}
	if req.Mode != nil {
		if !db.ValidNotifyMode(*req.Mode) {
			writeErr(w, 400, notifyErrModeInvalid)
			return
		}
		ch.Mode = *req.Mode
	}
	if req.RatePerMin != nil {
		// 显式给值就照用——包括 0，它表示「不限流」，是合法配置。
		if *req.RatePerMin < 0 {
			writeErr(w, 400, notifyErrRateNegative)
			return
		}
		ch.RatePerMin = *req.RatePerMin
	}
	// 只有「字段缺省」才套用渠道默认值。默认值必须在这里决定而不是在 db 层：
	// 只有请求体能区分「没传这个字段」与「显式传了 0」，而两者的含义完全不同
	// （前者=用默认，后者=不限流）。db 层把 0 也当未指定，会让不限流配置不可达。
	if req.RatePerMin == nil {
		ch.RatePerMin = channel.DefaultRatePerMin()
	}
	if req.Filter != nil {
		// 写入时校验取值受限的过滤字段（如 min_severity）。详见 notify.Filter.Validate：
		// 门槛打错字会让过滤器静默失效变成全推，必须在入口拦掉。
		if err := req.Filter.Validate(); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		raw, _ := json.Marshal(req.Filter)
		ch.Filter = raw
	}
	rawCfg, _ := json.Marshal(req.Config)
	ch.Config = rawCfg

	id, err := pg.SaveNotificationChannel(r.Context(), ch)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id})
}

func (s *Server) notifyUpdateChannel(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, notifyErrChannelID)
		return
	}
	current, err := pg.NotificationChannelByID(r.Context(), id)
	if err != nil {
		notifyChannelLookupErr(w, err)
		return
	}
	var req notifyChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, notifyErrBadJSON+err.Error())
		return
	}

	// kind 允许修改，但改类型意味着凭据字段整套替换，不能与旧配置合并。
	kind := current.Kind
	if req.Kind != nil {
		if !notify.ValidKind(*req.Kind) {
			writeErr(w, 400, fmt.Sprintf(notifyErrKindInvalidFmt, strings.Join(notify.Kinds(), " / ")))
			return
		}
		kind = *req.Kind
	}
	channel, _ := notify.Get(kind)

	var stored map[string]any
	if kind == current.Kind {
		if len(current.Config) > 0 {
			_ = json.Unmarshal(current.Config, &stored)
		}
	}
	if stored == nil {
		stored = map[string]any{}
	}
	// 用 PrepareConfigUpdate 而不是裸的 MergeConfig：目标地址变更时必须让操作者
	// 对凭据字段重新表态，否则「只改地址、凭据沿用」会把库里的真凭据发到新地址。
	merged, err := notify.PrepareConfigUpdate(kind, stored, req.Config)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := channel.Validate(merged); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	rawCfg, _ := json.Marshal(merged)

	ch := &db.NotificationChannel{
		ID:         id,
		Name:       current.Name,
		Kind:       kind,
		Enabled:    current.Enabled,
		Mode:       current.Mode,
		Config:     rawCfg,
		Filter:     current.Filter,
		RatePerMin: current.RatePerMin,
	}
	if req.Name != nil {
		if ch.Name = strings.TrimSpace(*req.Name); ch.Name == "" {
			writeErr(w, 400, notifyErrNameEmpty)
			return
		}
	}
	if req.Enabled != nil {
		ch.Enabled = req.Enabled
	}
	if req.Mode != nil {
		if !db.ValidNotifyMode(*req.Mode) {
			writeErr(w, 400, notifyErrModeInvalid)
			return
		}
		ch.Mode = *req.Mode
	}
	if req.RatePerMin != nil {
		if *req.RatePerMin < 0 {
			writeErr(w, 400, notifyErrRateNegative)
			return
		}
		ch.RatePerMin = *req.RatePerMin
	}
	if req.Filter != nil {
		if err := req.Filter.Validate(); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		raw, _ := json.Marshal(req.Filter)
		ch.Filter = raw
	}

	// 走 SetNotificationChannelEnabled 而非 SaveNotificationChannel 的路径，
	// 是为了让「停用」同时把存量待发投递标记为 skipped，避免重新启用时收到
	// 一批已过时的积压消息。
	enabledChanged := ch.Enabled != nil && current.Enabled != nil && *ch.Enabled != *current.Enabled
	if enabledChanged {
		// 先把配置更新落库（此时 enabled 用旧值，避免提前触发跳过逻辑），
		// 再单独切开关。两步之间没有并发窗口：本接口是唯一改这两个字段的入口。
		prev := ch.Enabled
		ch.Enabled = current.Enabled
		if _, err := pg.SaveNotificationChannel(r.Context(), ch); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		if err := pg.SetNotificationChannelEnabled(r.Context(), id, *prev); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"id": id})
		return
	}
	if _, err := pg.SaveNotificationChannel(r.Context(), ch); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"id": id})
}

func (s *Server) notifyDeleteChannel(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, notifyErrChannelID)
		return
	}
	if err := pg.DeleteNotificationChannel(r.Context(), id); err != nil {
		notifyChannelLookupErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// notifyTestChannel 用当前保存的配置发一条测试消息。
//
// 直接调用渠道 Send 而不经投递队列：测试的目的是立刻告诉用户「这套配置能不能
// 发出去」，走队列会把结果藏进投递历史，用户得再去翻一遍才知道成没成。
// 因此本接口是**同步**的，超时上限由 notify 包的 HTTP 客户端决定（15 秒）。
func (s *Server) notifyTestChannel(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, notifyErrChannelID)
		return
	}
	ch, err := pg.NotificationChannelByID(r.Context(), id)
	if err != nil {
		notifyChannelLookupErr(w, err)
		return
	}
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		writeErr(w, 400, fmt.Sprintf(notifyErrKindUnregFmt, ch.Kind))
		return
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if err := channel.Validate(cfg); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	msg := notifyTestMessage(s.notifierBaseURL(pg))
	start := time.Now()
	// 测试消息只有一条，送达条数这里不需要（渠道长度上限对单条消息而言
	// 由截断兜底，不涉及分段）。
	if _, err := channel.Send(r.Context(), cfg, msg); err != nil {
		// 把渠道返回的原始错误如实回给用户——这是他们调试配置的唯一线索。
		writeErr(w, 502, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"ok":         true,
		"latency_ms": time.Since(start).Milliseconds(),
	})
}

// notifyTestMessage 构造测试消息。刻意用一眼能看出是测试的内容：
// 收到的人不应该把它误判成真实漏洞。
func notifyTestMessage(baseURL string) notify.Message {
	return notify.Message{
		Items: []notify.Item{{
			FindingID: 0,
			Name:      notifyTestName,
			VulnClass: notifyTestClass,
			Severity:  "low",
			Summary:   notifyTestSummary,
			Assets:    []string{"artex.example.com"},
			DetailURL: baseURL,
		}},
		HomeURL: baseURL,
	}
}

// notifierBaseURL 读回链用的外部地址。
func (s *Server) notifierBaseURL(pg *db.DB) string {
	v, _, _ := pg.GetSetting(settingNotifyPublicBaseURL)
	return trimTrailingSlash(v)
}

func (s *Server) notifyListDeliveries(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	f := db.NotificationDeliveryFilter{
		State:     r.URL.Query().Get("state"),
		EventKind: r.URL.Query().Get("event_kind"),
	}
	if v := r.URL.Query().Get("channel_id"); v != "" {
		f.ChannelID = int64(atoiDefault(v, 0))
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 50)
	items, total, err := pg.ListNotificationDeliveries(r.Context(), f, page, pageSize)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]notifyDeliveryDTO, 0, len(items))
	for _, dl := range items {
		out = append(out, toNotifyDeliveryDTO(dl))
	}
	writeJSON(w, 200, map[string]any{"deliveries": out, "total": total, "page": page, "page_size": pageSize})
}

func (s *Server) notifyRetryDelivery(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok {
		writeErr(w, 400, notifyErrDeliveryID)
		return
	}
	if err := pg.RetryNotificationDelivery(r.Context(), id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// notifyChannelLookupErr 把「渠道不存在」翻译成 404，其余错误 500。
func notifyChannelLookupErr(w http.ResponseWriter, err error) {
	if errors.Is(err, db.ErrNotificationChannelNotFound) {
		writeErr(w, 404, notifyErrChannelNotFound)
		return
	}
	writeErr(w, 500, err.Error())
}
