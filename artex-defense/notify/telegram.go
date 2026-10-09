package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// telegramTextLimit 是 Telegram sendMessage 的 text 字段上限（字符数）。
const telegramTextLimit = 4096

// telegramChannel 实现 Telegram Bot API。
//
// 平台特性：
//   - 鉴权全部在 URL path 里（/bot<token>/sendMessage），无需加签。
//   - 用 HTML 解析模式而不是 MarkdownV2：MarkdownV2 要求转义 `_*[]()~`>#+-=|{}.!`
//     共 18 个字符，漏一个就整条消息被拒；HTML 只需转义 & < > 三个。
//   - 业务错误同样藏在 HTTP 200 里，靠 ok 字段判断。
type telegramChannel struct{}

func (telegramChannel) Kind() string { return KindTelegram }

// Telegram 单聊约 1 条/秒、群组 20 条/分钟。取保守值。
func (telegramChannel) DefaultRatePerMin() int { return 20 }

// Bot Token 是完整凭据；chat_id 只是收件人，不算秘密（拿到它没有 Token 也发不了消息）。
func (telegramChannel) SecretKeys() []string { return []string{"bot_token"} }

// base_url 决定 Token 被发往哪个 API 端点（如自建反代），改它必须重新表态 Token。
func (telegramChannel) DestinationKeys() []string { return []string{"base_url"} }

func (telegramChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "bot_token") == "" {
		return errors.New("Bot Token이 없습니다")
	}
	if cfgString(cfg, "chat_id") == "" {
		return errors.New("Chat ID가 없습니다")
	}
	if base := cfgString(cfg, "base_url"); base != "" {
		if err := validateHTTPURL(base); err != nil {
			return fmt.Errorf("API 주소가 올바르지 않습니다: %w", err)
		}
	}
	return nil
}

func (c telegramChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	endpoint, err := telegramEndpoint(cfg)
	if err != nil {
		return 0, Permanent(err)
	}
	text, kept := telegramHTML(m)
	payload := map[string]any{
		"chat_id":                  cfgString(cfg, "chat_id"),
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": false,
	}
	raw, err := doJSON(ctx, "POST", endpoint, nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		OK          bool   `json:"ok"`
		ErrorCode   int    `json:"error_code"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("Telegram 응답을 해석하지 못했습니다: %w (%s)", err, snippet(raw))
	}
	if res.OK {
		return kept, nil
	}
	// 429 是限流，退避后重试有效；其余（400 参数错、401 token 错、403 被拉黑、
	// 404 chat 不存在）都是配置问题，重试不会自愈。
	if res.ErrorCode == 429 {
		return 0, fmt.Errorf("Telegram 요청 제한에 걸렸습니다: %s", res.Description)
	}
	return 0, Permanent(fmt.Errorf("Telegram 응답 오류 %d: %s", res.ErrorCode, res.Description))
}

// telegramEndpoint 拼出 sendMessage 地址。base_url 留空时用官方 API，
// 非空时用于自建 Bot API 反代（国内网络下的常见需求）。
func telegramEndpoint(cfg map[string]any) (string, error) {
	base := cfgString(cfg, "base_url")
	if base == "" {
		base = "https://api.telegram.org"
	}
	base = strings.TrimSuffix(base, "/")
	token := cfgString(cfg, "bot_token")
	raw := base + "/bot" + token + "/sendMessage"
	u, err := url.Parse(raw)
	if err != nil {
		// 不透传 err：地址里含 Bot Token，且此时连 addr 都不该回显。
		return "", fmt.Errorf("API 주소를 조합하지 못했습니다 (API 주소: %s)", redactRequestTarget(base))
	}
	return u.String(), nil
}

// telegramHTML 渲染 HTML 正文，返回正文与实际写入的条目数（见 Channel.Send）。
func telegramHTML(m Message) (string, int) {
	var b strings.Builder
	b.WriteString("<b>" + telegramEscape(markdownTitle(m)) + "</b>\n")
	if m.Batch {
		// Telegram 的上限是**字符数**，所以打包也按字符计量（runeSize）。
		footer := ""
		if m.HomeURL != "" {
			footer = fmt.Sprintf("\n\n<a href=\"%s\">플랫폼에서 전체 보기</a>", telegramEscapeAttr(m.HomeURL))
		}
		kept := packItemCount(m.Items, telegramTextLimit, telegramReservedRunes, footer, runeSize, func(it Item, idx int) string {
			return telegramBatchLine(it, idx+1)
		})
		items := m.Items[:kept]
		b.Reset()
		b.WriteString("<b>" + telegramEscape(telegramBatchTitle(m, items, len(m.Items))) + "</b>")
		for i, it := range items {
			b.WriteString("\n" + telegramEscape(telegramBatchLine(it, i+1)))
		}
		b.WriteString(footer)
		return TruncateHTML(b.String(), telegramTextLimit), kept
	}
	if len(m.Items) == 0 {
		return b.String(), 0
	}
	it := m.Items[0]
	if it.IsStatusChange() {
		b.WriteString(fmt.Sprintf("\n<b>상태 변경</b>: %s → %s",
			telegramEscape(StatusLabel(it.FromStatus)), telegramEscape(StatusLabel(it.ToStatus))))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		b.WriteString("\n<b>유형</b>: " + telegramEscape(it.VulnClass))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		b.WriteString("\n<b>자산</b>: " + telegramEscape(a))
	}
	if s := OneLine(it.Summary, maxSummaryRunes); s != "" {
		b.WriteString("\n<b>개요</b>: " + telegramEscape(s))
	}
	if it.DetailURL != "" {
		b.WriteString(fmt.Sprintf("\n\n<a href=\"%s\">상세 보기</a>", telegramEscapeAttr(it.DetailURL)))
	}
	return TruncateHTML(b.String(), telegramTextLimit), 1
}

// telegramReservedRunes 预留给消息标题与可能出现的截断提示（按字符计）。
const telegramReservedRunes = 160

// telegramBatchLine 渲染汇总里的一条（未转义，由调用方统一转义）。
func telegramBatchLine(it Item, idx int) string {
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		return fmt.Sprintf("%d. %s · %s — %s", idx, SeverityLabel(it.Severity), it.Title(), a)
	}
	return fmt.Sprintf("%d. %s · %s", idx, SeverityLabel(it.Severity), it.Title())
}

// telegramBatchTitle 渲染汇总消息的标题行。条数用的是**本条实际包含**的条数，
// 而不是本批总数——否则读者会以为消息头写的数字就是全部。
func telegramBatchTitle(m Message, items []Item, total int) string {
	title := fmt.Sprintf("취약점 요약 · 총 %d건", total)
	if extra := total - len(items); extra > 0 {
		title += fmt.Sprintf(" (앞 %d건만 표시, 나머지 %d건은 다음 메시지에서 이어집니다)", len(items), extra)
	}
	if m.WindowMinutes > 0 {
		title = fmt.Sprintf("최근 %d분간 · %s", m.WindowMinutes, title)
	}
	return title
}

// telegramEscape 转义 HTML 文本内容。
// Telegram 只认这三种实体，转义后 &amp; 之类的已有实体会被二次转义——这正是
// 期望行为：我们要显示的是原始字符，不是让用户注入 HTML。
func telegramEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// telegramEscapeAttr 转义 HTML 属性值。在文本转义之外还要处理引号——
// URL 里带引号会提前闭合 href 属性，把后面的内容变成注入点。
func telegramEscapeAttr(s string) string {
	s = telegramEscape(s)
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
