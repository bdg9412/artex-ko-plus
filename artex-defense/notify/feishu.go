package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// feishuChannel 实现飞书（含 Lark）自定义机器人，走交互式卡片。
//
// 平台特性：
//   - 加签算法与钉钉**不同**，且极易写错，见 feishuSign 注释。
//   - 与钉钉一样把业务错误塞在 HTTP 200 的 body 里（code != 0）。
//   - 卡片 header 支持颜色模板，用级别映射配色，让人在消息列表里一眼看出严重程度。
type feishuChannel struct{}

func (feishuChannel) Kind() string { return KindFeishu }

// 飞书自定义机器人约 5 次/秒，折合 100 次/分钟。
func (feishuChannel) DefaultRatePerMin() int { return 100 }

// Webhook 地址末段即机器人唯一标识，属凭据。
func (feishuChannel) SecretKeys() []string { return []string{"webhook", "secret"} }

// 同理：改 Webhook 地址必须对新地址重新表态签名密钥。
func (feishuChannel) DestinationKeys() []string { return []string{"webhook"} }

func (feishuChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Webhook 주소가 없습니다")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Webhook 주소가 올바르지 않습니다: %w", err)
	}
	return nil
}

func (c feishuChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	card, kept := feishuCard(m)
	payload := map[string]any{
		"msg_type": "interactive",
		"card":     card,
	}
	// 加签参数与消息同层，且只在配置了 secret 时出现。
	if secret := cfgString(cfg, "secret"); secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		payload["timestamp"] = ts
		payload["sign"] = feishuSign(ts, secret)
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		Code int    `json:"code"`
		Msg  string `json:"msg"`
		// 部分版本的飞书 hook 用这套字段名，一并兼容。
		StatusCode    int    `json:"StatusCode"`
		StatusMessage string `json:"StatusMessage"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("Feishu 응답을 해석하지 못했습니다: %w (%s)", err, snippet(raw))
	}
	if res.Code != 0 {
		return 0, Permanent(fmt.Errorf("Feishu에서 오류가 발생했습니다 (%d): %s", res.Code, res.Msg))
	}
	if res.StatusCode != 0 {
		return 0, Permanent(fmt.Errorf("Feishu에서 오류가 발생했습니다 (%d): %s", res.StatusCode, res.StatusMessage))
	}
	return kept, nil
}

// feishuSign 按飞书官方规则计算签名。
//
// 这里特别容易踩坑：官方样例是
//
//	hmac.new(string_to_sign.encode(), digestmod=sha256)
//
// 也就是 **key = timestamp + "\n" + secret，message 为空**，而不是直觉上的
// 「key=secret, message=stringToSign」——那正是钉钉的算法。两边算法刚好反过来，
// 照着另一家的实现写必然签名校验失败（报 19021）。
func feishuSign(timestamp, secret string) string {
	stringToSign := timestamp + "\n" + secret
	mac := hmac.New(sha256.New, []byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// feishuSeverityTemplate 把漏洞级别映射到卡片 header 配色模板。
// 未知级别用 grey——不用 blue，免得和 low 混淆。
func feishuSeverityTemplate(severity string) string {
	switch severity {
	case "critical":
		return "red"
	case "high":
		return "orange"
	case "medium":
		return "yellow"
	case "low":
		return "blue"
	default:
		return "grey"
	}
}

// feishuMaxCardBytes 是卡片内容的保守上限。飞书对卡片有体积限制，超了整条被拒；
// 取一个明显低于官方上限的值，把 JSON 包装开销也算进来。
const feishuMaxCardBytes = 24000

// feishuCard 构造交互式卡片，返回卡片与**实际写入的条目数**。
// kept 的用途同 markdownBody：只有真正进了卡片的条目才该被标记为已送达。
func feishuCard(m Message) (map[string]any, int) {
	elements := []any{}
	kept := 0
	if m.Batch {
		// 先按整条打包再拼头部：头部要写「其余 N 条将在下一条消息继续」，
		// N 必须来自实际装下的条数。
		kept = packItemCount(m.Items, feishuMaxCardBytes, markdownReservedBytes, "", byteSize, func(it Item, idx int) string {
			return feishuBatchLine(it, idx+1)
		})
		items := m.Items[:kept]
		elements = append(elements, feishuMarkdownDiv(markdownBatchIntro(m, items, len(m.Items))))
		for i, it := range items {
			elements = append(elements, feishuMarkdownDiv(feishuBatchLine(it, i+1)))
		}
		if m.HomeURL != "" {
			elements = append(elements, feishuButton("플랫폼에서 전체 보기", m.HomeURL))
		}
	} else if len(m.Items) > 0 {
		kept = 1
		it := m.Items[0]
		elements = append(elements, feishuMarkdownDiv(feishuItemLines(it)))
		if it.DetailURL != "" {
			elements = append(elements, feishuButton("상세 보기", it.DetailURL))
		}
	}

	card := map[string]any{
		"config":   map[string]any{"wide_screen_mode": true},
		"header":   map[string]any{"title": map[string]any{"tag": "plain_text", "content": markdownTitle(m)}},
		"elements": elements,
	}
	if len(m.Items) > 0 {
		card["header"].(map[string]any)["template"] = feishuSeverityTemplate(m.Items[0].Severity)
	}
	return card, kept
}

func feishuMarkdownDiv(content string) map[string]any {
	return map[string]any{"tag": "div", "text": map[string]any{"tag": "lark_md", "content": content}}
}

func feishuButton(label, url string) map[string]any {
	return map[string]any{
		"tag": "action",
		"actions": []any{map[string]any{
			"tag":  "button",
			"text": map[string]any{"tag": "lark_md", "content": label},
			"url":  url,
			"type": "primary",
		}},
	}
}

// feishuItemLines 渲染单个漏洞的 lark_md 正文。
//
// lark_md 与 markdown 是同族的文本格式，同样会解析链接与强调，所以来自外部
// 的字段一律过 markdownText（单行化 + 转义）——否则一条漏洞标题就能在
// 飞书里变成可点击的外链。
func feishuItemLines(it Item) string {
	out := fmt.Sprintf("**%s · %s**", SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if it.IsStatusChange() {
		out += fmt.Sprintf("\n**상태 변경**: %s → %s",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		out += fmt.Sprintf("\n**유형**: %s", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		out += fmt.Sprintf("\n**자산**: %s", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			out += fmt.Sprintf("\n**개요**: %s", s)
		}
	}
	return out
}

// feishuBatchLine 渲染汇总卡片里的一条。
func feishuBatchLine(it Item, index int) string {
	line := fmt.Sprintf("**%d. %s · %s**", index, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		line += " — " + markdownText(a, 0)
	}
	return line
}
