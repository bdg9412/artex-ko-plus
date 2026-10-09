package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// weComMarkdownLimit 是企微群机器人 markdown content 的硬上限（字节，非字符）。
// 这是全部六个渠道里最紧的限制，也是 TruncateBytes 存在的主要原因。
const weComMarkdownLimit = 4096

// weComChannel 实现企业微信群机器人。
//
// 平台特性：
//   - 唯一通过 URL 上的 key 鉴权，不支持加签——所以 webhook 地址本身就是全部凭据。
//   - markdown content 上限 4096 **字节**，超长整条被拒（不是截断）。中文 3 字节/字，
//     意味着正文只有一千多字可写，必须客户端截断。
//   - 限流 20 条/分钟，同样靠客户端限流兜住。
type weComChannel struct{}

func (weComChannel) Kind() string { return KindWeCom }

func (weComChannel) DefaultRatePerMin() int { return 20 }

// 企业微信只有 Webhook 一处凭据（URL 上的 key），且它不支持加签——
// 整个地址就是全部凭据，没有别的字段需要掩码。
func (weComChannel) SecretKeys() []string { return []string{"webhook"} }

// 企微只有 Webhook 一处字段，它既是目的地也是凭据，因此没有「改地址后残留的凭据」可言。
func (weComChannel) DestinationKeys() []string { return []string{"webhook"} }

func (weComChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("Webhook 주소가 없습니다")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("Webhook 주소가 올바르지 않습니다: %w", err)
	}
	return nil
}

func (c weComChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	// 汇总批可能很长（50 条 × 每条一行 + 前缀），4096 字节很容易超。
	// 截断在这里做而不是靠平台报错：被拒意味着这一批全丢，而截断至少送达前若干条。
	content, kept := markdownBody(m, weComMarkdownLimit)
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]any{"content": content},
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("WeCom 응답을 해석하지 못했습니다: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 45009 是接口调用超过限制——平台的限流窗口会滚动，退避后重试是有效的，
		// 所以显式归为可重试。走到这里说明客户端 rate_per_min 配得过于激进，
		// 重试只是兜底，真正的修法是调低该渠道的限流值。
		if res.ErrCode == 45009 {
			return 0, fmt.Errorf("WeCom 요청이 제한되었습니다 (%d): %s", res.ErrCode, res.ErrMsg)
		}
		// 93000 是 webhook key 无效——永久失败，重试不会自愈。
		return 0, Permanent(fmt.Errorf("WeCom에서 오류가 발생했습니다 (%d): %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}
