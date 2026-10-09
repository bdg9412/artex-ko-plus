package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

// singleMsg 构造一条带引号与换行的单发消息。刻意用含 `"` 与 `\n` 的标题/摘要：
// 这正是模板插值最容易产出的非法 JSON 的输入。
func singleMsg() Message {
	return Message{
		Items: []Item{{
			FindingID: 42,
			Name:      `登录处 "SQL注入" 风险`,
			VulnClass: "SQL注入",
			Severity:  "high",
			Summary:   "参数 id\n未过滤 导致注入",
			Assets:    []string{"a.example.com", "b.example.com"},
			DetailURL: "https://artex.local/function/findings/detail?id=42",
		}},
	}
}

// batchMsg 构造一批汇总消息。
func batchMsg(n int) Message {
	m := Message{Batch: true, WindowMinutes: 30, HomeURL: "https://artex.local/function/findings"}
	for i := 0; i < n; i++ {
		m.Items = append(m.Items, Item{
			FindingID: int64(i + 1),
			Name:      "漏洞" + itoa(i+1),
			VulnClass: "XSS",
			Severity:  "medium",
			Summary:   "反射型跨站脚本",
			Assets:    []string{"target.example.com"},
		})
	}
	return m
}

// capturePost 起一个假接收端，把收到的请求体与头回传给断言函数。
func capturePost(t *testing.T, respBody string, assert func(t *testing.T, body map[string]any, r *http.Request)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &body); err != nil {
				t.Errorf("请求体不是合法 JSON: %v\n原文: %s", err, raw)
			}
		}
		if assert != nil {
			assert(t, body, r)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDingTalkSendsActionCardWhenLinkPresent(t *testing.T) {
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msgtype"] != "actionCard" {
			t.Fatalf("有回链时应发 actionCard，得到 %v", body["msgtype"])
		}
		card, _ := body["actionCard"].(map[string]any)
		if card["singleURL"] != "https://artex.local/function/findings/detail?id=42" {
			t.Errorf("回链丢失: %v", card["singleURL"])
		}
	})
	if _, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
}

func TestDingTalkFallsBackToMarkdownForBatch(t *testing.T) {
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msgtype"] != "markdown" {
			t.Fatalf("汇总消息应发 markdown，得到 %v", body["msgtype"])
		}
		md, _ := body["markdown"].(map[string]any)
		if !strings.Contains(md["text"].(string), "최근 30분간") {
			t.Errorf("汇总正文缺少时间窗: %v", md["text"])
		}
	})
	if _, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, batchMsg(3)); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
}

// TestDingTalkBusinessErrorIsPermanent 锁住「HTTP 200 但 errcode 非 0」的判定。
// 不检查 errcode 会把投递失败记成成功——这是各家国内 IM 平台共有的坑。
func TestDingTalkBusinessErrorIsPermanent(t *testing.T) {
	srv := capturePost(t, `{"errcode":310000,"errmsg":"keywords not in content"}`, nil)
	_, err := (dingTalkChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg())
	if err == nil {
		t.Fatal("errcode 非 0 应报错")
	}
	if !IsPermanent(err) {
		t.Fatalf("关键词不匹配属于配置错误，应标记为永久失败，得到 %v", err)
	}
	if !strings.Contains(err.Error(), "310000") {
		t.Errorf("错误信息应带上平台错误码，得到 %v", err)
	}
}

func TestWeComTruncatesCJKWithinByteLimit(t *testing.T) {
	var contentLen int
	srv := capturePost(t, `{"errcode":0,"errmsg":"ok"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		md, _ := body["markdown"].(map[string]any)
		content, _ := md["content"].(string)
		contentLen = len(content)
		if !utf8.ValidString(content) {
			t.Fatal("截断后不是合法 UTF-8——企微会整条拒收")
		}
	})
	// 造一批足够长的中文汇总，必然超过 4096 字节。
	m := batchMsg(200)
	if _, err := (weComChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, m); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
	if contentLen > weComMarkdownLimit {
		t.Fatalf("正文 %d 字节超出企微上限 %d", contentLen, weComMarkdownLimit)
	}
	if contentLen == 0 {
		t.Fatal("正文为空")
	}
}

func TestWeComRateLimitIsRetryableButKeyErrorIsPermanent(t *testing.T) {
	limited := capturePost(t, `{"errcode":45009,"errmsg":"api freq out of limit"}`, nil)
	_, err := (weComChannel{}).Send(context.Background(), map[string]any{"webhook": limited.URL}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("45009 是滚动窗口限流，应可重试，得到 %v", err)
	}

	badKey := capturePost(t, `{"errcode":93000,"errmsg":"invalid webhook url"}`, nil)
	_, err = (weComChannel{}).Send(context.Background(), map[string]any{"webhook": badKey.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("93000 是 key 无效，重试不会自愈，应为永久失败，得到 %v", err)
	}
}

func TestFeishuCardStructureAndSign(t *testing.T) {
	const secret = "SECtest123"
	srv := capturePost(t, `{"code":0,"msg":"success"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["msg_type"] != "interactive" {
			t.Fatalf("应发交互式卡片，得到 %v", body["msg_type"])
		}
		card, _ := body["card"].(map[string]any)
		header, _ := card["header"].(map[string]any)
		if header["template"] != "orange" {
			t.Errorf("high 级别应为 orange 配色，得到 %v", header["template"])
		}
		// 配了 secret 就必须带加签参数，否则飞书会以 19021 拒收。
		if body["sign"] == nil || body["timestamp"] == nil {
			t.Fatalf("缺少加签参数: %v", body)
		}
		// 卡片元素里应包含一个按钮，其 url 指向漏洞详情。
		elements, _ := card["elements"].([]any)
		foundButton := false
		for _, e := range elements {
			em, _ := e.(map[string]any)
			if em["tag"] != "action" {
				continue
			}
			actions, _ := em["actions"].([]any)
			for _, a := range actions {
				am, _ := a.(map[string]any)
				if am["url"] == "https://artex.local/function/findings/detail?id=42" {
					foundButton = true
				}
			}
		}
		if !foundButton {
			t.Fatal("卡片里没有指向详情页的按钮")
		}
	})
	cfg := map[string]any{"webhook": srv.URL, "secret": secret}
	if _, err := (feishuChannel{}).Send(context.Background(), cfg, singleMsg()); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
}

func TestFeishuWithoutSecretOmitsSign(t *testing.T) {
	srv := capturePost(t, `{"code":0,"msg":"success"}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["sign"] != nil || body["timestamp"] != nil {
			t.Fatalf("未配置 secret 时不应带加签参数: %v", body)
		}
	})
	if _, err := (feishuChannel{}).Send(context.Background(), map[string]any{"webhook": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
}

func TestTelegramEscapesHTMLInUntrustedContent(t *testing.T) {
	var text string
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		text, _ = body["text"].(string)
		if body["parse_mode"] != "HTML" {
			t.Fatalf("应使用 HTML 解析模式，得到 %v", body["parse_mode"])
		}
	})
	m := Message{Items: []Item{{
		Severity: "high",
		// 标题与摘要来自被测目标/模型输出，是不可信内容。
		Name:    `<script>alert(1)</script>`,
		Summary: "a & b < c",
	}}}
	if _, err := (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": srv.URL}, m); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
	if strings.Contains(text, "<script>") {
		t.Fatalf("未转义 HTML，存在注入: %q", text)
	}
	if !strings.Contains(text, "&lt;script&gt;") {
		t.Fatalf("期望转义后的实体，得到 %q", text)
	}
	if !strings.Contains(text, "a &amp; b") {
		t.Fatalf("& 未转义，得到 %q", text)
	}
}

func TestTelegramErrorClassification(t *testing.T) {
	rateLimited := capturePost(t, `{"ok":false,"error_code":429,"description":"Too Many Requests"}`, nil)
	_, err := (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": rateLimited.URL}, singleMsg())
	if err == nil || IsPermanent(err) {
		t.Fatalf("429 应可重试，得到 %v", err)
	}

	forbidden := capturePost(t, `{"ok":false,"error_code":403,"description":"bot was blocked by the user"}`, nil)
	_, err = (telegramChannel{}).Send(context.Background(),
		map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": forbidden.URL}, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("403 是配置问题，应为永久失败，得到 %v", err)
	}
}

func TestWebhookDefaultTemplateProducesValidJSON(t *testing.T) {
	// 这条是默认模板存在的意义：标题里带引号与换行时，任何朴素的
	// `"title": "{{.Title}}"` 写法都会产出非法 JSON。{{json .}} 才不会。
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, _ *http.Request) {
		if body["title"] != `[🟠 높음] 登录处 "SQL注入" 风险` {
			t.Errorf("标题未正确还原: %v", body["title"])
		}
		items, _ := body["items"].([]any)
		if len(items) != 1 {
			t.Fatalf("items 数量应为 1，得到 %d", len(items))
		}
		it, _ := items[0].(map[string]any)
		if it["summary"] != "参数 id\n未过滤 导致注入" {
			t.Errorf("摘要未正确还原: %v", it["summary"])
		}
		// 数值必须是 JSON 数字而不是字符串（json:"...,string" 之类的写法会踩这坑）。
		if _, ok := it["finding_id"].(float64); !ok {
			t.Errorf("finding_id 应为数字，得到 %T", it["finding_id"])
		}
	})
	if _, err := (webhookChannel{}).Send(context.Background(), map[string]any{"url": srv.URL}, singleMsg()); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
}

func TestWebhookCustomTemplateAndHeaders(t *testing.T) {
	srv := capturePost(t, `{"ok":true}`, func(t *testing.T, body map[string]any, r *http.Request) {
		if r.Header.Get("X-Token") != "s3cret" {
			t.Errorf("自定义头丢失: %v", r.Header)
		}
		if body["msg"] != "3 条" {
			t.Errorf("自定义模板渲染有误: %v", body["msg"])
		}
		if body["first"] != "漏洞1" {
			t.Errorf("range 提取有误: %v", body["first"])
		}
	})
	cfg := map[string]any{
		"url":           srv.URL,
		"headers":       map[string]any{"X-Token": "s3cret"},
		"body_template": `{"msg": {{json (printf "%d 条" .Count)}}, "first": {{json (index .Items 0).Name}}}`,
	}
	if _, err := (webhookChannel{}).Send(context.Background(), cfg, batchMsg(3)); err != nil {
		t.Fatalf("投递失败: %v", err)
	}
}

func TestWebhookRejectsNonJSONRenderResult(t *testing.T) {
	cfg := map[string]any{"url": "https://example.com/hook", "body_template": `not json at all`}
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("渲染结果非 JSON 应为永久失败（模板写错了，重试无用），得到 %v", err)
	}
}

func TestWebhookValidateCatchesBadConfigEarly(t *testing.T) {
	bad := []map[string]any{
		{},
		{"url": "file:///etc/passwd"},
		{"url": "https://example.com", "method": "DELETE"},
		{"url": "https://example.com", "body_template": `{{.Items.`},
	}
	for i, cfg := range bad {
		if err := (webhookChannel{}).Validate(cfg); err == nil {
			t.Errorf("第 %d 组配置应被拒绝: %v", i, cfg)
		}
	}
}

func TestEmailMessageIsWellFormed(t *testing.T) {
	msg, err := buildEmailMessage("artex@example.com", []string{"a@example.com", "b@example.com"}, singleMsg())
	if err != nil {
		t.Fatalf("组装邮件失败: %v", err)
	}
	if !strings.HasPrefix(msg, "From: artex@example.com\r\n") {
		t.Fatalf("From 头有误:\n%s", msg)
	}
	if !strings.Contains(msg, "To: a@example.com, b@example.com\r\n") {
		t.Fatalf("To 头有误:\n%s", msg)
	}
	// 中文主题必须 RFC 2047 编码，否则客户端显示成乱码。
	if !strings.Contains(msg, "Subject: =?utf-8?") {
		t.Fatalf("主题未做 RFC 2047 编码:\n%s", msg)
	}
	if dec, err := new(mime.WordDecoder).DecodeHeader(mustExtractHeader(t, msg, "Subject")); err != nil {
		t.Fatalf("主题无法解码: %v", err)
	} else if !strings.Contains(dec, "SQL注入") {
		t.Fatalf("主题解码后内容有误: %q", dec)
	}

	// 正文是 base64，解出来应是合法 HTML。
	parts := strings.SplitN(msg, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatal("邮件缺少头/体分隔")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(parts[1]), "\r\n", ""))
	if err != nil {
		t.Fatalf("正文 base64 解码失败: %v", err)
	}
	html := string(decoded)
	if !strings.HasPrefix(html, "<div") {
		t.Fatalf("正文不是 HTML: %.80s", html)
	}
	// 标题原样出现在文本位置：HTML 文本内容里的双引号是合法字符，无需转义。
	// 这里断言「原样保留」是为了防止将来有人误加一层引号转义，让中文引号
	// 显示成 &quot;。
	if !strings.Contains(html, `"SQL注入"`) {
		t.Fatalf("标题中的引号在文本位置应原样保留: %.200s", html)
	}
}

// TestEmailEscapesStructuralInjection 覆盖邮件正文真正需要防的注入：
// 漏洞标题与摘要来自被测目标与模型输出，是不可信内容。文本位置必须转义
// & < >（否则可以注入标签），属性位置还必须转义引号（否则可以闭合 href）。
func TestEmailEscapesStructuralInjection(t *testing.T) {
	m := Message{
		Items: []Item{{
			Severity:  "high",
			Name:      `<script>alert(1)</script>`,
			Summary:   "a & b > c",
			DetailURL: `https://artex.local/x?a="onmouseover=alert(1)`,
		}},
	}
	html := htmlBody(m, 0)
	if strings.Contains(html, "<script>") {
		t.Fatalf("标题未转义，可注入标签: %s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("期望转义后的实体: %s", html)
	}
	if !strings.Contains(html, "a &amp; b &gt; c") {
		t.Fatalf("& 与 > 未转义: %s", html)
	}
	// 回链是管理员可配的 public_base_url，本身可信度较高，但属性位置仍必须
	// 转义引号——否则一个带引号的地址会闭合 href 并注入事件处理器。
	if strings.Contains(html, `onmouseover=alert(1)">`) {
		t.Fatalf("href 属性未正确转义: %s", html)
	}
	if !strings.Contains(html, "&quot;") {
		t.Fatalf("属性位置的引号应被转义: %s", html)
	}
}

func mustExtractHeader(t *testing.T, msg, name string) string {
	t.Helper()
	for _, line := range strings.Split(msg, "\r\n") {
		if strings.HasPrefix(line, name+": ") {
			return strings.TrimPrefix(line, name+": ")
		}
	}
	t.Fatalf("未找到 %s 头", name)
	return ""
}

func TestChannelValidateReportsMissingFields(t *testing.T) {
	// 校验错误会直接展示给配置者，必须说清楚缺什么，而不是泛泛的「配置无效」。
	cases := []struct {
		kind   string
		cfg    map[string]any
		substr string
	}{
		{KindDingTalk, map[string]any{}, "Webhook"},
		{KindFeishu, map[string]any{}, "Webhook"},
		{KindWeCom, map[string]any{}, "Webhook"},
		{KindTelegram, map[string]any{}, "Bot Token"},
		{KindTelegram, map[string]any{"bot_token": "t"}, "Chat ID"},
		{KindEmail, map[string]any{}, "SMTP"},
		{KindEmail, map[string]any{"host": "h"}, "포트"},
		{KindEmail, map[string]any{"host": "h", "port": 587, "from": "f"}, "수신자"},
	}
	for _, tc := range cases {
		ch, ok := Get(tc.kind)
		if !ok {
			t.Fatalf("渠道 %s 未注册", tc.kind)
		}
		err := ch.Validate(tc.cfg)
		if err == nil {
			t.Errorf("%s 配置 %v 应校验失败", tc.kind, tc.cfg)
			continue
		}
		if !strings.Contains(err.Error(), tc.substr) {
			t.Errorf("%s 的错误信息应提到 %q，得到 %q", tc.kind, tc.substr, err.Error())
		}
	}
}

// TestEmailSMTPErrorClassification 锁住 SMTP 4xx/5xx 的语义区分。
// 若把 4xx 也判成永久失败，一个启用灰名单的邮件服务器会让每条推送都在第一次
// 尝试后落入 failed —— 而灰名单恰恰是自动重试最该发挥作用的场景。
func TestEmailSMTPErrorClassification(t *testing.T) {
	cases := []struct {
		reply     string
		permanent bool
	}{
		{"450 4.7.1 Greylisting in action, please come back later", false},
		{"451 4.3.0 Temporary system failure", false},
		{"452 4.2.2 Mailbox full", false},
		{"550 5.1.1 User unknown", true},
		{"553 5.1.3 Bad address syntax", true},
		{"554 5.7.1 Relay access denied", true},
		// 取不到应答码时按「可重试」处理：宁可多试一次，也不要把可能的瞬时
		// 故障判死。
		{"unexpected EOF", false},
		{"", false},
	}
	for _, tc := range cases {
		err := smtpStageError("收件人被拒", errors.New(tc.reply))
		if got := IsPermanent(err); got != tc.permanent {
			t.Errorf("应答 %q: 期望 permanent=%v 得到 %v", tc.reply, tc.permanent, got)
		}
		// 无论怎么分类，原文都要保留给使用者排查。
		if tc.reply != "" && !strings.Contains(err.Error(), tc.reply) {
			t.Errorf("应答 %q 的原文被丢弃: %v", tc.reply, err)
		}
	}
}

func TestRegistryCoversAllKinds(t *testing.T) {
	// 六个渠道缺一不可——少一个会在 UI 下拉里静默消失。
	want := []string{KindDingTalk, KindEmail, KindFeishu, KindTelegram, KindWebhook, KindWeCom}
	got := Kinds()
	if len(got) != len(want) {
		t.Fatalf("渠道数量应为 %d，得到 %d: %v", len(want), len(got), got)
	}
	for _, k := range want {
		if !ValidKind(k) {
			t.Errorf("渠道 %s 未注册", k)
		}
		if ch, ok := Get(k); !ok || ch.Kind() != k {
			t.Errorf("渠道 %s 的 Kind() 与注册键不一致", k)
		}
	}
	if ValidKind("nope") {
		t.Error("未注册的类型不应通过校验")
	}
}

func TestPermanentErrorUnwrap(t *testing.T) {
	base := &permanentSentinel{}
	err := Permanent(base)
	if !IsPermanent(err) {
		t.Fatal("应识别为永久失败")
	}
	if !strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("错误信息应透传底层: %v", err)
	}
	if Permanent(nil) != nil {
		t.Fatal("Permanent(nil) 必须返回 nil")
	}
	if IsPermanent(nil) {
		t.Fatal("nil 不是永久失败")
	}
}

type permanentSentinel struct{}

func (*permanentSentinel) Error() string { return "sentinel" }
