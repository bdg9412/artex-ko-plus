package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// 本文件是不变量测试：**任何**从渠道实现里冒出来的错误文本都不得携带凭据。
//
// 为什么单独拉一个文件：最初的渠道用例只覆盖了成功路径与平台业务错误，
// 完全没看传输层失败。而恰恰是传输层错误（连接被拒/DNS 失败/超时）最危险——
// http.Client.Do 返回的 *url.Error 会把**完整 URL** 打进错误文本，而本功能
// 这几家的凭据就在 URL 里。凭据顺着这条串流到了四个出口：
//
//	notification_deliveries.last_error  → 明文落库
//	GET /api/notify/deliveries 响应     → 绕过渠道配置的掩码，回显给浏览器
//	服务端日志                          → 常被外发留存
//	测试发送接口的 502 响应             → 直接弹在前端
//
// 所以这里不只测一个函数，而是逐个渠道真发一次必然失败的请求，断言错误文本
// 里找不到那个凭据。

// credentialCases 覆盖所有「凭据在 URL 里」的渠道形态：
// 钉钉/企微在 query，飞书在路径末段，Telegram 在路径中段。
var credentialCases = []struct {
	name   string
	ch     Channel
	cfg    map[string]any
	secret string
}{
	{
		name:   "钉钉 access_token 在 query",
		ch:     dingTalkChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/robot/send?access_token=" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "企业微信 key 在 query",
		ch:     weComChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/cgi-bin/webhook/send?key=" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "飞书 hook id 在路径末段",
		ch:     feishuChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/open-apis/bot/v2/hook/" + leakProbeToken},
		secret: leakProbeToken,
	},
	{
		name:   "Telegram bot token 在路径中段",
		ch:     telegramChannel{},
		cfg:    map[string]any{"bot_token": leakProbeToken, "chat_id": "1", "base_url": "http://127.0.0.1:1"},
		secret: leakProbeToken,
	},
	{
		name:   "钉钉加签密钥",
		ch:     dingTalkChannel{},
		cfg:    map[string]any{"webhook": "http://127.0.0.1:1/robot/send", "secret": leakProbeToken},
		secret: leakProbeToken,
	},
}

// leakProbeToken 是一个绝不可能是真实凭据的哨兵值，用于在错误文本里搜它。
const leakProbeToken = "LEAKPROBE0123456789abcdef"

// TestChannelErrorsNeverLeakCredentials 是核心不变量。
func TestChannelErrorsNeverLeakCredentials(t *testing.T) {
	for _, tc := range credentialCases {
		t.Run(tc.name, func(t *testing.T) {
			// 必然失败的对端：127.0.0.1:1 无人监听，走的是连接被拒这条路径。
			_, err := tc.ch.Send(context.Background(), tc.cfg, Message{
				Items: []Item{{FindingID: 1, Severity: "high", Name: "泄露探针"}},
			})
			if err == nil {
				t.Fatal("对不可达地址应报错")
			}
			assertNoSecret(t, err.Error(), tc.secret)
		})
	}
}

// TestChannelErrorsNeverLeakCredentialsInPermanentPath 覆盖永久失败分支：
// URL 校验失败、平台业务错误等也会把错误文本外传，同样不能带凭据。
func TestChannelErrorsNeverLeakCredentialsInPermanentPath(t *testing.T) {
	cases := []struct {
		name string
		ch   Channel
		cfg  map[string]any
	}{
		// 地址里带凭据但格式非法 → 触发 validateHTTPURL / url.Parse 分支。
		{"钉钉地址非法", dingTalkChannel{}, map[string]any{"webhook": "file:///" + leakProbeToken}},
		{"企微地址非法", weComChannel{}, map[string]any{"webhook": "gopher://" + leakProbeToken}},
		{"飞书地址非法", feishuChannel{}, map[string]any{"webhook": "ftp://" + leakProbeToken + "/hook"}},
		{"Telegram API 地址非法", telegramChannel{}, map[string]any{"bot_token": "tok", "chat_id": "1", "base_url": "file://" + leakProbeToken}},
		{"通用 Webhook 地址非法", webhookChannel{}, map[string]any{"url": "javascript:" + leakProbeToken}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ch.Send(context.Background(), tc.cfg, Message{Items: []Item{{Severity: "high"}}})
			if err == nil {
				t.Fatal("非法配置应报错")
			}
			assertNoSecret(t, err.Error(), leakProbeToken)
		})
	}
}

func assertNoSecret(t *testing.T, text, secret string) {
	t.Helper()
	if strings.Contains(text, secret) {
		t.Fatalf("错误文本泄露了凭据 %q:\n    %s", secret, text)
	}
}

func TestRedactRequestTargetKeepsOnlySchemeAndHost(t *testing.T) {
	cases := map[string]string{
		"https://oapi.dingtalk.com/robot/send?access_token=S1":    "https://oapi.dingtalk.com/…",
		"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=S2": "https://qyapi.weixin.qq.com/…",
		"https://open.feishu.cn/open-apis/bot/v2/hook/S3":         "https://open.feishu.cn/…",
		"https://api.telegram.org/botS4/sendMessage":              "https://api.telegram.org/…",
		"http://10.0.0.5:8080/hook":                               "http://10.0.0.5:8080/…",
	}
	for in, want := range cases {
		got := redactRequestTarget(in)
		if got != want {
			t.Errorf("redactRequestTarget(%q) = %q，期望 %q", in, got, want)
		}
		// 脱敏结果本身不得再含有原地址的任何路径/查询片段。
		if parts := strings.SplitN(in, "://", 2); len(parts) == 2 {
			if hostAndRest := strings.SplitN(parts[1], "/", 2); len(hostAndRest) == 2 && hostAndRest[1] != "" {
				if strings.Contains(got, hostAndRest[1]) {
					t.Errorf("脱敏后仍含路径/查询片段 %q: %q", hostAndRest[1], got)
				}
			}
		}
	}
	// 不可解析的输入绝不回显原串。
	for _, bad := range []string{"", "://", "not a url", "http://"} {
		if got := redactRequestTarget(bad); strings.Contains(got, bad) && bad != "" {
			t.Errorf("不可解析输入 %q 被回显为 %q", bad, got)
		}
	}
}

// TestRedactTransportErrorStripsURL 直接盯住 *url.Error 这个具体类型：
// 它是 http.Client.Do 的返回类型，也是泄露的第一现场。
func TestRedactTransportErrorStripsURL(t *testing.T) {
	inner := errors.New("dial tcp 127.0.0.1:1: connect: connection refused")
	uerr := &url.Error{
		Op:  "Post",
		URL: "https://api.telegram.org/bot" + leakProbeToken + "/sendMessage",
		Err: inner,
	}
	got := redactTransportError(uerr)
	assertNoSecret(t, got, leakProbeToken)
	if !strings.Contains(got, "api.telegram.org") {
		t.Errorf("应保留 host 以便排查，得到 %q", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Errorf("应保留底层原因以便排查，得到 %q", got)
	}
	// Op 也要保留（POST 还是 GET 对排查有意义）。
	if !strings.Contains(got, "Post") {
		t.Errorf("应保留操作名，得到 %q", got)
	}
}

// TestRedactURLsInTextHandlesFallback 兜底路径：非 *url.Error 的自定义错误
// （如重定向策略返回的错误）里的地址同样要被摘掉。
func TestRedactURLsInTextHandlesFallback(t *testing.T) {
	in := fmt.Sprintf("拒绝跨主机重定向（a.example → http://b.example/bot%s/send）", leakProbeToken)
	got := redactURLsInText(in)
	assertNoSecret(t, got, leakProbeToken)
	if !strings.Contains(got, "http://b.example/…") {
		t.Errorf("应把地址替换为脱敏形态，得到 %q", got)
	}
	// 不含地址的文本原样保留。
	if plain := "dial tcp: connection refused"; redactURLsInText(plain) != plain {
		t.Error("不含地址的文本不应被改动")
	}
}

// TestCrossHostRedirectRefused 覆盖「凭据在 URL 里 + 跟随跨主机跳转 = 交出凭据」。
// httptest 的两个服务监听在 127.0.0.1 的不同端口，端口不同即 Host 不同，
// 正好构成跨主机跳转。
func TestCrossHostRedirectRefused(t *testing.T) {
	var hit bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/robot/send?access_token="+leakProbeToken, http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	_, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": redirector.URL + "/robot/send?access_token=" + leakProbeToken},
		Message{Items: []Item{{Severity: "high"}}})
	if err == nil {
		t.Fatal("跨主机重定向应被拒绝")
	}
	if hit {
		t.Fatal("跳转目标被访问了——凭据已随重定向外泄")
	}
	assertNoSecret(t, err.Error(), leakProbeToken)
}

// TestSameHostRedirectAllowed 反向用例：同主机跳转（如末尾补斜杠）必须仍然可用，
// 否则会把正常工作流一起挡掉。
func TestSameHostRedirectAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robot/send" {
			// 同主机、同端口的跳转。
			http.Redirect(w, r, "/robot/send/", http.StatusTemporaryRedirect)
			return
		}
		_, _ = io.WriteString(w, `{"errcode":0,"errmsg":"ok"}`)
	}))
	defer srv.Close()

	if _, err := (dingTalkChannel{}).Send(context.Background(),
		map[string]any{"webhook": srv.URL + "/robot/send"},
		Message{Items: []Item{{Severity: "high"}}}); err != nil {
		t.Fatalf("同主机重定向不应被拒绝: %v", err)
	}
}
