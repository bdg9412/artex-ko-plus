package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// allowLocalTargets 决定是否允许把消息投递到环回 / 链路本地地址。
//
// 默认拒绝。这几段地址不是 IM 机器人或公网邮件服务器会出现的地方，而它们能
// 打到的东西很敏感：同机另一个服务的管理端口、以及云环境的元数据端点
// （169.254.169.254，可读出实例凭据）。投递地址是管理员配的，但一个被 XSS/CSRF
// 借用的管理会话、或共用同一 JWT 的第二个人，都能靠改配置把响应内容读回来
// ——doJSON 会把 4xx/5xx 的响应体前 200 字节写进 last_error，而投递历史接口
// 会把它回显出来，这就是一条半盲读原语。
//
// 但「本机 SMTP 中继」（127.0.0.1:25 上的 postfix）是自建邮件的常见配置，
// 一刀切会把人卡住。所以留一个显式逃生口而不是硬编码放行：
// 设置 ARTEX_NOTIFY_ALLOW_LOCAL=1 即允许。
//
// 导出为 AllowLocalTargetsEnv 是为了让测试能明确地打开它——本包与 server 包的
// 用例大量使用 127.0.0.1 上的 httptest 假接收端，不打开就全部被守卫拦下。
const AllowLocalTargetsEnv = "ARTEX_NOTIFY_ALLOW_LOCAL"

func allowLocalTargets() bool {
	v := strings.TrimSpace(os.Getenv(AllowLocalTargetsEnv))
	return v == "1" || strings.EqualFold(v, "true")
}

// isBlockedDialIP 报告目标 IP 是否属于「默认不允许投递」的地址段。
//
// 只拒绝环回、链路本地（含云元数据 169.254.169.254）、未指定与组播。
// **不拒绝** RFC1918 私网：内网自建 Mattermost / SMTP 中继是很常见的合法用法，
// 把它们一并挡掉会让功能在真实环境里直接不可用。这条取舍是刻意的——
// 防护要挡住真正敏感的目标，同时不能把正常部署一起废掉。
func isBlockedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// IPv4-mapped IPv6（::ffff:127.0.0.1）要还原成 IPv4 再判，否则绕过检查。
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// blockInternalDial 是 http.Transport 拨号器的 Control 钩子，在**连接建立时**
// 检查目标地址。
//
// 为什么设在拨号阶段而不是只在保存配置时校验：这里才是最终生效点。
// 它同时覆盖两种绕过配置校验的情形——DNS 重绑定（校验时解析到公网 IP、
// 真正连接时解析到内网）与重定向（虽然我们已拒绝跨主机跳转，但同主机跳转
// 仍可能把路径指到别处）。
func blockInternalDial(_, address string, _ syscall.RawConn) error {
	if allowLocalTargets() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("대상 주소를 해석할 수 없습니다: %q", host)
	}
	if isBlockedDialIP(ip) {
		return fmt.Errorf("로컬 또는 링크 로컬 주소 %s 로는 전송하지 않습니다 (로컬 서비스로 보내야 하면 %s=1 로 설정하세요)", ip, AllowLocalTargetsEnv)
	}
	return nil
}

// notifyTransport 在默认 Transport 的基础上只加一个拨号守卫。
// 用 Clone 保留默认的全部调优（连接池、HTTP/2、超时、proxy 等），
// 避免为了加一个检查而改动其它行为。
var notifyTransport = func() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{}
	}
	clone := t.Clone()
	clone.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: blockInternalDial}).DialContext
	return clone
}()

// httpClient 是所有渠道投递共用的客户端。
//
// 刻意**不**复用项目的全局出口代理（server 侧的 GlobalProxy）：那个代理是给渗透
// 目标流量用的，常是不稳定的隧道，而通知的可用性不该被目标网络的抖动绑架。
// IM 推送直连即可。超时设为 15 秒——比这更慢的对端实际上已经是故障状态。
//
// 拒绝跨主机重定向：本功能的投递地址都是「一个固定 endpoint」形态，正常不会
// 重定向到别的主机；而这几家的凭据（钉钉的 access_token、企微的 key、Telegram 的
// bot token）**就在 URL 里**，跟随跨主机跳转等于把凭据交给重定向目标。同主机
// 的跳转（如末尾补斜杠）仍允许。
var httpClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: notifyTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("리다이렉트가 너무 많습니다")
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("다른 호스트로의 리다이렉트는 허용하지 않습니다 (%s → %s)", via[0].URL.Host, req.URL.Host)
		}
		return nil
	},
}

// respBodyLimit 限制读取响应体的大小。对端异常时可能吐回超大内容，而我们只需要
// 错误码和一小段错误描述用于展示在投递历史里。
const respBodyLimit = 8 << 10

// doJSON 发送一次请求并返回响应体（已限长）。
//
// payload 为 nil 时发送空 body（用于 GET 或平台不要求 body 的场景）。
// headers 里的键值原样附加，用于通用 Webhook 的自定义头。
//
// 错误分类是这个函数的核心职责：网络层失败与 5xx/408/429 归为「可重试」，
// 其余 4xx 归为「永久失败」——重试一个 403 只是把同一个错误刷 3 遍日志。
func doJSON(ctx context.Context, method, url string, headers map[string]string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			// 序列化失败是本地 bug（配置字段类型不对），重试也不会变好。
			return nil, Permanent(fmt.Errorf("요청 본문을 만들지 못했습니다: %w", err))
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		// URL 非法——多半是用户把地址填错了，属于永久失败。
		// 这里同样不能透传 err：url.Parse 的错误文本里含完整地址。
		return nil, Permanent(fmt.Errorf("요청 주소가 올바르지 않습니다: %s", redactRequestTarget(url)))
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// 连接被拒、DNS 失败、超时——多为瞬时故障，交给退避重试。
		//
		// 错误文本必须脱敏后再往外传。原因：http.Client.Do 返回的是 *url.Error，
		// 它的 Error() 是 `Op "完整URL": 底层错误`，而本功能这几家的凭据**就在 URL 里**
		// （钉钉 access_token、企微 key、飞书 hook id、Telegram /bot<token>/）。
		// 不脱敏的话，凭据会顺着这条错误串流到四个地方：notification_deliveries
		// 的 last_error（明文落库）、投递历史接口的响应（**绕过渠道配置的掩码**）、
		// 服务端日志、以及测试发送接口回给前端的 502 文本。
		return nil, fmt.Errorf("요청에 실패했습니다: %s", redactTransportError(err))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	if readErr != nil {
		return nil, fmt.Errorf("응답을 읽지 못했습니다: %w", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	// 429（限流）与 408（超时）值得重试；其余 4xx 是配置或权限问题，重试无意义。
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return nil, fmt.Errorf("상대 서버가 요청을 제한하거나 응답이 지연되었습니다 (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("상대 서버에 오류가 발생했습니다 (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	return nil, Permanent(fmt.Errorf("상대 서버가 요청을 거부했습니다 (HTTP %d): %s", resp.StatusCode, snippet(raw)))
}

// snippet 把响应体压成一行短文本，用于错误信息。响应里可能带换行与大量空白，
// 直接塞进 last_error 会让投递历史页面排版崩掉。
func snippet(raw []byte) string {
	return OneLine(string(raw), 200)
}

// redactRequestTarget 把投递地址压成「scheme://host/…」，用于错误信息。
//
// 这是本包唯一的地址脱敏口径，刻意做得**足够粗暴**：除了 scheme 与 host，
// 其余一律丢弃。原因是没有一个「通用且安全」的方式判断 URL 的哪一段是凭据：
//
//	钉钉   凭据在 query      /robot/send?access_token=xxx
//	企微   凭据在 query      /cgi-bin/webhook/send?key=xxx
//	飞书   凭据在**路径末段** /open-apis/bot/v2/hook/<hook_id>
//	Telegram 凭据在**路径中段** /bot<token>/sendMessage
//
// 想「只保留有用部分」就得按渠道打补丁，而漏掉任何一家就是一次凭据泄露。
// 保留 host 已经够用于排查（DNS 解析不了、连不上、证书不对都能定位），
// 具体是哪个机器人由渠道配置里的掩码尾号提示去认。
//
// 解析失败时返回固定占位符——绝不把原始串回显出去。
func redactRequestTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(주소를 해석할 수 없음)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// redactTransportError 从传输层错误里剥掉地址，只保留底层原因。
//
// *url.Error 的结构是 {Op, URL, Err}，Error() 会把 URL 一起打出来。
// 这里显式取 Err 字段，绕开它的 Error() ——比事后做字符串替换更可靠，
// 因为替换要正确应对 URL 编码/转义后的各种变体，容易漏。
func redactTransportError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, parseErr := url.Parse(uerr.URL); parseErr == nil {
			host = u.Host
		}
		if uerr.Err != nil {
			return fmt.Sprintf("%s %s: %s", uerr.Op, host, uerr.Err)
		}
		return fmt.Sprintf("%s %s: 알 수 없는 오류", uerr.Op, host)
	}
	// 非 *url.Error（如重定向策略返回的错误）也可能带地址，统一走脱敏。
	return redactURLsInText(err.Error())
}

// redactURLsInText 把一段文本里出现的 http(s) 地址替换成脱敏形态。
//
// 用于兜底那些拿不到结构化字段的错误（重定向策略错误、第三方库的自定义错误）。
// 只识别 http/https 前缀，按空白与引号切分——地址不会包含这两类字符。
func redactURLsInText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
			end := len(rest)
			if j := strings.IndexAny(rest, " \t\n\"'"); j >= 0 {
				end = j
			}
			b.WriteString(redactRequestTarget(rest[:end]))
			i += end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
