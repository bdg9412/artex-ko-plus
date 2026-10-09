package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// emailDialTimeout / emailSessionTimeout 分别约束建连与整段 SMTP 会话。
// net/smtp 自身没有任何超时机制，不设这两道的话，一个卡住的对端会让
// 投递 goroutine 永久挂在那里——而 dispatcher 是单 goroutine 串行处理的，
// 等于整个通知系统停摆。
const (
	emailDialTimeout    = 10 * time.Second
	emailSessionTimeout = 45 * time.Second
)

// emailChannel 实现 SMTP 邮件投递。
type emailChannel struct{}

func (emailChannel) Kind() string { return KindEmail }

// 邮件没有平台限流，但不该用它刷屏；给一个宽松的默认值。
func (emailChannel) DefaultRatePerMin() int { return 60 }

// 只掩码密码。SMTP 主机、账号、收件人都不算秘密，掩码它们只会让编辑变麻烦。
func (emailChannel) SecretKeys() []string { return []string{"password"} }

// host/port 决定把密码交给哪台服务器；tls 决定是否加密传输。三者任一变化都
// 要求重新表态密码——顺带让「关掉 TLS」这一步必须显式带上凭据，而不是顺手一改。
func (emailChannel) DestinationKeys() []string { return []string{"host", "port", "tls"} }

func (emailChannel) Validate(cfg map[string]any) error {
	if cfgString(cfg, "host") == "" {
		return errors.New("SMTP 서버 주소가 없습니다")
	}
	port := cfgInt(cfg, "port")
	if port <= 0 || port > 65535 {
		return errors.New("SMTP 포트가 올바르지 않습니다 (1-65535 범위여야 합니다)")
	}
	if cfgString(cfg, "from") == "" {
		return errors.New("발신자 주소가 없습니다")
	}
	if len(cfgStrings(cfg, "to")) == 0 {
		return errors.New("수신자 주소가 최소 하나 필요합니다")
	}
	return nil
}

func (c emailChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	host := cfgString(cfg, "host")
	port := cfgInt(cfg, "port")
	from := cfgString(cfg, "from")
	to := cfgStrings(cfg, "to")
	username := cfgString(cfg, "username")
	password := cfgString(cfg, "password")
	implicitTLS := cfgBool(cfg, "tls")

	msg, err := buildEmailMessage(from, to, m)
	if err != nil {
		return 0, Permanent(err)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	client, err := emailDial(ctx, addr, host, implicitTLS)
	if err != nil {
		return 0, err
	}
	defer client.Close()

	// STARTTLS：对端支持就升级。明文会话下不能发凭据（见下面的 auth 说明）。
	if !implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
				return 0, fmt.Errorf("STARTTLS 실패: %w", err)
			}
		}
	}
	if username != "" {
		if err := client.Auth(smtp.PlainAuth("", username, password, host)); err != nil {
			// smtp.PlainAuth 会拒绝在未加密连接上发送凭据（除非目标是 localhost）。
			// 这是**正确**的安全行为，不能绕过，但需要把原因翻译清楚——
			// 否则使用者只会看到「unencrypted connection」而不知道该怎么办。
			if strings.Contains(err.Error(), "unencrypted connection") {
				return 0, Permanent(fmt.Errorf("자격 증명 전송을 거부했습니다: 연결이 암호화되지 않았습니다. TLS 를 켜거나, 465 포트(암시적 TLS)를 사용하거나, 「TLS 사용」을 체크하세요 (%w)", err))
			}
			return 0, Permanent(fmt.Errorf("SMTP 인증 실패: %w", err))
		}
	}
	if err := client.Mail(from); err != nil {
		return 0, smtpStageError(fmt.Sprintf("발신자 %s 주소가 거부되었습니다", from), err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return 0, smtpStageError(fmt.Sprintf("수신자 %s 주소가 거부되었습니다", rcpt), err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return 0, fmt.Errorf("SMTP DATA 실패: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return 0, fmt.Errorf("메일 본문 쓰기 실패: %w", err)
	}
	if err := w.Close(); err != nil {
		return 0, fmt.Errorf("메일 제출 실패: %w", err)
	}
	// Quit 失败不影响「邮件已被服务器接收」这个事实，因此忽略其错误。
	_ = client.Quit()
	// 邮件没有长度截断（HTML 正文全部发送），整批都算送达。
	return len(m.Items), nil
}

// emailDial 建立 SMTP 连接。
//
// implicitTLS=true 走 465 这类「连上即 TLS」的方式；false 走 25/587 明文建连后再
// STARTTLS。两者不能混：对 465 端口发明文 greeting 会被直接断开。
//
// 会话期限在**建连处**就设好（而非事后补设），因为 net/smtp 的 Client 把底层
// 连接藏在未导出字段里，外部拿不到它；连接一旦交出去就只能靠预先设置的 deadline
// 兜底。这也顺带覆盖了握手阶段的阻塞。
// Control 挂 blockInternalDial 与 HTTP 系渠道共用同一道守卫。不挂的话 SMTP
// 就是整套 SSRF 防护的缺口：host 填 169.254.169.254 或 127.0.0.1 能直接连上，
// 而 smtp.NewClient 握手失败时会把对端返回的那一行包进错误、经 last_error
// 由投递历史接口回显，构成半盲读原语；「连接被拒 vs 超时」的耗时差异还能
// 用来探测端口。拨号阶段是最终生效点，也覆盖 DNS 重绑定。
func emailDial(ctx context.Context, addr, host string, implicitTLS bool) (*smtp.Client, error) {
	d := &net.Dialer{Timeout: emailDialTimeout, Control: blockInternalDial}
	var conn net.Conn
	var err error
	if implicitTLS {
		conn, err = tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("SMTP 서버 연결 실패: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(emailSessionTimeout))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SMTP 핸드셰이크 실패: %w", err)
	}
	return client, nil
}

// smtpStageError 按 SMTP 应答码把某个阶段的失败分成「可重试」与「永久失败」。
//
// 为什么必须区分：SMTP 的 4xx 与 5xx 语义完全不同——
//   - 4xx（450 灰名单、451 本地错误、452 存储不足）是**临时**拒绝，
//     正规做法是稍后重试；尤其是灰名单，几乎每次首次投递都会遇到。
//   - 5xx（550 用户不存在、553 地址非法）是永久拒绝，重试没有意义。
//
// 若一律判永久失败，一个启用灰名单的邮件服务器会让**每一条**推送都在第一次
// 尝试后落入 failed——而这类失败恰恰是自动重试最该发挥作用的场景。
// 应答码取错误文本的前三位数字；取不到码时按可重试处理（宁可多试一次，
// 也不要因为解析不出就把可能的瞬时故障判死）。
func smtpStageError(what string, err error) error {
	code := smtpReplyCode(err.Error())
	if code >= 500 && code < 600 {
		return Permanent(fmt.Errorf("%s: %w", what, err))
	}
	return fmt.Errorf("%s: %w", what, err)
}

// smtpReplyCode 从 SMTP 错误文本里取前导的三位应答码，取不到返回 0。
// net/smtp 不导出错误码字段，只能从文本里取；格式为「450 4.7.1 ...」。
func smtpReplyCode(text string) int {
	if len(text) < 3 {
		return 0
	}
	n, err := strconv.Atoi(text[:3])
	if err != nil {
		return 0
	}
	return n
}

// buildEmailMessage 组装完整的 RFC 5322 邮件。
//
// 正文用 base64 编码有两个原因：一是 SMTP 规定单行不超过 1000 字节，而 HTML
// 正文（尤其汇总邮件）很容易出现超长行；二是 base64 天然不会出现以 "." 开头
// 的行，省去 SMTP 点号转义的麻烦。
func buildEmailMessage(from string, to []string, m Message) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	// 中文主题必须做 RFC 2047 编码，否则会被客户端显示成乱码。
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", htmlTitle(m)))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	// 邮件没有长度硬上限，因此不截断正文。
	b.WriteString("\r\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(htmlBody(m, 0)))
	// base64 按 76 字符折行，符合 RFC 2045。
	for len(encoded) > 76 {
		b.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded + "\r\n")
	return b.String(), nil
}
