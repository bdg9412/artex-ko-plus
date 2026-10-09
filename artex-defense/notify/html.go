package notify

import (
	"fmt"
	"strings"
)

// 本文件渲染邮件的 HTML 正文。刻意用内联样式 + 简单表格布局而不是现代 CSS：
// 邮件客户端（尤其 Outlook 与国内企业邮箱）对 <style> 块和 flex/grid 的支持
// 差异极大，内联样式是唯一在各家都能正确显示的写法。

// htmlSeverityColor 返回级别对应的强调色，用于左侧色条与标题。
func htmlSeverityColor(severity string) string {
	switch severity {
	case "critical":
		return "#d32029"
	case "high":
		return "#e8830c"
	case "medium":
		return "#d4b106"
	case "low":
		return "#1677ff"
	default:
		return "#8c8c8c"
	}
}

// htmlTitle 返回邮件主题。
func htmlTitle(m Message) string {
	return markdownTitle(m)
}

// htmlBody 渲染邮件正文 HTML。maxRunes<=0 表示不截断。
func htmlBody(m Message, maxRunes int) string {
	var b strings.Builder
	b.WriteString(`<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;font-size:14px;color:#262626;line-height:1.6;">`)
	if m.Batch {
		b.WriteString(htmlBatchIntro(m))
		for _, it := range m.Items {
			b.WriteString(htmlItem(it, false))
		}
	} else if len(m.Items) > 0 {
		b.WriteString(htmlItem(m.Items[0], true))
	}
	if m.HomeURL != "" {
		fmt.Fprintf(&b, `<p style="margin:16px 0 0;"><a href="%s" style="color:#1677ff;">플랫폼에서 전체 보기</a></p>`, htmlEscapeAttr(m.HomeURL))
	}
	b.WriteString(`</div>`)
	return TruncateHTML(b.String(), maxRunes)
}

// htmlBatchIntro 渲染汇总邮件开头：条数与级别分布。
func htmlBatchIntro(m Message) string {
	var b strings.Builder
	if m.WindowMinutes > 0 {
		fmt.Fprintf(&b, `<h2 style="font-size:16px;margin:0 0 4px;">최근 %d분간 신규 취약점 %d건</h2>`, m.WindowMinutes, len(m.Items))
	} else {
		fmt.Fprintf(&b, `<h2 style="font-size:16px;margin:0 0 4px;">신규 취약점 %d건</h2>`, len(m.Items))
	}
	counts := map[string]int{}
	for _, it := range m.Items {
		counts[it.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf(`<span style="color:%s;font-weight:600;">%s %d</span>`,
				htmlSeverityColor(sev), htmlEscape(SeverityLabel(sev)), n))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(&b, `<p style="margin:0 0 12px;">%s</p>`, strings.Join(parts, " &middot; "))
	}
	return b.String()
}

// htmlItem 渲染单个漏洞。full=true 时含摘要与回链（单条推送），
// false 时压缩成一行（汇总列表）。
func htmlItem(it Item, full bool) string {
	color := htmlSeverityColor(it.Severity)
	var b strings.Builder
	if full {
		fmt.Fprintf(&b, `<div style="border-left:4px solid %s;padding:8px 0 8px 12px;margin-bottom:12px;">`, color)
	} else {
		fmt.Fprintf(&b, `<div style="border-left:3px solid %s;padding:4px 0 4px 10px;margin-bottom:8px;">`, color)
	}
	fmt.Fprintf(&b, `<div style="font-weight:600;">%s &middot; %s</div>`,
		htmlEscape(SeverityLabel(it.Severity)), htmlEscape(it.Title()))

	if !full {
		var extras []string
		if a := assetLine(it.Assets, maxAssetsShown); a != "" {
			extras = append(extras, htmlEscape(a))
		}
		if it.Summary != "" {
			extras = append(extras, htmlEscape(OneLine(it.Summary, 60)))
		}
		if len(extras) > 0 {
			fmt.Fprintf(&b, `<div style="color:#595959;font-size:13px;">%s</div>`, strings.Join(extras, " &middot; "))
		}
		b.WriteString(`</div>`)
		return b.String()
	}

	if it.IsStatusChange() {
		fmt.Fprintf(&b, `<div><b>상태 변경</b>: %s → %s</div>`,
			htmlEscape(StatusLabel(it.FromStatus)), htmlEscape(StatusLabel(it.ToStatus)))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		fmt.Fprintf(&b, `<div><b>유형</b>: %s</div>`, htmlEscape(it.VulnClass))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		fmt.Fprintf(&b, `<div><b>자산</b>: %s</div>`, htmlEscape(a))
	}
	if s := OneLine(it.Summary, maxSummaryRunes); s != "" {
		fmt.Fprintf(&b, `<div><b>개요</b>: %s</div>`, htmlEscape(s))
	}
	if it.DetailURL != "" {
		fmt.Fprintf(&b, `<div style="margin-top:6px;"><a href="%s" style="color:#1677ff;">상세 보기</a></div>`, htmlEscapeAttr(it.DetailURL))
	}
	b.WriteString(`</div>`)
	return b.String()
}

// htmlEscape 转义 HTML 文本内容。漏洞标题与摘要来自被测目标与模型输出，
// 是不可信内容——不转义就等于允许把任意 HTML（含外链图片）注入到邮件里。
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// htmlEscapeAttr 转义 HTML 属性值（在文本转义之外额外处理引号，
// 防止 URL 里的引号提前闭合 href 属性）。
func htmlEscapeAttr(s string) string {
	s = htmlEscape(s)
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
