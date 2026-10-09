package notify

import (
	"fmt"
	"strings"
)

// 本文件是「Markdown 系」渠道（钉钉、企业微信）共用的消息渲染。
// 飞书用卡片 JSON、Telegram 用 HTML、邮件用 HTML，各自在适配器里渲染。

// maxAssetsShown 是消息里最多列出几个资产。一个漏洞可能锚定几十个资产，
// 全列会挤爆消息且没有信息价值——第 4 个之后的域名没人会在 IM 里看。
const maxAssetsShown = 3

// maxSummaryRunes 是摘要被压缩到多少字符。IM 消息是「提示去看详情」，
// 不是报告本体，完整内容在平台里。
const maxSummaryRunes = 120

// markdownReservedBytes 预留给消息头部（汇总行 + 级别分布 + 可能的截断提示）
// 与尾部（平台链接）。按整条打包时把这部分从预算里扣掉，保证头尾不会被截掉——
// 头尾一旦被截，读者连「这是哪一批、还有多少条没显示」都看不出来。
const markdownReservedBytes = 320

// markdownEscape 转义 markdown 元字符。
//
// 为什么必须做：漏洞标题、摘要、类型、资产展示名全都来自**不可信来源**——
// 标题与摘要出自模型输出（模型读的是被测目标的响应），资产的 url 则是扫描
// 得到的完整 URL（含目标可控的查询串）。不转义的话，一条标题为
//
//	登录口 SQL 注入\n[紧急：点此验证账号](http://attacker.tld)
//
// 的漏洞会在安全工程师的钉钉/飞书里渲染成**可点击的外链**；而
// `![](http://attacker.tld/beacon)` 会在渲染时被客户端拉取，等于通报了
// 「这条漏洞已经被看过」并泄露阅读者 IP。就算是无恶意的内容，注入的粗体或
// 引用块也能把下面的严重漏洞挤出折叠线。
//
// 转义集合覆盖标题/链接/强调/列表/引用/删除线这几类会改变结构或产生可点击
// 元素的字符。`\` 必须最先处理，否则会把后面补上的反斜杠再次转义。
func markdownEscape(s string) string {
	replacer := strings.NewReplacer(
		`\`, `\\`,
		"`", "\\`",
		"*", `\*`,
		"_", `\_`,
		"[", `\[`,
		"]", `\]`,
		"(", `\(`,
		")", `\)`,
		"!", `\!`,
		"#", `\#`,
		">", `\>`,
		"|", `\|`,
		"~", `\~`,
	)
	return replacer.Replace(s)
}

// markdownText 把不可信文本压成单行并转义，供 markdown 正文使用。
// 单行化是转义之外的另一半：换行本身就能伪造出新的列表项或引用块，
// 而转义字符挡不住它。
func markdownText(s string, maxRunes int) string {
	return markdownEscape(OneLine(s, maxRunes))
}

// markdownTitle 返回消息标题（IM 平台的标题栏/卡片标题），内容是**未转义的原文**。
//
// 这里刻意不做转义：这个标题被四种语境的渲染器共用——markdown 正文、Telegram 的
// HTML、飞书卡片的 plain_text、以及通用 Webhook 的 JSON 与邮件主题。每个语境的
// 转义规则都不同（markdown 转义塞进 HTML 会留下可见的反斜杠，塞进 JSON 会污染
// 数据），所以转义必须由各自的输出端负责，见 writeItem / feishuItemLines /
// telegramEscape。曾经在共享函数里加过 markdown 转义，结果 Telegram 消息里
// 出现了 `\(1\)` 这种可见的反斜杠。
func markdownTitle(m Message) string {
	if m.Batch {
		return fmt.Sprintf("취약점 요약 · 총 %d건", len(m.Items))
	}
	if len(m.Items) == 0 {
		return "취약점 알림"
	}
	it := m.Items[0]
	return fmt.Sprintf("[%s] %s", SeverityLabel(it.Severity), OneLine(it.Title(), 0))
}

// markdownBody 渲染消息正文，返回正文与**实际写入的条目数**。
//
// 返回值 kept 是这次投递真正送达的条目数，调用方据此只把前 kept 条标记为
// 已送达——被渠道长度上限挡在外面的条目必须留待下一批，而不是跟着一起被
// 标记成功。这正是「静默丢失」的来源：消息被截断了，但投递记录显示全部送达，
// 没有任何地方能看出后半截从未发出。
//
// maxBytes<=0 表示不限制。
func markdownBody(m Message, maxBytes int) (string, int) {
	if !m.Batch {
		if len(m.Items) == 0 {
			return "", 0
		}
		var b strings.Builder
		writeItem(&b, m.Items[0], "", true)
		// 单条消息即使超长也照发（由最终截断兜底）：一条漏洞的部分信息
		// 也好过一条都不发。
		return TruncateBytes(b.String(), maxBytes), 1
	}

	footer := ""
	if m.HomeURL != "" {
		footer = fmt.Sprintf("\n[플랫폼에서 전체 보기](%s)\n", m.HomeURL)
	}
	kept := packItemCount(m.Items, maxBytes, markdownReservedBytes, footer, byteSize, func(it Item, idx int) string {
		var b strings.Builder
		writeItem(&b, it, fmt.Sprintf("%d. ", idx+1), false)
		return b.String()
	})

	items := m.Items[:kept]
	var b strings.Builder
	b.WriteString(markdownBatchIntro(m, items, len(m.Items)))
	for i, it := range items {
		writeItem(&b, it, fmt.Sprintf("%d. ", i+1), false)
	}
	b.WriteString(footer)
	return TruncateBytes(b.String(), maxBytes), kept
}

// markdownBatchIntro 渲染汇总消息的开头：时间窗、条数与级别分布。
// 有了这些，收到汇总的人不用点进平台就能判断这批需不需要立刻处理。
//
// items 是**实际装下**的条目，total 是本批应有的总数。两者不同时必须明说
// 「还有多少条在下一条消息里」——否则读者会以为消息头写的那个数字就是全部，
// 而后面那些从未发出的条目在界面上完全不存在。
func markdownBatchIntro(m Message, items []Item, total int) string {
	var b strings.Builder
	if m.WindowMinutes > 0 {
		fmt.Fprintf(&b, "**최근 %d분간 신규 취약점 %d건**", m.WindowMinutes, total)
	} else {
		fmt.Fprintf(&b, "**신규 취약점 %d건**", total)
	}
	if extra := total - len(items); extra > 0 {
		fmt.Fprintf(&b, "(이 메시지에는 앞 %d건만 표시하며, 나머지 %d건은 다음 메시지에서 이어서 보냅니다)", len(items), extra)
	}
	// 按级别给出分布，让读者一眼看到有没有严重项。只统计**本条实际包含**的
	// 条目，保证「严重 3」和下面能数出来的条目一致。
	counts := map[string]int{}
	for _, it := range items {
		counts[it.Severity]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", SeverityLabel(sev), n))
		}
	}
	if len(parts) > 0 {
		b.WriteString("\n" + strings.Join(parts, " · "))
	}
	b.WriteString("\n\n")
	return b.String()
}

// writeItem 渲染单个漏洞条目。
//
// prefix 用于汇总列表的序号；single=true 时渲染完整版（含摘要与回链），
// 汇总列表里只渲染一行摘要——否则 50 条汇总会变成一篇长文档。
//
// 所有来自外部的内容（标题/类型/资产/摘要）都过 markdownText：
// 单行化 + 转义。回链是管理员配置的 public_base_url 拼出来的，不是不可信内容，
// 且必须是可点的链接，所以原样输出。
func writeItem(b *strings.Builder, it Item, prefix string, single bool) {
	line := fmt.Sprintf("%s**%s · %s**", prefix, SeverityLabel(it.Severity), markdownText(it.Title(), 0))
	if !single {
		// 汇总模式：单行呈现，资产与摘要压缩后跟在后面。
		var extras []string
		if a := assetLine(it.Assets, maxAssetsShown); a != "" {
			extras = append(extras, markdownText(a, 0))
		}
		if it.Summary != "" {
			extras = append(extras, markdownText(it.Summary, 60))
		}
		if len(extras) > 0 {
			line += " — " + strings.Join(extras, " · ")
		}
		b.WriteString(line + "\n")
		return
	}
	b.WriteString(line + "\n")
	if it.IsStatusChange() {
		fmt.Fprintf(b, "**상태 변경**: %s → %s\n",
			markdownText(StatusLabel(it.FromStatus), 0), markdownText(StatusLabel(it.ToStatus), 0))
	}
	if it.VulnClass != "" && it.VulnClass != it.Title() {
		fmt.Fprintf(b, "**유형**: %s\n", markdownText(it.VulnClass, 0))
	}
	if a := assetLine(it.Assets, maxAssetsShown); a != "" {
		fmt.Fprintf(b, "**자산**: %s\n", markdownText(a, 0))
	}
	if it.Summary != "" {
		if s := markdownText(it.Summary, maxSummaryRunes); s != "" {
			fmt.Fprintf(b, "**개요**: %s\n", s)
		}
	}
	if it.DetailURL != "" {
		fmt.Fprintf(b, "[상세 보기](%s)\n", it.DetailURL)
	}
}
