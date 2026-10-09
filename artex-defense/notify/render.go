package notify

import (
	"strings"
	"unicode/utf8"
)

const ellipsis = "…"

// TruncateBytes 把 s 截断到不超过 max 字节，保证结果是合法 UTF-8 且不切断字符。
//
// 为什么必须按字符边界切：企微群机器人的 markdown 有 4096 **字节**硬上限（不是
// 字符数），而中文一个字 3 字节。直接按字节切片会把一个汉字切成两半，产出非法
// UTF-8——平台侧要么整条拒收，要么显示成乱码方块。这里的做法是先从预算位置
// 往前回退到最近的 rune 起始字节（utf8.RuneStart 判定续字节 0b10xxxxxx）。
//
// max<=0 表示不限制。截断后追加省略号，除非 max 小到装不下省略号。
func TruncateBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	budget := max - len(ellipsis)
	suffix := ellipsis
	if budget < 0 {
		// max 比省略号还短：放弃省略号，纯截断，避免结果反而超出 max。
		budget = max
		suffix = ""
	}
	cut := budget
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + suffix
}

// OneLine 把多行文本压成单行：折叠所有空白，再按字符数截断。
// 用于 IM 消息的标题行——摘要里常有换行，直接塞进表格/标题会撑坏排版。
// max<=0 表示不限制长度。
func OneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	return TruncateRunes(s, max)
}

// TruncateRunes 把 s 截断到不超过 max 个字符（而非字节），超出时追加省略号。
// max<=0 表示不限制。
//
// 与 TruncateBytes 的区别在于平台口径：企微按字节限长，Telegram 按字符数限长。
// 用错口径不会报错，只会让消息被切得远比预期短（中文 1 字 = 3 字节，
// 按字节切 4096 只剩约 1365 字），所以两个函数都必须保留、按渠道选用。
func TruncateRunes(s string, max int) string {
	if max <= 0 {
		return s
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max <= 1 {
		return string(runes[:max])
	}
	return string(runes[:max-1]) + ellipsis
}

// TruncateHTML 按字符数截断 HTML 片段，并保证不产生半截标签。
//
// 直接对 HTML 做字符截断会切出 `<a href="htt` 这种残缺标签，平台解析器要么
// 报错拒收整条、要么把后续正文当成属性值吞掉。这里的做法是：先按字符截断，
// 再检查尾部是否有未闭合的 `<`，有就退到它之前。
//
// 不做标签配平（补全 </b> 之类）：Telegram 的 HTML 解析器会自动闭合未闭合标签，
// 而自己实现配平要处理属性里的引号、注释、自闭合标签，复杂度与收益不成比例。
func TruncateHTML(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	cut := TruncateRunes(s, max)
	// 尾部若是 `<` 开头的残片（最后出现 `<` 之后没有 `>`），退回 `<` 之前。
	if lt := strings.LastIndex(cut, "<"); lt >= 0 && !strings.Contains(cut[lt:], ">") {
		cut = cut[:lt]
	}
	// 尾部若是被切断的 HTML 实体（如 `&amp;` 被切成 `&amp`），同样要退回去。
	// 实体残片在一个只认实体的解析器里可能让**整条消息**被拒收——一条超过
	// 长度上限的汇总消息本来就常见，不值得为此丢掉整条通知。
	if amp := strings.LastIndex(cut, "&"); amp >= 0 && !strings.Contains(cut[amp:], ";") {
		cut = cut[:amp]
	}
	return cut
}

// packItemCount 计算在预算内能**完整**放下多少条，供汇总消息按整条打包。
//
// 为什么要按整条而不是渲染完整篇再截断：截断会让后半截条目凭空消失，
// 而它们的投递记录仍会被标记为已送达——消息里看不出来、投递历史里也看不出来，
// 漏洞就这么没了。按整条打包后，装不下的条目留在库里成为下一批，
// 调用方拿到的 kept 就是本条消息真正送达的条数。
//
// 参数：maxSize<=0 表示不限制；reserve 是给消息头部/尾部预留的量；
// size 负责计量（各平台口径不同：企微/钉钉按字节，Telegram 按字符数——
// 用错口径不会报错，只会让中文消息被压到远小于上限）；
// render 把第 idx 条渲染成它的实际文本——长度因内容而异，不能靠估算。
//
// 至少返回 1（只要还有条目）。单条极端超长时也要发出这一条、由调用方的
// 最终截断兜底，否则一条超长漏洞会把整批永久卡在原地。
func packItemCount(items []Item, maxSize, reserve int, footer string, size func(string) int, render func(Item, int) string) int {
	if maxSize <= 0 {
		return len(items)
	}
	budget := maxSize - reserve - size(footer)
	if budget < 0 {
		budget = 0
	}
	used := 0
	for i, it := range items {
		used += size(render(it, i))
		if used > budget && i > 0 {
			return i
		}
	}
	return len(items)
}

// byteSize / runeSize 是 packItemCount 的两种计量口径，命名出来避免调用处
// 出现裸的 func(s string) int 闭包，否则很难一眼看出用的是哪种口径。
func byteSize(s string) int { return len(s) }
func runeSize(s string) int { return utf8.RuneCountInString(s) }

// assetLine 把资产列表渲染成一行展示文本，超过 limit 个时省略其余并标注总数。
// 一个漏洞可能锚定几十个资产，全列出来会挤爆消息。
func assetLine(assets []string, limit int) string {
	if len(assets) == 0 {
		return ""
	}
	if limit <= 0 || len(assets) <= limit {
		return strings.Join(assets, ", ")
	}
	return strings.Join(assets[:limit], ", ") + " 등 " + itoa(len(assets)) + "개"
}

// itoa 是 strconv.Itoa 的短别名，仅用于拼接展示文本，避免到处 import strconv。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
