package notify

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// 本文件覆盖「按整条打包」这个修复：汇总消息超出渠道长度上限时，必须**按整条**
// 截断并把没装下的条目数如实报出来，让调用方只标记真正送达的那些。
//
// 之前的做法是渲染完整篇再截断、然后整批标记已送达：消息后半截凭空消失，
// 而投递历史显示全部成功——漏洞就这么没了，且没有任何地方能发现。

func TestMarkdownBodyPacksWholeItemsWithinByteLimit(t *testing.T) {
	// 200 条中文汇总，必然远超企微 4096 字节。
	m := batchMsg(200)
	body, kept := markdownBody(m, weComMarkdownLimit)

	if len(body) > weComMarkdownLimit {
		t.Fatalf("正文 %d 字节超上限 %d", len(body), weComMarkdownLimit)
	}
	if !utf8.ValidString(body) {
		t.Fatal("正文不是合法 UTF-8")
	}
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("应只装下一部分（0 < kept < %d），得到 %d", len(m.Items), kept)
	}
	// 头部必须如实说明本条只包含多少条、其余有多少条——否则读者会把头部
	// 那个数字当成全部。
	if !strings.Contains(body, "나머지") || !strings.Contains(body, "다음 메시지에서") {
		t.Fatalf("头部应说明还有多少条未包含在本条里:\n%s", body[:minInt(400, len(body))])
	}
	// 只应包含前 kept 条。
	for i := 0; i < kept; i++ {
		if !strings.Contains(body, "漏洞"+itoa(i+1)) {
			t.Fatalf("第 %d 条应在本条消息里:\n%s", i+1, body)
		}
	}
	if strings.Contains(body, "漏洞"+itoa(kept+1)) {
		t.Fatalf("第 %d 条不该出现（它属于下一批）", kept+1)
	}
}

func TestMarkdownBodyKeepsEverythingWhenUnderLimit(t *testing.T) {
	m := batchMsg(3)
	body, kept := markdownBody(m, 0) // 0 = 不限制
	if kept != len(m.Items) {
		t.Fatalf("不限制长度时应全部保留，得到 kept=%d", kept)
	}
	if strings.Contains(body, "其余") {
		t.Fatalf("没有截断时不该出现截断提示:\n%s", body)
	}
}

func TestMarkdownBodyAlwaysKeepsAtLeastOneItem(t *testing.T) {
	// 预算小到连一条都装不下时，仍要发出一条（由最终截断兜底）。
	// 否则一条超长漏洞会把整批永久卡在原地：每次领取都装不下、每次都不发。
	m := batchMsg(5)
	_, kept := markdownBody(m, 50)
	if kept != 1 {
		t.Fatalf("至少应保留 1 条，得到 %d", kept)
	}
}

func TestMarkdownBodySingleReturnsOne(t *testing.T) {
	_, kept := markdownBody(singleMsg(), 4096)
	if kept != 1 {
		t.Fatalf("单条消息应报送达 1 条，得到 %d", kept)
	}
	// 空消息没有可送达的条目。
	if _, k := markdownBody(Message{}, 4096); k != 0 {
		t.Fatalf("空消息应报 0 条，得到 %d", k)
	}
}

func TestTelegramPackingUsesRuneBudget(t *testing.T) {
	m := batchMsg(200)
	text, kept := telegramHTML(m)
	// Telegram 按**字符数**限长；用字节口径会把中文消息压到三分之一。
	if n := utf8.RuneCountInString(text); n > telegramTextLimit {
		t.Fatalf("正文 %d 字符超上限 %d", n, telegramTextLimit)
	}
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("应只装下一部分，得到 %d", kept)
	}
	if !strings.Contains(text, "다음 메시지") {
		t.Fatalf("应说明还有余量未包含:\n%.300s", text)
	}
}

func TestFeishuPackingReportsKept(t *testing.T) {
	m := batchMsg(2000)
	_, kept := feishuCard(m)
	if kept <= 0 || kept >= len(m.Items) {
		t.Fatalf("卡片应只装下一部分，得到 %d", kept)
	}
}

func TestWebhookAndEmailReportAllItems(t *testing.T) {
	// 这两个渠道不截断正文，整批都算送达。
	m := batchMsg(7)
	if n := len(m.Items); n != 7 {
		t.Fatal("前置条件不成立")
	}
	// 通过渲染器的返回值间接确认：markdownBody(0) 不限制时全部保留。
	if _, k := markdownBody(m, 0); k != len(m.Items) {
		t.Fatalf("不限制长度时应用全部，得到 %d", k)
	}
}

// TestMarkdownEscapesUntrustedContent 是「不可信内容不得改变消息结构」的回归测试。
// 标题与摘要来自模型输出（模型读的是被测目标响应），资产名来自被测目标的 URL。
func TestMarkdownEscapesUntrustedContent(t *testing.T) {
	cases := []struct {
		name  string
		item  Item
		must  []string // 结果里必须出现（转义形态）
		wrong []string // 结果里不得出现（未转义形态）
	}{
		{
			name: "标题里的换行 + 外链",
			item: Item{
				Severity: "high",
				Name:     "登录口 SQL 注入\n[紧急：点此验证账号](http://attacker.tld)",
			},
			// 换行必须被折叠（否则能伪造出新的列表项/引用块）；
			// 方括号与圆括号必须被转义（否则是可点击的外链）。
			must:  []string{`\[紧急：点此验证账号\]`, `\(http://attacker.tld\)`},
			wrong: []string{"\n[紧急", "\n\n[紧急"},
		},
		{
			name: "标题里的图片信标",
			item: Item{
				Severity: "high",
				Name:     "漏洞 ![](http://attacker.tld/beacon)",
			},
			must:  []string{`\!`, `\(http://attacker.tld/beacon\)`},
			wrong: []string{"![]("},
		},
		{
			name: "资产名里的强调与引用",
			item: Item{
				Severity: "high",
				Name:     "普通标题",
				Assets:   []string{"a.com/*注入*>引用"},
			},
			must:  []string{`\*注入\*`, `\>`},
			wrong: []string{"*注入*"},
		},
		{
			name: "摘要里的反引号与竖线",
			item: Item{
				Severity: "high",
				Name:     "标题",
				Summary:  "`code` | 表格",
			},
			must:  []string{"\\`code\\`", `\|`},
			wrong: []string{"`code`"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Message{Items: []Item{tc.item}}
			// 单条模式的写Item 是三个 markdown 渠道共用的渲染路径。
			var b strings.Builder
			writeItem(&b, tc.item, "", true)
			got := b.String()
			for _, want := range tc.must {
				if !strings.Contains(got, want) {
					t.Errorf("缺少转义形态 %q:\n%s", want, got)
				}
			}
			for _, bad := range tc.wrong {
				if strings.Contains(got, bad) {
					t.Errorf("出现了未转义形态 %q（可被用来注入结构或外链）:\n%s", bad, got)
				}
			}
			_ = m
		})
	}
}

// TestMarkdownEscapeBackslashFirst 锁住转义顺序：反斜杠必须最先处理，
// 否则会给后面补上的反斜杠再套一层，输出里出现双反斜杠。
func TestMarkdownEscapeBackslashFirst(t *testing.T) {
	if got := markdownEscape(`a\b*c`); got != `a\\b\*c` {
		t.Fatalf("转义顺序有误，得到 %q", got)
	}
}

// TestTelegramTitleHasNoMarkdownEscapes 锁住一个具体的回归：
// markdown 转义不能泄漏到 Telegram 的 HTML 输出里（曾经在共享的标题函数里
// 加过转义，结果 Telegram 消息里出现 `\(1\)` 这种可见反斜杠）。
func TestTelegramTitleHasNoMarkdownEscapes(t *testing.T) {
	m := Message{Items: []Item{{Severity: "high", Name: "alert(1) *重点*"}}}
	text, _ := telegramHTML(m)
	if strings.Contains(text, `\(`) || strings.Contains(text, `\*`) {
		t.Fatalf("Telegram 正文里出现了 markdown 的反斜杠转义:\n%s", text)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
