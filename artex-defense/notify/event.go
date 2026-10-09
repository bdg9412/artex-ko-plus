package notify

// Snapshot 是 notification_events.snapshot 这一 JSONB 列的契约。写方是 db 层的
// 漏洞落库事务，读方是 server 层的投递引擎与过滤匹配。定义放在本包是因为它是
// 「通知领域」的载荷：db 只负责序列化，不理解字段含义。
//
// 为什么冗余存漏洞字段而不在渲染时回查：漏洞事后会被改名、改级别、改状态，
// 而推送内容应当反映**事发当时**的结论——回查会得到「事后被改成 low」的
// 危险误导。另外 fan-out 与渲染因此不必 JOIN findings/tasks/assets 三张表。
type Snapshot struct {
	// 事件类型：finding_created / finding_status_changed
	Kind      string  `json:"kind"`
	FindingID int64   `json:"finding_id"`
	TaskID    int64   `json:"task_id"`
	VulnClass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`
	// 仅 kind=finding_status_changed 时非空。
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

// Item 是一条待推送的漏洞，供渠道渲染。
type Item struct {
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	// Assets 是解析后的资产展示名（如域名/IP）。由 server 层填充——
	// 本包不碰数据库，拿不到名字。
	Assets []string
	// DetailURL 是漏洞详情回链；为空表示未配 public_base_url，渲染时省略。
	DetailURL string
	// 状态变更事件专用；两项均非空时渲染成「待处理 → 已修复」。
	FromStatus string
	ToStatus   string
}

// IsStatusChange 报告该条目是否为状态变更事件。
func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

// Title 返回条目的展示标题：优先人工命名的 name，回退漏洞类型 vulnclass，
// 两者都空时用一个占位符——绝不输出空标题。
func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(이름 없는 취약점)"
}

// Message 是一次渠道发送的完整内容。
type Message struct {
	// 单条推送时长度为 1；汇总推送（digest）时为一整批。
	// 空切片是非法的，调用方须保证至少一条。
	Items []Item
	// Batch=true 时按汇总消息渲染（换标题、带上时间窗与条数）。
	Batch bool
	// WindowMinutes 是汇总周期（分钟），仅 Batch=true 时用于文案「近 N 分钟」。
	// 刻意由配置显式传入而不是渲染时算 time.Since：渲染保持确定性，才好测。
	WindowMinutes int
	// HomeURL 是平台面板地址（全局 public_base_url）；空则不带面板入口。
	HomeURL string
}
