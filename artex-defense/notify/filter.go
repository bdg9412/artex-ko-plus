package notify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Filter 是 notification_channels.filter 这一 JSONB 列的契约：渠道实例的过滤条件。
// 所有字段都可选，缺省即「不过滤」——这正是畸形配置的兜底语义，见 ParseFilter。
type Filter struct {
	// MinSeverity 是最低级别门槛（low/medium/high/critical），空=不设门槛。
	MinSeverity string `json:"min_severity"`
	// TaskIDs / AssetIDs 为空数组表示不限；非空则要求事件与它有交集。
	TaskIDs  []int64 `json:"task_ids"`
	AssetIDs []int64 `json:"asset_ids"`
	// VulnClassInclude 为空表示全收；非空则要求 vulnclass 命中其中任一关键词。
	// VulnClassExclude 命中任一关键词即排除（排除优先于包含）。
	// 匹配方式为大小写不敏感的子串——比正则安全：用户配错正则不会让渠道静默失效。
	VulnClassInclude []string `json:"vulnclass_include"`
	VulnClassExclude []string `json:"vulnclass_exclude"`
	// OnStatusChange 决定该渠道是否接收漏洞状态变更事件（仅 realtime 模式有意义）。
	OnStatusChange bool `json:"on_status_change"`
}

// ParseFilter 解析渠道过滤配置。
//
// **永不返回 error。** 这是刻意的设计选择：过滤条件配置畸形时一律退化为零值
// Filter（= 不过滤 = 全部命中），因为对一个漏洞通知系统来说，**多推一条远好过
// 静默漏掉一条高危**。让解析失败变成「不推送」，等于给用户一个看起来配好了、
// 实际什么都不推的渠道——这是最糟的失败模式。
func ParseFilter(raw []byte) Filter {
	var f Filter
	if len(raw) == 0 {
		return f
	}
	// 解析失败时 f 保持零值，即不过滤。
	_ = json.Unmarshal(raw, &f)
	return f
}

// ValidMinSeverity 报告 s 是否为合法的级别门槛（空串表示不设门槛）。
func ValidMinSeverity(s string) bool {
	if s == "" {
		return true
	}
	_, ok := severityRank[s]
	return ok
}

// Validate 校验过滤配置里**取值受限**的字段，供保存渠道时调用。
//
// 为什么必须在写入时拦：Match 对未知门槛的判定是 `rank >= 0`，恒为真——
// 也就是说 min_severity 打错一个字（"hgih"），过滤器会**静默失效**变成
// 「全推」。这与本包「宁可多推不可漏推」的取舍方向一致（不会漏），
// 但后果是用户以为自己在做分级推送、实际把全部漏洞灌进群里，
// 而且没有任何迹象提示他配错了。这类「静默降级」正应该在入口处拦掉。
//
// 注意 Validate 只用于**写入**路径。读取路径仍走 ParseFilter 的宽容语义，
// 这样历史数据里已经存在的坏值不会让渠道整个读不出来。
func (f Filter) Validate() error {
	if !ValidMinSeverity(f.MinSeverity) {
		return fmt.Errorf("올바르지 않은 최소 심각도입니다: %q. low / medium / high / critical 중에서 선택하거나, 비워 두면 제한하지 않습니다", f.MinSeverity)
	}
	return nil
}

// Match 判定一个事件是否应投递到带有该过滤条件的渠道。
//
// **永不返回 error**，理由同 ParseFilter：任何内部异常都按「命中」处理。
// 判定顺序：事件类型 → 级别门槛 → 任务/资产范围 → 漏洞类型关键词。
func Match(f Filter, s Snapshot) bool {
	// 状态变更事件只有显式开启的渠道才接收。默认关，因为绝大多数使用者
	// 期望「推送」指的是「发现新漏洞」，而不是流水账式地跟进每个状态流转。
	if s.Kind == EventFindingStatusChanged && !f.OnStatusChange {
		return false
	}
	if !AtLeast(s.Severity, f.MinSeverity) {
		return false
	}
	if len(f.TaskIDs) > 0 && !slices.Contains(f.TaskIDs, s.TaskID) {
		return false
	}
	if len(f.AssetIDs) > 0 && !intersectsInt(f.AssetIDs, s.AssetIDs) {
		return false
	}
	// 排除优先：命中任一排除关键词即出局，即便同时命中了包含列表。
	if len(f.VulnClassExclude) > 0 && containsAnyFold(s.VulnClass, f.VulnClassExclude) {
		return false
	}
	if len(f.VulnClassInclude) > 0 && !containsAnyFold(s.VulnClass, f.VulnClassInclude) {
		return false
	}
	return true
}

func intersectsInt(a, b []int64) bool {
	// 小集合线性扫描即可；两边的量级都是「人手勾选的几十个」，
	// 建 map 的开销大于收益。
	for _, v := range b {
		if slices.Contains(a, v) {
			return true
		}
	}
	return false
}

// containsAnyFold 报告 s 是否包含 keywords 中任一关键词（大小写不敏感）。
func containsAnyFold(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
