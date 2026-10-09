package notify

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Channel 是一个通知渠道的适配器。实现必须**无状态**：同一个实例会被多个渠道
// 配置并发复用，凭据一律从 cfg 参数传入。
type Channel interface {
	// Kind 返回渠道类型标识，须与注册表的键一致。
	Kind() string
	// Validate 在保存配置时调用，校验必填字段与格式。返回的错误会直接展示给
	// 配置者，所以文案要说明「缺哪个字段」而不是泛泛的「配置无效」。
	Validate(cfg map[string]any) error
	// Send 投递一次消息，返回**实际送达的条目数**与错误。
	//
	// 为什么要返回条数：各平台都有消息长度上限，汇总消息装不下整批时会被截断。
	// 若调用方无条件把整批标记为已送达，被截掉的那些条目就消失了——消息里看不到、
	// 投递历史里也显示成功，没有任何地方能发现漏洞从未发出。返回 kept 后，
	// 调用方只标记前 kept 条，其余留待下一批。
	//
	// 返回错误表示投递失败，其中 *PermanentError 表示不该重试。
	// 失败时 kept 无意义，调用方应忽略它。
	Send(ctx context.Context, cfg map[string]any, m Message) (int, error)
	// DefaultRatePerMin 返回该渠道官方建议的每分钟投递上限，作为新建渠道实例
	// 时的默认限流值。返回 0 表示无已知限制。
	DefaultRatePerMin() int
	// SecretKeys 返回该渠道配置里属于凭据的键名。API 回显时这些键的值会被掩码，
	// 更新时收到掩码值则保留库中的原值。只有实现自己清楚哪些字段算凭据
	// （企业微信的整个 Webhook 地址就是凭据，而钉钉的只是其中的 secret），
	// 所以这个知识必须由渠道提供，不能由上层猜测。
	SecretKeys() []string
	// DestinationKeys 返回该渠道配置里决定「消息发往哪里」的键名。
	//
	// 与 SecretKeys 一样是安全相关的东西：目标地址与凭据是两套独立字段，
	// 若允许「只改地址、凭据原样保留」，任何能改渠道配置的人都能把库里的真凭据
	// 发到自己控制的服务器，渠道配置的掩码就完全失去意义。
	// 详见 PrepareConfigUpdate。
	DestinationKeys() []string
}

// registry 是渠道注册表。刻意用显式字面量而不是 init() 自注册：这样「有哪些渠道」
// 在一个地方就能看全，且新增渠道会在编译期暴露遗漏，而不是靠运行时副作用。
var registry = map[string]Channel{
	KindDingTalk: dingTalkChannel{},
	KindFeishu:   feishuChannel{},
	KindWeCom:    weComChannel{},
	KindWebhook:  webhookChannel{},
	KindTelegram: telegramChannel{},
	KindEmail:    emailChannel{},
}

// Get 按类型取渠道实现。
func Get(kind string) (Channel, bool) {
	c, ok := registry[kind]
	return c, ok
}

// ValidKind 报告 kind 是否为受支持的渠道类型。
func ValidKind(kind string) bool {
	_, ok := registry[kind]
	return ok
}

// Kinds 返回全部受支持的渠道类型，按字典序排列（供 UI 下拉稳定展示）。
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PermanentError 标记一个不该重试的投递失败：凭据错误、目标拒绝、请求体非法等。
// 重试只对瞬时故障（网络抖动、限流、对端 5xx）有意义；对永久失败反复退避重试
// 既不会成功，又会把真正的错误刷没在重试日志里。
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent 把 err 标记为永久失败。err 为 nil 时返回 nil，
// 方便写成 `return Permanent(someCheck())`。
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

// IsPermanent 报告 err 链上是否带有永久失败标记。
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// ---- 配置读取helper ----
//
// 渠道配置来自数据库的 JSONB 列，经 encoding/json 反序列化后是 map[string]any，
// 数值一律是 float64、数组是 []any。下面这些 helper 统一这层转换，并容忍用户
// 在 UI 里留空导致的类型偏差（如把端口填成字符串）。

// cfgString 取字符串配置项，前后空白一律裁掉——从网页表单复制粘贴很容易带上。
func cfgString(cfg map[string]any, key string) string {
	v, ok := cfg[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// cfgInt 取整数配置项，兼容 float64（JSON 默认）与字符串两种来源。
func cfgInt(cfg map[string]any, key string) int {
	switch v := cfg[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// cfgBool 取布尔配置项，兼容字符串 "true"/"1"。
func cfgBool(cfg map[string]any, key string) bool {
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

// cfgStrings 取字符串数组配置项，自动裁空白并丢弃空串。
func cfgStrings(cfg map[string]any, key string) []string {
	raw, ok := cfg[key].([]any)
	if !ok {
		// 也接受单个字符串，方便只有一个值时的表单提交。
		if s := cfgString(cfg, key); s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cfgMap 取字符串映射配置项（如自定义 HTTP 头），键值都裁空白，丢弃空键。
func cfgMap(cfg map[string]any, key string) map[string]string {
	raw, ok := cfg[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		out[k] = s
	}
	return out
}
