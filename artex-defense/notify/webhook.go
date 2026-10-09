package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"
)

// webhookChannel 是通用 Webhook 适配器：用户自定 URL、方法、请求头与 JSON 模板。
// 它的存在让本功能不必为 Slack / Mattermost / Discord / 自建系统各写一个实现——
// 那些平台都能被一个可配模板覆盖。
type webhookChannel struct{}

func (webhookChannel) Kind() string { return KindWebhook }

// 通用 Webhook 没有官方限制，返回 0 表示默认不限流，由使用者按对端能力自定。
func (webhookChannel) DefaultRatePerMin() int { return 0 }

// 掩码 url 与 headers：目标地址本身常带 token，自定义头里通常放着鉴权凭据，
// 两者都会出现在接口回显里，所以都要挡。
// 代价是编辑时若想改动其中一个头，需要重新填整组头（掩码值会被解释为「保持原值」）——
// 这个取舍是刻意的：宁可多填一次，也不把凭据回显到浏览器。
func (webhookChannel) SecretKeys() []string { return []string{"url", "headers"} }

// 目的地是 url。改 url 时必须重新表态 headers —— 否则原始 Authorization 头
// 会被原样发到新地址，这正是掩码绕过的主路径。
func (webhookChannel) DestinationKeys() []string { return []string{"url"} }

// webhookDefaultTemplate 是未填模板时的兜底请求体：一个直白的 JSON 结构，
// 覆盖绝大多数「收一条 JSON 入库」的自建接收端。
const webhookDefaultTemplate = `{
  "title": {{json .Title}},
  "batch": {{.Batch}},
  "count": {{.Count}},
  "items": [
{{- range $i, $it := .Items}}
{{- if $i}},{{end}}
    {
      "finding_id": {{$it.FindingID}},
      "name": {{json $it.Name}},
      "vulnclass": {{json $it.VulnClass}},
      "severity": {{json $it.Severity}},
      "summary": {{json $it.Summary}},
      "assets": {{json $it.Assets}},
      "detail_url": {{json $it.DetailURL}}
    }
{{- end}}
  ]
}`

// webhookTemplateData 是暴露给用户模板的上下文。
type webhookTemplateData struct {
	Title   string
	Batch   bool
	Count   int
	Items   []webhookItem
	HomeURL string
	// SentAt 是本次投递时间（RFC3339），供接收端记录。
	SentAt string
}

type webhookItem struct {
	FindingID     int64
	Name          string
	VulnClass     string
	Severity      string
	SeverityLabel string
	Summary       string
	Assets        []string
	DetailURL     string
	FromStatus    string
	ToStatus      string
	// StatusLabel 是状态变更的可读描述，如「待处理 → 已修复」；非状态变更时为空。
	StatusLabel string
}

func (webhookChannel) Validate(cfg map[string]any) error {
	raw := cfgString(cfg, "url")
	if raw == "" {
		return errors.New("대상 URL이 없습니다")
	}
	if err := validateHTTPURL(raw); err != nil {
		return fmt.Errorf("대상 URL이 올바르지 않습니다: %w", err)
	}
	if m := strings.ToUpper(cfgString(cfg, "method")); m != "" && m != http.MethodGet && m != http.MethodPost && m != http.MethodPut && m != http.MethodPatch {
		return fmt.Errorf("지원하지 않는 메서드입니다: %s (GET/POST/PUT/PATCH 중에서 선택하세요)", m)
	}
	if tpl := cfgString(cfg, "body_template"); tpl != "" {
		if _, err := parseWebhookTemplate(tpl); err != nil {
			return fmt.Errorf("요청 본문 템플릿 문법이 올바르지 않습니다: %w", err)
		}
	}
	return nil
}

func (c webhookChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	method := strings.ToUpper(cfgString(cfg, "method"))
	if method == "" {
		method = http.MethodPost
	}

	// GET 不带请求体：把内容塞进 query 超出模板能力范围，也不符合 GET 语义，
	// 所以 GET 只适合「命中即触发钩子」这类接收端。
	var payload any
	if method != http.MethodGet {
		body, err := renderWebhookBody(cfgString(cfg, "body_template"), m)
		if err != nil {
			return 0, Permanent(err)
		}
		// 模板渲染出的是字符串形式的 JSON，这里转成 json.RawMessage 原样发出，
		// 避免二次转义把用户精心构造的结构套进一个 JSON 字符串里。
		if !json.Valid([]byte(body)) {
			return 0, Permanent(errors.New("요청 본문 템플릿의 렌더링 결과가 올바른 JSON이 아닙니다"))
		}
		payload = json.RawMessage(body)
	}

	headers := cfgMap(cfg, "headers")
	if ct := cfgString(cfg, "content_type"); ct != "" {
		// 允许覆盖，但放在 headers 之后应用，保证显式配置优先。
		if headers == nil {
			headers = map[string]string{}
		}
		headers["Content-Type"] = ct
	}
	if _, err := doJSON(ctx, method, cfgString(cfg, "url"), headers, payload); err != nil {
		return 0, err
	}
	// 通用 Webhook 不截断正文（接收端是用户自己的服务，体积由 body_template 决定），
	// 因此整批都算送达。
	return len(m.Items), nil
}

// renderWebhookBody 用用户模板（或默认模板）渲染请求体。
func renderWebhookBody(tpl string, m Message) (string, error) {
	if strings.TrimSpace(tpl) == "" {
		tpl = webhookDefaultTemplate
	}
	t, err := parseWebhookTemplate(tpl)
	if err != nil {
		return "", fmt.Errorf("요청 본문 템플릿 문법이 올바르지 않습니다: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, newWebhookTemplateData(m)); err != nil {
		return "", fmt.Errorf("요청 본문 템플릿을 렌더링하지 못했습니다: %w", err)
	}
	return buf.String(), nil
}

// parseWebhookTemplate 解析模板。
//
// missingkey=zero 让缺失的 map 键渲染成零值而不是报错——但本文件的上下文是结构体，
// 主要作用是让 .Items 为空时 range 不出错。真正需要防的是 .Items 为 nil。
func parseWebhookTemplate(tpl string) (*template.Template, error) {
	return template.New("body").Funcs(webhookTemplateFuncs).Option("missingkey=zero").Parse(tpl)
}

// webhookTemplateFuncs 是暴露给模板的辅助函数。
var webhookTemplateFuncs = template.FuncMap{
	// json 把任意值序列化成 JSON。
	//
	// 这个函数不是锦上添花而是必需的：省去它，用户只能写 {{.Title}} 直接插值，
	// 而漏洞标题里只要有引号或换行，整段请求体就不再是合法 JSON——接收端会
	// 拒收，且报错信息指向「JSON 解析失败」，完全联想不到是标题里有个引号。
	"json": func(v any) (string, error) {
		raw, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	},
	// jsons 用于把 JSON 片段嵌进另一段 JSON 字符串值内部（做一层字符串转义）。
	"jsons": func(v any) (string, error) {
		raw, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		quoted, err := json.Marshal(string(raw))
		if err != nil {
			return "", err
		}
		// 去掉外层引号：调用方自己决定要不要加引号。
		return string(quoted[1 : len(quoted)-1]), nil
	},
}

func newWebhookTemplateData(m Message) webhookTemplateData {
	d := webhookTemplateData{
		Title:   markdownTitle(m),
		Batch:   m.Batch,
		Count:   len(m.Items),
		HomeURL: m.HomeURL,
		SentAt:  time.Now().Format(time.RFC3339),
		Items:   make([]webhookItem, 0, len(m.Items)),
	}
	for _, it := range m.Items {
		wi := webhookItem{
			FindingID:     it.FindingID,
			Name:          it.Name,
			VulnClass:     it.VulnClass,
			Severity:      it.Severity,
			SeverityLabel: SeverityLabel(it.Severity),
			Summary:       it.Summary,
			Assets:        append([]string{}, it.Assets...),
			DetailURL:     it.DetailURL,
			FromStatus:    it.FromStatus,
			ToStatus:      it.ToStatus,
		}
		if it.IsStatusChange() {
			wi.StatusLabel = StatusLabel(it.FromStatus) + " → " + StatusLabel(it.ToStatus)
		}
		d.Items = append(d.Items, wi)
	}
	return d
}
