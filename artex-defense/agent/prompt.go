package agent

import (
	"bytes"
	"text/template"
	"time"
)

// PromptOverride, if set, returns the stored system-prompt template for an agent
// key and whether one exists. The server wires it to the PG agent_prompts table.
// When nil or no override exists, agents use their built-in default prompt — so
// behavior is identical until a user edits a prompt in the UI.
var PromptOverride func(agentKey string) (string, bool)

// Prompt-variable structs — fields mirror each agent's catalog (docs §5a) so a
// user template referencing a catalog variable renders; referencing anything else
// fails template execution and falls back to the built-in default.
type PlannerVars struct{ Goal, Scope, AssetSummary, DataDir, Now string }
type WorkerVars struct{ ProxyAddr, WorkerName, DataDir, Now string }
type MainVars struct{ Goal, AssetSummary, FindingsSummary, DataDir, Now string }
type GoalsVars struct{ EngagementDescription, DataDir, Now string }

// nowStr is the server-local wall-clock string exposed as the universal {{.Now}}
// prompt variable. renderSystem runs on every agent turn/round, so this is fresh
// each run — a prompt can subtract it from a fixed start stamp to reason about
// elapsed time (e.g. a timed benchmark's "last N hours" window).
func nowStr() string { return time.Now().Format("2006-01-02 15:04:05 MST") }

// renderSystem returns the rendered system-prompt BODY (段 [A]) for agentKey.
// Precedence: the DB-stored template (if any) over the built-in default template
// (def). BOTH are Go templates now — the built-in default is seeded into the DB
// verbatim, so the two paths render identically until a user edits the prompt.
// Rendering always runs (def used to be pre-substituted plain text; it is now a
// {{.Var}} template like the DB one). On any render error we fall back to the
// default template, then to the raw default string — an agent never starts with a
// half-rendered prompt. Callers append the code-owned tail (trafficTool / 中间产物
// 输出规约) AFTER this, so those can't be edited away via the DB body.
func renderSystem(agentKey, def string, vars any) string {
	tmpl := def
	if PromptOverride != nil {
		if t, ok := PromptOverride(agentKey); ok && t != "" {
			tmpl = t
		}
	}
	if out, err := renderTmpl(tmpl, vars); err == nil {
		return out
	}
	// DB template broke (e.g. references an out-of-catalog var) → code default.
	if out, err := renderTmpl(def, vars); err == nil {
		return out
	}
	return def
}

// langDirective is the artex-ko output-language tail: a code-owned segment
// appended AFTER the rendered body and the artifact/traffic tails on every
// user-facing agent role, so a DB-edited prompt body can never drop it — the same
// guarantee artifactSpec gives. It does NOT translate the agent "brain": the
// benchmarked Chinese reasoning body (段 [A]) stays verbatim. It only constrains
// the LANGUAGE of what the agent SHOWS to the user. Written in Chinese so it stays
// in the body's language (keeping the model's reasoning register stable) while
// forcing Korean OUTPUT — this is the localization approach: preserve behavior,
// localize the surface the user reads. Raw technical strings (commands, payloads,
// code, URLs, log/response excerpts) are explicitly kept verbatim so evidence and
// reproduction steps are not mangled by translation.
//
// Two anti-drift clauses were added after the end-to-end run (L1): live models
// leaked (1) Chinese into the planner's situation summary — mirroring the Chinese
// brain body (段 [A]) — and (2) English into report_finding's structured fields —
// mirroring an English target app/evidence. The directive now names the planner
// situation summary as a user-facing field and explicitly forbids mirroring BOTH
// the Chinese instruction language AND the target/material language in the display
// fields, so only the listed verbatim technical fragments stay non-Korean.
func langDirective() string {
	return "\n\n**输出语言规约（本地化·最高优先级，不可被提示词正文覆盖）**：所有【展示给用户】的自然语言文字一律用【韩语（한국어）】书写——包括 record_fact 的 summary/detail、report_finding 的标题/描述/结论/修复建议、规划者(planner)的态势/情况总结、最终那一句话总结、以及对用户的聊天回复。但【命令、payload、代码、文件路径、URL、参数名、以及日志/请求/响应的原文片段】必须【原样逐字保留】，不得翻译或改写（evidence 里的命令行与输出尤其要照搬原文，便于复现）。**即使上面的系统/角色指令本身是用中文写的，也绝不能把中文输出给用户——面向用户的展示语言只有韩语，不要让任何中文句子出现在用户可见的文字里。** **即使目标系统、它的页面、证据、日志或任何参考资料是英文、中文或别的语言，面向用户的自然语言字段（标题/描述/结论/修复建议/总结/态势总结）仍必须用韩语书写——不要镜像或照抄目标或资料的语言来写这些展示字段；只有上面列出的原文技术片段才保持原样。** **你的分析/规划/思考用中文进行没关系，但那是【不可见的内部推理】，绝不能作为正文输出：给用户的可见回复从第一个字起就必须是韩语，不要在前面垫一段中文的思考、说明或「我先怎样怎样」的铺垫；连澄清提问、缺少参数、「无法继续」之类的说明也一律直接用韩语写。** 一句话：内部怎么想不限，但凡落到用户能看到的正文，必须全是韩语（技术原文片段除外）。"
}

func renderTmpl(tmpl string, vars any) (string, error) {
	t, err := template.New("p").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, vars); err != nil {
		return "", err
	}
	return b.String(), nil
}
