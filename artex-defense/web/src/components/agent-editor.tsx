"use client";

import * as React from "react";

import {
  EyeIcon,
  GitCompareIcon,
  InfoIcon,
  PencilIcon,
  RotateCcwIcon,
  SaveIcon,
  Trash2Icon,
  XIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api } from "@/lib/api";
import type {
  Agent,
  AgentDetail,
  AgentTrigger,
  MCPServer,
  PromptVar,
  PromptVersion,
  Settings,
  SkillItem,
  Tool,
} from "@/lib/types";
import { cn } from "@/lib/utils";

// Traffic tools are host tools gated by the global 流量捕获 switch: bindable, but
// only usable when capture is on. Keep this list in sync with traffic.SeedToolMetas.
const TRAFFIC_TOOL_KEYS = new Set(["traffic_search", "traffic_get"]);

// AgentEditor is the tabbed editor for one agent, used inside the agents-page
// drawer (and reused full-page for deep links). Tabs: 配置与提示词 / MCP / Skill /
// Tools. Config + prompt save as before; visibility + tool bindings toggle live.
export function AgentEditor({ agentKey, onSaved }: { agentKey: string; onSaved?: () => void }) {
  const tr = useTranslations("agentEditor");
  const [detail, setDetail] = React.useState<AgentDetail | null>(null);
  const [versions, setVersions] = React.useState<PromptVersion[]>([]);
  const [variables, setVariables] = React.useState<PromptVar[]>([]);
  const [mcp, setMcp] = React.useState<MCPServer[]>([]);
  const [skills, setSkills] = React.useState<SkillItem[]>([]);
  const [tools, setTools] = React.useState<Tool[]>([]);
  const [loaded, setLoaded] = React.useState(false);
  const [viewVer, setViewVer] = React.useState<PromptVersion | null>(null);
  const [diffVer, setDiffVer] = React.useState<PromptVersion | null>(null);

  const [prompt, setPrompt] = React.useState("");
  const [mcpVisible, setMcpVisible] = React.useState<number[]>([]);
  const [skillVisible, setSkillVisible] = React.useState<string[]>([]);
  const [preview, setPreview] = React.useState("");
  const [maxTurns, setMaxTurns] = React.useState("0");
  const [runSecs, setRunSecs] = React.useState("600");
  // "" = 跟随(未绑定)；否则为 profile id 字符串
  const [llmProfileId, setLlmProfileId] = React.useState("");
  const [llmProfiles, setLlmProfiles] = React.useState<NonNullable<AgentDetail["llm_profiles"]>>([]);
  const [webSearch, setWebSearch] = React.useState(false);
  const [interactiveShell, setInteractiveShell] = React.useState(false);
  const [wrapup, setWrapup] = React.useState("");
  const [wrapupDefault, setWrapupDefault] = React.useState("");
  const [wrapupTurns, setWrapupTurns] = React.useState("0");
  const [wrapupTurnsDefault, setWrapupTurnsDefault] = React.useState(5);
  // 任务级超时收尾词(仅 worker/planner)
  const [ttSupported, setTtSupported] = React.useState(false);
  const [ttWrapup, setTtWrapup] = React.useState("");
  const [ttWrapupDefault, setTtWrapupDefault] = React.useState("");
  const [ttTurns, setTtTurns] = React.useState("0");
  const [ttTurnsDefault, setTtTurnsDefault] = React.useState(5);
  const [settings, setSettings] = React.useState<Settings | null>(null);

  React.useEffect(() => {
    api
      .mcpServers()
      .then(setMcp)
      .catch(() => {
        /* 조회 실패는 무시하고 기본 상태를 유지한다 */
      });
    api
      .skills()
      .then(setSkills)
      .catch(() => {
        /* 조회 실패는 무시하고 기본 상태를 유지한다 */
      });
    api
      .tools()
      .then(setTools)
      .catch(() => {
        /* 조회 실패는 무시하고 기본 상태를 유지한다 */
      });
    api
      .settings()
      .then(setSettings)
      .catch(() => {
        /* 조회 실패는 무시하고 기본 상태를 유지한다 */
      });
  }, []);
  // global gates: traffic tools need 流量捕获, web search needs the master switch.
  const captureOn = !!settings?.traffic_capture;
  const webSearchGlobalOn = !!settings?.web_search_enabled;

  const reload = React.useCallback(() => {
    api
      .getAgent(agentKey)
      .then((d) => {
        setDetail(d);
        setPrompt(d.prompt ?? "");
        setVariables(d.variables ?? []);
        setVersions(d.versions ?? []);
        setMcpVisible(d.visibility?.mcp ?? []);
        setSkillVisible(d.visibility?.skill ?? []);
        setMaxTurns(String(d.agent?.max_turns ?? 0));
        setRunSecs(String(d.agent?.run_seconds ?? 600));
        setLlmProfileId(d.agent?.llm_profile_id != null ? String(d.agent.llm_profile_id) : "");
        setLlmProfiles(d.llm_profiles ?? []);
        setWebSearch(!!d.agent?.web_search);
        setInteractiveShell(!!d.agent?.interactive_shell);
        setWrapup(d.wrapup_prompt ?? "");
        setWrapupDefault(d.wrapup_default ?? "");
        setWrapupTurns(String(d.wrapup_max_turns ?? 0));
        setWrapupTurnsDefault(d.wrapup_max_turns_default ?? 5);
        setTtSupported(!!d.task_timeout_wrapup_supported);
        setTtWrapup(d.task_timeout_wrapup_prompt ?? "");
        setTtWrapupDefault(d.task_timeout_wrapup_default ?? "");
        setTtTurns(String(d.task_timeout_wrapup_max_turns ?? 0));
        setTtTurnsDefault(d.task_timeout_wrapup_max_turns_default ?? 5);
      })
      .catch(() => setDetail(null))
      .finally(() => setLoaded(true));
  }, [agentKey]);
  React.useEffect(() => {
    reload();
  }, [reload]);

  async function doPreview() {
    try {
      const r = await api.previewAgentPrompt(agentKey, prompt);
      setPreview(r.error ? tr("preview.renderError", { error: r.error }) : r.rendered);
    } catch (e) {
      setPreview(tr("preview.failed", { error: (e as Error).message }));
    }
  }
  async function savePrompt() {
    try {
      const r = await api.saveAgentPrompt(agentKey, prompt);
      toast.success(tr("toast.savedVersion", { version: r.version }));
      reload();
      onSaved?.();
    } catch (e) {
      toast.error(tr("toast.saveFailed", { error: (e as Error).message }));
    }
  }
  async function resetPrompt() {
    try {
      const r = await api.resetAgentPrompt(agentKey);
      toast.success(tr("toast.resetToDefaultVersion", { version: r.version }));
      reload();
    } catch (e) {
      toast.error(tr("toast.resetFailed", { error: (e as Error).message }));
    }
  }
  async function saveWrapup() {
    try {
      const turns = Math.max(0, Math.floor(Number(wrapupTurns) || 0));
      await api.saveAgentWrapup(agentKey, wrapup, turns);
      toast.success(wrapup.trim() || turns > 0 ? tr("toast.wrapupSaved") : tr("toast.wrapupCleared"));
      reload();
    } catch (e) {
      toast.error(tr("toast.saveFailed", { error: (e as Error).message }));
    }
  }
  async function resetWrapup() {
    try {
      await api.resetAgentWrapup(agentKey);
      toast.success(tr("toast.resetToDefault"));
      reload();
    } catch (e) {
      toast.error(tr("toast.resetFailed", { error: (e as Error).message }));
    }
  }
  async function saveTaskTimeoutWrapup() {
    try {
      const turns = Math.max(0, Math.floor(Number(ttTurns) || 0));
      await api.saveAgentTaskTimeoutWrapup(agentKey, ttWrapup, turns);
      toast.success(tr("toast.taskTimeoutWrapupSaved"));
      reload();
    } catch (e) {
      toast.error(tr("toast.saveFailed", { error: (e as Error).message }));
    }
  }
  async function resetTaskTimeoutWrapup() {
    try {
      await api.resetAgentTaskTimeoutWrapup(agentKey);
      toast.success(tr("toast.resetToDefault"));
      reload();
    } catch (e) {
      toast.error(tr("toast.resetFailed", { error: (e as Error).message }));
    }
  }
  async function saveConfig() {
    try {
      // 只提交本 agent 实际展示的字段，避免把未显示项(如 goals 的 max_turns)覆盖成默认。
      const patch: Parameters<typeof api.saveAgentConfig>[1] = {
        llm_profile_id: llmProfileId === "" ? null : Number(llmProfileId),
      };
      if (showConfig) {
        patch.max_turns = Math.max(0, Math.floor(Number(maxTurns) || 0));
        patch.run_seconds = Math.max(0, Math.floor(Number(runSecs) || 0));
      }
      if (showWebSearch) patch.web_search = webSearch;
      if (showInteractiveShell) patch.interactive_shell = interactiveShell;
      await api.saveAgentConfig(agentKey, patch);
      toast.success(tr("toast.configSaved"));
      reload();
    } catch (e) {
      toast.error(tr("toast.saveFailed", { error: (e as Error).message }));
    }
  }
  // applyVis optimistically updates, persists, and toasts success/failure. On
  // failure it reverts to the prior selection so the UI never lies about state.
  async function applyVis(nextMcp: number[], nextSkill: string[], okMsg: string) {
    const prevMcp = mcpVisible;
    const prevSkill = skillVisible;
    setMcpVisible(nextMcp);
    setSkillVisible(nextSkill);
    try {
      await api.setAgentVisibility(agentKey, nextMcp, nextSkill);
      toast.success(okMsg);
      onSaved?.(); // refresh the list so the card's MCP/Skill counts stay in sync
    } catch (e) {
      setMcpVisible(prevMcp);
      setSkillVisible(prevSkill);
      toast.error(tr("toast.saveFailed", { error: (e as Error).message }));
    }
  }
  function toggleMcp(id: number) {
    const on = mcpVisible.includes(id);
    const name = mcp.find((m) => m.id === id)?.name ?? String(id);
    void applyVis(
      on ? mcpVisible.filter((x) => x !== id) : [...mcpVisible, id],
      skillVisible,
      on ? tr("toast.mcpVisOff", { name }) : tr("toast.mcpVisOn", { name }),
    );
  }
  function toggleSkill(name: string) {
    const on = skillVisible.includes(name);
    void applyVis(
      mcpVisible,
      on ? skillVisible.filter((x) => x !== name) : [...skillVisible, name],
      on ? tr("toast.skillVisOff", { name }) : tr("toast.skillVisOn", { name }),
    );
  }
  async function toggleTool(t: Tool) {
    const on = t.agents.includes(agentKey);
    const nextAgents = on ? t.agents.filter((k) => k !== agentKey) : [...t.agents, agentKey];
    // optimistic update
    setTools((ts) => ts.map((x) => (x.key === t.key ? { ...x, agents: nextAgents } : x)));
    try {
      await api.saveTool(t.key, {
        description: t.description,
        schema: t.schema,
        agents: nextAgents,
        enabled: t.enabled,
      });
      toast.success(on ? tr("toast.toolUnbound", { key: t.key }) : tr("toast.toolBound", { key: t.key }));
      onSaved?.(); // refresh the list so the card's 工具 count stays in sync
    } catch (e) {
      toast.error(tr("toast.toolBindFailed", { error: (e as Error).message }));
      reload();
      api
        .tools()
        .then(setTools)
        .catch(() => {
          /* 재조회 실패는 무시한다 */
        });
    }
  }

  if (loaded && !detail) {
    return <div className="text-muted-foreground p-6 text-center text-sm">{tr("notFound", { key: agentKey })}</div>;
  }
  // config is meaningless for the conversational main agent and the fixed-budget
  // goals decomposer; every other agent (workers, custom assistants) honors it.
  const showConfig = agentKey !== "mainagent" && agentKey !== "goals";
  // web search applies to every conversational/executing agent except the one-shot
  // goals decomposer; it's gated by the global master switch.
  const showWebSearch = agentKey !== "goals";
  // interactive shell (持久 PTY 会话工具族) 同样对除 goals 外的 agent 开放;无全局门控。
  const showInteractiveShell = agentKey !== "goals";
  // 每个 agent(含 goals/mainagent)都跑在某个 LLM 上,故「默认模型」绑定对所有 agent 开放。
  const showLLM = true;
  // triggers (P3) only attach to custom agents.
  const isCustom = !!detail && !detail.agent?.builtin;

  return (
    <Tabs defaultValue="prompt" className="flex min-h-0 flex-1 flex-col">
      <TabsList className="mx-4 mt-2 w-fit">
        <TabsTrigger value="prompt">{tr("tab.prompt")}</TabsTrigger>
        <TabsTrigger value="wrapup">{tr("tab.wrapup")}</TabsTrigger>
        <TabsTrigger value="mcp">MCP</TabsTrigger>
        <TabsTrigger value="skill">Skill</TabsTrigger>
        <TabsTrigger value="tools">Tools</TabsTrigger>
        {isCustom && <TabsTrigger value="triggers">{tr("tab.triggers")}</TabsTrigger>}
      </TabsList>

      {/* 配置 + 提示词 */}
      <TabsContent value="prompt" className="min-h-0 flex-1 overflow-y-auto px-4 pb-4">
        <div className="grid gap-4">
          {(showLLM || showConfig || showWebSearch || showInteractiveShell) && (
            <div className="grid gap-3 rounded-md border p-3">
              {showLLM && (
                <div className="grid gap-1.5">
                  <Label htmlFor="llm-profile" className="text-xs">
                    {tr("llm.label")}
                  </Label>
                  <div className="flex flex-wrap items-center gap-3">
                    <Select
                      value={llmProfileId || "__follow__"}
                      onValueChange={(v) => setLlmProfileId(v === "__follow__" ? "" : v)}
                    >
                      <SelectTrigger id="llm-profile" className="h-8 w-72">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="__follow__">{tr("llm.follow")}</SelectItem>
                        {llmProfiles.map((p) => (
                          <SelectItem key={p.id} value={String(p.id)}>
                            {p.name}({p.model}){p.is_default ? tr("llm.defaultSuffix") : ""}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <span className="text-muted-foreground max-w-md text-xs">{tr("llm.hint")}</span>
                  </div>
                </div>
              )}
              <div className="flex flex-wrap items-end gap-3">
                {showConfig && (
                  <>
                    <div className="grid gap-1.5">
                      <Label htmlFor="max-turns" className="text-xs">
                        {tr("config.maxTurns")}
                      </Label>
                      <Input
                        id="max-turns"
                        type="number"
                        min={0}
                        className="h-8 w-32"
                        value={maxTurns}
                        onChange={(e) => setMaxTurns(e.target.value)}
                      />
                    </div>
                    <div className="grid gap-1.5">
                      <Label htmlFor="run-seconds" className="text-xs">
                        {tr("config.runSeconds")}
                      </Label>
                      <Input
                        id="run-seconds"
                        type="number"
                        min={0}
                        className="h-8 w-32"
                        value={runSecs}
                        onChange={(e) => setRunSecs(e.target.value)}
                      />
                    </div>
                  </>
                )}
                <Button size="sm" variant="outline" onClick={saveConfig}>
                  <SaveIcon /> {tr("config.save")}
                </Button>
              </div>
              {showWebSearch && (
                <div className="flex items-center gap-3 border-t pt-3">
                  <Switch
                    id="web-search"
                    checked={webSearch}
                    disabled={!webSearchGlobalOn}
                    onCheckedChange={setWebSearch}
                  />
                  <div className="grid gap-0.5">
                    <Label htmlFor="web-search" className="text-sm">
                      {tr("webSearch.label")}
                    </Label>
                    <span className="text-muted-foreground text-xs">
                      {webSearchGlobalOn ? tr("webSearch.onHint") : tr("webSearch.offHint")}
                    </span>
                  </div>
                </div>
              )}
              {showInteractiveShell && (
                <div className="flex items-center gap-3 border-t pt-3">
                  <Switch id="interactive-shell" checked={interactiveShell} onCheckedChange={setInteractiveShell} />
                  <div className="grid gap-0.5">
                    <Label htmlFor="interactive-shell" className="text-sm">
                      {tr("shell.label")}
                    </Label>
                    <span className="text-muted-foreground text-xs">{tr("shell.hint")}</span>
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="grid gap-2">
            <Label className="text-muted-foreground text-xs">{tr("prompt.varsLabel")}</Label>
            <div className="flex flex-wrap gap-2">
              {variables.map((v) => (
                <Tooltip key={v.name}>
                  <TooltipTrigger asChild>
                    <button
                      type="button"
                      onClick={() => setPrompt((p) => `${p}{{.${v.name}}}`)}
                      className="hover:bg-muted inline-flex items-center gap-1 rounded-md border bg-muted/40 px-2 py-1 font-mono text-xs"
                    >
                      {`{{.${v.name}}}`}
                      <Badge variant="secondary" className="px-1 py-0 text-[10px]">
                        {v.source}
                      </Badge>
                    </button>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p className="font-medium">{v.description}</p>
                    <p className="text-muted-foreground mt-1">{tr("prompt.example", { example: v.example })}</p>
                  </TooltipContent>
                </Tooltip>
              ))}
              {variables.length === 0 && <span className="text-muted-foreground text-xs">{tr("prompt.noVars")}</span>}
            </div>
          </div>

          <Textarea
            className="font-mono text-xs"
            rows={16}
            value={prompt}
            placeholder={tr("prompt.placeholder")}
            onChange={(e) => setPrompt(e.target.value)}
          />

          <div className="flex flex-wrap gap-2">
            <Dialog>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm" onClick={doPreview}>
                  <EyeIcon /> {tr("prompt.previewBtn")}
                </Button>
              </DialogTrigger>
              <DialogContent className="sm:max-w-2xl">
                <DialogHeader>
                  <DialogTitle>{tr("preview.title")}</DialogTitle>
                  <DialogDescription>
                    {tr("preview.descPrefix")} {`{{.Var}}`} {tr("preview.descSuffix")}
                  </DialogDescription>
                </DialogHeader>
                <div className="max-h-[60vh] overflow-auto rounded-md border bg-muted/30 p-3">
                  <Markdown text={preview} />
                </div>
              </DialogContent>
            </Dialog>
            <Button size="sm" onClick={savePrompt}>
              <SaveIcon /> {tr("prompt.saveVersion")}
            </Button>
            <Button variant="outline" size="sm" onClick={resetPrompt}>
              <RotateCcwIcon /> {tr("prompt.resetDefault")}
            </Button>
          </div>

          <Separator />
          <div className="grid gap-2">
            <Label className="text-muted-foreground text-xs">{tr("version.historyLabel")}</Label>
            <ul className="grid gap-1">
              {versions.map((ver, i) => (
                <li
                  key={ver.version}
                  className="flex items-center gap-2 rounded-md px-1 py-0.5 text-xs hover:bg-muted/50"
                >
                  <span className="font-mono shrink-0">v{ver.version}</span>
                  {i === 0 && (
                    <Badge variant="secondary" className="px-1.5 py-0 shrink-0">
                      {tr("version.current")}
                    </Badge>
                  )}
                  <span className="text-muted-foreground truncate flex-1">{ver.note}</span>
                  {ver.ts && (
                    <span className="text-muted-foreground/60 shrink-0 tabular-nums">
                      {new Date(ver.ts).toLocaleDateString("ko-KR", {
                        month: "2-digit",
                        day: "2-digit",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                  )}
                  <Button variant="ghost" size="icon-sm" className="size-6 shrink-0" onClick={() => setViewVer(ver)}>
                    <EyeIcon className="size-3" />
                  </Button>
                  {i > 0 && versions[0] && (
                    <Button variant="ghost" size="icon-sm" className="size-6 shrink-0" onClick={() => setDiffVer(ver)}>
                      <GitCompareIcon className="size-3" />
                    </Button>
                  )}
                </li>
              ))}
              {versions.length === 0 && <li className="text-muted-foreground text-xs">{tr("version.none")}</li>}
            </ul>
          </div>

          {/* 查看版本 dialog */}
          <Dialog
            open={!!viewVer}
            onOpenChange={(o) => {
              if (!o) setViewVer(null);
            }}
          >
            <DialogContent className="sm:max-w-2xl">
              <DialogHeader>
                <DialogTitle>
                  v{viewVer?.version}
                  {viewVer?.version === versions[0]?.version && (
                    <Badge variant="secondary" className="ml-2 px-1.5 py-0 align-middle">
                      {tr("version.current")}
                    </Badge>
                  )}
                </DialogTitle>
                <DialogDescription>
                  {viewVer?.note || tr("version.noNote")}
                  {viewVer?.ts && (
                    <span className="ml-2 text-muted-foreground/60">
                      {new Date(viewVer.ts).toLocaleString("ko-KR")}
                    </span>
                  )}
                </DialogDescription>
              </DialogHeader>
              <pre className="bg-muted max-h-[55vh] overflow-auto whitespace-pre-wrap rounded-md p-3 font-mono text-xs">
                {viewVer?.template_text || tr("version.empty")}
              </pre>
              <div className="flex gap-2 justify-end">
                {viewVer && viewVer.version !== versions[0]?.version && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      if (viewVer) {
                        setDiffVer(viewVer);
                        setViewVer(null);
                      }
                    }}
                  >
                    <GitCompareIcon className="mr-1 size-3.5" /> {tr("version.compareCurrent")}
                  </Button>
                )}
                <Button
                  size="sm"
                  onClick={() => {
                    if (viewVer) {
                      setPrompt(viewVer.template_text);
                      setViewVer(null);
                      toast.success(tr("toast.loadedToEditor", { version: viewVer.version }));
                    }
                  }}
                >
                  {tr("version.loadToEditor")}
                </Button>
              </div>
            </DialogContent>
          </Dialog>

          {/* 版本对比 dialog */}
          <Dialog
            open={!!diffVer}
            onOpenChange={(o) => {
              if (!o) setDiffVer(null);
            }}
          >
            <DialogContent className="sm:max-w-3xl">
              <DialogHeader>
                <DialogTitle>
                  {tr("diff.title", { from: diffVer?.version ?? "", to: versions[0]?.version ?? "" })}
                </DialogTitle>
                <DialogDescription>
                  <span className="inline-flex items-center gap-3 text-xs">
                    <span className="rounded bg-red-500/15 px-1.5 py-0.5 text-red-600 dark:text-red-400">
                      {tr("diff.removed")}
                    </span>
                    <span className="rounded bg-green-500/15 px-1.5 py-0.5 text-green-600 dark:text-green-400">
                      {tr("diff.added")}
                    </span>
                  </span>
                </DialogDescription>
              </DialogHeader>
              <DiffView oldText={diffVer?.template_text ?? ""} newText={versions[0]?.template_text ?? ""} />
            </DialogContent>
          </Dialog>
        </div>
      </TabsContent>

      {/* 收尾提示词 */}
      <TabsContent value="wrapup" className="min-h-0 flex-1 overflow-y-auto px-4 pb-4">
        <div className="grid gap-3">
          <p className="text-muted-foreground text-xs leading-relaxed">
            {tr.rich("wrapup.desc", { b: (c) => <b>{c}</b> })}
          </p>
          <div className="flex items-center gap-2">
            <Label className="text-xs">{tr("wrapup.bodyLabel")}</Label>
            {wrapup.trim() ? (
              <Badge variant="secondary" className="px-1.5 py-0">
                {tr("wrapup.custom")}
              </Badge>
            ) : (
              <Badge variant="outline" className="px-1.5 py-0">
                {tr("wrapup.useDefault")}
              </Badge>
            )}
          </div>
          <Textarea
            className="font-mono text-xs"
            rows={10}
            value={wrapup}
            placeholder={wrapupDefault || tr("wrapup.placeholder")}
            onChange={(e) => setWrapup(e.target.value)}
          />
          <div className="grid gap-1.5">
            <Label htmlFor="wrapup-turns" className="text-xs">
              {tr("wrapup.turnsLabel", { default: wrapupTurnsDefault })}
            </Label>
            <Input
              id="wrapup-turns"
              type="number"
              min={0}
              className="h-8 w-32"
              value={wrapupTurns}
              onChange={(e) => setWrapupTurns(e.target.value)}
            />
          </div>
          <div className="flex gap-2">
            <Button size="sm" onClick={saveWrapup}>
              {tr("wrapup.save")}
            </Button>
            <Button size="sm" variant="outline" onClick={resetWrapup}>
              {tr("wrapup.resetDefault")}
            </Button>
          </div>
          {wrapupDefault && (
            <>
              <Separator />
              <div className="grid gap-1.5">
                <Label className="text-muted-foreground text-xs">{tr("wrapup.defaultLabel")}</Label>
                <pre className="text-muted-foreground max-h-40 overflow-y-auto rounded-md border bg-muted/30 p-2 text-xs whitespace-pre-wrap">
                  {wrapupDefault}
                </pre>
              </div>
            </>
          )}

          {ttSupported && (
            <>
              <Separator className="my-2" />
              <p className="text-muted-foreground text-xs leading-relaxed">
                {tr.rich("taskTimeout.desc", { b: (c) => <b>{c}</b> })}
              </p>
              <div className="flex items-center gap-2">
                <Label className="text-xs">{tr("taskTimeout.bodyLabel")}</Label>
                {ttWrapup.trim() ? (
                  <Badge variant="secondary" className="px-1.5 py-0">
                    {tr("wrapup.custom")}
                  </Badge>
                ) : (
                  <Badge variant="outline" className="px-1.5 py-0">
                    {tr("wrapup.useDefault")}
                  </Badge>
                )}
              </div>
              <Textarea
                className="font-mono text-xs"
                rows={10}
                value={ttWrapup}
                placeholder={ttWrapupDefault || tr("taskTimeout.placeholder")}
                onChange={(e) => setTtWrapup(e.target.value)}
              />
              <div className="grid gap-1.5">
                <Label htmlFor="tt-turns" className="text-xs">
                  {tr("taskTimeout.turnsLabel", { default: ttTurnsDefault })}
                </Label>
                <Input
                  id="tt-turns"
                  type="number"
                  min={0}
                  className="h-8 w-32"
                  value={ttTurns}
                  onChange={(e) => setTtTurns(e.target.value)}
                />
              </div>
              <div className="flex gap-2">
                <Button size="sm" onClick={saveTaskTimeoutWrapup}>
                  {tr("wrapup.save")}
                </Button>
                <Button size="sm" variant="outline" onClick={resetTaskTimeoutWrapup}>
                  {tr("wrapup.resetDefault")}
                </Button>
              </div>
              {ttWrapupDefault && (
                <div className="grid gap-1.5">
                  <Label className="text-muted-foreground text-xs">{tr("wrapup.defaultLabel")}</Label>
                  <pre className="text-muted-foreground max-h-40 overflow-y-auto rounded-md border bg-muted/30 p-2 text-xs whitespace-pre-wrap">
                    {ttWrapupDefault}
                  </pre>
                </div>
              )}
            </>
          )}
        </div>
      </TabsContent>

      {/* MCP 可见性 */}
      <TabsContent value="mcp" className="min-h-0 flex-1 overflow-y-auto px-4 pb-4">
        <p className="text-muted-foreground mb-3 text-xs">{tr("mcp.desc")}</p>
        <div className="grid gap-2">
          {mcp.map((m) => (
            <label key={m.id} className="flex items-center gap-2 rounded-md border p-2 text-sm">
              <Checkbox checked={mcpVisible.includes(m.id)} onCheckedChange={() => toggleMcp(m.id)} />
              {m.name}
              <span className="text-muted-foreground ml-auto text-xs">{m.transport}</span>
            </label>
          ))}
          {mcp.length === 0 && <span className="text-muted-foreground text-xs">{tr("mcp.none")}</span>}
        </div>
      </TabsContent>

      {/* Skill 可见性 */}
      <TabsContent value="skill" className="min-h-0 flex-1 overflow-y-auto px-4 pb-4">
        <p className="text-muted-foreground mb-3 text-xs">{tr("skill.desc")}</p>
        <div className="grid gap-2">
          {skills.map((s) => (
            <label key={s.name} className="flex items-center gap-2 rounded-md border p-2 text-sm">
              <Checkbox checked={skillVisible.includes(s.name)} onCheckedChange={() => toggleSkill(s.name)} />
              <span className="font-mono text-xs">{s.name}</span>
              {s.description && <span className="text-muted-foreground ml-auto truncate text-xs">{s.description}</span>}
            </label>
          ))}
          {skills.length === 0 && <span className="text-muted-foreground text-xs">{tr("skill.none")}</span>}
        </div>
      </TabsContent>

      {/* Tools 绑定 */}
      <TabsContent value="tools" className="min-h-0 flex-1 overflow-y-auto px-4 pb-4">
        <p className="text-muted-foreground mb-3 text-xs">{tr("tools.desc")}</p>
        <div className="grid gap-2">
          {tools.map((t) => {
            const isTraffic = TRAFFIC_TOOL_KEYS.has(t.key);
            const gated = isTraffic && !captureOn; // traffic tools need 流量捕获 on
            return (
              <label
                key={t.key}
                className={cn("flex items-center gap-2 rounded-md border p-2 text-sm", gated && "opacity-60")}
              >
                <Checkbox
                  checked={t.agents.includes(agentKey)}
                  disabled={gated}
                  onCheckedChange={() => toggleTool(t)}
                />
                <span className="font-mono text-xs">{t.key}</span>
                {isTraffic && (
                  <Badge variant="secondary" className="px-1 py-0 text-[9px]">
                    {tr("tools.trafficBadge")}
                  </Badge>
                )}
                {!t.enabled && (
                  <Badge variant="outline" className="text-destructive px-1 py-0 text-[9px]">
                    {tr("tools.disabledBadge")}
                  </Badge>
                )}
                {gated ? (
                  <span className="text-muted-foreground ml-auto text-xs">{tr("tools.needCapture")}</span>
                ) : (
                  t.description && (
                    <span className="text-muted-foreground ml-auto line-clamp-1 max-w-[55%] text-xs">
                      {t.description}
                    </span>
                  )
                )}
              </label>
            );
          })}
          {tools.length === 0 && <span className="text-muted-foreground text-xs">{tr("tools.none")}</span>}
        </div>
      </TabsContent>

      {/* 触发(P3, 仅自定义 agent) */}
      {isCustom && (
        <TabsContent value="triggers" className="min-h-0 flex-1 overflow-y-auto px-4 pb-4">
          <AgentTriggersTab agentKey={agentKey} agent={detail?.agent} />
        </TabsContent>
      )}
    </Tabs>
  );
}

// ---------- Diff helpers ----------

type DiffLine = { type: "same" | "add" | "del"; text: string };

function computeDiff(oldText: string, newText: string): DiffLine[] {
  const a = oldText.split("\n");
  const b = newText.split("\n");
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
  const result: DiffLine[] = [];
  let i = m;
  let j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i - 1] === b[j - 1]) {
      result.unshift({ type: "same", text: a[i - 1] });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      result.unshift({ type: "add", text: b[j - 1] });
      j--;
    } else {
      result.unshift({ type: "del", text: a[i - 1] });
      i--;
    }
  }
  return result;
}

function DiffView({ oldText, newText }: { oldText: string; newText: string }) {
  const lines = React.useMemo(() => computeDiff(oldText, newText), [oldText, newText]);
  return (
    <pre className="max-h-[60vh] overflow-auto rounded-md border bg-muted/30 p-2 font-mono text-xs leading-5">
      {lines.map((l, idx) => (
        <div
          key={idx}
          className={cn(
            "whitespace-pre-wrap px-1",
            l.type === "del" && "bg-red-500/15 text-red-700 dark:text-red-400",
            l.type === "add" && "bg-green-500/15 text-green-700 dark:text-green-400",
            l.type === "same" && "text-muted-foreground",
          )}
        >
          <span className="select-none mr-1 opacity-50">{l.type === "del" ? "-" : l.type === "add" ? "+" : " "}</span>
          {l.text}
        </div>
      ))}
    </pre>
  );
}

// AgentTriggersTab manages a custom agent's P3 triggers: list + add + delete.
// Each trigger fires (定时/发现finding/目标达成/任务超时/工具调用，可多选) → a new conversation runs
// in parallel with the base user message + auto context appended by the backend.
function AgentTriggersTab({ agentKey, agent }: { agentKey: string; agent?: Agent }) {
  const tr = useTranslations("agentEditor");
  const [triggers, setTriggers] = React.useState<AgentTrigger[]>([]);
  const [tools, setTools] = React.useState<Tool[]>([]);
  // 触发后处理策略(每 agent);初值来自 agent detail,改动即保存。
  const [runMode, setRunMode] = React.useState<"serial" | "parallel">(agent?.trigger_run_mode ?? "serial");
  const [mergeMode, setMergeMode] = React.useState<"by_task" | "all" | "none">(agent?.trigger_merge_mode ?? "all");
  const [maxParallel, setMaxParallel] = React.useState(String(agent?.trigger_max_parallel ?? 5));
  React.useEffect(() => {
    setRunMode(agent?.trigger_run_mode ?? "serial");
    setMergeMode(agent?.trigger_merge_mode ?? "all");
    setMaxParallel(String(agent?.trigger_max_parallel ?? 5));
  }, [agent?.trigger_run_mode, agent?.trigger_merge_mode, agent?.trigger_max_parallel]);

  async function saveBehavior(patch: {
    trigger_run_mode?: "serial" | "parallel";
    trigger_merge_mode?: "by_task" | "all" | "none";
    trigger_max_parallel?: number;
  }) {
    try {
      await api.saveAgentConfig(agentKey, patch);
    } catch (e) {
      toast.error(tr("triggers.savePolicyFailed", { error: (e as Error).message }));
    }
  }
  const [onInterval, setOnInterval] = React.useState(false);
  const [intervalSec, setIntervalSec] = React.useState("60");
  const [onFinding, setOnFinding] = React.useState(false);
  const [onGoalMet, setOnGoalMet] = React.useState(false);
  const [onTaskTimeout, setOnTaskTimeout] = React.useState(false);
  const [onToolCall, setOnToolCall] = React.useState(false);
  const [onTaskCreate, setOnTaskCreate] = React.useState(false);
  const [intervalMsg, setIntervalMsg] = React.useState("");
  const [findingMsg, setFindingMsg] = React.useState("");
  const [goalMsg, setGoalMsg] = React.useState("");
  const [taskTimeoutMsg, setTaskTimeoutMsg] = React.useState("");
  const [toolCallMsg, setToolCallMsg] = React.useState("");
  const [taskCreateMsg, setTaskCreateMsg] = React.useState("");
  const [toolNames, setToolNames] = React.useState<string[]>([]);
  const [saving, setSaving] = React.useState(false);
  // null = 新增模式；非 null = 正在编辑该 id 的触发器。
  const [editingId, setEditingId] = React.useState<number | null>(null);

  const reload = React.useCallback(() => {
    api
      .agentTriggers(agentKey)
      .then(setTriggers)
      .catch(() => setTriggers([]));
  }, [agentKey]);
  React.useEffect(() => {
    reload();
  }, [reload]);
  React.useEffect(() => {
    api
      .tools()
      .then(setTools)
      .catch(() => setTools([]));
  }, []);

  function toggleTool(key: string) {
    setToolNames((prev) => (prev.includes(key) ? prev.filter((k) => k !== key) : [...prev, key]));
  }

  // resetForm 清空表单并回到「新增」模式。
  function resetForm() {
    setEditingId(null);
    setOnInterval(false);
    setIntervalSec("60");
    setOnFinding(false);
    setOnGoalMet(false);
    setOnTaskTimeout(false);
    setOnToolCall(false);
    setOnTaskCreate(false);
    setIntervalMsg("");
    setFindingMsg("");
    setGoalMsg("");
    setTaskTimeoutMsg("");
    setToolCallMsg("");
    setTaskCreateMsg("");
    setToolNames([]);
  }

  // startEdit 把某条已有触发器灌进表单,进入「编辑」模式。
  function startEdit(t: AgentTrigger) {
    setEditingId(t.id);
    setOnInterval(t.interval_sec > 0);
    setIntervalSec(t.interval_sec > 0 ? String(t.interval_sec) : "60");
    setOnFinding(t.on_finding);
    setOnGoalMet(t.on_goal_met);
    setOnTaskTimeout(t.on_task_timeout);
    setOnToolCall(t.on_tool_call);
    setOnTaskCreate(t.on_task_create);
    setIntervalMsg(t.interval_message);
    setFindingMsg(t.finding_message);
    setGoalMsg(t.goal_message);
    setTaskTimeoutMsg(t.task_timeout_message);
    setToolCallMsg(t.tool_call_message);
    setTaskCreateMsg(t.task_create_message);
    setToolNames(t.tool_names ?? []);
  }

  // submit 依 editingId 走「新增」或「保存修改」;编辑时保留该触发器的启用状态。
  async function submit() {
    const n = onInterval ? Math.max(1, Math.floor(Number(intervalSec) || 0)) : 0;
    if (n === 0 && !onFinding && !onGoalMet && !onTaskTimeout && !onToolCall && !onTaskCreate) {
      toast.error(tr("triggers.errNoCondition"));
      return;
    }
    if (onToolCall && toolNames.length === 0) {
      toast.error(tr("triggers.errNoTool"));
      return;
    }
    const body = {
      interval_sec: n,
      on_finding: onFinding,
      on_goal_met: onGoalMet,
      on_task_timeout: onTaskTimeout,
      on_tool_call: onToolCall,
      on_task_create: onTaskCreate,
      interval_message: intervalMsg.trim(),
      finding_message: findingMsg.trim(),
      goal_message: goalMsg.trim(),
      task_timeout_message: taskTimeoutMsg.trim(),
      tool_call_message: toolCallMsg.trim(),
      task_create_message: taskCreateMsg.trim(),
      tool_names: onToolCall ? toolNames : [],
    };
    setSaving(true);
    try {
      if (editingId != null) {
        const cur = triggers.find((x) => x.id === editingId);
        await api.updateTrigger(editingId, { ...body, enabled: cur?.enabled ?? true });
        toast.success(tr("triggers.savedEdit"));
      } else {
        await api.createTrigger(agentKey, { ...body, enabled: true });
        toast.success(tr("triggers.added"));
      }
      resetForm();
      reload();
    } catch (e) {
      const msg = (e as Error).message;
      toast.error(
        editingId != null ? tr("triggers.saveEditFailed", { error: msg }) : tr("triggers.addFailed", { error: msg }),
      );
    } finally {
      setSaving(false);
    }
  }
  async function toggleEnabled(t: AgentTrigger) {
    try {
      await api.updateTrigger(t.id, {
        enabled: !t.enabled,
        interval_sec: t.interval_sec,
        on_finding: t.on_finding,
        on_goal_met: t.on_goal_met,
        on_task_timeout: t.on_task_timeout,
        on_tool_call: t.on_tool_call,
        on_task_create: t.on_task_create,
        interval_message: t.interval_message,
        finding_message: t.finding_message,
        goal_message: t.goal_message,
        task_timeout_message: t.task_timeout_message,
        tool_call_message: t.tool_call_message,
        task_create_message: t.task_create_message,
        tool_names: t.tool_names,
      });
      reload();
    } catch (e) {
      toast.error(tr("toast.saveFailed", { error: (e as Error).message }));
    }
  }
  async function del(id: number) {
    try {
      await api.deleteTrigger(id);
      if (editingId === id) resetForm();
      reload();
    } catch (e) {
      toast.error(tr("triggers.deleteFailed", { error: (e as Error).message }));
    }
  }

  function condLabel(t: AgentTrigger): string {
    const parts: string[] = [];
    if (t.interval_sec > 0) parts.push(tr("triggers.cond.everyN", { sec: t.interval_sec }));
    if (t.on_finding) parts.push(tr("triggers.cond.finding"));
    if (t.on_goal_met) parts.push(tr("triggers.cond.goalMet"));
    if (t.on_task_timeout) parts.push(tr("triggers.cond.taskTimeout"));
    if (t.on_tool_call) parts.push(tr("triggers.cond.toolCall", { count: t.tool_names.length }));
    if (t.on_task_create) parts.push(tr("triggers.cond.taskCreate"));
    return parts.join(" · ") || tr("triggers.cond.none");
  }

  return (
    <div className="grid gap-4">
      <p className="text-muted-foreground text-xs">{tr.rich("triggers.desc", { b: (c) => <b>{c}</b> })}</p>

      {/* 触发后处理策略 */}
      <div className="grid gap-3 rounded-md border p-3">
        <Label className="text-muted-foreground text-xs">{tr("triggers.policyLabel")}</Label>
        <div className="flex flex-wrap items-center gap-4">
          <div className="grid gap-1">
            <Label className="text-xs">{tr("triggers.runMode")}</Label>
            <Select
              value={runMode}
              onValueChange={(v) => {
                const rm = v as "serial" | "parallel";
                setRunMode(rm);
                void saveBehavior({ trigger_run_mode: rm });
              }}
            >
              <SelectTrigger size="sm" className="h-8 w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="serial">{tr("triggers.serial")}</SelectItem>
                <SelectItem value="parallel">{tr("triggers.parallel")}</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="grid gap-1">
            <Label className="text-xs">{tr("triggers.mergeMode")}</Label>
            <Select
              value={mergeMode}
              disabled={runMode === "parallel"}
              onValueChange={(v) => {
                const mm = v as "by_task" | "all" | "none";
                setMergeMode(mm);
                void saveBehavior({ trigger_merge_mode: mm });
              }}
            >
              <SelectTrigger size="sm" className="h-8 w-44">
                <SelectValue />
              </SelectTrigger>
              <SelectContent position="popper">
                <SelectItem value="by_task">{tr("triggers.mergeByTask")}</SelectItem>
                <SelectItem value="all">{tr("triggers.mergeAll")}</SelectItem>
                <SelectItem value="none">{tr("triggers.mergeNone")}</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {runMode === "parallel" && (
            <div className="grid gap-1">
              <Label htmlFor="tr-maxpar" className="text-xs">
                {tr("triggers.maxParallel")}
              </Label>
              <Input
                id="tr-maxpar"
                type="number"
                min={0}
                className="h-8 w-28"
                value={maxParallel}
                onChange={(e) => setMaxParallel(e.target.value)}
                onBlur={() => {
                  const n = Math.max(0, Math.floor(Number(maxParallel) || 0));
                  setMaxParallel(String(n));
                  void saveBehavior({ trigger_max_parallel: n });
                }}
              />
            </div>
          )}
        </div>
        <p className="text-muted-foreground text-xs">
          {runMode === "parallel"
            ? tr("triggers.policyParallel")
            : mergeMode === "by_task"
              ? tr("triggers.policyByTask")
              : mergeMode === "all"
                ? tr("triggers.policyAll")
                : tr("triggers.policyNone")}
        </p>
      </div>

      {/* 新增 / 编辑触发器 */}
      <div className="grid gap-3 rounded-md border p-3">
        <Label className="text-muted-foreground text-xs">
          {editingId != null ? tr("triggers.editTitle", { id: editingId }) : tr("triggers.addTitle")}
        </Label>

        {/* 定时 */}
        <div className="grid gap-1.5">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={onInterval} onCheckedChange={(v) => setOnInterval(!!v)} /> {tr("triggers.onInterval")}
          </label>
          {onInterval && (
            <div className="grid gap-1.5">
              <div className="flex items-center gap-2">
                <Label htmlFor="tr-interval" className="text-xs">
                  {tr("triggers.every")}
                </Label>
                <Input
                  id="tr-interval"
                  type="number"
                  min={1}
                  className="h-8 w-24"
                  value={intervalSec}
                  onChange={(e) => setIntervalSec(e.target.value)}
                />
                <span className="text-muted-foreground text-xs">{tr("triggers.seconds")}</span>
              </div>
              <Textarea
                className="text-xs"
                rows={2}
                value={intervalMsg}
                placeholder={tr("triggers.intervalPlaceholder")}
                onChange={(e) => setIntervalMsg(e.target.value)}
              />
            </div>
          )}
        </div>

        {/* finding */}
        <div className="grid gap-1.5">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={onFinding} onCheckedChange={(v) => setOnFinding(!!v)} /> {tr("triggers.onFinding")}
          </label>
          {onFinding && (
            <Textarea
              className="text-xs"
              rows={2}
              value={findingMsg}
              placeholder={tr("triggers.findingPlaceholder")}
              onChange={(e) => setFindingMsg(e.target.value)}
            />
          )}
        </div>

        {/* 目标达成 */}
        <div className="grid gap-1.5">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={onGoalMet} onCheckedChange={(v) => setOnGoalMet(!!v)} /> {tr("triggers.onGoalMet")}
          </label>
          {onGoalMet && (
            <Textarea
              className="text-xs"
              rows={2}
              value={goalMsg}
              placeholder={tr("triggers.goalPlaceholder")}
              onChange={(e) => setGoalMsg(e.target.value)}
            />
          )}
        </div>

        {/* 任务超时 */}
        <div className="grid gap-1.5">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={onTaskTimeout} onCheckedChange={(v) => setOnTaskTimeout(!!v)} />{" "}
            {tr("triggers.onTaskTimeout")}
          </label>
          {onTaskTimeout && (
            <Textarea
              className="text-xs"
              rows={2}
              value={taskTimeoutMsg}
              placeholder={tr("triggers.taskTimeoutPlaceholder")}
              onChange={(e) => setTaskTimeoutMsg(e.target.value)}
            />
          )}
        </div>

        {/* 工具调用 */}
        <div className="grid gap-1.5">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={onToolCall} onCheckedChange={(v) => setOnToolCall(!!v)} /> {tr("triggers.onToolCall")}
          </label>
          {onToolCall && (
            <div className="grid gap-1.5">
              <div className="text-muted-foreground text-xs">
                {tr.rich("triggers.toolSelectHint", { b: (c) => <b>{c}</b>, count: toolNames.length })}
              </div>
              <div className="max-h-40 overflow-y-auto rounded-md border p-2">
                {tools.length === 0 && (
                  <span className="text-muted-foreground text-xs">{tr("triggers.toolListEmpty")}</span>
                )}
                <div className="grid gap-1">
                  {tools.map((tool) => (
                    <label key={tool.key} className="flex items-start gap-2 text-xs">
                      <Checkbox
                        className="mt-0.5"
                        checked={toolNames.includes(tool.key)}
                        onCheckedChange={() => toggleTool(tool.key)}
                      />
                      <span className="min-w-0">
                        <span className="font-medium">{tool.key}</span>
                        {tool.description && (
                          <span className="text-muted-foreground line-clamp-1"> {tool.description}</span>
                        )}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
              <Textarea
                className="text-xs"
                rows={2}
                value={toolCallMsg}
                placeholder={tr("triggers.toolCallPlaceholder")}
                onChange={(e) => setToolCallMsg(e.target.value)}
              />
            </div>
          )}
        </div>

        {/* 任务创建 */}
        <div className="grid gap-1.5">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={onTaskCreate} onCheckedChange={(v) => setOnTaskCreate(!!v)} />{" "}
            {tr("triggers.onTaskCreate")}
          </label>
          {onTaskCreate && (
            <Textarea
              className="text-xs"
              rows={2}
              value={taskCreateMsg}
              placeholder={tr("triggers.taskCreatePlaceholder")}
              onChange={(e) => setTaskCreateMsg(e.target.value)}
            />
          )}
        </div>

        <div className="flex items-center gap-2">
          <Button size="sm" onClick={submit} disabled={saving}>
            <SaveIcon /> {editingId != null ? tr("triggers.saveEdit") : tr("triggers.add")}
          </Button>
          {editingId != null && (
            <Button size="sm" variant="ghost" onClick={resetForm} disabled={saving}>
              <XIcon /> {tr("triggers.cancelEdit")}
            </Button>
          )}
        </div>
      </div>

      {/* 已有触发器 */}
      <div className="grid gap-2">
        <Label className="text-muted-foreground text-xs">{tr("triggers.existing")}</Label>
        {triggers.length === 0 && <span className="text-muted-foreground text-xs">{tr("triggers.existingNone")}</span>}
        {triggers.map((t) => (
          <div
            key={t.id}
            className={cn(
              "flex items-start gap-2 rounded-md border p-2 text-sm",
              editingId === t.id && "border-primary bg-primary/5",
            )}
          >
            <Switch checked={t.enabled} onCheckedChange={() => toggleEnabled(t)} className="mt-0.5" />
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-medium">{condLabel(t)}</span>
                {!t.enabled && (
                  <Badge variant="outline" className="text-destructive px-1 py-0 text-[9px]">
                    {tr("tools.disabledBadge")}
                  </Badge>
                )}
              </div>
              <div className="text-muted-foreground grid gap-0.5 text-xs">
                {t.interval_sec > 0 && t.interval_message && (
                  <div className="line-clamp-1">{tr("triggers.detail.interval", { msg: t.interval_message })}</div>
                )}
                {t.on_finding && t.finding_message && (
                  <div className="line-clamp-1">{tr("triggers.detail.finding", { msg: t.finding_message })}</div>
                )}
                {t.on_goal_met && t.goal_message && (
                  <div className="line-clamp-1">{tr("triggers.detail.goal", { msg: t.goal_message })}</div>
                )}
                {t.on_task_timeout && t.task_timeout_message && (
                  <div className="line-clamp-1">{tr("triggers.detail.timeout", { msg: t.task_timeout_message })}</div>
                )}
                {t.on_task_create && t.task_create_message && (
                  <div className="line-clamp-1">{tr("triggers.detail.taskCreate", { msg: t.task_create_message })}</div>
                )}
                {t.on_tool_call && (
                  <>
                    <div className="line-clamp-1">
                      {tr("triggers.detail.tools", {
                        tools: t.tool_names.join(", ") || tr("triggers.detail.toolsNone"),
                      })}
                    </div>
                    {t.tool_call_message && (
                      <div className="line-clamp-1">{tr("triggers.detail.message", { msg: t.tool_call_message })}</div>
                    )}
                  </>
                )}
              </div>
            </div>
            <Button
              variant="ghost"
              size="icon-sm"
              className="text-muted-foreground hover:text-foreground"
              onClick={() => startEdit(t)}
              title={tr("triggers.edit")}
            >
              <PencilIcon className="size-3.5" />
            </Button>
            <Button
              variant="ghost"
              size="icon-sm"
              className="text-muted-foreground hover:text-destructive"
              onClick={() => del(t.id)}
              title={tr("triggers.delete")}
            >
              <Trash2Icon className="size-3.5" />
            </Button>
          </div>
        ))}
      </div>
    </div>
  );
}
