"use client";

import * as React from "react";

import { BotIcon, ListFilterIcon, PencilIcon, PlusIcon, ShieldAlertIcon, Trash2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { InterceptAction, InterceptRule, JudgeConfig, LLMProfile, Tool } from "@/lib/types";

// ---- tool scope ----

// SDK tools are intentionally not seeded into the DB (they apply to every agent
// and have no per-agent binding). We hardcode their keys here so they still
// appear in the scope dialog; descriptions are resolved from i18n at render time.
const SDK_EXEC_KEYS = [
  "Bash",
  "WebFetch",
  "web_search",
  "shell_open",
  "shell_send",
  "shell_read",
  "shell_close",
  "shell_list",
] as const;
const SDK_WRITE_KEYS = ["Write", "Edit", "MultiEdit"] as const;

const SDK_KEYS = new Set<string>([...SDK_EXEC_KEYS, ...SDK_WRITE_KEYS]);

// ---- form state ----

type RuleForm = {
  name: string;
  enabled: boolean;
  priority: number;
  match_target: "tool_name" | "tool_input";
  match_type: "string" | "regex";
  pattern: string;
  action: InterceptAction;
  message: string;
  timeout_enabled: boolean;
  timeout_seconds: number;
  timeout_action: "deny" | "allow";
};

const defaultForm = (): RuleForm => ({
  name: "",
  enabled: true,
  priority: 0,
  match_target: "tool_name",
  match_type: "string",
  pattern: "",
  action: "deny",
  message: "",
  timeout_enabled: true,
  timeout_seconds: 60,
  timeout_action: "deny",
});

// ---- small components ----

function ActionBadge({ action, label }: { action: InterceptAction; label: string }) {
  if (action === "allow") return <Badge variant="secondary">{label}</Badge>;
  if (action === "deny") return <Badge variant="destructive">{label}</Badge>;
  return (
    <Badge variant="outline" className="border-amber-400 text-amber-600">
      {label}
    </Badge>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <Label className="text-xs font-medium text-muted-foreground uppercase tracking-wide">{label}</Label>
      {children}
    </div>
  );
}

// ---- LLM fallback judge card ----

const FOLLOW_ACTIVE = "0"; // profile_id 0 = 활성/기본 설정 따르기

const defaultJudge = (): JudgeConfig => ({
  enabled: false,
  profile_id: 0,
  prompt: "",
  timeout_seconds: 15,
  fail_action: "allow",
  ask_timeout_seconds: 300,
  ask_timeout_action: "deny",
});

function JudgeCard() {
  const t = useTranslations("interceptPage");
  const [cfg, setCfg] = React.useState<JudgeConfig>(defaultJudge());
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [j, ps] = await Promise.all([api.interceptGetJudgeConfig(), api.llmProfiles()]);
      setCfg(j);
      setProfiles(ps);
    } catch (e) {
      toast.error(t("judge.loadConfigFailed", { error: (e as Error).message }));
    } finally {
      setLoading(false);
    }
  }, [t]);

  React.useEffect(() => {
    void load();
  }, [load]);

  function patch(p: Partial<JudgeConfig>) {
    setCfg((c) => ({ ...c, ...p }));
  }

  async function save() {
    setSaving(true);
    try {
      await api.interceptSetJudgeConfig(cfg);
      toast.success(t("judge.configSaved"));
      await load(); // 되읽기: 프롬프트를 비우면 내장 템플릿을 다시 채운다
    } catch (e) {
      toast.error(t("toast.saveFailed", { error: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }

  async function restorePrompt() {
    // 프롬프트를 비우고 저장하면 서버가 다음 응답에 내장 템플릿 전문을 돌려주고, 입력창에 다시 채워진다.
    setSaving(true);
    try {
      await api.interceptSetJudgeConfig({ ...cfg, prompt: "" });
      const j = await api.interceptGetJudgeConfig();
      setCfg(j);
      toast.success(t("judge.restored"));
    } catch (e) {
      toast.error(t("judge.restoreFailed", { error: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4">
      {/* 사용 스위치 — 독립 강조 바 */}
      <div
        className={`flex items-center justify-between gap-3 rounded-lg border px-4 py-3 ${
          cfg.enabled ? "border-violet-400/50 bg-violet-50/40 dark:bg-violet-950/20" : "bg-muted/40"
        }`}
      >
        <div className="flex items-center gap-2.5">
          <BotIcon className={`h-5 w-5 shrink-0 ${cfg.enabled ? "text-violet-600" : "text-muted-foreground"}`} />
          <div>
            <p className="text-sm font-semibold leading-tight">{t("judge.title")}</p>
            <p className="text-xs text-muted-foreground mt-0.5">
              {t.rich("judge.desc", {
                scope: (c) => <span className="font-medium text-foreground">{c}</span>,
                norule: (c) => <span className="font-medium text-foreground">{c}</span>,
              })}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <span className="text-xs text-muted-foreground">
            {cfg.enabled ? t("judge.enabled") : t("judge.disabled")}
          </span>
          <Switch checked={cfg.enabled} disabled={loading} onCheckedChange={(v) => patch({ enabled: v })} />
        </div>
      </div>

      {cfg.enabled && (
        <div className="grid gap-4 lg:grid-cols-5">
          {/* 왼쪽: 프롬프트 편집기(바로 펼침, 주 영역) */}
          <Card className="lg:col-span-3">
            <CardContent className="flex h-full flex-col gap-2 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">{t("judge.promptTitle")}</p>
                  <p className="text-xs text-muted-foreground">{t("judge.promptDesc")}</p>
                </div>
                <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={restorePrompt} disabled={saving}>
                  {t("judge.restoreTemplate")}
                </Button>
              </div>
              <Textarea
                className="min-h-[22rem] flex-1 resize-none font-mono text-xs leading-relaxed"
                value={cfg.prompt}
                onChange={(e) => patch({ prompt: e.target.value })}
                placeholder={t("judge.promptPlaceholder")}
                spellCheck={false}
              />
              <p className="text-right text-[11px] text-muted-foreground">
                {t("judge.charCount", { count: cfg.prompt.length })}
              </p>
            </CardContent>
          </Card>

          {/* 오른쪽: 판정 매개변수(설정 칸) */}
          <Card className="lg:col-span-2">
            <CardContent className="space-y-5 p-4">
              <div className="space-y-4">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {t("judge.modelAndPolicy")}
                </p>
                <Field label={t("judge.approvalModel")}>
                  <Select value={String(cfg.profile_id || 0)} onValueChange={(v) => patch({ profile_id: Number(v) })}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={FOLLOW_ACTIVE}>{t("judge.followActive")}</SelectItem>
                      {profiles.map((p) => (
                        <SelectItem key={p.id} value={p.id}>
                          {p.name}({p.model})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </Field>
                <Field label={t("judge.judgeTimeout")}>
                  <Input
                    type="number"
                    min={1}
                    value={cfg.timeout_seconds}
                    onChange={(e) => {
                      const n = parseInt(e.target.value, 10);
                      if (n > 0) patch({ timeout_seconds: n });
                    }}
                  />
                </Field>
                <Field label={t("judge.failAction")}>
                  <Select
                    value={cfg.fail_action}
                    onValueChange={(v) => patch({ fail_action: v as JudgeConfig["fail_action"] })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="allow">{t("judge.failAllow")}</SelectItem>
                      <SelectItem value="ask">{t("judge.failAsk")}</SelectItem>
                      <SelectItem value="deny">{t("judge.failDeny")}</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
              </div>

              <Separator />

              <div className="space-y-4">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  {t("judge.manualApproval")}
                </p>
                <Field label={t("judge.askTimeout")}>
                  <Input
                    type="number"
                    min={5}
                    value={cfg.ask_timeout_seconds}
                    onChange={(e) => {
                      const n = parseInt(e.target.value, 10);
                      if (n > 0) patch({ ask_timeout_seconds: n });
                    }}
                  />
                </Field>
                <Field label={t("judge.askTimeoutAction")}>
                  <Select
                    value={cfg.ask_timeout_action}
                    onValueChange={(v) => patch({ ask_timeout_action: v as JudgeConfig["ask_timeout_action"] })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="deny">{t("judge.askTimeoutDeny")}</SelectItem>
                      <SelectItem value="allow">{t("judge.askTimeoutAllow")}</SelectItem>
                    </SelectContent>
                  </Select>
                </Field>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      <div className="flex justify-end">
        <Button size="sm" onClick={save} disabled={saving || loading}>
          {saving ? t("judge.saving") : t("judge.saveConfig")}
        </Button>
      </div>
    </div>
  );
}

// ---- page ----

export default function InterceptPage() {
  const t = useTranslations("interceptPage");
  const [rules, setRules] = React.useState<InterceptRule[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<InterceptRule | null>(null);
  const [form, setForm] = React.useState<RuleForm>(defaultForm());
  const [saving, setSaving] = React.useState(false);
  const [regexErr, setRegexErr] = React.useState("");
  const [regexWarn, setRegexWarn] = React.useState(false); // true = JS 는 못 파싱하지만 Go 에서는 유효한 문법일 수 있음

  // ---- tool scope dialog ----
  const [scopeOpen, setScopeOpen] = React.useState(false);
  const [allTools, setAllTools] = React.useState<Tool[]>([]);
  const [enabledTools, setEnabledTools] = React.useState<Set<string>>(new Set());
  const [scopeLoading, setScopeLoading] = React.useState(false);
  const [scopeSaving, setScopeSaving] = React.useState(false);
  const [scopeTools, setScopeTools] = React.useState<string[]>([]); // 페이지 머리 정보 바: 현재 가로채기에 들어간 도구

  // ---- data ----

  const loadScope = React.useCallback(async () => {
    try {
      const cfg = await api.interceptGetToolConfig();
      setScopeTools(cfg.enabled_tools);
    } catch {
      // 정보 바는 핵심이 아니라 실패하면 조용히 넘긴다
    }
  }, []);

  const load = React.useCallback(async () => {
    try {
      const r = await api.interceptRules();
      setRules(r);
    } catch {
      toast.error(t("toast.loadRulesFailed"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  React.useEffect(() => {
    void load();
    void loadScope();
  }, [load, loadScope]);

  React.useEffect(() => {
    if (form.match_type !== "regex" || !form.pattern) {
      setRegexErr("");
      setRegexWarn(false);
      return;
    }
    try {
      new RegExp(form.pattern);
      setRegexErr("");
      setRegexWarn(false);
    } catch {
      // JS RegExp 는 Go RE2 확장 문법(예: (?i) 인라인 플래그)을 지원하지 않는다.
      // 여기서의 미리 보기 검증 실패가 Go 에서 무효하다는 뜻은 아니며, 최종 검증은 서버에 맡긴다.
      setRegexErr("");
      setRegexWarn(true);
    }
  }, [form.pattern, form.match_type]);

  // ---- rule handlers ----

  function set(patch: Partial<RuleForm>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  function openNew() {
    setEditing(null);
    setForm(defaultForm());
    setRegexErr("");
    setOpen(true);
  }

  function openEdit(rule: InterceptRule) {
    setEditing(rule);
    setForm({
      name: rule.name,
      enabled: rule.enabled,
      priority: rule.priority,
      match_target: rule.match_target,
      match_type: rule.match_type,
      pattern: rule.pattern,
      action: rule.action,
      message: rule.message,
      timeout_enabled: rule.timeout_enabled,
      timeout_seconds: rule.timeout_seconds,
      timeout_action: rule.timeout_action,
    });
    setRegexErr("");
    setOpen(true);
  }

  async function handleSave() {
    if (!form.name.trim()) {
      toast.error(t("toast.nameRequired"));
      return;
    }
    if (!form.pattern.trim()) {
      toast.error(t("toast.patternRequired"));
      return;
    }
    if (regexErr) {
      toast.error(t("toast.regexInvalid"));
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await api.updateInterceptRule(editing.id, form);
        toast.success(t("toast.ruleUpdated"));
      } else {
        await api.createInterceptRule(form);
        toast.success(t("toast.ruleCreated"));
      }
      setOpen(false);
      void load();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: number) {
    try {
      await api.deleteInterceptRule(id);
      toast.success(t("toast.ruleDeleted"));
      void load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  async function handleToggle(rule: InterceptRule) {
    try {
      await api.toggleInterceptRule(rule.id, !rule.enabled);
      void load();
    } catch (e) {
      toast.error((e as Error).message);
    }
  }

  // ---- scope handlers ----

  async function openScope() {
    setScopeOpen(true);
    setScopeLoading(true);
    try {
      const [tools, cfg] = await Promise.all([api.tools(), api.interceptGetToolConfig()]);
      setAllTools(tools);
      setEnabledTools(new Set(cfg.enabled_tools));
    } catch (e) {
      toast.error(t("toast.loadFailed", { error: (e as Error).message }));
    } finally {
      setScopeLoading(false);
    }
  }

  function toggleTool(key: string, val: boolean) {
    setEnabledTools((prev) => {
      const next = new Set(prev);
      if (val) next.add(key);
      else next.delete(key);
      return next;
    });
  }

  async function saveScope() {
    setScopeSaving(true);
    try {
      await api.interceptSetToolConfig([...enabledTools]);
      toast.success(t("toast.scopeSaved"));
      setScopeTools([...enabledTools]);
      setScopeOpen(false);
    } catch (e) {
      toast.error(t("toast.saveFailed", { error: (e as Error).message }));
    } finally {
      setScopeSaving(false);
    }
  }

  const toolGroups = React.useMemo(() => {
    const mk = (key: string): Tool => ({
      key,
      system: true,
      description: t(`toolDesc.${key}`),
      schema: {},
      agents: [],
      enabled: true,
      kind: "builtin",
    });
    const sdkExec = SDK_EXEC_KEYS.map(mk);
    const sdkWrite = SDK_WRITE_KEYS.map(mk);
    const sys: Tool[] = [],
      custom: Tool[] = [];
    for (const tool of allTools) {
      if (SDK_KEYS.has(tool.key)) continue; // 하드코딩 그룹에서 이미 다룸
      if (tool.system) sys.push(tool);
      else custom.push(tool);
    }
    return [
      { label: t("toolGroup.exec"), tools: sdkExec },
      { label: t("toolGroup.write"), tools: sdkWrite },
      { label: t("toolGroup.system"), tools: sys },
      { label: t("toolGroup.custom"), tools: custom },
    ].filter((g) => g.tools.length > 0);
  }, [allTools, t]);

  // ---- render ----

  return (
    <div className="flex flex-1 flex-col gap-5 p-6">
      {/* ---- header ---- */}
      <div className="flex items-center gap-2.5">
        <ShieldAlertIcon className="h-5 w-5 shrink-0" />
        <div>
          <h1 className="text-lg font-semibold leading-tight">{t("title")}</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{t("subtitle")}</p>
        </div>
      </div>

      {/* ---- 가로채기 범위 정보 바(규칙 대조와 모델 폴백 공용: 범위 밖 도구는 둘 다 개입 안 함) ---- */}
      <div
        className={`flex items-center justify-between gap-3 rounded-lg border px-4 py-2.5 ${
          scopeTools.length === 0 ? "border-amber-400/60 bg-amber-50/50 dark:bg-amber-950/20" : "bg-muted/40"
        }`}
      >
        <div className="flex min-w-0 items-center gap-2 text-sm">
          <ListFilterIcon className="h-4 w-4 shrink-0 text-muted-foreground" />
          <span className="shrink-0 font-medium">{t("scope.label")}</span>
          {scopeTools.length === 0 ? (
            <span className="text-amber-700 dark:text-amber-500">{t("scope.empty")}</span>
          ) : (
            <>
              <Badge variant="secondary" className="shrink-0">
                {t("scope.toolCount", { count: scopeTools.length })}
              </Badge>
              <span className="truncate text-muted-foreground" title={scopeTools.join(" · ")}>
                {scopeTools.join(" · ")}
              </span>
            </>
          )}
        </div>
        <Button
          variant={scopeTools.length === 0 ? "default" : "outline"}
          size="sm"
          className="shrink-0"
          onClick={openScope}
        >
          <ListFilterIcon className="h-4 w-4" />
          {t("scope.adjust")}
        </Button>
      </div>

      <Tabs defaultValue="rules" className="flex-1">
        <TabsList>
          <TabsTrigger value="rules">{t("tab.rules")}</TabsTrigger>
          <TabsTrigger value="judge">{t("tab.model")}</TabsTrigger>
        </TabsList>

        {/* ---- tab: rules ---- */}
        <TabsContent value="rules" className="mt-4 flex flex-col gap-4">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs text-muted-foreground">{t("rules.priorityHint")}</p>
            <Button onClick={openNew} size="sm" className="shrink-0">
              <PlusIcon className="h-4 w-4" />
              {t("rules.add")}
            </Button>
          </div>

          <Card>
            <CardContent className="p-0">
              {loading ? (
                <p className="p-6 text-sm text-muted-foreground">{t("rules.loading")}</p>
              ) : rules.length === 0 ? (
                <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
                  <ShieldAlertIcon className="h-8 w-8 text-muted-foreground/40" />
                  <p className="text-sm text-muted-foreground">{t("rules.empty")}</p>
                  <Button size="sm" variant="outline" onClick={openNew}>
                    <PlusIcon className="h-4 w-4" />
                    {t("rules.addFirst")}
                  </Button>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="w-[72px]">{t("rules.colPriority")}</TableHead>
                      <TableHead>{t("rules.colName")}</TableHead>
                      <TableHead className="w-[90px]">{t("rules.colTarget")}</TableHead>
                      <TableHead className="w-[80px]">{t("rules.colType")}</TableHead>
                      <TableHead>{t("rules.colPattern")}</TableHead>
                      <TableHead className="w-[72px]">{t("rules.colAction")}</TableHead>
                      <TableHead className="w-[64px] text-center">{t("rules.colEnabled")}</TableHead>
                      <TableHead className="w-[80px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.map((rule) => (
                      <TableRow key={rule.id} className={!rule.enabled ? "opacity-40" : ""}>
                        <TableCell>
                          <span className="font-mono text-xs tabular-nums">{rule.priority}</span>
                        </TableCell>
                        <TableCell className="font-medium text-sm">{rule.name}</TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground">
                            {rule.match_target === "tool_name" ? t("target.tool_name") : t("target.tool_input")}
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="text-xs text-muted-foreground">
                            {rule.match_type === "regex" ? t("matchType.regex") : t("matchType.string")}
                          </span>
                        </TableCell>
                        <TableCell className="max-w-[220px]">
                          <code className="block truncate rounded bg-muted px-1.5 py-0.5 text-xs font-mono">
                            {rule.pattern}
                          </code>
                        </TableCell>
                        <TableCell>
                          <ActionBadge action={rule.action} label={t(`action.${rule.action}`)} />
                        </TableCell>
                        <TableCell className="text-center">
                          <Switch checked={rule.enabled} onCheckedChange={() => handleToggle(rule)} />
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center justify-end gap-0.5">
                            <Button size="icon" variant="ghost" className="h-7 w-7" onClick={() => openEdit(rule)}>
                              <PencilIcon className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              size="icon"
                              variant="ghost"
                              className="h-7 w-7 text-destructive hover:text-destructive"
                              onClick={() => handleDelete(rule.id)}
                            >
                              <Trash2Icon className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ---- tab: model ---- */}
        <TabsContent value="judge" className="mt-4">
          <JudgeCard />
        </TabsContent>
      </Tabs>

      {/* ---- editor sheet ---- */}
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="flex flex-col gap-0 p-0 sm:max-w-md">
          <SheetHeader className="border-b px-6 py-4">
            <SheetTitle>{editing ? t("editor.editTitle") : t("editor.newTitle")}</SheetTitle>
            <SheetDescription className="text-xs">{t("editor.desc")}</SheetDescription>
          </SheetHeader>

          <div className="flex-1 min-h-0 overflow-y-auto px-6 py-5 space-y-5">
            <Field label={t("editor.name")}>
              <Input
                placeholder={t("editor.namePlaceholder")}
                value={form.name}
                onChange={(e) => set({ name: e.target.value })}
              />
            </Field>

            <Field label={t("editor.priority")}>
              <Input
                type="number"
                value={form.priority}
                onChange={(e) => set({ priority: parseInt(e.target.value) || 0 })}
              />
            </Field>

            <Separator />

            <Field label={t("editor.matchTarget")}>
              <Select
                value={form.match_target}
                onValueChange={(v) => set({ match_target: v as RuleForm["match_target"] })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="tool_name">{t("editor.targetToolName")}</SelectItem>
                  <SelectItem value="tool_input">{t("editor.targetToolInput")}</SelectItem>
                </SelectContent>
              </Select>
            </Field>

            <Field label={t("editor.matchTypeLabel")}>
              <Select value={form.match_type} onValueChange={(v) => set({ match_type: v as RuleForm["match_type"] })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="string">{t("editor.typeStringContains")}</SelectItem>
                  <SelectItem value="regex">{t("editor.typeRegex")}</SelectItem>
                </SelectContent>
              </Select>
            </Field>

            <Field label={t("editor.pattern")}>
              <Input
                placeholder={form.match_type === "regex" ? "^Bash$" : "rm -rf"}
                value={form.pattern}
                onChange={(e) => set({ pattern: e.target.value })}
                className={regexErr ? "border-destructive focus-visible:ring-destructive" : ""}
              />
              {regexErr && <p className="text-xs text-destructive mt-1">{regexErr}</p>}
              {regexWarn && (
                <p className="text-xs text-amber-600 mt-1">
                  {t.rich("editor.regexWarn", { code: (c) => <code className="font-mono">{c}</code> })}
                </p>
              )}
            </Field>

            <Separator />

            <Field label={t("editor.actionLabel")}>
              <Select value={form.action} onValueChange={(v) => set({ action: v as InterceptAction })}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="allow">{t("editor.actionAllow")}</SelectItem>
                  <SelectItem value="deny">{t("editor.actionDeny")}</SelectItem>
                  <SelectItem value="ask">{t("editor.actionAsk")}</SelectItem>
                </SelectContent>
              </Select>
            </Field>

            {form.action !== "allow" && (
              <Field label={form.action === "deny" ? t("editor.denyMessage") : t("editor.askMessage")}>
                <Textarea
                  placeholder={form.action === "deny" ? t("editor.denyMessagePlaceholder") : ""}
                  value={form.message}
                  onChange={(e) => set({ message: e.target.value })}
                  rows={2}
                  className="resize-none"
                />
              </Field>
            )}

            {form.action === "ask" && (
              <>
                <Separator />
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium">{t("editor.enableTimeout")}</p>
                    <p className="text-xs text-muted-foreground">{t("editor.enableTimeoutHint")}</p>
                  </div>
                  <Switch checked={form.timeout_enabled} onCheckedChange={(v) => set({ timeout_enabled: v })} />
                </div>
                {form.timeout_enabled && (
                  <div className="flex items-end gap-3">
                    <Field label={t("editor.timeoutSeconds")}>
                      <Input
                        type="number"
                        min={5}
                        className="w-28"
                        value={form.timeout_seconds}
                        onChange={(e) => {
                          const n = parseInt(e.target.value, 10);
                          if (n > 0) set({ timeout_seconds: n });
                        }}
                      />
                    </Field>
                    <Field label={t("editor.timeoutAction")}>
                      <Select
                        value={form.timeout_action}
                        onValueChange={(v) => set({ timeout_action: v as "deny" | "allow" })}
                      >
                        <SelectTrigger className="w-32">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="deny">{t("editor.timeoutDeny")}</SelectItem>
                          <SelectItem value="allow">{t("editor.timeoutAllow")}</SelectItem>
                        </SelectContent>
                      </Select>
                    </Field>
                  </div>
                )}
              </>
            )}

            <Separator />

            <div className="flex items-center gap-3">
              <Switch id="rule-enabled" checked={form.enabled} onCheckedChange={(v) => set({ enabled: v })} />
              <Label htmlFor="rule-enabled" className="cursor-pointer">
                {t("editor.enableRule")}
              </Label>
            </div>
          </div>

          <SheetFooter className="border-t px-6 py-4 flex-row justify-end gap-2">
            <Button variant="outline" onClick={() => setOpen(false)}>
              {t("editor.cancel")}
            </Button>
            <Button onClick={handleSave} disabled={saving || !!regexErr}>
              {saving ? t("editor.saving") : t("editor.save")}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>

      {/* ---- scope dialog ---- */}
      <Dialog open={scopeOpen} onOpenChange={setScopeOpen}>
        <DialogContent
          className="sm:max-w-lg flex flex-col overflow-hidden p-0 gap-0"
          style={{ maxHeight: "min(80vh, 560px)" }}
        >
          <DialogHeader className="shrink-0 border-b px-6 py-4">
            <DialogTitle className="flex items-center gap-2">
              <ListFilterIcon className="h-4 w-4" />
              {t("scope.dialogTitle")}
            </DialogTitle>
            <DialogDescription className="text-xs">{t("scope.dialogDesc")}</DialogDescription>
          </DialogHeader>

          <div className="flex-1 min-h-0 overflow-y-auto px-6 py-4 space-y-5">
            {scopeLoading ? (
              <p className="text-sm text-muted-foreground py-4">{t("rules.loading")}</p>
            ) : (
              toolGroups.map((group, gi) => (
                <div key={group.label}>
                  {gi > 0 && <Separator className="mb-5" />}
                  <p className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider mb-2">
                    {group.label}
                  </p>
                  <div className="space-y-0.5">
                    {group.tools.map((tool) => (
                      <div key={tool.key} className="flex items-center gap-3 rounded-md px-2 py-1.5 hover:bg-muted/50">
                        <Switch
                          id={`scope-${tool.key}`}
                          checked={enabledTools.has(tool.key)}
                          onCheckedChange={(v) => toggleTool(tool.key, v)}
                        />
                        <label htmlFor={`scope-${tool.key}`} className="flex-1 min-w-0 cursor-pointer">
                          <div className="flex items-center gap-1.5">
                            <span className="font-mono text-sm">{tool.key}</span>
                            {tool.kind && tool.kind !== "builtin" && (
                              <Badge variant="outline" className="px-1 py-0 text-[10px]">
                                {tool.kind}
                              </Badge>
                            )}
                          </div>
                          {tool.description && (
                            <p className="text-[11px] text-muted-foreground line-clamp-1">{tool.description}</p>
                          )}
                        </label>
                      </div>
                    ))}
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="shrink-0 border-t px-6 py-3 flex justify-end gap-2">
            <Button variant="outline" size="sm" onClick={() => setScopeOpen(false)}>
              {t("editor.cancel")}
            </Button>
            <Button size="sm" onClick={saveScope} disabled={scopeSaving || scopeLoading}>
              {scopeSaving ? t("editor.saving") : t("editor.save")}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
