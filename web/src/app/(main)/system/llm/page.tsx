"use client";

import * as React from "react";

import {
  ChevronDownIcon,
  Loader2Icon,
  PlugZapIcon,
  PlusIcon,
  RefreshCwIcon,
  RotateCcwIcon,
  SaveIcon,
  StarIcon,
  Trash2Icon,
  ZapIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import { type CyberAccessProgram, daybreakEditorState, daybreakRequestProgram } from "@/lib/daybreak-profile";
import {
  ORCAROUTER_API_BASE,
  ORCAROUTER_CYBER_MODELS,
  ORCAROUTER_CYBER_MODELS_RECOMMENDED,
  ORCAROUTER_CYBER_PAGE,
  ORCAROUTER_DEFAULT_MODEL,
  optionsFromIDs,
  type SelectorOptions,
} from "@/lib/orcarouter-catalog";
import type { LLMPoolMember, LLMPoolStatus, LLMProfile, LLMRetryOverride } from "@/lib/types";
import { canKeepRemoteOllamaToken, isOllamaFormat, remoteOllamaOptions, remoteOllamaURL } from "@/lib/ollama-profile";
import type { LLMPoolMember, LLMPoolStatus, LLMProfile, LLMRetryOverride, OllamaStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

import { ProfileRetryFields, RetryPolicyPanel, ZERO_OVERRIDE } from "./_components/retry";

// 思考开关(thinking.type)与思考强度(reasoning_effort)是两个【互相独立】的字段，
// 各自单独设置——有些接口没有 thinking 字段、只靠强度参数就能激活思考，故需解耦。
// 存库空字符串 = 该字段【不发送】；Radix Select 不接受空 value，故 UI 用 "none"
// 哨兵表示不发送，存取时与 "" 互转（NONE / fromStore / toStore）。
const NONE = "none";
const OLLAMA_DOCKER_URL = "http://host.docker.internal:11434/v1";
const BEDROCK_BASE_URL_EXAMPLE = "https://bedrock-runtime.us-east-1.amazonaws.com/anthropic";
const BEDROCK_CONVERSE_BASE_URL_EXAMPLE = "https://bedrock-runtime.ap-northeast-2.amazonaws.com";
const MARKETPLACE_BASE_URL_EXAMPLE = "https://bedrock-runtime.us-east-1.amazonaws.com";
const MARKETPLACE_ARN = /^arn:aws:sagemaker:([a-z0-9-]+):\d{12}:endpoint\/[A-Za-z0-9-]+$/;
const marketplaceRegionFromARN = (arn: string) => MARKETPLACE_ARN.exec(arn.trim())?.[1] ?? "";
const marketplaceBaseURLFromARN = (arn: string) => {
  const region = marketplaceRegionFromARN(arn);
  return region ? `https://bedrock-runtime.${region}.amazonaws.com` : "";
};
const MODEL_PLACEHOLDERS: Record<LLMProfile["format"], string> = {
  anthropic: "claude-opus-4-8",
  openai: "claude-opus-4-8",
  "openai-responses": "claude-opus-4-8",
  ollama: "예: llama3.2",
  "ollama-remote": "예: qwen3:8b",
  bedrock: "us.anthropic.claude-sonnet-4-6",
  "bedrock-converse": "예: zai.glm-4.7 또는 사용 중인 Bedrock 모델 ID",
  "bedrock-marketplace": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/my-model",
  orcarouter: ORCAROUTER_DEFAULT_MODEL,
};
const BASE_URL_PLACEHOLDERS: Record<LLMProfile["format"], string> = {
  anthropic: "https://api.openai.com/v1",
  openai: "https://api.openai.com/v1",
  "openai-responses": "https://api.openai.com/v1",
  ollama: OLLAMA_DOCKER_URL,
  "ollama-remote": "https://ollama.lab.example/v1",
  bedrock: BEDROCK_BASE_URL_EXAMPLE,
  "bedrock-converse": BEDROCK_CONVERSE_BASE_URL_EXAMPLE,
  "bedrock-marketplace": MARKETPLACE_BASE_URL_EXAMPLE,
  orcarouter: ORCAROUTER_API_BASE,
};
const BASE_URL_LABEL_KEYS = {
  anthropic: "profile.baseUrl.label",
  openai: "profile.baseUrl.label",
  "openai-responses": "profile.baseUrl.label",
  ollama: "profile.baseUrl.label",
  "ollama-remote": "profile.remote.urlLabel",
  bedrock: "profile.baseUrl.bedrockLabel",
  "bedrock-converse": "profile.baseUrl.converseLabel",
  "bedrock-marketplace": "profile.baseUrl.marketplaceLabel",
  orcarouter: "profile.baseUrl.label",
} as const;
const MAX_TOKENS_HINT_KEYS = {
  anthropic: "profile.maxTokens.hint",
  openai: "profile.maxTokens.hint",
  "openai-responses": "profile.maxTokens.hint",
  ollama: "profile.maxTokens.hint",
  "ollama-remote": "profile.maxTokens.hint",
  bedrock: "profile.maxTokens.bedrockHint",
  "bedrock-converse": "profile.maxTokens.converseHint",
  "bedrock-marketplace": "profile.maxTokens.marketplaceHint",
  orcarouter: "profile.maxTokens.hint",
} as const;
const RATE_HINT_KEYS = {
  anthropic: "profile.rateHint",
  openai: "profile.rateHint",
  "openai-responses": "profile.rateHint",
  ollama: "profile.rateHintOllama",
  "ollama-remote": "profile.rateHintOllama",
  bedrock: "profile.rateHint",
  "bedrock-converse": "profile.rateHint",
  "bedrock-marketplace": "profile.rateHintMarketplace",
  orcarouter: "profile.rateHint",
} as const;
const fromStore = (v?: string) => (v ? v : NONE);
const toStore = (v: string) => (v === NONE ? "" : v);

function cooldownText(secs: number) {
  if (secs <= 0) return "";
  if (secs < 60) return `${secs}s`;
  return `${Math.ceil(secs / 60)}min`;
}

// 一个配置在卡片上显示的「是否正常」。没填 Key 的配置根本发不出请求，比熔断更该先说；
// 其余状态来自轮询的熔断记录（轮询关着时不会产生新记录，此时「正常」= 没有已知故障）。
// 文案走 i18n（llmPage.health.*），所以把 t 传进来由调用方注入。
type Health = { label: string; cls: string; hint?: string };

// ─────────────────────────────────────────────────────────────────────────────
// 轮询配置抽屉
// ─────────────────────────────────────────────────────────────────────────────

function PoolSheet({
  open,
  onOpenChange,
  pool,
  onReload,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  pool: LLMPoolStatus | null;
  onReload: () => Promise<void>;
}) {
  const t = useTranslations("llmPage");
  const [busy, setBusy] = React.useState(false);

  // 冷却倒计时是后端算出的剩余秒数——抽屉开着且有配置不正常时才定时拉，让它走起来。
  React.useEffect(() => {
    if (!open || !pool?.enabled || !pool.chain.some((m) => m.state !== "ok")) return;
    const t = setInterval(() => void onReload(), 10_000);
    return () => clearInterval(t);
  }, [open, pool, onReload]);

  async function toggle(patch: { llm_pool_enabled?: boolean; llm_pool_bind_fallback?: boolean }) {
    if (busy) return;
    setBusy(true);
    try {
      await api.setSettings(patch);
      await onReload();
      if (patch.llm_pool_enabled !== undefined) {
        toast.success(patch.llm_pool_enabled ? t("pool.toast.enabled") : t("pool.toast.disabled"));
      } else {
        toast.success(t("pool.toast.fallbackUpdated"));
      }
    } catch (e) {
      toast.error(t("pool.toast.setFailed", { msg: (e as Error).message }));
    } finally {
      setBusy(false);
    }
  }

  async function recover(id?: string) {
    try {
      await api.resetLLMPool(id);
      await onReload();
      toast.success(id ? t("pool.toast.recoveredOne") : t("pool.toast.recoveredAll"));
    } catch (e) {
      toast.error(t("pool.toast.recoverFailed", { msg: (e as Error).message }));
    }
  }

  const enabled = pool?.enabled ?? false;
  const chain = pool?.chain ?? [];
  // 参与轮询的成员（排除被标记「不参与轮询」的），顺序即后端实际的尝试顺序。
  const inChain = chain.filter((m) => m.active || !m.excluded);
  const tripped = chain.filter((m) => m.state === "tripped");

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="flex flex-col gap-0 p-0 data-[side=right]:sm:max-w-lg">
        <SheetHeader className="px-4">
          <SheetTitle className="flex items-center gap-2">
            <ZapIcon className="size-4" /> {t("pool.title")}
          </SheetTitle>
          <SheetDescription>{t.rich("pool.desc", { b: (c) => <b>{c}</b> })}</SheetDescription>
        </SheetHeader>

        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-6">
          <div className="flex items-center justify-between gap-4 rounded-lg border p-3">
            <div className="grid gap-0.5">
              <Label className="text-sm">{t("pool.enable.label")}</Label>
              <p className="text-muted-foreground text-xs">{t("pool.enable.hint")}</p>
            </div>
            <Switch
              checked={enabled}
              disabled={busy}
              onCheckedChange={(v) => void toggle({ llm_pool_enabled: v })}
              aria-label={t("pool.enable.aria")}
            />
          </div>

          {enabled && (
            <>
              <div className="flex items-center justify-between gap-4 rounded-lg border p-3">
                <div className="grid gap-0.5">
                  <Label className="text-sm">{t("pool.bindFallback.label")}</Label>
                  <p className="text-muted-foreground text-xs">{t("pool.bindFallback.hint")}</p>
                </div>
                <Switch
                  checked={pool?.bind_fallback ?? false}
                  disabled={busy}
                  onCheckedChange={(v) => void toggle({ llm_pool_bind_fallback: v })}
                  aria-label={t("pool.bindFallback.aria")}
                />
              </div>

              <Separator />

              <div className="grid gap-2">
                <div className="flex items-center justify-between">
                  <Label className="text-sm">{t("pool.order.label")}</Label>
                  {tripped.length > 0 && (
                    <Button size="sm" variant="ghost" onClick={() => void recover()}>
                      <RotateCcwIcon /> {t("pool.recoverAll")}
                    </Button>
                  )}
                </div>
                {inChain.length < 2 && (
                  <p className="text-muted-foreground text-xs">{t("pool.order.tooFew", { n: inChain.length })}</p>
                )}
                {chain.map((m) => {
                  const excluded = m.excluded && !m.active;
                  const order = excluded ? null : inChain.findIndex((x) => x.profile_id === m.profile_id) + 1;
                  return (
                    <div
                      key={m.profile_id}
                      className={cn(
                        "grid gap-1 rounded-lg border p-2.5 text-sm",
                        excluded && "opacity-55",
                        m.state === "tripped" && "border-destructive/40",
                      )}
                    >
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                        <span className="w-5 shrink-0 text-center font-mono text-muted-foreground text-xs">
                          {order ?? "—"}
                        </span>
                        <span className="font-medium">{m.name}</span>
                        {m.active && (
                          <Badge variant="outline" className="border-amber-400/50 text-amber-500">
                            {t("pool.badge.active")}
                          </Badge>
                        )}
                        {excluded && <Badge variant="outline">{t("pool.badge.excluded")}</Badge>}
                        <div className="ml-auto flex items-center gap-2">
                          {m.state === "tripped" && m.cooldown_secs > 0 && (
                            <span className="text-muted-foreground text-xs">
                              {t("pool.cooldown", { cooldown: cooldownText(m.cooldown_secs) })}
                            </span>
                          )}
                          {m.state === "degraded" && (
                            <span className="text-muted-foreground text-xs">
                              {t("pool.consecutiveFails", { fails: m.fails })}
                            </span>
                          )}
                          {m.state !== "ok" && (
                            <Button
                              size="icon"
                              variant="ghost"
                              className="size-7"
                              aria-label={t("pool.recoverNow.aria")}
                              title={t("pool.recoverNow.title")}
                              onClick={() => void recover(m.profile_id)}
                            >
                              <RotateCcwIcon className="size-3.5" />
                            </Button>
                          )}
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center gap-x-3 pl-7 text-muted-foreground text-xs">
                        <code className="truncate font-mono">{m.model}</code>
                        {!m.active && <span>{t("pool.priority", { priority: m.priority })}</span>}
                      </div>
                      {m.last_error && (
                        <p className="truncate pl-7 font-mono text-muted-foreground text-xs" title={m.last_error}>
                          {m.last_error}
                        </p>
                      )}
                    </div>
                  );
                })}
                {chain.length === 0 && (
                  <div className="rounded-lg border border-dashed p-4 text-center text-muted-foreground text-sm">
                    {t("pool.empty")}
                  </div>
                )}
              </div>

              <div className="rounded-lg border border-dashed p-3 text-muted-foreground text-xs leading-relaxed">
                {t("pool.note")}
              </div>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// OrcaRouter Cyber Inference 모델 선택기
//
// 옵션은 서버가 실제 카탈로그(GET /v1/models?capability=chat)에서 가져온 목록만
// 쓴다. 직접 입력 칸이 아니라 펼쳐지는 목록이며, 검색 성공 시 그 결과가 유일한
// 기준이고 실패하면 검증된 소규모 시드만 'degraded'로 표시한다.
// ─────────────────────────────────────────────────────────────────────────────

function OrcaRouterModelPicker({
  value,
  options,
  loading,
  onRefresh,
  onSelect,
  labels,
}: {
  value: string;
  options: SelectorOptions | null;
  loading: boolean;
  onRefresh: () => void;
  onSelect: (id: string) => void;
  labels: { trigger: string; refresh: string; empty: string; degraded: string };
}) {
  const [open, setOpen] = React.useState(false);
  const ids = options?.ids ?? [];
  return (
    <div className="flex gap-2">
      <Popover open={open} onOpenChange={setOpen} modal>
        <PopoverTrigger asChild>
          <Button
            id="p-model"
            type="button"
            variant="outline"
            className="min-w-0 flex-1 justify-between font-mono font-normal"
            aria-label="OrcaRouter model"
          >
            <span className="truncate">{labels.trigger}</span>
            <ChevronDownIcon className="size-4 shrink-0 text-muted-foreground" />
          </Button>
        </PopoverTrigger>
        <PopoverContent
          align="end"
          className="max-h-72 w-80 gap-0 overflow-y-auto overscroll-contain border border-border bg-popover p-1"
        >
          {options?.degraded && <p className="border-b px-2 py-1.5 text-muted-foreground text-xs">{labels.degraded}</p>}
          {ids.length === 0 && <p className="px-2 py-1.5 text-muted-foreground text-xs">{labels.empty}</p>}
          {ids.map((id) => (
            <button
              key={id}
              type="button"
              data-orca-model={id}
              aria-current={id === value ? "true" : undefined}
              className={cn(
                "w-full shrink-0 rounded-md px-2 py-1.5 text-left font-mono text-xs hover:bg-accent hover:text-accent-foreground",
                id === value && "bg-accent/60",
              )}
              onClick={() => {
                onSelect(id);
                setOpen(false);
              }}
            >
              {id}
            </button>
          ))}
        </PopoverContent>
      </Popover>
      <Button
        type="button"
        variant="outline"
        size="icon"
        className="shrink-0"
        disabled={loading}
        onClick={onRefresh}
        title={labels.refresh}
        aria-label={labels.refresh}
      >
        {loading ? <Loader2Icon className="animate-spin" /> : <RefreshCwIcon />}
      </Button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// 模型配置抽屉（新建 / 编辑共用同一套表单）
// ─────────────────────────────────────────────────────────────────────────────

function ProfileSheet({
  profile,
  open,
  onOpenChange,
  onSaved,
}: {
  profile: LLMProfile | null; // null = 新建
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: (id: string) => void;
}) {
  const t = useTranslations("llmPage");
  const isNew = !profile;
  const [name, setName] = React.useState("");
  const [format, setFormat] = React.useState<LLMProfile["format"]>("anthropic");
  const [model, setModel] = React.useState("");
  const [baseUrl, setBaseUrl] = React.useState("");
  const [proxy, setProxy] = React.useState("");
  const [apiKey, setApiKey] = React.useState("");
  const [remoteOptions, setRemoteOptions] = React.useState(remoteOllamaOptions());
  const [remoteStatus, setRemoteStatus] = React.useState<OllamaStatus | null>(null);
  const [checkingStatus, setCheckingStatus] = React.useState(false);
  const statusRequest = React.useRef(0);
  const lastStatusInput = React.useRef("");
  const [keyHint, setKeyHint] = React.useState("");
  const [rps, setRps] = React.useState("0");
  const [rpm, setRpm] = React.useState("0");
  const [cw, setCw] = React.useState("0"); // 上下文窗口(K tokens);0=默认200K
  const [thinkingType, setThinkingType] = React.useState(NONE);
  const [effort, setEffort] = React.useState(NONE);
  const [daybreakEnabled, setDaybreakEnabled] = React.useState(false);
  const [cyberProgram, setCyberProgram] = React.useState<CyberAccessProgram>("daybreak_blue");
  const [priority, setPriority] = React.useState("0"); // 轮询顺位;越大越先
  const [poolExclude, setPoolExclude] = React.useState(false);
  const [streaming, setStreaming] = React.useState(true); // true=流式(默认);false=非流式
  const [maxTokens, setMaxTokens] = React.useState("0"); // 单次回复输出上限;0=不发送
  const [maxTokensField, setMaxTokensField] = React.useState(NONE); // 上限用哪个字段名;NONE=max_tokens
  const [invokeSchema, setInvokeSchema] = React.useState<"tgi" | "deepseek">("tgi");
  const [promptStyle, setPromptStyle] = React.useState<"raw" | "deepseek" | "qwen" | "llama">("raw");
  const [sessionHeaderKey, setSessionHeaderKey] = React.useState(""); // 自定义会话头名;空=不发送
  const [retry, setRetry] = React.useState<LLMRetryOverride>(ZERO_OVERRIDE); // 本配置的重试覆盖;全 0=跟随全局
  const [testing, setTesting] = React.useState(false);
  const [testError, setTestError] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [models, setModels] = React.useState<string[]>([]);
  const [loadingModels, setLoadingModels] = React.useState(false);
  const [modelsOpen, setModelsOpen] = React.useState(false);
  // OrcaRouter keeps its discovered catalog separate: the options that reach the
  // model selector are capability-filtered there, never a raw string list.
  const [orcaCatalog, setOrcaCatalog] = React.useState<SelectorOptions | null>(null);

  // 思考开关 / 上限字段名 / 思考强度三组选项的标签走 i18n，故在组件内按当前语言构造。
  const THINKING_TYPES: { value: string; label: string }[] = [
    { value: NONE, label: t("profile.thinkingType.opt.none") },
    { value: "disabled", label: t("profile.thinkingType.opt.disabled") },
    { value: "enabled", label: t("profile.thinkingType.opt.enabled") },
  ];
  const MAX_TOKENS_FIELDS: { value: string; label: string }[] = [
    { value: NONE, label: t("profile.maxTokensField.opt.default") },
    { value: "max_completion_tokens", label: "max_completion_tokens" },
  ];
  const EFFORT_LEVELS: { value: string; label: string }[] = [
    { value: NONE, label: t("profile.effort.opt.none") },
    { value: "low", label: "low" },
    { value: "medium", label: "medium" },
    { value: "high", label: "high" },
    { value: "xhigh", label: "xhigh" },
    { value: "max", label: "max" },
  ];

  // 每次打开时从传入的 profile 灌一遍表单（新建则重置为默认值）。抽屉关掉再打开
  // 就是一次干净的开始，不会留下上一个配置的残影。
  React.useEffect(() => {
    if (!open) return;
    setName(profile?.name ?? "");
    setFormat(profile?.format ?? "anthropic");
    setModel(profile?.model ?? "");
    setBaseUrl(profile?.base_url ?? "");
    setProxy(profile?.proxy ?? "");
    setRps(String(profile?.rate_per_second ?? 0));
    setRpm(String(profile?.rate_per_minute ?? 0));
    setCw(String(profile?.context_window_k ?? 0));
    setThinkingType(fromStore(profile?.thinking_type));
    setEffort(fromStore(profile?.reasoning_effort));
    const daybreak = daybreakEditorState(profile?.format ?? "anthropic", profile?.cyber_access_program);
    setDaybreakEnabled(daybreak.enabled);
    setCyberProgram(daybreak.program);
    setPriority(String(profile?.priority ?? 0));
    setPoolExclude(profile?.pool_exclude ?? false);
    setStreaming(
      profile?.format === "bedrock-marketplace" || profile?.format === "bedrock-converse"
        ? false
        : (profile?.streaming ?? true),
    );
    setMaxTokens(String(profile?.max_tokens ?? 0));
    setMaxTokensField(fromStore(profile?.max_tokens_field));
    setInvokeSchema(profile?.invoke_schema ?? "tgi");
    setPromptStyle(profile?.prompt_style ?? "raw");
    setSessionHeaderKey(profile?.session_header_key ?? "");
    setRetry(profile?.retry ?? ZERO_OVERRIDE);
    setApiKey("");
    setRemoteOptions(remoteOllamaOptions(profile?.ollama_remote));
    setRemoteStatus(null);
    setKeyHint(profile?.api_key_hint ?? "");
    setTestError("");
    setModels([]);
    setModelsOpen(false);
  }, [open, profile]);

  const profileId = profile ? Number(profile.id) : undefined;
  const remote = format === "ollama-remote";
  const ollama = isOllamaFormat(format);
  const statusInput = JSON.stringify([baseUrl, apiKey, proxy, model, remoteOptions, format, open]);
  React.useEffect(() => {
    if (lastStatusInput.current === statusInput) return;
    lastStatusInput.current = statusInput;
    statusRequest.current++;
    setRemoteStatus(null);
    setCheckingStatus(false);
  }, [statusInput]);
  const marketplace = format === "bedrock-marketplace";
  const converse = format === "bedrock-converse";
  const isOrcaRouter = format === "orcarouter";
  const singleResponse = marketplace || converse;
  const bedrockKeyFormat = format === "bedrock" || converse || marketplace;
  let apiKeyPlaceholder = "sk-…";
  if (isOrcaRouter) apiKeyPlaceholder = "sk-orca-…";
  else if (bedrockKeyFormat) apiKeyPlaceholder = t("profile.apiKey.bedrockPlaceholder");
  let apiKeyPlaceholder = "sk-…";
  if (format === "bedrock" || converse || marketplace) apiKeyPlaceholder = t("profile.apiKey.bedrockPlaceholder");
  if (remote) apiKeyPlaceholder = t("profile.remote.tokenPlaceholder");
  let apiKeyLabel = "API Key";
  if (format === "bedrock" || converse || marketplace) apiKeyLabel = t("profile.apiKey.bedrockLabel");
  if (remote) apiKeyLabel = t("profile.remote.tokenLabel");
  const responseTestLabel = remote ? t("profile.remote.responseTest") : t("profile.testConnection");
  let loadedStatusLabel = t("profile.remote.unknown");
  if (remoteStatus?.running_known)
    loadedStatusLabel = t(remoteStatus.model_loaded ? "profile.remote.yes" : "profile.remote.no");

  function changeFormat(next: LLMProfile["format"]) {
    if (next === format) return;
    setTestError("");
    setRemoteOptions(remoteOllamaOptions());
    setRemoteStatus(null);
    setFormat(next);
    setModel("");
    setBaseUrl(next === "ollama" ? OLLAMA_DOCKER_URL : "");
    if (next === "bedrock-marketplace") setProxy("");
    setApiKey("");
    setKeyHint("");
    setModels([]);
    setModelsOpen(false);
    setInvokeSchema("tgi");
    setPromptStyle("raw");
    setStreaming(next !== "bedrock-marketplace" && next !== "bedrock-converse");
    if (next !== "openai-responses") setDaybreakEnabled(false);
    if (next === "orcarouter") {
      // Named provider defaults: its own API origin and its default routing model.
      applyOrcaRouterDefaults();
      return;
    }
    if (next === "ollama") {
    if (isOllamaFormat(next)) {
      setCw("32");
      setThinkingType(NONE);
      setEffort(NONE);
      setMaxTokensField(NONE);
    } else if (next === "bedrock" || next === "bedrock-converse" || next === "bedrock-marketplace") {
      setCw(next === "bedrock-marketplace" ? "32" : "0");
      setThinkingType(NONE);
      setEffort(NONE);
      setMaxTokens("0");
      setMaxTokensField(NONE);
      setSessionHeaderKey("");
    }
  }

  async function loadModels() {
    if (loadingModels) return;
    const remoteProblem = remoteError();
    if (remoteProblem) {
      setTestError(remoteProblem);
      return;
    }
    setLoadingModels(true);
    setModels([]);
    setOrcaCatalog(null);
    try {
      const r = await api.fetchLLMModels(format, baseUrl, apiKey, proxy, profileId, remote ? remoteOptions : undefined);
      if (r.ok && r.models && r.models.length > 0) {
        setModels(r.models);
        if (isOrcaRouter) setOrcaCatalog(optionsFromIDs(r.models));
        setModelsOpen(true);
        toast.success(t("profile.toast.modelsLoaded", { n: r.models.length }));
      } else {
        const error = r.error ?? t("profile.toast.noModels");
        // OrcaRouter keeps a small verified outage seed so a fresh install stays
        // usable; the selector marks it degraded instead of falling back to a
        // free-text field.
        if (isOrcaRouter) setOrcaCatalog(optionsFromIDs([], { degraded: true, error }));
        toast.error(t("profile.toast.loadModelsFailed", { error }));
      }
    } catch (e) {
      const msg = (e as Error).message;
      if (isOrcaRouter) setOrcaCatalog(optionsFromIDs([], { degraded: true, error: msg }));
      toast.error(t("profile.toast.loadModelsError", { msg }));
    } finally {
      setLoadingModels(false);
    }
  }

  // Switching to OrcaRouter rewrites the draft to the provider's own defaults so
  // the user never has to type a base URL or a model id by hand.
  function applyOrcaRouterDefaults() {
    setBaseUrl(ORCAROUTER_API_BASE);
    setModel(ORCAROUTER_DEFAULT_MODEL);
    setModels([]);
    setOrcaCatalog(null);
  function remoteError() {
    if (!remote) return "";
    if (!remoteOllamaURL(baseUrl)) return t("profile.remote.invalidUrl");
    if (remoteOptions.auth_mode === "bearer" && !apiKey.trim() && !canKeepRemoteOllamaToken(profile, baseUrl))
      return t("profile.remote.tokenRequired");
    if (
      remoteOptions.max_concurrent < 1 ||
      remoteOptions.max_concurrent > 8 ||
      remoteOptions.queue_timeout_seconds < 1 ||
      remoteOptions.queue_timeout_seconds > 3600 ||
      remoteOptions.request_timeout_seconds < 5 ||
      remoteOptions.request_timeout_seconds > 7200
    )
      return t("profile.remote.invalidLimits");
    return "";
  }

  async function checkStatus() {
    const error = remoteError();
    if (error) {
      setTestError(error);
      return;
    }
    if (checkingStatus) return;
    setCheckingStatus(true);
    const request = ++statusRequest.current;
    setTestError("");
    setRemoteStatus(null);
    try {
      const result = await api.ollamaStatus({
        provider: format,
        model,
        base_url: baseUrl,
        api_key: apiKey,
        proxy,
        profile_id: profileId,
        ollama_remote: remoteOptions,
      });
      if (request !== statusRequest.current) return;
      if (result.ok && result.status) setRemoteStatus(result.status);
      else setTestError(result.error ?? t("profile.toast.unknown"));
    } catch (error) {
      if (request === statusRequest.current) setTestError((error as Error).message);
    } finally {
      if (request === statusRequest.current) setCheckingStatus(false);
    }
  }

  async function testConnection() {
    if (testing) return;
    const remoteProblem = remoteError();
    if (remoteProblem) {
      setTestError(remoteProblem);
      return;
    }
    setTestError("");
    if (marketplace && (!MARKETPLACE_ARN.test(model.trim()) || !baseUrl.trim() || (!apiKey.trim() && !keyHint))) {
      const error = t("profile.toast.marketplaceCredentialsRequired");
      setTestError(error);
      toast.error(error);
      return;
    }
    if (
      (format === "bedrock" || converse) &&
      (!baseUrl.trim() || (!apiKey.trim() && !keyHint) || (converse && !model.trim()))
    ) {
      const error = t(
        converse ? "profile.toast.converseCredentialsRequired" : "profile.toast.bedrockCredentialsRequired",
      );
      setTestError(error);
      toast.error(error);
      return;
    }
    setTesting(true);
    try {
      // 用配置实际会跑的思考参数来测，这样不支持该字段的模型在这里就失败，
      // 而不是等到跑任务时才炸。传 profile id：Key 输入框留空时用已存的 Key。
      const r = await api.testLLM(
        format,
        model,
        baseUrl,
        apiKey,
        marketplace ? "" : proxy,
        ollama || singleResponse ? "" : toStore(thinkingType),
        ollama || singleResponse ? "" : toStore(effort),
        profileId,
        singleResponse ? false : streaming,
        marketplace ? "" : sessionHeaderKey.trim(),
        daybreakRequestProgram(format, daybreakEnabled, cyberProgram),
        Math.max(0, Number(maxTokens) || 0),
        marketplace ? invokeSchema : "",
        marketplace ? promptStyle : "",
        remote ? remoteOptions : undefined,
      );
      // 回复内容一并展示：看得见模型确实说了话，才算和会话里跑通是一回事。
      if (r.ok)
        toast.success(t("profile.toast.testOk", { latency: r.latency_ms ?? "?", model: r.model ?? model }), {
          description: r.reply ? t("profile.toast.testReply", { reply: r.reply }) : undefined,
        });
      else {
        const error = t("profile.toast.testFailed", { error: r.error ?? t("profile.toast.unknown") });
        setTestError(error);
        toast.error(error);
      }
    } catch (e) {
      const error = t("profile.toast.testError", { msg: (e as Error).message });
      setTestError(error);
      toast.error(error);
    } finally {
      setTesting(false);
    }
  }

  async function save() {
    const remoteProblem = remoteError();
    if (remoteProblem) {
      setTestError(remoteProblem);
      return;
    }
    if (!name.trim() || !model.trim()) {
      toast.error(t("profile.toast.nameModelRequired"));
      return;
    }
    if ((format === "bedrock" || converse) && (!baseUrl.trim() || (!apiKey.trim() && !keyHint))) {
      toast.error(
        t(converse ? "profile.toast.converseCredentialsRequired" : "profile.toast.bedrockCredentialsRequired"),
      );
      return;
    }
    if (marketplace && (!MARKETPLACE_ARN.test(model.trim()) || !baseUrl.trim() || (!apiKey.trim() && !keyHint))) {
      toast.error(t("profile.toast.marketplaceCredentialsRequired"));
      return;
    }
    if (saving) return;
    setSaving(true);
    try {
      const { id } = await api.saveLLMProfile({
        ...(profile ? { id: Number(profile.id) } : {}),
        name: name.trim(),
        format,
        model: model.trim(),
        base_url: baseUrl.trim(),
        proxy: marketplace ? "" : proxy.trim(),
        api_key: remote && remoteOptions.auth_mode === "none" ? "" : apiKey,
        ollama_remote: remote ? remoteOptions : undefined,
        rate_per_second: Number(rps) || 0,
        rate_per_minute: Number(rpm) || 0,
        context_window_k: Number(cw) || 0,
        thinking_type: ollama || singleResponse ? "" : toStore(thinkingType),
        reasoning_effort: ollama || singleResponse ? "" : toStore(effort),
        cyber_access_program: daybreakRequestProgram(format, daybreakEnabled, cyberProgram),
        priority: Number(priority) || 0,
        pool_exclude: poolExclude,
        streaming: singleResponse ? false : streaming,
        max_tokens: Math.max(0, Number(maxTokens) || 0),
        // 字段名开关只对 openai(Chat Completions) 有意义，其它格式一律回落到默认；
        // 后端也会再做一次同样的归一化，这里只是别让 UI 送出自相矛盾的值。
        max_tokens_field: format === "openai" ? toStore(maxTokensField) : "",
        ...(marketplace ? { invoke_schema: invokeSchema, prompt_style: promptStyle } : {}),
        session_header_key: marketplace ? "" : sessionHeaderKey.trim(),
        retry,
      });
      if (isNew) toast.success(t("profile.toast.created", { name: name.trim() }));
      else toast.success(profile?.is_default ? t("profile.toast.savedActive") : t("profile.toast.saved"));
      onSaved(String(id));
      onOpenChange(false);
    } catch (e) {
      toast.error(t("profile.toast.saveFailed", { msg: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="flex flex-col gap-0 p-0 data-[side=right]:min-w-[420px] data-[side=right]:sm:max-w-xl"
      >
        <SheetHeader className="px-4">
          <SheetTitle className="flex items-center gap-2">
            {isNew ? t("profile.titleNew") : t("profile.titleEdit", { name: profile?.name ?? "" })}
            {profile?.is_default && (
              <Badge variant="outline" className="border-amber-400/50 text-amber-500">
                {t("profile.activeBadge")}
              </Badge>
            )}
          </SheetTitle>
          <SheetDescription>{isNew ? t("profile.descNew") : t("profile.descEdit")}</SheetDescription>
        </SheetHeader>

        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="p-name">{t("profile.name.label")}</Label>
              <Input
                id="p-name"
                placeholder={t("profile.name.placeholder")}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label>{t("profile.format.label")}</Label>
              <Select value={format} onValueChange={(v) => changeFormat(v as LLMProfile["format"])}>
                <SelectTrigger>
                  <SelectValue placeholder={t("profile.format.placeholder")} />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="anthropic">Anthropic</SelectItem>
                  <SelectItem value="openai">OpenAI (Chat Completions)</SelectItem>
                  <SelectItem value="openai-responses">OpenAI (Responses API)</SelectItem>
                  <SelectItem value="ollama">{t("profile.format.ollama")}</SelectItem>
                  <SelectItem value="ollama-remote">{t("profile.format.ollamaRemote")}</SelectItem>
                  <SelectItem value="bedrock-converse">{t("profile.format.converse")}</SelectItem>
                  <SelectItem value="orcarouter">{t("profile.format.orcarouter")}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid gap-2">
            <Label htmlFor="p-model">{t(marketplace ? "profile.model.marketplaceLabel" : "profile.model.label")}</Label>
            {isOrcaRouter ? (
              <OrcaRouterModelPicker
                value={model}
                options={orcaCatalog}
                loading={loadingModels}
                onRefresh={loadModels}
                onSelect={(id) => {
                  setModel(id);
                  setTestError("");
                }}
                labels={{
                  trigger: model || t("profile.model.orcaPlaceholder"),
                  refresh: t("profile.model.loadTitle"),
                  empty: t("profile.model.orcaEmpty"),
                  degraded: t("profile.model.orcaDegraded"),
                }}
              />
            ) : (
              <div className="flex gap-2">
                <Input
                  id="p-model"
                  className="font-mono"
                  placeholder={MODEL_PLACEHOLDERS[format]}
                  value={model}
                  onChange={(e) => {
                    const nextModel = e.target.value;
                    setTestError("");
                    if (marketplace) {
                      const previousAutoURL = marketplaceBaseURLFromARN(model);
                      const nextAutoURL = marketplaceBaseURLFromARN(nextModel);
                      if (nextAutoURL && (!baseUrl.trim() || baseUrl === previousAutoURL)) setBaseUrl(nextAutoURL);
                    }
                    setModel(nextModel);
                  }}
                />
                {/* modal: 这个 Popover 的内容被 portal 到 <body>，在 Sheet 的滚动锁之外，
                  不加 modal 时列表能渲染却滚不动。modal 让它自己持有最上层滚动锁。 */}
                {format !== "bedrock" && !converse && !marketplace && (
                  <Popover open={modelsOpen} onOpenChange={setModelsOpen} modal>
                    <PopoverTrigger asChild>
                      <Button
                        type="button"
                        variant="outline"
                        size="icon"
                        className="shrink-0"
                        disabled={loadingModels}
                        onClick={loadModels}
                        title={t("profile.model.loadTitle")}
                      >
                        {loadingModels ? <Loader2Icon className="animate-spin" /> : <RefreshCwIcon />}
                      </Button>
                    </PopoverTrigger>
                    {models.length > 0 && (
                      <PopoverContent
                        className="max-h-72 w-72 gap-0 overflow-y-auto overscroll-contain p-1"
                        align="end"
                      >
                        {models.map((m) => (
                          <button
                            key={m}
                            type="button"
                            className="w-full shrink-0 rounded-md px-2 py-1.5 text-left font-mono text-xs hover:bg-accent hover:text-accent-foreground"
                            onClick={() => {
                              setModel(m);
                              setModelsOpen(false);
                            }}
                          >
                            {m}
                          </button>
                        ))}
                      </PopoverContent>
                    )}
                  </Popover>
                )}
              </div>
            )}
          </div>

          {ollama && <p className="-mt-2 text-muted-foreground text-xs">{t("profile.model.ollamaHint")}</p>}
          {format === "bedrock" && (
            <p className="-mt-2 text-muted-foreground text-xs">{t("profile.model.bedrockHint")}</p>
          )}
          {converse && <p className="-mt-2 text-muted-foreground text-xs">{t("profile.model.converseHint")}</p>}
          {marketplace && (
            <div className="-mt-2 grid gap-1 text-muted-foreground text-xs">
              <p>{t("profile.model.marketplaceHint")}</p>
              {marketplaceRegionFromARN(model) && (
                <p>{t("profile.marketplace.region", { region: marketplaceRegionFromARN(model) })}</p>
              )}
            </div>
          )}

          {isOrcaRouter && (
            <div className="-mt-2 grid gap-2 rounded-lg border p-3 text-xs">
              <p className="text-muted-foreground">{t("profile.orcarouter.intro")}</p>
              <div className="flex flex-wrap gap-x-3 gap-y-1">
                <a
                  className="underline underline-offset-2"
                  href={ORCAROUTER_CYBER_PAGE}
                  target="_blank"
                  rel="noreferrer"
                >
                  OrcaRouter Cyber
                </a>
                <a
                  className="underline underline-offset-2"
                  href={ORCAROUTER_CYBER_MODELS}
                  target="_blank"
                  rel="noreferrer"
                >
                  {t("profile.orcarouter.modelsLink")}
                </a>
              </div>
              <div className="grid gap-1">
                <p className="font-medium">{t("profile.orcarouter.defaultLabel")}</p>
                <code className="font-mono">{ORCAROUTER_DEFAULT_MODEL}</code>
                <p className="font-medium">{t("profile.orcarouter.cyberLabel")}</p>
                {ORCAROUTER_CYBER_MODELS_RECOMMENDED.map((model) => (
                  <p key={model.id} className="text-muted-foreground">
                    <code className="font-mono">{model.id}</code> — {model.label}
                  </p>
                ))}
                <p className="text-muted-foreground">{t("profile.orcarouter.cyberHint")}</p>
              </div>
            </div>
          )}

          <div className="grid gap-2">
            <Label htmlFor="p-base-url">{t(BASE_URL_LABEL_KEYS[format])}</Label>
            <Input
              id="p-base-url"
              className="font-mono"
              placeholder={BASE_URL_PLACEHOLDERS[format]}
              value={baseUrl}
              onChange={(e) => {
                setBaseUrl(e.target.value);
                setTestError("");
              }}
            />
            {format === "ollama" && <p className="text-muted-foreground text-xs">{t("profile.baseUrl.ollamaHint")}</p>}
            {format === "bedrock" && (
              <p className="text-muted-foreground text-xs">{t("profile.baseUrl.bedrockHint")}</p>
            )}
            {converse && <p className="text-muted-foreground text-xs">{t("profile.baseUrl.converseHint")}</p>}
            {marketplace && <p className="text-muted-foreground text-xs">{t("profile.baseUrl.marketplaceHint")}</p>}
          </div>

          {remote && (
            <div className="grid gap-3 rounded-md border p-3">
              <p className="text-muted-foreground text-xs">{t("profile.remote.hint")}</p>
              <div className="grid gap-2">
                <Label htmlFor="p-remote-auth">{t("profile.remote.authLabel")}</Label>
                <Select
                  value={remoteOptions.auth_mode}
                  onValueChange={(value) => {
                    setRemoteOptions({ ...remoteOptions, auth_mode: value as "none" | "bearer" });
                    setApiKey("");
                    setKeyHint("");
                  }}
                >
                  <SelectTrigger id="p-remote-auth">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">{t("profile.remote.authNone")}</SelectItem>
                    <SelectItem value="bearer">{t("profile.remote.authBearer")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-3 sm:grid-cols-3">
                <div className="grid gap-2">
                  <Label htmlFor="p-remote-concurrency">{t("profile.remote.concurrency")}</Label>
                  <Input
                    id="p-remote-concurrency"
                    type="number"
                    min={1}
                    max={8}
                    value={remoteOptions.max_concurrent}
                    onChange={(event) =>
                      setRemoteOptions({ ...remoteOptions, max_concurrent: Number(event.target.value) })
                    }
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="p-remote-queue">{t("profile.remote.queueTimeout")}</Label>
                  <Input
                    id="p-remote-queue"
                    type="number"
                    min={1}
                    max={3600}
                    value={remoteOptions.queue_timeout_seconds}
                    onChange={(event) =>
                      setRemoteOptions({ ...remoteOptions, queue_timeout_seconds: Number(event.target.value) })
                    }
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="p-remote-timeout">{t("profile.remote.requestTimeout")}</Label>
                  <Input
                    id="p-remote-timeout"
                    type="number"
                    min={5}
                    max={7200}
                    value={remoteOptions.request_timeout_seconds}
                    onChange={(event) =>
                      setRemoteOptions({ ...remoteOptions, request_timeout_seconds: Number(event.target.value) })
                    }
                  />
                </div>
              </div>
              <p className="text-muted-foreground text-xs">{t("profile.remote.limitsHint")}</p>
              <Button type="button" variant="outline" onClick={checkStatus} disabled={checkingStatus}>
                {checkingStatus ? <Loader2Icon className="animate-spin" /> : <RefreshCwIcon />}
                {t("profile.remote.checkStatus")}
              </Button>
              <p className="text-muted-foreground text-xs">{t("profile.remote.statusHint")}</p>
              {remoteStatus && (
                <p role="status" className="text-sm">
                  {t("profile.remote.statusResult", {
                    time: new Date(remoteStatus.checked_at).toLocaleString(),
                    available: t(remoteStatus.model_available ? "profile.remote.yes" : "profile.remote.no"),
                    loaded: loadedStatusLabel,
                  })}
                </p>
              )}
            </div>
          )}

          {!marketplace && (
            <div className="grid gap-2">
              <Label htmlFor="p-proxy">{t("profile.proxy.label")}</Label>
              <Input
                id="p-proxy"
                className="font-mono"
                placeholder="socks5://user:pass@127.0.0.1:1080 · http://127.0.0.1:8080"
                value={proxy}
                onChange={(e) => setProxy(e.target.value)}
              />
              <p className="text-muted-foreground text-xs">{t("profile.proxy.hint")}</p>
            </div>
          )}

          {!marketplace && (
            <div className="grid gap-2">
              <Label htmlFor="p-session-header">{t("profile.sessionHeader.label")}</Label>
              <Input
                id="p-session-header"
                className="font-mono"
                placeholder={t("profile.sessionHeader.placeholder")}
                value={sessionHeaderKey}
                onChange={(e) => setSessionHeaderKey(e.target.value)}
              />
              <p className="text-muted-foreground text-xs">
                {t.rich("profile.sessionHeader.hint", { b: (c) => <b>{c}</b> })}
              </p>
            </div>
          )}

          {(!ollama || (remote && remoteOptions.auth_mode === "bearer")) && (
            <div className="grid gap-2">
              <Label htmlFor="p-api-key">{apiKeyLabel}</Label>
              <Input
                id="p-api-key"
                type="password"
                placeholder={
                  keyHint && (!remote || canKeepRemoteOllamaToken(profile, baseUrl))
                    ? t("profile.apiKey.placeholderSet", { hint: keyHint })
                    : apiKeyPlaceholder
                }
                value={apiKey}
                onChange={(e) => {
                  setApiKey(e.target.value);
                  setTestError("");
                }}
              />
              {(format === "bedrock" || converse || marketplace) && (
                <p className="text-muted-foreground text-xs">{t("profile.apiKey.bedrockHint")}</p>
              )}
              {isOrcaRouter && (
                <p className="text-muted-foreground text-xs">
                  {t("profile.apiKey.orcaHint")}{" "}
                  <a
                    className="underline underline-offset-2"
                    href="https://www.orcarouter.ai/console/keys"
                    target="_blank"
                    rel="noreferrer"
                  >
                    OrcaRouter
                  </a>
                </p>
              )}
            </div>
          )}

          {marketplace && (
            <div className="grid gap-3 rounded-lg border p-3">
              <p className="text-muted-foreground text-xs">{t("profile.marketplace.hint")}</p>
              <div className="grid gap-2">
                <Label>{t("profile.marketplace.schemaLabel")}</Label>
                <Select value={invokeSchema} onValueChange={(value) => setInvokeSchema(value as typeof invokeSchema)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="tgi">{t("profile.marketplace.schemaTgi")}</SelectItem>
                    <SelectItem value="deepseek">{t("profile.marketplace.schemaDeepseek")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label>{t("profile.marketplace.promptLabel")}</Label>
                <Select value={promptStyle} onValueChange={(value) => setPromptStyle(value as typeof promptStyle)}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="raw">{t("profile.marketplace.promptRaw")}</SelectItem>
                    <SelectItem value="deepseek">{t("profile.marketplace.promptDeepseek")}</SelectItem>
                    <SelectItem value="qwen">{t("profile.marketplace.promptQwen")}</SelectItem>
                    <SelectItem value="llama">{t("profile.marketplace.promptLlama")}</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <p className="text-muted-foreground text-xs">{t("profile.marketplace.testHint")}</p>
            </div>
          )}

          {format === "openai-responses" && (
            <div className="grid gap-3 rounded-lg border p-3">
              <div className="flex items-center justify-between gap-4">
                <div className="grid gap-0.5">
                  <Label className="text-sm">{t("profile.daybreak.enabled")}</Label>
                  <p className="text-muted-foreground text-xs">{t("profile.daybreak.hint")}</p>
                </div>
                <Switch
                  checked={daybreakEnabled}
                  onCheckedChange={setDaybreakEnabled}
                  aria-label={t("profile.daybreak.enabled")}
                />
              </div>
              {daybreakEnabled && (
                <div className="flex items-center justify-between gap-4 border-t pt-3">
                  <Label className="text-sm">{t("profile.daybreak.program")}</Label>
                  <Select value={cyberProgram} onValueChange={(v) => setCyberProgram(v as CyberAccessProgram)}>
                    <SelectTrigger className="w-48 shrink-0">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="daybreak_blue">Daybreak Blue</SelectItem>
                      <SelectItem value="daybreak_red">Daybreak Red</SelectItem>
                      <SelectItem value="standard">Standard</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>
          )}

          <div className="grid gap-4 sm:grid-cols-3">
            <div className="grid gap-2">
              <Label htmlFor="p-rps">{t("profile.rps")}</Label>
              <Input id="p-rps" type="number" min={0} value={rps} onChange={(e) => setRps(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="p-rpm">{t("profile.rpm")}</Label>
              <Input id="p-rpm" type="number" min={0} value={rpm} onChange={(e) => setRpm(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="p-cw">{t("profile.cw")}</Label>
              <Input
                id="p-cw"
                type="number"
                min={0}
                max={1000}
                value={cw}
                onChange={(e) => setCw(e.target.value)}
                placeholder={ollama || marketplace ? "32" : "200"}
              />
            </div>
          </div>
          <p className="-mt-2 text-muted-foreground text-xs">{t(RATE_HINT_KEYS[format])}</p>

          <div className="grid gap-3 rounded-lg border p-3">
            <div className="flex items-center justify-between gap-4">
              <div className="grid gap-0.5">
                <Label htmlFor="p-priority" className="text-sm">
                  {t("profile.priority.label")}
                </Label>
                <p className="text-muted-foreground text-xs">{t("profile.priority.hint")}</p>
              </div>
              <Input
                id="p-priority"
                type="number"
                className="w-24 shrink-0"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
              />
            </div>
            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="grid gap-0.5">
                <Label className="text-sm">{t("profile.exclude.label")}</Label>
                <p className="text-muted-foreground text-xs">{t("profile.exclude.hint")}</p>
              </div>
              <Switch checked={poolExclude} onCheckedChange={setPoolExclude} aria-label={t("profile.exclude.aria")} />
            </div>
            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="grid gap-0.5">
                <Label className="text-sm">{t("profile.streaming.label")}</Label>
                <p className="text-muted-foreground text-xs">
                  {t(
                    marketplace
                      ? "profile.streaming.marketplaceHint"
                      : converse
                        ? "profile.streaming.converseHint"
                        : "profile.streaming.hint",
                  )}
                </p>
              </div>
              <Switch
                checked={singleResponse ? false : streaming}
                onCheckedChange={setStreaming}
                disabled={singleResponse}
                aria-label={t("profile.streaming.aria")}
              />
            </div>
          </div>

          <div className="grid gap-3 rounded-lg border p-3">
            <div className="flex items-center justify-between gap-4">
              <div className="grid gap-0.5">
                <Label htmlFor="p-max-tokens" className="text-sm">
                  {t("profile.maxTokens.label")}
                </Label>
                <p className="text-muted-foreground text-xs">{t(MAX_TOKENS_HINT_KEYS[format])}</p>
              </div>
              <Input
                id="p-max-tokens"
                type="number"
                min={0}
                className="w-28 shrink-0"
                value={maxTokens}
                onChange={(e) => setMaxTokens(e.target.value)}
                placeholder="0"
              />
            </div>
            {!marketplace && (
              <div className="flex items-center justify-between gap-4 border-t pt-3">
                <div className="grid gap-0.5">
                  <Label className="text-sm">{t("profile.maxTokensField.label")}</Label>
                  <p className="text-muted-foreground text-xs">{t(`profile.maxTokensFieldHint.${format}`)}</p>
                </div>
                <Select
                  value={format === "openai" ? maxTokensField : NONE}
                  onValueChange={setMaxTokensField}
                  disabled={format !== "openai"}
                >
                  <SelectTrigger className="w-56 shrink-0">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {MAX_TOKENS_FIELDS.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
          </div>

          {!ollama && !singleResponse && (
            <div className="grid gap-3 rounded-lg border p-3">
              <div className="flex items-center justify-between gap-4">
                <div className="grid gap-0.5">
                  <Label className="text-sm">{t("profile.thinkingType.label")}</Label>
                  <p className="text-muted-foreground text-xs">{t("profile.thinkingType.hint")}</p>
                </div>
                <Select value={thinkingType} onValueChange={setThinkingType}>
                  <SelectTrigger className="w-32 shrink-0">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {THINKING_TYPES.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="flex items-center justify-between gap-4 border-t pt-3">
                <div className="grid gap-0.5">
                  <Label className="text-sm">{t("profile.effort.label")}</Label>
                  <p className="text-muted-foreground text-xs">{t("profile.effort.hint")}</p>
                </div>
                <Select value={effort} onValueChange={setEffort}>
                  <SelectTrigger className="w-32 shrink-0">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {EFFORT_LEVELS.map((o) => (
                      <SelectItem key={o.value} value={o.value}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          )}

          <ProfileRetryFields value={retry} onChange={setRetry} />
        </div>

        <div className="shrink-0 border-t">
          {testError && (
            <p
              role="alert"
              className="mx-4 mt-3 max-h-32 overflow-y-auto rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2 text-xs text-destructive whitespace-pre-wrap [overflow-wrap:anywhere]"
            >
              {testError}
            </p>
          )}
          <div className="flex gap-2 px-4 py-3">
            <Button variant="outline" onClick={testConnection} disabled={testing}>
              {testing ? <Loader2Icon className="animate-spin" /> : <PlugZapIcon />}
              {testing ? t("profile.testing") : responseTestLabel}
            </Button>
            <Button onClick={save} disabled={saving} className="flex-1">
              {saving && <Loader2Icon className="animate-spin" />}
              {!saving && (isNew ? <PlusIcon /> : <SaveIcon />)}
              {isNew ? t("profile.create") : t("profile.save")}
            </Button>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}

// ─────────────────────────────────────────────────────────────────────────────

export default function LLMPage() {
  const t = useTranslations("llmPage");
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [pool, setPool] = React.useState<LLMPoolStatus | null>(null);
  const [poolOpen, setPoolOpen] = React.useState(false);
  // 抽屉的开关和内容分开存：关闭时 editing 保持不变，否则关闭动画期间标题会从
  // 「编辑 X」闪成「新建」。editing = null 表示新建。
  const [editOpen, setEditOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<LLMProfile | null>(null);
  const openEditor = React.useCallback((p: LLMProfile | null) => {
    setEditing(p);
    setEditOpen(true);
  }, []);

  // 一个配置在卡片上显示的「是否正常」。没填 Key 的配置根本发不出请求，比熔断更该先说。
  const healthOf = React.useCallback(
    (p: LLMProfile, m?: LLMPoolMember): Health => {
      if ((!isOllamaFormat(p.format) || p.ollama_remote?.auth_mode === "bearer") && !p.api_key_hint) {
        return {
          label: t("health.noKey.label"),
          cls: "border-muted-foreground/40 text-muted-foreground",
          hint: t("health.noKey.hint"),
        };
      }
      if (m?.state === "tripped") {
        return {
          label:
            m.cooldown_secs > 0
              ? t("health.trippedCooldown", { cooldown: cooldownText(m.cooldown_secs) })
              : t("health.tripped"),
          cls: "border-destructive/50 text-destructive",
          hint: m.last_error,
        };
      }
      if (m?.state === "degraded") {
        return {
          label: t("health.degraded", { fails: m.fails }),
          cls: "border-amber-500/50 text-amber-600 dark:text-amber-400",
          hint: m.last_error,
        };
      }
      return {
        label: t(p.format === "ollama-remote" ? "health.noKnownError" : "health.ok"),
        cls: "border-emerald-500/50 text-emerald-600 dark:text-emerald-400",
        hint: p.format === "ollama-remote" ? t("health.remoteHint") : undefined,
      };
    },
    [t],
  );

  const loadPool = React.useCallback(async () => {
    try {
      setPool(await api.llmPool());
    } catch {
      /* ignore */
    }
  }, []);

  const load = React.useCallback(async () => {
    try {
      setProfiles(await api.llmProfiles());
    } catch {
      /* ignore */
    }
    await loadPool();
  }, [loadPool]);

  React.useEffect(() => {
    void load();
  }, [load]);

  // 卡片上的健康徽章按 profile id 取轮询状态。
  const health = React.useMemo(() => {
    const m = new Map<string, LLMPoolMember>();
    for (const c of pool?.chain ?? []) m.set(c.profile_id, c);
    return m;
  }, [pool]);

  async function activate(id: string, name: string) {
    try {
      await api.activateLLMProfile(id);
      toast.success(t("page.toast.activated", { name }));
      await load();
    } catch (e) {
      toast.error(t("page.toast.activateFailed", { msg: (e as Error).message }));
    }
  }

  async function remove(p: LLMProfile) {
    if (p.is_default) {
      toast.error(t("page.toast.cannotDeleteActive"));
      return;
    }
    try {
      await api.deleteLLMProfile(p.id);
      toast.success(t("page.toast.deleted", { name: p.name }));
      await load();
    } catch (e) {
      toast.error(t("page.toast.deleteFailed", { msg: (e as Error).message }));
    }
  }

  const poolOn = pool?.enabled ?? false;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="font-semibold text-xl tracking-tight">LLM</h1>
          <p className="text-muted-foreground text-sm">{t("page.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="outline" onClick={() => setPoolOpen(true)}>
            <ZapIcon /> {t("page.poolConfig")}
            {poolOn && (
              <Badge variant="outline" className="ml-1 border-emerald-500/50 text-emerald-600 dark:text-emerald-400">
                {t("page.enabled")}
              </Badge>
            )}
          </Button>
          <Button size="sm" variant="outline" onClick={() => openEditor(null)}>
            <PlusIcon /> {t("page.new")}
          </Button>
        </div>
      </div>

      <Tabs defaultValue="profiles" className="flex-1">
        <TabsList>
          <TabsTrigger value="profiles">{t("page.tab.profiles")}</TabsTrigger>
          <TabsTrigger value="retry">{t("page.tab.retry")}</TabsTrigger>
        </TabsList>

        <TabsContent value="profiles" className="mt-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {profiles.map((p) => {
              const h = healthOf(p, health.get(p.id));
              return (
                // biome-ignore lint/a11y/useSemanticElements: 卡片内含自己的操作按钮，用原生 <button> 会造成按钮嵌套（非法 HTML）
                <Card
                  key={p.id}
                  role="button"
                  tabIndex={0}
                  onClick={() => openEditor(p)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      openEditor(p);
                    }
                  }}
                  className={cn(
                    "cursor-pointer gap-0 py-4 outline-none transition-colors hover:border-foreground/30",
                    p.is_default && "border-amber-400/50 bg-amber-400/5",
                  )}
                >
                  <CardContent className="grid gap-2 px-4">
                    <div className="flex items-start gap-2">
                      <StarIcon
                        className={cn(
                          "mt-0.5 size-4 shrink-0",
                          p.is_default ? "fill-amber-400 text-amber-400" : "text-muted-foreground",
                        )}
                      />
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="truncate font-medium text-sm">{p.name}</span>
                          <Badge variant="outline" className="uppercase">
                            {p.format}
                          </Badge>
                          <Badge variant="outline" className={cn("ml-auto", h.cls)} title={h.hint}>
                            {h.label}
                          </Badge>
                        </div>
                        <code className="mt-1 block truncate font-mono text-muted-foreground text-xs">{p.model}</code>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-x-3 gap-y-0.5 pl-6 text-muted-foreground text-xs">
                      {p.api_key_hint && <span>{p.api_key_hint}</span>}
                      <span>
                        {p.rate_per_second}/s · {p.rate_per_minute}/min
                      </span>
                      {p.proxy && <span className="truncate">{t("card.proxy", { proxy: p.proxy })}</span>}
                      {p.reasoning_effort && (
                        <span>
                          {t("card.thinking", {
                            effort: p.reasoning_effort === "off" ? t("card.thinkingOff") : p.reasoning_effort,
                          })}
                        </span>
                      )}
                      {/* 轮询相关的两个字段只在轮询开着时才有意义，关着时不占版面 */}
                      {poolOn &&
                        !p.is_default &&
                        (p.pool_exclude ? (
                          <span>{t("card.excluded")}</span>
                        ) : (
                          <span>{t("card.priority", { priority: p.priority ?? 0 })}</span>
                        ))}
                    </div>

                    <div className="mt-1 flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        className="flex-1"
                        disabled={p.is_default}
                        onClick={(e) => {
                          e.stopPropagation();
                          void activate(p.id, p.name);
                        }}
                      >
                        {p.is_default ? t("card.active") : t("card.activate")}
                      </Button>
                      <Button
                        size="icon"
                        variant="outline"
                        aria-label={t("card.deleteAria")}
                        onClick={(e) => {
                          e.stopPropagation();
                          void remove(p);
                        }}
                      >
                        <Trash2Icon className="text-destructive" />
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
            {profiles.length === 0 && (
              <div className="col-span-full rounded-lg border border-dashed p-10 text-center text-muted-foreground text-sm">
                {t("page.empty")}
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="retry" className="mt-4">
          <RetryPolicyPanel />
        </TabsContent>
      </Tabs>

      <ProfileSheet profile={editing} open={editOpen} onOpenChange={setEditOpen} onSaved={() => void load()} />
      <PoolSheet open={poolOpen} onOpenChange={setPoolOpen} pool={pool} onReload={loadPool} />
    </div>
  );
}
