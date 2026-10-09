"use client";

import * as React from "react";

import { BellIcon, PlusIcon, SendIcon, Trash2Icon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type { NotificationChannel, NotificationFilter, NotificationMeta } from "@/lib/types";

import {
  CHANNEL_FIELDS,
  type ChannelForm,
  emptyForm,
  parseIDs,
  parseKeywords,
  parseKV,
  SEVERITY_OPTIONS,
} from "./_components/channel-fields";
import { ConfigField, FilterSummary } from "./_components/channel-form";
import { DeliveryList } from "./_components/delivery-list";
import { formatBacklog, StatTile } from "./_components/stat-tile";

// 本页只负责编排：加载数据、维护表单状态、调用接口。
// 字段定义与解析在 _components/channel-fields.ts，控件与过滤摘要在
// _components/channel-form.tsx，投递记录在 _components/delivery-list.tsx——
// 拆开是因为它们各自能被单独读懂，而挤在一个文件里时这个页面接近 1100 行。
export default function NotifyPage() {
  const t = useTranslations("notifyPage");
  // 渠道类型展示名：已知的 6 种走 i18n（notifyPage.kind.<kind>），
  // 后端若回传未知类型则原样显示该 key（保留原来的 `?? ch.kind` 语义）。
  const kindLabel = (k: string) => (k in CHANNEL_FIELDS ? t(`kind.${k}`) : k);
  const [meta, setMeta] = React.useState<NotificationMeta | null>(null);
  const [channels, setChannels] = React.useState<NotificationChannel[]>([]);
  const [tab, setTab] = React.useState<"channels" | "deliveries">("channels");

  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<NotificationChannel | null>(null);
  const [form, setForm] = React.useState<ChannelForm>(emptyForm("dingtalk"));
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);

  const [globalSaving, setGlobalSaving] = React.useState(false);
  const [baseURL, setBaseURL] = React.useState("");
  const [digestMin, setDigestMin] = React.useState("");

  const load = React.useCallback(() => {
    api
      .notifyMeta()
      .then((m) => {
        setMeta(m);
        setBaseURL(m.public_base_url);
        setDigestMin(m.digest_interval_min);
      })
      .catch((e) => toast.error(t("toast.loadConfigFailed", { msg: (e as Error).message })));
    // 渠道列表加载失败要报出来：静默失败会显示成「一个渠道都没有」，
    // 用户会以为配置丢了，比直接报错更让人慌。
    api
      .notifyChannels()
      .then(setChannels)
      .catch((e) => toast.error(t("toast.loadChannelsFailed", { msg: (e as Error).message })));
  }, [t]);
  React.useEffect(() => {
    load();
  }, [load]);

  function setF(patch: Partial<ChannelForm>) {
    setForm((f) => ({ ...f, ...patch }));
  }
  function setCfg(key: string, value: unknown) {
    setForm((f) => ({ ...f, config: { ...f.config, [key]: value } }));
  }

  function openAdd() {
    setEditing(null);
    setForm(emptyForm(meta?.kinds[0]?.kind ?? "dingtalk"));
    setOpen(true);
  }

  function openEdit(ch: NotificationChannel) {
    setEditing(ch);
    // filter 在后端是 Go 结构体，永远序列化成对象（不会是 null），所以不需要兜底。
    const f = ch.filter;
    setForm({
      name: ch.name,
      kind: ch.kind,
      mode: ch.mode,
      enabled: ch.enabled,
      ratePerMin: String(ch.rate_per_min),
      // 后端回显的 config 里凭据是掩码值；原样放进表单，提交时原样送回，
      // 后端据此保留库中原值。
      config: { ...ch.config },
      minSeverity: f.min_severity ?? "",
      includeText: (f.vulnclass_include ?? []).join("\n"),
      excludeText: (f.vulnclass_exclude ?? []).join("\n"),
      taskIDsText: (f.task_ids ?? []).join(","),
      assetIDsText: (f.asset_ids ?? []).join(","),
      onStatusChange: f.on_status_change ?? false,
    });
    setOpen(true);
  }

  // buildConfig 把表单状态转成渠道 config。
  //
  // 唯一的规则，两类值：
  //   - 掩码值（"__masked__..."）原样送回 → 后端解读为「这个字段没改，保留库中原值」
  //   - 其余一律按用户输入提交，空串即「清空该字段」
  //
  // 之所以不特殊照顾凭据字段（比如「凭据留空就跳过」），是因为那会让用户**无法清除**
  // 一个设错的密钥——界面上没有任何操作能表达「我要把它删掉」。现在的规则下，
  // 清空输入框就等于清空该字段，语义唯一且用户可控。
  // 掩码值不会出现在输入框里（见 ConfigField），所以「框里有字」永远等于
  // 「用户主动填的」。
  function buildConfig(): Record<string, unknown> {
    const defs = CHANNEL_FIELDS[form.kind] ?? [];
    const out: Record<string, unknown> = {};
    for (const d of defs) {
      const raw = form.config[d.key];
      if (d.kind === "switch") {
        out[d.key] = raw === true;
        continue;
      }
      if (typeof raw === "string" && raw.startsWith("__masked__")) {
        out[d.key] = raw;
        continue;
      }
      if (d.kind === "number") {
        const n = Number(raw);
        out[d.key] = Number.isFinite(n) && n > 0 ? n : 0;
        continue;
      }
      if (d.kind === "kv") {
        out[d.key] = parseKV(String(raw ?? ""));
        continue;
      }
      if (d.kind === "list") {
        out[d.key] = String(raw ?? "")
          .split(/[\s,，]+/)
          .map((s) => s.trim())
          .filter(Boolean);
        continue;
      }
      out[d.key] = String(raw ?? "").trim();
    }
    return out;
  }

  function buildFilter(): NotificationFilter {
    return {
      min_severity: form.minSeverity || undefined,
      vulnclass_include: parseKeywords(form.includeText),
      vulnclass_exclude: parseKeywords(form.excludeText),
      task_ids: parseIDs(form.taskIDsText),
      asset_ids: parseIDs(form.assetIDsText),
      on_status_change: form.onStatusChange,
    };
  }

  async function saveForm() {
    if (!form.name.trim()) {
      toast.error(t("toast.nameRequired"));
      return;
    }
    setSaving(true);
    try {
      const payload = {
        name: form.name.trim(),
        kind: form.kind,
        mode: form.mode,
        enabled: form.enabled,
        config: buildConfig(),
        filter: buildFilter(),
        rate_per_min: form.ratePerMin.trim() === "" ? undefined : Number(form.ratePerMin),
      };
      if (editing) {
        await api.notifyUpdateChannel(editing.id, payload);
        toast.success(t("toast.saved"));
        setOpen(false);
      } else {
        await api.notifyCreateChannel(payload);
        toast.success(t("toast.channelAdded"));
        setOpen(false);
      }
      load();
    } catch (e) {
      toast.error(t("toast.saveFailed", { msg: (e as Error).message }));
    } finally {
      setSaving(false);
    }
  }

  async function testChannel() {
    if (!editing) return;
    setTesting(true);
    try {
      const r = await api.notifyTestChannel(editing.id);
      toast.success(t("toast.testSent", { ms: r.latency_ms }));
    } catch (e) {
      // 后端把渠道返回的原始错误如实回传，这是排查配置的唯一线索，原样展示。
      toast.error(t("toast.testFailed", { msg: (e as Error).message }), { duration: 12000 });
    } finally {
      setTesting(false);
    }
  }

  async function removeChannel(ch: NotificationChannel) {
    try {
      await api.notifyDeleteChannel(ch.id);
      toast.success(t("toast.deleted", { name: ch.name }));
      setOpen(false);
      load();
    } catch (e) {
      toast.error(t("toast.deleteFailed", { msg: (e as Error).message }));
    }
  }

  async function toggleEnabled(ch: NotificationChannel) {
    try {
      await api.notifyUpdateChannel(ch.id, { enabled: !ch.enabled });
      load();
    } catch (e) {
      toast.error(t("toast.actionFailed", { msg: (e as Error).message }));
    }
  }

  async function toggleGlobal(on: boolean) {
    setGlobalSaving(true);
    try {
      await api.setSettings({ notify_enabled: on });
      setMeta((m) => (m ? { ...m, enabled: on } : m));
      toast.success(on ? t("toast.globalOn") : t("toast.globalOff"));
    } catch (e) {
      toast.error(t("toast.actionFailed", { msg: (e as Error).message }));
    } finally {
      setGlobalSaving(false);
    }
  }

  async function saveGlobal() {
    setGlobalSaving(true);
    try {
      const patch: Record<string, unknown> = { notify_public_base_url: baseURL.trim() };
      const n = Number(digestMin);
      if (Number.isFinite(n) && n > 0) patch.notify_digest_interval_min = n;
      await api.setSettings(patch);
      toast.success(t("toast.saved"));
      load();
    } catch (e) {
      toast.error(t("toast.saveFailed", { msg: (e as Error).message }));
    } finally {
      setGlobalSaving(false);
    }
  }

  const fields = CHANNEL_FIELDS[form.kind] ?? [];
  const secretKeys = new Set(meta?.kinds.find((k) => k.kind === form.kind)?.secret_keys ?? []);
  const defaultRate = meta?.kinds.find((k) => k.kind === form.kind)?.default_rate_per_min ?? 0;

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{t("title")}</h1>
          <p className="text-muted-foreground text-sm">{t("subtitle")}</p>
        </div>
        {meta && (
          // 用 div 而不是 label：Switch 自带 aria-label，外面再套一层 label
          // 既关联不到任何原生控件，又会让点击文字看起来应该能切换。
          <div className="flex shrink-0 items-center gap-2 text-sm">
            <span className="text-muted-foreground">{t("globalSwitch")}</span>
            <Switch
              checked={meta.enabled}
              disabled={globalSaving}
              onCheckedChange={toggleGlobal}
              aria-label={t("aria.globalSwitch")}
            />
          </div>
        )}
      </div>

      {meta && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <StatTile
            label={t("stats.channels")}
            value={`${meta.stats.channels_on} / ${meta.stats.channels}`}
            hint={t("stats.channelsHint")}
          />
          <StatTile label={t("stats.sentToday")} value={String(meta.stats.sent_today)} />
          <StatTile label={t("stats.pending")} value={String(meta.stats.pending)} />
          <StatTile
            label={t("stats.failed")}
            value={String(meta.stats.failed)}
            tone={meta.stats.failed > 0 ? "red" : undefined}
          />
          <StatTile
            label={t("stats.backlog")}
            value={formatBacklog(meta.stats.backlog_age_ms, t)}
            // 积压年龄比积压条数有用得多：积压 3 条可以是从 3 秒到 3 小时。
            hint={meta.stats.backlog_age_ms > 5 * 60_000 ? t("stats.backlogStuck") : undefined}
            tone={meta.stats.backlog_age_ms > 5 * 60_000 ? "red" : undefined}
          />
        </div>
      )}

      <Card className="gap-3">
        <CardHeader>
          <CardTitle className="text-base">{t("global.title")}</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2">
          <div className="grid gap-2">
            <Label htmlFor="n-base">{t("global.baseUrl")}</Label>
            <Input
              id="n-base"
              placeholder="https://artex.example.com"
              value={baseURL}
              onChange={(e) => setBaseURL(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">{t("global.baseUrlHint")}</p>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="n-digest">{t("global.digest")}</Label>
            <Input
              id="n-digest"
              type="number"
              min={1}
              max={1440}
              placeholder="30"
              value={digestMin}
              onChange={(e) => setDigestMin(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">{t("global.digestHint")}</p>
          </div>
          <div className="sm:col-span-2">
            <Button onClick={saveGlobal} disabled={globalSaving}>
              {t("global.save")}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Tabs value={tab} onValueChange={(v) => setTab(v as "channels" | "deliveries")} className="flex flex-col gap-4">
        <TabsList>
          <TabsTrigger value="channels">{t("tab.channels")}</TabsTrigger>
          <TabsTrigger value="deliveries">{t("tab.deliveries")}</TabsTrigger>
        </TabsList>

        <TabsContent value="channels">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <button
              type="button"
              onClick={openAdd}
              className="text-foreground/70 border-foreground/70 hover:bg-muted/60 hover:shadow-sm flex min-h-[130px] flex-col items-center justify-center gap-2 rounded-xl border border-dashed transition"
            >
              <PlusIcon className="size-6" />
              <span className="text-sm">{t("addChannel")}</span>
            </button>

            {channels.map((ch) => (
              <Card
                key={ch.id}
                onClick={() => openEdit(ch)}
                className="hover:border-primary/60 cursor-pointer gap-3 transition hover:shadow-sm"
              >
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <BellIcon className="text-muted-foreground size-4 shrink-0" />
                    <CardTitle className="truncate text-base">{ch.name}</CardTitle>
                    {/* 卡片整体可点（进入编辑），所以这两个控件必须各自吞掉冒泡，
                        否则开关/删除会顺带触发编辑。把 stopPropagation 挂在控件自己
                        身上，而不是套一层 div：套 div 会造出一个「看起来可交互但没有
                        角色」的静态元素，既触发 a11y 告警，语义上也说不通。 */}
                    <div className="ml-auto flex items-center gap-2">
                      <Switch
                        checked={ch.enabled}
                        onCheckedChange={() => toggleEnabled(ch)}
                        onClick={(e) => e.stopPropagation()}
                        aria-label={t("aria.enable")}
                      />
                      <Button
                        size="icon"
                        variant="outline"
                        aria-label={t("aria.delete")}
                        onClick={(e) => {
                          e.stopPropagation();
                          // void 显式丢弃 Promise：removeChannel 自己 catch 并 toast，
                          // 这里不需要 await（onClick 不是 async）。
                          void removeChannel(ch);
                        }}
                      >
                        <Trash2Icon className="text-destructive" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="grid gap-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline">{kindLabel(ch.kind)}</Badge>
                    <Badge variant="outline">{ch.mode === "digest" ? t("mode.digest") : t("mode.realtime")}</Badge>
                    {!ch.enabled && <Badge variant="outline">{t("disabled")}</Badge>}
                  </div>
                  <FilterSummary filter={ch.filter} />
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="deliveries">
          <DeliveryList channels={channels} />
        </TabsContent>
      </Tabs>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="w-full data-[side=right]:sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>{editing ? editing.name : t("sheet.addTitle")}</SheetTitle>
            <SheetDescription>
              {kindLabel(form.kind)}
              {defaultRate > 0 ? t("sheet.rateLimited", { rate: defaultRate }) : t("sheet.rateUnlimited")}
            </SheetDescription>
          </SheetHeader>

          <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-4">
            <div className="grid gap-4 py-4">
              <div className="grid gap-2">
                <Label>{t("sheet.kindLabel")}</Label>
                <Select
                  value={form.kind}
                  onValueChange={(v) => {
                    // 换类型等于换一套凭据字段，不能把旧配置合并进来。
                    setF({ kind: v, config: {} });
                  }}
                  disabled={!!editing}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(meta?.kinds ?? []).map((k) => (
                      <SelectItem key={k.kind} value={k.kind}>
                        {kindLabel(k.kind)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {editing && <p className="text-muted-foreground text-xs">{t("sheet.kindLocked")}</p>}
              </div>

              <div className="grid gap-2">
                <Label htmlFor="n-name">{t("sheet.nameLabel")}</Label>
                <Input
                  id="n-name"
                  placeholder={t("sheet.namePlaceholder")}
                  value={form.name}
                  onChange={(e) => setF({ name: e.target.value })}
                />
              </div>

              {fields.length === 0 ? (
                <p className="text-muted-foreground text-sm">{t("sheet.noFields")}</p>
              ) : (
                fields.map((d) => (
                  <ConfigField
                    key={d.key}
                    def={d}
                    value={form.config[d.key]}
                    isSecret={secretKeys.has(d.key)}
                    onChange={(v) => setCfg(d.key, v)}
                  />
                ))
              )}

              <div className="grid gap-2">
                <Label>{t("sheet.modeLabel")}</Label>
                <Select value={form.mode} onValueChange={(v) => setF({ mode: v as "realtime" | "digest" })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="realtime">{t("sheet.modeRealtime")}</SelectItem>
                    <SelectItem value="digest">{t("sheet.modeDigest")}</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-muted-foreground text-xs">{t("sheet.modeHint")}</p>
              </div>

              <div className="grid gap-2">
                <Label htmlFor="n-rate">{t("sheet.rateLabel")}</Label>
                <Input
                  id="n-rate"
                  type="number"
                  min={0}
                  placeholder={defaultRate > 0 ? String(defaultRate) : t("sheet.ratePlaceholder")}
                  value={form.ratePerMin}
                  onChange={(e) => setF({ ratePerMin: e.target.value })}
                />
                <p className="text-muted-foreground text-xs">{t("sheet.rateHint")}</p>
              </div>

              <div className="border-t pt-4">
                <p className="mb-3 text-sm font-medium">{t("filter.title")}</p>
                <div className="grid gap-4">
                  <div className="grid gap-2">
                    <Label>{t("filter.minSeverity")}</Label>
                    <Select
                      value={form.minSeverity || "all"}
                      onValueChange={(v) => setF({ minSeverity: v === "all" ? "" : v })}
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {SEVERITY_OPTIONS.map((o) => (
                          <SelectItem key={o.value || "all"} value={o.value || "all"}>
                            {t(o.label)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-inc">{t("filter.includeLabel")}</Label>
                    <Textarea
                      id="n-inc"
                      placeholder={t("filter.includePlaceholder")}
                      value={form.includeText}
                      onChange={(e) => setF({ includeText: e.target.value })}
                    />
                    <p className="text-muted-foreground text-xs">{t("filter.includeHint")}</p>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-exc">{t("filter.excludeLabel")}</Label>
                    <Textarea
                      id="n-exc"
                      placeholder={t("filter.excludePlaceholder")}
                      value={form.excludeText}
                      onChange={(e) => setF({ excludeText: e.target.value })}
                    />
                    <p className="text-muted-foreground text-xs">{t("filter.excludeHint")}</p>
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-tasks">{t("filter.taskIds")}</Label>
                    <Input
                      id="n-tasks"
                      placeholder="1, 2, 3"
                      value={form.taskIDsText}
                      onChange={(e) => setF({ taskIDsText: e.target.value })}
                    />
                  </div>
                  <div className="grid gap-2">
                    <Label htmlFor="n-assets">{t("filter.assetIds")}</Label>
                    <Input
                      id="n-assets"
                      placeholder="10, 11"
                      value={form.assetIDsText}
                      onChange={(e) => setF({ assetIDsText: e.target.value })}
                    />
                    <p className="text-muted-foreground text-xs">{t("filter.idsHint")}</p>
                  </div>
                  <div className="flex items-center gap-2 text-sm">
                    <Switch
                      checked={form.onStatusChange}
                      onCheckedChange={(v) => setF({ onStatusChange: v })}
                      aria-label={t("aria.statusChange")}
                    />
                    {t("filter.onStatusChange")}
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 text-sm">
                <Switch
                  checked={form.enabled}
                  onCheckedChange={(v) => setF({ enabled: v })}
                  aria-label={t("aria.enable")}
                />
                {t("sheet.enable")}
              </div>
            </div>

            <div className="flex gap-2 pt-2 pb-6">
              <Button onClick={saveForm} disabled={saving}>
                {editing ? t("sheet.save") : t("sheet.add")}
              </Button>
              {editing && (
                <Button variant="outline" onClick={testChannel} disabled={testing}>
                  <SendIcon /> {t("sheet.sendTest")}
                </Button>
              )}
            </div>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
