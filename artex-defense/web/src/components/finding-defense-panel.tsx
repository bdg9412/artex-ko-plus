"use client";

import * as React from "react";

import { ArrowUpRightIcon, RefreshCwIcon, ShieldCheckIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { DefenseStateBadge } from "@/components/defense-state-badge";
import { FindingDefenseExecutionPanel } from "@/components/finding-defense-execution-panel";
import { FindingDefenseReplayPanel } from "@/components/finding-defense-replay-panel";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { HttpError } from "@/lib/api";
import {
  type DefensePlanFields,
  type DetectionResult,
  type FindingDefense,
  type PreventionResult,
  purpleApi,
  type RuleFormat,
} from "@/lib/purple-api";

const EMPTY_PLAN: DefensePlanFields = {
  hypothesis: "",
  log_source: "",
  rule_format: "query",
  rule_text: "",
  remediation: "",
};
const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-background px-3 text-sm disabled:opacity-50";
const EXAMPLE_EVENT_RULE = JSON.stringify(
  { version: 1, all: [{ field: "event.action", op: "eq", value: "access_denied" }] },
  null,
  2,
);

function planFields(data: FindingDefense): DefensePlanFields {
  if (!data.plan) return { ...EMPTY_PLAN };
  const { hypothesis, log_source, rule_format, rule_text, remediation } = data.plan;
  return { hypothesis, log_source, rule_format, rule_text, remediation };
}

function localNow() {
  const now = new Date();
  return new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

export function FindingDefensePanel({
  findingId,
  readOnly = false,
  onOpenRetest,
}: {
  findingId: string;
  readOnly?: boolean;
  onOpenRetest: () => void;
}) {
  const t = useTranslations("purple");
  const fieldId = React.useId();
  const [data, setData] = React.useState<FindingDefense | null>(null);
  const [draft, setDraft] = React.useState<DefensePlanFields>({ ...EMPTY_PLAN });
  const [error, setError] = React.useState("");
  const [conflictDraft, setConflictDraft] = React.useState<DefensePlanFields | null>(null);
  const [busy, setBusy] = React.useState<"load" | "plan" | "validation" | "replay" | "execution" | null>("load");
  const [detection, setDetection] = React.useState<DetectionResult>("not_tested");
  const [prevention, setPrevention] = React.useState<PreventionResult>("not_tested");
  const [observedAt, setObservedAt] = React.useState(localNow);
  const [evidence, setEvidence] = React.useState("");
  const [notes, setNotes] = React.useState("");
  const requestSeq = React.useRef(0);

  const accept = React.useCallback((result: FindingDefense) => {
    setData(result);
    setDraft(planFields(result));
  }, []);

  const load = React.useCallback(async () => {
    const seq = ++requestSeq.current;
    setBusy("load");
    setError("");
    try {
      const result = await purpleApi.findingDefense(findingId);
      if (seq !== requestSeq.current) return false;
      accept(result);
      return true;
    } catch (e) {
      if (seq === requestSeq.current) setError((e as Error).message);
      return false;
    } finally {
      if (seq === requestSeq.current) setBusy(null);
    }
  }, [accept, findingId]);

  React.useEffect(() => {
    void load();
    return () => {
      requestSeq.current++;
    };
  }, [load]);

  const dirty = data !== null && JSON.stringify(draft) !== JSON.stringify(planFields(data));
  const latest = data?.validations?.[0];

  const mutationError = async (e: unknown, keepDraft = false) => {
    if (e instanceof HttpError && e.status === 409) {
      if (keepDraft) setConflictDraft({ ...draft });
      if (await load()) setError(t("conflict"));
    } else {
      setError((e as Error).message);
    }
  };

  const savePlan = async () => {
    if (!data || busy || readOnly) return;
    setBusy("plan");
    setError("");
    try {
      accept(await purpleApi.savePlan(findingId, draft, data.plan?.revision ?? 0));
      setConflictDraft(null);
      toast.success(t("planSaved"));
    } catch (e) {
      await mutationError(e, true);
    } finally {
      setBusy(null);
    }
  };

  const recordValidation = async () => {
    if (!data?.plan || busy || dirty || readOnly) return;
    const date = new Date(observedAt);
    if (!Number.isFinite(date.getTime()) || date.getUTCFullYear() < 1970 || date.getTime() > Date.now() + 5 * 60000) {
      setError(t("invalidTime"));
      return;
    }
    setBusy("validation");
    setError("");
    try {
      accept(
        await purpleApi.recordValidation(findingId, {
          plan_revision: data.plan.revision,
          expected_evidence_version: data.evidence_version,
          expected_source_fingerprint: data.source_fingerprint,
          detection,
          prevention,
          evidence: evidence.trim(),
          observed_at: date.toISOString(),
          notes: notes.trim(),
        }),
      );
      setEvidence("");
      setNotes("");
      setDetection("not_tested");
      setPrevention("not_tested");
      setObservedAt(localNow());
      toast.success(t("validationSaved"));
    } catch (e) {
      await mutationError(e);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-5">
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div className="flex flex-col gap-1.5">
            <CardTitle className="flex items-center gap-2">
              <ShieldCheckIcon className="size-5 text-violet-500" />
              {t("title")}
            </CardTitle>
            <CardDescription>{t("panelDescription")}</CardDescription>
          </div>
          <Button variant="outline" size="sm" disabled={!!busy || dirty} onClick={() => void load()}>
            <RefreshCwIcon className={busy === "load" ? "animate-spin" : undefined} />
            {t("refresh")}
          </Button>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {error ? (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}
          {conflictDraft ? (
            <Alert>
              <AlertDescription className="flex flex-wrap items-center gap-3">
                <span>{t("draftRetained")}</span>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={!!busy}
                  onClick={() => {
                    setDraft(conflictDraft);
                    setConflictDraft(null);
                  }}
                >
                  {t("restoreDraft")}
                </Button>
              </AlertDescription>
            </Alert>
          ) : null}
          {!data && busy ? <Skeleton className="h-16 w-full" /> : null}
          {data ? (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <DefenseStateBadge state={data.state} />
                <Badge variant="secondary">{t("manualRecord")}</Badge>
                {data.plan ? (
                  <span className="text-xs text-muted-foreground">
                    {t("revision", { n: data.plan.revision })} · {t("evidenceVersion", { n: data.evidence_version })}
                  </span>
                ) : null}
              </div>
              <p className="text-sm text-muted-foreground">{t(`stateDescription.${data.state}`)}</p>
              {data.state === "current" && latest ? (
                <div className="flex flex-wrap gap-4 text-sm">
                  <span>
                    {t("detection")}: <strong>{t(`detectionResult.${latest.detection}`)}</strong>
                  </span>
                  <span>
                    {t("prevention")}: <strong>{t(`preventionResult.${latest.prevention}`)}</strong>
                  </span>
                </div>
              ) : null}
              {readOnly ? <p className="text-sm text-muted-foreground">{t("readOnly")}</p> : null}
            </>
          ) : null}
        </CardContent>
      </Card>

      {data ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>{t("planTitle")}</CardTitle>
              <CardDescription>{t("planDescription")}</CardDescription>
            </CardHeader>
            <CardContent>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  void savePlan();
                }}
              >
                <fieldset className="flex flex-col gap-4" disabled={!!busy || readOnly}>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div className="flex flex-col gap-2">
                      <Label htmlFor={`${fieldId}-hypothesis`}>{t("hypothesis")}</Label>
                      <Textarea
                        id={`${fieldId}-hypothesis`}
                        required
                        maxLength={4000}
                        rows={3}
                        placeholder={t("hypothesisPlaceholder")}
                        value={draft.hypothesis}
                        onChange={(event) => setDraft({ ...draft, hypothesis: event.target.value })}
                      />
                    </div>
                    <div className="flex flex-col gap-2">
                      <Label htmlFor={`${fieldId}-source`}>{t("logSource")}</Label>
                      <Textarea
                        id={`${fieldId}-source`}
                        maxLength={2000}
                        rows={3}
                        placeholder={t("logSourcePlaceholder")}
                        value={draft.log_source}
                        onChange={(event) => setDraft({ ...draft, log_source: event.target.value })}
                      />
                    </div>
                  </div>
                  <div className="flex flex-col gap-2 sm:max-w-xs">
                    <Label htmlFor={`${fieldId}-format`}>{t("ruleFormat")}</Label>
                    <select
                      id={`${fieldId}-format`}
                      className={SELECT_CLASS}
                      value={draft.rule_format}
                      onChange={(event) => setDraft({ ...draft, rule_format: event.target.value as RuleFormat })}
                    >
                      <option value="event_filter">{t("replay.eventFilter")}</option>
                      <option value="query">{t("format.query")}</option>
                      <option value="sigma">Sigma</option>
                      <option value="other">{t("format.other")}</option>
                    </select>
                  </div>
                  <div className="flex flex-col gap-2">
                    <Label htmlFor={`${fieldId}-rule`}>{t("ruleText")}</Label>
                    <Textarea
                      id={`${fieldId}-rule`}
                      className="min-h-32 font-mono text-xs"
                      rows={6}
                      maxLength={32000}
                      placeholder={t("rulePlaceholder")}
                      value={draft.rule_text}
                      onChange={(event) => setDraft({ ...draft, rule_text: event.target.value })}
                    />
                    <p className="text-xs text-muted-foreground">
                      {draft.rule_format === "event_filter" ? t("replay.ruleHelp") : t("draftOnly")}
                    </p>
                    {!readOnly ? (
                      <div className="flex flex-wrap items-center gap-3">
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          disabled={!!draft.rule_text.trim()}
                          onClick={() =>
                            setDraft({ ...draft, rule_format: "event_filter", rule_text: EXAMPLE_EVENT_RULE })
                          }
                        >
                          {t("replay.fillRule")}
                        </Button>
                        <span className="text-xs text-muted-foreground">{t("replay.fillRuleHelp")}</span>
                      </div>
                    ) : null}
                  </div>
                  <div className="flex flex-col gap-2">
                    <Label htmlFor={`${fieldId}-remediation`}>{t("remediation")}</Label>
                    <Textarea
                      id={`${fieldId}-remediation`}
                      rows={3}
                      maxLength={8000}
                      placeholder={t("remediationPlaceholder")}
                      value={draft.remediation}
                      onChange={(event) => setDraft({ ...draft, remediation: event.target.value })}
                    />
                  </div>
                  {!readOnly ? (
                    <div className="flex flex-wrap items-center gap-3">
                      <Button type="submit" disabled={!dirty || !draft.hypothesis.trim()}>
                        {busy === "plan" ? <Spinner /> : null}
                        {t("savePlan")}
                      </Button>
                      {dirty ? (
                        <>
                          <Button type="button" variant="ghost" onClick={() => setDraft(planFields(data))}>
                            {t("discard")}
                          </Button>
                          <span className="text-xs text-muted-foreground">{t("unsaved")}</span>
                        </>
                      ) : null}
                    </div>
                  ) : null}
                </fieldset>
              </form>
            </CardContent>
          </Card>

          <FindingDefenseExecutionPanel
            findingId={findingId}
            data={data}
            dirty={dirty}
            readOnly={readOnly}
            parentBusy={busy !== null && busy !== "execution"}
            onRefresh={load}
            onRunningChange={(running) => setBusy(running ? "execution" : null)}
          />

          <FindingDefenseReplayPanel
            findingId={findingId}
            data={data}
            dirty={dirty}
            readOnly={readOnly}
            parentBusy={busy !== null && busy !== "replay"}
            onRefresh={load}
            onRunningChange={(running) => setBusy(running ? "replay" : null)}
          />

          <Card>
            <CardHeader className="flex flex-row flex-wrap justify-between gap-3">
              <div className="flex flex-col gap-1.5">
                <CardTitle>{t("validationTitle")}</CardTitle>
                <CardDescription>{t("validationDescription")}</CardDescription>
              </div>
              <Button variant="outline" size="sm" onClick={onOpenRetest}>
                {t("viewRetest")}
                <ArrowUpRightIcon />
              </Button>
            </CardHeader>
            <CardContent>
              {!data.plan ? <p className="text-sm text-muted-foreground">{t("savePlanFirst")}</p> : null}
              {dirty ? (
                <p className="mb-4 text-sm text-amber-700 dark:text-amber-300">{t("saveChangesFirst")}</p>
              ) : null}
              {data.plan && !readOnly ? (
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    void recordValidation();
                  }}
                >
                  <fieldset className="flex flex-col gap-4" disabled={!!busy || dirty}>
                    <div className="grid gap-4 sm:grid-cols-3">
                      <div className="flex flex-col gap-2">
                        <Label htmlFor={`${fieldId}-detection`}>{t("detection")}</Label>
                        <select
                          id={`${fieldId}-detection`}
                          className={SELECT_CLASS}
                          value={detection}
                          onChange={(event) => setDetection(event.target.value as DetectionResult)}
                        >
                          {(["not_tested", "detected", "missed"] as const).map((value) => (
                            <option key={value} value={value}>
                              {t(`detectionResult.${value}`)}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="flex flex-col gap-2">
                        <Label htmlFor={`${fieldId}-prevention`}>{t("prevention")}</Label>
                        <select
                          id={`${fieldId}-prevention`}
                          className={SELECT_CLASS}
                          value={prevention}
                          onChange={(event) => setPrevention(event.target.value as PreventionResult)}
                        >
                          {(["not_tested", "blocked", "not_blocked"] as const).map((value) => (
                            <option key={value} value={value}>
                              {t(`preventionResult.${value}`)}
                            </option>
                          ))}
                        </select>
                      </div>
                      <div className="flex flex-col gap-2">
                        <Label htmlFor={`${fieldId}-observed`}>{t("observedAt")}</Label>
                        <Input
                          id={`${fieldId}-observed`}
                          type="datetime-local"
                          required
                          value={observedAt}
                          onChange={(event) => setObservedAt(event.target.value)}
                        />
                      </div>
                    </div>
                    <div className="flex flex-col gap-2">
                      <Label htmlFor={`${fieldId}-evidence`}>{t("evidence")}</Label>
                      <Textarea
                        id={`${fieldId}-evidence`}
                        required
                        rows={5}
                        maxLength={32000}
                        placeholder={t("evidencePlaceholder")}
                        value={evidence}
                        onChange={(event) => setEvidence(event.target.value)}
                      />
                    </div>
                    <div className="flex flex-col gap-2">
                      <Label htmlFor={`${fieldId}-notes`}>{t("notes")}</Label>
                      <Textarea
                        id={`${fieldId}-notes`}
                        rows={2}
                        maxLength={4000}
                        value={notes}
                        onChange={(event) => setNotes(event.target.value)}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground">{t("immutableNotice")}</p>
                    <Button
                      className="self-start"
                      type="submit"
                      disabled={!evidence.trim() || (detection === "not_tested" && prevention === "not_tested")}
                    >
                      {busy === "validation" ? <Spinner /> : null}
                      {t("recordValidation")}
                    </Button>
                  </fieldset>
                </form>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>{t("historyTitle", { n: data.validations?.length ?? 0 })}</CardTitle>
              <CardDescription>{t("historyDescription")}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              {!data.validations?.length ? (
                <p className="text-sm text-muted-foreground">{t("historyEmpty")}</p>
              ) : (
                data.validations.map((item, index) => (
                  <div key={item.id} className="min-w-0 rounded-lg border p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline">{t("manualRecord")}</Badge>
                      {index === 0 && data.state === "current" ? <DefenseStateBadge state="current" /> : null}
                      <span className="text-xs text-muted-foreground">
                        {t("revision", { n: item.plan_revision })} ·{" "}
                        {t("evidenceVersion", { n: item.evidence_version })}
                      </span>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-4 text-sm">
                      <span>
                        {t("detection")}: <strong>{t(`detectionResult.${item.detection}`)}</strong>
                      </span>
                      <span>
                        {t("prevention")}: <strong>{t(`preventionResult.${item.prevention}`)}</strong>
                      </span>
                    </div>
                    <p className="mt-2 text-xs text-muted-foreground">
                      {t("observedAt")}: {new Date(item.observed_at).toLocaleString()} · {t("recordedAt")}:{" "}
                      {new Date(item.created_at).toLocaleString()}
                    </p>
                    <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 font-mono text-xs">
                      {item.evidence}
                    </pre>
                    {item.notes ? (
                      <p className="mt-2 whitespace-pre-wrap break-words text-sm text-muted-foreground">{item.notes}</p>
                    ) : null}
                    {item.plan_snapshot ? (
                      <details className="mt-3 text-sm">
                        <summary className="cursor-pointer text-muted-foreground">{t("snapshot")}</summary>
                        <dl className="mt-3 grid gap-3">
                          <div>
                            <dt className="font-medium">{t("hypothesis")}</dt>
                            <dd className="whitespace-pre-wrap break-words text-muted-foreground">
                              {item.plan_snapshot.hypothesis}
                            </dd>
                          </div>
                          <div>
                            <dt className="font-medium">{t("logSource")}</dt>
                            <dd className="whitespace-pre-wrap break-words text-muted-foreground">
                              {item.plan_snapshot.log_source}
                            </dd>
                          </div>
                          <div>
                            <dt className="font-medium">
                              {t("ruleText")} · {item.plan_snapshot.rule_format}
                            </dt>
                            <dd>
                              <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 text-xs">
                                {item.plan_snapshot.rule_text || "—"}
                              </pre>
                            </dd>
                          </div>
                          <div>
                            <dt className="font-medium">{t("remediation")}</dt>
                            <dd className="whitespace-pre-wrap break-words text-muted-foreground">
                              {item.plan_snapshot.remediation || "—"}
                            </dd>
                          </div>
                        </dl>
                      </details>
                    ) : null}
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  );
}
