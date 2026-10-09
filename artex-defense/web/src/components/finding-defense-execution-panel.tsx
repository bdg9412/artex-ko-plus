"use client";

import * as React from "react";

import Link from "next/link";

import { CableIcon, DownloadIcon, PlayIcon, RefreshCwIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { FindingDefenseFileUpload } from "@/components/finding-defense-file-upload";
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
import type { FindingDefense } from "@/lib/purple-api";
import {
  type DefenseAssessment,
  type DefenseComparison,
  type DefenseExecution,
  type DefenseFileConfig,
  downloadSecurityJSON,
  type SecuritySource,
  securityApi,
} from "@/lib/security-api";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-background px-3 text-sm disabled:opacity-50";
const active = (execution: DefenseExecution) =>
  execution.retest.status === "pending" || execution.retest.status === "running";
const formatTime = (value: string) => new Date(value).toLocaleString();
const DEFAULT_FILE_CONFIG: DefenseFileConfig = {
  label: "",
  timestamp_field: "timestamp",
  correlation_field: "artex_verification_id",
  action_field: "action",
  event_id_field: "id",
};
const FILE_MAPPING_FIELDS = ["timestamp_field", "correlation_field", "action_field", "event_id_field"] as const;
const executionSourceKind = (execution: DefenseExecution) =>
  execution.source_kind ?? ("kind" in execution.source_snapshot ? execution.source_snapshot.kind : "splunk");

function AssessmentView({ assessment }: { assessment: DefenseAssessment }) {
  const t = useTranslations("purple.execution");
  const tu = useTranslations("purple.upload");
  const diagnostics = assessment.diagnostics?.length ? assessment.diagnostics : (assessment.evidence.diagnostics ?? []);
  const upload = assessment.evidence.upload;
  let completenessLabel = assessment.evidence.complete ? t("complete") : t("incomplete");
  if (upload) completenessLabel = assessment.evidence.complete ? tu("fileComplete") : tu("fileIncomplete");
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-lg border p-3">
          <p className="text-xs text-muted-foreground">{t("detectionTitle")}</p>
          <p className="mt-1 font-semibold">{t(`detection.${assessment.detection}`)}</p>
        </div>
        <div className="rounded-lg border p-3">
          <p className="text-xs text-muted-foreground">{t("preventionTitle")}</p>
          <p className="mt-1 font-semibold">{t(`prevention.${assessment.prevention}`)}</p>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        {upload ? tu("fileEvidenceBoundary") : tu("directEvidenceBoundary")}
      </p>
      <p className="text-xs text-muted-foreground">
        {t("window")}: {formatTime(assessment.evidence.window_start)} — {formatTime(assessment.evidence.window_end)}
      </p>
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant={assessment.evidence.complete ? "outline" : "secondary"}>{completenessLabel}</Badge>
        <span className="text-xs text-muted-foreground">
          {t("collectedAt")}: {formatTime(assessment.evidence.collected_at)} ·{" "}
          {t("events", { n: assessment.event_count, audits: assessment.audit_count, alerts: assessment.alert_count })}
        </span>
      </div>
      {!diagnostics.length && assessment.reasons.length ? (
        <ul className="list-disc space-y-1 pl-5 text-sm">
          {assessment.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      ) : null}
      {diagnostics.length ? (
        <div className="grid gap-3 sm:grid-cols-2">
          {(["observed", "hypothesis"] as const).map((certainty) => {
            const items = diagnostics.filter((item) => item.certainty === certainty);
            return items.length ? (
              <div key={certainty} className="flex min-w-0 flex-col gap-3 rounded-lg border p-3">
                <h4 className="text-sm font-medium">{tu(`diagnostics.${certainty}`)}</h4>
                {items.map((item) => (
                  <div
                    key={`${item.code}-${item.file_name ?? ""}-${item.line ?? 0}-${item.event_ids?.join(",") ?? ""}`}
                    className="flex flex-col gap-1.5 text-sm"
                  >
                    <p className="whitespace-pre-wrap break-words">{item.message}</p>
                    {item.file_name ? (
                      <p className="break-all text-xs text-muted-foreground">
                        {item.file_name}
                        {item.line ? ` · ${tu("line", { n: item.line })}` : ""}
                      </p>
                    ) : null}
                    {item.event_ids?.length ? (
                      <p className="break-all font-mono text-xs text-muted-foreground">
                        {tu("eventIds")}: {item.event_ids.join(", ")}
                      </p>
                    ) : null}
                    {item.recommendation ? (
                      <p className="whitespace-pre-wrap break-words text-xs text-muted-foreground">
                        <span className="font-medium">{t("recommendations")}: </span>
                        {item.recommendation}
                      </p>
                    ) : null}
                  </div>
                ))}
              </div>
            ) : null;
          })}
        </div>
      ) : null}
      {assessment.evidence.warnings.length ? (
        <Alert>
          <AlertDescription>
            <ul className="list-disc space-y-1 pl-4">
              {assessment.evidence.warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      ) : null}
      {!diagnostics.length && assessment.recommendations.length ? (
        <div className="rounded-lg bg-muted/50 p-3">
          <h4 className="mb-2 text-sm font-medium">{t("recommendations")}</h4>
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {assessment.recommendations.map((recommendation) => (
              <li key={recommendation}>{recommendation}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {upload ? (
        <details className="rounded-lg border p-3">
          <summary className="cursor-pointer text-sm font-medium">{tu("provenance")}</summary>
          <div className="mt-3 flex flex-col gap-3">
            <p className="text-xs text-muted-foreground">
              {tu("coverageDeclaration")}: {upload.coverage_complete ? tu("declared") : tu("notDeclared")} ·{" "}
              {tu("noAlertsDeclaration")}: {upload.no_alerts ? tu("declared") : tu("notDeclared")}
            </p>
            <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              {(
                [
                  "total_rows",
                  "matched",
                  "unrelated",
                  "outside_window",
                  "invalid_events",
                  "duplicate_events",
                  "truncated",
                ] as const
              ).map((key) => (
                <div key={key} className="rounded-md bg-muted/50 p-2">
                  <dt className="text-xs text-muted-foreground">{tu(`stats.${key}`)}</dt>
                  <dd className="mt-1 font-medium">{upload.stats[key]}</dd>
                </div>
              ))}
            </dl>
            {upload.files.map((file) => (
              <div key={`${file.kind}-${file.sha256}`} className="min-w-0 rounded-md bg-muted/50 p-3">
                <p className="break-all text-sm">
                  {t(`eventKind.${file.kind}`)} · {file.name}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {tu("fileStats", { bytes: file.bytes, rows: file.rows })}
                </p>
                <p className="mt-1 break-all font-mono text-xs">SHA-256 · {file.sha256}</p>
              </div>
            ))}
            <p className="text-xs text-muted-foreground">{tu("originalInExport")}</p>
          </div>
        </details>
      ) : null}
      {assessment.evidence_truncated ? <p className="text-xs text-muted-foreground">{t("truncated")}</p> : null}
      <details>
        <summary className="cursor-pointer text-sm">{t("evidenceDetails")}</summary>
        <div className="mt-3 flex flex-col gap-2">
          {assessment.evidence.events.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("noEvents")}</p>
          ) : (
            assessment.evidence.events.map((event) => (
              <details key={`${event.kind}-${event.id}`} className="rounded-md border p-3">
                <summary className="cursor-pointer break-all text-xs">
                  {t(`eventKind.${event.kind}`)} · {event.id} · {formatTime(event.occurred_at)} ·{" "}
                  {t(`action.${event.action}`)}
                </summary>
                <p className="mt-2 break-all font-mono text-xs">{event.correlation_id}</p>
                {event.file_name ? (
                  <p className="mt-2 break-all text-xs text-muted-foreground">
                    {event.file_name}
                    {event.line ? ` · ${tu("line", { n: event.line })}` : ""}
                  </p>
                ) : null}
                <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3 font-mono text-xs">
                  {event.raw ? JSON.stringify(event.raw, null, 2) : t("rawInExport")}
                </pre>
              </details>
            ))
          )}
        </div>
      </details>
    </div>
  );
}

function ComparisonView({ comparison }: { comparison: DefenseComparison }) {
  const t = useTranslations("purple.execution");
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-violet-500/30 p-4">
      <h4 className="font-medium">{t("comparisonTitle")}</h4>
      <Badge className="self-start" variant={comparison.comparable ? "outline" : "secondary"}>
        {comparison.comparable ? t("comparable") : t("notComparable")}
      </Badge>
      {comparison.reasons.length ? (
        <ul className="list-disc space-y-1 pl-5 text-sm">
          {comparison.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      ) : null}
      {comparison.comparable ? (
        <div className="grid gap-3 sm:grid-cols-2">
          {(["baseline", "current"] as const).map((key) => {
            const execution = comparison[key];
            const result = execution.assessments[0];
            return (
              <div key={key} className="rounded-md bg-muted/50 p-3">
                <p className="font-medium">
                  {t(key)} · #{execution.id}
                </p>
                <p className="mt-1 text-xs text-muted-foreground">{formatTime(execution.created_at)}</p>
                <p className="mt-2 text-sm">
                  {t("detectionTitle")}: {result ? t(`detection.${result.detection}`) : t("uncollected")}
                </p>
                <p className="text-sm">
                  {t("preventionTitle")}: {result ? t(`prevention.${result.prevention}`) : t("uncollected")}
                </p>
              </div>
            );
          })}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">{t("comparisonUnavailable")}</p>
      )}
    </div>
  );
}

export function FindingDefenseExecutionPanel({
  findingId,
  data,
  dirty,
  readOnly,
  parentBusy,
  onRefresh,
  onRunningChange,
}: {
  findingId: string;
  data: FindingDefense;
  dirty: boolean;
  readOnly: boolean;
  parentBusy: boolean;
  onRefresh: () => Promise<boolean>;
  onRunningChange: (running: boolean) => void;
}) {
  const t = useTranslations("purple.execution");
  const tp = useTranslations("purple");
  const fieldId = React.useId();
  const tu = useTranslations("purple.upload");
  const [sourceKind, setSourceKind] = React.useState<"file" | "splunk">("file");
  const [fileConfig, setFileConfig] = React.useState<DefenseFileConfig>({ ...DEFAULT_FILE_CONFIG });
  const [sources, setSources] = React.useState<SecuritySource[] | null>(null);
  const [sourceId, setSourceId] = React.useState("");
  const [sourceError, setSourceError] = React.useState("");
  const [executions, setExecutions] = React.useState<DefenseExecution[] | null>(null);
  const [selectedId, setSelectedId] = React.useState("");
  const [baselineId, setBaselineId] = React.useState("");
  const [remediation, setRemediation] = React.useState("");
  const [notes, setNotes] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [busy, setBusy] = React.useState<"start" | "collect" | "compare" | "export" | "upload" | null>(null);
  const [error, setError] = React.useState("");
  const [historyError, setHistoryError] = React.useState("");
  const [comparison, setComparison] = React.useState<DefenseComparison | null>(null);
  const [visible, setVisible] = React.useState(true);
  const seq = React.useRef(0);
  const selected = executions?.find((execution) => execution.id === selectedId);
  const readySources = sources?.filter((source) => source.enabled && source.credential_set) ?? [];
  const sourceReady =
    sourceKind === "file"
      ? Object.values(fileConfig).every((value) => value.trim())
      : readySources.some((source) => source.id === sourceId);
  const hasActive = executions?.some(active) ?? false;

  const sourceSeq = React.useRef(0);
  const loadSources = React.useCallback(async () => {
    const request = ++sourceSeq.current;
    setSourceError("");
    try {
      const result = await securityApi.sources();
      if (request !== sourceSeq.current) return;
      const rows = result.sources ?? [];
      setSources(rows);
      setSourceId((current) => current || rows.find((source) => source.enabled && source.credential_set)?.id || "");
    } catch (e) {
      if (request === sourceSeq.current) setSourceError((e as Error).message);
    }
  }, []);
  React.useEffect(() => {
    if (sourceKind !== "splunk") return;
    void loadSources();
    return () => {
      sourceSeq.current++;
    };
  }, [loadSources, sourceKind]);

  const load = React.useCallback(async () => {
    const request = ++seq.current;
    setLoading(true);
    setHistoryError("");
    try {
      const result = await securityApi.executions(findingId);
      if (request !== seq.current) return;
      const rows = result.executions ?? [];
      setExecutions(rows);
      setSelectedId((current) => (rows.some((row) => row.id === current) ? current : (rows[0]?.id ?? "")));
    } catch (e) {
      if (request === seq.current) setHistoryError((e as Error).message);
    } finally {
      if (request === seq.current) setLoading(false);
    }
  }, [findingId]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: plan/source changes invalidate stored execution comparisons and must refresh state.
  React.useEffect(() => {
    void load();
    setComparison(null);
    return () => {
      seq.current++;
    };
  }, [load, data.plan?.revision, data.source_fingerprint]);

  React.useEffect(() => {
    const updateVisibility = () => {
      const current = document.visibilityState === "visible";
      setVisible(current);
    };
    updateVisibility();
    document.addEventListener("visibilitychange", updateVisibility);
    return () => document.removeEventListener("visibilitychange", updateVisibility);
  }, []);

  React.useEffect(() => {
    if (!visible || !hasActive || loading || busy || historyError) return;
    const timer = setTimeout(() => void load(), 5000);
    return () => clearTimeout(timer);
  }, [visible, hasActive, loading, busy, historyError, load]);

  const start = async () => {
    if (
      !data.plan ||
      dirty ||
      readOnly ||
      busy ||
      parentBusy ||
      hasActive ||
      !sourceReady ||
      (baselineId && !remediation.trim())
    )
      return;
    setBusy("start");
    onRunningChange(true);
    setError("");
    try {
      const result = await securityApi.startExecution(findingId, {
        source_kind: sourceKind,
        source_id: sourceKind === "file" ? "0" : sourceId,
        ...(sourceKind === "file" ? { file_config: fileConfig } : {}),
        plan_revision: data.plan.revision,
        expected_evidence_version: data.evidence_version,
        expected_source_fingerprint: data.source_fingerprint,
        ...(baselineId ? { baseline_id: baselineId } : {}),
        remediation_note: remediation.trim(),
        notes: notes.trim(),
      });
      seq.current++;
      setLoading(false);
      setExecutions((current) => [
        result.execution,
        ...(current ?? []).filter((item) => item.id !== result.execution.id),
      ]);
      setSelectedId(result.execution.id);
      setComparison(null);
      setNotes("");
      setRemediation("");
      setBaselineId("");
      toast.success(t("started"));
    } catch (e) {
      if (e instanceof HttpError && e.status === 409) {
        await load();
        await onRefresh();
      }
      setError((e as Error).message);
    } finally {
      setBusy(null);
      onRunningChange(false);
    }
  };

  const collect = async () => {
    if (!selected || busy || parentBusy || readOnly) return;
    setBusy("collect");
    onRunningChange(true);
    setError("");
    setComparison(null);
    try {
      await securityApi.collect(findingId, selected.id);
      await load();
      toast.success(t("collected"));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
      onRunningChange(false);
    }
  };

  const compare = async () => {
    if (!selected?.baseline_id || busy) return;
    setBusy("compare");
    setError("");
    const request = seq.current;
    try {
      const result = await securityApi.compare(findingId, selected.baseline_id, selected.id);
      if (request === seq.current) setComparison(result);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const exportExecution = async () => {
    if (!selected || busy) return;
    setBusy("export");
    setError("");
    try {
      downloadSecurityJSON(
        await securityApi.exportExecution(findingId, selected.id),
        `artex-defense-execution-${findingId}-${selected.id}.json`,
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card className="border-violet-500/40">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="flex flex-col gap-1.5">
          <CardTitle className="flex items-center gap-2">
            <CableIcon className="size-5 text-violet-500" />
            {t("title")}
          </CardTitle>
          <CardDescription>{t("description")}</CardDescription>
        </div>
        <Button asChild variant="outline" size="sm">
          <Link href="/function/purple/sources">{t("manageSources")}</Link>
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {sourceKind === "splunk" && sourceError ? (
          <Alert variant="destructive">
            <AlertDescription>{sourceError}</AlertDescription>
          </Alert>
        ) : null}
        <p className="text-sm text-muted-foreground">{t("scope")}</p>
        <details className="rounded-lg bg-muted/50 p-3">
          <summary className="cursor-pointer text-sm font-medium">{t("correlationHelpTitle")}</summary>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{t("correlationHelp")}</p>
        </details>
        {!data.plan ? <p className="text-sm text-muted-foreground">{tp("savePlanFirst")}</p> : null}
        {dirty ? <p className="text-sm text-amber-700 dark:text-amber-300">{tp("saveChangesFirst")}</p> : null}
        {sourceKind === "splunk" && sources !== null && !readySources.length ? (
          <Alert>
            <AlertDescription>
              {t("noSources")}{" "}
              <Link className="underline" href="/function/purple/sources">
                {t("manageSources")}
              </Link>
            </AlertDescription>
          </Alert>
        ) : null}
        {!readOnly ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void start();
            }}
          >
            <fieldset className="flex flex-col gap-4" disabled={!!busy || parentBusy || hasActive}>
              <div className="flex flex-col gap-2">
                <Label htmlFor={`${fieldId}-kind`}>{tu("sourceKind")}</Label>
                <select
                  id={`${fieldId}-kind`}
                  className={SELECT_CLASS}
                  value={sourceKind}
                  onChange={(event) => {
                    setSourceKind(event.target.value as "file" | "splunk");
                    setBaselineId("");
                  }}
                >
                  <option value="file">{tu("fileMode")}</option>
                  <option value="splunk">{tu("splunkMode")}</option>
                </select>
                <p className="text-xs text-muted-foreground">
                  {sourceKind === "file" ? tu("fileModeHelp") : tu("splunkModeHelp")}
                </p>
              </div>
              {sourceKind === "file" ? (
                <div className="flex flex-col gap-3">
                  <div className="flex flex-col gap-2">
                    <Label htmlFor={`${fieldId}-file-label`}>{tu("label")}</Label>
                    <Input
                      id={`${fieldId}-file-label`}
                      required
                      maxLength={120}
                      placeholder={tu("labelPlaceholder")}
                      value={fileConfig.label}
                      onChange={(event) => setFileConfig({ ...fileConfig, label: event.target.value })}
                    />
                  </div>
                  <details className="rounded-lg bg-muted/50 p-3">
                    <summary className="cursor-pointer text-sm">{tu("advancedMapping")}</summary>
                    <p className="mt-3 text-xs text-muted-foreground">{tu("mappingHelp")}</p>
                    <div className="mt-3 grid gap-3 sm:grid-cols-2">
                      {FILE_MAPPING_FIELDS.map((key) => (
                        <div key={key} className="flex flex-col gap-2">
                          <Label htmlFor={`${fieldId}-${key}`}>{tu(key)}</Label>
                          <Input
                            id={`${fieldId}-${key}`}
                            required
                            maxLength={128}
                            value={fileConfig[key]}
                            onChange={(event) => setFileConfig({ ...fileConfig, [key]: event.target.value })}
                          />
                          <p className="text-xs text-muted-foreground">{tu(`${key}_help`)}</p>
                        </div>
                      ))}
                    </div>
                    <p className="mt-3 text-xs text-muted-foreground">{tu("formatExampleHelp")}</p>
                    <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-words rounded-md bg-background p-3 font-mono text-xs">
                      {
                        '{"timestamp":"<ISO8601>","artex_verification_id":"<execution UUID>","action":"<blocked|allowed>","id":"<event ID>"}'
                      }
                    </pre>
                  </details>
                </div>
              ) : null}
              <div className="grid gap-4 sm:grid-cols-2">
                {sourceKind === "splunk" ? (
                  <div className="flex flex-col gap-2">
                    <Label htmlFor={`${fieldId}-source`}>{t("source")}</Label>
                    <select
                      id={`${fieldId}-source`}
                      className={SELECT_CLASS}
                      value={sourceId}
                      onChange={(event) => setSourceId(event.target.value)}
                    >
                      <option value="">{t("chooseSource")}</option>
                      {readySources.map((source) => (
                        <option key={source.id} value={source.id}>
                          {source.name} · v{source.revision}
                        </option>
                      ))}
                    </select>
                  </div>
                ) : null}
                <div className="flex flex-col gap-2">
                  <Label htmlFor={`${fieldId}-baseline`}>{t("baselineChoice")}</Label>
                  <select
                    id={`${fieldId}-baseline`}
                    className={SELECT_CLASS}
                    value={baselineId}
                    onChange={(event) => setBaselineId(event.target.value)}
                  >
                    <option value="">{t("noBaseline")}</option>
                    {executions
                      ?.filter(
                        (execution) =>
                          execution.retest.status === "completed" &&
                          execution.assessments.length > 0 &&
                          executionSourceKind(execution) === sourceKind,
                      )
                      .map((execution) => (
                        <option key={execution.id} value={execution.id}>
                          #{execution.id} · {formatTime(execution.created_at)}
                        </option>
                      ))}
                  </select>
                </div>
              </div>
              {baselineId ? (
                <div className="flex flex-col gap-2">
                  <Label htmlFor={`${fieldId}-remediation`}>{t("remediation")}</Label>
                  <Textarea
                    id={`${fieldId}-remediation`}
                    required
                    rows={3}
                    maxLength={8000}
                    value={remediation}
                    onChange={(event) => setRemediation(event.target.value)}
                  />
                </div>
              ) : null}
              <div className="flex flex-col gap-2">
                <Label htmlFor={`${fieldId}-notes`}>{tp("notes")}</Label>
                <Textarea
                  id={`${fieldId}-notes`}
                  rows={2}
                  maxLength={4000}
                  value={notes}
                  onChange={(event) => setNotes(event.target.value)}
                />
              </div>
              <Button
                type="submit"
                className="self-start"
                disabled={!data.plan || dirty || !sourceReady || (baselineId !== "" && !remediation.trim())}
              >
                {busy === "start" ? <Spinner /> : <PlayIcon />}
                {t("start")}
              </Button>
            </fieldset>
          </form>
        ) : null}
        {hasActive ? <p className="text-sm text-muted-foreground">{t("activeNotice")}</p> : null}
        <div className="flex flex-col gap-3 border-t pt-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-medium">{t("history")}</h3>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={loading || !!busy}
              onClick={() => {
                setComparison(null);
                void load();
                if (sourceKind === "splunk") void loadSources();
              }}
            >
              <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
              {tp("refresh")}
            </Button>
          </div>
          {historyError ? (
            <Alert variant="destructive">
              <AlertDescription>{historyError}</AlertDescription>
            </Alert>
          ) : null}
          {!executions && loading ? <Skeleton className="h-24" /> : null}
          {executions?.length === 0 ? <p className="text-sm text-muted-foreground">{t("empty")}</p> : null}
          {executions?.length ? (
            <div className="flex flex-col gap-2">
              <Label htmlFor={`${fieldId}-history`}>{t("selectExecution")}</Label>
              <select
                id={`${fieldId}-history`}
                className={SELECT_CLASS}
                value={selectedId}
                disabled={!!busy}
                onChange={(event) => {
                  setSelectedId(event.target.value);
                  setComparison(null);
                }}
              >
                {executions.map((execution) => (
                  <option key={execution.id} value={execution.id}>
                    #{execution.id} · {t(`status.${execution.retest.status}`)} · {formatTime(execution.created_at)}
                  </option>
                ))}
              </select>
            </div>
          ) : null}
          {selected ? (
            <div className="flex min-w-0 flex-col gap-4 rounded-lg border p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">
                    {executionSourceKind(selected) === "file" ? tu("fileModeShort") : "Splunk"} ·{" "}
                    {selected.source_snapshot.name} · v{selected.source_revision}
                  </Badge>
                  <Badge variant={selected.state === "stale" ? "secondary" : "outline"}>
                    {selected.state === "stale" ? t("stale") : t("currentState")}
                  </Badge>
                  <span className="text-xs text-muted-foreground">
                    {tp("revision", { n: selected.plan_snapshot.revision })}
                  </span>
                </div>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={!!busy}
                  onClick={() => void exportExecution()}
                >
                  {busy === "export" ? <Spinner /> : <DownloadIcon />}
                  {t("export")}
                </Button>
              </div>
              <p className="break-all font-mono text-xs text-muted-foreground">
                {t("correlationId")}: {selected.correlation_id}
              </p>
              <div className="rounded-lg bg-muted/50 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h4 className="text-sm font-medium">
                    {t("diagnosis")}: {t(`status.${selected.retest.status}`)}
                  </h4>
                  {selected.retest.conversation_id != null ? (
                    <Button asChild variant="ghost" size="sm">
                      <Link href={`/chat?c=${selected.retest.conversation_id}`}>{t("viewSession")}</Link>
                    </Button>
                  ) : null}
                </div>
                {selected.retest.verdict ? (
                  <p className="mt-2 text-sm">
                    {t("diagnosisVerdict")}: {t(`verdict.${selected.retest.verdict}`)}
                  </p>
                ) : null}
                {selected.retest.summary ? (
                  <p className="mt-2 whitespace-pre-wrap break-words text-sm text-muted-foreground">
                    {selected.retest.summary}
                  </p>
                ) : null}
                {selected.retest.error ? (
                  <p className="mt-2 whitespace-pre-wrap break-words text-sm text-destructive">
                    {selected.retest.error}
                  </p>
                ) : null}
                <p className="mt-2 text-xs text-muted-foreground">{t("verdictBoundary")}</p>
              </div>
              {selected.remediation_note ? (
                <div>
                  <h4 className="text-sm font-medium">{t("remediationRecorded")}</h4>
                  <p className="mt-1 whitespace-pre-wrap break-words text-sm text-muted-foreground">
                    {selected.remediation_note}
                  </p>
                </div>
              ) : null}
              <div className="flex flex-col gap-2">
                <div className="flex flex-wrap gap-2">
                  {executionSourceKind(selected) === "splunk" ? (
                    <Button
                      type="button"
                      variant="outline"
                      disabled={!!busy || parentBusy || readOnly || active(selected)}
                      onClick={() => void collect()}
                    >
                      {busy === "collect" ? <Spinner /> : <RefreshCwIcon />}
                      {t("collect")}
                    </Button>
                  ) : null}
                  {selected.baseline_id ? (
                    <Button type="button" variant="outline" disabled={!!busy} onClick={() => void compare()}>
                      {busy === "compare" ? <Spinner /> : null}
                      {t("compare")}
                    </Button>
                  ) : null}
                </div>
                <p className="text-xs text-muted-foreground">
                  {executionSourceKind(selected) === "file" ? tu("periodHelp") : t("settling")}
                </p>
              </div>
              {executionSourceKind(selected) === "file" && active(selected) ? (
                <p className="text-sm text-muted-foreground">{tu("waitForDiagnosis")}</p>
              ) : null}
              {executionSourceKind(selected) === "file" && !active(selected) ? (
                <FindingDefenseFileUpload
                  key={selected.id}
                  findingId={findingId}
                  execution={selected}
                  disabled={parentBusy || (busy !== null && busy !== "upload")}
                  readOnly={readOnly}
                  onRunningChange={(running) => {
                    setBusy(running ? "upload" : null);
                    onRunningChange(running);
                  }}
                  onUploaded={async () => {
                    setComparison(null);
                    await load();
                  }}
                />
              ) : null}
              {selected.assessments.length ? (
                <AssessmentView assessment={selected.assessments[0]} />
              ) : (
                <p className="text-sm text-muted-foreground">{t("uncollected")}</p>
              )}
              {comparison?.current.id === selected.id ? <ComparisonView comparison={comparison} /> : null}
              {selected.assessments_truncated ? (
                <p className="text-xs text-muted-foreground">{t("truncated")}</p>
              ) : null}
              {selected.assessments.length > 1 ? (
                <details>
                  <summary className="cursor-pointer text-sm">
                    {t("previousAssessments", { n: selected.assessments.length - 1 })}
                  </summary>
                  <div className="mt-3 flex flex-col gap-4">
                    {selected.assessments.slice(1).map((assessment) => (
                      <div key={assessment.id} className="rounded-lg border p-3">
                        <p className="mb-3 text-xs text-muted-foreground">
                          #{assessment.id} · {formatTime(assessment.created_at)}
                        </p>
                        <AssessmentView assessment={assessment} />
                      </div>
                    ))}
                  </div>
                </details>
              ) : null}
            </div>
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}
