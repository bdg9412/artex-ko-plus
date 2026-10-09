"use client";

import * as React from "react";

import { DownloadIcon, FileJsonIcon, PlayIcon, RefreshCwIcon } from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { DefenseReplayBadge } from "@/components/defense-state-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { HttpError } from "@/lib/api";
import { type DefenseReplay, type FindingDefense, purpleApi } from "@/lib/purple-api";

const MAX_LOG_BYTES = 1024 * 1024;
const EXAMPLE_TARGET = '{"event":{"action":"access_denied"}}';
const EXAMPLE_CONTROL = '{"event":{"action":"page_view"}}';

function byteLength(value: string) {
  return new TextEncoder().encode(value).byteLength;
}

function ReplayResultDetails({ run }: { run: DefenseReplay }) {
  const t = useTranslations("purple.replay");
  const issues = run.result.evaluations.filter((event) =>
    event.dataset === "target" ? event.outcome !== "match" : event.outcome !== "no_match",
  );
  return (
    <div className="flex flex-col gap-3">
      <p className="text-xs text-muted-foreground">{t("scope")}</p>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t("dataset")}</TableHead>
            <TableHead>{t("total")}</TableHead>
            <TableHead>{t("matched")}</TableHead>
            <TableHead>{t("unmatched")}</TableHead>
            <TableHead>{t("undecidable")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {(["target", "control"] as const).map((dataset) => (
            <TableRow key={dataset}>
              <TableCell>{t(dataset)}</TableCell>
              <TableCell>{run.result[dataset].total}</TableCell>
              <TableCell
                className={dataset === "control" && run.result[dataset].matched ? "text-destructive" : undefined}
              >
                {run.result[dataset].matched}
              </TableCell>
              <TableCell
                className={dataset === "target" && run.result[dataset].missed ? "text-destructive" : undefined}
              >
                {run.result[dataset].missed}
              </TableCell>
              <TableCell>{run.result[dataset].inconclusive}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <p className="text-xs text-muted-foreground">{t("countsHelp")}</p>
      {run.result.reasons.length ? (
        <ul className="list-disc space-y-1 pl-5 text-sm">
          {run.result.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      ) : null}
      {run.evaluations_truncated ? <p className="text-xs text-muted-foreground">{t("limitedPreview")}</p> : null}
      {issues.length ? (
        <details>
          <summary className="cursor-pointer text-sm">
            {t(run.evaluations_truncated ? "previewIssues" : "issues", { n: issues.length })}
          </summary>
          <div className="mt-3">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("dataset")}</TableHead>
                  <TableHead>{t("line")}</TableHead>
                  <TableHead>{t("eventResult")}</TableHead>
                  <TableHead>{t("missingFields")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {issues.map((event) => (
                  <TableRow key={`${event.dataset}-${event.line}`}>
                    <TableCell>{t(event.dataset)}</TableCell>
                    <TableCell>{event.line}</TableCell>
                    <TableCell>{t(`outcome.${event.outcome}`)}</TableCell>
                    <TableCell className="max-w-sm whitespace-normal break-words font-mono text-xs">
                      {event.missing_fields?.join(", ") || "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </details>
      ) : null}
      {run.notes ? <p className="whitespace-pre-wrap break-words text-sm text-muted-foreground">{run.notes}</p> : null}
      <details>
        <summary className="cursor-pointer text-sm text-muted-foreground">{t("reproducibility")}</summary>
        <div className="mt-3 flex flex-col gap-2 text-xs">
          <p>{run.evaluator_version}</p>
          <p>{t("savedRule")}</p>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted p-3">
            {run.plan_snapshot.rule_text}
          </pre>
          <dl className="grid gap-2">
            {(["rule_sha256", "target_sha256", "control_sha256"] as const).map((key) => (
              <div key={key}>
                <dt className="text-muted-foreground">{t(key)}</dt>
                <dd className="break-all font-mono">{run[key]}</dd>
              </div>
            ))}
          </dl>
        </div>
      </details>
    </div>
  );
}

export function FindingDefenseReplayPanel({
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
  const t = useTranslations("purple.replay");
  const tp = useTranslations("purple");
  const fieldId = React.useId();
  const [targetLogs, setTargetLogs] = React.useState("");
  const [controlLogs, setControlLogs] = React.useState("");
  const [notes, setNotes] = React.useState("");
  const [runs, setRuns] = React.useState<DefenseReplay[] | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [running, setRunning] = React.useState(false);
  const [readingFile, setReadingFile] = React.useState(false);
  const [exporting, setExporting] = React.useState<string | null>(null);
  const [error, setError] = React.useState("");
  const [historyError, setHistoryError] = React.useState("");
  const requestSeq = React.useRef(0);
  const totalBytes = byteLength(targetLogs) + byteLength(controlLogs);
  const executable = data.plan?.rule_format === "event_filter";

  const loadRuns = React.useCallback(async () => {
    const seq = ++requestSeq.current;
    setLoading(true);
    setHistoryError("");
    try {
      const result = await purpleApi.replays(findingId);
      if (seq === requestSeq.current) setRuns(result.runs ?? []);
    } catch (e) {
      if (seq === requestSeq.current) setHistoryError((e as Error).message);
    } finally {
      if (seq === requestSeq.current) setLoading(false);
    }
  }, [findingId]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: plan/source changes require recomputing each stored run's current/stale status.
  React.useEffect(() => {
    void loadRuns();
    return () => {
      requestSeq.current++;
    };
  }, [loadRuns, data.plan?.revision, data.source_fingerprint]);

  const loadFile = async (file: File | undefined, dataset: "target" | "control") => {
    if (!file) return;
    setError("");
    if (file.size > MAX_LOG_BYTES) {
      setError(t("tooLarge"));
      return;
    }
    setReadingFile(true);
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(await file.arrayBuffer());
      const other = dataset === "target" ? controlLogs : targetLogs;
      if (byteLength(text) + byteLength(other) > MAX_LOG_BYTES) {
        setError(t("tooLarge"));
        return;
      }
      if (dataset === "target") setTargetLogs(text);
      else setControlLogs(text);
    } catch {
      setError(t("fileError"));
    } finally {
      setReadingFile(false);
    }
  };

  const fillExamples = () => {
    const sampleNote = notes ? `${notes}\n${t("sampleNote")}` : t("sampleNote");
    if (sampleNote.length > 4000) {
      setError(t("exampleNotesFull"));
      return;
    }
    setTargetLogs(EXAMPLE_TARGET);
    setControlLogs(EXAMPLE_CONTROL);
    setNotes(sampleNote);
  };

  const runReplay = async () => {
    if (!data.plan || !executable || dirty || readOnly || parentBusy || running || readingFile) return;
    if (totalBytes > MAX_LOG_BYTES) {
      setError(t("tooLarge"));
      return;
    }
    setRunning(true);
    onRunningChange(true);
    setError("");
    try {
      await purpleApi.replay(findingId, {
        plan_revision: data.plan.revision,
        expected_evidence_version: data.evidence_version,
        expected_source_fingerprint: data.source_fingerprint,
        target_logs: targetLogs,
        control_logs: controlLogs,
        notes: notes.trim(),
      });
      await loadRuns();
      toast.success(t("saved"));
    } catch (e) {
      if (e instanceof HttpError && e.status === 409) {
        await onRefresh();
        await loadRuns();
        setError(t("conflict"));
      } else {
        setError((e as Error).message);
      }
    } finally {
      setRunning(false);
      onRunningChange(false);
    }
  };

  const exportRun = async (runId: string) => {
    setExporting(runId);
    setHistoryError("");
    try {
      const result = await purpleApi.exportReplay(findingId, runId);
      const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `artex-defense-replay-${findingId}-${runId}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      setHistoryError((e as Error).message);
    } finally {
      setExporting(null);
    }
  };

  return (
    <Card className="border-violet-500/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileJsonIcon className="size-5 text-violet-500" />
          {t("title")}
        </CardTitle>
        <CardDescription>{t("scope")}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {!data.plan ? <p className="text-sm text-muted-foreground">{tp("savePlanFirst")}</p> : null}
        {data.plan && !executable ? (
          <Alert>
            <AlertDescription>{t("formatRequired")}</AlertDescription>
          </Alert>
        ) : null}
        {dirty ? <p className="text-sm text-amber-700 dark:text-amber-300">{tp("saveChangesFirst")}</p> : null}
        {!readOnly ? (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void runReplay();
            }}
          >
            <fieldset className="flex flex-col gap-4" disabled={running || readingFile || parentBusy}>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <p className="text-xs text-muted-foreground">{t("inputHelp")}</p>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={!!targetLogs || !!controlLogs}
                  onClick={fillExamples}
                >
                  {t("fillExample")}
                </Button>
              </div>
              <div className="grid gap-4 lg:grid-cols-2">
                {(["target", "control"] as const).map((dataset) => (
                  <div key={dataset} className="flex min-w-0 flex-col gap-2">
                    <Label htmlFor={`${fieldId}-${dataset}`}>{t(dataset)}</Label>
                    <p className="text-xs text-muted-foreground">{t(`${dataset}Help`)}</p>
                    <Textarea
                      id={`${fieldId}-${dataset}`}
                      className="min-h-44 font-mono text-xs"
                      rows={8}
                      maxLength={MAX_LOG_BYTES}
                      value={dataset === "target" ? targetLogs : controlLogs}
                      placeholder={t("logPlaceholder")}
                      onChange={(event) => {
                        if (dataset === "target") setTargetLogs(event.target.value);
                        else setControlLogs(event.target.value);
                      }}
                    />
                    <Label className="text-xs text-muted-foreground" htmlFor={`${fieldId}-${dataset}-file`}>
                      {t("file")}
                    </Label>
                    <Input
                      id={`${fieldId}-${dataset}-file`}
                      type="file"
                      accept=".json,.jsonl,.ndjson,.txt"
                      className="text-xs"
                      onChange={(event) => {
                        const file = event.target.files?.[0];
                        event.target.value = "";
                        void loadFile(file, dataset);
                      }}
                    />
                  </div>
                ))}
              </div>
              <p className={totalBytes > MAX_LOG_BYTES ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
                {t("limits", { n: (totalBytes / 1024).toFixed(1) })}
              </p>
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
              <p className="text-xs text-muted-foreground">{t("retention")}</p>
              <Button
                className="self-start"
                type="submit"
                disabled={
                  !data.plan ||
                  !executable ||
                  dirty ||
                  totalBytes > MAX_LOG_BYTES ||
                  (!targetLogs.trim() && !controlLogs.trim())
                }
              >
                {running ? <Spinner /> : <PlayIcon />}
                {t("run")}
              </Button>
            </fieldset>
          </form>
        ) : null}
        <div className="flex flex-col gap-3 border-t pt-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-medium">{t("history")}</h3>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              disabled={loading || running}
              onClick={() => void loadRuns()}
            >
              <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
              {tp("refresh")}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">{t("historyHelp")}</p>
          {historyError ? (
            <Alert variant="destructive">
              <AlertDescription>{historyError}</AlertDescription>
            </Alert>
          ) : null}
          {!runs && loading ? <Skeleton className="h-20 w-full" /> : null}
          {runs?.length === 0 ? <p className="py-3 text-sm text-muted-foreground">{t("empty")}</p> : null}
          {runs?.map((run, index) => (
            <div key={run.id} className="min-w-0 rounded-lg border p-4">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <DefenseReplayBadge verdict={run.result.verdict} />
                  {run.state === "stale" ? (
                    <Badge variant="destructive">{t("stale")}</Badge>
                  ) : (
                    <Badge variant="secondary">{t("current")}</Badge>
                  )}
                  <span className="text-xs text-muted-foreground">
                    #{run.id} · {tp("revision", { n: run.plan_revision })} · {new Date(run.created_at).toLocaleString()}
                  </span>
                </div>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  disabled={exporting !== null}
                  onClick={() => void exportRun(run.id)}
                >
                  {exporting === run.id ? <Spinner /> : <DownloadIcon />}
                  {t("export")}
                </Button>
              </div>
              <details open={index === 0}>
                <summary className="cursor-pointer text-sm">{t("resultDetails")}</summary>
                <div className="mt-4">
                  <ReplayResultDetails run={run} />
                </div>
              </details>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
