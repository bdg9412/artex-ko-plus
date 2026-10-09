"use client";

import * as React from "react";

import { DownloadIcon, RefreshCwIcon, SearchIcon, SquareIcon, WorkflowIcon, XIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import {
  type InvestigationAgentObservation,
  type InvestigationAgentProgress,
  type InvestigationAgentRun,
  type InvestigationAgentRunEvent,
  type InvestigationAgentRunSummary,
  type InvestigationAgentStatus,
  investigationAgentApi,
} from "@/lib/investigation-agent-api";
import type { InvestigationCollection, InvestigationEvent, InvestigationRecord } from "@/lib/investigation-api";
import { downloadSecurityJSON } from "@/lib/security-api";

type CitedEvent = { event: InvestigationEvent; query?: string };

function active(status: InvestigationAgentStatus) {
  return status === "queued" || status === "running";
}

function stageLabel(stage: string) {
  if (stage === "planner") return "planner";
  if (stage === "worker") return "worker";
  return "runtime";
}

function progress(event: InvestigationAgentRunEvent): InvestigationAgentProgress | null {
  return "summary" in event.payload ? event.payload : null;
}

function StringList({ items }: { items: string[] | null | undefined }) {
  if (!items?.length) return null;
  return (
    <ul className="list-disc space-y-1 pl-5 text-sm leading-relaxed">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}

function Citations({
  refs,
  evidence,
  onSelect,
}: {
  refs: string[] | null | undefined;
  evidence: Map<string, CitedEvent>;
  onSelect: (event: CitedEvent) => void;
}) {
  const t = useTranslations("investigationAgent");
  if (!refs?.length) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {refs.map((ref) => {
        const item = evidence.get(ref);
        return item ? (
          <Button
            key={ref}
            variant="outline"
            size="sm"
            className="h-auto max-w-full py-1 text-xs"
            onClick={() => onSelect(item)}
          >
            <span className="truncate">
              {item.event.file_name} · {t("line", { n: item.event.line })}
            </span>
          </Button>
        ) : (
          <span key={ref} className="break-all text-muted-foreground text-xs">
            {t("unresolvedRef", { ref })}
          </span>
        );
      })}
    </div>
  );
}

function ObservationGroup({
  kind,
  observations,
  evidence,
  onSelect,
}: {
  kind: InvestigationAgentObservation["kind"];
  observations: InvestigationAgentObservation[];
  evidence: Map<string, CitedEvent>;
  onSelect: (event: CitedEvent) => void;
}) {
  const t = useTranslations("investigationAgent");
  const titles = { observed: "observed", inferred: "inferred", insufficient_data: "unsupported" } as const;
  const items = observations.filter((item) => item.kind === kind);
  return (
    <div className="space-y-3 rounded-lg border p-4">
      <h4 className="font-medium text-sm">{t(titles[kind])}</h4>
      {!items.length ? <p className="text-muted-foreground text-xs">{t("noClaims")}</p> : null}
      {items.map((item) => (
        <div key={item.id} className="space-y-2 border-t pt-3 text-sm first-of-type:border-t-0 first-of-type:pt-0">
          <p className="whitespace-pre-wrap leading-relaxed">{item.summary}</p>
          {item.known_artex ? <Badge variant="secondary">{t("knownARTEX")}</Badge> : null}
          <Citations refs={item.evidence_refs} evidence={evidence} onSelect={onSelect} />
          {item.alternatives?.length ? (
            <div className="space-y-1 text-muted-foreground">
              <p className="font-medium text-xs">{t("alternatives")}</p>
              <StringList items={item.alternatives} />
            </div>
          ) : null}
          {item.next_steps?.length ? (
            <div className="space-y-1">
              <p className="font-medium text-xs">{t("nextSteps")}</p>
              <StringList items={item.next_steps} />
            </div>
          ) : null}
        </div>
      ))}
    </div>
  );
}

export function FindingInvestigationAgentPanel({
  findingId,
  record,
  readOnly = false,
  pendingEvidence = false,
}: {
  findingId: string;
  record: InvestigationRecord;
  readOnly?: boolean;
  pendingEvidence?: boolean;
}) {
  const t = useTranslations("investigationAgent");
  const fieldId = React.useId();
  const [question, setQuestion] = React.useState(record.question);
  const [runs, setRuns] = React.useState<InvestigationAgentRunSummary[]>([]);
  const [run, setRun] = React.useState<InvestigationAgentRun | null>(null);
  const [busy, setBusy] = React.useState<"load" | "start" | "cancel" | "open" | null>("load");
  const [error, setError] = React.useState("");
  const [exporting, setExporting] = React.useState(false);
  const [truncated, setTruncated] = React.useState(false);
  const [selectedEvidence, setSelectedEvidence] = React.useState<CitedEvent | null>(null);
  const mounted = React.useRef(true);
  const selectedRun = React.useRef<string | null>(null);
  const generation = React.useRef(0);
  const evidenceRef = React.useRef<HTMLDivElement>(null);

  const adopt = React.useCallback((next: InvestigationAgentRun) => {
    setRun(next);
    selectedRun.current = next.id;
    setRuns((current) =>
      [next, ...current.filter((item) => item.id !== next.id)].sort((a, b) => b.created_at.localeCompare(a.created_at)),
    );
  }, []);

  const refresh = React.useCallback(async () => {
    const request = ++generation.current;
    setBusy("load");
    setError("");
    try {
      const response = await investigationAgentApi.list(findingId, record.id);
      if (!mounted.current || request !== generation.current) return;
      setRuns(response.runs ?? []);
      setTruncated(response.history_truncated ?? false);
      const id = selectedRun.current ?? response.runs?.[0]?.id;
      if (id) {
        const detail = await investigationAgentApi.get(findingId, record.id, id);
        if (mounted.current && request === generation.current) adopt(detail);
      }
    } catch (caught) {
      if (mounted.current && request === generation.current) setError((caught as Error).message);
    } finally {
      if (mounted.current && request === generation.current) setBusy(null);
    }
  }, [findingId, record.id, adopt]);

  React.useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => {
      mounted.current = false;
      generation.current++;
    };
  }, [refresh]);

  const runId = run?.id;
  const runStatus = run?.status;
  React.useEffect(() => {
    if (!runId || !runStatus || !active(runStatus) || busy) return;
    const id = runId;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const next = await investigationAgentApi.get(findingId, record.id, id);
        if (disposed || !mounted.current || selectedRun.current !== id) return;
        adopt(next);
        setError("");
        if (active(next.status)) timer = setTimeout(() => void poll(), 3000);
      } catch (caught) {
        if (disposed || !mounted.current || selectedRun.current !== id) return;
        setError((caught as Error).message);
        timer = setTimeout(() => void poll(), 5000);
      }
    };
    timer = setTimeout(() => void poll(), 2000);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [runId, runStatus, busy, findingId, record.id, adopt]);

  const start = async () => {
    if (busy || readOnly || pendingEvidence || record.state === "stale" || runs.some((item) => active(item.status)))
      return;
    generation.current++;
    setBusy("start");
    setError("");
    try {
      const next = await investigationAgentApi.create(findingId, record.id, { question: question.trim() });
      if (mounted.current) {
        adopt(next);
        setSelectedEvidence(null);
      }
    } catch (caught) {
      if (mounted.current) setError((caught as Error).message);
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  const open = async (id: string) => {
    const request = ++generation.current;
    setBusy("open");
    setError("");
    selectedRun.current = id;
    try {
      const next = await investigationAgentApi.get(findingId, record.id, id);
      if (mounted.current && request === generation.current) {
        adopt(next);
        setSelectedEvidence(null);
      }
    } catch (caught) {
      if (mounted.current && request === generation.current) setError((caught as Error).message);
    } finally {
      if (mounted.current && request === generation.current) setBusy(null);
    }
  };

  const cancel = async () => {
    if (!run || busy || readOnly) return;
    generation.current++;
    setBusy("cancel");
    setError("");
    try {
      const next = await investigationAgentApi.cancel(findingId, record.id, run.id);
      if (mounted.current) adopt(next);
    } catch (caught) {
      if (mounted.current) setError((caught as Error).message);
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  const exportRun = async () => {
    if (!run || exporting) return;
    setExporting(true);
    try {
      downloadSecurityJSON(
        await investigationAgentApi.export(findingId, record.id, run.id),
        `artex-agent-investigation-${run.id}.json`,
      );
    } catch (caught) {
      if (mounted.current) setError((caught as Error).message);
    } finally {
      if (mounted.current) setExporting(false);
    }
  };

  const evidence = React.useMemo(() => {
    const index = new Map<string, CitedEvent>();
    const add = (collection: InvestigationCollection) => {
      for (const event of collection.events ?? []) index.set(event.ref, { event, query: collection.query });
    };
    add(record.collection);
    for (const entry of run?.events ?? []) if ("collection" in entry.payload) add(entry.payload.collection);
    for (const collection of run?.result?.collections ?? []) add(collection);
    return index;
  }, [record.collection, run?.events, run?.result?.collections]);

  const selectEvidence = (item: CitedEvent) => {
    setSelectedEvidence(item);
    requestAnimationFrame(() => evidenceRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" }));
  };
  const trace = (run?.events ?? []).flatMap((entry) => {
    const item = progress(entry);
    return item ? [{ ...item, sequence: entry.sequence, created_at: entry.created_at }] : [];
  });
  const observations = run?.result?.observations ?? [
    ...new Map(
      trace.flatMap((item) => (item.observation ? [[item.observation.id, item.observation] as const] : [])),
    ).values(),
  ];
  const intents = run?.result?.intents ?? [
    ...new Map(trace.flatMap((item) => (item.intent ? [[item.intent.id, item.intent] as const] : []))).values(),
  ];
  const searches =
    run?.result?.searches ??
    (run?.events ?? []).flatMap((entry) => ("search" in entry.payload ? [entry.payload.search] : []));
  const usage = run?.result?.usage ?? run?.usage;
  const anyActive = runs.some((item) => active(item.status));
  const partial = run && ["budget_exhausted", "cancelled", "model_error", "interrupted"].includes(run.status);

  return (
    <Card className="border-sky-500/40">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2">
            <WorkflowIcon className="size-5 text-sky-500" />
            {t("title")}
          </CardTitle>
          <CardDescription>{t("description")}</CardDescription>
        </div>
        <Button variant="outline" size="sm" onClick={() => void refresh()} disabled={!!busy}>
          <RefreshCwIcon className={busy === "load" ? "animate-spin" : undefined} />
          {t("refresh")}
        </Button>
      </CardHeader>
      <CardContent className="space-y-5">
        <p className="text-sky-700 text-sm dark:text-sky-300">{t("flow")}</p>
        <div className="space-y-2 rounded-lg bg-muted/40 p-4 text-sm">
          <p className="font-medium">{t("record", { title: record.title || record.id })}</p>
          <p className="text-muted-foreground text-xs">
            {t("recordSavedAt", { at: new Date(record.created_at).toLocaleString() })}
          </p>
          <p className="break-all">
            {t("scope")}: {record.scope.target}
            {record.scope.path_prefix}
          </p>
          <p className="text-muted-foreground text-xs">
            {new Date(record.scope.start).toLocaleString()} → {new Date(record.scope.end).toLocaleString()}
          </p>
          <p className="text-muted-foreground text-xs leading-relaxed">{t("scopeHelp")}</p>
          <p className="text-muted-foreground text-xs leading-relaxed">
            {t(record.source_kind === "splunk" ? "splunkHelp" : "fileHelp")}
          </p>
        </div>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {readOnly ? (
          <Alert>
            <AlertDescription>{t("readOnly")}</AlertDescription>
          </Alert>
        ) : null}
        {record.state === "stale" ? (
          <Alert>
            <AlertDescription>{t("stale")}</AlertDescription>
          </Alert>
        ) : null}
        {pendingEvidence && !readOnly ? (
          <Alert>
            <AlertDescription>{t("pendingEvidence")}</AlertDescription>
          </Alert>
        ) : null}
        <div className="space-y-3">
          <Label htmlFor={`${fieldId}-question`}>{t("question")}</Label>
          <Textarea
            id={`${fieldId}-question`}
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            placeholder={t("questionPlaceholder")}
            maxLength={4000}
            rows={2}
            disabled={!!busy || anyActive || readOnly || record.state === "stale"}
          />
          <p className="text-muted-foreground text-xs leading-relaxed">{t("disclosure")}</p>
          <div className="flex flex-wrap items-center gap-3">
            <Button
              onClick={() => void start()}
              disabled={!!busy || anyActive || readOnly || pendingEvidence || record.state === "stale"}
            >
              {busy === "start" ? <Spinner /> : <SearchIcon />}
              {t(runs.length ? "again" : "start")}
            </Button>
            {run && active(run.status) ? (
              <Button variant="outline" onClick={() => void cancel()} disabled={!!busy || readOnly}>
                {busy === "cancel" ? <Spinner /> : <SquareIcon />}
                {t("cancel")}
              </Button>
            ) : null}
          </div>
          <p className="text-muted-foreground text-xs">{t("budget")}</p>
        </div>
        <div className="space-y-2">
          <Label htmlFor={`${fieldId}-history`}>{t("history")}</Label>
          {runs.length ? (
            <select
              id={`${fieldId}-history`}
              value={run?.id ?? ""}
              onChange={(event) => void open(event.target.value)}
              disabled={!!busy}
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm disabled:opacity-50"
            >
              {runs.map((item) => (
                <option key={item.id} value={item.id}>
                  {new Date(item.created_at).toLocaleString()} · {t(`status.${item.status}`)}
                </option>
              ))}
            </select>
          ) : (
            <p className="text-muted-foreground text-sm">{t("emptyHistory")}</p>
          )}
          {truncated ? <p className="text-muted-foreground text-xs">{t("historyTruncated")}</p> : null}
        </div>
        {run ? (
          <div className="space-y-5 border-t pt-5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2" role="status">
                {active(run.status) ? <Spinner /> : null}
                <Badge variant={run.status === "completed" ? "default" : "secondary"}>
                  {t(`status.${run.status}`)}
                </Badge>
                <span className="text-muted-foreground text-xs">{new Date(run.updated_at).toLocaleString()}</span>
              </div>
              <Button variant="outline" size="sm" onClick={() => void exportRun()} disabled={exporting}>
                {exporting ? <Spinner /> : <DownloadIcon />}
                {t("export")}
              </Button>
            </div>
            {run.options.question ? <p className="whitespace-pre-wrap text-sm">{run.options.question}</p> : null}
            {usage ? (
              <div className="space-y-1 text-muted-foreground text-xs">
                <p>{t("usage", { models: usage.model_calls ?? 0, queries: usage.queries ?? 0 })}</p>
                <p>{t("tokens", { input: usage.input_tokens ?? 0, output: usage.output_tokens ?? 0 })}</p>
              </div>
            ) : null}
            {run.error ? (
              <Alert variant="destructive">
                <AlertDescription>{run.error}</AlertDescription>
              </Alert>
            ) : null}
            {partial ? (
              <Alert>
                <AlertDescription>{t("partial")}</AlertDescription>
              </Alert>
            ) : null}
            {intents.length ? (
              <div className="space-y-3">
                <h3 className="font-medium text-sm">{t("plan")}</h3>
                {intents.map((item) => (
                  <div key={item.id} className="space-y-2 rounded-lg border p-4 text-sm">
                    <p className="font-medium">{item.hypothesis}</p>
                    <p>{item.objective}</p>
                    <p className="text-muted-foreground">{item.reason}</p>
                    <Citations refs={item.evidence_refs} evidence={evidence} onSelect={selectEvidence} />
                  </div>
                ))}
              </div>
            ) : null}
            <details className="rounded-lg border p-4" open={active(run.status)}>
              <summary className="cursor-pointer font-medium text-sm">{t("progress")}</summary>
              {!trace.length ? (
                <p className="mt-3 text-muted-foreground text-sm">{t(active(run.status) ? "waiting" : "noProgress")}</p>
              ) : null}
              <ol className="mt-3 space-y-3">
                {trace.map((item) => (
                  <li key={item.sequence} className="space-y-2 border-sky-500/30 border-l-2 pl-3">
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <Badge variant="outline">{t(stageLabel(item.stage))}</Badge>
                      <span className="text-muted-foreground">{new Date(item.created_at).toLocaleTimeString()}</span>
                    </div>
                    <p
                      className={`whitespace-pre-wrap text-sm leading-relaxed ${item.is_error ? "text-destructive" : ""}`}
                    >
                      {item.summary}
                    </p>
                    <Citations
                      refs={
                        item.evidence_refs ??
                        item.observation?.evidence_refs ??
                        item.decision?.evidence_refs ??
                        item.intent?.evidence_refs
                      }
                      evidence={evidence}
                      onSelect={selectEvidence}
                    />
                    {item.detail ? (
                      <details>
                        <summary className="cursor-pointer text-muted-foreground text-xs">{t("stepDetails")}</summary>
                        <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
                          {item.detail}
                        </pre>
                      </details>
                    ) : null}
                  </li>
                ))}
              </ol>
            </details>
            {run.result || observations.length ? (
              <div className="space-y-4">
                <h3 className="font-medium">{t("result")}</h3>
                {run.result?.summary ? (
                  <p className="whitespace-pre-wrap text-sm leading-relaxed">{run.result.summary}</p>
                ) : null}
                <p className="text-muted-foreground text-xs leading-relaxed">{t("assessmentBoundary")}</p>
                <div className="space-y-3">
                  {(["observed", "inferred", "insufficient_data"] as const).map((kind) => (
                    <ObservationGroup
                      key={kind}
                      kind={kind}
                      observations={observations}
                      evidence={evidence}
                      onSelect={selectEvidence}
                    />
                  ))}
                </div>
                {run.result?.gaps?.length ? (
                  <div className="space-y-2">
                    <h4 className="font-medium text-sm">{t("neededLogs")}</h4>
                    <StringList items={run.result.gaps} />
                  </div>
                ) : null}
                {run.result?.next_steps?.length ? (
                  <div className="space-y-2">
                    <h4 className="font-medium text-sm">{t("nextSteps")}</h4>
                    <StringList items={run.result.next_steps} />
                  </div>
                ) : null}
              </div>
            ) : null}
            {searches.length ? (
              <details className="rounded-lg border p-4">
                <summary className="cursor-pointer font-medium text-sm">{t("queries")}</summary>
                <div className="mt-3 space-y-3">
                  {searches.map((search) => (
                    <div key={JSON.stringify(search)} className="space-y-2 rounded-md bg-muted/40 p-3 text-xs">
                      <Badge variant="outline">{t(search.remote ? "remoteQuery" : "localQuery")}</Badge>
                      <p className="break-all">
                        {search.scope.target}
                        {search.scope.path_prefix}
                      </p>
                      <p className="text-muted-foreground">
                        {new Date(search.scope.start).toLocaleString()} → {new Date(search.scope.end).toLocaleString()}
                      </p>
                      {search.source_ip ? (
                        <p>
                          {t("sourceIP")}: {search.source_ip}
                        </p>
                      ) : null}
                      {search.user ? (
                        <p>
                          {t("account")}: {search.user}
                        </p>
                      ) : null}
                      {search.session ? (
                        <p>
                          {t("session")}: {search.session}
                        </p>
                      ) : null}
                      {search.path_contains ? (
                        <p>
                          {t("pathContains")}: {search.path_contains}
                        </p>
                      ) : null}
                      {search.event_kind ? (
                        <p>
                          {t("eventKind")}: {search.event_kind}
                        </p>
                      ) : null}
                      {search.offset ? <p>{t("offset", { n: search.offset })}</p> : null}
                    </div>
                  ))}
                </div>
              </details>
            ) : null}
            {selectedEvidence ? (
              <div ref={evidenceRef} className="scroll-mt-28 space-y-3 rounded-lg border border-sky-500/40 p-4">
                <div className="flex items-start justify-between gap-3">
                  <h4 className="font-medium text-sm">
                    {t("evidence")}: {selectedEvidence.event.file_name} ·{" "}
                    {t("line", { n: selectedEvidence.event.line })}
                  </h4>
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setSelectedEvidence(null)}
                    aria-label={t("closeEvidence")}
                  >
                    <XIcon />
                  </Button>
                </div>
                <p className="break-all text-muted-foreground text-xs">
                  {selectedEvidence.event.ref} · {new Date(selectedEvidence.event.timestamp).toLocaleString()}
                </p>
                {selectedEvidence.event.known_artex ? <Badge variant="secondary">{t("knownARTEX")}</Badge> : null}
                <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
                  {selectedEvidence.event.raw || t("noRaw")}
                </pre>
                {selectedEvidence.query ? (
                  <div className="space-y-2">
                    <p className="font-medium text-xs">{t("sourceQuery")}</p>
                    <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
                      {selectedEvidence.query}
                    </pre>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
