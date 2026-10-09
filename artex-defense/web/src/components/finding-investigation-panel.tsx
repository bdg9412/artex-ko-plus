"use client";

import * as React from "react";

import Link from "next/link";

import {
  ArrowUpRightIcon,
  DownloadIcon,
  FileSearchIcon,
  RefreshCwIcon,
  SearchIcon,
  UploadIcon,
  XIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { FindingInvestigationAgentPanel } from "@/components/finding-investigation-agent-panel";
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
  DEFAULT_INVESTIGATION_MAPPING,
  type FindingInvestigations,
  type InvestigationEvent,
  type InvestigationInput,
  type InvestigationMapping,
  type InvestigationPlan,
  type InvestigationPreview,
  type InvestigationRecord,
  investigationApi,
} from "@/lib/investigation-api";
import { downloadSecurityJSON, type SecuritySource, securityApi } from "@/lib/security-api";

const MAX_BYTES = 8 * 1024 * 1024;
const PAGE_SIZE = 25;
const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-background px-3 text-sm disabled:opacity-50";
type LoadedFile = { name: string; content: string; bytes: number };

function localTime(time: number) {
  const date = new Date(time);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
}

function TextList({ items }: { items: string[] | null | undefined }) {
  if (!items?.length) return null;
  return (
    <ul className="list-disc space-y-1 pl-5 text-sm leading-relaxed">
      {items.map((item) => (
        <li key={item}>{item}</li>
      ))}
    </ul>
  );
}

function PlanView({ plan }: { plan: InvestigationPlan }) {
  const t = useTranslations("investigation");
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="secondary">{t("curatedPlan")}</Badge>
        <span className="text-muted-foreground text-xs">{t("planBoundary")}</span>
      </div>
      <p className="text-sm leading-relaxed">{plan.summary}</p>
      <div className="space-y-2">
        {(plan.hypotheses ?? []).map((hypothesis, index) => (
          <details key={hypothesis.id} className="rounded-lg border p-4" open={index === 0}>
            <summary className="cursor-pointer font-medium text-sm">{hypothesis.title}</summary>
            <div className="mt-3 space-y-3">
              <p className="text-sm leading-relaxed">{hypothesis.statement}</p>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-1">
                  <h4 className="font-medium text-muted-foreground text-xs">{t("preconditions")}</h4>
                  <TextList items={hypothesis.preconditions} />
                </div>
                <div className="space-y-1">
                  <h4 className="font-medium text-muted-foreground text-xs">{t("requiredLogs")}</h4>
                  <TextList items={hypothesis.required_logs} />
                </div>
              </div>
              <p className="text-muted-foreground text-xs">
                {t("requiredFields")}: {(hypothesis.required_fields ?? []).join(", ")}
              </p>
              <div className="rounded-md bg-muted/50 p-3 text-sm">
                <span className="font-medium">{t("hunt")}</span>
                <p className="mt-1 whitespace-pre-wrap leading-relaxed">{hypothesis.hunt}</p>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-1">
                  <h4 className="font-medium text-muted-foreground text-xs">{t("benignAlternatives")}</h4>
                  <TextList items={hypothesis.benign_alternatives} />
                </div>
                <div className="space-y-1">
                  <h4 className="font-medium text-muted-foreground text-xs">{t("nextSteps")}</h4>
                  <TextList items={hypothesis.next_steps} />
                </div>
              </div>
              {hypothesis.references?.length ? (
                <div className="flex flex-wrap gap-3 text-xs">
                  {hypothesis.references
                    .filter((ref) => /^https:\/\//.test(ref.url))
                    .map((ref) => (
                      <a
                        key={ref.url}
                        href={ref.url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 underline underline-offset-2"
                      >
                        {ref.title}
                        <ArrowUpRightIcon className="size-3" />
                      </a>
                    ))}
                </div>
              ) : null}
            </div>
          </details>
        ))}
      </div>
      <TextList items={plan.limitations} />
    </div>
  );
}

function EvidenceButtons({
  refs,
  events,
  onSelect,
}: {
  refs: string[] | null | undefined;
  events: Map<string, InvestigationEvent>;
  onSelect: (event: InvestigationEvent) => void;
}) {
  const t = useTranslations("investigation");
  const allRefs = refs ?? [];
  const visible = allRefs.slice(0, 10);
  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {visible.map((ref) => {
        const event = events.get(ref);
        return event ? (
          <Button
            key={ref}
            size="sm"
            variant="outline"
            className="h-auto max-w-full py-1 text-xs"
            onClick={() => onSelect(event)}
          >
            <span className="truncate">
              {event.file_name} · {t("line", { n: event.line })}
            </span>
          </Button>
        ) : (
          <code key={ref} className="break-all text-muted-foreground text-xs">
            {ref}
          </code>
        );
      })}
      {allRefs.length > visible.length ? (
        <span className="self-center text-muted-foreground text-xs">
          {t("moreRefs", { n: allRefs.length - visible.length })}
        </span>
      ) : null}
    </div>
  );
}

function InvestigationResult({
  record,
  exporting,
  onExport,
}: {
  record: InvestigationRecord;
  exporting: boolean;
  onExport: () => void;
}) {
  const t = useTranslations("investigation");
  const [page, setPage] = React.useState(0);
  const [includeARTEX, setIncludeARTEX] = React.useState(true);
  const [selectedEvidence, setSelectedEvidence] = React.useState<InvestigationEvent | null>(null);
  const events = React.useMemo(
    () => new Map((record.collection.events ?? []).map((event) => [event.ref, event])),
    [record.collection.events],
  );
  const timeline = (record.analysis.timeline ?? []).filter((event) => includeARTEX || !event.known_artex);
  const pages = Math.max(1, Math.ceil(timeline.length / PAGE_SIZE));
  const activePage = Math.min(page, pages - 1);
  const evidenceRef = React.useRef<HTMLDivElement>(null);
  const selectEvidence = (event: InvestigationEvent) => {
    setSelectedEvidence(event);
    requestAnimationFrame(() => evidenceRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" }));
  };
  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="space-y-1.5">
          <CardTitle>{record.title || t("resultTitle")}</CardTitle>
          <CardDescription>
            {new Date(record.created_at).toLocaleString()} ·{" "}
            {t(record.source_kind === "splunk" ? "splunkSource" : "fileSource")}
          </CardDescription>
        </div>
        <Button size="sm" variant="outline" onClick={onExport} disabled={exporting}>
          {exporting ? <Spinner /> : <DownloadIcon />}
          {t("export")}
        </Button>
      </CardHeader>
      <CardContent className="space-y-5">
        {record.state === "stale" ? (
          <Alert>
            <AlertDescription>{t("stale")}</AlertDescription>
          </Alert>
        ) : null}
        <div className="rounded-lg border border-sky-500/30 bg-sky-500/5 p-4">
          <p className="font-medium text-sm leading-relaxed">{record.analysis.summary}</p>
          <p className="mt-2 text-muted-foreground text-xs">{t("resultBoundary")}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            <Badge variant="outline">{t("observedCount", { n: record.analysis.observed_count })}</Badge>
            <Badge variant="secondary">{t("artexCount", { n: record.analysis.known_artex_count })}</Badge>
            <Badge variant="outline">{t(record.collection.complete ? "coverageComplete" : "coverageIncomplete")}</Badge>
          </div>
        </div>
        <div className="space-y-2 text-sm">
          <p className="break-all">
            <span className="text-muted-foreground">{t("scope")}: </span>
            {record.scope.target}
            {record.scope.path_prefix}
          </p>
          <p className="text-muted-foreground">
            {new Date(record.scope.start).toLocaleString()} → {new Date(record.scope.end).toLocaleString()}
          </p>
          {record.question ? <p>{record.question}</p> : null}
        </div>
        <section className="space-y-3">
          <h3 className="font-semibold text-sm">{t("hypothesisResults")}</h3>
          {(record.analysis.hypotheses ?? []).map((result) => (
            <div key={result.hypothesis_id} className="space-y-2 rounded-lg border p-4">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant={result.status === "suspicious" ? "destructive" : "secondary"}>
                  {t(`resultStatus.${result.status}`)}
                </Badge>
                <h4 className="font-medium text-sm">
                  {record.plan.hypotheses?.find((hypothesis) => hypothesis.id === result.hypothesis_id)?.title ??
                    result.hypothesis_id}
                </h4>
              </div>
              <p className="text-sm leading-relaxed">{result.summary}</p>
              <EvidenceButtons refs={result.evidence_refs} events={events} onSelect={selectEvidence} />
              <TextList items={result.next_steps} />
            </div>
          ))}
        </section>
        {record.analysis.signals?.length ? (
          <section className="space-y-2">
            <h3 className="font-semibold text-sm">{t("signals")}</h3>
            {record.analysis.signals.map((signal) => (
              <div key={`${signal.kind}:${signal.key}`} className="rounded-lg border p-3">
                <p className="text-sm leading-relaxed">{signal.summary}</p>
                <EvidenceButtons refs={signal.evidence_refs} events={events} onSelect={selectEvidence} />
              </div>
            ))}
          </section>
        ) : null}
        <section className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h3 className="font-semibold text-sm">{t("timeline")}</h3>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={includeARTEX}
                onChange={(event) => {
                  setIncludeARTEX(event.target.checked);
                  setPage(0);
                }}
              />
              {t("includeARTEX")}
            </label>
          </div>
          {timeline.length === 0 ? (
            <p className="rounded-md bg-muted/40 p-4 text-muted-foreground text-sm">{t("emptyTimeline")}</p>
          ) : (
            <div className="space-y-2">
              {timeline.slice(activePage * PAGE_SIZE, (activePage + 1) * PAGE_SIZE).map((entry) => (
                <div key={entry.evidence_ref} className="grid gap-2 rounded-md border p-3 md:grid-cols-[160px_1fr]">
                  <div className="space-y-1">
                    <time className="text-muted-foreground text-xs">{new Date(entry.timestamp).toLocaleString()}</time>
                    {entry.known_artex ? (
                      <Badge variant="secondary" className="block w-fit">
                        {t("knownARTEX")}
                      </Badge>
                    ) : null}
                  </div>
                  <div>
                    <p className="text-sm leading-relaxed">{entry.summary}</p>
                    <EvidenceButtons refs={[entry.evidence_ref]} events={events} onSelect={selectEvidence} />
                  </div>
                </div>
              ))}
            </div>
          )}
          {pages > 1 ? (
            <div className="flex items-center justify-end gap-3">
              <span className="text-muted-foreground text-xs">
                {t("page", { page: activePage + 1, pages, count: timeline.length })}
              </span>
              <Button size="sm" variant="outline" disabled={activePage === 0} onClick={() => setPage(activePage - 1)}>
                {t("previous")}
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={activePage + 1 >= pages}
                onClick={() => setPage(activePage + 1)}
              >
                {t("next")}
              </Button>
            </div>
          ) : null}
        </section>
        <div ref={evidenceRef}>
          {selectedEvidence ? (
            <div className="space-y-3 rounded-lg border border-sky-500/40 p-4">
              <div className="flex items-center justify-between gap-2">
                <h3 className="font-semibold text-sm">{t("originalEvidence")}</h3>
                <Button
                  size="icon"
                  variant="ghost"
                  aria-label={t("closeEvidence")}
                  onClick={() => setSelectedEvidence(null)}
                >
                  <XIcon />
                </Button>
              </div>
              <p className="break-all text-xs">
                {selectedEvidence.file_name} · {t("line", { n: selectedEvidence.line })} · {t("eventID")}:{" "}
                {selectedEvidence.id}
              </p>
              <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
                {selectedEvidence.raw ?? JSON.stringify(selectedEvidence, null, 2)}
              </pre>
            </div>
          ) : null}
        </div>
        <section className="space-y-2">
          <h3 className="font-semibold text-sm">{t("gaps")}</h3>
          <TextList
            items={Array.from(new Set([...(record.collection.warnings ?? []), ...(record.analysis.limitations ?? [])]))}
          />
          <p className="text-muted-foreground text-xs leading-relaxed">{t("artexBoundary")}</p>
        </section>
        <section className="space-y-2">
          <h3 className="font-semibold text-sm">{t("nextSteps")}</h3>
          <TextList items={record.analysis.next_steps} />
        </section>
        <details className="rounded-lg border p-4">
          <summary className="cursor-pointer font-medium text-sm">{t("provenance")}</summary>
          <div className="mt-3 space-y-3">
            <p className="text-muted-foreground text-xs">
              {t("collectionStats", {
                total: record.collection.stats.total_rows,
                selected: record.collection.stats.selected,
                invalid: record.collection.stats.invalid_events,
                truncated: record.collection.stats.truncated,
              })}
            </p>
            <p className="text-muted-foreground text-xs">
              {t("scopeStats", {
                window: record.collection.stats.outside_window,
                target: record.collection.stats.unrelated_target,
                path: record.collection.stats.unrelated_path,
                missing: record.collection.stats.missing_target,
              })}
            </p>
            <p className="text-muted-foreground text-xs">
              {t("declarations", {
                coverage: t(record.collection.coverage_confirmed ? "confirmed" : "unconfirmed"),
                target: t(record.collection.target_scope_confirmed ? "confirmed" : "unconfirmed"),
              })}
            </p>
            {(record.collection.files ?? []).map((file) => (
              <div key={`${file.name}:${file.sha256}`} className="rounded-md bg-muted/40 p-3 text-xs">
                <p>
                  {file.name} · {t("fileStats", { bytes: file.bytes, rows: file.rows })}
                </p>
                <code className="mt-1 block break-all">SHA-256: {file.sha256}</code>
              </div>
            ))}
            {record.collection.query ? (
              <pre className="overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
                {record.collection.query}
              </pre>
            ) : null}
            <p className="text-muted-foreground text-xs">{t("exportHelp")}</p>
            <details>
              <summary className="cursor-pointer font-medium text-xs">{t("savedPlan")}</summary>
              <div className="mt-3">
                <PlanView plan={record.plan} />
              </div>
            </details>
          </div>
        </details>
      </CardContent>
    </Card>
  );
}

export function FindingInvestigationPanel({
  findingId,
  readOnly = false,
  onOpenDefense,
}: {
  findingId: string;
  readOnly?: boolean;
  onOpenDefense: () => void;
}) {
  const t = useTranslations("investigation");
  const ta = useTranslations("investigationAgent");
  const fieldId = React.useId();
  const [data, setData] = React.useState<FindingInvestigations | null>(null);
  const [sources, setSources] = React.useState<SecuritySource[]>([]);
  const [sourceError, setSourceError] = React.useState("");
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState<"load" | "read" | "preview" | "create" | "record" | null>("load");
  const [sourceKind, setSourceKind] = React.useState<"file" | "splunk">("file");
  const [sourceId, setSourceId] = React.useState("");
  const [sourcetypes, setSourcetypes] = React.useState("");
  const [title, setTitle] = React.useState("");
  const [question, setQuestion] = React.useState("");
  const [target, setTarget] = React.useState("");
  const [pathPrefix, setPathPrefix] = React.useState("");
  const [start, setStart] = React.useState(() => localTime(Date.now() - 7 * 86400000));
  const [end, setEnd] = React.useState(() => localTime(Date.now()));
  const [mapping, setMapping] = React.useState<InvestigationMapping>({ ...DEFAULT_INVESTIGATION_MAPPING });
  const [fileLabel, setFileLabel] = React.useState("");
  const [files, setFiles] = React.useState<LoadedFile[]>([]);
  const [coverageConfirmed, setCoverageConfirmed] = React.useState(false);
  const [targetScopeConfirmed, setTargetScopeConfirmed] = React.useState(false);
  const [preview, setPreview] = React.useState<{ key: string; result: InvestigationPreview } | null>(null);
  const [record, setRecord] = React.useState<InvestigationRecord | null>(null);
  const [pendingEvidence, setPendingEvidence] = React.useState(false);
  const [exporting, setExporting] = React.useState(false);
  const initialized = React.useRef(false);
  const requestSeq = React.useRef(0);
  const resultRef = React.useRef<HTMLDivElement>(null);
  const selectedSource = sources.find((source) => source.id === sourceId);
  const totalBytes = files.reduce((sum, file) => sum + file.bytes, 0);
  const previewKey = JSON.stringify({
    sourceId,
    sourceRevision: selectedSource?.revision,
    sourcetypes,
    target,
    pathPrefix,
    start,
    end,
    mapping,
  });
  const validPreview = preview?.key === previewKey ? preview.result : null;

  const load = React.useCallback(async () => {
    const seq = ++requestSeq.current;
    setBusy("load");
    setError("");
    const results = await Promise.allSettled([investigationApi.list(findingId), securityApi.sources()]);
    if (seq !== requestSeq.current) return;
    if (results[0].status === "fulfilled") {
      const loaded = results[0].value;
      setData(loaded);
      if (!initialized.current) {
        setTarget(loaded.targets?.[0] ?? "");
        setPathPrefix(loaded.recommended_path ?? "");
        if (loaded.mapping) setMapping(loaded.mapping);
        initialized.current = true;
        const latest = loaded.investigations?.[0];
        if (latest) {
          try {
            const saved = await investigationApi.get(findingId, latest.id);
            if (seq !== requestSeq.current) return;
            setRecord(saved);
          } catch (caught) {
            if (seq === requestSeq.current) setError((caught as Error).message);
          }
        }
      }
    } else setError((results[0].reason as Error).message);
    if (seq !== requestSeq.current) return;
    if (results[1].status === "fulfilled") {
      setSources(results[1].value.sources ?? []);
      setSourceError("");
    } else setSourceError((results[1].reason as Error).message);
    setBusy(null);
  }, [findingId]);

  React.useEffect(() => {
    void load();
    return () => {
      requestSeq.current++;
    };
  }, [load]);

  const buildInput = (): InvestigationInput | null => {
    if (!data) return null;
    const from = new Date(start);
    const until = new Date(end);
    if (
      !Number.isFinite(from.getTime()) ||
      !Number.isFinite(until.getTime()) ||
      until <= from ||
      from.getUTCFullYear() < 1970 ||
      until.getTime() > Date.now() ||
      until.getTime() - from.getTime() > 31 * 86400000
    ) {
      setError(t("invalidPeriod"));
      return null;
    }
    if (!target.trim()) {
      setError(t("targetRequired"));
      return null;
    }
    if (sourceKind === "splunk" && (!selectedSource?.enabled || !selectedSource.credential_set)) {
      setError(t("sourceRequired"));
      return null;
    }
    return {
      title: title.trim(),
      question: question.trim(),
      scope: {
        target: target.trim(),
        path_prefix: pathPrefix.trim(),
        start: from.toISOString(),
        end: until.toISOString(),
      },
      mapping,
      source_kind: sourceKind,
      file_label: fileLabel.trim(),
      files: sourceKind === "file" ? files.map(({ name, content }) => ({ name, content })) : [],
      source_id: sourceKind === "splunk" ? sourceId : "0",
      expected_source_revision: sourceKind === "splunk" ? (selectedSource?.revision ?? 0) : 0,
      sourcetypes:
        sourceKind === "splunk"
          ? sourcetypes
              .split(/[,\n]/)
              .map((value) => value.trim())
              .filter(Boolean)
          : [],
      coverage_confirmed: sourceKind === "file" && coverageConfirmed,
      target_scope_confirmed: sourceKind === "file" && targetScopeConfirmed,
      expected_evidence_version: data.evidence_version,
      expected_source_fingerprint: data.source_fingerprint,
    };
  };

  const handleError = async (caught: unknown) => {
    if (caught instanceof HttpError && caught.status === 409) {
      setPreview(null);
      await load();
      setError(t("conflict"));
    } else setError((caught as Error).message);
  };

  const readFiles = async (chosen: FileList | null) => {
    if (!chosen?.length) return;
    const additions = Array.from(chosen);
    if (additions.reduce((sum, file) => sum + file.size, totalBytes) > MAX_BYTES) {
      setError(t("tooLarge"));
      return;
    }
    if (
      new Set([...files.map((file) => file.name), ...additions.map((file) => file.name)]).size !==
      files.length + additions.length
    ) {
      setError(t("duplicateFile"));
      return;
    }
    setBusy("read");
    setError("");
    try {
      const loaded = await Promise.all(
        additions.map(async (file) => ({
          name: file.name,
          bytes: file.size,
          content: new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(await file.arrayBuffer()),
        })),
      );
      setFiles((current) => [...current, ...loaded]);
      setCoverageConfirmed(false);
      setTargetScopeConfirmed(false);
    } catch {
      setError(t("fileError"));
    } finally {
      setBusy(null);
    }
  };

  const previewQuery = async () => {
    if (busy || readOnly) return;
    setError("");
    const input = buildInput();
    if (!input) return;
    setBusy("preview");
    setPreview(null);
    try {
      setPreview({ key: previewKey, result: await investigationApi.preview(findingId, input) });
    } catch (caught) {
      await handleError(caught);
    } finally {
      setBusy(null);
    }
  };

  const create = async () => {
    if (busy || readOnly) return;
    setError("");
    const input = buildInput();
    if (!input) return;
    if (sourceKind === "file" && (!files.length || !fileLabel.trim())) {
      setError(t("fileRequired"));
      return;
    }
    if (sourceKind === "splunk" && !validPreview) {
      setError(t("previewRequired"));
      return;
    }
    if (validPreview && sourceKind === "splunk") input.expected_source_revision = validPreview.source_revision;
    setBusy("create");
    try {
      const saved = await investigationApi.create(findingId, input);
      setRecord(saved);
      setPendingEvidence(false);
      toast.success(t("saved"));
      try {
        setData(await investigationApi.list(findingId));
      } catch {
        setError(t("historyRefreshError"));
      }
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch (caught) {
      await handleError(caught);
    } finally {
      setBusy(null);
    }
  };

  const openRecord = async (id: string) => {
    setBusy("record");
    setError("");
    try {
      setRecord(await investigationApi.get(findingId, id));
      setPendingEvidence(false);
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setBusy(null);
    }
  };

  const exportRecord = async () => {
    if (!record || exporting) return;
    setExporting(true);
    try {
      downloadSecurityJSON(
        await investigationApi.export(findingId, record.id),
        `artex-investigation-${record.id}.json`,
      );
    } catch (caught) {
      setError((caught as Error).message);
    } finally {
      setExporting(false);
    }
  };

  const changeMode = (next: "file" | "splunk") => {
    setSourceKind(next);
    setPreview(null);
    setCoverageConfirmed(false);
    setTargetScopeConfirmed(false);
    setMapping(
      next === "splunk"
        ? { ...DEFAULT_INVESTIGATION_MAPPING, timestamp: "_time", event_id: "_cd", target: "host" }
        : { ...DEFAULT_INVESTIGATION_MAPPING },
    );
  };

  return (
    <div className="mx-auto flex w-full max-w-5xl flex-col gap-5">
      <Card>
        <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <FileSearchIcon className="size-5 text-sky-500" />
              {t("title")}
            </CardTitle>
            <CardDescription>{t("description")}</CardDescription>
          </div>
          <Button variant="outline" size="sm" disabled={!!busy} onClick={() => void load()}>
            <RefreshCwIcon className={busy === "load" ? "animate-spin" : undefined} />
            {t("refresh")}
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sky-700 text-sm dark:text-sky-300">{ta("workflow")}</p>
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
          {!data && busy ? <Skeleton className="h-32 w-full" /> : null}
          {data ? (
            <details>
              <summary className="cursor-pointer font-medium text-sm">{ta("initialGuidance")}</summary>
              <div className="mt-4">
                <PlanView plan={data.plan} />
              </div>
            </details>
          ) : null}
          {!record ? <p className="text-muted-foreground text-sm">{ta("prepareHint")}</p> : null}
        </CardContent>
      </Card>
      {data ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("newInvestigation")}</CardTitle>
            <CardDescription>{t("newDescription")}</CardDescription>
          </CardHeader>
          <CardContent>
            <fieldset
              disabled={!!busy || readOnly}
              onChangeCapture={() => setPendingEvidence(true)}
              className="space-y-5 disabled:opacity-70"
            >
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-title`}>{t("caseTitle")}</Label>
                  <Input
                    id={`${fieldId}-title`}
                    value={title}
                    onChange={(event) => setTitle(event.target.value)}
                    maxLength={200}
                    placeholder={t("titlePlaceholder")}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-mode`}>{t("source")}</Label>
                  <select
                    id={`${fieldId}-mode`}
                    className={SELECT_CLASS}
                    value={sourceKind}
                    onChange={(event) => changeMode(event.target.value as "file" | "splunk")}
                  >
                    <option value="file">{t("fileSource")}</option>
                    <option value="splunk">{t("splunkSource")}</option>
                  </select>
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor={`${fieldId}-question`}>{t("question")}</Label>
                <Textarea
                  id={`${fieldId}-question`}
                  value={question}
                  onChange={(event) => setQuestion(event.target.value)}
                  maxLength={4000}
                  rows={2}
                  placeholder={t("questionPlaceholder")}
                />
                <p className="text-muted-foreground text-xs">{t("questionHelp")}</p>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-target`}>{t("target")}</Label>
                  <Input
                    id={`${fieldId}-target`}
                    list={`${fieldId}-targets`}
                    value={target}
                    onChange={(event) => {
                      setTarget(event.target.value);
                      setTargetScopeConfirmed(false);
                      setCoverageConfirmed(false);
                    }}
                    placeholder={t("targetPlaceholder")}
                  />
                  <datalist id={`${fieldId}-targets`}>
                    {data.targets?.map((value) => (
                      <option key={value} value={value} />
                    ))}
                  </datalist>
                  <p className="text-muted-foreground text-xs">{t("targetHelp")}</p>
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-path`}>{t("pathPrefix")}</Label>
                  <Input
                    id={`${fieldId}-path`}
                    value={pathPrefix}
                    onChange={(event) => {
                      setPathPrefix(event.target.value);
                      setCoverageConfirmed(false);
                    }}
                    placeholder="/ftp"
                  />
                  <p className="text-muted-foreground text-xs">{t("pathHelp")}</p>
                </div>
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-start`}>{t("start")}</Label>
                  <Input
                    id={`${fieldId}-start`}
                    type="datetime-local"
                    step="1"
                    value={start}
                    onChange={(event) => {
                      setStart(event.target.value);
                      setCoverageConfirmed(false);
                    }}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${fieldId}-end`}>{t("end")}</Label>
                  <Input
                    id={`${fieldId}-end`}
                    type="datetime-local"
                    step="1"
                    value={end}
                    onChange={(event) => {
                      setEnd(event.target.value);
                      setCoverageConfirmed(false);
                    }}
                  />
                </div>
              </div>
              <p className="text-muted-foreground text-xs">{t("timeHelp")}</p>
              {sourceKind === "file" ? (
                <div className="space-y-4 rounded-lg border p-4">
                  <div className="space-y-2">
                    <Label htmlFor={`${fieldId}-label`}>{t("fileLabel")}</Label>
                    <Input
                      id={`${fieldId}-label`}
                      value={fileLabel}
                      onChange={(event) => setFileLabel(event.target.value)}
                      maxLength={120}
                      placeholder={t("fileLabelPlaceholder")}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor={`${fieldId}-files`}>{t("files")}</Label>
                    <Input
                      id={`${fieldId}-files`}
                      type="file"
                      multiple
                      accept=".json,.jsonl,.ndjson,.csv,application/json,text/csv"
                      onChange={(event) => {
                        void readFiles(event.target.files);
                        event.target.value = "";
                      }}
                    />
                    <p className="text-muted-foreground text-xs leading-relaxed">
                      {t("fileLimits", { n: Math.ceil(totalBytes / 1024) })}
                    </p>
                  </div>
                  {files.length ? (
                    <div className="space-y-2">
                      {files.map((file) => (
                        <div
                          key={file.name}
                          className="flex items-center justify-between gap-2 rounded-md bg-muted/50 px-3 py-2"
                        >
                          <span className="min-w-0 truncate text-sm">
                            {file.name}{" "}
                            <span className="text-muted-foreground text-xs">({Math.ceil(file.bytes / 1024)} KiB)</span>
                          </span>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            aria-label={t("removeFile", { name: file.name })}
                            onClick={() => {
                              setPendingEvidence(true);
                              setFiles((current) => current.filter((item) => item.name !== file.name));
                              setCoverageConfirmed(false);
                              setTargetScopeConfirmed(false);
                            }}
                          >
                            <XIcon />
                          </Button>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  <label className="flex items-start gap-2 text-sm leading-relaxed">
                    <input
                      type="checkbox"
                      className="mt-1"
                      checked={coverageConfirmed}
                      onChange={(event) => setCoverageConfirmed(event.target.checked)}
                    />
                    <span>{t("confirmCoverage")}</span>
                  </label>
                  <label className="flex items-start gap-2 text-sm leading-relaxed">
                    <input
                      type="checkbox"
                      className="mt-1"
                      checked={targetScopeConfirmed}
                      onChange={(event) => setTargetScopeConfirmed(event.target.checked)}
                    />
                    <span>{t("confirmTarget")}</span>
                  </label>
                  <p className="text-muted-foreground text-xs leading-relaxed">{t("attestationHelp")}</p>
                </div>
              ) : (
                <div className="space-y-4 rounded-lg border p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <Label htmlFor={`${fieldId}-splunk`}>{t("splunkConnection")}</Label>
                    <Link
                      href="/function/purple/sources/"
                      className="inline-flex items-center gap-1 text-xs underline underline-offset-2"
                    >
                      {t("manageSources")}
                      <ArrowUpRightIcon className="size-3" />
                    </Link>
                  </div>
                  {sourceError ? (
                    <Alert variant="destructive">
                      <AlertDescription>{sourceError}</AlertDescription>
                    </Alert>
                  ) : null}
                  <select
                    id={`${fieldId}-splunk`}
                    className={SELECT_CLASS}
                    value={sourceId}
                    onChange={(event) => {
                      const id = event.target.value;
                      setSourceId(id);
                      const source = sources.find((item) => item.id === id);
                      setSourcetypes(
                        Array.from(
                          new Set([source?.config.audit_sourcetype, source?.config.alert_sourcetype].filter(Boolean)),
                        ).join(", "),
                      );
                    }}
                  >
                    <option value="">{t("chooseSource")}</option>
                    {sources.map((source) => (
                      <option key={source.id} value={source.id} disabled={!source.enabled || !source.credential_set}>
                        {source.name}
                        {!source.enabled || !source.credential_set ? ` · ${t("unavailableSource")}` : ""}
                      </option>
                    ))}
                  </select>
                  {!sources.length ? <p className="text-muted-foreground text-sm">{t("noSources")}</p> : null}
                  <div className="space-y-2">
                    <Label htmlFor={`${fieldId}-sourcetypes`}>{t("sourcetypes")}</Label>
                    <Input
                      id={`${fieldId}-sourcetypes`}
                      value={sourcetypes}
                      onChange={(event) => setSourcetypes(event.target.value)}
                    />
                    <p className="text-muted-foreground text-xs">{t("sourcetypesHelp")}</p>
                  </div>
                  <p className="text-muted-foreground text-xs leading-relaxed">{t("splunkHelp")}</p>
                </div>
              )}
              <details className="rounded-lg border p-4">
                <summary className="cursor-pointer font-medium text-sm">{t("mapping")}</summary>
                <p className="mt-3 text-muted-foreground text-xs leading-relaxed">{t("mappingHelp")}</p>
                <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                  {(Object.keys(mapping) as (keyof InvestigationMapping)[]).map((key) => (
                    <div key={key} className="space-y-1.5">
                      <Label htmlFor={`${fieldId}-map-${key}`}>{t(`fields.${key}`)}</Label>
                      <Input
                        id={`${fieldId}-map-${key}`}
                        value={mapping[key]}
                        onChange={(event) => {
                          setMapping((current) => ({ ...current, [key]: event.target.value }));
                          setCoverageConfirmed(false);
                          setTargetScopeConfirmed(false);
                        }}
                        maxLength={128}
                      />
                    </div>
                  ))}
                </div>
                <p className="mt-3 text-muted-foreground text-xs leading-relaxed">{t("actionHelp")}</p>
              </details>
              {sourceKind === "splunk" ? (
                <div className="space-y-3">
                  <Button
                    type="button"
                    variant="outline"
                    onClick={() => void previewQuery()}
                    disabled={!selectedSource?.enabled || !selectedSource.credential_set}
                  >
                    {busy === "preview" ? <Spinner /> : <SearchIcon />}
                    {t("preview")}
                  </Button>
                  {validPreview ? (
                    <div className="space-y-2 rounded-lg border border-sky-500/30 p-4">
                      <p className="font-medium text-xs">{t("previewReady")}</p>
                      <pre className="overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-xs">
                        {validPreview.query}
                      </pre>
                      <p className="text-muted-foreground text-xs">
                        {t("previewHelp", { revision: validPreview.source_revision })}
                      </p>
                    </div>
                  ) : (
                    <p className="text-muted-foreground text-xs">{t("previewRequired")}</p>
                  )}
                </div>
              ) : null}
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  type="button"
                  onClick={() => void create()}
                  disabled={sourceKind === "file" ? !files.length || !fileLabel.trim() : !validPreview}
                >
                  {busy === "create" ? <Spinner /> : <UploadIcon />}
                  {t(sourceKind === "file" ? "analyzeFile" : "analyzeSplunk")}
                </Button>
                <p className="text-muted-foreground text-xs">{t("privacy")}</p>
              </div>
            </fieldset>
            {busy === "create" ? (
              <p role="status" className="mt-4 flex items-center gap-2 text-muted-foreground text-sm">
                <Spinner />
                {t(sourceKind === "splunk" ? "searching" : "analyzing")}
              </p>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
      {record ? (
        <div ref={resultRef} className="scroll-mt-28">
          <FindingInvestigationAgentPanel
            key={`agent-${record.id}`}
            findingId={findingId}
            record={record}
            readOnly={readOnly}
            pendingEvidence={pendingEvidence}
          />
        </div>
      ) : null}
      <div className="space-y-3">
        {record ? (
          <>
            <InvestigationResult
              key={record.id}
              record={record}
              exporting={exporting}
              onExport={() => void exportRecord()}
            />
            <div className="flex flex-wrap items-center gap-3 rounded-lg border p-4">
              <Button variant="outline" onClick={onOpenDefense}>
                {t("openDefense")}
                <ArrowUpRightIcon />
              </Button>
              <p className="text-muted-foreground text-xs">{t("defenseHelp")}</p>
            </div>
          </>
        ) : null}
      </div>
      {data ? (
        <Card>
          <CardHeader>
            <CardTitle>{t("history")}</CardTitle>
            <CardDescription>{t("historyHelp")}</CardDescription>
          </CardHeader>
          <CardContent>
            {data.history_truncated ? (
              <p className="mb-3 text-muted-foreground text-xs">{t("historyTruncated")}</p>
            ) : null}
            {data.investigations?.length ? (
              <div className="space-y-2">
                {data.investigations.map((item) => (
                  <button
                    type="button"
                    key={item.id}
                    disabled={!!busy}
                    onClick={() => void openRecord(item.id)}
                    className={`w-full space-y-2 rounded-lg border p-4 text-left transition-colors hover:bg-muted/50 disabled:opacity-50 ${record?.id === item.id ? "border-sky-500/50 bg-sky-500/5" : ""}`}
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium text-sm">{item.title || t("resultTitle")}</span>
                      <Badge variant="outline">
                        {t(item.source_kind === "splunk" ? "splunkSource" : "fileSource")}
                      </Badge>
                      {item.state === "stale" ? <Badge variant="secondary">{t("staleShort")}</Badge> : null}
                      <span className="text-muted-foreground text-xs">
                        {new Date(item.created_at).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-muted-foreground text-sm">{item.summary}</p>
                  </button>
                ))}
              </div>
            ) : (
              <p className="text-muted-foreground text-sm">{t("emptyHistory")}</p>
            )}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
