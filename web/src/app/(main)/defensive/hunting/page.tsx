"use client";

import * as React from "react";

import Link from "next/link";

import { ChevronDownIcon, DownloadIcon, PlayIcon, PlusIcon, RefreshCwIcon, SquareIcon } from "lucide-react";

import { HuntingProgress } from "@/components/hunting-progress";
import { HuntingResultView } from "@/components/hunting-result-view";
import { HuntingTrendExplorer } from "@/components/hunting-trend-explorer";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { HttpError } from "@/lib/api";
import {
  type HuntingRequest,
  type HuntingRun,
  type HuntingRunSummary,
  type HuntingTrendCollection,
  type HuntingTrendInventory,
  type HuntingTrendReport,
  huntingApi,
  huntingRunActive,
  huntingStatusLabel,
} from "@/lib/hunting-api";
import type { HuntingPhaseId } from "@/lib/hunting-progress";
import { DEFAULT_INVESTIGATION_MAPPING, type InvestigationMapping } from "@/lib/investigation-api";
import { investigationMappingForSource } from "@/lib/investigation-mapping";
import { downloadSecurityJSON, type SecuritySource, securityApi, securitySourceSourcetypes } from "@/lib/security-api";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-background px-3 text-sm disabled:opacity-50";
const FIELD_LABELS: Record<keyof InvestigationMapping, string> = {
  timestamp: "이벤트 시각",
  event_id: "원본 이벤트 ID",
  target: "실제 요청 대상 자산",
  path: "요청 경로",
  source_ip: "출발지 IP",
  user: "사용자·계정",
  session: "세션",
  action: "처리 조치",
  status: "응답·처리 상태",
  bytes: "전송 바이트",
  verification_id: "ARTEX 검증 ID",
  event_kind: "이벤트 종류",
  response_complete: "응답 완료 여부",
};

function localTime(time: number) {
  const date = new Date(time);
  return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 19);
}

function upsertRun(items: HuntingRunSummary[], run: HuntingRun): HuntingRunSummary[] {
  const summary: HuntingRunSummary = {
    id: run.id,
    status: run.status,
    term: run.request.term,
    request: run.request,
    error: run.error,
    created_at: run.created_at,
    updated_at: run.updated_at,
  };
  return [summary, ...items.filter((item) => item.id !== run.id)];
}

function mergeHistory(current: HuntingRunSummary[], loaded: HuntingRunSummary[]) {
  const merged = new Map(current.map((item) => [item.id, item]));
  for (const item of loaded) {
    const existing = merged.get(item.id);
    if (!existing || Date.parse(item.updated_at) >= Date.parse(existing.updated_at)) merged.set(item.id, item);
  }
  return [...merged.values()]
    .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at))
    .slice(0, 50);
}

function updateRunQuery(id: string) {
  const url = new URL(window.location.href);
  if (id) url.searchParams.set("run", id);
  else url.searchParams.delete("run");
  window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
}

export default function HuntingPage() {
  const fieldId = React.useId();
  const [sources, setSources] = React.useState<SecuritySource[]>([]);
  const [runs, setRuns] = React.useState<HuntingRunSummary[]>([]);
  const [trendReports, setTrendReports] = React.useState<HuntingTrendReport[]>([]);
  const [trendCollection, setTrendCollection] = React.useState<HuntingTrendCollection | null>(null);
  const [trendInventory, setTrendInventory] = React.useState<HuntingTrendInventory | null>(null);
  const [trendError, setTrendError] = React.useState("");
  const [trendStarting, setTrendStarting] = React.useState(false);
  const [view, setView] = React.useState<"trends" | "hunt">("trends");
  const [historyTruncated, setHistoryTruncated] = React.useState(false);
  const [sourceError, setSourceError] = React.useState("");
  const [historyError, setHistoryError] = React.useState("");
  const [error, setError] = React.useState("");
  const [detailError, setDetailError] = React.useState("");
  const [actionError, setActionError] = React.useState("");
  const [loading, setLoading] = React.useState(true);
  const [detailLoading, setDetailLoading] = React.useState(false);
  const [busy, setBusy] = React.useState<"start" | "cancel" | "export" | null>(null);
  const [term, setTerm] = React.useState("");
  const [researchURLs, setResearchURLs] = React.useState("");
  const [sourceId, setSourceId] = React.useState("");
  const [sourcetypes, setSourcetypes] = React.useState<string[]>([]);
  const [target, setTarget] = React.useState("");
  const [pathPrefix, setPathPrefix] = React.useState("");
  const [start, setStart] = React.useState(() => localTime(Date.now() - 86400000));
  const [end, setEnd] = React.useState(() => localTime(Date.now()));
  const [mapping, setMapping] = React.useState<InvestigationMapping>(() =>
    investigationMappingForSource({ ...DEFAULT_INVESTIGATION_MAPPING }, "file", "splunk"),
  );
  const [confirmedScope, setConfirmedScope] = React.useState<string | null>(null);
  const [selectedId, setSelectedId] = React.useState("");
  const [activePhase, setActivePhase] = React.useState<HuntingPhaseId>("research");
  const [run, setRun] = React.useState<HuntingRun | null>(null);
  const [refreshKey, setRefreshKey] = React.useState(0);
  const [formOpen, setFormOpen] = React.useState(true);
  const mounted = React.useRef(true);
  const metadataSeq = React.useRef(0);
  const detailEpoch = React.useRef(0);
  const selectedRef = React.useRef("");
  const initialSelection = React.useRef(false);
  const resultTabsRef = React.useRef<HTMLDivElement>(null);
  const resultTabsId = `${fieldId}-result-tabs`;
  const selectedSource = sources.find((source) => source.id === sourceId);
  const scopeKey = JSON.stringify({
    sourceId,
    revision: selectedSource?.revision,
    sourcetypes,
    target,
    pathPrefix,
    start,
    end,
    mapping,
  });
  const scopeConfirmed = confirmedScope === scopeKey;

  const loadTrends = React.useCallback(async () => {
    try {
      const response = await huntingApi.trends();
      if (!mounted.current) return;
      setTrendReports(response.reports ?? []);
      setTrendCollection(response.collection);
      setTrendInventory(response.inventory);
      setTrendError("");
    } catch (caught) {
      if (mounted.current) setTrendError((caught as Error).message);
    }
  }, []);

  const load = React.useCallback(async () => {
    const seq = ++metadataSeq.current;
    setLoading(true);
    const results = await Promise.allSettled([securityApi.sources(), huntingApi.list()]);
    if (!mounted.current || metadataSeq.current !== seq) return;
    if (results[0].status === "fulfilled") {
      setSources(results[0].value.sources ?? []);
      setSourceError("");
    } else setSourceError((results[0].reason as Error).message);
    if (results[1].status === "fulfilled") {
      const response = results[1].value;
      setRuns((current) => mergeHistory(current, response.hunts ?? []));
      setHistoryTruncated(response.history_truncated ?? false);
      setHistoryError("");
      if (!initialSelection.current) {
        initialSelection.current = true;
        const history = mergeHistory([], response.hunts ?? []);
        const requestedId = new URLSearchParams(window.location.search).get("run");
        const selected = history.find((item) => item.id === requestedId) ?? history[0];
        if (selected) {
          selectedRef.current = selected.id;
          setSelectedId(selected.id);
          setActivePhase("research");
          setFormOpen(false);
        }
      }
    } else setHistoryError((results[1].reason as Error).message);
    setLoading(false);
  }, []);

  React.useEffect(() => {
    mounted.current = true;
    if (new URLSearchParams(window.location.search).has("run")) setView("hunt");
    void load();
    void loadTrends();
    return () => {
      mounted.current = false;
      metadataSeq.current++;
    };
  }, [load, loadTrends]);

  React.useEffect(() => {
    if (!trendCollection?.busy) return;
    const timer = setTimeout(() => void loadTrends(), 3000);
    return () => clearTimeout(timer);
  }, [trendCollection, loadTrends]);

  React.useEffect(() => {
    const timer = setInterval(() => void loadTrends(), 30000);
    return () => clearInterval(timer);
  }, [loadTrends]);

  const collectTrends = async () => {
    if (trendStarting || trendCollection?.busy) return;
    setTrendStarting(true);
    setTrendError("");
    try {
      await huntingApi.collectTrends();
      await loadTrends();
    } catch (caught) {
      setTrendError((caught as Error).message);
      await loadTrends();
    } finally {
      if (mounted.current) setTrendStarting(false);
    }
  };

  // biome-ignore lint/correctness/useExhaustiveDependencies: refreshKey intentionally restarts polling on manual refresh or reselection.
  React.useEffect(() => {
    if (!selectedId) return;
    const epoch = ++detailEpoch.current;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
    setDetailLoading(true);
    setDetailError("");
    const poll = async () => {
      let retry = true;
      try {
        const current = await huntingApi.get(selectedId, controller.signal);
        if (disposed || epoch !== detailEpoch.current || selectedRef.current !== selectedId) return;
        setRun(current);
        setRuns((items) => upsertRun(items, current));
        setDetailError("");
        retry = huntingRunActive(current.status);
      } catch (caught) {
        if (disposed || epoch !== detailEpoch.current || controller.signal.aborted) return;
        setDetailError((caught as Error).message);
        retry = !(caught instanceof HttpError && [403, 404].includes(caught.status));
      } finally {
        if (!disposed && epoch === detailEpoch.current) {
          setDetailLoading(false);
          if (retry) timer = setTimeout(() => void poll(), 3000);
        }
      }
    };
    void poll();
    return () => {
      disposed = true;
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [selectedId, refreshKey]);

  const selectRun = (item: HuntingRunSummary) => {
    setView("hunt");
    detailEpoch.current++;
    setActionError("");
    if (selectedRef.current !== item.id) {
      setRun(null);
      setActivePhase("research");
    }
    selectedRef.current = item.id;
    setSelectedId(item.id);
    updateRunQuery(item.id);
    setFormOpen(false);
    setRefreshKey((key) => key + 1);
  };

  const openNewHunt = () => {
    initialSelection.current = true;
    detailEpoch.current++;
    selectedRef.current = "";
    setSelectedId("");
    updateRunQuery("");
    setActivePhase("research");
    setRun(null);
    setDetailError("");
    setActionError("");
    setFormOpen(true);
  };

  const startFromReport = (report: HuntingTrendReport, assetTarget = "") => {
    openNewHunt();
    setView("hunt");
    setTerm(report.term);
    setTarget(assetTarget);
    setPathPrefix("");
    setStart(localTime(Date.now() - 86400000));
    setEnd(localTime(Date.now()));
    setResearchURLs(
      report.references
        .filter((reference) => reference.source !== "CISA KEV")
        .map((reference) => reference.url)
        .slice(0, 8)
        .join("\n"),
    );
    setConfirmedScope(null);
    requestAnimationFrame(() => document.getElementById(`${fieldId}-term`)?.focus());
  };

  const selectPhase = (phase: HuntingPhaseId) => {
    if (!run || run.id !== selectedRef.current) return;
    const runId = run.id;
    setActivePhase(phase);
    requestAnimationFrame(() => {
      if (!mounted.current || selectedRef.current !== runId) return;
      const tabs = resultTabsRef.current;
      tabs?.querySelector<HTMLButtonElement>(`[data-hunting-phase="${phase}"]`)?.focus({ preventScroll: true });
      tabs?.scrollIntoView({
        behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
        block: "start",
      });
    });
  };

  const create = async () => {
    if (busy) return;
    setError("");
    const from = new Date(start);
    const until = new Date(end);
    if (!term.trim() || !target.trim()) {
      setError("조사할 취약점·공격 기법과 대상 자산을 입력해 주세요.");
      return;
    }
    if (Array.from(term.trim()).length > 200) {
      setError("조사 주제는 200자 이내로 입력해 주세요.");
      return;
    }
    if (
      !Number.isFinite(from.getTime()) ||
      !Number.isFinite(until.getTime()) ||
      from.getUTCFullYear() < 1970 ||
      until <= from ||
      until.getTime() > Date.now() ||
      until.getTime() - from.getTime() > 31 * 86400000
    ) {
      setError("조사 구간은 과거의 시작·종료 시각으로 최대 31일입니다.");
      return;
    }
    if (!selectedSource?.enabled || !selectedSource.credential_set || !sourcetypes.length || !scopeConfirmed) {
      setError("사용 가능한 Splunk 연결과 로그 유형을 선택하고 조회 범위를 확인해 주세요.");
      return;
    }
    if (sourcetypes.length > 8) {
      setError("한 실행에서 로그 유형은 최대 8개까지 선택할 수 있습니다. 필요한 유형을 직접 골라 주세요.");
      return;
    }
    const urls = [
      ...new Set(
        researchURLs
          .split(/\r?\n/)
          .map((value) => value.trim())
          .filter(Boolean),
      ),
    ];
    if (
      urls.length > 8 ||
      urls.some((value) => {
        try {
          const url = new URL(value);
          return (
            value.length > 2048 || !["http:", "https:"].includes(url.protocol) || Boolean(url.username || url.password)
          );
        } catch {
          return true;
        }
      })
    ) {
      setError("공개 참고 URL은 인증정보 없는 HTTP(S) 주소로 최대 8개, 한 줄에 하나씩 입력해 주세요.");
      return;
    }
    const input: HuntingRequest & { scope_confirmed: true } = {
      term: term.trim(),
      research_urls: urls,
      source_id: selectedSource.id,
      expected_source_revision: selectedSource.revision,
      scope: {
        target: target.trim(),
        path_prefix: pathPrefix.trim(),
        start: from.toISOString(),
        end: until.toISOString(),
      },
      mapping,
      sourcetypes,
      scope_confirmed: true,
    };
    setBusy("start");
    try {
      const saved = await huntingApi.create(input);
      if (!mounted.current) return;
      detailEpoch.current++;
      setActionError("");
      selectedRef.current = saved.id;
      setActivePhase("research");
      setRun(saved);
      setSelectedId(saved.id);
      updateRunQuery(saved.id);
      setRefreshKey((key) => key + 1);
      setRuns((items) => upsertRun(items, saved));
      setFormOpen(false);
    } catch (caught) {
      if (!mounted.current) return;
      setError((caught as Error).message);
      if (caught instanceof HttpError && caught.status === 409) {
        setConfirmedScope(null);
        void load();
      }
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  const cancel = async () => {
    if (!run || busy) return;
    const id = run.id;
    detailEpoch.current++;
    setBusy("cancel");
    setActionError("");
    try {
      const stopped = await huntingApi.cancel(id);
      if (!mounted.current || selectedRef.current !== id) return;
      setRun(stopped);
      setRuns((items) => upsertRun(items, stopped));
    } catch (caught) {
      if (mounted.current && selectedRef.current === id) setActionError((caught as Error).message);
    } finally {
      if (mounted.current) {
        if (selectedRef.current === id) setRefreshKey((key) => key + 1);
        setBusy(null);
      }
    }
  };

  const exportRun = async () => {
    if (!run || busy) return;
    const id = run.id;
    setBusy("export");
    setActionError("");
    try {
      const blob = await huntingApi.export(id);
      if (mounted.current) downloadSecurityJSON(blob, `aegisloop-hunt-${id}.json`);
    } catch (caught) {
      if (mounted.current && selectedRef.current === id) setActionError((caught as Error).message);
    } finally {
      if (mounted.current) setBusy(null);
    }
  };

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1 space-y-2">
          <Badge variant="outline">Defensive · Autonomous Hunting</Badge>
          <h1 className="font-semibold text-2xl tracking-tight">자율 위협 헌팅</h1>
          <p className="max-w-3xl text-muted-foreground text-sm leading-relaxed">
            취약점·공격 기법을 조사하고 공격 가설과 탐지 질문을 설계한 뒤, 허용한 Splunk 로그에서 근거를 찾습니다.
          </p>
        </div>
      </div>
      <Tabs value={view} onValueChange={(next) => setView(next as "trends" | "hunt")} className="space-y-4">
        <TabsList aria-label="자율 위협 헌팅 화면">
          <TabsTrigger value="trends">위협 동향 · {trendReports.length}</TabsTrigger>
          <TabsTrigger value="hunt">헌팅 작업</TabsTrigger>
        </TabsList>
        <TabsContent value="trends" className="mt-0">
          <HuntingTrendExplorer
            reports={trendReports}
            collection={trendCollection}
            inventory={trendInventory}
            error={trendError}
            starting={trendStarting}
            huntBusy={!!busy}
            onCollect={() => void collectTrends()}
            onHunt={startFromReport}
          />
        </TabsContent>
        <TabsContent value="hunt" className="mt-0 space-y-4">
          <HuntingProgress
            run={run}
            loading={!!selectedId && !run && detailLoading}
            activePhase={activePhase}
            onPhaseSelect={selectPhase}
            resultTabsId={resultTabsId}
          />
          <div className="space-y-3 rounded-lg border p-3">
            <div className="flex flex-wrap items-end gap-2">
              <div className="w-full min-w-0 space-y-1.5 lg:w-auto lg:flex-1">
                <Label htmlFor={`${fieldId}-run`}>헌팅 이력</Label>
                <select
                  id={`${fieldId}-run`}
                  className={SELECT_CLASS}
                  value={selectedId}
                  disabled={!!busy || loading}
                  onChange={(event) => {
                    const item = runs.find((entry) => entry.id === event.target.value);
                    if (item) selectRun(item);
                    else openNewHunt();
                  }}
                >
                  <option value="">새 헌팅</option>
                  {runs.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.term || item.request?.term || `헌팅 #${item.id}`} · {huntingStatusLabel(item.status)} ·{" "}
                      {new Date(item.created_at).toLocaleString()}
                    </option>
                  ))}
                </select>
              </div>
              <Button variant="outline" size="sm" onClick={openNewHunt} disabled={!!busy}>
                <PlusIcon />새 헌팅
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  void load();
                  if (selectedId) {
                    detailEpoch.current++;
                    setRefreshKey((key) => key + 1);
                  }
                }}
                disabled={loading || detailLoading || !!busy}
              >
                <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
                새로고침
              </Button>
              {selectedId ? (
                <>
                  {run && huntingRunActive(run.status) ? (
                    <Button variant="outline" size="sm" disabled={!!busy} onClick={() => void cancel()}>
                      {busy === "cancel" ? <Spinner /> : <SquareIcon />}중지
                    </Button>
                  ) : null}
                  <Button variant="outline" size="sm" disabled={!run || !!busy} onClick={() => void exportRun()}>
                    {busy === "export" ? <Spinner /> : <DownloadIcon />}JSON 내보내기
                  </Button>
                </>
              ) : null}
            </div>
            {historyError ? (
              <Alert variant="destructive">
                <AlertDescription>{historyError}</AlertDescription>
              </Alert>
            ) : null}
            {historyTruncated ? <p className="text-muted-foreground text-xs">최근 이력 일부를 표시합니다.</p> : null}
            {!loading && !historyError && !runs.length ? (
              <p className="text-muted-foreground text-xs">저장된 헌팅 실행이 없습니다.</p>
            ) : null}
          </div>
          {formOpen ? (
            <Collapsible open={formOpen} onOpenChange={setFormOpen}>
              <Card className="gap-0 py-0">
                <CardHeader className="flex flex-row items-center justify-between gap-3 py-3">
                  <div className="space-y-1">
                    <CardTitle className="text-sm">새 헌팅 설정</CardTitle>
                    {formOpen ? (
                      <CardDescription>조사 주제와 허용할 자산·기간·로그를 지정하세요.</CardDescription>
                    ) : null}
                  </div>
                  <CollapsibleTrigger asChild>
                    <Button variant="ghost" size="sm" aria-label={formOpen ? "헌팅 설정 접기" : "헌팅 설정 펼치기"}>
                      {formOpen ? "접기" : "펼치기"}
                      <ChevronDownIcon className={formOpen ? "rotate-180" : undefined} />
                    </Button>
                  </CollapsibleTrigger>
                </CardHeader>
                <CollapsibleContent>
                  <CardContent className="pb-5">
                    {error ? (
                      <Alert variant="destructive" className="mb-4">
                        <AlertDescription>{error}</AlertDescription>
                      </Alert>
                    ) : null}
                    <form
                      onSubmit={(event) => {
                        event.preventDefault();
                        void create();
                      }}
                    >
                      <fieldset disabled={!!busy || loading} className="space-y-5 disabled:opacity-70">
                        <div className="space-y-2">
                          <Label htmlFor={`${fieldId}-term`}>취약점·공격 기법 또는 조사 질문</Label>
                          <Textarea
                            id={`${fieldId}-term`}
                            value={term}
                            onChange={(event) => setTerm(event.target.value)}
                            required
                            maxLength={200}
                            rows={2}
                            placeholder="예: 공개된 디렉터리의 민감 파일 접근 흔적 조사"
                          />
                        </div>
                        <details className="rounded-lg border p-4">
                          <summary className="cursor-pointer font-medium text-sm">공개 참고 URL 추가 (선택)</summary>
                          <div className="mt-3 space-y-2">
                            <Label htmlFor={`${fieldId}-urls`}>공식 권고문·기술 자료 URL</Label>
                            <Textarea
                              id={`${fieldId}-urls`}
                              value={researchURLs}
                              onChange={(event) => setResearchURLs(event.target.value)}
                              rows={3}
                              maxLength={16000}
                              placeholder="https://… (한 줄에 하나, 최대 8개)"
                            />
                            <p className="text-muted-foreground text-xs">
                              인증정보나 내부 시스템 주소를 넣지 마세요. 실제로 가져온 자료의 출처와 발췌문을 결과에서
                              확인할 수 있습니다.
                            </p>
                          </div>
                        </details>
                        <div className="space-y-3 rounded-lg border p-4">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <Label htmlFor={`${fieldId}-source`}>Splunk 연결</Label>
                            <Link href="/function/purple/sources" className="text-xs underline underline-offset-2">
                              로그 연결 관리
                            </Link>
                          </div>
                          {sourceError ? (
                            <Alert variant="destructive">
                              <AlertDescription>{sourceError}</AlertDescription>
                            </Alert>
                          ) : null}
                          <select
                            id={`${fieldId}-source`}
                            className={SELECT_CLASS}
                            value={sourceId}
                            onChange={(event) => {
                              const id = event.target.value;
                              setSourceId(id);
                              setSourcetypes(securitySourceSourcetypes(sources.find((source) => source.id === id)));
                            }}
                            required
                          >
                            <option value="">연결을 선택하세요</option>
                            {sources.map((source) => (
                              <option
                                key={source.id}
                                value={source.id}
                                disabled={!source.enabled || !source.credential_set}
                              >
                                {source.name} · v{source.revision}
                                {!source.enabled || !source.credential_set ? " · 사용 불가" : ""}
                              </option>
                            ))}
                          </select>
                          {!loading && !sources.some((source) => source.enabled && source.credential_set) ? (
                            <p className="text-muted-foreground text-sm">
                              활성화와 인증 설정을 마친 Splunk 연결이 필요합니다.
                            </p>
                          ) : null}
                          {selectedSource ? (
                            <div className="space-y-2">
                              <p className="font-medium text-sm">조회할 로그 유형</p>
                              {securitySourceSourcetypes(selectedSource).map((kind) => (
                                <label key={kind} className="flex items-start gap-2 text-sm">
                                  <input
                                    type="checkbox"
                                    className="mt-1"
                                    checked={sourcetypes.includes(kind)}
                                    onChange={(event) => {
                                      const checked = event.target.checked;
                                      setSourcetypes((current) =>
                                        checked ? [...current, kind] : current.filter((value) => value !== kind),
                                      );
                                    }}
                                  />
                                  <span className="break-all">
                                    {kind}
                                    <span className="ml-2 text-muted-foreground text-xs">
                                      {[
                                        ...new Set(
                                          selectedSource.config.streams
                                            ?.filter((stream) => stream.sourcetype === kind)
                                            .map((stream) => stream.index) ??
                                            [selectedSource.config.index].filter(Boolean),
                                        ),
                                      ].join(", ")}
                                    </span>
                                  </span>
                                </label>
                              ))}
                              <p className="text-muted-foreground text-xs">
                                연결을 선택하면 등록된 모든 로그 유형이 기본 선택됩니다. 필요하면 해제하세요. 저장된
                                연결의 허용 인덱스와 선택한 로그 유형 안에서 조회합니다.
                              </p>
                              {sourcetypes.length > 8 ? (
                                <Alert variant="destructive">
                                  <AlertDescription>
                                    로그 유형 {sourcetypes.length}개가 선택되어 있습니다. 한 실행의 한도는 8개이므로
                                    조사에 필요한 유형을 직접 선택해 주세요.
                                  </AlertDescription>
                                </Alert>
                              ) : null}
                            </div>
                          ) : null}
                        </div>
                        <div className="grid gap-4 md:grid-cols-2">
                          <div className="space-y-2">
                            <Label htmlFor={`${fieldId}-target`}>대상 자산</Label>
                            <Input
                              id={`${fieldId}-target`}
                              value={target}
                              onChange={(event) => setTarget(event.target.value)}
                              required
                              maxLength={1024}
                              placeholder="portal.lab 또는 portal.lab:8080"
                            />
                            <p className="text-muted-foreground text-xs">
                              URL 경로를 제외한 실제 요청 대상 호스트·포트입니다.
                            </p>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor={`${fieldId}-path`}>허용 경로 접두어 (선택)</Label>
                            <Input
                              id={`${fieldId}-path`}
                              value={pathPrefix}
                              onChange={(event) => setPathPrefix(event.target.value)}
                              maxLength={2048}
                              placeholder="/exports"
                            />
                            <p className="text-muted-foreground text-xs">
                              비워 두면 지정한 자산의 전체 경로를 조회합니다. 웹·호스트 로그를 함께 조사할 때는 경로를
                              비워 두세요.
                            </p>
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor={`${fieldId}-start`}>조사 시작 (현지 시각)</Label>
                            <Input
                              id={`${fieldId}-start`}
                              type="datetime-local"
                              step="1"
                              value={start}
                              onChange={(event) => setStart(event.target.value)}
                              required
                            />
                          </div>
                          <div className="space-y-2">
                            <Label htmlFor={`${fieldId}-end`}>조사 종료 (현지 시각)</Label>
                            <Input
                              id={`${fieldId}-end`}
                              type="datetime-local"
                              step="1"
                              value={end}
                              onChange={(event) => setEnd(event.target.value)}
                              required
                            />
                          </div>
                        </div>
                        <p className="text-muted-foreground text-xs">
                          과거 구간을 최대 31일까지 지정할 수 있습니다. 조회 결과의 부재와 수집·보존 자료의 부재는
                          구분해 표시합니다.
                        </p>
                        <details className="rounded-lg border p-4">
                          <summary className="cursor-pointer font-medium text-sm">원본 로그 필드 매핑</summary>
                          <p className="mt-3 text-muted-foreground text-xs leading-relaxed">
                            Splunk의 host는 수집기일 수 있습니다. 대상 필드는 실제 요청 자산이 기록된 필드로 지정하세요.
                            시각은 Splunk의 _time을 기준으로 조회합니다.
                          </p>
                          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
                            {(Object.keys(mapping) as (keyof InvestigationMapping)[]).map((key) => (
                              <div key={key} className="space-y-1.5">
                                <Label htmlFor={`${fieldId}-map-${key}`}>{FIELD_LABELS[key]}</Label>
                                <Input
                                  id={`${fieldId}-map-${key}`}
                                  value={mapping[key]}
                                  readOnly={key === "timestamp"}
                                  onChange={(event) =>
                                    setMapping((current) => ({ ...current, [key]: event.target.value }))
                                  }
                                  maxLength={128}
                                  required={
                                    key === "timestamp" ||
                                    key === "target" ||
                                    (key === "path" && Boolean(pathPrefix.trim()))
                                  }
                                />
                              </div>
                            ))}
                          </div>
                        </details>
                        <label className="flex items-start gap-2 text-sm leading-relaxed">
                          <input
                            type="checkbox"
                            className="mt-1"
                            checked={scopeConfirmed}
                            onChange={(event) => setConfirmedScope(event.target.checked ? scopeKey : null)}
                            required
                          />
                          <span>
                            지정한 자산·기간·로그 유형의 읽기 전용 조회를 허용합니다. 조회 범위를 바꾸면 다시
                            확인합니다.
                          </span>
                        </label>
                        <p className="text-muted-foreground text-xs leading-relaxed">
                          실행에는 LLM·공개 자료 조회·Splunk 조회가 포함됩니다. 조사 주제와 선택 범위의 로그 발췌가
                          설정한 모델로 전달되며, 모델·조회·시간 한도와 중지 기능을 적용합니다.
                        </p>
                        <div className="flex flex-wrap gap-2">
                          <Button
                            type="submit"
                            disabled={
                              !term.trim() ||
                              !target.trim() ||
                              !selectedSource?.enabled ||
                              !selectedSource.credential_set ||
                              !sourcetypes.length ||
                              sourcetypes.length > 8 ||
                              !scopeConfirmed
                            }
                          >
                            {busy === "start" ? <Spinner /> : <PlayIcon />}자율 헌팅 시작
                          </Button>
                          <Button
                            type="button"
                            variant="outline"
                            onClick={() => void load()}
                            disabled={loading || !!busy}
                          >
                            <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
                            연결·이력 새로고침
                          </Button>
                        </div>
                      </fieldset>
                    </form>
                  </CardContent>
                </CollapsibleContent>
              </Card>
            </Collapsible>
          ) : null}
          {selectedId ? (
            <div className="space-y-4">
              {detailError ? (
                <Alert variant="destructive">
                  <AlertDescription>{detailError} 기존에 표시한 결과는 보존합니다.</AlertDescription>
                </Alert>
              ) : null}
              {actionError ? (
                <Alert variant="destructive">
                  <AlertDescription>{actionError}</AlertDescription>
                </Alert>
              ) : null}
              {!run && detailLoading ? <Skeleton className="h-40 w-full" /> : null}
              {run ? (
                <HuntingResultView
                  key={run.id}
                  run={run}
                  activePhase={activePhase}
                  onPhaseChange={setActivePhase}
                  tabsRef={resultTabsRef}
                  tabsId={resultTabsId}
                />
              ) : null}
            </div>
          ) : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}
