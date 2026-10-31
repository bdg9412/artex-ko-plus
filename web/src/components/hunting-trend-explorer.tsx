"use client";

import * as React from "react";

import { ArrowUpIcon, PlayIcon, RefreshCwIcon, SearchIcon } from "lucide-react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import type { HuntingTrendCollection, HuntingTrendInventory, HuntingTrendReport } from "@/lib/hunting-api";

type PriorityFilter = "all" | HuntingTrendReport["priority"];

const PRIORITY_LABELS = { high: "KEV", medium: "CVE 보도", review: "보안 동향" } as const;

interface HuntingTrendExplorerProps {
  reports: HuntingTrendReport[];
  collection: HuntingTrendCollection | null;
  inventory: HuntingTrendInventory | null;
  error: string;
  starting: boolean;
  huntBusy: boolean;
  onCollect: () => void;
  onHunt: (report: HuntingTrendReport, assetTarget?: string) => void;
}

export function HuntingTrendExplorer({
  reports,
  collection,
  inventory,
  error,
  starting,
  huntBusy,
  onCollect,
  onHunt,
}: HuntingTrendExplorerProps) {
  const [query, setQuery] = React.useState("");
  const [priority, setPriority] = React.useState<PriorityFilter>("all");
  const [selectedKey, setSelectedKey] = React.useState("");
  const listRef = React.useRef<HTMLElement>(null);
  const detailRef = React.useRef<HTMLElement>(null);
  const counts = React.useMemo(
    () => ({
      all: reports.length,
      high: reports.filter((report) => report.priority === "high").length,
      medium: reports.filter((report) => report.priority === "medium").length,
      review: reports.filter((report) => report.priority === "review").length,
    }),
    [reports],
  );
  const filtered = React.useMemo(() => {
    const term = query.trim().toLocaleLowerCase();
    return reports.filter((report) => {
      if (priority !== "all" && report.priority !== priority) return false;
      return (
        !term ||
        [report.title, report.term, report.summary, report.vendor, report.product].some((value) =>
          value?.toLocaleLowerCase().includes(term),
        )
      );
    });
  }, [reports, priority, query]);
  const selected = filtered.find((report) => report.topic_key === selectedKey) ?? filtered[0];

  React.useEffect(() => {
    if (!selectedKey || window.matchMedia("(min-width: 1024px)").matches) return;
    detailRef.current?.scrollIntoView({
      behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth",
      block: "start",
    });
  }, [selectedKey]);

  return (
    <Card className="gap-0 py-0">
      <CardHeader className="flex flex-row items-start justify-between gap-3 py-4">
        <div className="space-y-1">
          <CardTitle className="text-base">자동 위협 동향 리포트</CardTitle>
          <CardDescription>
            공개 피드와 CISA KEV를 15분마다 수집합니다. 리포트를 검토하고 헌팅 범위를 선택하세요.
          </CardDescription>
        </div>
        <Button variant="outline" size="sm" onClick={onCollect} disabled={starting || collection?.busy}>
          {starting || collection?.busy ? <Spinner /> : <RefreshCwIcon />}지금 수집
        </Button>
      </CardHeader>
      <CardContent className="space-y-3 pb-4">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-muted-foreground text-xs">
          <span>
            리포트 <strong className="text-foreground">{reports.length}건</strong>
          </span>
          {collection?.last_success ? (
            <span>최근 수집 {new Date(collection.last_success).toLocaleString()}</span>
          ) : null}
          {inventory?.available ? (
            <span>
              등록 자산 제품 지문 {inventory.scanned_assets}건 대조{inventory.truncated ? " (최근 5,000건)" : ""}
            </span>
          ) : null}
          {collection?.busy ? <span>수집 중…</span> : null}
        </div>
        {collection?.last_error ? (
          <p className="text-amber-700 text-xs">일부 출처 수집 오류: {collection.last_error}</p>
        ) : null}
        {inventory && !inventory.available ? (
          <p className="text-amber-700 text-xs">자산 제품 지문 대조를 완료하지 못했습니다.</p>
        ) : null}
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative min-w-0 flex-1">
            <SearchIcon className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              aria-label="위협 동향 검색"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="CVE, 제품명, 제목 검색"
              className="pl-9"
            />
          </div>
          <fieldset className="flex max-w-full gap-1 overflow-x-auto">
            <legend className="sr-only">리포트 유형 필터</legend>
            {(["all", "high", "medium", "review"] as const).map((value) => (
              <Button
                key={value}
                type="button"
                variant={priority === value ? "secondary" : "ghost"}
                size="sm"
                aria-pressed={priority === value}
                className="shrink-0"
                onClick={() => setPriority(value)}
              >
                {value === "all" ? "전체" : PRIORITY_LABELS[value]} {counts[value]}
              </Button>
            ))}
          </fieldset>
        </div>
        <div className="grid gap-3 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          <section
            ref={listRef}
            className="flex flex-col overflow-hidden rounded-lg border lg:h-[calc(100vh-390px)] lg:max-h-[540px] lg:min-h-[320px]"
            aria-label="위협 동향 목록"
          >
            <div className="flex items-center justify-between border-b px-3 py-2 text-muted-foreground text-xs">
              <span>리포트 목록</span>
              <span>{filtered.length}건</span>
            </div>
            <div className="h-64 overflow-y-auto lg:h-auto lg:min-h-0 lg:flex-1">
              {filtered.length ? (
                filtered.map((report) => (
                  <button
                    key={report.topic_key}
                    type="button"
                    aria-pressed={selected?.topic_key === report.topic_key}
                    onClick={() => setSelectedKey(report.topic_key)}
                    className={`w-full border-b px-3 py-2.5 text-left transition-colors last:border-b-0 hover:bg-muted/60 ${
                      selected?.topic_key === report.topic_key
                        ? "bg-primary/5 shadow-[inset_3px_0_0_var(--primary)]"
                        : ""
                    }`}
                  >
                    <span className="flex items-center gap-2 text-muted-foreground text-xs">
                      <Badge
                        variant={report.priority === "high" ? "destructive" : "outline"}
                        className="px-1.5 py-0 text-[10px]"
                      >
                        {PRIORITY_LABELS[report.priority]}
                      </Badge>
                      <span>{new Date(report.published_at).toLocaleDateString()}</span>
                      {(report.asset_match_count ?? 0) > 0 ? (
                        <span className="ml-auto text-amber-700">자산 단서 {report.asset_match_count}</span>
                      ) : null}
                    </span>
                    <span className="mt-1 line-clamp-2 block font-medium text-sm leading-snug">{report.title}</span>
                  </button>
                ))
              ) : (
                <p className="p-4 text-muted-foreground text-sm">
                  일치하는 리포트가 없습니다. 검색어나 필터를 바꿔 보세요.
                </p>
              )}
            </div>
          </section>
          <article
            ref={detailRef}
            key={selected?.topic_key ?? "empty"}
            className="flex h-[440px] min-h-64 flex-col overflow-hidden rounded-lg border lg:h-[calc(100vh-390px)] lg:max-h-[540px] lg:min-h-[320px]"
            aria-label="선택한 위협 동향 리포트"
          >
            {selected ? (
              <>
                <div className="min-h-0 flex-1 space-y-4 overflow-y-auto p-4">
                  <div className="space-y-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant={selected.priority === "high" ? "destructive" : "outline"}>
                        {PRIORITY_LABELS[selected.priority]}
                      </Badge>
                      <span className="text-muted-foreground text-xs">
                        {new Date(selected.published_at).toLocaleDateString()}
                      </span>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="ml-auto lg:hidden"
                        onClick={() => listRef.current?.scrollIntoView({ block: "start" })}
                      >
                        <ArrowUpIcon />
                        목록으로
                      </Button>
                    </div>
                    <h3 className="font-semibold text-base leading-snug">{selected.title}</h3>
                  </div>
                  <div className="space-y-1.5">
                    <p className="font-medium text-xs">요약</p>
                    <p className="whitespace-pre-wrap text-muted-foreground text-sm leading-relaxed">
                      {selected.summary || "원문을 확인해 주세요."}
                    </p>
                  </div>
                  {selected.product ? (
                    <div className="space-y-1.5">
                      <p className="font-medium text-xs">공개 데이터의 제품명</p>
                      <p className="text-sm">{[selected.vendor, selected.product].filter(Boolean).join(" ")}</p>
                    </div>
                  ) : null}
                  <div className="space-y-1.5">
                    <p className="font-medium text-xs">헌팅 검토 이유</p>
                    <p className="text-muted-foreground text-sm leading-relaxed">{selected.reason}</p>
                  </div>
                  {(selected.asset_match_count ?? 0) > 0 ? (
                    <div className="space-y-2 rounded-md border border-amber-500/40 bg-amber-500/5 p-3 text-xs">
                      <p className="font-medium">
                        등록 자산 제품명 단서 {selected.asset_match_count}건 · 영향 버전·설정 미확인
                      </p>
                      {selected.asset_matches?.map((match) => (
                        <div
                          key={match.asset_id}
                          className="flex flex-wrap items-center justify-between gap-2 border-amber-500/20 border-t pt-2"
                        >
                          <span>
                            {match.label} · {match.observed} ·{" "}
                            {match.basis === "kev_product" ? "KEV 제품명" : "기사 제목"} 일치 · 자산 최종 관측{" "}
                            {new Date(match.last_seen).toLocaleDateString()}
                          </span>
                          {match.target ? (
                            <Button
                              variant="outline"
                              size="sm"
                              disabled={huntBusy}
                              onClick={() => onHunt(selected, match.target)}
                            >
                              이 자산으로 설정
                            </Button>
                          ) : null}
                        </div>
                      ))}
                      {(selected.asset_match_count ?? 0) > (selected.asset_matches?.length ?? 0) ? (
                        <p>상위 {selected.asset_matches?.length ?? 0}건을 표시합니다.</p>
                      ) : null}
                    </div>
                  ) : null}
                  <div className="space-y-1.5">
                    <p className="font-medium text-xs">원문 출처</p>
                    <div className="flex flex-wrap gap-x-3 gap-y-1">
                      {selected.references.map((reference) => (
                        <a
                          key={reference.url}
                          href={reference.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          title={reference.title}
                          className="text-primary text-xs underline underline-offset-2"
                        >
                          {reference.source}
                        </a>
                      ))}
                    </div>
                  </div>
                  <p className="text-muted-foreground text-xs">
                    제품명 일치는 헌팅 단서입니다. 실제 영향 버전이나 설정은 별도로 확인해야 합니다.
                  </p>
                </div>
                <div className="border-t bg-background p-3">
                  <Button size="sm" onClick={() => onHunt(selected)} disabled={huntBusy}>
                    <PlayIcon />이 리포트로 헌팅 설정
                  </Button>
                </div>
              </>
            ) : (
              <p className="p-4 text-muted-foreground text-sm">
                {reports.length
                  ? "검색 결과에서 리포트를 선택하세요."
                  : "아직 리포트가 없습니다. 지금 수집을 눌러 첫 동향을 가져올 수 있습니다."}
              </p>
            )}
          </article>
        </div>
      </CardContent>
    </Card>
  );
}
