"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowUpRightIcon, RefreshCwIcon, ShieldCheckIcon } from "lucide-react";
import { useTranslations } from "next-intl";

import { DefenseReplayBadge, DefenseStateBadge } from "@/components/defense-state-badge";
import { StatusBadge } from "@/components/status-badge";
import { TablePagination } from "@/components/table-pagination";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { type PurpleOverview, purpleApi } from "@/lib/purple-api";

const METRICS = [
  "total_findings",
  "planned",
  "validated",
  "needs_revalidation",
  "detected",
  "missed",
  "blocked",
] as const;
const REPLAY_METRICS = ["replayed", "replay_passed", "replay_needs_revalidation"] as const;
const EXECUTION_METRICS = [
  "execution_total",
  "execution_detected",
  "execution_missed",
  "execution_blocked",
  "execution_inconclusive",
] as const;

export default function PurplePage() {
  const t = useTranslations("purple");
  const [data, setData] = React.useState<PurpleOverview | null>(null);
  const [page, setPage] = React.useState(1);
  const [limit, setLimit] = React.useState(20);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [refresh, setRefresh] = React.useState(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: refresh explicitly reloads the same page at the user's request.
  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    setError("");
    purpleApi
      .overview(page, limit)
      .then((result) => {
        if (alive) setData(result);
      })
      .catch((e: Error) => {
        if (alive) setError(e.message);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [page, limit, refresh]);

  const coverage = data?.stats.total_findings
    ? Math.round((data.stats.validated / data.stats.total_findings) * 100)
    : 0;

  return (
    <div className="flex flex-1 flex-col">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3 lg:px-6">
        <div className="flex items-center gap-3">
          <SidebarTrigger className="-ml-1" />
          <ShieldCheckIcon className="size-5 text-violet-500" />
          <h1 className="font-semibold">{t("title")}</h1>
          <Badge variant="outline">PURPLE</Badge>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="outline" size="sm" asChild>
            <Link href="/function/purple/sources">
              {t("sources.title")}
              <ArrowUpRightIcon />
            </Link>
          </Button>
          <Button variant="outline" size="sm" disabled={loading} onClick={() => setRefresh((value) => value + 1)}>
            <RefreshCwIcon className={loading ? "animate-spin" : undefined} />
            {t("refresh")}
          </Button>
        </div>
      </header>
      <div className="flex flex-col gap-6 p-4 lg:p-6">
        <div className="flex flex-col gap-2">
          <h2 className="text-xl font-semibold tracking-tight">{t("boardTitle")}</h2>
          <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{t("boardDescription")}</p>
        </div>
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        ) : null}
        {!data && loading ? (
          <div className="grid gap-3 sm:grid-cols-3">
            {[1, 2, 3].map((item) => (
              <Skeleton key={item} className="h-28" />
            ))}
          </div>
        ) : null}
        {data ? (
          <>
            <Card className="border-violet-500/40 bg-violet-500/5">
              <CardHeader>
                <CardTitle>{t("execution.boardTitle")}</CardTitle>
                <CardDescription>{t("execution.boardDescription")}</CardDescription>
              </CardHeader>
              <CardContent className="grid grid-cols-2 gap-3 lg:grid-cols-5">
                {EXECUTION_METRICS.map((key) => (
                  <div key={key} className="rounded-lg bg-background/70 p-4">
                    <p className="text-xs text-muted-foreground">{t(`execution.metrics.${key}`)}</p>
                    <p className="mt-2 text-2xl font-semibold tabular-nums">{data.stats[key].toLocaleString()}</p>
                  </div>
                ))}
              </CardContent>
            </Card>
            <Card className="border-violet-500/30">
              <CardHeader>
                <CardTitle>{t("replay.boardTitle")}</CardTitle>
                <CardDescription>{t("replay.scope")}</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4 sm:grid-cols-3">
                {REPLAY_METRICS.map((key) => (
                  <div key={key} className="rounded-lg bg-muted/50 p-4">
                    <p className="text-xs text-muted-foreground">{t(`replay.metrics.${key}`)}</p>
                    <p className="mt-2 text-2xl font-semibold tabular-nums">{data.stats[key].toLocaleString()}</p>
                  </div>
                ))}
              </CardContent>
            </Card>
            <h3 className="text-sm font-medium">{t("manualRecord")}</h3>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7" aria-busy={loading}>
              {METRICS.map((key) => (
                <Card
                  key={key}
                  className={key === "needs_revalidation" && data.stats[key] > 0 ? "border-amber-500/50" : undefined}
                >
                  <CardHeader className="pb-2">
                    <CardDescription>{t(`metrics.${key}`)}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <p className="text-2xl font-semibold tabular-nums">{data.stats[key].toLocaleString()}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
            <Card className="border-violet-500/20 bg-violet-500/5">
              <CardContent className="flex flex-col gap-3 pt-6 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex flex-col gap-1">
                  <p className="font-medium">{t("coverage", { n: coverage })}</p>
                  <p className="text-xs text-muted-foreground">{t("coverageDescription")}</p>
                </div>
                <Badge variant="outline" className="self-start sm:self-auto">
                  {t("manualRecord")}
                </Badge>
              </CardContent>
            </Card>
            <Card className="gap-0 overflow-hidden py-0">
              <CardHeader className="py-5">
                <CardTitle>{t("findingsTitle")}</CardTitle>
                <CardDescription>{t("findingsDescription")}</CardDescription>
              </CardHeader>
              {data.total === 0 ? (
                <Empty className="border-t py-14">
                  <EmptyHeader>
                    <ShieldCheckIcon className="mx-auto mb-2 size-8 text-muted-foreground" />
                    <EmptyTitle>{t("emptyTitle")}</EmptyTitle>
                    <EmptyDescription>{t("emptyDescription")}</EmptyDescription>
                  </EmptyHeader>
                  <Button variant="outline" asChild>
                    <Link href="/function/tasks">
                      {t("viewTasks")}
                      <ArrowUpRightIcon />
                    </Link>
                  </Button>
                </Empty>
              ) : (
                <>
                  <Table aria-busy={loading}>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="pl-6">{t("finding")}</TableHead>
                        <TableHead>{t("severity")}</TableHead>
                        <TableHead>{t("execution.tableTitle")}</TableHead>
                        <TableHead>{t("replay.title")}</TableHead>
                        <TableHead>{t("execution.manualState")}</TableHead>
                        <TableHead>{t("execution.manualDetection")}</TableHead>
                        <TableHead>{t("execution.manualPrevention")}</TableHead>
                        <TableHead className="pr-6 text-right">{t("action")}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.items.map((item) => (
                        <TableRow key={item.finding_id}>
                          <TableCell className="max-w-xs pl-6">
                            <Link
                              className="block truncate font-medium hover:underline"
                              href={`/function/findings/detail?id=${encodeURIComponent(item.finding_id)}&tab=defense`}
                            >
                              {item.name || item.vulnclass || t("unnamedFinding")}
                            </Link>
                            <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                              <span>#{item.finding_id}</span>
                              <StatusBadge domain="finding" value={item.finding_status} />
                            </div>
                          </TableCell>
                          <TableCell>
                            <StatusBadge domain="severity" value={item.severity} dot />
                          </TableCell>
                          <TableCell className="max-w-64 whitespace-normal">
                            {item.execution_state !== "none" && item.execution_id ? (
                              <Link
                                className="flex flex-col gap-1 text-xs hover:underline"
                                href={`/function/findings/detail?id=${encodeURIComponent(item.finding_id)}&tab=defense`}
                              >
                                <span className="font-medium">
                                  #{item.execution_id} ·{" "}
                                  {item.execution_status
                                    ? t(`execution.status.${item.execution_status}`)
                                    : t("execution.tableTitle")}
                                </span>
                                {item.execution_state === "stale" ? (
                                  <span className="text-muted-foreground">{t("execution.stale")}</span>
                                ) : (
                                  <span className="text-muted-foreground">
                                    {item.execution_detection
                                      ? `${t(`execution.detection.${item.execution_detection}`)} · ${item.execution_prevention ? t(`execution.prevention.${item.execution_prevention}`) : t("execution.waitingEvidence")}`
                                      : t("execution.waitingEvidence")}
                                  </span>
                                )}
                              </Link>
                            ) : (
                              <span className="text-xs text-muted-foreground">{t("execution.notStarted")}</span>
                            )}
                          </TableCell>
                          <TableCell>
                            {item.replay_verdict ? (
                              <DefenseReplayBadge verdict={item.replay_verdict} stale={item.replay_state === "stale"} />
                            ) : (
                              <span className="text-xs text-muted-foreground">{t("replay.none")}</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <DefenseStateBadge state={item.state} />
                            {item.plan_revision > 0 ? (
                              <p className="mt-1 text-xs text-muted-foreground">
                                {t("revision", { n: item.plan_revision })}
                              </p>
                            ) : null}
                          </TableCell>
                          <TableCell
                            className={
                              item.state === "current" && item.detection === "missed" ? "text-destructive" : undefined
                            }
                          >
                            {item.state === "current" ? t(`detectionResult.${item.detection}`) : "—"}
                          </TableCell>
                          <TableCell>
                            {item.state === "current" ? t(`preventionResult.${item.prevention}`) : "—"}
                          </TableCell>
                          <TableCell className="pr-6 text-right">
                            <Button variant="ghost" size="sm" asChild>
                              <Link
                                href={`/function/findings/detail?id=${encodeURIComponent(item.finding_id)}&tab=defense`}
                              >
                                {t("openFinding")}
                                <ArrowUpRightIcon />
                              </Link>
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                  <TablePagination
                    page={page}
                    pageSize={limit}
                    total={data.total}
                    onPageChange={setPage}
                    onPageSizeChange={(size) => {
                      setLimit(size);
                      setPage(1);
                    }}
                  />
                </>
              )}
            </Card>
          </>
        ) : null}
      </div>
    </div>
  );
}
