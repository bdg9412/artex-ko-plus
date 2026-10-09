"use client";

import { useTranslations } from "next-intl";

import { Badge } from "@/components/ui/badge";
import type { DefenseState, ReplayVerdict } from "@/lib/purple-api";

export function DefenseStateBadge({ state }: { state: DefenseState }) {
  const t = useTranslations("purple");
  return (
    <Badge
      variant={state === "stale" ? "destructive" : "outline"}
      className={state === "current" ? "border-teal-600/30 bg-teal-500/10 text-teal-700 dark:text-teal-300" : undefined}
    >
      {t(`state.${state}`)}
    </Badge>
  );
}

export function DefenseReplayBadge({ verdict, stale = false }: { verdict: ReplayVerdict; stale?: boolean }) {
  const t = useTranslations("purple.replay");
  return (
    <Badge variant={stale || verdict === "fail" ? "destructive" : "outline"}>
      {stale ? t("stale") : t(`verdict.${verdict}`)}
    </Badge>
  );
}
