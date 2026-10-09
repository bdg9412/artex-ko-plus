import type { useTranslations } from "next-intl";

import { Card, CardContent } from "@/components/ui/card";

// 本文件被 client 页面引用，但自身是纯展示/纯函数，不直接调用 useTranslations。
// formatBacklog 需要 i18n 单位文案，所以由调用方把 t 注入进来（tasks/approval-records 先例）。
type Translator = ReturnType<typeof useTranslations>;

export function StatTile({ label, value, hint, tone }: { label: string; value: string; hint?: string; tone?: string }) {
  return (
    <Card size="sm" className="gap-1">
      <CardContent>
        <p className="text-muted-foreground text-xs">{label}</p>
        <p className={`text-lg font-semibold ${tone === "red" ? "text-rose-600" : ""}`}>{value}</p>
        {hint && <p className={`text-xs ${tone === "red" ? "text-rose-600" : "text-muted-foreground"}`}>{hint}</p>}
      </CardContent>
    </Card>
  );
}

// formatBacklog 把积压毫秒数渲染成人看得懂的量级。
export function formatBacklog(ms: number, t: Translator): string {
  if (!ms) return "—";
  if (ms < 60_000) return t("unit.sec", { n: Math.round(ms / 1000) });
  if (ms < 3_600_000) return t("unit.min", { n: Math.round(ms / 60_000) });
  return t("unit.hour", { n: (ms / 3_600_000).toFixed(1) });
}
