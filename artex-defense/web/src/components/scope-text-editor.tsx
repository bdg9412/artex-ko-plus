"use client";

import * as React from "react";

import { useTranslations } from "next-intl";

import { Badge } from "@/components/ui/badge";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Textarea } from "@/components/ui/textarea";
import { MAX_COMPANY_SCOPE_VALUE_LENGTH, type ParsedCompanyScopeText } from "@/lib/company-scope";
import type { CompanyScopeKind } from "@/lib/types";

// 라벨은 렌더 시점에 t(`kind.${kind}`) 로 해석(아래 배지).
const SCOPE_KINDS: CompanyScopeKind[] = ["domain", "ip", "cidr", "icp", "keyword"];

export function ScopeTextEditor({
  id,
  value,
  onValueChange,
  parsed,
  label,
  description,
}: {
  id: string;
  value: string;
  onValueChange: (value: string) => void;
  parsed: ParsedCompanyScopeText;
  label?: string;
  description?: string;
}) {
  const t = useTranslations("scopeEditor");
  const counts = React.useMemo(() => {
    const result = new Map<CompanyScopeKind, number>();
    for (const rule of parsed.rules) result.set(rule.kind, (result.get(rule.kind) ?? 0) + 1);
    return result;
  }, [parsed.rules]);
  // company-scope.ts 는 번역할 수 없는 순수 모듈이라 오류 "코드"만 돌려준다. 여기서
  // 코드별 메시지로 해석한다(tooLong 은 최대 글자 수를 함께 보간).
  const errorText = React.useCallback(
    (code: string) => {
      if (code === "tooLong") return t("error.tooLong", { max: MAX_COMPANY_SCOPE_VALUE_LENGTH });
      const key = `error.${code}`;
      return t.has(key) ? t(key) : code;
    },
    [t],
  );

  return (
    <Field data-invalid={parsed.errors.length > 0}>
      <FieldLabel htmlFor={id}>{label ?? t("defaultLabel")}</FieldLabel>
      <FieldDescription>{description ?? t("defaultDescription")}</FieldDescription>
      <Textarea
        id={id}
        rows={8}
        value={value}
        aria-invalid={parsed.errors.length > 0}
        placeholder={t("placeholder")}
        className="min-h-36 resize-y font-mono text-sm"
        onChange={(event) => onValueChange(event.target.value)}
      />
      {parsed.rules.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 text-muted-foreground text-xs">
          <span>{t("recognized", { count: parsed.rules.length })}</span>
          {SCOPE_KINDS.map((kind) => {
            const count = counts.get(kind) ?? 0;
            return count > 0 ? (
              <Badge key={kind} variant="secondary" className="font-mono tabular-nums">
                {t(`kind.${kind}`)} {count}
              </Badge>
            ) : null;
          })}
        </div>
      )}
      {parsed.errors.length > 0 && (
        <FieldError>
          {parsed.errors.slice(0, 5).map((item) => (
            <span key={`${item.line}-${item.error}`} className="block">
              {t("lineError", { line: item.line, error: errorText(item.error) })}
            </span>
          ))}
          {parsed.errors.length > 5 && (
            <span className="block">{t("moreErrors", { count: parsed.errors.length - 5 })}</span>
          )}
        </FieldError>
      )}
    </Field>
  );
}
