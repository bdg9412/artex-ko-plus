import type { CompanyScopeKind, CompanyScopeRule } from "@/lib/types";

export const MAX_COMPANY_SCOPE_VALUE_LENGTH = 1024;

// 검증 결과는 지역화 가능한 "오류 코드"로 돌려준다. 이 모듈은 React 밖 순수 함수라
// 직접 번역할 수 없으므로, 노출 지점(scope-text-editor 는 next-intl 의 t(), mock
// handler 는 companyScopeErrorText())이 코드를 각 언어 문구로 바꾼다.
export type CompanyScopeErrorCode =
  | "empty"
  | "tooLong"
  | "domainSpace"
  | "domainInvalid"
  | "ipInvalid"
  | "cidrInvalid"
  | "cidrPrefixV4"
  | "cidrPrefixV6";

export type CompanyScopeTextIssue = {
  line: number;
  rule?: CompanyScopeRule;
  error?: CompanyScopeErrorCode;
};

export type ParsedCompanyScopeText = {
  rules: CompanyScopeRule[];
  errors: Array<{ line: number; error: CompanyScopeErrorCode }>;
};

export const COMPANY_SCOPE_KINDS = new Set<CompanyScopeKind>(["domain", "ip", "cidr", "icp", "keyword"]);

export function isCompanyScopeKind(value: unknown): value is CompanyScopeKind {
  return typeof value === "string" && COMPANY_SCOPE_KINDS.has(value as CompanyScopeKind);
}

function isIPv4(value: string): boolean {
  const parts = value.split(".");
  return (
    parts.length === 4 && parts.every((part) => (part === "0" || /^[1-9]\d{0,2}$/.test(part)) && Number(part) <= 255)
  );
}

function isIPv6(value: string): boolean {
  if (!value.includes(":") || /[^0-9a-f:.]/i.test(value) || value.includes(":::")) return false;
  const halves = value.split("::");
  if (halves.length > 2) return false;
  const countSegments = (half: string): number | null => {
    if (!half) return 0;
    const segments = half.split(":");
    let count = 0;
    for (const [index, segment] of segments.entries()) {
      if (segment.includes(".")) {
        if (index !== segments.length - 1 || !isIPv4(segment)) return null;
        count += 2;
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(segment)) return null;
        count++;
      }
    }
    return count;
  };
  const left = countSegments(halves[0]);
  const right = countSegments(halves[1] ?? "");
  if (left === null || right === null) return false;
  return halves.length === 2 ? left + right < 8 : left === 8;
}

function ipVersion(value: string): 4 | 6 | null {
  if (isIPv4(value)) return 4;
  if (isIPv6(value)) return 6;
  return null;
}

function looksLikeIPAddress(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.includes("://") || /\s/.test(trimmed)) return false;
  if ((trimmed.match(/:/g) ?? []).length >= 2) {
    const parts = trimmed.split(":");
    let validSegments = 0;
    for (const part of parts) {
      if (!part) {
        if (validSegments > 0 || trimmed.startsWith("::")) return true;
        continue;
      }
      if (part.length > 4 || !/^[0-9a-f]+$/i.test(part)) return false;
      validSegments++;
      if (validSegments >= 2) return true;
    }
    return false;
  }
  return trimmed.includes(".") && /^[0-9.]+$/.test(trimmed);
}

function domainHostname(value: string): string | null {
  try {
    let candidate = value;
    if (value.startsWith("//")) candidate = `http:${value}`;
    else if (!value.includes("://")) candidate = `http://${value}`;
    const url = new URL(candidate);
    return (
      url.hostname
        .replace(/^\[|\]$/g, "")
        .replace(/\.$/, "")
        .toLowerCase() || null
    );
  } catch {
    return null;
  }
}

export function companyScopeRuleError(rule: CompanyScopeRule): CompanyScopeErrorCode | "" {
  const value = rule.value.trim();
  if (!value) return "empty";
  if (Array.from(value).length > MAX_COMPANY_SCOPE_VALUE_LENGTH) {
    return "tooLong";
  }
  if (rule.kind === "domain") {
    if (/\s/.test(value)) return "domainSpace";
    const hostname = domainHostname(value);
    if (!hostname || ipVersion(hostname) !== null) return "domainInvalid";
    const labels = hostname.split(".");
    if (
      hostname.length > 253 ||
      labels.length < 2 ||
      labels.some(
        (label) =>
          !label || label.length > 63 || label.startsWith("-") || label.endsWith("-") || !/^[a-z0-9-]+$/i.test(label),
      )
    ) {
      return "domainInvalid";
    }
  }
  if (rule.kind === "ip" && ipVersion(value) === null) return "ipInvalid";
  if (rule.kind === "cidr") {
    const separator = value.lastIndexOf("/");
    if (separator <= 0) return "cidrInvalid";
    const address = value.slice(0, separator);
    const prefixText = value.slice(separator + 1);
    const version = ipVersion(address);
    if (version === null || !/^\d+$/.test(prefixText)) return "cidrInvalid";
    const prefix = Number(prefixText);
    if (version === 4 && (prefix < 16 || prefix > 32)) return "cidrPrefixV4";
    if (version === 6 && (prefix < 32 || prefix > 128)) return "cidrPrefixV6";
  }
  return "";
}

// mock handler(React 밖) 전용: 오류 코드를 한국어 문구로 바꾼다. 실제 UI 는
// scope-text-editor 가 next-intl 의 t("scopeEditor.error.*") 로 지역화한다.
export function companyScopeErrorText(code: CompanyScopeErrorCode | "" | undefined): string {
  switch (code) {
    case "empty":
      return "범위 값을 입력해 주세요";
    case "tooLong":
      return `최대 ${MAX_COMPANY_SCOPE_VALUE_LENGTH}자까지 입력할 수 있습니다`;
    case "domainSpace":
      return "공백 없이 유효한 도메인 또는 URL을 입력해 주세요";
    case "domainInvalid":
      return "유효한 도메인 또는 URL을 입력해 주세요";
    case "ipInvalid":
      return "유효한 IP를 입력해 주세요";
    case "cidrInvalid":
      return "유효한 CIDR 대역을 입력해 주세요";
    case "cidrPrefixV4":
      return "IPv4 대역 프리픽스는 /16 ~ /32 범위여야 합니다";
    case "cidrPrefixV6":
      return "IPv6 대역 프리픽스는 /32 ~ /128 범위여야 합니다";
    default:
      return "";
  }
}

export function classifyCompanyScopeLine(
  raw: string,
  line: number,
  preservedRule?: CompanyScopeRule,
): CompanyScopeTextIssue {
  const value = raw.trim();
  if (Array.from(value).length > MAX_COMPANY_SCOPE_VALUE_LENGTH) {
    return { line, error: "tooLong" };
  }
  if (preservedRule) {
    const rule = { kind: preservedRule.kind, value };
    const error = companyScopeRuleError(rule);
    return error ? { line, error } : { line, rule };
  }

  const separator = value.lastIndexOf("/");
  if (
    separator > 0 &&
    (ipVersion(value.slice(0, separator)) !== null || looksLikeIPAddress(value.slice(0, separator)))
  ) {
    const rule: CompanyScopeRule = { kind: "cidr", value };
    const error = companyScopeRuleError(rule);
    return error ? { line, error } : { line, rule };
  }
  if (ipVersion(value) !== null) return { line, rule: { kind: "ip", value } };
  if (looksLikeIPAddress(value)) return { line, error: "ipInvalid" };

  const looksLikeDomain = value.includes("://") || (!/\s/.test(value) && value.includes("."));
  if (looksLikeDomain) {
    const hostname = domainHostname(value);
    if (hostname && ipVersion(hostname) !== null) return { line, rule: { kind: "ip", value: hostname } };
    const rule: CompanyScopeRule = { kind: "domain", value };
    const error = companyScopeRuleError(rule);
    return error ? { line, error } : { line, rule };
  }
  if (/icp|备案/i.test(value)) return { line, rule: { kind: "icp", value } };
  return { line, rule: { kind: "keyword", value } };
}

export function parseCompanyScopeText(
  value: string,
  options: { preservedRules?: CompanyScopeRule[] } = {},
): ParsedCompanyScopeText {
  const nonEmpty = value
    .split(/\r?\n/)
    .map((raw, index) => ({ raw, line: index + 1 }))
    .filter(({ raw }) => raw.trim());
  const preserved = new Map<string, CompanyScopeRule[]>();
  for (const rule of options.preservedRules ?? []) {
    const key = rule.value.trim();
    preserved.set(key, [...(preserved.get(key) ?? []), rule]);
  }
  const issues = nonEmpty.map(({ raw, line }) => {
    const key = raw.trim();
    const queue = preserved.get(key);
    const preservedRule = queue?.shift();
    return classifyCompanyScopeLine(raw, line, preservedRule);
  });
  return {
    rules: issues.flatMap((item) => (item.rule ? [item.rule] : [])),
    errors: issues.flatMap((item) => (item.error ? [{ line: item.line, error: item.error }] : [])),
  };
}

export function normalizeCompanyScopeValue(rule: CompanyScopeRule): string {
  const value = rule.value.trim();
  if (rule.kind === "domain") return domainHostname(value) ?? value.toLowerCase();
  if (rule.kind === "icp") return value.toLowerCase().replace(/\s/gu, "");
  if (rule.kind === "keyword") return value.toLowerCase().split(/\s+/u).filter(Boolean).join(" ");
  return value.toLowerCase();
}
