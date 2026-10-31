import { http } from "@/lib/api";
import type { InvestigationCollection, InvestigationMapping, InvestigationScope } from "@/lib/investigation-api";

export interface HuntingRequest {
  term: string;
  research_urls?: string[];
  source_id: string;
  expected_source_revision: number;
  scope: InvestigationScope;
  mapping: InvestigationMapping;
  sourcetypes: string[];
}

export interface HuntingTrendReport {
  topic_key: string;
  term: string;
  title: string;
  summary: string;
  reason: string;
  priority: "high" | "medium" | "review";
  kind: "kev" | "news";
  vendor?: string;
  product?: string;
  published_at: string;
  references: { source: string; url: string; title: string }[];
  asset_matches?: HuntingTrendAssetMatch[];
  asset_match_count?: number;
}

export interface HuntingTrendAssetMatch {
  asset_id: string;
  label: string;
  target?: string;
  observed: string;
  basis: "kev_product" | "headline_technology";
  last_seen: string;
}

export interface HuntingTrendInventory {
  scanned_assets: number;
  truncated: boolean;
  available: boolean;
}

export interface HuntingTrendCollection {
  last_attempt: string | null;
  last_success: string | null;
  last_error: string;
  busy: boolean;
}

export interface HuntingResearchSource {
  id: string;
  url: string;
  title: string;
  excerpt: string;
  sha256: string;
  fetched_at: string;
}

export interface HuntingStage {
  id: string;
  attack_description: string;
  detection_question: string;
  required_fields: string[] | null;
  success_criteria: string;
  benign_alternatives: string[] | null;
  source_ids: string[] | null;
  event_kinds?: string[] | null;
  path_contains?: string[] | null;
  depends_on?: string[] | null;
}

export interface HuntingStageAssessment {
  stage_id: string;
  status: string;
  summary: string;
  evidence_refs: string[] | null;
  known_verification_refs: string[] | null;
  missing_fields: string[] | null;
  reasons: string[] | null;
  alternatives: string[] | null;
  next_steps: string[] | null;
  rejected_observations: number;
}

export interface HuntingEvent {
  sequence: number;
  stage: string;
  kind: string;
  summary: string;
  detail?: string;
  payload?: unknown;
  at: string;
}

export interface HuntingStoredEvent {
  sequence: number;
  kind: string;
  payload: unknown;
  created_at: string;
}

export interface HuntingResult {
  engine_version: string;
  status: string;
  stage: string;
  started_at: string;
  finished_at: string;
  research: {
    term: string;
    summary: string;
    cves: string[] | null;
    sources: HuntingResearchSource[] | null;
    claims: { text: string; source_ids: string[] | null }[] | null;
    warnings: string[] | null;
  };
  design: { title: string; summary: string; stages: HuntingStage[] | null };
  investigation: {
    status: string;
    summary: string;
    observations:
      | {
          stage_id: string;
          kind: string;
          summary: string;
          evidence_refs: string[] | null;
          alternatives: string[] | null;
          next_steps: string[] | null;
        }[]
      | null;
    collections: InvestigationCollection[] | null;
    usage: {
      rounds: number;
      model_calls: number;
      queries: number;
      remote_queries: number;
      input_tokens: number;
      output_tokens: number;
    };
    gaps: string[] | null;
    next_steps: string[] | null;
  };
  verification: {
    status: string;
    summary: string;
    stages: HuntingStageAssessment[] | null;
    warnings: string[] | null;
    impact_confirmed: boolean;
  };
  events: HuntingEvent[] | null;
  error?: string;
}

export interface HuntingRun {
  id: string;
  status: string;
  request: HuntingRequest;
  result: HuntingResult | null;
  events: HuntingStoredEvent[] | null;
  error: string;
  created_at: string;
  updated_at: string;
}

export interface HuntingRunSummary {
  id: string;
  status: string;
  term?: string;
  request?: HuntingRequest;
  error?: string;
  created_at: string;
  updated_at: string;
}

const path = "/defensive/hunts";
const runPath = (id: string) => `${path}/${encodeURIComponent(id)}`;

export const huntingApi = {
  trends: () =>
    http<{ reports: HuntingTrendReport[]; collection: HuntingTrendCollection; inventory: HuntingTrendInventory }>(
      `${path}/trends`,
      {
        cache: "no-store",
      },
    ),
  collectTrends: () => http<{ started: boolean }>(`${path}/trends/collect`, { method: "POST" }),
  list: () => http<{ hunts: HuntingRunSummary[]; history_truncated?: boolean }>(path, { cache: "no-store" }),
  get: (id: string, signal?: AbortSignal) => http<HuntingRun>(runPath(id), { cache: "no-store", signal }),
  create: (request: HuntingRequest & { scope_confirmed: true }) =>
    http<HuntingRun>(path, { method: "POST", body: JSON.stringify(request) }),
  cancel: (id: string) => http<HuntingRun>(`${runPath(id)}/cancel`, { method: "POST" }),
  export: (id: string) => http<Blob>(`${runPath(id)}/export`, undefined, "blob"),
};

export function huntingRunActive(status: string) {
  return ["queued", "running", "researching", "designing", "investigating", "verifying"].includes(status);
}

const STATUS_LABELS: Record<string, string> = {
  queued: "대기 중",
  running: "실행 중",
  researching: "자료 조사 중",
  designing: "공격 가설·탐지 질문 설계 중",
  investigating: "Splunk 근거 조사 중",
  verifying: "근거 검증 중",
  completed: "조사 실행 완료",
  insufficient_data: "자료 부족",
  budget_exhausted: "실행 한도 도달",
  cancelled: "사용자 중지",
  interrupted: "실행 중단",
  model_error: "모델 연결 오류",
  failed: "실행 실패",
};

export const huntingStatusLabel = (status: string) => STATUS_LABELS[status] ?? status;
