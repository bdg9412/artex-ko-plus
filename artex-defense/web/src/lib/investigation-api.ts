import { http } from "@/lib/api";

export interface InvestigationScope {
  target: string;
  path_prefix: string;
  start: string;
  end: string;
}

export interface InvestigationMapping {
  timestamp: string;
  event_id: string;
  target: string;
  path: string;
  source_ip: string;
  user: string;
  session: string;
  action: string;
  status: string;
  bytes: string;
  verification_id: string;
  event_kind: string;
  response_complete: string;
}

export const DEFAULT_INVESTIGATION_MAPPING: InvestigationMapping = {
  timestamp: "timestamp",
  event_id: "id",
  target: "target",
  path: "path",
  source_ip: "source_ip",
  user: "user",
  session: "session",
  action: "action",
  status: "status",
  bytes: "bytes",
  verification_id: "artex_verification_id",
  event_kind: "event_kind",
  response_complete: "response_complete",
};

export interface InvestigationHypothesis {
  id: string;
  title: string;
  statement: string;
  preconditions: string[] | null;
  required_logs: string[] | null;
  required_fields: string[] | null;
  hunt: string;
  benign_alternatives: string[] | null;
  next_steps: string[] | null;
  references: { title: string; url: string }[] | null;
}

export interface InvestigationPlan {
  engine_version: string;
  method: string;
  family: string;
  summary: string;
  hypotheses: InvestigationHypothesis[] | null;
  limitations: string[] | null;
}

export interface InvestigationEvent {
  ref: string;
  id: string;
  timestamp: string;
  target: string;
  path: string;
  source_ip?: string;
  user?: string;
  session?: string;
  action?: string;
  status?: string;
  bytes?: number;
  verification_id?: string;
  known_artex: boolean;
  event_kind?: string;
  response_complete?: boolean;
  file_name: string;
  line: number;
  raw?: string;
}

export interface InvestigationCollection {
  source_kind: "file" | "splunk";
  collected_at: string;
  scope: InvestigationScope;
  mapping: InvestigationMapping;
  coverage_confirmed: boolean;
  target_scope_confirmed: boolean;
  events: InvestigationEvent[] | null;
  files: { name: string; sha256: string; bytes: number; rows: number; content?: string }[] | null;
  complete: boolean;
  warnings: string[] | null;
  stats: {
    total_rows: number;
    selected: number;
    outside_window: number;
    unrelated_target: number;
    unrelated_path: number;
    invalid_events: number;
    missing_target: number;
    known_artex: number;
    unrecognized_markers: number;
    truncated: number;
  };
  query?: string;
}

export interface InvestigationAnalysis {
  engine_version: string;
  summary: string;
  hypotheses:
    | {
        hypothesis_id: string;
        status: "observed" | "suspicious" | "not_observed" | "insufficient_data" | "manual_review";
        summary: string;
        evidence_refs: string[] | null;
        next_steps: string[] | null;
      }[]
    | null;
  timeline:
    | { timestamp: string; evidence_ref: string; event_id: string; summary: string; known_artex: boolean }[]
    | null;
  signals: { kind: string; key: string; summary: string; evidence_refs: string[] | null }[] | null;
  limitations: string[] | null;
  next_steps: string[] | null;
  observed_count: number;
  known_artex_count: number;
}

export interface InvestigationRecord {
  id: string;
  finding_id: string;
  title: string;
  question: string;
  source_kind: "file" | "splunk";
  source_id: string;
  source_revision: number;
  file_label?: string;
  scope: InvestigationScope;
  mapping: InvestigationMapping;
  plan: InvestigationPlan;
  finding_snapshot: Record<string, unknown>;
  collection: InvestigationCollection;
  analysis: InvestigationAnalysis;
  evidence_version: number;
  source_fingerprint: string;
  created_at: string;
  state: string;
}

export interface InvestigationSummary {
  id: string;
  title: string;
  source_kind: "file" | "splunk";
  created_at: string;
  summary: string;
  state: string;
}

export interface FindingInvestigations {
  plan: InvestigationPlan;
  targets: string[];
  recommended_path?: string;
  mapping?: InvestigationMapping;
  history_truncated?: boolean;
  evidence_version: number;
  source_fingerprint: string;
  investigations: InvestigationSummary[];
}

export interface InvestigationInput {
  title: string;
  question: string;
  scope: InvestigationScope;
  mapping: InvestigationMapping;
  source_kind: "file" | "splunk";
  file_label: string;
  files: { name: string; content: string }[];
  source_id: string;
  expected_source_revision: number;
  sourcetypes: string[];
  coverage_confirmed: boolean;
  target_scope_confirmed: boolean;
  expected_evidence_version: number;
  expected_source_fingerprint: string;
}

export interface InvestigationPreview {
  query: string;
  source_revision: number;
  limits: Record<string, number | string>;
}

const path = (findingId: string) => `/exploration/findings/${encodeURIComponent(findingId)}/investigations`;

export const investigationApi = {
  list: (findingId: string) => http<FindingInvestigations>(path(findingId)),
  get: (findingId: string, caseId: string) =>
    http<InvestigationRecord>(`${path(findingId)}/${encodeURIComponent(caseId)}`),
  create: (findingId: string, input: InvestigationInput) =>
    http<InvestigationRecord>(path(findingId), { method: "POST", body: JSON.stringify(input) }),
  preview: (findingId: string, input: InvestigationInput) =>
    http<InvestigationPreview>(`${path(findingId)}/preview`, { method: "POST", body: JSON.stringify(input) }),
  export: (findingId: string, caseId: string) =>
    http<Blob>(`${path(findingId)}/${encodeURIComponent(caseId)}/export`, undefined, "blob"),
};
