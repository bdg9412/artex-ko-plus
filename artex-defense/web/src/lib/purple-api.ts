import { http } from "@/lib/api";
import type { FindingStatus, Severity } from "@/lib/types";

export type DefenseState = "unplanned" | "untested" | "current" | "stale";
export type DetectionResult = "detected" | "missed" | "not_tested";
export type PreventionResult = "blocked" | "not_blocked" | "not_tested";
export type RuleFormat = "query" | "sigma" | "other" | "event_filter";

export interface DefensePlanFields {
  hypothesis: string;
  log_source: string;
  rule_format: RuleFormat;
  rule_text: string;
  remediation: string;
}

export interface DefensePlan extends DefensePlanFields {
  finding_id: string;
  revision: number;
  updated_at: string;
}

export interface DefenseValidation {
  id: string;
  finding_id: string;
  plan_revision: number;
  evidence_version: number;
  source_fingerprint: string;
  plan_snapshot: DefensePlan;
  detection: DetectionResult;
  prevention: PreventionResult;
  evidence: string;
  observed_at: string;
  notes: string;
  created_at: string;
}

export interface FindingDefense {
  source_fingerprint: string;
  plan: DefensePlan | null;
  evidence_version: number;
  validations: DefenseValidation[];
  state: DefenseState;
}

export interface DefenseValidationInput {
  expected_source_fingerprint: string;
  plan_revision: number;
  expected_evidence_version: number;
  detection: DetectionResult;
  prevention: PreventionResult;
  evidence: string;
  observed_at: string;
  notes: string;
}

export type ReplayVerdict = "pass" | "fail" | "inconclusive";
export type ReplayState = "current" | "stale";

export interface ReplayDatasetResult {
  total: number;
  matched: number;
  missed: number;
  inconclusive: number;
}

export interface DefenseReplay {
  id: string;
  finding_id: string;
  plan_revision: number;
  evidence_version: number;
  source_fingerprint: string;
  plan_snapshot: DefensePlan;
  rule_sha256: string;
  target_sha256: string;
  control_sha256: string;
  evaluator_version: string;
  evaluations_truncated: boolean;
  result: {
    engine: string;
    verdict: ReplayVerdict;
    target: ReplayDatasetResult;
    control: ReplayDatasetResult;
    reasons: string[];
    evaluations: {
      dataset: "target" | "control";
      line: number;
      outcome: "match" | "no_match" | "inconclusive";
      missing_fields: string[];
    }[];
  };
  notes: string;
  created_at: string;
  state: ReplayState;
}

export interface DefenseReplayInput {
  plan_revision: number;
  expected_evidence_version: number;
  expected_source_fingerprint: string;
  target_logs: string;
  control_logs: string;
  notes: string;
}

export interface PurpleOverview {
  stats: {
    total_findings: number;
    planned: number;
    validated: number;
    needs_revalidation: number;
    detected: number;
    missed: number;
    blocked: number;
    replayed: number;
    replay_passed: number;
    replay_needs_revalidation: number;
    execution_total: number;
    execution_detected: number;
    execution_missed: number;
    execution_blocked: number;
    execution_inconclusive: number;
  };
  items: {
    finding_id: string;
    name: string;
    vulnclass: string;
    severity: Severity;
    finding_status: FindingStatus;
    state: DefenseState;
    plan_revision: number;
    detection: DetectionResult;
    prevention: PreventionResult;
    updated_at: string;
    replay_state: "none" | ReplayState;
    replay_verdict: "" | ReplayVerdict;
    execution_id?: string;
    execution_state: "none" | "current" | "stale";
    execution_status?: "pending" | "running" | "completed" | "failed" | "stopped";
    execution_detection?: "detected" | "missed" | "inconclusive";
    execution_prevention?: "blocked" | "not_blocked" | "inconclusive";
  }[];
  total: number;
  page: number;
  limit: number;
}

const defensePath = (id: string) => `/exploration/findings/${encodeURIComponent(id)}/defense`;

export const purpleApi = {
  findingDefense: (id: string) => http<FindingDefense>(defensePath(id)),
  savePlan: (id: string, fields: DefensePlanFields, expectedRevision: number) =>
    http<FindingDefense>(defensePath(id), {
      method: "PUT",
      body: JSON.stringify({ ...fields, expected_revision: expectedRevision }),
    }),
  recordValidation: (id: string, input: DefenseValidationInput) =>
    http<FindingDefense>(`${defensePath(id)}/validations`, {
      method: "POST",
      body: JSON.stringify(input),
    }),
  replays: (id: string) => http<{ runs: DefenseReplay[] }>(`${defensePath(id)}/replays`),
  replay: (id: string, input: DefenseReplayInput) =>
    http<DefenseReplay>(`${defensePath(id)}/replays`, {
      method: "POST",
      body: JSON.stringify(input),
    }),
  exportReplay: (id: string, runId: string) =>
    http<DefenseReplay & { target_logs: string; control_logs: string }>(
      `${defensePath(id)}/replays/${encodeURIComponent(runId)}/export`,
    ),
  overview: (page: number, limit: number) => http<PurpleOverview>(`/purple/overview?page=${page}&limit=${limit}`),
};
