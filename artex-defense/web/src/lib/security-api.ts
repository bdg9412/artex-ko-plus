import { http } from "@/lib/api";
import type { DefensePlan } from "@/lib/purple-api";
import type { FindingRetest } from "@/lib/types";

export interface SecuritySourceConfig {
  base_url: string;
  index: string;
  audit_sourcetype: string;
  alert_sourcetype: string;
  correlation_field: string;
  action_field: string;
  tls_fingerprint: string;
}

export interface SecuritySource {
  id: string;
  name: string;
  revision: number;
  config: SecuritySourceConfig;
  enabled: boolean;
  credential_set: boolean;
  updated_at: string;
}

export interface SecuritySourceInput {
  name: string;
  config: SecuritySourceConfig;
  enabled: boolean;
  expected_revision: number;
  username?: string;
  password?: string;
  token?: string;
}

export interface DefenseFileConfig {
  label: string;
  timestamp_field: string;
  correlation_field: string;
  action_field: string;
  event_id_field: string;
}

export interface DefenseDiagnostic {
  code: string;
  certainty: "observed" | "hypothesis";
  message: string;
  recommendation: string;
  event_ids?: string[];
  file_name?: string;
  line?: number;
}

export interface DefenseFileUpload {
  audit_file: { name: string; content: string };
  alert_file?: { name: string; content: string };
  no_alerts: boolean;
  coverage_start: string;
  coverage_end: string;
  coverage_complete: boolean;
}

export interface DefenseUploadEvidence {
  config: DefenseFileConfig;
  files: { kind: "audit" | "alert"; name: string; sha256: string; bytes: number; rows: number; content?: string }[];
  coverage_complete: boolean;
  no_alerts: boolean;
  stats: {
    total_rows: number;
    matched: number;
    unrelated: number;
    outside_window: number;
    invalid_events: number;
    duplicate_events: number;
    truncated: number;
  };
}

export interface FileSourceSnapshot {
  kind: "file";
  name: string;
  config: DefenseFileConfig;
  revision: number;
}

export interface DefenseAssessment {
  id: string;
  execution_id: string;
  detection: "detected" | "missed" | "inconclusive";
  prevention: "blocked" | "not_blocked" | "inconclusive";
  reasons: string[];
  recommendations: string[];
  created_at: string;
  event_count: number;
  audit_count: number;
  alert_count: number;
  evidence_truncated: boolean;
  diagnostics?: DefenseDiagnostic[];
  evidence: {
    events: {
      id: string;
      kind: "audit" | "alert";
      correlation_id: string;
      occurred_at: string;
      action: "blocked" | "allowed" | "unknown";
      raw: Record<string, unknown> | null;
      file_name?: string;
      line?: number;
    }[];
    complete: boolean;
    collected_at: string;
    window_start: string;
    window_end: string;
    warnings: string[];
    upload?: DefenseUploadEvidence;
    diagnostics?: DefenseDiagnostic[];
  };
}

export interface DefenseExecution {
  id: string;
  finding_id: string;
  source_id: string;
  retest_id: number;
  correlation_id: string;
  source_revision: number;
  source_kind?: "file" | "splunk";
  source_snapshot: SecuritySource | FileSourceSnapshot;
  plan_snapshot: DefensePlan;
  evidence_version: number;
  source_fingerprint: string;
  baseline_id?: string;
  remediation_note: string;
  notes?: string;
  created_at: string;
  retest: FindingRetest;
  assessments: DefenseAssessment[];
  assessments_truncated: boolean;
  state: "current" | "stale";
}

export interface DefenseExecutionInput {
  source_id: string;
  source_kind: "file" | "splunk";
  file_config?: DefenseFileConfig;
  plan_revision: number;
  expected_evidence_version: number;
  expected_source_fingerprint: string;
  baseline_id?: string;
  remediation_note: string;
  notes: string;
}

export interface DefenseComparison {
  baseline: DefenseExecution;
  current: DefenseExecution;
  comparable: boolean;
  reasons: string[];
}

const executionPath = (id: string) => `/exploration/findings/${encodeURIComponent(id)}/defense/executions`;

export const securityApi = {
  sources: () => http<{ sources: SecuritySource[] }>("/purple/sources"),
  saveSource: (id: string | null, input: SecuritySourceInput) =>
    http<SecuritySource>(id ? `/purple/sources/${encodeURIComponent(id)}` : "/purple/sources", {
      method: id ? "PUT" : "POST",
      body: JSON.stringify(input),
    }),
  testSource: (id: string) =>
    http<{ ok: boolean; detail: string }>(`/purple/sources/${encodeURIComponent(id)}/test`, { method: "POST" }),
  executions: (id: string) => http<{ executions: DefenseExecution[] }>(executionPath(id)),
  startExecution: (id: string, input: DefenseExecutionInput) =>
    http<{ execution: DefenseExecution; retest: FindingRetest; created: boolean }>(executionPath(id), {
      method: "POST",
      body: JSON.stringify(input),
    }),
  collect: (id: string, executionId: string) =>
    http<DefenseAssessment>(`${executionPath(id)}/${encodeURIComponent(executionId)}/collect`, { method: "POST" }),
  upload: (id: string, executionId: string, input: DefenseFileUpload) =>
    http<DefenseAssessment>(`${executionPath(id)}/${encodeURIComponent(executionId)}/upload`, {
      method: "POST",
      body: JSON.stringify(input),
    }),
  exportExecution: (id: string, executionId: string) =>
    http<Blob>(`${executionPath(id)}/${encodeURIComponent(executionId)}/export`, undefined, "blob"),
  compare: (id: string, baselineId: string, currentId: string) =>
    http<DefenseComparison>(
      `${executionPath(id)}/compare?baseline_id=${encodeURIComponent(baselineId)}&current_id=${encodeURIComponent(currentId)}`,
    ),
};

export function downloadSecurityJSON(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
