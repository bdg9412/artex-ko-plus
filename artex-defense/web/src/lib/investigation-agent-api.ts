import { http } from "@/lib/api";
import type { InvestigationCollection, InvestigationScope } from "@/lib/investigation-api";

export type InvestigationAgentStatus =
  | "queued"
  | "running"
  | "completed"
  | "insufficient_data"
  | "budget_exhausted"
  | "cancelled"
  | "model_error"
  | "interrupted";

export interface InvestigationAgentUsage {
  model_calls: number;
  queries: number;
  input_tokens: number;
  output_tokens: number;
  reserved_tokens?: number;
}

export interface InvestigationAgentIntent {
  id: string;
  round: number;
  hypothesis: string;
  objective: string;
  reason: string;
  evidence_refs: string[] | null;
  state: string;
}

export interface InvestigationAgentObservation {
  id: string;
  intent_id: string;
  kind: "observed" | "inferred" | "insufficient_data";
  summary: string;
  evidence_refs: string[] | null;
  alternatives: string[] | null;
  next_steps: string[] | null;
  known_artex: boolean;
}

export interface InvestigationAgentDecision {
  round: number;
  action: string;
  reason: string;
  evidence_refs: string[] | null;
}

export interface InvestigationAgentProgress {
  at: string;
  stage: string;
  round: number;
  kind: string;
  tool?: string;
  summary: string;
  detail?: string;
  is_error?: boolean;
  usage?: InvestigationAgentUsage;
  evidence_refs?: string[] | null;
  intent?: InvestigationAgentIntent;
  observation?: InvestigationAgentObservation;
  decision?: InvestigationAgentDecision;
}

export interface InvestigationAgentSearch {
  scope: InvestigationScope;
  source_ip?: string;
  user?: string;
  session?: string;
  event_kind?: string;
  path_contains?: string;
  remote: boolean;
  offset?: number;
}

export interface InvestigationAgentReport {
  version: string;
  status: InvestigationAgentStatus;
  summary: string;
  started_at: string;
  finished_at: string;
  scope: InvestigationScope;
  budget: {
    max_rounds: number;
    max_model_calls: number;
    max_queries: number;
    max_tokens: number;
    timeout_seconds: number;
  };
  usage: InvestigationAgentUsage;
  decisions: InvestigationAgentDecision[] | null;
  intents: InvestigationAgentIntent[] | null;
  observations: InvestigationAgentObservation[] | null;
  gaps: string[] | null;
  next_steps: string[] | null;
  trace: InvestigationAgentProgress[] | null;
  searches: InvestigationAgentSearch[] | null;
  collections: InvestigationCollection[] | null;
}

export interface InvestigationAgentRunEvent {
  sequence: number;
  kind: string;
  payload: InvestigationAgentProgress | { search: InvestigationAgentSearch; collection: InvestigationCollection };
  created_at: string;
}

export interface InvestigationAgentRunSummary {
  id: string;
  finding_id: string;
  investigation_id: string;
  status: InvestigationAgentStatus;
  usage: InvestigationAgentUsage;
  error: string;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  updated_at: string;
}

export interface InvestigationAgentRun extends InvestigationAgentRunSummary {
  options: { question: string; model?: string; profile?: string; remote_enabled?: boolean };
  events: InvestigationAgentRunEvent[] | null;
  result: InvestigationAgentReport | null;
}

const path = (findingId: string, investigationId: string) =>
  `/exploration/findings/${encodeURIComponent(findingId)}/investigations/${encodeURIComponent(investigationId)}/agent-runs`;

export const investigationAgentApi = {
  list: (findingId: string, investigationId: string) =>
    http<{ runs: InvestigationAgentRunSummary[]; history_truncated?: boolean }>(path(findingId, investigationId)),
  get: (findingId: string, investigationId: string, runId: string) =>
    http<InvestigationAgentRun>(`${path(findingId, investigationId)}/${encodeURIComponent(runId)}`),
  create: (findingId: string, investigationId: string, input: { question: string }) =>
    http<InvestigationAgentRun>(path(findingId, investigationId), {
      method: "POST",
      body: JSON.stringify(input),
    }),
  cancel: (findingId: string, investigationId: string, runId: string) =>
    http<InvestigationAgentRun>(`${path(findingId, investigationId)}/${encodeURIComponent(runId)}/cancel`, {
      method: "POST",
    }),
  export: (findingId: string, investigationId: string, runId: string) =>
    http<Blob>(`${path(findingId, investigationId)}/${encodeURIComponent(runId)}/export`, undefined, "blob"),
};
