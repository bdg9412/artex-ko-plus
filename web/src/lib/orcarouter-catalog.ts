// OrcaRouter Cyber Inference catalog helpers.
//
// The model list is never hand-written: the single source of truth is
// GET {base}/models?capability=chat on the configured OrcaRouter origin. The
// small verified seed below only keeps a fresh install usable when that call
// fails, and its entries keep the metadata the UI relies on (context window,
// input modalities, reasoning ladder). See docs/ORCAROUTER_PROVIDER_KO.md.

export const ORCAROUTER_PROVIDER_ID = "orcarouter";
export const ORCAROUTER_DISPLAY_NAME = "OrcaRouter Cyber Inference";
export const ORCAROUTER_API_BASE = "https://api.orcarouter.ai/v1";
export const ORCAROUTER_AUTH_BASE = "https://www.orcarouter.ai";
export const ORCAROUTER_CYBER_PAGE = "https://www.orcarouter.ai/cyber";
export const ORCAROUTER_CYBER_MODELS = "https://www.orcarouter.ai/models?tier=cyber";
export const ORCAROUTER_DEFAULT_MODEL = "orcarouter/auto";
export const ORCAROUTER_FALLBACK_MODEL = "orcarouter/fusion";

// Recommended dedicated cyber models for verified security teams. They are
// surfaced as recommendations; they are not the default because access is
// gated behind business verification on the OrcaRouter side.
export const ORCAROUTER_CYBER_MODELS_RECOMMENDED = [
  {
    id: "orcacyber-ultra-1.0",
    label: "OrcaCyber Ultra — security code scanning, multi-step reasoning over large codebases",
  },
  { id: "orcacyber-zero-1.5", label: "OrcaCyber Zero — OrcaCyber harness driven agentic security work" },
] as const;

export interface ModelCapabilities {
  // Endpoint families the model advertises. Text entries must offer at least
  // one of these; anything else (image/video/rerank only) is not a chat model.
  endpointTypes: string[];
  // Input modalities declared by the catalog. Absent metadata fails closed.
  inputModalities: string[];
  contextLength?: number;
  reasoningEfforts?: string[];
}

export interface CatalogModel {
  id: string;
  name?: string;
  capabilities: ModelCapabilities;
}

export type CatalogSource = "live" | "seed";

export interface CatalogResult {
  models: CatalogModel[];
  source: CatalogSource;
  // Set when live discovery failed and the verified seed was used instead.
  degraded: boolean;
  error?: string;
}

const TEXT_ENDPOINT_TYPES = ["openai", "anthropic", "gemini", "openai-response"];
const NON_TEXT_ONLY_TYPES = ["image-generation", "openai-video", "jina-rerank", "embeddings"];

// Verified outage fallback. Kept intentionally small, with the metadata the
// repository already uses (context window + multimodal + reasoning ladder).
export const ORCAROUTER_SEED_MODELS: CatalogModel[] = [
  {
    id: "openai/gpt-5.5",
    capabilities: {
      endpointTypes: ["openai", "openai-response"],
      inputModalities: ["text", "image"],
      contextLength: 400000,
      reasoningEfforts: ["low", "medium", "high", "xhigh"],
    },
  },
  {
    id: "anthropic/claude-opus-4.8",
    capabilities: {
      endpointTypes: ["anthropic"],
      inputModalities: ["text", "image"],
      contextLength: 200000,
    },
  },
  {
    id: "google/gemini-3.5-flash",
    capabilities: {
      endpointTypes: ["gemini", "openai"],
      inputModalities: ["text", "image"],
      contextLength: 1000000,
    },
  },
  {
    id: "deepseek/deepseek-v4-pro",
    capabilities: {
      endpointTypes: ["openai", "anthropic"],
      inputModalities: ["text"],
      contextLength: 128000,
    },
  },
  {
    id: ORCAROUTER_DEFAULT_MODEL,
    capabilities: {
      endpointTypes: ["openai", "anthropic", "gemini", "openai-response"],
      inputModalities: ["text", "image"],
      contextLength: 200000,
    },
  },
];

// downloadModelsURL returns the authoritative discovery URL for one origin.
export function downloadModelsURL(baseURL?: string, capability = "chat"): string {
  const base = (baseURL?.trim() || ORCAROUTER_API_BASE).replace(/\/+$/, "");
  return `${base}/models?capability=${capability}`;
}

// modelsRequestHeaders builds the request headers. The key stays server-side;
// this helper exists so both the Go server and the tests use one shape.
export function modelsRequestHeaders(apiKey?: string): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const key = apiKey?.trim();
  if (key && !/[\r\n]/.test(key)) headers.Authorization = `Bearer ${key}`;
  return headers;
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

// parseCatalogRecord normalizes one catalog record. Unknown shapes are dropped
// rather than guessed at, so a malformed entry can never masquerade as a model.
export function parseCatalogRecord(raw: unknown): CatalogModel | null {
  if (!raw || typeof raw !== "object") return null;
  const record = raw as Record<string, unknown>;
  const id = typeof record.id === "string" ? record.id.trim() : "";
  if (!id || /\s/.test(id)) return null;
  const architecture =
    record.architecture && typeof record.architecture === "object"
      ? (record.architecture as Record<string, unknown>)
      : {};
  const supported = asStrings(record.supported_endpoint_types);
  // The catalog sometimes only carries endpoint_capabilities; map the families
  // we understand instead of storing a free-form string.
  const endpointCapabilities = asStrings(record.endpoint_capabilities);
  const endpointTypes = supported.length > 0 ? supported : endpointCapabilityTypes(endpointCapabilities);
  const efforts = asStrings((record.supported_parameters as Record<string, unknown> | undefined)?.reasoning_effort);
  return {
    id,
    name: typeof record.name === "string" ? record.name : undefined,
    capabilities: {
      endpointTypes,
      inputModalities: asStrings(architecture.input_modalities),
      contextLength:
        typeof record.context_length === "number" && record.context_length > 0 ? record.context_length : undefined,
      reasoningEfforts: efforts.length > 0 ? efforts : undefined,
    },
  };
}

function endpointCapabilityTypes(capabilities: string[]): string[] {
  const mapped = new Set<string>();
  for (const capability of capabilities) {
    switch (capability) {
      case "chat_completions":
        mapped.add("openai");
        break;
      case "openai_responses":
        mapped.add("openai-response");
        break;
      case "anthropic_messages":
        mapped.add("anthropic");
        break;
      case "gemini_generate_content":
        mapped.add("gemini");
        break;
      default:
        break;
    }
  }
  return [...mapped];
}

export function parseCatalog(payload: unknown): CatalogModel[] {
  const data =
    payload && typeof payload === "object" && Array.isArray((payload as { data?: unknown }).data)
      ? (payload as { data: unknown[] }).data
      : [];
  const out: CatalogModel[] = [];
  const seen = new Set<string>();
  for (const raw of data) {
    const model = parseCatalogRecord(raw);
    if (!model || seen.has(model.id)) continue;
    seen.add(model.id);
    out.push(model);
  }
  return out;
}

// isChatModel excludes models that only serve non-text routes (image
// generation, video, rerank, embeddings) even when they appear in a chat-tagged
// catalog page.
export function isChatModel(model: CatalogModel): boolean {
  const types = model.capabilities.endpointTypes;
  if (types.length === 0) return false;
  const speaksText = types.some((type) => TEXT_ENDPOINT_TYPES.includes(type));
  if (!speaksText) return false;
  return !types.every((type) => NON_TEXT_ONLY_TYPES.includes(type));
}

// filterChatModels returns the options bound to a text-only model selector.
// Unsupported records fail closed; nothing is inferred from the model name.
export function filterChatModels(models: CatalogModel[]): CatalogModel[] {
  return models.filter(isChatModel);
}

// filterMultimodalModels narrows a chat catalog to models that explicitly
// declare the uploaded modality. Undeclared capability = excluded.
export function filterMultimodalModels(models: CatalogModel[], modality: "image" | "audio" | "video"): CatalogModel[] {
  return filterChatModels(models).filter((model) => model.capabilities.inputModalities.includes(modality));
}

export interface SelectorOptions {
  models: CatalogModel[];
  ids: string[];
  source: CatalogSource;
  degraded: boolean;
  error?: string;
}

// buildSelectorOptions is the single place that decides what the model selector
// may show: live catalog when the request succeeded, otherwise the verified
// seed, clearly flagged as degraded.
export function buildSelectorOptions(result: CatalogResult, modality?: "image" | "audio" | "video"): SelectorOptions {
  const source = result.source === "live" ? result.models : ORCAROUTER_SEED_MODELS;
  const models = modality ? filterMultimodalModels(source, modality) : filterChatModels(source);
  return {
    models,
    ids: models.map((model) => model.id),
    source: result.source,
    degraded: result.degraded,
    error: result.error,
  };
}

// reconcileSelection clears a previously chosen model that is no longer
// compatible, so the selector can never silently keep a stale value.
export function reconcileSelection(current: string, options: SelectorOptions): string {
  if (!current) return current;
  if (options.ids.includes(current)) return current;
  if (options.source === "seed" && ORCAROUTER_SEED_MODELS.some((model) => model.id === current)) {
    // A degraded catalog may legitimately be narrower than the stored pick.
    return options.ids.includes(current) ? current : "";
  }
  return "";
}

// optionsFromIDs builds selector options from the backend's discovery response.
// The backend already applied the chat-capability filter on the authoritative
// catalog, so the client trusts exactly those IDs and never appends extras.
export function optionsFromIDs(ids: string[], state: { degraded?: boolean; error?: string } = {}): SelectorOptions {
  const unique = [...new Set(ids.map((id) => id.trim()).filter(Boolean))];
  const models: CatalogModel[] = unique.map((id) => ({
    id,
    capabilities: { endpointTypes: ["openai"], inputModalities: ["text"] },
  }));
  return {
    models,
    ids: unique,
    source: state.degraded ? "seed" : "live",
    degraded: state.degraded === true,
    error: state.error,
  };
}

// catalogFromPayload turns an API response body into a CatalogResult.
export function catalogFromPayload(payload: unknown): CatalogResult {
  const models = parseCatalog(payload);
  if (models.length === 0) {
    return { models: ORCAROUTER_SEED_MODELS, source: "seed", degraded: true, error: "empty catalog" };
  }
  return { models, source: "live", degraded: false };
}

// fallbackCatalog is what the UI shows when the discovery request itself fails
// (auth error, network error, timeout).
export function fallbackCatalog(error: string): CatalogResult {
  return { models: ORCAROUTER_SEED_MODELS, source: "seed", degraded: true, error };
}

// redactAPIKey is the only key formatting the UI is allowed to show.
export function redactAPIKey(key: string): string {
  const trimmed = key.trim();
  if (trimmed.length < 8) return trimmed ? "…" : "";
  return `…${trimmed.slice(-4)}`;
}
