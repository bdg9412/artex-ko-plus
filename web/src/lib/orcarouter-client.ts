// OrcaRouter Cyber Inference wire client.
//
// Inference and model discovery go to the API origin only; credential issuance
// lives on the auth origin and is never derived from the API origin (see
// docs/ORCAROUTER_PROVIDER_KO.md). The API key stays on the server: this module
// is the shared request builder used by the Go backend's discovery endpoint and
// by the focused tests, and takes the key as an argument.
//
// Kept dependency-free (no relative imports) so node's type-stripping test
// runner can import it directly.

export const ORCAROUTER_CLIENT_API_BASE = "https://api.orcarouter.ai/v1";

export interface CompletionResult {
  model: string;
  content: string;
}

function apiBase(baseURL?: string): string {
  return (baseURL?.trim() || ORCAROUTER_CLIENT_API_BASE).replace(/\/+$/, "");
}

function authHeaders(apiKey: string): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/json" };
  const key = apiKey.trim();
  // A key with header-breaking characters is never forwarded.
  if (key && !/[\r\n]/.test(key)) headers.Authorization = `Bearer ${key}`;
  return headers;
}

// catalogURL is the authoritative discovery endpoint for one origin.
export function catalogURL(baseURL?: string, capability = "chat"): string {
  return `${apiBase(baseURL)}/models?capability=${encodeURIComponent(capability)}`;
}

// requestCatalog performs the authoritative discovery call:
// GET {base}/models?capability=chat.
export async function requestCatalog(
  apiKey: string,
  baseURL: string = ORCAROUTER_CLIENT_API_BASE,
  fetchImpl: typeof fetch = fetch,
): Promise<unknown> {
  const response = await fetchImpl(catalogURL(baseURL, "chat"), {
    method: "GET",
    headers: authHeaders(apiKey),
  });
  if (!response.ok) {
    throw new Error(`orcarouter catalog request failed: ${response.status}`);
  }
  return response.json();
}

// requestCompletion performs one real chat completion through the OrcaRouter
// API origin using the OpenAI wire format.
export async function requestCompletion(
  apiKey: string,
  model: string,
  prompt: string,
  baseURL: string = ORCAROUTER_CLIENT_API_BASE,
  fetchImpl: typeof fetch = fetch,
): Promise<CompletionResult> {
  const response = await fetchImpl(`${apiBase(baseURL)}/chat/completions`, {
    method: "POST",
    headers: { ...authHeaders(apiKey), "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: prompt }],
      max_tokens: 32,
    }),
  });
  if (!response.ok) {
    throw new Error(`orcarouter completion failed: ${response.status}`);
  }
  const body = (await response.json()) as {
    model?: string;
    choices?: { message?: { content?: string } }[];
  };
  return {
    model: body.model ?? model,
    content: body.choices?.[0]?.message?.content ?? "",
  };
}
