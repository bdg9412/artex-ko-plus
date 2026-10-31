import type { LLMProfile, OllamaRemoteOptions } from "./types";

export const isOllamaFormat = (format: string) => format === "ollama" || format === "ollama-remote";

export function remoteOllamaOptions(stored?: OllamaRemoteOptions): Required<OllamaRemoteOptions> {
  return {
    auth_mode: stored?.auth_mode || "none",
    max_concurrent: stored?.max_concurrent || 1,
    queue_timeout_seconds: stored?.queue_timeout_seconds || 120,
    request_timeout_seconds: stored?.request_timeout_seconds || 600,
  };
}

export function remoteOllamaURL(value: string): string | null {
  try {
    const url = new URL(value.trim());
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash)
      return null;
    const path = url.pathname.replace(/\/+$/, "").replace(/\/chat\/completions$/, "");
    url.pathname = path.endsWith("/v1") ? path : `${path}/v1`;
    return url.toString();
  } catch {
    return null;
  }
}

export function canKeepRemoteOllamaToken(profile: LLMProfile | null, url: string): boolean {
  return (
    !!profile &&
    profile.format === "ollama-remote" &&
    profile.ollama_remote?.auth_mode === "bearer" &&
    !!profile.api_key_hint &&
    remoteOllamaURL(url) !== null &&
    remoteOllamaURL(url) === remoteOllamaURL(profile.base_url ?? "")
  );
}
