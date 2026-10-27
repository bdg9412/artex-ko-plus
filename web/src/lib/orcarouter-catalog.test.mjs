import assert from "node:assert/strict";
import test from "node:test";

import {
  ORCAROUTER_API_BASE,
  ORCAROUTER_DEFAULT_MODEL,
  ORCAROUTER_DISPLAY_NAME,
  ORCAROUTER_PROVIDER_ID,
  ORCAROUTER_SEED_MODELS,
  buildSelectorOptions,
  catalogFromPayload,
  downloadModelsURL,
  fallbackCatalog,
  filterChatModels,
  filterMultimodalModels,
  modelsRequestHeaders,
  optionsFromIDs,
  parseCatalog,
  parseCatalogRecord,
  reconcileSelection,
  redactAPIKey,
} from "./orcarouter-catalog.ts";

// Realistic catalog records, shaped like GET https://api.orcarouter.ai/v1/models.
const textOnly = {
  id: "deepseek/deepseek-v4-pro",
  supported_endpoint_types: ["openai", "anthropic"],
  architecture: { input_modalities: ["text"] },
  context_length: 128000,
};
const imageInput = {
  id: "deepseek/deepseek-v4-flash-vision-exp",
  supported_endpoint_types: ["openai", "openai-response"],
  architecture: { input_modalities: ["text", "image"] },
  context_length: 1048576,
};
const embeddingOnly = {
  id: "vendor/text-embedding-3",
  supported_endpoint_types: ["embeddings"],
  architecture: { input_modalities: ["text"] },
};
const imageGeneration = {
  id: "vendor/flux-pro",
  supported_endpoint_types: ["image-generation"],
  architecture: { input_modalities: [] },
};
const videoGeneration = {
  id: "vendor/video-1",
  supported_endpoint_types: ["openai-video"],
  architecture: { input_modalities: [] },
};
const rerank = {
  id: "vendor/jina-reranker",
  supported_endpoint_types: ["jina-rerank"],
  architecture: { input_modalities: [] },
};
const autoRouter = {
  id: "orcarouter/auto",
  supported_endpoint_types: ["openai", "anthropic", "gemini", "openai-response"],
  architecture: { input_modalities: ["text", "image"] },
  context_length: 200000,
};

const catalog = { data: [textOnly, imageInput, embeddingOnly, imageGeneration, videoGeneration, rerank, autoRouter] };

test("the provider is a named first-class entry with its own identity and origin", () => {
  assert.equal(ORCAROUTER_PROVIDER_ID, "orcarouter");
  assert.equal(ORCAROUTER_DISPLAY_NAME, "OrcaRouter Cyber Inference");
  assert.equal(ORCAROUTER_API_BASE, "https://api.orcarouter.ai/v1");
  // Discovery must ask the configured origin, not a hardcoded competitor URL.
  assert.equal(downloadModelsURL(), "https://api.orcarouter.ai/v1/models?capability=chat");
  assert.equal(
    downloadModelsURL("https://self-hosted.example/v1/"),
    "https://self-hosted.example/v1/models?capability=chat",
  );
});

test("API-key handling keeps the key out of URLs and rejects header-breaking input", () => {
  assert.deepEqual(modelsRequestHeaders(""), { Accept: "application/json" });
  assert.deepEqual(modelsRequestHeaders("sk-orca-test1234"), {
    Accept: "application/json",
    Authorization: "Bearer sk-orca-test1234",
  });
  // A newline would let a stored value inject a second header; it is dropped.
  assert.equal(modelsRequestHeaders("sk-orca-test\r\nX-Evil: 1").Authorization, undefined);
  assert.equal(redactAPIKey("sk-orca-abcdefgh"), "…efgh");
  assert.equal(redactAPIKey(""), "");
});

test("catalog parsing keeps vendor/model namespace and drops malformed records", () => {
  const models = parseCatalog(catalog);
  assert.deepEqual(
    models.map((model) => model.id),
    [
      "deepseek/deepseek-v4-pro",
      "deepseek/deepseek-v4-flash-vision-exp",
      "vendor/text-embedding-3",
      "vendor/flux-pro",
      "vendor/video-1",
      "vendor/jina-reranker",
      "orcarouter/auto",
    ],
  );
  assert.equal(models[0].capabilities.contextLength, 128000);
  assert.deepEqual(models[1].capabilities.inputModalities, ["text", "image"]);
  assert.equal(parseCatalogRecord({ id: "bad id" }), null);
  assert.equal(parseCatalogRecord({ id: "" }), null);
  assert.equal(parseCatalogRecord(null), null);
  // Duplicates never reach the selector twice.
  assert.equal(parseCatalog({ data: [textOnly, textOnly] }).length, 1);
});

test("text selector options exclude non-chat models and undeclared capabilities fail closed", () => {
  const ids = filterChatModels(parseCatalog(catalog)).map((model) => model.id);
  assert.deepEqual(ids, [
    "deepseek/deepseek-v4-pro",
    "deepseek/deepseek-v4-flash-vision-exp",
    "orcarouter/auto",
  ]);
  assert.ok(!ids.includes("vendor/flux-pro"));
  assert.ok(!ids.includes("vendor/video-1"));
  assert.ok(!ids.includes("vendor/jina-reranker"));
  assert.ok(!ids.includes("vendor/text-embedding-3"));
  // A model with no declared endpoint family is not guessed into the list.
  assert.equal(filterChatModels([{ id: "vendor/mystery", capabilities: { endpointTypes: [], inputModalities: [] } }]).length, 0);
});

test("multimodal options keep only chat models that declare image input", () => {
  const ids = filterMultimodalModels(parseCatalog(catalog), "image").map((model) => model.id);
  assert.deepEqual(ids, ["deepseek/deepseek-v4-flash-vision-exp", "orcarouter/auto"]);
});

test("a live catalog is authoritative and is never mixed with the seed", () => {
  const result = catalogFromPayload(catalog);
  assert.equal(result.source, "live");
  assert.equal(result.degraded, false);
  const options = buildSelectorOptions(result);
  assert.deepEqual(options.ids, [
    "deepseek/deepseek-v4-pro",
    "deepseek/deepseek-v4-flash-vision-exp",
    "orcarouter/auto",
  ]);
  // Nothing from the seed appears when discovery succeeded.
  assert.ok(!options.ids.includes("openai/gpt-5.5"));
  assert.equal(options.source, "live");
});

test("outage and error paths fall back only to the verified seed, flagged degraded", () => {
  const empty = catalogFromPayload({ data: [] });
  assert.equal(empty.source, "seed");
  assert.equal(empty.degraded, true);
  const failed = fallbackCatalog("catalog request failed: 503");
  assert.equal(failed.degraded, true);
  assert.equal(failed.error, "catalog request failed: 503");
  const options = buildSelectorOptions(failed);
  assert.equal(options.degraded, true);
  assert.equal(options.source, "seed");
  assert.deepEqual(options.ids, ORCAROUTER_SEED_MODELS.map((model) => model.id));
  // The seed keeps the metadata the UI relies on.
  const gpt55 = ORCAROUTER_SEED_MODELS.find((model) => model.id === "openai/gpt-5.5");
  assert.deepEqual(gpt55.capabilities.reasoningEfforts, ["low", "medium", "high", "xhigh"]);
  assert.ok(gpt55.capabilities.inputModalities.includes("image"));
  assert.equal(ORCAROUTER_SEED_MODELS[ORCAROUTER_SEED_MODELS.length - 1].id, ORCAROUTER_DEFAULT_MODEL);
});

test("backend discovery results bind straight into the selector options", () => {
  const options = optionsFromIDs(["orcarouter/auto", " orca/orcacyber-ultra-1.0 ", "orcarouter/auto"]);
  assert.deepEqual(options.ids, ["orcarouter/auto", "orca/orcacyber-ultra-1.0"]);
  assert.equal(options.source, "live");
  assert.equal(options.degraded, false);
  const degraded = optionsFromIDs([], { degraded: true, error: "no key" });
  assert.deepEqual(degraded.ids, []);
  assert.equal(degraded.degraded, true);
});

test("a stale selection is cleared when it leaves the compatible list", () => {
  const options = optionsFromIDs(["deepseek/deepseek-v4-flash-vision-exp"]);
  assert.equal(reconcileSelection("deepseek/deepseek-v4-flash-vision-exp", options), "deepseek/deepseek-v4-flash-vision-exp");
  assert.equal(reconcileSelection("deepseek/deepseek-v4-pro", options), "");
  // Regression: other providers' free-text selections are untouched because they
  // never go through this helper (the OrcaRouter picker is the only caller).
  assert.equal(reconcileSelection("", options), "");
});
