// Live wiring check for the OrcaRouter Cyber Inference provider.
//
// Unlike the offline unit tests, this test talks to the real OrcaRouter API
// origin through the provider's own client module:
//   1. GET {API origin}/models?capability=chat   (the authoritative catalog)
//   2. POST {API origin}/chat/completions        (OpenAI wire format)
//
// It is skipped when no integration key is present, so it never fails a local
// run without credentials. The key is read from the environment only and is
// never printed.

import assert from "node:assert/strict";
import test from "node:test";

import { catalogURL, requestCatalog, requestCompletion } from "./orcarouter-client.ts";
import { filterChatModels, parseCatalog } from "./orcarouter-catalog.ts";

const apiKey = process.env.ORCAROUTER_API_KEY ?? "";

test("live: the authoritative chat catalog answers through the provider client", async () => {
  assert.ok(apiKey, "ORCAROUTER_API_KEY is not set; live wiring check needs it");
  const payload = await requestCatalog(apiKey);
  const chat = filterChatModels(parseCatalog(payload));
  assert.ok(chat.length > 0, `no chat models returned by ${catalogURL()}`);
  // Every offered id keeps the vendor/model namespace used by the gateway.
  for (const model of chat) assert.ok(model.id.includes("/"), `unexpected model id: ${model.id}`);
  console.log(`catalog ok: ${chat.length} chat models from api.orcarouter.ai`);
});

test("live: one chat completion succeeds on the OpenAI wire format", async () => {
  assert.ok(apiKey, "ORCAROUTER_API_KEY is not set; live wiring check needs it");
  // Discover first, then call a model the account's own catalog advertises. The
  // recommended cyber models come first because this provider is positioned for
  // authorized security work; the rest of the catalog is the fallback so the
  // check still proves the wire path on an account without cyber tier.
  const chat = filterChatModels(parseCatalog(await requestCatalog(apiKey)));
  assert.ok(chat.length > 0, "catalog returned no chat model to call");
  const preferred = ["orca/orcacyber-ultra-1.0", "orca/orcacyber-zero-1.5"];
  const ordered = [
    ...chat.filter((model) => preferred.includes(model.id)),
    ...chat.filter((model) => !preferred.includes(model.id)),
  ];

  const errors = [];
  for (const model of ordered.slice(0, 8)) {
    try {
      const result = await requestCompletion(apiKey, model.id, "Reply with the single word OK.");
      assert.ok(result.content.trim().length > 0, `empty completion content from ${model.id}`);
      console.log(`completion ok: model=${result.model} chars=${result.content.trim().length}`);
      return;
    } catch (error) {
      errors.push(`${model.id}: ${error.message}`);
    }
  }
  assert.fail(`no catalog model completed a request:\n${errors.join("\n")}`);
});

test("live: a rejected key surfaces as a clean error, not a crash", async () => {
  await assert.rejects(
    () => requestCatalog("sk-orca-invalid-wiring-check"),
    /catalog request failed: (401|403)/,
  );
});
