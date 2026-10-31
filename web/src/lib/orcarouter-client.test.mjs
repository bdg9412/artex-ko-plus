import assert from "node:assert/strict";
import test from "node:test";

import {
  ORCAROUTER_CLIENT_API_BASE,
  catalogURL,
  requestCatalog,
  requestCompletion,
} from "./orcarouter-client.ts";

function fakeFetch(handler) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init);
  };
  impl.calls = calls;
  return impl;
}

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

test("discovery always targets the OrcaRouter API origin", () => {
  assert.equal(ORCAROUTER_CLIENT_API_BASE, "https://api.orcarouter.ai/v1");
  assert.equal(catalogURL(), "https://api.orcarouter.ai/v1/models?capability=chat");
  assert.equal(catalogURL("https://api.orcarouter.ai/v1///"), "https://api.orcarouter.ai/v1/models?capability=chat");
  // The auth origin is never used for inference or discovery.
  assert.ok(!catalogURL().includes("www.orcarouter.ai"));
});

test("requestCatalog sends a GET with the key in a header, never in the URL", async () => {
  const fetchImpl = fakeFetch(() => jsonResponse({ data: [{ id: "orcarouter/auto" }] }));
  const payload = await requestCatalog("sk-orca-test-key", "https://api.orcarouter.ai/v1", fetchImpl);
  assert.deepEqual(payload, { data: [{ id: "orcarouter/auto" }] });

  const [{ url, init }] = fetchImpl.calls;
  assert.equal(url, "https://api.orcarouter.ai/v1/models?capability=chat");
  assert.equal(init.method, "GET");
  assert.equal(init.headers.Authorization, "Bearer sk-orca-test-key");
  assert.equal(init.body, undefined);
  assert.ok(!url.includes("sk-orca-test-key"));
});

test("requestCatalog fails closed on an error status", async () => {
  const fetchImpl = fakeFetch(() => jsonResponse({ error: "unauthorized" }, 401));
  await assert.rejects(() => requestCatalog("sk-orca-bad", undefined, fetchImpl), /catalog request failed: 401/);
});

test("requestCompletion uses the OpenAI chat-completions wire format", async () => {
  const fetchImpl = fakeFetch(() =>
    jsonResponse({ model: "orcarouter/auto", choices: [{ message: { content: "OK" } }] }),
  );
  const result = await requestCompletion(
    "sk-orca-test-key",
    "orcarouter/auto",
    "reply with OK",
    "https://api.orcarouter.ai/v1",
    fetchImpl,
  );
  assert.deepEqual(result, { model: "orcarouter/auto", content: "OK" });

  const [{ url, init }] = fetchImpl.calls;
  assert.equal(url, "https://api.orcarouter.ai/v1/chat/completions");
  assert.equal(init.method, "POST");
  assert.equal(init.headers["Content-Type"], "application/json");
  assert.equal(init.headers.Authorization, "Bearer sk-orca-test-key");
  const body = JSON.parse(init.body);
  assert.equal(body.model, "orcarouter/auto");
  assert.deepEqual(body.messages, [{ role: "user", content: "reply with OK" }]);
  assert.equal(body.max_tokens, 32);
});

test("requestCompletion falls back to the requested model and empty content", async () => {
  const fetchImpl = fakeFetch(() => jsonResponse({}));
  const result = await requestCompletion("sk-orca-test-key", "orcarouter/fusion", "hi", undefined, fetchImpl);
  assert.deepEqual(result, { model: "orcarouter/fusion", content: "" });
});

test("requestCompletion fails closed on an error status", async () => {
  const fetchImpl = fakeFetch(() => jsonResponse({ error: "payment required" }, 402));
  await assert.rejects(
    () => requestCompletion("sk-orca-test-key", "orcarouter/auto", "hi", undefined, fetchImpl),
    /completion failed: 402/,
  );
});

test("a header-breaking key is never forwarded", async () => {
  const fetchImpl = fakeFetch(() => jsonResponse({ data: [] }));
  await requestCatalog("sk-orca-key\r\nX-Injected: 1", undefined, fetchImpl);
  assert.equal(fetchImpl.calls[0].init.headers.Authorization, undefined);
});
