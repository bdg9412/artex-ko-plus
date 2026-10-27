import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

// Source-level regression tests for the Go provider wiring. The Go toolchain is
// not part of the verification image, so these assert the committed wiring
// literals (provider id, display name, origins, defaults, schema, UI copy)
// instead of compiling the package. Behavioural tests for the catalog/client
// live in orcarouter-catalog.test.mjs and orcarouter-client.test.mjs.

const read = (path) => readFileSync(new URL(`../../../${path}`, import.meta.url), "utf8");

const provider = read("agent/provider.go");
const orcarouter = read("agent/orcarouter.go");
const schema = read("db/schema.sql");
const types = read("web/src/lib/types.ts");
const page = read("web/src/app/(main)/system/llm/page.tsx");
const ko = JSON.parse(read("web/messages/ko.json"));
const zh = JSON.parse(read("web/messages/zh.json"));

test("the Go provider is registered as its own named format", () => {
  assert.match(orcarouter, /OrcaRouterProviderID\s+=\s+"orcarouter"/);
  assert.match(orcarouter, /OrcaRouterDisplayName\s+=\s+"OrcaRouter Cyber Inference"/);
  assert.match(orcarouter, /OrcaRouterAPIBase\s+=\s+"https:\/\/api\.orcarouter\.ai\/v1"/);
  assert.match(orcarouter, /OrcaRouterDefaultModel\s+=\s+"orcarouter\/auto"/);
  // The provider switch has a dedicated case in both configuration paths.
  assert.equal((provider.match(/case "orcarouter":/g) ?? []).length, 2);
  assert.match(provider, /func \(c Config\) IsOrcaRouter\(\) bool/);
});

test("the persisted profile format accepts orcarouter without touching other formats", () => {
  const checks = (schema.match(/format IN \([^)]*\)/g) ?? []).filter((check) => check.includes("'openai'"));
  assert.ok(checks.length >= 2, "expected both llm_profiles format constraints");
  for (const check of checks) assert.ok(check.includes("'orcarouter'"), check);
  // Existing formats stay allowed: the CHECK is widened, not replaced.
  for (const format of ["'openai'", "'anthropic'", "'ollama'", "'bedrock'"]) {
    assert.ok(checks[0].includes(format), `lost existing format ${format}`);
  }
  assert.match(types, /"orcarouter"/);
  assert.match(types, /format:\s*"openai" \| "anthropic"/);
});

test("the UI offers the provider and its own default endpoint/model", () => {
  assert.match(page, /<SelectItem value="orcarouter">/);
  assert.match(page, /const isOrcaRouter = format === "orcarouter"/);
  assert.match(page, /setBaseUrl\(ORCAROUTER_API_BASE\)/);
  assert.match(page, /setModel\(ORCAROUTER_DEFAULT_MODEL\)/);
  assert.match(page, /"sk-orca-…"/);
  // Free-text model entry is replaced by the discovery-backed picker.
  assert.match(page, /<OrcaRouterModelPicker/);
});

test("both locales name the provider and keep parity", () => {
  assert.equal(ko.llmPage.profile.format.orcarouter, "OrcaRouter Cyber Inference");
  assert.equal(zh.llmPage.profile.format.orcarouter, "orcaRouter Cyber Inference".replace("orcaRouter", "OrcaRouter"));
  const flat = (value, prefix = "") =>
    Object.entries(value).flatMap(([key, item]) =>
      item && typeof item === "object" ? flat(item, `${prefix}${key}.`) : [`${prefix}${key}`],
    );
  assert.deepEqual(flat(ko).sort(), flat(zh).sort());
  assert.match(page, /t\("profile\.format\.orcarouter"\)/);
});
