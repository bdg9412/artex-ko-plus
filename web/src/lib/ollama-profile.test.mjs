import { canKeepRemoteOllamaToken, isOllamaFormat, remoteOllamaOptions, remoteOllamaURL } from "./ollama-profile.ts";
import assert from "node:assert/strict";
import test from "node:test";

test("local and remote are distinct choices sharing Ollama behavior", () => {
  assert.equal(isOllamaFormat("ollama"), true);
  assert.equal(isOllamaFormat("ollama-remote"), true);
  assert.equal(isOllamaFormat("openai"), false);
  assert.deepEqual(remoteOllamaOptions(), {
    auth_mode: "none",
    max_concurrent: 1,
    queue_timeout_seconds: 120,
    request_timeout_seconds: 600,
  });
});

test("remote URLs normalize without introducing a localhost fallback", () => {
  for (const value of ["", "file:///tmp/x", "https://user:secret@model.example", "https://model.example?key=x"])
    assert.equal(remoteOllamaURL(value), null);
  assert.equal(remoteOllamaURL("http://MODEL-PC:11434/"), "http://model-pc:11434/v1");
  assert.equal(remoteOllamaURL("https://model.example/ollama/v1/chat/completions/"), "https://model.example/ollama/v1");
});

test("an existing token is reusable only for the same remote server", () => {
  const profile = {
    format: "ollama-remote",
    base_url: "https://one.example/v1",
    api_key_hint: "stored",
    ollama_remote: { auth_mode: "bearer" },
  };
  assert.equal(canKeepRemoteOllamaToken(profile, "https://one.example/v1/"), true);
  assert.equal(canKeepRemoteOllamaToken(profile, "https://two.example/v1"), false);
  assert.equal(canKeepRemoteOllamaToken({ ...profile, format: "openai" }, "https://one.example/v1"), false);
  assert.equal(
    canKeepRemoteOllamaToken({ ...profile, ollama_remote: { auth_mode: "none" } }, "https://one.example/v1"),
    false,
  );
});
