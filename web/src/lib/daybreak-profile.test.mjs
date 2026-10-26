import assert from "node:assert/strict";
import test from "node:test";

import { daybreakEditorState, daybreakRequestProgram } from "./daybreak-profile.ts";

test("new and legacy Responses profiles keep Daybreak off and omit the request field", () => {
  const editor = daybreakEditorState("openai-responses", "");
  assert.deepEqual(editor, { enabled: false, program: "daybreak_blue" });
  assert.equal(daybreakRequestProgram("openai-responses", editor.enabled, editor.program), "");
});

test("an explicit Blue selection survives save and reopen", () => {
  const saved = daybreakRequestProgram("openai-responses", true, "daybreak_blue");
  assert.equal(saved, "daybreak_blue");
  assert.deepEqual(daybreakEditorState("openai-responses", saved), {
    enabled: true,
    program: "daybreak_blue",
  });
});

test("Red and Standard selections restore on edit, and turning off clears them", () => {
  for (const program of ["daybreak_red", "standard"]) {
    const editor = daybreakEditorState("openai-responses", program);
    assert.deepEqual(editor, { enabled: true, program });
    assert.equal(daybreakRequestProgram("openai-responses", false, editor.program), "");
  }
});

test("switching away from Responses cannot send a cyber access program", () => {
  assert.deepEqual(daybreakEditorState("ollama", "daybreak_blue"), {
    enabled: false,
    program: "daybreak_blue",
  });
  assert.equal(daybreakRequestProgram("ollama", true, "daybreak_red"), "");
  assert.equal(daybreakRequestProgram("openai-responses", true, "unexpected"), "");
});
