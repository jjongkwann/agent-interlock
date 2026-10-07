import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { matchesEdge, matchesGlob } from "../app/runtime.ts";

test("dynamic selectors match the shared Python fnmatchcase fixture", async () => {
  const cases = JSON.parse(await readFile(new URL("../../tests/fixtures/runtime-glob.json", import.meta.url), "utf8"));
  for (const item of cases) assert.equal(matchesGlob(item.value, item.pattern), item.matches, JSON.stringify(item));
  const edge = { id: "e", source: "coordinator", target: "template", relationship: "DELEGATES", relationshipId: "REL-06", dynamic: true, targetSelector: { idPattern: "worker.[a-c]?" } };
  const observation = { source: "coordinator", target: "worker.b7", relationship: "DELEGATES", relationshipId: "REL-06" };
  assert.equal(matchesEdge(edge, observation), true);
  assert.equal(matchesEdge(edge, { ...observation, target: "template-1" }), false);
  assert.equal(matchesEdge(edge, { ...observation, relationshipId: "REL-05" }), false);
});
