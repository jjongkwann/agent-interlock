import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { summarizeSecurityStatistics } from "../app/analytics.mjs";

// Cross-language golden contract: Python (agent_interlock.analytics) and this
// Studio port must reduce the shared fixture to byte-identical JSON. See
// `schemas/security-statistics.schema.json` and `tests/test_analytics.py`.
const fixturesRoot = new URL("../../schemas/fixtures/", import.meta.url);

function sortKeysDeep(value) {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (value && typeof value === "object") {
    const sorted = {};
    for (const key of Object.keys(value).sort()) sorted[key] = sortKeysDeep(value[key]);
    return sorted;
  }
  return value;
}

test("summarizeSecurityStatistics matches the Python golden fixture byte-for-byte", async () => {
  const events = JSON.parse(await readFile(new URL("analytics-events.json", fixturesRoot), "utf8"));
  const golden = await readFile(new URL("analytics-statistics.json", fixturesRoot), "utf8");

  const produced = JSON.stringify(sortKeysDeep(summarizeSecurityStatistics(events)), null, 2) + "\n";
  assert.equal(produced, golden);
});

test("summarizeSecurityStatistics on an empty event list matches Python parity", () => {
  assert.deepEqual(summarizeSecurityStatistics([]), {
    apiVersion: "interlock.dev/v1alpha1",
    kind: "SecurityStatistics",
    interactionCount: 0,
    partitions: [],
  });
});
