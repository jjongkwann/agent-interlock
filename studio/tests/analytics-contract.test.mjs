import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { ledgerEventsForStatistics, summarizeSecurityStatistics } from "../app/analytics.mjs";
import { demoRuntimeTelemetry } from "../app/runtime.ts";

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

test("ledgerEventsForStatistics accepts a bare array and an events wrapper", () => {
  const events = [{ event_type: "INTERACTION_REQUESTED" }];
  assert.deepEqual(ledgerEventsForStatistics(events), events);
  assert.deepEqual(ledgerEventsForStatistics({ events }), events);
  assert.equal(ledgerEventsForStatistics({ resourceSpans: [] }), null);
});

test("statistics sorting follows Unicode code-point order like Python", () => {
  const event = (interaction_id, source_actor_id) => ({
    event_type: "INTERACTION_REQUESTED",
    occurred_at: "2026-07-19T12:00:00Z",
    tenant_id: "tenant-a",
    environment: "DEV",
    data_source: "PRODUCTION",
    interaction_id,
    source_actor_id,
    target_actor_id: "tool.test",
    relationship_id: "REL-05",
    payload: {},
  });
  const summary = summarizeSecurityStatistics([
    event("ia-supplementary", "\u{10000}"),
    event("ia-bmp", "\ue000"),
  ]);
  assert.deepEqual(summary.partitions[0].byActor.map((item) => item.sourceActorId), ["\ue000", "\u{10000}"]);
});

test("the built-in drift demo is also valid Statistics telemetry", () => {
  const summary = summarizeSecurityStatistics(demoRuntimeTelemetry);
  assert.equal(summary.interactionCount, 3);
  assert.equal(summary.partitions[0].dataSource, "DEMO");
  assert.equal(summary.partitions[0].counters.partialOrBypassCount, 1);
});
