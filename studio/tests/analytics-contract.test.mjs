import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { checkCatalogue, coverageDeclarations, ledgerEventsForStatistics, summarizeSecurityStatistics } from "../app/analytics.mjs";

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

test("a declaration whose body contradicts its digest takes the digest down with it", async () => {
  // Mirrors UntrustedDeclarationTests in tests/test_control_coverage.py. The golden fixture cannot
  // cover this -- it holds no forged declaration -- so the port needs its own, or the two sides
  // could diverge on untrusted input with the byte-parity test still green.
  const events = JSON.parse(await readFile(new URL("analytics-events.json", fixturesRoot), "utf8"));
  const legit = events.find((event) => event.event_type === "CONTROL_COVERAGE_DECLARED");
  const digest = legit.payload.coverage.profileDigest;
  assert.ok(coverageDeclarations(events).has(digest));

  const forged = JSON.parse(JSON.stringify(legit));
  forged.event_id = "evt-forged";
  forged.occurred_at = forged.ingested_at = "2026-07-19T00:00:00Z";
  forged.payload.coverage.evaluated = legit.payload.coverage.armed.map((entry) => entry.id).sort();
  assert.equal(coverageDeclarations([forged, ...events]).has(digest), false);

  // A restart re-declares the same body; that is a no-op, not a conflict.
  assert.ok(coverageDeclarations([legit, ...events]).has(digest));
});

test("a bare string where a list belongs is one id, not one per character", () => {
  const declared = {
    event_type: "CONTROL_COVERAGE_DECLARED",
    payload: { coverage: { profileDigest: "sha256:x", armed: [{ id: "CHECK-A", scope: "PAIR" }], evaluated: "CHECK-A" } },
  };
  const catalogue = checkCatalogue(coverageDeclarations([declared]));
  assert.deepEqual([...catalogue.keys()], ["CHECK-A"]);
});

test("the test-only drift fixture is also valid Statistics telemetry", async () => {
  const fixture = JSON.parse(await readFile(new URL("fixtures/drift-demo.json", import.meta.url), "utf8"));
  const summary = summarizeSecurityStatistics(fixture);
  assert.equal(summary.interactionCount, 3);
  assert.equal(summary.partitions[0].dataSource, "DEMO");
  assert.equal(summary.partitions[0].counters.partialOrBypassCount, 1);
});
