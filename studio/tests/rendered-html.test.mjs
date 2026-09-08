import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";
import { computeRuntimeDiff, parseRuntimeTelemetry } from "../app/runtime.ts";

const templateRoot = new URL("../", import.meta.url);
const previewRoot = new URL("../app/_sites-preview/", import.meta.url);

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the Agent Interlock Studio", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>Agent Interlock · Security Architecture Studio<\/title>/i);
  assert.match(html, /Agent Interlock/);
  assert.match(html, /Security Architecture Studio/);
  assert.match(html, /Export manifest/);
  assert.doesNotMatch(html, /Your site is taking shape|react-loading-skeleton|Codex is working/i);
});

test("exports the backend architecture contract and removes starter artifacts", async () => {
  const [page, panels, layout, packageJson, manifest] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/panels.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../app/manifest.ts", import.meta.url), "utf8"),
  ]);

  // The manifest <-> Studio-state translation (export and import) lives in the pure
  // studio/app/manifest.ts module so studio/tests/manifest-roundtrip.test.mjs can exercise it
  // without React; page.tsx just calls into it.
  assert.match(manifest, /apiVersion: "interlock\.dev\/v1alpha1"/);
  assert.match(manifest, /enforcementPoint: control\.point/);
  assert.match(manifest, /targetSelector:/);
  assert.match(manifest, /trustZone: node\.trustZone/);
  assert.match(manifest, /trustZoneId: node\.trustZoneId/);
  assert.match(manifest, /trustZones: manifestZones/);
  assert.match(manifest, /trustBoundaries: manifestBoundaries/);
  assert.match(manifest, /orchestration: manifestOrchestration/);
  assert.match(page, /definitionDigest/);
  assert.match(page, /allowedDomains/);
  // The canvas must be able to say what an Actor holds. exportManifest hard-coded `dataAccess: []`
  // for every node, and the CLI's ARCH-DATA-CLASS-EXCEEDS-ACTOR rule skips an empty grant, so no
  // Studio-authored graph was covered by that CRITICAL rule at all. Three halves of the fix:
  // the export carries the real value, the inspector can edit it, and Studio raises the same
  // "cannot evaluate" finding the linter does rather than reporting the draft clean.
  assert.match(manifest, /dataAccess: node\.dataAccess \?\? \[\]/);
  assert.doesNotMatch(manifest, /dataAccess: \[\],\n/);
  assert.match(page, /Data access<input/);
  assert.match(page, /Target actor declares no data access/);
  assert.match(page, /Runtime graph/);
  assert.match(page, /label: "Runs"/);
  assert.match(page, /Import telemetry/);
  assert.match(page, /interlock\.control\.evaluated/);
  assert.match(page, /stdio-process-sandbox/);
  assert.match(page, /"SANDBOX"/);
  assert.match(page, /Remove actor/);
  assert.match(page, /Remove relationship/);
  assert.match(page, /ACTOR_NODE_WIDTH/);
  assert.match(page, /boardSize\.width - ACTOR_NODE_WIDTH/);
  assert.match(page, /Connected relationships will also be removed/);
  assert.match(page, />Fit</);
  assert.match(page, />Focus</);
  assert.match(page, />Undo</);
  assert.match(page, />Reset draft</);
  assert.match(page, /runtimeResultCount/);
  assert.match(page, /mobile-panel-actions/);
  assert.match(page, /const MIN_ZOOM = 0\.3/);
  assert.match(page, /aria-label="Require human approval"/);
  assert.match(page, /event\.code === "Equal"/);
  assert.match(page, /event\.code === "Minus"/);
  assert.match(page, /event\.metaKey \|\| event\.ctrlKey/);
  assert.match(page, /addEventListener\("wheel", onGraphWheel, \{ passive: false \}\)/);
  assert.match(page, /event\.preventDefault\(\)/);
  assert.match(page, /Mouse wheel or Command\/Ctrl \+ wheel/);
  assert.match(page, /Cross-zone edges must bind a directional Trust Boundary/);
  assert.match(page, /assignSelectedNodeToZone/);
  assert.match(page, /Add trust zone/);
  assert.match(page, /Fit around actors/);
  assert.match(page, /Move into zone/);
  assert.match(page, /Resize zone: \$\{zone\.label\}/);
  assert.match(page, /Actor topology/);
  assert.match(page, /Task workflow/);
  assert.match(page, /Create matching boundary/);
  assert.match(page, /workflow task added/);
  assert.match(page, /workflowDependencyCreatesCycle/);
  assert.match(page, /Unavailable because it would create a workflow cycle/);
  assert.match(page, /\["USER", "AGENT", "SUBAGENT", "RAG", "TOOL", "MEMORY", "SCHEDULER", "EXTERNAL"\]/);
  assert.match(panels, /Design does not become runtime directly/);
  assert.match(panels, /Telemetry cannot be aggregated/);
  assert.match(panels, /Sign approval context/);
  assert.match(panels, /Deployment-bound workflow runs/);
  assert.match(panels, /Start run/);
  assert.match(panels, /\/v1\/runs/);
  assert.match(panels, /WAITING_APPROVAL/);
  assert.match(panels, /missing adapters fail closed/);
  assert.match(page, /controlPlaneToken/);
  assert.doesNotMatch(panels, /localStorage|sessionStorage/);
  assert.doesNotMatch(page, /demoRuntimeTelemetry|Load drift demo/);
  assert.doesNotMatch(panels, /fake adapter|fake run/i);
  assert.match(page, /— undeclared/);
  assert.match(page, /Compare design with runtime to find undeclared/);
  assert.match(layout, /Agent Interlock · Security Architecture Studio/);
  assert.match(packageJson, /"name": "agent-interlock-studio"/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);

  await assert.rejects(access(previewRoot));
  await assert.rejects(access(new URL("public/_sites-preview", templateRoot)));
});

test("normalizes OTLP security context and computes runtime drift", async () => {
  const telemetry = JSON.parse(await readFile(new URL("../../examples/runtime_drift_otlp.json", import.meta.url), "utf8"));
  const imported = parseRuntimeTelemetry(telemetry);
  assert.equal(imported.format, "OTLP_JSON");
  assert.equal(imported.observations.length, 3);
  assert.equal(imported.observations.filter((item) => item.controlEvaluated).length, 2);
  assert.deepEqual(imported.issues, []);

  const diff = computeRuntimeDiff([
    { id: "edge.support-research", source: "agent.support", target: "agent.research", relationship: "DELEGATES", relationshipId: "REL-06", dynamic: true },
    { id: "edge.support-email-tool", source: "agent.support", target: "tool.send-email", relationship: "INVOKES", relationshipId: "REL-05", dynamic: false },
  ], imported.observations);
  assert.equal(diff.undeclared.length, 1);
  assert.deepEqual(diff.controlBypassInteractionIds, ["interaction-bypass-42"]);
});
