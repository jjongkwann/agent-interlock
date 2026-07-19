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
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /apiVersion: "interlock\.dev\/v1alpha1"/);
  assert.match(page, /enforcementPoint: control\.point/);
  assert.match(page, /targetSelector:/);
  assert.match(page, /definitionDigest/);
  assert.match(page, /allowedDomains/);
  assert.match(page, /Runtime graph/);
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
