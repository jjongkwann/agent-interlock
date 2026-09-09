import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { buildManifestPayload, emptyOrchestration, parseManifestPayload } from "../app/manifest.ts";

// A representative Studio graph: two zones, a directional boundary, a dynamic delegation edge
// (which round-trips through targetSelector.sameTenant), a static tool edge with two controls of
// different assurance, and a two-task workflow with a dependency. Exercises every field
// buildManifestPayload/parseManifestPayload carry.
function sampleSnapshot() {
  return {
    zones: [
      { id: "zone.control", label: "Control plane", kind: "INTERNAL", description: "Managed identities", x: 0, y: 0, width: 300, height: 300 },
      { id: "zone.worker", label: "Worker plane", kind: "INTERNAL", description: "Delegated agents", x: 400, y: 0, width: 300, height: 300 },
    ],
    boundaries: [
      { id: "boundary.control-worker", label: "Control to worker", sourceZoneId: "zone.control", targetZoneId: "zone.worker", point: "A2A_BROKER", allowedRelationships: ["DELEGATES"], allowedData: ["D2", "D3"], deniedData: ["D5"], mode: "ENFORCE", failureMode: "FAIL_CLOSED", requireIdentity: true, requireTenantBinding: true, maxPayloadBytes: 65536, description: "Delegation boundary" },
    ],
    nodes: [
      { id: "agent.coordinator", label: "Coordinator", type: "AGENT", owner: "Platform", identity: "spiffe://demo/coordinator", capabilities: ["DELEGATE"], dataAccess: ["D2", "D3"], tenantMode: "REQUIRED", maxDelegationDepth: 2, trustZone: "INTERNAL", trustZoneId: "zone.control", x: 40, y: 60 },
      { id: "agent.worker", label: "Worker", type: "SUBAGENT", owner: "Platform", identity: "spiffe://demo/worker", capabilities: ["RESEARCH"], dataAccess: ["D2"], tenantMode: "REQUIRED", maxDelegationDepth: 0, trustZone: "INTERNAL", trustZoneId: "zone.worker", x: 440, y: 60 },
      { id: "tool.lookup", label: "Lookup tool", type: "TOOL", owner: "Platform", identity: "spiffe://demo/lookup", capabilities: ["LOOKUP"], dataAccess: ["D2"], tenantMode: "REQUIRED", maxDelegationDepth: 0, trustZone: "INTERNAL", trustZoneId: "zone.control", definitionDigest: "sha256:" + "b".repeat(64), sideEffects: ["READ"], inputSchema: { type: "object", properties: { query: { type: "string" } } }, outputSchema: { type: "object", properties: { result: { type: "string" } } }, annotations: { readOnlyHint: true }, x: 40, y: 200 },
    ],
    edges: [
      { id: "edge.coordinator-worker", source: "agent.coordinator", target: "agent.worker", relationshipId: "REL-06", relationship: "DELEGATES", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D2", "D3"], allowedPurposes: ["RESEARCH_DELEGATION"], approvalRequired: false, dynamic: true, sameTenant: true, maxDepth: 1, boundaryId: "boundary.control-worker", controls: [
        { id: "delegation-binding", objective: "PREVENT", timing: "PRE_EXECUTION", point: "A2A_BROKER", assurance: "ENFORCED" },
        { id: "delegation-audit", objective: "EVIDENCE", timing: "POST_EXECUTION", point: "AUDIT_SINK", assurance: "OBSERVED" },
      ] },
      { id: "edge.coordinator-lookup", source: "agent.coordinator", target: "tool.lookup", relationshipId: "REL-05", relationship: "INVOKES", mode: "SHADOW", failureMode: "FAIL_CLOSED", allowedData: ["D2"], allowedPurposes: [], approvalRequired: true, dynamic: false, sameTenant: true, maxDepth: 0, maxExportRecords: 100, maxExportBytes: 1048576, volumeAction: "HOLD", secretAction: "BLOCK", destructiveWriteAction: "QUARANTINE", undeclaredSideEffectAction: "BLOCK", controls: [
        { id: "mcp-call-guard", objective: "PREVENT", timing: "PRE_EXECUTION", point: "MCP_GATEWAY", assurance: "DECLARED" },
      ] },
    ],
    orchestration: {
      coordinatorActorId: "agent.coordinator",
      pattern: "HYBRID",
      maxParallelism: 2,
      maxTasks: 10,
      maxDurationSeconds: 600,
      maxMessages: 40,
      failFast: true,
      tasks: [
        { id: "task.research", label: "Research", sourceActorId: "agent.coordinator", targetActorId: "agent.worker", transport: "A2A", purpose: "RESEARCH", dependsOn: [], dataClasses: ["D2"], acceptanceCriteria: ["Grounded"], maxAttempts: 2, timeoutSeconds: 90, approvalRequired: false, onFailure: "FAIL_WORKFLOW", x: 100, y: 150 },
        { id: "task.lookup", label: "Lookup", sourceActorId: "agent.coordinator", targetActorId: "tool.lookup", transport: "MCP", purpose: "LOOKUP", dependsOn: ["task.research"], dataClasses: ["D2"], acceptanceCriteria: [], maxAttempts: 1, timeoutSeconds: 30, approvalRequired: true, onFailure: "SKIP", x: 400, y: 150 },
      ],
    },
  };
}

const sampleProject = { id: "roundtrip-test", version: "0.3.1" };

test("opening an exported manifest and re-exporting it reproduces the same payload", () => {
  const exported = buildManifestPayload(sampleSnapshot(), sampleProject);

  const parsed = parseManifestPayload(exported);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.project, sampleProject);
  assert.equal(parsed.snapshot.nodes.length, 3);
  assert.equal(parsed.snapshot.edges.length, 2);
  assert.equal(parsed.snapshot.orchestration.tasks.length, 2);
  // The dynamic edge's sameTenant is not a first-class manifest field; it is recovered from
  // targetSelector.sameTenant on import.
  const delegationEdge = parsed.snapshot.edges.find((edge) => edge.id === "edge.coordinator-worker");
  assert.equal(delegationEdge.sameTenant, true);
  assert.equal(delegationEdge.maxDepth, 1);
  assert.deepEqual(delegationEdge.allowedPurposes, ["RESEARCH_DELEGATION"]);

  const lookupTool = parsed.snapshot.nodes.find((node) => node.id === "tool.lookup");
  assert.deepEqual(lookupTool.sideEffects, ["READ"]);
  assert.deepEqual(lookupTool.inputSchema, { type: "object", properties: { query: { type: "string" } } });
  assert.deepEqual(lookupTool.outputSchema, { type: "object", properties: { result: { type: "string" } } });
  assert.deepEqual(lookupTool.annotations, { readOnlyHint: true });

  const lookupEdge = parsed.snapshot.edges.find((edge) => edge.id === "edge.coordinator-lookup");
  assert.equal(lookupEdge.maxExportRecords, 100);
  assert.equal(lookupEdge.maxExportBytes, 1048576);
  assert.equal(lookupEdge.volumeAction, "HOLD");
  assert.equal(lookupEdge.secretAction, "BLOCK");
  assert.equal(lookupEdge.destructiveWriteAction, "QUARANTINE");
  assert.equal(lookupEdge.undeclaredSideEffectAction, "BLOCK");

  const reExported = buildManifestPayload(parsed.snapshot, parsed.project);
  assert.deepEqual(reExported, exported);
});

test("omits the orchestration key when there are no tasks and no coordinator", () => {
  const snapshot = sampleSnapshot();
  snapshot.orchestration = { ...emptyOrchestration };
  const exported = buildManifestPayload(snapshot, sampleProject);
  assert.equal("orchestration" in exported.spec, false);

  const parsed = parseManifestPayload(exported);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.snapshot.orchestration.tasks, []);
  assert.equal(parsed.snapshot.orchestration.coordinatorActorId, "");
});

test("preserves a node's declared sideEffects instead of the type-based heuristic", () => {
  const snapshot = sampleSnapshot();
  const tool = snapshot.nodes.find((node) => node.id === "tool.lookup");
  tool.sideEffects = ["DESTRUCTIVE_WRITE"];
  const exported = buildManifestPayload(snapshot, sampleProject);
  const exportedTool = exported.spec.nodes.find((node) => node.id === "tool.lookup");
  assert.deepEqual(exportedTool.sideEffects, ["DESTRUCTIVE_WRITE"]);
});

test("parses the compiler's reference manifest and preserves its positions and delegation depth", async () => {
  const raw = JSON.parse(await readFile(new URL("../../examples/secure_multi_agent_architecture.json", import.meta.url), "utf8"));
  const parsed = parseManifestPayload(raw);
  assert.equal(parsed.ok, true);
  assert.deepEqual(parsed.project, { id: "customer-support-multi-agent", version: "1.0.0" });
  assert.equal(parsed.snapshot.nodes.length, 7);
  assert.equal(parsed.snapshot.edges.length, 6);

  const support = parsed.snapshot.nodes.find((node) => node.id === "agent.support");
  assert.deepEqual({ x: support.x, y: support.y }, { x: 260, y: 120 });
  assert.equal(support.maxDelegationDepth, 2);

  const delegation = parsed.snapshot.edges.find((edge) => edge.id === "edge.support-research");
  assert.equal(delegation.dynamic, true);
  assert.equal(delegation.sameTenant, true);
  assert.equal(delegation.maxDepth, 2);

  const sendReply = parsed.snapshot.orchestration.tasks.find((task) => task.id === "task.send-reply");
  assert.deepEqual(sendReply.dependsOn, ["task.research"]);
  assert.equal(sendReply.approvalRequired, true);
});

test("assigns a grid position to nodes and tasks whose manifest omits one", () => {
  const manifest = {
    apiVersion: "interlock.dev/v1alpha1",
    kind: "Architecture",
    metadata: { id: "no-positions", version: "0.1.0" },
    spec: {
      trustZones: [{ id: "zone.a", label: "Zone A", kind: "INTERNAL", description: "", bounds: { x: 0, y: 0, width: 200, height: 200 } }],
      nodes: [
        { id: "agent.one", type: "AGENT", owner: "team", identity: "spiffe://demo/one", trustZoneId: "zone.a" },
        { id: "agent.two", type: "AGENT", owner: "team", identity: "spiffe://demo/two", trustZoneId: "zone.a" },
      ],
      edges: [
        { id: "edge.one-two", relationshipId: "REL-06", source: "agent.one", target: "agent.two", relationship: "DELEGATES", policy: { mode: "SHADOW" }, controls: [{ id: "c1", objective: "PREVENT", timing: "PRE_EXECUTION", enforcementPoint: "A2A_BROKER", assurance: "DECLARED" }] },
      ],
      orchestration: {
        coordinatorActorId: "agent.one",
        pattern: "HYBRID",
        tasks: [
          { id: "task.one", label: "One", sourceActorId: "agent.one", targetActorId: "agent.two", transport: "A2A", purpose: "WORK" },
        ],
      },
    },
  };

  const parsed = parseManifestPayload(manifest);
  assert.equal(parsed.ok, true);
  for (const node of parsed.snapshot.nodes) {
    assert.equal(typeof node.x, "number");
    assert.equal(typeof node.y, "number");
  }
  assert.notDeepEqual(
    { x: parsed.snapshot.nodes[0].x, y: parsed.snapshot.nodes[0].y },
    { x: parsed.snapshot.nodes[1].x, y: parsed.snapshot.nodes[1].y },
  );
  const [task] = parsed.snapshot.orchestration.tasks;
  assert.equal(typeof task.x, "number");
  assert.equal(typeof task.y, "number");
});

test("rejects JSON that is not an Architecture manifest", () => {
  assert.equal(parseManifestPayload({ kind: "Something else" }).ok, false);
  assert.equal(parseManifestPayload({ kind: "Architecture" }).ok, false); // no spec
  assert.equal(parseManifestPayload(null).ok, false);
  assert.equal(parseManifestPayload("not an object").ok, false);
  const result = parseManifestPayload({ kind: "Deployment", spec: {} });
  assert.equal(result.ok, false);
  assert.match(result.error, /Architecture manifest/);
});
