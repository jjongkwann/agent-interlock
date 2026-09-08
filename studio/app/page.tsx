"use client";

import { ChangeEvent, PointerEvent as ReactPointerEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  computeRuntimeDiff,
  matchesEdge,
  parseRuntimeTelemetry,
  type RuntimeImport,
} from "./runtime";
import { DeployPanel, RunsPanel, StatsPanel } from "./panels";
import { ledgerEventsForStatistics } from "./analytics.mjs";
import {
  buildManifestPayload,
  emptyOrchestration,
  EMPTY_PROJECT,
  isValidProjectId,
  parseManifestPayload,
  parseSavedProjects,
  PROJECTS_STORAGE_KEY,
  STARTER_PROJECT,
  type Assurance,
  type ArchitectureEdge,
  type ArchitectureNode,
  type ArchitectureSnapshot,
  type Control,
  type EnforcementPoint,
  type Mode,
  type NodeType,
  type OrchestrationDesign,
  type ProjectIdentity,
  type SavedProjectsIndex,
  type TrustBoundaryDefinition,
  type TrustZone,
  type TrustZoneDefinition,
  type WorkflowTask,
} from "./manifest";

type GraphView = "design" | "runtime" | "drift" | "stats" | "deploy" | "runs";
type DesignSurface = "topology" | "workflow";
type Selection = { kind: "node" | "edge" | "zone" | "task"; id: string };
type MobilePanel = "palette" | "inspector" | null;
type VisualEdge = Pick<ArchitectureEdge, "id" | "source" | "target" | "relationship" | "relationshipId" | "mode"> & {
  visualState: "design" | "observed" | "unobserved" | "bypass" | "undeclared";
  interactionId?: string;
};

// Undo/redo history also carries project identity, so New project / Open manifest are undoable
// the same way an ordinary graph edit is.
type StudioSnapshot = ArchitectureSnapshot & { projectId: string; projectVersion: string };

type ZoneGesture = {
  id: string;
  mode: "move" | "resize";
  startClientX: number;
  startClientY: number;
  origin: TrustZoneDefinition;
  members: Record<string, { x: number; y: number }>;
};

const initialZones: TrustZoneDefinition[] = [
  { id: "zone.external-input", label: "External callers", kind: "EXTERNAL", description: "Untrusted callers and ingress identities", x: 20, y: 54, width: 205, height: 570 },
  { id: "zone.control", label: "Internal control plane", kind: "INTERNAL", description: "Coordinator, managed tools, and evidence services", x: 265, y: 54, width: 230, height: 570 },
  { id: "zone.worker", label: "Internal worker plane", kind: "INTERNAL", description: "Delegated agents and tenant-scoped retrieval", x: 515, y: 54, width: 240, height: 570 },
  { id: "zone.external-output", label: "External destinations", kind: "EXTERNAL", description: "Third-party and untrusted egress destinations", x: 775, y: 54, width: 255, height: 570 },
];

const initialNodes: ArchitectureNode[] = [
  { id: "user.customer", label: "Customer", type: "USER", owner: "Customer Platform", identity: "oidc://customer", capabilities: ["SUPPORT_REQUEST"], dataAccess: ["D2", "D3"], tenantMode: "REQUIRED", maxDelegationDepth: 0, trustZone: "EXTERNAL", trustZoneId: "zone.external-input", x: 42, y: 255 },
  { id: "agent.support", label: "Support Agent", type: "AGENT", owner: "Customer Platform", identity: "spiffe://prod.example/agent/support", capabilities: ["SUPPORT_REPLY", "DELEGATE_RESEARCH", "EMAIL_SEND"], dataAccess: ["D2", "D3", "D7"], tenantMode: "REQUIRED", maxDelegationDepth: 2, trustZone: "INTERNAL", trustZoneId: "zone.control", x: 286, y: 255 },
  { id: "agent.research", label: "Research Sub-Agent", type: "SUBAGENT", owner: "Customer Platform", identity: "spiffe://prod.example/agent/research", capabilities: ["KNOWLEDGE_SEARCH"], dataAccess: ["D2", "D3", "D7"], tenantMode: "REQUIRED", maxDelegationDepth: 0, trustZone: "INTERNAL", trustZoneId: "zone.worker", x: 536, y: 88 },
  { id: "rag.support-knowledge", label: "Support Knowledge", type: "RAG", owner: "Knowledge Platform", identity: "spiffe://prod.example/rag/support", capabilities: ["TENANT_RETRIEVAL"], dataAccess: ["D2", "D3", "D7"], tenantMode: "REQUIRED", maxDelegationDepth: 0, trustZone: "INTERNAL", trustZoneId: "zone.worker", x: 536, y: 350 },
  { id: "tool.send-email", label: "Send Email", type: "TOOL", owner: "Messaging Platform", identity: "spiffe://prod.example/tool/send-email", capabilities: ["EMAIL_SEND"], dataAccess: ["D2", "D3", "D7"], tenantMode: "REQUIRED", maxDelegationDepth: 0, trustZone: "INTERNAL", trustZoneId: "zone.control", definitionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", x: 286, y: 350 },
  { id: "external.customer-email", label: "Customer Email", type: "EXTERNAL", owner: "Messaging Platform", identity: "dns://customer.example", capabilities: [], dataAccess: ["D3", "D7"], tenantMode: "REQUIRED", maxDelegationDepth: 0, trustZone: "EXTERNAL", trustZoneId: "zone.external-output", allowedDomains: ["customer.example"], x: 788, y: 350 },
  { id: "external.audit-ledger", label: "Interlock Ledger", type: "EXTERNAL", owner: "Security Platform", identity: "spiffe://prod.example/interlock/ledger", capabilities: ["APPEND_ONLY_AUDIT"], dataAccess: ["D2", "D3", "D7"], tenantMode: "REQUIRED", maxDelegationDepth: 0, trustZone: "INTERNAL", trustZoneId: "zone.control", x: 286, y: 520 },
];

const audit = (id: string): Control => ({ id, objective: "EVIDENCE", timing: "POST_EXECUTION", point: "AUDIT_SINK", assurance: "OBSERVED" });
const prevent = (id: string, point: EnforcementPoint): Control => ({ id, objective: "PREVENT", timing: "PRE_EXECUTION", point, assurance: "ENFORCED" });

const initialEdges: ArchitectureEdge[] = [
  { id: "edge.user-support", source: "user.customer", target: "agent.support", relationshipId: "REL-01", relationship: "REQUESTS", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D2", "D3"], approvalRequired: false, dynamic: false, sameTenant: true, maxDepth: 0, boundaryId: "boundary.external-control-input", controls: [prevent("input-identity-taint", "INPUT_GATEWAY"), audit("input-audit")] },
  { id: "edge.support-research", source: "agent.support", target: "agent.research", relationshipId: "REL-06", relationship: "DELEGATES", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D2", "D3", "D7"], approvalRequired: false, dynamic: true, sameTenant: true, maxDepth: 2, boundaryId: "boundary.control-worker-a2a", controls: [prevent("delegation-binding", "A2A_BROKER"), audit("delegation-audit")] },
  { id: "edge.research-rag", source: "agent.research", target: "rag.support-knowledge", relationshipId: "REL-03", relationship: "READS", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D2", "D3", "D7"], approvalRequired: false, dynamic: false, sameTenant: true, maxDepth: 0, controls: [prevent("rag-tenant-acl", "RAG_GATEWAY"), audit("rag-provenance")] },
  { id: "edge.support-email", source: "agent.support", target: "tool.send-email", relationshipId: "REL-05", relationship: "INVOKES", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D2", "D3", "D7"], approvalRequired: true, dynamic: false, sameTenant: true, maxDepth: 0, controls: [prevent("mcp-call-guard", "MCP_GATEWAY"), prevent("stdio-process-sandbox", "SANDBOX"), audit("mcp-audit")] },
  { id: "edge.email-customer", source: "tool.send-email", target: "external.customer-email", relationshipId: "REL-07", relationship: "SENDS", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D3", "D7"], approvalRequired: true, dynamic: false, sameTenant: true, maxDepth: 0, boundaryId: "boundary.control-external-egress", controls: [prevent("egress-dlp", "EGRESS_GATEWAY"), { ...audit("egress-receipt"), assurance: "RECONCILED", objective: "DETECT" }] },
  { id: "edge.support-ledger", source: "agent.support", target: "external.audit-ledger", relationshipId: "REL-12", relationship: "LOGS_TO", mode: "ENFORCE", failureMode: "DEGRADE_READ_ONLY", allowedData: ["D2", "D3", "D7"], approvalRequired: false, dynamic: false, sameTenant: true, maxDepth: 0, controls: [{ ...audit("append-only-audit"), assurance: "RECONCILED" }] },
];

const initialBoundaries: TrustBoundaryDefinition[] = [
  { id: "boundary.external-control-input", label: "External request ingress", sourceZoneId: "zone.external-input", targetZoneId: "zone.control", point: "INPUT_GATEWAY", allowedRelationships: ["REQUESTS"], allowedData: ["D2", "D3"], deniedData: ["D5", "D8"], mode: "ENFORCE", failureMode: "FAIL_CLOSED", requireIdentity: true, requireTenantBinding: true, maxPayloadBytes: 262144, description: "Authenticated and tenant-bound request ingress" },
  { id: "boundary.control-worker-a2a", label: "Control to worker A2A", sourceZoneId: "zone.control", targetZoneId: "zone.worker", point: "A2A_BROKER", allowedRelationships: ["DELEGATES"], allowedData: ["D2", "D3", "D7"], deniedData: ["D5", "D8"], mode: "ENFORCE", failureMode: "FAIL_CLOSED", requireIdentity: true, requireTenantBinding: true, maxPayloadBytes: 1048576, description: "Policy-bound A2A delegation boundary" },
  { id: "boundary.control-external-egress", label: "Approved external egress", sourceZoneId: "zone.control", targetZoneId: "zone.external-output", point: "EGRESS_GATEWAY", allowedRelationships: ["SENDS"], allowedData: ["D3", "D7"], deniedData: ["D5", "D8"], mode: "ENFORCE", failureMode: "FAIL_CLOSED", requireIdentity: true, requireTenantBinding: true, maxPayloadBytes: 1048576, description: "Destination, DLP, approval, and receipt boundary" },
];

const initialOrchestration: OrchestrationDesign = {
  coordinatorActorId: "agent.support",
  pattern: "HYBRID",
  maxParallelism: 4,
  maxTasks: 50,
  maxDurationSeconds: 1800,
  maxMessages: 200,
  failFast: true,
  tasks: [
    { id: "task.research", label: "Research the support request", sourceActorId: "agent.support", targetActorId: "agent.research", transport: "A2A", purpose: "SUPPORT_RESEARCH", dependsOn: [], dataClasses: ["D2", "D3", "D7"], acceptanceCriteria: ["Answer is grounded in tenant-scoped knowledge"], maxAttempts: 2, timeoutSeconds: 120, approvalRequired: false, onFailure: "FAIL_WORKFLOW", x: 120, y: 180 },
    { id: "task.send-reply", label: "Send the approved reply", sourceActorId: "agent.support", targetActorId: "tool.send-email", transport: "MCP", purpose: "SUPPORT_REPLY", dependsOn: ["task.research"], dataClasses: ["D3", "D7"], acceptanceCriteria: ["Delivery receipt matches the approved destination"], maxAttempts: 1, timeoutSeconds: 60, approvalRequired: true, onFailure: "FAIL_WORKFLOW", x: 480, y: 180 },
  ],
};

const nodeTone: Record<NodeType, string> = {
  USER: "slate", AGENT: "violet", SUBAGENT: "indigo", RAG: "cyan", TOOL: "amber", MEMORY: "emerald", SCHEDULER: "blue", EXTERNAL: "rose",
};

const GRAPH_BOARD_MIN_WIDTH = 1050;
const GRAPH_BOARD_MIN_HEIGHT = 660;
const ACTOR_NODE_WIDTH = 174;
const ACTOR_NODE_HEIGHT = 76;
const TASK_NODE_WIDTH = 230;
const TASK_NODE_HEIGHT = 104;
const GRAPH_BOARD_PADDING = 12;
const GRAPH_BOARD_GROWTH_MARGIN = 24;
const ZONE_MIN_WIDTH = 190;
const ZONE_MIN_HEIGHT = 180;
const ZONE_INSET = 18;
const ZONE_HEADER_HEIGHT = 34;
const MIN_ZOOM = 0.3;
const MAX_ZOOM = 1.35;
const ZOOM_STEP = 0.1;
const HISTORY_LIMIT = 40;

const graphViewOptions: ReadonlyArray<{ id: GraphView; label: string; phase: string; description: string }> = [
  { id: "design", label: "Design graph", phase: "Declare intent", description: "Edit intended actors, trust zones, relationships, and security controls." },
  { id: "deploy", label: "Deploy", phase: "Compile & promote", description: "Compile outside the browser, then approve and promote a signed SHADOW bundle." },
  { id: "runs", label: "Runs", phase: "Execute workflow", description: "Start and operate the workflow from the exact active ENFORCE deployment bundle." },
  { id: "runtime", label: "Runtime graph", phase: "Observe reality", description: "Render actors and calls observed in imported Ledger or OTLP telemetry." },
  { id: "drift", label: "Drift", phase: "Reconcile", description: "Compare design with runtime to find undeclared, bypassed, or unobserved relationships." },
  { id: "stats", label: "Statistics", phase: "Analyze evidence", description: "Aggregate Ledger interactions by actor, mode, relationship, policy, and outcome." },
];

function zoneAtNodePosition(zones: TrustZoneDefinition[], x: number, y: number): TrustZoneDefinition | undefined {
  const centerX = x + ACTOR_NODE_WIDTH / 2;
  const centerY = y + ACTOR_NODE_HEIGHT / 2;
  return zones
    .filter((zone) => centerX >= zone.x && centerX <= zone.x + zone.width && centerY >= zone.y && centerY <= zone.y + zone.height)
    .sort((left, right) => left.width * left.height - right.width * right.height)[0];
}

function clampNodeToZone(node: Pick<ArchitectureNode, "x" | "y">, zone: TrustZoneDefinition) {
  const minX = zone.x + ZONE_INSET;
  const maxX = Math.max(minX, zone.x + zone.width - ACTOR_NODE_WIDTH - ZONE_INSET);
  const minY = zone.y + ZONE_HEADER_HEIGHT;
  const maxY = Math.max(minY, zone.y + zone.height - ACTOR_NODE_HEIGHT - ZONE_INSET);
  return { x: Math.max(minX, Math.min(maxX, node.x)), y: Math.max(minY, Math.min(maxY, node.y)) };
}

function edgeDefaults(source: ArchitectureNode, target: ArchitectureNode, index: number): ArchitectureEdge {
  let relationshipId = "REL-10";
  let relationship = "ROUTES";
  let point: EnforcementPoint = "INPUT_GATEWAY";
  if (source.type === "USER" && ["AGENT", "SUBAGENT"].includes(target.type)) {
    [relationshipId, relationship, point] = ["REL-01", "REQUESTS", "INPUT_GATEWAY"];
  } else if (["AGENT", "SUBAGENT"].includes(source.type) && ["AGENT", "SUBAGENT"].includes(target.type)) {
    [relationshipId, relationship, point] = ["REL-06", "DELEGATES", "A2A_BROKER"];
  } else if (target.type === "RAG") {
    [relationshipId, relationship, point] = ["REL-03", "READS", "RAG_GATEWAY"];
  } else if (target.type === "TOOL") {
    [relationshipId, relationship, point] = ["REL-05", "INVOKES", "MCP_GATEWAY"];
  } else if (target.type === "MEMORY") {
    [relationshipId, relationship, point] = ["REL-04", "READS", "RAG_GATEWAY"];
  } else if (target.type === "EXTERNAL") {
    [relationshipId, relationship, point] = ["REL-07", "SENDS", "EGRESS_GATEWAY"];
  }
  return {
    id: `edge.${source.id}.${target.id}.${index}`,
    source: source.id,
    target: target.id,
    relationshipId,
    relationship,
    mode: "SHADOW",
    failureMode: "FAIL_CLOSED",
    allowedData: ["D2", "D3"],
    approvalRequired: target.type === "TOOL" || target.type === "EXTERNAL",
    dynamic: relationshipId === "REL-06",
    sameTenant: true,
    maxDepth: relationshipId === "REL-06" ? 1 : 0,
    controls: [
      { ...prevent(`control-${index}`, point), assurance: "DECLARED" },
      audit(`audit-${index}`),
    ],
  };
}

function enforcementPointForRelationship(relationshipId: string): EnforcementPoint {
  return relationshipId === "REL-01" ? "INPUT_GATEWAY"
    : relationshipId === "REL-03" ? "RAG_GATEWAY"
      : relationshipId === "REL-05" ? "MCP_GATEWAY"
        : relationshipId === "REL-06" ? "A2A_BROKER"
          : relationshipId === "REL-07" ? "EGRESS_GATEWAY"
            : "AUDIT_SINK";
}

function boundaryDefaults(edge: ArchitectureEdge, source: ArchitectureNode, target: ArchitectureNode, index: number): TrustBoundaryDefinition {
  return {
    id: `boundary.${source.trustZoneId}.${target.trustZoneId}.${index}`.replace(/[^a-zA-Z0-9._-]/g, "-"),
    label: `${source.trustZoneId} → ${target.trustZoneId}`,
    sourceZoneId: source.trustZoneId,
    targetZoneId: target.trustZoneId,
    point: enforcementPointForRelationship(edge.relationshipId),
    allowedRelationships: [edge.relationship],
    allowedData: [...edge.allowedData],
    deniedData: ["D5", "D8"].filter((item) => !edge.allowedData.includes(item)),
    mode: edge.mode,
    failureMode: edge.failureMode,
    requireIdentity: true,
    requireTenantBinding: true,
    maxPayloadBytes: 1048576,
    description: `Directional policy boundary for ${edge.relationship}`,
  };
}

function workflowCycleTask(tasks: WorkflowTask[]): string | null {
  const dependencies = Object.fromEntries(tasks.map((task) => [task.id, task.dependsOn]));
  const visiting = new Set<string>();
  const visited = new Set<string>();
  function visit(taskId: string): string | null {
    if (visiting.has(taskId)) return taskId;
    if (visited.has(taskId)) return null;
    visiting.add(taskId);
    for (const dependency of dependencies[taskId] ?? []) {
      const cycle = visit(dependency);
      if (cycle) return cycle;
    }
    visiting.delete(taskId);
    visited.add(taskId);
    return null;
  }
  for (const task of tasks) {
    const cycle = visit(task.id);
    if (cycle) return cycle;
  }
  return null;
}

function workflowDependencyCreatesCycle(tasks: WorkflowTask[], taskId: string, dependencyId: string): boolean {
  const next = tasks.map((task) => task.id === taskId
    ? { ...task, dependsOn: [...new Set([...task.dependsOn, dependencyId])] }
    : task);
  return workflowCycleTask(next) !== null;
}

export default function Home() {
  const [nodes, setNodes] = useState(initialNodes);
  const [edges, setEdges] = useState(initialEdges);
  const [zones, setZones] = useState(initialZones);
  const [boundaries, setBoundaries] = useState(initialBoundaries);
  const [orchestration, setOrchestration] = useState(initialOrchestration);
  const [designSurface, setDesignSurface] = useState<DesignSurface>("topology");
  const [selected, setSelected] = useState<Selection>({ kind: "edge", id: "edge.support-research" });
  const [connectFrom, setConnectFrom] = useState<string | null>(null);
  const [dragging, setDragging] = useState<{ id: string; dx: number; dy: number } | null>(null);
  const [taskDragging, setTaskDragging] = useState<{ id: string; dx: number; dy: number } | null>(null);
  const [zoneGesture, setZoneGesture] = useState<ZoneGesture | null>(null);
  const [zoneAssignmentActor, setZoneAssignmentActor] = useState("");
  const [notice, setNotice] = useState("All changes are local drafts · use Projects to save or open a manifest");
  const [activeGraph, setActiveGraph] = useState<GraphView>("design");
  const [controlPlaneUrl, setControlPlaneUrl] = useState("http://127.0.0.1:8792");
  const [controlPlaneToken, setControlPlaneToken] = useState("");
  const [runtimeImport, setRuntimeImport] = useState<RuntimeImport | null>(null);
  const [rawLedgerEvents, setRawLedgerEvents] = useState<Array<Record<string, unknown>> | null>(null);
  const [zoom, setZoom] = useState(1);
  const [focusedNodeId, setFocusedNodeId] = useState<string | null>(null);
  const [past, setPast] = useState<StudioSnapshot[]>([]);
  const [future, setFuture] = useState<StudioSnapshot[]>([]);
  const [mobilePanel, setMobilePanel] = useState<MobilePanel>(null);
  const [projectId, setProjectId] = useState(STARTER_PROJECT.id);
  const [projectVersion, setProjectVersion] = useState(STARTER_PROJECT.version);
  const [savedProjects, setSavedProjects] = useState<SavedProjectsIndex>(() => {
    if (typeof window === "undefined") return {};
    try {
      return parseSavedProjects(window.localStorage.getItem(PROJECTS_STORAGE_KEY));
    } catch {
      return {};
    }
  });
  const [showProjectMenu, setShowProjectMenu] = useState(false);
  const telemetryInput = useRef<HTMLInputElement>(null);
  const manifestInput = useRef<HTMLInputElement>(null);
  const canvasScroll = useRef<HTMLDivElement>(null);
  const dragCheckpointed = useRef(false);
  const zoomRef = useRef(1);
  const wheelZoomDelta = useRef(0);
  const wheelZoomFrame = useRef<number | null>(null);
  const pointerOverGraph = useRef(false);
  const initialFitDone = useRef(false);

  const nodeMap = useMemo(() => Object.fromEntries(nodes.map((node) => [node.id, node])), [nodes]);
  const zoneMap = useMemo(() => Object.fromEntries(zones.map((zone) => [zone.id, zone])), [zones]);
  const boundaryMap = useMemo(() => Object.fromEntries(boundaries.map((boundary) => [boundary.id, boundary])), [boundaries]);
  const selectedNode = selected.kind === "node" ? nodeMap[selected.id] : undefined;
  const selectedEdge = selected.kind === "edge" ? edges.find((edge) => edge.id === selected.id) : undefined;
  const selectedZone = selected.kind === "zone" ? zoneMap[selected.id] : undefined;
  const selectedTask = selected.kind === "task" ? orchestration.tasks.find((task) => task.id === selected.id) : undefined;
  const selectedBoundary = selectedEdge?.boundaryId ? boundaryMap[selectedEdge.boundaryId] : undefined;
  const selectedEdgeSource = selectedEdge ? nodeMap[selectedEdge.source] : undefined;
  const selectedEdgeTarget = selectedEdge ? nodeMap[selectedEdge.target] : undefined;
  const selectedEdgeCrossesZone = Boolean(selectedEdgeSource && selectedEdgeTarget && selectedEdgeSource.trustZoneId !== selectedEdgeTarget.trustZoneId);
  const selectedZoneMembers = selectedZone ? nodes.filter((node) => node.trustZoneId === selectedZone.id) : [];
  const runtimeDiff = useMemo(() => computeRuntimeDiff(edges, runtimeImport?.observations ?? []), [edges, runtimeImport]);

  const runtimeNodes = useMemo(() => {
    if (!runtimeImport) return [];
    const actorIds = Array.from(new Set(runtimeImport.observations.flatMap((item) => [item.source, item.target])));
    return actorIds.map((id, index): ArchitectureNode => {
      const exact = nodeMap[id];
      if (exact) return exact;
      const template = [...nodes].sort((a, b) => b.id.length - a.id.length).find((node) => id.startsWith(`${node.id}.`) || id.startsWith(`${node.id}-`));
      if (template) return { ...template, id, label: `${template.label} · runtime`, x: Math.min(850, template.x + 22), y: Math.min(555, template.y + 105) };
      const inferredType: NodeType = id.startsWith("agent.") ? "SUBAGENT" : id.startsWith("tool.") ? "TOOL" : id.startsWith("rag.") ? "RAG" : id.startsWith("memory.") ? "MEMORY" : "EXTERNAL";
      const externalZone = [...zones].reverse().find((zone) => zone.kind === "EXTERNAL") ?? zones[0];
      return { id, label: "Undeclared Actor", type: inferredType, owner: "Runtime only", identity: `observed://${id}`, capabilities: [], dataAccess: [], tenantMode: "REQUIRED", maxDelegationDepth: 0, trustZone: externalZone?.kind ?? "EXTERNAL", trustZoneId: externalZone?.id ?? "zone.external-output", x: (externalZone?.x ?? 775) + 18 + (index % 2) * 25, y: Math.min(555, 420 + index * 48) };
    });
  }, [runtimeImport, nodeMap, nodes, zones]);

  const visualNodes = useMemo(() => {
    if (activeGraph === "design") return nodes;
    if (activeGraph === "runtime") return runtimeNodes;
    const runtimeOnly = runtimeNodes.filter((node) => !nodeMap[node.id]);
    return [...nodes, ...runtimeOnly];
  }, [activeGraph, nodes, runtimeNodes, nodeMap]);
  const boardSize = useMemo(() => ({
    width: Math.max(GRAPH_BOARD_MIN_WIDTH, ...visualNodes.map((node) => node.x + ACTOR_NODE_WIDTH + GRAPH_BOARD_GROWTH_MARGIN), ...zones.map((zone) => zone.x + zone.width + GRAPH_BOARD_GROWTH_MARGIN)),
    height: Math.max(GRAPH_BOARD_MIN_HEIGHT, ...visualNodes.map((node) => node.y + ACTOR_NODE_HEIGHT + GRAPH_BOARD_GROWTH_MARGIN), ...zones.map((zone) => zone.y + zone.height + GRAPH_BOARD_GROWTH_MARGIN)),
  }), [visualNodes, zones]);
  const visualNodeMap = useMemo(() => Object.fromEntries(visualNodes.map((node) => [node.id, node])), [visualNodes]);
  const runtimeResultCount = runtimeImport ? runtimeDiff.undeclared.length + runtimeDiff.controlBypassInteractionIds.length + runtimeDiff.unobservedEdgeIds.length : 0;
  const isGraphView = activeGraph === "design" || activeGraph === "runtime" || activeGraph === "drift";
  const activeView = graphViewOptions.find((view) => view.id === activeGraph) ?? graphViewOptions[0];

  const visualEdges = useMemo((): VisualEdge[] => {
    const observed = (runtimeImport?.observations ?? []).map((item): VisualEdge => {
      const declared = edges.some((edge) => matchesEdge(edge, item));
      return {
        id: `runtime.${item.interactionId}`,
        source: item.source,
        target: item.target,
        relationship: item.relationship,
        relationshipId: item.relationshipId,
        mode: "ENFORCE",
        visualState: !declared ? "undeclared" : !item.controlEvaluated ? "bypass" : "observed",
        interactionId: item.interactionId,
      };
    });
    if (activeGraph === "runtime") return observed;
    const designed = edges.map((edge): VisualEdge => ({
      id: edge.id,
      source: edge.source,
      target: edge.target,
      relationship: edge.relationship,
      relationshipId: edge.relationshipId,
      mode: edge.mode,
        visualState: activeGraph === "drift" && runtimeImport && runtimeDiff.unobservedEdgeIds.includes(edge.id) ? "unobserved" : "design",
    }));
    return activeGraph === "drift" ? [...designed, ...observed] : designed;
  }, [activeGraph, edges, runtimeImport, runtimeDiff.unobservedEdgeIds]);

  const findings = useMemo(() => {
    const result: { severity: "critical" | "warning"; text: string; target: string }[] = [];
    nodes.forEach((node) => {
      if (!edges.some((edge) => edge.source === node.id || edge.target === node.id)) result.push({ severity: "warning", text: "Unconnected actor has no security boundary", target: node.id });
      if (node.type === "TOOL" && !node.definitionDigest) result.push({ severity: "critical", text: "Tool definition digest is not pinned", target: node.id });
      if (node.type === "EXTERNAL" && edges.some((edge) => edge.target === node.id && edge.relationshipId === "REL-07") && !node.allowedDomains?.length) result.push({ severity: "critical", text: "External destination has no allowed domain boundary", target: node.id });
    });
    edges.forEach((edge) => {
      if (edge.allowedData.length && !nodeMap[edge.target]?.dataAccess?.length) result.push({ severity: "warning", text: "Target actor declares no data access, so the grant comparison cannot run", target: edge.id });
      if (edge.controls.some((control) => control.assurance === "DECLARED")) result.push({ severity: "warning", text: "Declared control is not attached to a runtime enforcement point", target: edge.id });
      if (["REL-03", "REL-05", "REL-06", "REL-07"].includes(edge.relationshipId) && edge.mode === "OBSERVE") result.push({ severity: "critical", text: "High-risk relationship is OBSERVE only", target: edge.id });
      if (edge.failureMode === "FAIL_OPEN") result.push({ severity: "critical", text: "Security boundary fails open", target: edge.id });
      if (edge.relationshipId === "REL-06" && (!edge.sameTenant || edge.maxDepth < 1)) result.push({ severity: "critical", text: "Delegation tenant or depth boundary is unsafe", target: edge.id });
      if (edge.dynamic && !nodeMap[edge.target]?.capabilities.length) result.push({ severity: "critical", text: "Dynamic target requires a capability boundary", target: edge.target });
      if (!edge.controls.some((control) => control.point === "AUDIT_SINK")) result.push({ severity: "warning", text: "No audit evidence control", target: edge.id });
      if (edge.allowedData.includes("D5")) result.push({ severity: "critical", text: "Credential class D5 is allowed across the edge", target: edge.id });
      const source = nodeMap[edge.source];
      const target = nodeMap[edge.target];
      if (!source || !target) return;
      const crossesZone = source.trustZoneId !== target.trustZoneId;
      const boundary = edge.boundaryId ? boundaryMap[edge.boundaryId] : undefined;
      if (crossesZone && !boundary) result.push({ severity: "critical", text: "Zone crossing has no executable trust boundary", target: edge.id });
      if (boundary && (boundary.sourceZoneId !== source.trustZoneId || boundary.targetZoneId !== target.trustZoneId)) result.push({ severity: "critical", text: "Trust boundary direction does not match this edge", target: edge.id });
      if (boundary && !boundary.allowedRelationships.includes(edge.relationship)) result.push({ severity: "critical", text: "Trust boundary denies this relationship", target: edge.id });
      if (boundary && edge.allowedData.some((item) => !boundary.allowedData.includes(item) || boundary.deniedData.includes(item))) result.push({ severity: "critical", text: "Edge data exceeds its trust-boundary contract", target: edge.id });
      if (boundary && boundary.point !== enforcementPointForRelationship(edge.relationshipId)) result.push({ severity: "critical", text: "Trust boundary uses the wrong enforcement point", target: edge.id });
      if (boundary && boundary.failureMode === "FAIL_OPEN") result.push({ severity: "critical", text: "Trust boundary fails open", target: edge.id });
    });
    orchestration.tasks.forEach((task) => {
      const relationshipId = task.transport === "A2A" ? "REL-06" : task.transport === "MCP" ? "REL-05" : null;
      if (relationshipId && !edges.some((edge) => edge.source === task.sourceActorId && edge.target === task.targetActorId && edge.relationshipId === relationshipId)) result.push({ severity: "critical", text: `${task.transport} task has no declared transport edge`, target: task.id });
      if (!task.acceptanceCriteria.length) result.push({ severity: "warning", text: "Workflow task has no acceptance criteria", target: task.id });
      if (task.maxAttempts < 1 || task.timeoutSeconds < 1) result.push({ severity: "critical", text: "Workflow task retry or timeout budget is invalid", target: task.id });
      const target = nodeMap[task.targetActorId];
      if ((target?.type === "TOOL" || target?.type === "EXTERNAL") && !task.approvalRequired) result.push({ severity: "critical", text: "High-impact workflow task has no approval gate", target: task.id });
    });
    const cycleTask = workflowCycleTask(orchestration.tasks);
    if (cycleTask) result.push({ severity: "critical", text: "Workflow dependency cycle must be removed", target: cycleTask });
    return result;
  }, [nodes, edges, nodeMap, boundaryMap, orchestration.tasks]);

  const allControls = edges.flatMap((edge) => edge.controls);
  const assuredControls = allControls.filter((control) => control.assurance === "ENFORCED" || control.assurance === "RECONCILED").length;
  const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
  const warningCount = findings.length - criticalCount;
  const score = Math.max(0, 100 - criticalCount * 18 - warningCount * 6);
  const coverage = allControls.length ? Math.round((assuredControls / allControls.length) * 100) : 0;

  function checkpoint() {
    setPast((items) => [...items.slice(-(HISTORY_LIMIT - 1)), { nodes, edges, zones, boundaries, orchestration, projectId, projectVersion }]);
    setFuture([]);
  }

  function restoreSnapshot(snapshot: StudioSnapshot) {
    setNodes(snapshot.nodes);
    setEdges(snapshot.edges);
    setZones(snapshot.zones);
    setBoundaries(snapshot.boundaries);
    setOrchestration(snapshot.orchestration);
    setProjectId(snapshot.projectId);
    setProjectVersion(snapshot.projectVersion);
    const selectionStillExists = selected.kind === "node"
      ? snapshot.nodes.some((node) => node.id === selected.id)
      : selected.kind === "edge"
        ? snapshot.edges.some((edge) => edge.id === selected.id)
        : selected.kind === "zone"
          ? snapshot.zones.some((zone) => zone.id === selected.id)
          : snapshot.orchestration.tasks.some((task) => task.id === selected.id);
    if (!selectionStillExists) {
      if (snapshot.edges[0]) setSelected({ kind: "edge", id: snapshot.edges[0].id });
      else if (snapshot.nodes[0]) setSelected({ kind: "node", id: snapshot.nodes[0].id });
      else setSelected({ kind: "node", id: "" });
    }
    setConnectFrom(null);
    setDragging(null);
    setZoneGesture(null);
  }

  function undo() {
    const snapshot = past[past.length - 1];
    if (!snapshot) return;
    setPast((items) => items.slice(0, -1));
    setFuture((items) => [{ nodes, edges, zones, boundaries, orchestration, projectId, projectVersion }, ...items].slice(0, HISTORY_LIMIT));
    restoreSnapshot(snapshot);
    setNotice("Last architecture change undone");
  }

  function redo() {
    const snapshot = future[0];
    if (!snapshot) return;
    setFuture((items) => items.slice(1));
    setPast((items) => [...items.slice(-(HISTORY_LIMIT - 1)), { nodes, edges, zones, boundaries, orchestration, projectId, projectVersion }]);
    restoreSnapshot(snapshot);
    setNotice("Architecture change restored");
  }

  function resetDraft() {
    checkpoint();
    restoreSnapshot({ nodes: initialNodes, edges: initialEdges, zones: initialZones, boundaries: initialBoundaries, orchestration: initialOrchestration, projectId: STARTER_PROJECT.id, projectVersion: STARTER_PROJECT.version });
    setSelected({ kind: "edge", id: "edge.support-research" });
    setNotice("Draft reset to the secure reference architecture · Undo is available");
  }

  const changeZoom = useCallback((nextZoom: number, behavior: ScrollBehavior = "smooth", anchor?: { clientX: number; clientY: number }) => {
    const viewport = canvasScroll.current;
    const clamped = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, nextZoom));
    const currentZoom = zoomRef.current;
    zoomRef.current = clamped;
    if (!viewport) {
      setZoom(clamped);
      return;
    }
    const rect = viewport.getBoundingClientRect();
    const viewportX = anchor ? anchor.clientX - rect.left : viewport.clientWidth / 2;
    const viewportY = anchor ? anchor.clientY - rect.top : viewport.clientHeight / 2;
    const centerX = (viewport.scrollLeft + viewportX) / currentZoom;
    const centerY = (viewport.scrollTop + viewportY) / currentZoom;
    setZoom(clamped);
    requestAnimationFrame(() => viewport.scrollTo({
      left: Math.max(0, centerX * clamped - viewportX),
      top: Math.max(0, centerY * clamped - viewportY),
      behavior,
    }));
  }, []);

  useEffect(() => {
    function onZoomShortcut(event: KeyboardEvent) {
      const target = event.target;
      const editing = target instanceof HTMLElement && (target.isContentEditable || target.matches("input, textarea, select"));
      const graphFocused = pointerOverGraph.current || Boolean(canvasScroll.current?.contains(document.activeElement));
      if (!isGraphView || editing || !graphFocused || !(event.metaKey || event.ctrlKey) || event.altKey) return;
      if (event.code === "Equal" || event.code === "NumpadAdd") {
        event.preventDefault();
        changeZoom(zoomRef.current + ZOOM_STEP);
      } else if (event.code === "Minus" || event.code === "NumpadSubtract") {
        event.preventDefault();
        changeZoom(zoomRef.current - ZOOM_STEP);
      }
    }
    window.addEventListener("keydown", onZoomShortcut);
    return () => window.removeEventListener("keydown", onZoomShortcut);
  }, [changeZoom, isGraphView]);

  useEffect(() => {
    const viewport = canvasScroll.current;
    if (!viewport) return;
    function onGraphWheel(event: WheelEvent) {
      const modifierZoom = event.metaKey || event.ctrlKey;
      const physicalWheel = event.deltaMode === 1 || (!modifierZoom && Math.abs(event.deltaY) >= 40);
      if ((!modifierZoom && !physicalWheel) || event.altKey || event.shiftKey || event.deltaY === 0) return;
      event.preventDefault();
      const normalizedDelta = event.deltaY * (event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? viewport!.clientHeight : 1);
      wheelZoomDelta.current += normalizedDelta;
      if (wheelZoomFrame.current !== null) return;
      wheelZoomFrame.current = requestAnimationFrame(() => {
        const delta = wheelZoomDelta.current;
        wheelZoomDelta.current = 0;
        wheelZoomFrame.current = null;
        const step = Math.max(-ZOOM_STEP, Math.min(ZOOM_STEP, -delta * 0.002));
        changeZoom(zoomRef.current + step, "auto", { clientX: event.clientX, clientY: event.clientY });
      });
    }
    viewport.addEventListener("wheel", onGraphWheel, { passive: false });
    return () => {
      viewport.removeEventListener("wheel", onGraphWheel);
      if (wheelZoomFrame.current !== null) cancelAnimationFrame(wheelZoomFrame.current);
      wheelZoomFrame.current = null;
      wheelZoomDelta.current = 0;
    };
  }, [activeGraph, changeZoom]);

  const fitGraph = useCallback((announce = true) => {
    const viewport = canvasScroll.current;
    if (!viewport) return;
    const nextZoom = Math.max(MIN_ZOOM, Math.min(1, (viewport.clientWidth - 48) / boardSize.width, (viewport.clientHeight - 48) / boardSize.height));
    zoomRef.current = nextZoom;
    setZoom(nextZoom);
    requestAnimationFrame(() => viewport.scrollTo({ left: 0, top: 0, behavior: "smooth" }));
    if (announce) setNotice(`Graph fitted to viewport · ${Math.round(nextZoom * 100)}%`);
  }, [boardSize.height, boardSize.width]);

  useEffect(() => {
    if (initialFitDone.current || !isGraphView) return;
    initialFitDone.current = true;
    const frame = requestAnimationFrame(() => fitGraph(false));
    return () => cancelAnimationFrame(frame);
  }, [fitGraph, isGraphView]);

  function focusNode(nodeId: string, announce = true) {
    const node = visualNodeMap[nodeId];
    const viewport = canvasScroll.current;
    if (!node || !viewport) return;
    setFocusedNodeId(nodeId);
    viewport.scrollTo({
      left: Math.max(0, (node.x + ACTOR_NODE_WIDTH / 2) * zoom - viewport.clientWidth / 2),
      top: Math.max(0, (node.y + ACTOR_NODE_HEIGHT / 2) * zoom - viewport.clientHeight / 2),
      behavior: "smooth",
    });
    if (announce) setNotice(`${node.label} centered in the graph`);
  }

  function focusZone(zoneId: string, announce = true) {
    const zone = zoneMap[zoneId];
    const viewport = canvasScroll.current;
    if (!zone || !viewport) return;
    viewport.scrollTo({
      left: Math.max(0, (zone.x + zone.width / 2) * zoom - viewport.clientWidth / 2),
      top: Math.max(0, (zone.y + zone.height / 2) * zoom - viewport.clientHeight / 2),
      behavior: "smooth",
    });
    if (announce) setNotice(`${zone.label} centered in the graph`);
  }

  function focusCurrentContext() {
    if (activeGraph === "design") {
      if (designSurface === "workflow") {
        fitGraph();
        return;
      }
      if (selectedNode) focusNode(selectedNode.id);
      else if (selectedEdge) focusNode(selectedEdge.target);
      else if (selectedZone) focusZone(selectedZone.id);
      else fitGraph();
      return;
    }
    const anomalyId = runtimeDiff.undeclared[0]?.target
      ?? runtimeImport?.observations.find((item) => runtimeDiff.controlBypassInteractionIds.includes(item.interactionId))?.target
      ?? visualNodes[0]?.id;
    if (anomalyId) focusNode(anomalyId);
    else fitGraph();
  }

  function updateNode(patch: Partial<ArchitectureNode>) {
    if (!selectedNode) return;
    checkpoint();
    setNodes((items) => items.map((item) => item.id === selectedNode.id ? { ...item, ...patch } : item));
  }

  function updateEdge(patch: Partial<ArchitectureEdge>) {
    if (!selectedEdge) return;
    checkpoint();
    setEdges((items) => items.map((item) => item.id === selectedEdge.id ? { ...item, ...patch } : item));
  }

  function updateControl(controlId: string, patch: Partial<Control>) {
    if (!selectedEdge) return;
    updateEdge({ controls: selectedEdge.controls.map((control) => control.id === controlId ? { ...control, ...patch } : control) });
  }

  function updateSelectedBoundary(patch: Partial<TrustBoundaryDefinition>) {
    if (!selectedBoundary) return;
    checkpoint();
    setBoundaries((items) => items.map((item) => item.id === selectedBoundary.id ? { ...item, ...patch } : item));
  }

  function bindBoundaryToSelectedEdge() {
    if (!selectedEdge) return;
    const source = nodeMap[selectedEdge.source];
    const target = nodeMap[selectedEdge.target];
    if (!source || !target || source.trustZoneId === target.trustZoneId) {
      setNotice("A trust boundary is only required when an edge crosses two zones");
      return;
    }
    checkpoint();
    const existing = boundaries.find((boundary) => boundary.sourceZoneId === source.trustZoneId && boundary.targetZoneId === target.trustZoneId && boundary.allowedRelationships.includes(selectedEdge.relationship));
    const boundary = existing ?? boundaryDefaults(selectedEdge, source, target, boundaries.length + 1);
    if (!existing) setBoundaries((items) => [...items, boundary]);
    setEdges((items) => items.map((edge) => edge.id === selectedEdge.id ? { ...edge, boundaryId: boundary.id } : edge));
    setNotice(`${boundary.label} bound to ${selectedEdge.relationship}`);
  }

  function updateOrchestration(patch: Partial<Omit<OrchestrationDesign, "tasks">>) {
    checkpoint();
    setOrchestration((value) => ({ ...value, ...patch }));
  }

  function updateSelectedTask(patch: Partial<WorkflowTask>) {
    if (!selectedTask) return;
    checkpoint();
    setOrchestration((value) => ({ ...value, tasks: value.tasks.map((task) => task.id === selectedTask.id ? { ...task, ...patch } : task) }));
  }

  function addWorkflowTask(transport: WorkflowTask["transport"]) {
    checkpoint();
    const index = orchestration.tasks.length + 1;
    const coordinator = nodeMap[orchestration.coordinatorActorId] ?? nodes.find((node) => node.type === "AGENT" || node.type === "SCHEDULER") ?? nodes[0];
    const target = transport === "A2A"
      ? nodes.find((node) => ["AGENT", "SUBAGENT"].includes(node.type) && node.id !== coordinator?.id)
      : transport === "MCP"
        ? nodes.find((node) => node.type === "TOOL")
        : transport === "HUMAN"
          ? nodes.find((node) => node.type === "USER")
          : coordinator;
    if (!coordinator || !target) {
      setNotice(`Add a compatible actor before creating a ${transport} task`);
      return;
    }
    const task: WorkflowTask = {
      id: `task.new-${index}`,
      label: `New ${transport} task`,
      sourceActorId: coordinator.id,
      targetActorId: target.id,
      transport,
      purpose: transport === "A2A" ? "DELEGATED_WORK" : transport === "MCP" ? "TOOL_EXECUTION" : "WORKFLOW_STEP",
      dependsOn: orchestration.tasks.length ? [orchestration.tasks[orchestration.tasks.length - 1].id] : [],
      dataClasses: ["D3"],
      acceptanceCriteria: [],
      maxAttempts: 1,
      timeoutSeconds: 300,
      approvalRequired: transport === "MCP" || transport === "HUMAN",
      onFailure: "FAIL_WORKFLOW",
      x: 100 + ((index - 1) % 3) * 300,
      y: 150 + Math.floor((index - 1) / 3) * 170,
    };
    setOrchestration((value) => ({ ...value, tasks: [...value.tasks, task] }));
    setSelected({ kind: "task", id: task.id });
    setMobilePanel("inspector");
    setNotice(`${transport} workflow task added · define its actor edge and acceptance criteria`);
  }

  function removeSelectedTask() {
    if (!selectedTask) return;
    checkpoint();
    setOrchestration((value) => ({
      ...value,
      tasks: value.tasks
        .filter((task) => task.id !== selectedTask.id)
        .map((task) => ({ ...task, dependsOn: task.dependsOn.filter((id) => id !== selectedTask.id) })),
    }));
    const remaining = orchestration.tasks.filter((task) => task.id !== selectedTask.id);
    if (remaining[0]) setSelected({ kind: "task", id: remaining[0].id });
    else if (edges[0]) setSelected({ kind: "edge", id: edges[0].id });
    setNotice(`${selectedTask.label} removed from the task graph`);
  }

  function addNode(type: NodeType) {
    checkpoint();
    const count = nodes.filter((node) => node.type === type).length + 1;
    const id = `${type.toLowerCase()}.new-${count}`;
    const preferredZone = type === "USER"
      ? zones.find((zone) => zone.kind === "EXTERNAL")
      : type === "EXTERNAL"
        ? [...zones].reverse().find((zone) => zone.kind === "EXTERNAL")
        : zones.find((zone) => zone.kind === "INTERNAL");
    const zone = preferredZone ?? zones[0];
    if (!zone) return;
    const memberCount = nodes.filter((node) => node.trustZoneId === zone.id).length;
    const columns = Math.max(1, Math.floor((zone.width - ZONE_INSET * 2) / (ACTOR_NODE_WIDTH + 12)));
    const tentative = {
      x: zone.x + ZONE_INSET + (memberCount % columns) * (ACTOR_NODE_WIDTH + 12),
      y: zone.y + ZONE_HEADER_HEIGHT + Math.floor(memberCount / columns) * (ACTOR_NODE_HEIGHT + 14),
    };
    const position = clampNodeToZone(tentative, zone);
    const node: ArchitectureNode = { id, label: `New ${type.replace("SUBAGENT", "Sub-Agent")}`, type, owner: "Unassigned", identity: `unbound://${id}`, capabilities: [], tenantMode: "REQUIRED", maxDelegationDepth: type === "AGENT" || type === "SUBAGENT" ? 1 : 0, trustZone: zone.kind, trustZoneId: zone.id, allowedDomains: type === "EXTERNAL" ? [] : undefined, ...position };
    setNodes((items) => [...items, node]);
    setSelected({ kind: "node", id });
    setFocusedNodeId(id);
    setMobilePanel("inspector");
    setNotice(`${node.label} added · connect it to define a security boundary`);
  }

  function addZone() {
    checkpoint();
    const index = zones.length + 1;
    const viewport = canvasScroll.current;
    const x = Math.max(GRAPH_BOARD_PADDING, ((viewport?.scrollLeft ?? 0) + 60) / zoom);
    const y = Math.max(GRAPH_BOARD_PADDING, ((viewport?.scrollTop ?? 0) + 70) / zoom);
    const zone: TrustZoneDefinition = { id: `zone.custom-${index}`, label: `New trust zone ${index}`, kind: "INTERNAL", description: "Managed security boundary", x, y, width: 320, height: 300 };
    setZones((items) => [...items, zone]);
    setSelected({ kind: "zone", id: zone.id });
    setMobilePanel("inspector");
    setNotice(`${zone.label} added · resize it and assign actors in the inspector`);
  }

  function assignSelectedNodeToZone(zoneId: string) {
    const zone = zoneMap[zoneId];
    if (!selectedNode || !zone || selectedNode.trustZoneId === zone.id) return;
    checkpoint();
    const position = clampNodeToZone(selectedNode, zone);
    setNodes((items) => items.map((item) => item.id === selectedNode.id ? { ...item, trustZone: zone.kind, trustZoneId: zone.id, ...position } : item));
    setNotice(`${selectedNode.label} assigned to ${zone.label}`);
  }

  function updateSelectedZone(patch: Partial<TrustZoneDefinition>, shiftMembers = false) {
    if (!selectedZone) return;
    checkpoint();
    const next = { ...selectedZone, ...patch };
    const dx = next.x - selectedZone.x;
    const dy = next.y - selectedZone.y;
    setZones((items) => items.map((item) => item.id === selectedZone.id ? next : item));
    setNodes((items) => items.map((node) => {
      if (node.trustZoneId !== selectedZone.id) return node;
      const moved = { ...node, trustZone: next.kind, ...(shiftMembers ? { x: node.x + dx, y: node.y + dy } : {}) };
      return { ...moved, ...clampNodeToZone(moved, next) };
    }));
  }

  function assignActorToSelectedZone(actorId: string) {
    if (!selectedZone) return;
    const actor = nodeMap[actorId];
    if (!actor || actor.trustZoneId === selectedZone.id) return;
    checkpoint();
    const position = clampNodeToZone(actor, selectedZone);
    setNodes((items) => items.map((node) => node.id === actorId ? { ...node, trustZone: selectedZone.kind, trustZoneId: selectedZone.id, ...position } : node));
    setZoneAssignmentActor("");
    setNotice(`${actor.label} assigned to ${selectedZone.label}`);
  }

  function fitSelectedZoneAroundActors() {
    if (!selectedZone || selectedZoneMembers.length === 0) {
      setNotice("Assign at least one actor before fitting the zone");
      return;
    }
    checkpoint();
    const left = Math.max(GRAPH_BOARD_PADDING, Math.min(...selectedZoneMembers.map((node) => node.x)) - ZONE_INSET);
    const top = Math.max(GRAPH_BOARD_PADDING, Math.min(...selectedZoneMembers.map((node) => node.y)) - ZONE_HEADER_HEIGHT);
    const right = Math.max(...selectedZoneMembers.map((node) => node.x + ACTOR_NODE_WIDTH)) + ZONE_INSET;
    const bottom = Math.max(...selectedZoneMembers.map((node) => node.y + ACTOR_NODE_HEIGHT)) + ZONE_INSET;
    setZones((items) => items.map((zone) => zone.id === selectedZone.id ? { ...zone, x: left, y: top, width: Math.max(ZONE_MIN_WIDTH, right - left), height: Math.max(ZONE_MIN_HEIGHT, bottom - top) } : zone));
    setNotice(`${selectedZone.label} fitted around ${selectedZoneMembers.length} actors`);
  }

  function removeSelectedZone() {
    if (!selectedZone || selectedZoneMembers.length > 0) return;
    checkpoint();
    setZones((items) => items.filter((zone) => zone.id !== selectedZone.id));
    const removedBoundaryIds = new Set(boundaries.filter((boundary) => boundary.sourceZoneId === selectedZone.id || boundary.targetZoneId === selectedZone.id).map((boundary) => boundary.id));
    setBoundaries((items) => items.filter((boundary) => !removedBoundaryIds.has(boundary.id)));
    setEdges((items) => items.map((edge) => edge.boundaryId && removedBoundaryIds.has(edge.boundaryId) ? { ...edge, boundaryId: undefined } : edge));
    if (nodes[0]) setSelected({ kind: "node", id: nodes[0].id });
    else if (edges[0]) setSelected({ kind: "edge", id: edges[0].id });
    setNotice(`${selectedZone.label} removed`);
  }

  function removeSelectedNode() {
    if (!selectedNode) return;
    checkpoint();
    const nodeId = selectedNode.id;
    const remainingNodes = nodes.filter((node) => node.id !== nodeId);
    const removedEdges = edges.filter((edge) => edge.source === nodeId || edge.target === nodeId);
    const remainingEdges = edges.filter((edge) => edge.source !== nodeId && edge.target !== nodeId);
    setNodes(remainingNodes);
    setEdges(remainingEdges);
    const removedTaskIds = new Set(orchestration.tasks.filter((task) => task.sourceActorId === nodeId || task.targetActorId === nodeId).map((task) => task.id));
    setOrchestration((value) => ({
      ...value,
      coordinatorActorId: value.coordinatorActorId === nodeId ? remainingNodes.find((node) => node.type === "AGENT" || node.type === "SCHEDULER")?.id ?? "" : value.coordinatorActorId,
      tasks: value.tasks.filter((task) => !removedTaskIds.has(task.id)).map((task) => ({ ...task, dependsOn: task.dependsOn.filter((id) => !removedTaskIds.has(id)) })),
    }));
    if (connectFrom === nodeId) setConnectFrom(null);
    setDragging(null);
    if (remainingNodes[0]) setSelected({ kind: "node", id: remainingNodes[0].id });
    else if (remainingEdges[0]) setSelected({ kind: "edge", id: remainingEdges[0].id });
    else setSelected({ kind: "node", id: "" });
    setNotice(`${selectedNode.label} removed · ${removedEdges.length} connected relationship${removedEdges.length === 1 ? "" : "s"} removed`);
  }

  function removeSelectedEdge() {
    if (!selectedEdge) return;
    checkpoint();
    const edgeId = selectedEdge.id;
    const remainingEdges = edges.filter((edge) => edge.id !== edgeId);
    setEdges(remainingEdges);
    if (remainingEdges[0]) setSelected({ kind: "edge", id: remainingEdges[0].id });
    else if (nodes[0]) setSelected({ kind: "node", id: nodes[0].id });
    else setSelected({ kind: "node", id: "" });
    setNotice(`${selectedEdge.relationship} relationship removed`);
  }

  function selectNode(node: ArchitectureNode) {
    if (connectFrom && connectFrom !== node.id) {
      const source = nodeMap[connectFrom];
      const edge = edgeDefaults(source, node, edges.length + 1);
      const crossesZone = source.trustZoneId !== node.trustZoneId;
      const existingBoundary = crossesZone ? boundaries.find((boundary) => boundary.sourceZoneId === source.trustZoneId && boundary.targetZoneId === node.trustZoneId && boundary.allowedRelationships.includes(edge.relationship)) : undefined;
      const boundary = crossesZone ? existingBoundary ?? boundaryDefaults(edge, source, node, boundaries.length + 1) : undefined;
      const nextEdge = boundary ? { ...edge, boundaryId: boundary.id } : edge;
      checkpoint();
      if (boundary && !existingBoundary) setBoundaries((items) => [...items, boundary]);
      setEdges((items) => [...items, nextEdge]);
      setSelected({ kind: "edge", id: nextEdge.id });
      setConnectFrom(null);
      setMobilePanel("inspector");
      setNotice(boundary ? "Relationship and directional trust boundary created in SHADOW" : "Relationship created in SHADOW · attach the declared control before enforcement");
      return;
    }
    setSelected({ kind: "node", id: node.id });
    setFocusedNodeId(node.id);
    setMobilePanel("inspector");
  }

  function beginConnection() {
    if (!selectedNode) {
      setNotice("Select a source box before creating a relationship");
      return;
    }
    setConnectFrom(selectedNode.id);
    setNotice(`Connecting from ${selectedNode.label} · select a target box`);
  }

  function onNodePointerDown(event: ReactPointerEvent<HTMLButtonElement>, node: ArchitectureNode) {
    if (connectFrom || activeGraph !== "design") return;
    const rect = event.currentTarget.getBoundingClientRect();
    event.currentTarget.setPointerCapture(event.pointerId);
    dragCheckpointed.current = false;
    setDragging({ id: node.id, dx: event.clientX - rect.left, dy: event.clientY - rect.top });
  }

  function onZonePointerDown(event: ReactPointerEvent<HTMLButtonElement>, zone: TrustZoneDefinition, mode: ZoneGesture["mode"]) {
    if (activeGraph !== "design") return;
    event.stopPropagation();
    event.currentTarget.setPointerCapture(event.pointerId);
    dragCheckpointed.current = false;
    setZoneGesture({
      id: zone.id,
      mode,
      startClientX: event.clientX,
      startClientY: event.clientY,
      origin: { ...zone },
      members: Object.fromEntries(nodes.filter((node) => node.trustZoneId === zone.id).map((node) => [node.id, { x: node.x, y: node.y }])),
    });
    setSelected({ kind: "zone", id: zone.id });
  }

  function onTaskPointerDown(event: ReactPointerEvent<HTMLButtonElement>, task: WorkflowTask) {
    if (activeGraph !== "design" || designSurface !== "workflow") return;
    const rect = event.currentTarget.getBoundingClientRect();
    event.currentTarget.setPointerCapture(event.pointerId);
    dragCheckpointed.current = false;
    setTaskDragging({ id: task.id, dx: event.clientX - rect.left, dy: event.clientY - rect.top });
    setSelected({ kind: "task", id: task.id });
  }

  function onCanvasMove(event: ReactPointerEvent<HTMLDivElement>) {
    if (activeGraph !== "design") return;
    if (designSurface === "workflow") {
      if (!taskDragging) return;
      if (!dragCheckpointed.current) {
        checkpoint();
        dragCheckpointed.current = true;
      }
      const rect = event.currentTarget.getBoundingClientRect();
      const x = Math.max(GRAPH_BOARD_PADDING, Math.min(GRAPH_BOARD_MIN_WIDTH - TASK_NODE_WIDTH - GRAPH_BOARD_PADDING, (event.clientX - rect.left + event.currentTarget.scrollLeft - taskDragging.dx) / zoom));
      const y = Math.max(80, Math.min(GRAPH_BOARD_MIN_HEIGHT - TASK_NODE_HEIGHT - GRAPH_BOARD_PADDING, (event.clientY - rect.top + event.currentTarget.scrollTop - taskDragging.dy) / zoom));
      setOrchestration((value) => ({ ...value, tasks: value.tasks.map((task) => task.id === taskDragging.id ? { ...task, x, y } : task) }));
      return;
    }
    if (zoneGesture) {
      if (!dragCheckpointed.current) {
        checkpoint();
        dragCheckpointed.current = true;
      }
      const dx = (event.clientX - zoneGesture.startClientX) / zoom;
      const dy = (event.clientY - zoneGesture.startClientY) / zoom;
      if (zoneGesture.mode === "move") {
        const x = Math.max(GRAPH_BOARD_PADDING, zoneGesture.origin.x + dx);
        const y = Math.max(GRAPH_BOARD_PADDING, zoneGesture.origin.y + dy);
        const appliedX = x - zoneGesture.origin.x;
        const appliedY = y - zoneGesture.origin.y;
        setZones((items) => items.map((zone) => zone.id === zoneGesture.id ? { ...zone, x, y } : zone));
        setNodes((items) => items.map((node) => zoneGesture.members[node.id]
          ? { ...node, x: zoneGesture.members[node.id].x + appliedX, y: zoneGesture.members[node.id].y + appliedY }
          : node));
      } else {
        const width = Math.max(ZONE_MIN_WIDTH, zoneGesture.origin.width + dx);
        const height = Math.max(ZONE_MIN_HEIGHT, zoneGesture.origin.height + dy);
        setZones((items) => items.map((zone) => zone.id === zoneGesture.id ? { ...zone, width, height } : zone));
      }
      return;
    }
    if (!dragging) return;
    if (!dragCheckpointed.current) {
      checkpoint();
      dragCheckpointed.current = true;
    }
    const rect = event.currentTarget.getBoundingClientRect();
    const maxX = boardSize.width - ACTOR_NODE_WIDTH - GRAPH_BOARD_PADDING;
    const maxY = boardSize.height - ACTOR_NODE_HEIGHT - GRAPH_BOARD_PADDING;
    const x = Math.max(GRAPH_BOARD_PADDING, Math.min(maxX, (event.clientX - rect.left + event.currentTarget.scrollLeft - dragging.dx) / zoom));
    const y = Math.max(GRAPH_BOARD_PADDING, Math.min(maxY, (event.clientY - rect.top + event.currentTarget.scrollTop - dragging.dy) / zoom));
    const zone = zoneAtNodePosition(zones, x, y);
    setNodes((items) => items.map((node) => node.id === dragging.id ? { ...node, x, y, ...(zone ? { trustZone: zone.kind, trustZoneId: zone.id } : {}) } : node));
  }

  function finishPointerInteraction() {
    if (taskDragging) setTaskDragging(null);
    if (dragging) {
      setNodes((items) => items.map((node) => {
        if (node.id !== dragging.id) return node;
        const zone = zoneMap[node.trustZoneId];
        return zone ? { ...node, ...clampNodeToZone(node, zone) } : node;
      }));
    }
    if (zoneGesture?.mode === "resize") {
      const zone = zoneMap[zoneGesture.id];
      if (zone) setNodes((items) => items.map((node) => node.trustZoneId === zone.id ? { ...node, ...clampNodeToZone(node, zone) } : node));
    }
    setDragging(null);
    setTaskDragging(null);
    setZoneGesture(null);
    dragCheckpointed.current = false;
  }

  function applyTelemetry(value: unknown, source: string, destination: "runtime" | "drift" | "stats" = activeGraph === "drift" || activeGraph === "stats" ? activeGraph : "runtime") {
    try {
      const imported = parseRuntimeTelemetry(value);
      setRuntimeImport(imported);
      setRawLedgerEvents(
        imported.format === "INTERLOCK_LEDGER" ? ledgerEventsForStatistics(value) : null,
      );
      setActiveGraph(destination);
      setConnectFrom(null);
      setMobilePanel(null);
      const diff = computeRuntimeDiff(edges, imported.observations);
      setNotice(`${source} imported · ${imported.observations.length} relationships · ${diff.undeclared.length} undeclared · ${diff.controlBypassInteractionIds.length} bypass`);
    } catch (error) {
      setNotice(`Telemetry import rejected · ${error instanceof Error ? error.message : "invalid JSON"}`);
    }
  }

  async function importTelemetryFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      setNotice("Telemetry import rejected · files must be 5 MB or smaller");
      return;
    }
    try {
      applyTelemetry(JSON.parse(await file.text()), file.name);
    } catch {
      setNotice("Telemetry import rejected · file is not valid JSON");
    }
  }

  function selectGraph(view: GraphView) {
    setActiveGraph(view);
    pointerOverGraph.current = false;
    setConnectFrom(null);
    setMobilePanel(null);
    if ((view === "runtime" || view === "drift") && !runtimeImport) setNotice("Import Ledger or OTLP JSON telemetry to build the runtime graph");
    else if (view === "runs") setNotice("Connect to Run Control to operate the exact active ENFORCE deployment");
    else if (view === "deploy") setNotice("Compile and sign outside the browser, then promote through the Control Plane");
  }

  function reviseDesignFromDrift() {
    const undeclared = runtimeDiff.undeclared[0];
    const bypass = runtimeImport?.observations.find((item) => runtimeDiff.controlBypassInteractionIds.includes(item.interactionId));
    const relatedEdge = bypass ? edges.find((edge) => matchesEdge(edge, bypass)) : undefined;
    const unobservedEdge = edges.find((edge) => runtimeDiff.unobservedEdgeIds.includes(edge.id));
    const sourceTemplate = undeclared && [...nodes].sort((a, b) => b.id.length - a.id.length).find((node) => undeclared.source === node.id || undeclared.source.startsWith(`${node.id}.`) || undeclared.source.startsWith(`${node.id}-`));
    const target = relatedEdge ?? unobservedEdge;
    if (target) setSelected({ kind: "edge", id: target.id });
    else if (sourceTemplate) setSelected({ kind: "node", id: sourceTemplate.id });
    setActiveGraph("design");
    setDesignSurface("topology");
    setConnectFrom(null);
    setMobilePanel(null);
    pointerOverGraph.current = false;
    const focusId = target?.target ?? sourceTemplate?.id ?? nodes[0]?.id;
    requestAnimationFrame(() => { if (focusId) focusNode(focusId, false); });
    setNotice(undeclared
      ? `Design revision started · decide whether to declare ${undeclared.source} → ${undeclared.target} or block it at runtime`
      : "Design revision started · review the selected drift finding before exporting a new version");
  }

  function currentProject(): ProjectIdentity {
    return { id: projectId, version: projectVersion };
  }

  function exportManifest() {
    if (!isValidProjectId(projectId)) {
      setNotice("Export rejected · project id must be a lowercase slug, e.g. refund-agent");
      return;
    }
    const payload = buildManifestPayload({ nodes, edges, zones, boundaries, orchestration }, currentProject());
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    link.download = `${projectId}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    setNotice("Draft architecture exported · review is required before policy deployment");
  }

  function newProject() {
    checkpoint();
    restoreSnapshot({ nodes: [], edges: [], zones: initialZones, boundaries: [], orchestration: emptyOrchestration, projectId: EMPTY_PROJECT.id, projectVersion: EMPTY_PROJECT.version });
    setActiveGraph("design");
    setDesignSurface("topology");
    setNotice("New project created · Undo is available");
  }

  function applyManifestImport(value: unknown, source: string) {
    const result = parseManifestPayload(value);
    if (!result.ok) {
      setNotice(`Manifest import rejected · ${result.error}`);
      return;
    }
    checkpoint();
    restoreSnapshot({ ...result.snapshot, projectId: result.project.id, projectVersion: result.project.version });
    setActiveGraph("design");
    setDesignSurface("topology");
    setNotice(`${source} opened · ${result.snapshot.nodes.length} actor${result.snapshot.nodes.length === 1 ? "" : "s"}, ${result.snapshot.edges.length} relationship${result.snapshot.edges.length === 1 ? "" : "s"}`);
  }

  async function importManifestFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    try {
      applyManifestImport(JSON.parse(await file.text()), file.name);
    } catch {
      setNotice("Manifest import rejected · file is not valid JSON");
    }
  }

  function persistSavedProjects(next: SavedProjectsIndex) {
    setSavedProjects(next);
    try {
      window.localStorage.setItem(PROJECTS_STORAGE_KEY, JSON.stringify(next));
    } catch {
      // localStorage unavailable (private browsing, quota, disabled storage) · the project list
      // still works for this session, it just will not survive a reload.
    }
  }

  function saveProject() {
    if (!isValidProjectId(projectId)) {
      setNotice("Save rejected · project id must be a lowercase slug, e.g. refund-agent");
      return;
    }
    const manifest = buildManifestPayload({ nodes, edges, zones, boundaries, orchestration }, currentProject());
    persistSavedProjects({ ...savedProjects, [projectId]: { savedAt: new Date().toISOString(), manifest } });
    setNotice(`${projectId} saved locally · v${projectVersion}`);
  }

  function openSavedProject(id: string) {
    const saved = savedProjects[id];
    if (!saved) return;
    applyManifestImport(saved.manifest, id);
    setShowProjectMenu(false);
  }

  function deleteSavedProject(id: string) {
    const next = { ...savedProjects };
    delete next[id];
    persistSavedProjects(next);
    setNotice(`${id} removed from saved projects`);
  }

  return (
    <main className="studio-shell">
      <header className="topbar">
        <div className="brand-lockup"><span className="brand-mark">AI</span><div><strong>Agent Interlock</strong><span>Security Architecture Studio</span></div></div>
        <div className="architecture-title project-identity">
          <span className="draft-dot" />
          <input className={`project-id-input ${isValidProjectId(projectId) ? "" : "invalid"}`} aria-label="Project id" title="Project id · lowercase slug" value={projectId} onChange={(event) => setProjectId(event.target.value)} />
          <small><input className="project-version-input" aria-label="Project version" title="Project version" value={projectVersion} onChange={(event) => setProjectVersion(event.target.value)} /></small>
        </div>
        <div className="top-actions">
          <div className="project-menu">
            <button className="quiet-button" aria-haspopup="menu" aria-expanded={showProjectMenu} onClick={() => setShowProjectMenu((value) => !value)}>Projects</button>
            {showProjectMenu && <div className="project-menu-panel" role="menu">
              <button role="menuitem" onClick={() => { newProject(); setShowProjectMenu(false); }}>New project</button>
              <button role="menuitem" onClick={() => { manifestInput.current?.click(); setShowProjectMenu(false); }}>Open manifest…</button>
              <button role="menuitem" onClick={() => { saveProject(); setShowProjectMenu(false); }}>Save “{projectId || "untitled"}”</button>
              <div className="project-menu-rule" />
              <div className="project-menu-heading">Saved projects</div>
              {Object.keys(savedProjects).length === 0 && <p className="project-menu-empty">None saved in this browser yet.</p>}
              {Object.entries(savedProjects).sort(([, a], [, b]) => b.savedAt.localeCompare(a.savedAt)).map(([id, saved]) => (
                <div className="project-list-item" key={id}>
                  <button role="menuitem" onClick={() => openSavedProject(id)}><strong>{id}</strong><small>saved {new Date(saved.savedAt).toLocaleString()}</small></button>
                  <button className="project-delete" aria-label={`Delete saved project ${id}`} onClick={() => deleteSavedProject(id)}>×</button>
                </div>
              ))}
            </div>}
          </div>
          <input ref={manifestInput} className="file-input" type="file" accept="application/json,.json" onChange={importManifestFile} />
          {activeGraph === "design" && <><button className="quiet-button" onClick={() => setNotice(`${findings.length} findings · ${criticalCount} require attention`)}>Run security check</button><button className="primary-button" onClick={exportManifest}>Export manifest</button></>}
          {activeGraph === "deploy" && <button className="primary-button" onClick={() => selectGraph("design")}>Back to design</button>}
          {activeGraph === "runtime" && <><button className="quiet-button" onClick={() => telemetryInput.current?.click()}>Import telemetry</button><button className="primary-button" disabled={!runtimeImport} onClick={() => selectGraph("drift")}>Review drift</button></>}
          {activeGraph === "drift" && <><button className="quiet-button" onClick={() => telemetryInput.current?.click()}>Replace telemetry</button><button className="primary-button" onClick={reviseDesignFromDrift}>Revise design</button></>}
          {activeGraph === "stats" && <><button className="quiet-button" onClick={() => runtimeImport && selectGraph("drift")} disabled={!runtimeImport}>Review drift</button><button className="primary-button" onClick={() => telemetryInput.current?.click()}>Import telemetry</button></>}
        </div>
      </header>

      <section className={`workspace workspace-${activeGraph} ${isGraphView ? "" : "focus-workspace"}`}>
        {mobilePanel && <button className="mobile-scrim" aria-label="Close side panel" onClick={() => setMobilePanel(null)} />}
        <aside className={`toolbox ${mobilePanel === "palette" ? "mobile-open" : ""}`} aria-label={activeGraph === "design" ? designSurface === "topology" ? "Actor palette" : "Task palette" : "Runtime telemetry"}>
          <button className="panel-close" aria-label={activeGraph === "design" ? designSurface === "topology" ? "Close actor palette" : "Close task palette" : "Close runtime telemetry"} onClick={() => setMobilePanel(null)}>×</button>
          {activeGraph === "design" ? designSurface === "topology" ? <>
            <div className="panel-heading"><span>BUILD</span><strong>Actor palette</strong></div>
            <p className="panel-note">Add an actor. Its trust zone is persisted and updates when you move it across a zone boundary.</p>
            <div className="palette-grid">
              {(["USER", "AGENT", "SUBAGENT", "RAG", "TOOL", "MEMORY", "SCHEDULER", "EXTERNAL"] as NodeType[]).map((type) => <button key={type} className={`palette-item tone-${nodeTone[type]}`} onClick={() => addNode(type)}><span>{type === "SUBAGENT" ? "SA" : type.slice(0, 2)}</span>{type === "SUBAGENT" ? "Sub-Agent" : type[0] + type.slice(1).toLowerCase()}</button>)}
            </div>
            <button className="add-zone-button" onClick={addZone}><span>＋</span>Add trust zone</button>
            <div className="toolbox-rule" />
            <button className={`connect-button ${connectFrom ? "active" : ""}`} onClick={beginConnection}><span>↗</span>{connectFrom ? "Choose target box" : "Connect selected box"}</button>
            <div className="legend">
              <strong>Assurance</strong>
              <span><i className="dot declared" />Declared</span><span><i className="dot observed" />Observed</span><span><i className="dot enforced" />Enforced</span><span><i className="dot reconciled" />Reconciled</span>
            </div>
            <div className="zone-guide">
              <strong>Trust zones</strong>
              <span><b>Internal</b><small>Managed identities and controlled services</small></span>
              <span><b>External</b><small>Third-party or untrusted destinations</small></span>
              <p>Cross-zone edges must bind a directional Trust Boundary. The boundary is compiled and enforced by the matching gateway.</p>
            </div>
          </> : <>
            <div className="panel-heading"><span>ORCHESTRATE</span><strong>Task palette</strong></div>
            <p className="panel-note">Tasks reference actors from the topology. A2A and MCP tasks must have matching declared edges.</p>
            <div className="task-palette">
              {(["A2A", "MCP", "LOCAL", "HUMAN"] as WorkflowTask["transport"][]).map((transport) => <button key={transport} onClick={() => addWorkflowTask(transport)}><span>{transport === "HUMAN" ? "H" : transport}</span><div><strong>{transport} task</strong><small>{transport === "A2A" ? "Delegate to another agent" : transport === "MCP" ? "Invoke a governed tool" : transport === "HUMAN" ? "Pause for a person" : "Run a host adapter"}</small></div></button>)}
            </div>
            <div className="toolbox-rule" />
            <label className="toolbox-field">Coordinator<select value={orchestration.coordinatorActorId} onChange={(event) => updateOrchestration({ coordinatorActorId: event.target.value })}>{nodes.filter((node) => ["AGENT", "SUBAGENT", "SCHEDULER"].includes(node.type)).map((node) => <option key={node.id} value={node.id}>{node.label}</option>)}</select></label>
            <label className="toolbox-field">Pattern<select value={orchestration.pattern} onChange={(event) => updateOrchestration({ pattern: event.target.value as OrchestrationDesign["pattern"] })}><option>STATE_GRAPH</option><option>HIERARCHICAL</option><option>CONVERSATIONAL</option><option>HYBRID</option></select></label>
            <div className="run-budget-card"><strong>Run limits</strong><span><b>{orchestration.maxParallelism}</b> parallel</span><span><b>{orchestration.maxMessages}</b> messages</span><span><b>{Math.round(orchestration.maxDurationSeconds / 60)}</b> minutes</span></div>
          </> : <>
            <div className="panel-heading"><span>OBSERVE</span><strong>Runtime telemetry</strong></div>
            <p className="panel-note">Import Interlock Ledger events or OTLP/HTTP JSON. Files stay in this browser session.</p>
            <input ref={telemetryInput} className="file-input" type="file" accept="application/json,.json" onChange={importTelemetryFile} />
            <button className="telemetry-button primary" onClick={() => telemetryInput.current?.click()}><span>↑</span>Import telemetry</button>
            <div className="runtime-source-card"><span>FORMAT</span><strong>{runtimeImport?.format ?? "No telemetry"}</strong><small>{runtimeImport ? `${runtimeImport.observations.length} observed relationships` : "JSON · maximum 5 MB"}</small></div>
            <div className="toolbox-rule" />
            <div className="runtime-contract"><strong>Security context</strong><code>interlock.source.actor.id</code><code>interlock.target.actor.id</code><code>interlock.relationship.id</code><code>interlock.control.evaluated</code></div>
            <div className="legend runtime-legend"><strong>Runtime state</strong><span><i className="dot observed" />Observed</span><span><i className="dot reconciled" />Controlled</span><span><i className="dot critical" />Drift / bypass</span></div>
          </>}
        </aside>

        <section className="canvas-region">
          <div className="canvas-toolbar">
            <nav className="workflow-nav" aria-label="Security lifecycle">
              {graphViewOptions.map((view, index) => <button key={view.id} aria-label={`${index + 1}. ${view.label}: ${view.phase}`} aria-current={activeGraph === view.id ? "step" : undefined} aria-pressed={activeGraph === view.id} className={activeGraph === view.id ? "active" : ""} title={view.description} onClick={() => selectGraph(view.id)}><span className="workflow-number">{index + 1}</span><span className="workflow-copy"><strong>{view.label}</strong><small>{view.phase}</small></span>{view.id === "runtime" && runtimeImport && <i aria-label="Telemetry loaded">✓</i>}</button>)}
            </nav>
            <div className="context-toolbar">
              <div className="view-intro"><strong>{activeView.phase}</strong><span>{activeView.description}</span></div>
              {activeGraph === "design" && <div className="design-surface-switch" aria-label="Design graph surface"><button className={designSurface === "topology" ? "active" : ""} aria-pressed={designSurface === "topology"} onClick={() => { setDesignSurface("topology"); setSelected({ kind: "edge", id: edges[0]?.id ?? "" }); }}>Actor topology</button><button className={designSurface === "workflow" ? "active" : ""} aria-pressed={designSurface === "workflow"} onClick={() => { setDesignSurface("workflow"); setSelected({ kind: "task", id: orchestration.tasks[0]?.id ?? "" }); }}>Task workflow</button></div>}
              {isGraphView && <div className="mobile-panel-actions"><button onClick={() => setMobilePanel("palette")}>{activeGraph === "design" ? designSurface === "topology" ? "Actors" : "Tasks" : "Telemetry"}</button><button onClick={() => setMobilePanel("inspector")}>Inspect</button></div>}
              {isGraphView && <div className="canvas-toolbar-right">
                <div className="canvas-stats">{activeGraph === "design" ? designSurface === "topology" ? <><span>{nodes.length} actors</span><span>{edges.length} relationships</span><span>{boundaries.length} boundaries</span><span>{coverage}% enforced</span></> : <><span>{orchestration.tasks.length} tasks</span><span>{orchestration.tasks.filter((task) => task.transport === "A2A").length} A2A</span><span>{orchestration.maxParallelism} parallel</span></> : activeGraph === "runtime" ? <><span>{runtimeNodes.length} runtime actors</span><span>{runtimeImport?.observations.length ?? 0} calls</span><span>{runtimeImport?.observations.filter((item) => item.controlEvaluated).length ?? 0} controlled</span></> : runtimeImport ? <><span>{runtimeDiff.undeclared.length} undeclared</span><span>{runtimeDiff.unobservedEdgeIds.length} unobserved</span><span>{runtimeDiff.controlBypassInteractionIds.length} bypass</span></> : <><span>— undeclared</span><span>— unobserved</span><span>— bypass</span></>}</div>
                <div className="view-controls" aria-label="Graph view controls" title="Mouse wheel or Command/Ctrl + wheel zooms · Shift + wheel pans · Keyboard shortcuts work while the graph is focused"><button aria-label="Zoom out" aria-keyshortcuts="Meta+- Control+-" title="Zoom out · Command− on Mac · Ctrl− on Windows" onClick={() => changeZoom(zoom - ZOOM_STEP)}>−</button><span>{Math.round(zoom * 100)}%</span><button aria-label="Zoom in" aria-keyshortcuts="Meta+= Control+=" title="Zoom in · Command+ on Mac · Ctrl+ on Windows" onClick={() => changeZoom(zoom + ZOOM_STEP)}>+</button><button onClick={() => fitGraph()}>Fit</button><button onClick={focusCurrentContext}>Focus</button></div>
              </div>}
            </div>
          </div>
          {activeGraph === "stats" ? <StatsPanel rawLedgerEvents={rawLedgerEvents} importedFormat={runtimeImport?.format ?? null} notify={setNotice} onImportTelemetry={() => telemetryInput.current?.click()} />
          : activeGraph === "deploy" ? <DeployPanel notify={setNotice} onBackToDesign={() => selectGraph("design")} apiUrl={controlPlaneUrl} token={controlPlaneToken} onApiUrlChange={setControlPlaneUrl} onTokenChange={setControlPlaneToken} />
          : activeGraph === "runs" ? <RunsPanel notify={setNotice} apiUrl={controlPlaneUrl} token={controlPlaneToken} onApiUrlChange={setControlPlaneUrl} onTokenChange={setControlPlaneToken} onOpenRuntimeTelemetry={(events, source) => applyTelemetry(events, source, "runtime")} />
          : <div ref={canvasScroll} tabIndex={0} aria-label={`${activeView.label} canvas`} className={`canvas-scroll ${connectFrom ? "connecting" : ""}`} onPointerEnter={() => { pointerOverGraph.current = true; }} onPointerLeave={() => { pointerOverGraph.current = false; }} onPointerMove={onCanvasMove} onPointerUp={finishPointerInteraction} onPointerCancel={finishPointerInteraction}>
            <div className="graph-surface" style={{ width: boardSize.width * zoom, height: boardSize.height * zoom }}>
            <div className={`graph-board ${dragging ? `drag-zone-${nodeMap[dragging.id]?.trustZone.toLowerCase()}` : ""} ${zoneGesture ? "editing-zone" : ""}`} style={{ width: boardSize.width, height: boardSize.height, transform: `scale(${zoom})` }}>
              {activeGraph === "design" && designSurface === "workflow" ? <>
              <div className="workflow-board-header"><div><span>ORCHESTRATION</span><strong>{orchestration.pattern.replaceAll("_", " ")}</strong><small>Coordinator · {nodeMap[orchestration.coordinatorActorId]?.label ?? "Not assigned"}</small></div><div className="workflow-budget"><span><b>{orchestration.maxParallelism}</b> parallel</span><span><b>{orchestration.maxMessages}</b> messages</span><span><b>{Math.round(orchestration.maxDurationSeconds / 60)}</b> min</span></div></div>
              <svg className="workflow-edge-layer" viewBox={`0 0 ${boardSize.width} ${boardSize.height}`} aria-label="Workflow task dependencies">
                <defs><marker id="workflow-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L7,3 z" /></marker></defs>
                {orchestration.tasks.flatMap((task) => task.dependsOn.map((dependencyId) => { const dependency = orchestration.tasks.find((item) => item.id === dependencyId); if (!dependency) return null; const x1 = dependency.x + TASK_NODE_WIDTH, y1 = dependency.y + TASK_NODE_HEIGHT / 2, x2 = task.x, y2 = task.y + TASK_NODE_HEIGHT / 2, bend = Math.max(55, Math.abs(x2 - x1) * .45); return <path key={`${dependencyId}-${task.id}`} d={`M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`} markerEnd="url(#workflow-arrow)" />; }))}
              </svg>
              {orchestration.tasks.map((task) => <button key={task.id} className={`workflow-task transport-${task.transport.toLowerCase()} ${selected.kind === "task" && selected.id === task.id ? "selected" : ""} ${taskDragging?.id === task.id ? "dragging" : ""}`} style={{ left: task.x, top: task.y }} onPointerDown={(event) => onTaskPointerDown(event, task)} onLostPointerCapture={() => { setTaskDragging(null); dragCheckpointed.current = false; }} onClick={() => { setSelected({ kind: "task", id: task.id }); setMobilePanel("inspector"); }} aria-label={`${task.label}, ${task.transport} task`}><span className="task-transport">{task.transport}</span><span className="task-copy"><strong>{task.label}</strong><small>{nodeMap[task.sourceActorId]?.label ?? task.sourceActorId} → {nodeMap[task.targetActorId]?.label ?? task.targetActorId}</small><em>{task.purpose}</em></span><i className={task.approvalRequired ? "approval" : ""}>{task.approvalRequired ? "H" : task.maxAttempts}</i></button>)}
              {orchestration.tasks.length === 0 && <div className="canvas-empty workflow-empty"><span>WF</span><strong>No workflow tasks</strong><p>Add A2A, MCP, Local, or Human tasks from the palette.</p></div>}
              </> : <>
              {zones.map((zone) => <div key={zone.id} className={`trust-zone zone-${zone.kind.toLowerCase()} ${activeGraph === "design" && selected.kind === "zone" && selected.id === zone.id ? "selected" : ""}`} role="group" aria-label={`${zone.label}, ${zone.kind} trust zone`} style={{ left: zone.x, top: zone.y, width: zone.width, height: zone.height }}>
                {activeGraph === "design"
                  ? <button className="zone-label" title={`${zone.description} · drag to move the zone and its actors`} aria-label={`Move zone: ${zone.label}`} onPointerDown={(event) => onZonePointerDown(event, zone, "move")} onClick={() => { setSelected({ kind: "zone", id: zone.id }); setMobilePanel("inspector"); }}><b>{zone.kind}</b><small>{zone.label}</small><i>{nodes.filter((node) => node.trustZoneId === zone.id).length}</i></button>
                  : <span className="zone-label static"><b>{zone.kind}</b><small>{zone.label}</small></span>}
                {activeGraph === "design" && <button className="zone-resize-handle" aria-label={`Resize zone: ${zone.label}`} title="Drag to resize" onPointerDown={(event) => onZonePointerDown(event, zone, "resize")}>↘</button>}
              </div>)}
              {(activeGraph === "runtime" || activeGraph === "drift") && !runtimeImport && <div className="canvas-empty"><span>RT</span><strong>No runtime telemetry</strong><p>Import Ledger events or OTLP JSON emitted by a real run to reconcile actual calls with this architecture.</p><button onClick={() => telemetryInput.current?.click()}>Import telemetry</button></div>}
              <svg className="edge-layer" viewBox={`0 0 ${boardSize.width} ${boardSize.height}`} aria-label="Architecture relationships">
                <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto" markerUnits="strokeWidth"><path d="M0,0 L0,6 L7,3 z" /></marker></defs>
                {visualEdges.map((edge) => {
                  const source = visualNodeMap[edge.source]; const target = visualNodeMap[edge.target]; if (!source || !target) return null;
                  const x1 = source.x + ACTOR_NODE_WIDTH, y1 = source.y + ACTOR_NODE_HEIGHT / 2, x2 = target.x, y2 = target.y + ACTOR_NODE_HEIGHT / 2, bend = Math.max(45, Math.abs(x2 - x1) * .46);
                  const selectedLine = activeGraph === "design" && selected.kind === "edge" && selected.id === edge.id;
                  return <path key={edge.id} className={`edge-path ${selectedLine ? "selected" : ""} mode-${edge.mode.toLowerCase()} visual-${edge.visualState}`} d={`M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}`} markerEnd="url(#arrow)" />;
                })}
              </svg>
              {visualEdges.map((edge) => {
                const source = visualNodeMap[edge.source]; const target = visualNodeMap[edge.target]; if (!source || !target) return null;
                const left = (source.x + ACTOR_NODE_WIDTH + target.x) / 2 - 48; const top = (source.y + target.y) / 2 + 19;
                const designedEdge = edges.find((item) => item.id === edge.id);
                return <button key={edge.id} title={`${edge.source} → ${edge.target}${designedEdge?.boundaryId ? ` · ${designedEdge.boundaryId}` : ""}`} style={{ left, top }} className={`edge-label visual-${edge.visualState} ${designedEdge?.boundaryId ? "boundary-crossing" : ""} ${activeGraph === "design" && selected.kind === "edge" && selected.id === edge.id ? "selected" : ""}`} onClick={() => { if (activeGraph === "design") { setSelected({ kind: "edge", id: edge.id }); setMobilePanel("inspector"); } else { focusNode(edge.target); setNotice(`${edge.relationshipId} ${edge.source} → ${edge.target} · ${edge.visualState}`); } }}><span>{edge.relationship}</span><small>{edge.relationshipId}{edge.visualState === "bypass" || edge.visualState === "undeclared" ? " !" : ""}</small>{designedEdge?.boundaryId && <i title="Compiled trust boundary">B</i>}</button>;
              })}
              {visualNodes.map((node) => { const runtimeOnly = !nodeMap[node.id]; const zone = zoneMap[node.trustZoneId]; return <button key={node.id} data-trust-zone={node.trustZone} data-trust-zone-id={node.trustZoneId} title={`${node.label} · ${runtimeOnly ? node.id : `${node.type} · ${node.owner} · ${zone?.label ?? node.trustZone}`}`} style={{ left: node.x, top: node.y }} className={`actor-node tone-${nodeTone[node.type]} trust-${node.trustZone.toLowerCase()} ${activeGraph === "design" && selected.kind === "node" && selected.id === node.id ? "selected" : ""} ${focusedNodeId === node.id ? "focused" : ""} ${dragging?.id === node.id ? "dragging" : ""} ${connectFrom === node.id ? "connect-source" : ""} ${runtimeOnly ? "runtime-only" : ""}`} onPointerDown={(event) => onNodePointerDown(event, node)} onLostPointerCapture={() => { setDragging(null); dragCheckpointed.current = false; }} onClick={() => activeGraph === "design" ? selectNode(node) : focusNode(node.id)} aria-label={`${node.label}, ${node.type}, ${zone?.label ?? node.trustZone} trust zone`}><span className="node-icon">{node.type === "SUBAGENT" ? "SA" : node.type.slice(0, 2)}</span><span className="node-copy"><strong>{node.label}</strong><small>{runtimeOnly ? node.id : `${node.type} · ${zone?.label ?? node.trustZone}`}</small></span><i className={`node-status ${runtimeOnly ? "warning" : ""}`} /></button>; })}
              </>}
            </div>
            </div>
          </div>}
          <div className="notice-bar"><div className="notice-copy" role="status" aria-live="polite"><span>●</span>{notice}</div>{activeGraph === "design" && <div className="draft-actions"><button disabled={!past.length} onClick={undo}>Undo</button><button disabled={!future.length} onClick={redo}>Redo</button><button onClick={resetDraft}>Reset draft</button></div>}</div>
        </section>

        <aside className={`inspector ${mobilePanel === "inspector" ? "mobile-open" : ""}`} aria-label="Architecture inspector">
          <button className="panel-close" aria-label="Close inspector" onClick={() => setMobilePanel(null)}>×</button>
          <div className="panel-heading"><span>INSPECT</span><strong>{activeGraph === "design" ? selectedTask ? "Workflow task" : selectedEdge ? "Relationship security" : selectedZone ? "Trust zone" : "Actor contract" : "Runtime reconciliation"}</strong></div>
          {activeGraph !== "design" ? <>
            <div className="inspector-body runtime-inspector">
              <div className="runtime-health"><span className={!runtimeImport ? "pending" : runtimeDiff.undeclared.length || runtimeDiff.controlBypassInteractionIds.length ? "unsafe" : "safe"}>{!runtimeImport ? "·" : runtimeDiff.undeclared.length || runtimeDiff.controlBypassInteractionIds.length ? "!" : "✓"}</span><div><strong>{runtimeImport ? runtimeDiff.undeclared.length || runtimeDiff.controlBypassInteractionIds.length ? "Runtime drift detected" : "Runtime conforms" : "Awaiting telemetry"}</strong><small>{runtimeImport?.format ?? "Ledger or OTLP JSON"}</small></div></div>
              <div className="runtime-metrics"><div><span>{runtimeImport ? runtimeImport.observations.length : "—"}</span><small>Observed</small></div><div><span>{runtimeImport ? runtimeDiff.undeclared.length : "—"}</span><small>Undeclared</small></div><div><span>{runtimeImport ? runtimeDiff.controlBypassInteractionIds.length : "—"}</span><small>Bypass</small></div></div>
              <div className="control-heading"><span>Reconciliation results</span><small>{runtimeResultCount}</small></div>
              {!runtimeImport && <div className="runtime-empty-note">Import runtime telemetry to see actual relationship evidence.</div>}
              {runtimeImport && runtimeDiff.undeclared.map((item) => <button className="drift-card critical" key={`undeclared-${item.interactionId}`} onClick={() => { focusNode(item.target); setMobilePanel(null); }}><i>!</i><span><strong>Undeclared relationship</strong><small>{item.source} → {item.target}</small><code>{item.relationshipId} · {item.interactionId}</code></span></button>)}
              {runtimeImport && runtimeDiff.controlBypassInteractionIds.map((id) => { const observation = runtimeImport.observations.find((item) => item.interactionId === id); return <button className="drift-card critical" key={`bypass-${id}`} onClick={() => { if (observation) focusNode(observation.target); setMobilePanel(null); }}><i>!</i><span><strong>Control evaluation missing</strong><small>Interaction reached runtime without control evidence</small><code>{id}</code></span></button>; })}
              {runtimeImport && runtimeDiff.unobservedEdgeIds.slice(0, 4).map((id) => { const edge = edges.find((item) => item.id === id); return <button className="drift-card warning" key={`unobserved-${id}`} onClick={() => { if (edge) focusNode(edge.target); setMobilePanel(null); }}><i>–</i><span><strong>Design edge not observed</strong><small>No matching call in this telemetry set</small><code>{id}</code></span></button>; })}
              {(runtimeImport?.issues ?? []).map((issue, index) => <div className="drift-card warning" key={`${issue.code}-${index}`}><i>?</i><span><strong>{issue.code}</strong><small>{issue.message}</small><code>{issue.spanId ?? "no span id"}</code></span></div>)}
            </div>
            <div className="runtime-boundary-note"><strong>No inferred security facts</strong><span>Standard GenAI fields classify spans. Exact drift decisions require explicit <code>interlock.*</code> attributes.</span></div>
          </> : <>
          {selectedTask ? (
            <div className="inspector-body task-inspector">
              <div className="selection-summary"><span className={`task-summary transport-${selectedTask.transport.toLowerCase()}`}>{selectedTask.transport === "HUMAN" ? "H" : selectedTask.transport.slice(0, 2)}</span><div><strong>{selectedTask.label}</strong><small>{selectedTask.id}</small></div><em>{selectedTask.transport}</em></div>
              <label>Task name<input value={selectedTask.label} onChange={(event) => updateSelectedTask({ label: event.target.value })} /></label>
              <label>Transport<select value={selectedTask.transport} onChange={(event) => updateSelectedTask({ transport: event.target.value as WorkflowTask["transport"] })}><option>A2A</option><option>MCP</option><option>LOCAL</option><option>HUMAN</option></select></label>
              <label>Source actor<select value={selectedTask.sourceActorId} onChange={(event) => updateSelectedTask({ sourceActorId: event.target.value })}>{nodes.map((node) => <option key={node.id} value={node.id}>{node.label} · {node.type}</option>)}</select></label>
              <label>Target actor<select value={selectedTask.targetActorId} onChange={(event) => updateSelectedTask({ targetActorId: event.target.value })}>{nodes.map((node) => <option key={node.id} value={node.id}>{node.label} · {node.type}</option>)}</select></label>
              <label>Purpose<input value={selectedTask.purpose} onChange={(event) => updateSelectedTask({ purpose: event.target.value })} /></label>
              <div className="field-group"><span>Depends on</span><div className="dependency-list">{orchestration.tasks.filter((task) => task.id !== selectedTask.id).map((task) => { const selected = selectedTask.dependsOn.includes(task.id); const createsCycle = !selected && workflowDependencyCreatesCycle(orchestration.tasks, selectedTask.id, task.id); return <button key={task.id} disabled={createsCycle} title={createsCycle ? "Unavailable because it would create a workflow cycle" : undefined} className={selected ? "chip selected" : "chip"} onClick={() => updateSelectedTask({ dependsOn: selected ? selectedTask.dependsOn.filter((id) => id !== task.id) : [...selectedTask.dependsOn, task.id] })}>{task.label}{createsCycle ? " · cycle" : ""}</button>; })}</div></div>
              <div className="field-group"><span>Data classes</span><div className="chip-row">{["D2", "D3", "D5", "D7", "D8"].map((item) => <button key={item} className={selectedTask.dataClasses.includes(item) ? "chip selected" : "chip"} onClick={() => updateSelectedTask({ dataClasses: selectedTask.dataClasses.includes(item) ? selectedTask.dataClasses.filter((value) => value !== item) : [...selectedTask.dataClasses, item] })}>{item}</button>)}</div></div>
              <label>Acceptance criteria<input placeholder="Grounded evidence, schema valid" value={selectedTask.acceptanceCriteria.join(", ")} onChange={(event) => updateSelectedTask({ acceptanceCriteria: event.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} /></label>
              <div className="geometry-grid task-limits"><label>Attempts<input type="number" min="1" max="10" value={selectedTask.maxAttempts} onChange={(event) => updateSelectedTask({ maxAttempts: Math.max(1, Number(event.target.value)) })} /></label><label>Timeout sec<input type="number" min="1" value={selectedTask.timeoutSeconds} onChange={(event) => updateSelectedTask({ timeoutSeconds: Math.max(1, Number(event.target.value)) })} /></label></div>
              <label>On failure<select value={selectedTask.onFailure} onChange={(event) => updateSelectedTask({ onFailure: event.target.value as WorkflowTask["onFailure"] })}><option>FAIL_WORKFLOW</option><option>SKIP</option><option>CONTINUE</option></select></label>
              <div className="toggle-row"><div><strong>Human approval gate</strong><small>Pause the run before dispatch</small></div><button aria-label="Require approval for workflow task" aria-pressed={selectedTask.approvalRequired} className={`toggle ${selectedTask.approvalRequired ? "on" : ""}`} onClick={() => updateSelectedTask({ approvalRequired: !selectedTask.approvalRequired })}><i /></button></div>
              <div className="control-heading"><span>Run policy</span><small>{orchestration.pattern}</small></div>
              <div className="geometry-grid task-limits"><label>Parallel<input type="number" min="1" value={orchestration.maxParallelism} onChange={(event) => updateOrchestration({ maxParallelism: Math.max(1, Number(event.target.value)) })} /></label><label>Messages<input type="number" min="1" value={orchestration.maxMessages} onChange={(event) => updateOrchestration({ maxMessages: Math.max(1, Number(event.target.value)) })} /></label><label>Max tasks<input type="number" min="1" value={orchestration.maxTasks} onChange={(event) => updateOrchestration({ maxTasks: Math.max(1, Number(event.target.value)) })} /></label><label>Duration sec<input type="number" min="1" value={orchestration.maxDurationSeconds} onChange={(event) => updateOrchestration({ maxDurationSeconds: Math.max(1, Number(event.target.value)) })} /></label></div>
              <button className="danger-button" onClick={removeSelectedTask}><span>Remove workflow task</span><small>Dependent tasks will be unlinked</small></button>
            </div>
          ) : selectedEdge ? (
            <div className="inspector-body">
              <div className="selection-summary"><span className="relation-mark">→</span><div><strong>{selectedEdge.relationship}</strong><small>{selectedEdge.source} → {selectedEdge.target}</small></div><em>{selectedEdge.relationshipId}</em></div>
              <label>Enforcement mode<select value={selectedEdge.mode} onChange={(e) => updateEdge({ mode: e.target.value as Mode })}><option>OBSERVE</option><option>SHADOW</option><option>ENFORCE</option></select></label>
              <label>Failure mode<select value={selectedEdge.failureMode} onChange={(e) => updateEdge({ failureMode: e.target.value as ArchitectureEdge["failureMode"] })}><option>FAIL_CLOSED</option><option>DEGRADE_READ_ONLY</option><option>FAIL_OPEN</option></select></label>
              <div className="field-group"><span>Allowed data</span><div className="chip-row">{["D2", "D3", "D5", "D7", "D8"].map((item) => <button key={item} className={selectedEdge.allowedData.includes(item) ? "chip selected" : "chip"} onClick={() => updateEdge({ allowedData: selectedEdge.allowedData.includes(item) ? selectedEdge.allowedData.filter((value) => value !== item) : [...selectedEdge.allowedData, item] })}>{item}</button>)}</div></div>
              <div className="control-heading"><span>Trust boundary</span><small>{selectedEdgeCrossesZone ? "Required" : "Same zone"}</small></div>
              {selectedEdgeCrossesZone ? <div className="boundary-editor">
                <label>Directional boundary<select value={selectedEdge.boundaryId ?? ""} onChange={(event) => updateEdge({ boundaryId: event.target.value || undefined })}><option value="">Unbound · deployment blocked</option>{boundaries.filter((boundary) => boundary.sourceZoneId === selectedEdgeSource?.trustZoneId && boundary.targetZoneId === selectedEdgeTarget?.trustZoneId).map((boundary) => <option key={boundary.id} value={boundary.id}>{boundary.label} · {boundary.point}</option>)}</select></label>
                {!selectedBoundary && <button className="secondary-button" onClick={bindBoundaryToSelectedEdge}>Create matching boundary</button>}
                {selectedBoundary && <><div className="boundary-route"><span>{zoneMap[selectedBoundary.sourceZoneId]?.label ?? selectedBoundary.sourceZoneId}</span><b>→</b><span>{zoneMap[selectedBoundary.targetZoneId]?.label ?? selectedBoundary.targetZoneId}</span></div><label>Boundary name<input value={selectedBoundary.label} onChange={(event) => updateSelectedBoundary({ label: event.target.value })} /></label><label>Enforcement point<select value={selectedBoundary.point} onChange={(event) => updateSelectedBoundary({ point: event.target.value as EnforcementPoint })}>{["INPUT_GATEWAY", "RAG_GATEWAY", "MCP_GATEWAY", "A2A_BROKER", "EGRESS_GATEWAY", "AUDIT_SINK"].map((point) => <option key={point}>{point}</option>)}</select></label><div className="geometry-grid task-limits"><label>Mode<select value={selectedBoundary.mode} onChange={(event) => updateSelectedBoundary({ mode: event.target.value as Mode })}><option>OBSERVE</option><option>SHADOW</option><option>ENFORCE</option></select></label><label>Failure<select value={selectedBoundary.failureMode} onChange={(event) => updateSelectedBoundary({ failureMode: event.target.value as TrustBoundaryDefinition["failureMode"] })}><option>FAIL_CLOSED</option><option>DEGRADE_READ_ONLY</option><option>FAIL_OPEN</option></select></label></div><div className="field-group"><span>Boundary data</span><div className="chip-row">{["D2", "D3", "D5", "D7", "D8"].map((item) => <button key={item} className={selectedBoundary.allowedData.includes(item) ? "chip selected" : "chip"} onClick={() => updateSelectedBoundary({ allowedData: selectedBoundary.allowedData.includes(item) ? selectedBoundary.allowedData.filter((value) => value !== item) : [...selectedBoundary.allowedData, item], deniedData: selectedBoundary.allowedData.includes(item) ? [...new Set([...selectedBoundary.deniedData, item])] : selectedBoundary.deniedData.filter((value) => value !== item) })}>{item}</button>)}</div></div><label>Maximum payload bytes<input type="number" min="1" value={selectedBoundary.maxPayloadBytes} onChange={(event) => updateSelectedBoundary({ maxPayloadBytes: Math.max(1, Number(event.target.value)) })} /></label><div className="toggle-row"><div><strong>Identity binding</strong><small>Require authenticated source actor</small></div><button aria-label="Require boundary identity binding" aria-pressed={selectedBoundary.requireIdentity} className={`toggle ${selectedBoundary.requireIdentity ? "on" : ""}`} onClick={() => updateSelectedBoundary({ requireIdentity: !selectedBoundary.requireIdentity })}><i /></button></div><div className="toggle-row"><div><strong>Tenant binding</strong><small>Keep A2A and data flows tenant-scoped</small></div><button aria-label="Require boundary tenant binding" aria-pressed={selectedBoundary.requireTenantBinding} className={`toggle ${selectedBoundary.requireTenantBinding ? "on" : ""}`} onClick={() => updateSelectedBoundary({ requireTenantBinding: !selectedBoundary.requireTenantBinding })}><i /></button></div></>}
              </div> : <div className="same-zone-note">Both actors are in <strong>{zoneMap[selectedEdgeSource?.trustZoneId ?? ""]?.label ?? "the same zone"}</strong>. The relationship policy still applies; no cross-zone boundary is needed.</div>}
              <div className="toggle-row"><div><strong>Human approval</strong><small>Required before high-impact execution</small></div><button aria-label="Require human approval" aria-pressed={selectedEdge.approvalRequired} className={`toggle ${selectedEdge.approvalRequired ? "on" : ""}`} onClick={() => updateEdge({ approvalRequired: !selectedEdge.approvalRequired })}><i /></button></div>
              {selectedEdge.relationshipId === "REL-06" && <><div className="toggle-row"><div><strong>Same tenant only</strong><small>Reject cross-tenant delegation</small></div><button aria-label="Restrict delegation to the same tenant" aria-pressed={selectedEdge.sameTenant} className={`toggle ${selectedEdge.sameTenant ? "on" : ""}`} onClick={() => updateEdge({ sameTenant: !selectedEdge.sameTenant })}><i /></button></div><label>Maximum delegation depth<input type="number" min="0" max="8" value={selectedEdge.maxDepth} onChange={(e) => updateEdge({ maxDepth: Number(e.target.value) })} /></label></>}
              <div className="control-heading"><span>Security controls</span><small>{selectedEdge.controls.length}</small></div>
              {selectedEdge.controls.map((control) => <div className="control-card" key={control.id}><div><strong>{control.id}</strong><small>{control.objective} · {control.timing}</small></div><div className="control-settings"><select className="point-select" aria-label={`${control.id} enforcement point`} value={control.point} onChange={(e) => updateControl(control.id, { point: e.target.value as EnforcementPoint })}>{["INPUT_GATEWAY", "RAG_GATEWAY", "MCP_GATEWAY", "A2A_BROKER", "EGRESS_GATEWAY", "SANDBOX", "AUDIT_SINK"].map((point) => <option key={point}>{point}</option>)}</select><select className={`assurance-select assurance-${control.assurance.toLowerCase()}`} aria-label={`${control.id} assurance`} value={control.assurance} onChange={(e) => updateControl(control.id, { assurance: e.target.value as Assurance })}><option>DECLARED</option><option>OBSERVED</option><option>ENFORCED</option><option>RECONCILED</option></select></div></div>)}
              <button className="danger-button" onClick={removeSelectedEdge}><span>Remove relationship</span><small>Only this connection will be removed</small></button>
            </div>
          ) : selectedZone ? (
            <div className="inspector-body zone-inspector">
              <div className="selection-summary"><span className={`zone-summary tone-${selectedZone.kind.toLowerCase()}`}>ZN</span><div><strong>{selectedZone.label}</strong><small>{selectedZone.id}</small></div><em>{selectedZone.kind}</em></div>
              <label>Zone name<input required value={selectedZone.label} onChange={(event) => updateSelectedZone({ label: event.target.value })} /></label>
              <label>Trust classification<select value={selectedZone.kind} onChange={(event) => updateSelectedZone({ kind: event.target.value as TrustZone })}><option value="INTERNAL">INTERNAL · managed</option><option value="EXTERNAL">EXTERNAL · untrusted</option></select></label>
              <label>Description<input value={selectedZone.description} onChange={(event) => updateSelectedZone({ description: event.target.value })} /></label>
              <div className="field-group"><span>Zone geometry</span><div className="geometry-grid">
                <label>X<input aria-label="Zone X" type="number" min="0" value={Math.round(selectedZone.x)} onChange={(event) => updateSelectedZone({ x: Math.max(0, Number(event.target.value)) }, true)} /></label>
                <label>Y<input aria-label="Zone Y" type="number" min="0" value={Math.round(selectedZone.y)} onChange={(event) => updateSelectedZone({ y: Math.max(0, Number(event.target.value)) }, true)} /></label>
                <label>Width<input aria-label="Zone width" type="number" min={ZONE_MIN_WIDTH} value={Math.round(selectedZone.width)} onChange={(event) => updateSelectedZone({ width: Math.max(ZONE_MIN_WIDTH, Number(event.target.value)) })} /></label>
                <label>Height<input aria-label="Zone height" type="number" min={ZONE_MIN_HEIGHT} value={Math.round(selectedZone.height)} onChange={(event) => updateSelectedZone({ height: Math.max(ZONE_MIN_HEIGHT, Number(event.target.value)) })} /></label>
              </div></div>
              <button className="secondary-button zone-fit-button" onClick={fitSelectedZoneAroundActors}>Fit around actors</button>
              <div className="control-heading"><span>Zone actors</span><small>{selectedZoneMembers.length}</small></div>
              <div className="zone-member-list">{selectedZoneMembers.map((node) => <button key={node.id} onClick={() => { setSelected({ kind: "node", id: node.id }); focusNode(node.id); }}><span className={`node-icon tone-${nodeTone[node.type]}`}>{node.type === "SUBAGENT" ? "SA" : node.type.slice(0, 2)}</span><span><strong>{node.label}</strong><small>{node.type} · {node.id}</small></span><i>›</i></button>)}</div>
              {nodes.some((node) => node.trustZoneId !== selectedZone.id) && <div className="zone-assignment"><label>Assign existing actor<select aria-label="Actor to assign" value={zoneAssignmentActor} onChange={(event) => setZoneAssignmentActor(event.target.value)}><option value="">Choose actor…</option>{nodes.filter((node) => node.trustZoneId !== selectedZone.id).map((node) => <option key={node.id} value={node.id}>{node.label} · {zoneMap[node.trustZoneId]?.label ?? node.trustZone}</option>)}</select></label><button className="secondary-button" disabled={!zoneAssignmentActor} onClick={() => assignActorToSelectedZone(zoneAssignmentActor)}>Move into zone</button></div>}
              <button className="danger-button" disabled={selectedZoneMembers.length > 0} onClick={removeSelectedZone}><span>Remove trust zone</span><small>{selectedZoneMembers.length > 0 ? "Move all actors to another zone first" : "The empty zone will be removed"}</small></button>
            </div>
          ) : selectedNode ? (
            <div className="inspector-body">
              <div className="selection-summary"><span className={`node-icon tone-${nodeTone[selectedNode.type]}`}>{selectedNode.type.slice(0, 2)}</span><div><strong>{selectedNode.label}</strong><small>{selectedNode.id}</small></div></div>
              <label>Display name<input value={selectedNode.label} onChange={(e) => updateNode({ label: e.target.value })} /></label>
              <label>Actor type<select value={selectedNode.type} onChange={(e) => updateNode({ type: e.target.value as NodeType })}>{["USER", "AGENT", "SUBAGENT", "RAG", "TOOL", "MEMORY", "SCHEDULER", "EXTERNAL"].map((type) => <option key={type}>{type}</option>)}</select></label>
              <label>Trust zone<select value={selectedNode.trustZoneId} onChange={(e) => assignSelectedNodeToZone(e.target.value)}>{zones.map((zone) => <option key={zone.id} value={zone.id}>{zone.label} · {zone.kind}</option>)}</select></label>
              <label>Owner<input value={selectedNode.owner} onChange={(e) => updateNode({ owner: e.target.value })} /></label>
              <label>Workload identity<input value={selectedNode.identity} onChange={(e) => updateNode({ identity: e.target.value })} /></label>
              <label>Tenant boundary<select value={selectedNode.tenantMode} onChange={(e) => updateNode({ tenantMode: e.target.value as ArchitectureNode["tenantMode"] })}><option>REQUIRED</option><option>OPTIONAL</option><option>GLOBAL</option></select></label>
              {(selectedNode.type === "AGENT" || selectedNode.type === "SUBAGENT") && <label>Actor delegation limit<input type="number" min="0" max="8" value={selectedNode.maxDelegationDepth} onChange={(e) => updateNode({ maxDelegationDepth: Number(e.target.value) })} /></label>}
              {selectedNode.type === "TOOL" && <label>Definition digest<input placeholder="sha256:…" value={selectedNode.definitionDigest ?? ""} onChange={(e) => updateNode({ definitionDigest: e.target.value })} /></label>}
              <label>Data access<input placeholder="D2, D3, D7" value={(selectedNode.dataAccess ?? []).join(", ")} onChange={(e) => updateNode({ dataAccess: e.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} /></label>
              {selectedNode.type === "EXTERNAL" && <label>Allowed domains<input placeholder="api.example.com, files.example.com" value={(selectedNode.allowedDomains ?? []).join(", ")} onChange={(e) => updateNode({ allowedDomains: e.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} /></label>}
              <label>Capabilities<input placeholder="SUPPORT_REPLY, KNOWLEDGE_SEARCH" value={selectedNode.capabilities.join(", ")} onChange={(e) => updateNode({ capabilities: e.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} /></label>
              <button className="danger-button" onClick={removeSelectedNode}><span>Remove actor</span><small>Connected relationships will also be removed</small></button>
            </div>
          ) : null}
          <div className="posture-card"><div className="posture-score"><span>{score}</span><div><strong>Security posture</strong><small>{criticalCount ? "Action required" : warningCount ? "Review warnings" : "Architecture conforms"}</small></div></div><div className="score-track"><i style={{ width: `${score}%` }} /></div><div className="finding-counts"><span><b className="critical-count">{criticalCount}</b> Critical</span><span><b>{warningCount}</b> Warnings</span></div></div>
          {findings.length > 0 && <div className="findings"><strong>Active findings</strong>{findings.slice(0, 3).map((finding, index) => <button key={`${finding.target}-${index}`} onClick={() => { const kind: Selection["kind"] = finding.target.startsWith("edge.") ? "edge" : finding.target.startsWith("task.") ? "task" : "node"; setSelected({ kind, id: finding.target }); if (kind === "task") { setDesignSurface("workflow"); fitGraph(); } else { setDesignSurface("topology"); const edge = kind === "edge" ? edges.find((item) => item.id === finding.target) : undefined; focusNode(edge?.target ?? finding.target); } }}><i className={finding.severity} /> <span>{finding.text}<small>{finding.target}</small></span></button>)}</div>}
          </>}
        </aside>
      </section>
    </main>
  );
}
