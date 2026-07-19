"use client";

import { ChangeEvent, PointerEvent as ReactPointerEvent, useEffect, useMemo, useRef, useState } from "react";
import {
  computeRuntimeDiff,
  demoRuntimeTelemetry,
  matchesEdge,
  parseRuntimeTelemetry,
  type RuntimeImport,
} from "./runtime";

type NodeType = "USER" | "AGENT" | "SUBAGENT" | "RAG" | "TOOL" | "MEMORY" | "EXTERNAL";
type Mode = "OBSERVE" | "SHADOW" | "ENFORCE";
type Assurance = "DECLARED" | "OBSERVED" | "ENFORCED" | "RECONCILED";
type EnforcementPoint = "INPUT_GATEWAY" | "RAG_GATEWAY" | "MCP_GATEWAY" | "A2A_BROKER" | "EGRESS_GATEWAY" | "SANDBOX" | "AUDIT_SINK";
type GraphView = "design" | "runtime" | "drift";
type Selection = { kind: "node" | "edge"; id: string };
type MobilePanel = "palette" | "inspector" | null;
type VisualEdge = Pick<ArchitectureEdge, "id" | "source" | "target" | "relationship" | "relationshipId" | "mode"> & {
  visualState: "design" | "observed" | "unobserved" | "bypass" | "undeclared";
  interactionId?: string;
};

type ArchitectureNode = {
  id: string;
  label: string;
  type: NodeType;
  owner: string;
  identity: string;
  capabilities: string[];
  tenantMode: "REQUIRED" | "OPTIONAL" | "GLOBAL";
  maxDelegationDepth: number;
  definitionDigest?: string;
  allowedDomains?: string[];
  x: number;
  y: number;
};

type Control = {
  id: string;
  objective: "PREVENT" | "DETECT" | "RESPOND" | "EVIDENCE";
  timing: "PRE_EXECUTION" | "POST_EXECUTION";
  point: EnforcementPoint;
  assurance: Assurance;
};

type ArchitectureEdge = {
  id: string;
  source: string;
  target: string;
  relationshipId: string;
  relationship: string;
  mode: Mode;
  failureMode: "FAIL_CLOSED" | "DEGRADE_READ_ONLY" | "FAIL_OPEN";
  allowedData: string[];
  approvalRequired: boolean;
  dynamic: boolean;
  sameTenant: boolean;
  maxDepth: number;
  controls: Control[];
};

type ArchitectureSnapshot = {
  nodes: ArchitectureNode[];
  edges: ArchitectureEdge[];
};

const initialNodes: ArchitectureNode[] = [
  { id: "user.customer", label: "Customer", type: "USER", owner: "Customer Platform", identity: "oidc://customer", capabilities: ["SUPPORT_REQUEST"], tenantMode: "REQUIRED", maxDelegationDepth: 0, x: 42, y: 255 },
  { id: "agent.support", label: "Support Agent", type: "AGENT", owner: "Customer Platform", identity: "spiffe://prod/agent/support", capabilities: ["SUPPORT_REPLY", "DELEGATE_RESEARCH"], tenantMode: "REQUIRED", maxDelegationDepth: 2, x: 286, y: 255 },
  { id: "agent.research", label: "Research Sub-Agent", type: "SUBAGENT", owner: "Customer Platform", identity: "spiffe://prod/agent/research", capabilities: ["KNOWLEDGE_SEARCH"], tenantMode: "REQUIRED", maxDelegationDepth: 0, x: 536, y: 88 },
  { id: "rag.support", label: "Support Knowledge", type: "RAG", owner: "Knowledge Platform", identity: "spiffe://prod/rag/support", capabilities: ["TENANT_RETRIEVAL"], tenantMode: "REQUIRED", maxDelegationDepth: 0, x: 788, y: 88 },
  { id: "tool.email", label: "Send Email", type: "TOOL", owner: "Messaging Platform", identity: "spiffe://prod/tool/email", capabilities: ["EMAIL_SEND"], tenantMode: "REQUIRED", maxDelegationDepth: 0, definitionDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", x: 536, y: 350 },
  { id: "external.customer", label: "Customer Email", type: "EXTERNAL", owner: "Messaging Platform", identity: "dns://customer.example", capabilities: [], tenantMode: "REQUIRED", maxDelegationDepth: 0, allowedDomains: ["customer.example"], x: 788, y: 350 },
  { id: "external.ledger", label: "Interlock Ledger", type: "EXTERNAL", owner: "Security Platform", identity: "spiffe://prod/interlock/ledger", capabilities: ["APPEND_ONLY_AUDIT"], tenantMode: "REQUIRED", maxDelegationDepth: 0, x: 536, y: 520 },
];

const audit = (id: string): Control => ({ id, objective: "EVIDENCE", timing: "POST_EXECUTION", point: "AUDIT_SINK", assurance: "OBSERVED" });
const prevent = (id: string, point: EnforcementPoint): Control => ({ id, objective: "PREVENT", timing: "PRE_EXECUTION", point, assurance: "ENFORCED" });

const initialEdges: ArchitectureEdge[] = [
  { id: "edge.user-support", source: "user.customer", target: "agent.support", relationshipId: "REL-01", relationship: "REQUESTS", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D2", "D3"], approvalRequired: false, dynamic: false, sameTenant: true, maxDepth: 0, controls: [prevent("input-identity-taint", "INPUT_GATEWAY"), audit("input-audit")] },
  { id: "edge.support-research", source: "agent.support", target: "agent.research", relationshipId: "REL-06", relationship: "DELEGATES", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D2", "D3", "D7"], approvalRequired: false, dynamic: true, sameTenant: true, maxDepth: 2, controls: [prevent("delegation-binding", "A2A_BROKER"), audit("delegation-audit")] },
  { id: "edge.research-rag", source: "agent.research", target: "rag.support", relationshipId: "REL-03", relationship: "READS", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D2", "D3", "D7"], approvalRequired: false, dynamic: false, sameTenant: true, maxDepth: 0, controls: [prevent("rag-tenant-acl", "RAG_GATEWAY"), audit("rag-provenance")] },
  { id: "edge.support-email", source: "agent.support", target: "tool.email", relationshipId: "REL-05", relationship: "INVOKES", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D2", "D3", "D7"], approvalRequired: true, dynamic: false, sameTenant: true, maxDepth: 0, controls: [prevent("mcp-call-guard", "MCP_GATEWAY"), prevent("stdio-process-sandbox", "SANDBOX"), audit("mcp-audit")] },
  { id: "edge.email-customer", source: "tool.email", target: "external.customer", relationshipId: "REL-07", relationship: "SENDS", mode: "ENFORCE", failureMode: "FAIL_CLOSED", allowedData: ["D3", "D7"], approvalRequired: true, dynamic: false, sameTenant: true, maxDepth: 0, controls: [prevent("egress-dlp", "EGRESS_GATEWAY"), { ...audit("egress-receipt"), assurance: "RECONCILED", objective: "DETECT" }] },
  { id: "edge.support-ledger", source: "agent.support", target: "external.ledger", relationshipId: "REL-12", relationship: "LOGS_TO", mode: "ENFORCE", failureMode: "DEGRADE_READ_ONLY", allowedData: ["D2", "D3", "D7"], approvalRequired: false, dynamic: false, sameTenant: true, maxDepth: 0, controls: [{ ...audit("append-only-audit"), assurance: "RECONCILED" }] },
];

const nodeTone: Record<NodeType, string> = {
  USER: "slate", AGENT: "violet", SUBAGENT: "indigo", RAG: "cyan", TOOL: "amber", MEMORY: "emerald", EXTERNAL: "rose",
};

const GRAPH_BOARD_MIN_WIDTH = 1050;
const GRAPH_BOARD_MIN_HEIGHT = 660;
const ACTOR_NODE_WIDTH = 174;
const ACTOR_NODE_HEIGHT = 76;
const GRAPH_BOARD_PADDING = 12;
const GRAPH_BOARD_GROWTH_MARGIN = 24;
const MIN_ZOOM = 0.3;
const MAX_ZOOM = 1.35;
const ZOOM_STEP = 0.1;
const HISTORY_LIMIT = 40;

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

export default function Home() {
  const [nodes, setNodes] = useState(initialNodes);
  const [edges, setEdges] = useState(initialEdges);
  const [selected, setSelected] = useState<Selection>({ kind: "edge", id: "edge.support-research" });
  const [connectFrom, setConnectFrom] = useState<string | null>(null);
  const [dragging, setDragging] = useState<{ id: string; dx: number; dy: number } | null>(null);
  const [notice, setNotice] = useState("Architecture v1.0.0 · all changes are local drafts");
  const [activeGraph, setActiveGraph] = useState<GraphView>("design");
  const [runtimeImport, setRuntimeImport] = useState<RuntimeImport | null>(null);
  const [zoom, setZoom] = useState(1);
  const [focusedNodeId, setFocusedNodeId] = useState<string | null>(null);
  const [past, setPast] = useState<ArchitectureSnapshot[]>([]);
  const [future, setFuture] = useState<ArchitectureSnapshot[]>([]);
  const [mobilePanel, setMobilePanel] = useState<MobilePanel>(null);
  const telemetryInput = useRef<HTMLInputElement>(null);
  const canvasScroll = useRef<HTMLDivElement>(null);
  const dragCheckpointed = useRef(false);

  const nodeMap = useMemo(() => Object.fromEntries(nodes.map((node) => [node.id, node])), [nodes]);
  const selectedNode = selected.kind === "node" ? nodeMap[selected.id] : undefined;
  const selectedEdge = selected.kind === "edge" ? edges.find((edge) => edge.id === selected.id) : undefined;
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
      return { id, label: "Undeclared Actor", type: inferredType, owner: "Runtime only", identity: `observed://${id}`, capabilities: [], tenantMode: "REQUIRED", maxDelegationDepth: 0, x: 790 + (index % 2) * 25, y: Math.min(555, 420 + index * 48) };
    });
  }, [runtimeImport, nodeMap, nodes]);

  const visualNodes = useMemo(() => {
    if (activeGraph === "design") return nodes;
    if (activeGraph === "runtime") return runtimeNodes;
    const runtimeOnly = runtimeNodes.filter((node) => !nodeMap[node.id]);
    return [...nodes, ...runtimeOnly];
  }, [activeGraph, nodes, runtimeNodes, nodeMap]);
  const boardSize = useMemo(() => ({
    width: Math.max(GRAPH_BOARD_MIN_WIDTH, ...visualNodes.map((node) => node.x + ACTOR_NODE_WIDTH + GRAPH_BOARD_GROWTH_MARGIN)),
    height: Math.max(GRAPH_BOARD_MIN_HEIGHT, ...visualNodes.map((node) => node.y + ACTOR_NODE_HEIGHT + GRAPH_BOARD_GROWTH_MARGIN)),
  }), [visualNodes]);
  const visualNodeMap = useMemo(() => Object.fromEntries(visualNodes.map((node) => [node.id, node])), [visualNodes]);
  const runtimeResultCount = runtimeImport ? runtimeDiff.undeclared.length + runtimeDiff.controlBypassInteractionIds.length + runtimeDiff.unobservedEdgeIds.length : 0;

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
      if (edge.controls.some((control) => control.assurance === "DECLARED")) result.push({ severity: "warning", text: "Declared control is not attached to a runtime enforcement point", target: edge.id });
      if (["REL-03", "REL-05", "REL-06", "REL-07"].includes(edge.relationshipId) && edge.mode === "OBSERVE") result.push({ severity: "critical", text: "High-risk relationship is OBSERVE only", target: edge.id });
      if (edge.failureMode === "FAIL_OPEN") result.push({ severity: "critical", text: "Security boundary fails open", target: edge.id });
      if (edge.relationshipId === "REL-06" && (!edge.sameTenant || edge.maxDepth < 1)) result.push({ severity: "critical", text: "Delegation tenant or depth boundary is unsafe", target: edge.id });
      if (edge.dynamic && !nodeMap[edge.target]?.capabilities.length) result.push({ severity: "critical", text: "Dynamic target requires a capability boundary", target: edge.target });
      if (!edge.controls.some((control) => control.point === "AUDIT_SINK")) result.push({ severity: "warning", text: "No audit evidence control", target: edge.id });
      if (edge.allowedData.includes("D5")) result.push({ severity: "critical", text: "Credential class D5 is allowed across the edge", target: edge.id });
    });
    return result;
  }, [nodes, edges, nodeMap]);

  const allControls = edges.flatMap((edge) => edge.controls);
  const assuredControls = allControls.filter((control) => control.assurance === "ENFORCED" || control.assurance === "RECONCILED").length;
  const criticalCount = findings.filter((finding) => finding.severity === "critical").length;
  const warningCount = findings.length - criticalCount;
  const score = Math.max(0, 100 - criticalCount * 18 - warningCount * 6);
  const coverage = allControls.length ? Math.round((assuredControls / allControls.length) * 100) : 0;

  function checkpoint() {
    setPast((items) => [...items.slice(-(HISTORY_LIMIT - 1)), { nodes, edges }]);
    setFuture([]);
  }

  function restoreSnapshot(snapshot: ArchitectureSnapshot) {
    setNodes(snapshot.nodes);
    setEdges(snapshot.edges);
    const selectionStillExists = selected.kind === "node"
      ? snapshot.nodes.some((node) => node.id === selected.id)
      : snapshot.edges.some((edge) => edge.id === selected.id);
    if (!selectionStillExists) {
      if (snapshot.edges[0]) setSelected({ kind: "edge", id: snapshot.edges[0].id });
      else if (snapshot.nodes[0]) setSelected({ kind: "node", id: snapshot.nodes[0].id });
      else setSelected({ kind: "node", id: "" });
    }
    setConnectFrom(null);
    setDragging(null);
  }

  function undo() {
    const snapshot = past[past.length - 1];
    if (!snapshot) return;
    setPast((items) => items.slice(0, -1));
    setFuture((items) => [{ nodes, edges }, ...items].slice(0, HISTORY_LIMIT));
    restoreSnapshot(snapshot);
    setNotice("Last architecture change undone");
  }

  function redo() {
    const snapshot = future[0];
    if (!snapshot) return;
    setFuture((items) => items.slice(1));
    setPast((items) => [...items.slice(-(HISTORY_LIMIT - 1)), { nodes, edges }]);
    restoreSnapshot(snapshot);
    setNotice("Architecture change restored");
  }

  function resetDraft() {
    checkpoint();
    restoreSnapshot({ nodes: initialNodes, edges: initialEdges });
    setSelected({ kind: "edge", id: "edge.support-research" });
    setNotice("Draft reset to the secure reference architecture · Undo is available");
  }

  function changeZoom(nextZoom: number) {
    const viewport = canvasScroll.current;
    const clamped = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, nextZoom));
    if (!viewport) {
      setZoom(clamped);
      return;
    }
    const centerX = (viewport.scrollLeft + viewport.clientWidth / 2) / zoom;
    const centerY = (viewport.scrollTop + viewport.clientHeight / 2) / zoom;
    setZoom(clamped);
    requestAnimationFrame(() => viewport.scrollTo({
      left: Math.max(0, centerX * clamped - viewport.clientWidth / 2),
      top: Math.max(0, centerY * clamped - viewport.clientHeight / 2),
      behavior: "smooth",
    }));
  }

  function fitGraph() {
    const viewport = canvasScroll.current;
    if (!viewport) return;
    const nextZoom = Math.max(MIN_ZOOM, Math.min(1, (viewport.clientWidth - 48) / boardSize.width, (viewport.clientHeight - 48) / boardSize.height));
    setZoom(nextZoom);
    requestAnimationFrame(() => viewport.scrollTo({ left: 0, top: 0, behavior: "smooth" }));
    setNotice(`Graph fitted to viewport · ${Math.round(nextZoom * 100)}%`);
  }

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

  useEffect(() => {
    if (activeGraph === "design" || !runtimeImport) return;
    const anomalyId = runtimeDiff.undeclared[0]?.target
      ?? runtimeImport.observations.find((item) => runtimeDiff.controlBypassInteractionIds.includes(item.interactionId))?.target;
    const node = anomalyId ? visualNodeMap[anomalyId] : undefined;
    const viewport = canvasScroll.current;
    if (!node || !viewport) return;
    const frame = requestAnimationFrame(() => {
      setFocusedNodeId(node.id);
      viewport.scrollTo({
        left: Math.max(0, (node.x + ACTOR_NODE_WIDTH / 2) * zoom - viewport.clientWidth / 2),
        top: Math.max(0, (node.y + ACTOR_NODE_HEIGHT / 2) * zoom - viewport.clientHeight / 2),
        behavior: "smooth",
      });
    });
    return () => cancelAnimationFrame(frame);
  }, [activeGraph, runtimeImport, runtimeDiff.undeclared, runtimeDiff.controlBypassInteractionIds, visualNodeMap, zoom]);

  function focusCurrentContext() {
    if (activeGraph === "design") {
      if (selectedNode) focusNode(selectedNode.id);
      else if (selectedEdge) focusNode(selectedEdge.target);
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

  function addNode(type: NodeType) {
    checkpoint();
    const count = nodes.filter((node) => node.type === type).length + 1;
    const id = `${type.toLowerCase()}.new-${count}`;
    const viewport = canvasScroll.current;
    const offset = nodes.filter((node) => node.id.includes(".new-")).length % 5;
    const visibleCenterX = ((viewport?.scrollLeft ?? 0) + (viewport?.clientWidth ?? GRAPH_BOARD_MIN_WIDTH) / 2) / zoom;
    const visibleCenterY = ((viewport?.scrollTop ?? 0) + (viewport?.clientHeight ?? GRAPH_BOARD_MIN_HEIGHT) / 2) / zoom;
    const x = Math.max(GRAPH_BOARD_PADDING, visibleCenterX - ACTOR_NODE_WIDTH / 2 + offset * 22);
    const y = Math.max(GRAPH_BOARD_PADDING, visibleCenterY - ACTOR_NODE_HEIGHT / 2 + offset * 22);
    const node: ArchitectureNode = { id, label: `New ${type.replace("SUBAGENT", "Sub-Agent")}`, type, owner: "Unassigned", identity: `unbound://${id}`, capabilities: [], tenantMode: "REQUIRED", maxDelegationDepth: type === "AGENT" || type === "SUBAGENT" ? 1 : 0, allowedDomains: type === "EXTERNAL" ? [] : undefined, x, y };
    setNodes((items) => [...items, node]);
    setSelected({ kind: "node", id });
    setFocusedNodeId(id);
    setMobilePanel("inspector");
    setNotice(`${node.label} added · connect it to define a security boundary`);
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
      checkpoint();
      setEdges((items) => [...items, edge]);
      setSelected({ kind: "edge", id: edge.id });
      setConnectFrom(null);
      setMobilePanel("inspector");
      setNotice("Relationship created in SHADOW · attach the declared control before enforcement");
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

  function onCanvasMove(event: ReactPointerEvent<HTMLDivElement>) {
    if (!dragging || activeGraph !== "design") return;
    if (!dragCheckpointed.current) {
      checkpoint();
      dragCheckpointed.current = true;
    }
    const rect = event.currentTarget.getBoundingClientRect();
    const maxX = boardSize.width - ACTOR_NODE_WIDTH - GRAPH_BOARD_PADDING;
    const maxY = boardSize.height - ACTOR_NODE_HEIGHT - GRAPH_BOARD_PADDING;
    const x = Math.max(GRAPH_BOARD_PADDING, Math.min(maxX, (event.clientX - rect.left + event.currentTarget.scrollLeft - dragging.dx) / zoom));
    const y = Math.max(GRAPH_BOARD_PADDING, Math.min(maxY, (event.clientY - rect.top + event.currentTarget.scrollTop - dragging.dy) / zoom));
    setNodes((items) => items.map((node) => node.id === dragging.id ? { ...node, x, y } : node));
  }

  function applyTelemetry(value: unknown, source: string) {
    try {
      const imported = parseRuntimeTelemetry(value);
      setRuntimeImport(imported);
      setActiveGraph("runtime");
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
    setConnectFrom(null);
    setMobilePanel(null);
    if (view !== "design" && !runtimeImport) setNotice("Import Ledger or OTLP JSON telemetry to build the runtime graph");
  }

  function exportManifest() {
    const manifestNodes = nodes.map((node) => ({
      id: node.id,
      type: node.type,
      owner: node.owner,
      identity: node.identity,
      capabilities: node.capabilities,
      dataAccess: [],
      sideEffects: node.type === "TOOL" ? ["EXTERNAL_WRITE"] : node.type === "RAG" || node.type === "MEMORY" ? ["READ"] : [],
      tenantMode: node.tenantMode,
      failureMode: "FAIL_CLOSED",
      allowedDomains: node.allowedDomains ?? [],
      maxDelegationDepth: node.maxDelegationDepth,
      ...(node.definitionDigest ? { definitionDigest: node.definitionDigest } : {}),
      position: { x: node.x, y: node.y },
    }));
    const manifestEdges = edges.map((edge) => {
      const target = nodeMap[edge.target];
      return {
        id: edge.id,
        relationshipId: edge.relationshipId,
        source: edge.source,
        target: edge.target,
        relationship: edge.relationship,
        dynamic: edge.dynamic,
        ...(edge.dynamic && target ? { targetSelector: { types: [target.type], requiredCapabilities: target.capabilities, idPattern: `${target.id}*`, sameTenant: edge.sameTenant } } : {}),
        policy: {
          id: `${edge.id}-policy`,
          version: "1.0.0",
          mode: edge.mode,
          allowedDataClasses: edge.allowedData,
          deniedDataClasses: ["D5", "D8"].filter((item) => !edge.allowedData.includes(item)),
          requireActiveDefinition: true,
          requireDigestPin: true,
          requireExplicitDestination: true,
          newDestinationAction: "HOLD",
          tokenPassthrough: false,
          requireAudience: true,
          requireResource: true,
          requireActorBinding: true,
          maxDelegationDepth: edge.maxDepth,
          externalWriteRequiresApproval: edge.approvalRequired,
          failureMode: edge.failureMode,
          decisionTtlSeconds: 30,
        },
        controls: edge.controls.map((control) => ({ id: control.id, objective: control.objective, timing: control.timing, enforcementPoint: control.point, assurance: control.assurance })),
      };
    });
    const payload = { apiVersion: "interlock.dev/v1alpha1", kind: "Architecture", metadata: { id: "customer-support-multi-agent", version: "1.0.0-draft" }, spec: { nodes: manifestNodes, edges: manifestEdges } };
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }));
    link.download = "agent-interlock-architecture.json";
    link.click();
    URL.revokeObjectURL(link.href);
    setNotice("Draft architecture exported · review is required before policy deployment");
  }

  return (
    <main className="studio-shell">
      <header className="topbar">
        <div className="brand-lockup"><span className="brand-mark">AI</span><div><strong>Agent Interlock</strong><span>Security Architecture Studio</span></div></div>
        <div className="architecture-title"><span className="draft-dot" />Customer Support Architecture <small>v1.0.0 draft</small></div>
        <div className="top-actions"><button className="quiet-button" onClick={() => activeGraph === "design" ? setNotice(`${findings.length} findings · ${criticalCount} require attention`) : setNotice(runtimeImport ? `${runtimeDiff.undeclared.length} undeclared · ${runtimeDiff.controlBypassInteractionIds.length} control bypass · ${runtimeImport.issues.length} import issues` : "Import telemetry before running a drift check")}>{activeGraph === "design" ? "Run security check" : "Run drift check"}</button><button className="primary-button" onClick={exportManifest}>Export manifest</button></div>
      </header>

      <section className="workspace">
        {mobilePanel && <button className="mobile-scrim" aria-label="Close side panel" onClick={() => setMobilePanel(null)} />}
        <aside className={`toolbox ${mobilePanel === "palette" ? "mobile-open" : ""}`} aria-label={activeGraph === "design" ? "Actor palette" : "Runtime telemetry"}>
          <button className="panel-close" aria-label="Close actor palette" onClick={() => setMobilePanel(null)}>×</button>
          {activeGraph === "design" ? <>
            <div className="panel-heading"><span>BUILD</span><strong>Actor palette</strong></div>
            <p className="panel-note">Add a security-aware building block, then connect its trust boundary.</p>
            <div className="palette-grid">
              {(["AGENT", "SUBAGENT", "RAG", "TOOL", "MEMORY", "EXTERNAL"] as NodeType[]).map((type) => <button key={type} className={`palette-item tone-${nodeTone[type]}`} onClick={() => addNode(type)}><span>{type === "SUBAGENT" ? "SA" : type.slice(0, 2)}</span>{type === "SUBAGENT" ? "Sub-Agent" : type[0] + type.slice(1).toLowerCase()}</button>)}
            </div>
            <div className="toolbox-rule" />
            <button className={`connect-button ${connectFrom ? "active" : ""}`} onClick={beginConnection}><span>↗</span>{connectFrom ? "Choose target box" : "Connect selected box"}</button>
            <div className="legend">
              <strong>Assurance</strong>
              <span><i className="dot declared" />Declared</span><span><i className="dot observed" />Observed</span><span><i className="dot enforced" />Enforced</span><span><i className="dot reconciled" />Reconciled</span>
            </div>
          </> : <>
            <div className="panel-heading"><span>OBSERVE</span><strong>Runtime telemetry</strong></div>
            <p className="panel-note">Import Interlock Ledger events or OTLP/HTTP JSON. Files stay in this browser session.</p>
            <input ref={telemetryInput} className="file-input" type="file" accept="application/json,.json" onChange={importTelemetryFile} />
            <button className="telemetry-button primary" onClick={() => telemetryInput.current?.click()}><span>↑</span>Import telemetry</button>
            <button className="telemetry-button" onClick={() => applyTelemetry(demoRuntimeTelemetry, "Drift demo")}><span>▶</span>Load drift demo</button>
            <div className="runtime-source-card"><span>FORMAT</span><strong>{runtimeImport?.format ?? "No telemetry"}</strong><small>{runtimeImport ? `${runtimeImport.observations.length} observed relationships` : "JSON · maximum 5 MB"}</small></div>
            <div className="toolbox-rule" />
            <div className="runtime-contract"><strong>Security context</strong><code>interlock.source.actor.id</code><code>interlock.target.actor.id</code><code>interlock.relationship.id</code><code>interlock.control.evaluated</code></div>
            <div className="legend runtime-legend"><strong>Runtime state</strong><span><i className="dot observed" />Observed</span><span><i className="dot reconciled" />Controlled</span><span><i className="dot critical" />Drift / bypass</span></div>
          </>}
        </aside>

        <section className="canvas-region">
          <div className="canvas-toolbar">
            <div className="graph-tabs"><button aria-pressed={activeGraph === "design"} className={activeGraph === "design" ? "active" : ""} onClick={() => selectGraph("design")}>Design graph</button><button aria-pressed={activeGraph === "runtime"} className={activeGraph === "runtime" ? "active" : ""} onClick={() => selectGraph("runtime")}>Runtime graph</button><button aria-pressed={activeGraph === "drift"} className={activeGraph === "drift" ? "active" : ""} onClick={() => selectGraph("drift")}>Drift</button></div>
            <div className="mobile-panel-actions"><button onClick={() => setMobilePanel("palette")}>{activeGraph === "design" ? "Actors" : "Telemetry"}</button><button onClick={() => setMobilePanel("inspector")}>Inspect</button></div>
            <div className="canvas-toolbar-right">
              <div className="canvas-stats">{activeGraph === "design" ? <><span>{nodes.length} actors</span><span>{edges.length} relationships</span><span>{coverage}% enforced</span></> : activeGraph === "runtime" ? <><span>{runtimeNodes.length} runtime actors</span><span>{runtimeImport?.observations.length ?? 0} calls</span><span>{runtimeImport?.observations.filter((item) => item.controlEvaluated).length ?? 0} controlled</span></> : <><span>{runtimeImport ? runtimeDiff.undeclared.length : 0} undeclared</span><span>{runtimeImport ? runtimeDiff.unobservedEdgeIds.length : 0} unobserved</span><span>{runtimeImport ? runtimeDiff.controlBypassInteractionIds.length : 0} bypass</span></>}</div>
              <div className="view-controls" aria-label="Graph view controls"><button aria-label="Zoom out" onClick={() => changeZoom(zoom - ZOOM_STEP)}>−</button><span>{Math.round(zoom * 100)}%</span><button aria-label="Zoom in" onClick={() => changeZoom(zoom + ZOOM_STEP)}>+</button><button onClick={fitGraph}>Fit</button><button onClick={focusCurrentContext}>Focus</button></div>
            </div>
          </div>
          <div ref={canvasScroll} className={`canvas-scroll ${connectFrom ? "connecting" : ""}`} onPointerMove={onCanvasMove} onPointerUp={() => { setDragging(null); dragCheckpointed.current = false; }} onPointerCancel={() => { setDragging(null); dragCheckpointed.current = false; }}>
            <div className="graph-surface" style={{ width: boardSize.width * zoom, height: boardSize.height * zoom }}>
            <div className="graph-board" style={{ width: boardSize.width, height: boardSize.height, transform: `scale(${zoom})` }}>
              <div className="trust-zone zone-internal"><span>INTERNAL TRUST ZONE</span></div>
              <div className="trust-zone zone-external"><span>EXTERNAL</span></div>
              {activeGraph !== "design" && !runtimeImport && <div className="canvas-empty"><span>RT</span><strong>No runtime telemetry</strong><p>Import Ledger events or OTLP JSON to reconcile actual calls with this architecture.</p><button onClick={() => applyTelemetry(demoRuntimeTelemetry, "Drift demo")}>Load drift demo</button></div>}
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
                return <button key={edge.id} title={`${edge.source} → ${edge.target}`} style={{ left, top }} className={`edge-label visual-${edge.visualState} ${activeGraph === "design" && selected.kind === "edge" && selected.id === edge.id ? "selected" : ""}`} onClick={() => { if (activeGraph === "design") { setSelected({ kind: "edge", id: edge.id }); setMobilePanel("inspector"); } else { focusNode(edge.target); setNotice(`${edge.relationshipId} ${edge.source} → ${edge.target} · ${edge.visualState}`); } }}><span>{edge.relationship}</span><small>{edge.relationshipId}{edge.visualState === "bypass" || edge.visualState === "undeclared" ? " !" : ""}</small></button>;
              })}
              {visualNodes.map((node) => { const runtimeOnly = !nodeMap[node.id]; return <button key={node.id} title={`${node.label} · ${runtimeOnly ? node.id : `${node.type} · ${node.owner}`}`} style={{ left: node.x, top: node.y }} className={`actor-node tone-${nodeTone[node.type]} ${activeGraph === "design" && selected.kind === "node" && selected.id === node.id ? "selected" : ""} ${focusedNodeId === node.id ? "focused" : ""} ${dragging?.id === node.id ? "dragging" : ""} ${connectFrom === node.id ? "connect-source" : ""} ${runtimeOnly ? "runtime-only" : ""}`} onPointerDown={(event) => onNodePointerDown(event, node)} onLostPointerCapture={() => { setDragging(null); dragCheckpointed.current = false; }} onClick={() => activeGraph === "design" ? selectNode(node) : focusNode(node.id)} aria-label={`${node.label}, ${node.type}`}><span className="node-icon">{node.type === "SUBAGENT" ? "SA" : node.type.slice(0, 2)}</span><span className="node-copy"><strong>{node.label}</strong><small>{runtimeOnly ? node.id : `${node.type} · ${node.owner}`}</small></span><i className={`node-status ${runtimeOnly ? "warning" : ""}`} /></button>; })}
            </div>
            </div>
          </div>
          <div className="notice-bar"><div className="notice-copy"><span>●</span>{notice}</div><div className="draft-actions"><button disabled={!past.length} onClick={undo}>Undo</button><button disabled={!future.length} onClick={redo}>Redo</button><button onClick={resetDraft}>Reset draft</button></div></div>
        </section>

        <aside className={`inspector ${mobilePanel === "inspector" ? "mobile-open" : ""}`} aria-label="Architecture inspector">
          <button className="panel-close" aria-label="Close inspector" onClick={() => setMobilePanel(null)}>×</button>
          <div className="panel-heading"><span>INSPECT</span><strong>{activeGraph === "design" ? selectedEdge ? "Relationship security" : "Actor contract" : "Runtime reconciliation"}</strong></div>
          {activeGraph !== "design" ? <>
            <div className="inspector-body runtime-inspector">
              <div className="runtime-health"><span className={!runtimeImport ? "pending" : runtimeDiff.undeclared.length || runtimeDiff.controlBypassInteractionIds.length ? "unsafe" : "safe"}>{!runtimeImport ? "·" : runtimeDiff.undeclared.length || runtimeDiff.controlBypassInteractionIds.length ? "!" : "✓"}</span><div><strong>{runtimeImport ? runtimeDiff.undeclared.length || runtimeDiff.controlBypassInteractionIds.length ? "Runtime drift detected" : "Runtime conforms" : "Awaiting telemetry"}</strong><small>{runtimeImport?.format ?? "Ledger or OTLP JSON"}</small></div></div>
              <div className="runtime-metrics"><div><span>{runtimeImport?.observations.length ?? 0}</span><small>Observed</small></div><div><span>{runtimeImport ? runtimeDiff.undeclared.length : 0}</span><small>Undeclared</small></div><div><span>{runtimeImport ? runtimeDiff.controlBypassInteractionIds.length : 0}</span><small>Bypass</small></div></div>
              <div className="control-heading"><span>Reconciliation results</span><small>{runtimeResultCount}</small></div>
              {!runtimeImport && <div className="runtime-empty-note">Import telemetry or load the drift demo to see actual relationship evidence.</div>}
              {runtimeImport && runtimeDiff.undeclared.map((item) => <button className="drift-card critical" key={`undeclared-${item.interactionId}`} onClick={() => { focusNode(item.target); setMobilePanel(null); }}><i>!</i><span><strong>Undeclared relationship</strong><small>{item.source} → {item.target}</small><code>{item.relationshipId} · {item.interactionId}</code></span></button>)}
              {runtimeImport && runtimeDiff.controlBypassInteractionIds.map((id) => { const observation = runtimeImport.observations.find((item) => item.interactionId === id); return <button className="drift-card critical" key={`bypass-${id}`} onClick={() => { if (observation) focusNode(observation.target); setMobilePanel(null); }}><i>!</i><span><strong>Control evaluation missing</strong><small>Interaction reached runtime without control evidence</small><code>{id}</code></span></button>; })}
              {runtimeImport && runtimeDiff.unobservedEdgeIds.slice(0, 4).map((id) => { const edge = edges.find((item) => item.id === id); return <button className="drift-card warning" key={`unobserved-${id}`} onClick={() => { if (edge) focusNode(edge.target); setMobilePanel(null); }}><i>–</i><span><strong>Design edge not observed</strong><small>No matching call in this telemetry set</small><code>{id}</code></span></button>; })}
              {(runtimeImport?.issues ?? []).map((issue, index) => <div className="drift-card warning" key={`${issue.code}-${index}`}><i>?</i><span><strong>{issue.code}</strong><small>{issue.message}</small><code>{issue.spanId ?? "no span id"}</code></span></div>)}
            </div>
            <div className="runtime-boundary-note"><strong>No inferred security facts</strong><span>Standard GenAI fields classify spans. Exact drift decisions require explicit <code>interlock.*</code> attributes.</span></div>
          </> : <>
          {selectedEdge ? (
            <div className="inspector-body">
              <div className="selection-summary"><span className="relation-mark">→</span><div><strong>{selectedEdge.relationship}</strong><small>{selectedEdge.source} → {selectedEdge.target}</small></div><em>{selectedEdge.relationshipId}</em></div>
              <label>Enforcement mode<select value={selectedEdge.mode} onChange={(e) => updateEdge({ mode: e.target.value as Mode })}><option>OBSERVE</option><option>SHADOW</option><option>ENFORCE</option></select></label>
              <label>Failure mode<select value={selectedEdge.failureMode} onChange={(e) => updateEdge({ failureMode: e.target.value as ArchitectureEdge["failureMode"] })}><option>FAIL_CLOSED</option><option>DEGRADE_READ_ONLY</option><option>FAIL_OPEN</option></select></label>
              <div className="field-group"><span>Allowed data</span><div className="chip-row">{["D2", "D3", "D5", "D7", "D8"].map((item) => <button key={item} className={selectedEdge.allowedData.includes(item) ? "chip selected" : "chip"} onClick={() => updateEdge({ allowedData: selectedEdge.allowedData.includes(item) ? selectedEdge.allowedData.filter((value) => value !== item) : [...selectedEdge.allowedData, item] })}>{item}</button>)}</div></div>
              <div className="toggle-row"><div><strong>Human approval</strong><small>Required before high-impact execution</small></div><button aria-label="Require human approval" aria-pressed={selectedEdge.approvalRequired} className={`toggle ${selectedEdge.approvalRequired ? "on" : ""}`} onClick={() => updateEdge({ approvalRequired: !selectedEdge.approvalRequired })}><i /></button></div>
              {selectedEdge.relationshipId === "REL-06" && <><div className="toggle-row"><div><strong>Same tenant only</strong><small>Reject cross-tenant delegation</small></div><button aria-label="Restrict delegation to the same tenant" aria-pressed={selectedEdge.sameTenant} className={`toggle ${selectedEdge.sameTenant ? "on" : ""}`} onClick={() => updateEdge({ sameTenant: !selectedEdge.sameTenant })}><i /></button></div><label>Maximum delegation depth<input type="number" min="0" max="8" value={selectedEdge.maxDepth} onChange={(e) => updateEdge({ maxDepth: Number(e.target.value) })} /></label></>}
              <div className="control-heading"><span>Security controls</span><small>{selectedEdge.controls.length}</small></div>
              {selectedEdge.controls.map((control) => <div className="control-card" key={control.id}><div><strong>{control.id}</strong><small>{control.objective} · {control.timing}</small></div><div className="control-settings"><select className="point-select" aria-label={`${control.id} enforcement point`} value={control.point} onChange={(e) => updateControl(control.id, { point: e.target.value as EnforcementPoint })}>{["INPUT_GATEWAY", "RAG_GATEWAY", "MCP_GATEWAY", "A2A_BROKER", "EGRESS_GATEWAY", "SANDBOX", "AUDIT_SINK"].map((point) => <option key={point}>{point}</option>)}</select><select className={`assurance-select assurance-${control.assurance.toLowerCase()}`} aria-label={`${control.id} assurance`} value={control.assurance} onChange={(e) => updateControl(control.id, { assurance: e.target.value as Assurance })}><option>DECLARED</option><option>OBSERVED</option><option>ENFORCED</option><option>RECONCILED</option></select></div></div>)}
              <button className="danger-button" onClick={removeSelectedEdge}><span>Remove relationship</span><small>Only this connection will be removed</small></button>
            </div>
          ) : selectedNode ? (
            <div className="inspector-body">
              <div className="selection-summary"><span className={`node-icon tone-${nodeTone[selectedNode.type]}`}>{selectedNode.type.slice(0, 2)}</span><div><strong>{selectedNode.label}</strong><small>{selectedNode.id}</small></div></div>
              <label>Display name<input value={selectedNode.label} onChange={(e) => updateNode({ label: e.target.value })} /></label>
              <label>Actor type<select value={selectedNode.type} onChange={(e) => updateNode({ type: e.target.value as NodeType })}>{["USER", "AGENT", "SUBAGENT", "RAG", "TOOL", "MEMORY", "EXTERNAL"].map((type) => <option key={type}>{type}</option>)}</select></label>
              <label>Owner<input value={selectedNode.owner} onChange={(e) => updateNode({ owner: e.target.value })} /></label>
              <label>Workload identity<input value={selectedNode.identity} onChange={(e) => updateNode({ identity: e.target.value })} /></label>
              <label>Tenant boundary<select value={selectedNode.tenantMode} onChange={(e) => updateNode({ tenantMode: e.target.value as ArchitectureNode["tenantMode"] })}><option>REQUIRED</option><option>OPTIONAL</option><option>GLOBAL</option></select></label>
              {(selectedNode.type === "AGENT" || selectedNode.type === "SUBAGENT") && <label>Actor delegation limit<input type="number" min="0" max="8" value={selectedNode.maxDelegationDepth} onChange={(e) => updateNode({ maxDelegationDepth: Number(e.target.value) })} /></label>}
              {selectedNode.type === "TOOL" && <label>Definition digest<input placeholder="sha256:…" value={selectedNode.definitionDigest ?? ""} onChange={(e) => updateNode({ definitionDigest: e.target.value })} /></label>}
              {selectedNode.type === "EXTERNAL" && <label>Allowed domains<input placeholder="api.example.com, files.example.com" value={(selectedNode.allowedDomains ?? []).join(", ")} onChange={(e) => updateNode({ allowedDomains: e.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} /></label>}
              <label>Capabilities<input placeholder="SUPPORT_REPLY, KNOWLEDGE_SEARCH" value={selectedNode.capabilities.join(", ")} onChange={(e) => updateNode({ capabilities: e.target.value.split(",").map((item) => item.trim()).filter(Boolean) })} /></label>
              <button className="danger-button" onClick={removeSelectedNode}><span>Remove actor</span><small>Connected relationships will also be removed</small></button>
            </div>
          ) : null}
          <div className="posture-card"><div className="posture-score"><span>{score}</span><div><strong>Security posture</strong><small>{criticalCount ? "Action required" : warningCount ? "Review warnings" : "Architecture conforms"}</small></div></div><div className="score-track"><i style={{ width: `${score}%` }} /></div><div className="finding-counts"><span><b className="critical-count">{criticalCount}</b> Critical</span><span><b>{warningCount}</b> Warnings</span></div></div>
          {findings.length > 0 && <div className="findings"><strong>Active findings</strong>{findings.slice(0, 3).map((finding, index) => <button key={`${finding.target}-${index}`} onClick={() => { const kind = finding.target.startsWith("edge.") ? "edge" : "node"; setSelected({ kind, id: finding.target }); const edge = kind === "edge" ? edges.find((item) => item.id === finding.target) : undefined; focusNode(edge?.target ?? finding.target); }}><i className={finding.severity} /> <span>{finding.text}<small>{finding.target}</small></span></button>)}</div>}
          </>}
        </aside>
      </section>
    </main>
  );
}
