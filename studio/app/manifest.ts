// Pure (no React) manifest domain types and the export/import logic that translates between
// Studio's editable graph state and the Architecture manifest JSON the Python compiler accepts
// (schemas/architecture.schema.json, parsed by ArchitectureGraph.from_dict). Kept dependency-free
// so studio/tests/manifest-roundtrip.test.mjs can import it directly.

export type NodeType = "USER" | "AGENT" | "SUBAGENT" | "RAG" | "TOOL" | "MEMORY" | "SCHEDULER" | "EXTERNAL";
export type TrustZone = "INTERNAL" | "EXTERNAL";
export type Mode = "OBSERVE" | "SHADOW" | "ENFORCE";
export type Assurance = "DECLARED" | "OBSERVED" | "ENFORCED" | "RECONCILED";
export type EnforcementPoint = "INPUT_GATEWAY" | "RAG_GATEWAY" | "MCP_GATEWAY" | "A2A_BROKER" | "EGRESS_GATEWAY" | "SANDBOX" | "AUDIT_SINK";

export type ArchitectureNode = {
  id: string;
  label: string;
  type: NodeType;
  owner: string;
  identity: string;
  capabilities: string[];
  tenantMode: "REQUIRED" | "OPTIONAL" | "GLOBAL";
  maxDelegationDepth: number;
  trustZone: TrustZone;
  trustZoneId: string;
  definitionDigest?: string;
  dataAccess: string[];
  allowedDomains?: string[];
  sideEffects?: string[];
  inputSchema?: Record<string, unknown>;
  outputSchema?: Record<string, unknown>;
  annotations?: Record<string, unknown>;
  x: number;
  y: number;
};

export type TrustZoneDefinition = {
  id: string;
  label: string;
  kind: TrustZone;
  description: string;
  x: number;
  y: number;
  width: number;
  height: number;
};

export type TrustBoundaryDefinition = {
  id: string;
  label: string;
  sourceZoneId: string;
  targetZoneId: string;
  point: EnforcementPoint;
  allowedRelationships: string[];
  allowedData: string[];
  deniedData: string[];
  mode: Mode;
  failureMode: "FAIL_CLOSED" | "DEGRADE_READ_ONLY" | "FAIL_OPEN";
  requireIdentity: boolean;
  requireTenantBinding: boolean;
  maxPayloadBytes: number;
  description: string;
};

export type WorkflowTask = {
  id: string;
  label: string;
  sourceActorId: string;
  targetActorId: string;
  transport: "A2A" | "MCP" | "LOCAL" | "HUMAN";
  purpose: string;
  dependsOn: string[];
  dataClasses: string[];
  acceptanceCriteria: string[];
  maxAttempts: number;
  timeoutSeconds: number;
  approvalRequired: boolean;
  onFailure: "FAIL_WORKFLOW" | "SKIP" | "CONTINUE";
  x: number;
  y: number;
};

export type OrchestrationDesign = {
  coordinatorActorId: string;
  pattern: "STATE_GRAPH" | "HIERARCHICAL" | "CONVERSATIONAL" | "HYBRID";
  maxParallelism: number;
  maxTasks: number;
  maxDurationSeconds: number;
  maxMessages: number;
  failFast: boolean;
  tasks: WorkflowTask[];
};

export type Control = {
  id: string;
  objective: "PREVENT" | "DETECT" | "RESPOND" | "EVIDENCE";
  timing: "PRE_EXECUTION" | "POST_EXECUTION";
  point: EnforcementPoint;
  assurance: Assurance;
};

export type ArchitectureEdge = {
  id: string;
  source: string;
  target: string;
  relationshipId: string;
  relationship: string;
  mode: Mode;
  failureMode: "FAIL_CLOSED" | "DEGRADE_READ_ONLY" | "FAIL_OPEN";
  allowedData: string[];
  allowedPurposes: string[];
  approvalRequired: boolean;
  dynamic: boolean;
  sameTenant: boolean;
  maxDepth: number;
  boundaryId?: string;
  maxExportRecords?: number;
  maxExportBytes?: number;
  volumeAction?: string;
  secretAction?: string;
  destructiveWriteAction?: string;
  undeclaredSideEffectAction?: string;
  controls: Control[];
};

export type ArchitectureSnapshot = {
  nodes: ArchitectureNode[];
  edges: ArchitectureEdge[];
  zones: TrustZoneDefinition[];
  boundaries: TrustBoundaryDefinition[];
  orchestration: OrchestrationDesign;
};

export type ProjectIdentity = { id: string; version: string };

// Project id must be a non-empty slug: lowercase letters, digits, ".", "-", starting alphanumeric.
export const PROJECT_ID_PATTERN = /^[a-z0-9][a-z0-9.-]*$/;
export function isValidProjectId(id: string): boolean {
  return PROJECT_ID_PATTERN.test(id);
}

export const STARTER_PROJECT: ProjectIdentity = { id: "customer-support-multi-agent", version: "1.0.0-draft" };
export const EMPTY_PROJECT: ProjectIdentity = { id: "new-architecture", version: "0.1.0" };

export const emptyOrchestration: OrchestrationDesign = {
  coordinatorActorId: "",
  pattern: "HYBRID",
  maxParallelism: 4,
  maxTasks: 50,
  maxDurationSeconds: 1800,
  maxMessages: 200,
  failFast: true,
  tasks: [],
};

// --- Export: Studio state -> Architecture manifest -------------------------------------------

export function buildManifestPayload(snapshot: ArchitectureSnapshot, project: ProjectIdentity) {
  const { nodes, edges, zones, boundaries, orchestration } = snapshot;
  const nodeMap = Object.fromEntries(nodes.map((node) => [node.id, node]));
  const manifestNodes = nodes.map((node) => ({
    id: node.id,
    type: node.type,
    owner: node.owner,
    identity: node.identity,
    capabilities: node.capabilities,
    dataAccess: node.dataAccess ?? [],
    sideEffects: node.sideEffects ?? (node.type === "TOOL" ? ["EXTERNAL_WRITE"] : node.type === "RAG" || node.type === "MEMORY" ? ["READ"] : []),
    ...(node.inputSchema ? { inputSchema: node.inputSchema } : {}),
    ...(node.outputSchema ? { outputSchema: node.outputSchema } : {}),
    tenantMode: node.tenantMode,
    failureMode: "FAIL_CLOSED",
    allowedDomains: node.allowedDomains ?? [],
    maxDelegationDepth: node.maxDelegationDepth,
    trustZone: node.trustZone,
    trustZoneId: node.trustZoneId,
    ...(node.definitionDigest ? { definitionDigest: node.definitionDigest } : {}),
    ...(node.annotations ? { annotations: node.annotations } : {}),
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
      ...(edge.boundaryId ? { boundaryId: edge.boundaryId } : {}),
      dynamic: edge.dynamic,
      ...(edge.dynamic && target ? { targetSelector: { types: [target.type], requiredCapabilities: target.capabilities, idPattern: `${target.id}*`, sameTenant: edge.sameTenant } } : {}),
      policy: {
        id: `${edge.id}-policy`,
        version: "1.0.0",
        mode: edge.mode,
        allowedPurposes: edge.allowedPurposes,
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
        ...(edge.maxExportRecords !== undefined ? { maxExportRecords: edge.maxExportRecords } : {}),
        ...(edge.maxExportBytes !== undefined ? { maxExportBytes: edge.maxExportBytes } : {}),
        ...(edge.volumeAction !== undefined ? { volumeAction: edge.volumeAction } : {}),
        ...(edge.secretAction !== undefined ? { secretAction: edge.secretAction } : {}),
        ...(edge.destructiveWriteAction !== undefined ? { destructiveWriteAction: edge.destructiveWriteAction } : {}),
        ...(edge.undeclaredSideEffectAction !== undefined ? { undeclaredSideEffectAction: edge.undeclaredSideEffectAction } : {}),
      },
      controls: edge.controls.map((control) => ({ id: control.id, objective: control.objective, timing: control.timing, enforcementPoint: control.point, assurance: control.assurance })),
    };
  });
  const manifestZones = zones.map((zone) => ({ id: zone.id, label: zone.label, kind: zone.kind, description: zone.description, bounds: { x: zone.x, y: zone.y, width: zone.width, height: zone.height } }));
  const manifestBoundaries = boundaries.map((boundary) => ({ id: boundary.id, label: boundary.label, sourceZoneId: boundary.sourceZoneId, targetZoneId: boundary.targetZoneId, enforcementPoint: boundary.point, allowedRelationships: boundary.allowedRelationships, allowedDataClasses: boundary.allowedData, deniedDataClasses: boundary.deniedData, mode: boundary.mode, failureMode: boundary.failureMode, requireIdentity: boundary.requireIdentity, requireTenantBinding: boundary.requireTenantBinding, maxPayloadBytes: boundary.maxPayloadBytes, description: boundary.description }));
  const manifestOrchestration = {
    coordinatorActorId: orchestration.coordinatorActorId,
    pattern: orchestration.pattern,
    runPolicy: { maxParallelism: orchestration.maxParallelism, maxTasks: orchestration.maxTasks, maxDurationSeconds: orchestration.maxDurationSeconds, maxMessages: orchestration.maxMessages, failFast: orchestration.failFast },
    tasks: orchestration.tasks.map((task) => ({ id: task.id, label: task.label, sourceActorId: task.sourceActorId, targetActorId: task.targetActorId, transport: task.transport, purpose: task.purpose, dependsOn: task.dependsOn, dataClasses: task.dataClasses, acceptanceCriteria: task.acceptanceCriteria, maxAttempts: task.maxAttempts, timeoutSeconds: task.timeoutSeconds, approvalRequired: task.approvalRequired, onFailure: task.onFailure, position: { x: task.x, y: task.y } })),
  };
  const hasOrchestration = orchestration.tasks.length > 0 || Boolean(orchestration.coordinatorActorId);
  return { apiVersion: "interlock.dev/v1alpha1", kind: "Architecture", metadata: { id: project.id, version: project.version }, spec: { trustZones: manifestZones, trustBoundaries: manifestBoundaries, nodes: manifestNodes, edges: manifestEdges, ...(hasOrchestration ? { orchestration: manifestOrchestration } : {}) } };
}

// --- Import: Architecture manifest -> Studio state --------------------------------------------

export type ManifestImportResult =
  | { ok: true; snapshot: ArchitectureSnapshot; project: ProjectIdentity }
  | { ok: false; error: string };

// Grid used to place nodes/tasks whose manifest omits `position`. Purely a placement convenience:
// dragging in the canvas is unaffected, and manifests that already carry positions never use it.
const NODE_GRID = { columns: 4, cellWidth: 210, cellHeight: 120, originX: 40, originY: 90 };
const TASK_GRID = { columns: 3, cellWidth: 300, cellHeight: 170, originX: 100, originY: 150 };

function gridPosition(index: number, grid: typeof NODE_GRID) {
  return { x: grid.originX + (index % grid.columns) * grid.cellWidth, y: grid.originY + Math.floor(index / grid.columns) * grid.cellHeight };
}

export function parseManifestPayload(value: unknown): ManifestImportResult {
  if (!isRecord(value) || value.kind !== "Architecture" || !isRecord(value.spec)) {
    return { ok: false, error: 'not an Architecture manifest — expected "kind": "Architecture" with a "spec" object' };
  }
  try {
    const metadata = isRecord(value.metadata) ? value.metadata : {};
    const project: ProjectIdentity = { id: text(metadata.id) ?? EMPTY_PROJECT.id, version: text(metadata.version) ?? EMPTY_PROJECT.version };
    const spec = value.spec;

    const zones: TrustZoneDefinition[] = arrayOf(spec.trustZones).map((raw) => {
      const zone = isRecord(raw) ? raw : {};
      const bounds = isRecord(zone.bounds) ? zone.bounds : {};
      return {
        id: text(zone.id) ?? "",
        label: text(zone.label) ?? text(zone.id) ?? "",
        kind: zone.kind === "EXTERNAL" ? "EXTERNAL" : "INTERNAL",
        description: text(zone.description) ?? "",
        x: numberOr(bounds.x, 0),
        y: numberOr(bounds.y, 0),
        width: numberOr(bounds.width, 240),
        height: numberOr(bounds.height, 220),
      };
    });
    const zoneKind = Object.fromEntries(zones.map((zone) => [zone.id, zone.kind]));
    const defaultZoneId = zones[0]?.id ?? "";

    const boundaries: TrustBoundaryDefinition[] = arrayOf(spec.trustBoundaries).map((raw) => {
      const boundary = isRecord(raw) ? raw : {};
      return {
        id: text(boundary.id) ?? "",
        label: text(boundary.label) ?? text(boundary.id) ?? "",
        sourceZoneId: text(boundary.sourceZoneId) ?? "",
        targetZoneId: text(boundary.targetZoneId) ?? "",
        point: (text(boundary.enforcementPoint) as EnforcementPoint) ?? "INPUT_GATEWAY",
        allowedRelationships: stringArray(boundary.allowedRelationships),
        allowedData: stringArray(boundary.allowedDataClasses),
        deniedData: stringArray(boundary.deniedDataClasses),
        mode: (text(boundary.mode) as Mode) ?? "SHADOW",
        failureMode: (text(boundary.failureMode) as TrustBoundaryDefinition["failureMode"]) ?? "FAIL_CLOSED",
        requireIdentity: boundary.requireIdentity === true,
        requireTenantBinding: boundary.requireTenantBinding === true,
        maxPayloadBytes: numberOr(boundary.maxPayloadBytes, 1048576),
        description: text(boundary.description) ?? "",
      };
    });

    let nextNodeGridIndex = 0;
    const nodes: ArchitectureNode[] = arrayOf(spec.nodes).map((raw) => {
      const node = isRecord(raw) ? raw : {};
      const position = isRecord(node.position) ? { x: numberOr(node.position.x, NaN), y: numberOr(node.position.y, NaN) } : null;
      const placed = position && !Number.isNaN(position.x) && !Number.isNaN(position.y) ? position : gridPosition(nextNodeGridIndex++, NODE_GRID);
      const trustZoneId = text(node.trustZoneId) ?? defaultZoneId;
      return {
        id: text(node.id) ?? "",
        label: text(node.label) ?? text(node.id) ?? "",
        type: (text(node.type) as NodeType) ?? "TOOL",
        owner: text(node.owner) ?? "",
        identity: text(node.identity) ?? "",
        capabilities: stringArray(node.capabilities),
        dataAccess: stringArray(node.dataAccess),
        tenantMode: (text(node.tenantMode) as ArchitectureNode["tenantMode"]) ?? "REQUIRED",
        maxDelegationDepth: numberOr(node.maxDelegationDepth, 0),
        trustZone: (text(node.trustZone) as TrustZone) ?? zoneKind[trustZoneId] ?? "INTERNAL",
        trustZoneId,
        ...(text(node.definitionDigest) ? { definitionDigest: text(node.definitionDigest) } : {}),
        allowedDomains: stringArray(node.allowedDomains),
        ...(Array.isArray(node.sideEffects) ? { sideEffects: stringArray(node.sideEffects) } : {}),
        ...(isRecord(node.inputSchema) ? { inputSchema: node.inputSchema } : {}),
        ...(isRecord(node.outputSchema) ? { outputSchema: node.outputSchema } : {}),
        ...(isRecord(node.annotations) ? { annotations: node.annotations } : {}),
        x: placed.x,
        y: placed.y,
      };
    });

    const edges: ArchitectureEdge[] = arrayOf(spec.edges).map((raw) => {
      const edge = isRecord(raw) ? raw : {};
      const policy = isRecord(edge.policy) ? edge.policy : {};
      const targetSelector = isRecord(edge.targetSelector) ? edge.targetSelector : null;
      const dynamic = edge.dynamic === true;
      return {
        id: text(edge.id) ?? "",
        source: text(edge.source) ?? "",
        target: text(edge.target) ?? "",
        relationshipId: text(edge.relationshipId) ?? "",
        relationship: text(edge.relationship) ?? "",
        mode: (text(policy.mode) as Mode) ?? "SHADOW",
        failureMode: (text(policy.failureMode) as ArchitectureEdge["failureMode"]) ?? "FAIL_CLOSED",
        allowedData: stringArray(policy.allowedDataClasses),
        allowedPurposes: stringArray(policy.allowedPurposes),
        approvalRequired: policy.externalWriteRequiresApproval === true,
        dynamic,
        sameTenant: dynamic && targetSelector ? targetSelector.sameTenant !== false : true,
        maxDepth: numberOr(policy.maxDelegationDepth, 0),
        ...(text(edge.boundaryId) ? { boundaryId: text(edge.boundaryId) } : {}),
        ...(typeof policy.maxExportRecords === "number" ? { maxExportRecords: policy.maxExportRecords } : {}),
        ...(typeof policy.maxExportBytes === "number" ? { maxExportBytes: policy.maxExportBytes } : {}),
        ...(text(policy.volumeAction) ? { volumeAction: text(policy.volumeAction) } : {}),
        ...(text(policy.secretAction) ? { secretAction: text(policy.secretAction) } : {}),
        ...(text(policy.destructiveWriteAction) ? { destructiveWriteAction: text(policy.destructiveWriteAction) } : {}),
        ...(text(policy.undeclaredSideEffectAction) ? { undeclaredSideEffectAction: text(policy.undeclaredSideEffectAction) } : {}),
        controls: arrayOf(edge.controls).map((rawControl) => {
          const control = isRecord(rawControl) ? rawControl : {};
          return {
            id: text(control.id) ?? "",
            objective: (text(control.objective) as Control["objective"]) ?? "PREVENT",
            timing: (text(control.timing) as Control["timing"]) ?? "PRE_EXECUTION",
            point: (text(control.enforcementPoint) as EnforcementPoint) ?? "AUDIT_SINK",
            assurance: (text(control.assurance) as Assurance) ?? "DECLARED",
          };
        }),
      };
    });

    const orchestrationRaw = isRecord(spec.orchestration) ? spec.orchestration : {};
    const runPolicy = isRecord(orchestrationRaw.runPolicy) ? orchestrationRaw.runPolicy : {};
    let nextTaskGridIndex = 0;
    const orchestration: OrchestrationDesign = {
      coordinatorActorId: text(orchestrationRaw.coordinatorActorId) ?? "",
      pattern: (text(orchestrationRaw.pattern) as OrchestrationDesign["pattern"]) ?? "HYBRID",
      maxParallelism: numberOr(runPolicy.maxParallelism, 4),
      maxTasks: numberOr(runPolicy.maxTasks, 50),
      maxDurationSeconds: numberOr(runPolicy.maxDurationSeconds, 1800),
      maxMessages: numberOr(runPolicy.maxMessages, 200),
      failFast: runPolicy.failFast !== false,
      tasks: arrayOf(orchestrationRaw.tasks).map((raw) => {
        const task = isRecord(raw) ? raw : {};
        const position = isRecord(task.position) ? { x: numberOr(task.position.x, NaN), y: numberOr(task.position.y, NaN) } : null;
        const placed = position && !Number.isNaN(position.x) && !Number.isNaN(position.y) ? position : gridPosition(nextTaskGridIndex++, TASK_GRID);
        return {
          id: text(task.id) ?? "",
          label: text(task.label) ?? text(task.id) ?? "",
          sourceActorId: text(task.sourceActorId) ?? "",
          targetActorId: text(task.targetActorId) ?? "",
          transport: (text(task.transport) as WorkflowTask["transport"]) ?? "LOCAL",
          purpose: text(task.purpose) ?? "",
          dependsOn: stringArray(task.dependsOn),
          dataClasses: stringArray(task.dataClasses),
          acceptanceCriteria: stringArray(task.acceptanceCriteria),
          maxAttempts: numberOr(task.maxAttempts, 1),
          timeoutSeconds: numberOr(task.timeoutSeconds, 60),
          approvalRequired: task.approvalRequired === true,
          onFailure: (text(task.onFailure) as WorkflowTask["onFailure"]) ?? "FAIL_WORKFLOW",
          x: placed.x,
          y: placed.y,
        };
      }),
    };

    return { ok: true, project, snapshot: { nodes, edges, zones, boundaries, orchestration } };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "manifest could not be parsed" };
  }
}

// --- Local project storage --------------------------------------------------------------------

export const PROJECTS_STORAGE_KEY = "agent-interlock.studio.projects";

export type SavedProject = { savedAt: string; manifest: unknown };
export type SavedProjectsIndex = Record<string, SavedProject>;

export function parseSavedProjects(raw: string | null): SavedProjectsIndex {
  if (!raw) return {};
  try {
    const value = JSON.parse(raw);
    if (!isRecord(value)) return {};
    const result: SavedProjectsIndex = {};
    for (const [id, entry] of Object.entries(value)) {
      if (isRecord(entry) && typeof entry.savedAt === "string") result[id] = { savedAt: entry.savedAt, manifest: entry.manifest };
    }
    return result;
  } catch {
    return {};
  }
}

// --- Shared parsing helpers ---------------------------------------------------------------------

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function arrayOf(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value : [];
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === "number" && !Number.isNaN(value) ? value : fallback;
}
