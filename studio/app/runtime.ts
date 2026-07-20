export type RuntimeObservation = {
  source: string;
  target: string;
  relationship: string;
  relationshipId: string;
  interactionId: string;
  traceId?: string;
  spanId?: string;
  controlEvaluated: boolean;
};

export type RuntimeImportIssue = {
  code: string;
  message: string;
  spanId?: string;
};

export type RuntimeImport = {
  format: "INTERLOCK_LEDGER" | "OTLP_JSON";
  observations: RuntimeObservation[];
  issues: RuntimeImportIssue[];
};

export type DesignEdgeContract = {
  id: string;
  source: string;
  target: string;
  relationship: string;
  relationshipId: string;
  dynamic: boolean;
};

export type RuntimeDiff = {
  undeclared: RuntimeObservation[];
  unobservedEdgeIds: string[];
  controlBypassInteractionIds: string[];
};

const trackedOperations = new Set([
  "invoke_agent",
  "execute_tool",
  "retrieval",
  "search_memory",
  "create_memory",
  "update_memory",
  "upsert_memory",
  "delete_memory",
]);

export function parseRuntimeTelemetry(value: unknown): RuntimeImport {
  if (isRecord(value) && Array.isArray(value.resourceSpans)) return parseOtlp(value);
  if (isRecord(value) && Array.isArray(value.events)) return parseLedger(value.events);
  if (Array.isArray(value)) return parseLedger(value);
  throw new Error("Expected an Interlock event array or OTLP resourceSpans object");
}

export function computeRuntimeDiff(edges: DesignEdgeContract[], observations: RuntimeObservation[]): RuntimeDiff {
  const undeclared = observations.filter((item) => !edges.some((edge) => matchesEdge(edge, item)));
  const unobservedEdgeIds = edges.filter((edge) => !observations.some((item) => matchesEdge(edge, item))).map((edge) => edge.id);
  const controlBypassInteractionIds = Array.from(new Set(observations.filter((item) => !item.controlEvaluated).map((item) => item.interactionId)));
  return { undeclared, unobservedEdgeIds, controlBypassInteractionIds };
}

export function matchesEdge(edge: DesignEdgeContract, item: RuntimeObservation): boolean {
  if (edge.source !== item.source || edge.relationship !== item.relationship || edge.relationshipId !== item.relationshipId) return false;
  return edge.dynamic ? item.target.startsWith(edge.target) : edge.target === item.target;
}

function parseLedger(values: unknown[]): RuntimeImport {
  const issues: RuntimeImportIssue[] = [];
  const controls = new Set<string>();
  const requested: Record<string, unknown>[] = [];
  values.forEach((value, index) => {
    if (!isRecord(value)) {
      issues.push({ code: "TELEMETRY_EVENT_INVALID", message: `Event ${index + 1} is not an object` });
      return;
    }
    if ("integrity_hash" in value) issues.push({ code: "TELEMETRY_INTEGRITY_UNVERIFIED", message: "Browser import does not verify Ledger integrity hashes; confirm with the Python CLI", spanId: text(value.span_id) });
    const interactionId = text(value.interaction_id);
    if (value.event_type === "CONTROL_EVALUATED") {
      if (interactionId) controls.add(interactionId);
      else issues.push({ code: "TELEMETRY_CONTROL_INTERACTION_MISSING", message: "CONTROL_EVALUATED has no interaction_id", spanId: text(value.span_id) });
    } else if (value.event_type === "INTERACTION_REQUESTED") requested.push(value);
  });
  const observations = requested.map((value, index) => observationFrom(value, controls, issues, `Event ${index + 1}`)).filter((item): item is RuntimeObservation => Boolean(item));
  return { format: "INTERLOCK_LEDGER", observations: unique(observations), issues };
}

function parseOtlp(value: Record<string, unknown>): RuntimeImport {
  const observations: RuntimeObservation[] = [];
  const issues: RuntimeImportIssue[] = [];
  otlpSpans(value).forEach((span) => {
    const attributes = attributeMap(span.attributes);
    const operation = text(attributes["gen_ai.operation.name"]);
    const mcpMethod = text(attributes["mcp.method.name"]);
    const spanId = text(span.spanId);
    if (!text(attributes["interlock.relationship.id"])) {
      if ((operation && trackedOperations.has(operation)) || mcpMethod === "tools/call") issues.push({ code: "TELEMETRY_SECURITY_CONTEXT_MISSING", message: "Tracked GenAI/MCP span has no Interlock relationship context", spanId });
      return;
    }
    const mapped = {
      source_actor_id: attributes["interlock.source.actor.id"],
      target_actor_id: attributes["interlock.target.actor.id"],
      relationship_type: attributes["interlock.relationship.type"],
      relationship_id: attributes["interlock.relationship.id"],
      interaction_id: attributes["interlock.interaction.id"] ?? spanId,
      trace_id: span.traceId,
      span_id: spanId,
      control_evaluated: booleanValue(attributes["interlock.control.evaluated"]),
    };
    const observation = observationFrom(mapped, new Set(), issues, "OTLP span");
    if (observation) observations.push(observation);
  });
  return { format: "OTLP_JSON", observations: unique(observations), issues };
}

function observationFrom(value: Record<string, unknown>, controls: Set<string>, issues: RuntimeImportIssue[], context: string): RuntimeObservation | null {
  const source = text(value.source_actor_id);
  const target = text(value.target_actor_id);
  const relationship = text(value.relationship_type);
  const relationshipId = text(value.relationship_id);
  const spanId = text(value.span_id);
  const interactionId = text(value.interaction_id) ?? spanId;
  const missing = [["source_actor_id", source], ["target_actor_id", target], ["relationship_type", relationship], ["relationship_id", relationshipId], ["interaction_id", interactionId]].filter(([, item]) => !item).map(([name]) => name);
  if (missing.length) {
    issues.push({ code: "TELEMETRY_RELATIONSHIP_INCOMPLETE", message: `${context} is missing ${missing.join(", ")}`, spanId });
    return null;
  }
  return {
    source: source!, target: target!, relationship: relationship!, relationshipId: relationshipId!, interactionId: interactionId!,
    traceId: text(value.trace_id), spanId,
    controlEvaluated: booleanValue(value.control_evaluated) || controls.has(interactionId!),
  };
}

function otlpSpans(value: Record<string, unknown>): Record<string, unknown>[] {
  const spans: Record<string, unknown>[] = [];
  for (const resource of value.resourceSpans as unknown[]) {
    if (!isRecord(resource)) continue;
    const scopes = Array.isArray(resource.scopeSpans) ? resource.scopeSpans : Array.isArray(resource.instrumentationLibrarySpans) ? resource.instrumentationLibrarySpans : [];
    for (const scope of scopes) {
      if (!isRecord(scope) || !Array.isArray(scope.spans)) continue;
      scope.spans.forEach((span) => { if (isRecord(span)) spans.push(span); });
    }
  }
  return spans;
}

function attributeMap(value: unknown): Record<string, unknown> {
  if (isRecord(value)) return value;
  const result: Record<string, unknown> = {};
  if (!Array.isArray(value)) return result;
  value.forEach((item) => { if (isRecord(item) && text(item.key)) result[text(item.key)!] = otlpValue(item.value); });
  return result;
}

function otlpValue(value: unknown): unknown {
  if (!isRecord(value)) return value;
  for (const key of ["stringValue", "boolValue", "intValue", "doubleValue", "bytesValue"]) if (key in value) return value[key];
  if (isRecord(value.arrayValue) && Array.isArray(value.arrayValue.values)) return value.arrayValue.values.map(otlpValue);
  if (isRecord(value.kvlistValue)) return attributeMap(value.kvlistValue.values);
  return value;
}

function unique(values: RuntimeObservation[]): RuntimeObservation[] {
  return Array.from(new Map(values.map((item) => [`${item.source}\u0000${item.target}\u0000${item.relationshipId}\u0000${item.interactionId}`, item])).values());
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function text(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return String(value);
}

function booleanValue(value: unknown): boolean {
  return value === true || String(value).toLowerCase() === "true" || value === 1;
}

export const demoRuntimeTelemetry = [
  { event_type: "INTERACTION_REQUESTED", occurred_at: "2026-07-20T01:00:00Z", tenant_id: "tenant-demo", environment: "DEV", data_source: "DEMO", trace_id: "trace-demo", span_id: "span-delegation", interaction_id: "interaction-delegation", source_actor_id: "agent.support", target_actor_id: "agent.research.runtime-42", relationship_type: "DELEGATES", relationship_id: "REL-06", payload: {} },
  { event_type: "CONTROL_EVALUATED", occurred_at: "2026-07-20T01:00:01Z", tenant_id: "tenant-demo", environment: "DEV", data_source: "DEMO", trace_id: "trace-demo", span_id: "span-delegation", interaction_id: "interaction-delegation", payload: { control: { decision: "ALLOW", actualEnforced: true, policyId: "demo-delegation", mode: "ENFORCE", reasonCodes: [] } } },
  { event_type: "INTERACTION_REQUESTED", occurred_at: "2026-07-20T01:01:00Z", tenant_id: "tenant-demo", environment: "DEV", data_source: "DEMO", trace_id: "trace-demo", span_id: "span-tool", interaction_id: "interaction-tool", source_actor_id: "agent.support", target_actor_id: "tool.email", relationship_type: "INVOKES", relationship_id: "REL-05", payload: {} },
  { event_type: "CONTROL_EVALUATED", occurred_at: "2026-07-20T01:01:01Z", tenant_id: "tenant-demo", environment: "DEV", data_source: "DEMO", trace_id: "trace-demo", span_id: "span-tool", interaction_id: "interaction-tool", payload: { control: { decision: "ALLOW", actualEnforced: true, policyId: "demo-tool", mode: "ENFORCE", reasonCodes: [] } } },
  { event_type: "INTERACTION_REQUESTED", occurred_at: "2026-07-20T01:02:00Z", tenant_id: "tenant-demo", environment: "DEV", data_source: "DEMO", trace_id: "trace-demo", span_id: "span-bypass", interaction_id: "interaction-bypass", source_actor_id: "agent.research.runtime-42", target_actor_id: "external.unknown", relationship_type: "SENDS", relationship_id: "REL-07", payload: {} },
  { event_type: "SECURITY_OUTCOME_SET", occurred_at: "2026-07-20T01:02:01Z", tenant_id: "tenant-demo", environment: "DEV", data_source: "DEMO", trace_id: "trace-demo", span_id: "span-bypass", interaction_id: "interaction-bypass", payload: { securityOutcome: "PARTIALLY_EXECUTED" } },
];
