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
  targetSelector?: { idPattern: string };
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
  return edge.dynamic ? matchesGlob(item.target, edge.targetSelector?.idPattern ?? `${edge.target}*`) : edge.target === item.target;
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

// Python fnmatchcase semantics: case-sensitive, * and ? include slashes/newlines,
// bracket ranges and [!...] negation. Dynamic programming avoids regex backtracking.
export function matchesGlob(value: string, pattern: string): boolean {
  const characters = Array.from(value);
  const glob = Array.from(pattern);
  let matched = [true, ...characters.map(() => false)];
  for (let i = 0; i < glob.length; i++) {
    const token = glob[i];
    let accepts = (character: string) => token === "?" || character === token;
    if (token === "[") {
      let end = i + 1;
      if (glob[end] === "!") end++;
      if (glob[end] === "]") end++;
      while (end < glob.length && glob[end] !== "]") end++;
      if (end < glob.length) {
        // fnmatch removes descending ranges before interpreting leading !.
        const chunks: string[][] = [];
        let start = i + 1;
        let dash = start + (glob[start] === "!" ? 2 : 1);
        while (dash < end) {
          while (dash < end && glob[dash] !== "-") dash++;
          if (dash === end) break;
          chunks.push(glob.slice(start, dash));
          start = dash + 1;
          dash += 3;
        }
        if (start < end) chunks.push(glob.slice(start, end));
        else chunks[chunks.length - 1].push("-");
        for (let j = chunks.length - 1; j > 0; j--) {
          if (chunks[j - 1].at(-1)!.codePointAt(0)! > chunks[j][0].codePointAt(0)!) {
            chunks[j - 1] = [...chunks[j - 1].slice(0, -1), ...chunks[j].slice(1)];
            chunks.splice(j, 1);
          }
        }
        const negated = chunks[0]?.[0] === "!";
        if (negated) chunks[0].shift();
        const body = chunks.map((chunk) => chunk.map((character) => "\\[]^-/".includes(character) ? `\\${character}` : character).join("")).join("-");
        const matcher = body ? new RegExp(`^[${negated ? "^" : ""}${body}]$`, "u") : null;
        accepts = (character) => matcher ? matcher.test(character) : negated;
        i = end;
      }
    }
    const next = [token === "*" && matched[0]];
    characters.forEach((character, index) => {
      next.push(token === "*" ? matched[index + 1] || next[index] : matched[index] && accepts(character));
    });
    matched = next;
  }
  return matched[characters.length];
}
