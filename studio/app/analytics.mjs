// Security statistics: interaction-level reduction and the aggregate model.
//
// This is a 1:1 port of `src/agent_interlock/analytics.py`, which remains the
// semantic source of truth (see its docstring for the pinned semantics and
// `schemas/security-statistics.schema.json` for the contract shape). The
// golden fixture pair `schemas/fixtures/analytics-events.json` /
// `analytics-statistics.json` must reduce to byte-identical JSON on both
// sides -- see `tests/analytics-contract.test.mjs`. Any semantic change
// belongs in the Python module first, then here.

/**
 * @typedef {Object} CheckCoverage
 * Mirrors `CheckCoverage` in analytics.py: three nested sets of check ids for
 * one interaction. `flagged` subset of `ran` subset of `armed`; ABSENT is
 * everything in the catalogue not in `armed`, so it lives in `coverageState`,
 * not here.
 * @property {Set<string>} armed
 * @property {Set<string>} ran
 * @property {Set<string>} flagged
 */

/**
 * @typedef {Object} InteractionRecord
 * @property {string} interactionId
 * @property {string} tenantId
 * @property {string} environment
 * @property {string} dataSource
 * @property {string} sourceActorId
 * @property {string|null} targetActorId
 * @property {string} relationshipId
 * @property {string|null} policyId
 * @property {string|null} mode
 * @property {string} decision
 * @property {boolean} actualEnforced
 * @property {boolean} executionPermitted
 * @property {string[]} reasonCodes
 * @property {boolean} controlEvaluated
 * @property {CheckCoverage} coverage
 * @property {boolean} executionAttempted
 * @property {boolean} executionSucceeded
 * @property {boolean} enforcementActionCompleted
 * @property {string} securityOutcome
 * @property {string} firstOccurredAt
 * @property {boolean} blockDecision
 * @property {boolean} shadowWouldBlock
 * @property {boolean} enforcedBlock
 * @property {[string, string, string]|null} edgeKey
 * @property {boolean} partialOrBypass
 */

/**
 * @typedef {Object} Counters
 * @property {number} interactionCount
 * @property {number} blockDecisionCount
 * @property {number} shadowWouldBlockCount
 * @property {number} enforcedBlockCount
 * @property {number} executionAttemptCount
 * @property {number} executionSuccessCount
 * @property {number} partialOrBypassCount
 * @property {number} noControlRecordCount
 */

/**
 * @typedef {Object} CheckCoverageRow
 * @property {string} checkId
 * @property {string} scope
 * @property {number} ranCleanCount
 * @property {number} ranFlaggedCount
 * @property {number} inapplicableCount
 * @property {number} absentCount
 */

/**
 * @typedef {Object} EdgeRow
 * @property {string} sourceActorId
 * @property {string} targetActorId
 * @property {string} policyId
 * @property {Counters} counters
 * @property {CheckCoverageRow[]} byCheck
 */

export const STATISTICS_API_VERSION = "interlock.dev/v1alpha1";
export const STATISTICS_KIND = "SecurityStatistics";

// Mirrors `COVERAGE_STATES` in analytics.py.
export const COVERAGE_STATES = ["RAN_CLEAN", "RAN_FLAGGED", "INAPPLICABLE", "ABSENT"];

// Mirrors `_DECISION_RANK` in `src/agent_interlock/models.py`, which is the
// definition -- every ControlDecision member, no fallback rank. BYPASSED ranks
// below ALLOW (skipped raised no objection) and ERROR sits between BLOCK and
// QUARANTINE; see the comment there for why. Unknown decision strings fail
// closed to BLOCK (see `_control_decision` in analytics.py).
const DECISION_RANK = {
  BYPASSED: 0,
  ALLOW: 1,
  SANITIZE: 2,
  DEGRADE: 3,
  CHALLENGE: 4,
  HOLD: 5,
  BLOCK: 6,
  ERROR: 7,
  QUARANTINE: 8,
  REVOKE: 9,
  KILL: 10,
};

/**
 * Mirrors `CheckCoverage.state`: RAN_FLAGGED > RAN_CLEAN > INAPPLICABLE > ABSENT.
 *
 * @param {CheckCoverage} coverage
 * @param {string} checkId
 * @returns {string}
 */
function coverageState(coverage, checkId) {
  if (coverage.flagged.has(checkId)) return "RAN_FLAGGED";
  if (coverage.ran.has(checkId)) return "RAN_CLEAN";
  if (coverage.armed.has(checkId)) return "INAPPLICABLE";
  return "ABSENT";
}

/**
 * Mirrors `coverage_declarations`: every CONTROL_COVERAGE_DECLARED payload in
 * the stream, keyed by its digest. First declaration per digest wins.
 *
 * @param {Iterable<Record<string, any>>} events
 * @returns {Map<string, Record<string, any>>}
 */
export function coverageDeclarations(events) {
  const declarations = new Map();
  for (const event of events) {
    if (event.event_type !== "CONTROL_COVERAGE_DECLARED") continue;
    const payload = event.payload;
    const coverage = isPlainObject(payload) ? payload.coverage : null;
    if (isPlainObject(coverage) && typeof coverage.profileDigest === "string") {
      if (!declarations.has(coverage.profileDigest)) declarations.set(coverage.profileDigest, coverage);
    }
  }
  return declarations;
}

/**
 * Mirrors `check_catalogue`: check id -> scope, over the union of every armed
 * set declared in the stream.
 *
 * @param {Map<string, Record<string, any>>} declarations
 * @returns {Map<string, string>}
 */
export function checkCatalogue(declarations) {
  const catalogue = new Map();
  for (const declaration of declarations.values()) {
    for (const entry of declaration.armed ?? []) {
      if (isPlainObject(entry) && typeof entry.id === "string" && !catalogue.has(entry.id)) {
        catalogue.set(entry.id, String(entry.scope ?? ""));
      }
    }
  }
  return catalogue;
}

/**
 * Mirrors `_coverage`: join one interaction's control records to the
 * coverage they were declared under. A digest the stream never declared
 * contributes nothing.
 *
 * @param {Record<string, any>[]} controls
 * @param {Map<string, Record<string, any>>} declarations
 * @returns {CheckCoverage}
 */
function coverageFor(controls, declarations) {
  const armed = new Set();
  const ran = new Set();
  const flagged = new Set();
  for (const control of controls) {
    // Mirrors _coverage in analytics.py: a bare string is iterable in both languages, so an
    // unguarded loop contributes one check per character.
    const rawFlagged = typeof control.flaggedChecks === "string"
      ? [control.flaggedChecks]
      : Array.isArray(control.flaggedChecks) ? control.flaggedChecks : [];
    for (const checkId of rawFlagged) flagged.add(String(checkId));
    const declaration = declarations.get(String(control.evaluatedProfile ?? ""));
    if (declaration === undefined) continue;
    for (const entry of declaration.armed ?? []) {
      if (isPlainObject(entry) && typeof entry.id === "string") armed.add(entry.id);
    }
    for (const checkId of declaration.evaluated ?? []) ran.add(String(checkId));
  }
  // A flagged check ran, and a check that ran is armed, whatever an inconsistent stream claims.
  for (const checkId of flagged) ran.add(checkId);
  for (const checkId of ran) armed.add(checkId);
  return { armed, ran, flagged };
}

/**
 * Extract raw Ledger events from either supported import envelope.
 *
 * @param {unknown} value
 * @returns {Record<string, unknown>[]|null}
 */
export function ledgerEventsForStatistics(value) {
  if (Array.isArray(value)) return value.filter(isPlainObject);
  if (isPlainObject(value) && Array.isArray(value.events)) return value.events.filter(isPlainObject);
  return null;
}

/**
 * Join event-envelope objects (the JSON shape of `Event.to_dict()`) by interaction.
 *
 * @param {Iterable<Record<string, any>>} events
 * @returns {InteractionRecord[]}
 */
export function reduceInteractions(events) {
  const eventList = Array.isArray(events) ? events : [...events];
  const declarations = coverageDeclarations(eventList);
  const grouped = new Map();
  for (const event of eventList) {
    const interactionId = event.interaction_id;
    if (interactionId) {
      const tenantId = String(event.tenant_id ?? "");
      if (!grouped.has(tenantId)) grouped.set(tenantId, new Map());
      const tenant = grouped.get(tenantId);
      if (!tenant.has(String(interactionId))) tenant.set(String(interactionId), []);
      tenant.get(String(interactionId)).push(event);
    }
  }
  const records = [];
  for (const tenant of grouped.values()) {
    for (const [interactionId, items] of tenant) {
      const record = reduceOne(interactionId, items, declarations);
      if (record) records.push(record);
    }
  }
  records.sort((a, b) => eventTime({ occurred_at: a.firstOccurredAt }) - eventTime({ occurred_at: b.firstOccurredAt })
    || cmp(a.tenantId, b.tenantId)
    || cmp(a.interactionId, b.interactionId));
  return records;
}

/**
 * @param {string} interactionId
 * @param {Record<string, any>[]} events
 * @param {Map<string, Record<string, any>>} declarations
 * @returns {InteractionRecord|null}
 */
function reduceOne(interactionId, events, declarations) {
  const orderedIndices = events
    .map((_, index) => index)
    .sort((a, b) => eventTime(events[a]) - eventTime(events[b])
      || cmp(String(events[a].event_id ?? ""), String(events[b].event_id ?? ""))
      || a - b);
  const requestedIndices = orderedIndices.filter((index) => events[index].event_type === "INTERACTION_REQUESTED");
  if (requestedIndices.length === 0) return null;

  const controls = [];
  let executionAttempted = false;
  let executionSucceeded = false;
  let enforcementActionCompleted = false;
  let outcome = "UNKNOWN";

  for (const index of orderedIndices) {
    const event = events[index];
    const eventType = event.event_type;
    const payload = isPlainObject(event.payload) ? event.payload : {};
    if (eventType === "CONTROL_EVALUATED" && isPlainObject(payload.control)) {
      controls.push(payload.control);
    } else if (eventType === "ACTION_EXECUTED") {
      if (payload.connectorExecutionId !== null && payload.connectorExecutionId !== undefined) {
        executionAttempted = true;
        if (payload.result === "COMPLETED") executionSucceeded = true;
      } else if (payload.result === "COMPLETED") {
        enforcementActionCompleted = true;
      }
    } else if (eventType === "SECURITY_OUTCOME_SET" && payload.securityOutcome) {
      outcome = String(payload.securityOutcome);
    }
  }

  const decisions = controls.map(controlDecision);
  const decision = strongestDecision(decisions);
  let chosen = {};
  for (let i = 0; i < controls.length; i += 1) {
    if (decisions[i] === decision) {
      chosen = controls[i];
      break;
    }
  }

  const reasonCodes = [];
  for (const control of controls) {
    const codes = typeof control.reasonCodes === "string"
      ? [control.reasonCodes]
      : Array.isArray(control.reasonCodes) ? control.reasonCodes : [];
    for (const code of codes) {
      const value = String(code);
      if (!reasonCodes.includes(value)) reasonCodes.push(value);
    }
  }

  const first = events[requestedIndices[0]];
  const executionPermitted = controls.every((control) => (
    control.executionPermitted === undefined || control.executionPermitted === true
  ));
  const blockDecision = decision !== "ALLOW" || !executionPermitted;
  const actualEnforced = chosen.actualEnforced === true;
  const shadowWouldBlock = blockDecision && !actualEnforced;
  const enforcedBlock = blockDecision && actualEnforced && enforcementActionCompleted && !executionAttempted && outcome === "BLOCKED";
  const partialOrBypass = outcome === "PARTIALLY_EXECUTED" || (blockDecision && actualEnforced && executionAttempted);
  const sourceActorId = String(first.source_actor_id ?? "");
  const targetActorId = first.target_actor_id ?? null;
  const policyId = typeof chosen.policyId === "string" ? chosen.policyId : null;
  // Mirrors `edge_key`: no complete (source, target, policy) triple -> unattributed.
  const edgeKey = targetActorId === null || policyId === null ? null : [sourceActorId, targetActorId, policyId];

  return {
    interactionId,
    tenantId: String(first.tenant_id ?? ""),
    environment: String(first.environment ?? ""),
    dataSource: String(first.data_source ?? ""),
    sourceActorId,
    targetActorId,
    relationshipId: String(first.relationship_id ?? ""),
    policyId,
    mode: typeof chosen.mode === "string" ? chosen.mode : null,
    decision,
    actualEnforced,
    executionPermitted,
    reasonCodes,
    controlEvaluated: controls.length > 0,
    coverage: coverageFor(controls, declarations),
    executionAttempted,
    executionSucceeded,
    enforcementActionCompleted,
    securityOutcome: outcome,
    firstOccurredAt: String(first.occurred_at ?? ""),
    blockDecision,
    shadowWouldBlock,
    enforcedBlock,
    edgeKey,
    partialOrBypass,
  };
}

/**
 * @param {Record<string, any>} control
 * @returns {string}
 */
function controlDecision(control) {
  const raw = control.decision;
  return Object.prototype.hasOwnProperty.call(DECISION_RANK, raw) ? raw : "BLOCK";
}

/**
 * @param {string[]} decisions
 * @returns {string}
 */
function strongestDecision(decisions) {
  if (decisions.length === 0) return "ALLOW";
  let strongest = decisions[0];
  for (let i = 1; i < decisions.length; i += 1) {
    if (DECISION_RANK[decisions[i]] > DECISION_RANK[strongest]) strongest = decisions[i];
  }
  return strongest;
}

/**
 * Aggregate events into the SecurityStatistics contract value.
 *
 * @param {Iterable<Record<string, any>>} events
 * @returns {{apiVersion: string, kind: string, interactionCount: number, partitions: object[]}}
 */
export function summarizeSecurityStatistics(events) {
  const eventList = Array.isArray(events) ? events : [...events];
  const records = reduceInteractions(eventList);
  const catalogue = checkCatalogue(coverageDeclarations(eventList));
  const dataSources = [...new Set(records.map((record) => record.dataSource))].sort(cmp);
  const partitions = dataSources.map((dataSource) => {
    const subset = records.filter((record) => record.dataSource === dataSource);
    return {
      dataSource,
      counters: counters(subset),
      outcomes: outcomeCounts(subset),
      byRelationship: grouped(subset, "relationshipId", (r) => r.relationshipId),
      byActor: grouped(subset, "sourceActorId", (r) => r.sourceActorId),
      byPolicy: grouped(subset, "policyId", (r) => r.policyId),
      byMode: grouped(subset, "mode", (r) => r.mode),
      byReasonCode: reasonCounts(subset),
      byCheck: byCheck(subset, catalogue),
      byEdge: byEdge(subset, catalogue),
      unattributed: counters(subset.filter((record) => record.edgeKey === null)),
      timeSeries: timeSeries(subset),
    };
  });
  return {
    apiVersion: STATISTICS_API_VERSION,
    kind: STATISTICS_KIND,
    interactionCount: records.length,
    partitions,
  };
}

/**
 * @param {InteractionRecord[]} records
 * @returns {Counters}
 */
function counters(records) {
  return {
    interactionCount: records.length,
    blockDecisionCount: records.filter((r) => r.blockDecision).length,
    shadowWouldBlockCount: records.filter((r) => r.shadowWouldBlock).length,
    enforcedBlockCount: records.filter((r) => r.enforcedBlock).length,
    executionAttemptCount: records.filter((r) => r.executionAttempted).length,
    executionSuccessCount: records.filter((r) => r.executionSucceeded).length,
    partialOrBypassCount: records.filter((r) => r.partialOrBypass).length,
    // See `_counters` in analytics.py for why this is counted in every grouping.
    noControlRecordCount: records.filter((r) => !r.controlEvaluated).length,
  };
}

/**
 * Mirrors `_by_check`: per canonical check id, how many interactions ended in
 * each of the four coverage states.
 *
 * @param {InteractionRecord[]} records
 * @param {Map<string, string>} catalogue
 * @returns {CheckCoverageRow[]}
 */
function byCheck(records, catalogue) {
  return [...catalogue.keys()].sort(cmp).map((checkId) => {
    const counts = { RAN_CLEAN: 0, RAN_FLAGGED: 0, INAPPLICABLE: 0, ABSENT: 0 };
    for (const record of records) counts[coverageState(record.coverage, checkId)] += 1;
    return {
      checkId,
      scope: catalogue.get(checkId),
      ranCleanCount: counts.RAN_CLEAN,
      ranFlaggedCount: counts.RAN_FLAGGED,
      inapplicableCount: counts.INAPPLICABLE,
      absentCount: counts.ABSENT,
    };
  });
}

/**
 * Mirrors `_by_edge`: the deliverable cross-tabulation, grouped by the
 * (source, target, policy) triple. Rows ABSENT for every interaction on the
 * edge are omitted.
 *
 * @param {InteractionRecord[]} records
 * @param {Map<string, string>} catalogue
 * @returns {EdgeRow[]}
 */
function byEdge(records, catalogue) {
  const groups = new Map();
  for (const record of records) {
    if (record.edgeKey === null) continue;
    const key = JSON.stringify(record.edgeKey);
    if (!groups.has(key)) groups.set(key, { edgeKey: record.edgeKey, records: [] });
    groups.get(key).records.push(record);
  }
  const keys = [...groups.keys()].sort((a, b) => {
    const left = groups.get(a).edgeKey;
    const right = groups.get(b).edgeKey;
    return cmp(left[0], right[0]) || cmp(left[1], right[1]) || cmp(left[2], right[2]);
  });
  return keys.map((key) => {
    const { edgeKey, records: edgeRecords } = groups.get(key);
    return {
      sourceActorId: edgeKey[0],
      targetActorId: edgeKey[1],
      policyId: edgeKey[2],
      counters: counters(edgeRecords),
      byCheck: byCheck(edgeRecords, catalogue).filter((row) => row.absentCount !== edgeRecords.length),
    };
  });
}

/**
 * @param {InteractionRecord[]} records
 * @returns {Record<string, number>}
 */
function outcomeCounts(records) {
  const counts = new Map();
  for (const record of records) {
    counts.set(record.securityOutcome, (counts.get(record.securityOutcome) || 0) + 1);
  }
  const result = {};
  for (const key of [...counts.keys()].sort(cmp)) result[key] = counts.get(key);
  return result;
}

/**
 * @param {InteractionRecord[]} records
 * @param {string} keyName
 * @param {(record: InteractionRecord) => string|null} keyFn
 * @returns {object[]}
 */
function grouped(records, keyName, keyFn) {
  const groups = new Map();
  for (const record of records) {
    const value = keyFn(record);
    if (value === null || value === undefined) continue;
    const key = String(value);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(record);
  }
  return [...groups.keys()].sort(cmp).map((key) => ({ [keyName]: key, counters: counters(groups.get(key)) }));
}

/**
 * @param {InteractionRecord[]} records
 * @returns {{reasonCode: string, interactionCount: number}[]}
 */
function reasonCounts(records) {
  const counts = new Map();
  for (const record of records) {
    for (const code of record.reasonCodes) {
      counts.set(code, (counts.get(code) || 0) + 1);
    }
  }
  return [...counts.keys()].sort(cmp).map((code) => ({ reasonCode: code, interactionCount: counts.get(code) }));
}

/**
 * @param {InteractionRecord[]} records
 * @returns {{bucketStart: string, counters: Counters}[]}
 */
function timeSeries(records) {
  const buckets = new Map();
  for (const record of records) {
    const start = hourBucket(record.firstOccurredAt);
    if (!buckets.has(start)) buckets.set(start, []);
    buckets.get(start).push(record);
  }
  return [...buckets.keys()].sort(cmp).map((start) => ({ bucketStart: start, counters: counters(buckets.get(start)) }));
}

/**
 * @param {string} occurredAt
 * @returns {string}
 */
function hourBucket(occurredAt) {
  const moment = new Date(occurredAt);
  const year = moment.getUTCFullYear();
  const month = String(moment.getUTCMonth() + 1).padStart(2, "0");
  const day = String(moment.getUTCDate()).padStart(2, "0");
  const hour = String(moment.getUTCHours()).padStart(2, "0");
  return `${year}-${month}-${day}T${hour}:00:00Z`;
}

/**
 * @param {Record<string, any>} event
 * @returns {string}
 */
function eventTime(event) {
  const value = String(event.occurred_at ?? "");
  if (!/(?:Z|[+-]\d{2}:\d{2})$/u.test(value)) throw new Error("event timestamps must carry a UTC offset");
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new Error("event timestamp is invalid");
  return milliseconds;
}

/**
 * @param {unknown} value
 * @returns {boolean}
 */
function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

/**
 * Code-point-ascending comparator, matching Python's default string sort.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
function cmp(a, b) {
  const left = Array.from(String(a), (value) => value.codePointAt(0));
  const right = Array.from(String(b), (value) => value.codePointAt(0));
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return left.length - right.length;
}
