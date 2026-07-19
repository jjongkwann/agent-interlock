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
 * @property {string[]} reasonCodes
 * @property {boolean} executionAttempted
 * @property {boolean} executionSucceeded
 * @property {string} securityOutcome
 * @property {string} firstOccurredAt
 * @property {boolean} blockDecision
 * @property {boolean} shadowWouldBlock
 * @property {boolean} enforcedBlock
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
 */

export const STATISTICS_API_VERSION = "interlock.dev/v1alpha1";
export const STATISTICS_KIND = "SecurityStatistics";

// ALLOW < SANITIZE < HOLD < BLOCK < QUARANTINE < KILL; unknown decision
// strings fail closed to BLOCK (see `_control_decision` in analytics.py).
const DECISION_RANK = { ALLOW: 0, SANITIZE: 1, HOLD: 2, BLOCK: 3, QUARANTINE: 4, KILL: 5 };

/**
 * Join event-envelope objects (the JSON shape of `Event.to_dict()`) by interaction.
 *
 * @param {Iterable<Record<string, any>>} events
 * @returns {InteractionRecord[]}
 */
export function reduceInteractions(events) {
  const grouped = new Map();
  for (const event of events) {
    const interactionId = event.interaction_id;
    if (interactionId) {
      if (!grouped.has(interactionId)) grouped.set(interactionId, []);
      grouped.get(interactionId).push(event);
    }
  }
  const records = [];
  for (const [interactionId, items] of grouped) {
    records.push(reduceOne(interactionId, items));
  }
  records.sort((a, b) => cmp(a.firstOccurredAt, b.firstOccurredAt) || cmp(a.interactionId, b.interactionId));
  return records;
}

/**
 * @param {string} interactionId
 * @param {Record<string, any>[]} events
 * @returns {InteractionRecord}
 */
function reduceOne(interactionId, events) {
  const orderedIndices = events
    .map((_, index) => index)
    .sort((a, b) => cmp(occurredAtKey(events[a]), occurredAtKey(events[b])) || a - b);

  const controls = [];
  let executionAttempted = false;
  let executionSucceeded = false;
  let outcome = "UNKNOWN";

  for (const index of orderedIndices) {
    const event = events[index];
    const eventType = event.event_type;
    const payload = event.payload || {};
    if (eventType === "CONTROL_EVALUATED" && isPlainObject(payload.control)) {
      controls.push(payload.control);
    } else if (eventType === "ACTION_EXECUTED" && payload.connectorExecutionId) {
      executionAttempted = true;
      if (payload.result === "COMPLETED") executionSucceeded = true;
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
    for (const code of control.reasonCodes || []) {
      const value = String(code);
      if (!reasonCodes.includes(value)) reasonCodes.push(value);
    }
  }

  const first = events[orderedIndices[0]];
  const blockDecision = decision !== "ALLOW";
  const actualEnforced = Boolean(chosen.actualEnforced);
  const shadowWouldBlock = blockDecision && !actualEnforced;
  const enforcedBlock = blockDecision && actualEnforced && !executionAttempted;
  const partialOrBypass = outcome === "PARTIALLY_EXECUTED" || (blockDecision && actualEnforced && executionAttempted);

  return {
    interactionId,
    tenantId: String(first.tenant_id ?? ""),
    environment: String(first.environment ?? ""),
    dataSource: String(first.data_source ?? ""),
    sourceActorId: String(first.source_actor_id ?? ""),
    targetActorId: first.target_actor_id ?? null,
    relationshipId: String(first.relationship_id ?? ""),
    policyId: chosen.policyId ?? null,
    mode: chosen.mode ?? null,
    decision,
    actualEnforced,
    reasonCodes,
    executionAttempted,
    executionSucceeded,
    securityOutcome: outcome,
    firstOccurredAt: String(first.occurred_at ?? ""),
    blockDecision,
    shadowWouldBlock,
    enforcedBlock,
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
  const records = reduceInteractions(events);
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
      byReasonCode: reasonCounts(subset),
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
  };
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
function occurredAtKey(event) {
  return String(event.occurred_at ?? "");
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
  return a < b ? -1 : a > b ? 1 : 0;
}
