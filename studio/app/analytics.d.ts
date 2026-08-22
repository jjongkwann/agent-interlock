// Type declarations for `./analytics.mjs`. Keep in sync with the JSDoc types
// there and with `src/agent_interlock/analytics.py` (semantic source of truth).

export declare const STATISTICS_API_VERSION: string;
export declare const STATISTICS_KIND: string;
export declare const COVERAGE_STATES: readonly ["RAN_CLEAN", "RAN_FLAGGED", "INAPPLICABLE", "ABSENT"];

export interface CheckCoverage {
  armed: Set<string>;
  ran: Set<string>;
  flagged: Set<string>;
}

export interface InteractionRecord {
  interactionId: string;
  tenantId: string;
  environment: string;
  dataSource: string;
  sourceActorId: string;
  targetActorId: string | null;
  relationshipId: string;
  policyId: string | null;
  mode: string | null;
  decision: string;
  actualEnforced: boolean;
  executionPermitted: boolean;
  reasonCodes: string[];
  controlEvaluated: boolean;
  coverage: CheckCoverage;
  executionAttempted: boolean;
  executionSucceeded: boolean;
  enforcementActionCompleted: boolean;
  securityOutcome: string;
  firstOccurredAt: string;
  blockDecision: boolean;
  shadowWouldBlock: boolean;
  enforcedBlock: boolean;
  edgeKey: [string, string, string] | null;
  partialOrBypass: boolean;
}

export interface Counters {
  interactionCount: number;
  blockDecisionCount: number;
  shadowWouldBlockCount: number;
  enforcedBlockCount: number;
  executionAttemptCount: number;
  executionSuccessCount: number;
  partialOrBypassCount: number;
  noControlRecordCount: number;
}

export interface ReasonCodeCount {
  reasonCode: string;
  interactionCount: number;
}

export interface TimeSeriesBucket {
  bucketStart: string;
  counters: Counters;
}

export interface CheckCoverageRow {
  checkId: string;
  scope: string;
  ranCleanCount: number;
  ranFlaggedCount: number;
  inapplicableCount: number;
  absentCount: number;
}

export interface EdgeRow {
  sourceActorId: string;
  targetActorId: string;
  policyId: string;
  counters: Counters;
  byCheck: CheckCoverageRow[];
}

export interface SecurityStatisticsPartition {
  dataSource: string;
  counters: Counters;
  outcomes: Record<string, number>;
  byRelationship: Array<{ relationshipId: string; counters: Counters }>;
  byActor: Array<{ sourceActorId: string; counters: Counters }>;
  byPolicy: Array<{ policyId: string; counters: Counters }>;
  byMode: Array<{ mode: string; counters: Counters }>;
  byReasonCode: ReasonCodeCount[];
  byCheck: CheckCoverageRow[];
  byEdge: EdgeRow[];
  unattributed: Counters;
  timeSeries: TimeSeriesBucket[];
}

export interface SecurityStatistics {
  apiVersion: string;
  kind: string;
  interactionCount: number;
  partitions: SecurityStatisticsPartition[];
}

export declare function coverageDeclarations(events: Iterable<Record<string, unknown>>): Map<string, Record<string, unknown>>;
export declare function checkCatalogue(declarations: Map<string, Record<string, unknown>>): Map<string, string>;
export declare function reduceInteractions(events: Iterable<Record<string, unknown>>): InteractionRecord[];
export declare function summarizeSecurityStatistics(events: Iterable<Record<string, unknown>>): SecurityStatistics;
export declare function ledgerEventsForStatistics(value: unknown): Array<Record<string, unknown>> | null;
