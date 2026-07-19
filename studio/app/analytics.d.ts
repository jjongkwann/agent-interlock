// Type declarations for `./analytics.mjs`. Keep in sync with the JSDoc types
// there and with `src/agent_interlock/analytics.py` (semantic source of truth).

export declare const STATISTICS_API_VERSION: string;
export declare const STATISTICS_KIND: string;

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
  reasonCodes: string[];
  executionAttempted: boolean;
  executionSucceeded: boolean;
  securityOutcome: string;
  firstOccurredAt: string;
  blockDecision: boolean;
  shadowWouldBlock: boolean;
  enforcedBlock: boolean;
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
}

export interface ReasonCodeCount {
  reasonCode: string;
  interactionCount: number;
}

export interface TimeSeriesBucket {
  bucketStart: string;
  counters: Counters;
}

export interface SecurityStatisticsPartition {
  dataSource: string;
  counters: Counters;
  outcomes: Record<string, number>;
  byRelationship: Array<{ relationshipId: string; counters: Counters }>;
  byActor: Array<{ sourceActorId: string; counters: Counters }>;
  byPolicy: Array<{ policyId: string; counters: Counters }>;
  byReasonCode: ReasonCodeCount[];
  timeSeries: TimeSeriesBucket[];
}

export interface SecurityStatistics {
  apiVersion: string;
  kind: string;
  interactionCount: number;
  partitions: SecurityStatisticsPartition[];
}

export declare function reduceInteractions(events: Iterable<Record<string, unknown>>): InteractionRecord[];
export declare function summarizeSecurityStatistics(events: Iterable<Record<string, unknown>>): SecurityStatistics;
