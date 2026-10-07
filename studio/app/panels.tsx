"use client";

import { useLanguage } from "./language";
import { message, type Message } from "./i18n";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { compileDraftRequest } from "./deployment.mjs";
import { signApproval } from "./signing.mjs";
import { InputFields, Readiness } from "./builder";
import {HostReadiness} from "./host-readiness";
import {CandidateComparison} from "./comparison";
import { reduceInteractions, summarizeSecurityStatistics } from "./analytics.mjs";
import type { Counters, SecurityStatistics, SecurityStatisticsPartition } from "./analytics";

const COUNTER_LABELS: Array<{ key: keyof Counters; label: string; tone?: "danger" | "warn" | "ok" }> = [
  { key: "interactionCount", label: "Interactions" },
  { key: "blockDecisionCount", label: "Block decisions", tone: "warn" },
  { key: "shadowWouldBlockCount", label: "Shadow would-block", tone: "warn" },
  { key: "enforcedBlockCount", label: "Enforced blocks", tone: "ok" },
  { key: "executionAttemptCount", label: "Execution attempts" },
  { key: "executionSuccessCount", label: "Execution successes" },
  { key: "partialOrBypassCount", label: "Partial / bypass", tone: "danger" },
];

function PartitionView({ partition, onFilter }: { partition: SecurityStatisticsPartition; onFilter: (field: string, value: string) => void }) {
  const { t } = useLanguage();
  return (
    <section className="stats-partition">
      <div className="panel-heading"><span>{t("DATA SOURCE")}</span><strong>{partition.dataSource}</strong></div>
      <div className="stat-grid">
        {COUNTER_LABELS.map(({ key, label, tone }) => (
          <div className={`stat-tile ${tone && partition.counters[key] > 0 ? tone : ""}`} key={key}>
            <strong>{partition.counters[key]}</strong>
            <span>{t(label)}</span>
          </div>
        ))}
      </div>
      <div className="stats-columns">
        <div>
          <h4>{t("Outcomes")}</h4>
          <table className="stats-table"><tbody>
            {Object.entries(partition.outcomes).map(([outcome, count]) => (
              <tr key={outcome}><td><button className="table-link" onClick={() => onFilter("outcome", outcome)}>{t(outcome)}</button></td><td>{count}</td></tr>
            ))}
          </tbody></table>
          <h4>{t("Reason codes")} <small>{t("(one interaction can carry several)")}</small></h4>
          <table className="stats-table"><tbody>
            {partition.byReasonCode.length === 0 && <tr><td colSpan={2}>{t("none")}</td></tr>}
            {partition.byReasonCode.map((item) => (
              <tr key={item.reasonCode}><td><button className="table-link" onClick={() => onFilter("reasonCode", item.reasonCode)}>{item.reasonCode}</button></td><td>{item.interactionCount}</td></tr>
            ))}
          </tbody></table>
        </div>
        <div>
          <h4>{t("By relationship")}</h4>
          <table className="stats-table"><tbody>
            {partition.byRelationship.map((item) => (
              <tr key={item.relationshipId}><td><button className="table-link" onClick={() => onFilter("relationshipId", item.relationshipId)}>{item.relationshipId}</button></td><td>{item.counters.interactionCount} {t("calls")}</td><td>{item.counters.blockDecisionCount} {t("blocked")}</td></tr>
            ))}
          </tbody></table>
          <h4>{t("By source actor")}</h4>
          <table className="stats-table"><tbody>
            {partition.byActor.map((item) => (
              <tr key={item.sourceActorId}><td><button className="table-link" onClick={() => onFilter("sourceActorId", item.sourceActorId)}>{item.sourceActorId}</button></td><td>{item.counters.interactionCount} {t("calls")}</td><td>{item.counters.blockDecisionCount} {t("blocked")}</td></tr>
            ))}
          </tbody></table>
          <h4>{t("By policy")}</h4>
          <table className="stats-table"><tbody>
            {partition.byPolicy.length === 0 && <tr><td colSpan={3}>{t("none")}</td></tr>}
            {partition.byPolicy.map((item) => (
              <tr key={item.policyId}><td><button className="table-link" onClick={() => onFilter("policyId", item.policyId)}>{item.policyId}</button></td><td>{item.counters.interactionCount} {t("calls")}</td><td>{item.counters.blockDecisionCount} {t("blocked")}</td></tr>
            ))}
          </tbody></table>
          <h4>{t("By mode")}</h4>
          <table className="stats-table"><tbody>
            {partition.byMode.length === 0 && <tr><td colSpan={3}>{t("none")}</td></tr>}
            {partition.byMode.map((item) => (
              <tr key={item.mode}><td><button className="table-link" onClick={() => onFilter("mode", item.mode)}>{t(item.mode)}</button></td><td>{item.counters.interactionCount} {t("calls")}</td><td>{item.counters.blockDecisionCount} {t("blocked")}</td></tr>
            ))}
          </tbody></table>
        </div>
      </div>
      <h4>{t("Hourly buckets (UTC)")}</h4>
      <table className="stats-table stats-timeseries"><thead>
        <tr><th>{t("Bucket")}</th><th>{t("Interactions")}</th><th>{t("Block decisions")}</th><th>{t("Enforced")}</th><th>{t("Would-block")}</th><th>{t("Partial/bypass")}</th></tr>
      </thead><tbody>
        {partition.timeSeries.map((bucket) => (
          <tr key={bucket.bucketStart}>
            <td><code>{bucket.bucketStart}</code></td>
            <td>{bucket.counters.interactionCount}</td>
            <td>{bucket.counters.blockDecisionCount}</td>
            <td>{bucket.counters.enforcedBlockCount}</td>
            <td>{bucket.counters.shadowWouldBlockCount}</td>
            <td>{bucket.counters.partialOrBypassCount}</td>
          </tr>
        ))}
      </tbody></table>
    </section>
  );
}

type InvestigationRecord = {
  interactionId: string; traceId?: string; tenantId?: string; dataSource: string;
  sourceActorId: string; targetActorId: string | null; relationshipId: string; policyId: string | null;
  mode: string | null; reasonCodes: string[]; controlEvaluated: boolean; securityOutcome: string;
  firstOccurredAt: string; coverage?: { armed: string[]; ran: string[]; flagged: string[] };
};
const SEARCH_FIELDS = ["sourceActorId", "targetActorId", "traceId", "reasonCode", "outcome", "relationshipId", "policyId", "mode", "dataSource"] as const;
type InvestigationFilters = Record<typeof SEARCH_FIELDS[number], string>;
const FILTER_LABELS: Record<typeof SEARCH_FIELDS[number], string> = { sourceActorId: "Source actor", targetActorId: "Target actor", traceId: "Trace ID", reasonCode: "Reason code", outcome: "Outcome", relationshipId: "Relationship", policyId: "Policy", mode: "Mode", dataSource: "Evidence source" };
function readInvestigationRecords(value: unknown): InvestigationRecord[] {
  if (!Array.isArray(value) || value.some((record) => !record || typeof record !== "object" ||
    ["interactionId", "dataSource", "sourceActorId", "relationshipId", "securityOutcome", "firstOccurredAt"].some((key) => typeof record[key] !== "string") ||
    !Array.isArray(record.reasonCodes) || record.reasonCodes.some((reason: unknown) => typeof reason !== "string") ||
    record.coverage && ["armed", "ran", "flagged"].some((key) => !Array.isArray(record.coverage[key])))) throw new Error("Invalid interaction search response");
  return value as InvestigationRecord[];
}
const emptyFilters: InvestigationFilters = { sourceActorId: "", targetActorId: "", traceId: "", reasonCode: "", outcome: "", relationshipId: "", policyId: "", mode: "", dataSource: "" };
type LocalReview = { status: "unreviewed" | "investigating" | "resolved"; notes: string };

export type LedgerConnection = { apiUrl: string; token: string; tenantId: string; rangeFrom: string; rangeTo: string };

export function StatsPanel({ rawLedgerEvents, importedFormat, notify, onImportTelemetry, initialTraceId, onContext, ledgerConnection, onLedgerConnection }: {
  rawLedgerEvents: Array<Record<string, unknown>> | null; importedFormat: string | null;
  notify: (message: Message) => void; onImportTelemetry: () => void; initialTraceId: string;
  onContext: (patch: LifecycleContext) => void;
  ledgerConnection: LedgerConnection; onLedgerConnection: (patch: Partial<LedgerConnection>) => void;
}) {
  const { t } = useLanguage();
  const [source, setSource] = useState<"offline" | "live">(initialTraceId ? "live" : "offline");
  const { apiUrl, token, tenantId, rangeFrom, rangeTo } = ledgerConnection;
  const [liveStats, setLiveStats] = useState<SecurityStatistics | null>(null);
  const [fetching, setFetching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<InvestigationFilters>({ ...emptyFilters, traceId: initialTraceId });
  const [interactions, setInteractions] = useState<InvestigationRecord[] | null>(null);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [searchScope, setSearchScope] = useState<Message>("");
  const [selectedInteraction, setSelectedInteraction] = useState<InvestigationRecord | null>(null);
  const [traceOnlyId, setTraceOnlyId] = useState("");
  const [traceEvents, setTraceEvents] = useState<Array<Record<string, unknown>>>([]);
  const [traceCursor, setTraceCursor] = useState<string | null>(null);
  const [traceLoaded, setTraceLoaded] = useState(false);
  const [traceBusy, setTraceBusy] = useState(false);
  const [traceError, setTraceError] = useState<string | null>(null);
  const [review, setReview] = useState<LocalReview>({ status: "unreviewed", notes: "" });
  const [reviewMessage, setReviewMessage] = useState("");
  const [reviewKey, setReviewKey] = useState("");
  const searchRequest = useRef(0);
  const traceRequest = useRef(0);
  const resultQuery = useRef<URLSearchParams | null>(null);
  const resultConnection = useRef<{ url: string; token: string; tenant: string } | null>(null);
  const investigator = useRef<HTMLElement>(null);
  useEffect(() => () => { searchRequest.current += 1; traceRequest.current += 1; }, []);
  const offlineResult = useMemo(() => {
    if (!rawLedgerEvents) return { stats: null, records: [] as InvestigationRecord[], error: null };
    try {
      const records = reduceInteractions(rawLedgerEvents).map((record): InvestigationRecord => {
        const traceId = rawLedgerEvents.find((event) => event.interaction_id === record.interactionId)?.trace_id;
        return { ...record, traceId: typeof traceId === "string" ? traceId : undefined, coverage: { armed: [...record.coverage.armed], ran: [...record.coverage.ran], flagged: [...record.coverage.flagged] } };
      });
      return { stats: summarizeSecurityStatistics(rawLedgerEvents) as SecurityStatistics, records, error: null };
    } catch (cause) { return { stats: null, records: [], error: cause instanceof Error ? cause.message : "Invalid Ledger events" }; }
  }, [rawLedgerEvents]);

  async function ledgerCall(path: string, connection = { url: apiUrl, token, tenant: tenantId }): Promise<Record<string, unknown>> {
    const response = await fetch(`${connection.url.replace(/\/$/, "")}${path}`, { headers: { Authorization: `Bearer ${connection.token}`, "X-Interlock-Tenant-Id": connection.tenant } });
    const body = await response.json();
    if (!response.ok) throw new Error(body?.error?.code ?? `HTTP ${response.status}`);
    return body;
  }
  function validateWindow() {
    if (!Number.isFinite(Date.parse(rangeFrom)) || !Number.isFinite(Date.parse(rangeTo)) || Date.parse(rangeFrom) >= Date.parse(rangeTo)) throw new Error("Enter a valid ISO 8601 observation window with From before To");
  }
  function resetInvestigation() {
    searchRequest.current += 1; traceRequest.current += 1;
    setInteractions(null); setNextCursor(null); setSelectedInteraction(null); setTraceOnlyId(""); setSearchScope(""); resultQuery.current = null; resultConnection.current = null;
    setTraceEvents([]); setTraceCursor(null); setTraceLoaded(false); setTraceBusy(false); setFetching(false); setError(null); setLiveStats(null);
  }
  async function fetchLive() {
    const request = ++searchRequest.current;
    setFetching(true); setError(null);
    try {
      validateWindow();
      const body = await ledgerCall(`/v1/statistics?${new URLSearchParams({ from: rangeFrom, to: rangeTo })}`);
      if (request !== searchRequest.current) return;
      setLiveStats(body.statistics as SecurityStatistics);
      onContext({ observation: message("Ledger API · {0} → {1} · aggregate", String(rangeFrom), String(rangeTo)) });
      notify("Live statistics loaded for the selected observation window");
    } catch (cause) { if (request === searchRequest.current) { setLiveStats(null); setError(cause instanceof Error ? cause.message : "Statistics request failed"); } }
    finally { if (request === searchRequest.current) setFetching(false); }
  }
  async function searchInteractions(cursor?: string, appliedFilters = filters) {
    const request = ++searchRequest.current;
    setFetching(true); setError(null);
    if (!cursor) { setInteractions(null); setNextCursor(null); setSelectedInteraction(null); setTraceOnlyId(""); traceRequest.current += 1; setTraceBusy(false); }
    try {
      if (source === "offline") {
        const rows = offlineResult.records.filter((record) => SEARCH_FIELDS.every((key) => {
          const value = appliedFilters[key];
          return !value || (key === "reasonCode" ? record.reasonCodes.includes(value) : key === "outcome" ? record.securityOutcome === value : record[key] === value);
        }));
        setInteractions(rows); setSearchScope(message("Imported {0} · {1} events · {2} matched interactions · {3}", String(importedFormat ?? "Ledger"), String(rawLedgerEvents?.length ?? 0), String(rows.length), String(Object.entries(appliedFilters).filter(([, value]) => value).map(([key, value]) => `${key}=${value}`).join(", ") || "all filters clear")));
        onContext({ observation: message("Imported {0} · {1} events", String(importedFormat), String(rawLedgerEvents?.length ?? 0)) });
        return;
      }
      let query: URLSearchParams;
      if (cursor && resultQuery.current) query = new URLSearchParams(resultQuery.current);
      else {
        validateWindow();
        query = new URLSearchParams({ start: rangeFrom, end: rangeTo, limit: "100" });
        SEARCH_FIELDS.forEach((key) => { if (appliedFilters[key]) query.set(key, appliedFilters[key]); });
        resultQuery.current = query;
        resultConnection.current = { url: apiUrl, token, tenant: tenantId };
      }
      if (cursor) query.set("cursor", cursor);
      const body = await ledgerCall(`/v1/interactions?${query}`, resultConnection.current!);
      if (request !== searchRequest.current) return;
      const rows = readInvestigationRecords(body.interactions);
      setInteractions((previous) => cursor ? [...(previous ?? []), ...rows] : rows);
      setNextCursor(typeof body.nextCursor === "string" ? body.nextCursor : null);
      const observation = body.observation as { eventCount?: number } | undefined;
      const scope = message("Ledger API · {0} → {1} · {2} observed events · {3}", String(query.get("start")), String(query.get("end")), String(observation?.eventCount ?? "—"), String(SEARCH_FIELDS.filter((key) => query.has(key)).map((key) => `${key}=${query.get(key)}`).join(", ") || "all filters clear"));
      setSearchScope(scope); onContext({ observation: scope });
    } catch (cause) { if (request === searchRequest.current) setError(cause instanceof Error ? cause.message : "Interaction search failed"); }
    finally { if (request === searchRequest.current) setFetching(false); }
  }
  async function loadTrace(record: Pick<InvestigationRecord, "traceId">, cursor?: string) {
    const request = ++traceRequest.current;
    setTraceBusy(true); setTraceError(null);
    if (!cursor) { setTraceEvents([]); setTraceCursor(null); setTraceLoaded(false); }
    try {
      if (!record.traceId) throw new Error("This interaction has no trace ID in the available evidence");
      if (source === "offline") {
        setTraceEvents((rawLedgerEvents ?? []).filter((event) => event.trace_id === record.traceId)); setTraceLoaded(true); return;
      }
      const query = new URLSearchParams({ limit: "100" });
      if (cursor) query.set("cursor", cursor);
      const body = await ledgerCall(`/v1/traces/${encodeURIComponent(record.traceId)}?${query}`, resultConnection.current ?? undefined);
      if (request !== traceRequest.current) return;
      if (!Array.isArray(body.events)) throw new Error("Invalid trace response");
      setTraceEvents((previous) => cursor ? [...previous, ...body.events as Array<Record<string, unknown>>] : body.events as Array<Record<string, unknown>>);
      setTraceCursor(typeof body.next_cursor === "string" ? body.next_cursor : null); setTraceLoaded(true);
    } catch (cause) { if (request === traceRequest.current) setTraceError(cause instanceof Error ? cause.message : "Trace request failed"); }
    finally { if (request === traceRequest.current) setTraceBusy(false); }
  }
  function selectInteraction(record: InvestigationRecord) {
    setTraceOnlyId(""); setSelectedInteraction(record); onContext({ trace: record.traceId ?? "Unavailable" });
    const key = `interlock.studio.review.v1:${JSON.stringify([source === "live" ? resultConnection.current?.url : "import", record.tenantId ?? tenantId, record.dataSource, record.interactionId])}`;
    setReviewKey(key); setReview({ status: "unreviewed", notes: "" }); setReviewMessage("");
    try {
      const stored = window.localStorage.getItem(key);
      if (stored) {
        const value = JSON.parse(stored);
        if (!["unreviewed", "investigating", "resolved"].includes(value.status) || typeof value.notes !== "string") throw new Error("Invalid stored review");
        setReview(value);
      }
    } catch { setReviewMessage("Local review could not be read. Existing stored notes have not been changed."); }
    void loadTrace(record);
  }
  function openTrace() {
    if (!filters.traceId.trim()) return;
    setSelectedInteraction(null); setTraceOnlyId(filters.traceId.trim());
    resultConnection.current = { url: apiUrl, token, tenant: tenantId };
    onContext({ trace: filters.traceId.trim() });
    void loadTrace({ traceId: filters.traceId.trim() });
  }
  function saveReview() {
    try { window.localStorage.setItem(reviewKey, JSON.stringify(review)); setReviewMessage("Saved in this browser only. Ledger evidence is unchanged."); }
    catch { setReviewMessage("Save failed: browser storage is unavailable or full. Copy your notes before leaving."); }
  }
  function filterFromSummary(field: string, value: string, dataSource: string) {
    const next = { ...emptyFilters, dataSource, [field]: value };
    setFilters(next); investigator.current?.scrollIntoView({ block: "start", behavior: "smooth" });
    void searchInteractions(undefined, next);
  }
  const importedWindow = useMemo(() => {
    const times = (rawLedgerEvents ?? []).reduce<[number, number]>((range, event) => {
      const time = typeof event.occurred_at === "string" ? Date.parse(event.occurred_at) : NaN;
      return Number.isFinite(time) ? [Math.min(range[0], time), Math.max(range[1], time)] : range;
    }, [Infinity, -Infinity]);
    return Number.isFinite(times[0]) ? `${new Date(times[0]).toISOString()} → ${new Date(times[1]).toISOString()}` : "No dated events";
  }, [rawLedgerEvents]);
  const stats = source === "live" ? liveStats : offlineResult.stats;
  return <div className="stats-panel">
    <div className="stats-source-row"><div className="graph-tabs"><button aria-pressed={source === "offline"} className={source === "offline" ? "active" : ""} onClick={() => { resetInvestigation(); setSource("offline"); }}>{t("Imported telemetry")}</button><button aria-pressed={source === "live"} className={source === "live" ? "active" : ""} onClick={() => { resetInvestigation(); setSource("live"); }}>{t("Live API")}</button></div></div>
    {source === "live" && <div className="live-controls live-control-grid">
      <label>{t("Ledger API URL")}<input value={apiUrl} onChange={(event) => { resetInvestigation(); onLedgerConnection({ apiUrl: event.target.value }); }} /></label>
      <label>{t("Bearer token")}<input type="password" value={token} onChange={(event) => { resetInvestigation(); onLedgerConnection({ token: event.target.value }); }} placeholder="statistics:read and events:read" /></label>
      <label>{t("Tenant")}<input value={tenantId} onChange={(event) => { resetInvestigation(); onLedgerConnection({ tenantId: event.target.value }); }} /></label>
      <label>{t("From · ISO 8601")}<input value={rangeFrom} onChange={(event) => { resetInvestigation(); onLedgerConnection({ rangeFrom: event.target.value }); }} /></label>
      <label>{t("To · ISO 8601")}<input value={rangeTo} onChange={(event) => { resetInvestigation(); onLedgerConnection({ rangeTo: event.target.value }); }} /></label>
      <button className="primary-button" disabled={fetching || !token || !tenantId} onClick={fetchLive}>{fetching ? t("Loading…") : t("Fetch statistics")}</button>
    </div>}
    <p className="panel-note">{source === "live" ? t("statistics:read loads aggregates; events:read searches interactions and trace evidence. The time window selects interactions by their first event; completed outcomes may arrive later.") : t(message("Source: {0} · {1} events · {2}. Imported evidence is limited to this file; integrity hashes are not verified in the browser.", importedFormat ?? t("No import"), String(rawLedgerEvents?.length ?? 0), t(importedWindow)))} {t("Observed control coverage describes evaluated checks, not proof that all intended controls ran.")}</p>
    {(error || offlineResult.error && source === "offline") && <p className="connection-status error" role="alert">{t(error ?? offlineResult.error)}</p>}
    {!stats && <div className="runtime-empty-note">{source === "live" ? t("No aggregate loaded. Connect and fetch statistics, or search interactions below.") : t("Import raw Ledger events to view statistics and investigate interactions.")}{source === "offline" && <button className="secondary-button" onClick={onImportTelemetry}>{t("Import Ledger telemetry")}</button>}</div>}
    <section className="investigation-panel" ref={investigator} aria-label={t("Interaction investigation")}>
      <h3>{t("Investigate interactions")}</h3><p className="panel-note">{t("Filters match exact IDs or values. Choose an interaction to inspect its trace and keep local investigation notes.")}</p>
      <div className="investigation-filters">{SEARCH_FIELDS.slice(0, 3).map((key) => <label key={key}>{t(FILTER_LABELS[key])}<input value={filters[key]} onChange={(event) => setFilters((current) => ({ ...current, [key]: event.target.value }))} /></label>)}</div><details className="advanced-filters"><summary>{t("More filters")}</summary><div className="investigation-filters">{SEARCH_FIELDS.slice(3).map((key) => <label key={key}>{t(FILTER_LABELS[key])}<input value={filters[key]} onChange={(event) => setFilters((current) => ({ ...current, [key]: event.target.value }))} /></label>)}</div></details>
      <div className="run-actions"><button className="primary-button" disabled={fetching || source === "live" && (!token || !tenantId)} onClick={() => void searchInteractions()}>{t("Search interactions")}</button><button className="secondary-button" disabled={!filters.traceId.trim() || traceBusy || source === "live" && (!token || !tenantId)} onClick={openTrace}>{t("Open trace evidence")}</button><button className="secondary-button" onClick={() => setFilters(emptyFilters)}>{t("Clear filters")}</button></div>
      {searchScope && <p className="panel-note">{t(searchScope)}. {interactions?.length ?? 0} {t("loaded")}{nextCursor ? t(" · more results available") : t(" · result set complete")}.</p>}
      {interactions?.length === 0 && <p>{t("No matching interactions in the available evidence.")}</p>}
      {interactions && interactions.length > 0 && <div className="interaction-list">{interactions.map((record) => <button key={record.interactionId} aria-pressed={selectedInteraction?.interactionId === record.interactionId} className="interaction-row" onClick={() => selectInteraction(record)}><strong>{record.sourceActorId} → {record.targetActorId ?? t("Unknown target")}</strong><span>{record.interactionId} · {t(record.securityOutcome)} · {record.mode ?? t("Unknown mode")}</span><small>{record.firstOccurredAt} · {record.dataSource} · {record.controlEvaluated ? t("Control evaluated") : t("No control evaluation evidence")}</small></button>)}</div>}
      {nextCursor && <button className="secondary-button" disabled={fetching} onClick={() => void searchInteractions(nextCursor)}>{t("Load more interactions")}</button>}
      {(selectedInteraction || traceOnlyId) && <article className="interaction-detail"><h4>{t("Trace:")} {selectedInteraction?.traceId ?? traceOnlyId}</h4>{selectedInteraction && <><p>{selectedInteraction.relationshipId} · {selectedInteraction.policyId ?? t("No policy ID")} · {selectedInteraction.reasonCodes.join(", ") || t("No reason codes")}</p><p className="panel-note">{t("Observed checks:")} {selectedInteraction.coverage?.ran.length ?? 0} {t("ran,")} {selectedInteraction.coverage?.flagged.length ?? 0} {t("flagged,")} {selectedInteraction.coverage?.armed.length ?? 0} {t("armed. Missing evidence is not a clean result.")}</p></>}
        {traceError && <p role="alert" className="connection-status error">{t(traceError)}</p>}<p>{traceBusy ? t("Loading trace evidence…") : traceLoaded ? t(message("{0} events loaded{1}", String(traceEvents.length), t(traceCursor ? " · incomplete, load the next page" : source === "offline" ? " · imported file only" : " · all available trace pages loaded"))) : t("Trace evidence not loaded")}</p>
        <div className="trace-events">{traceEvents.map((event, index) => <details key={String(event.id ?? event.event_id ?? index)}><summary>{String(event.occurred_at ?? t("Unknown time"))} · {String(event.event_type ?? t("Unknown event"))}</summary><pre>{JSON.stringify(event, null, 2)}</pre></details>)}</div>
        <button className="secondary-button" disabled={traceBusy || !(selectedInteraction?.traceId ?? traceOnlyId)} onClick={() => void loadTrace({ traceId: selectedInteraction?.traceId ?? traceOnlyId }, traceCursor ?? undefined)}>{traceCursor ? t("Load more trace events") : t("Refresh trace")}</button>
        {selectedInteraction && <div className="local-review"><h4>{t("Local investigation · this browser only")}</h4><label>{t("Status")}<select value={review.status} onChange={(event) => setReview((current) => ({ ...current, status: event.target.value as LocalReview["status"] }))}><option value="unreviewed">{t("Unreviewed")}</option><option value="investigating">{t("Investigating")}</option><option value="resolved">{t("Resolved locally")}</option></select></label><label>{t("Reviewer notes")}<textarea value={review.notes} onChange={(event) => setReview((current) => ({ ...current, notes: event.target.value }))} /></label><button className="secondary-button" onClick={saveReview}>{t("Save local review")}</button><p className="panel-note" role="status">{t(reviewMessage) || t("These notes are not shared, sent to the server, or an operational approval.")}</p></div>}
      </article>}
    </section>
    {stats?.partitions.length === 0 && <p>{t("No interaction lifecycles in the aggregate.")}</p>}
    {stats?.partitions.map((partition) => <PartitionView key={partition.dataSource} partition={partition} onFilter={(field, value) => filterFromSummary(field, value, partition.dataSource)} />)}
  </div>;
}

type BundleFile = {
  architectureId: string;
  version: string;
  bundleDigest: string;
  deployable: boolean;
  rawText: string;
};

type RunTask = {
  pendingCall?: {requestId: string; [key: string]: unknown} | null;
  taskId: string;
  state: string;
  attempts: number;
  output?: Record<string, unknown>;
  errorCode?: string | null;
  errorMessage?: string | null;
  externalTaskId?: string | null;
  executed?: boolean;
  goalMet?: boolean | null;
  securityMet?: boolean | null;
};

type RunOutcomes = { executed: number; goalMet: number; securityMet: number; total: number };

type WorkflowRun = {
  input?: Record<string, unknown>;
  id: string;
  architectureId: string;
  architectureVersion: string;
  traceId: string;
  state: string;
  tasks: Record<string, RunTask>;
  createdAt: string;
  updatedAt: string;
  messagesUsed: number;
  errorCode?: string | null;
  bundleDigest: string;
  outcomes?: RunOutcomes;
};

const OUTCOME_COLORS: Record<"yes" | "no" | "unknown", string> = {
  yes: "#1a7f37",
  no: "#c62828",
  unknown: "#8a8f98",
};

function outcomeState(value: boolean | null | undefined): "yes" | "no" | "unknown" {
  if (value === true) return "yes";
  if (value === false) return "no";
  return "unknown";
}

function OutcomeBadge({ label, value }: { label: string; value: boolean | null | undefined }) {
  const { t } = useLanguage();
  const state = outcomeState(value);
  return (
    <span
      className={`outcome-badge outcome-${state}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "0.3em",
        padding: "0.05em 0.5em",
        borderRadius: "999px",
        border: `1px solid ${OUTCOME_COLORS[state]}`,
        color: OUTCOME_COLORS[state],
        fontSize: "0.78em",
        fontWeight: 600,
      }}
    >
     {t(label)} · {t(state)}
    </span>
  );
}

type RunEvent = {
  [key: string]: unknown;
  event_type?: string;
  occurred_at?: string;
  payload?: Record<string, unknown>;
};

const TERMINAL_RUN_STATES = new Set(["COMPLETED", "FAILED", "CANCELED"]);

export type LifecycleContext = { bundle?: Message; activeDeployment?: Message; run?: Message; trace?: Message; observation?: Message };

type ControlPlaneConnectionProps = {
  onContext: (patch: LifecycleContext) => void;
  apiUrl: string;
  token: string;
  onApiUrlChange: (value: string) => void;
  onTokenChange: (value: string) => void;
};

function readRun(value: unknown): WorkflowRun | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const run = value as Partial<WorkflowRun>;
  if (typeof run.id !== "string" || typeof run.state !== "string" || !run.tasks || typeof run.tasks !== "object") return null;
  return run as WorkflowRun;
}

export function RunsPanel({
  notify,
  apiUrl,
  token,
  onApiUrlChange,
  onTokenChange,
  onOpenRuntimeTelemetry,
  onOpenStatisticsTrace,
  onContext,
}: {
  notify: (message: Message) => void;
  onOpenStatisticsTrace: (traceId: string, createdAt: string) => void;
  onOpenRuntimeTelemetry: (events: Array<Record<string, unknown>>, source: string) => void;
} & ControlPlaneConnectionProps) {
  const { t } = useLanguage();
  const [inputText, setInputText] = useState("{}");
  const [inputSchema, setInputSchema] = useState<Record<string, unknown>>();
  const [runReadiness, setRunReadiness] = useState<{ready?: boolean | null; hostConfigured?: boolean} | null>(null);
  const [runs, setRuns] = useState<WorkflowRun[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedRun, setSelectedRun] = useState<WorkflowRun | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [busy, setBusy] = useState(false);
  const connectionKey = `${apiUrl}\n${token}`;
  const [connection, setConnection] = useState<{ key: string; state: "loading" | "connected" | "error"; active: Record<string, unknown> | null; error: Message | null } | null>(null);
  const [operationError, setOperationError] = useState<Message | null>(null);
  const connectionState = connection?.key === connectionKey ? connection.state : "disconnected";
  const activeDeployment = connectionState === "connected" ? connection?.active : null;
  const canStart = connectionState === "connected" && activeDeployment?.mode === "ENFORCE" && (runReadiness?.ready === true || runReadiness?.hostConfigured === false);
  const shouldAutoLoad = useRef(Boolean(token));
  const autoLoadStarted = useRef(false);

  const call = useCallback(async (path: string, init?: RequestInit): Promise<Record<string, unknown>> => {
    const response = await fetch(`${apiUrl.replace(/\/$/, "")}${path}`, {
      ...init,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(init?.body ? { "Content-Type": "application/json" } : {}),
        ...init?.headers,
      },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = body as { error?: { code?: string; message?: string } };
      throw new Error(error.error?.code ?? error.error?.message ?? `HTTP ${response.status}`);
    }
    return body as Record<string, unknown>;
  }, [apiUrl, token]);

  const loadRun = useCallback(async (runId: string, announce = false) => {
    try {
      const [runBody, eventBody] = await Promise.all([
        call(`/v1/runs/${encodeURIComponent(runId)}`),
        call(`/v1/runs/${encodeURIComponent(runId)}/events`),
      ]);
      const run = readRun(runBody.run);
      if (!run) throw new Error("RUN-RESPONSE-INVALID");
      setSelectedRun(run);
      onContext({ run: `${run.id} · ${run.architectureId} v${run.architectureVersion}`, trace: run.traceId });
      setRuns((items) => items.map((item) => item.id === run.id ? run : item));
      setEvents(Array.isArray(eventBody.events) ? eventBody.events as RunEvent[] : []);
      if (announce) notify(message("Run refreshed · {0}", String(run.state)));
    } catch (error) {
      setOperationError(message("Run refresh failed · {0}", String(error instanceof Error ? error.message : "request error")));
      if (announce) notify(message("Run refresh failed · {0}", String(error instanceof Error ? error.message : "request error")));
    }
  }, [call, notify, onContext]);

  const refreshRuns = useCallback(async (announce = true) => {
    setBusy(true);
    setOperationError(null);
    setConnection({ key: connectionKey, state: "loading", active: null, error: null });
    try {
      const [body, deployment] = await Promise.all([call("/v1/runs"), call("/v1/runtime/status")]);
      const readiness = deployment.runtimeReadiness as Record<string, unknown> | undefined;
      setInputSchema(readiness?.runInputSchema as Record<string, unknown> | undefined);
      setRunReadiness(readiness ?? null);
      setConnection({ key: connectionKey, state: "connected", active: deployment.active as Record<string, unknown> | null, error: null });
      onContext({ activeDeployment: deployment.active ? String((deployment.active as Record<string, unknown>).bundleDigest) : "None" });
      const nextRuns = (Array.isArray(body.runs) ? body.runs : []).map(readRun).filter((item): item is WorkflowRun => Boolean(item));
      setRuns(nextRuns);
      const nextId = selectedRunId && nextRuns.some((run) => run.id === selectedRunId) ? selectedRunId : nextRuns[0]?.id ?? null;
      setSelectedRunId(nextId);
      setSelectedRun(nextId ? nextRuns.find((run) => run.id === nextId) ?? null : null);
      if (nextId) await loadRun(nextId);
      else setEvents([]);
      if (announce) notify(message("Runs refreshed · {0} visible", String(nextRuns.length)));
    } catch (error) {
      const failure = message("Runs failed · {0}", String(error instanceof Error ? error.message : "request error"));
      setConnection({ key: connectionKey, state: "error", active: null, error: failure });
      if (announce) notify(failure);
    } finally {
      setBusy(false);
    }
  }, [call, connectionKey, loadRun, notify, onContext, selectedRunId]);

  useEffect(() => {
    if (!shouldAutoLoad.current || autoLoadStarted.current) return;
    autoLoadStarted.current = true;
    void refreshRuns(false);
  }, [refreshRuns]);

  useEffect(() => {
    if (connectionState !== "connected" || !selectedRunId || (selectedRun && TERMINAL_RUN_STATES.has(selectedRun.state))) return;
    const timer = window.setInterval(() => { void loadRun(selectedRunId); }, 1500);
    return () => window.clearInterval(timer);
  }, [connectionState, loadRun, selectedRun, selectedRunId]);

  async function startRun() {
    if (!canStart) return;
    setOperationError(null);
    setBusy(true);
    try {
      const input = JSON.parse(inputText);
      if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Input must be a JSON object");
      const body = await call("/v1/runs", { method: "POST", body: JSON.stringify({ input }) });
      const run = readRun(body.run);
      if (!run) throw new Error("RUN-RESPONSE-INVALID");
      setRuns((items) => [run, ...items.filter((item) => item.id !== run.id)]);
      setSelectedRunId(run.id);
      setSelectedRun(run);
      onContext({ run: `${run.id} · ${run.architectureId} v${run.architectureVersion}`, trace: run.traceId });
      setEvents([]);
      notify(message("Run started · {0}", String(run.id)));
    } catch (error) {
      setOperationError(message("Start failed · {0}", String(error instanceof Error ? error.message : "request error")));
      notify(message("Start failed · {0}", String(error instanceof Error ? error.message : "request error")));
    } finally {
      setBusy(false);
    }
  }

  async function runCommand(path: string, success: Message) {
    if (!selectedRunId) return;
    setBusy(true);
    try {
      const body = await call(`/v1/runs/${encodeURIComponent(selectedRunId)}${path}`, { method: "POST", body: "{}" });
      const run = readRun(body.run);
      if (run) setSelectedRun(run);
      notify(success);
      await loadRun(selectedRunId);
    } catch (error) {
      setOperationError(message("Run command failed · {0}", String(error instanceof Error ? error.message : "request error")));
      notify(message("Run command failed · {0}", String(error instanceof Error ? error.message : "request error")));
    } finally {
      setBusy(false);
    }
  }

  async function approveTask(taskId: string, requestId?: string) {
    if (!selectedRunId) return;
    setBusy(true);
    try {
      await call(`/v1/runs/${encodeURIComponent(selectedRunId)}/tasks/${encodeURIComponent(taskId)}/approve`, { method: "POST", body: JSON.stringify(requestId ? {requestId} : {}) });
      notify(message("Approval submitted · {0}", String(taskId)));
      await loadRun(selectedRunId);
    } catch (error) {
      setOperationError(message("Approval failed · {0}", String(error instanceof Error ? error.message : "request error")));
      notify(message("Approval failed · {0}", String(error instanceof Error ? error.message : "request error")));
    } finally {
      setBusy(false);
    }
  }

  const selectedTasks = selectedRun ? Object.entries(selectedRun.tasks) : [];
  const terminal = selectedRun ? TERMINAL_RUN_STATES.has(selectedRun.state) : false;
  return (
    <div className="stats-panel runs-panel">
      <div className="deploy-header">
        <div className="panel-heading"><span>{t("RUN")}</span><strong>{t("Deployment-bound workflow runs")}</strong></div>
        <p className="panel-note">{t("A run uses the exact architecture in the active ENFORCE bundle. The host must provide every A2A, MCP, Local, or Human transport adapter; missing adapters fail closed.")}</p>
      </div>

      <div className="control-plane-card runs-connection">
        <div><strong>{t("Run Control")}</strong><span>{t("Bearer credentials stay in this browser session only.")}</span></div>
        <div className="live-controls live-control-grid compact">
          <label><span>{t("Control plane URL")}</span><input value={apiUrl} onChange={(event) => onApiUrlChange(event.target.value)} placeholder="http://127.0.0.1:8792" /></label>
          <label><span>{t("Bearer token")}</span><input value={token} onChange={(event) => onTokenChange(event.target.value)} placeholder="run:read, run:create, deploy:read" type="password" /></label>
          <button className="secondary-button" disabled={busy || !token.trim() || !apiUrl.trim()} onClick={() => void refreshRuns()}>{busy ? t("Working…") : t("Refresh runs")}</button>
        </div>
      </div>

      <div className={`connection-status ${connectionState}`} role="status"><strong>{connectionState === "disconnected" ? t("Not connected") : connectionState === "loading" ? t("Checking runs and active deployment…") : connectionState === "error" ? t("Connection failed") : t("Connected")}</strong><span>{connectionState === "error" ? t(connection?.error) : activeDeployment ? t(message("Active: {0} · {1}", String(activeDeployment.mode), String(activeDeployment.bundleDigest))) : connectionState === "connected" ? t("No active deployment. Promote an approved bundle in Deploy.") : t("Ask the control-plane administrator for a tenant-bound token with run:read, run:create, and deploy:read. Task approvals need run:approve; cancellation needs run:cancel. Then refresh.")}</span></div>
      {operationError && <p className="connection-status error" role="alert">{t(operationError)}</p>}
      <Readiness value={connectionState === "connected" ? runReadiness : null}/>
      <section className="run-start-card">
        <div><strong>{t("Start from active deployment")}</strong><span>{t("Input is sent to the deployed workflow coordinator. Run and trace IDs are generated server-side.")}</span></div>
        <InputFields schema={inputSchema} text={inputText} onChange={setInputText}/><label className="deploy-field"><span>{t("Workflow input · advanced JSON object")}</span><textarea className="run-input" value={inputText} onChange={(event) => setInputText(event.target.value)} spellCheck={false} /></label>
        <button className="primary-button run-start-button" disabled={busy || !canStart || !inputText.trim()} onClick={() => void startRun()}>{t("Start run")}</button>
      </section>

      <div className="runs-layout">
        <section className="run-list-card">
          <div className="run-section-heading"><div><strong>{t("Runs")}</strong><span>{connectionState === "connected" ? runs.length : "—"} {t("visible to this tenant")}</span></div></div>
          <div className="run-list">
            {runs.length === 0 && <div className="run-empty">{t("Connect and refresh to inspect tenant-scoped runs.")}</div>}
            {(connectionState === "connected" ? runs : []).map((run) => <button key={run.id} className={selectedRunId === run.id ? "active" : ""} onClick={() => { setSelectedRunId(run.id); setSelectedRun(run); void loadRun(run.id); }}><span><strong>{run.id}</strong><small>{run.architectureId} · v{run.architectureVersion}</small></span><i className={`run-state state-${run.state.toLowerCase()}`}>{t(run.state).replaceAll("_", " ")}</i></button>)}
          </div>
        </section>

        <section className="run-detail-card">
          {!selectedRun && <div className="run-empty detail">{t("Select a run to inspect task state, approvals, and ledger evidence.")}</div>}
          {connectionState === "connected" && selectedRun && <>
            <div className="run-detail-header">
              <div><span>{t("RUN")}</span><strong>{selectedRun.id}</strong><small><code>{selectedRun.bundleDigest}</code></small></div>
              <i className={`run-state state-${selectedRun.state.toLowerCase()}`}>{t(selectedRun.state).replaceAll("_", " ")}</i>
            </div>
            <div className="run-meta"><span><b>{t("Trace")}</b><code>{selectedRun.traceId}</code></span><span><b>{t("Messages")}</b>{selectedRun.messagesUsed}</span><span><b>{t("Updated")}</b>{selectedRun.updatedAt}</span>{selectedRun.errorCode && <span className="run-error"><b>{t("Error")}</b>{selectedRun.errorCode}</span>}</div>
            {selectedRun.errorCode === "RUN-EFFECT-UNCERTAIN" && <p role="status">{t("Execution server contact was lost after execution started. External actions may have completed. Check the destination before creating another run; this run will not be replayed automatically.")}</p>}
            {selectedRun.outcomes && <div className="run-meta run-outcomes-summary">
              <span><b>{t("Executed")}</b>{selectedRun.outcomes.executed}/{selectedRun.outcomes.total}</span>
              <span><b>{t("Goal met")}</b>{selectedRun.outcomes.goalMet}/{selectedRun.outcomes.total}</span>
              <span><b>{t("Security met")}</b>{selectedRun.outcomes.securityMet}/{selectedRun.outcomes.total}</span>
            </div>}
            <details open><summary>{t("Submitted workflow input")}</summary><pre>{JSON.stringify(selectedRun.input ?? {}, null, 2)}</pre></details>
            <div className="run-actions">
              <button className="secondary-button" disabled={busy} onClick={() => void loadRun(selectedRun.id, true)}>{t("Refresh")}</button>
              <button className="primary-button" disabled={busy || events.length === 0} onClick={() => onOpenRuntimeTelemetry(events, `Run ${selectedRun.id}`)}>{t("Open runtime graph")}</button>
              <button className="secondary-button" onClick={() => onOpenStatisticsTrace(selectedRun.traceId, selectedRun.createdAt)}>{t("Investigate trace")}</button>
              <button className="secondary-button" disabled={busy || terminal} onClick={() => void runCommand("/resume", "Resume requested")}>{t("Resume")}</button>
              <button className="danger-button" disabled={busy || terminal} onClick={() => void runCommand("/cancel", "Run canceled")}>{t("Cancel")}</button>
            </div>
            <div className="run-section-heading"><div><strong>{t("Tasks")}</strong><span>{selectedTasks.length} {t("deployment tasks")}</span></div></div>
            <div className="run-task-list">
              {selectedTasks.map(([taskId, task]) => <article className="run-task" key={taskId}>
                <div><span><strong>{taskId}</strong><small>{t(message("{0} attempt{1}", task.attempts, task.attempts === 1 ? "" : "s"))}{task.externalTaskId ? ` · ${task.externalTaskId}` : ""}</small></span><i className={`run-state state-${task.state.toLowerCase()}`}>{t(task.state).replaceAll("_", " ")}</i></div>
                <div className="run-task-outcomes" style={{ display: "flex", gap: "0.4em", flexWrap: "wrap", margin: "0.35em 0" }}>
                  <OutcomeBadge label={t("Executed")} value={task.executed ?? false} />
                  <OutcomeBadge label={t("Goal")} value={task.goalMet ?? null} />
                  <OutcomeBadge label={t("Security")} value={task.securityMet ?? null} />
                </div>
                {(task.errorCode || task.errorMessage) && <p className="run-task-error">{task.errorCode}{task.errorMessage ? ` · ${task.errorMessage}` : ""}</p>}
                {task.output && Object.keys(task.output).length > 0 && <pre><code>{JSON.stringify(task.output, null, 2)}</code></pre>}
                {task.pendingCall && <div className="pending-call"><strong>{t("Exact proposed tool call")}</strong><pre>{JSON.stringify(task.pendingCall, null, 2)}</pre><small>{t("Approval applies only to this request ID and arguments. Changed proposals require a new review.")}</small></div>}
                {task.state === "WAITING_APPROVAL" && <button className="primary-button approve-task" disabled={busy} onClick={() => void approveTask(taskId, task.pendingCall?.requestId)}>{t("Approve reviewed task")}</button>}
              </article>)}
            </div>
            <div className="run-section-heading events-heading"><div><strong>{t("Ledger evidence")}</strong><span>{events.length} {t("trace events")}</span></div></div>
            <div className="run-events">
              {events.length === 0 && <div className="run-empty">{t("No events returned for this trace.")}</div>}
              {[...events].reverse().slice(0, 30).map((event, index) => <div key={`${event.occurred_at ?? "event"}-${index}`}><span>{event.occurred_at ?? "—"}</span><strong>{event.event_type ?? "UNKNOWN_EVENT"}</strong>{Boolean(event.payload?.reason_code) && <code>{String(event.payload?.reason_code)}</code>}</div>)}
            </div>
          </>}
        </section>
      </div>
    </div>
  );
}

export function DeployPanel({
  notify,
  onContext,
  draftProject,
  rawArchitecture,
  onBackToDesign,
  apiUrl,
  token,
  onApiUrlChange,
  onTokenChange,
}: {
  notify: (message: Message) => void;
  onBackToDesign: () => void;
  draftProject: { id: string; version: string };
  rawArchitecture: string;
} & ControlPlaneConnectionProps) {
  const { t } = useLanguage();
  const [active, setActive] = useState<Record<string, unknown> | null>(null);
  const [history, setHistory] = useState<string[]>([]);
  const [bundle, setBundle] = useState<BundleFile | null>(null);
  const requiredRefs = useMemo(() => {
    try {
      const manifest = bundle ? JSON.parse(bundle.rawText).architecture : JSON.parse(rawArchitecture);
      return [...new Set((manifest?.nodes ?? []).map((node: {annotations?:Record<string,unknown>}) =>
        (node.annotations?.["interlock.runtime"] as Record<string,unknown> | undefined)?.credentialRef)
        .filter((ref:unknown):ref is string=>typeof ref === "string" && Boolean(ref)))] as string[];
    } catch {return [];}
  },[rawArchitecture,bundle]);
  const [approvalText, setApprovalText] = useState("");
  const [hostStatus, setHostStatus] = useState<Record<string, unknown> | null>(null);
  const [readiness, setReadiness] = useState<unknown>(null);
  const [approvalContext, setApprovalContext] = useState<{statement: Record<string, unknown>; trustedApprovers: Array<{approverId:string;keyId:string;publicKeyHex:string}>} | null>(null);
  const [approverKeyId, setApproverKeyId] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [signingBusy, setSigningBusy] = useState(false);
  const [pendingApprovals, setPendingApprovals] = useState<number>(0);
  const bundleInput = useRef<HTMLInputElement>(null);
  const [statusMessage, setStatusMessage] = useState<Message>("Not connected · refresh to inspect the active deployment");
  const [statusChecked, setStatusChecked] = useState(false);
  const [statusLoading, setStatusLoading] = useState(false);
  const [diff, setDiff] = useState<{ baseDigest: string | null; bundleDigest: string; changes: Array<{ path: string; before: unknown; after: unknown }>; changeCount: number } | null>(null);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const deploymentRequest = useRef(0);
  useEffect(() => () => { deploymentRequest.current += 1; }, []);
  function invalidateConnection() { setApproverKeyId(""); setBundle(null); setReadiness(null); setPendingApprovals(0); setHistory([]); setApprovalContext(null); setReviewed(false); setApprovalText(""); setHostStatus(null); deploymentRequest.current += 1; setDiff(null); setStatusLoading(false); setDiffLoading(false); setStatusChecked(false); setActive(null); onContext({ activeDeployment: "Connection changed · not checked" }); }
  async function refreshDiff(digest: string, baseDigest: string | null, request = deploymentRequest.current) {
    setDiff(null); setDiffError(null); setDiffLoading(true); setApprovalContext(null); setReviewed(false); setApprovalText("");
    try {
      const body = await call(`/v1/bundles/${encodeURIComponent(digest)}/diff`);
      if (request !== deploymentRequest.current) return;
      if (body.baseDigest !== baseDigest || body.bundleDigest !== digest || !Array.isArray(body.changes)) throw new Error("Deployment changed during comparison. Refresh status before signing.");
      const context = await call(`/v1/bundles/${encodeURIComponent(digest)}/approval-context`);
      if (request !== deploymentRequest.current) return;
      const statement = context.statement as Record<string, unknown>;
      if (statement.bundleDigest !== digest || statement.fromDigest !== baseDigest) throw new Error("Approval context changed. Refresh comparison.");
      setApprovalContext(context as NonNullable<typeof approvalContext>);
      setDiff(body as NonNullable<typeof diff>);
    } catch (error) { if (request === deploymentRequest.current) setDiffError(error instanceof Error ? error.message : "Policy comparison failed"); }
    finally { if (request === deploymentRequest.current) setDiffLoading(false); }
  }
  function report(message: Message) { setStatusMessage(message); notify(message); }

  async function call(path: string, init?: RequestInit): Promise<Record<string, unknown>> {
    const request = deploymentRequest.current;
    const response = await fetch(`${apiUrl.replace(/\/$/, "")}${path}`, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, ...(init?.body ? { "Content-Type": "application/json" } : {}), ...init?.headers },
    });
    const body = await response.json().catch(() => ({}));
    if (request !== deploymentRequest.current) throw new Error("Deployment context changed; retry in the current connection");
    if (!response.ok) throw new Error([body?.error?.code, body?.error?.message].filter(Boolean).join(": ") || `HTTP ${response.status}`);
    return body as Record<string, unknown>;
  }

  async function refreshStatus() {
    const request = ++deploymentRequest.current;
    setStatusLoading(true);
    setStatusChecked(false);
    setDiff(null);
    try {
      const [body, host] = await Promise.all([call("/v1/deploy/status"), call("/v1/runtime/status")]);
      if (request === deploymentRequest.current) setHostStatus(host);
      if (request !== deploymentRequest.current) return;
      setActive((body.active as Record<string, unknown>) ?? null);
      onContext({ activeDeployment: body.active ? String((body.active as Record<string, unknown>).bundleDigest) : "None" });
      setHistory((body.history as string[]) ?? []);
      setStatusChecked(true);
      report("Deployment status refreshed");
      if (bundle) await refreshDiff(bundle.bundleDigest, (body.active as Record<string, unknown> | null)?.bundleDigest as string ?? null, request);
    } catch (error) {
      if (request !== deploymentRequest.current) return;
      report(message("Status failed · {0}", String(error instanceof Error ? error.message : "request error")));
    } finally { if (request === deploymentRequest.current) setStatusLoading(false); }
  }

  async function importBundle(file: File) {
    const request = ++deploymentRequest.current; setReadiness(null); setDiff(null); setDiffError(null); setDiffLoading(false); setStatusLoading(false); setApprovalText("");
    try {
      const rawText = await file.text();
      if (request !== deploymentRequest.current) return;
      const value = JSON.parse(rawText);
      if (typeof value.bundleDigest !== "string" || !/^sha256:[a-f0-9]{64}$/.test(value.bundleDigest) || value.deployable !== true || typeof value.architectureId !== "string" || typeof value.version !== "string") throw new Error("not a deployable --shadow bundle");
      setBundle({ architectureId: value.architectureId, version: String(value.version), bundleDigest: value.bundleDigest, deployable: true, rawText });
      setPendingApprovals(0);
      onContext({ bundle: `${value.architectureId} v${value.version} · ${value.bundleDigest}` });
      report(message("Bundle loaded · {0}…", String(value.bundleDigest.slice(0, 18))));
    } catch (error) {
      report(message("Bundle rejected · {0}", String(error instanceof Error ? error.message : "invalid JSON")));
    }
  }

  async function propose() {
    if (!bundle) return;
    try {
      // Preserve the compiler's numeric JSON lexemes. Parsing and then
      // JSON.stringify-ing can turn `110.0` into `110`, invalidating the
      // canonical bundle digest even though the numeric value is unchanged.
      const body = await call("/v1/bundles", { method: "POST", body: bundle.rawText });
      report(message("Proposed · commit {0}", String((body.commit as string).slice(0, 10))));
      await refreshStatus();
    } catch (error) {
      report(message("Propose failed · {0}", String(error instanceof Error ? error.message : "request error")));
    }
  }

  async function submitApproval() {
    if (!bundle || !statement) return;
    try {
      const value = JSON.parse(approvalText);
      const body = await call(`/v1/bundles/${bundle.bundleDigest}/approvals`, {
        method: "POST",
        body: JSON.stringify({ approverId: value.approverId, keyId: value.keyId, signature: value.signature }),
      });
      setPendingApprovals(Number(body.pendingApprovals ?? 0));
      setApprovalText("");
      report(message("Approval accepted · {0} pending", String(body.pendingApprovals)));
    } catch (error) {
      report(message("Approval rejected · {0}", String(error instanceof Error ? error.message : "invalid approval JSON")));
    }
  }

  async function promote() {
    if (!bundle || !statement) return;
    try {
      const body = await call(`/v1/bundles/${bundle.bundleDigest}/promote`, { method: "POST" });
      setActive(((body.active as Record<string, unknown>) ?? null));
      onContext({ activeDeployment: body.active ? String((body.active as Record<string, unknown>).bundleDigest) : "None" });
      setDiff(null); setApprovalText("");
      await refreshStatus();
      report("Promoted SHADOW → ENFORCE");
    } catch (error) {
      report(message("Promotion refused · {0}", String(error instanceof Error ? error.message : "request error")));
    }
  }

  async function rollback(targetDigest: string) {
    try {
      const body = await call("/v1/deploy/rollback", { method: "POST", body: JSON.stringify({ targetDigest }) });
      setActive(((body.active as Record<string, unknown>) ?? null));
      onContext({ activeDeployment: body.active ? String((body.active as Record<string, unknown>).bundleDigest) : "None" });
      setDiff(null); setApprovalText("");
      await refreshStatus();
      report("Rolled back");
    } catch (error) {
      report(message("Rollback refused · {0}", String(error instanceof Error ? error.message : "request error")));
    }
  }

  const statement = bundle && statusChecked && diff && diff.bundleDigest === bundle.bundleDigest && diff.baseDigest === (active?.bundleDigest ?? null) ? approvalContext?.statement ?? null : null;
  async function compileDraft() {
    const request = ++deploymentRequest.current;
    setSigningBusy(true); setPendingApprovals(0); setBundle(null); setDiff(null); setApprovalContext(null); setReviewed(false); setApprovalText("");
    try {
      const response = await compileDraftRequest(call, rawArchitecture);
      if (request !== deploymentRequest.current) return;
      setReadiness(response.runtimeReadiness ?? response.findings);
      if (response.deployable !== true) throw new Error(t(message("Draft is not deployable. {0}", String(JSON.stringify(response.findings)))));
      if (typeof response.rawBundle !== "string") throw new Error("Compiler did not return the exact raw bundle");
      setBundle({architectureId:String(response.architectureId), version:String(response.version), bundleDigest:String(response.bundleDigest), deployable:true, rawText:response.rawBundle});
      onContext({bundle:String(response.bundleDigest)}); report("Draft compiled. Propose it to load the review comparison.");
    } catch (error) {report(error instanceof Error ? error.message : "Compilation failed");}
    finally {setSigningBusy(false);}
  }
  async function signFile(file: File) {
    if (!statement || !reviewed || !approvalContext) return;
    if (file.size > 1024) {report("Signing seed file is too large. Choose 32 raw bytes or 64 hexadecimal characters."); return;}
    const context = approvalContext; const request = deploymentRequest.current;
    setSigningBusy(true);
    try {
      const approver = context.trustedApprovers.find(item => item.keyId === approverKeyId);
      if (!approver) throw new Error("Choose a trusted approver");
      const signed = await signApproval(new Uint8Array(await file.arrayBuffer()), statement, approver);
      if (request !== deploymentRequest.current || context !== approvalContext) return;
      setApprovalText(JSON.stringify(signed, null, 2)); report("Signed locally and verified against the trusted public key. Submit when ready.");
    } catch (error) {report(error instanceof Error ? error.message : "Signing failed");}
    finally {setSigningBusy(false);}
  }

  return (
    <div className="stats-panel deploy-panel">
      <div className="deploy-header">
        <div className="panel-heading"><span>{t("OPERATE")}</span><strong>{t("Compile, approve, and promote")}</strong></div>
        <p className="panel-note">{t("Compile the current draft, review its changes, sign locally, then promote. Runtime evidence appears after you start a run.")}</p>
        <div className="deploy-handoff">
          <div><span>{t("DESIGN HANDOFF")}</span><strong>{draftProject.id} v{draftProject.version} {t("→ signed deployment bundle")}</strong></div>
          <span>{t("Daily workflow stays in Studio. The host manages adapters, credentials, and trusted public keys.")}</span>
          <button className="secondary-button" onClick={onBackToDesign}>{t("Back to design")}</button>
        </div>
        <p className="panel-note signing-note">{t("Signing happens in browser memory with WebCrypto. Private key bytes are never sent or saved; the server verifies distinct trusted approvals.")}</p>
      </div>

      <div className="control-plane-card">
        <div><strong>{t("Control plane")}</strong><span>{t("Connect to inspect status and submit the bundle.")}</span></div>
        <div className="live-controls live-control-grid compact">
          <label><span>{t("Control plane URL")}</span><input value={apiUrl} onChange={(event) => { invalidateConnection(); setStatusMessage("Connection changed · refresh status"); onApiUrlChange(event.target.value); }} placeholder="http://127.0.0.1:8792" /></label>
          <label><span>{t("Bearer token")}</span><input value={token} onChange={(event) => { invalidateConnection(); setStatusMessage("Credentials changed · refresh status"); onTokenChange(event.target.value); }} placeholder={t("deployment scope")} type="password" /></label>
          <button className="secondary-button" disabled={statusLoading || !token.trim()} onClick={refreshStatus}>{statusLoading ? t("Checking…") : t("Refresh status")}</button>
        </div>
      </div>

      <p className="connection-status" role="status">{t(statusMessage)}</p>
      {hostStatus && <HostReadiness value={hostStatus} apiUrl={apiUrl} requiredRefs={requiredRefs}/>}
      <Readiness value={readiness}/>
      <div className="deploy-steps">
        <section className="deploy-step">
          <div className="step-heading"><span>1</span><div><strong>{t("Compile current draft")}</strong><small>{bundle ? t("Bundle ready") : t("Ready to compile your draft")}</small></div></div>
          <p>{t("Server compilation validates the current draft and checks runtime bindings.")}</p><button className="primary-button" disabled={signingBusy || !token.trim()} onClick={() => void compileDraft()}>{t("Compile current draft")}</button>
          <input ref={bundleInput} className="file-input" type="file" accept="application/json,.json" onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ""; if (file) void importBundle(file); }} />
          <button className="telemetry-button primary deploy-file" onClick={() => bundleInput.current?.click()}><span>↑</span>{t("Import compiled bundle (advanced)")}</button>
          {bundle && <div className="runtime-source-card"><span>{t("BUNDLE")}</span><strong>{bundle.architectureId} v{bundle.version}</strong><small><code>{bundle.bundleDigest}</code></small></div>}
          <button className="secondary-button" disabled={!bundle} onClick={propose}>{t("Propose to review store")}</button>
        </section>

        <section className="deploy-step">
          <div className="step-heading"><span>2</span><div><strong>{t("Sign approval context")}</strong><small>{statement ? t("Context ready") : t("Available after step 1")}</small></div></div>
          <p>{t("Compare the proposed architecture with the active deployment before signing. Each approver signs the exact server-issued context below.")}</p>
          {bundle && <button className="secondary-button" disabled={statusLoading || diffLoading || !token} onClick={refreshStatus}>{t("Refresh deployment comparison")}</button>}
          {diffLoading && <p role="status">{t("Comparing proposed and active architecture…")}</p>}
          {diffError && <p className="connection-status error" role="alert">{t("Comparison unavailable:")} {t(diffError)}{t(". Propose the bundle first, then refresh.")}</p>}
          {diff && <div className="deployment-diff"><strong>{diff.changeCount} {t("policy and architecture changes")}</strong><p className="panel-note">{t("Base:")} {diff.baseDigest ?? t("No active deployment")}<br />{t("Proposed:")} {diff.bundleDigest}</p>{diff.changes.length === 0 && <p>{t("No architecture changes from the active deployment.")}</p>}{diff.changes.map((change) => <details key={change.path}><summary>{change.path}</summary><div className="diff-values"><div><strong>{t("Before")}</strong><pre>{JSON.stringify(change.before, null, 2)}</pre></div><div><strong>{t("After")}</strong><pre>{JSON.stringify(change.after, null, 2)}</pre></div></div></details>)}</div>}
          {bundle && diff && hostStatus && <CandidateComparison key={JSON.stringify([bundle.bundleDigest,diff.baseDigest,apiUrl,token,hostStatus.targetId,hostStatus.tenantId])} bundle={bundle} baseDigest={diff.baseDigest} hostStatus={hostStatus} readiness={readiness} call={call}/>}
          {bundle && (bundle.architectureId !== draftProject.id || bundle.version !== draftProject.version) && <p className="connection-status">{t("Loaded bundle is")} {bundle.architectureId} v{bundle.version}{t("; the current local draft is")} {draftProject.id} v{draftProject.version}{t(". Approval applies to the loaded bundle.")}</p>}
          {statement && <dl className="host-context review-context"><dt>{t("Control plane")}</dt><dd>{apiUrl}</dd><dt>{t("Target")}</dt><dd>{String(statement.targetId ?? hostStatus?.targetId ?? "Unknown")}</dd><dt>{t("Tenant")}</dt><dd>{String(statement.tenantId ?? hostStatus?.tenantId ?? "Unknown")}</dd></dl>}
          {statement
            ? <pre className="statement-block"><code>{JSON.stringify(statement, null, 2)}</code></pre>
            : <div className="step-placeholder">{t("Load and propose a bundle, then refresh its comparison with the active deployment to generate the signing context.")}</div>}
        </section>

        <section className="deploy-step">
          <div className="step-heading"><span>3</span><div><strong>{t("Submit signed approvals")}</strong><small>{pendingApprovals > 0 ? t(message("{0} pending", String(pendingApprovals))) : t("Distinct reviewer identities verified server-side")}</small></div></div>
          <label className="review-confirm"><input type="checkbox" checked={reviewed} disabled={!statement} onChange={e => {setReviewed(e.target.checked);setApprovalText("");}}/>{t("I reviewed the proposed changes and deployment context.")}</label>
          <label>{t("Trusted approver")}<select value={approverKeyId} onChange={e => {setApproverKeyId(e.target.value);setApprovalText("");}}><option value="">{t("Choose approver…")}</option>{approvalContext?.trustedApprovers.map(item => <option key={item.keyId} value={item.keyId}>{item.approverId} · {item.keyId}</option>)}</select></label>
          <label>{t("Private signing seed file")}<input type="file" disabled={!statement || !reviewed || !approverKeyId || signingBusy} onChange={e => {const file=e.target.files?.[0];e.target.value="";if(file) void signFile(file);}}/><small>{t("32 raw bytes or 64 hexadecimal characters. Sign again with a different approver for the second approval.")}</small></label>
          <label className="deploy-field"><span>{t("Signed approval JSON")}</span><textarea className="approval-input" value={approvalText} onChange={(event) => setApprovalText(event.target.value)} placeholder='{"approverId": …, "keyId": …, "signature": …}' /></label>
          <button className="secondary-button" disabled={!statement || !reviewed || !approvalText.trim() || signingBusy} onClick={submitApproval}>{t("Submit approval")}</button>
        </section>

        <section className="deploy-step">
          <div className="step-heading"><span>4</span><div><strong>{t("Promote and monitor")}</strong><small>{active ? t(message("{0} active", String(active.mode ?? "ENFORCE"))) : statusChecked ? t("No active deployment") : t("Deployment not checked")}</small></div></div>
          <button className="primary-button promote-button" disabled={!statement || statusLoading || diffLoading} onClick={promote}>{t("Promote SHADOW → ENFORCE")}</button>
          {active ? <div className="runtime-source-card"><span>{String(active.mode ?? "ENFORCE")}</span><strong><code>{String(active.bundleDigest ?? "")}</code></strong>{Array.isArray(active.approvers) && <small>{t("approved by")} {(active.approvers as string[]).join(", ")}</small>}<button className="danger-button" disabled={!bundle || bundle.bundleDigest === String(active.bundleDigest)} onClick={() => bundle && rollback(bundle.bundleDigest)}>{t("Rollback to loaded bundle")}</button></div> : <div className="step-placeholder">{t("Connect to the control plane to inspect the active bundle.")}</div>}
          {history.length > 0 && <><h4>{t("Deployment history")}</h4><ul className="deploy-history">{history.slice(0, 8).map((line, index) => <li key={index}><code>{line}</code></li>)}</ul></>}
        </section>
      </div>
    </div>
  );
}
