"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { summarizeSecurityStatistics } from "./analytics.mjs";
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

function PartitionView({ partition }: { partition: SecurityStatisticsPartition }) {
  return (
    <section className="stats-partition">
      <div className="panel-heading"><span>DATA SOURCE</span><strong>{partition.dataSource}</strong></div>
      <div className="stat-grid">
        {COUNTER_LABELS.map(({ key, label, tone }) => (
          <div className={`stat-tile ${tone && partition.counters[key] > 0 ? tone : ""}`} key={key}>
            <strong>{partition.counters[key]}</strong>
            <span>{label}</span>
          </div>
        ))}
      </div>
      <div className="stats-columns">
        <div>
          <h4>Outcomes</h4>
          <table className="stats-table"><tbody>
            {Object.entries(partition.outcomes).map(([outcome, count]) => (
              <tr key={outcome}><td>{outcome}</td><td>{count}</td></tr>
            ))}
          </tbody></table>
          <h4>Reason codes <small>(one interaction can carry several)</small></h4>
          <table className="stats-table"><tbody>
            {partition.byReasonCode.length === 0 && <tr><td colSpan={2}>none</td></tr>}
            {partition.byReasonCode.map((item) => (
              <tr key={item.reasonCode}><td><code>{item.reasonCode}</code></td><td>{item.interactionCount}</td></tr>
            ))}
          </tbody></table>
        </div>
        <div>
          <h4>By relationship</h4>
          <table className="stats-table"><tbody>
            {partition.byRelationship.map((item) => (
              <tr key={item.relationshipId}><td>{item.relationshipId}</td><td>{item.counters.interactionCount} calls</td><td>{item.counters.blockDecisionCount} blocked</td></tr>
            ))}
          </tbody></table>
          <h4>By source actor</h4>
          <table className="stats-table"><tbody>
            {partition.byActor.map((item) => (
              <tr key={item.sourceActorId}><td>{item.sourceActorId}</td><td>{item.counters.interactionCount} calls</td><td>{item.counters.blockDecisionCount} blocked</td></tr>
            ))}
          </tbody></table>
          <h4>By policy</h4>
          <table className="stats-table"><tbody>
            {partition.byPolicy.length === 0 && <tr><td colSpan={3}>none</td></tr>}
            {partition.byPolicy.map((item) => (
              <tr key={item.policyId}><td>{item.policyId}</td><td>{item.counters.interactionCount} calls</td><td>{item.counters.blockDecisionCount} blocked</td></tr>
            ))}
          </tbody></table>
          <h4>By mode</h4>
          <table className="stats-table"><tbody>
            {partition.byMode.length === 0 && <tr><td colSpan={3}>none</td></tr>}
            {partition.byMode.map((item) => (
              <tr key={item.mode}><td>{item.mode}</td><td>{item.counters.interactionCount} calls</td><td>{item.counters.blockDecisionCount} blocked</td></tr>
            ))}
          </tbody></table>
        </div>
      </div>
      <h4>Hourly buckets (UTC)</h4>
      <table className="stats-table stats-timeseries"><thead>
        <tr><th>Bucket</th><th>Interactions</th><th>Block decisions</th><th>Enforced</th><th>Would-block</th><th>Partial/bypass</th></tr>
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

export function StatsPanel({
  rawLedgerEvents,
  importedFormat,
  notify,
  onImportTelemetry,
}: {
  rawLedgerEvents: Array<Record<string, unknown>> | null;
  importedFormat: string | null;
  notify: (message: string) => void;
  onImportTelemetry: () => void;
}) {
  const [source, setSource] = useState<"offline" | "live">("offline");
  const [apiUrl, setApiUrl] = useState("http://127.0.0.1:8791");
  const [token, setToken] = useState("");
  const [tenantId, setTenantId] = useState("tenant-a");
  const [rangeFrom, setRangeFrom] = useState("2026-01-01T00:00:00Z");
  const [rangeTo, setRangeTo] = useState("2027-01-01T00:00:00Z");
  const [liveStats, setLiveStats] = useState<SecurityStatistics | null>(null);
  const [fetching, setFetching] = useState(false);

  const offlineResult = useMemo((): { stats: SecurityStatistics | null; error: string | null } => {
    if (!rawLedgerEvents) return { stats: null, error: null };
    try {
      return { stats: summarizeSecurityStatistics(rawLedgerEvents), error: null };
    } catch (error) {
      return { stats: null, error: error instanceof Error ? error.message : "invalid Ledger events" };
    }
  }, [rawLedgerEvents]);

  async function fetchLive() {
    setFetching(true);
    try {
      const query = new URLSearchParams({ from: rangeFrom, to: rangeTo });
      const response = await fetch(`${apiUrl.replace(/\/$/, "")}/v1/statistics?${query}`, {
        headers: { Authorization: `Bearer ${token}`, "X-Interlock-Tenant-Id": tenantId },
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body?.error?.code ?? `HTTP ${response.status}`);
      setLiveStats(body.statistics);
      notify(`Live statistics loaded · ${body.statistics.interactionCount} interactions in range`);
    } catch (error) {
      setLiveStats(null);
      notify(`Live statistics failed · ${error instanceof Error ? error.message : "request error"}`);
    } finally {
      setFetching(false);
    }
  }

  const stats = source === "live" ? liveStats : offlineResult.stats;
  return (
    <div className="stats-panel">
      <div className="stats-source-row">
        <div className="graph-tabs">
          <button aria-pressed={source === "offline"} className={source === "offline" ? "active" : ""} onClick={() => setSource("offline")}>Imported telemetry</button>
          <button aria-pressed={source === "live"} className={source === "live" ? "active" : ""} onClick={() => setSource("live")}>Live API</button>
        </div>
        {source === "live" && (
          <div className="live-controls live-control-grid">
            <label><span>Ledger API URL</span><input value={apiUrl} onChange={(event) => setApiUrl(event.target.value)} placeholder="http://127.0.0.1:8791" /></label>
            <label><span>Bearer token</span><input value={token} onChange={(event) => setToken(event.target.value)} placeholder="statistics:read" type="password" /></label>
            <label><span>Tenant</span><input value={tenantId} onChange={(event) => setTenantId(event.target.value)} placeholder="tenant-a" /></label>
            <label><span>From · ISO 8601</span><input value={rangeFrom} onChange={(event) => setRangeFrom(event.target.value)} /></label>
            <label><span>To · ISO 8601</span><input value={rangeTo} onChange={(event) => setRangeTo(event.target.value)} /></label>
            <button className="primary-button" disabled={fetching} onClick={fetchLive}>{fetching ? "Fetching…" : "Fetch"}</button>
          </div>
        )}
      </div>
      {source === "offline" && offlineResult.error && (
        <div className="canvas-empty static error-state"><span>!</span><strong>Telemetry cannot be aggregated</strong>
          <p>{offlineResult.error}. Import Ledger events with valid UTC timestamps, or choose Live API.</p>
          <button onClick={onImportTelemetry}>Replace telemetry</button>
        </div>
      )}
      {!stats && source === "offline" && !offlineResult.error && (
        <div className="canvas-empty static"><span>Σ</span><strong>No ledger events to aggregate</strong>
          <p>{importedFormat === "OTLP_JSON"
            ? "Statistics need raw Interlock Ledger events; the current import is OTLP spans."
            : "Import Interlock Ledger JSON (the same file the drift view uses), or switch to Live API."}</p>
          <button onClick={onImportTelemetry}>Import Ledger telemetry</button>
        </div>
      )}
      {!stats && source === "live" && (
        <div className="canvas-empty static"><span>Σ</span><strong>Not connected</strong><p>Point at a Ledger API with the statistics:read scope and fetch a range.</p></div>
      )}
      {stats && stats.partitions.length === 0 && (
        <div className="canvas-empty static"><span>Σ</span><strong>No interactions in range</strong><p>The event set contains no interaction lifecycles to aggregate.</p></div>
      )}
      {stats && source === "offline" && rawLedgerEvents?.some((event) => "integrity_hash" in event) && (
        <p className="panel-note">Offline browser statistics do not verify Ledger integrity hashes. Confirm evidence with the authenticated API or Python verifier.</p>
      )}
      {stats && stats.partitions.map((partition) => <PartitionView key={partition.dataSource} partition={partition} />)}
    </div>
  );
}

type BundleFile = {
  architectureId: string;
  version: string;
  bundleDigest: string;
  deployable: boolean;
  rawText: string;
};

type RunTask = {
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
      {label} · {state}
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

type ControlPlaneConnectionProps = {
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
}: {
  notify: (message: string) => void;
  onOpenRuntimeTelemetry: (events: Array<Record<string, unknown>>, source: string) => void;
} & ControlPlaneConnectionProps) {
  const [inputText, setInputText] = useState("{}");
  const [runs, setRuns] = useState<WorkflowRun[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [selectedRun, setSelectedRun] = useState<WorkflowRun | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [busy, setBusy] = useState(false);
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
      setRuns((items) => items.map((item) => item.id === run.id ? run : item));
      setEvents(Array.isArray(eventBody.events) ? eventBody.events as RunEvent[] : []);
      if (announce) notify(`Run refreshed · ${run.state}`);
    } catch (error) {
      if (announce) notify(`Run refresh failed · ${error instanceof Error ? error.message : "request error"}`);
    }
  }, [call, notify]);

  const refreshRuns = useCallback(async (announce = true) => {
    setBusy(true);
    try {
      const body = await call("/v1/runs");
      const nextRuns = (Array.isArray(body.runs) ? body.runs : []).map(readRun).filter((item): item is WorkflowRun => Boolean(item));
      setRuns(nextRuns);
      const nextId = selectedRunId && nextRuns.some((run) => run.id === selectedRunId) ? selectedRunId : nextRuns[0]?.id ?? null;
      setSelectedRunId(nextId);
      setSelectedRun(nextId ? nextRuns.find((run) => run.id === nextId) ?? null : null);
      if (nextId) await loadRun(nextId);
      else setEvents([]);
      if (announce) notify(`Runs refreshed · ${nextRuns.length} visible`);
    } catch (error) {
      if (announce) notify(`Runs failed · ${error instanceof Error ? error.message : "request error"}`);
    } finally {
      setBusy(false);
    }
  }, [call, loadRun, notify, selectedRunId]);

  useEffect(() => {
    if (!shouldAutoLoad.current || autoLoadStarted.current) return;
    autoLoadStarted.current = true;
    void refreshRuns(false);
  }, [refreshRuns]);

  useEffect(() => {
    if (!selectedRunId || (selectedRun && TERMINAL_RUN_STATES.has(selectedRun.state))) return;
    const timer = window.setInterval(() => { void loadRun(selectedRunId); }, 1500);
    return () => window.clearInterval(timer);
  }, [loadRun, selectedRun, selectedRunId]);

  async function startRun() {
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
      setEvents([]);
      notify(`Run started · ${run.id}`);
    } catch (error) {
      notify(`Start failed · ${error instanceof Error ? error.message : "request error"}`);
    } finally {
      setBusy(false);
    }
  }

  async function runCommand(path: string, success: string) {
    if (!selectedRunId) return;
    setBusy(true);
    try {
      const body = await call(`/v1/runs/${encodeURIComponent(selectedRunId)}${path}`, { method: "POST", body: "{}" });
      const run = readRun(body.run);
      if (run) setSelectedRun(run);
      notify(success);
      await loadRun(selectedRunId);
    } catch (error) {
      notify(`Run command failed · ${error instanceof Error ? error.message : "request error"}`);
    } finally {
      setBusy(false);
    }
  }

  async function approveTask(taskId: string) {
    if (!selectedRunId) return;
    setBusy(true);
    try {
      await call(`/v1/runs/${encodeURIComponent(selectedRunId)}/tasks/${encodeURIComponent(taskId)}/approve`, { method: "POST", body: "{}" });
      notify(`Approval submitted · ${taskId}`);
      await loadRun(selectedRunId);
    } catch (error) {
      notify(`Approval failed · ${error instanceof Error ? error.message : "request error"}`);
    } finally {
      setBusy(false);
    }
  }

  const selectedTasks = selectedRun ? Object.entries(selectedRun.tasks) : [];
  const terminal = selectedRun ? TERMINAL_RUN_STATES.has(selectedRun.state) : false;
  return (
    <div className="stats-panel runs-panel">
      <div className="deploy-header">
        <div className="panel-heading"><span>RUN</span><strong>Deployment-bound workflow runs</strong></div>
        <p className="panel-note">A run uses the exact architecture in the active ENFORCE bundle. The host must provide every A2A, MCP, Local, or Human transport adapter; missing adapters fail closed.</p>
      </div>

      <div className="control-plane-card runs-connection">
        <div><strong>Run Control</strong><span>Bearer credentials stay in this browser session only.</span></div>
        <div className="live-controls live-control-grid compact">
          <label><span>Control plane URL</span><input value={apiUrl} onChange={(event) => onApiUrlChange(event.target.value)} placeholder="http://127.0.0.1:8792" /></label>
          <label><span>Bearer token</span><input value={token} onChange={(event) => onTokenChange(event.target.value)} placeholder="run scopes" type="password" /></label>
          <button className="secondary-button" disabled={busy} onClick={() => void refreshRuns()}>{busy ? "Working…" : "Refresh runs"}</button>
        </div>
      </div>

      <section className="run-start-card">
        <div><strong>Start from active deployment</strong><span>Input is sent to the deployed workflow coordinator. Run and trace IDs are generated server-side.</span></div>
        <label className="deploy-field"><span>Workflow input · JSON object</span><textarea className="run-input" value={inputText} onChange={(event) => setInputText(event.target.value)} spellCheck={false} /></label>
        <button className="primary-button run-start-button" disabled={busy || !inputText.trim()} onClick={() => void startRun()}>Start run</button>
      </section>

      <div className="runs-layout">
        <section className="run-list-card">
          <div className="run-section-heading"><div><strong>Runs</strong><span>{runs.length} visible to this tenant</span></div></div>
          <div className="run-list">
            {runs.length === 0 && <div className="run-empty">Connect and refresh to inspect tenant-scoped runs.</div>}
            {runs.map((run) => <button key={run.id} className={selectedRunId === run.id ? "active" : ""} onClick={() => { setSelectedRunId(run.id); setSelectedRun(run); void loadRun(run.id); }}><span><strong>{run.id}</strong><small>{run.architectureId} · v{run.architectureVersion}</small></span><i className={`run-state state-${run.state.toLowerCase()}`}>{run.state.replaceAll("_", " ")}</i></button>)}
          </div>
        </section>

        <section className="run-detail-card">
          {!selectedRun && <div className="run-empty detail">Select a run to inspect task state, approvals, and ledger evidence.</div>}
          {selectedRun && <>
            <div className="run-detail-header">
              <div><span>RUN</span><strong>{selectedRun.id}</strong><small><code>{selectedRun.bundleDigest}</code></small></div>
              <i className={`run-state state-${selectedRun.state.toLowerCase()}`}>{selectedRun.state.replaceAll("_", " ")}</i>
            </div>
            <div className="run-meta"><span><b>Trace</b><code>{selectedRun.traceId}</code></span><span><b>Messages</b>{selectedRun.messagesUsed}</span><span><b>Updated</b>{selectedRun.updatedAt}</span>{selectedRun.errorCode && <span className="run-error"><b>Error</b>{selectedRun.errorCode}</span>}</div>
            {selectedRun.outcomes && <div className="run-meta run-outcomes-summary">
              <span><b>Executed</b>{selectedRun.outcomes.executed}/{selectedRun.outcomes.total}</span>
              <span><b>Goal met</b>{selectedRun.outcomes.goalMet}/{selectedRun.outcomes.total}</span>
              <span><b>Security met</b>{selectedRun.outcomes.securityMet}/{selectedRun.outcomes.total}</span>
            </div>}
            <div className="run-actions">
              <button className="secondary-button" disabled={busy} onClick={() => void loadRun(selectedRun.id, true)}>Refresh</button>
              <button className="primary-button" disabled={busy || events.length === 0} onClick={() => onOpenRuntimeTelemetry(events, `Run ${selectedRun.id}`)}>Open runtime graph</button>
              <button className="secondary-button" disabled={busy || terminal} onClick={() => void runCommand("/resume", "Resume requested")}>Resume</button>
              <button className="danger-button" disabled={busy || terminal} onClick={() => void runCommand("/cancel", "Run canceled")}>Cancel</button>
            </div>
            <div className="run-section-heading"><div><strong>Tasks</strong><span>{selectedTasks.length} deployment tasks</span></div></div>
            <div className="run-task-list">
              {selectedTasks.map(([taskId, task]) => <article className="run-task" key={taskId}>
                <div><span><strong>{taskId}</strong><small>{task.attempts} attempt{task.attempts === 1 ? "" : "s"}{task.externalTaskId ? ` · ${task.externalTaskId}` : ""}</small></span><i className={`run-state state-${task.state.toLowerCase()}`}>{task.state.replaceAll("_", " ")}</i></div>
                <div className="run-task-outcomes" style={{ display: "flex", gap: "0.4em", flexWrap: "wrap", margin: "0.35em 0" }}>
                  <OutcomeBadge label="Executed" value={task.executed ?? false} />
                  <OutcomeBadge label="Goal" value={task.goalMet ?? null} />
                  <OutcomeBadge label="Security" value={task.securityMet ?? null} />
                </div>
                {(task.errorCode || task.errorMessage) && <p className="run-task-error">{task.errorCode}{task.errorMessage ? ` · ${task.errorMessage}` : ""}</p>}
                {task.output && Object.keys(task.output).length > 0 && <pre><code>{JSON.stringify(task.output, null, 2)}</code></pre>}
                {task.state === "WAITING_APPROVAL" && <button className="primary-button approve-task" disabled={busy} onClick={() => void approveTask(taskId)}>Approve task</button>}
              </article>)}
            </div>
            <div className="run-section-heading events-heading"><div><strong>Ledger evidence</strong><span>{events.length} trace events</span></div></div>
            <div className="run-events">
              {events.length === 0 && <div className="run-empty">No events returned for this trace.</div>}
              {[...events].reverse().slice(0, 30).map((event, index) => <div key={`${event.occurred_at ?? "event"}-${index}`}><span>{event.occurred_at ?? "—"}</span><strong>{event.event_type ?? "UNKNOWN_EVENT"}</strong>{event.payload?.reason_code && <code>{String(event.payload.reason_code)}</code>}</div>)}
            </div>
          </>}
        </section>
      </div>
    </div>
  );
}

export function DeployPanel({
  notify,
  onBackToDesign,
  apiUrl,
  token,
  onApiUrlChange,
  onTokenChange,
}: {
  notify: (message: string) => void;
  onBackToDesign: () => void;
} & ControlPlaneConnectionProps) {
  const [active, setActive] = useState<Record<string, unknown> | null>(null);
  const [history, setHistory] = useState<string[]>([]);
  const [bundle, setBundle] = useState<BundleFile | null>(null);
  const [approvalText, setApprovalText] = useState("");
  const [pendingApprovals, setPendingApprovals] = useState<number>(0);
  const bundleInput = useRef<HTMLInputElement>(null);

  async function call(path: string, init?: RequestInit): Promise<Record<string, unknown>> {
    const response = await fetch(`${apiUrl.replace(/\/$/, "")}${path}`, {
      ...init,
      headers: { Authorization: `Bearer ${token}`, ...(init?.body ? { "Content-Type": "application/json" } : {}), ...init?.headers },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error((body as { error?: { code?: string } })?.error?.code ?? `HTTP ${response.status}`);
    return body as Record<string, unknown>;
  }

  async function refreshStatus() {
    try {
      const body = await call("/v1/deploy/status");
      setActive((body.active as Record<string, unknown>) ?? null);
      setHistory((body.history as string[]) ?? []);
      notify("Deployment status refreshed");
    } catch (error) {
      notify(`Status failed · ${error instanceof Error ? error.message : "request error"}`);
    }
  }

  async function importBundle(file: File) {
    try {
      const rawText = await file.text();
      const value = JSON.parse(rawText);
      if (!value.bundleDigest || !value.deployable) throw new Error("not a deployable --shadow bundle");
      setBundle({ architectureId: value.architectureId, version: String(value.version), bundleDigest: value.bundleDigest, deployable: true, rawText });
      setPendingApprovals(0);
      notify(`Bundle loaded · ${value.bundleDigest.slice(0, 18)}…`);
    } catch (error) {
      notify(`Bundle rejected · ${error instanceof Error ? error.message : "invalid JSON"}`);
    }
  }

  async function propose() {
    if (!bundle) return;
    try {
      // Preserve the compiler's numeric JSON lexemes. Parsing and then
      // JSON.stringify-ing can turn `110.0` into `110`, invalidating the
      // canonical bundle digest even though the numeric value is unchanged.
      const body = await call("/v1/bundles", { method: "POST", body: bundle.rawText });
      notify(`Proposed · commit ${(body.commit as string).slice(0, 10)}`);
    } catch (error) {
      notify(`Propose failed · ${error instanceof Error ? error.message : "request error"}`);
    }
  }

  async function submitApproval() {
    if (!bundle) return;
    try {
      const value = JSON.parse(approvalText);
      const body = await call(`/v1/bundles/${bundle.bundleDigest}/approvals`, {
        method: "POST",
        body: JSON.stringify({ approverId: value.approverId, keyId: value.keyId, signature: value.signature }),
      });
      setPendingApprovals(Number(body.pendingApprovals ?? 0));
      setApprovalText("");
      notify(`Approval accepted · ${body.pendingApprovals} pending`);
    } catch (error) {
      notify(`Approval rejected · ${error instanceof Error ? error.message : "invalid approval JSON"}`);
    }
  }

  async function promote() {
    if (!bundle) return;
    try {
      const body = await call(`/v1/bundles/${bundle.bundleDigest}/promote`, { method: "POST" });
      setActive(((body.active as Record<string, unknown>) ?? null));
      notify("Promoted SHADOW → ENFORCE");
    } catch (error) {
      notify(`Promotion refused · ${error instanceof Error ? error.message : "request error"}`);
    }
  }

  async function rollback(targetDigest: string) {
    try {
      const body = await call("/v1/deploy/rollback", { method: "POST", body: JSON.stringify({ targetDigest }) });
      setActive(((body.active as Record<string, unknown>) ?? null));
      notify("Rolled back");
    } catch (error) {
      notify(`Rollback refused · ${error instanceof Error ? error.message : "request error"}`);
    }
  }

  const statement = bundle
    ? {
        purpose: "studio-architecture-deploy",
        architectureId: bundle.architectureId,
        bundleDigest: bundle.bundleDigest,
        fromDigest: (active?.bundleDigest as string | undefined) ?? null,
        toMode: "ENFORCE",
      }
    : null;

  return (
    <div className="stats-panel deploy-panel">
      <div className="deploy-header">
        <div className="panel-heading"><span>OPERATE</span><strong>Compile, approve, and promote</strong></div>
        <p className="panel-note">Design does not become runtime directly. Export the manifest, compile a SHADOW bundle with the CLI, then promote it here. Runtime appears only after real telemetry is observed.</p>
        <div className="deploy-handoff">
          <div><span>DESIGN HANDOFF</span><strong>Browser draft → signed deployment bundle</strong></div>
          <code>interlock studio lint architecture.json</code>
          <code>interlock studio compile --shadow architecture.json</code>
          <button className="secondary-button" onClick={onBackToDesign}>Back to design</button>
        </div>
        <p className="panel-note signing-note">Signing keys never enter this browser. Approvers sign with <code>interlock studio approve</code>; the control plane verifies the two-person rule server-side.</p>
      </div>

      <div className="control-plane-card">
        <div><strong>Control plane</strong><span>Connect to inspect status and submit the bundle.</span></div>
        <div className="live-controls live-control-grid compact">
          <label><span>Control plane URL</span><input value={apiUrl} onChange={(event) => onApiUrlChange(event.target.value)} placeholder="http://127.0.0.1:8792" /></label>
          <label><span>Bearer token</span><input value={token} onChange={(event) => onTokenChange(event.target.value)} placeholder="deployment scope" type="password" /></label>
          <button className="secondary-button" onClick={refreshStatus}>Refresh status</button>
        </div>
      </div>

      <div className="deploy-steps">
        <section className="deploy-step">
          <div className="step-heading"><span>1</span><div><strong>Load compiled bundle</strong><small>{bundle ? "Bundle ready" : "Waiting for --shadow bundle"}</small></div></div>
          <p>Choose the deployable JSON produced by the CLI.</p>
          <input ref={bundleInput} className="file-input" type="file" accept="application/json,.json" onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ""; if (file) void importBundle(file); }} />
          <button className="telemetry-button primary deploy-file" onClick={() => bundleInput.current?.click()}><span>↑</span>Load compile --shadow bundle</button>
          {bundle && <div className="runtime-source-card"><span>BUNDLE</span><strong>{bundle.architectureId} v{bundle.version}</strong><small><code>{bundle.bundleDigest}</code></small></div>}
          <button className="secondary-button" disabled={!bundle} onClick={propose}>Propose to review store</button>
        </section>

        <section className="deploy-step">
          <div className="step-heading"><span>2</span><div><strong>Sign approval context</strong><small>{statement ? "Context ready" : "Available after step 1"}</small></div></div>
          <p>Each approver signs this context with <code>interlock studio approve</code>.</p>
          {statement
            ? <pre className="statement-block"><code>{JSON.stringify(statement, null, 2)}</code></pre>
            : <div className="step-placeholder">Load and propose a bundle to generate the exact signing context.</div>}
        </section>

        <section className="deploy-step">
          <div className="step-heading"><span>3</span><div><strong>Submit signed approvals</strong><small>{pendingApprovals > 0 ? `${pendingApprovals} pending` : "Two-person rule verified server-side"}</small></div></div>
          <label className="deploy-field"><span>Signed approval JSON</span><textarea className="approval-input" value={approvalText} onChange={(event) => setApprovalText(event.target.value)} placeholder='{"approverId": …, "keyId": …, "signature": …}' /></label>
          <button className="secondary-button" disabled={!bundle || !approvalText.trim()} onClick={submitApproval}>Submit approval</button>
        </section>

        <section className="deploy-step">
          <div className="step-heading"><span>4</span><div><strong>Promote and monitor</strong><small>{active ? `${String(active.mode ?? "ENFORCE")} active` : "No active deployment"}</small></div></div>
          <button className="primary-button promote-button" disabled={!bundle} onClick={promote}>Promote SHADOW → ENFORCE</button>
          {active ? <div className="runtime-source-card"><span>{String(active.mode ?? "ENFORCE")}</span><strong><code>{String(active.bundleDigest ?? "")}</code></strong>{Array.isArray(active.approvers) && <small>approved by {(active.approvers as string[]).join(", ")}</small>}<button className="danger-button" disabled={!bundle || bundle.bundleDigest === String(active.bundleDigest)} onClick={() => bundle && rollback(bundle.bundleDigest)}>Rollback to loaded bundle</button></div> : <div className="step-placeholder">Connect to the control plane to inspect the active bundle.</div>}
          {history.length > 0 && <><h4>Deployment history</h4><ul className="deploy-history">{history.slice(0, 8).map((line, index) => <li key={index}><code>{line}</code></li>)}</ul></>}
        </section>
      </div>
    </div>
  );
}
