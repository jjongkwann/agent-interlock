"use client";

import { useMemo, useState } from "react";
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
}: {
  rawLedgerEvents: Array<Record<string, unknown>> | null;
  importedFormat: string | null;
  notify: (message: string) => void;
}) {
  const [source, setSource] = useState<"offline" | "live">("offline");
  const [apiUrl, setApiUrl] = useState("http://127.0.0.1:8791");
  const [token, setToken] = useState("");
  const [tenantId, setTenantId] = useState("tenant-a");
  const [rangeFrom, setRangeFrom] = useState("2026-01-01T00:00:00Z");
  const [rangeTo, setRangeTo] = useState("2027-01-01T00:00:00Z");
  const [liveStats, setLiveStats] = useState<SecurityStatistics | null>(null);
  const [fetching, setFetching] = useState(false);

  const offlineStats = useMemo(
    () => (rawLedgerEvents ? summarizeSecurityStatistics(rawLedgerEvents) : null),
    [rawLedgerEvents],
  );

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

  const stats = source === "live" ? liveStats : offlineStats;
  return (
    <div className="stats-panel">
      <div className="stats-source-row">
        <div className="graph-tabs">
          <button aria-pressed={source === "offline"} className={source === "offline" ? "active" : ""} onClick={() => setSource("offline")}>Imported telemetry</button>
          <button aria-pressed={source === "live"} className={source === "live" ? "active" : ""} onClick={() => setSource("live")}>Live API</button>
        </div>
        {source === "live" && (
          <div className="live-controls">
            <input value={apiUrl} onChange={(event) => setApiUrl(event.target.value)} placeholder="Ledger API URL" aria-label="Ledger API URL" />
            <input value={token} onChange={(event) => setToken(event.target.value)} placeholder="Bearer token (statistics:read)" aria-label="Bearer token" type="password" />
            <input value={tenantId} onChange={(event) => setTenantId(event.target.value)} placeholder="Tenant" aria-label="Tenant" />
            <input value={rangeFrom} onChange={(event) => setRangeFrom(event.target.value)} aria-label="From (ISO 8601)" />
            <input value={rangeTo} onChange={(event) => setRangeTo(event.target.value)} aria-label="To (ISO 8601)" />
            <button className="primary-button" disabled={fetching} onClick={fetchLive}>{fetching ? "Fetching…" : "Fetch"}</button>
          </div>
        )}
      </div>
      {!stats && source === "offline" && (
        <div className="canvas-empty static"><span>Σ</span><strong>No ledger events to aggregate</strong>
          <p>{importedFormat === "OTLP_JSON"
            ? "Statistics need raw Interlock Ledger events; the current import is OTLP spans."
            : "Import Interlock Ledger JSON (the same file the drift view uses), or switch to Live API."}</p>
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
  raw: Record<string, unknown>;
};

export function DeployPanel({ notify }: { notify: (message: string) => void }) {
  const [apiUrl, setApiUrl] = useState("http://127.0.0.1:8792");
  const [token, setToken] = useState("");
  const [active, setActive] = useState<Record<string, unknown> | null>(null);
  const [history, setHistory] = useState<string[]>([]);
  const [bundle, setBundle] = useState<BundleFile | null>(null);
  const [approvalText, setApprovalText] = useState("");
  const [pendingApprovals, setPendingApprovals] = useState<number>(0);

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
      const value = JSON.parse(await file.text());
      if (!value.bundleDigest || !value.deployable) throw new Error("not a deployable --shadow bundle");
      setBundle({ architectureId: value.architectureId, version: String(value.version), bundleDigest: value.bundleDigest, deployable: true, raw: value });
      setPendingApprovals(0);
      notify(`Bundle loaded · ${value.bundleDigest.slice(0, 18)}…`);
    } catch (error) {
      notify(`Bundle rejected · ${error instanceof Error ? error.message : "invalid JSON"}`);
    }
  }

  async function propose() {
    if (!bundle) return;
    try {
      const body = await call("/v1/bundles", { method: "POST", body: JSON.stringify(bundle.raw) });
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
      <div className="panel-heading"><span>OPERATE</span><strong>SHADOW → ENFORCE promotion</strong></div>
      <p className="panel-note">
        Signing keys never enter this browser. Approvers sign with <code>interlock studio approve</code>;
        this panel only submits their signed approvals to the control plane, which verifies the
        two-person rule server-side.
      </p>
      <div className="live-controls">
        <input value={apiUrl} onChange={(event) => setApiUrl(event.target.value)} placeholder="Control plane URL" aria-label="Control plane URL" />
        <input value={token} onChange={(event) => setToken(event.target.value)} placeholder="Bearer token" aria-label="Control plane token" type="password" />
        <button className="quiet-button" onClick={refreshStatus}>Refresh status</button>
      </div>
      <div className="deploy-columns">
        <section>
          <h4>1 · Bundle</h4>
          <label className="telemetry-button primary deploy-file">
            <span>↑</span>Load compile --shadow bundle
            <input className="file-input" type="file" accept="application/json,.json" onChange={(event) => { const file = event.target.files?.[0]; event.target.value = ""; if (file) void importBundle(file); }} />
          </label>
          {bundle && (
            <div className="runtime-source-card">
              <span>BUNDLE</span><strong>{bundle.architectureId} v{bundle.version}</strong>
              <small><code>{bundle.bundleDigest}</code></small>
            </div>
          )}
          <button className="quiet-button" disabled={!bundle} onClick={propose}>Propose to review store</button>
          {statement && (
            <>
              <h4>2 · Approval context</h4>
              <p className="panel-note">The CLI signs this context plus its approverId and keyId with the approver&apos;s Ed25519 private key:</p>
              <pre className="statement-block"><code>{JSON.stringify(statement, null, 2)}</code></pre>
            </>
          )}
        </section>
        <section>
          <h4>3 · Submit signed approvals</h4>
          <textarea
            className="approval-input"
            value={approvalText}
            onChange={(event) => setApprovalText(event.target.value)}
            placeholder='Paste one approval JSON ({"approverId": …, "keyId": …, "signature": …})'
            aria-label="Signed approval JSON"
          />
          <button className="quiet-button" disabled={!bundle || !approvalText.trim()} onClick={submitApproval}>Submit approval</button>
          {pendingApprovals > 0 && <p className="panel-note">{pendingApprovals} approval{pendingApprovals > 1 ? "s" : ""} pending on the control plane.</p>}
          <h4>4 · Promote</h4>
          <button className="primary-button" disabled={!bundle} onClick={promote}>Promote SHADOW → ENFORCE</button>
          <h4>Active deployment</h4>
          {active ? (
            <div className="runtime-source-card">
              <span>{String(active.mode ?? "ENFORCE")}</span>
              <strong><code>{String(active.bundleDigest ?? "")}</code></strong>
              {Array.isArray(active.approvers) && <small>approved by {(active.approvers as string[]).join(", ")}</small>}
              <button
                className="danger-button"
                disabled={!bundle || bundle.bundleDigest === String(active.bundleDigest)}
                onClick={() => bundle && rollback(bundle.bundleDigest)}
              >Rollback to loaded bundle</button>
            </div>
          ) : (
            <p className="panel-note">No active bundle (or not connected).</p>
          )}
          {history.length > 0 && (
            <>
              <h4>Deployment history</h4>
              <ul className="deploy-history">{history.slice(0, 8).map((line, index) => <li key={index}><code>{line}</code></li>)}</ul>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
