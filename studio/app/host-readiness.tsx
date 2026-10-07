"use client";

import {useLanguage} from "./language";

export function HostReadiness({value, apiUrl, requiredRefs}: {value:Record<string,unknown>;apiUrl:string;requiredRefs:string[]}) {
  const {t} = useLanguage();
  const setup = (value.credentialSetup ?? []) as Array<{reference:string;environmentVariable:string;loaded:boolean}>;
  const loaded = (value.credentialRefs ?? []) as string[];
  const refs = [...new Set([...requiredRefs, ...setup.map(item=>item.reference), ...loaded])].sort();
  const approvers = (value.trustedApprovers ?? []) as Array<{approverId:string;keyId:string}>;
  const remote = (value.capabilities as {scheduler?:string} | undefined)?.scheduler === "REMOTE_WORKERS";
  const distributed = value.distributed as {workers:Array<{workerId:string;online:boolean;projects:string[];credentialRefs:string[]}>;queue:{pending:number;leased:number}} | null;
  return <section className="runtime-readiness host-readiness"><h3>{t("Host readiness")}</h3>
    <dl className="host-context"><dt>{t("Control plane")}</dt><dd>{apiUrl}</dd><dt>{t("Target")}</dt><dd>{String(value.targetId ?? "Unknown")}</dd><dt>{t("Tenant")}</dt><dd>{String(value.tenantId ?? "Unknown")}</dd></dl>
    {remote ? <><h4>{t("Remote execution servers")}</h4>
      <p>{t("One control plane stores runs and approvals. Remote servers claim entire runs; credential values stay on each execution server.")}</p>
      {distributed ? <><dl className="host-context"><dt>{t("Queued runs")}</dt><dd>{distributed.queue.pending}</dd><dt>{t("Assigned runs")}</dt><dd>{distributed.queue.leased}</dd></dl>
        {distributed.workers.length ? <ul>{distributed.workers.map(worker=><li key={worker.workerId}><strong>{worker.workerId}</strong> · {t(worker.online ? "Online" : "Offline")}<br/>{t("Projects")}: {worker.projects.join(", ")}<br/>{t("Credential references")}: {worker.credentialRefs.join(", ") || t("None")}</li>)}</ul> : <p>{t("No execution servers are registered. Configure workers.json and start a worker.")}</p>}
      </> : <p>{t("Ask the host administrator to inspect execution server availability.")}</p>}
      <p>{t("Each run requires one authorized online server with all required credential references. Configure them with worker --credential-env REF=ENV, then refresh status.")}</p>
      <p>{t("An expired assignment is reassigned only before execution starts. If execution has started and its result is unknown, the run fails with RUN-EFFECT-UNCERTAIN and is not automatically replayed.")}</p>
    </> : <>
    <h4>{t("Credential references")}</h4><p>{t("Secret values stay on the host. This view shows names and loading status only.")}</p>
    {refs.length ? <ul>{refs.map(ref=>{const mapping=setup.find(item=>item.reference===ref);return <li key={ref}><code>{ref}</code> · <strong>{t(loaded.includes(ref) || mapping?.loaded ? "Loaded" : "Missing")}</strong>{mapping ? <> · {t("environment variable")} <code>{mapping.environmentVariable}</code></> : <> · {t("no environment mapping reported")}</>}</li>;})}</ul> : <p>{t("No credential references are required or configured.")}</p>}
    <p>{t("For the local host, add the reference → environment-variable name to credentialEnv in the host’s config.json. Set that variable in the host process environment, restart the host, then refresh status. Ask the host administrator to make these changes.")}</p>
    </>}
    <h4>{t("Trusted reviewers")}</h4>{approvers.length ? <ul>{approvers.map(item=><li key={item.keyId}>{item.approverId} · <code>{item.keyId}</code></li>)}</ul> : <p>{t("No trusted reviewer keys reported.")}</p>}
    <p>{t("Two signing keys do not establish two independent people. Assign keys to distinct reviewers and keep each private seed under its reviewer’s control.")}</p>
    <p>{t("Candidate comparison runs local JSON transforms in ENFORCE mode. HTTP and model tasks are unsupported.")}</p>
    <details><summary>{t("Full host diagnostics")}</summary><pre>{JSON.stringify(value,null,2)}</pre></details>
  </section>;
}
