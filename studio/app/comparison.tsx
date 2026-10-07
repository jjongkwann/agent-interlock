"use client";

import {useEffect,useRef,useState} from "react";
import {InputFields,Readiness} from "./builder";
import {compareBundleRequest} from "./deployment.mjs";
import {useLanguage} from "./language";

type ComparisonTask = {state:string;output:Record<string,unknown>;errorCode?:string;errorMessage?:string};
type ComparisonRun = {bundleDigest:string;state:string;tasks:Record<string,ComparisonTask>;policyOutcome:string;policyDecisions:Array<Record<string,unknown>>;readiness:unknown};
type ComparisonResult = {kind:string;mode:string;input:Record<string,unknown>;targetId:string;tenantId:string;candidate:ComparisonRun;baseline:ComparisonRun|null;changes:Array<{taskId:string;change:string;before:ComparisonTask|null;after:ComparisonTask|null}>};

function ComparisonRunView({label,run}: {label:string;run:ComparisonRun|null}) {
  const {t}=useLanguage();
  return <section><h4>{t(label)}</h4>{run ? <><code>{run.bundleDigest}</code><p><strong>{run.state}</strong> · {t("Policy outcome")}: {run.policyOutcome}</p>
    {Object.entries(run.tasks).map(([id,task])=><div className="comparison-task" key={id}><strong>{id} · {task.state}</strong>{task.errorMessage && <p role="alert">{task.errorCode}: {task.errorMessage}</p>}<pre>{JSON.stringify(task.output,null,2)}</pre></div>)}
    {run.state === "NOT_READY" && <Readiness value={run.readiness}/>}
    <details open={run.policyOutcome !== "ALLOW" && run.policyOutcome !== "NOT_EVALUATED"}><summary>{t("Policy decisions and failures")}</summary>{run.policyDecisions.length ? run.policyDecisions.map((decision,index)=><pre key={index}>{JSON.stringify(decision,null,2)}</pre>) : <p>{t("No policy decisions recorded.")}</p>}</details>
  </> : <p>{t("No active baseline deployment. This comparison evaluates the candidate only.")}</p>}</section>;
}

export function CandidateComparison({bundle,baseDigest,hostStatus,readiness,call}: {bundle:{bundleDigest:string};baseDigest:string|null;hostStatus:Record<string,unknown>;readiness:unknown;call:(path:string,init?:RequestInit)=>Promise<Record<string,unknown>>}) {
  const {t}=useLanguage();
  const status = readiness as {runInputSchema?:Record<string,unknown>;runInputExample?:Record<string,unknown>} | null;
  const [input,setInput] = useState(JSON.stringify(status?.runInputExample ?? {},null,2));
  const [result,setResult] = useState<ComparisonResult|null>(null);
  const [error,setError] = useState("");
  const [busy,setBusy] = useState(false);
  const requestId = useRef(0);
  useEffect(()=>()=>{requestId.current += 1;},[]);
  function changeInput(text:string) {requestId.current += 1;setInput(text);setResult(null);setError("");setBusy(false);}
  async function compare() {
    const request = ++requestId.current;
    setResult(null);setError("");setBusy(true);
    try {
      const body=await compareBundleRequest(call,bundle.bundleDigest,baseDigest,input,hostStatus.targetId,hostStatus.tenantId) as ComparisonResult;
      if (request !== requestId.current) return;
      setResult(body);
    } catch (error) {if(request===requestId.current) setError(error instanceof Error ? error.message : "Comparison failed");}
    finally {if(request===requestId.current) setBusy(false);}
  }
  return <section className="candidate-comparison"><h4>{t("Compare runtime outcomes")}</h4>
    <p>{t("Run the active baseline and this candidate with the same input in isolated memory, with ENFORCE policies. Only LOCAL JSON_TRANSFORM workflows are supported. The host checks both bundles before executing either; HTTP and model tasks are rejected. Approval holds remain holds.")}</p>
    <p>{t("This check does not promote a bundle or authorize a deployment.")}</p>
    <InputFields schema={status?.runInputSchema} text={input} onChange={changeInput}/>
    <details open={!status?.runInputSchema}><summary>{t("Advanced comparison input JSON")}</summary><label>{t("Input for both bundles")}<textarea value={input} onChange={event=>changeInput(event.target.value)} spellCheck={false}/></label></details>
    <button className="secondary-button" disabled={busy} onClick={()=>void compare()}>{t(busy ? "Comparing outcomes…" : "Compare runtime outcomes")}</button>
    {error && <p className="connection-status error" role="alert">{t(error)}</p>}
    {result && <div className="comparison-results" role="status"><p><strong>{t("Completed comparison")} · {result.mode}</strong></p><p>{t("Target")}: {result.targetId} · {t("Tenant")}: {result.tenantId}</p><details><summary>{t("Exact compared input")}</summary><pre>{JSON.stringify(result.input,null,2)}</pre></details>
      <div className="diff-values"><ComparisonRunView label="Active baseline" run={result.baseline}/><ComparisonRunView label="Candidate" run={result.candidate}/></div>
      <h4>{result.changes.length} {t("task outcome differences")}</h4>{result.changes.length === 0 && <p>{t("No task outcome differences for this input.")}</p>}{result.changes.map(change=><details key={change.taskId}><summary>{change.taskId} · {change.change}</summary><div className="diff-values"><div><strong>{t("Baseline")}</strong><pre>{JSON.stringify(change.before,null,2)}</pre></div><div><strong>{t("Candidate")}</strong><pre>{JSON.stringify(change.after,null,2)}</pre></div></div></details>)}
    </div>}
  </section>;
}
