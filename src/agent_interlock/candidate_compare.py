"""Compare reviewed local JSON workflows without touching a host or its active state."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import replace
from typing import Any

from .architecture import ArchitectureCompiler, ArchitectureGraph, TaskTransport
from .canonical import canonical_digest
from .configurable_runtime import RUNTIME_KEY, configurable_adapter_provider, runtime_status
from .ledger import InMemoryLedger
from .models import ActorType, ControlDecision
from .orchestration import InMemoryWorkflowRunStore, OrchestrationEngine
from .policy import strongest_decision
from .studio_deploy import DeploymentBundle, deployed_architecture


def _prepare(bundle: DeploymentBundle) -> tuple[ArchitectureGraph, dict[str, Any]]:
    if canonical_digest(bundle.body) != bundle.bundle_digest:
        raise ValueError("comparison bundle digest does not match its body")
    graph = deployed_architecture(bundle.body, "ENFORCE")
    nodes = {node.id: node for node in graph.nodes}
    for task in graph.orchestration.tasks if graph.orchestration else ():
        source, target = nodes.get(task.source_actor_id), nodes.get(task.target_actor_id)
        config = target.annotations.get(RUNTIME_KEY) if target else None
        if (task.transport != TaskTransport.LOCAL or not isinstance(config, Mapping)
                or config.get("kind") != "JSON_TRANSFORM"
                or source is None or source.actor.type not in {ActorType.AGENT, ActorType.SUBAGENT}
                or source.annotations.get(RUNTIME_KEY) is not None):
            raise ValueError(f"task {task.id}: comparison requires LOCAL JSON_TRANSFORM and no model source")
    return graph, runtime_status(graph)


def _run(bundle: DeploymentBundle, prepared: tuple[ArchitectureGraph, dict[str, Any]],
         workflow_input: Mapping[str, Any], tenant_id: str) -> dict[str, Any]:
    graph, readiness = prepared
    tasks = {task.id: {"state": "NOT_RUN", "output": {}, "errorCode": None, "errorMessage": None,
                       "executed": False, "goalMet": None, "securityMet": None, "pendingCall": None}
             for task in graph.orchestration.tasks} if graph.orchestration else {}
    result = {"bundleDigest": bundle.bundle_digest, "readiness": readiness, "state": "NOT_READY",
              "tasks": tasks, "policyOutcome": "NOT_EVALUATED", "policyDecisions": []}
    if not readiness["ready"]:
        return result
    compiled = replace(ArchitectureCompiler().compile(graph), bundle_digest=bundle.bundle_digest)
    ledger, store = InMemoryLedger(), InMemoryWorkflowRunStore()
    engine = OrchestrationEngine(
        compiled, adapters=configurable_adapter_provider(ledger, store, {})(compiled),
        run_store=store, ledger=ledger, bundle_digest=bundle.bundle_digest,
    )
    run = engine.start(tenant_id=tenant_id, workflow_input=workflow_input)
    tasks = {}
    for task_id, task in run.tasks.items():
        tasks[task_id] = {"state": task.state.value, "output": dict(task.output),
                          "errorCode": task.error_code, "errorMessage": task.error_message,
                          "executed": task.executed, "goalMet": task.goal_met,
                          "securityMet": task.security_met, "pendingCall": task.pending_call}
    decisions = [{"sourceActorId": event.source_actor_id, "targetActorId": event.target_actor_id,
                  **dict(event.payload["control"])} for event in ledger.all()
                 if event.event_type == "CONTROL_EVALUATED" and "decision" in event.payload.get("control", {})
                 and event.payload["control"]["decision"] in {decision.value for decision in ControlDecision}]
    verdicts = [ControlDecision(item["decision"]) for item in decisions]
    if any(task.state.value == "WAITING_APPROVAL" for task in run.tasks.values()):
        verdicts.append(ControlDecision.HOLD)
    result.update(state=run.state.value, tasks=tasks, policyDecisions=decisions,
                  policyOutcome=strongest_decision(verdicts).value if verdicts else "NOT_EVALUATED")
    return result


def compare_bundles(candidate: DeploymentBundle, baseline: DeploymentBundle | None,
                    workflow_input: Mapping[str, Any], tenant_id: str) -> dict[str, Any]:
    """Execute supported candidates in fresh memory; unsupported inputs raise ValueError.

    Both bundles are checked before either executes. Approvals remain HOLD, and
    only JSON transforms can run. Results are ephemeral and do not authorize a deployment.
    """
    if not isinstance(workflow_input, Mapping) or not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("comparison requires a JSON input object and tenant ID")
    try:
        # Copy without canonical normalization: newline and Unicode input bytes affect transforms.
        input_copy = json.loads(json.dumps(dict(workflow_input), allow_nan=False))
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("comparison input must contain JSON values") from error
    candidate_prepared = _prepare(candidate)
    baseline_prepared = _prepare(baseline) if baseline else None
    after = _run(candidate, candidate_prepared, input_copy, tenant_id)
    before = _run(baseline, baseline_prepared, input_copy, tenant_id) if baseline else None
    old_tasks = before["tasks"] if before else {}
    changes = []
    for task_id in sorted(old_tasks.keys() | after["tasks"].keys()):
        old, new = old_tasks.get(task_id), after["tasks"].get(task_id)
        if old != new:
            changes.append({"taskId": task_id, "change": "ADDED" if old is None else "REMOVED" if new is None
                            else "CHANGED", "before": old, "after": new})
    return {"kind": "LOCAL_JSON_COMPARISON", "mode": "ENFORCE", "input": input_copy,
            "candidate": after, "baseline": before, "changes": changes}
