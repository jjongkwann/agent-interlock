"""Durable external-effect checkpoints and evidence-bound reconciliation.

A resolver is trusted host code, never model output or a client-supplied verdict.
NOT_EXECUTED requires the external system to fence the old request atomically.
An absent receipt or an eventually consistent read can only establish UNKNOWN.
"""
from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from .canonical import canonical_digest, canonical_json
from .orchestration import (
    _RUN_TERMINAL,
    OrchestrationError,
    TaskExecutionInput,
    WorkflowRun,
    WorkflowRunState,
    WorkflowTaskState,
    _now,
)


class EffectStatus(StrEnum):
    COMPLETED = "COMPLETED"
    NOT_EXECUTED = "NOT_EXECUTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class EffectResolution:
    status: EffectStatus
    idempotency_key: str
    invocation_digest: str
    evidence: str
    result: Mapping[str, Any] | None = None
    # True means the old request can never commit, even if a lost worker wakes up.
    fenced: bool = False


EffectResolver = Callable[[WorkflowRun, str, Mapping[str, Any]], EffectResolution]


def _copy(value):
    return json.loads(canonical_json(value))


def checkpoint_run(run, task_id, checkpoint, expected):
    """CAS one task checkpoint, preserving concurrent approval and other task updates."""
    task = run.tasks[task_id]
    if run.state in _RUN_TERMINAL or task.state != WorkflowTaskState.RUNNING:
        raise OrchestrationError("RUN-EFFECT-NOT-RUNNING", "effect checkpoint requires an active task")
    if task.effect_checkpoint != expected:
        raise OrchestrationError("RUN-EFFECT-CONFLICT", "effect checkpoint changed")
    checkpoint = _copy(checkpoint)
    if type(checkpoint.get("sequence")) is not int or checkpoint["sequence"] < 1:
        raise OrchestrationError("RUN-EFFECT-TRANSITION-INVALID", "effect sequence must be a positive integer")
    if checkpoint.get("runGeneration") != run.created_at:
        raise OrchestrationError("RUN-EFFECT-GENERATION-MISMATCH", "effect belongs to a different run generation")
    old_sequence = expected["sequence"] if expected else 0
    new_effect = checkpoint["sequence"] == old_sequence + 1 and checkpoint["state"] == "STARTED"
    if new_effect:
        if expected and expected["state"] not in {"COMPLETED", "NOT_EXECUTED"}:
            raise OrchestrationError("RUN-EFFECT-UNCERTAIN", "previous effect is not resolved")
        key = canonical_digest([run.tenant_id, run.id, run.created_at, task_id,
                                checkpoint["sequence"], checkpoint["invocation"]]).removeprefix("sha256:")
        if checkpoint.get("idempotencyKey") != key:
            raise OrchestrationError("RUN-EFFECT-KEY-INVALID", "effect key is not bound to this invocation")
    elif (not expected or checkpoint["sequence"] != old_sequence or checkpoint["state"] != "COMPLETED"
          or expected["state"] not in {"STARTED", "CONFIRMED"}
          or any(checkpoint[key] != expected[key] for key in
                 ("invocation", "invocationDigest", "idempotencyKey", "runGeneration"))):
        raise OrchestrationError("RUN-EFFECT-TRANSITION-INVALID", "invalid effect checkpoint transition")
    if checkpoint["invocationDigest"] != canonical_digest(checkpoint["invocation"]):
        raise OrchestrationError("RUN-EFFECT-DIGEST-INVALID", "effect invocation digest does not match")
    return replace(run, tasks={**run.tasks, task_id: replace(task, effect_checkpoint=checkpoint)}, updated_at=_now())


class EffectJournal:
    """Execute a policy-approved effect once, with its stable transport idempotency key.

    The caller MUST authorize before invoking execute. dispatch(key, confirmed_result)
    performs the guarded invocation: when confirmed_result is supplied it must process
    that result through its normal output checks without sending another write.
    """

    def __init__(self, run_store, ledger):
        self.run_store, self.ledger = run_store, ledger

    def execute(self, value: TaskExecutionInput, invocation: Mapping[str, Any], dispatch):
        if time.time() >= value.deadline_epoch:
            raise OrchestrationError("ORCH-TASK-DEADLINE", "task deadline elapsed before external effect")
        invocation = _copy(invocation)
        run = self.run_store.get(tenant_id=value.tenant_id, run_id=value.run_id)
        if value.run_generation != run.created_at:
            raise OrchestrationError("RUN-EFFECT-GENERATION-MISMATCH", "task belongs to a different run generation")
        old = run.tasks[value.task.id].effect_checkpoint
        same = old and old["invocationDigest"] == canonical_digest(invocation)
        if same and old["state"] == "COMPLETED":
            return _copy(old["output"])
        if old and old["state"] in {"STARTED", "CONFIRMED"} and not same:
            raise OrchestrationError("RUN-EFFECT-UNCERTAIN", "another effect still needs reconciliation")
        if same and old["state"] == "STARTED":
            raise OrchestrationError("RUN-EFFECT-UNCERTAIN", "effect acknowledgement is unknown")
        if same and old["state"] == "CONFIRMED":
            checkpoint = old
            confirmed = _copy(old["result"])
        else:
            sequence = old["sequence"] + 1 if old else 1
            checkpoint = {"sequence": sequence, "state": "STARTED", "invocation": invocation,
                          "runGeneration": run.created_at,
                          "invocationDigest": canonical_digest(invocation),
                          "idempotencyKey": canonical_digest([
                              run.tenant_id, run.id, run.created_at, value.task.id, sequence, invocation,
                          ]).removeprefix("sha256:"), "startedAt": _now()}
            self.run_store.checkpoint_effect(tenant_id=run.tenant_id, run_id=run.id,
                                            task_id=value.task.id, checkpoint=checkpoint, expected=old)
            confirmed = None
        self._event(run, value.task.id, checkpoint, "dispatch" if confirmed is None else "restore")
        try:
            if time.time() >= value.deadline_epoch:
                raise TimeoutError("effect deadline elapsed before dispatch")
            output = _copy(dispatch(checkpoint["idempotencyKey"], confirmed))
            if not isinstance(output, Mapping):
                raise ValueError("effect output must be a JSON object")
            done = {**checkpoint, "state": "COMPLETED", "output": output, "completedAt": _now()}
            self.run_store.checkpoint_effect(tenant_id=run.tenant_id, run_id=run.id,
                                            task_id=value.task.id, checkpoint=done, expected=checkpoint)
            self._event(run, value.task.id, done, "completed")
            return output
        except Exception as error:
            raise OrchestrationError("RUN-EFFECT-UNCERTAIN", "external effect requires reconciliation") from error

    def _event(self, run, task_id, checkpoint, phase):
        invocation = checkpoint["invocation"]
        self.ledger.append(
            "WORKFLOW_TASK_STATUS_UPDATED", tenant_id=run.tenant_id, trace_id=run.trace_id,
            span_id=f"workflow-{run.id}-{task_id}-effect-{checkpoint['sequence']}",
            source_actor_id=invocation["sourceActorId"], target_actor_id=invocation["targetActorId"],
            payload={"runId": run.id, "taskId": task_id, "bundleDigest": run.bundle_digest,
                     "effectPhase": phase, "effectState": checkpoint["state"],
                     "invocationDigest": checkpoint["invocationDigest"],
                     "idempotencyKey": checkpoint["idempotencyKey"]},
        )


def reconcile_effects(run_store, ledger, *, run: WorkflowRun, resolver: EffectResolver):
    """Resolve every interrupted task before reviving this run. No execution happens here."""
    if run.state != WorkflowRunState.FAILED or run.error_code not in {
        "RUN-EFFECT-UNCERTAIN", "RUN-INTERRUPTED", "ORCH-TASK-FAILED", "ORCH-RUN-DEADLINE",
    }:
        raise OrchestrationError("RUN-NOT-UNCERTAIN", "only interrupted effects can be reconciled")
    tasks, reports, unresolved = dict(run.tasks), {}, False
    for task_id, task in run.tasks.items():
        if task.state in {WorkflowTaskState.COMPLETED, WorkflowTaskState.CANCELED}:
            continue
        checkpoint = task.effect_checkpoint
        if checkpoint is None:
            # The coordinator preserves unstarted and approval-waiting checkpoints.
            # Old snapshots marked every task FAILED; without a journal they remain unknown.
            if task.state in {WorkflowTaskState.PENDING, WorkflowTaskState.WAITING_APPROVAL}:
                continue
            reports[task_id] = {"status": "UNKNOWN", "reason": "no durable effect checkpoint"}
            unresolved = True
            continue
        status = EffectStatus.UNKNOWN
        updated = checkpoint
        if checkpoint["state"] in {"COMPLETED", "CONFIRMED", "NOT_EXECUTED"}:
            status = EffectStatus.NOT_EXECUTED if checkpoint["state"] == "NOT_EXECUTED" else EffectStatus.COMPLETED
        else:
            try:
                answer = resolver(run, task_id, _copy(checkpoint))
                valid = (isinstance(answer, EffectResolution) and isinstance(answer.status, EffectStatus)
                         and isinstance(answer.evidence, str) and 0 < len(answer.evidence.strip()) <= 4096
                         and answer.idempotency_key == checkpoint["idempotencyKey"]
                         and answer.invocation_digest == checkpoint["invocationDigest"])
                if valid and answer.status == EffectStatus.COMPLETED and isinstance(answer.result, Mapping):
                    updated = {**checkpoint, "state": "CONFIRMED", "result": _copy(answer.result),
                               "evidence": answer.evidence, "resolvedAt": _now()}
                    status = EffectStatus.COMPLETED
                elif valid and answer.status == EffectStatus.NOT_EXECUTED and answer.fenced is True:
                    status = EffectStatus.NOT_EXECUTED
                    updated = {**checkpoint, "state": "NOT_EXECUTED", "evidence": answer.evidence,
                               "resolvedAt": _now()}
            except Exception:
                # Endpoint failures and malformed/mismatched receipts do not authorize replay.
                status, updated = EffectStatus.UNKNOWN, checkpoint
        reports[task_id] = {"status": status.value, "idempotencyKey": checkpoint["idempotencyKey"],
                            "invocationDigest": checkpoint["invocationDigest"], "previousAttempts": task.attempts}
        unresolved |= status == EffectStatus.UNKNOWN
        tasks[task_id] = replace(task, effect_checkpoint=updated)
        ledger.append(
            "WORKFLOW_TASK_STATUS_UPDATED", tenant_id=run.tenant_id, trace_id=run.trace_id,
            span_id=f"workflow-{run.id}-{task_id}-reconcile", source_actor_id="interlock.run-control",
            payload={"runId": run.id, "taskId": task_id, "bundleDigest": run.bundle_digest,
                     "effectPhase": "reconciled", **reports[task_id]},
        )
    if not reports:
        unresolved = True
    if not unresolved:
        for task_id, task in tasks.items():
            if task.effect_checkpoint is not None and task.state != WorkflowTaskState.COMPLETED:
                tasks[task_id] = replace(task, state=WorkflowTaskState.PENDING, error_code=None,
                                        error_message=None, ended_at=None, attempts=0)
    recovered = replace(run, tasks=tasks, updated_at=_now(),
                        state=WorkflowRunState.FAILED if unresolved else WorkflowRunState.PENDING,
                        error_code="RUN-EFFECT-UNCERTAIN" if unresolved else None)
    run_store.recover_effects(run, recovered)
    return recovered, reports
