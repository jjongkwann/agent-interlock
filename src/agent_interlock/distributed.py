"""Durable, fenced whole-run dispatch to authenticated cooperative workers.

An expired started lease is never replayed: its external effects may have committed.
Only a claim that has not started can be reassigned automatically.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from collections.abc import Mapping
from dataclasses import asdict, replace

from .architecture import ArchitectureGraph
from .canonical import canonical_digest
from .configurable_runtime import RUNTIME_KEY, configured_definition, runtime_status
from .ledger import Event, verify_event
from .ledger_http import LedgerAPIError
from .models import DataSource, Environment
from .orchestration import _RUN_TERMINAL, WorkflowRunState, WorkflowTaskState, _now
from .workflow_store import SQLiteWorkflowRunStore, _decode

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_EVENTS = frozenset(
    {
        "WORKFLOW_RUN_STARTED",
        "WORKFLOW_RUN_WAITING_APPROVAL",
        "WORKFLOW_RUN_COMPLETED",
        "WORKFLOW_RUN_FAILED",
        "WORKFLOW_TASK_STATUS_UPDATED",
        "CONTROL_EVALUATED",
        "CONTROL_COVERAGE_DECLARED",
        "INTERACTION_REQUESTED",
        "ACTION_EXECUTED",
        "INTERACTION_COMPLETED",
        "DATA_FLOW_OBSERVED",
        "SECURITY_OUTCOME_SET",
    }
)


class DistributedCoordinator:
    def __init__(
        self,
        run_store: SQLiteWorkflowRunStore,
        deployment_store,
        ledger,
        *,
        worker_projects: Mapping[str, frozenset[str]],
        lease_seconds: float = 30,
    ):
        if not isinstance(run_store, SQLiteWorkflowRunStore):
            raise ValueError("distributed dispatch requires SQLiteWorkflowRunStore")
        if isinstance(lease_seconds, bool) or not 0.1 <= lease_seconds <= 3600:
            raise ValueError("lease_seconds must be between 0.1 and 3600")
        self.run_store, self.deployment_store, self.ledger = run_store, deployment_store, ledger
        self.worker_projects = {subject: frozenset(projects) for subject, projects in worker_projects.items()}
        self.lease_seconds = lease_seconds
        self._workers = {}
        self._lock = threading.RLock()
        self.recover()

    def _allowed(self, subject, project_id):
        grants = self.worker_projects.get(subject, ())
        return "*" in grants or project_id in grants

    def _prune_workers(self, connection):
        active = {
            tuple(row)
            for row in connection.execute(
                "SELECT tenant_id,subject,session FROM workflow_dispatch WHERE subject IS NOT NULL AND expires>?",
                (time.time(),),
            ).fetchall()
        }
        # Bound metadata to leased sessions plus one last report per enrolled worker.
        latest = {}
        for key, worker in sorted(self._workers.items(), key=lambda item: item[1]["lastSeen"], reverse=True):
            latest.setdefault(key[:2], key)
        self._workers = {
            key: worker for key, worker in self._workers.items() if key in active or key == latest[key[:2]]
        }

    def _bundle(self, run):
        bundle = self.deployment_store.bundle(run.bundle_digest)
        graph = ArchitectureGraph.from_dict(bundle.body["architecture"])
        if graph.id != bundle.architecture_id:
            raise LedgerAPIError(409, "WORKER-BUNDLE-MISMATCH", "run bundle project identity is invalid")
        return bundle, graph

    def _uncertain(self, connection, run):
        if run.state in _RUN_TERMINAL:
            return
        failed = replace(
            run,
            state=WorkflowRunState.FAILED,
            error_code="RUN-EFFECT-UNCERTAIN",
            updated_at=_now(),
            tasks={
                key: replace(task, state=WorkflowTaskState.FAILED, error_code="RUN-EFFECT-UNCERTAIN", ended_at=_now())
                if task.state
                in {WorkflowTaskState.PENDING, WorkflowTaskState.RUNNING, WorkflowTaskState.WAITING_APPROVAL}
                else task
                for key, task in run.tasks.items()
            },
        )
        self.ledger.append(
            "WORKFLOW_RUN_FAILED",
            tenant_id=run.tenant_id,
            trace_id=run.trace_id,
            span_id=f"workflow-{run.id}-lease-recovery",
            source_actor_id="interlock.run-control",
            payload={
                "runId": run.id,
                "bundleDigest": run.bundle_digest,
                "reasonCode": "RUN-EFFECT-UNCERTAIN",
                "state": "FAILED",
            },
            idempotency_key="worker-recovery:" + canonical_digest([run.tenant_id, run.id, run.created_at]),
        )
        self.run_store._write(connection, failed)

    def recover(self):
        """Recover durable leases, without replaying work after the start boundary."""
        with self._lock, self.run_store._transaction() as connection:
            connection.row_factory = sqlite3.Row
            for row in connection.execute(
                "SELECT * FROM workflow_dispatch WHERE subject IS NOT NULL AND expires<=?", (time.time(),)
            ).fetchall():
                try:
                    run = self.run_store._get(connection, row["tenant_id"], row["run_id"])
                except Exception:
                    # Pruning can remove a finished run before its worker releases the lease.
                    if (
                        connection.execute(
                            "SELECT 1 FROM workflow_runs WHERE tenant_id=? AND run_id=?",
                            (row["tenant_id"], row["run_id"]),
                        ).fetchone()
                        is not None
                    ):
                        raise
                    connection.execute(
                        "UPDATE workflow_dispatch SET subject=NULL,session=NULL,expires=0,"
                        "started=0,queued=0 WHERE tenant_id=? AND run_id=?",
                        (row["tenant_id"], row["run_id"]),
                    )
                    continue
                if row["started"]:
                    self._uncertain(connection, run)
                queue = not row["started"] and run.state not in _RUN_TERMINAL
                connection.execute(
                    "UPDATE workflow_dispatch SET subject=NULL,session=NULL,expires=0,started=0,queued=? "
                    "WHERE tenant_id=? AND run_id=?",
                    (int(queue), run.tenant_id, run.id),
                )
            orphans = connection.execute(
                "SELECT body FROM workflow_runs r WHERE NOT EXISTS "
                "(SELECT 1 FROM workflow_dispatch d WHERE d.tenant_id=r.tenant_id "
                "AND d.run_id=r.run_id)"
            ).fetchall()
            for row in orphans:
                run = _decode(row["body"])
                if run.state == WorkflowRunState.RUNNING:
                    self._uncertain(connection, run)
                connection.execute(
                    "INSERT INTO workflow_dispatch (tenant_id,run_id,queued) VALUES (?,?,?)",
                    (run.tenant_id, run.id, int(run.state == WorkflowRunState.PENDING)),
                )
            connection.execute(
                "UPDATE workflow_dispatch SET queued=1 WHERE subject IS NULL AND EXISTS "
                "(SELECT 1 FROM workflow_runs r WHERE r.tenant_id=workflow_dispatch.tenant_id "
                "AND r.run_id=workflow_dispatch.run_id AND r.state='PENDING')"
            )
            self._prune_workers(connection)

    def enqueue(self, tenant_id, run_id):
        self.recover()
        with self._lock, self.run_store._transaction() as connection:
            run = self.run_store._get(connection, tenant_id, run_id)
            if run.state in _RUN_TERMINAL:
                return
            connection.execute(
                "INSERT INTO workflow_dispatch (tenant_id,run_id,queued,wakeup) VALUES (?,?,1,1) "
                "ON CONFLICT(tenant_id,run_id) DO UPDATE SET queued=1,wakeup=wakeup+1",
                (tenant_id, run_id),
            )

    def readiness(self, graph):
        with self._lock:
            candidates = [
                (subject, worker)
                for (tenant, subject, _session), worker in self._workers.items()
                if tenant == self.deployment_store.tenant_id
                and self._allowed(subject, graph.id)
                and worker["lastSeen"] > time.time() - self.lease_seconds * 2
            ]
        reports = [(subject, runtime_status(graph, worker["credentialRefs"])) for subject, worker in candidates]
        eligible = sorted({subject for subject, report in reports if report["ready"]})
        report = next((report for _, report in reports if report["ready"]), runtime_status(graph))
        return {
            **report,
            "ready": bool(eligible),
            "eligibleWorkers": eligible,
            "problems": report["problems"] + ([] if eligible else ["no online authorized worker is ready"]),
        }

    def status(self, tenant_id):
        self.recover()
        with self._lock, self.run_store._transaction() as connection:
            workers = []
            for subject, projects in self.worker_projects.items():
                sessions = [
                    {
                        "sessionId": session,
                        **worker,
                        "online": worker["lastSeen"] > time.time() - self.lease_seconds * 2,
                    }
                    for (tenant, owner, session), worker in self._workers.items()
                    if tenant == tenant_id and owner == subject
                ]
                latest = max(
                    sessions,
                    key=lambda worker: worker["lastSeen"],
                    default={"credentialRefs": [], "lastSeen": 0, "online": False},
                )
                workers.append({"workerId": subject, "projects": sorted(projects), **latest, "sessions": sessions})
            queue = connection.execute(
                "SELECT SUM(queued=1 AND subject IS NULL),SUM(subject IS NOT NULL) "
                "FROM workflow_dispatch WHERE tenant_id=?",
                (tenant_id,),
            ).fetchone()
        return {
            "workers": workers,
            "queue": {"pending": queue[0] or 0, "leased": queue[1] or 0},
            "leaseSeconds": self.lease_seconds,
        }

    def api(self, principal, action, value):
        if "worker:execute" not in principal.scopes or principal.subject not in self.worker_projects:
            raise LedgerAPIError(403, "WORKER-ACCESS-DENIED", "worker execution permission is required")
        if principal.tenant_id != self.deployment_store.tenant_id:
            raise LedgerAPIError(403, "WORKER-TENANT-DENIED", "worker belongs to another deployment tenant")
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("sessionId"), str)
            or not _IDENTIFIER.fullmatch(value["sessionId"])
        ):
            raise LedgerAPIError(400, "WORKER-REQUEST-INVALID", "a safe worker sessionId is required")
        self.recover()
        with self._lock, self.run_store._transaction() as connection:
            connection.row_factory = sqlite3.Row
            if action == "claim":
                return self._claim(connection, principal, value)
            extra = {"save": {"revision", "run"}, "append": {"event"}}.get(action, set())
            if action not in {"start", "heartbeat", "get", "save", "append", "trace", "finish"}:
                raise LedgerAPIError(404, "WORKER-ROUTE-NOT-FOUND", "worker action does not exist")
            if (
                set(value) != {"runId", "sessionId", "fence"} | extra
                or not isinstance(value["runId"], str)
                or type(value["fence"]) is not int
            ):
                raise LedgerAPIError(400, "WORKER-REQUEST-INVALID", "worker action fields are invalid")
            row = connection.execute(
                "SELECT * FROM workflow_dispatch WHERE tenant_id=? AND run_id=?", (principal.tenant_id, value["runId"])
            ).fetchone()
            if (
                row is None
                or row["subject"] != principal.subject
                or row["session"] != value["sessionId"]
                or row["fence"] != value["fence"]
                or row["expires"] <= time.time()
            ):
                raise LedgerAPIError(409, "WORKER-LEASE-LOST", "worker lease is no longer owned")
            run = self.run_store._get(connection, principal.tenant_id, value["runId"])
            _, graph = self._bundle(run)
            if not self._allowed(principal.subject, graph.id):
                raise LedgerAPIError(403, "WORKER-PROJECT-DENIED", "worker cannot access this project")
            if action == "start":
                if run.state in _RUN_TERMINAL:
                    raise LedgerAPIError(409, "WORKER-RUN-TERMINAL", "run is already terminal")
                connection.execute(
                    "UPDATE workflow_dispatch SET started=1 WHERE tenant_id=? AND run_id=?", (run.tenant_id, run.id)
                )
                return {}
            if action == "heartbeat":
                expiry = time.time() + self.lease_seconds
                connection.execute(
                    "UPDATE workflow_dispatch SET expires=? WHERE tenant_id=? AND run_id=?",
                    (expiry, run.tenant_id, run.id),
                )
                self._workers.get((principal.tenant_id, principal.subject, value["sessionId"]), {}).update(
                    lastSeen=time.time()
                )
                return {"expiresAt": expiry, "canceled": run.state == WorkflowRunState.CANCELED}
            if action == "get":
                return self._snapshot(connection, run)
            if not row["started"]:
                raise LedgerAPIError(409, "WORKER-START-REQUIRED", "durable start is required before execution")
            if action == "save":
                return self._save(connection, run, value)
            if action == "append":
                return {"event": self._append(run, graph, value["event"]).to_dict()}
            if action == "trace":
                return {
                    "events": [
                        event.to_dict()
                        for event in self.ledger.trace(run.tenant_id, run.trace_id)
                        if event.payload.get("workflowRunId") == run.id or event.payload.get("runId") == run.id
                    ]
                }
            if run.state == WorkflowRunState.RUNNING or run.state == WorkflowRunState.PENDING:
                raise LedgerAPIError(409, "WORKER-FINISH-NOT-READY", "run must finish or wait for approval")
            queue = run.state == WorkflowRunState.WAITING_APPROVAL and row["wakeup"] > row["claimed_wakeup"]
            connection.execute(
                "UPDATE workflow_dispatch SET subject=NULL,session=NULL,expires=0,started=0,queued=? "
                "WHERE tenant_id=? AND run_id=?",
                (int(queue), run.tenant_id, run.id),
            )
            return {}

    def _claim(self, connection, principal, value):
        refs = value.get("credentialRefs")
        if (
            set(value) != {"sessionId", "credentialRefs"}
            or not isinstance(refs, list)
            or len(refs) > 256
            or any(not isinstance(ref, str) or not _IDENTIFIER.fullmatch(ref) for ref in refs)
        ):
            raise LedgerAPIError(400, "WORKER-REQUEST-INVALID", "claim requires credential reference names")
        self._workers[(principal.tenant_id, principal.subject, value["sessionId"])] = {
            "credentialRefs": sorted(set(refs)),
            "lastSeen": time.time(),
        }
        self._prune_workers(connection)
        rows = connection.execute(
            "SELECT d.* FROM workflow_dispatch d JOIN workflow_runs r "
            "ON d.tenant_id=r.tenant_id AND d.run_id=r.run_id "
            "WHERE d.tenant_id=? AND d.queued=1 AND d.subject IS NULL "
            "AND r.state IN ('PENDING','WAITING_APPROVAL') ORDER BY r.updated_at,r.run_id",
            (principal.tenant_id,),
        ).fetchall()
        for row in rows:
            run = self.run_store._get(connection, principal.tenant_id, row["run_id"])
            bundle, graph = self._bundle(run)
            if not self._allowed(principal.subject, graph.id) or not runtime_status(graph, refs)["ready"]:
                continue
            expiry, fence = time.time() + self.lease_seconds, row["fence"] + 1
            connection.execute(
                "UPDATE workflow_dispatch SET subject=?,session=?,fence=?,expires=?,started=0,queued=0,"
                "claimed_wakeup=wakeup WHERE tenant_id=? AND run_id=?",
                (principal.subject, value["sessionId"], fence, expiry, run.tenant_id, run.id),
            )
            return {
                "claim": {
                    "tenantId": run.tenant_id,
                    "runId": run.id,
                    "owner": value["sessionId"],
                    "workerId": principal.subject,
                    "fence": fence,
                    "expiresAt": expiry,
                    "leaseSeconds": self.lease_seconds,
                    "targetId": self.deployment_store.target_id,
                    "bundleDigest": run.bundle_digest,
                    "bundle": dict(bundle.body),
                    **self._snapshot(connection, run),
                }
            }
        return {"claim": None}

    @staticmethod
    def _snapshot(connection, run):
        revision = connection.execute(
            "SELECT revision FROM workflow_runs WHERE tenant_id=? AND run_id=?", (run.tenant_id, run.id)
        ).fetchone()[0]
        return {"run": asdict(run), "revision": revision}

    def _save(self, connection, prior, value):
        snapshot = self._snapshot(connection, prior)
        if type(value["revision"]) is not int or value["revision"] != snapshot["revision"]:
            raise LedgerAPIError(
                409, "WORKER-REVISION-CONFLICT", "run revision changed; read the authoritative snapshot"
            )
        raw = value["run"]
        if (
            not isinstance(raw, dict)
            or set(raw) != set(snapshot["run"])
            or not isinstance(raw.get("tasks"), dict)
            or not isinstance(raw.get("approvals"), dict)
            or not isinstance(raw.get("workflow_input"), dict)
            or type(raw.get("messages_used")) is not int
            or raw["messages_used"] < prior.messages_used
            or any(not isinstance(task, dict) for task in raw["tasks"].values())
        ):
            raise LedgerAPIError(400, "WORKER-SNAPSHOT-INVALID", "run snapshot fields are invalid")
        try:
            run = _decode(json.dumps(value["run"], allow_nan=False))
        except (ValueError, TypeError, KeyError) as error:
            raise LedgerAPIError(400, "WORKER-SNAPSHOT-INVALID", "run snapshot is invalid") from error
        immutable = (
            "id",
            "tenant_id",
            "architecture_id",
            "architecture_version",
            "bundle_digest",
            "trace_id",
            "workflow_input",
            "created_at",
        )
        unchanged = json.dumps({field: getattr(run, field) for field in immutable}, sort_keys=True, allow_nan=False)
        expected = json.dumps({field: getattr(prior, field) for field in immutable}, sort_keys=True, allow_nan=False)
        if (
            unchanged != expected
            or set(run.tasks) != set(prior.tasks)
            or any(task.task_id != key for key, task in run.tasks.items())
            or any(prior.approvals.get(key) != approver for key, approver in run.approvals.items())
        ):
            raise LedgerAPIError(
                403, "WORKER-SNAPSHOT-FORBIDDEN", "worker cannot change run identity, tasks or approvals"
            )
        if prior.state in _RUN_TERMINAL:
            return snapshot
        if run.state == WorkflowRunState.CANCELED:
            raise LedgerAPIError(403, "WORKER-SNAPSHOT-FORBIDDEN", "only the control plane may cancel a run")
        _, graph = self._bundle(run)
        if run.messages_used > graph.orchestration.run_policy.max_messages:
            raise LedgerAPIError(400, "WORKER-SNAPSHOT-INVALID", "run exceeded its message budget")
        specs = {task.id: task for task in graph.orchestration.tasks}
        for key, task in run.tasks.items():
            old = prior.tasks[key]
            if (
                type(task.attempts) is not int
                or not 0 <= task.attempts <= specs[key].max_attempts
                or not isinstance(task.output, dict)
                or type(task.executed) is not bool
                or task.goal_met is not None
                and type(task.goal_met) is not bool
                or task.security_met is not None
                and type(task.security_met) is not bool
                or task.pending_call is not None
                and not isinstance(task.pending_call, dict)
            ):
                raise LedgerAPIError(400, "WORKER-SNAPSHOT-INVALID", "task snapshot fields are invalid")
            if old.state in {WorkflowTaskState.COMPLETED, WorkflowTaskState.SKIPPED, WorkflowTaskState.CANCELED}:
                if task != old:
                    raise LedgerAPIError(403, "WORKER-SNAPSHOT-FORBIDDEN", "completed task checkpoints are immutable")
            if task.pending_call:
                pending = task.pending_call
                if not isinstance(pending, dict) or pending.get("requestId") != canonical_digest(
                    {k: v for k, v in pending.items() if k != "requestId"}
                ):
                    raise LedgerAPIError(
                        400, "WORKER-PENDING-CALL-INVALID", "pending approval must match its request ID"
                    )
        self.run_store._write(connection, replace(run, approvals=prior.approvals, updated_at=_now()))
        return self._snapshot(connection, self.run_store._get(connection, prior.tenant_id, prior.id))

    def _append(self, run, graph, value):
        try:
            event = Event(**value)
            valid = verify_event(event)
        except (TypeError, ValueError) as error:
            raise LedgerAPIError(400, "WORKER-EVENT-INVALID", "worker event envelope is invalid") from error
        payload = event.payload
        if (
            not valid
            or event.event_type not in _EVENTS
            or event.tenant_id != run.tenant_id
            or event.trace_id != run.trace_id
            or not isinstance(payload, Mapping)
            or any(payload[key] != run.id for key in ("runId", "workflowRunId") if key in payload)
            or payload.get("bundleDigest", run.bundle_digest) != run.bundle_digest
        ):
            raise LedgerAPIError(403, "WORKER-EVENT-FORBIDDEN", "worker event is outside its run scope")
        tasks = {task.id: task for task in graph.orchestration.tasks}
        task_id = payload.get("workflowTaskId", payload.get("taskId"))
        if task_id is not None:
            task = tasks.get(task_id)
            if task is None or "taskId" in payload and payload["taskId"] != task_id:
                raise LedgerAPIError(403, "WORKER-EVENT-FORBIDDEN", "event task is outside its run scope")
            source = graph.node_map[task.source_actor_id]
            runtime = source.annotations.get(RUNTIME_KEY, {})
            targets = set(runtime.get("toolActorIds", [task.target_actor_id]))
            targets.add(task.target_actor_id)
            if runtime.get("providerActorId"):
                targets.add(runtime["providerActorId"])
            actor_pair = event.source_actor_id == task.source_actor_id and event.target_actor_id in targets
            definition_pair = False
            if event.event_type == "CONTROL_EVALUATED" and "toolDefinition" in payload:
                for target in targets:
                    node = graph.node_map.get(target)
                    config = node.annotations.get(RUNTIME_KEY) if node else None
                    if not config or config.get("kind") == "ANTHROPIC":
                        continue
                    definition = configured_definition(node)
                    definition_pair |= (
                        event.source_actor_id == definition.server_id
                        and event.target_actor_id == definition.tool_id
                        and payload["toolDefinition"].get("observedDigest") == node.actor.definition_digest
                    )
            if not actor_pair and not definition_pair:
                raise LedgerAPIError(
                    403, "WORKER-EVENT-FORBIDDEN", "event actors are outside the task's reviewed scope"
                )
        elif (
            not event.event_type.startswith("WORKFLOW_RUN_")
            or event.source_actor_id != graph.orchestration.coordinator_actor_id
            or event.target_actor_id is not None
        ):
            raise LedgerAPIError(403, "WORKER-EVENT-FORBIDDEN", "task correlation is required for worker evidence")
        fields = {
            key: getattr(event, key)
            for key in (
                "tenant_id",
                "trace_id",
                "span_id",
                "source_actor_id",
                "target_actor_id",
                "interaction_id",
                "parent_span_id",
                "relationship_type",
                "relationship_id",
                "severity",
            )
        }
        return self.ledger.append(
            event.event_type,
            **fields,
            payload={**payload, "workflowRunId": run.id, "bundleDigest": run.bundle_digest},
            environment=Environment(event.environment),
            data_source=DataSource(event.data_source),
            idempotency_key="worker-event:" + canonical_digest([run.id, run.created_at, event.event_id]),
        )
