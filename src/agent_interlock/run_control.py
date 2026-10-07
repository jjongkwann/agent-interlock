"""Deployment-bound workflow Run Control service.

The service never supplies simulated transports. A host must provide adapters
for every transport used by the promoted Architecture bundle. Tests may inject
fakes, while production wiring supplies real A2A, MCP, LOCAL, or HUMAN
adapters.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from .architecture import (
    ArchitectureCompiler,
    CompiledArchitecture,
    OrchestrationTask,
    TaskTransport,
)
from .canonical import canonical_digest
from .ledger import InMemoryLedger, Ledger, redact_payload
from .orchestration import (
    AcceptanceEvaluator,
    InMemoryWorkflowRunStore,
    OrchestrationEngine,
    OrchestrationError,
    OrchestrationTaskAdapter,
    WorkflowRun,
    WorkflowRunState,
    WorkflowRunStore,
    WorkflowTaskState,
    _now,
)
from .studio_deploy import GitBundleStore, deployed_architecture

AdapterProvider = Callable[[CompiledArchitecture], Mapping[TaskTransport, OrchestrationTaskAdapter]]


class RunControlError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class RunBinding:
    tenant_id: str
    bundle_digest: str
    engine: OrchestrationEngine


class RunControlService:
    """Start and operate runs against the exact active deployment bundle."""

    def __init__(
        self,
        deployment_store: GitBundleStore,
        adapter_provider: AdapterProvider,
        *,
        ledger: Ledger | None = None,
        run_store: WorkflowRunStore | None = None,
        acceptance_evaluator: AcceptanceEvaluator | None = None,
        max_runs: int = 1024,
        dispatcher: Any = None,
    ) -> None:
        if max_runs < 1:
            raise ValueError("max_runs must be positive")
        self.deployment_store = deployment_store
        self.adapter_provider = adapter_provider
        self.ledger = ledger or InMemoryLedger()
        self.run_store = run_store or InMemoryWorkflowRunStore(max_runs=max_runs)
        self.acceptance_evaluator = acceptance_evaluator
        self.max_runs = max_runs
        self.dispatcher = dispatcher
        self._engines: dict[str, OrchestrationEngine] = {}
        self._workers: dict[tuple[str, str], threading.Thread] = {}
        self._pending_resumes: set[tuple[str, str]] = set()
        self._lock = threading.RLock()
        self._closed = False
        if self.dispatcher is not None:
            # Remote ownership survives coordinator restart until its durable lease expires.
            self.dispatcher.recover()
            return
        # One host owns dispatch. Never replay an interrupted side effect on restart.
        for run in self.run_store.list():
            if run.state == WorkflowRunState.RUNNING:
                interrupted = replace(
                    run,
                    state=WorkflowRunState.FAILED,
                    error_code="RUN-INTERRUPTED",
                    updated_at=_now(),
                    tasks={
                        key: replace(task, state=WorkflowTaskState.FAILED, error_code="RUN-INTERRUPTED")
                        if task.state == WorkflowTaskState.RUNNING
                        else task
                        for key, task in run.tasks.items()
                    },
                )
                self.ledger.append(
                    "WORKFLOW_RUN_FAILED",
                    tenant_id=run.tenant_id,
                    trace_id=run.trace_id,
                    span_id=f"workflow-{run.id}-recovery",
                    source_actor_id="interlock.run-control",
                    payload={"runId": run.id, "bundleDigest": run.bundle_digest, "reasonCode": "RUN-INTERRUPTED"},
                    idempotency_key=f"workflow-recovery:{run.id}",
                )
                self.run_store.save(interrupted)

    def create(
        self,
        *,
        tenant_id: str,
        workflow_input: Mapping[str, Any],
        run_id: str | None = None,
        trace_id: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(workflow_input, Mapping):
            raise RunControlError(400, "RUN-INPUT-INVALID", "input must be a JSON object")
        with self._lock:
            if self._closed:
                raise RunControlError(503, "RUN-HOST-CLOSED", "run control host is closing")
            if self.dispatcher is not None:
                self.dispatcher.recover()
            if (
                sum(
                    run.state not in {WorkflowRunState.COMPLETED, WorkflowRunState.FAILED, WorkflowRunState.CANCELED}
                    for run in self.run_store.list()
                )
                >= self.max_runs
            ):
                raise RunControlError(503, "RUN-CAPACITY", "run control is at capacity")
            digest, engine = self._engine_for_active_bundle()
            try:
                run = engine.create(
                    tenant_id=tenant_id,
                    workflow_input=workflow_input,
                    run_id=run_id,
                    trace_id=trace_id,
                )
            except OrchestrationError as error:
                status = 409 if error.reason_code == "ORCH-RUN-DUPLICATE" else 503
                raise RunControlError(status, error.reason_code, str(error)) from error
            value = self._public_run(run, digest)
            self._resume_async_locked(tenant_id, run.id)
            return value

    def get(self, *, tenant_id: str, run_id: str) -> dict[str, Any]:
        with self._lock:
            if self.dispatcher is not None:
                self.dispatcher.recover()
            run = self._get_run(tenant_id, run_id)
            return self._public_run(run, run.bundle_digest)

    def list(self, *, tenant_id: str) -> tuple[dict[str, Any], ...]:
        with self._lock:
            if self.dispatcher is not None:
                self.dispatcher.recover()
            return tuple(self._public_run(run, run.bundle_digest) for run in self.run_store.list(tenant_id=tenant_id))

    def prune(self, *, tenant_id: str, before: str) -> int:
        """Explicitly remove terminal snapshots; Ledger evidence and bundles are retained."""
        with self._lock:
            removed = self.run_store.prune(tenant_id=tenant_id, before=before)
            digests = {run.bundle_digest for run in self.run_store.list()}
            self._engines = {key: engine for key, engine in self._engines.items() if key in digests}
            return removed

    def close(self, *, timeout: float = 10) -> bool:
        """Stop accepting work and wait briefly; interrupted adapters recover as FAILED."""
        with self._lock:
            self._closed = True
            workers = tuple(self._workers.values())
        deadline = time.monotonic() + max(0, timeout)
        for worker in workers:
            worker.join(timeout=max(0, deadline - time.monotonic()))
        return all(not worker.is_alive() for worker in workers)

    def edge_modes(self, *, tenant_id: str, run_id: str) -> dict[str, str]:
        """Read-only view of the compiled edge policy modes bound to one run.

        Reflects what Run Control actually enforces after applying the
        deployment record's mode (D5), not the manifest's authored modes.
        """
        with self._lock:
            binding = self._binding(tenant_id, run_id)
            return {edge_id: policy.mode.value for edge_id, policy in binding.engine.architecture.links.items()}

    def resume(self, *, tenant_id: str, run_id: str) -> dict[str, Any]:
        with self._lock:
            binding = self._binding(tenant_id, run_id)
            run = binding.engine.get(tenant_id=tenant_id, run_id=run_id)
            if run.state in {WorkflowRunState.COMPLETED, WorkflowRunState.FAILED, WorkflowRunState.CANCELED}:
                return self._public_run(run, binding.bundle_digest)
            self._resume_async_locked(tenant_id, run_id)
            return self._public_run(run, binding.bundle_digest)

    def approve(
        self, *, tenant_id: str, run_id: str, task_id: str, approved_by: str, request_id: str | None = None
    ) -> dict[str, Any]:
        with self._lock:
            binding = self._binding(tenant_id, run_id)
            run = binding.engine.get(tenant_id=tenant_id, run_id=run_id)
            task = run.tasks.get(task_id)
            spec = next((item for item in binding.engine.definition.tasks if item.id == task_id), None)
            if task is None or spec is None:
                raise RunControlError(404, "RUN-TASK-NOT-FOUND", "workflow task was not found")
            if not spec.approval_required and not task.pending_call:
                raise RunControlError(409, "RUN-TASK-APPROVAL-NOT-REQUIRED", "task does not require approval")
            if task.state != WorkflowTaskState.WAITING_APPROVAL:
                raise RunControlError(409, "RUN-TASK-NOT-WAITING", "task is not waiting for approval")
            approval_key = task_id
            if task.pending_call:
                expected = canonical_digest({k: v for k, v in task.pending_call.items() if k != "requestId"})
                if request_id != expected or task.pending_call.get("requestId") != expected:
                    raise RunControlError(
                        409, "RUN-APPROVAL-STALE", "approval must match the pending invocation requestId"
                    )
                approval_key = f"{task_id}:{expected}"
                if approval_key in run.tasks:
                    raise RunControlError(
                        409,
                        "RUN-APPROVAL-SCOPE-COLLISION",
                        "a task ID overlaps this invocation approval; rename the conflicting task",
                    )
            elif request_id is not None:
                raise RunControlError(409, "RUN-APPROVAL-STALE", "task has no matching pending invocation")
            if approval_key not in run.approvals:
                self.ledger.append(
                    "WORKFLOW_TASK_APPROVED",
                    tenant_id=tenant_id,
                    trace_id=run.trace_id,
                    span_id=f"workflow-{run.id}-{task_id}-approval",
                    source_actor_id=approved_by,
                    target_actor_id=binding.engine.definition.coordinator_actor_id,
                    relationship_type="ROUTES",
                    relationship_id="REL-02",
                    payload={
                        "runId": run.id,
                        "taskId": task_id,
                        "approvedBy": approved_by,
                        "bundleDigest": run.bundle_digest,
                        "requestId": request_id,
                    },
                    idempotency_key="workflow-approval:" + canonical_digest([tenant_id, run_id, approval_key]),
                )
                run = self.run_store.approve(
                    tenant_id=tenant_id, run_id=run_id, task_id=approval_key, approved_by=approved_by
                )
            self._resume_async_locked(tenant_id, run_id)
            return self._public_run(run, binding.bundle_digest)

    def cancel(self, *, tenant_id: str, run_id: str) -> dict[str, Any]:
        with self._lock:
            binding = self._binding(tenant_id, run_id)
            run = binding.engine.cancel(tenant_id=tenant_id, run_id=run_id)
            return self._public_run(run, binding.bundle_digest)

    def events(self, *, tenant_id: str, run_id: str) -> tuple[dict[str, Any], ...]:
        with self._lock:
            run = self._get_run(tenant_id, run_id)
            return tuple(event.to_dict() for event in self.ledger.trace(tenant_id, run.trace_id))

    def _engine_for_active_bundle(self) -> tuple[str, OrchestrationEngine]:
        active = self.deployment_store.active()
        if active is None or active.get("mode") != "ENFORCE":
            raise RunControlError(409, "RUN-ACTIVE-DEPLOYMENT-REQUIRED", "an ENFORCE deployment is required")
        digest = active.get("bundleDigest")
        if not isinstance(digest, str) or not digest:
            raise RunControlError(422, "RUN-ACTIVE-DEPLOYMENT-INVALID", "active deployment digest is invalid")
        return digest, self._engine_for_bundle(digest)

    def _engine_for_bundle(self, digest: str) -> OrchestrationEngine:
        cached = self._engines.get(digest)
        if cached is not None:
            return cached
        bundle = self.deployment_store.bundle(digest)
        active_mode = "ENFORCE"
        architecture = bundle.body.get("architecture")
        if not isinstance(architecture, Mapping):
            raise RunControlError(
                422,
                "RUN-ARCHITECTURE-MISSING",
                "active bundle does not contain an executable architecture",
            )
        try:
            graph = deployed_architecture(bundle.body, active_mode)
            compiled = replace(ArchitectureCompiler().compile(graph), bundle_digest=digest)
            adapters = dict(self.adapter_provider(compiled)) if self.dispatcher is None else {}
        except RunControlError:
            raise
        except Exception as error:
            raise RunControlError(422, "RUN-ARCHITECTURE-INVALID", "active architecture cannot be loaded") from error
        # No mode check follows: `deployed_architecture` sets every edge policy to the record's
        # mode and the compiler carries a policy's mode through untouched, so a disagreement is
        # unreachable here. A guard for it would be a check that can never fire, which reads like
        # a control and is not one. An unparseable mode raises inside the try above and surfaces
        # as RUN-ARCHITECTURE-INVALID.
        definition = compiled.graph.orchestration
        if definition is None:
            raise RunControlError(422, "RUN-WORKFLOW-MISSING", "active architecture has no workflow")
        required = {task.transport for task in definition.tasks}
        missing = sorted(item.value for item in required if item not in adapters)
        if missing and self.dispatcher is None:
            raise RunControlError(
                503,
                "RUN-ADAPTER-MISSING",
                f"runtime adapters are not configured for: {', '.join(missing)}",
            )
        engine = OrchestrationEngine(
            compiled,
            adapters=adapters,
            run_store=self.run_store,
            approval_provider=self._is_approved,
            acceptance_evaluator=self.acceptance_evaluator,
            ledger=self.ledger,
            bundle_digest=digest,
        )
        self._engines[digest] = engine
        return engine

    def _get_run(self, tenant_id: str, run_id: str) -> WorkflowRun:
        try:
            return self.run_store.get(tenant_id=tenant_id, run_id=run_id)
        except OrchestrationError as error:
            raise RunControlError(404, "RUN-NOT-FOUND", "run is not visible to this tenant") from error

    def _binding(self, tenant_id: str, run_id: str) -> RunBinding:
        run = self._get_run(tenant_id, run_id)
        if not run.bundle_digest:
            raise RunControlError(409, "RUN-BUNDLE-MISSING", "run has no deployment binding")
        return RunBinding(tenant_id, run.bundle_digest, self._engine_for_bundle(run.bundle_digest))

    def _resume_async_locked(self, tenant_id: str, run_id: str) -> None:
        if self._closed:
            raise RunControlError(503, "RUN-HOST-CLOSED", "run control host is closing")
        if self.dispatcher is not None:
            self.dispatcher.enqueue(tenant_id, run_id)
            return
        key = (tenant_id, run_id)
        worker = self._workers.get(key)
        if worker is not None and worker.is_alive():
            self._pending_resumes.add(key)
            return
        binding = self._binding(tenant_id, run_id)
        worker = threading.Thread(
            target=self._resume_worker,
            args=(key, binding),
            daemon=True,
            name=f"interlock-run-{run_id}",
        )
        self._workers[key] = worker
        worker.start()

    def _resume_worker(self, key: tuple[str, str], binding: RunBinding) -> None:
        _, run_id = key
        while True:
            try:
                binding.engine.resume(tenant_id=binding.tenant_id, run_id=run_id)
            except Exception:  # noqa: BLE001 - unexpected worker failures become terminal evidence
                binding.engine.fail(
                    tenant_id=binding.tenant_id,
                    run_id=run_id,
                    reason_code="RUN-WORKER-FAILED",
                )
            with self._lock:
                if key in self._pending_resumes and not self._closed:
                    self._pending_resumes.remove(key)
                    continue
                self._workers.pop(key, None)
                return

    def _is_approved(
        self,
        tenant_id: str,
        run_id: str,
        task: OrchestrationTask,
        _context: Mapping[str, Any],
    ) -> bool:
        with self._lock:
            return task.id in self._get_run(tenant_id, run_id).approvals

    @staticmethod
    def _public_run(run: WorkflowRun, bundle_digest: str | None) -> dict[str, Any]:
        value = redact_payload(run.to_dict())
        value["bundleDigest"] = bundle_digest
        return value
