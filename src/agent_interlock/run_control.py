"""Deployment-bound workflow Run Control service.

The service never supplies simulated transports. A host must provide adapters
for every transport used by the promoted Architecture bundle. Tests may inject
fakes, while production wiring supplies real A2A, MCP, LOCAL, or HUMAN
adapters.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .architecture import (
    ArchitectureCompiler,
    CompiledArchitecture,
    OrchestrationTask,
    TaskTransport,
)
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
    ) -> None:
        if max_runs < 1:
            raise ValueError("max_runs must be positive")
        self.deployment_store = deployment_store
        self.adapter_provider = adapter_provider
        self.ledger = ledger or InMemoryLedger()
        self.run_store = run_store or InMemoryWorkflowRunStore(max_runs=max_runs)
        self.acceptance_evaluator = acceptance_evaluator
        self.max_runs = max_runs
        self._engines: dict[str, OrchestrationEngine] = {}
        self._bindings: dict[tuple[str, str], RunBinding] = {}
        self._run_order: list[tuple[str, str]] = []
        self._approvals: set[tuple[str, str, str]] = set()
        self._workers: dict[tuple[str, str], threading.Thread] = {}
        self._pending_resumes: set[tuple[str, str]] = set()
        self._lock = threading.RLock()

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
            if len(self._bindings) >= self.max_runs:
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
            key = (tenant_id, run.id)
            self._bindings[key] = RunBinding(tenant_id, digest, engine)
            self._run_order.append(key)
            value = self._public_run(run, digest)
            self._resume_async_locked(tenant_id, run.id)
            return value

    def get(self, *, tenant_id: str, run_id: str) -> dict[str, Any]:
        with self._lock:
            binding = self._binding(tenant_id, run_id)
            run = binding.engine.get(tenant_id=tenant_id, run_id=run_id)
            return self._public_run(run, binding.bundle_digest)

    def list(self, *, tenant_id: str) -> tuple[dict[str, Any], ...]:
        with self._lock:
            result: list[dict[str, Any]] = []
            for run_tenant_id, run_id in reversed(self._run_order):
                if run_tenant_id != tenant_id:
                    continue
                binding = self._bindings[(run_tenant_id, run_id)]
                run = binding.engine.get(tenant_id=tenant_id, run_id=run_id)
                result.append(self._public_run(run, binding.bundle_digest))
            return tuple(result)

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

    def approve(self, *, tenant_id: str, run_id: str, task_id: str, approved_by: str) -> dict[str, Any]:
        with self._lock:
            binding = self._binding(tenant_id, run_id)
            run = binding.engine.get(tenant_id=tenant_id, run_id=run_id)
            task = run.tasks.get(task_id)
            spec = next((item for item in binding.engine.definition.tasks if item.id == task_id), None)
            if task is None or spec is None:
                raise RunControlError(404, "RUN-TASK-NOT-FOUND", "workflow task was not found")
            if not spec.approval_required:
                raise RunControlError(409, "RUN-TASK-APPROVAL-NOT-REQUIRED", "task does not require approval")
            if task.state != WorkflowTaskState.WAITING_APPROVAL:
                raise RunControlError(409, "RUN-TASK-NOT-WAITING", "task is not waiting for approval")
            approval_key = (tenant_id, run_id, task_id)
            if approval_key not in self._approvals:
                self._approvals.add(approval_key)
                self.ledger.append(
                    "WORKFLOW_TASK_APPROVED",
                    tenant_id=tenant_id,
                    trace_id=run.trace_id,
                    span_id=f"workflow-{run.id}-{task_id}-approval",
                    source_actor_id=approved_by,
                    target_actor_id=binding.engine.definition.coordinator_actor_id,
                    relationship_type="ROUTES",
                    relationship_id="REL-02",
                    payload={"runId": run.id, "taskId": task_id, "approvedBy": approved_by},
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
            binding = self._binding(tenant_id, run_id)
            run = binding.engine.get(tenant_id=tenant_id, run_id=run_id)
            return tuple(event.to_dict() for event in self.ledger.trace(tenant_id, run.trace_id))

    def _engine_for_active_bundle(self) -> tuple[str, OrchestrationEngine]:
        active = self.deployment_store.active()
        if active is None or active.get("mode") != "ENFORCE":
            raise RunControlError(409, "RUN-ACTIVE-DEPLOYMENT-REQUIRED", "an ENFORCE deployment is required")
        digest = active.get("bundleDigest")
        if not isinstance(digest, str) or not digest:
            raise RunControlError(422, "RUN-ACTIVE-DEPLOYMENT-INVALID", "active deployment digest is invalid")
        cached = self._engines.get(digest)
        if cached is not None:
            return digest, cached
        bundle = self.deployment_store.bundle(digest)
        active_mode = active["mode"]
        architecture = bundle.body.get("architecture")
        if not isinstance(architecture, Mapping):
            raise RunControlError(
                422,
                "RUN-ARCHITECTURE-MISSING",
                "active bundle does not contain an executable architecture",
            )
        try:
            graph = deployed_architecture(bundle.body, active_mode)
            compiled = ArchitectureCompiler().compile(graph)
            adapters = dict(self.adapter_provider(compiled))
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
        if missing:
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
        )
        self._engines[digest] = engine
        return digest, engine

    def _binding(self, tenant_id: str, run_id: str) -> RunBinding:
        binding = self._bindings.get((tenant_id, run_id))
        if binding is None:
            raise RunControlError(404, "RUN-NOT-FOUND", "run is not visible to this tenant")
        return binding

    def _resume_async_locked(self, tenant_id: str, run_id: str) -> None:
        key = (tenant_id, run_id)
        worker = self._workers.get(key)
        if worker is not None and worker.is_alive():
            self._pending_resumes.add(key)
            return
        binding = self._bindings[key]
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
                if key in self._pending_resumes:
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
            return (tenant_id, run_id, task.id) in self._approvals

    @staticmethod
    def _public_run(run: WorkflowRun, bundle_digest: str) -> dict[str, Any]:
        value = redact_payload(run.to_dict())
        value["bundleDigest"] = bundle_digest
        return value
