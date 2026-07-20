"""Bounded task-graph orchestration with pluggable transports and A2A support."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from .a2a import (
    A2ABroker,
    A2AMessage,
    A2AMessageRole,
    A2APart,
    A2APrincipal,
    A2ASendContext,
    A2ATaskState,
)
from .architecture import (
    CompiledArchitecture,
    OrchestrationTask,
    TaskFailureAction,
    TaskTransport,
)
from .ledger import InMemoryLedger, Ledger


class OrchestrationError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class WorkflowRunState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class WorkflowTaskState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    CANCELED = "CANCELED"


_RUN_TERMINAL = {WorkflowRunState.COMPLETED, WorkflowRunState.FAILED, WorkflowRunState.CANCELED}
_TASK_TERMINAL = {
    WorkflowTaskState.COMPLETED,
    WorkflowTaskState.FAILED,
    WorkflowTaskState.SKIPPED,
    WorkflowTaskState.CANCELED,
}


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class TaskExecutionInput:
    run_id: str
    tenant_id: str
    trace_id: str
    task: OrchestrationTask
    workflow_input: Mapping[str, Any]
    dependency_outputs: Mapping[str, Mapping[str, Any]]
    attempt: int
    deadline_epoch: float


@dataclass(frozen=True, slots=True)
class TaskExecutionResult:
    output: Mapping[str, Any]
    external_task_id: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)


class OrchestrationTaskAdapter(Protocol):
    def execute(self, value: TaskExecutionInput) -> TaskExecutionResult: ...


PrincipalProvider = Callable[[OrchestrationTask, str, str], A2APrincipal]
ApprovalProvider = Callable[[str, str, OrchestrationTask, Mapping[str, Any]], bool]
AcceptanceEvaluator = Callable[[OrchestrationTask, TaskExecutionResult], tuple[bool, str | None]]


class A2AOrchestrationAdapter:
    """Turns a workflow task into a policy-bound A2A ``message/send`` call."""

    def __init__(self, broker: A2ABroker, principal_provider: PrincipalProvider) -> None:
        self.broker = broker
        self.principal_provider = principal_provider

    def execute(self, value: TaskExecutionInput) -> TaskExecutionResult:
        if time.time() >= value.deadline_epoch:
            raise OrchestrationError("ORCH-TASK-DEADLINE", "task deadline elapsed before A2A dispatch")
        task = value.task
        principal = self.principal_provider(task, value.tenant_id, value.run_id)
        message = A2AMessage(
            role=A2AMessageRole.USER,
            parts=(
                A2APart.data_part(
                    {
                        "runId": value.run_id,
                        "taskId": task.id,
                        "objective": task.label,
                        "input": dict(value.workflow_input),
                        "dependencies": {
                            key: dict(output) for key, output in value.dependency_outputs.items()
                        },
                    }
                ),
            ),
            context_id=value.run_id,
            metadata={"interlock.dev/orchestrationTaskId": task.id},
        )
        remote = self.broker.send_message(
            message,
            A2ASendContext(
                principal=principal,
                source_actor_id=task.source_actor_id,
                target_actor_id=task.target_actor_id,
                purpose=task.purpose,
                data_classes=task.data_classes,
                idempotency_key=f"{value.run_id}:{task.id}:{value.attempt}",
                trace_id=value.trace_id,
            ),
        )
        if remote.status.state != A2ATaskState.COMPLETED:
            raise OrchestrationError(
                "ORCH-A2A-TASK-INCOMPLETE",
                f"A2A task ended in state {remote.status.state.value}",
            )
        return TaskExecutionResult(
            output={
                "a2aTaskId": remote.id,
                "artifacts": [artifact.to_dict() for artifact in remote.artifacts],
                **({"message": remote.status.message.to_dict()} if remote.status.message else {}),
            },
            external_task_id=remote.id,
            metadata={"transport": "A2A"},
        )


class CallableTaskAdapter:
    """Adapter for local/MCP/Human integrations supplied by the host app."""

    def __init__(self, function: Callable[[TaskExecutionInput], TaskExecutionResult]) -> None:
        self.function = function

    def execute(self, value: TaskExecutionInput) -> TaskExecutionResult:
        return self.function(value)


@dataclass(frozen=True, slots=True)
class WorkflowTaskRun:
    task_id: str
    state: WorkflowTaskState = WorkflowTaskState.PENDING
    attempts: int = 0
    output: Mapping[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None
    external_task_id: str | None = None
    started_at: str | None = None
    ended_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "taskId": self.task_id,
            "state": self.state.value,
            "attempts": self.attempts,
            "output": dict(self.output),
            "errorCode": self.error_code,
            "errorMessage": self.error_message,
            "externalTaskId": self.external_task_id,
            "startedAt": self.started_at,
            "endedAt": self.ended_at,
        }


@dataclass(frozen=True, slots=True)
class WorkflowRun:
    id: str
    architecture_id: str
    architecture_version: str
    tenant_id: str
    trace_id: str
    state: WorkflowRunState
    workflow_input: Mapping[str, Any]
    tasks: Mapping[str, WorkflowTaskRun]
    created_at: str
    updated_at: str
    messages_used: int = 0
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "architectureId": self.architecture_id,
            "architectureVersion": self.architecture_version,
            "tenantId": self.tenant_id,
            "traceId": self.trace_id,
            "state": self.state.value,
            "input": dict(self.workflow_input),
            "tasks": {task_id: task.to_dict() for task_id, task in self.tasks.items()},
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "messagesUsed": self.messages_used,
            "errorCode": self.error_code,
        }


class WorkflowRunStore(Protocol):
    def create(self, run: WorkflowRun) -> None: ...

    def save(self, run: WorkflowRun) -> None: ...

    def get(self, *, tenant_id: str, run_id: str) -> WorkflowRun: ...


class InMemoryWorkflowRunStore:
    def __init__(self, *, max_runs: int = 1024) -> None:
        if max_runs < 1:
            raise ValueError("max_runs must be positive")
        self._max_runs = max_runs
        self._runs: dict[str, WorkflowRun] = {}
        self._lock = threading.RLock()

    def create(self, run: WorkflowRun) -> None:
        with self._lock:
            if run.id in self._runs:
                raise OrchestrationError("ORCH-RUN-DUPLICATE", "workflow run id already exists")
            if len(self._runs) >= self._max_runs:
                raise OrchestrationError("ORCH-RUN-CAPACITY", "workflow run store is at capacity")
            self._runs[run.id] = run

    def save(self, run: WorkflowRun) -> None:
        with self._lock:
            prior = self._runs.get(run.id)
            if prior is None or prior.tenant_id != run.tenant_id:
                raise OrchestrationError("ORCH-RUN-NOT-FOUND", "workflow run is not visible to this tenant")
            self._runs[run.id] = run

    def get(self, *, tenant_id: str, run_id: str) -> WorkflowRun:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None or run.tenant_id != tenant_id:
                raise OrchestrationError("ORCH-RUN-NOT-FOUND", "workflow run is not visible to this tenant")
            return run


@dataclass(slots=True)
class _Budget:
    messages_remaining: int
    lock: threading.Lock = field(default_factory=threading.Lock)

    def consume(self) -> None:
        with self.lock:
            if self.messages_remaining < 1:
                raise OrchestrationError("ORCH-MESSAGE-BUDGET", "workflow message budget is exhausted")
            self.messages_remaining -= 1


class OrchestrationEngine:
    """Executes a validated DAG in dependency waves with bounded parallelism."""

    def __init__(
        self,
        architecture: CompiledArchitecture,
        *,
        adapters: Mapping[TaskTransport, OrchestrationTaskAdapter] | None = None,
        run_store: WorkflowRunStore | None = None,
        approval_provider: ApprovalProvider | None = None,
        acceptance_evaluator: AcceptanceEvaluator | None = None,
        ledger: Ledger | None = None,
    ) -> None:
        if architecture.graph.orchestration is None:
            raise ValueError("compiled architecture has no orchestration definition")
        self.architecture = architecture
        self.definition = architecture.graph.orchestration
        self.adapters = dict(adapters or {})
        self.run_store = run_store or InMemoryWorkflowRunStore()
        self.approval_provider = approval_provider
        self.acceptance_evaluator = acceptance_evaluator or self._default_acceptance
        self.ledger = ledger or InMemoryLedger()

    def register_adapter(self, transport: TaskTransport, adapter: OrchestrationTaskAdapter) -> None:
        self.adapters[transport] = adapter

    def start(
        self,
        *,
        tenant_id: str,
        workflow_input: Mapping[str, Any],
        run_id: str | None = None,
        trace_id: str | None = None,
    ) -> WorkflowRun:
        if not tenant_id:
            raise ValueError("tenant_id is required")
        now = _now()
        run = WorkflowRun(
            id=run_id or str(uuid.uuid4()),
            architecture_id=self.architecture.graph.id,
            architecture_version=self.architecture.graph.version,
            tenant_id=tenant_id,
            trace_id=trace_id or f"workflow-{uuid.uuid4()}",
            state=WorkflowRunState.PENDING,
            workflow_input=dict(workflow_input),
            tasks={task.id: WorkflowTaskRun(task.id) for task in self.definition.tasks},
            created_at=now,
            updated_at=now,
        )
        self.run_store.create(run)
        self._append_run_event("WORKFLOW_RUN_CREATED", run)
        return self._execute(replace(run, state=WorkflowRunState.RUNNING, updated_at=_now()))

    def resume(self, *, tenant_id: str, run_id: str) -> WorkflowRun:
        run = self.run_store.get(tenant_id=tenant_id, run_id=run_id)
        if run.state in _RUN_TERMINAL:
            return run
        tasks = {
            task_id: replace(task, state=WorkflowTaskState.PENDING)
            if task.state == WorkflowTaskState.WAITING_APPROVAL
            else task
            for task_id, task in run.tasks.items()
        }
        return self._execute(
            replace(run, state=WorkflowRunState.RUNNING, tasks=tasks, updated_at=_now(), error_code=None)
        )

    def get(self, *, tenant_id: str, run_id: str) -> WorkflowRun:
        return self.run_store.get(tenant_id=tenant_id, run_id=run_id)

    def cancel(self, *, tenant_id: str, run_id: str) -> WorkflowRun:
        run = self.run_store.get(tenant_id=tenant_id, run_id=run_id)
        if run.state in _RUN_TERMINAL:
            return run
        tasks = {
            task_id: replace(task, state=WorkflowTaskState.CANCELED, ended_at=_now())
            if task.state not in _TASK_TERMINAL
            else task
            for task_id, task in run.tasks.items()
        }
        canceled = replace(run, state=WorkflowRunState.CANCELED, tasks=tasks, updated_at=_now())
        self.run_store.save(canceled)
        self._append_run_event("WORKFLOW_RUN_CANCELED", canceled)
        return canceled

    def _execute(self, run: WorkflowRun) -> WorkflowRun:
        self.run_store.save(run)
        self._append_run_event("WORKFLOW_RUN_STARTED", run)
        started = time.monotonic()
        policy = self.definition.run_policy
        budget = _Budget(policy.max_messages - run.messages_used)
        task_specs = {task.id: task for task in self.definition.tasks}
        while True:
            if time.monotonic() - started > policy.max_duration_seconds:
                return self._fail_run(run, "ORCH-RUN-DEADLINE")
            waiting = [task for task in run.tasks.values() if task.state == WorkflowTaskState.WAITING_APPROVAL]
            if waiting:
                paused = replace(run, state=WorkflowRunState.WAITING_APPROVAL, updated_at=_now())
                self.run_store.save(paused)
                self._append_run_event("WORKFLOW_RUN_WAITING_APPROVAL", paused)
                return paused
            pending_ids = [task_id for task_id, task in run.tasks.items() if task.state == WorkflowTaskState.PENDING]
            if not pending_ids:
                failed = [
                    task_id
                    for task_id, task_run in run.tasks.items()
                    if task_run.state == WorkflowTaskState.FAILED
                    and task_specs[task_id].on_failure == TaskFailureAction.FAIL_WORKFLOW
                ]
                if failed:
                    return self._fail_run(run, "ORCH-TASK-FAILED")
                completed = replace(run, state=WorkflowRunState.COMPLETED, updated_at=_now())
                self.run_store.save(completed)
                self._append_run_event("WORKFLOW_RUN_COMPLETED", completed)
                return completed
            ready = [
                task_specs[task_id]
                for task_id in pending_ids
                if self._dependencies_satisfied(task_specs[task_id], run.tasks, task_specs)
            ]
            if not ready:
                return self._fail_run(run, "ORCH-DAG-STALLED")
            wave = ready[: policy.max_parallelism]
            run = self._run_wave(run, wave, budget)
            if policy.fail_fast and any(
                run.tasks[task.id].state == WorkflowTaskState.FAILED
                and task.on_failure == TaskFailureAction.FAIL_WORKFLOW
                for task in wave
            ):
                return self._fail_run(run, "ORCH-TASK-FAILED")

    def _run_wave(self, run: WorkflowRun, tasks: list[OrchestrationTask], budget: _Budget) -> WorkflowRun:
        task_runs = dict(run.tasks)
        for task in tasks:
            current = task_runs[task.id]
            task_runs[task.id] = replace(
                current,
                state=WorkflowTaskState.RUNNING,
                started_at=current.started_at or _now(),
            )
        run = replace(run, tasks=task_runs, updated_at=_now())
        self.run_store.save(run)
        futures: dict[str, Future[WorkflowTaskRun]] = {}
        executor = ThreadPoolExecutor(max_workers=min(len(tasks), self.definition.run_policy.max_parallelism))
        try:
            for task in tasks:
                futures[task.id] = executor.submit(self._execute_task, run, task, budget)
            results: dict[str, WorkflowTaskRun] = {}
            for task in tasks:
                try:
                    results[task.id] = futures[task.id].result(timeout=task.timeout_seconds * task.max_attempts)
                except FutureTimeout:
                    futures[task.id].cancel()
                    results[task.id] = replace(
                        run.tasks[task.id],
                        state=WorkflowTaskState.FAILED,
                        error_code="ORCH-TASK-TIMEOUT",
                        error_message="task exceeded its execution timeout",
                        ended_at=_now(),
                    )
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        merged = {**dict(run.tasks), **results}
        updated = replace(
            run,
            tasks=merged,
            messages_used=self.definition.run_policy.max_messages - budget.messages_remaining,
            updated_at=_now(),
        )
        self.run_store.save(updated)
        for task_id in results:
            self._append_task_event(updated, results[task_id])
        return updated

    def _execute_task(self, run: WorkflowRun, task: OrchestrationTask, budget: _Budget) -> WorkflowTaskRun:
        current = run.tasks[task.id]
        dependency_outputs = {
            dependency: dict(run.tasks[dependency].output) for dependency in task.depends_on
        }
        approval_context = {
            "input": dict(run.workflow_input),
            "dependencies": dependency_outputs,
        }
        if task.approval_required and (
            self.approval_provider is None
            or not self.approval_provider(run.tenant_id, run.id, task, approval_context)
        ):
            return replace(current, state=WorkflowTaskState.WAITING_APPROVAL)
        adapter = self.adapters.get(task.transport)
        if adapter is None:
            return self._failed_task(current, task, "ORCH-ADAPTER-MISSING", "task transport has no adapter")
        last_error: Exception | None = None
        for attempt in range(current.attempts + 1, task.max_attempts + 1):
            try:
                budget.consume()
                deadline = time.time() + task.timeout_seconds
                result = adapter.execute(
                    TaskExecutionInput(
                        run_id=run.id,
                        tenant_id=run.tenant_id,
                        trace_id=run.trace_id,
                        task=task,
                        workflow_input=run.workflow_input,
                        dependency_outputs=dependency_outputs,
                        attempt=attempt,
                        deadline_epoch=deadline,
                    )
                )
                if time.time() > deadline:
                    raise OrchestrationError("ORCH-TASK-TIMEOUT", "task exceeded its execution timeout")
                accepted, reason = self.acceptance_evaluator(task, result)
                if not accepted:
                    raise OrchestrationError("ORCH-ACCEPTANCE-FAILED", reason or "task acceptance failed")
                return replace(
                    current,
                    state=WorkflowTaskState.COMPLETED,
                    attempts=attempt,
                    output=dict(result.output),
                    external_task_id=result.external_task_id,
                    ended_at=_now(),
                )
            except Exception as error:  # noqa: BLE001 - retries contain adapter failures
                last_error = error
        reason_code = getattr(last_error, "reason_code", "ORCH-TASK-EXECUTION-FAILED")
        message = str(last_error) if last_error else "task execution failed"
        return self._failed_task(current, task, reason_code, message, attempts=task.max_attempts)

    @staticmethod
    def _failed_task(
        current: WorkflowTaskRun,
        task: OrchestrationTask,
        reason_code: str,
        message: str,
        *,
        attempts: int | None = None,
    ) -> WorkflowTaskRun:
        state = WorkflowTaskState.SKIPPED if task.on_failure == TaskFailureAction.SKIP else WorkflowTaskState.FAILED
        return replace(
            current,
            state=state,
            attempts=current.attempts if attempts is None else attempts,
            error_code=reason_code,
            error_message=message,
            ended_at=_now(),
        )

    @staticmethod
    def _dependencies_satisfied(
        task: OrchestrationTask,
        runs: Mapping[str, WorkflowTaskRun],
        specs: Mapping[str, OrchestrationTask],
    ) -> bool:
        for dependency in task.depends_on:
            state = runs[dependency].state
            if state in {WorkflowTaskState.COMPLETED, WorkflowTaskState.SKIPPED}:
                continue
            if state == WorkflowTaskState.FAILED and specs[dependency].on_failure == TaskFailureAction.CONTINUE:
                continue
            return False
        return True

    def _fail_run(self, run: WorkflowRun, reason_code: str) -> WorkflowRun:
        failed = replace(run, state=WorkflowRunState.FAILED, updated_at=_now(), error_code=reason_code)
        self.run_store.save(failed)
        self._append_run_event("WORKFLOW_RUN_FAILED", failed)
        return failed

    @staticmethod
    def _default_acceptance(task: OrchestrationTask, result: TaskExecutionResult) -> tuple[bool, str | None]:
        if result.metadata.get("accepted") is False:
            return False, "adapter marked result as not accepted"
        return True, None

    def _append_run_event(self, event_type: str, run: WorkflowRun) -> None:
        self.ledger.append(
            event_type,
            tenant_id=run.tenant_id,
            trace_id=run.trace_id,
            span_id=f"workflow-{run.id}",
            source_actor_id=self.definition.coordinator_actor_id,
            relationship_type="ROUTES",
            relationship_id="REL-02",
            payload={"runId": run.id, "state": run.state.value, "errorCode": run.error_code},
        )

    def _append_task_event(self, run: WorkflowRun, task: WorkflowTaskRun) -> None:
        spec = next(item for item in self.definition.tasks if item.id == task.task_id)
        self.ledger.append(
            "WORKFLOW_TASK_STATUS_UPDATED",
            tenant_id=run.tenant_id,
            trace_id=run.trace_id,
            span_id=f"workflow-{run.id}-{task.task_id}",
            source_actor_id=spec.source_actor_id,
            target_actor_id=spec.target_actor_id,
            relationship_type="ROUTES",
            relationship_id="REL-02",
            payload={
                "runId": run.id,
                "taskId": task.task_id,
                "state": task.state.value,
                "attempts": task.attempts,
                "errorCode": task.error_code,
                "externalTaskId": task.external_task_id,
            },
        )
