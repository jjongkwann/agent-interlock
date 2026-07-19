"""Server-initiated MCP requests and async task lifecycle.

MCP lets a server send *requests* to the client (sampling, elicitation, roots)
and run long tasks. Both are attack surface: a compromised or confused server
can ask the client to act on its behalf, and a task result replayed across a
retry can double-apply an effect.

``ServerRequestRouter`` handles server-initiated requests behind a fail-closed
allowlist — only explicitly permitted methods reach a handler, everything else
gets a JSON-RPC ``method not found`` error, and every decision is recorded.
``AsyncTaskRegistry`` models the task lifecycle with a one-time result consume
(replay refused) and idempotent cancellation, principal-bound so one caller
cannot consume or cancel another's task.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Callable, Mapping

_PrincipalKey = tuple[str, str, str]

# JSON-RPC error codes
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INTERNAL_ERROR = -32603


class MCPAsyncError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


ServerRequestHandler = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def _json_rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


class ServerRequestRouter:
    """Fail-closed allowlist for server-initiated JSON-RPC requests.

    Only methods with a registered handler are executed; an unknown method
    returns a ``method not found`` error without ever reaching client code. A
    handler that raises is contained as an internal-error response, never a
    crash. Every routing decision is appended to an audit log.
    """

    def __init__(self, handlers: Mapping[str, ServerRequestHandler] | None = None) -> None:
        self._handlers: dict[str, ServerRequestHandler] = dict(handlers or {})
        self._log: list[tuple[str, str]] = []
        self._lock = threading.RLock()

    def allow(self, method: str, handler: ServerRequestHandler) -> None:
        with self._lock:
            self._handlers[method] = handler

    @property
    def allowed_methods(self) -> frozenset[str]:
        with self._lock:
            return frozenset(self._handlers)

    @property
    def audit_log(self) -> tuple[tuple[str, str], ...]:
        with self._lock:
            return tuple(self._log)

    def handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        request_id = request.get("id")
        method = request.get("method")
        if request.get("jsonrpc") != "2.0" or not isinstance(method, str) or "id" not in request:
            return _json_rpc_error(request_id, _INVALID_REQUEST, "invalid server-initiated request")
        with self._lock:
            handler = self._handlers.get(method)
            if handler is None:
                self._log.append((method, "denied"))
                return _json_rpc_error(request_id, _METHOD_NOT_FOUND, f"server method not allowed: {method}")
        try:
            result = handler(request.get("params") or {})
        except Exception:  # noqa: BLE001 - a bad handler must not crash the transport
            with self._lock:
                self._log.append((method, "error"))
            return _json_rpc_error(request_id, _INTERNAL_ERROR, "server-request handler failed")
        if not isinstance(result, Mapping):
            with self._lock:
                self._log.append((method, "error"))
            return _json_rpc_error(request_id, _INTERNAL_ERROR, "server-request handler returned no result")
        with self._lock:
            self._log.append((method, "handled"))
        return {"jsonrpc": "2.0", "id": request_id, "result": dict(result)}


class TaskState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


_TERMINAL = {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED}


@dataclass(slots=True)
class TaskRecord:
    task_id: str
    principal_key: _PrincipalKey
    state: TaskState
    result: Mapping[str, Any] | None = None
    error: Mapping[str, Any] | None = None
    consumed: bool = False


class AsyncTaskRegistry:
    """Bounded, principal-bound async task registry with one-time result consume."""

    def __init__(self, *, max_tasks: int = 1024) -> None:
        if max_tasks <= 0:
            raise ValueError("max_tasks must be positive")
        self._max_tasks = max_tasks
        self._tasks: dict[str, TaskRecord] = {}
        self._lock = threading.RLock()

    def _bound(self, task_id: str, principal_key: _PrincipalKey) -> TaskRecord:
        task = self._tasks.get(task_id)
        if task is None or task.principal_key != principal_key:
            raise MCPAsyncError("MCP-TASK-NOT-FOUND", "task is unknown for this principal")
        return task

    def create(self, task_id: str, principal_key: _PrincipalKey) -> TaskRecord:
        with self._lock:
            if task_id in self._tasks:
                raise MCPAsyncError("MCP-TASK-DUPLICATE", "task id already exists")
            if len(self._tasks) >= self._max_tasks:
                raise MCPAsyncError("MCP-TASK-CAPACITY", "task registry is at capacity")
            record = TaskRecord(task_id, principal_key, TaskState.PENDING)
            self._tasks[task_id] = record
            return record

    def start(self, task_id: str, principal_key: _PrincipalKey) -> TaskState:
        with self._lock:
            task = self._bound(task_id, principal_key)
            if task.state != TaskState.PENDING:
                raise MCPAsyncError("MCP-TASK-STATE-INVALID", "only a pending task can start")
            task.state = TaskState.RUNNING
            return task.state

    def complete(self, task_id: str, principal_key: _PrincipalKey, result: Mapping[str, Any]) -> TaskState:
        with self._lock:
            task = self._bound(task_id, principal_key)
            if task.state not in (TaskState.PENDING, TaskState.RUNNING):
                raise MCPAsyncError("MCP-TASK-STATE-INVALID", "task already reached a terminal state")
            task.state = TaskState.COMPLETED
            task.result = dict(result)
            return task.state

    def fail(self, task_id: str, principal_key: _PrincipalKey, error: Mapping[str, Any]) -> TaskState:
        with self._lock:
            task = self._bound(task_id, principal_key)
            if task.state not in (TaskState.PENDING, TaskState.RUNNING):
                raise MCPAsyncError("MCP-TASK-STATE-INVALID", "task already reached a terminal state")
            task.state = TaskState.FAILED
            task.error = dict(error)
            return task.state

    def cancel(self, task_id: str, principal_key: _PrincipalKey) -> bool:
        """Cancel a pending/running task. Idempotent: returns True only for the
        call that transitions it; a task already terminal returns False."""
        with self._lock:
            task = self._bound(task_id, principal_key)
            if task.state in _TERMINAL:
                return False
            task.state = TaskState.CANCELLED
            return True

    def state(self, task_id: str, principal_key: _PrincipalKey) -> TaskState | None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None or task.principal_key != principal_key:
                return None
            return task.state

    def consume(self, task_id: str, principal_key: _PrincipalKey) -> Mapping[str, Any]:
        """Return a completed task's result exactly once; a replayed consume is
        refused so a retried request cannot double-apply the result."""
        with self._lock:
            task = self._bound(task_id, principal_key)
            if task.state != TaskState.COMPLETED:
                raise MCPAsyncError("MCP-TASK-NOT-COMPLETED", "task has no consumable result")
            if task.consumed:
                raise MCPAsyncError("MCP-TASK-RESULT-REPLAY", "task result was already consumed")
            task.consumed = True
            return dict(task.result or {})

    def delete(self, task_id: str, principal_key: _PrincipalKey) -> bool:
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None or task.principal_key != principal_key:
                return False
            del self._tasks[task_id]
            return True
