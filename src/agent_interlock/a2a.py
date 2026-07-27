"""Policy-bound A2A contracts, task store, broker, and JSON-RPC routing.

The module implements the protocol core without coupling it to an agent
framework.  Agent Cards describe discoverable capabilities; Message, Part,
Artifact, and Task model the A2A exchange; ``A2ABroker`` binds every send to a
compiled REL-06 edge and, when zones differ, to the compiled trust boundary.
"""

from __future__ import annotations

import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from typing import Any, Protocol

from .architecture import ArchitectureEdge, CompiledArchitecture
from .canonical import canonical_digest, canonical_json
from .ledger import InMemoryLedger, Ledger
from .models import (
    ActorType,
    ControlDecision,
    CredentialClaims,
    DataSource,
    Environment,
    InvocationIntent,
    PolicyMode,
)
from .policy import A2A_BOUNDARY_PROFILE, A2A_LINK_PROFILE, CheckContext, run_checks
from .security import validate_schema


class A2AError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class A2APolicyError(A2AError):
    def __init__(self, reason_codes: tuple[str, ...]) -> None:
        self.reason_codes = reason_codes
        super().__init__(reason_codes[0], f"A2A message blocked: {', '.join(reason_codes)}")


class A2APartKind(StrEnum):
    TEXT = "text"
    DATA = "data"
    FILE = "file"


class A2AMessageRole(StrEnum):
    USER = "user"
    AGENT = "agent"


class A2ATaskState(StrEnum):
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    AUTH_REQUIRED = "auth-required"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"
    REJECTED = "rejected"


_A2A_V1_TASK_STATES = {
    A2ATaskState.SUBMITTED: "TASK_STATE_SUBMITTED",
    A2ATaskState.WORKING: "TASK_STATE_WORKING",
    A2ATaskState.INPUT_REQUIRED: "TASK_STATE_INPUT_REQUIRED",
    A2ATaskState.AUTH_REQUIRED: "TASK_STATE_AUTH_REQUIRED",
    A2ATaskState.COMPLETED: "TASK_STATE_COMPLETED",
    A2ATaskState.FAILED: "TASK_STATE_FAILED",
    A2ATaskState.CANCELED: "TASK_STATE_CANCELED",
    A2ATaskState.REJECTED: "TASK_STATE_REJECTED",
}


_TERMINAL_TASK_STATES = {
    A2ATaskState.COMPLETED,
    A2ATaskState.FAILED,
    A2ATaskState.CANCELED,
    A2ATaskState.REJECTED,
}


@dataclass(frozen=True, slots=True)
class A2AAgentSkill:
    id: str
    name: str
    description: str
    tags: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()
    input_modes: tuple[str, ...] = ()
    output_modes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id or not self.name or not self.description:
            raise ValueError("A2A skill id, name, and description are required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "tags": list(self.tags),
            "examples": list(self.examples),
            **({"inputModes": list(self.input_modes)} if self.input_modes else {}),
            **({"outputModes": list(self.output_modes)} if self.output_modes else {}),
        }


@dataclass(frozen=True, slots=True)
class A2AAgentCard:
    actor_id: str
    name: str
    description: str
    url: str
    version: str
    skills: tuple[A2AAgentSkill, ...]
    protocol_version: str = "1.0"
    preferred_transport: str = "JSONRPC"
    streaming: bool = False
    push_notifications: bool = False
    state_transition_history: bool = True
    default_input_modes: tuple[str, ...] = ("text/plain", "application/json")
    default_output_modes: tuple[str, ...] = ("text/plain", "application/json")
    security_schemes: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.actor_id or not self.name or not self.description or not self.url or not self.version:
            raise ValueError("A2A Agent Card identity fields are required")
        version_parts = self.protocol_version.split(".")
        if len(version_parts) != 2 or not all(part.isdigit() for part in version_parts):
            raise ValueError("A2A Agent Card protocol_version must use Major.Minor format")
        skill_ids = [skill.id for skill in self.skills]
        if len(skill_ids) != len(set(skill_ids)):
            raise ValueError("A2A Agent Card skill ids must be unique")

    def to_dict(self, *, protocol_version: str | None = None) -> dict[str, Any]:
        version = protocol_version or self.protocol_version
        common = {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "capabilities": {
                "streaming": self.streaming,
                "pushNotifications": self.push_notifications,
            },
            "defaultInputModes": list(self.default_input_modes),
            "defaultOutputModes": list(self.default_output_modes),
            "skills": [skill.to_dict() for skill in self.skills],
            **({"securitySchemes": dict(self.security_schemes)} if self.security_schemes else {}),
        }
        if version.startswith("0.3"):
            return {
                "protocolVersion": "0.3",
                **common,
                "url": self.url,
                "preferredTransport": self.preferred_transport,
                "capabilities": {
                    **common["capabilities"],
                    "stateTransitionHistory": self.state_transition_history,
                },
                "extensions": {"interlock.dev/actorId": self.actor_id},
            }
        return {
            **common,
            "supportedInterfaces": [
                {
                    "url": self.url,
                    "protocolBinding": self.preferred_transport,
                    "protocolVersion": version,
                }
            ],
        }


@dataclass(frozen=True, slots=True)
class A2APart:
    kind: A2APartKind
    text: str | None = None
    data: Mapping[str, Any] | None = None
    file_uri: str | None = None
    media_type: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        present = sum(value is not None for value in (self.text, self.data, self.file_uri))
        if present != 1:
            raise ValueError("an A2A Part must contain exactly one text, data, or file value")
        expected = {
            A2APartKind.TEXT: self.text,
            A2APartKind.DATA: self.data,
            A2APartKind.FILE: self.file_uri,
        }[self.kind]
        if expected is None:
            raise ValueError(f"A2A Part kind {self.kind.value} does not match its value")
        if self.kind == A2APartKind.FILE and not self.media_type:
            raise ValueError("an A2A file Part requires media_type")

    @classmethod
    def text_part(cls, text: str, *, metadata: Mapping[str, Any] | None = None) -> A2APart:
        return cls(A2APartKind.TEXT, text=text, metadata=dict(metadata or {}))

    @classmethod
    def data_part(cls, data: Mapping[str, Any], *, metadata: Mapping[str, Any] | None = None) -> A2APart:
        return cls(A2APartKind.DATA, data=dict(data), metadata=dict(metadata or {}))

    @classmethod
    def file_part(
        cls,
        uri: str,
        media_type: str,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> A2APart:
        return cls(A2APartKind.FILE, file_uri=uri, media_type=media_type, metadata=dict(metadata or {}))

    def to_dict(self, *, protocol_version: str = "1.0") -> dict[str, Any]:
        legacy = protocol_version.startswith("0.3")
        if self.kind == A2APartKind.TEXT:
            value: dict[str, Any] = {**({"kind": "text"} if legacy else {}), "text": self.text}
        elif self.kind == A2APartKind.DATA:
            value = {
                **({"kind": "data"} if legacy else {}),
                "data": dict(self.data or {}),
                **({"mediaType": self.media_type or "application/json"} if not legacy else {}),
            }
        elif legacy:
            value = {
                "kind": "file",
                "file": {"uri": self.file_uri, "mimeType": self.media_type},
            }
        else:
            value = {"url": self.file_uri, "mediaType": self.media_type}
        if self.metadata:
            value["metadata"] = dict(self.metadata)
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> A2APart:
        metadata = _optional_mapping(value.get("metadata"), "part.metadata")
        kind_value = value.get("kind")
        if kind_value is not None:
            kind = A2APartKind(_required_string(value, "kind"))
        elif "text" in value:
            kind = A2APartKind.TEXT
        elif "data" in value:
            kind = A2APartKind.DATA
        elif "url" in value or "raw" in value:
            kind = A2APartKind.FILE
        else:
            raise ValueError("A2A Part must contain text, data, url, or raw")
        if kind == A2APartKind.TEXT:
            return cls.text_part(_required_string(value, "text"), metadata=metadata)
        if kind == A2APartKind.DATA:
            return cls.data_part(_required_mapping(value, "data"), metadata=metadata)
        if kind_value is None:
            if "raw" in value:
                raise ValueError("inline raw file Parts are not accepted; use a policy-scoped URL")
            return cls.file_part(
                _required_string(value, "url"),
                _required_string(value, "mediaType"),
                metadata=metadata,
            )
        file_value = _required_mapping(value, "file")
        return cls.file_part(
            _required_string(file_value, "uri"),
            _required_string(file_value, "mimeType"),
            metadata=metadata,
        )


@dataclass(frozen=True, slots=True)
class A2AMessage:
    role: A2AMessageRole
    parts: tuple[A2APart, ...]
    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    context_id: str | None = None
    task_id: str | None = None
    reference_task_ids: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.message_id or not self.parts:
            raise ValueError("A2A Message message_id and at least one Part are required")

    def to_dict(self, *, protocol_version: str = "1.0") -> dict[str, Any]:
        legacy = protocol_version.startswith("0.3")
        return {
            "messageId": self.message_id,
            "role": self.role.value if legacy else f"ROLE_{self.role.value.upper()}",
            "parts": [part.to_dict(protocol_version=protocol_version) for part in self.parts],
            **({"kind": "message"} if legacy else {}),
            **({"contextId": self.context_id} if self.context_id else {}),
            **({"taskId": self.task_id} if self.task_id else {}),
            **({"referenceTaskIds": list(self.reference_task_ids)} if self.reference_task_ids else {}),
            **({"metadata": dict(self.metadata)} if self.metadata else {}),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> A2AMessage:
        parts_value = value.get("parts")
        if not isinstance(parts_value, list):
            raise ValueError("message.parts must be an array")
        references = value.get("referenceTaskIds", [])
        if not isinstance(references, list) or not all(isinstance(item, str) for item in references):
            raise ValueError("message.referenceTaskIds must contain strings")
        return cls(
            role=A2AMessageRole(_required_string(value, "role").removeprefix("ROLE_").lower()),
            parts=tuple(A2APart.from_dict(_as_mapping(item, "message part")) for item in parts_value),
            message_id=_required_string(value, "messageId"),
            context_id=_optional_string(value.get("contextId"), "contextId"),
            task_id=_optional_string(value.get("taskId"), "taskId"),
            reference_task_ids=tuple(references),
            metadata=_optional_mapping(value.get("metadata"), "message.metadata"),
        )


@dataclass(frozen=True, slots=True)
class A2AArtifact:
    artifact_id: str
    name: str
    parts: tuple[A2APart, ...]
    description: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.artifact_id or not self.name or not self.parts:
            raise ValueError("A2A Artifact id, name, and at least one Part are required")

    def to_dict(self, *, protocol_version: str = "1.0") -> dict[str, Any]:
        return {
            "artifactId": self.artifact_id,
            "name": self.name,
            "parts": [part.to_dict(protocol_version=protocol_version) for part in self.parts],
            **({"description": self.description} if self.description else {}),
            **({"metadata": dict(self.metadata)} if self.metadata else {}),
        }


@dataclass(frozen=True, slots=True)
class A2ATaskStatus:
    state: A2ATaskState
    message: A2AMessage | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z"))

    def to_dict(self, *, protocol_version: str = "1.0") -> dict[str, Any]:
        return {
            "state": self.state.value if protocol_version.startswith("0.3") else _A2A_V1_TASK_STATES[self.state],
            "timestamp": self.timestamp,
            **({"message": self.message.to_dict(protocol_version=protocol_version)} if self.message else {}),
        }


@dataclass(frozen=True, slots=True)
class A2ATask:
    id: str
    context_id: str
    status: A2ATaskStatus
    history: tuple[A2AMessage, ...] = ()
    artifacts: tuple[A2AArtifact, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(
        self,
        *,
        history_length: int | None = None,
        protocol_version: str = "1.0",
    ) -> dict[str, Any]:
        history = self.history if history_length is None else self.history[-max(0, history_length) :]
        return {
            "id": self.id,
            "contextId": self.context_id,
            "status": self.status.to_dict(protocol_version=protocol_version),
            "history": [message.to_dict(protocol_version=protocol_version) for message in history],
            "artifacts": [artifact.to_dict(protocol_version=protocol_version) for artifact in self.artifacts],
            **({"kind": "task"} if protocol_version.startswith("0.3") else {}),
            **({"metadata": dict(self.metadata)} if self.metadata else {}),
        }


@dataclass(frozen=True, slots=True)
class A2AHandlerResult:
    state: A2ATaskState
    message: A2AMessage | None = None
    artifacts: tuple[A2AArtifact, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.state not in {
            A2ATaskState.COMPLETED,
            A2ATaskState.FAILED,
            A2ATaskState.INPUT_REQUIRED,
            A2ATaskState.AUTH_REQUIRED,
            A2ATaskState.REJECTED,
        }:
            raise ValueError("A2A handler result must produce a response state")


@dataclass(frozen=True, slots=True)
class A2APrincipal:
    tenant_id: str
    subject: str
    actor_id: str
    audience: str
    resource: str
    delegation_depth: int = 0
    exchanged: bool = True
    authenticated: bool = True

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.subject or not self.actor_id:
            raise ValueError("A2A principal tenant, subject, and actor are required")
        if self.delegation_depth < 0:
            raise ValueError("A2A principal delegation depth must be non-negative")

    @classmethod
    def for_edge(
        cls,
        *,
        tenant_id: str,
        subject: str,
        source_actor_id: str,
        target_actor_id: str,
        target_identity: str,
        delegation_depth: int = 0,
    ) -> A2APrincipal:
        return cls(
            tenant_id=tenant_id,
            subject=subject,
            actor_id=source_actor_id,
            audience=target_identity,
            resource=f"a2a://{target_actor_id}",
            delegation_depth=delegation_depth,
        )


@dataclass(frozen=True, slots=True)
class A2ASendContext:
    principal: A2APrincipal
    source_actor_id: str
    target_actor_id: str
    purpose: str
    data_classes: frozenset[str]
    idempotency_key: str
    trace_id: str | None = None
    environment: Environment = Environment.DEV
    data_source: DataSource = DataSource.PRODUCTION

    def __post_init__(self) -> None:
        if not self.source_actor_id or not self.target_actor_id or not self.purpose or not self.idempotency_key:
            raise ValueError("A2A send context source, target, purpose, and idempotency key are required")


A2AAgentHandler = Callable[[A2ATask, A2AMessage, A2ASendContext], A2AHandlerResult]


@dataclass(slots=True)
class _StoredTask:
    tenant_id: str
    source_actor_id: str
    target_actor_id: str
    task: A2ATask
    request_fingerprint: str


class A2ATaskStore(Protocol):
    def create_or_get(
        self,
        *,
        tenant_id: str,
        source_actor_id: str,
        target_actor_id: str,
        idempotency_key: str,
        request_fingerprint: str,
        task: A2ATask,
    ) -> tuple[A2ATask, bool]: ...

    def update(self, *, tenant_id: str, task: A2ATask) -> None: ...

    def get(self, *, tenant_id: str, actor_id: str, task_id: str) -> A2ATask: ...

    def cancel(self, *, tenant_id: str, actor_id: str, task_id: str) -> A2ATask: ...


class InMemoryA2ATaskStore:
    """Bounded tenant/participant-scoped store with idempotency binding."""

    def __init__(self, *, max_tasks: int = 4096) -> None:
        if max_tasks < 1:
            raise ValueError("max_tasks must be positive")
        self._max_tasks = max_tasks
        self._tasks: dict[str, _StoredTask] = {}
        self._idempotency: dict[tuple[str, str], tuple[str, str]] = {}
        self._lock = threading.RLock()

    def create_or_get(
        self,
        *,
        tenant_id: str,
        source_actor_id: str,
        target_actor_id: str,
        idempotency_key: str,
        request_fingerprint: str,
        task: A2ATask,
    ) -> tuple[A2ATask, bool]:
        with self._lock:
            key = (tenant_id, idempotency_key)
            prior = self._idempotency.get(key)
            if prior:
                prior_fingerprint, task_id = prior
                if prior_fingerprint != request_fingerprint:
                    raise A2AError("A2A-IDEMPOTENCY-CONFLICT", "idempotency key is bound to another request")
                return self._tasks[task_id].task, False
            stored = self._tasks.get(task.id)
            if stored is not None:
                if (
                    stored.tenant_id != tenant_id
                    or stored.source_actor_id != source_actor_id
                    or stored.target_actor_id != target_actor_id
                ):
                    raise A2AError("A2A-TASK-DUPLICATE", "A2A task id belongs to another interaction")
                stored.task = task
                stored.request_fingerprint = request_fingerprint
                self._idempotency[key] = (request_fingerprint, task.id)
                return task, True
            if len(self._tasks) >= self._max_tasks:
                raise A2AError("A2A-TASK-CAPACITY", "A2A task store is at capacity")
            self._tasks[task.id] = _StoredTask(
                tenant_id,
                source_actor_id,
                target_actor_id,
                task,
                request_fingerprint,
            )
            self._idempotency[key] = (request_fingerprint, task.id)
            return task, True

    def update(self, *, tenant_id: str, task: A2ATask) -> None:
        with self._lock:
            stored = self._tasks.get(task.id)
            if stored is None or stored.tenant_id != tenant_id:
                raise A2AError("A2A-TASK-NOT-FOUND", "A2A task is not visible to this tenant")
            stored.task = task

    def get(self, *, tenant_id: str, actor_id: str, task_id: str) -> A2ATask:
        with self._lock:
            stored = self._tasks.get(task_id)
            if (
                stored is None
                or stored.tenant_id != tenant_id
                or actor_id not in {stored.source_actor_id, stored.target_actor_id}
            ):
                raise A2AError("A2A-TASK-NOT-FOUND", "A2A task is not visible to this principal")
            return stored.task

    def cancel(self, *, tenant_id: str, actor_id: str, task_id: str) -> A2ATask:
        with self._lock:
            task = self.get(tenant_id=tenant_id, actor_id=actor_id, task_id=task_id)
            if task.status.state == A2ATaskState.CANCELED:
                return task
            if task.status.state in _TERMINAL_TASK_STATES:
                raise A2AError("A2A-TASK-NOT-CANCELABLE", "A2A task is already in a terminal state")
            canceled = replace(task, status=A2ATaskStatus(A2ATaskState.CANCELED))
            self._tasks[task_id].task = canceled
            return canceled


def _credential_from(principal: A2APrincipal) -> CredentialClaims:
    """The A2A principal is a credential; the shared checks read it as one."""
    return CredentialClaims(
        reference="",
        issuer="",
        subject=principal.subject,
        actor=principal.actor_id,
        audience=principal.audience,
        resource=principal.resource,
        delegation_depth=principal.delegation_depth,
        exchanged=principal.exchanged,
        tenant_id=principal.tenant_id,
        authenticated=principal.authenticated,
    )


class A2ABroker:
    """Executes A2A messages through compiled edge and boundary contracts."""

    def __init__(
        self,
        architecture: CompiledArchitecture,
        *,
        ledger: Ledger | None = None,
        task_store: A2ATaskStore | None = None,
    ) -> None:
        self.architecture = architecture
        self.ledger = ledger or InMemoryLedger()
        self.task_store = task_store or InMemoryA2ATaskStore()
        self._cards: dict[str, A2AAgentCard] = {}
        self._handlers: dict[str, A2AAgentHandler] = {}

    def register_agent(self, actor_id: str, card: A2AAgentCard, handler: A2AAgentHandler) -> None:
        actor = self.architecture.actors.get(actor_id)
        if actor is None:
            raise A2AError("A2A-ACTOR-UNKNOWN", "agent is not declared in the compiled architecture")
        if actor.type not in {ActorType.AGENT, ActorType.SUBAGENT, ActorType.SCHEDULER}:
            raise A2AError("A2A-ACTOR-TYPE-DENIED", "only Agent, Sub-Agent, or Scheduler actors may serve A2A")
        if card.actor_id != actor_id:
            raise A2AError("A2A-CARD-ACTOR-MISMATCH", "Agent Card actor id does not match registration")
        declared_capabilities = actor.capabilities
        undeclared_skills = {skill.id for skill in card.skills} - declared_capabilities
        if undeclared_skills:
            raise A2AError("A2A-CARD-SKILL-UNDECLARED", "Agent Card publishes undeclared actor capabilities")
        self._cards[actor_id] = card
        self._handlers[actor_id] = handler

    def agent_card(self, actor_id: str) -> A2AAgentCard:
        try:
            return self._cards[actor_id]
        except KeyError as error:
            raise A2AError("A2A-CARD-NOT-FOUND", "agent has no registered Agent Card") from error

    def send_message(self, message: A2AMessage, context: A2ASendContext) -> A2ATask:
        if context.principal.tenant_id == "" or context.principal.tenant_id != context.principal.tenant_id.strip():
            raise A2AError("A2A-TENANT-INVALID", "tenant binding is invalid")
        edge = self.architecture.edge_for(context.source_actor_id, context.target_actor_id, "REL-06")
        if edge is None:
            raise A2APolicyError(("A2A-RELATIONSHIP-UNDECLARED",))
        target = self.architecture.actors.get(context.target_actor_id)
        if target is None or context.target_actor_id not in self._handlers:
            raise A2AError("A2A-TARGET-UNAVAILABLE", "target agent is not registered")
        boundary = self.architecture.boundary_for(edge)
        payload_bytes = len(canonical_json(message.to_dict()))
        trace_id = context.trace_id or f"a2a-{uuid.uuid4()}"
        span_id = f"span-{uuid.uuid4()}"
        interaction_id = str(uuid.uuid4())
        check_context = CheckContext(
            source=self.architecture.actors[context.source_actor_id],
            target=target,
            # The broker's audience and resource expectations are derived from the target, not
            # declared by the caller; naming them here keeps the shared check comparing intent
            # against credential the way it does at every other point.
            intent=InvocationIntent(
                purpose=context.purpose,
                data_classes=context.data_classes,
                expected_audience=target.identity,
                expected_resource=f"a2a://{target.id}",
            ),
            arguments=message.to_dict(),
            interaction_id=interaction_id,
            trace_id=trace_id,
            span_id=span_id,
            credential=_credential_from(context.principal),
            boundary=boundary,
            payload_bytes=payload_bytes,
            relationship=edge.relationship,
        )
        link_reasons, _, _ = run_checks(edge.policy, check_context, A2A_LINK_PROFILE)
        # A bound boundary that did not compile is a wiring error, not a policy finding: no check
        # can express it, because the profile is handed the boundary that is missing.
        if edge.boundary_id is not None and boundary is None:
            boundary_reasons = ["A2A-BOUNDARY-NOT-COMPILED"]
        else:
            boundary_reasons, _, _ = run_checks(edge.policy, check_context, A2A_BOUNDARY_PROFILE)
        reasons = tuple(dict.fromkeys((*link_reasons, *boundary_reasons)))
        enforced = bool(
            (link_reasons and edge.policy.mode == PolicyMode.ENFORCE)
            or (boundary_reasons and boundary is not None and boundary.mode == PolicyMode.ENFORCE)
        )
        prior_task: A2ATask | None = None
        if message.task_id:
            prior_task = self.task_store.get(
                tenant_id=context.principal.tenant_id,
                actor_id=context.principal.actor_id,
                task_id=message.task_id,
            )
            if prior_task.status.state in _TERMINAL_TASK_STATES:
                raise A2AError("A2A-TASK-TERMINAL", "a terminal A2A task cannot be restarted")
            if message.context_id and message.context_id != prior_task.context_id:
                raise A2AError("A2A-CONTEXT-MISMATCH", "message context does not match the existing task")
        task_id = prior_task.id if prior_task else str(uuid.uuid4())
        context_id = prior_task.context_id if prior_task else message.context_id or str(uuid.uuid4())
        request_fingerprint = canonical_digest(
            {
                "source": context.source_actor_id,
                "target": context.target_actor_id,
                "purpose": context.purpose,
                "dataClasses": sorted(context.data_classes),
                "message": message.to_dict(),
            }
        )
        submitted = A2ATask(
            id=task_id,
            context_id=context_id,
            status=A2ATaskStatus(A2ATaskState.SUBMITTED),
            history=(
                *((prior_task.history if prior_task else ())),
                replace(message, task_id=task_id, context_id=context_id),
            ),
            artifacts=prior_task.artifacts if prior_task else (),
            metadata={
                **(dict(prior_task.metadata) if prior_task else {}),
                "interlock.dev/edgeId": edge.id,
                **({"interlock.dev/boundaryId": boundary.id} if boundary else {}),
            },
        )
        task, created = self.task_store.create_or_get(
            tenant_id=context.principal.tenant_id,
            source_actor_id=context.source_actor_id,
            target_actor_id=context.target_actor_id,
            idempotency_key=context.idempotency_key,
            request_fingerprint=request_fingerprint,
            task=submitted,
        )
        if not created:
            return task
        common = {
            "tenant_id": context.principal.tenant_id,
            "trace_id": trace_id,
            "span_id": span_id,
            "interaction_id": interaction_id,
            "source_actor_id": context.source_actor_id,
            "target_actor_id": context.target_actor_id,
            "relationship_type": edge.relationship,
            "relationship_id": edge.relationship_id,
            "environment": context.environment,
            "data_source": context.data_source,
        }
        self.ledger.append(
            "INTERACTION_REQUESTED",
            payload={
                "a2a": {"method": "SendMessage", "taskId": task_id, "contextId": context_id},
                "messageHash": canonical_digest(message.to_dict()),
                "purpose": context.purpose,
                "boundaryId": boundary.id if boundary else None,
            },
            **common,
        )
        self.ledger.append(
            "DATA_FLOW_OBSERVED",
            payload={
                "dataClasses": sorted(context.data_classes),
                "contentHash": canonical_digest(message.to_dict()),
                "payloadBytes": payload_bytes,
            },
            **common,
        )
        decision = ControlDecision.BLOCK if reasons else ControlDecision.ALLOW
        self.ledger.append(
            "CONTROL_EVALUATED",
            payload={
                "control": {
                    "policyId": edge.policy.id,
                    "policyVersion": edge.policy.version,
                    "mode": edge.policy.mode.value,
                    "decision": decision.value,
                    "reasonCodes": list(reasons),
                    "actualEnforced": enforced,
                },
                "boundary": {
                    "id": boundary.id if boundary else None,
                    "mode": boundary.mode.value if boundary else None,
                },
            },
            severity="HIGH" if reasons else "INFO",
            **common,
        )
        if reasons and enforced:
            rejected = replace(task, status=A2ATaskStatus(A2ATaskState.REJECTED))
            self.task_store.update(tenant_id=context.principal.tenant_id, task=rejected)
            self._append_task_event("A2A_TASK_REJECTED", rejected, common, reasons)
            self.ledger.append(
                "ACTION_EXECUTED",
                payload={
                    "result": "COMPLETED",
                    "connectorExecutionId": None,
                    "enforcement": "A2A_BROKER",
                    "taskId": task_id,
                },
                **common,
            )
            self.ledger.append("SECURITY_OUTCOME_SET", payload={"securityOutcome": "BLOCKED"}, **common)
            raise A2APolicyError(reasons)

        working = replace(task, status=A2ATaskStatus(A2ATaskState.WORKING))
        self.task_store.update(tenant_id=context.principal.tenant_id, task=working)
        self._append_task_event("A2A_TASK_WORKING", working, common)
        try:
            result = self._handlers[context.target_actor_id](working, working.history[-1], context)
            completed = self._apply_handler_result(working, result, target.output_schema)
        except Exception as error:
            if isinstance(error, A2AError):
                failure_code = error.reason_code
            else:
                failure_code = "A2A-HANDLER-FAILED"
            failed_message = A2AMessage(
                role=A2AMessageRole.AGENT,
                parts=(A2APart.data_part({"error": failure_code}),),
                task_id=task_id,
                context_id=context_id,
            )
            completed = replace(
                working,
                status=A2ATaskStatus(A2ATaskState.FAILED, failed_message),
                history=(*working.history, failed_message),
            )
            self.task_store.update(tenant_id=context.principal.tenant_id, task=completed)
            self._append_task_event("A2A_TASK_FAILED", completed, common, (failure_code,))
            self.ledger.append(
                "ACTION_EXECUTED",
                payload={
                    "result": "FAILED",
                    "connectorExecutionId": task_id,
                    "taskId": task_id,
                    "failure": failure_code,
                },
                **common,
            )
            self.ledger.append("SECURITY_OUTCOME_SET", payload={"securityOutcome": "UNKNOWN"}, **common)
            if isinstance(error, A2AError):
                raise
            raise A2AError(failure_code, "A2A target handler failed") from error
        self.task_store.update(tenant_id=context.principal.tenant_id, task=completed)
        self._append_task_event("A2A_TASK_STATUS_UPDATED", completed, common)
        self.ledger.append(
            "ACTION_EXECUTED",
            payload={"result": "COMPLETED", "connectorExecutionId": task_id, "taskId": task_id},
            **common,
        )
        self.ledger.append(
            "INTERACTION_COMPLETED",
            payload={"taskId": task_id, "state": completed.status.state.value},
            **common,
        )
        self.ledger.append(
            "SECURITY_OUTCOME_SET",
            payload={"securityOutcome": "SUCCEEDED"},
            **common,
        )
        return completed

    def get_task(self, *, principal: A2APrincipal, task_id: str) -> A2ATask:
        return self.task_store.get(tenant_id=principal.tenant_id, actor_id=principal.actor_id, task_id=task_id)

    def cancel_task(self, *, principal: A2APrincipal, task_id: str) -> A2ATask:
        task = self.task_store.cancel(
            tenant_id=principal.tenant_id,
            actor_id=principal.actor_id,
            task_id=task_id,
        )
        return task

    @staticmethod
    def _apply_handler_result(task: A2ATask, result: A2AHandlerResult, output_schema: Mapping[str, Any]) -> A2ATask:
        response = result.message
        if response is not None:
            response = replace(response, task_id=task.id, context_id=task.context_id)
        artifacts = tuple(result.artifacts)
        data_parts = [
            dict(part.data or {})
            for artifact in artifacts
            for part in artifact.parts
            if part.kind == A2APartKind.DATA
        ]
        schema_value: Any = data_parts[0] if len(data_parts) == 1 else {"artifacts": data_parts}
        if data_parts and validate_schema(schema_value, output_schema):
            raise A2AError("A2A-OUTPUT-SCHEMA-INVALID", "A2A artifact failed the target output schema")
        return replace(
            task,
            status=A2ATaskStatus(result.state, response),
            history=(*task.history, *((response,) if response else ())),
            artifacts=(*task.artifacts, *artifacts),
            metadata={**dict(task.metadata), **dict(result.metadata)},
        )

    def _append_task_event(
        self,
        event_type: str,
        task: A2ATask,
        common: Mapping[str, Any],
        reasons: tuple[str, ...] = (),
    ) -> None:
        self.ledger.append(
            event_type,
            payload={"taskId": task.id, "state": task.status.state.value, "reasonCodes": list(reasons)},
            **common,
        )


class A2AJSONRPCRouter:
    """Authenticated A2A 1.0 JSON-RPC core with 0.3 method aliases."""

    _INVALID_REQUEST = -32600
    _METHOD_NOT_FOUND = -32601
    _INVALID_PARAMS = -32602
    _INTERNAL_ERROR = -32603
    _TASK_NOT_FOUND = -32001
    _TASK_NOT_CANCELABLE = -32002
    _POLICY_BLOCKED = -32099

    def __init__(
        self,
        broker: A2ABroker,
        *,
        target_actor_id: str,
        environment: Environment = Environment.DEV,
        data_source: DataSource = DataSource.PRODUCTION,
    ) -> None:
        self.broker = broker
        self.target_actor_id = target_actor_id
        self.environment = environment
        self.data_source = data_source

    def handle(
        self,
        request: Mapping[str, Any],
        principal: A2APrincipal,
        *,
        protocol_version: str = "1.0",
    ) -> dict[str, Any]:
        request_id = request.get("id")
        method = request.get("method")
        legacy = protocol_version.startswith("0.3")
        if request.get("jsonrpc") != "2.0" or "id" not in request or not isinstance(method, str):
            return self._error(request_id, self._INVALID_REQUEST, "invalid A2A JSON-RPC request")
        try:
            params = _optional_mapping(request.get("params"), "params")
            if method in {"SendMessage", "message/send"}:
                task = self._send(params, principal)
                result = task.to_dict(protocol_version=protocol_version) if legacy else {
                    "task": task.to_dict(protocol_version=protocol_version)
                }
            elif method in {"GetTask", "tasks/get"}:
                task_id = _required_string(params, "id")
                history_length = params.get("historyLength")
                if history_length is not None and (not isinstance(history_length, int) or history_length < 0):
                    raise ValueError("historyLength must be a non-negative integer")
                task_value = self.broker.get_task(principal=principal, task_id=task_id).to_dict(
                    history_length=history_length,
                    protocol_version=protocol_version,
                )
                result = task_value if legacy else {"task": task_value}
            elif method in {"CancelTask", "tasks/cancel"}:
                task_value = self.broker.cancel_task(
                    principal=principal,
                    task_id=_required_string(params, "id"),
                ).to_dict(protocol_version=protocol_version)
                result = task_value if legacy else {"task": task_value}
            elif method in {"GetExtendedAgentCard", "agent/getCard"}:
                card = self.broker.agent_card(self.target_actor_id).to_dict(protocol_version=protocol_version)
                result = card if legacy else {"agentCard": card}
            else:
                return self._error(request_id, self._METHOD_NOT_FOUND, f"A2A method not found: {method}")
        except A2APolicyError as error:
            return self._error(request_id, self._POLICY_BLOCKED, str(error), {"reasonCodes": error.reason_codes})
        except A2AError as error:
            if error.reason_code == "A2A-TASK-NOT-FOUND":
                code = self._TASK_NOT_FOUND
            elif error.reason_code == "A2A-TASK-NOT-CANCELABLE":
                code = self._TASK_NOT_CANCELABLE
            else:
                code = self._INTERNAL_ERROR
            return self._error(request_id, code, str(error), {"reasonCode": error.reason_code})
        except (TypeError, ValueError) as error:
            return self._error(request_id, self._INVALID_PARAMS, str(error))
        except Exception:  # noqa: BLE001 - transport must contain application failures
            return self._error(request_id, self._INTERNAL_ERROR, "A2A request failed")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _send(self, params: Mapping[str, Any], principal: A2APrincipal) -> A2ATask:
        message = A2AMessage.from_dict(_required_mapping(params, "message"))
        metadata = _optional_mapping(params.get("metadata"), "params.metadata")
        purpose = params.get("purpose", metadata.get("interlock.dev/purpose"))
        data_classes_value = params.get(
            "dataClasses",
            metadata.get("interlock.dev/dataClasses", ["D3"]),
        )
        if not isinstance(data_classes_value, list) or not all(isinstance(item, str) for item in data_classes_value):
            raise ValueError("dataClasses must contain strings")
        idempotency_key = params.get(
            "idempotencyKey",
            metadata.get("interlock.dev/idempotencyKey", message.message_id),
        )
        trace_id = params.get("traceId", metadata.get("interlock.dev/traceId"))
        return self.broker.send_message(
            message,
            A2ASendContext(
                principal=principal,
                source_actor_id=principal.actor_id,
                target_actor_id=self.target_actor_id,
                purpose=_required_string({"purpose": purpose}, "purpose"),
                data_classes=frozenset(data_classes_value),
                idempotency_key=_required_string({"idempotencyKey": idempotency_key}, "idempotencyKey"),
                trace_id=_optional_string(trace_id, "traceId"),
                environment=self.environment,
                data_source=self.data_source,
            ),
        )

    @staticmethod
    def _error(request_id: Any, code: int, message: str, data: Mapping[str, Any] | None = None) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data:
            error["data"] = dict(data)
        return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _as_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return value


def _required_mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    return _as_mapping(value.get(key), key)


def _optional_mapping(value: Any, name: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    return _as_mapping(value, name)


def _required_string(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise ValueError(f"{key} must be a non-empty string")
    return item


def _optional_string(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def dynamic_target_matches(edge: ArchitectureEdge, actor_id: str, capabilities: frozenset[str]) -> bool:
    """Public helper for registries admitting dynamic REL-06 instances."""

    selector = edge.target_selector
    return bool(
        edge.dynamic
        and selector
        and fnmatchcase(actor_id, selector.id_pattern)
        and selector.required_capabilities <= capabilities
    )
