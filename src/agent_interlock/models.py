"""Domain types shared by the SDK, policy engine, gateway, and ledger."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Callable, Mapping, Protocol


class ActorType(StrEnum):
    USER = "USER"
    AGENT = "AGENT"
    SUBAGENT = "SUBAGENT"
    TOOL = "TOOL"
    RAG = "RAG"
    MEMORY = "MEMORY"
    SCHEDULER = "SCHEDULER"
    EXTERNAL = "EXTERNAL"


class FailureMode(StrEnum):
    FAIL_OPEN = "FAIL_OPEN"
    FAIL_CLOSED = "FAIL_CLOSED"
    DEGRADE_READ_ONLY = "DEGRADE_READ_ONLY"


class PolicyMode(StrEnum):
    OBSERVE = "OBSERVE"
    SHADOW = "SHADOW"
    ENFORCE = "ENFORCE"


class DefinitionState(StrEnum):
    DISCOVERED = "DISCOVERED"
    QUARANTINED = "QUARANTINED"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    DRIFTED = "DRIFTED"
    REJECTED = "REJECTED"
    REVOKED = "REVOKED"


class SideEffect(StrEnum):
    NONE = "NONE"
    READ = "READ"
    INTERNAL_WRITE = "INTERNAL_WRITE"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"
    DESTRUCTIVE_WRITE = "DESTRUCTIVE_WRITE"
    PAYMENT = "PAYMENT"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"


class ControlDecision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CHALLENGE = "CHALLENGE"
    HOLD = "HOLD"
    SANITIZE = "SANITIZE"
    QUARANTINE = "QUARANTINE"
    REVOKE = "REVOKE"
    DEGRADE = "DEGRADE"
    KILL = "KILL"
    ERROR = "ERROR"
    BYPASSED = "BYPASSED"


class ActionResult(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    PARTIAL = "PARTIAL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class SecurityOutcome(StrEnum):
    ATTEMPTED = "ATTEMPTED"
    BLOCKED = "BLOCKED"
    PARTIALLY_EXECUTED = "PARTIALLY_EXECUTED"
    SUCCEEDED = "SUCCEEDED"
    UNKNOWN = "UNKNOWN"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SIMULATED = "SIMULATED"


class Environment(StrEnum):
    DEV = "DEV"
    STAGE = "STAGE"
    PROD = "PROD"


class DataSource(StrEnum):
    PRODUCTION = "PRODUCTION"
    SIMULATION = "SIMULATION"
    RED_TEAM = "RED_TEAM"
    TEST = "TEST"


@dataclass(frozen=True, slots=True)
class ActorSpec:
    id: str
    type: ActorType
    owner: str
    identity: str
    capabilities: frozenset[str] = frozenset()
    data_access: frozenset[str] = frozenset()
    side_effects: frozenset[SideEffect] = frozenset()
    input_schema: Mapping[str, Any] = field(default_factory=dict)
    output_schema: Mapping[str, Any] = field(default_factory=dict)
    tenant_mode: str = "REQUIRED"
    failure_mode: FailureMode = FailureMode.FAIL_CLOSED
    allowed_domains: frozenset[str] = frozenset()
    max_delegation_depth: int = 1
    definition_digest: str | None = None

    def __post_init__(self) -> None:
        if not self.id or not self.owner or not self.identity:
            raise ValueError("ActorSpec id, owner, and identity are required")
        if self.tenant_mode not in {"REQUIRED", "OPTIONAL", "GLOBAL"}:
            raise ValueError("invalid tenant_mode")
        if self.max_delegation_depth < 0:
            raise ValueError("max_delegation_depth must be non-negative")


@dataclass(frozen=True, slots=True)
class LinkPolicy:
    id: str = "mcp-tool-invoke-default"
    version: str = "1.0.0"
    mode: PolicyMode = PolicyMode.ENFORCE
    source_types: frozenset[ActorType] = frozenset({ActorType.AGENT, ActorType.SUBAGENT})
    target_types: frozenset[ActorType] = frozenset({ActorType.TOOL})
    relationship: str = "INVOKES"
    allowed_purposes: frozenset[str] = frozenset()
    allowed_data_classes: frozenset[str] = frozenset({"D2", "D3", "D7"})
    denied_data_classes: frozenset[str] = frozenset({"D5", "D8"})
    require_active_definition: bool = True
    require_digest_pin: bool = True
    allow_cross_server_references: bool = False
    require_explicit_destination: bool = True
    new_destination_action: ControlDecision = ControlDecision.HOLD
    token_passthrough: bool = False
    require_audience: bool = True
    require_resource: bool = True
    require_actor_binding: bool = True
    max_delegation_depth: int = 1
    external_write_requires_approval: bool = True
    destructive_write_action: ControlDecision = ControlDecision.BLOCK
    undeclared_side_effect_action: ControlDecision = ControlDecision.BLOCK
    secret_action: ControlDecision = ControlDecision.BLOCK
    failure_mode: FailureMode = FailureMode.FAIL_CLOSED
    decision_ttl_seconds: int = 30


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    server_id: str
    tool_name: str
    title: str
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any] = field(default_factory=dict)
    annotations: Mapping[str, Any] = field(default_factory=dict)
    protocol_extensions: Mapping[str, Any] = field(default_factory=dict)
    endpoint: str = ""
    transport: str = "streamable-http"
    publisher: str = ""
    artifact_digest: str = ""

    @property
    def tool_id(self) -> str:
        return f"{self.server_id}:{self.tool_name}"

    def canonical_value(self) -> dict[str, Any]:
        return {
            "serverId": self.server_id,
            "toolName": self.tool_name,
            "title": self.title,
            "description": self.description,
            "inputSchema": dict(self.input_schema),
            "outputSchema": dict(self.output_schema),
            "annotations": dict(self.annotations),
            "protocolExtensions": dict(self.protocol_extensions),
            "endpoint": self.endpoint,
            "transport": self.transport,
            "publisher": self.publisher,
            "artifactDigest": self.artifact_digest,
        }


@dataclass(frozen=True, slots=True)
class CredentialClaims:
    reference: str
    issuer: str
    subject: str
    actor: str
    audience: str
    resource: str
    scopes: frozenset[str] = frozenset()
    delegation_depth: int = 0
    exchanged: bool = True
    fingerprint: str = ""


@dataclass(frozen=True, slots=True)
class InvocationIntent:
    purpose: str
    data_classes: frozenset[str] = frozenset({"D3"})
    destinations: tuple[str, ...] = ()
    estimated_side_effect: SideEffect = SideEffect.NONE
    taint_labels: frozenset[str] = frozenset()
    approval_id: str | None = None
    expected_audience: str = ""
    expected_resource: str = ""


@dataclass(frozen=True, slots=True)
class PolicyDecisionRecord:
    decision_id: str
    decision: ControlDecision
    reason_codes: tuple[str, ...]
    policy_id: str
    policy_version: str
    mode: PolicyMode
    arguments_hash: str
    canonical_destinations: tuple[str, ...]
    expires_at_epoch: float
    enforced: bool
    interaction_id: str
    trace_id: str
    span_id: str

    @property
    def permits_execution(self) -> bool:
        return not self.enforced or self.decision == ControlDecision.ALLOW


@dataclass(frozen=True, slots=True)
class InvocationResult:
    value: Any
    decision: PolicyDecisionRecord
    connector_execution_id: str | None
    labels: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ConnectorExecutionContext:
    connector_execution_id: str
    tenant_id: str
    decision_id: str
    interaction_id: str
    trace_id: str
    arguments_hash: str
    expected_destinations: tuple[str, ...] = ()


class ContextualConnector(Protocol):
    def execute_with_context(
        self,
        arguments: Mapping[str, Any],
        context: ConnectorExecutionContext,
    ) -> Any: ...


Connector = Callable[[Mapping[str, Any]], Any]
ConnectorLike = Connector | ContextualConnector
