"""Domain types shared by the SDK, policy engine, gateway, and ledger."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol


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


# Severity order for strongest_decision and would_block. It is a total function of
# ControlDecision, so it belongs beside the enum: whoever adds a twelfth member sees the map and
# the coverage check on the same screen.
#
# BYPASSED ranks below ALLOW: a bypassed control raised no objection, it was skipped, so it must
# not outrank a control that ran and permitted the call.
#
# ERROR ranks above BLOCK but below QUARANTINE, not highest. FAIL_CLOSED needs only ERROR >
# ALLOW -- at any rank above ALLOW every ``!= ALLOW`` predicate in src/ denies. Ranking it above
# KILL would buy nothing and would cost strongest_decision([KILL, ERROR]) == ERROR: one check
# erroring erases a definite KILL, so a consumer routing on the decision takes "unknown, retry"
# instead of "terminate this agent". Neither BYPASSED nor ERROR has a producer in src/; both are
# reachable only through the unconstrained LinkPolicy action fields, and neither is defined
# anywhere yet -- see the spec's open questions before wiring a statistic to either.
#
# There is no fallback rank. A shared fallback made five members tie with BLOCK, which let
# profile check order decide the emitted verdict.
_DECISION_RANK = {
    ControlDecision.BYPASSED: 0,
    ControlDecision.ALLOW: 1,
    ControlDecision.SANITIZE: 2,
    ControlDecision.DEGRADE: 3,
    ControlDecision.CHALLENGE: 4,
    ControlDecision.HOLD: 5,
    ControlDecision.BLOCK: 6,
    ControlDecision.ERROR: 7,
    ControlDecision.QUARANTINE: 8,
    ControlDecision.REVOKE: 9,
    ControlDecision.KILL: 10,
}

# Raised, not asserted: `python -O` strips asserts, and a load-time guarantee must not be
# conditional on an optimisation flag. A twelfth member fails on import rather than reaching
# strongest_decision as a KeyError.
if set(_DECISION_RANK) != set(ControlDecision):
    raise RuntimeError("decision rank map must cover every ControlDecision")


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
    max_export_records: int = 0
    max_export_bytes: int = 0
    volume_action: ControlDecision = ControlDecision.BLOCK
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
    # Read by the A2A broker's identity-binding and boundary-tenant checks. Both default to the
    # value those checks read as *unbound*: a credential nobody authenticated must not be
    # indistinguishable from one that passed, so only a producer that actually verified the
    # principal says so. `exchanged` above predates this and keeps its own (opposite) default.
    tenant_id: str = ""
    authenticated: bool = False


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
    estimated_record_count: int = 1
    estimated_byte_count: int = 0


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
        """Whether this invocation may run now. Tests ``== ALLOW``, not the rank map, on purpose.

        This and would_block disagree on exactly one member, BYPASSED, and the disagreement is
        deliberate rather than an oversight: BYPASSED is not a block, because a skipped control
        raised no objection, and it is also not a permission, because nothing in src/ defines
        what a BYPASSED verdict means. Both answers fail closed. Widening this to "anything not
        would_block" would let an undefined verdict execute; narrowing would_block to ``!= ALLOW``
        would count a bypass as an objection. tests/test_decision_ranking.py pins both.
        """
        return not self.enforced or self.decision == ControlDecision.ALLOW

    @property
    def would_block(self) -> bool:
        """Whether the verdict is more severe than ALLOW, regardless of enforcement mode.

        permits_execution answers "may this run now", which is True in SHADOW even for a BLOCK
        verdict. This answers "is the verdict above ALLOW".

        Read from _DECISION_RANK rather than written as ``!= ALLOW`` so the two cannot drift:
        BYPASSED ranks below ALLOW and is not a block -- the control was skipped, it did not
        object -- and any future member ranked below ALLOW inherits that without an edit here.
        """
        return _DECISION_RANK[self.decision] > _DECISION_RANK[ControlDecision.ALLOW]


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
