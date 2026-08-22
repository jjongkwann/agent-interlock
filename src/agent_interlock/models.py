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
# ALLOW -- and note it is would_block and strongest_decision that need it, not the ``!= ALLOW``
# predicates elsewhere in src/, which deny at any rank including below ALLOW. Ranking it above
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
class ControlCoverage:
    """Which controls were switched on, which looked, and which flagged, for one decision.

    Rides on PolicyDecisionRecord because the gateway composes its ledger event from the record
    alone. ``declaration`` is the whole CONTROL_COVERAGE_DECLARED payload, digest included, built
    once by policy.coverage_declaration; ``digest`` is the same value lifted out so the per-event
    field does not have to index into a mapping.

    Only ``flagged`` is per-invocation. The other two are properties of the link, which is why the
    declaration is emitted once per digest instead of on every event.
    """

    enforcement_point: str
    digest: str
    flagged: tuple[str, ...]
    declaration: Mapping[str, Any]

    def event_fields(self) -> dict[str, Any]:
        """The three keys this adds to ``payload.control`` on CONTROL_EVALUATED.

        Defined once so the three enforcement points cannot spell the wire differently, which is
        the failure mode `executionPermitted` already hit: the A2A broker does not carry it and a
        reducer has to know that. ``flaggedChecks`` carries check ids because
        ``Profile.reason_codes`` is not injective -- two reason keys can rename onto one code -- so
        a reader cannot recover which check fired from the codes it emitted.
        """
        return {
            "enforcementPoint": self.enforcement_point,
            "evaluatedProfile": self.digest,
            "flaggedChecks": list(self.flagged),
        }


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
    # Whether every control decision that contributed to this record was ALLOW; see
    # policy.execution_permitted, which computes it. Carried as its own field because `decision`
    # cannot express it: strongest_decision reduces by severity and annihilates every member ranked
    # below ALLOW, so a record reduced from [ALLOW, BYPASSED] reads ALLOW. Defaults True so a
    # hand-built record behaves exactly as it did before this field existed -- permits_execution
    # ANDs the two, so the field can only ever narrow a permit, never widen one.
    execution_permitted: bool = True
    coverage: ControlCoverage | None = None

    @property
    def permits_execution(self) -> bool:
        """Whether this invocation may run now. Two conditions, and neither implies the other.

        ``decision == ALLOW`` is the severity test, kept rather than derived from the rank map on
        purpose: BYPASSED ranks *below* ALLOW, so a rank-based reading would let an undefined
        verdict execute. ``execution_permitted`` is the separate permission aggregate, and it is
        what catches the case severity cannot see -- ``max`` annihilates BYPASSED, so a record
        reduced from [ALLOW, BYPASSED] has ``decision == ALLOW`` while a control was bypassed.
        Before the second condition existed, adding one unrelated ALLOW finding to a bypassed
        control produced an ENFORCE-mode execution permit.

        This and would_block still disagree on BYPASSED, deliberately: a skipped control raised no
        objection (so it is not a block) and it is not defined anywhere in src/ (so it is not a
        permission). Both answers fail closed. tests/test_decision_ranking.py pins both, and
        tests/test_execution_permit.py pins the aggregate.

        Note the two risk directions differ and only this one is fail-closed. would_block gates
        nothing -- it feeds statistics -- so its BYPASSED answer risks under-reporting instead,
        which is the open question the spec raises about shadowWouldBlockCount.
        """
        return not self.enforced or (self.execution_permitted and self.decision == ControlDecision.ALLOW)

    @property
    def would_block(self) -> bool:
        """Whether the verdict is more severe than ALLOW, regardless of enforcement mode.

        permits_execution answers "may this run now", which is True in SHADOW even for a BLOCK
        verdict. This answers "is the verdict above ALLOW".

        Read from _DECISION_RANK rather than written as ``!= ALLOW`` so the two cannot drift:
        BYPASSED ranks below ALLOW and is not a block -- the control was skipped, it did not
        object -- and any future member ranked below ALLOW inherits that without an edit here.

        This disagrees with permits_execution on BYPASSED, deliberately; read its docstring
        before changing either. Four other predicates in src/ still test ``!= ALLOW`` and so
        disagree with this one on that member -- the spec's open questions list them. The
        statistics reducer left that list by reading the permit beside the decision.
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
