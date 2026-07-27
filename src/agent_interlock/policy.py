"""Deterministic LinkPolicy evaluation for MCP Tool invocations."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Protocol

from .canonical import canonical_digest
from .models import (
    _DECISION_RANK,
    ActorSpec,
    ControlDecision,
    CredentialClaims,
    DefinitionState,
    InvocationIntent,
    LinkPolicy,
    PolicyDecisionRecord,
    PolicyMode,
    SideEffect,
)
from .registry import ToolRevision
from .security import canonical_destination, contains_secret, destination_domain, validate_schema


class CheckScope(StrEnum):
    ACTOR = "ACTOR"
    PAYLOAD = "PAYLOAD"
    PAIR = "PAIR"
    BOUNDARY = "BOUNDARY"


class BoundaryLike(Protocol):
    """Structural view of ArchitectureBoundary.

    policy.py must not import architecture.py: architecture imports sdk, and sdk
    imports policy, so a direct import would close the cycle.
    """

    allowed_relationships: frozenset[str]
    allowed_data_classes: frozenset[str]
    denied_data_classes: frozenset[str]
    require_identity: bool
    require_tenant_binding: bool
    max_payload_bytes: int
    mode: PolicyMode


Findings = tuple[tuple[str, ControlDecision], ...]


@dataclass(frozen=True, slots=True)
class Check:
    id: str
    scope: CheckScope
    armed: Callable[[LinkPolicy], bool]
    run: Callable[[LinkPolicy, "CheckContext"], Findings | None]


@dataclass(frozen=True, slots=True)
class Profile:
    enforcement_point: str
    checks: tuple[str, ...]
    reason_codes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CheckContext:
    source: ActorSpec
    target: ActorSpec
    intent: InvocationIntent
    arguments: Mapping[str, Any]
    interaction_id: str
    trace_id: str
    span_id: str
    revision: ToolRevision | None = None
    credential: CredentialClaims | None = None
    approval_valid: bool = False
    boundary: BoundaryLike | None = None
    payload_bytes: int = 0
    relationship: str = ""


EvaluationInput = CheckContext


def _actor_type(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.source.type in policy.source_types and context.target.type in policy.target_types:
        return ()
    return (("INTERLOCK-ACTOR-TYPE-DENIED", ControlDecision.BLOCK),)


def _purpose(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.intent.purpose in policy.allowed_purposes:
        return ()
    return (("INTERLOCK-PURPOSE-DENIED", ControlDecision.BLOCK),)


def _definition_state(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    # revision=None means this control does not apply to the invocation -- it is a valid
    # CheckContext (Tasks 5-7 build one before a revision is resolved), not a crash. That is
    # INAPPLICABLE, so it returns None and stays out of run_checks' `ran` set; () would claim the
    # control ran and passed. The record evaluate() assembles cannot tell the two apart, but the
    # coverage layer in Plan 2 reads `ran`, and there the difference is the whole point.
    if context.revision is None:
        return None
    if context.revision.state == DefinitionState.ACTIVE:
        return ()
    # The inline branch paired N forwarded reason codes with a single QUARANTINE; as findings that
    # is N pairs, which dedupe and strongest_decision collapse back to the same record.
    codes = context.revision.reason_codes or ("L1-M2-DEFINITION-NOT-ACTIVE",)
    return tuple((code, ControlDecision.QUARANTINE) for code in codes)


def _definition_drift(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.revision is None:  # INAPPLICABLE, see _definition_state
        return None
    approved = context.target.definition_digest
    if approved and approved == context.revision.canonical_digest:
        return ()
    return (("L1-M2-DEFINITION-DRIFT", ControlDecision.QUARANTINE),)


def _input_schema(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    # Falls back to the actor's own schema when no revision is resolved: unlike the M2 checks, a
    # missing revision does not make this control inapplicable -- the SDK never builds one, and
    # skipping here silently dropped schema validation from every wrap() call.
    schema = context.revision.definition.input_schema if context.revision is not None else context.target.input_schema
    # A tool that ships no input schema: INAPPLICABLE, see _definition_state. validate_schema
    # short-circuits on an empty schema, so () here would report a clean pass over a validation that
    # never happened -- on a fleet of schema-less tools, near-total coverage of nothing.
    if not schema:
        return None
    if not validate_schema(context.arguments, schema):
        return ()
    return (("INTERLOCK-INPUT-SCHEMA-INVALID", ControlDecision.BLOCK),)


def _data_classes(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """One check, two reason keys: which one is emitted depends on the classes involved, so a
    profile renaming this check has to map both (see run_checks)."""
    denied = context.intent.data_classes & policy.denied_data_classes
    unexpected = context.intent.data_classes - policy.allowed_data_classes
    if not denied and not unexpected:
        return ()
    key = "L1-M9-SENSITIVE-EGRESS" if "D7" in denied else "INTERLOCK-DATA-CLASS-DENIED"
    return ((key, ControlDecision.BLOCK),)


def _secret(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if not contains_secret(context.arguments):
        return ()
    return (("L1-M8-CREDENTIAL-DETECTED", policy.secret_action),)


def _canonical_destinations(destinations: tuple[str, ...]) -> tuple[str, ...]:
    """Canonicalise what parses and drop what does not. Must not raise: the unparseable entries
    are what the L1-M9-NEW-DESTINATION check reports, and the record needs the rest either way."""
    canonical: list[str] = []
    for destination in destinations:
        try:
            canonical.append(canonical_destination(destination))
        except ValueError:
            continue
    return tuple(canonical)


def _new_destination(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """Three former inline branches, one check: destinations that do not parse, destinations
    outside the target's allowlist, and an external write with no destination at all. All three
    emit the same key with the same decision, so their relative order never reaches the record."""
    destinations = context.intent.destinations
    require_explicit = (
        policy.require_explicit_destination and context.intent.estimated_side_effect == SideEffect.EXTERNAL_WRITE
    )
    if not destinations and not require_explicit:
        return None
    canonical = _canonical_destinations(destinations)
    allowed = {item.rstrip(".").encode("idna").decode("ascii").lower() for item in context.target.allowed_domains}
    finding = ("L1-M9-NEW-DESTINATION", policy.new_destination_action)
    findings = [finding] * (len(destinations) - len(canonical))
    findings.extend(finding for item in canonical if destination_domain(item) not in allowed)
    if require_explicit and not canonical:
        findings.append(finding)
    return tuple(findings)


def _volume(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if (policy.max_export_records and context.intent.estimated_record_count > policy.max_export_records) or (
        policy.max_export_bytes and context.intent.estimated_byte_count > policy.max_export_bytes
    ):
        return (("L1-M9-VOLUME-EXCEEDED", policy.volume_action),)
    return ()


def _side_effect_declared(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.intent.estimated_side_effect in {SideEffect.NONE, *context.target.side_effects}:
        return ()
    return (("L1-UNDECLARED-SIDE-EFFECT", policy.undeclared_side_effect_action),)


def _destructive_write(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.intent.estimated_side_effect != SideEffect.DESTRUCTIVE_WRITE:
        return ()
    return (("INTERLOCK-DESTRUCTIVE-WRITE", policy.destructive_write_action),)


def _tainted_external_write(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.intent.estimated_side_effect != SideEffect.EXTERNAL_WRITE:
        return None
    if not context.intent.taint_labels:
        return ()
    return (("INTERLOCK-TAINTED-EXTERNAL-WRITE", ControlDecision.BLOCK),)


def _approval(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.intent.estimated_side_effect == SideEffect.EXTERNAL_WRITE and not context.approval_valid:
        return (("INTERLOCK-APPROVAL-REQUIRED", ControlDecision.HOLD),)
    return ()


def _credential_missing(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if not (context.intent.expected_audience or context.intent.expected_resource):
        return None  # the intent names no audience or resource, so there is no credential to miss
    if context.credential is not None:
        return ()
    return (("L1-M5-CREDENTIAL-MISSING", ControlDecision.BLOCK),)


def _token_passthrough(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.credential is None:  # nothing presented, _credential_missing owns that verdict
        return None
    if context.credential.exchanged:
        return ()
    return (("L1-M5-TOKEN-PASSTHROUGH", ControlDecision.BLOCK),)


def _token_audience(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """One check, two reason keys. The audience comparison and the resource comparison stay two
    conditions inside one check because each carries its own policy flag, and they emit distinct
    keys because the A2A broker has always reported them as two separate codes. GATEWAY_PROFILE
    and SDK_PROFILE map the resource key back onto the audience one, which is the single code
    those two points have always emitted for both."""
    credential = context.credential
    if credential is None:  # nothing presented, _credential_missing owns that verdict
        return None
    audience = context.intent.expected_audience if policy.require_audience else ""
    resource = context.intent.expected_resource if policy.require_resource else ""
    if not audience and not resource:
        return None  # the intent declares nothing to compare the credential against
    findings: list[tuple[str, ControlDecision]] = []
    if audience and credential.audience != audience:
        findings.append(("L1-M5-TOKEN-AUDIENCE-MISMATCH", ControlDecision.BLOCK))
    if resource and credential.resource != resource:
        findings.append(("L1-M5-TOKEN-RESOURCE-MISMATCH", ControlDecision.BLOCK))
    return tuple(findings)


def _token_actor(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.credential is None:  # nothing presented, _credential_missing owns that verdict
        return None
    if context.credential.actor == context.source.id:
        return ()
    return (("L1-M5-TOKEN-ACTOR-MISMATCH", ControlDecision.BLOCK),)


def _delegation_depth(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.credential is None:  # nothing presented, _credential_missing owns that verdict
        return None
    if context.credential.delegation_depth <= policy.max_delegation_depth:
        return ()
    return (("L1-M5-DELEGATION-DEPTH", ControlDecision.BLOCK),)


def _identity_binding(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """The A2A broker's own binding check: the presented credential must belong to the source
    actor and must be authenticated. Distinct from L1-M5-TOKEN-ACTOR-MISMATCH, which compares the
    same two ids but only when the edge policy asks for actor binding."""
    credential = context.credential
    if credential is None:  # nothing presented, _credential_missing owns that verdict
        return None
    if credential.actor == context.source.id and credential.authenticated:
        return ()
    return (("A2A-IDENTITY-BINDING-MISMATCH", ControlDecision.BLOCK),)


def _message_parts_schema(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """A2A validates the message's data Parts against the target's input schema, not the whole
    envelope the way the gateway validates tool arguments, so it cannot reuse _input_schema. The
    Parts are read back out of the canonical message dict; `arguments` stays the envelope because
    that is what the secret scan has always been given."""
    parts = context.arguments.get("parts") or ()
    data_parts = [part["data"] for part in parts if isinstance(part, Mapping) and "data" in part]
    # No data Parts, or a target that ships no schema: INAPPLICABLE, see _definition_state.
    if not data_parts or not context.target.input_schema:
        return None
    value: Any = data_parts[0] if len(data_parts) == 1 else {"parts": data_parts}
    if not validate_schema(value, context.target.input_schema):
        return ()
    return (("A2A-INPUT-SCHEMA-INVALID", ControlDecision.BLOCK),)


def _payload_present(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.payload_bytes >= 1:
        return ()
    return (("A2A-PAYLOAD-INVALID", ControlDecision.BLOCK),)


def _boundary_relationship(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.boundary is None:  # no boundary on this link, so no boundary contract to answer to
        return None
    if context.relationship in context.boundary.allowed_relationships:
        return ()
    return (("A2A-BOUNDARY-RELATIONSHIP-DENIED", ControlDecision.BLOCK),)


def _boundary_data_classes(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.boundary is None:
        return None
    classes = context.intent.data_classes
    denied = classes & context.boundary.denied_data_classes
    unexpected = classes - context.boundary.allowed_data_classes
    if not denied and not unexpected:
        return ()
    return (("A2A-BOUNDARY-DATA-CLASS-DENIED", ControlDecision.BLOCK),)


def _boundary_identity(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    # The boundary arms these two, not the LinkPolicy, and `armed` is only handed the policy. A
    # boundary with the requirement switched off therefore reports INAPPLICABLE here rather than a
    # clean run of a control nobody asked for.
    if context.boundary is None or not context.boundary.require_identity:
        return None
    if context.credential is not None and context.credential.authenticated:
        return ()
    return (("A2A-BOUNDARY-IDENTITY-REQUIRED", ControlDecision.BLOCK),)


def _boundary_tenant(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.boundary is None or not context.boundary.require_tenant_binding:
        return None
    if context.credential is not None and context.credential.tenant_id:
        return ()
    return (("A2A-BOUNDARY-TENANT-REQUIRED", ControlDecision.BLOCK),)


def _boundary_payload_size(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.boundary is None:
        return None
    if context.payload_bytes <= context.boundary.max_payload_bytes:
        return ()
    return (("A2A-BOUNDARY-PAYLOAD-TOO-LARGE", ControlDecision.BLOCK),)


def _build_check_table(checks: tuple[Check, ...]) -> dict[str, Check]:
    """Build the id-keyed table, raising if two checks share an id: a silent collision would
    drop a control and surface later as a baffling missing-reason-code failure."""
    table: dict[str, Check] = {}
    for check in checks:
        if check.id in table:
            raise ValueError(f"duplicate check id: {check.id!r}")
        table[check.id] = check
    return table


CHECKS: dict[str, Check] = _build_check_table(
    (
        Check(
            id="INTERLOCK-ACTOR-TYPE-DENIED",
            scope=CheckScope.PAIR,
            armed=lambda policy: True,
            run=_actor_type,
        ),
        Check(
            id="INTERLOCK-PURPOSE-DENIED",
            scope=CheckScope.PAIR,
            armed=lambda policy: bool(policy.allowed_purposes),
            run=_purpose,
        ),
        Check(
            id="L1-M2-DEFINITION-NOT-ACTIVE",
            scope=CheckScope.ACTOR,
            armed=lambda policy: policy.require_active_definition,
            run=_definition_state,
        ),
        Check(
            id="L1-M2-DEFINITION-DRIFT",
            scope=CheckScope.ACTOR,
            armed=lambda policy: policy.require_digest_pin,
            run=_definition_drift,
        ),
        Check(
            id="INTERLOCK-INPUT-SCHEMA-INVALID",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy: True,
            run=_input_schema,
        ),
        Check(
            id="INTERLOCK-DATA-CLASS-DENIED",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy: True,
            run=_data_classes,
        ),
        Check(
            id="L1-M8-CREDENTIAL-DETECTED",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy: True,
            run=_secret,
        ),
        Check(
            id="L1-M9-NEW-DESTINATION",
            scope=CheckScope.ACTOR,
            armed=lambda policy: True,
            run=_new_destination,
        ),
        Check(
            id="L1-M9-VOLUME-EXCEEDED",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy: bool(policy.max_export_records or policy.max_export_bytes),
            run=_volume,
        ),
        Check(
            id="L1-UNDECLARED-SIDE-EFFECT",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy: True,
            run=_side_effect_declared,
        ),
        Check(
            id="INTERLOCK-DESTRUCTIVE-WRITE",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy: True,
            run=_destructive_write,
        ),
        Check(
            id="INTERLOCK-TAINTED-EXTERNAL-WRITE",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy: True,
            run=_tainted_external_write,
        ),
        Check(
            id="INTERLOCK-APPROVAL-REQUIRED",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy: policy.external_write_requires_approval,
            run=_approval,
        ),
        Check(
            id="L1-M5-CREDENTIAL-MISSING",
            scope=CheckScope.PAIR,
            armed=lambda policy: True,
            run=_credential_missing,
        ),
        Check(
            id="L1-M5-TOKEN-PASSTHROUGH",
            scope=CheckScope.PAIR,
            armed=lambda policy: not policy.token_passthrough,
            run=_token_passthrough,
        ),
        Check(
            id="L1-M5-TOKEN-AUDIENCE-MISMATCH",
            scope=CheckScope.PAIR,
            armed=lambda policy: policy.require_audience or policy.require_resource,
            run=_token_audience,
        ),
        Check(
            id="L1-M5-TOKEN-ACTOR-MISMATCH",
            scope=CheckScope.PAIR,
            armed=lambda policy: policy.require_actor_binding,
            run=_token_actor,
        ),
        Check(
            id="L1-M5-DELEGATION-DEPTH",
            scope=CheckScope.PAIR,
            armed=lambda policy: True,
            run=_delegation_depth,
        ),
        Check(
            id="A2A-IDENTITY-BINDING-MISMATCH",
            scope=CheckScope.PAIR,
            armed=lambda policy: True,
            run=_identity_binding,
        ),
        Check(
            id="A2A-INPUT-SCHEMA-INVALID",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy: True,
            run=_message_parts_schema,
        ),
        Check(
            id="A2A-PAYLOAD-INVALID",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy: True,
            run=_payload_present,
        ),
        Check(
            id="A2A-BOUNDARY-RELATIONSHIP-DENIED",
            scope=CheckScope.BOUNDARY,
            armed=lambda policy: True,
            run=_boundary_relationship,
        ),
        Check(
            id="A2A-BOUNDARY-DATA-CLASS-DENIED",
            scope=CheckScope.BOUNDARY,
            armed=lambda policy: True,
            run=_boundary_data_classes,
        ),
        Check(
            id="A2A-BOUNDARY-IDENTITY-REQUIRED",
            scope=CheckScope.BOUNDARY,
            armed=lambda policy: True,
            run=_boundary_identity,
        ),
        Check(
            id="A2A-BOUNDARY-TENANT-REQUIRED",
            scope=CheckScope.BOUNDARY,
            armed=lambda policy: True,
            run=_boundary_tenant,
        ),
        Check(
            id="A2A-BOUNDARY-PAYLOAD-TOO-LARGE",
            scope=CheckScope.BOUNDARY,
            armed=lambda policy: True,
            run=_boundary_payload_size,
        ),
    )
)


def run_checks(
    policy: LinkPolicy,
    context: CheckContext,
    profile: Profile,
) -> tuple[list[str], list[ControlDecision], set[str]]:
    """Run a profile's checks. Returns emitted reason codes, decisions, and the ids that ran.

    `profile.reason_codes` is keyed on the reason key a check's `run` emits, not on the check's
    id: a single check can emit more than one distinct reason key (see policy.py's own
    L1-M9-SENSITIVE-EGRESS / INTERLOCK-DATA-CLASS-DENIED branch), so a profile that renames must
    map every key its checks can produce.
    """
    reasons: list[str] = []
    decisions: list[ControlDecision] = []
    ran: set[str] = set()
    for check_id in profile.checks:
        check = CHECKS[check_id]
        if not check.armed(policy):
            continue
        findings = check.run(policy, context)
        if findings is None:
            continue
        ran.add(check_id)
        for key, decision in findings:
            reasons.append(profile.reason_codes.get(key, key))
            decisions.append(decision)
    return reasons, decisions, ran


GATEWAY_PROFILE = Profile(
    enforcement_point="MCP_GATEWAY",
    checks=(
        "INTERLOCK-ACTOR-TYPE-DENIED",
        "INTERLOCK-PURPOSE-DENIED",
        "L1-M2-DEFINITION-NOT-ACTIVE",
        "L1-M2-DEFINITION-DRIFT",
        "INTERLOCK-INPUT-SCHEMA-INVALID",
        "INTERLOCK-DATA-CLASS-DENIED",
        "L1-M8-CREDENTIAL-DETECTED",
        "L1-M9-NEW-DESTINATION",
        "L1-M9-VOLUME-EXCEEDED",
        "L1-UNDECLARED-SIDE-EFFECT",
        "INTERLOCK-DESTRUCTIVE-WRITE",
        # Sits with the other estimated_side_effect checks. Its slot used to be verdict-bearing --
        # it emits a hard-coded BLOCK, and strongest_decision resolved ties by first position, so
        # an earlier slot masked a configured CHALLENGE/REVOKE -- but _DECISION_RANK is total now
        # and this position sets reason-code order only.
        "INTERLOCK-TAINTED-EXTERNAL-WRITE",
        "INTERLOCK-APPROVAL-REQUIRED",
        "L1-M5-CREDENTIAL-MISSING",
        "L1-M5-TOKEN-PASSTHROUGH",
        "L1-M5-TOKEN-AUDIENCE-MISMATCH",
        "L1-M5-TOKEN-ACTOR-MISMATCH",
        "L1-M5-DELEGATION-DEPTH",
    ),
    # _token_audience emits a separate key for the resource comparison so the A2A broker can keep
    # reporting the two as two codes. This point has always emitted one code for both.
    reason_codes={"L1-M5-TOKEN-RESOURCE-MISMATCH": "L1-M5-TOKEN-AUDIENCE-MISMATCH"},
)


SDK_PROFILE = Profile(
    enforcement_point="SDK",
    # Derived from GATEWAY_PROFILE in its order, not rewritten, so the two points keep emitting
    # reason codes in the same order; since _DECISION_RANK became total the order no longer moves
    # the verdict. The two M2 checks are dropped by id rather than left to return None -- the SDK
    # has no ToolRevision to pin, so the control is ABSENT at this enforcement point, not
    # inapplicable to this invocation.
    checks=tuple(
        check_id
        for check_id in GATEWAY_PROFILE.checks
        if check_id not in {"L1-M2-DEFINITION-NOT-ACTIVE", "L1-M2-DEFINITION-DRIFT"}
    ),
    reason_codes=GATEWAY_PROFILE.reason_codes,
)


A2A_PROFILE = Profile(
    enforcement_point="A2A_BROKER",
    # Ordered exactly as A2ABroker emitted these findings inline: the broker reports the whole list
    # and raises on its first entry, so the order is on the wire.
    checks=(
        "A2A-IDENTITY-BINDING-MISMATCH",
        "INTERLOCK-ACTOR-TYPE-DENIED",
        "INTERLOCK-PURPOSE-DENIED",
        "INTERLOCK-DATA-CLASS-DENIED",
        "L1-M8-CREDENTIAL-DETECTED",
        "L1-M5-TOKEN-ACTOR-MISMATCH",
        "L1-M5-TOKEN-AUDIENCE-MISMATCH",
        "L1-M5-TOKEN-PASSTHROUGH",
        "L1-M5-DELEGATION-DEPTH",
        "A2A-INPUT-SCHEMA-INVALID",
        "A2A-PAYLOAD-INVALID",
        "A2A-BOUNDARY-RELATIONSHIP-DENIED",
        "A2A-BOUNDARY-DATA-CLASS-DENIED",
        "A2A-BOUNDARY-IDENTITY-REQUIRED",
        "A2A-BOUNDARY-TENANT-REQUIRED",
        "A2A-BOUNDARY-PAYLOAD-TOO-LARGE",
    ),
    # Keyed on the reason key a check emits, so a check with two keys needs two entries:
    # INTERLOCK-DATA-CLASS-DENIED also emits L1-M9-SENSITIVE-EGRESS on a denied D7, and
    # L1-M5-TOKEN-AUDIENCE-MISMATCH also emits L1-M5-TOKEN-RESOURCE-MISMATCH. Miss one and a
    # gateway-namespace string reaches the A2A wire.
    reason_codes={
        "INTERLOCK-ACTOR-TYPE-DENIED": "A2A-ACTOR-TYPE-DENIED",
        "INTERLOCK-PURPOSE-DENIED": "A2A-PURPOSE-DENIED",
        "INTERLOCK-DATA-CLASS-DENIED": "A2A-DATA-CLASS-DENIED",
        "L1-M9-SENSITIVE-EGRESS": "A2A-DATA-CLASS-DENIED",
        "L1-M8-CREDENTIAL-DETECTED": "A2A-CREDENTIAL-DETECTED",
        "L1-M5-TOKEN-ACTOR-MISMATCH": "A2A-ACTOR-BINDING-MISMATCH",
        "L1-M5-TOKEN-AUDIENCE-MISMATCH": "A2A-AUDIENCE-MISMATCH",
        "L1-M5-TOKEN-RESOURCE-MISMATCH": "A2A-RESOURCE-MISMATCH",
        "L1-M5-TOKEN-PASSTHROUGH": "A2A-TOKEN-PASSTHROUGH",
        "L1-M5-DELEGATION-DEPTH": "A2A-DELEGATION-DEPTH",
    },
)


# Split by scope, not collapsed into one run: the broker answers link findings to the edge policy's
# mode and boundary findings to the boundary's own mode, independently, and neither wins over the
# other. Derived once here rather than rebuilt per message.
A2A_LINK_PROFILE = replace(
    A2A_PROFILE,
    checks=tuple(item for item in A2A_PROFILE.checks if CHECKS[item].scope is not CheckScope.BOUNDARY),
)
A2A_BOUNDARY_PROFILE = replace(
    A2A_PROFILE,
    checks=tuple(item for item in A2A_PROFILE.checks if CHECKS[item].scope is CheckScope.BOUNDARY),
)


def evaluate(policy: LinkPolicy, value: CheckContext) -> PolicyDecisionRecord:
    reasons, decisions, _ = run_checks(policy, value, GATEWAY_PROFILE)
    canonical_destinations = _canonical_destinations(value.intent.destinations)
    return PolicyDecisionRecord(
        decision_id=str(uuid.uuid4()),
        decision=strongest_decision(decisions),
        reason_codes=tuple(dict.fromkeys(reasons)),
        policy_id=policy.id,
        policy_version=policy.version,
        mode=policy.mode,
        arguments_hash=canonical_digest(value.arguments),
        canonical_destinations=canonical_destinations,
        expires_at_epoch=time.time() + policy.decision_ttl_seconds,
        enforced=policy.mode == PolicyMode.ENFORCE,
        interaction_id=value.interaction_id,
        trace_id=value.trace_id,
        span_id=value.span_id,
    )


def strongest_decision(decisions: list[ControlDecision]) -> ControlDecision:
    """The most severe decision in the list, by _DECISION_RANK.

    Every member is ranked and every rank is distinct, so the result does not depend on argument
    order: a profile's check order sets reason-code order and nothing else.
    """
    if not decisions:
        return ControlDecision.ALLOW
    return max(decisions, key=lambda item: _DECISION_RANK[item])
