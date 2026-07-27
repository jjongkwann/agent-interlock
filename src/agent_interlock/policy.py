"""Deterministic LinkPolicy evaluation for MCP Tool invocations."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from .canonical import canonical_digest
from .models import (
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
    # No revision, or a tool that ships no input schema: INAPPLICABLE, see _definition_state.
    # validate_schema short-circuits on an empty schema, so () here would report a clean pass over
    # a validation that never happened -- on a fleet of schema-less tools, near-total coverage of
    # nothing.
    if context.revision is None or not context.revision.definition.input_schema:
        return None
    if not validate_schema(context.arguments, context.revision.definition.input_schema):
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
    """The audience comparison and the resource comparison emit the same reason key (inherited,
    not introduced here) and check ids are unique, so they are one check. They stay two
    conditions inside it because each carries its own policy flag."""
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
        findings.append(("L1-M5-TOKEN-AUDIENCE-MISMATCH", ControlDecision.BLOCK))
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
        # Sits with the other estimated_side_effect checks, and after the two whose decision the
        # policy configures: it emits a hard-coded BLOCK, and strongest_decision resolves ties by
        # first position, so an earlier slot would mask a configured CHALLENGE/REVOKE here.
        "INTERLOCK-TAINTED-EXTERNAL-WRITE",
        "INTERLOCK-APPROVAL-REQUIRED",
        "L1-M5-CREDENTIAL-MISSING",
        "L1-M5-TOKEN-PASSTHROUGH",
        "L1-M5-TOKEN-AUDIENCE-MISMATCH",
        "L1-M5-TOKEN-ACTOR-MISMATCH",
        "L1-M5-DELEGATION-DEPTH",
    ),
)


SDK_PROFILE = Profile(
    enforcement_point="SDK",
    # Derived from GATEWAY_PROFILE in its order, not rewritten: strongest_decision still resolves
    # ties by position, so a fresh tuple would silently change verdicts. The two M2 checks are
    # dropped by id rather than left to return None -- the SDK has no ToolRevision to pin, so the
    # control is ABSENT at this enforcement point, not inapplicable to this invocation.
    checks=tuple(
        check_id
        for check_id in GATEWAY_PROFILE.checks
        if check_id not in {"L1-M2-DEFINITION-NOT-ACTIVE", "L1-M2-DEFINITION-DRIFT"}
    ),
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
    if not decisions:
        return ControlDecision.ALLOW
    order = {
        ControlDecision.ALLOW: 0,
        ControlDecision.SANITIZE: 1,
        ControlDecision.HOLD: 2,
        ControlDecision.BLOCK: 3,
        ControlDecision.QUARANTINE: 4,
        ControlDecision.KILL: 5,
    }
    return max(decisions, key=lambda item: order.get(item, 3))
