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


GATEWAY_PROFILE = Profile(enforcement_point="MCP_GATEWAY", checks=("INTERLOCK-ACTOR-TYPE-DENIED",))


def evaluate(policy: LinkPolicy, value: CheckContext) -> PolicyDecisionRecord:
    reasons, decisions, _ = run_checks(policy, value, GATEWAY_PROFILE)
    arguments_hash = canonical_digest(value.arguments)

    if policy.allowed_purposes and value.intent.purpose not in policy.allowed_purposes:
        reasons.append("INTERLOCK-PURPOSE-DENIED")
        decisions.append(ControlDecision.BLOCK)
    if (
        policy.require_active_definition
        and value.revision is not None
        and value.revision.state != DefinitionState.ACTIVE
    ):
        reasons.extend(value.revision.reason_codes or ("L1-M2-DEFINITION-NOT-ACTIVE",))
        decisions.append(ControlDecision.QUARANTINE)
    if policy.require_digest_pin and value.revision is not None:
        approved = value.target.definition_digest
        if not approved or approved != value.revision.canonical_digest:
            reasons.append("L1-M2-DEFINITION-DRIFT")
            decisions.append(ControlDecision.QUARANTINE)

    # A missing revision means "this check does not apply", not a crash: revision=None is a
    # valid CheckContext (Tasks 5-7 build one before a revision is resolved).
    schema_errors = (
        validate_schema(value.arguments, value.revision.definition.input_schema)
        if value.revision is not None
        else ()
    )
    if schema_errors:
        reasons.append("INTERLOCK-INPUT-SCHEMA-INVALID")
        decisions.append(ControlDecision.BLOCK)
    denied_classes = value.intent.data_classes & policy.denied_data_classes
    unexpected_classes = value.intent.data_classes - policy.allowed_data_classes
    if denied_classes or unexpected_classes:
        reasons.append("L1-M9-SENSITIVE-EGRESS" if "D7" in denied_classes else "INTERLOCK-DATA-CLASS-DENIED")
        decisions.append(ControlDecision.BLOCK)
    if contains_secret(value.arguments):
        reasons.append("L1-M8-CREDENTIAL-DETECTED")
        decisions.append(policy.secret_action)

    canonical_destinations: list[str] = []
    for destination in value.intent.destinations:
        try:
            canonical_destinations.append(canonical_destination(destination))
        except ValueError:
            reasons.append("L1-M9-NEW-DESTINATION")
            decisions.append(policy.new_destination_action)
    allowed_domains = {item.rstrip(".").encode("idna").decode("ascii").lower() for item in value.target.allowed_domains}
    for destination in canonical_destinations:
        if destination_domain(destination) not in allowed_domains:
            reasons.append("L1-M9-NEW-DESTINATION")
            decisions.append(policy.new_destination_action)
    if (
        policy.require_explicit_destination
        and value.intent.estimated_side_effect == SideEffect.EXTERNAL_WRITE
        and not canonical_destinations
    ):
        reasons.append("L1-M9-NEW-DESTINATION")
        decisions.append(policy.new_destination_action)
    if (policy.max_export_records and value.intent.estimated_record_count > policy.max_export_records) or (
        policy.max_export_bytes and value.intent.estimated_byte_count > policy.max_export_bytes
    ):
        reasons.append("L1-M9-VOLUME-EXCEEDED")
        decisions.append(policy.volume_action)

    if value.intent.estimated_side_effect not in {SideEffect.NONE, *value.target.side_effects}:
        reasons.append("L1-UNDECLARED-SIDE-EFFECT")
        decisions.append(policy.undeclared_side_effect_action)
    if value.intent.estimated_side_effect == SideEffect.DESTRUCTIVE_WRITE:
        decisions.append(policy.destructive_write_action)
        reasons.append("INTERLOCK-DESTRUCTIVE-WRITE")
    if (
        value.intent.estimated_side_effect == SideEffect.EXTERNAL_WRITE
        and policy.external_write_requires_approval
        and not value.approval_valid
    ):
        decisions.append(ControlDecision.HOLD)
        reasons.append("INTERLOCK-APPROVAL-REQUIRED")

    credential = value.credential
    if not credential and (value.intent.expected_audience or value.intent.expected_resource):
        reasons.append("L1-M5-CREDENTIAL-MISSING")
        decisions.append(ControlDecision.BLOCK)
    elif credential:
        if not policy.token_passthrough and not credential.exchanged:
            reasons.append("L1-M5-TOKEN-PASSTHROUGH")
            decisions.append(ControlDecision.BLOCK)
        if (
            policy.require_audience
            and value.intent.expected_audience
            and credential.audience != value.intent.expected_audience
        ):
            reasons.append("L1-M5-TOKEN-AUDIENCE-MISMATCH")
            decisions.append(ControlDecision.BLOCK)
        if (
            policy.require_resource
            and value.intent.expected_resource
            and credential.resource != value.intent.expected_resource
        ):
            reasons.append("L1-M5-TOKEN-AUDIENCE-MISMATCH")
            decisions.append(ControlDecision.BLOCK)
        if policy.require_actor_binding and credential.actor != value.source.id:
            reasons.append("L1-M5-TOKEN-ACTOR-MISMATCH")
            decisions.append(ControlDecision.BLOCK)
        if credential.delegation_depth > policy.max_delegation_depth:
            reasons.append("L1-M5-DELEGATION-DEPTH")
            decisions.append(ControlDecision.BLOCK)

    decision = strongest_decision(decisions)
    return PolicyDecisionRecord(
        decision_id=str(uuid.uuid4()),
        decision=decision,
        reason_codes=tuple(dict.fromkeys(reasons)),
        policy_id=policy.id,
        policy_version=policy.version,
        mode=policy.mode,
        arguments_hash=arguments_hash,
        canonical_destinations=tuple(canonical_destinations),
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
