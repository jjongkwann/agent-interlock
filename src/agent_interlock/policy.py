"""Deterministic LinkPolicy evaluation for MCP Tool invocations."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Protocol

from .canonical import canonical_digest
from .intent import derive_intent, side_effect_rank
from .models import (
    _DECISION_RANK,
    ActorSpec,
    ControlCoverage,
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
from .security import (
    canonical_destination,
    contains_secret,
    destination_domain,
    has_scannable_text,
    validate_schema,
)


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
    """One control, declared once and selected by profile.

    ``armed`` answers "is this control switched on for this link at all" and ``run`` answers "what
    did it find on this invocation". The split is what separates ABSENT from INAPPLICABLE: a
    control the operator turned off never had a subject, while one that is on but met an
    invocation it does not apply to did.

    ``armed`` is handed the whole context but may read only the **link-constant** half of it --
    ``policy``, ``source``, ``target``, ``boundary``, ``revision``, ``relationship``. Reading
    ``intent``, ``arguments``, ``credential``, ``approval_valid`` or ``payload_bytes`` would make
    the armed set vary per invocation, and the armed set is declared once per coverage digest
    rather than recorded per event. ``test_check_table`` pins the invariant over every check by
    varying exactly the per-invocation fields.
    """

    id: str
    scope: CheckScope
    armed: Callable[[LinkPolicy, "CheckContext"], bool]
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


def _effective_schema(context: CheckContext) -> Mapping[str, Any]:
    """The schema _input_schema validates against: the resolved revision's, or the actor's own.

    Falls back to the actor when no revision is resolved -- unlike the M2 checks, a missing
    revision does not make this control inapplicable; the SDK never builds one, and skipping here
    silently dropped schema validation from every wrap() call. Shared with `armed` so the two
    cannot disagree about whether there is a schema: arming on the actor alone would report ABSENT
    for a gateway call whose revision carries one, and the check would then run while declared off.
    """
    if context.revision is not None:
        return context.revision.definition.input_schema
    return context.target.input_schema


def _input_schema(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    # A tool that ships no input schema switches this control off for the link -- `armed` reads the
    # same helper, so this branch is reached only from a directly-built context. validate_schema
    # short-circuits on an empty schema, so () here would report a clean pass over a validation
    # that never happened -- on a fleet of schema-less tools, near-total coverage of nothing.
    schema = _effective_schema(context)
    if not schema:
        return None
    if not validate_schema(context.arguments, schema):
        return ()
    return (("INTERLOCK-INPUT-SCHEMA-INVALID", ControlDecision.BLOCK),)


def _data_classes(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """One check, two reason keys: which one is emitted depends on the classes involved, so a
    profile renaming this check has to map both (see run_checks)."""
    if not context.intent.data_classes:
        return None  # nothing declared to classify: INAPPLICABLE, see _definition_state
    denied = context.intent.data_classes & policy.denied_data_classes
    unexpected = context.intent.data_classes - policy.allowed_data_classes
    if not denied and not unexpected:
        return ()
    key = "L1-M9-SENSITIVE-EGRESS" if "D7" in denied else "INTERLOCK-DATA-CLASS-DENIED"
    return ((key, ControlDecision.BLOCK),)


def _secret(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    # contains_secret is False both for "scanned, clean" and for "there was nothing to scan".
    # Only the first is RAN_CLEAN; a numeric-only argument map is INAPPLICABLE.
    if not has_scannable_text(context.arguments):
        return None
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


def _canonical_domains(domains: frozenset[str]) -> set[str]:
    """IDNA-encode the allowlist entries that encode and drop the ones that do not.

    Must not raise, for the same reason _canonical_destinations must not: this runs inside a check,
    and neither evaluate() nor the SDK wraps the call, so a UnicodeError from an entry that is not a
    domain (an over-63-character DNS label, an empty label in "x..y") escapes all the way out of
    wrap() -- past CONTROL_EVALUATED, leaving a ledger interaction with no control record at all.

    Dropping the entry is the fail-closed direction and needs no new reason code. canonical_destination
    applies the same .encode("idna") to the destination host, so an entry that cannot be encoded could
    never have matched anything on the wire: removing it cannot turn a deny into a permit, and the
    destination it was meant to permit is then simply not allowed. Dropping is per entry, so a
    malformed entry does not disarm its well-formed siblings.
    """
    allowed: set[str] = set()
    for domain in domains:
        try:
            allowed.add(domain.rstrip(".").encode("idna").decode("ascii").lower())
        except UnicodeError:
            continue
    return allowed


def _new_destination(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """Three former inline branches, one check: destinations that do not parse, destinations
    outside the target's allowlist, and an external write with no destination at all. All three
    emit the same key with the same decision, so their relative order never reaches the record."""
    destinations = context.intent.destinations
    require_explicit = (
        policy.require_explicit_destination and context.intent.estimated_side_effect == SideEffect.EXTERNAL_WRITE
    )
    # No destination declared and none required: the control has no subject, so it is INAPPLICABLE
    # (see _definition_state) whatever the allowlist looks like. Canonicalising the allowlist above
    # this line -- which is where the gateway used to do it -- would make a malformed entry crash an
    # invocation that declares no egress at all.
    if not destinations and not require_explicit:
        return None
    canonical = _canonical_destinations(destinations)
    allowed = _canonical_domains(context.target.allowed_domains)
    finding = ("L1-M9-NEW-DESTINATION", policy.new_destination_action)
    findings = [finding] * (len(destinations) - len(canonical))
    findings.extend(finding for item in canonical if destination_domain(item) not in allowed)
    if require_explicit and not canonical:
        findings.append(finding)
    return tuple(findings)


def _annotations(context: CheckContext) -> Mapping[str, Any]:
    """The MCP annotations the intent derivation reads. The SDK resolves no revision, so there are
    none there; shared with `armed` so the two cannot disagree about whether any exist."""
    if context.revision is None:
        return {}
    return context.revision.definition.annotations


def _intent_argument_mismatch(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """The declared intent has to cover what the arguments actually say.

    Every other M9 control reads `context.intent`, which is whatever the caller wrote. That is
    sound when the caller is the integrator; on the adoption path the caller is an agent framework
    relaying a model's tool call, so the declaration is the one input an attacker-influenced model
    chooses. This check compares it against a derivation from evidence the caller did not author --
    the tool's input schema and its MCP annotations -- and reports each way the declaration falls
    short. Under-declaring is the whole attack: an intent naming no destination and NONE walks past
    the destination, volume, approval and side-effect controls with nothing for them to judge.

    One finding per violation, all under one key, so an argument naming three undeclared recipients
    is not indistinguishable from one naming a single recipient.
    """
    derived = derive_intent(context.arguments, _effective_schema(context), _annotations(context))
    if not derived.derivable:
        # Nothing marks a destination and no annotation asserts a side effect: no evidence to
        # compare the declaration against, which is INAPPLICABLE (see _definition_state). Returning
        # () here would report a control that examined nothing as one that examined and cleared.
        return None
    finding = ("INTERLOCK-INTENT-ARGUMENT-MISMATCH", ControlDecision.BLOCK)
    declared = {destination_domain(item) for item in _canonical_destinations(context.intent.destinations)}
    findings: list[tuple[str, ControlDecision]] = []
    for destination in derived.destinations:
        try:
            canonical = canonical_destination(destination)
        except ValueError:
            findings.append(finding)  # an argument that names no parseable destination is uncovered
            continue
        if destination_domain(canonical) not in declared:
            findings.append(finding)
    if side_effect_rank(derived.side_effect) > side_effect_rank(context.intent.estimated_side_effect):
        findings.append(finding)
    return tuple(findings)


def _volume_records(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """The record half of the volume cap.

    Split from the byte half because each carries its own policy field: as one check armed on
    `max_export_records or max_export_bytes`, a link that caps bytes only reported the record
    control as RAN_CLEAN on every invocation -- a control that is off, reported as one that ran and
    found nothing. Both halves keep emitting L1-M9-VOLUME-EXCEEDED; only the check id splits, and
    every profile maps the byte key back onto the wire code the point has always emitted.
    """
    if context.intent.estimated_record_count <= 0:
        return None  # no estimate to compare the cap against
    if context.intent.estimated_record_count > policy.max_export_records:
        return (("L1-M9-VOLUME-EXCEEDED", policy.volume_action),)
    return ()


def _volume_bytes(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.intent.estimated_byte_count <= 0:
        return None
    if context.intent.estimated_byte_count > policy.max_export_bytes:
        return (("L1-M9-VOLUME-BYTES-EXCEEDED", policy.volume_action),)
    return ()


def _side_effect_declared(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.intent.estimated_side_effect in {SideEffect.NONE, *context.target.side_effects}:
        return ()
    return (("L1-UNDECLARED-SIDE-EFFECT", policy.undeclared_side_effect_action),)


def _destructive_write(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    # One convention across the three side-effect checks: the side effect a check governs IS its
    # subject, so a different one means INAPPLICABLE, not a clean pass. Two of the three used to
    # return () here, so read-only traffic showed _tainted_external_write near 100% INAPPLICABLE
    # and these two near 100% RAN_CLEAN -- the same situation, opposite statistic.
    if context.intent.estimated_side_effect != SideEffect.DESTRUCTIVE_WRITE:
        return None
    return (("INTERLOCK-DESTRUCTIVE-WRITE", policy.destructive_write_action),)


def _tainted_external_write(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.intent.estimated_side_effect != SideEffect.EXTERNAL_WRITE:
        return None
    if not context.intent.taint_labels:
        return ()
    return (("INTERLOCK-TAINTED-EXTERNAL-WRITE", ControlDecision.BLOCK),)


def _approval(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.intent.estimated_side_effect != SideEffect.EXTERNAL_WRITE:
        return None  # one convention, see _destructive_write
    if not context.approval_valid:
        return (("INTERLOCK-APPROVAL-REQUIRED", ControlDecision.HOLD),)
    return ()


def _usable_credential(credential: CredentialClaims | None) -> bool:
    """Whether the M5 family has a credential it can rely on: one that was presented, and that a
    producer which actually ran a verifier marked `authenticated`.

    The single definition the whole family reads. Every other field on CredentialClaims is whatever
    the caller wrote -- issuer, subject, actor, audience, resource, delegation_depth -- so on a
    credential nobody verified, each of the comparison checks below compares a forged claim against
    itself. mcp_oauth.MCPAuthorizationCodeTokenClient.exchange is the one producer in src/ that runs
    the claims verifier and therefore the one that sets the flag.

    Shared rather than restated in each check because the family disagreeing about it is the defect:
    when only the presence check read `authenticated`, absence made its four siblings INAPPLICABLE
    while a forgery made them RAN_CLEAN, and the forgery read as *better examined* than the absence
    in the coverage channel.
    """
    return credential is not None and credential.authenticated


def _credential_missing(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """The M5 presence check: does this invocation have a credential it can rely on?

    Reads `authenticated`, not the object's existence, and owns the unusable-credential verdict for
    the whole family -- the four comparison checks below defer to it rather than reporting a clean
    pass over fields the caller chose.

    L1-M5-CREDENTIAL-MISSING carries the unverified case rather than a new code, and carrying it
    here is the point rather than a compromise: presenting a forged credential used to be strictly
    better for an attacker than presenting none -- none blocked here, forged satisfied every M5
    check and reported the invocation checked and clean. Both now reach the same verdict under the
    same code, which is what removes the incentive. To M5, an unverified claims blob is not a
    credential that is present; it is a credential that is missing.

    A credential that was presented and is unusable is flagged whatever the intent names. The
    expectation gate applies only to the *absent* case: with nothing presented and nothing expected
    this control has no subject, so it is INAPPLICABLE. Gating both cases on the expectation is what
    would leave the deferral above unowned -- a forged credential under an intent naming no audience
    or resource would then be refused only by whichever sibling its attacker-chosen fields happened
    to trip, which is the attacker declining to set a field rather than a control.
    """
    if _usable_credential(context.credential):
        # Verified, so this control's question is answered; it only has a subject at all when the
        # intent named something to rely on the credential for.
        return () if (context.intent.expected_audience or context.intent.expected_resource) else None
    if context.credential is None and not (context.intent.expected_audience or context.intent.expected_resource):
        return None  # nothing presented and nothing expected, so there is no credential to miss
    return (("L1-M5-CREDENTIAL-MISSING", ControlDecision.BLOCK),)


def _token_passthrough(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if not _usable_credential(context.credential):
        # No credential this check can rely on -- nothing presented, or nothing verified. Either way
        # there is nothing here to examine, and _credential_missing owns that verdict (on A2A_PROFILE,
        # which does not carry it, _identity_binding does).
        return None
    if context.credential.exchanged:
        return ()
    return (("L1-M5-TOKEN-PASSTHROUGH", ControlDecision.BLOCK),)


def _token_audience(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """The audience comparison, armed by `require_audience` alone.

    Was one check with the resource comparison, armed on `require_audience or require_resource`.
    That bundling is why the split exists: with require_audience off, require_resource on and a
    wrong audience, the pair reported RAN_CLEAN -- the audience control switched off, the audience
    wrong, and the statistic saying the check ran and found nothing. Each half now answers to its
    own flag. The two still emit distinct reason keys, because the A2A broker has always reported
    them as two codes; GATEWAY_PROFILE and SDK_PROFILE map the resource key back onto the audience
    one, the single code those two points have always emitted for both.
    """
    credential = context.credential
    if not _usable_credential(credential):  # nothing to compare against, see _token_passthrough
        return None
    if not context.intent.expected_audience:
        return None  # the intent declares no audience to compare the credential against
    if credential.audience != context.intent.expected_audience:
        return (("L1-M5-TOKEN-AUDIENCE-MISMATCH", ControlDecision.BLOCK),)
    return ()


def _token_resource(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """The resource comparison, armed by `require_resource` alone. See _token_audience."""
    credential = context.credential
    if not _usable_credential(credential):
        return None
    if not context.intent.expected_resource:
        return None
    if credential.resource != context.intent.expected_resource:
        return (("L1-M5-TOKEN-RESOURCE-MISMATCH", ControlDecision.BLOCK),)
    return ()


def _token_actor(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if not _usable_credential(context.credential):  # nothing to compare against, see _token_passthrough
        return None
    if context.credential.actor == context.source.id:
        return ()
    return (("L1-M5-TOKEN-ACTOR-MISMATCH", ControlDecision.BLOCK),)


def _delegation_depth(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if not _usable_credential(context.credential):  # attacker-chosen depth, see _token_passthrough
        return None
    if context.credential.delegation_depth <= policy.max_delegation_depth:
        return ()
    return (("L1-M5-DELEGATION-DEPTH", ControlDecision.BLOCK),)


def _identity_binding(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    """The A2A broker's own binding check: the presented credential must belong to the source
    actor and must be authenticated. Distinct from L1-M5-TOKEN-ACTOR-MISMATCH, which compares the
    same two ids but only when the edge policy asks for actor binding.

    This is the check that *owns* the unusable-credential verdict on A2A_PROFILE, which does not
    carry L1-M5-CREDENTIAL-MISSING -- so unlike the four M5 comparison checks it flags an
    unauthenticated credential rather than deferring. A2ABroker always builds a credential from its
    principal, so the None branch below is reachable only from a hand-built CheckContext.
    """
    credential = context.credential
    if credential is None:  # nothing presented at all, so this check has no subject either
        return None
    if credential.actor == context.source.id and _usable_credential(credential):
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
    """Unsatisfiable through A2ABroker: A2AMessage.__post_init__ requires at least one part, so
    payload_bytes is never below 2 on the live path and this check reports RAN_CLEAN on every
    message. Kept rather than deleted -- the constructor is what enforces the invariant today, and
    a second producer that builds a CheckContext directly would meet no guard at all. Read its
    byCheck row as "the constructor held", not as a control that was exercised;
    test_check_table pins both halves of that sentence."""
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
    if not classes:
        return None  # nothing declared to classify, see _data_classes
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
    """Unsatisfiable through A2ABroker for the same reason as _payload_present:
    A2APrincipal.__post_init__ rejects an empty tenant, so the credential the broker builds always
    carries one. Read its byCheck row accordingly."""
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
            armed=lambda policy, context: True,
            run=_actor_type,
        ),
        Check(
            id="INTERLOCK-PURPOSE-DENIED",
            scope=CheckScope.PAIR,
            armed=lambda policy, context: bool(policy.allowed_purposes),
            run=_purpose,
        ),
        Check(
            id="L1-M2-DEFINITION-NOT-ACTIVE",
            scope=CheckScope.ACTOR,
            armed=lambda policy, context: policy.require_active_definition,
            run=_definition_state,
        ),
        Check(
            id="L1-M2-DEFINITION-DRIFT",
            scope=CheckScope.ACTOR,
            armed=lambda policy, context: policy.require_digest_pin,
            run=_definition_drift,
        ),
        Check(
            id="INTERLOCK-INPUT-SCHEMA-INVALID",
            scope=CheckScope.PAYLOAD,
            # An actor property, not a policy switch: a tool that ships no schema has this control
            # off for every call on the link, which is ABSENT, not INAPPLICABLE per invocation.
            armed=lambda policy, context: bool(_effective_schema(context)),
            run=_input_schema,
        ),
        Check(
            id="INTERLOCK-DATA-CLASS-DENIED",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy, context: True,
            run=_data_classes,
        ),
        Check(
            id="L1-M8-CREDENTIAL-DETECTED",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy, context: True,
            run=_secret,
        ),
        Check(
            id="L1-M9-NEW-DESTINATION",
            scope=CheckScope.ACTOR,
            armed=lambda policy, context: True,
            run=_new_destination,
        ),
        Check(
            id="INTERLOCK-INTENT-ARGUMENT-MISMATCH",
            scope=CheckScope.PAYLOAD,
            # Link-constant, like every other `armed`: a schema to read destination marks off, or
            # annotations to read a side effect from. A tool that ships neither offers this control
            # no evidence on any call over the link, which is ABSENT, not per-invocation
            # INAPPLICABLE -- the same distinction INTERLOCK-INPUT-SCHEMA-INVALID draws.
            armed=lambda policy, context: bool(_effective_schema(context)) or bool(_annotations(context)),
            run=_intent_argument_mismatch,
        ),
        Check(
            id="L1-M9-VOLUME-EXCEEDED",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy, context: bool(policy.max_export_records),
            run=_volume_records,
        ),
        Check(
            id="L1-M9-VOLUME-BYTES-EXCEEDED",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy, context: bool(policy.max_export_bytes),
            run=_volume_bytes,
        ),
        Check(
            id="L1-UNDECLARED-SIDE-EFFECT",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy, context: True,
            run=_side_effect_declared,
        ),
        Check(
            id="INTERLOCK-DESTRUCTIVE-WRITE",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy, context: True,
            run=_destructive_write,
        ),
        Check(
            id="INTERLOCK-TAINTED-EXTERNAL-WRITE",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy, context: True,
            run=_tainted_external_write,
        ),
        Check(
            id="INTERLOCK-APPROVAL-REQUIRED",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy, context: policy.external_write_requires_approval,
            run=_approval,
        ),
        Check(
            id="L1-M5-CREDENTIAL-MISSING",
            scope=CheckScope.PAIR,
            armed=lambda policy, context: True,
            run=_credential_missing,
        ),
        Check(
            id="L1-M5-TOKEN-PASSTHROUGH",
            scope=CheckScope.PAIR,
            armed=lambda policy, context: not policy.token_passthrough,
            run=_token_passthrough,
        ),
        Check(
            id="L1-M5-TOKEN-AUDIENCE-MISMATCH",
            scope=CheckScope.PAIR,
            armed=lambda policy, context: policy.require_audience,
            run=_token_audience,
        ),
        Check(
            id="L1-M5-TOKEN-RESOURCE-MISMATCH",
            scope=CheckScope.PAIR,
            armed=lambda policy, context: policy.require_resource,
            run=_token_resource,
        ),
        Check(
            id="L1-M5-TOKEN-ACTOR-MISMATCH",
            scope=CheckScope.PAIR,
            armed=lambda policy, context: policy.require_actor_binding,
            run=_token_actor,
        ),
        Check(
            id="L1-M5-DELEGATION-DEPTH",
            scope=CheckScope.PAIR,
            armed=lambda policy, context: True,
            run=_delegation_depth,
        ),
        Check(
            id="A2A-IDENTITY-BINDING-MISMATCH",
            scope=CheckScope.PAIR,
            armed=lambda policy, context: True,
            run=_identity_binding,
        ),
        Check(
            id="A2A-INPUT-SCHEMA-INVALID",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy, context: bool(context.target.input_schema),
            run=_message_parts_schema,
        ),
        Check(
            id="A2A-PAYLOAD-INVALID",
            scope=CheckScope.PAYLOAD,
            armed=lambda policy, context: True,
            run=_payload_present,
        ),
        Check(
            id="A2A-BOUNDARY-RELATIONSHIP-DENIED",
            scope=CheckScope.BOUNDARY,
            armed=lambda policy, context: context.boundary is not None,
            run=_boundary_relationship,
        ),
        Check(
            id="A2A-BOUNDARY-DATA-CLASS-DENIED",
            scope=CheckScope.BOUNDARY,
            armed=lambda policy, context: context.boundary is not None,
            run=_boundary_data_classes,
        ),
        Check(
            id="A2A-BOUNDARY-IDENTITY-REQUIRED",
            scope=CheckScope.BOUNDARY,
            armed=lambda policy, context: context.boundary is not None and context.boundary.require_identity,
            run=_boundary_identity,
        ),
        Check(
            id="A2A-BOUNDARY-TENANT-REQUIRED",
            scope=CheckScope.BOUNDARY,
            armed=lambda policy, context: context.boundary is not None and context.boundary.require_tenant_binding,
            run=_boundary_tenant,
        ),
        Check(
            id="A2A-BOUNDARY-PAYLOAD-TOO-LARGE",
            scope=CheckScope.BOUNDARY,
            armed=lambda policy, context: context.boundary is not None,
            run=_boundary_payload_size,
        ),
    )
)


@dataclass(frozen=True, slots=True)
class CheckOutcome:
    """What one profile's checks did on one invocation.

    ``reasons`` and ``decisions`` are the verdict; the other three are the coverage channel, and
    they are what separates "no control objected" from "no control looked".

    - ``armed`` -- ids switched on for this link, in profile order. Ids in the profile but absent
      here are ABSENT: the operator turned the control off, or the point never carried it.
    - ``ran`` -- armed ids whose ``run`` returned findings (empty or not). Armed but not here is
      INAPPLICABLE: the control is on and this invocation gave it nothing to judge.
    - ``flagged`` -- ids that returned at least one finding. In ``ran`` but not here is RAN_CLEAN.

    ``flagged`` carries check ids rather than leaving consumers to invert ``profile.reason_codes``:
    that map is not injective -- L1-M9-SENSITIVE-EGRESS and INTERLOCK-DATA-CLASS-DENIED both emit
    A2A-DATA-CLASS-DENIED -- so a reason code cannot name the check that produced it.
    """

    reasons: list[str]
    decisions: list[ControlDecision]
    ran: set[str]
    armed: tuple[str, ...]
    flagged: set[str]


def run_checks(
    policy: LinkPolicy,
    context: CheckContext,
    profile: Profile,
) -> CheckOutcome:
    """Run a profile's checks, returning the verdict and the coverage channel.

    `profile.reason_codes` is keyed on the reason key a check's `run` emits, not on the check's
    id: a single check can emit more than one distinct reason key (see policy.py's own
    L1-M9-SENSITIVE-EGRESS / INTERLOCK-DATA-CLASS-DENIED branch), so a profile that renames must
    map every key its checks can produce.
    """
    reasons: list[str] = []
    decisions: list[ControlDecision] = []
    ran: set[str] = set()
    armed: list[str] = []
    flagged: set[str] = set()
    for check_id in profile.checks:
        check = CHECKS[check_id]
        if not check.armed(policy, context):
            continue
        armed.append(check_id)
        findings = check.run(policy, context)
        if findings is None:
            continue
        ran.add(check_id)
        if findings:
            flagged.add(check_id)
        for key, decision in findings:
            reasons.append(profile.reason_codes.get(key, key))
            decisions.append(decision)
    return CheckOutcome(
        reasons=reasons,
        decisions=decisions,
        ran=ran,
        armed=tuple(armed),
        flagged=flagged,
    )


def coverage_declaration(
    policy: LinkPolicy,
    profile: Profile,
    *outcomes: CheckOutcome,
) -> dict[str, Any]:
    """The CONTROL_COVERAGE_DECLARED payload for one coverage shape, digest included.

    The digest covers the whole payload, not just ``evaluated``: two invocations can run the same
    checks with different sets armed, and keying on the evaluated set alone would let the first
    declaration seen speak for both. Since the digest is over everything the payload says, a
    reader can recompute it from the event and a producer emitting a second, different declaration
    under one digest is not expressible.
    """
    armed = [check_id for outcome in outcomes for check_id in outcome.armed]
    evaluated = sorted({check_id for outcome in outcomes for check_id in outcome.ran})
    body = {
        "enforcementPoint": profile.enforcement_point,
        "policyId": policy.id,
        "policyVersion": policy.version,
        "armed": [{"id": check_id, "scope": CHECKS[check_id].scope.value} for check_id in armed],
        "evaluated": evaluated,
    }
    return {"profileDigest": canonical_digest(body), **body}


def control_coverage(policy: LinkPolicy, profile: Profile, *outcomes: CheckOutcome) -> ControlCoverage:
    """The coverage a decision was reached under, ready for both the event and the declaration.

    Takes several outcomes because the A2A broker runs two profiles over one message -- link scope
    against the edge's mode, boundary scope against the boundary's -- and records one
    CONTROL_EVALUATED. Their check sets are disjoint by scope, so the union is exactly A2A_PROFILE.
    """
    declaration = coverage_declaration(policy, profile, *outcomes)
    return ControlCoverage(
        enforcement_point=profile.enforcement_point,
        digest=declaration["profileDigest"],
        flagged=tuple(sorted({check_id for outcome in outcomes for check_id in outcome.flagged})),
        declaration=declaration,
    )


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
        # Sits with the destination control it backstops: L1-M9-NEW-DESTINATION judges the
        # destinations the caller declared, and this one judges whether that declaration covers the
        # arguments. Neither is any use without the other on a caller-supplied intent.
        "INTERLOCK-INTENT-ARGUMENT-MISMATCH",
        "L1-M9-VOLUME-EXCEEDED",
        "L1-M9-VOLUME-BYTES-EXCEEDED",
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
        "L1-M5-TOKEN-RESOURCE-MISMATCH",
        "L1-M5-TOKEN-ACTOR-MISMATCH",
        "L1-M5-DELEGATION-DEPTH",
    ),
    # Both splits keep the wire unchanged: the resource comparison and the byte half of the volume
    # cap are separate check ids so each can be armed and counted on its own, and each maps back
    # onto the single code this point has always emitted for both halves.
    reason_codes={
        "L1-M5-TOKEN-RESOURCE-MISMATCH": "L1-M5-TOKEN-AUDIENCE-MISMATCH",
        "L1-M9-VOLUME-BYTES-EXCEEDED": "L1-M9-VOLUME-EXCEEDED",
    },
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
    # Its own map, not GATEWAY_PROFILE's object: the two points agree on the resource key but not on
    # the data-class one, and while they shared a dict that divergence could not even be expressed.
    reason_codes={
        **GATEWAY_PROFILE.reason_codes,
        # _data_classes emits a second key for a denied D7. The gateway has always put that key on
        # the wire; the SDK never has -- its inline check had no second branch and reported every
        # data-class denial as INTERLOCK-DATA-CLASS-DENIED. Unmapped, one byReasonCode bucket
        # silently splits in two for readers of the SDK's ledger.
        "L1-M9-SENSITIVE-EGRESS": "INTERLOCK-DATA-CLASS-DENIED",
    },
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
        "L1-M5-TOKEN-RESOURCE-MISMATCH",
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
    outcome = run_checks(policy, value, GATEWAY_PROFILE)
    reasons, decisions = outcome.reasons, outcome.decisions
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
        execution_permitted=execution_permitted(decisions),
        coverage=control_coverage(policy, GATEWAY_PROFILE, outcome),
    )


def execution_permitted(decisions: list[ControlDecision]) -> bool:
    """Whether these contributing decisions, together, permit the invocation to run.

    Aggregated separately from strongest_decision, and that separation is the whole content of this
    function. strongest_decision reduces by severity through _DECISION_RANK, where ``max``
    annihilates every member ranked below ALLOW: ``[ALLOW, BYPASSED]`` reduces to ALLOW, so a
    control the operator deliberately bypassed turned into an execution permit as soon as any
    unrelated check was configured to ALLOW. BYPASSED alone was already refused; it was only in
    company that it became permission.

    Severity and permission are different questions and one reduction cannot answer both. A permit
    requires every contributing decision to be affirmative -- one non-ALLOW anywhere denies. An
    empty list is permitted: no check found anything to say.

    Deliberately not derived from _DECISION_RANK. The rank map's ordering is what would_block and
    Plan 2's coverage axis read, and it stays exactly as it is; this predicate does not consult it.
    """
    return all(decision == ControlDecision.ALLOW for decision in decisions)


def strongest_decision(decisions: list[ControlDecision]) -> ControlDecision:
    """The most severe decision in the list, by _DECISION_RANK.

    Every member is ranked and every rank is distinct, so the result does not depend on argument
    order: a profile's check order sets reason-code order and nothing else.
    """
    if not decisions:
        return ControlDecision.ALLOW
    return max(decisions, key=lambda item: _DECISION_RANK[item])
