"""Security statistics: interaction-level reduction and the aggregate model.

The contract is ``schemas/security-statistics.schema.json`` plus the shared
fixture pair ``schemas/fixtures/analytics-events.json`` /
``analytics-statistics.json``. The Studio offline importer must produce the
identical statistics JSON for the same events (golden contract test on both
sides), so every semantic decision lives HERE and in the schema descriptions,
not in either UI.

Pinned semantics:

- Aggregation is a per-tenant, per-``interaction_id`` state join over the event lifecycle
  (INTERACTION_REQUESTED → CONTROL_EVALUATED → ACTION_EXECUTED →
  SECURITY_OUTCOME_SET). Events without an ``interaction_id`` (for example
  definition-admission CONTROL_EVALUATED) and groups without an
  INTERACTION_REQUESTED do not participate.
- ``decision`` is ``strongest_decision`` over every CONTROL_EVALUATED
  ``control.decision`` in the interaction; ``mode`` / ``actualEnforced`` /
  ``policyId`` come from the first control event carrying that decision.
- ``execution_permitted`` is the AND of ``control.executionPermitted`` over the
  same events, and an absent key reads as ``True`` -- matching
  ``PolicyDecisionRecord.execution_permitted``'s default, so the A2A broker
  (which does not emit the key) and every event written before it existed are
  unaffected. A present value that is not ``True`` denies.
- A block is ``decision != ALLOW`` OR a denied permit. The two are separate
  aggregates: a control that permits nothing while every decision reduces to
  ALLOW is a real refusal, and counting only the decision reports it as zero.
- A connector execution attempt is an ACTION_EXECUTED whose payload
  ``connectorExecutionId`` is non-null. The enforcement ACTION_EXECUTED the
  gateway emits when it blocks carries ``connectorExecutionId: null`` and is
  NOT an execution attempt.
- An enforced block requires a completed enforcement ACTION_EXECUTED, no
  connector execution attempt, and a final BLOCKED security outcome.
- ``securityOutcome`` is the last SECURITY_OUTCOME_SET in the interaction
  (``UNKNOWN`` when none was set).
- ``reasonCodes`` are deduped per interaction but one interaction can carry
  several, so per-reason sums legitimately exceed interaction counts.

Coverage (the second question the statistics answer -- which controls looked, not
only which fired):

- ``CONTROL_COVERAGE_DECLARED`` carries no ``interaction_id``: what is armed is a
  property of the link, not of a call. Declarations are collected from the whole
  stream and keyed by ``profileDigest``; CONTROL_EVALUATED points at one with
  ``control.evaluatedProfile``.
- The catalogue is the union of every ``armed`` set seen in the stream, so the
  reducer stays a pure function of the events and the Studio port needs no access
  to the Python check table.
- Per interaction and check id: in ``flaggedChecks`` is RAN_FLAGGED, else in the
  declaration's ``evaluated`` is RAN_CLEAN, else in its ``armed`` is INAPPLICABLE,
  else ABSENT. An interaction whose events carry no digest is ABSENT throughout --
  no control looked, which is not the same as no control objected.
- ``flaggedChecks`` carries check ids, not reason codes. ``Profile.reason_codes``
  is not injective, so a code cannot name the check that produced it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .models import ControlDecision, SecurityOutcome
from .policy import strongest_decision

STATISTICS_API_VERSION = "interlock.dev/v1alpha1"
STATISTICS_KIND = "SecurityStatistics"


COVERAGE_STATES = ("RAN_CLEAN", "RAN_FLAGGED", "INAPPLICABLE", "ABSENT")


@dataclass(frozen=True, slots=True)
class CheckCoverage:
    """What one interaction's controls did, as three nested sets of check ids.

    ``flagged`` is a subset of ``ran``, which is a subset of ``armed``; the fourth state, ABSENT,
    is everything in the catalogue that is not in ``armed``, so it is a property of the stream
    rather than of the interaction and cannot be stored here.
    """

    armed: frozenset[str] = frozenset()
    ran: frozenset[str] = frozenset()
    flagged: frozenset[str] = frozenset()

    def state(self, check_id: str) -> str:
        if check_id in self.flagged:
            return "RAN_FLAGGED"
        if check_id in self.ran:
            return "RAN_CLEAN"
        if check_id in self.armed:
            return "INAPPLICABLE"
        return "ABSENT"


@dataclass(frozen=True, slots=True)
class InteractionRecord:
    """One interaction's joined security state, reduced from its events."""

    interaction_id: str
    tenant_id: str
    environment: str
    data_source: str
    source_actor_id: str
    target_actor_id: str | None
    relationship_id: str
    policy_id: str | None
    mode: str | None
    decision: ControlDecision
    actual_enforced: bool
    execution_permitted: bool
    reason_codes: tuple[str, ...]
    control_evaluated: bool
    coverage: CheckCoverage
    execution_attempted: bool
    execution_succeeded: bool
    enforcement_action_completed: bool
    security_outcome: str
    first_occurred_at: str

    @property
    def block_decision(self) -> bool:
        return self.decision != ControlDecision.ALLOW or not self.execution_permitted

    @property
    def shadow_would_block(self) -> bool:
        return self.block_decision and not self.actual_enforced

    @property
    def enforced_block(self) -> bool:
        return (
            self.block_decision
            and self.actual_enforced
            and self.enforcement_action_completed
            and not self.execution_attempted
            and self.security_outcome == SecurityOutcome.BLOCKED.value
        )

    @property
    def edge_key(self) -> tuple[str, str, str] | None:
        """The (source, target, policy) triple byEdge groups on, or None when it is incomplete.

        The graph allows several edges between one actor pair -- ArchitectureGraph.edges is a tuple
        and uniqueness is enforced on edge ids -- so the pair alone is not a key, and policyId is
        what splits precisely where the armed set can differ. An interaction with no control record
        has no policyId, so it cannot be placed on the grid at all; those are counted in
        ``unattributed`` rather than dropped or folded into some other edge's row.
        """
        if self.target_actor_id is None or self.policy_id is None:
            return None
        return (self.source_actor_id, self.target_actor_id, self.policy_id)

    @property
    def partial_or_bypass(self) -> bool:
        if self.security_outcome == SecurityOutcome.PARTIALLY_EXECUTED.value:
            return True
        return self.block_decision and self.actual_enforced and self.execution_attempted


def coverage_declarations(events: Iterable[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    """Every CONTROL_COVERAGE_DECLARED payload in the stream, keyed by its digest.

    First declaration per digest wins; a producer cannot emit two different bodies under one digest
    without the digest changing, since it covers the whole body.
    """
    declarations: dict[str, Mapping[str, Any]] = {}
    for event in events:
        if event.get("event_type") != "CONTROL_COVERAGE_DECLARED":
            continue
        payload = event.get("payload")
        coverage = payload.get("coverage") if isinstance(payload, Mapping) else None
        if isinstance(coverage, Mapping) and isinstance(coverage.get("profileDigest"), str):
            declarations.setdefault(coverage["profileDigest"], coverage)
    return declarations


def check_catalogue(declarations: Mapping[str, Mapping[str, Any]]) -> dict[str, str]:
    """Check id -> scope, over the union of every armed set declared in the stream.

    This is what makes ABSENT expressible without the Python check table: a control missing from
    one link's armed set is only ABSENT relative to the links that do arm it.
    """
    catalogue: dict[str, str] = {}
    for declaration in declarations.values():
        for entry in declaration.get("armed") or ():
            if isinstance(entry, Mapping) and isinstance(entry.get("id"), str):
                catalogue.setdefault(entry["id"], str(entry.get("scope", "")))
    return catalogue


def reduce_interactions(events: Iterable[Mapping[str, Any]]) -> tuple[InteractionRecord, ...]:
    """Join event-envelope dicts (``Event.to_dict()`` shape) by interaction."""
    events = list(events)
    declarations = coverage_declarations(events)
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for event in events:
        interaction_id = event.get("interaction_id")
        if interaction_id:
            key = (str(event.get("tenant_id", "")), str(interaction_id))
            grouped.setdefault(key, []).append(event)
    records = [
        record
        for (_tenant_id, interaction_id), items in grouped.items()
        if (record := _reduce_one(interaction_id, items, declarations)) is not None
    ]
    records.sort(
        key=lambda record: (
            _event_time({"occurred_at": record.first_occurred_at}),
            record.tenant_id,
            record.interaction_id,
        )
    )
    return tuple(records)


def _reduce_one(
    interaction_id: str,
    events: list[Mapping[str, Any]],
    declarations: Mapping[str, Mapping[str, Any]],
) -> InteractionRecord | None:
    ordered = sorted(
        range(len(events)),
        key=lambda index: (_event_time(events[index]), str(events[index].get("event_id", "")), index),
    )
    requested = [index for index in ordered if events[index].get("event_type") == "INTERACTION_REQUESTED"]
    if not requested:
        return None
    controls: list[Mapping[str, Any]] = []
    execution_attempted = False
    execution_succeeded = False
    enforcement_action_completed = False
    outcome = SecurityOutcome.UNKNOWN.value
    for index in ordered:
        event = events[index]
        event_type = event.get("event_type")
        payload_value = event.get("payload")
        payload = payload_value if isinstance(payload_value, Mapping) else {}
        if event_type == "CONTROL_EVALUATED" and isinstance(payload.get("control"), Mapping):
            controls.append(payload["control"])
        elif event_type == "ACTION_EXECUTED":
            if payload.get("connectorExecutionId") is not None:
                execution_attempted = True
                if payload.get("result") == "COMPLETED":
                    execution_succeeded = True
            elif payload.get("result") == "COMPLETED":
                enforcement_action_completed = True
        elif event_type == "SECURITY_OUTCOME_SET" and payload.get("securityOutcome"):
            outcome = str(payload["securityOutcome"])

    coverage = _coverage(controls, declarations)
    decisions = [_control_decision(control) for control in controls]
    decision = strongest_decision(decisions)
    permitted = all(control.get("executionPermitted", True) is True for control in controls)
    chosen: Mapping[str, Any] = {}
    for control, value in zip(controls, decisions, strict=True):
        if value == decision:
            chosen = control
            break
    reason_codes: list[str] = []
    for control in controls:
        raw_codes = control.get("reasonCodes")
        codes = (raw_codes,) if isinstance(raw_codes, str) else raw_codes if isinstance(raw_codes, Sequence) else ()
        for code in codes:
            value = str(code)
            if value not in reason_codes:
                reason_codes.append(value)

    first = events[requested[0]]
    return InteractionRecord(
        interaction_id=interaction_id,
        tenant_id=str(first.get("tenant_id", "")),
        environment=str(first.get("environment", "")),
        data_source=str(first.get("data_source", "")),
        source_actor_id=str(first.get("source_actor_id", "")),
        target_actor_id=first.get("target_actor_id"),
        relationship_id=str(first.get("relationship_id", "")),
        policy_id=chosen.get("policyId") if isinstance(chosen.get("policyId"), str) else None,
        mode=chosen.get("mode") if isinstance(chosen.get("mode"), str) else None,
        decision=decision,
        actual_enforced=chosen.get("actualEnforced") is True,
        execution_permitted=permitted,
        control_evaluated=bool(controls),
        coverage=coverage,
        reason_codes=tuple(reason_codes),
        execution_attempted=execution_attempted,
        execution_succeeded=execution_succeeded,
        enforcement_action_completed=enforcement_action_completed,
        security_outcome=outcome,
        first_occurred_at=str(first.get("occurred_at", "")),
    )


def _coverage(
    controls: Sequence[Mapping[str, Any]],
    declarations: Mapping[str, Mapping[str, Any]],
) -> CheckCoverage:
    """Join one interaction's control records to the coverage they were declared under.

    A control record naming a digest the stream never declared contributes nothing rather than
    being guessed at: an unresolvable digest is missing evidence, and inventing an armed set for it
    would report coverage the ledger does not carry.
    """
    armed: set[str] = set()
    ran: set[str] = set()
    flagged: set[str] = set()
    for control in controls:
        # Same shape guard reasonCodes already carries below: a bare string is iterable, so a
        # producer writing a single id instead of a list would otherwise contribute one check per
        # character.
        raw_flagged = control.get("flaggedChecks")
        if isinstance(raw_flagged, str):
            raw_flagged = (raw_flagged,)
        elif not isinstance(raw_flagged, Sequence):
            raw_flagged = ()
        for check_id in raw_flagged:
            flagged.add(str(check_id))
        declaration = declarations.get(str(control.get("evaluatedProfile", "")))
        if declaration is None:
            continue
        for entry in declaration.get("armed") or ():
            if isinstance(entry, Mapping) and isinstance(entry.get("id"), str):
                armed.add(entry["id"])
        for check_id in declaration.get("evaluated") or ():
            ran.add(str(check_id))
    # A flagged check ran, and a check that ran is armed, whatever an inconsistent stream claims.
    ran |= flagged
    armed |= ran
    return CheckCoverage(armed=frozenset(armed), ran=frozenset(ran), flagged=frozenset(flagged))


def _control_decision(control: Mapping[str, Any]) -> ControlDecision:
    try:
        return ControlDecision(control.get("decision"))
    except (TypeError, ValueError):
        return ControlDecision.BLOCK  # unknown decision strings fail closed


def summarize_security_statistics(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate events into the SecurityStatistics contract value."""
    events = list(events)
    records = reduce_interactions(events)
    catalogue = check_catalogue(coverage_declarations(events))
    partitions = []
    for data_source in sorted({record.data_source for record in records}):
        subset = [record for record in records if record.data_source == data_source]
        partitions.append(
            {
                "dataSource": data_source,
                "counters": _counters(subset),
                "outcomes": _outcome_counts(subset),
                "byRelationship": _grouped(subset, "relationshipId", lambda r: r.relationship_id),
                "byActor": _grouped(subset, "sourceActorId", lambda r: r.source_actor_id),
                "byPolicy": _grouped(subset, "policyId", lambda r: r.policy_id),
                "byMode": _grouped(subset, "mode", lambda r: r.mode),
                "byReasonCode": _reason_counts(subset),
                "byCheck": _by_check(subset, catalogue),
                "byEdge": _by_edge(subset, catalogue),
                "unattributed": _counters([record for record in subset if record.edge_key is None]),
                "timeSeries": _time_series(subset),
            }
        )
    return {
        "apiVersion": STATISTICS_API_VERSION,
        "kind": STATISTICS_KIND,
        "interactionCount": len(records),
        "partitions": partitions,
    }


def _counters(records: Sequence[InteractionRecord]) -> dict[str, int]:
    return {
        "interactionCount": len(records),
        "blockDecisionCount": sum(1 for r in records if r.block_decision),
        "shadowWouldBlockCount": sum(1 for r in records if r.shadow_would_block),
        "enforcedBlockCount": sum(1 for r in records if r.enforced_block),
        "executionAttemptCount": sum(1 for r in records if r.execution_attempted),
        "executionSuccessCount": sum(1 for r in records if r.execution_succeeded),
        "partialOrBypassCount": sum(1 for r in records if r.partial_or_bypass),
        # An interaction whose events carry no CONTROL_EVALUATED reduces to decision ALLOW with an
        # empty reason list, which is shape-identical to a control that ran and allowed. Counted
        # here in every grouping rather than only in the partition's `unattributed` bucket, because
        # the blind spot is per-row: byActor showing "40 calls, 0 blocked" reads as forty examined
        # calls whether or not any control saw them.
        "noControlRecordCount": sum(1 for r in records if not r.control_evaluated),
    }


def _by_check(records: Sequence[InteractionRecord], catalogue: Mapping[str, str]) -> list[dict[str, Any]]:
    """Per canonical check id, how many interactions ended in each of the four coverage states.

    Spans all three enforcement points: the ids are the canonical check ids, not the per-point
    reason codes, so the same control correlates across the gateway, the SDK and the broker without
    claiming the three implementations are byte-identical.
    """
    rows = []
    for check_id in sorted(catalogue):
        counts = dict.fromkeys(COVERAGE_STATES, 0)
        for record in records:
            counts[record.coverage.state(check_id)] += 1
        rows.append(
            {
                "checkId": check_id,
                "scope": catalogue[check_id],
                "ranCleanCount": counts["RAN_CLEAN"],
                "ranFlaggedCount": counts["RAN_FLAGGED"],
                "inapplicableCount": counts["INAPPLICABLE"],
                "absentCount": counts["ABSENT"],
            }
        )
    return rows


def _by_edge(records: Sequence[InteractionRecord], catalogue: Mapping[str, str]) -> list[dict[str, Any]]:
    """The deliverable cross-tabulation: on this segment, which controls applied and what happened.

    Rows ABSENT for every interaction on the edge are omitted -- on a link that arms six of
    twenty-eight checks, listing the other twenty-two as zeroes on every edge is most of the
    document. Their absence from a row means ABSENT throughout, which byCheck still reports at the
    partition level.
    """
    groups: dict[tuple[str, str, str], list[InteractionRecord]] = {}
    for record in records:
        key = record.edge_key
        if key is not None:
            groups.setdefault(key, []).append(record)
    return [
        {
            "sourceActorId": source,
            "targetActorId": target,
            "policyId": policy_id,
            "counters": _counters(groups[(source, target, policy_id)]),
            "byCheck": [
                row
                for row in _by_check(groups[(source, target, policy_id)], catalogue)
                if row["absentCount"] != len(groups[(source, target, policy_id)])
            ],
        }
        for source, target, policy_id in sorted(groups)
    ]


def _outcome_counts(records: Sequence[InteractionRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.security_outcome] = counts.get(record.security_outcome, 0) + 1
    return dict(sorted(counts.items()))


def _grouped(records, key_name, key):  # noqa: ANN001
    groups: dict[str, list[InteractionRecord]] = {}
    for record in records:
        value = key(record)
        if value is not None:
            groups.setdefault(str(value), []).append(record)
    return [{key_name: value, "counters": _counters(groups[value])} for value in sorted(groups)]


def _reason_counts(records: Sequence[InteractionRecord]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for record in records:
        for code in record.reason_codes:
            counts[code] = counts.get(code, 0) + 1
    return [{"reasonCode": code, "interactionCount": counts[code]} for code in sorted(counts)]


def _time_series(records: Sequence[InteractionRecord]) -> list[dict[str, Any]]:
    buckets: dict[str, list[InteractionRecord]] = {}
    for record in records:
        buckets.setdefault(_hour_bucket(record.first_occurred_at), []).append(record)
    return [{"bucketStart": start, "counters": _counters(buckets[start])} for start in sorted(buckets)]


def _hour_bucket(occurred_at: str) -> str:
    moment = _event_time({"occurred_at": occurred_at})
    return moment.replace(minute=0, second=0, microsecond=0).strftime("%Y-%m-%dT%H:00:00Z")


def _event_time(event: Mapping[str, Any]) -> datetime:
    moment = datetime.fromisoformat(str(event.get("occurred_at", "")).replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("event timestamps must carry a UTC offset")
    return moment.astimezone(timezone.utc)
