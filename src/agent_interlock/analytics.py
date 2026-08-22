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
    def partial_or_bypass(self) -> bool:
        if self.security_outcome == SecurityOutcome.PARTIALLY_EXECUTED.value:
            return True
        return self.block_decision and self.actual_enforced and self.execution_attempted


def reduce_interactions(events: Iterable[Mapping[str, Any]]) -> tuple[InteractionRecord, ...]:
    """Join event-envelope dicts (``Event.to_dict()`` shape) by interaction."""
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for event in events:
        interaction_id = event.get("interaction_id")
        if interaction_id:
            key = (str(event.get("tenant_id", "")), str(interaction_id))
            grouped.setdefault(key, []).append(event)
    records = [
        record
        for (_tenant_id, interaction_id), items in grouped.items()
        if (record := _reduce_one(interaction_id, items)) is not None
    ]
    records.sort(
        key=lambda record: (
            _event_time({"occurred_at": record.first_occurred_at}),
            record.tenant_id,
            record.interaction_id,
        )
    )
    return tuple(records)


def _reduce_one(interaction_id: str, events: list[Mapping[str, Any]]) -> InteractionRecord | None:
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
        reason_codes=tuple(reason_codes),
        execution_attempted=execution_attempted,
        execution_succeeded=execution_succeeded,
        enforcement_action_completed=enforcement_action_completed,
        security_outcome=outcome,
        first_occurred_at=str(first.get("occurred_at", "")),
    )


def _control_decision(control: Mapping[str, Any]) -> ControlDecision:
    try:
        return ControlDecision(control.get("decision"))
    except (TypeError, ValueError):
        return ControlDecision.BLOCK  # unknown decision strings fail closed


def summarize_security_statistics(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate events into the SecurityStatistics contract value."""
    records = reduce_interactions(events)
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
    }


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
