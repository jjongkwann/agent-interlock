"""Append-only event ledger contracts with integrity-safe, bounded queries."""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from .canonical import canonical_digest, canonical_json
from .models import ControlCoverage, DataSource, Environment
from .security import sanitize_secrets

_SENSITIVE_KEY = re.compile(r"(?i)(authorization|password|secret|token|api[_-]?key|credential)")
_FINGERPRINT = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_QUERY_LIMIT = 500


class LedgerError(RuntimeError):
    """Base error for Ledger storage and query failures."""


class LedgerIdempotencyConflict(LedgerError):
    """Raised when one idempotency key is reused for a different event."""


class LedgerIntegrityError(LedgerError):
    """Raised when a stored event no longer matches its canonical hash."""


class LedgerRangeTooLarge(LedgerError):
    """Raised when a time-range query matches more events than its limit."""


def parse_event_time(value: str) -> datetime:
    """Parse an event timestamp (ISO 8601, Z or offset) to aware UTC."""
    moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if moment.tzinfo is None:
        raise ValueError("event timestamps must carry a UTC offset")
    return moment.astimezone(UTC)


def _uuid7() -> str:
    timestamp_ms = int(time.time() * 1000)
    value = (timestamp_ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= secrets.randbits(12) << 64
    value |= 0b10 << 62
    value |= secrets.randbits(62)
    return str(uuid.UUID(int=value))


def redact_payload(value: Any, key: str = "") -> Any:
    if key == "credentialFingerprint":
        return value if isinstance(value, str) and _FINGERPRINT.fullmatch(value) else "[REDACTED]"
    if key in {"secretDetected", "tokenPassthrough"}:
        return value if isinstance(value, bool) else "[REDACTED]"
    if not isinstance(value, (Mapping, list, tuple, set, frozenset)) and _SENSITIVE_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, Mapping):
        return {str(k): redact_payload(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact_payload(item) for item in value]
    if isinstance(value, str):
        return sanitize_secrets(value)[0]
    return value


@dataclass(frozen=True, slots=True)
class Event:
    event_id: str
    event_type: str
    schema_version: str
    occurred_at: str
    ingested_at: str
    tenant_id: str
    environment: str
    data_source: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    interaction_id: str | None
    source_actor_id: str
    target_actor_id: str | None
    relationship_type: str
    relationship_id: str
    severity: str
    payload: Mapping[str, Any]
    integrity_hash: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def declare_coverage(ledger: "Ledger", seen: set[str], coverage: ControlCoverage, **common: Any) -> None:
    """Append CONTROL_COVERAGE_DECLARED the first time an enforcement point sees a coverage digest.

    Which controls are armed is a property of the link, not of the call, so recording it on every
    CONTROL_EVALUATED would put twenty-odd ids on every event to say the same thing. The event
    carries the digest; this carries what the digest means, once.

    ``seen`` is the caller's own set, so the dedup is per enforcement-point instance and a restart
    re-declares. That is deliberate: the reducer keys on the digest and a repeat is a no-op, while
    a process-lifetime cache that outlived the ledger it was writing to would leave a digest on the
    wire that nothing in the stream explains.

    No ``interaction_id``: the declaration belongs to the link, and stamping it with one call's id
    would file a link-level fact under a single interaction.
    """
    if coverage.digest in seen:
        return
    seen.add(coverage.digest)
    common.pop("interaction_id", None)
    ledger.append("CONTROL_COVERAGE_DECLARED", payload={"coverage": dict(coverage.declaration)}, **common)


@dataclass(frozen=True, slots=True)
class EventPage:
    events: tuple[Event, ...]
    next_cursor: str | None


class Ledger(Protocol):
    """Storage contract used by the SDK, Gateway, and query API."""

    def append(
        self,
        event_type: str,
        *,
        tenant_id: str,
        trace_id: str,
        span_id: str,
        source_actor_id: str,
        payload: Mapping[str, Any],
        target_actor_id: str | None = None,
        interaction_id: str | None = None,
        parent_span_id: str | None = None,
        relationship_type: str = "INVOKES",
        relationship_id: str = "REL-05",
        severity: str = "INFO",
        environment: Environment = Environment.DEV,
        data_source: DataSource = DataSource.PRODUCTION,
        idempotency_key: str | None = None,
    ) -> Event: ...

    def trace(self, tenant_id: str, trace_id: str) -> tuple[Event, ...]: ...

    def interaction(self, tenant_id: str, interaction_id: str) -> tuple[Event, ...]: ...

    def query_trace(
        self,
        tenant_id: str,
        trace_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
    ) -> EventPage: ...

    def events_between(
        self,
        tenant_id: str,
        start: str,
        end: str,
        *,
        limit: int = 100_000,
    ) -> tuple[Event, ...]: ...

    def interaction_lifecycles_started_between(
        self,
        tenant_id: str,
        start: str,
        end: str,
        *,
        data_source: str | None = None,
        limit: int = 100_000,
    ) -> tuple[Event, ...]: ...


def build_event(
    event_type: str,
    *,
    tenant_id: str,
    trace_id: str,
    span_id: str,
    source_actor_id: str,
    payload: Mapping[str, Any],
    target_actor_id: str | None = None,
    interaction_id: str | None = None,
    parent_span_id: str | None = None,
    relationship_type: str = "INVOKES",
    relationship_id: str = "REL-05",
    severity: str = "INFO",
    environment: Environment = Environment.DEV,
    data_source: DataSource = DataSource.PRODUCTION,
    event_id: str | None = None,
    occurred_at: str | None = None,
    ingested_at: str | None = None,
) -> Event:
    """Create one canonical event; storage adapters persist this exact value."""

    if not tenant_id or not trace_id or not span_id or not source_actor_id:
        raise ValueError("tenant_id, trace_id, span_id, and source_actor_id are required")
    if not isinstance(payload, Mapping):
        raise ValueError("payload must be a mapping")
    normalized_payload = json.loads(canonical_json(redact_payload(payload)))
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    body = {
        "event_id": event_id or _uuid7(),
        "event_type": event_type,
        "schema_version": "1.0",
        "occurred_at": occurred_at or now,
        "ingested_at": ingested_at or now,
        "tenant_id": tenant_id,
        "environment": environment.value,
        "data_source": data_source.value,
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "interaction_id": interaction_id,
        "source_actor_id": source_actor_id,
        "target_actor_id": target_actor_id,
        "relationship_type": relationship_type,
        "relationship_id": relationship_id,
        "severity": severity,
        "payload": normalized_payload,
    }
    return Event(**body, integrity_hash=canonical_digest(body))


def event_request_digest(event: Event) -> str:
    """Hash stable producer-controlled fields for idempotency binding."""

    return canonical_digest(
        {
            "event_type": event.event_type,
            "schema_version": event.schema_version,
            "tenant_id": event.tenant_id,
            "environment": event.environment,
            "data_source": event.data_source,
            "trace_id": event.trace_id,
            "span_id": event.span_id,
            "parent_span_id": event.parent_span_id,
            "interaction_id": event.interaction_id,
            "source_actor_id": event.source_actor_id,
            "target_actor_id": event.target_actor_id,
            "relationship_type": event.relationship_type,
            "relationship_id": event.relationship_id,
            "severity": event.severity,
            "payload": event.payload,
        }
    )


def verify_event(event: Event) -> bool:
    body = asdict(event)
    expected = body.pop("integrity_hash")
    return canonical_digest(body) == expected


def validate_query(tenant_id: str, value: str, limit: int) -> None:
    if not tenant_id or not value:
        raise ValueError("tenant_id and query identifier are required")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= _MAX_QUERY_LIMIT:
        raise ValueError(f"limit must be between 1 and {_MAX_QUERY_LIMIT}")


def encode_event_cursor(event: Event) -> str:
    value = json.dumps([event.occurred_at, event.event_id], separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_event_cursor(cursor: str) -> tuple[str, str]:
    if not isinstance(cursor, str) or not cursor or len(cursor) > 512:
        raise ValueError("cursor is invalid")
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
        value = json.loads(decoded)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("cursor is invalid") from error
    if not isinstance(value, list) or len(value) != 2 or not all(isinstance(item, str) and item for item in value):
        raise ValueError("cursor is invalid")
    try:
        datetime.fromisoformat(value[0].replace("Z", "+00:00"))
        uuid.UUID(value[1])
    except ValueError as error:
        raise ValueError("cursor is invalid") from error
    return value[0], value[1]


class InMemoryLedger:
    """Thread-safe append-only ledger used by the reference runtime and tests."""

    def __init__(self) -> None:
        self._events: list[Event] = []
        self._idempotency: dict[tuple[str, str], tuple[str, Event]] = {}
        self._lock = threading.RLock()

    def append(
        self,
        event_type: str,
        *,
        tenant_id: str,
        trace_id: str,
        span_id: str,
        source_actor_id: str,
        payload: Mapping[str, Any],
        target_actor_id: str | None = None,
        interaction_id: str | None = None,
        parent_span_id: str | None = None,
        relationship_type: str = "INVOKES",
        relationship_id: str = "REL-05",
        severity: str = "INFO",
        environment: Environment = Environment.DEV,
        data_source: DataSource = DataSource.PRODUCTION,
        idempotency_key: str | None = None,
    ) -> Event:
        event = build_event(
            event_type,
            tenant_id=tenant_id,
            trace_id=trace_id,
            span_id=span_id,
            source_actor_id=source_actor_id,
            payload=payload,
            target_actor_id=target_actor_id,
            interaction_id=interaction_id,
            parent_span_id=parent_span_id,
            relationship_type=relationship_type,
            relationship_id=relationship_id,
            severity=severity,
            environment=environment,
            data_source=data_source,
        )
        with self._lock:
            if idempotency_key is not None:
                key = (tenant_id, idempotency_key)
                if not idempotency_key or len(idempotency_key) > 200:
                    raise ValueError("idempotency_key must be between 1 and 200 characters")
                existing = self._idempotency.get(key)
                digest = event_request_digest(event)
                if existing is not None:
                    existing_digest, existing_event = existing
                    if existing_digest != digest:
                        raise LedgerIdempotencyConflict("idempotency key is already bound to another event")
                    return existing_event
                self._idempotency[key] = (digest, event)
            self._events.append(event)
        return event

    def all(self) -> tuple[Event, ...]:
        with self._lock:
            return tuple(self._events)

    def trace(self, tenant_id: str, trace_id: str) -> tuple[Event, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (event for event in self._events if event.tenant_id == tenant_id and event.trace_id == trace_id),
                    key=lambda item: (item.occurred_at, item.event_id),
                )
            )

    def interaction(self, tenant_id: str, interaction_id: str) -> tuple[Event, ...]:
        with self._lock:
            return tuple(
                sorted(
                    (
                        event
                        for event in self._events
                        if event.tenant_id == tenant_id and event.interaction_id == interaction_id
                    ),
                    key=lambda item: (item.occurred_at, item.event_id),
                )
            )

    def query_trace(
        self,
        tenant_id: str,
        trace_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
    ) -> EventPage:
        validate_query(tenant_id, trace_id, limit)
        boundary = decode_event_cursor(cursor) if cursor is not None else None
        with self._lock:
            values = sorted(
                (
                    event
                    for event in self._events
                    if event.tenant_id == tenant_id
                    and event.trace_id == trace_id
                    and (boundary is None or (event.occurred_at, event.event_id) > boundary)
                ),
                key=lambda item: (item.occurred_at, item.event_id),
            )
        page = tuple(values[:limit])
        next_cursor = encode_event_cursor(page[-1]) if len(values) > limit and page else None
        return EventPage(page, next_cursor)

    def events_between(
        self,
        tenant_id: str,
        start: str,
        end: str,
        *,
        limit: int = 100_000,
    ) -> tuple[Event, ...]:
        if not tenant_id or limit < 1:
            raise ValueError("tenant_id and a positive limit are required")
        start_at = parse_event_time(start)
        end_at = parse_event_time(end)
        if start_at >= end_at:
            raise ValueError("start must be before end")
        with self._lock:
            values = sorted(
                (
                    event
                    for event in self._events
                    if event.tenant_id == tenant_id and start_at <= parse_event_time(event.occurred_at) < end_at
                ),
                key=lambda item: (item.occurred_at, item.event_id),
            )
        if len(values) > limit:
            raise LedgerRangeTooLarge("time range matches more events than the limit")
        return tuple(values)

    def interaction_lifecycles_started_between(
        self,
        tenant_id: str,
        start: str,
        end: str,
        *,
        data_source: str | None = None,
        limit: int = 100_000,
    ) -> tuple[Event, ...]:
        if not tenant_id or limit < 1:
            raise ValueError("tenant_id and a positive limit are required")
        start_at = parse_event_time(start)
        end_at = parse_event_time(end)
        if start_at >= end_at:
            raise ValueError("start must be before end")
        with self._lock:
            interaction_ids = {
                event.interaction_id
                for event in self._events
                if event.tenant_id == tenant_id
                and event.event_type == "INTERACTION_REQUESTED"
                and event.interaction_id is not None
                and start_at <= parse_event_time(event.occurred_at) < end_at
                and (data_source is None or event.data_source == data_source)
            }
            values = sorted(
                (
                    event
                    for event in self._events
                    if event.tenant_id == tenant_id
                    and (
                        event.interaction_id in interaction_ids
                        # Coverage declarations carry no interaction_id -- what is armed belongs to
                        # the link, not to a call -- so an interaction filter cannot see them, and
                        # without them summarize_security_statistics reports every check ABSENT for
                        # the whole window. One that was emitted before the window still explains a
                        # digest used inside it, so the bound is `occurred_at < end` rather than the
                        # window itself.
                        # ponytail: every declaration ever emitted for the tenant, deduped by digest
                        # downstream; narrow to the digests the window references if the count grows.
                        or (
                            event.event_type == "CONTROL_COVERAGE_DECLARED"
                            and parse_event_time(event.occurred_at) < end_at
                        )
                    )
                ),
                key=lambda item: (parse_event_time(item.occurred_at), item.event_id),
            )
        if len(values) > limit:
            raise LedgerRangeTooLarge("interaction lifecycles match more events than the limit")
        return tuple(values)

    @staticmethod
    def verify(event: Event) -> bool:
        return verify_event(event)
