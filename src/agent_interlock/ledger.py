"""Append-only event ledger with integrity hashes and secret-safe payloads."""

from __future__ import annotations

import re
import secrets
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Mapping

from .canonical import canonical_digest
from .models import DataSource, Environment
from .security import sanitize_secrets


_SENSITIVE_KEY = re.compile(r"(?i)(authorization|password|secret|token|api[_-]?key|credential)")


def _uuid7() -> str:
    timestamp_ms = int(time.time() * 1000)
    value = (timestamp_ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= secrets.randbits(12) << 64
    value |= 0b10 << 62
    value |= secrets.randbits(62)
    return str(uuid.UUID(int=value))


def redact_payload(value: Any, key: str = "") -> Any:
    if not isinstance(value, (Mapping, list, tuple, set, frozenset)) and _SENSITIVE_KEY.search(key) and key not in {
        "credentialFingerprint",
        "secretDetected",
        "tokenPassthrough",
    }:
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


class InMemoryLedger:
    """Thread-safe append-only ledger used by the reference runtime and tests."""

    def __init__(self) -> None:
        self._events: list[Event] = []
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
    ) -> Event:
        if not tenant_id or not trace_id or not span_id or not source_actor_id:
            raise ValueError("tenant_id, trace_id, span_id, and source_actor_id are required")
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        body = {
            "event_id": _uuid7(),
            "event_type": event_type,
            "schema_version": "1.0",
            "occurred_at": now,
            "ingested_at": now,
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
            "payload": redact_payload(payload),
        }
        event = Event(**body, integrity_hash=canonical_digest(body))
        with self._lock:
            self._events.append(event)
        return event

    def all(self) -> tuple[Event, ...]:
        with self._lock:
            return tuple(self._events)

    def trace(self, tenant_id: str, trace_id: str) -> tuple[Event, ...]:
        with self._lock:
            return tuple(event for event in self._events if event.tenant_id == tenant_id and event.trace_id == trace_id)

    def interaction(self, tenant_id: str, interaction_id: str) -> tuple[Event, ...]:
        with self._lock:
            return tuple(
                event for event in self._events
                if event.tenant_id == tenant_id and event.interaction_id == interaction_id
            )

    @staticmethod
    def verify(event: Event) -> bool:
        body = asdict(event)
        expected = body.pop("integrity_hash")
        return canonical_digest(body) == expected
