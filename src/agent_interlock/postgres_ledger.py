"""PostgreSQL-backed append-only Ledger with database-enforced tenant binding."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any, Protocol

from .canonical import canonical_json
from .ledger import (
    Event,
    EventPage,
    LedgerError,
    LedgerIdempotencyConflict,
    LedgerIntegrityError,
    LedgerRangeTooLarge,
    build_event,
    decode_event_cursor,
    encode_event_cursor,
    event_request_digest,
    parse_event_time,
    validate_query,
    verify_event,
)
from .models import DataSource, Environment


class PostgreSQLDriverUnavailable(LedgerError):
    """Raised when DSN construction is requested without psycopg installed."""


class LedgerTenantMismatch(LedgerError):
    """Raised before access when the authenticated DB role is not tenant-bound."""


class LedgerQueryLimitExceeded(LedgerError):
    """Raised when an unpaged internal query exceeds its safety bound."""


class Cursor(Protocol):
    def execute(self, query: str, parameters: tuple[Any, ...] = ()) -> Any: ...

    def fetchone(self) -> tuple[Any, ...] | None: ...

    def fetchall(self) -> list[tuple[Any, ...]]: ...

    def close(self) -> None: ...


class Connection(Protocol):
    def cursor(self) -> Cursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[[], Connection]

_SELECT_COLUMNS = """
event_id::text, event_type, schema_version,
occurred_at, ingested_at, tenant_id, environment, data_source,
trace_id, span_id, parent_span_id, interaction_id,
source_actor_id, target_actor_id, relationship_type, relationship_id,
severity, payload_canonical, integrity_hash
""".strip()

_INSERT_EVENT = """
INSERT INTO interlock.security_events (
    event_id, event_type, schema_version, occurred_at, ingested_at,
    tenant_id, environment, data_source, trace_id, span_id,
    parent_span_id, interaction_id, source_actor_id, target_actor_id,
    relationship_type, relationship_id, severity,
    payload, payload_canonical, integrity_hash
) VALUES (
    %s::uuid, %s, %s, %s::timestamptz, %s::timestamptz,
    %s, %s, %s, %s, %s,
    %s, %s, %s, %s,
    %s, %s, %s, %s::jsonb, %s, %s
)
""".strip()


class PostgreSQLLedger:
    """A synchronous psycopg/DB-API adapter for the Interaction Ledger.

    Each instance is bound to one tenant. The migration independently maps the
    authenticated PostgreSQL ``session_user`` to the same tenant and enforces
    that mapping with FORCE ROW LEVEL SECURITY. The adapter checks the mapping
    at the start of every transaction so a pool or credential mix-up fails
    before an event query or mutation is attempted.
    """

    def __init__(
        self,
        connection_factory: ConnectionFactory,
        *,
        bound_tenant_id: str,
        max_unpaged_events: int = 5_000,
    ) -> None:
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        if not bound_tenant_id:
            raise ValueError("bound_tenant_id is required")
        if not 1 <= max_unpaged_events <= 50_000:
            raise ValueError("max_unpaged_events must be between 1 and 50000")
        self._connection_factory = connection_factory
        self.bound_tenant_id = bound_tenant_id
        self.max_unpaged_events = max_unpaged_events

    @classmethod
    def from_dsn(
        cls,
        dsn: str,
        *,
        bound_tenant_id: str,
        max_unpaged_events: int = 5_000,
        connect_timeout_seconds: int = 5,
    ) -> PostgreSQLLedger:
        if not dsn:
            raise ValueError("dsn is required")
        if not 1 <= connect_timeout_seconds <= 30:
            raise ValueError("connect_timeout_seconds must be between 1 and 30")
        try:
            import psycopg
        except ImportError as error:
            raise PostgreSQLDriverUnavailable(
                "install the 'postgres' project extra to use PostgreSQLLedger.from_dsn"
            ) from error

        def connect() -> Connection:
            return psycopg.connect(
                dsn,
                autocommit=False,
                connect_timeout=connect_timeout_seconds,
                application_name="agent-interlock-ledger",
            )

        return cls(
            connect,
            bound_tenant_id=bound_tenant_id,
            max_unpaged_events=max_unpaged_events,
        )

    def __repr__(self) -> str:
        return (
            f"PostgreSQLLedger(bound_tenant_id={self.bound_tenant_id!r}, "
            f"max_unpaged_events={self.max_unpaged_events!r})"
        )

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
        self._require_bound_tenant(tenant_id)
        if idempotency_key is not None and (
            not isinstance(idempotency_key, str) or not idempotency_key or len(idempotency_key) > 200
        ):
            raise ValueError("idempotency_key must be between 1 and 200 characters")
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
        request_hash = event_request_digest(event)
        with self._transaction() as connection:
            cursor = connection.cursor()
            try:
                if idempotency_key is not None:
                    cursor.execute(
                        """
                        INSERT INTO interlock.event_ingest_keys (
                            tenant_id, idempotency_key, request_hash,
                            event_id, event_occurred_at
                        ) VALUES (%s, %s, %s, %s::uuid, %s::timestamptz)
                        ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
                        RETURNING event_id::text, event_occurred_at, request_hash
                        """,
                        (
                            tenant_id,
                            idempotency_key,
                            request_hash,
                            event.event_id,
                            event.occurred_at,
                        ),
                    )
                    reserved = cursor.fetchone()
                    if reserved is None:
                        cursor.execute(
                            """
                            SELECT event_id::text, event_occurred_at, request_hash
                            FROM interlock.event_ingest_keys
                            WHERE tenant_id = %s AND idempotency_key = %s
                            """,
                            (tenant_id, idempotency_key),
                        )
                        existing = cursor.fetchone()
                        if existing is None:
                            raise LedgerError("idempotency reservation is not visible")
                        if existing[2] != request_hash:
                            raise LedgerIdempotencyConflict("idempotency key is already bound to another event")
                        loaded = self._load_event(cursor, tenant_id, existing[0], existing[1])
                        if loaded is None:
                            raise LedgerError("idempotency record has no event")
                        return loaded
                cursor.execute(_INSERT_EVENT, _event_parameters(event))
            finally:
                cursor.close()
        return event

    def trace(self, tenant_id: str, trace_id: str) -> tuple[Event, ...]:
        return self._bounded_unpaged_query(tenant_id, "trace_id", trace_id)

    def interaction(self, tenant_id: str, interaction_id: str) -> tuple[Event, ...]:
        return self._bounded_unpaged_query(tenant_id, "interaction_id", interaction_id)

    def query_trace(
        self,
        tenant_id: str,
        trace_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
    ) -> EventPage:
        self._require_bound_tenant(tenant_id)
        validate_query(tenant_id, trace_id, limit)
        boundary = decode_event_cursor(cursor) if cursor is not None else None
        with self._transaction() as connection:
            database_cursor = connection.cursor()
            try:
                if boundary is None:
                    database_cursor.execute(
                        f"""
                        SELECT {_SELECT_COLUMNS}
                        FROM interlock.security_events
                        WHERE tenant_id = %s AND trace_id = %s
                        ORDER BY occurred_at, event_id
                        LIMIT %s
                        """,
                        (tenant_id, trace_id, limit + 1),
                    )
                else:
                    database_cursor.execute(
                        f"""
                        SELECT {_SELECT_COLUMNS}
                        FROM interlock.security_events
                        WHERE tenant_id = %s AND trace_id = %s
                          AND (occurred_at, event_id) > (%s::timestamptz, %s::uuid)
                        ORDER BY occurred_at, event_id
                        LIMIT %s
                        """,
                        (tenant_id, trace_id, boundary[0], boundary[1], limit + 1),
                    )
                values = tuple(_event_from_row(row) for row in database_cursor.fetchall())
            finally:
                database_cursor.close()
        page = values[:limit]
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
        self._require_bound_tenant(tenant_id)
        if not tenant_id or limit < 1:
            raise ValueError("tenant_id and a positive limit are required")
        if parse_event_time(start) >= parse_event_time(end):
            raise ValueError("start must be before end")
        with self._transaction() as connection:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    f"""
                    SELECT {_SELECT_COLUMNS}
                    FROM interlock.security_events
                    WHERE tenant_id = %s
                      AND occurred_at >= %s::timestamptz AND occurred_at < %s::timestamptz
                    ORDER BY occurred_at, event_id
                    LIMIT %s
                    """,
                    (tenant_id, start, end, limit + 1),
                )
                values = tuple(_event_from_row(row) for row in cursor.fetchall())
            finally:
                cursor.close()
        if len(values) > limit:
            raise LedgerRangeTooLarge("time range matches more events than the limit")
        return values

    def interaction_lifecycles_started_between(
        self,
        tenant_id: str,
        start: str,
        end: str,
        *,
        data_source: str | None = None,
        limit: int = 100_000,
    ) -> tuple[Event, ...]:
        self._require_bound_tenant(tenant_id)
        if not tenant_id or limit < 1:
            raise ValueError("tenant_id and a positive limit are required")
        if parse_event_time(start) >= parse_event_time(end):
            raise ValueError("start must be before end")
        with self._transaction() as connection:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    f"""
                    SELECT {_SELECT_COLUMNS}
                    FROM interlock.security_events
                    WHERE tenant_id = %s
                      AND (
                          interaction_id IN (
                              SELECT interaction_id
                              FROM interlock.security_events
                              WHERE tenant_id = %s
                                AND event_type = 'INTERACTION_REQUESTED'
                                AND interaction_id IS NOT NULL
                                AND occurred_at >= %s::timestamptz AND occurred_at < %s::timestamptz
                                AND (%s::text IS NULL OR data_source = %s::text)
                          )
                          -- Coverage declarations carry no interaction_id, so the interaction
                          -- filter cannot see them and the statistics would report every check
                          -- ABSENT. See the InMemoryLedger comment for why the bound is `< end`.
                          OR (event_type = 'CONTROL_COVERAGE_DECLARED'
                              AND occurred_at < %s::timestamptz)
                      )
                    ORDER BY occurred_at, event_id
                    LIMIT %s
                    """,
                    (tenant_id, tenant_id, start, end, data_source, data_source, end, limit + 1),
                )
                values = tuple(_event_from_row(row) for row in cursor.fetchall())
            finally:
                cursor.close()
        if len(values) > limit:
            raise LedgerRangeTooLarge("interaction lifecycles match more events than the limit")
        return values

    def _bounded_unpaged_query(
        self,
        tenant_id: str,
        column: str,
        value: str,
    ) -> tuple[Event, ...]:
        self._require_bound_tenant(tenant_id)
        validate_query(tenant_id, value, 1)
        if column not in {"trace_id", "interaction_id"}:
            raise ValueError("unsupported query column")
        with self._transaction() as connection:
            cursor = connection.cursor()
            try:
                cursor.execute(
                    f"""
                    SELECT {_SELECT_COLUMNS}
                    FROM interlock.security_events
                    WHERE tenant_id = %s AND {column} = %s
                    ORDER BY occurred_at, event_id
                    LIMIT %s
                    """,
                    (tenant_id, value, self.max_unpaged_events + 1),
                )
                rows = cursor.fetchall()
            finally:
                cursor.close()
        if len(rows) > self.max_unpaged_events:
            raise LedgerQueryLimitExceeded("unpaged Ledger query exceeded max_unpaged_events; use query_trace")
        return tuple(_event_from_row(row) for row in rows)

    @staticmethod
    def _load_event(
        cursor: Cursor,
        tenant_id: str,
        event_id: str,
        occurred_at: Any,
    ) -> Event | None:
        cursor.execute(
            f"""
            SELECT {_SELECT_COLUMNS}
            FROM interlock.security_events
            WHERE tenant_id = %s AND event_id = %s::uuid AND occurred_at = %s::timestamptz
            """,
            (tenant_id, event_id, occurred_at),
        )
        row = cursor.fetchone()
        return _event_from_row(row) if row is not None else None

    def _require_bound_tenant(self, tenant_id: str) -> None:
        if tenant_id != self.bound_tenant_id:
            raise LedgerTenantMismatch("requested tenant does not match the Ledger binding")

    @contextmanager
    def _transaction(self) -> Iterator[Connection]:
        connection = self._connection_factory()
        try:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT interlock.current_tenant()")
                row = cursor.fetchone()
            finally:
                cursor.close()
            if row is None or row[0] != self.bound_tenant_id:
                raise LedgerTenantMismatch("authenticated PostgreSQL role does not match the Ledger tenant binding")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


def _event_parameters(event: Event) -> tuple[Any, ...]:
    payload_canonical = canonical_json(event.payload).decode("utf-8")
    return (
        event.event_id,
        event.event_type,
        event.schema_version,
        event.occurred_at,
        event.ingested_at,
        event.tenant_id,
        event.environment,
        event.data_source,
        event.trace_id,
        event.span_id,
        event.parent_span_id,
        event.interaction_id,
        event.source_actor_id,
        event.target_actor_id,
        event.relationship_type,
        event.relationship_id,
        event.severity,
        payload_canonical,
        payload_canonical,
        event.integrity_hash,
    )


def _event_from_row(row: tuple[Any, ...]) -> Event:
    payload = json.loads(row[17]) if isinstance(row[17], str) else row[17]
    if not isinstance(payload, Mapping):
        raise LedgerError("stored event payload is not an object")
    event = Event(
        event_id=str(row[0]),
        event_type=str(row[1]),
        schema_version=str(row[2]),
        occurred_at=_timestamp(row[3]),
        ingested_at=_timestamp(row[4]),
        tenant_id=str(row[5]),
        environment=str(row[6]),
        data_source=str(row[7]),
        trace_id=str(row[8]),
        span_id=str(row[9]),
        parent_span_id=str(row[10]) if row[10] is not None else None,
        interaction_id=str(row[11]) if row[11] is not None else None,
        source_actor_id=str(row[12]),
        target_actor_id=str(row[13]) if row[13] is not None else None,
        relationship_type=str(row[14]),
        relationship_id=str(row[15]),
        severity=str(row[16]),
        payload=payload,
        integrity_hash=str(row[18]),
    )
    if not verify_event(event):
        raise LedgerIntegrityError("stored event failed canonical integrity verification")
    return event


def _timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        normalized = value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return normalized.isoformat().replace("+00:00", "Z")
    return str(value).replace("+00:00", "Z")
