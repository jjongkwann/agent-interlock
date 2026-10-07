"""Local durable Ledger with the same event and query contract as PostgreSQL."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

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


def _time(value: str) -> str:
    return parse_event_time(value).isoformat(timespec="microseconds")


class SQLiteLedger:
    """Append-only local evidence. This is not a cross-process tool execution cache."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        with self._connection(write=True) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError(f"unsupported SQLite Ledger schema version: {version}")
            connection.execute("""CREATE TABLE IF NOT EXISTS ledger_events (
                event_id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, trace_id TEXT NOT NULL,
                interaction_id TEXT, event_type TEXT NOT NULL, data_source TEXT NOT NULL,
                occurred_at TEXT NOT NULL, body TEXT NOT NULL,
                idempotency_key TEXT, request_digest TEXT NOT NULL,
                UNIQUE (tenant_id, idempotency_key))""")
            connection.execute("""CREATE INDEX IF NOT EXISTS ledger_trace
                ON ledger_events(tenant_id, trace_id, occurred_at, event_id)""")
            connection.execute("""CREATE INDEX IF NOT EXISTS ledger_interaction
                ON ledger_events(tenant_id, interaction_id, occurred_at, event_id)""")
            connection.execute("""CREATE INDEX IF NOT EXISTS ledger_time
                ON ledger_events(tenant_id, occurred_at, event_id)""")
            for operation in ("UPDATE", "DELETE"):
                connection.execute(f"""CREATE TRIGGER IF NOT EXISTS ledger_no_{operation.lower()}
                    BEFORE {operation} ON ledger_events
                    BEGIN SELECT RAISE(ABORT, 'ledger events are append-only'); END""")
            connection.execute("PRAGMA user_version = 1")

    @contextmanager
    def _connection(self, *, write: bool = False):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            if write:
                connection.execute("BEGIN IMMEDIATE")
            with connection:
                yield connection
        except sqlite3.Error as error:
            raise LedgerError("SQLite Ledger operation failed") from error
        finally:
            connection.close()

    @staticmethod
    def _event(row: sqlite3.Row) -> Event:
        try:
            event = Event(**json.loads(row["body"]))
            if not verify_event(event) or row["request_digest"] != event_request_digest(event) or any(
                row[field] != getattr(event, field)
                for field in ("event_id", "tenant_id", "trace_id", "interaction_id", "event_type", "data_source")
            ) or row["occurred_at"] != _time(event.occurred_at):
                raise ValueError("stored event integrity mismatch")
            return event
        except (ValueError, TypeError, KeyError) as error:
            raise LedgerIntegrityError("stored event integrity mismatch") from error

    def append(self, event_type: str, *, idempotency_key: str | None = None, **fields) -> Event:
        if idempotency_key is not None and (
            not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 200
        ):
            raise ValueError("idempotency_key must be between 1 and 200 characters")
        event = build_event(event_type, **fields)
        digest = event_request_digest(event)
        with self._connection(write=True) as connection:
            if idempotency_key is not None:
                existing = connection.execute(
                    "SELECT * FROM ledger_events WHERE tenant_id = ? AND idempotency_key = ?",
                    (event.tenant_id, idempotency_key),
                ).fetchone()
                if existing is not None:
                    saved = self._event(existing)
                    if existing["request_digest"] != digest or event_request_digest(saved) != digest:
                        raise LedgerIdempotencyConflict("idempotency key is already bound to another event")
                    return saved
            connection.execute(
                "INSERT INTO ledger_events VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (event.event_id, event.tenant_id, event.trace_id, event.interaction_id, event.event_type,
                 event.data_source, _time(event.occurred_at), json.dumps(event.to_dict()), idempotency_key, digest),
            )
        return event

    def _read(self, where: str, parameters: tuple, *, limit: int | None = None) -> tuple[Event, ...]:
        query = "SELECT * FROM ledger_events WHERE " + where + " ORDER BY occurred_at, event_id"
        if limit is not None:
            query += " LIMIT ?"
            parameters += (limit,)
        with self._connection() as connection:
            return tuple(self._event(row) for row in connection.execute(query, parameters))

    def trace(self, tenant_id: str, trace_id: str) -> tuple[Event, ...]:
        validate_query(tenant_id, trace_id, 1)
        return self._read("tenant_id = ? AND trace_id = ?", (tenant_id, trace_id))

    def interaction(self, tenant_id: str, interaction_id: str) -> tuple[Event, ...]:
        validate_query(tenant_id, interaction_id, 1)
        return self._read("tenant_id = ? AND interaction_id = ?", (tenant_id, interaction_id))

    def query_trace(self, tenant_id: str, trace_id: str, *, limit: int = 100,
                    cursor: str | None = None) -> EventPage:
        validate_query(tenant_id, trace_id, limit)
        where = "tenant_id = ? AND trace_id = ?"
        parameters = (tenant_id, trace_id)
        if cursor is not None:
            occurred_at, event_id = decode_event_cursor(cursor)
            where += " AND (occurred_at, event_id) > (?, ?)"
            parameters += (_time(occurred_at), event_id)
        events = self._read(where, parameters, limit=limit + 1)
        return EventPage(events[:limit], encode_event_cursor(events[limit - 1]) if len(events) > limit else None)

    @staticmethod
    def _range(tenant_id: str, start: str, end: str, limit: int) -> tuple[str, str]:
        if not tenant_id or not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise ValueError("tenant_id and a positive limit are required")
        start_at, end_at = _time(start), _time(end)
        if start_at >= end_at:
            raise ValueError("start must be before end")
        return start_at, end_at

    def events_between(self, tenant_id: str, start: str, end: str, *, limit: int = 100_000) -> tuple[Event, ...]:
        start_at, end_at = self._range(tenant_id, start, end, limit)
        events = self._read("tenant_id = ? AND occurred_at >= ? AND occurred_at < ?",
                            (tenant_id, start_at, end_at), limit=limit + 1)
        if len(events) > limit:
            raise LedgerRangeTooLarge("time range matches more events than the limit")
        return events

    def interaction_lifecycles_started_between(
        self, tenant_id: str, start: str, end: str, *, data_source: str | None = None, limit: int = 100_000,
    ) -> tuple[Event, ...]:
        start_at, end_at = self._range(tenant_id, start, end, limit)
        events = self._read(
            """tenant_id = ? AND (
                interaction_id IN (
                    SELECT interaction_id FROM ledger_events WHERE tenant_id = ?
                    AND event_type = 'INTERACTION_REQUESTED' AND interaction_id IS NOT NULL
                    AND occurred_at >= ? AND occurred_at < ? AND (? IS NULL OR data_source = ?)
                ) OR (event_type = 'CONTROL_COVERAGE_DECLARED' AND occurred_at < ?
                      AND (? IS NULL OR data_source = ?)))""",
            (tenant_id, tenant_id, start_at, end_at, data_source, data_source, end_at, data_source, data_source),
            limit=limit + 1,
        )
        if len(events) > limit:
            raise LedgerRangeTooLarge("interaction lifecycles match more events than the limit")
        return events

    verify = staticmethod(verify_event)
