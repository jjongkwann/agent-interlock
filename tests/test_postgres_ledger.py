from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_interlock import (
    LedgerIdempotencyConflict,
    LedgerIntegrityError,
    LedgerTenantMismatch,
    PostgreSQLDriverUnavailable,
    PostgreSQLLedger,
    build_event,
)
from agent_interlock.postgres_ledger import _event_from_row

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/postgresql/0001_interaction_ledger.sql"


class RecordingCursor:
    def __init__(self, tenant_id: str | None):
        self.tenant_id = tenant_id
        self.executed: list[tuple[str, tuple]] = []

    def execute(self, query: str, parameters: tuple = ()):
        self.executed.append((query, parameters))

    def fetchone(self):
        return (self.tenant_id,)

    def fetchall(self):
        return []

    def close(self):
        return None


class RecordingConnection:
    def __init__(self, tenant_id: str | None):
        self.cursor_value = RecordingCursor(tenant_id)
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return self.cursor_value

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class PostgreSQLLedgerUnitTests(unittest.TestCase):
    def test_db_role_tenant_mismatch_fails_before_event_sql(self):
        connection = RecordingConnection("tenant-b")
        ledger = PostgreSQLLedger(lambda: connection, bound_tenant_id="tenant-a")
        with self.assertRaises(LedgerTenantMismatch):
            ledger.append(
                "INTERACTION_REQUESTED",
                tenant_id="tenant-a",
                trace_id="trace-one",
                span_id="span-one",
                source_actor_id="agent.support",
                payload={},
            )
        self.assertEqual(len(connection.cursor_value.executed), 1)
        self.assertIn("current_tenant", connection.cursor_value.executed[0][0])
        self.assertTrue(connection.rolled_back)
        self.assertTrue(connection.closed)
        self.assertFalse(connection.committed)

    def test_requested_tenant_mismatch_opens_no_connection(self):
        calls = 0

        def connect():
            nonlocal calls
            calls += 1
            return RecordingConnection("tenant-a")

        ledger = PostgreSQLLedger(connect, bound_tenant_id="tenant-a")
        with self.assertRaises(LedgerTenantMismatch):
            ledger.trace("tenant-b", "trace-one")
        self.assertEqual(calls, 0)

    def test_dsn_error_and_repr_do_not_expose_credentials(self):
        dsn = "postgresql://ledger:super-secret@db.example/interlock"
        with (
            patch.dict(sys.modules, {"psycopg": None}),
            self.assertRaises(PostgreSQLDriverUnavailable) as raised,
        ):
            PostgreSQLLedger.from_dsn(dsn, bound_tenant_id="tenant-a")
        self.assertNotIn("super-secret", str(raised.exception))
        ledger = PostgreSQLLedger(
            lambda: RecordingConnection("tenant-a"),
            bound_tenant_id="tenant-a",
        )
        self.assertNotIn("super-secret", repr(ledger))

    def test_migration_has_database_side_tenant_and_append_only_controls(self):
        sql = MIGRATION.read_text(encoding="utf-8")
        required = (
            "PARTITION BY RANGE (occurred_at)",
            "session_user",
            "ENABLE ROW LEVEL SECURITY",
            "FORCE ROW LEVEL SECURITY",
            "WITH CHECK (tenant_id = interlock.current_tenant())",
            "security_events_no_mutation",
            "REVOKE ALL ON interlock.role_tenant FROM PUBLIC",
            "NOBYPASSRLS",
            "DEFERRABLE INITIALLY DEFERRED",
            "payload = payload_canonical::jsonb",
        )
        for value in required:
            self.assertIn(value, sql)
        self.assertNotIn("current_setting('app.tenant_id')", sql)

    def test_stored_event_integrity_mismatch_is_rejected(self):
        event = build_event(
            "INTERACTION_REQUESTED",
            tenant_id="tenant-a",
            trace_id="trace-integrity",
            span_id="span-integrity",
            source_actor_id="agent.support",
            payload={"marker": "safe"},
        )
        row = (
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
            json.dumps({"marker": "tampered"}),
            event.integrity_hash,
        )
        with self.assertRaises(LedgerIntegrityError):
            _event_from_row(row)


@unittest.skipUnless(
    os.environ.get("INTERLOCK_TEST_POSTGRES_DSN_TENANT_A") and os.environ.get("INTERLOCK_TEST_POSTGRES_DSN_TENANT_B"),
    "set tenant PostgreSQL DSNs to run the live adapter integration",
)
class PostgreSQLLedgerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ledger_a = PostgreSQLLedger.from_dsn(
            os.environ["INTERLOCK_TEST_POSTGRES_DSN_TENANT_A"],
            bound_tenant_id="tenant-a",
        )
        cls.ledger_b = PostgreSQLLedger.from_dsn(
            os.environ["INTERLOCK_TEST_POSTGRES_DSN_TENANT_B"],
            bound_tenant_id="tenant-b",
        )

    def test_live_idempotency_rls_and_pagination(self):
        key = "live-adapter-idempotency"
        common = dict(
            tenant_id="tenant-a",
            trace_id="trace-live-postgres",
            span_id="span-one",
            source_actor_id="agent.support",
            payload={"marker": "one", "largeNumber": 1e20, "negativeZero": -0.0},
            idempotency_key=key,
        )
        first = self.ledger_a.append("INTERACTION_REQUESTED", **common)
        replay = self.ledger_a.append("INTERACTION_REQUESTED", **common)
        self.assertEqual(first.event_id, replay.event_id)
        self.assertEqual(replay.payload["largeNumber"], 1e20)
        self.assertEqual(replay.payload["negativeZero"], -0.0)
        with self.assertRaises(LedgerIdempotencyConflict):
            self.ledger_a.append(
                "INTERACTION_REQUESTED",
                **{**common, "payload": {"marker": "different"}},
            )
        self.ledger_a.append(
            "CONTROL_EVALUATED",
            tenant_id="tenant-a",
            trace_id="trace-live-postgres",
            span_id="span-two",
            source_actor_id="agent.support",
            payload={"decision": "ALLOW"},
            idempotency_key="live-adapter-second",
        )
        first_page = self.ledger_a.query_trace("tenant-a", "trace-live-postgres", limit=1)
        self.assertEqual(len(first_page.events), 1)
        self.assertIsNotNone(first_page.next_cursor)
        second_page = self.ledger_a.query_trace(
            "tenant-a",
            "trace-live-postgres",
            limit=1,
            cursor=first_page.next_cursor,
        )
        self.assertEqual(len(second_page.events), 1)
        self.assertEqual(self.ledger_b.trace("tenant-b", "trace-live-postgres"), ())

        self.ledger_b.append(
            "INTERACTION_REQUESTED",
            tenant_id="tenant-b",
            trace_id="trace-shared-name",
            span_id="span-tenant-b",
            source_actor_id="agent.support",
            payload={"marker": "tenant-b"},
            idempotency_key="live-tenant-b-event",
        )
        self.ledger_a.append(
            "INTERACTION_REQUESTED",
            tenant_id="tenant-a",
            trace_id="trace-shared-name",
            span_id="span-tenant-a",
            source_actor_id="agent.support",
            payload={"marker": "tenant-a"},
            idempotency_key="live-tenant-a-event",
        )
        self.assertEqual(len(self.ledger_a.trace("tenant-a", "trace-shared-name")), 1)
        self.assertEqual(len(self.ledger_b.trace("tenant-b", "trace-shared-name")), 1)

    def test_live_guc_set_role_and_mutation_cannot_cross_the_boundary(self):
        import psycopg

        self.ledger_a.append(
            "INTERACTION_REQUESTED",
            tenant_id="tenant-a",
            trace_id="trace-live-boundary",
            span_id="span-boundary",
            source_actor_id="agent.support",
            payload={"marker": "tenant-a-boundary"},
            idempotency_key="live-boundary-seed",
        )
        dsn = os.environ["INTERLOCK_TEST_POSTGRES_DSN_TENANT_A"]
        with psycopg.connect(dsn) as connection, connection.cursor() as cursor:
            cursor.execute("SET app.tenant_id = 'tenant-b'")
            cursor.execute("SELECT DISTINCT tenant_id FROM interlock.security_events ORDER BY tenant_id")
            self.assertEqual(cursor.fetchall(), [("tenant-a",)])

        with (
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
            psycopg.connect(dsn) as connection,
        ):
            connection.execute("SET ROLE tenant_b_app")

        with (
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
            psycopg.connect(dsn) as connection,
        ):
            connection.execute(
                "UPDATE interlock.security_events SET severity = 'LOW' WHERE tenant_id = %s",
                ("tenant-a",),
            )

        with (
            self.assertRaises(psycopg.errors.InsufficientPrivilege),
            psycopg.connect(dsn) as connection,
        ):
            connection.execute(
                """
                    INSERT INTO interlock.event_ingest_keys (
                        tenant_id, idempotency_key, request_hash,
                        event_id, event_occurred_at
                    ) VALUES (%s, %s, %s, %s::uuid, now())
                    """,
                (
                    "tenant-b",
                    "cross-tenant-attempt",
                    "sha256:" + "0" * 64,
                    "00000000-0000-7000-8000-000000000000",
                ),
            )


if __name__ == "__main__":
    unittest.main()
