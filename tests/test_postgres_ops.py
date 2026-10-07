"""PostgreSQL migration runner, partition maintenance, connection pool.

Unit tests drive fakes; the live class applies real migrations, provisions and
prunes partitions, and pools real connections against a DSN-gated database.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from datetime import date
from pathlib import Path

from agent_interlock import (
    MigrationError,
    PartitionMaintenance,
    PoolExhausted,
    PostgreSQLConnectionPool,
    PostgreSQLMigrationRunner,
)

ROOT = Path(__file__).resolve().parents[1]


class ScriptedCursor:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, query, parameters=()):
        self.connection.executed.append((query, parameters))
        results = self.connection.results
        self.connection.current = results.pop(0) if results else None

    def fetchone(self):
        return self.connection.current if isinstance(self.connection.current, tuple) else None

    def fetchall(self):
        return self.connection.current if isinstance(self.connection.current, list) else []

    def close(self):
        return None


class ScriptedConnection:
    def __init__(self, *results):
        self.results = list(results)
        self.executed = []
        self.current = None
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self):
        return ScriptedCursor(self)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class MigrationRunnerTests(unittest.TestCase):
    def test_packaged_migrations_match_repository_sql(self):
        packaged = PostgreSQLMigrationRunner(None, lambda: ScriptedConnection()).discover()
        repository = PostgreSQLMigrationRunner(ROOT / "migrations/postgresql", lambda: ScriptedConnection()).discover()
        self.assertEqual(packaged, repository)
        self.assertTrue(packaged)
        self.assertEqual([version for version, _ in packaged][:4], ["0001", "0002", "0003", "0004"])

    def test_workflow_event_vocabulary_matches_database_and_http_contracts(self):
        from agent_interlock.ledger_http import _EVENT_TYPES
        migration = (ROOT / "src/agent_interlock/migrations/postgresql/0005_workflow_events.sql").read_text()
        envelope = json.loads((ROOT / "schemas/event-envelope.schema.json").read_text())
        schema_types = set(envelope["properties"]["event_type"]["enum"])
        sql_types = set(re.findall(r"'([A-Z_]+)'", migration))
        self.assertEqual(sql_types, _EVENT_TYPES)
        self.assertEqual(sql_types, schema_types)
        self.assertIn("WORKFLOW_TASK_APPROVED", sql_types)

    def test_discover_orders_and_ignores_legacy_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "0002_b.sql").write_text("SELECT 2;")
            (d / "0001_a.sql").write_text("SELECT 1;")
            (d / "001_legacy.sql").write_text("SELECT 0;")
            (d / "notes.txt").write_text("ignore")
            runner = PostgreSQLMigrationRunner(d, lambda: ScriptedConnection())
            self.assertEqual([v for v, _ in runner.discover()], ["0001", "0002"])

    def test_applies_only_pending_and_records_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "0001_a.sql").write_text("SELECT 1;")
            (d / "0002_b.sql").write_text("SELECT 2;")
            checksum_0001 = PostgreSQLMigrationRunner._checksum("SELECT 1;")
            # applied() runs: CREATE TABLE, then SELECT returning one applied row.
            connection = ScriptedConnection(None, [("0001", checksum_0001)])
            runner = PostgreSQLMigrationRunner(d, lambda: connection)
            applied = runner.apply()
            self.assertEqual(applied, ["0002"])  # 0001 already applied, skipped
            self.assertTrue(connection.committed)
            inserts = [q for q, _ in connection.executed if "INSERT INTO public.interlock_schema_migrations" in q]
            self.assertEqual(len(inserts), 1)

    def test_checksum_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "0001_a.sql").write_text("SELECT 1;")
            connection = ScriptedConnection(None, [("0001", "sha256:" + "0" * 64)])
            runner = PostgreSQLMigrationRunner(d, lambda: connection)
            with self.assertRaises(MigrationError):
                runner.apply()
            self.assertTrue(connection.rolled_back)


class PartitionMaintenanceTests(unittest.TestCase):
    def test_ensure_creates_current_and_future_months(self):
        connection = ScriptedConnection(("security_events_2026_07",), ("security_events_2026_08",))
        maint = PartitionMaintenance(lambda: connection)
        created = maint.ensure_partitions(today=date(2026, 7, 17), months_ahead=1)
        self.assertEqual(created, ["security_events_2026_07", "security_events_2026_08"])
        months = [params[0] for q, params in connection.executed if "create_security_events_partition" in q]
        self.assertEqual(months, ["2026-07-01", "2026-08-01"])
        self.assertTrue(connection.committed)

    def test_drop_removes_only_partitions_older_than_cutoff(self):
        partitions = [
            ("security_events_2026_04",),
            ("security_events_2026_05",),
            ("security_events_2026_06",),
            ("security_events_default",),
        ]
        connection = ScriptedConnection(partitions)
        maint = PartitionMaintenance(lambda: connection)
        dropped = maint.drop_partitions_older_than(cutoff_month=date(2026, 6, 1))
        self.assertEqual(dropped, ["security_events_2026_04", "security_events_2026_05"])
        drops = [q for q, _ in connection.executed if q.startswith("DROP TABLE")]
        self.assertTrue(all("_2026_06" not in q and "default" not in q for q in drops))
        # each drop detaches first and prunes the partition's ingest keys
        self.assertTrue(any(q.startswith("ALTER TABLE") and "DETACH PARTITION" in q for q, _ in connection.executed))
        self.assertTrue(any("DELETE FROM interlock.event_ingest_keys" in q for q, _ in connection.executed))


class ConnectionPoolTests(unittest.TestCase):
    def test_reuses_idle_connection_and_bounds_capacity(self):
        created = []

        def factory():
            connection = ScriptedConnection()
            created.append(connection)
            return connection

        pool = PostgreSQLConnectionPool(factory, max_size=2)
        a = pool.factory()
        b = pool.factory()
        self.assertEqual(pool.in_use, 2)
        with self.assertRaises(PoolExhausted):
            pool.factory()  # at capacity
        a.close()  # returns to pool (rollback first)
        self.assertEqual(pool.idle, 1)
        self.assertTrue(created[0].rolled_back)
        c = pool.factory()  # reuses the idle one, no new connection
        self.assertEqual(len(created), 2)
        b.close()
        c.close()

    def test_proxy_close_is_idempotent_and_pool_closeall(self):
        connection = ScriptedConnection()
        pool = PostgreSQLConnectionPool(lambda: connection, max_size=1)
        handle = pool.factory()
        handle.close()
        handle.close()  # second close is a no-op
        self.assertEqual(pool.in_use, 0)
        pool.closeall()
        self.assertTrue(connection.closed)


@unittest.skipUnless(
    os.environ.get("INTERLOCK_TEST_POSTGRES_ADMIN_DSN"),
    "set INTERLOCK_TEST_POSTGRES_ADMIN_DSN (migration owner) to run the live ops integration",
)
class PostgreSQLOpsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = os.environ["INTERLOCK_TEST_POSTGRES_ADMIN_DSN"]

    def _factory(self):
        from agent_interlock.postgres_ops import _dsn_factory

        return _dsn_factory(self.dsn, "agent-interlock-ops-test")

    def test_migration_runner_is_idempotent(self):
        runner = PostgreSQLMigrationRunner.from_dsn(ROOT / "migrations/postgresql", self.dsn)
        runner.apply()  # first apply (or no-op if already applied)
        self.assertEqual(runner.apply(), [])  # second apply does nothing

    def test_partition_ensure_and_prune_roundtrip(self):
        maint = PartitionMaintenance(self._factory())
        created = maint.ensure_partitions(today=date(2020, 1, 15), months_ahead=1)
        self.assertIn("security_events_2020_01", created)
        dropped = maint.drop_partitions_older_than(cutoff_month=date(2020, 3, 1))
        self.assertIn("security_events_2020_01", dropped)
        self.assertIn("security_events_2020_02", dropped)

    def test_pool_serves_working_connections(self):
        pool = PostgreSQLConnectionPool(self._factory(), max_size=2)
        try:
            connection = pool.factory()
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT 1")
                self.assertEqual(cursor.fetchone()[0], 1)
            finally:
                cursor.close()
            connection.close()
            self.assertEqual(pool.idle, 1)
        finally:
            pool.closeall()


if __name__ == "__main__":
    unittest.main()
