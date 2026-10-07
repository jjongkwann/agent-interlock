"""Durable local Ledger reuses the event, integrity, pagination and lifecycle contracts."""

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent_interlock.ledger import LedgerIdempotencyConflict, LedgerIntegrityError, LedgerRangeTooLarge
from agent_interlock.models import DataSource
from agent_interlock.sqlite_ledger import SQLiteLedger


class SQLiteLedgerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "ledger.sqlite3"
        self.ledger = SQLiteLedger(self.path)

    def append(self, **kwargs):
        fields = {"tenant_id": "tenant-a", "trace_id": "trace", "span_id": "span", "source_actor_id": "agent",
                  "payload": {"api_key": "private", "safe": "kept"}}
        fields.update(kwargs)
        return self.ledger.append("INTERACTION_REQUESTED", **fields)

    def test_restart_isolation_redaction_pagination_and_idempotency(self):
        event = self.append(idempotency_key="once", interaction_id="interaction")
        self.assertEqual(event.payload, {"api_key": "[REDACTED]", "safe": "kept"})
        self.assertTrue(self.ledger.verify(event))
        self.append(tenant_id="tenant-b", idempotency_key="once")
        self.ledger = SQLiteLedger(self.path)
        self.assertEqual(self.append(idempotency_key="once", interaction_id="interaction"), event)
        with self.assertRaises(LedgerIdempotencyConflict):
            self.append(idempotency_key="once", payload={"different": True})
        last = self.append(span_id="last")
        page = self.ledger.query_trace("tenant-a", "trace", limit=1)
        self.assertEqual(page.events, (event,))
        self.assertEqual(self.ledger.query_trace("tenant-a", "trace", cursor=page.next_cursor).events, (last,))
        self.assertEqual(self.ledger.trace("unknown", "trace"), ())
        self.assertEqual(self.ledger.interaction("tenant-a", "interaction"), (event,))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            self.ledger.query_trace("tenant-a", "trace", cursor="invalid")

    def test_multiple_instances_have_atomic_idempotency(self):
        ledgers = [SQLiteLedger(self.path), SQLiteLedger(self.path)]
        def append(index):
            return ledgers[index % 2].append("ACTION_EXECUTED", tenant_id="t", trace_id="trace", span_id="s",
                                            source_actor_id="a", payload={}, idempotency_key="once")
        with ThreadPoolExecutor(max_workers=8) as pool:
            events = list(pool.map(append, range(24)))
        self.assertEqual(len({event.event_id for event in events}), 1)
        self.assertEqual(len(self.ledger.trace("t", "trace")), 1)

    def test_time_range_and_full_lifecycle_match_started_interactions(self):
        self.append(occurred_at="2026-09-11T10:00:00Z", interaction_id="i", data_source=DataSource.PRODUCTION)
        end = self.ledger.append("INTERACTION_COMPLETED", tenant_id="tenant-a", trace_id="trace", span_id="end",
                                 source_actor_id="agent", payload={}, interaction_id="i",
                                 occurred_at="2026-09-12T10:00:00Z")
        declaration = self.ledger.append("CONTROL_COVERAGE_DECLARED", tenant_id="tenant-a", trace_id="trace",
                                         span_id="coverage", source_actor_id="agent", payload={},
                                         occurred_at="2026-09-10T10:00:00Z")
        self.append(tenant_id="tenant-b", interaction_id="i", occurred_at="2026-09-11T10:00:00Z")
        self.append(data_source=DataSource.TEST, interaction_id="test", occurred_at="2026-09-11T10:00:00Z")
        bounds = ("tenant-a", "2026-09-11T11:00:00+02:00", "2026-09-11T12:00:00+01:00")
        events = self.ledger.interaction_lifecycles_started_between(*bounds, data_source="PRODUCTION")
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0], declaration)
        self.assertEqual(events[-1], end)
        self.assertEqual(len(self.ledger.events_between(*bounds)), 2)
        with self.assertRaises(LedgerRangeTooLarge):
            self.ledger.interaction_lifecycles_started_between(*bounds, limit=2)
        with self.assertRaises(LedgerRangeTooLarge):
            self.ledger.events_between(*bounds, limit=1)
        with self.assertRaises(ValueError):
            self.ledger.events_between("tenant-a", "2026-09-11", "2026-09-12")

    def test_append_only_and_tamper_detection(self):
        self.append()
        with sqlite3.connect(self.path) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM ledger_events")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE ledger_events SET tenant_id = 'other'")
            connection.execute("DROP TRIGGER ledger_no_update")
            body = json.loads(connection.execute("SELECT body FROM ledger_events").fetchone()[0])
            body["payload"]["safe"] = "tampered"
            connection.execute("UPDATE ledger_events SET body = ?", (json.dumps(body),))
        with self.assertRaises(LedgerIntegrityError):
            self.ledger.trace("tenant-a", "trace")


if __name__ == "__main__":
    unittest.main()
