"""WORM audit store: append-only, hash-chained, tamper-evident retention."""

from __future__ import annotations

import unittest
from dataclasses import replace

from agent_interlock import (
    InMemoryLedger,
    InMemoryWORMAuditStore,
    SignedAuditSink,
    WORMViolation,
)

KEY = b"worm-audit-signing-key-000000000"


def sealed(index: int):
    ledger = InMemoryLedger()
    event = ledger.append(
        "CONTROL_EVALUATED",
        tenant_id="tenant-a",
        trace_id=f"trace-{index}",
        span_id=f"span-{index}",
        source_actor_id="agent.support",
        payload={"control": {"decision": "BLOCK", "reasonCodes": ["L1-M8-CREDENTIAL-DETECTED"]}},
    )
    return SignedAuditSink(KEY).seal(event)


class WORMAuditStoreTests(unittest.TestCase):
    def test_append_chains_entries_and_verifies(self):
        store = InMemoryWORMAuditStore()
        first = store.append(sealed(1))
        second = store.append(sealed(2))
        self.assertEqual(first.sequence, 0)
        self.assertEqual(second.sequence, 1)
        self.assertEqual(second.previous_hash, first.entry_hash)
        self.assertTrue(store.verify_chain())

    def test_duplicate_record_is_rejected_write_once(self):
        store = InMemoryWORMAuditStore()
        record = sealed(1)
        store.append(record)
        with self.assertRaises(WORMViolation):
            store.append(record)

    def test_no_update_or_delete_method_exists(self):
        store = InMemoryWORMAuditStore()
        self.assertFalse(hasattr(store, "update"))
        self.assertFalse(hasattr(store, "delete"))

    def test_deletion_breaks_the_chain(self):
        store = InMemoryWORMAuditStore()
        for index in range(3):
            store.append(sealed(index))
        self.assertTrue(store.verify_chain())
        # Simulate tampering by removing the middle entry from the private list.
        del store._entries[1]
        self.assertFalse(store.verify_chain())

    def test_record_substitution_breaks_the_chain(self):
        store = InMemoryWORMAuditStore()
        store.append(sealed(1))
        target = store.append(sealed(2))
        forged = replace(target, record=sealed(99))
        store._entries[1] = forged  # entry_hash no longer matches its contents
        self.assertFalse(store.verify_chain())

    def test_reordering_breaks_the_chain(self):
        store = InMemoryWORMAuditStore()
        store.append(sealed(1))
        store.append(sealed(2))
        store._entries.reverse()
        self.assertFalse(store.verify_chain())


if __name__ == "__main__":
    unittest.main()
