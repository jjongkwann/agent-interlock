"""File-backed persistent WORM audit store: durability, reload, tamper detection."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agent_interlock import (
    FileWORMAuditStore,
    InMemoryLedger,
    SignedAuditSink,
    WORMViolation,
)

KEY = b"file-worm-signing-key-0000000000"


def sealed(index: int):
    event = InMemoryLedger().append(
        "CONTROL_EVALUATED",
        tenant_id="tenant-a",
        trace_id=f"trace-{index}",
        span_id=f"span-{index}",
        source_actor_id="agent.support",
        payload={"control": {"decision": "BLOCK", "reasonCodes": ["L1-M8-CREDENTIAL-DETECTED"]}},
    )
    return SignedAuditSink(KEY).seal(event)


class FileWORMAuditStoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="file-worm-")
        self.path = os.path.join(self.dir, "sub", "audit.jsonl")
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)

    def test_append_persists_and_survives_reload(self):
        store = FileWORMAuditStore(self.path)
        store.append(sealed(1))
        store.append(sealed(2))
        self.assertTrue(Path(self.path).exists())
        # A fresh instance reloads and re-verifies the chain.
        reopened = FileWORMAuditStore(self.path)
        self.assertEqual(len(reopened.entries()), 2)
        self.assertTrue(reopened.verify_chain())

    def test_write_once_dedupe_survives_restart(self):
        record = sealed(1)
        FileWORMAuditStore(self.path).append(record)
        reopened = FileWORMAuditStore(self.path)
        with self.assertRaises(WORMViolation):
            reopened.append(record)  # same (tenant, event) already persisted

    def test_chain_continues_across_restarts(self):
        FileWORMAuditStore(self.path).append(sealed(1))
        store2 = FileWORMAuditStore(self.path)
        entry = store2.append(sealed(2))
        self.assertEqual(entry.sequence, 1)
        self.assertEqual(entry.previous_hash, store2.entries()[0].entry_hash)

    def test_tampered_line_is_detected_on_open(self):
        store = FileWORMAuditStore(self.path)
        store.append(sealed(1))
        store.append(sealed(2))
        lines = Path(self.path).read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["record"]["signature"] = "hmac-sha256:" + "f" * 64  # forge a record
        lines[0] = json.dumps(first, sort_keys=True)
        Path(self.path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(WORMViolation):
            FileWORMAuditStore(self.path)

    def test_truncated_deletion_is_detected_on_open(self):
        store = FileWORMAuditStore(self.path)
        store.append(sealed(1))
        store.append(sealed(2))
        store.append(sealed(3))
        lines = Path(self.path).read_text(encoding="utf-8").splitlines()
        del lines[1]  # remove the middle entry
        Path(self.path).write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(WORMViolation):
            FileWORMAuditStore(self.path)

    def test_empty_path_starts_a_fresh_chain(self):
        store = FileWORMAuditStore(self.path)
        self.assertEqual(store.entries(), ())
        self.assertTrue(store.verify_chain())

    def test_concurrent_instances_share_sequence_and_dedupe(self):
        stores = [FileWORMAuditStore(self.path), FileWORMAuditStore(self.path)]
        records = [sealed(index) for index in range(12)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            entries = list(pool.map(lambda pair: stores[pair[0] % 2].append(pair[1]), enumerate(records)))
        self.assertEqual(sorted(entry.sequence for entry in entries), list(range(12)))
        self.assertEqual(len(stores[0].entries()), 12)
        self.assertTrue(FileWORMAuditStore(self.path).verify_chain())
        with self.assertRaises(WORMViolation):
            stores[1].append(records[0])


if __name__ == "__main__":
    unittest.main()
