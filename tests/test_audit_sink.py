from __future__ import annotations

import unittest
from dataclasses import replace

from agent_interlock import (
    AuditSinkError,
    InMemoryLedger,
    SignedAuditSink,
)

KEY = b"audit-sink-signing-key-000000000"
OTHER_KEY = b"another-audit-sink-key-111111111"


def _one_event():
    ledger = InMemoryLedger()
    return ledger.append(
        "CONTROL_EVALUATED",
        tenant_id="tenant-a",
        trace_id="trace-1",
        span_id="span-1",
        source_actor_id="agent.support",
        payload={"control": {"decision": "BLOCK", "reasonCodes": ["L1-M8-CREDENTIAL-DETECTED"]}},
    )


class SignedAuditSinkTests(unittest.TestCase):
    def test_seal_and_verify_round_trip(self):
        sink = SignedAuditSink(KEY)
        event = _one_event()
        record = sink.seal(event)
        self.assertEqual(record.event_id, event.event_id)
        self.assertEqual(record.integrity_hash, event.integrity_hash)
        self.assertTrue(sink.verify(event, record))

    def test_wrong_key_cannot_verify(self):
        event = _one_event()
        record = SignedAuditSink(KEY).seal(event)
        self.assertFalse(SignedAuditSink(OTHER_KEY).verify(event, record))

    def test_swapped_event_is_rejected(self):
        sink = SignedAuditSink(KEY)
        first = _one_event()
        second = _one_event()
        record = sink.seal(first)
        # A record does not vouch for a different event, even a valid one.
        self.assertFalse(sink.verify(second, record))

    def test_tampered_event_is_not_sealed(self):
        event = _one_event()
        forged = replace(event, payload={"control": {"decision": "ALLOW"}})
        with self.assertRaises(AuditSinkError):
            SignedAuditSink(KEY).seal(forged)

    def test_record_with_stale_integrity_hash_is_rejected(self):
        sink = SignedAuditSink(KEY)
        event = _one_event()
        record = sink.seal(event)
        stale = replace(record, integrity_hash="sha256:" + "0" * 64)
        self.assertFalse(sink.verify(event, stale))

    def test_empty_key_is_refused(self):
        with self.assertRaises(ValueError):
            SignedAuditSink(b"")


if __name__ == "__main__":
    unittest.main()
