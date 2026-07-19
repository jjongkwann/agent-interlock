"""Security-statistics contract tests.

The golden pair under ``schemas/fixtures/`` is the cross-language contract:
the Studio offline importer must produce ``analytics-statistics.json``
byte-for-byte (canonical: sorted keys) from ``analytics-events.json``. The
live-gateway test guards the other seam: real gateway event shapes must keep
reducing correctly.
"""

import json
import unittest
from pathlib import Path

from l1_harness import TENANT, build_gateway

from agent_interlock import (
    ControlDecision,
    InvocationBlocked,
    InvocationIntent,
    reduce_interactions,
    summarize_security_statistics,
)

FIXTURES = Path(__file__).resolve().parent.parent / "schemas" / "fixtures"


class GoldenContractTests(unittest.TestCase):
    def setUp(self):
        self.events = json.loads((FIXTURES / "analytics-events.json").read_text())
        self.golden = json.loads((FIXTURES / "analytics-statistics.json").read_text())

    def test_summary_matches_golden_exactly(self):
        self.assertEqual(summarize_security_statistics(self.events), self.golden)

    def test_summary_is_canonical_under_sorted_key_serialization(self):
        produced = json.dumps(summarize_security_statistics(self.events), indent=2, sort_keys=True) + "\n"
        self.assertEqual(produced, (FIXTURES / "analytics-statistics.json").read_text())

    def test_hand_computed_production_counters(self):
        # Independent of the golden file: the semantics themselves.
        production = summarize_security_statistics(self.events)["partitions"][0]
        self.assertEqual(production["dataSource"], "PRODUCTION")
        self.assertEqual(
            production["counters"],
            {
                "interactionCount": 5,
                "blockDecisionCount": 2,
                "shadowWouldBlockCount": 1,
                "enforcedBlockCount": 1,
                "executionAttemptCount": 4,
                "executionSuccessCount": 3,
                "partialOrBypassCount": 1,
            },
        )

    def test_reason_code_sum_may_exceed_blocked_interactions(self):
        production = summarize_security_statistics(self.events)["partitions"][0]
        reason_total = sum(item["interactionCount"] for item in production["byReasonCode"])
        self.assertGreater(reason_total, production["counters"]["blockDecisionCount"])

    def test_definition_level_control_events_are_ignored(self):
        records = reduce_interactions(self.events)
        self.assertEqual(len(records), 6)
        self.assertNotIn(None, [record.interaction_id for record in records])

    def test_simulation_traffic_is_partitioned_not_merged(self):
        summary = summarize_security_statistics(self.events)
        self.assertEqual([p["dataSource"] for p in summary["partitions"]], ["PRODUCTION", "SIMULATION"])
        self.assertEqual(summary["partitions"][1]["counters"]["interactionCount"], 1)


class LiveGatewayReductionTests(unittest.TestCase):
    """Real gateway events must reduce with the same semantics as the fixture."""

    def test_allowed_and_blocked_invocations_reduce_correctly(self):
        gateway, revision, source, _target = build_gateway(external_approval=False)
        gateway.invoke(
            connector=lambda arguments: {"status": "SENT", "messageId": "m-1"},
            idempotency_key="idem-allow",
            tenant_id=TENANT,
            source_actor_id=source.id,
            revision_id=revision.revision_id,
            intent=InvocationIntent(purpose="notify-customer"),
            arguments={"to": "user@customer.example", "body": "hello"},
        )
        with self.assertRaises(InvocationBlocked):
            gateway.invoke(
                connector=lambda arguments: {"status": "SENT", "messageId": "m-2"},
                idempotency_key="idem-block",
                tenant_id=TENANT,
                source_actor_id=source.id,
                revision_id=revision.revision_id,
                intent=InvocationIntent(purpose="exfiltrate", data_classes=frozenset({"D5"})),
                arguments={"to": "user@customer.example", "body": "secret"},
            )

        records = reduce_interactions(event.to_dict() for event in gateway.ledger.all())
        self.assertEqual(len(records), 2)
        allowed = next(r for r in records if r.decision == ControlDecision.ALLOW)
        blocked = next(r for r in records if r.decision != ControlDecision.ALLOW)
        self.assertTrue(allowed.execution_attempted and allowed.execution_succeeded)
        self.assertTrue(blocked.enforced_block)
        self.assertFalse(blocked.execution_attempted)
        self.assertEqual(blocked.security_outcome, "BLOCKED")
        self.assertTrue(blocked.reason_codes)

        summary = summarize_security_statistics(event.to_dict() for event in gateway.ledger.all())
        counters = summary["partitions"][0]["counters"]
        self.assertEqual(counters["interactionCount"], 2)
        self.assertEqual(counters["enforcedBlockCount"], 1)
        self.assertEqual(counters["executionAttemptCount"], 1)
        self.assertEqual(counters["executionSuccessCount"], 1)


if __name__ == "__main__":
    unittest.main()
