from __future__ import annotations

import json
import unittest
from dataclasses import asdict
from pathlib import Path

from agent_interlock import (
    ArchitectureGraph,
    InMemoryLedger,
    compare_observed_runtime,
    import_runtime_telemetry,
)


ROOT = Path(__file__).resolve().parents[1]
ARCHITECTURE = ROOT / "examples" / "secure_multi_agent_architecture.json"
OTLP_DRIFT = ROOT / "examples" / "runtime_drift_otlp.json"


def graph() -> ArchitectureGraph:
    return ArchitectureGraph.from_dict(json.loads(ARCHITECTURE.read_text(encoding="utf-8")))


class RuntimeTelemetryImportTests(unittest.TestCase):
    def test_imports_interlock_ledger_events(self):
        telemetry = [
            {
                "event_type": "INTERACTION_REQUESTED",
                "span_id": "span-1",
                "interaction_id": "interaction-1",
                "source_actor_id": "user.customer",
                "target_actor_id": "agent.support",
                "relationship_type": "REQUESTS",
                "relationship_id": "REL-01",
            },
            {
                "event_type": "CONTROL_EVALUATED",
                "span_id": "span-1",
                "interaction_id": "interaction-1",
            },
        ]
        imported = import_runtime_telemetry(telemetry)
        self.assertEqual(imported.format, "INTERLOCK_LEDGER")
        self.assertEqual(len(imported.observations), 1)
        self.assertEqual(imported.control_evaluated_interactions, {"interaction-1"})
        self.assertEqual(imported.issues, ())

        value = json.loads(ARCHITECTURE.read_text(encoding="utf-8"))
        value["spec"]["edges"] = [value["spec"]["edges"][0]]
        diff = compare_observed_runtime(
            ArchitectureGraph.from_dict(value),
            imported.observations,
            imported.control_evaluated_interactions,
        )
        self.assertTrue(diff.conforms)

    def test_rejects_tampered_ledger_event_with_integrity_hash(self):
        ledger = InMemoryLedger()
        event = ledger.append(
            "INTERACTION_REQUESTED",
            tenant_id="tenant-a",
            trace_id="trace-signed",
            span_id="span-signed",
            interaction_id="interaction-signed",
            source_actor_id="user.customer",
            target_actor_id="agent.support",
            relationship_type="REQUESTS",
            relationship_id="REL-01",
            payload={},
        )
        tampered = asdict(event)
        tampered["target_actor_id"] = "agent.attacker"
        imported = import_runtime_telemetry([tampered])
        self.assertEqual(imported.observations, ())
        self.assertEqual(imported.issues[0].code, "TELEMETRY_INTEGRITY_INVALID")

    def test_imports_otlp_and_finds_drift_and_control_bypass(self):
        imported = import_runtime_telemetry(json.loads(OTLP_DRIFT.read_text(encoding="utf-8")))
        self.assertEqual(imported.format, "OTLP_JSON")
        self.assertEqual(len(imported.observations), 3)
        self.assertEqual(len(imported.control_evaluated_interactions), 2)
        self.assertEqual(imported.issues, ())

        diff = compare_observed_runtime(
            graph(), imported.observations, imported.control_evaluated_interactions
        )
        self.assertFalse(diff.conforms)
        self.assertEqual(len(diff.undeclared_edges), 1)
        self.assertEqual(diff.undeclared_edges[0].target, "external.unknown")
        self.assertEqual(diff.control_bypass_interactions, ("interaction-bypass-42",))

    def test_tracked_standard_span_without_security_context_is_an_issue(self):
        payload = {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "spanId": "span-incomplete",
                                    "attributes": {
                                        "gen_ai.operation.name": "execute_tool",
                                        "gen_ai.tool.name": "send-email",
                                    },
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        imported = import_runtime_telemetry(payload)
        self.assertEqual(imported.observations, ())
        self.assertEqual(len(imported.issues), 1)
        self.assertEqual(imported.issues[0].code, "TELEMETRY_SECURITY_CONTEXT_MISSING")

    def test_relationship_without_control_is_reported_as_bypass(self):
        payload = {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "spanId": "span-bypass",
                                    "attributes": {
                                        "interlock.source.actor.id": "user.customer",
                                        "interlock.target.actor.id": "agent.support",
                                        "interlock.relationship.id": "REL-01",
                                        "interlock.relationship.type": "REQUESTS",
                                    },
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        imported = import_runtime_telemetry(payload)
        diff = compare_observed_runtime(
            graph(), imported.observations, imported.control_evaluated_interactions
        )
        self.assertEqual(diff.control_bypass_interactions, ("span-bypass",))


if __name__ == "__main__":
    unittest.main()
