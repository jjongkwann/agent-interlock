"""OTLP semantic-convention alias adapter + telemetry/audit-sink health linkage."""

from __future__ import annotations

import unittest

from agent_interlock import (
    ControlHealthReporter,
    RuntimeGraphDiff,
    import_runtime_telemetry,
    normalize_otlp_semconv,
    normalize_semconv_attributes,
)
from agent_interlock.telemetry import RuntimeTelemetryImport, TelemetryImportIssue

TENANT = "tenant-a"


class SemconvAttributeTests(unittest.TestCase):
    def test_legacy_keys_are_renamed_to_canonical(self):
        legacy = {
            "gen_ai.operation": "execute_tool",
            "interlock.source_actor_id": "agent.support",
            "interlock.relationship_id": "REL-05",
        }
        normalized = normalize_semconv_attributes(legacy)
        self.assertEqual(normalized["gen_ai.operation.name"], "execute_tool")
        self.assertEqual(normalized["interlock.source.actor.id"], "agent.support")
        self.assertEqual(normalized["interlock.relationship.id"], "REL-05")
        self.assertNotIn("gen_ai.operation", normalized)

    def test_canonical_value_wins_over_alias(self):
        mixed = {"gen_ai.operation": "old", "gen_ai.operation.name": "current"}
        self.assertEqual(normalize_semconv_attributes(mixed)["gen_ai.operation.name"], "current")

    def test_unknown_keys_are_passed_through(self):
        attrs = {"custom.attr": 1, "mcp.method": "tools/call"}
        normalized = normalize_semconv_attributes(attrs)
        self.assertEqual(normalized["custom.attr"], 1)
        self.assertEqual(normalized["mcp.method.name"], "tools/call")


class OtlpNormalizationTests(unittest.TestCase):
    def _legacy_otlp(self):
        return {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "spanId": "s1",
                                    "attributes": [
                                        {
                                            "key": "interlock.source_actor_id",
                                            "value": {"stringValue": "agent.support"},
                                        },
                                        {
                                            "key": "interlock.target_actor_id",
                                            "value": {"stringValue": "tool.send-email"},
                                        },
                                        {
                                            "key": "interlock.relationship_type",
                                            "value": {"stringValue": "INVOKES"},
                                        },
                                        {
                                            "key": "interlock.relationship_id",
                                            "value": {"stringValue": "REL-05"},
                                        },
                                        {
                                            "key": "interlock.interaction_id",
                                            "value": {"stringValue": "i1"},
                                        },
                                        {
                                            "key": "interlock.control_evaluated",
                                            "value": {"boolValue": True},
                                        },
                                    ],
                                }
                            ]
                        }
                    ]
                }
            ]
        }

    def test_legacy_otlp_reconciles_after_normalization(self):
        # Without normalization the legacy names carry no interlock context.
        raw = import_runtime_telemetry(self._legacy_otlp())
        self.assertEqual(raw.observations, ())
        # After normalization the edge is recovered.
        normalized = normalize_otlp_semconv(self._legacy_otlp())
        result = import_runtime_telemetry(normalized)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].relationship_id, "REL-05")
        self.assertEqual(result.control_evaluated_interactions, frozenset({"i1"}))

    def test_rejects_non_otlp_payload(self):
        with self.assertRaises(ValueError):
            normalize_otlp_semconv({"events": []})


class ControlHealthReporterTests(unittest.TestCase):
    def setUp(self):
        self.reporter = ControlHealthReporter(tenant_id=TENANT)

    def test_clean_import_emits_nothing(self):
        clean = RuntimeTelemetryImport("OTLP_JSON", (), frozenset(), ())
        self.assertIsNone(self.reporter.report_telemetry_import(clean))

    def test_import_issues_emit_degraded(self):
        result = RuntimeTelemetryImport(
            "OTLP_JSON",
            (),
            frozenset(),
            (TelemetryImportIssue("TELEMETRY_INTEGRITY_INVALID", "bad"),),
        )
        event_id = self.reporter.report_telemetry_import(result)
        self.assertIsNotNone(event_id)
        event = next(e for e in _all_events(self.reporter.ledger) if e.event_id == event_id)
        self.assertEqual(event.payload["control"]["status"], "DEGRADED")
        self.assertIn("L1-HEALTH-TELEMETRY-IMPORT-ISSUES", event.payload["control"]["reasonCodes"])
        self.assertEqual(event.severity, "HIGH")

    def test_sampling_gap_from_diff_emits_degraded(self):
        clean = RuntimeTelemetryImport("OTLP_JSON", (), frozenset(), ())
        diff = RuntimeGraphDiff(undeclared_edges=(), unobserved_edge_ids=(), control_bypass_interactions=("i9",))
        event_id = self.reporter.report_telemetry_import(clean, diff=diff)
        event = next(e for e in _all_events(self.reporter.ledger) if e.event_id == event_id)
        self.assertIn("L1-HEALTH-TELEMETRY-SAMPLING-GAP", event.payload["control"]["reasonCodes"])
        self.assertEqual(event.payload["health"]["controlBypassInteractions"], ["i9"])

    def test_audit_sink_failure_emits_degraded(self):
        event_id = self.reporter.report_audit_sink_failure("seal refused", event_id="evt-1")
        event = next(e for e in _all_events(self.reporter.ledger) if e.event_id == event_id)
        self.assertIn("L1-HEALTH-AUDIT-SINK-FAILURE", event.payload["control"]["reasonCodes"])
        self.assertEqual(event.payload["health"]["failedEventId"], "evt-1")
        self.assertEqual(event.relationship_id, "REL-12")


def _all_events(ledger):
    return list(ledger.all())


if __name__ == "__main__":
    unittest.main()
