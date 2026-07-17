"""Langfuse / LangSmith trace adapters into the runtime telemetry importer."""

from __future__ import annotations

import unittest

from agent_interlock import (
    import_langfuse_traces,
    import_langsmith_runs,
    langfuse_traces_to_otlp,
    langsmith_runs_to_otlp,
)

# The interlock security context an instrumented agent records in vendor metadata.
INTERLOCK_METADATA = {
    "gen_ai.operation.name": "execute_tool",
    "interlock.source.actor.id": "agent.support",
    "interlock.target.actor.id": "tool.send-email",
    "interlock.relationship.type": "INVOKES",
    "interlock.relationship.id": "REL-05",
    "interlock.interaction.id": "interaction-1",
    "interlock.control.evaluated": True,
}


class LangfuseAdapterTests(unittest.TestCase):
    def test_observations_map_to_reconciled_edges(self):
        payload = {"observations": [{"id": "obs-1", "type": "SPAN", "metadata": INTERLOCK_METADATA}]}
        result = import_langfuse_traces(payload)
        self.assertEqual(len(result.observations), 1)
        edge = result.observations[0]
        self.assertEqual(edge.source, "agent.support")
        self.assertEqual(edge.target, "tool.send-email")
        self.assertEqual(edge.relationship_id, "REL-05")
        self.assertEqual(result.control_evaluated_interactions, frozenset({"interaction-1"}))
        self.assertEqual(result.issues, ())

    def test_data_wrapper_and_bare_list_are_accepted(self):
        observation = {"id": "obs-1", "metadata": INTERLOCK_METADATA}
        for payload in ({"data": [observation]}, [observation]):
            self.assertEqual(len(import_langfuse_traces(payload).observations), 1)

    def test_boolean_attribute_is_typed_in_otlp(self):
        otlp = langfuse_traces_to_otlp({"observations": [{"id": "obs-1", "metadata": INTERLOCK_METADATA}]})
        span = otlp["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        evaluated = next(a for a in span["attributes"] if a["key"] == "interlock.control.evaluated")
        self.assertEqual(evaluated["value"], {"boolValue": True})

    def test_observation_without_metadata_is_skipped(self):
        payload = {"observations": [{"id": "obs-1"}, {"id": "obs-2", "metadata": INTERLOCK_METADATA}]}
        self.assertEqual(len(import_langfuse_traces(payload).observations), 1)


class LangSmithAdapterTests(unittest.TestCase):
    def test_runs_with_extra_metadata_map_to_edges(self):
        payload = {"runs": [{"id": "run-1", "run_type": "tool", "extra": {"metadata": INTERLOCK_METADATA}}]}
        result = import_langsmith_runs(payload)
        self.assertEqual(len(result.observations), 1)
        self.assertEqual(result.observations[0].target, "tool.send-email")
        self.assertEqual(result.control_evaluated_interactions, frozenset({"interaction-1"}))

    def test_top_level_metadata_fallback(self):
        payload = {"runs": [{"id": "run-1", "metadata": INTERLOCK_METADATA}]}
        self.assertEqual(len(import_langsmith_runs(payload).observations), 1)

    def test_missing_relationship_surfaces_an_issue_not_an_edge(self):
        incomplete = {"gen_ai.operation.name": "execute_tool"}  # tracked op, no relationship
        payload = {"runs": [{"id": "run-1", "extra": {"metadata": incomplete}}]}
        result = import_langsmith_runs(payload)
        self.assertEqual(result.observations, ())
        self.assertTrue(any(i.code == "TELEMETRY_SECURITY_CONTEXT_MISSING" for i in result.issues))

    def test_span_id_defaults_to_run_id(self):
        otlp = langsmith_runs_to_otlp({"runs": [{"id": "run-xyz", "extra": {"metadata": INTERLOCK_METADATA}}]})
        span = otlp["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertEqual(span["spanId"], "run-xyz")


if __name__ == "__main__":
    unittest.main()
