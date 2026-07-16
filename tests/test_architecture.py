from __future__ import annotations

import json
import unittest
from pathlib import Path

from agent_interlock import (
    ArchitectureCompileError,
    ArchitectureCompiler,
    ArchitectureGraph,
    ArchitectureLinter,
    EnforcementPoint,
    FindingSeverity,
    InMemoryLedger,
    compare_runtime,
)


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "secure_multi_agent_architecture.json"


def manifest() -> dict:
    return json.loads(EXAMPLE.read_text(encoding="utf-8"))


def graph() -> ArchitectureGraph:
    return ArchitectureGraph.from_dict(manifest())


class ArchitectureModelTests(unittest.TestCase):
    def test_secure_multi_agent_manifest_parses(self):
        value = graph()
        self.assertEqual(value.id, "customer-support-multi-agent")
        self.assertEqual(len(value.nodes), 7)
        self.assertEqual(len(value.edges), 6)
        delegation = next(edge for edge in value.edges if edge.relationship_id == "REL-06")
        self.assertTrue(delegation.dynamic)
        self.assertEqual(delegation.policy.max_delegation_depth, 2)
        self.assertEqual(delegation.target_selector.id_pattern, "agent.research*")
        tool_edge = next(edge for edge in value.edges if edge.relationship_id == "REL-05")
        self.assertIn(
            EnforcementPoint.SANDBOX,
            {control.enforcement_point for control in tool_edge.controls},
        )

    def test_compiler_produces_actor_and_link_contracts(self):
        compiled = ArchitectureCompiler().compile(graph())
        self.assertEqual(set(compiled.actors), {node.id for node in compiled.graph.nodes})
        self.assertEqual(set(compiled.links), {edge.id for edge in compiled.graph.edges})
        self.assertEqual(compiled.findings, ())
        runtime = compiled.build_interlock()
        self.assertEqual(len(runtime.design_graph()["nodes"]), 7)
        self.assertEqual(len(runtime.design_graph()["edges"]), 6)

    def test_graph_rejects_unknown_node_reference(self):
        value = manifest()
        value["spec"]["edges"][0]["target"] = "agent.unknown"
        with self.assertRaises(ValueError):
            ArchitectureGraph.from_dict(value)

    def test_graph_rejects_duplicate_control_ids(self):
        value = manifest()
        value["spec"]["edges"][1]["controls"][0]["id"] = value["spec"]["edges"][0]["controls"][0]["id"]
        with self.assertRaises(ValueError):
            ArchitectureGraph.from_dict(value)

    def test_graph_rejects_unknown_api_version(self):
        value = manifest()
        value["apiVersion"] = "interlock.dev/v9"
        with self.assertRaises(ValueError):
            ArchitectureGraph.from_dict(value)


class ArchitectureSecurityLintTests(unittest.TestCase):
    def test_declared_only_a2a_control_cannot_compile(self):
        value = manifest()
        edge = next(item for item in value["spec"]["edges"] if item["relationshipId"] == "REL-06")
        edge["controls"][0]["assurance"] = "DECLARED"
        findings = ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        codes = {item.code for item in findings}
        self.assertIn("ARCH-ENFORCEMENT-POINT-MISSING", codes)
        self.assertIn("ARCH-DECLARED-ONLY", codes)
        with self.assertRaises(ArchitectureCompileError):
            ArchitectureCompiler().compile(ArchitectureGraph.from_dict(value))

    def test_credential_class_on_edge_is_critical(self):
        value = manifest()
        value["spec"]["edges"][0]["policy"]["allowedDataClasses"].append("D5")
        findings = ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        finding = next(item for item in findings if item.code == "ARCH-CREDENTIAL-DATA-ALLOWED")
        self.assertEqual(finding.severity, FindingSeverity.CRITICAL)

    def test_prevent_control_cannot_run_only_after_execution(self):
        value = manifest()
        value["spec"]["edges"][0]["controls"][0]["timing"] = "POST_EXECUTION"
        codes = {
            item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        }
        self.assertIn("ARCH-PREVENT-AFTER-EXECUTION", codes)

    def test_tool_digest_pin_requires_declared_digest(self):
        value = manifest()
        tool = next(item for item in value["spec"]["nodes"] if item["id"] == "tool.send-email")
        tool.pop("definitionDigest")
        codes = {
            item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        }
        self.assertIn("ARCH-TOOL-DIGEST-UNPINNED", codes)

    def test_delegation_depth_cannot_exceed_actor_limit(self):
        value = manifest()
        supervisor = next(item for item in value["spec"]["nodes"] if item["id"] == "agent.support")
        supervisor["maxDelegationDepth"] = 1
        codes = {
            item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        }
        self.assertIn("ARCH-DELEGATION-DEPTH-EXCEEDS-ACTOR", codes)

    def test_dynamic_target_pattern_cannot_be_unbounded(self):
        value = manifest()
        edge = next(item for item in value["spec"]["edges"] if item["relationshipId"] == "REL-06")
        edge["targetSelector"]["idPattern"] = "*"
        codes = {
            item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        }
        self.assertIn("ARCH-DYNAMIC-TARGET-UNBOUNDED", codes)

    def test_dynamic_target_capability_cannot_be_unbounded(self):
        value = manifest()
        edge = next(item for item in value["spec"]["edges"] if item["relationshipId"] == "REL-06")
        edge["targetSelector"]["requiredCapabilities"] = []
        codes = {
            item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        }
        self.assertIn("ARCH-DYNAMIC-CAPABILITY-UNBOUNDED", codes)

    def test_relationship_id_must_match_relationship_type(self):
        value = manifest()
        value["spec"]["edges"][0]["relationship"] = "INVOKES"
        codes = {
            item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        }
        self.assertIn("ARCH-RELATIONSHIP-ID-MISMATCH", codes)


class RuntimeGraphDiffTests(unittest.TestCase):
    def test_dynamic_subagent_instance_matches_declared_contract(self):
        value = manifest()
        value["spec"]["edges"] = [
            next(item for item in value["spec"]["edges"] if item["relationshipId"] == "REL-06")
        ]
        dynamic_graph = ArchitectureGraph.from_dict(value)
        ledger = InMemoryLedger()
        common = {
            "tenant_id": "tenant-a",
            "trace_id": "trace-dynamic",
            "span_id": "span-dynamic",
            "interaction_id": "interaction-dynamic",
            "source_actor_id": "agent.support",
            "target_actor_id": "agent.research.runtime-42",
            "relationship_type": "DELEGATES",
            "relationship_id": "REL-06",
        }
        ledger.append("INTERACTION_REQUESTED", payload={}, **common)
        ledger.append("CONTROL_EVALUATED", payload={"decision": "ALLOW"}, **common)
        diff = compare_runtime(dynamic_graph, ledger.all())
        self.assertTrue(diff.conforms)
        self.assertEqual(diff.unobserved_edge_ids, ())

    def test_runtime_diff_finds_undeclared_edge_and_control_bypass(self):
        ledger = InMemoryLedger()
        common = {
            "tenant_id": "tenant-a",
            "trace_id": "trace-architecture",
            "span_id": "span-user-support",
            "interaction_id": "interaction-declared",
            "source_actor_id": "user.customer",
            "target_actor_id": "agent.support",
            "relationship_type": "REQUESTS",
            "relationship_id": "REL-01",
        }
        ledger.append("INTERACTION_REQUESTED", payload={}, **common)
        ledger.append("CONTROL_EVALUATED", payload={"decision": "ALLOW"}, **common)
        ledger.append(
            "INTERACTION_REQUESTED",
            tenant_id="tenant-a",
            trace_id="trace-architecture",
            span_id="span-bypass",
            interaction_id="interaction-bypass",
            source_actor_id="agent.research",
            target_actor_id="external.unknown",
            relationship_type="SENDS",
            relationship_id="REL-07",
            payload={},
        )
        diff = compare_runtime(graph(), ledger.all())
        self.assertFalse(diff.conforms)
        self.assertEqual(len(diff.undeclared_edges), 1)
        self.assertEqual(diff.undeclared_edges[0].target, "external.unknown")
        self.assertEqual(diff.control_bypass_interactions, ("interaction-bypass",))
        self.assertIn("edge.support-research", diff.unobserved_edge_ids)

    def test_matching_runtime_edge_with_control_conforms(self):
        value = manifest()
        value["spec"]["edges"] = [value["spec"]["edges"][0]]
        minimal = ArchitectureGraph.from_dict(value)
        ledger = InMemoryLedger()
        common = {
            "tenant_id": "tenant-a",
            "trace_id": "trace-conform",
            "span_id": "span-conform",
            "interaction_id": "interaction-conform",
            "source_actor_id": "user.customer",
            "target_actor_id": "agent.support",
            "relationship_type": "REQUESTS",
            "relationship_id": "REL-01",
        }
        ledger.append("INTERACTION_REQUESTED", payload={}, **common)
        ledger.append("CONTROL_EVALUATED", payload={"decision": "ALLOW"}, **common)
        diff = compare_runtime(minimal, ledger.all())
        self.assertTrue(diff.conforms)
        self.assertEqual(diff.unobserved_edge_ids, ())


if __name__ == "__main__":
    unittest.main()
