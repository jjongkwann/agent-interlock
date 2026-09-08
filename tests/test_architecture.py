from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from agent_interlock import (
    AcceptanceCriterion,
    ArchitectureCompileError,
    ArchitectureCompiler,
    ArchitectureGraph,
    ArchitectureLinter,
    EnforcementPoint,
    FindingSeverity,
    InMemoryLedger,
    compare_runtime,
    parse_acceptance_criterion,
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

    def test_node_schema_with_unsupported_keyword_is_rejected_with_node_context(self):
        value = manifest()
        node = value["spec"]["nodes"][0]
        node["inputSchema"] = {"type": "object", "properties": {"to": {"type": "string", "minLength": 1}}}
        with self.assertRaises(ValueError) as ctx:
            ArchitectureGraph.from_dict(value)
        message = str(ctx.exception)
        self.assertIn(node["id"], message)
        self.assertIn("minLength", message)

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

    def test_edge_policy_cannot_allow_a_data_class_the_target_actor_lacks(self):
        value = manifest()
        rag = next(item for item in value["spec"]["nodes"] if item["id"] == "rag.support-knowledge")
        rag["dataAccess"] = ["D3"]
        findings = ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        finding = next(item for item in findings if item.code == "ARCH-DATA-CLASS-EXCEEDS-ACTOR")
        self.assertEqual(finding.severity, FindingSeverity.CRITICAL)
        self.assertEqual(finding.edge_id, "edge.research-rag")

    def test_data_class_excess_finding_names_the_classes_the_actor_lacks(self):
        value = manifest()
        rag = next(item for item in value["spec"]["nodes"] if item["id"] == "rag.support-knowledge")
        rag["dataAccess"] = ["D3"]
        findings = ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        finding = next(item for item in findings if item.code == "ARCH-DATA-CLASS-EXCEEDS-ACTOR")
        self.assertIn("D2", finding.message)
        self.assertIn("D7", finding.message)
        self.assertNotIn("D3", finding.message)

    def test_data_class_excess_is_reported_when_the_actor_grant_is_disjoint(self):
        value = manifest()
        rag = next(item for item in value["spec"]["nodes"] if item["id"] == "rag.support-knowledge")
        rag["dataAccess"] = ["D1"]
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertIn("ARCH-DATA-CLASS-EXCEEDS-ACTOR", codes)

    def test_actor_without_declared_data_access_is_not_treated_as_holding_nothing(self):
        value = manifest()
        rag = next(item for item in value["spec"]["nodes"] if item["id"] == "rag.support-knowledge")
        rag["dataAccess"] = []
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertNotIn("ARCH-DATA-CLASS-EXCEEDS-ACTOR", codes)

    def test_an_undeclared_grant_says_so_instead_of_skipping_the_rule_silently(self):
        """The skip above is correct and was silent, which is the part that was not.

        ARCH-DATA-CLASS-EXCEEDS-ACTOR is CRITICAL and the compiler refuses CRITICALs, so on a graph
        whose actors omit dataAccess the rule can never fire and the compiler calls the graph clean.
        A control that could not evaluate is not a control that passed.
        """
        value = manifest()
        rag = next(item for item in value["spec"]["nodes"] if item["id"] == "rag.support-knowledge")
        rag["dataAccess"] = []
        finding = next(
            item
            for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
            if item.code == "ARCH-DATA-CLASS-ACTOR-UNDECLARED"
        )
        self.assertEqual(finding.severity, FindingSeverity.WARNING)
        self.assertEqual(finding.edge_id, "edge.research-rag")

    def test_the_undeclared_finding_reports_missing_evidence_and_does_not_block_compile(self):
        # WARNING, not CRITICAL: it says the rule had no subject, not that a policy is wrong.
        # Raising it to CRITICAL would refuse every graph that omits an optional field.
        value = manifest()
        for node in value["spec"]["nodes"]:
            node.pop("dataAccess", None)
        findings = ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        undeclared = [item for item in findings if item.code == "ARCH-DATA-CLASS-ACTOR-UNDECLARED"]
        self.assertTrue(undeclared)
        self.assertEqual({item.severity for item in undeclared}, {FindingSeverity.WARNING})
        ArchitectureCompiler().compile(ArchitectureGraph.from_dict(value))  # must not raise

    def test_an_edge_allowing_nothing_needs_no_grant_to_compare_against(self):
        value = manifest()
        edge = next(item for item in value["spec"]["edges"] if item["id"] == "edge.research-rag")
        edge["policy"]["allowedDataClasses"] = []
        rag = next(item for item in value["spec"]["nodes"] if item["id"] == "rag.support-knowledge")
        rag["dataAccess"] = []
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertNotIn("ARCH-DATA-CLASS-ACTOR-UNDECLARED", codes)

    def test_the_shipped_example_now_evaluates_the_rule_on_its_egress_edges(self):
        """The example's two external sinks declared no grant, so the rule skipped exactly the two
        edges it most exists for -- D7 leaving the system. Both are declared now, and narrowing one
        produces the CRITICAL that was previously unreachable there."""
        example = json.loads(
            (Path(__file__).resolve().parent.parent / "examples" / "secure_multi_agent_architecture.json").read_text()
        )
        self.assertEqual(ArchitectureLinter().lint(ArchitectureGraph.from_dict(example)), ())

        narrowed = copy.deepcopy(example)
        sink = next(item for item in narrowed["spec"]["nodes"] if item["id"] == "external.customer-email")
        sink["dataAccess"] = ["D3"]  # keeps the destination class, drops business data
        finding = next(
            item
            for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(narrowed))
            if item.code == "ARCH-DATA-CLASS-EXCEEDS-ACTOR"
        )
        self.assertEqual(finding.edge_id, "edge.email-customer")
        self.assertIn("D7", finding.message)

    def test_prevent_control_cannot_run_only_after_execution(self):
        value = manifest()
        value["spec"]["edges"][0]["controls"][0]["timing"] = "POST_EXECUTION"
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertIn("ARCH-PREVENT-AFTER-EXECUTION", codes)

    def test_tool_digest_pin_requires_declared_digest(self):
        value = manifest()
        tool = next(item for item in value["spec"]["nodes"] if item["id"] == "tool.send-email")
        tool.pop("definitionDigest")
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertIn("ARCH-TOOL-DIGEST-UNPINNED", codes)

    def test_delegation_depth_cannot_exceed_actor_limit(self):
        value = manifest()
        supervisor = next(item for item in value["spec"]["nodes"] if item["id"] == "agent.support")
        supervisor["maxDelegationDepth"] = 1
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertIn("ARCH-DELEGATION-DEPTH-EXCEEDS-ACTOR", codes)

    def test_dynamic_target_pattern_cannot_be_unbounded(self):
        value = manifest()
        edge = next(item for item in value["spec"]["edges"] if item["relationshipId"] == "REL-06")
        edge["targetSelector"]["idPattern"] = "*"
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertIn("ARCH-DYNAMIC-TARGET-UNBOUNDED", codes)

    def test_dynamic_target_capability_cannot_be_unbounded(self):
        value = manifest()
        edge = next(item for item in value["spec"]["edges"] if item["relationshipId"] == "REL-06")
        edge["targetSelector"]["requiredCapabilities"] = []
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertIn("ARCH-DYNAMIC-CAPABILITY-UNBOUNDED", codes)

    def test_relationship_id_must_match_relationship_type(self):
        value = manifest()
        value["spec"]["edges"][0]["relationship"] = "INVOKES"
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertIn("ARCH-RELATIONSHIP-ID-MISMATCH", codes)


class RuntimeGraphDiffTests(unittest.TestCase):
    def test_dynamic_subagent_instance_matches_declared_contract(self):
        value = manifest()
        value["spec"]["edges"] = [next(item for item in value["spec"]["edges"] if item["relationshipId"] == "REL-06")]
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


class AcceptanceCriterionGrammarTests(unittest.TestCase):
    def test_required_parses_a_dotted_path(self):
        self.assertEqual(
            parse_acceptance_criterion("required:receiptId"),
            AcceptanceCriterion("required", ("receiptId",)),
        )

    def test_nonempty_parses_a_nested_path(self):
        self.assertEqual(
            parse_acceptance_criterion("nonempty:delivery.receiptId"),
            AcceptanceCriterion("nonempty", ("delivery", "receiptId")),
        )

    def test_equals_parses_path_and_value(self):
        self.assertEqual(
            parse_acceptance_criterion("equals:status=DELIVERED"),
            AcceptanceCriterion("equals", ("status",), "DELIVERED"),
        )

    def test_entries_outside_the_grammar_do_not_parse(self):
        for entry in ("Answer is grounded", "required:", "equals:status", "nonempty:a..b", "unknown:status"):
            self.assertIsNone(parse_acceptance_criterion(entry), entry)

    def test_invalid_criterion_is_a_critical_lint_finding_and_blocks_compile(self):
        value = manifest()
        task = value["spec"]["orchestration"]["tasks"][0]
        task["acceptanceCriteria"] = ["Answer is grounded in tenant-scoped support knowledge"]
        findings = ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))
        matches = [item for item in findings if item.code == "ARCH-TASK-ACCEPTANCE-INVALID"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, FindingSeverity.CRITICAL)
        with self.assertRaises(ArchitectureCompileError):
            ArchitectureCompiler().compile(ArchitectureGraph.from_dict(value))


if __name__ == "__main__":
    unittest.main()
