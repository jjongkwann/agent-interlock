"""Local comparisons preserve policy decisions and cannot dispatch external work."""

import copy
import json
import time
import unittest
from dataclasses import replace
from unittest.mock import patch

from agent_interlock.architecture import (
    ArchitectureEdge,
    ArchitectureGraph,
    ArchitectureNode,
    AssuranceLevel,
    ControlTiming,
    EnforcementPoint,
    OrchestrationDefinition,
    OrchestrationPattern,
    OrchestrationTask,
    SecurityControl,
    SecurityObjective,
    TaskTransport,
)
from agent_interlock.candidate_compare import compare_bundles
from agent_interlock.configurable_runtime import RUNTIME_KEY
from agent_interlock.models import ActorSpec, ActorType, LinkPolicy, SideEffect
from agent_interlock.orchestration import CallableTaskAdapter, TaskExecutionHeld, TaskExecutionResult
from agent_interlock.studio_deploy import DeploymentBundle, compile_review_bundle


def graph():
    source = ArchitectureNode(ActorSpec("agent", ActorType.AGENT, "owner", "worker",
                                       data_access=frozenset({"D3"})))
    target = ArchitectureNode(ActorSpec("tool", ActorType.TOOL, "owner", "transform",
        data_access=frozenset({"D3"}), side_effects=frozenset({SideEffect.READ}),
        input_schema={"type": "object"}, output_schema={"type": "object"}),
        annotations={RUNTIME_KEY: {"kind": "JSON_TRANSFORM", "purpose": "TRANSFORM", "dataClasses": ["D3"],
                                  "arguments": {"$path": "input"}, "template": {"$path": "arguments"}}})
    edge = ArchitectureEdge("invoke", "REL-05", source.id, target.id, "INVOKES", LinkPolicy(
        allowed_purposes=frozenset({"TRANSFORM"}), allowed_data_classes=frozenset({"D3"}),
        max_export_bytes=10000, max_export_records=100),
        controls=(SecurityControl("guard", SecurityObjective.PREVENT, ControlTiming.PRE_EXECUTION,
                                  EnforcementPoint.MCP_GATEWAY, AssuranceLevel.ENFORCED),))
    task = OrchestrationTask("transform", "Transform", source.id, target.id, TaskTransport.LOCAL, "TRANSFORM")
    return ArchitectureGraph("comparison", "1", (source, target), (edge,),
                             orchestration=OrchestrationDefinition(coordinator_actor_id=source.id,
                                 pattern=OrchestrationPattern.STATE_GRAPH, tasks=(task,)))


def bundle(value):
    compiled = compile_review_bundle(value)
    assert compiled["deployable"], compiled["findings"]
    return DeploymentBundle.from_compile_output(compiled)


class CandidateComparisonTests(unittest.TestCase):
    def test_large_valid_task_timeout_does_not_overflow_the_platform_wait(self):
        original = graph()
        task = replace(original.orchestration.tasks[0], timeout_seconds=10**100)
        candidate = bundle(replace(original, orchestration=replace(original.orchestration, tasks=(task,))))

        def execute(_value):
            time.sleep(0.02)  # Ensure Future.result must wait, exposing platform timeout overflow.
            return TaskExecutionResult(output={"completed": True})

        with patch("agent_interlock.candidate_compare.configurable_adapter_provider",
                   return_value=lambda _: {TaskTransport.LOCAL: CallableTaskAdapter(execute)}):
            result = compare_bundles(candidate, None, {}, "tenant")
        self.assertEqual(result["candidate"]["state"], "COMPLETED", result)
        self.assertEqual(result["candidate"]["tasks"][task.id]["output"], {"completed": True})

    def test_output_changes_and_inputs_are_not_mutated(self):
        original = graph()
        node = original.nodes[1]
        changed = replace(original, nodes=(original.nodes[0], replace(node, annotations={RUNTIME_KEY: {
            **node.annotations[RUNTIME_KEY], "template": {"message": "changed"}}})))
        candidate, baseline = bundle(changed), bundle(original)
        value = {"message": "Ada\r\n"}
        snapshot = copy.deepcopy((candidate.body, baseline.body, value))
        with patch("agent_interlock.studio_deploy.GitBundleStore", side_effect=AssertionError("host store touched")):
            result = compare_bundles(candidate, baseline, value, "tenant")
        self.assertEqual(result["candidate"]["state"], "COMPLETED", result)
        self.assertEqual(result["baseline"]["tasks"]["transform"]["output"], {"message": "Ada\n"})
        self.assertEqual(result["input"], value)
        self.assertEqual(result["candidate"]["policyOutcome"], "ALLOW")
        self.assertEqual(result["candidate"]["bundleDigest"], candidate.bundle_digest)
        self.assertEqual(result["baseline"]["bundleDigest"], baseline.bundle_digest)
        self.assertEqual([change["change"] for change in result["changes"]], ["CHANGED"])
        self.assertEqual((candidate.body, baseline.body, value), snapshot)
        json.dumps(result, allow_nan=False)

    def test_unchanged_added_removed_and_candidate_only(self):
        original = graph()
        task = original.orchestration.tasks[0]
        renamed = replace(original, orchestration=replace(original.orchestration, tasks=(replace(task, id="new"),)))
        before, after = bundle(original), bundle(renamed)
        self.assertEqual(compare_bundles(before, before, {}, "tenant")["changes"], [])
        result = compare_bundles(after, before, {}, "tenant")
        self.assertEqual([(row["taskId"], row["change"]) for row in result["changes"]],
                         [("new", "ADDED"), ("transform", "REMOVED")])
        self.assertIsNone(compare_bundles(after, None, {}, "tenant")["baseline"])

    def test_task_and_invocation_approval_are_held(self):
        original = graph()
        task = original.orchestration.tasks[0]
        explicit = replace(original, orchestration=replace(original.orchestration,
                                                          tasks=(replace(task, approval_required=True),)))
        side = compare_bundles(bundle(explicit), None, {"name": "Ada"}, "tenant")["candidate"]
        self.assertEqual(side["state"], "WAITING_APPROVAL", side)
        self.assertEqual(side["policyOutcome"], "HOLD")
        self.assertFalse(side["tasks"]["transform"]["executed"])
        self.assertEqual(side["tasks"]["transform"]["output"], {})

        def hold(_value):
            raise TaskExecutionHeld({"arguments": {"name": "Ada"}})

        with patch("agent_interlock.candidate_compare.configurable_adapter_provider",
                   return_value=lambda _compiled: {TaskTransport.LOCAL: CallableTaskAdapter(hold)}):
            side = compare_bundles(bundle(original), None, {"name": "Ada"}, "tenant")["candidate"]
        self.assertEqual(side["policyOutcome"], "HOLD")
        self.assertFalse(side["tasks"]["transform"]["executed"])
        self.assertEqual(side["tasks"]["transform"]["pendingCall"]["arguments"], {"name": "Ada"})

    def test_shadow_bundle_policies_are_enforced(self):
        original = graph()
        blocked = replace(original, edges=(replace(original.edges[0],
                          policy=replace(original.edges[0].policy, max_export_bytes=1)),))
        result = compare_bundles(bundle(blocked), bundle(original), {"name": "Ada"}, "tenant")
        side = result["candidate"]
        self.assertEqual(side["state"], "FAILED", side)
        self.assertEqual(side["policyOutcome"], "BLOCK")
        self.assertEqual(side["tasks"]["transform"]["output"], {})
        self.assertTrue(all(item["mode"] == "ENFORCE" for item in side["policyDecisions"] if "mode" in item))

    def test_external_baseline_and_model_candidate_reject_before_execution(self):
        original = graph()
        node = original.nodes[1]
        http = replace(original, nodes=(original.nodes[0], replace(node, actor=replace(node.actor,
            allowed_domains=frozenset({"service.example"})), annotations={RUNTIME_KEY: {
                "kind": "HTTP_JSON", "purpose": "TRANSFORM", "dataClasses": ["D3"],
                "endpoint": "https://service.example/api", "method": "GET"}})))
        model = replace(original, nodes=(replace(original.nodes[0], annotations={RUNTIME_KEY: {
            "kind": "ANTHROPIC", "model": "fixture", "credentialRef": "fixture", "systemPrompt": "test",
            "providerActorId": "provider", "purpose": "MODEL", "dataClasses": ["D3"],
            "maxTokens": 10, "maxSteps": 1}}), node))
        for candidate, baseline in ((bundle(original), bundle(http)), (bundle(model), None)):
            with self.subTest(candidate=candidate.bundle_digest), patch(
                "agent_interlock.candidate_compare.configurable_adapter_provider"
            ) as provider:
                with self.assertRaisesRegex(ValueError, "LOCAL JSON_TRANSFORM"):
                    compare_bundles(candidate, baseline, {}, "tenant")
                provider.assert_not_called()

    def test_invalid_input_digest_and_readiness(self):
        original = graph()
        valid = bundle(original)
        for value in ([], {"number": float("nan")}, {"value": object()}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                compare_bundles(valid, None, value, "tenant")
        with self.assertRaisesRegex(ValueError, "digest"):
            compare_bundles(replace(valid, bundle_digest="sha256:wrong"), None, {}, "tenant")
        mismatched = replace(original, orchestration=replace(original.orchestration,
            tasks=(replace(original.orchestration.tasks[0], purpose="OTHER"),)))
        side = compare_bundles(bundle(mismatched), None, {}, "tenant")["candidate"]
        self.assertFalse(side["readiness"]["ready"])
        self.assertEqual(side["state"], "NOT_READY")
        self.assertEqual(side["policyOutcome"], "NOT_EVALUATED")


if __name__ == "__main__":
    unittest.main()
