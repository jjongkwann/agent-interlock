"""The generated project must import, wire its manifest's tools, and pass its own security tests."""

import contextlib
import importlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

from agent_interlock.__main__ import main
from agent_interlock.architecture import ArchitectureGraph, DynamicTargetSelector
from agent_interlock.models import ActorType
from agent_interlock.scaffold import edge_coverage, generate_security_tests, generate_skeleton, python_identifier

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
MANIFEST = EXAMPLES / "secure_multi_agent_architecture.json"
SUPPORT_AGENT = EXAMPLES / "support_agent" / "architecture.json"


class GeneratedProject:
    """A generated skeleton and test module, written to a temp dir next to their manifest."""

    def __init__(self, skeleton, result, graph, built):
        self.skeleton = skeleton
        self.result = result
        self.graph = graph
        self.gateway, self.tools = built

    @property
    def tool_edges(self):
        targets = {node.id for node in self.graph.nodes if node.actor.type.value == "TOOL"}
        return [
            edge
            for edge in self.graph.edges
            if not edge.dynamic and edge.relationship_id == "REL-05" and edge.target in targets
        ]


class SkeletonGenerationTests(unittest.TestCase):
    def _generate_and_run(self, value: dict) -> GeneratedProject:
        """Write ``value`` as a manifest, generate both modules beside it, import and run them.

        The manifest goes to disk because the generated ``build()`` reads it at call time: a graph
        mutated only in memory would not be the graph the generated project loads.
        """
        graph = ArchitectureGraph.from_dict(value)
        base = python_identifier(graph.id)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            manifest = out / "architecture.json"
            manifest.write_text(json.dumps(value), encoding="utf-8")
            (out / f"{base}_skeleton.py").write_text(generate_skeleton(graph, manifest), encoding="utf-8")
            (out / f"test_{base}_security.py").write_text(
                generate_security_tests(graph, f"{base}_skeleton"), encoding="utf-8"
            )
            sys.path.insert(0, tmp)
            try:
                skeleton = importlib.import_module(f"{base}_skeleton")
                generated = importlib.import_module(f"test_{base}_security")
                result = unittest.TestResult()
                unittest.defaultTestLoader.loadTestsFromModule(generated).run(result)
                # build() reads the manifest, so it has to run before the temp dir is removed.
                return GeneratedProject(skeleton, result, graph, skeleton.build())
            finally:
                sys.path.remove(tmp)
                for name in (f"{base}_skeleton", f"test_{base}_security"):
                    sys.modules.pop(name, None)

    def _assert_passed(self, project: GeneratedProject) -> None:
        self.assertTrue(
            project.result.wasSuccessful(),
            [str(item) for item in project.result.failures + project.result.errors],
        )
        self.assertEqual(project.result.testsRun, 2 * len(project.tool_edges))

    def test_generated_modules_wire_the_manifest_and_pass_their_own_tests(self):
        project = self._generate_and_run(json.loads(MANIFEST.read_text(encoding="utf-8")))
        gateway = project.gateway

        self.assertEqual(len(project.tools), len(project.tool_edges))
        for edge in project.tool_edges:
            self.assertIsNotNone(gateway.actor(edge.target), edge.target)
            self.assertIsNotNone(gateway.link_policy(edge.source, edge.target), edge.id)
        self.assertEqual([binding.actor_id for binding in project.skeleton.BINDINGS], ["tool.send-email"])
        self._assert_passed(project)

    def test_the_generated_contract_matches_the_hand_written_example_project(self):
        """``examples/support_agent`` is the reference the generator has to reproduce: same source
        Actor, same bindings, same purposes. Only the handlers and descriptions are the author's."""
        sys.path.insert(0, str(EXAMPLES.parent))
        try:
            from examples.support_agent import build as example
        finally:
            sys.path.remove(str(EXAMPLES.parent))
        project = self._generate_and_run(json.loads(SUPPORT_AGENT.read_text(encoding="utf-8")))

        self.assertEqual(project.skeleton.SOURCE_ACTOR_ID, example.SOURCE_ACTOR_ID)
        def contract(bindings):
            return [(item.definition.tool_name, item.actor_id, item.purpose) for item in bindings]

        self.assertEqual(contract(project.skeleton.BINDINGS), contract(example.BINDINGS))
        self._assert_passed(project)

    def test_a_policy_that_denies_no_data_class_still_gets_one_the_edge_refuses(self):
        """The denied-flow test picks an explicitly denied class when there is one. A policy that
        denies nothing still has an allow-list, and the generated class has to sit outside it."""
        value = json.loads(SUPPORT_AGENT.read_text(encoding="utf-8"))
        for edge in value["spec"]["edges"]:
            edge["policy"].pop("deniedDataClasses", None)
        self._assert_passed(self._generate_and_run(value))

    def test_coverage_distinguishes_first_source_dynamic_and_manual_edges(self):
        from dataclasses import replace

        graph = ArchitectureGraph.from_dict(json.loads(SUPPORT_AGENT.read_text(encoding="utf-8")))
        first = replace(next(edge for edge in graph.edges if edge.relationship_id == "REL-05"), controls=())
        graph = replace(graph, edges=(
            first,
            replace(first, id="other-source", source="user.customer"),
            replace(first, id="dynamic", dynamic=True,
                    target_selector=DynamicTargetSelector(frozenset({ActorType.TOOL}))),
            replace(first, id="duplicate-target"),
        ))
        coverage = edge_coverage(graph)
        self.assertEqual([item["bindingStatus"] for item in coverage], ["WIRED", "MANUAL", "MANUAL", "MANUAL"])
        self.assertEqual(coverage[0]["profile"], "MCP_GATEWAY")
        self.assertIn("Different invocation source", coverage[1]["reason"])
        self.assertIn("Dynamic selector", coverage[2]["reason"])
        self.assertIn("already has", coverage[3]["reason"])

    def test_cli_input_errors_are_structured_without_tracebacks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            for contents in (None, "{", "[]", '{"apiVersion":"invalid"}'):
                if contents is not None:
                    path.write_text(contents)
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(main(["architecture", "lint", str(path)]), 2)
                error = json.loads(stderr.getvalue())["error"]
                self.assertEqual(error["code"], "INTERLOCK-CLI-INPUT-INVALID")
                self.assertTrue(error["remediation"])

    def test_cli_skeleton_writes_both_files(self):
        base = python_identifier(json.loads(MANIFEST.read_text(encoding="utf-8"))["metadata"]["id"])
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = main(["architecture", "skeleton", str(MANIFEST), "--out-dir", tmp])
            self.assertEqual(code, 0)
            coverage = json.loads((Path(tmp) / f"{base}_edge_coverage.json").read_text())
            self.assertEqual(json.loads(stdout.getvalue())["edgeCoverage"], coverage)
            self.assertEqual(len(coverage), len(json.loads(MANIFEST.read_text())["spec"]["edges"]))
            names = sorted(item.name for item in Path(tmp).iterdir())
            self.assertEqual(names, sorted([
                f"{base}_skeleton.py", f"test_{base}_security.py", f"{base}_edge_coverage.json",
            ]))
            written = (Path(tmp) / f"{base}_skeleton.py").read_text(encoding="utf-8")
            self.assertIn(f"MANIFEST = Path({str(MANIFEST)!r})", written)


if __name__ == "__main__":
    unittest.main()
