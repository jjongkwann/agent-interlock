"""The generated skeleton must import, wire the manifest, and pass its own security tests."""

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from agent_interlock.__main__ import main
from agent_interlock.architecture import ArchitectureGraph, ArchitectureLinter
from agent_interlock.scaffold import generate_security_tests, generate_skeleton, python_identifier

MANIFEST = Path(__file__).resolve().parent.parent / "examples" / "secure_multi_agent_architecture.json"


class SkeletonGenerationTests(unittest.TestCase):
    def setUp(self):
        self.graph = ArchitectureGraph.from_dict(json.loads(MANIFEST.read_text(encoding="utf-8")))
        self.base = python_identifier(self.graph.id)

    def _run_generated_security_tests(self, graph) -> unittest.TestResult:
        base = python_identifier(graph.id)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / f"{base}_skeleton.py").write_text(generate_skeleton(graph), encoding="utf-8")
            (out / f"test_{base}_security.py").write_text(
                generate_security_tests(graph, f"{base}_skeleton"), encoding="utf-8"
            )
            sys.path.insert(0, tmp)
            try:
                generated = importlib.import_module(f"test_{base}_security")
                suite = unittest.defaultTestLoader.loadTestsFromModule(generated)
                result = unittest.TestResult()
                suite.run(result)
                return result
            finally:
                sys.path.remove(tmp)
                for name in (f"{base}_skeleton", f"test_{base}_security"):
                    sys.modules.pop(name, None)

    def test_generated_modules_wire_the_manifest_and_pass_their_own_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / f"{self.base}_skeleton.py").write_text(generate_skeleton(self.graph), encoding="utf-8")
            (out / f"test_{self.base}_security.py").write_text(
                generate_security_tests(self.graph, f"{self.base}_skeleton"), encoding="utf-8"
            )
            sys.path.insert(0, tmp)
            try:
                skeleton = importlib.import_module(f"{self.base}_skeleton")
                interlock, actors = skeleton.build()
                self.assertEqual(set(actors), {node.id for node in self.graph.nodes})
                static_edges = [edge for edge in self.graph.edges if not edge.dynamic]
                self.assertEqual(len(interlock.design_graph()["edges"]), len(static_edges))
                self.assertTrue(all(callable(handler) for handler in skeleton.HANDLERS.values()))

                generated_tests = importlib.import_module(f"test_{self.base}_security")
                suite = unittest.defaultTestLoader.loadTestsFromModule(generated_tests)
                result = unittest.TestResult()
                suite.run(result)
                self.assertTrue(
                    result.wasSuccessful(),
                    [str(item) for item in result.failures + result.errors],
                )
                self.assertGreaterEqual(result.testsRun, 2 * len(static_edges))
            finally:
                sys.path.remove(tmp)
                for name in (f"{self.base}_skeleton", f"test_{self.base}_security"):
                    sys.modules.pop(name, None)

    def test_declared_flow_holds_when_the_actor_grant_is_wider_than_the_edge_policy(self):
        """ARCH-DATA-CLASS-EXCEEDS-ACTOR only pins allowed ⊆ grant, so the grant may still hold
        a class the edge policy denies. The generated allowed-flow test must not pick that class."""
        value = json.loads(MANIFEST.read_text(encoding="utf-8"))
        support = next(item for item in value["spec"]["nodes"] if item["id"] == "agent.support")
        support["dataAccess"] = ["D1", *support["dataAccess"]]
        graph = ArchitectureGraph.from_dict(value)
        self.assertEqual(ArchitectureLinter().lint(graph), ())
        result = self._run_generated_security_tests(graph)
        self.assertTrue(result.wasSuccessful(), [str(item) for item in result.failures + result.errors])

    def test_cli_skeleton_writes_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = main(["architecture", "skeleton", str(MANIFEST), "--out-dir", tmp])
            self.assertEqual(code, 0)
            names = sorted(item.name for item in Path(tmp).iterdir())
            self.assertEqual(names, sorted([f"{self.base}_skeleton.py", f"test_{self.base}_security.py"]))


if __name__ == "__main__":
    unittest.main()
