from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agent_interlock import ArchitectureCompiler, ArchitectureGraph
from agent_interlock.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "secure_multi_agent_architecture.json"
SCHEMA = ROOT / "schemas" / "architecture.schema.json"

CRITICAL_MANIFEST = {
    "apiVersion": "interlock.dev/v1alpha1",
    "kind": "Architecture",
    "metadata": {"id": "broken", "version": "1"},
    "spec": {
        "nodes": [
            {"id": "agent.a", "type": "AGENT", "owner": "o", "identity": "spiffe://a"},
            {"id": "tool.b", "type": "TOOL", "owner": "o", "identity": "spiffe://b"},
        ],
        # Edge has no security control -> ARCH-CONTROL-MISSING (CRITICAL).
        "edges": [
            {
                "id": "e1",
                "relationshipId": "REL-05",
                "source": "agent.a",
                "target": "tool.b",
                "relationship": "INVOKES",
                "policy": {"mode": "SHADOW"},
            }
        ],
    },
}


def run_cli(args):
    out = io.StringIO()
    with redirect_stdout(out):
        code = main(args)
    return code, out.getvalue()


class StudioRoundTripTests(unittest.TestCase):
    def test_example_manifest_compiles_and_builds_runtime(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        graph = ArchitectureGraph.from_dict(manifest)
        compiled = ArchitectureCompiler().compile(graph)  # reject_critical=True: must not raise
        runtime = compiled.build_interlock()
        self.assertEqual(len(runtime.design_graph()["edges"]), len(graph.edges))

    def test_manifest_has_all_schema_required_top_level_keys(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        for key in schema.get("required", []):
            self.assertIn(key, manifest, f"studio-format manifest is missing schema-required key {key}")
        # And the compiler's parser accepts the studio export shape.
        ArchitectureGraph.from_dict(manifest)


class CompileShadowTests(unittest.TestCase):
    def test_shadow_forces_every_edge_and_emits_a_digest(self):
        code, output = run_cli(["architecture", "compile", "--shadow", str(MANIFEST)])
        self.assertEqual(code, 0)
        bundle = json.loads(output)
        self.assertTrue(bundle["deployable"])
        self.assertEqual(bundle["mode"], "SHADOW")
        self.assertTrue(bundle["bundleDigest"].startswith("sha256:"))
        self.assertTrue(bundle["links"])
        self.assertTrue(all(link["mode"] == "SHADOW" for link in bundle["links"]))

    def test_shadow_bundle_digest_is_stable(self):
        first = json.loads(run_cli(["architecture", "compile", "--shadow", str(MANIFEST)])[1])
        second = json.loads(run_cli(["architecture", "compile", "--shadow", str(MANIFEST)])[1])
        self.assertEqual(first["bundleDigest"], second["bundleDigest"])

    def test_critical_findings_block_deploy_at_the_review_gate(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
            json.dump(CRITICAL_MANIFEST, handle)
            path = handle.name
        try:
            code, output = run_cli(["architecture", "compile", "--shadow", path])
        finally:
            Path(path).unlink()
        self.assertEqual(code, 2)
        result = json.loads(output)
        self.assertFalse(result["deployable"])
        self.assertNotIn("links", result)
        codes = [finding["code"] for finding in result["findings"]]
        self.assertIn("ARCH-CONTROL-MISSING", codes)


if __name__ == "__main__":
    unittest.main()
