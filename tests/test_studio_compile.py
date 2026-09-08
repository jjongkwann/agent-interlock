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

    def test_executable_manifest_round_trip_is_lossless(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        graph = ArchitectureGraph.from_dict(manifest)
        restored = ArchitectureGraph.from_dict(graph.to_manifest())
        self.assertEqual(restored, graph)

    def test_trust_zone_round_trips_through_the_architecture_parser(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest["spec"]["trustZones"].append(
            {
                "id": "zone.external",
                "label": "External callers",
                "kind": "EXTERNAL",
                "description": "Untrusted ingress",
                "bounds": {"x": 20, "y": 54, "width": 205, "height": 570},
            }
        )
        manifest["spec"]["nodes"][0]["trustZone"] = "EXTERNAL"
        manifest["spec"]["nodes"][0]["trustZoneId"] = "zone.external"
        graph = ArchitectureGraph.from_dict(manifest)
        design = graph.to_design_graph()
        zone = next(item for item in design["trustZones"] if item["id"] == "zone.external")
        self.assertEqual(zone["bounds"]["width"], 205.0)
        self.assertEqual(design["nodes"][0]["trustZone"], "EXTERNAL")
        self.assertEqual(design["nodes"][0]["trustZoneId"], "zone.external")

    def test_actor_cannot_reference_an_unknown_or_mismatched_trust_zone(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest["spec"]["trustZones"].append(
            {
                "id": "zone.internal",
                "label": "Internal",
                "kind": "INTERNAL",
                "bounds": {"x": 0, "y": 0, "width": 400, "height": 300},
            }
        )
        manifest["spec"]["nodes"][0].update({"trustZone": "EXTERNAL", "trustZoneId": "zone.internal"})
        with self.assertRaisesRegex(ValueError, "kind does not match"):
            ArchitectureGraph.from_dict(manifest)

        manifest["spec"]["nodes"][0].update({"trustZone": "INTERNAL", "trustZoneId": "zone.missing"})
        with self.assertRaisesRegex(ValueError, "unknown trust zone"):
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
        self.assertEqual(bundle["architecture"]["kind"], "Architecture")
        # The example manifest authors every edge as ENFORCE; --shadow must rewrite the
        # architecture body itself (not just the derived links) so both stay consistent (D5).
        source_manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertTrue(all(edge["policy"]["mode"] == "ENFORCE" for edge in source_manifest["spec"]["edges"]))
        self.assertTrue(
            all(edge["policy"]["mode"] == "SHADOW" for edge in bundle["architecture"]["spec"]["edges"])
        )
        self.assertEqual(
            len(bundle["architecture"]["spec"]["trustBoundaries"]),
            len(ArchitectureGraph.from_dict(json.loads(MANIFEST.read_text(encoding="utf-8"))).boundaries),
        )
        self.assertTrue(bundle["architecture"]["spec"]["orchestration"]["tasks"])

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
