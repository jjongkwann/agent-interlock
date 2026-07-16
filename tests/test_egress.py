from __future__ import annotations

import json
import unittest
from pathlib import Path

from agent_interlock import (
    ArchitectureCompiler,
    ArchitectureGraph,
    ControlDecision,
    DestinationEgressGuard,
    DestinationEgressPolicy,
    EgressRequest,
    InMemoryNetworkEgressBackend,
    canonical_network_destination,
    compile_destination_egress_policy,
)


ARTIFACT = "sha256:" + "a" * 64
PROVENANCE = "sha256:" + "b" * 64
SANDBOX = "sha256:" + "c" * 64
ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "secure_multi_agent_architecture.json"


def policy() -> DestinationEgressPolicy:
    return DestinationEgressPolicy(
        policy_id="trusted-mail-egress-v1",
        tenant_id="tenant-a",
        allowed_workload_ids=frozenset({"stdio-mail-tool-1"}),
        allowed_destinations=frozenset({"https://mail-api.example"}),
        allowed_artifact_digests=frozenset({ARTIFACT}),
        allowed_provenance_digests=frozenset({PROVENANCE}),
        allowed_sandbox_profile_digests=frozenset({SANDBOX}),
    )


def request(destination: str, **overrides) -> EgressRequest:
    values = {
        "tenant_id": "tenant-a",
        "workload_id": "stdio-mail-tool-1",
        "destination": destination,
        "artifact_digest": ARTIFACT,
        "provenance_digest": PROVENANCE,
        "sandbox_profile_digest": SANDBOX,
    }
    values.update(overrides)
    return EgressRequest(**values)


class DestinationCanonicalizationTests(unittest.TestCase):
    def test_https_origin_is_idna_normalized_with_explicit_port(self):
        self.assertEqual(
            canonical_network_destination("https://MAIL-API.EXAMPLE./"),
            "https://mail-api.example:443",
        )

    def test_credentials_paths_and_private_ips_are_rejected(self):
        for value in (
            "https://user:password@mail-api.example",
            "https://mail-api.example/path",
            "https://127.0.0.1",
            "http://mail-api.example",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_network_destination(value)


class DestinationEgressGuardTests(unittest.TestCase):
    def setUp(self):
        self.backend = InMemoryNetworkEgressBackend()
        self.terminated: list[str] = []

        def terminate(workload_id: str) -> bool:
            self.terminated.append(workload_id)
            return True

        self.guard = DestinationEgressGuard(
            policy(),
            self.backend,
            terminate_workload=terminate,
        )

    def test_non_allowlisted_destination_blocks_before_backend_and_terminates(self):
        receipt = self.guard.execute(request("https://exfil.attacker.example"))
        self.assertEqual(receipt.decision, ControlDecision.BLOCK)
        self.assertIn("L1-M4-EGRESS-DENIED", receipt.reason_codes)
        self.assertEqual(receipt.socket_count, 0)
        self.assertTrue(receipt.process_terminated)
        self.assertEqual(self.backend.connections, ())
        self.assertEqual(self.terminated, ["stdio-mail-tool-1"])

    def test_allowed_destination_produces_one_bound_receipt(self):
        receipt = self.guard.execute(request("https://mail-api.example:443"))
        self.assertEqual(receipt.decision, ControlDecision.ALLOW)
        self.assertEqual(receipt.canonical_destination, "https://mail-api.example:443")
        self.assertEqual(receipt.socket_count, 1)
        self.assertFalse(receipt.process_terminated)
        self.assertEqual(receipt.provenance_digest, PROVENANCE)
        self.assertEqual(receipt.policy_digest, policy().digest)
        self.assertEqual(len(self.backend.connections), 1)
        self.assertEqual(self.terminated, [])

    def test_artifact_provenance_and_sandbox_are_exactly_bound(self):
        for field, value in (
            ("tenant_id", "tenant-b"),
            ("workload_id", "other-workload"),
            ("artifact_digest", "sha256:" + "d" * 64),
            ("provenance_digest", "sha256:" + "e" * 64),
            ("sandbox_profile_digest", "sha256:" + "f" * 64),
        ):
            with self.subTest(field=field):
                receipt = self.guard.execute(
                    request("https://mail-api.example", **{field: value})
                )
                self.assertEqual(receipt.decision, ControlDecision.BLOCK)
                self.assertIn("L1-M4-EGRESS-BINDING-MISMATCH", receipt.reason_codes)
        self.assertEqual(self.backend.connections, ())

    def test_termination_failure_is_explicit_evidence(self):
        guard = DestinationEgressGuard(
            policy(),
            self.backend,
            terminate_workload=lambda workload_id: False,
        )
        receipt = guard.execute(request("https://exfil.attacker.example"))
        self.assertFalse(receipt.process_terminated)
        self.assertIn("L1-M4-PROCESS-TERMINATION-FAILED", receipt.reason_codes)


class ArchitectureEgressCompilationTests(unittest.TestCase):
    def test_rel07_box_domains_compile_into_runtime_allowlist(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        compiled = ArchitectureCompiler().compile(ArchitectureGraph.from_dict(manifest))
        compiled_policy = compile_destination_egress_policy(
            compiled,
            "edge.email-customer",
            tenant_id="tenant-a",
            artifact_digest=ARTIFACT,
            provenance_digest=PROVENANCE,
            sandbox_profile_digest=SANDBOX,
        )
        self.assertEqual(compiled_policy.allowed_workload_ids, frozenset({"tool.send-email"}))
        self.assertEqual(
            compiled_policy.allowed_destinations,
            frozenset({"https://customer.example:443"}),
        )
        self.assertEqual(compiled_policy.policy_id, "customer-email-egress")

    def test_non_egress_edge_cannot_compile_as_network_policy(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        compiled = ArchitectureCompiler().compile(ArchitectureGraph.from_dict(manifest))
        with self.assertRaises(ValueError):
            compile_destination_egress_policy(
                compiled,
                "edge.support-email-tool",
                tenant_id="tenant-a",
                artifact_digest=ARTIFACT,
                provenance_digest=PROVENANCE,
                sandbox_profile_digest=SANDBOX,
            )

    def test_shadow_edge_cannot_silently_become_an_enforced_guard(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        edge = next(item for item in manifest["spec"]["edges"] if item["id"] == "edge.email-customer")
        edge["policy"]["mode"] = "SHADOW"
        compiled = ArchitectureCompiler().compile(ArchitectureGraph.from_dict(manifest))
        with self.assertRaises(ValueError):
            compile_destination_egress_policy(
                compiled,
                "edge.email-customer",
                tenant_id="tenant-a",
                artifact_digest=ARTIFACT,
                provenance_digest=PROVENANCE,
                sandbox_profile_digest=SANDBOX,
            )


if __name__ == "__main__":
    unittest.main()
