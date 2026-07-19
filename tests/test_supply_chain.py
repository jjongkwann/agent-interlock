from __future__ import annotations

import unittest
from dataclasses import replace

from agent_interlock import (
    ArtifactAdmissionPolicy,
    ArtifactProvenance,
    ControlDecision,
    MCPServerAdmissionError,
    MCPServerProfile,
    MCPToolGateway,
    MCPTransportAdapter,
    sign_artifact_provenance,
)

PUBLISHER_KEY = b"platform-publisher-signing-key-v1"
ARTIFACT_DIGEST = "sha256:" + "a" * 64
REPOSITORY = "https://github.example/platform/trusted-mail"


def provenance(*, publisher: str = "platform-team") -> ArtifactProvenance:
    return ArtifactProvenance(
        server_id="tenant-a/prod/trusted-mail",
        publisher=publisher,
        artifact_digest=ARTIFACT_DIGEST,
        source_repository=REPOSITORY,
        source_revision="commit-8f41d9a",
        build_id="build-2026-07-17-001",
    )


def policy() -> ArtifactAdmissionPolicy:
    return ArtifactAdmissionPolicy(
        {"platform-team": {"publisher-key-v1": PUBLISHER_KEY}},
        allowed_repositories={"platform-team": frozenset({REPOSITORY})},
    )


class ArtifactAdmissionTests(unittest.TestCase):
    def test_signed_trusted_provenance_is_admitted(self):
        item = provenance()
        signature = sign_artifact_provenance(
            item,
            key_id="publisher-key-v1",
            key=PUBLISHER_KEY,
        )
        decision = policy().admit(item, signature)
        self.assertEqual(decision.decision, ControlDecision.ALLOW)
        self.assertTrue(decision.evidence["signatureVerified"])
        self.assertEqual(decision.evidence["artifactDigest"], ARTIFACT_DIGEST)
        self.assertEqual(decision.evidence["provenanceDigest"], item.digest)

    def test_untrusted_or_unsigned_publisher_is_quarantined(self):
        decision = policy().admit(provenance(publisher="attacker-team"), None)
        self.assertEqual(decision.decision, ControlDecision.QUARANTINE)
        self.assertIn("L1-M4-UNTRUSTED-PUBLISHER", decision.reason_codes)
        self.assertFalse(decision.evidence["signatureVerified"])

    def test_tampered_provenance_breaks_the_signature(self):
        original = provenance()
        signature = sign_artifact_provenance(
            original,
            key_id="publisher-key-v1",
            key=PUBLISHER_KEY,
        )
        tampered = replace(original, source_revision="commit-attacker")
        decision = policy().admit(tampered, signature)
        self.assertEqual(decision.decision, ControlDecision.QUARANTINE)
        self.assertIn("L1-M4-SIGNATURE-INVALID", decision.reason_codes)

    def test_repository_allowlist_is_part_of_admission(self):
        item = replace(provenance(), source_repository="https://evil.example/package")
        signature = sign_artifact_provenance(
            item,
            key_id="publisher-key-v1",
            key=PUBLISHER_KEY,
        )
        decision = policy().admit(item, signature)
        self.assertIn("L1-M4-PROVENANCE-DENIED", decision.reason_codes)


class MCPServerAdmissionBindingTests(unittest.TestCase):
    def test_profile_requires_exact_provenance_binding(self):
        item = provenance()
        signature = sign_artifact_provenance(
            item,
            key_id="publisher-key-v1",
            key=PUBLISHER_KEY,
        )
        with self.assertRaises(ValueError):
            MCPServerProfile(
                tenant_id="tenant-a",
                server_id=item.server_id,
                endpoint="https://mcp.example/mcp",
                publisher=item.publisher,
                artifact_digest="sha256:" + "0" * 64,
                artifact_provenance=item,
                artifact_signature=signature,
            )

    def test_adapter_rejects_before_server_call_when_admission_is_missing(self):
        calls: list[object] = []
        profile = MCPServerProfile(
            tenant_id="tenant-a",
            server_id="tenant-a/prod/trusted-mail",
            endpoint="https://mcp.example/mcp",
            publisher="platform-team",
            artifact_digest=ARTIFACT_DIGEST,
        )
        with self.assertRaises(MCPServerAdmissionError) as raised:
            MCPTransportAdapter(
                MCPToolGateway(),
                profile,
                lambda request: calls.append(request),
                artifact_admission_policy=policy(),
            )
        self.assertIn("L1-M4-UNTRUSTED-PUBLISHER", raised.exception.decision.reason_codes)
        self.assertEqual(calls, [])

    def test_adapter_carries_the_admitted_provenance_decision(self):
        item = provenance()
        signature = sign_artifact_provenance(
            item,
            key_id="publisher-key-v1",
            key=PUBLISHER_KEY,
        )
        profile = MCPServerProfile(
            tenant_id="tenant-a",
            server_id=item.server_id,
            endpoint="https://mcp.example/mcp",
            publisher=item.publisher,
            artifact_digest=item.artifact_digest,
            artifact_provenance=item,
            artifact_signature=signature,
        )
        adapter = MCPTransportAdapter(
            MCPToolGateway(),
            profile,
            lambda request: None,
            artifact_admission_policy=policy(),
        )
        self.assertIsNotNone(adapter.artifact_admission_decision)
        self.assertTrue(adapter.artifact_admission_decision.admitted)


if __name__ == "__main__":
    unittest.main()
