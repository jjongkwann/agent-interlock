from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

from agent_interlock import (
    AttestationVerifier,
    AttestedExternalSandboxBackend,
    MCPStdioClient,
    MCPStdioClientConfig,
    MCPStdioError,
    SandboxAttestation,
    StdioArtifactPin,
    StdioSandboxProfile,
    sha256_file,
    sign_attestation,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "mcp_stdio_fixture_server.py"

KEY = b"sandbox-backend-signing-key-0000"
OTHER_KEY = b"a-different-sandbox-key-11111111"
BACKEND_ID = "operator-sandbox"


def enforcing_profile() -> StdioSandboxProfile:
    return StdioSandboxProfile(
        profile_id="attested-fixture",
        executable=StdioArtifactPin(sys.executable, sha256_file(sys.executable)),
        arguments=(str(FIXTURE), "normal", "-", "-"),
        additional_artifacts=(StdioArtifactPin(str(FIXTURE), sha256_file(str(FIXTURE))),),
        working_directory=str(ROOT),
        read_only_paths=(str(FIXTURE),),
        allow_unenforced_test_mode=False,
    )


def signed_backend(profile: StdioSandboxProfile, *, key: bytes | None = KEY) -> AttestedExternalSandboxBackend:
    return AttestedExternalSandboxBackend(
        launcher=StdioArtifactPin(sys.executable, sha256_file(sys.executable)),
        approved_profile_digest=profile.profile_digest,
        fixed_arguments=("--strict",),
        backend_id=BACKEND_ID,
        evidence_reference="ref://attested/1",
        filesystem_restricted=True,
        network_restricted=True,
        child_process_restricted=True,
        signing_key=key,
    )


def _attestation(**overrides) -> SandboxAttestation:
    base = dict(
        backend_id=BACKEND_ID,
        evidence_reference="ref://1",
        profile_digest="sha256:" + "a" * 64,
        artifact_set_digest="sha256:" + "b" * 64,
        filesystem_restricted=True,
        network_restricted=True,
        child_process_restricted=True,
    )
    base.update(overrides)
    return SandboxAttestation(**base)


class AttestationSignatureTests(unittest.TestCase):
    def test_sign_and_verify_round_trip(self):
        signed = sign_attestation(_attestation(), KEY)
        self.assertTrue(signed.signature)
        self.assertTrue(AttestationVerifier({BACKEND_ID: KEY}).verify(signed))

    def test_unsigned_attestation_is_not_trusted(self):
        self.assertFalse(AttestationVerifier({BACKEND_ID: KEY}).verify(_attestation()))

    def test_wrong_key_is_not_trusted(self):
        signed = sign_attestation(_attestation(), KEY)
        self.assertFalse(AttestationVerifier({BACKEND_ID: OTHER_KEY}).verify(signed))

    def test_tampered_restriction_bit_breaks_signature(self):
        signed = sign_attestation(_attestation(), KEY)
        forged = replace(signed, network_restricted=False)
        self.assertFalse(AttestationVerifier({BACKEND_ID: KEY}).verify(forged))

    def test_unknown_backend_id_is_not_trusted(self):
        signed = sign_attestation(_attestation(backend_id="rogue"), KEY)
        self.assertFalse(AttestationVerifier({BACKEND_ID: KEY}).verify(signed))

    def test_verifier_requires_a_key(self):
        with self.assertRaises(ValueError):
            AttestationVerifier({})


class AttestedBackendSigningTests(unittest.TestCase):
    def test_backend_signs_a_verifiable_attestation(self):
        profile = enforcing_profile()
        plan = signed_backend(profile).prepare(profile)
        self.assertTrue(AttestationVerifier({BACKEND_ID: KEY}).verify(plan.attestation))
        self.assertFalse(AttestationVerifier({BACKEND_ID: OTHER_KEY}).verify(plan.attestation))

    def test_backend_without_key_is_unsigned(self):
        profile = enforcing_profile()
        plan = signed_backend(profile, key=None).prepare(profile)
        self.assertEqual(plan.attestation.signature, "")


class ClientAttestationEnforcementTests(unittest.TestCase):
    def test_verifier_accepts_signed_plan_before_spawn(self):
        profile = enforcing_profile()
        backend = signed_backend(profile)
        client = MCPStdioClient(
            MCPStdioClientConfig(profile),
            sandbox_backend=backend,
            attestation_verifier=AttestationVerifier({BACKEND_ID: KEY}),
        )
        # Should not raise; process is never spawned by _validate_launch_plan.
        client._validate_launch_plan(backend.prepare(profile))
        self.assertFalse(client.running)

    def test_verifier_rejects_wrong_key_before_spawn(self):
        profile = enforcing_profile()
        backend = signed_backend(profile)
        client = MCPStdioClient(
            MCPStdioClientConfig(profile),
            sandbox_backend=backend,
            attestation_verifier=AttestationVerifier({BACKEND_ID: OTHER_KEY}),
        )
        with self.assertRaises(MCPStdioError) as raised:
            client._validate_launch_plan(backend.prepare(profile))
        self.assertEqual(raised.exception.reason_code, "MCP-STDIO-SANDBOX-ATTESTATION-UNSIGNED")

    def test_verifier_rejects_unsigned_backend_before_spawn(self):
        profile = enforcing_profile()
        backend = signed_backend(profile, key=None)
        client = MCPStdioClient(
            MCPStdioClientConfig(profile),
            sandbox_backend=backend,
            attestation_verifier=AttestationVerifier({BACKEND_ID: KEY}),
        )
        with self.assertRaises(MCPStdioError) as raised:
            client._validate_launch_plan(backend.prepare(profile))
        self.assertEqual(raised.exception.reason_code, "MCP-STDIO-SANDBOX-ATTESTATION-UNSIGNED")

    def test_without_verifier_unsigned_plan_still_validates(self):
        # Backward compatible: no verifier configured -> no signature requirement.
        profile = enforcing_profile()
        backend = signed_backend(profile, key=None)
        client = MCPStdioClient(MCPStdioClientConfig(profile), sandbox_backend=backend)
        client._validate_launch_plan(backend.prepare(profile))


if __name__ == "__main__":
    unittest.main()
