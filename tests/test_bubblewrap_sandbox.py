"""Unit coverage for BubblewrapSandboxBackend argv + honest attestation.

Actual bwrap confinement is environment-specific (needs a Linux host with user
namespaces and the target's full runtime closure declared in the profile), so it
is a documented Linux-CI follow-up. These tests verify the parts that hold on
any platform: argv construction, the honesty of each attestation bit, fail-
closed refusals, and signature binding. The launcher is a real pinned file
stand-in — prepare() only re-verifies its digest, it never executes it.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from agent_interlock import (
    AttestationVerifier,
    BubblewrapSandboxBackend,
    MCPStdioClient,
    MCPStdioClientConfig,
    MCPStdioError,
    MCPStdioSandboxUnavailable,
    StdioArtifactPin,
    StdioSandboxProfile,
    sha256_file,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "mcp_stdio_fixture_server.py"
RESOLVED_EXE = str(Path(sys.executable).resolve())

KEY = b"bubblewrap-backend-signing-key-00"
OTHER_KEY = b"another-bubblewrap-key-1111111111"
BACKEND_ID = "linux-bubblewrap-v1"


def launcher() -> StdioArtifactPin:
    return StdioArtifactPin(sys.executable, sha256_file(sys.executable))


def profile(
    *,
    allow_network=False,
    allow_child_processes=True,
    writable_paths=(),
    read_only_paths=(str(FIXTURE),),
):
    return StdioSandboxProfile(
        profile_id="bwrap-fixture",
        executable=StdioArtifactPin(sys.executable, sha256_file(sys.executable)),
        arguments=(str(FIXTURE), "normal", "-", "-"),
        additional_artifacts=(StdioArtifactPin(str(FIXTURE), sha256_file(str(FIXTURE))),),
        working_directory=str(ROOT),
        read_only_paths=read_only_paths,
        writable_paths=writable_paths,
        allow_network=allow_network,
        allow_child_processes=allow_child_processes,
    )


def backend(*, signing_key=KEY):
    return BubblewrapSandboxBackend(launcher=launcher(), signing_key=signing_key)


class BubblewrapArgvTests(unittest.TestCase):
    def test_argv_confines_and_ends_with_the_command(self):
        plan = backend().prepare(profile())
        argv = plan.argv
        self.assertEqual(argv[0], RESOLVED_EXE)
        for flag in (
            "--unshare-all",
            "--unshare-user",
            "--disable-userns",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--remount-ro",
        ):
            self.assertIn(flag, argv)
        self.assertNotIn("--share-net", argv)  # network denied by default
        # Pinned executable and fixture are read-only bound.
        self.assertIn("--ro-bind", argv)
        # Command is passed after the argument separator, unchanged.
        separator = argv.index("--")
        self.assertEqual(argv[separator + 1 :], (RESOLVED_EXE, str(FIXTURE), "normal", "-", "-"))

    def test_environment_is_reconstructed_and_equals_the_profile(self):
        secure_profile = profile()
        plan = backend().prepare(secure_profile)
        self.assertEqual(dict(plan.environment), dict(secure_profile.environment))
        # With an empty declared environment there are no --setenv pairs.
        self.assertNotIn("--setenv", plan.argv)

    def test_allow_network_shares_net_and_flips_the_bit(self):
        plan = backend().prepare(profile(allow_network=True))
        self.assertIn("--share-net", plan.argv)
        self.assertFalse(plan.attestation.network_restricted)


class BubblewrapAttestationHonestyTests(unittest.TestCase):
    def test_bits_are_exactly_true_true_false_when_network_denied(self):
        attestation = backend().prepare(profile()).attestation
        self.assertTrue(attestation.filesystem_restricted)
        self.assertTrue(attestation.network_restricted)
        self.assertFalse(attestation.child_process_restricted)  # bwrap cannot honestly claim this
        self.assertEqual(attestation.backend_id, BACKEND_ID)
        self.assertTrue(attestation.evidence_reference.startswith("bubblewrap-policy:v1;launcher=sha256:"))

    def test_signature_verifies_with_the_backend_key(self):
        attestation = backend().prepare(profile()).attestation
        self.assertTrue(AttestationVerifier({BACKEND_ID: KEY}).verify(attestation))
        self.assertFalse(AttestationVerifier({BACKEND_ID: OTHER_KEY}).verify(attestation))

    def test_child_denying_profile_is_refused_before_signing(self):
        with self.assertRaises(MCPStdioSandboxUnavailable):
            backend().prepare(profile(allow_child_processes=False))

    def test_overbroad_mount_is_refused(self):
        with self.assertRaises(MCPStdioError) as raised:
            backend().prepare(profile(read_only_paths=(), writable_paths=("/",)))
        self.assertEqual(raised.exception.reason_code, "MCP-STDIO-SANDBOX-UNSAFE-MOUNT")

    def test_empty_signing_key_is_refused(self):
        with self.assertRaises(ValueError):
            BubblewrapSandboxBackend(launcher=launcher(), signing_key=b"")


class BubblewrapClientBindingTests(unittest.TestCase):
    def test_signed_plan_passes_validation_before_spawn(self):
        secure_profile = profile()
        sandbox = backend()
        client = MCPStdioClient(
            MCPStdioClientConfig(secure_profile),
            sandbox_backend=sandbox,
            attestation_verifier=AttestationVerifier({BACKEND_ID: KEY}),
        )
        client._validate_launch_plan(sandbox.prepare(secure_profile))  # must not raise
        self.assertFalse(client.running)

    def test_wrong_verifier_key_is_rejected_before_spawn(self):
        secure_profile = profile()
        sandbox = backend()
        client = MCPStdioClient(
            MCPStdioClientConfig(secure_profile),
            sandbox_backend=sandbox,
            attestation_verifier=AttestationVerifier({BACKEND_ID: OTHER_KEY}),
        )
        with self.assertRaises(MCPStdioError) as raised:
            client._validate_launch_plan(sandbox.prepare(secure_profile))
        self.assertEqual(raised.exception.reason_code, "MCP-STDIO-SANDBOX-ATTESTATION-UNSIGNED")


if __name__ == "__main__":
    unittest.main()
