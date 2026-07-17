"""SeatbeltSandboxBackend: policy/attestation units + macOS live enforcement.

Policy construction, honest attestation bits, refusals and signature binding
are verified on any platform (the pinned launcher stand-in is only digest-
checked, never executed). The live class actually launches python under the
generated sandbox-exec argv and is gated on darwin + /usr/bin/sandbox-exec +
an interpreter whose runtime closure resolves under the declared paths.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

from agent_interlock import (
    AttestationVerifier,
    MCPStdioClient,
    MCPStdioClientConfig,
    MCPStdioError,
    SeatbeltSandboxBackend,
    StdioArtifactPin,
    StdioSandboxProfile,
    sha256_file,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "mcp_stdio_fixture_server.py"
RESOLVED_EXE = str(Path(sys.executable).resolve())

KEY = b"seatbelt-backend-signing-key-0000"
OTHER_KEY = b"another-seatbelt-key-111111111111"
BACKEND_ID = "darwin-seatbelt-v1"
SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")


def launcher() -> StdioArtifactPin:
    # Unit tests never execute the launcher; any pinned regular file works,
    # so the tests run on non-macOS hosts too.
    path = str(SANDBOX_EXEC) if SANDBOX_EXEC.exists() else RESOLVED_EXE
    return StdioArtifactPin(path, sha256_file(path))


def profile(
    *,
    allow_network=False,
    allow_child_processes=False,
    writable_paths=(),
    read_only_paths=(str(FIXTURE),),
    arguments=(str(FIXTURE), "normal", "-", "-"),
):
    return StdioSandboxProfile(
        profile_id="seatbelt-fixture",
        executable=StdioArtifactPin(sys.executable, sha256_file(sys.executable)),
        arguments=arguments,
        additional_artifacts=(StdioArtifactPin(str(FIXTURE), sha256_file(str(FIXTURE))),),
        working_directory=str(ROOT),
        read_only_paths=read_only_paths,
        writable_paths=writable_paths,
        allow_network=allow_network,
        allow_child_processes=allow_child_processes,
    )


def backend(*, signing_key=KEY):
    return SeatbeltSandboxBackend(launcher=launcher(), signing_key=signing_key)


class SeatbeltPolicyTests(unittest.TestCase):
    def test_argv_is_sandbox_exec_with_inline_policy_then_command(self):
        plan = backend().prepare(profile())
        self.assertEqual(plan.argv[0], launcher().path)
        self.assertEqual(plan.argv[1], "-p")
        self.assertEqual(plan.argv[3:], (RESOLVED_EXE, str(FIXTURE), "normal", "-", "-"))
        self.assertEqual(dict(plan.environment), {})
        self.assertEqual(plan.working_directory, str(ROOT))

    def test_policy_denies_by_default_and_reallows_only_declared_paths(self):
        policy = backend()._policy(profile())
        self.assertIn("(deny default)", policy)
        self.assertIn('(deny file-read* (subpath "/Users")', policy)
        self.assertIn(f'(literal "{RESOLVED_EXE}")', policy)
        self.assertIn(f'(literal "{FIXTURE}")', policy)
        self.assertNotIn("file-write*", policy)  # nothing declared writable
        self.assertIn("(deny process-fork)", policy)
        self.assertNotIn("(allow network*)", policy)

    def test_allow_flags_flip_policy_and_attestation_bits(self):
        open_profile = profile(allow_network=True, allow_child_processes=True)
        plan = backend().prepare(open_profile)
        policy = backend()._policy(open_profile)
        self.assertIn("(allow network*)", policy)
        self.assertNotIn("(deny process-fork)", policy)
        self.assertFalse(plan.attestation.network_restricted)
        self.assertFalse(plan.attestation.child_process_restricted)

    def test_writable_paths_are_granted_write_and_read(self):
        writable = profile(writable_paths=(str(ROOT / "src"),))
        policy = backend()._policy(writable)
        resolved = str((ROOT / "src").resolve())
        self.assertIn(f'(allow file-write* (subpath "{resolved}"))', policy)


class SeatbeltAttestationHonestyTests(unittest.TestCase):
    def test_bits_are_true_true_true_for_a_fully_denying_profile(self):
        attestation = backend().prepare(profile()).attestation
        self.assertTrue(attestation.filesystem_restricted)
        self.assertTrue(attestation.network_restricted)
        self.assertTrue(attestation.child_process_restricted)  # seatbelt CAN deny fork, unlike bwrap
        self.assertEqual(attestation.backend_id, BACKEND_ID)
        self.assertIn("policy=sha256:", attestation.evidence_reference)

    def test_policy_digest_in_evidence_is_stable(self):
        first = backend().prepare(profile()).attestation.evidence_reference
        second = backend().prepare(profile()).attestation.evidence_reference
        self.assertEqual(first, second)

    def test_signature_verifies_with_the_backend_key(self):
        attestation = backend().prepare(profile()).attestation
        self.assertTrue(AttestationVerifier({BACKEND_ID: KEY}).verify(attestation))
        self.assertFalse(AttestationVerifier({BACKEND_ID: OTHER_KEY}).verify(attestation))

    def test_overbroad_paths_are_refused(self):
        for path in ("/System", "/Users", "/private"):
            if not Path(path).is_dir():
                continue
            with self.assertRaises(MCPStdioError) as raised:
                backend().prepare(profile(read_only_paths=(path,)))
            self.assertEqual(raised.exception.reason_code, "MCP-STDIO-SANDBOX-UNSAFE-MOUNT")

    def test_unquotable_path_is_refused_before_policy_injection(self):
        from agent_interlock.mcp_stdio import _seatbelt_path

        with self.assertRaises(MCPStdioError) as raised:
            _seatbelt_path('/tmp/pwn") (allow default) ("')
        self.assertEqual(raised.exception.reason_code, "MCP-STDIO-SANDBOX-UNSAFE-MOUNT")

    def test_empty_signing_key_is_refused(self):
        with self.assertRaises(ValueError):
            SeatbeltSandboxBackend(launcher=launcher(), signing_key=b"")


class SeatbeltClientBindingTests(unittest.TestCase):
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


def _interpreter_closure() -> str:
    return str(Path(sys.base_prefix).resolve())


def _run_sandboxed(plan, code: str) -> subprocess.CompletedProcess:
    argv = list(plan.argv[:3]) + [RESOLVED_EXE, "-c", code]
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=plan.working_directory,
        env=dict(plan.environment),
    )


@unittest.skipUnless(
    sys.platform == "darwin" and SANDBOX_EXEC.exists(),
    "macOS with sandbox-exec is required for the live Seatbelt enforcement tests",
)
class SeatbeltLiveEnforcementTests(unittest.TestCase):
    """Actually runs python under the generated policy on this host."""

    @classmethod
    def setUpClass(cls):
        closure = _interpreter_closure()
        cls.live_profile = StdioSandboxProfile(
            profile_id="seatbelt-live",
            executable=StdioArtifactPin(sys.executable, sha256_file(sys.executable)),
            arguments=("-c", "print('unused')"),
            working_directory=closure,
            read_only_paths=(closure,),
        )
        cls.plan = SeatbeltSandboxBackend(
            launcher=StdioArtifactPin(str(SANDBOX_EXEC), sha256_file(str(SANDBOX_EXEC))),
            signing_key=KEY,
        ).prepare(cls.live_profile)
        probe = _run_sandboxed(cls.plan, "print('sandbox-probe-ok')")
        if probe.returncode != 0 or "sandbox-probe-ok" not in probe.stdout:
            raise unittest.SkipTest(
                "interpreter runtime closure is not satisfiable under Seatbelt on this host: "
                + (probe.stderr or f"exit {probe.returncode}").strip()[:200]
            )

    def test_python_runs_and_reads_the_declared_closure(self):
        result = _run_sandboxed(self.plan, "import os, sys; os.listdir(sys.base_prefix); print('closure-ok')")
        self.assertIn("closure-ok", result.stdout)

    def test_user_home_is_unreadable(self):
        result = _run_sandboxed(
            self.plan,
            "import os\n"
            "try:\n"
            "    os.listdir(os.path.expanduser('~') if os.environ.get('HOME') else '/Users')\n"
            "    print('LEAKED')\n"
            "except OSError:\n"
            "    print('home-denied')\n",
        )
        self.assertIn("home-denied", result.stdout)

    def test_writes_outside_writable_paths_are_denied(self):
        result = _run_sandboxed(
            self.plan,
            "try:\n"
            "    open('/private/tmp/seatbelt-live-leak.txt', 'w').write('x')\n"
            "    print('LEAKED')\n"
            "except OSError:\n"
            "    print('write-denied')\n",
        )
        self.assertIn("write-denied", result.stdout)

    def test_child_processes_are_denied(self):
        result = _run_sandboxed(
            self.plan,
            "import subprocess\n"
            "try:\n"
            "    subprocess.run(['/usr/bin/true'])\n"
            "    print('LEAKED')\n"
            "except OSError:\n"
            "    print('fork-denied')\n",
        )
        self.assertIn("fork-denied", result.stdout)

    def test_network_is_denied(self):
        result = _run_sandboxed(
            self.plan,
            "import socket\n"
            "try:\n"
            "    connection = socket.socket()\n"
            "    connection.settimeout(2)\n"
            "    connection.connect(('127.0.0.1', 9))\n"
            "    print('LEAKED')\n"
            "except OSError:\n"
            "    print('net-denied')\n",
        )
        self.assertIn("net-denied", result.stdout)


if __name__ == "__main__":
    unittest.main()
