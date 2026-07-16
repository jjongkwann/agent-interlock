from __future__ import annotations

import os
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from agent_interlock import (
    ArchitectureCompiler,
    ArchitectureGraph,
    DirectTestSandboxBackend,
    MCPStdioClient,
    MCPStdioClientConfig,
    MCPStdioError,
    MCPStdioSandboxUnavailable,
    MCPInvocationContext,
    MCPServerProfile,
    MCPToolGateway,
    MCPTransportAdapter,
    StdioArtifactPin,
    StdioSandboxProfile,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "mcp_stdio_fixture_server.py"
MANIFEST = ROOT / "examples" / "secure_multi_agent_architecture.json"


def profile(
    mode: str = "normal",
    *,
    marker: str = "-",
    child_pid: str = "-",
    timeout: float = 1.0,
    max_message_bytes: int = 4096,
    test_mode: bool = True,
    executable_digest: str | None = None,
) -> StdioSandboxProfile:
    return StdioSandboxProfile(
        profile_id=f"fixture-{mode}",
        executable=StdioArtifactPin(
            sys.executable,
            executable_digest or sha256_file(sys.executable),
        ),
        arguments=(str(FIXTURE), mode, marker, child_pid),
        additional_artifacts=(StdioArtifactPin(str(FIXTURE), sha256_file(str(FIXTURE))),),
        working_directory=str(ROOT),
        read_only_paths=(str(FIXTURE),),
        allow_unenforced_test_mode=test_mode,
        request_timeout_seconds=timeout,
        termination_grace_seconds=0.05,
        max_message_bytes=max_message_bytes,
    )


def initialized_client(value: StdioSandboxProfile) -> MCPStdioClient:
    client = MCPStdioClient(
        MCPStdioClientConfig(value),
        sandbox_backend=DirectTestSandboxBackend(),
    )
    client.initialize(client_name="stdio-test", client_version="1.0")
    return client


class StdioSandboxProfileTests(unittest.TestCase):
    def test_shell_environment_and_relative_artifacts_are_denied(self):
        shell = "/bin/sh" if Path("/bin/sh").exists() else sys.executable
        if Path(shell).name == "sh":
            with self.assertRaises(ValueError):
                StdioSandboxProfile(
                    profile_id="shell",
                    executable=StdioArtifactPin(shell, sha256_file(shell)),
                )
        with self.assertRaises(ValueError):
            StdioSandboxProfile(
                profile_id="env",
                executable=StdioArtifactPin(sys.executable, sha256_file(sys.executable)),
                environment={"PYTHONPATH": "/tmp/inject"},
            )
        with self.assertRaises(ValueError):
            StdioArtifactPin("relative-server", "sha256:" + "0" * 64)
        with self.assertRaises(ValueError):
            StdioSandboxProfile(
                profile_id="unpinned-script",
                executable=StdioArtifactPin(sys.executable, sha256_file(sys.executable)),
                arguments=(str(FIXTURE),),
                working_directory=str(ROOT),
            )

    def test_artifact_digest_mismatch_fails_before_process_start(self):
        client = MCPStdioClient(
            MCPStdioClientConfig(profile(executable_digest="sha256:" + "0" * 64)),
            sandbox_backend=DirectTestSandboxBackend(),
        )
        with self.assertRaises(MCPStdioError) as raised:
            client.initialize()
        self.assertEqual(raised.exception.reason_code, "L1-M4-ARTIFACT-DIGEST-MISMATCH")
        self.assertFalse(client.running)

    def test_missing_enforcing_backend_fails_closed_before_attack_process(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "startup-marker")
            client = MCPStdioClient(MCPStdioClientConfig(profile("startup-write", marker=marker)))
            with self.assertRaises(MCPStdioSandboxUnavailable):
                client.initialize()
            self.assertFalse(Path(marker).exists())
            self.assertFalse(client.running)

    def test_unenforced_backend_cannot_run_without_explicit_test_profile(self):
        client = MCPStdioClient(
            MCPStdioClientConfig(profile(test_mode=False)),
            sandbox_backend=DirectTestSandboxBackend(),
        )
        with self.assertRaises(MCPStdioSandboxUnavailable):
            client.initialize()


class StdioProtocolTests(unittest.TestCase):
    def test_initialize_json_lines_notification_and_stderr_redaction(self):
        notifications = []
        client = MCPStdioClient(
            MCPStdioClientConfig(profile("notification")),
            sandbox_backend=DirectTestSandboxBackend(),
            server_message_handler=notifications.append,
        )
        result = client.initialize()
        self.assertIn("tools", result["capabilities"])
        response = client.call(
            {"jsonrpc": "2.0", "id": "list", "method": "tools/list", "params": {}}
        )
        self.assertEqual(response["result"]["tools"][0]["name"], "echo")
        self.assertEqual(notifications[0]["method"], "notifications/tools/list_changed")
        deadline = time.monotonic() + 1
        while "fixture log" not in client.stderr_text and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertIn("[REDACTED_SECRET]", client.stderr_text)
        self.assertNotIn("abcd1234secretvalue", client.stderr_text)
        self.assertEqual(client.sandbox_attestation.backend_id, "test-only-unenforced")
        client.close()

    def test_parent_environment_is_not_inherited(self):
        previous = os.environ.get("INTERLOCK_PARENT_SECRET")
        os.environ["INTERLOCK_PARENT_SECRET"] = "parent-only-value"
        try:
            client = initialized_client(profile("environment"))
            response = client.call(
                {
                    "jsonrpc": "2.0",
                    "id": "env",
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {}},
                }
            )
            self.assertEqual(response["result"]["structuredContent"]["value"], "absent")
            client.close()
        finally:
            if previous is None:
                os.environ.pop("INTERLOCK_PARENT_SECRET", None)
            else:
                os.environ["INTERLOCK_PARENT_SECRET"] = previous

    def test_non_protocol_stdout_and_oversized_message_kill_process(self):
        for mode, expected in (
            ("noise", "MCP-STDIO-STDOUT-INVALID"),
            ("oversized", "MCP-STDIO-MESSAGE-TOO-LARGE"),
        ):
            with self.subTest(mode=mode):
                client = MCPStdioClient(
                    MCPStdioClientConfig(profile(mode, max_message_bytes=1024)),
                    sandbox_backend=DirectTestSandboxBackend(),
                )
                with self.assertRaises(MCPStdioError) as raised:
                    client.initialize()
                self.assertEqual(raised.exception.reason_code, expected)
                self.assertFalse(client.running)

    def test_timeout_is_not_retried_and_process_group_is_terminated(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "calls")
            child_pid_path = Path(directory) / "child.pid"
            client = initialized_client(
                profile(
                    "child-hang",
                    marker=marker,
                    child_pid=str(child_pid_path),
                    timeout=0.15,
                )
            )
            with self.assertRaises(MCPStdioError) as raised:
                client.call(
                    {
                        "jsonrpc": "2.0",
                        "id": "slow",
                        "method": "tools/call",
                        "params": {"name": "echo", "arguments": {"value": "once"}},
                    }
                )
            self.assertEqual(raised.exception.reason_code, "MCP-STDIO-TIMEOUT")
            self.assertEqual(Path(marker).read_text(encoding="utf-8").splitlines(), ["call"])
            self.assertFalse(client.running)
            if child_pid_path.exists() and os.name == "posix":
                child_pid = child_pid_path.read_text(encoding="ascii")
                status = subprocess.run(
                    ["ps", "-o", "stat=", "-p", child_pid],
                    capture_output=True,
                    text=True,
                    check=False,
                ).stdout.strip()
                self.assertTrue(not status or status.startswith("Z"), status)

    def test_server_initiated_request_fails_closed(self):
        client = initialized_client(profile("server-request"))
        with self.assertRaises(MCPStdioError) as raised:
            client.call(
                {
                    "jsonrpc": "2.0",
                    "id": "host-call",
                    "method": "tools/call",
                    "params": {"name": "echo", "arguments": {}},
                }
            )
        self.assertEqual(raised.exception.reason_code, "MCP-STDIO-SERVER-REQUEST-UNSUPPORTED")
        self.assertFalse(client.running)


class StdioTransportIntegrationTests(unittest.TestCase):
    def test_stdio_client_runs_transport_adapter_with_exact_architecture_binding(self):
        sandbox_profile = profile("normal")
        client = initialized_client(sandbox_profile)
        gateway = MCPToolGateway()
        server_profile = MCPServerProfile(
            tenant_id="tenant-a",
            server_id="tenant-a/prod/stdio-echo",
            endpoint="stdio://approved/echo",
            transport="stdio",
            publisher="test-platform",
            artifact_digest=sandbox_profile.artifact_set_digest,
        )
        adapter = MCPTransportAdapter(
            gateway,
            server_profile,
            client.server_caller(server_profile),
        )
        client.set_server_message_handler(adapter.handle_server_message)
        hidden = adapter.handle_client_message(
            {"jsonrpc": "2.0", "id": "discover", "method": "tools/list", "params": {}}
        )
        self.assertEqual(hidden["result"]["tools"], [])
        revision = adapter.observed_revisions[0]
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        tool = next(item for item in manifest["spec"]["nodes"] if item["id"] == "tool.send-email")
        tool["definitionDigest"] = revision.canonical_digest
        edge = next(
            item for item in manifest["spec"]["edges"] if item["relationshipId"] == "REL-05"
        )
        edge["policy"]["externalWriteRequiresApproval"] = False
        compiled = ArchitectureCompiler().compile(ArchitectureGraph.from_dict(manifest))
        adapter.bind_compiled_architecture(
            compiled,
            tool_bindings={"echo": "tool.send-email"},
            approver="stdio-security-reviewer",
        )
        response = adapter.handle_client_message(
            {
                "jsonrpc": "2.0",
                "id": "echo-call",
                "method": "tools/call",
                "params": {"name": "echo", "arguments": {"value": "safe"}},
            },
            context=MCPInvocationContext(
                tenant_id="tenant-a",
                source_actor_id="agent.support",
                purpose="SUPPORT_REPLY",
            ),
        )
        self.assertEqual(response["result"]["structuredContent"], {"value": "safe"})
        self.assertEqual(response["result"]["_meta"]["interlock"]["decision"], "ALLOW")
        self.assertIsNotNone(client.sandbox_attestation)
        client.close()

    def test_stdio_server_profile_cannot_claim_a_different_artifact(self):
        sandbox_profile = profile("normal")
        client = MCPStdioClient(
            MCPStdioClientConfig(sandbox_profile),
            sandbox_backend=DirectTestSandboxBackend(),
        )
        server_profile = MCPServerProfile(
            tenant_id="tenant-a",
            server_id="tenant-a/prod/stdio-echo",
            endpoint="stdio://approved/echo",
            transport="stdio",
            artifact_digest="sha256:" + "0" * 64,
        )
        with self.assertRaises(MCPStdioError) as raised:
            client.server_caller(server_profile)
        self.assertEqual(raised.exception.reason_code, "MCP-STDIO-ARTIFACT-BINDING-MISMATCH")


if __name__ == "__main__":
    unittest.main()
