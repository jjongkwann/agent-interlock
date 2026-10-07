"""Private bootstrap and real authenticated HTTP over the durable local host."""

import contextlib
import http.client
import importlib.util
import io
import json
import os
import select
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_interlock.local_host import _local_principals, bootstrap, main, serve_local, single_owner
from agent_interlock.signing import ed25519_public_key_bytes


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "cryptography ('jwt' extra) is required")
class LocalHostTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)

    def test_bootstrap_is_private_and_restart_does_not_read_reviewer_keys(self):
        config = bootstrap(self.path)
        self.assertEqual(config, {"version": 1, "tenantId": "tenant-local", "credentialEnv": {}})
        trust = json.loads((self.path / "trusted-approvers.json").read_text())
        keys = [self.path / "reviewers" / f"reviewer-{number}.key" for number in (1, 2)]
        seeds = [bytes.fromhex(key.read_text().strip()) for key in keys]
        self.assertNotEqual(seeds[0], seeds[1])
        for number, seed in enumerate(seeds, 1):
            self.assertEqual(trust[f"reviewer-{number}"]["publicKeyHex"], ed25519_public_key_bytes(seed).hex())
        for path in keys + [self.path / name for name in ("config.json", "operator.token", "trusted-approvers.json")]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        before = (self.path / "operator.token").read_text()
        for key in keys:
            key.unlink()  # reviewer keys may be held elsewhere; startup must not need them
        with patch("agent_interlock.local_host.ed25519_public_key_bytes", side_effect=AssertionError("key read")):
            self.assertEqual(bootstrap(self.path), config)
        self.assertEqual((self.path / "operator.token").read_text(), before)

    def test_serve_cli_prints_paths_not_secrets_and_stops_on_sigterm(self):
        process = subprocess.Popen(
            [sys.executable, "-m", "agent_interlock", "serve", "--data-dir", str(self.path), "--port", "0"],
            cwd=Path(__file__).resolve().parents[1], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        try:
            readable, _, _ = select.select([process.stdout], [], [], 10)
            self.assertTrue(readable, "host did not announce startup")
            output = os.read(process.stdout.fileno(), 8192).decode()
            self.assertTrue(output.startswith("Studio API: http://127.0.0.1:"), output)
            while "Local bootstrap:" not in output:
                readable, _, _ = select.select([process.stdout], [], [], 10)
                self.assertTrue(readable, "host did not finish startup")
                chunk = os.read(process.stdout.fileno(), 8192)
                self.assertTrue(chunk, "host exited during startup")
                output += chunk.decode()
            process.terminate()
            stdout, stderr = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, stderr)
            output += stdout
            self.assertIn(str(self.path / "operator.token"), output)
            self.assertNotIn((self.path / "operator.token").read_text().strip(), output)
            for key in (self.path / "reviewers").glob("*.key"):
                self.assertNotIn(key.read_text().strip(), output)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    def test_refuses_second_owner_and_insecure_or_invalid_configuration(self):
        with single_owner(self.path / "owner.lock"):
            with self.assertRaises(RuntimeError):
                with single_owner(self.path / "owner.lock"):
                    pass
        bootstrap(self.path)
        config_path = self.path / "config.json"
        config_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "0600"):
            bootstrap(self.path)
        config_path.chmod(0o600)
        config_path.write_text(json.dumps({"version": 1, "tenantId": "tenant-local", "credentialEnv": {"key": 42}}))
        with self.assertRaisesRegex(ValueError, "credentialEnv"):
            bootstrap(self.path)

    @staticmethod
    def request(server, method, path, *, token=None, body=None, origin=None, tenant="tenant-local"):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        headers = {"Content-Type": "application/json", "X-Interlock-Tenant-Id": tenant}
        if method == "POST" and path == "/v1/events":
            headers["Idempotency-Key"] = "local-smoke-event"
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if origin is not None:
            headers["Origin"] = origin
        connection.request(method, path, json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse()
        value = response.read()
        result = response.status, dict(response.getheaders()), json.loads(value) if value else {}
        connection.close()
        return result

    def test_single_port_authenticated_ledger_control_and_restart(self):
        with serve_local(self.path, port=0, origins=["http://localhost:5173"]) as server:
            token = (self.path / "operator.token").read_text().strip()
            self.assertEqual(self.request(server, "GET", "/v1/deploy/status")[0], 401)
            status, _, value = self.request(server, "GET", "/v1/deploy/status", token=token)
            self.assertEqual(status, 200)
            self.assertNotIn(token, json.dumps(value))
            event = {"event_type": "WORKFLOW_RUN_CREATED", "tenant_id": "tenant-local", "trace_id": "trace",
                     "span_id": "span", "source_actor_id": "local-operator", "payload": {"secret": "not-visible"}}
            status, _, _ = self.request(server, "POST", "/v1/events", token=token, body=event)
            self.assertEqual(status, 201)
            status, headers, value = self.request(server, "GET", "/v1/traces/trace", token=token,
                                                  origin="http://localhost:5173")
            self.assertEqual(status, 200)
            self.assertEqual(headers["Access-Control-Allow-Origin"], "http://localhost:5173")
            self.assertEqual(value["events"][0]["payload"]["secret"], "[REDACTED]")
            self.assertEqual(self.request(server, "GET", "/v1/traces/trace", token=token, tenant="another")[0], 403)
            self.assertEqual(self.request(server, "GET", "/v1/deploy/status", token=token,
                                          origin="https://other.example")[0], 403)
            self.assertEqual(self.request(server, "GET", "/reviewers/reviewer-1.key", token=token)[0], 404)
            with self.assertRaises(RuntimeError):
                with serve_local(self.path, port=0):
                    pass
        with serve_local(self.path, port=0) as restarted:
            self.assertEqual(len(self.request(restarted, "GET", "/v1/traces/trace", token=token)[2]["events"]), 1)

    def test_credential_values_stay_in_memory_and_startup_errors_are_structured(self):
        bootstrap(self.path)
        config_path = self.path / "config.json"
        config = json.loads(config_path.read_text())
        config["credentialEnv"] = {"provider": "INTERLOCK_LOCAL_TEST_CREDENTIAL", "missing": "INTERLOCK_MISSING_TEST"}
        config_path.write_text(json.dumps(config))
        with (
            patch.dict(os.environ, {"INTERLOCK_LOCAL_TEST_CREDENTIAL": "private-provider-value"}),
            patch("agent_interlock.configurable_runtime.configurable_adapter_provider",
                  return_value=lambda _: {}) as provider,
        ):
            with serve_local(self.path, port=0) as server:
                self.assertEqual(provider.call_args.args[2], {"provider": "private-provider-value"})
                token = (self.path / "operator.token").read_text().strip()
                status = self.request(server, "GET", "/v1/deploy/status", token=token)[2]
                self.assertNotIn("private-provider-value", json.dumps(status))
                self.assertNotIn("INTERLOCK_LOCAL_TEST_CREDENTIAL", json.dumps(status))
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            self.assertEqual(main(["--data-dir", str(self.path), "--port", "-1"]), 2)
        self.assertEqual(json.loads(error.getvalue())["error"]["code"], "INTERLOCK-HOST-STARTUP-INVALID")

    def test_team_projects_are_scoped_conflicts_do_not_overwrite_and_restart_preserves_identity(self):
        bootstrap(self.path)
        members = [{"subject": subject, "tokenEnv": f"INTERLOCK_{subject.upper()}_TOKEN",
                    "scopes": ["project:read", "project:write", "deploy:read"],
                    "projects": {project: ["read", "write", "deploy"]}}
                   for subject, project in (("alice", "alpha"), ("bob", "beta"))]
        path = self.path / "principals.json"
        path.write_text(json.dumps(members))
        path.chmod(0o600)
        tokens = {"INTERLOCK_ALICE_TOKEN": "alice-private-team-token", "INTERLOCK_BOB_TOKEN": "bob-private-team-token"}
        with patch.dict(os.environ, tokens):
            for restart in (False, True):
                with serve_local(self.path, port=0) as server:
                    alice, bob = tokens.values()
                    target = self.request(server, "GET", "/v1/runtime/status", token=alice)[2]["targetId"]
                    if not restart:
                        body = {"targetId": target, "revision": 0,
                                "manifest": {"metadata": {"id": "alpha"}, "draft": "original"}}
                        status, _, saved = self.request(server, "POST", "/v1/projects/alpha", token=alice, body=body)
                        self.assertEqual(status, 200, saved)
                        self.assertEqual(saved["project"]["updatedBy"], "alice")
                        self.assertEqual(saved["project"]["revision"], 1)
                        body["manifest"]["draft"] = "stale overwrite"
                        status, _, conflict = self.request(server, "POST", "/v1/projects/alpha", token=alice, body=body)
                        self.assertEqual(status, 409, conflict)
                        self.assertEqual(conflict["error"]["code"], "PROJECT-REVISION-CONFLICT")
                        body["targetId"] = "different-host"
                        status, _, error = self.request(server, "POST", "/v1/projects/alpha", token=alice, body=body)
                        self.assertEqual(status, 409)
                        self.assertEqual(error["error"]["code"], "PROJECT-TARGET-CHANGED")
                    self.assertEqual(self.request(server, "GET", "/v1/projects/alpha", token=bob)[0], 403)
                    self.assertEqual(self.request(server, "POST", "/v1/projects/alpha", token=bob,
                        body={"targetId": target, "revision": 1,
                              "manifest": {"metadata": {"id": "alpha"}}})[0], 403)
                    self.assertEqual(self.request(server, "GET", "/v1/projects", token=bob)[2]["projects"], [])
                    result = self.request(server, "GET", "/v1/projects/alpha", token=alice)[2]
                    self.assertEqual(result["project"]["manifest"]["draft"], "original")
                    self.assertEqual(result["project"]["updatedBy"], "alice")
                    runtime = self.request(server, "GET", "/v1/runtime/status", token=alice)[2]
                    for token in tokens.values():
                        self.assertNotIn(token, json.dumps(runtime))
                    self.assertEqual(self.request(server, "GET", "/v1/traces/private", token=alice)[0], 403)

    def test_team_credentials_fail_closed_for_duplicates_privilege_bypass_and_public_files(self):
        bootstrap(self.path)
        operator = (self.path / "operator.token").read_text().strip()
        path = self.path / "principals.json"
        member = {"subject": "alice", "tokenEnv": "INTERLOCK_TEAM_TEST", "scopes": ["project:read"],
                  "projects": {"alpha": ["read"]}}
        invalid = [
            [{**member, "subject": "local-operator"}], [member, member],
            [{**member, "scopes": ["events:read"]}], [{**member, "scopes": ["telemetry:write"]}],
            [{**member, "projects": {"alpha": ["admin"]}}], [{**member, "tokenEnv": "MISSING_TEAM_TOKEN"}],
        ]
        with patch.dict(os.environ, {"INTERLOCK_TEAM_TEST": "team-private-token"}):
            for members in invalid:
                path.write_text(json.dumps(members))
                path.chmod(0o600)
                with self.subTest(members=members), self.assertRaises(ValueError):
                    _local_principals(self.path, "tenant-local", operator)
            path.write_text(json.dumps([member]))
            with patch.dict(os.environ, {"INTERLOCK_TEAM_TEST": operator}), self.assertRaises(ValueError):
                _local_principals(self.path, "tenant-local", operator)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "0600"):
                _local_principals(self.path, "tenant-local", operator)


if __name__ == "__main__":
    unittest.main()
