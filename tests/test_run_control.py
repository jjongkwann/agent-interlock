"""Run Control API tests. Fake transports stay in this test module only."""

from __future__ import annotations

import http.client
import io
import json
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agent_interlock import (
    CallableTaskAdapter,
    ControlPlaneAPI,
    ControlPlaneConfig,
    DeploymentBundle,
    GitBundleStore,
    InMemoryLedger,
    LedgerAPIPrincipal,
    RunControlService,
    SigningBackendUnavailable,
    StaticBearerAuthenticator,
    TaskExecutionResult,
    TaskTransport,
    TrustedApprovalKey,
    create_control_plane_server,
    ed25519_public_key_bytes,
    sign_deployment_approval,
)
from agent_interlock.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "secure_multi_agent_architecture.json"
OPERATOR_TOKEN = "run-operator-token-test-only"
VIEWER_TOKEN = "run-viewer-token-test-only"
OTHER_TENANT_TOKEN = "run-other-tenant-token-test-only"
KEY_ONE = bytes.fromhex("31" * 32)
KEY_TWO = bytes.fromhex("32" * 32)

try:
    TRUSTED_APPROVERS = {
        "run-key-one": TrustedApprovalKey("run-security-reviewer", ed25519_public_key_bytes(KEY_ONE)),
        "run-key-two": TrustedApprovalKey("run-platform-reviewer", ed25519_public_key_bytes(KEY_TWO)),
    }
    CRYPTO_AVAILABLE = True
except SigningBackendUnavailable:
    TRUSTED_APPROVERS = {}
    CRYPTO_AVAILABLE = False


def compile_bundle() -> dict:
    output = io.StringIO()
    with redirect_stdout(output):
        code = main(["architecture", "compile", "--shadow", str(MANIFEST)])
    assert code == 0
    return json.loads(output.getvalue())


def activate_bundle(store: GitBundleStore) -> DeploymentBundle:
    bundle = DeploymentBundle.from_compile_output(compile_bundle())
    store.propose(bundle)
    approvals = (
        sign_deployment_approval(
            bundle,
            from_digest=None,
            to_mode="ENFORCE",
            approver_id="run-security-reviewer",
            key_id="run-key-one",
            key=KEY_ONE,
        ),
        sign_deployment_approval(
            bundle,
            from_digest=None,
            to_mode="ENFORCE",
            approver_id="run-platform-reviewer",
            key_id="run-key-two",
            key=KEY_TWO,
        ),
    )
    store.promote(bundle.bundle_digest, approvals, trusted_approvers=TRUSTED_APPROVERS)
    return bundle


class RunningRunControl:
    def __init__(
        self,
        root: str,
        adapter_provider,  # noqa: ANN001
        *,
        activate: bool = True,
        allowed_origins: frozenset[str] = frozenset(),
        ledger: InMemoryLedger | None = None,
    ) -> None:
        self.store = GitBundleStore(root)
        if activate:
            activate_bundle(self.store)
        scopes = frozenset(
            {
                "deploy:read",
                "deploy:propose",
                "deploy:approve",
                "deploy:promote",
                "run:create",
                "run:read",
                "run:approve",
                "run:cancel",
            }
        )
        authenticator = StaticBearerAuthenticator.from_tokens(
            {
                OPERATOR_TOKEN: LedgerAPIPrincipal("run-operator", "tenant-run-a", scopes, frozenset()),
                VIEWER_TOKEN: LedgerAPIPrincipal(
                    "run-viewer",
                    "tenant-run-a",
                    frozenset({"run:read"}),
                    frozenset(),
                ),
                OTHER_TENANT_TOKEN: LedgerAPIPrincipal("run-operator-b", "tenant-run-b", scopes, frozenset()),
            }
        )
        self.ledger = ledger or InMemoryLedger()
        self.run_service = RunControlService(self.store, adapter_provider, ledger=self.ledger)
        self.api = ControlPlaneAPI(
            self.store,
            authenticator,
            trusted_approvers=TRUSTED_APPROVERS,
            run_service=self.run_service,
            config=ControlPlaneConfig(allowed_origins=allowed_origins),
        )
        self.server = create_control_plane_server(self.api)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method: str, path: str, *, token: str = OPERATOR_TOKEN, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=2)
        headers = {"Authorization": f"Bearer {token}"}
        encoded = None
        if body is not None:
            encoded = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        try:
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
        finally:
            connection.close()

    def wait_for_state(self, run_id: str, state: str, *, timeout: float = 2.0) -> dict:
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            status, body = self.request("GET", f"/v1/runs/{run_id}", token=VIEWER_TOKEN)
            assert status == 200
            last = body["run"]
            if last["state"] == state:
                return last
            time.sleep(0.01)
        raise AssertionError(f"run did not reach {state}: {last}")


@unittest.skipUnless(CRYPTO_AVAILABLE, "Ed25519 is required for deployment-bound Run Control tests")
class RunControlAPITests(unittest.TestCase):
    def test_active_bundle_run_waits_for_approval_and_completes(self) -> None:
        calls = {"a2a": 0, "mcp": 0}

        def adapter_provider(_compiled):  # noqa: ANN001
            def a2a(value):  # noqa: ANN001
                calls["a2a"] += 1
                return TaskExecutionResult(
                    output={"evidenceIds": ["kb-test-only-001"], "artifacts": [{"artifactId": "test-only"}]},
                    metadata={"accepted": True},
                )

            def mcp(value):  # noqa: ANN001
                calls["mcp"] += 1
                return TaskExecutionResult(
                    output={"receiptId": "receipt-test-only-001", "status": "TEST_ONLY"},
                    metadata={"accepted": True},
                )

            return {
                TaskTransport.A2A: CallableTaskAdapter(a2a),
                TaskTransport.MCP: CallableTaskAdapter(mcp),
            }

        with tempfile.TemporaryDirectory() as root, RunningRunControl(root, adapter_provider) as plane:
            status, body = plane.request(
                "POST",
                "/v1/runs",
                body={
                    "runId": "run-api-test-only-001",
                    "traceId": "trace-api-test-only-001",
                    "input": {"customerId": "customer-test-only-001", "customerToken": "must-redact"},
                },
            )
            self.assertEqual(status, 202)
            run_id = body["run"]["id"]
            self.assertEqual(body["run"]["input"]["customerToken"], "[REDACTED]")

            paused = plane.wait_for_state(run_id, "WAITING_APPROVAL")
            self.assertEqual(paused["tasks"]["task.research"]["state"], "COMPLETED")
            self.assertEqual(paused["tasks"]["task.send-reply"]["state"], "WAITING_APPROVAL")
            self.assertEqual(calls, {"a2a": 1, "mcp": 0})

            status, _ = plane.request(
                "POST",
                f"/v1/runs/{run_id}/tasks/task.send-reply/approve",
                body={},
            )
            self.assertEqual(status, 202)
            completed = plane.wait_for_state(run_id, "COMPLETED")
            self.assertEqual(completed["tasks"]["task.send-reply"]["output"]["status"], "TEST_ONLY")
            self.assertEqual(calls, {"a2a": 1, "mcp": 1})

            self.assertEqual(
                completed["outcomes"],
                {"executed": 2, "goalMet": 2, "securityMet": 0, "total": 2},
            )
            self.assertTrue(completed["tasks"]["task.research"]["executed"])
            self.assertTrue(completed["tasks"]["task.research"]["goalMet"])
            self.assertIsNone(completed["tasks"]["task.research"]["securityMet"])

            status, listed = plane.request("GET", "/v1/runs", token=VIEWER_TOKEN)
            self.assertEqual(status, 200)
            self.assertEqual([item["id"] for item in listed["runs"]], [run_id])
            status, events = plane.request("GET", f"/v1/runs/{run_id}/events", token=VIEWER_TOKEN)
            self.assertEqual(status, 200)
            event_types = {item["event_type"] for item in events["events"]}
            self.assertIn("WORKFLOW_RUN_WAITING_APPROVAL", event_types)
            self.assertIn("WORKFLOW_TASK_APPROVED", event_types)
            self.assertIn("WORKFLOW_RUN_COMPLETED", event_types)

    def test_scope_and_tenant_isolation_are_enforced(self) -> None:
        def adapter_provider(_compiled):  # noqa: ANN001
            done = CallableTaskAdapter(
                lambda _value: TaskExecutionResult(output={}, metadata={"accepted": True})
            )
            return {TaskTransport.A2A: done, TaskTransport.MCP: done}

        with tempfile.TemporaryDirectory() as root, RunningRunControl(root, adapter_provider) as plane:
            status, body = plane.request(
                "POST",
                "/v1/runs",
                body={"runId": "run-tenant-test-only", "input": {}},
            )
            self.assertEqual(status, 202)
            run_id = body["run"]["id"]
            status, denied = plane.request("POST", "/v1/runs", token=VIEWER_TOKEN, body={"input": {}})
            self.assertEqual((status, denied["error"]["code"]), (403, "CONTROL-SCOPE-DENIED"))
            status, hidden = plane.request("GET", f"/v1/runs/{run_id}", token=OTHER_TENANT_TOKEN)
            self.assertEqual((status, hidden["error"]["code"]), (404, "RUN-NOT-FOUND"))

            status, other = plane.request(
                "POST",
                "/v1/runs",
                token=OTHER_TENANT_TOKEN,
                body={"runId": run_id, "input": {}},
            )
            self.assertEqual(status, 202)
            self.assertEqual(other["run"]["id"], run_id)
            status, visible = plane.request("GET", f"/v1/runs/{run_id}", token=OTHER_TENANT_TOKEN)
            self.assertEqual(status, 200)
            self.assertEqual(visible["run"]["tenantId"], "tenant-run-b")

            status, duplicate = plane.request("POST", "/v1/runs", body={"runId": run_id, "input": {}})
            self.assertEqual((status, duplicate["error"]["code"]), (409, "ORCH-RUN-DUPLICATE"))
            status, invalid = plane.request("POST", "/v1/runs", body={"runId": "../unsafe", "input": {}})
            self.assertEqual((status, invalid["error"]["code"]), (400, "RUN-ID-INVALID"))

    def test_active_deployment_and_all_real_transport_adapters_are_required(self) -> None:
        with tempfile.TemporaryDirectory() as root, RunningRunControl(
            root,
            lambda _compiled: {},
            activate=False,
        ) as plane:
            status, body = plane.request("POST", "/v1/runs", body={"input": {}})
            self.assertEqual((status, body["error"]["code"]), (409, "RUN-ACTIVE-DEPLOYMENT-REQUIRED"))

        with tempfile.TemporaryDirectory() as root, RunningRunControl(
            root,
            lambda _compiled: {
                TaskTransport.A2A: CallableTaskAdapter(
                    lambda _value: TaskExecutionResult(output={}, metadata={"accepted": True})
                )
            },
        ) as plane:
            status, body = plane.request("POST", "/v1/runs", body={"input": {}})
            self.assertEqual((status, body["error"]["code"]), (503, "RUN-ADAPTER-MISSING"))

    def test_cancel_wins_over_an_in_flight_test_adapter(self) -> None:
        started = threading.Event()
        release = threading.Event()

        def adapter_provider(_compiled):  # noqa: ANN001
            def slow(_value):
                started.set()
                release.wait(timeout=2)
                return TaskExecutionResult(output={"ignored": True}, metadata={"accepted": True})

            done = CallableTaskAdapter(
                lambda _value: TaskExecutionResult(output={}, metadata={"accepted": True})
            )
            return {TaskTransport.A2A: CallableTaskAdapter(slow), TaskTransport.MCP: done}

        with tempfile.TemporaryDirectory() as root, RunningRunControl(root, adapter_provider) as plane:
            status, body = plane.request(
                "POST",
                "/v1/runs",
                body={"runId": "run-cancel-test-only", "input": {}},
            )
            self.assertEqual(status, 202)
            run_id = body["run"]["id"]
            self.assertTrue(started.wait(timeout=1))
            status, canceled = plane.request("POST", f"/v1/runs/{run_id}/cancel", body={})
            self.assertEqual(status, 200)
            self.assertEqual(canceled["run"]["state"], "CANCELED")
            release.set()
            self.assertEqual(plane.wait_for_state(run_id, "CANCELED")["state"], "CANCELED")

    def test_run_edges_are_enforced_regardless_of_the_bundles_authored_mode(self) -> None:
        def adapter_provider(_compiled):  # noqa: ANN001
            def a2a(value):  # noqa: ANN001
                return TaskExecutionResult(
                    output={"evidenceIds": ["kb-test-only-001"], "artifacts": [{"artifactId": "test-only"}]},
                    metadata={"accepted": True},
                )

            def mcp(value):  # noqa: ANN001
                return TaskExecutionResult(
                    output={"receiptId": "receipt-test-only-001", "status": "TEST_ONLY"},
                    metadata={"accepted": True},
                )

            return {
                TaskTransport.A2A: CallableTaskAdapter(a2a),
                TaskTransport.MCP: CallableTaskAdapter(mcp),
            }

        with tempfile.TemporaryDirectory() as root, RunningRunControl(root, adapter_provider) as plane:
            active = plane.store.active()
            self.assertEqual(active["mode"], "ENFORCE")
            promoted_bundle = plane.store.bundle(active["bundleDigest"])
            # compile --shadow authors every edge in the bundle body as SHADOW; the deployment
            # record's mode (ENFORCE) is still what Run Control must actually enforce (D5).
            self.assertTrue(
                all(
                    edge["policy"]["mode"] == "SHADOW"
                    for edge in promoted_bundle.body["architecture"]["spec"]["edges"]
                )
            )

            status, body = plane.request(
                "POST",
                "/v1/runs",
                body={"runId": "run-mode-test-only-001", "input": {}},
            )
            self.assertEqual(status, 202)
            run_id = body["run"]["id"]

            modes = plane.run_service.edge_modes(tenant_id="tenant-run-a", run_id=run_id)
            self.assertTrue(modes)
            self.assertTrue(all(mode == "ENFORCE" for mode in modes.values()))


if __name__ == "__main__":
    unittest.main()
