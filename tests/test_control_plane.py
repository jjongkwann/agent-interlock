"""Control plane HTTP flow: propose → approvals → two-person promote → rollback."""

import http.client
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import Mock

from test_candidate_compare import graph as comparison_graph

from agent_interlock import (
    ControlPlaneAPI,
    LedgerAPIPrincipal,
    SigningBackendUnavailable,
    StaticBearerAuthenticator,
    TrustedApprovalKey,
    create_control_plane_server,
    ed25519_public_key_bytes,
)
from agent_interlock.__main__ import main
from agent_interlock.canonical import canonical_digest
from agent_interlock.studio_deploy import (
    DeploymentBundle,
    GitBundleStore,
    compile_review_bundle,
    sign_deployment_approval,
)

MANIFEST = Path(__file__).resolve().parent.parent / "examples" / "secure_multi_agent_architecture.json"
OPERATOR_TOKEN = "control-operator-token-canary"
VIEWER_TOKEN = "control-viewer-token-canary"
KEY_ONE = bytes.fromhex("11" * 32)
KEY_TWO = bytes.fromhex("22" * 32)
try:
    TRUSTED_APPROVERS = {
        "key-one": TrustedApprovalKey("security-lead", ed25519_public_key_bytes(KEY_ONE)),
        "key-two": TrustedApprovalKey("platform-lead", ed25519_public_key_bytes(KEY_TWO)),
    }
    CRYPTO_AVAILABLE = True
except SigningBackendUnavailable:
    TRUSTED_APPROVERS = {}
    CRYPTO_AVAILABLE = False


def compile_bundle() -> dict:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main(["architecture", "compile", str(MANIFEST), "--shadow"])
    assert code == 0
    return json.loads(buffer.getvalue())


class RunningControlPlane:
    def __init__(self, repo: str):
        authenticator = StaticBearerAuthenticator.from_tokens(
            {
                OPERATOR_TOKEN: LedgerAPIPrincipal(
                    "operator",
                    "tenant-a",
                    frozenset({"deploy:read", "deploy:propose", "deploy:approve", "deploy:promote"}),
                    frozenset(),
                ),
                VIEWER_TOKEN: LedgerAPIPrincipal("viewer", "tenant-a", frozenset({"deploy:read"}), frozenset()),
            }
        )
        self.store = GitBundleStore(repo, tenant_id="tenant-a")
        self.api = ControlPlaneAPI(
            self.store,
            authenticator,
            trusted_approvers=TRUSTED_APPROVERS,
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
            encoded = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        try:
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
        finally:
            connection.close()


@unittest.skipUnless(CRYPTO_AVAILABLE, "the jwt extra is required for Ed25519 deployment approvals")
class ControlPlaneTests(unittest.TestCase):
    def test_browser_compile_context_and_readonly_preflight(self):
        manifest = json.loads(MANIFEST.read_text())
        with tempfile.TemporaryDirectory() as tmp, RunningControlPlane(tmp) as plane:
            status, compiled = plane.request("POST", "/v1/architectures/compile", body=manifest)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(compiled["rawBundle"])["bundleDigest"], compiled["bundleDigest"])
            self.assertEqual(DeploymentBundle.from_compile_output(json.loads(compiled["rawBundle"])), self.bundle)
            status, _ = plane.request("POST", "/v1/architectures/compile", body=manifest, token=VIEWER_TOKEN)
            self.assertEqual(status, 403)
            status, readiness = plane.request("POST", "/v1/runtime/validate", body=manifest, token=VIEWER_TOKEN)
            self.assertEqual(status, 200)
            self.assertFalse(readiness["ready"])
            plane.request("POST", "/v1/bundles", body=json.loads(compiled["rawBundle"]))
            status, context = plane.request("GET", f"/v1/bundles/{compiled['bundleDigest']}/approval-context")
            self.assertEqual(status, 200)
            self.assertEqual(context["statement"]["bundleDigest"], compiled["bundleDigest"])
            self.assertIsNone(context["statement"]["fromDigest"])
            self.assertEqual(len(context["trustedApprovers"]), 2)
            plane.api.credential_refs = frozenset({"model-reference"})
            status, runtime = plane.request("GET", "/v1/runtime/status")
            self.assertEqual(status, 200)
            self.assertEqual(runtime["credentialRefs"], ["model-reference"])
            self.assertIsNone(runtime["active"])
            invalid = json.loads(json.dumps(manifest))
            invalid["spec"]["nodes"][0]["annotations"] = {"interlock.runtime": {"kind": {}}}
            status, rejected = plane.request("POST", "/v1/architectures/compile", body=invalid)
            self.assertEqual(status, 200)
            self.assertFalse(rejected["deployable"])
            self.assertTrue(rejected["runtimeReadiness"]["nodes"][0]["problems"])
            status, _ = plane.request("POST", "/v1/architectures/compile", body=[])
            self.assertEqual(status, 400)

    def setUp(self):
        self.bundle_value = compile_bundle()
        self.bundle = DeploymentBundle.from_compile_output(self.bundle_value)

    def approval_body(self, store, approver: str, key_id: str, key: bytes, *, from_digest=None):
        approval = sign_deployment_approval(
            self.bundle,
            target_id=store.target_id, tenant_id=store.tenant_id,
            from_digest=from_digest,
            to_mode="ENFORCE",
            approver_id=approver,
            key_id=key_id,
            key=key,
        )
        return {
            "approverId": approval.approver_id,
            "keyId": approval.key_id,
            "signature": approval.signature,
        }

    def test_pending_signatures_survive_restart_and_policy_diff_names_the_changed_cap(self):
        with tempfile.TemporaryDirectory() as root:
            digest = self.bundle.bundle_digest
            with RunningControlPlane(root) as first:
                first.request("POST", "/v1/bundles", body=self.bundle_value)
                status, _ = first.request(
                    "POST",
                    f"/v1/bundles/{digest}/approvals",
                    body=self.approval_body(first.store, "security-lead", "key-one", KEY_ONE),
                )
                self.assertEqual(status, 202)
            with RunningControlPlane(root) as second:
                second.request(
                    "POST",
                    f"/v1/bundles/{digest}/approvals",
                    body=self.approval_body(second.store, "platform-lead", "key-two", KEY_TWO),
                )
                status, _ = second.request("POST", f"/v1/bundles/{digest}/promote", body={})
                self.assertEqual(status, 200)
                body = json.loads(json.dumps(self.bundle.body))
                body["architecture"]["spec"]["edges"][0]["policy"]["maxExportBytes"] = 4096
                candidate = DeploymentBundle(
                    self.bundle.architecture_id, self.bundle.version, canonical_digest(body), body
                )
                second.store.propose(candidate)
                encoded_digest = candidate.bundle_digest.replace(":", "%3A")
                status, difference = second.request("GET", f"/v1/bundles/{encoded_digest}/diff")
                self.assertEqual(difference["baseDigest"], digest)
                self.assertEqual(difference["changeCount"], 1)
                self.assertTrue(difference["changes"][0]["path"].endswith("/policy/maxExportBytes"))
                self.assertEqual(difference["changes"][0]["after"], 4096)

    def test_two_person_promotion_and_rollback_over_http(self):
        with tempfile.TemporaryDirectory() as tmp, RunningControlPlane(tmp) as plane:
            status, proposed = plane.request("POST", "/v1/bundles", body=self.bundle_value)
            self.assertEqual(status, 201)
            digest = proposed["bundleDigest"]
            status, difference = plane.request("GET", f"/v1/bundles/{digest}/diff", token=VIEWER_TOKEN)
            self.assertEqual(status, 200)
            self.assertIsNone(difference["baseDigest"])
            self.assertGreater(difference["changeCount"], 0)

            status, first = plane.request(
                "POST",
                f"/v1/bundles/{digest}/approvals",
                body=self.approval_body(plane.store, "security-lead", "key-one", KEY_ONE),
            )
            self.assertEqual((status, first["pendingApprovals"]), (202, 1))
            status, second = plane.request(
                "POST",
                f"/v1/bundles/{digest}/approvals",
                body=self.approval_body(plane.store, "platform-lead", "key-two", KEY_TWO),
            )
            self.assertEqual((status, second["pendingApprovals"]), (202, 2))

            status, promoted = plane.request("POST", f"/v1/bundles/{digest}/promote")
            self.assertEqual(status, 200)
            self.assertEqual(promoted["active"]["mode"], "ENFORCE")
            self.assertEqual(promoted["active"]["bundleDigest"], digest)

            status, state = plane.request("GET", "/v1/deploy/status", token=VIEWER_TOKEN)
            self.assertEqual(status, 200)
            self.assertEqual(state["active"]["bundleDigest"], digest)

            for approver, key_id, key in (
                ("security-lead", "key-one", KEY_ONE),
                ("platform-lead", "key-two", KEY_TWO),
            ):
                plane.request(
                    "POST",
                    f"/v1/bundles/{digest}/approvals",
                    body=self.approval_body(plane.store, approver, key_id, key, from_digest=digest),
                )
            status, rolled = plane.request("POST", "/v1/deploy/rollback", body={"targetDigest": digest})
            self.assertEqual(status, 200)
            self.assertEqual(rolled["active"]["bundleDigest"], digest)

    def test_rollback_cannot_activate_a_bundle_that_was_only_proposed(self):
        with tempfile.TemporaryDirectory() as tmp, RunningControlPlane(tmp) as plane:
            status, proposed = plane.request("POST", "/v1/bundles", body=self.bundle_value)
            self.assertEqual(status, 201)
            digest = proposed["bundleDigest"]
            for approver, key_id, key in (
                ("security-lead", "key-one", KEY_ONE),
                ("platform-lead", "key-two", KEY_TWO),
            ):
                plane.request(
                    "POST",
                    f"/v1/bundles/{digest}/approvals",
                    body=self.approval_body(plane.store, approver, key_id, key),
                )
            status, body = plane.request("POST", "/v1/deploy/rollback", body={"targetDigest": digest})
            self.assertEqual(status, 422)
            self.assertEqual(body["error"]["code"], "L1-STUDIO-ROLLBACK-TARGET-NOT-ACTIVE")

    def test_single_or_forged_approvals_cannot_promote(self):
        with tempfile.TemporaryDirectory() as tmp, RunningControlPlane(tmp) as plane:
            status, proposed = plane.request("POST", "/v1/bundles", body=self.bundle_value)
            digest = proposed["bundleDigest"]

            plane.request(
                "POST",
                f"/v1/bundles/{digest}/approvals",
                body=self.approval_body(plane.store, "security-lead", "key-one", KEY_ONE),
            )
            status, body = plane.request("POST", f"/v1/bundles/{digest}/promote")
            self.assertEqual(status, 422)
            self.assertEqual(body["error"]["code"], "L1-STUDIO-TWO-PERSON-APPROVAL-REQUIRED")

            forged = self.approval_body(plane.store, "mallory", "key-two", b"\x99" * 32)
            status, body = plane.request("POST", f"/v1/bundles/{digest}/approvals", body=forged)
            self.assertEqual(status, 422)
            self.assertEqual(body["error"]["code"], "L1-STUDIO-APPROVAL-SIGNATURE-INVALID")

    def test_scopes_gate_privileged_actions(self):
        with tempfile.TemporaryDirectory() as tmp, RunningControlPlane(tmp) as plane:
            status, body = plane.request("POST", "/v1/bundles", token=VIEWER_TOKEN, body=self.bundle_value)
            self.assertEqual(status, 403)
            self.assertEqual(body["error"]["code"], "CONTROL-SCOPE-DENIED")
            status, _ = plane.request("GET", "/v1/deploy/status", token="wrong-token")
            self.assertEqual(status, 401)

    def test_unknown_bundle_promotion_is_404(self):
        with tempfile.TemporaryDirectory() as tmp, RunningControlPlane(tmp) as plane:
            status, body = plane.request("POST", "/v1/bundles/sha256%3Aunknown/promote")
            self.assertIn(status, (404, 422))

    def test_project_permissions_cover_deployment_and_digest_bound_runs(self):
        with tempfile.TemporaryDirectory() as tmp, RunningControlPlane(tmp) as plane:
            digest = self.bundle.bundle_digest
            plane.store.propose(self.bundle)
            approvals = tuple(sign_deployment_approval(
                self.bundle, target_id=plane.store.target_id, tenant_id=plane.store.tenant_id,
                from_digest=None, to_mode="ENFORCE", approver_id=approver, key_id=key_id, key=key,
            ) for approver, key_id, key in (("security-lead", "key-one", KEY_ONE),
                                          ("platform-lead", "key-two", KEY_TWO)))
            plane.store.promote(digest, approvals, trusted_approvers=TRUSTED_APPROVERS)
            scopes = frozenset({"deploy:read", "deploy:propose", "deploy:approve", "deploy:promote",
                                "run:read", "run:create", "run:approve", "run:cancel", "run:prune"})
            plane.api.authenticator = StaticBearerAuthenticator.from_tokens({
                OPERATOR_TOKEN: LedgerAPIPrincipal("owner", "tenant-a", scopes),
                VIEWER_TOKEN: LedgerAPIPrincipal("member", "tenant-a", scopes),
            })
            plane.api.project_permissions = {
                "owner": {"*": frozenset({"read", "write", "deploy"})},
                "member": {"my-project": frozenset({"read", "write", "deploy"})},
            }
            # The display architectureId cannot override the immutable run bundle's project.
            run = {"id": "private-run", "architectureId": "my-project", "bundleDigest": digest}
            service = Mock()
            service.dispatcher = None
            service.get.return_value = run
            service.list.return_value = [run]
            plane.api.run_service = service
            before = plane.store.active()
            requests = [
                ("POST", "/v1/architectures/compile", self.bundle.body["architecture"]),
                ("POST", "/v1/runtime/validate", self.bundle.body["architecture"]),
                ("POST", "/v1/bundles", self.bundle_value),
                ("GET", f"/v1/bundles/{digest}/diff", None),
                ("GET", f"/v1/bundles/{digest}/approval-context", None),
                ("POST", f"/v1/bundles/{digest}/compare", {"input": {}, "baseDigest": digest}),
                ("POST", f"/v1/bundles/{digest}/approvals", {"approverId": "x", "keyId": "x", "signature": "x"}),
                ("POST", f"/v1/bundles/{digest}/promote", {}),
                ("POST", "/v1/deploy/rollback", {"targetDigest": digest}),
                ("POST", "/v1/runs", {"input": {}}),
                ("GET", "/v1/runs/private-run", None),
                ("GET", "/v1/runs/private-run/events", None),
                ("POST", "/v1/runs/private-run/resume", {}),
                ("POST", "/v1/runs/private-run/cancel", {}),
                ("POST", "/v1/runs/private-run/tasks/private-task/approve", {}),
                ("POST", "/v1/runs/prune", {"before": "2020-01-01T00:00:00Z"}),
            ]
            for method, path, body in requests:
                with self.subTest(path=path):
                    status, error = plane.request(method, path, token=VIEWER_TOKEN, body=body)
                    self.assertEqual(status, 403, error)
                    self.assertEqual(error["error"]["code"], "PROJECT-ACCESS-DENIED")
            self.assertEqual(plane.request("GET", "/v1/runs", token=VIEWER_TOKEN)[1]["runs"], [])
            self.assertEqual(plane.request("GET", "/v1/runs", token=OPERATOR_TOKEN)[1]["runs"], [run])
            runtime = plane.request("GET", "/v1/runtime/status", token=VIEWER_TOKEN)[1]
            self.assertIsNone(runtime["active"])
            self.assertIsNone(runtime["architecture"])
            self.assertEqual(plane.request("GET", "/v1/deploy/status", token=VIEWER_TOKEN)[1],
                             {"active": None, "history": []})
            self.assertEqual(plane.store.active(), before)
            plane.api.project_permissions["member"][self.bundle.architecture_id] = frozenset({"read", "deploy"})
            status, error = plane.request("POST", "/v1/runs", token=VIEWER_TOKEN,
                                          body={"input": {}, "traceId": "another-project-trace"})
            self.assertEqual(status, 403, error)
            self.assertEqual(error["error"]["code"], "PROJECT-TRACE-ID-RESTRICTED")
            service.create.assert_not_called()
            plane.api.project_permissions["member"][self.bundle.architecture_id] = frozenset({"deploy"})
            for path in ("/v1/runs", "/v1/runs/private-run/resume", "/v1/runs/private-run/cancel"):
                status, error = plane.request("POST", path, token=VIEWER_TOKEN, body={})
                self.assertEqual(status, 403, error)
                self.assertEqual(error["error"]["code"], "PROJECT-ACCESS-DENIED")
            del plane.api.project_permissions["member"][self.bundle.architecture_id]
            for operation in ("create", "resume", "cancel", "approve", "events", "prune"):
                getattr(service, operation).assert_not_called()

            body = json.loads(json.dumps(self.bundle.body))
            body["architectureId"] = "my-project"
            forged = {**body, "deployable": True, "bundleDigest": canonical_digest(body)}
            status, error = plane.request("POST", "/v1/bundles", token=VIEWER_TOKEN, body=forged)
            self.assertEqual(status, 400)
            self.assertEqual(error["error"]["code"], "PROJECT-BUNDLE-ID-MISMATCH")
            body["architecture"]["metadata"]["id"] = "my-project"
            own = {**body, "deployable": True, "bundleDigest": canonical_digest(body)}
            self.assertEqual(plane.request("POST", "/v1/bundles", token=VIEWER_TOKEN, body=own)[0], 201)
            # Own candidate cannot reveal another project's active baseline through diff/context.
            for suffix in ("diff", "approval-context"):
                self.assertEqual(plane.request("GET", f"/v1/bundles/{own['bundleDigest']}/{suffix}",
                                                token=VIEWER_TOKEN)[0], 403)
            plane.api.project_permissions["member"][self.bundle.architecture_id] = frozenset({"read"})
            self.assertEqual(plane.request("GET", f"/v1/bundles/{own['bundleDigest']}/approval-context",
                                            token=VIEWER_TOKEN)[0], 200)
            for path, payload in ((f"/v1/bundles/{own['bundleDigest']}/promote", {}),
                                  ("/v1/deploy/rollback", {"targetDigest": own["bundleDigest"]})):
                status, error = plane.request("POST", path, token=VIEWER_TOKEN, body=payload)
                self.assertEqual(status, 403, error)
                self.assertEqual(error["error"]["code"], "PROJECT-ACCESS-DENIED")
            self.assertEqual(plane.store.active(), before)

    def test_comparison_http_contract_preserves_host_state(self):
        with tempfile.TemporaryDirectory() as tmp, RunningControlPlane(tmp) as plane:
            local = compile_review_bundle(comparison_graph())
            self.assertEqual(plane.request("POST", "/v1/bundles", body=local)[0], 201)
            plane.store.propose(self.bundle)
            digest = local["bundleDigest"]
            request = {"input": {"name": "Ada"}, "baseDigest": None}
            before = (plane.store.active(), plane.store.history(), plane.store.approval_path().read_bytes())
            service = Mock()
            plane.api.run_service = service
            status, result = plane.request("POST", f"/v1/bundles/{digest}/compare", body=request)
            self.assertEqual(status, 200, result)
            self.assertEqual(result["candidate"]["tasks"]["transform"]["output"], {"name": "Ada"})
            self.assertIsNone(result["baseline"])
            self.assertEqual(result["targetId"], plane.store.target_id)
            self.assertEqual(plane.request("GET", f"/v1/bundles/{digest}/compare")[0], 404)
            self.assertEqual(plane.request("POST", f"/v1/bundles/{digest}/compare",
                                            token=VIEWER_TOKEN, body=request)[0], 403)
            self.assertEqual(plane.request("POST", f"/v1/bundles/{digest}/compare",
                                            body={**request, "baseDigest": "stale"})[0], 409)
            status, result = plane.request("POST", f"/v1/bundles/{self.bundle.bundle_digest}/compare", body=request)
            self.assertEqual(status, 422, result)
            self.assertEqual(result["error"]["code"], "COMPARISON-UNSUPPORTED")
            self.assertEqual((plane.store.active(), plane.store.history(), plane.store.approval_path().read_bytes()),
                             before)
            self.assertEqual(service.mock_calls, [])

    def test_legacy_pending_signatures_archive_while_active_survives_and_can_be_resigned(self):
        with tempfile.TemporaryDirectory() as tmp:
            digest = self.bundle.bundle_digest
            with RunningControlPlane(tmp) as plane:
                plane.store.propose(self.bundle)
                for identity, key_id, key in (("security-lead", "key-one", KEY_ONE),
                                              ("platform-lead", "key-two", KEY_TWO)):
                    self.assertEqual(plane.request("POST", f"/v1/bundles/{digest}/approvals",
                        body=self.approval_body(plane.store, identity, key_id, key))[0], 202)
                self.assertEqual(plane.request("POST", f"/v1/bundles/{digest}/promote", body={})[0], 200)
                active = plane.store.active()
                path = plane.store.approval_path()
            legacy = json.dumps({digest: [{"approver_id": "old", "key_id": "old", "signature": "old"}]}).encode()
            path.write_bytes(legacy)
            (Path(tmp) / "deploy" / "target.json").unlink()
            with RunningControlPlane(tmp) as restarted:
                self.assertEqual(restarted.store.active(), active)
                self.assertEqual(restarted.api._approvals, {})
                archives = list(path.parent.glob("interlock-legacy-approvals-*.json"))
                self.assertEqual(len(archives), 1)
                self.assertEqual(archives[0].read_bytes(), legacy)
                self.assertEqual(restarted.request("POST", f"/v1/bundles/{digest}/promote", body={})[0], 422)
                for identity, key_id, key in (("security-lead", "key-one", KEY_ONE),
                                              ("platform-lead", "key-two", KEY_TWO)):
                    self.assertEqual(restarted.request("POST", f"/v1/bundles/{digest}/approvals",
                        body=self.approval_body(restarted.store, identity, key_id, key, from_digest=digest))[0], 202)
                self.assertEqual(restarted.request("POST", f"/v1/bundles/{digest}/promote", body={})[0], 200)
            future = json.dumps({"version": 3, "futureData": "must survive"}).encode()
            path.write_bytes(future)
            with self.assertRaisesRegex(ValueError, "unsupported pending approval"):
                RunningControlPlane(tmp)
            self.assertEqual(path.read_bytes(), future)
            self.assertEqual(len(list(path.parent.glob("interlock-legacy-approvals-*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
