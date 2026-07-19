"""Control plane HTTP flow: propose → approvals → two-person promote → rollback."""

import http.client
import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

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
from agent_interlock.studio_deploy import DeploymentBundle, GitBundleStore, sign_deployment_approval

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
        self.store = GitBundleStore(repo)
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
    def setUp(self):
        self.bundle_value = compile_bundle()
        self.bundle = DeploymentBundle.from_compile_output(self.bundle_value)

    def approval_body(self, approver: str, key_id: str, key: bytes, *, from_digest=None):
        approval = sign_deployment_approval(
            self.bundle,
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

    def test_two_person_promotion_and_rollback_over_http(self):
        with tempfile.TemporaryDirectory() as tmp, RunningControlPlane(tmp) as plane:
            status, proposed = plane.request("POST", "/v1/bundles", body=self.bundle_value)
            self.assertEqual(status, 201)
            digest = proposed["bundleDigest"]

            status, first = plane.request(
                "POST",
                f"/v1/bundles/{digest}/approvals",
                body=self.approval_body("security-lead", "key-one", KEY_ONE),
            )
            self.assertEqual((status, first["pendingApprovals"]), (202, 1))
            status, second = plane.request(
                "POST",
                f"/v1/bundles/{digest}/approvals",
                body=self.approval_body("platform-lead", "key-two", KEY_TWO),
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
                    body=self.approval_body(approver, key_id, key, from_digest=digest),
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
                    body=self.approval_body(approver, key_id, key),
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
                body=self.approval_body("security-lead", "key-one", KEY_ONE),
            )
            status, body = plane.request("POST", f"/v1/bundles/{digest}/promote")
            self.assertEqual(status, 422)
            self.assertEqual(body["error"]["code"], "L1-STUDIO-TWO-PERSON-APPROVAL-REQUIRED")

            forged = self.approval_body("mallory", "key-two", b"\x99" * 32)
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


if __name__ == "__main__":
    unittest.main()
