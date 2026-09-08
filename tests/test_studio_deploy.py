"""Studio git-backed deployment: propose → two-person promote → rollback.

Drives a real git repository via subprocess against a temp dir, using a real
compile --shadow bundle from the example manifest.
"""

from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agent_interlock import (
    DeploymentBundle,
    GitBundleStore,
    PolicyMode,
    SigningBackendUnavailable,
    StudioDeploymentError,
    TrustedApprovalKey,
    deployed_architecture,
    ed25519_public_key_bytes,
    sign_deployment_approval,
)
from agent_interlock.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "secure_multi_agent_architecture.json"

KEY_A = b"studio-approver-key-a-0000000000"
KEY_B = b"studio-approver-key-b-1111111111"
try:
    TRUSTED_APPROVERS = {
        "key-a": TrustedApprovalKey("alice", ed25519_public_key_bytes(KEY_A)),
        "key-b": TrustedApprovalKey("bob", ed25519_public_key_bytes(KEY_B)),
    }
    CRYPTO_AVAILABLE = True
except SigningBackendUnavailable:
    TRUSTED_APPROVERS = {}
    CRYPTO_AVAILABLE = False


def compile_bundle() -> DeploymentBundle:
    out = io.StringIO()
    with redirect_stdout(out):
        code = main(["architecture", "compile", "--shadow", str(MANIFEST)])
    assert code == 0, "example manifest must compile to a deployable bundle"
    return DeploymentBundle.from_compile_output(json.loads(out.getvalue()))


@unittest.skipUnless(
    shutil.which("git") and CRYPTO_AVAILABLE,
    "git and the jwt extra are required for the studio deployment workflow",
)
class StudioDeploymentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="studio-deploy-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.store = GitBundleStore(self.dir)
        self.bundle = compile_bundle()

    def _approvals(self, from_digest, *pairs):
        return tuple(
            sign_deployment_approval(
                self.bundle,
                from_digest=from_digest,
                to_mode="ENFORCE",
                approver_id=approver,
                key_id=key_id,
                key={"key-a": KEY_A, "key-b": KEY_B}[key_id],
            )
            for approver, key_id in pairs
        )

    def test_empty_store_history_is_empty(self):
        self.assertEqual(self.store.history(), ())

    def test_propose_then_two_person_promote(self):
        self.store.propose(self.bundle)
        self.assertIsNone(self.store.active())
        approvals = self._approvals(None, ("alice", "key-a"), ("bob", "key-b"))
        self.store.promote(self.bundle.bundle_digest, approvals, trusted_approvers=TRUSTED_APPROVERS)
        active = self.store.active()
        self.assertEqual(active["mode"], "ENFORCE")
        self.assertEqual(active["bundleDigest"], self.bundle.bundle_digest)
        self.assertEqual(active["approvers"], ["alice", "bob"])
        # git log is the audit trail
        self.assertTrue(any("promote" in line for line in self.store.history()))

    def test_single_approver_is_rejected(self):
        self.store.propose(self.bundle)
        approvals = self._approvals(None, ("alice", "key-a"), ("alice", "key-a"))
        with self.assertRaises(StudioDeploymentError) as raised:
            self.store.promote(self.bundle.bundle_digest, approvals, trusted_approvers=TRUSTED_APPROVERS)
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-TWO-PERSON-APPROVAL-REQUIRED")
        self.assertIsNone(self.store.active())

    def test_forged_signature_is_rejected(self):
        self.store.propose(self.bundle)
        good = self._approvals(None, ("alice", "key-a"))[0]
        forged = good.__class__("bob", "key-b", good.signature)  # bob's key never signed this
        with self.assertRaises(StudioDeploymentError) as raised:
            self.store.promote(self.bundle.bundle_digest, (good, forged), trusted_approvers=TRUSTED_APPROVERS)
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-APPROVAL-SIGNATURE-INVALID")

    def test_two_identities_mapped_to_the_same_public_key_are_insufficient(self):
        self.store.propose(self.bundle)
        duplicated = {
            "key-a": TrustedApprovalKey("alice", ed25519_public_key_bytes(KEY_A)),
            "key-b": TrustedApprovalKey("bob", ed25519_public_key_bytes(KEY_A)),
        }
        approvals = tuple(
            sign_deployment_approval(
                self.bundle,
                from_digest=None,
                to_mode="ENFORCE",
                approver_id=approver,
                key_id=key_id,
                key=KEY_A,
            )
            for approver, key_id in (("alice", "key-a"), ("bob", "key-b"))
        )
        with self.assertRaises(StudioDeploymentError) as raised:
            self.store.promote(self.bundle.bundle_digest, approvals, trusted_approvers=duplicated)
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-TWO-PERSON-APPROVAL-REQUIRED")

    def test_promote_unknown_bundle_is_rejected(self):
        approvals = self._approvals(None, ("alice", "key-a"), ("bob", "key-b"))
        with self.assertRaises(StudioDeploymentError) as raised:
            self.store.promote("sha256:" + "0" * 64, approvals, trusted_approvers=TRUSTED_APPROVERS)
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-BUNDLE-UNKNOWN")

    def test_rollback_restores_a_previous_bundle(self):
        # First bundle promoted to ENFORCE.
        self.store.propose(self.bundle)
        self.store.promote(
            self.bundle.bundle_digest,
            self._approvals(None, ("alice", "key-a"), ("bob", "key-b")),
            trusted_approvers=TRUSTED_APPROVERS,
        )
        first_digest = self.bundle.bundle_digest

        # A second bundle (bump the manifest version) is proposed and promoted.
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest["metadata"]["version"] = str(manifest["metadata"]["version"]) + "-next"
        second = _compile_dict(manifest)
        self.store.propose(second)
        self.store.promote(
            second.bundle_digest,
            tuple(
                sign_deployment_approval(
                    second,
                    from_digest=first_digest,
                    to_mode="ENFORCE",
                    approver_id=approver,
                    key_id=key_id,
                    key={"key-a": KEY_A, "key-b": KEY_B}[key_id],
                )
                for approver, key_id in (("alice", "key-a"), ("bob", "key-b"))
            ),
            trusted_approvers=TRUSTED_APPROVERS,
        )
        self.assertEqual(self.store.active()["bundleDigest"], second.bundle_digest)

        # Rollback to the first, known-good bundle.
        rollback_approvals = self._approvals(
            second.bundle_digest,
            ("alice", "key-a"),
            ("bob", "key-b"),
        )
        self.store.rollback(
            first_digest,
            rollback_approvals,
            trusted_approvers=TRUSTED_APPROVERS,
        )
        active = self.store.active()
        self.assertEqual(active["bundleDigest"], first_digest)
        self.assertEqual(active["rolledBackFrom"], second.bundle_digest)

    def test_rollback_rejects_a_bundle_that_was_only_proposed(self):
        self.store.propose(self.bundle)
        approvals = self._approvals(None, ("alice", "key-a"), ("bob", "key-b"))
        with self.assertRaises(StudioDeploymentError) as raised:
            self.store.rollback(
                self.bundle.bundle_digest,
                approvals,
                trusted_approvers=TRUSTED_APPROVERS,
            )
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-ROLLBACK-TARGET-NOT-ACTIVE")

    def test_bundle_digest_tamper_is_rejected_at_parse(self):
        out = io.StringIO()
        with redirect_stdout(out):
            main(["architecture", "compile", "--shadow", str(MANIFEST)])
        value = json.loads(out.getvalue())
        value["bundleDigest"] = "sha256:" + "0" * 64
        with self.assertRaises(StudioDeploymentError) as raised:
            DeploymentBundle.from_compile_output(value)
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-BUNDLE-DIGEST-MISMATCH")


class DeployedArchitectureTests(unittest.TestCase):
    """D5: the deployment record's mode always wins over per-edge modes in the bundle body."""

    def test_applies_enforce_to_a_body_whose_edges_are_shadow(self):
        bundle = compile_bundle()  # --shadow: every edge in the body is already SHADOW
        edges = bundle.body["architecture"]["spec"]["edges"]
        self.assertTrue(all(edge["policy"]["mode"] == "SHADOW" for edge in edges))

        graph = deployed_architecture(bundle.body, "ENFORCE")
        self.assertTrue(graph.edges)
        self.assertTrue(all(edge.policy.mode == PolicyMode.ENFORCE for edge in graph.edges))

    def test_applies_shadow_to_a_body_whose_edges_are_enforce(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(["architecture", "compile", str(MANIFEST)])
        self.assertEqual(code, 0)
        body = json.loads(out.getvalue())
        edges = body["architecture"]["spec"]["edges"]
        self.assertTrue(all(edge["policy"]["mode"] == "ENFORCE" for edge in edges))

        graph = deployed_architecture(body, "SHADOW")
        self.assertTrue(graph.edges)
        self.assertTrue(all(edge.policy.mode == PolicyMode.SHADOW for edge in graph.edges))

    def test_missing_architecture_is_rejected(self):
        with self.assertRaises(StudioDeploymentError) as raised:
            deployed_architecture({"architectureId": "a", "version": "1"}, "ENFORCE")
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-BUNDLE-UNKNOWN")


def _compile_dict(manifest: dict) -> DeploymentBundle:
    import tempfile as _tempfile

    with _tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(manifest, handle)
        path = handle.name
    out = io.StringIO()
    with redirect_stdout(out):
        code = main(["architecture", "compile", "--shadow", path])
    assert code == 0
    return DeploymentBundle.from_compile_output(json.loads(out.getvalue()))


if __name__ == "__main__":
    unittest.main()
