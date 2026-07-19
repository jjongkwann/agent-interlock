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
    StudioDeploymentError,
    sign_deployment_approval,
)
from agent_interlock.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "secure_multi_agent_architecture.json"

KEY_A = b"studio-approver-key-a-0000000000"
KEY_B = b"studio-approver-key-b-1111111111"
TRUSTED_KEYS = {"key-a": KEY_A, "key-b": KEY_B}


def compile_bundle() -> DeploymentBundle:
    out = io.StringIO()
    with redirect_stdout(out):
        code = main(["architecture", "compile", "--shadow", str(MANIFEST)])
    assert code == 0, "example manifest must compile to a deployable bundle"
    return DeploymentBundle.from_compile_output(json.loads(out.getvalue()))


@unittest.skipUnless(shutil.which("git"), "git is required for the studio deployment workflow")
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
                key=TRUSTED_KEYS[key_id],
            )
            for approver, key_id in pairs
        )

    def test_propose_then_two_person_promote(self):
        self.store.propose(self.bundle)
        self.assertIsNone(self.store.active())
        approvals = self._approvals(None, ("alice", "key-a"), ("bob", "key-b"))
        self.store.promote(self.bundle.bundle_digest, approvals, trusted_keys=TRUSTED_KEYS)
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
            self.store.promote(self.bundle.bundle_digest, approvals, trusted_keys=TRUSTED_KEYS)
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-TWO-PERSON-APPROVAL-REQUIRED")
        self.assertIsNone(self.store.active())

    def test_forged_signature_is_rejected(self):
        self.store.propose(self.bundle)
        good = self._approvals(None, ("alice", "key-a"))[0]
        forged = good.__class__("bob", "key-b", good.signature)  # bob's key never signed this
        with self.assertRaises(StudioDeploymentError) as raised:
            self.store.promote(self.bundle.bundle_digest, (good, forged), trusted_keys=TRUSTED_KEYS)
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-APPROVAL-SIGNATURE-INVALID")

    def test_promote_unknown_bundle_is_rejected(self):
        approvals = self._approvals(None, ("alice", "key-a"), ("bob", "key-b"))
        with self.assertRaises(StudioDeploymentError) as raised:
            self.store.promote("sha256:" + "0" * 64, approvals, trusted_keys=TRUSTED_KEYS)
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-BUNDLE-UNKNOWN")

    def test_rollback_restores_a_previous_bundle(self):
        # First bundle promoted to ENFORCE.
        self.store.propose(self.bundle)
        self.store.promote(
            self.bundle.bundle_digest,
            self._approvals(None, ("alice", "key-a"), ("bob", "key-b")),
            trusted_keys=TRUSTED_KEYS,
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
                    key=TRUSTED_KEYS[key_id],
                )
                for approver, key_id in (("alice", "key-a"), ("bob", "key-b"))
            ),
            trusted_keys=TRUSTED_KEYS,
        )
        self.assertEqual(self.store.active()["bundleDigest"], second.bundle_digest)

        # Rollback to the first, known-good bundle.
        self.store.rollback(first_digest)
        active = self.store.active()
        self.assertEqual(active["bundleDigest"], first_digest)
        self.assertEqual(active["rolledBackFrom"], second.bundle_digest)

    def test_bundle_digest_tamper_is_rejected_at_parse(self):
        out = io.StringIO()
        with redirect_stdout(out):
            main(["architecture", "compile", "--shadow", str(MANIFEST)])
        value = json.loads(out.getvalue())
        value["bundleDigest"] = "sha256:" + "0" * 64
        with self.assertRaises(StudioDeploymentError) as raised:
            DeploymentBundle.from_compile_output(value)
        self.assertEqual(raised.exception.reason_code, "L1-STUDIO-BUNDLE-DIGEST-MISMATCH")


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
