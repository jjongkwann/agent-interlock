"""End-to-end studio CLI: compile --shadow → propose → 2 approvals → promote → rollback."""

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent_interlock import SigningBackendUnavailable, ed25519_public_key_bytes
from agent_interlock.__main__ import main

MANIFEST = Path(__file__).resolve().parent.parent / "examples" / "secure_multi_agent_architecture.json"

KEY_ONE = "11" * 32
KEY_TWO = "22" * 32
try:
    PUBLIC_ONE = ed25519_public_key_bytes(bytes.fromhex(KEY_ONE)).hex()
    PUBLIC_TWO = ed25519_public_key_bytes(bytes.fromhex(KEY_TWO)).hex()
    CRYPTO_AVAILABLE = True
except SigningBackendUnavailable:
    PUBLIC_ONE = PUBLIC_TWO = ""
    CRYPTO_AVAILABLE = False


def run_cli(*argv: str) -> tuple[int, dict]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main(list(argv))
    output = buffer.getvalue()
    return code, json.loads(output) if output.strip() else {}


@unittest.skipUnless(
    shutil.which("git") and CRYPTO_AVAILABLE,
    "git and the jwt extra are required for the Studio CLI workflow",
)
class StudioCLITests(unittest.TestCase):
    def test_explicit_tenant_initializes_store_and_reopen_preserves_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "deployment"
            code, compiled = run_cli("architecture", "compile", str(MANIFEST), "--shadow")
            self.assertEqual(code, 0)
            bundle = Path(tmp) / "bundle.json"
            bundle.write_text(json.dumps(compiled))
            code, _ = run_cli("studio", "propose", str(bundle), "--repo", str(repo), "--tenant", "tenant-acme")
            self.assertEqual(code, 0)
            target_path = repo / "deploy/target.json"
            target = target_path.read_bytes()
            self.assertEqual(json.loads(target)["tenantId"], "tenant-acme")
            self.assertEqual(run_cli("studio", "status", "--repo", str(repo))[0], 0)
            with patch.dict("os.environ", {"INTERLOCK_APPROVAL_KEY": KEY_ONE}):
                code, approval = run_cli("studio", "approve", str(bundle), "--repo", str(repo),
                                         "--approver", "alice", "--key-id", "key-one")
            self.assertEqual(code, 0)
            self.assertEqual(approval["statement"]["tenantId"], "tenant-acme")
            self.assertEqual(approval["statement"]["targetId"], json.loads(target)["targetId"])
            error = io.StringIO()
            with redirect_stderr(error):
                code, _ = run_cli("studio", "status", "--repo", str(repo), "--tenant", "tenant-other")
            self.assertEqual(code, 2)
            self.assertIn("different tenant", error.getvalue())
            self.assertEqual(target_path.read_bytes(), target)

    def test_full_promotion_and_rollback_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "deploy-repo"

            code, bundle_value = run_cli("architecture", "compile", str(MANIFEST), "--shadow")
            self.assertEqual(code, 0)
            self.assertTrue(bundle_value["deployable"])
            bundle_path = root / "bundle.json"
            bundle_path.write_text(json.dumps(bundle_value), encoding="utf-8")

            code, proposed = run_cli("studio", "propose", str(bundle_path), "--repo", str(repo))
            self.assertEqual(code, 0)
            digest = proposed["bundleDigest"]
            self.assertEqual(digest, bundle_value["bundleDigest"])

            approvals = []
            for approver, key_id, key_hex in (
                ("security-lead", "key-one", KEY_ONE),
                ("platform-lead", "key-two", KEY_TWO),
            ):
                with patch.dict("os.environ", {"INTERLOCK_APPROVAL_KEY": key_hex}):
                    code, approval = run_cli(
                        "studio",
                        "approve",
                        str(bundle_path),
                        "--repo",
                        str(repo),
                        "--approver",
                        approver,
                        "--key-id",
                        key_id,
                    )
                self.assertEqual(code, 0)
                path = root / f"approval-{approver}.json"
                path.write_text(json.dumps(approval), encoding="utf-8")
                approvals.append(path)

            trusted = root / "trusted-keys.json"
            trusted.write_text(
                json.dumps(
                    {
                        "key-one": {"approverId": "security-lead", "publicKey": PUBLIC_ONE},
                        "key-two": {"approverId": "platform-lead", "publicKey": PUBLIC_TWO},
                    }
                ),
                encoding="utf-8",
            )

            code, promoted = run_cli(
                "studio",
                "promote",
                digest,
                "--repo",
                str(repo),
                "--approval",
                str(approvals[0]),
                "--approval",
                str(approvals[1]),
                "--trusted-keys",
                str(trusted),
            )
            self.assertEqual(code, 0)
            self.assertEqual(promoted["active"]["mode"], "ENFORCE")
            self.assertEqual(promoted["active"]["bundleDigest"], digest)
            self.assertEqual(promoted["active"]["approvers"], ["platform-lead", "security-lead"])

            code, status = run_cli("studio", "status", "--repo", str(repo))
            self.assertEqual(code, 0)
            self.assertEqual(status["active"]["bundleDigest"], digest)
            self.assertTrue(any("promote" in line for line in status["history"]))

            rollback_approvals = []
            for approver, key_id, key_hex in (
                ("security-lead", "key-one", KEY_ONE),
                ("platform-lead", "key-two", KEY_TWO),
            ):
                with patch.dict("os.environ", {"INTERLOCK_APPROVAL_KEY": key_hex}):
                    code, approval = run_cli(
                        "studio",
                        "approve",
                        str(bundle_path),
                        "--repo",
                        str(repo),
                        "--approver",
                        approver,
                        "--key-id",
                        key_id,
                    )
                self.assertEqual(code, 0)
                path = root / f"rollback-approval-{approver}.json"
                path.write_text(json.dumps(approval), encoding="utf-8")
                rollback_approvals.append(path)
            code, rolled = run_cli(
                "studio",
                "rollback",
                digest,
                "--repo",
                str(repo),
                "--approval",
                str(rollback_approvals[0]),
                "--approval",
                str(rollback_approvals[1]),
                "--trusted-keys",
                str(trusted),
            )
            self.assertEqual(code, 0)
            self.assertEqual(rolled["active"]["bundleDigest"], digest)

    def test_single_approval_cannot_promote(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "deploy-repo"
            code, bundle_value = run_cli("architecture", "compile", str(MANIFEST), "--shadow")
            bundle_path = root / "bundle.json"
            bundle_path.write_text(json.dumps(bundle_value), encoding="utf-8")
            code, proposed = run_cli("studio", "propose", str(bundle_path), "--repo", str(repo))
            with patch.dict("os.environ", {"INTERLOCK_APPROVAL_KEY": KEY_ONE}):
                code, approval = run_cli(
                    "studio",
                    "approve",
                    str(bundle_path),
                    "--repo",
                    str(repo),
                    "--approver",
                    "solo",
                    "--key-id",
                    "key-one",
                )
            approval_path = root / "approval.json"
            approval_path.write_text(json.dumps(approval), encoding="utf-8")
            trusted = root / "trusted-keys.json"
            trusted.write_text(
                json.dumps({"key-one": {"approverId": "solo", "publicKey": PUBLIC_ONE}}),
                encoding="utf-8",
            )
            code, _ = run_cli(
                "studio",
                "promote",
                proposed["bundleDigest"],
                "--repo",
                str(repo),
                "--approval",
                str(approval_path),
                "--approval",
                str(approval_path),
                "--trusted-keys",
                str(trusted),
            )
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
