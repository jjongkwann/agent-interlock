"""End-to-end studio CLI: compile --shadow → propose → 2 approvals → promote → rollback."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent_interlock.__main__ import main

MANIFEST = Path(__file__).resolve().parent.parent / "examples" / "secure_multi_agent_architecture.json"

KEY_ONE = "11" * 32
KEY_TWO = "22" * 32


def run_cli(*argv: str) -> tuple[int, dict]:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = main(list(argv))
    output = buffer.getvalue()
    return code, json.loads(output) if output.strip() else {}


class StudioCLITests(unittest.TestCase):
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
            trusted.write_text(json.dumps({"key-one": KEY_ONE, "key-two": KEY_TWO}), encoding="utf-8")

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

            code, rolled = run_cli("studio", "rollback", digest, "--repo", str(repo))
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
            trusted.write_text(json.dumps({"key-one": KEY_ONE}), encoding="utf-8")
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
