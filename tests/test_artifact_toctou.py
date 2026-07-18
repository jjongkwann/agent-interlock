"""FD-based artifact verification closes the check-to-exec TOCTOU window.

The digest is verified over a single open fd (not a re-opened path), so the
verified inode is fixed for the fd's lifetime. On hosts with /proc/self/fd the
client executes that fd, so the exec'd inode equals the verified one. These
tests cover the fd-verify helper (any platform) and that every backend marks
argv[0] for fd-execution.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

from agent_interlock import (
    BubblewrapSandboxBackend,
    DirectTestSandboxBackend,
    MCPStdioError,
    SeatbeltSandboxBackend,
    StdioArtifactPin,
    StdioSandboxProfile,
    sha256_file,
)
from agent_interlock.mcp_stdio import _FD_EXEC_AVAILABLE, _open_verified_artifact, _verify_artifact

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "mcp_stdio_fixture_server.py"
SCRATCH = Path(os.environ.get("TMPDIR", "/tmp"))
KEY = b"toctou-sandbox-signing-key-000000"


class FdVerifyHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = SCRATCH / f"toctou-artifact-{os.getpid()}-{id(self)}.bin"
        self.path.write_bytes(b"trusted-artifact-bytes")
        self.addCleanup(lambda: self.path.exists() and self.path.unlink())
        self.pin = StdioArtifactPin(str(self.path), sha256_file(str(self.path)))

    def test_returns_open_fd_for_a_matching_artifact(self):
        fd = _open_verified_artifact(self.pin)
        try:
            self.assertGreaterEqual(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            self.assertEqual(os.read(fd, 4096), b"trusted-artifact-bytes")
        finally:
            os.close(fd)

    def test_tampered_bytes_are_rejected(self):
        pin = StdioArtifactPin(str(self.path), "sha256:" + "0" * 64)
        with self.assertRaises(MCPStdioError) as raised:
            _open_verified_artifact(pin)
        self.assertEqual(raised.exception.reason_code, "L1-M4-ARTIFACT-DIGEST-MISMATCH")

    def test_swap_after_pinning_is_caught(self):
        # Simulate the classic TOCTOU: the file is replaced after it was pinned.
        self.path.write_bytes(b"attacker-swapped-bytes")
        with self.assertRaises(MCPStdioError) as raised:
            _open_verified_artifact(self.pin)
        self.assertEqual(raised.exception.reason_code, "L1-M4-ARTIFACT-DIGEST-MISMATCH")

    def test_non_regular_file_is_rejected(self):
        fifo = SCRATCH / f"toctou-fifo-{os.getpid()}"
        if fifo.exists():
            fifo.unlink()
        os.mkfifo(fifo)
        self.addCleanup(lambda: fifo.exists() and fifo.unlink())
        # A non-regular file is rejected at pin construction (regular-file guard).
        with self.assertRaises(ValueError):
            StdioArtifactPin(str(fifo), "sha256:" + "0" * 64)

    def test_verify_artifact_does_not_leak_fds(self):
        fd_dir = "/dev/fd" if os.path.isdir("/dev/fd") else "/proc/self/fd"
        if not os.path.isdir(fd_dir):
            self.skipTest("no fd directory to observe on this host")
        before = len(os.listdir(fd_dir))
        for _ in range(50):
            _verify_artifact(self.pin)
        self.assertLessEqual(len(os.listdir(fd_dir)), before + 2)


def _profile(**kw):
    return StdioSandboxProfile(
        profile_id="toctou",
        executable=StdioArtifactPin(sys.executable, sha256_file(sys.executable)),
        arguments=(str(FIXTURE), "normal", "-", "-"),
        additional_artifacts=(StdioArtifactPin(str(FIXTURE), sha256_file(str(FIXTURE))),),
        working_directory=str(ROOT),
        read_only_paths=(str(FIXTURE),),
        **kw,
    )


class PlanMarksArgv0ForFdExecTests(unittest.TestCase):
    def test_direct_backend_pins_executable_digest(self):
        plan = DirectTestSandboxBackend().prepare(_profile(allow_unenforced_test_mode=True))
        self.assertEqual(plan.executable_digest, sha256_file(sys.executable))
        self.assertEqual(plan.argv[0], plan.argv[0])  # argv[0] is the pinned executable

    def test_bubblewrap_pins_launcher_digest(self):
        launcher = StdioArtifactPin(sys.executable, sha256_file(sys.executable))
        plan = BubblewrapSandboxBackend(launcher=launcher, signing_key=KEY).prepare(
            _profile(allow_child_processes=True)
        )
        self.assertEqual(plan.executable_digest, launcher.digest)
        self.assertEqual(plan.argv[0], launcher.path)

    def test_seatbelt_pins_launcher_digest(self):
        launcher = StdioArtifactPin(sys.executable, sha256_file(sys.executable))
        plan = SeatbeltSandboxBackend(launcher=launcher, signing_key=KEY).prepare(_profile())
        self.assertEqual(plan.executable_digest, launcher.digest)


class FdExecPlatformTests(unittest.TestCase):
    def test_fd_exec_availability_matches_proc(self):
        self.assertEqual(_FD_EXEC_AVAILABLE, os.path.isdir("/proc/self/fd"))


if __name__ == "__main__":
    unittest.main()
