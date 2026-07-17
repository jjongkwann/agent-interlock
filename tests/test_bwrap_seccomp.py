"""Bubblewrap seccomp child-denial: BPF structure + argv/attestation + Linux live.

The BPF program's byte structure and the backend's honest attestation are
checked on any platform. The `--seccomp` filter's *real* enforcement (fork
denied, threads allowed) can only run on Linux with bubblewrap, which is what
the CI live class exercises.
"""

from __future__ import annotations

import platform
import shutil
import struct
import subprocess
import sys
import unittest
from pathlib import Path

from agent_interlock import (
    AttestationVerifier,
    BubblewrapSandboxBackend,
    MCPStdioError,
    MCPStdioSandboxUnavailable,
    StdioArtifactPin,
    StdioSandboxProfile,
    build_no_subprocess_seccomp,
    sha256_file,
)
from agent_interlock.mcp_stdio import _SECCOMP_FD_TOKEN, _RET_ALLOW, _RET_ERRNO_EPERM

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "mcp_stdio_fixture_server.py"
RESOLVED_EXE = str(Path(sys.executable).resolve())
KEY = b"bwrap-seccomp-signing-key-0000000"
BACKEND_ID = "linux-bubblewrap-v1"


def launcher() -> StdioArtifactPin:
    return StdioArtifactPin(sys.executable, sha256_file(sys.executable))


def profile(*, allow_child_processes: bool):
    return StdioSandboxProfile(
        profile_id="bwrap-seccomp",
        executable=StdioArtifactPin(sys.executable, sha256_file(sys.executable)),
        arguments=(str(FIXTURE), "normal", "-", "-"),
        additional_artifacts=(StdioArtifactPin(str(FIXTURE), sha256_file(str(FIXTURE))),),
        working_directory=str(ROOT),
        read_only_paths=(str(FIXTURE),),
        allow_child_processes=allow_child_processes,
    )


def seccomp_backend(machine="x86_64"):
    return BubblewrapSandboxBackend(
        launcher=launcher(), signing_key=KEY, seccomp_child_denial=True, machine=machine
    )


def unpack(program: bytes):
    return [struct.unpack("<HBBI", program[i : i + 8]) for i in range(0, len(program), 8)]


def simulate(program: bytes, nr: int, arch: int, arg0: int) -> int:
    """Tiny classic-BPF interpreter for our seccomp subset — validates that the
    jump offsets are correct without needing a Linux kernel."""
    instructions = unpack(program)
    memory = {0: nr, 4: arch, 16: arg0 & 0xFFFFFFFF}
    accumulator = 0
    pc = 0
    for _ in range(1000):
        code, jt, jf, k = instructions[pc]
        if code == 0x20:  # BPF_LD | BPF_W | BPF_ABS
            accumulator = memory.get(k, 0)
            pc += 1
        elif code == 0x54:  # BPF_ALU | BPF_AND | BPF_K
            accumulator &= k
            pc += 1
        elif code == 0x15:  # BPF_JMP | BPF_JEQ | BPF_K
            pc += 1 + (jt if accumulator == k else jf)
        elif code == 0x06:  # BPF_RET | BPF_K
            return k
        else:  # pragma: no cover
            raise AssertionError(f"unexpected opcode {code:#x}")
    raise AssertionError("filter did not return")


_X86_64 = 0xC000003E
_AARCH64 = 0xC00000B7
_KILL = 0x80000000
_CLONE_THREAD = 0x00010000


class SeccompBpfStructureTests(unittest.TestCase):
    def test_program_is_well_formed_sock_filter_array(self):
        program = build_no_subprocess_seccomp("x86_64")
        self.assertEqual(len(program) % 8, 0)
        instructions = unpack(program)
        ks = [k for _, _, _, k in instructions]
        self.assertIn(0xC000003E, ks)  # AUDIT_ARCH_X86_64 guard
        self.assertIn(57, ks)  # fork
        self.assertIn(58, ks)  # vfork
        self.assertIn(435, ks)  # clone3
        self.assertIn(56, ks)  # clone (flag-checked)
        self.assertIn(0x00010000, ks)  # CLONE_THREAD mask
        self.assertIn(_RET_ERRNO_EPERM, ks)
        self.assertIn(_RET_ALLOW, ks)

    def test_aarch64_uses_clone_not_fork(self):
        program = build_no_subprocess_seccomp("aarch64")
        ks = [k for _, _, _, k in unpack(program)]
        self.assertIn(0xC00000B7, ks)  # AUDIT_ARCH_AARCH64
        self.assertIn(220, ks)  # clone
        self.assertIn(435, ks)  # clone3
        self.assertNotIn(57, ks)  # aarch64 has no fork syscall

    def test_unknown_architecture_fails_closed(self):
        with self.assertRaises(MCPStdioSandboxUnavailable):
            build_no_subprocess_seccomp("s390x")

    def test_terminal_instruction_allows_by_default(self):
        # A non-process syscall must reach an ALLOW return, never fall into EPERM.
        instructions = unpack(build_no_subprocess_seccomp("x86_64"))
        self.assertEqual(instructions[-1][3], _RET_ALLOW)

    def test_x86_64_filter_decisions_are_correct(self):
        program = build_no_subprocess_seccomp("x86_64")
        self.assertEqual(simulate(program, 57, 0xDEAD, 0), _KILL)  # wrong arch
        for nr in (57, 58, 435, 56):  # fork, vfork, clone3, clone(process)
            self.assertEqual(simulate(program, nr, _X86_64, 0), _RET_ERRNO_EPERM)
        self.assertEqual(simulate(program, 56, _X86_64, _CLONE_THREAD), _RET_ALLOW)  # thread
        for nr in (0, 59):  # read, execve must run
            self.assertEqual(simulate(program, nr, _X86_64, 0), _RET_ALLOW)

    def test_aarch64_filter_decisions_are_correct(self):
        program = build_no_subprocess_seccomp("aarch64")
        for nr in (220, 435):  # clone(process), clone3
            self.assertEqual(simulate(program, nr, _AARCH64, 0), _RET_ERRNO_EPERM)
        self.assertEqual(simulate(program, 220, _AARCH64, _CLONE_THREAD), _RET_ALLOW)  # thread
        self.assertEqual(simulate(program, 63, _AARCH64, 0), _RET_ALLOW)  # read
        self.assertEqual(simulate(program, 220, _X86_64, 0), _KILL)  # wrong arch


class SeccompBackendHonestyTests(unittest.TestCase):
    def test_child_bit_true_only_with_seccomp_and_argv_carries_token(self):
        plan = seccomp_backend().prepare(profile(allow_child_processes=False))
        self.assertTrue(plan.attestation.child_process_restricted)
        self.assertIn("--seccomp", plan.argv)
        self.assertIn(_SECCOMP_FD_TOKEN, plan.argv)
        self.assertTrue(plan.seccomp_program)
        self.assertIn("seccomp=sha256:", plan.attestation.evidence_reference)
        self.assertTrue(AttestationVerifier({BACKEND_ID: KEY}).verify(plan.attestation))

    def test_child_allowed_uses_no_seccomp_and_bit_false(self):
        plan = seccomp_backend().prepare(profile(allow_child_processes=True))
        self.assertFalse(plan.attestation.child_process_restricted)
        self.assertNotIn("--seccomp", plan.argv)
        self.assertEqual(plan.seccomp_program, b"")

    def test_without_seccomp_flag_child_denial_still_refused(self):
        plain = BubblewrapSandboxBackend(launcher=launcher(), signing_key=KEY)
        with self.assertRaises(MCPStdioSandboxUnavailable):
            plain.prepare(profile(allow_child_processes=False))

    def test_unknown_arch_refuses_before_signing(self):
        with self.assertRaises(MCPStdioSandboxUnavailable):
            seccomp_backend(machine="s390x").prepare(profile(allow_child_processes=False))


@unittest.skipUnless(sys.platform == "darwin", "python-seccomp probe is a macOS-side sanity check")
class SeccompProgramNativeProbeTests(unittest.TestCase):
    """A cheap structural probe that the built bytes match what the kernel ABI
    expects (fixed 8-byte records, arch guard first). Not enforcement."""

    def test_first_instruction_loads_arch_word(self):
        code, jt, jf, k = unpack(build_no_subprocess_seccomp("x86_64"))[0]
        self.assertEqual(code, 0x20)  # BPF_LD | BPF_W | BPF_ABS
        self.assertEqual(k, 4)  # seccomp_data.arch offset


@unittest.skipUnless(
    sys.platform.startswith("linux") and shutil.which("bwrap") is not None,
    "Linux with bubblewrap is required for live seccomp enforcement",
)
class BubblewrapSeccompLiveTests(unittest.TestCase):
    """Runs the real bwrap+seccomp argv; proves fork denied, threads allowed."""

    @classmethod
    def setUpClass(cls):
        cls.backend = BubblewrapSandboxBackend(
            launcher=StdioArtifactPin(shutil.which("bwrap"), sha256_file(shutil.which("bwrap"))),
            signing_key=KEY,
            seccomp_child_denial=True,
        )

    def _run(self, code: str):
        machine = platform.machine()
        program = build_no_subprocess_seccomp(machine)
        # Build a minimal bwrap argv directly for a -c probe; reuse the backend's
        # confinement flags but run python with inline code.
        prof = profile(allow_child_processes=False)
        plan = self.backend.prepare(prof)
        import os

        fd = os.memfd_create("probe-seccomp", 0)
        os.write(fd, program)
        os.lseek(fd, 0, os.SEEK_SET)
        os.set_inheritable(fd, True)
        argv = [str(fd) if t == _SECCOMP_FD_TOKEN else t for t in plan.argv]
        # replace the fixture command tail with an inline python probe
        sep = argv.index("--")
        argv = argv[: sep + 1] + [RESOLVED_EXE, "-c", code]
        try:
            return subprocess.run(argv, capture_output=True, text=True, timeout=30, pass_fds=(fd,))
        finally:
            os.close(fd)

    def test_thread_is_allowed(self):
        result = self._run(
            "import threading\n"
            "done = []\n"
            "t = threading.Thread(target=lambda: done.append(1)); t.start(); t.join()\n"
            "print('thread-ok' if done == [1] else 'thread-bad')\n"
        )
        self.assertIn("thread-ok", result.stdout)

    def test_fork_is_denied(self):
        result = self._run(
            "import os\n"
            "try:\n"
            "    os.fork(); print('LEAKED')\n"
            "except OSError:\n"
            "    print('fork-denied')\n"
        )
        self.assertIn("fork-denied", result.stdout)

    def test_subprocess_is_denied(self):
        result = self._run(
            "import subprocess\n"
            "try:\n"
            "    subprocess.run(['/bin/true']); print('LEAKED')\n"
            "except OSError:\n"
            "    print('spawn-denied')\n"
        )
        self.assertIn("spawn-denied", result.stdout)


if __name__ == "__main__":
    unittest.main()
