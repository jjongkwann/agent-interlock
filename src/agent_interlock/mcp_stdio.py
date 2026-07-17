"""MCP stdio transport with fail-closed sandbox attestation and process limits."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import signal
import stat
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol

from .canonical import canonical_digest, raw_digest
from .mcp_transport import MCP_PROTOCOL_VERSION, MCPServerProfile
from .security import contains_secret, sanitize_secrets
from .signing import sign_canonical, verify_canonical


_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DANGEROUS_ENV = re.compile(
    r"(?i)^(?:.*(?:TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|AUTHORIZATION).*$|"
    r"PATH|PYTHONPATH|PYTHONHOME|NODE_OPTIONS|RUBYOPT|PERL5OPT|BASH_ENV|ENV|SHELLOPTS|"
    r"LD_PRELOAD|LD_LIBRARY_PATH|DYLD_.*|GIT_.*|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)$"
)
_SHELL_EXECUTABLES = frozenset(
    {"sh", "bash", "zsh", "fish", "dash", "ksh", "cmd", "cmd.exe", "powershell", "pwsh"}
)
_EOF = object()


class MCPStdioError(RuntimeError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class MCPStdioSandboxUnavailable(MCPStdioError):
    def __init__(self, message: str = "an enforcing stdio sandbox backend is required") -> None:
        super().__init__("MCP-STDIO-SANDBOX-UNAVAILABLE", message)


@dataclass(frozen=True, slots=True)
class StdioArtifactPin:
    path: str
    digest: str

    def __post_init__(self) -> None:
        if not _SHA256_RE.fullmatch(self.digest):
            raise ValueError("artifact digest must be lowercase sha256")
        resolved = _resolved_regular_file(self.path)
        object.__setattr__(self, "path", resolved)


@dataclass(frozen=True, slots=True)
class StdioSandboxProfile:
    profile_id: str
    executable: StdioArtifactPin
    arguments: tuple[str, ...] = ()
    additional_artifacts: tuple[StdioArtifactPin, ...] = ()
    working_directory: str = "/"
    environment: Mapping[str, str] = field(default_factory=dict, repr=False)
    read_only_paths: tuple[str, ...] = ()
    writable_paths: tuple[str, ...] = ()
    allow_network: bool = False
    allow_child_processes: bool = False
    allow_shell_executable: bool = False
    allow_unenforced_test_mode: bool = False
    request_timeout_seconds: float = 10.0
    termination_grace_seconds: float = 0.5
    max_message_bytes: int = 1_048_576
    max_stderr_bytes: int = 65_536
    max_pending_messages: int = 128

    def __post_init__(self) -> None:
        if not self.profile_id:
            raise ValueError("stdio sandbox profile id is required")
        if Path(self.executable.path).name.casefold() in _SHELL_EXECUTABLES and not self.allow_shell_executable:
            raise ValueError("shell executables are denied by default")
        _validate_arguments(self.arguments)
        if len({item.path for item in self.additional_artifacts}) != len(self.additional_artifacts):
            raise ValueError("additional artifact paths must be unique")
        working_directory = _resolved_directory(self.working_directory)
        read_only = tuple(_resolved_existing_path(item) for item in self.read_only_paths)
        writable = tuple(_resolved_directory(item) for item in self.writable_paths)
        if any(_paths_overlap(left, right) for left in read_only for right in writable):
            raise ValueError("sandbox paths cannot be both read-only and writable")
        environment = _validated_environment(self.environment)
        pinned_paths = {self.executable.path, *(item.path for item in self.additional_artifacts)}
        for argument in self.arguments:
            candidate = Path(argument) if Path(argument).is_absolute() else Path(working_directory, argument)
            if candidate.exists() and candidate.is_file():
                resolved_argument = str(candidate.resolve(strict=True))
                if resolved_argument not in pinned_paths:
                    raise ValueError("existing file arguments must have an approved artifact digest")
        if (
            self.request_timeout_seconds <= 0
            or self.termination_grace_seconds < 0
            or self.max_message_bytes <= 0
            or self.max_stderr_bytes <= 0
            or self.max_pending_messages <= 0
        ):
            raise ValueError("stdio process and message limits must be positive")
        object.__setattr__(self, "working_directory", working_directory)
        object.__setattr__(self, "read_only_paths", read_only)
        object.__setattr__(self, "writable_paths", writable)
        object.__setattr__(self, "environment", MappingProxyType(environment))

    @property
    def command(self) -> tuple[str, ...]:
        return self.executable.path, *self.arguments

    @property
    def profile_digest(self) -> str:
        return canonical_digest(
            {
                "profileId": self.profile_id,
                "executable": {"path": self.executable.path, "digest": self.executable.digest},
                "arguments": list(self.arguments),
                "additionalArtifacts": [
                    {"path": item.path, "digest": item.digest}
                    for item in self.additional_artifacts
                ],
                "workingDirectory": self.working_directory,
                "environment": dict(self.environment),
                "readOnlyPaths": list(self.read_only_paths),
                "writablePaths": list(self.writable_paths),
                "allowNetwork": self.allow_network,
                "allowChildProcesses": self.allow_child_processes,
                "allowShellExecutable": self.allow_shell_executable,
                "allowUnenforcedTestMode": self.allow_unenforced_test_mode,
                "limits": {
                    "requestTimeoutSeconds": self.request_timeout_seconds,
                    "terminationGraceSeconds": self.termination_grace_seconds,
                    "maxMessageBytes": self.max_message_bytes,
                    "maxStderrBytes": self.max_stderr_bytes,
                    "maxPendingMessages": self.max_pending_messages,
                },
            }
        )

    @property
    def artifact_set_digest(self) -> str:
        return canonical_digest(
            [
                {"path": item.path, "digest": item.digest}
                for item in (self.executable, *self.additional_artifacts)
            ]
        )


@dataclass(frozen=True, slots=True)
class SandboxAttestation:
    backend_id: str
    evidence_reference: str
    profile_digest: str
    artifact_set_digest: str
    filesystem_restricted: bool
    network_restricted: bool
    child_process_restricted: bool
    signature: str = ""


def _attestation_body(attestation: SandboxAttestation) -> dict[str, Any]:
    """Canonical fields a signature covers (everything except the signature)."""
    return {
        "backendId": attestation.backend_id,
        "evidenceReference": attestation.evidence_reference,
        "profileDigest": attestation.profile_digest,
        "artifactSetDigest": attestation.artifact_set_digest,
        "filesystemRestricted": attestation.filesystem_restricted,
        "networkRestricted": attestation.network_restricted,
        "childProcessRestricted": attestation.child_process_restricted,
    }


def sign_attestation(attestation: SandboxAttestation, key: bytes) -> SandboxAttestation:
    """Return a copy of the attestation carrying a keyed signature over its claims."""
    return replace(attestation, signature=sign_canonical(_attestation_body(attestation), key))


class AttestationVerifier:
    """Trusts a backend's self-asserted restriction bits only under a valid signature.

    Keys are held per backend id: an attestation is trusted only if its named
    backend has a configured key and the signature over the claims verifies.
    """

    __slots__ = ("_keys",)

    def __init__(self, keys: Mapping[str, bytes]) -> None:
        self._keys = {backend_id: key for backend_id, key in keys.items() if key}
        if not self._keys:
            raise ValueError("at least one trusted backend key is required")

    def verify(self, attestation: SandboxAttestation) -> bool:
        key = self._keys.get(attestation.backend_id)
        if not key or not attestation.signature:
            return False
        return verify_canonical(_attestation_body(attestation), attestation.signature, key)


@dataclass(frozen=True, slots=True)
class SandboxLaunchPlan:
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    working_directory: str
    attestation: SandboxAttestation


class StdioSandboxBackend(Protocol):
    def prepare(self, profile: StdioSandboxProfile) -> SandboxLaunchPlan: ...


class DenyUnisolatedSandboxBackend:
    def prepare(self, profile: StdioSandboxProfile) -> SandboxLaunchPlan:
        raise MCPStdioSandboxUnavailable()


class DirectTestSandboxBackend:
    """Explicitly unenforced launcher; accepted only by a test-mode profile."""

    def prepare(self, profile: StdioSandboxProfile) -> SandboxLaunchPlan:
        if not profile.allow_unenforced_test_mode:
            raise MCPStdioSandboxUnavailable("direct process launch is test-only")
        return SandboxLaunchPlan(
            argv=profile.command,
            environment=profile.environment,
            working_directory=profile.working_directory,
            attestation=SandboxAttestation(
                backend_id="test-only-unenforced",
                evidence_reference="test-only:no-os-isolation",
                profile_digest=profile.profile_digest,
                artifact_set_digest=profile.artifact_set_digest,
                filesystem_restricted=False,
                network_restricted=False,
                child_process_restricted=False,
            ),
        )


@dataclass(frozen=True, slots=True)
class AttestedExternalSandboxBackend:
    """Pinned adapter for an operator-managed sandbox/container launcher."""

    launcher: StdioArtifactPin
    approved_profile_digest: str
    fixed_arguments: tuple[str, ...]
    backend_id: str
    evidence_reference: str
    filesystem_restricted: bool
    network_restricted: bool
    child_process_restricted: bool
    signing_key: bytes | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if not self.backend_id or not self.evidence_reference:
            raise ValueError("sandbox backend identity and evidence reference are required")
        if not self.approved_profile_digest.startswith("sha256:"):
            raise ValueError("approved sandbox profile digest is required")
        _validate_arguments(self.fixed_arguments)

    def prepare(self, profile: StdioSandboxProfile) -> SandboxLaunchPlan:
        _verify_artifact(self.launcher)
        if profile.profile_digest != self.approved_profile_digest:
            raise MCPStdioError(
                "MCP-STDIO-SANDBOX-PROFILE-MISMATCH",
                "sandbox backend is not approved for this profile",
            )
        attestation = SandboxAttestation(
            backend_id=self.backend_id,
            evidence_reference=self.evidence_reference,
            profile_digest=profile.profile_digest,
            artifact_set_digest=profile.artifact_set_digest,
            filesystem_restricted=self.filesystem_restricted,
            network_restricted=self.network_restricted,
            child_process_restricted=self.child_process_restricted,
        )
        if self.signing_key:
            attestation = sign_attestation(attestation, self.signing_key)
        return SandboxLaunchPlan(
            argv=(self.launcher.path, *self.fixed_arguments, "--", *profile.command),
            environment=profile.environment,
            working_directory=profile.working_directory,
            attestation=attestation,
        )


_UNSAFE_SANDBOX_MOUNTS = frozenset({"/", "/proc", "/dev", "/sys", "/run", "/tmp", "/home"})


@dataclass(frozen=True, slots=True)
class BubblewrapSandboxBackend:
    """Linux bubblewrap backend that attests only what its argv actually enforces.

    Enforces a private empty root with deny-by-default bind mounts (filesystem)
    and an isolated network namespace (network). It does NOT prevent the target
    from forking/exec'ing children — bwrap cannot without a seccomp filter, which
    the current launch contract can't carry — so it attests child_process as
    False and REFUSES a profile that denies child processes rather than sign a
    false claim. The pinned bwrap launcher is re-verified before each plan.
    """

    launcher: StdioArtifactPin
    signing_key: bytes = field(repr=False)
    disable_userns: bool = True

    def __post_init__(self) -> None:
        if not self.signing_key:
            raise ValueError("bubblewrap sandbox backend requires a non-empty signing key")

    def prepare(self, profile: StdioSandboxProfile) -> SandboxLaunchPlan:
        _verify_artifact(self.launcher)
        if not profile.allow_child_processes:
            raise MCPStdioSandboxUnavailable(
                "bubblewrap cannot honestly restrict child processes; profile must allow_child_processes"
            )
        for path in (*profile.read_only_paths, *profile.writable_paths):
            if (path.rstrip("/") or "/") in _UNSAFE_SANDBOX_MOUNTS:
                raise MCPStdioError(
                    "MCP-STDIO-SANDBOX-UNSAFE-MOUNT",
                    f"path {path} is too broad to bind into the sandbox",
                )
        attestation = SandboxAttestation(
            backend_id="linux-bubblewrap-v1",
            evidence_reference=f"bubblewrap-policy:v1;launcher={self.launcher.digest}",
            profile_digest=profile.profile_digest,
            artifact_set_digest=profile.artifact_set_digest,
            filesystem_restricted=True,
            network_restricted=not profile.allow_network,
            child_process_restricted=False,
        )
        return SandboxLaunchPlan(
            argv=self._argv(profile),
            environment=profile.environment,
            working_directory=profile.working_directory,
            attestation=sign_attestation(attestation, self.signing_key),
        )

    def _argv(self, profile: StdioSandboxProfile) -> tuple[str, ...]:
        argv: list[str] = [self.launcher.path, "--unshare-all", "--unshare-user"]
        if profile.allow_network:
            argv.append("--share-net")
        if self.disable_userns:
            argv.append("--disable-userns")
        argv += ["--cap-drop", "ALL", "--die-with-parent", "--new-session", "--clearenv"]
        for key in sorted(profile.environment):
            argv += ["--setenv", key, profile.environment[key]]
        argv += ["--proc", "/proc", "--dev", "/dev", "--perms", "1777", "--tmpfs", "/tmp", "--dir", profile.working_directory]
        for path in profile.writable_paths:
            argv += ["--bind", path, path]
        for path in profile.read_only_paths:
            argv += ["--ro-bind", path, path]
        seen = {profile.executable.path}
        argv += ["--ro-bind", profile.executable.path, profile.executable.path]
        for artifact in profile.additional_artifacts:
            if artifact.path not in seen:
                argv += ["--ro-bind", artifact.path, artifact.path]
                seen.add(artifact.path)
        argv += ["--remount-ro", "/", "--chdir", profile.working_directory, "--", *profile.command]
        return tuple(argv)


# Roots that must never be granted as sandbox paths on macOS: OS code, system
# configuration, and whole user-data volumes.
_UNSAFE_SEATBELT_MOUNTS = _UNSAFE_SANDBOX_MOUNTS | frozenset(
    {"/System", "/usr", "/Library", "/private", "/var", "/etc", "/Users", "/Volumes", "/Network", "/Applications"}
)

# User-data subtrees the generated Seatbelt policy makes unreadable unless a
# descendant is explicitly declared by the profile (later allow rules win).
_SEATBELT_DENIED_SUBTREES = (
    "/Users",
    "/Volumes",
    "/Network",
    "/tmp",
    "/private/tmp",
    "/private/var/tmp",
    "/private/var/folders",
    "/opt",
    "/usr/local",
    "/Library/Keychains",
    "/Library/Application Support",
)


def _seatbelt_path(path: str) -> str:
    """Quote a path for interpolation into an SBPL string literal."""
    if any(character in path for character in ('"', "\\", "\n", "\r", ";")):
        raise MCPStdioError(
            "MCP-STDIO-SANDBOX-UNSAFE-MOUNT",
            "sandbox path contains characters that cannot be safely quoted in a Seatbelt policy",
        )
    return f'"{path}"'


@dataclass(frozen=True, slots=True)
class SeatbeltSandboxBackend:
    """macOS Seatbelt (sandbox-exec) backend that attests only what its
    generated policy actually enforces.

    The policy starts from ``(deny default)``: all writes are denied except the
    declared writable paths, and the user-data subtrees in
    ``_SEATBELT_DENIED_SUBTREES`` are unreadable except declared descendants.
    OS runtime paths stay readable — a pure read allow-list is not portable
    across macOS releases because dyld probes several shared-cache locations —
    so ``filesystem_restricted`` claims exactly that write-deny + user-data-deny
    model, and the evidence reference carries the policy digest a verifier can
    review. Unlike bubblewrap, Seatbelt CAN deny process forking
    (``(deny process-fork)`` covers fork and posix_spawn), so a profile with
    ``allow_child_processes=False`` is honored and attested rather than
    refused. The pinned sandbox-exec launcher is re-verified before each plan.
    """

    launcher: StdioArtifactPin
    signing_key: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not self.signing_key:
            raise ValueError("seatbelt sandbox backend requires a non-empty signing key")

    def prepare(self, profile: StdioSandboxProfile) -> SandboxLaunchPlan:
        _verify_artifact(self.launcher)
        for path in (*profile.read_only_paths, *profile.writable_paths):
            if (path.rstrip("/") or "/") in _UNSAFE_SEATBELT_MOUNTS:
                raise MCPStdioError(
                    "MCP-STDIO-SANDBOX-UNSAFE-MOUNT",
                    f"path {path} is too broad to grant inside the sandbox",
                )
        policy = self._policy(profile)
        attestation = SandboxAttestation(
            backend_id="darwin-seatbelt-v1",
            evidence_reference=(
                f"seatbelt-policy:v1;launcher={self.launcher.digest};"
                f"policy={raw_digest(policy.encode('utf-8'))}"
            ),
            profile_digest=profile.profile_digest,
            artifact_set_digest=profile.artifact_set_digest,
            filesystem_restricted=True,
            network_restricted=not profile.allow_network,
            child_process_restricted=not profile.allow_child_processes,
        )
        return SandboxLaunchPlan(
            argv=(self.launcher.path, "-p", policy, *profile.command),
            environment=profile.environment,
            working_directory=profile.working_directory,
            attestation=sign_attestation(attestation, self.signing_key),
        )

    def _policy(self, profile: StdioSandboxProfile) -> str:
        declared: list[str] = []
        seen: set[str] = set()
        for path in (
            profile.executable.path,
            *(artifact.path for artifact in profile.additional_artifacts),
            *profile.read_only_paths,
            *profile.writable_paths,
        ):
            if path not in seen:
                seen.add(path)
                scheme = "subpath" if Path(path).is_dir() else "literal"
                declared.append(f"({scheme} {_seatbelt_path(path)})")
        lines = [
            "(version 1)",
            "(deny default)",
            "(allow process-exec)",
            "(allow file-read-metadata)",
            "(allow file-read*)",
            "(deny file-read* "
            + " ".join(f"(subpath {_seatbelt_path(path)})" for path in _SEATBELT_DENIED_SUBTREES)
            + ")",
            "(allow file-read* " + " ".join(declared) + ")",
        ]
        if profile.writable_paths:
            lines.append(
                "(allow file-write* "
                + " ".join(f"(subpath {_seatbelt_path(path)})" for path in profile.writable_paths)
                + ")"
            )
        lines += [
            '(allow file-ioctl (subpath "/dev"))',
            "(allow sysctl-read)",
            "(allow mach-lookup)",
            "(allow process-info* (target self))",
            "(allow signal (target self))",
        ]
        if profile.allow_network:
            lines.append("(allow network*)")
        if not profile.allow_child_processes:
            lines.append("(deny process-fork)")
        # One line: the client's argv validation forbids control delimiters,
        # and SBPL needs no newlines.
        return " ".join(lines)


@dataclass(frozen=True, slots=True)
class MCPStdioClientConfig:
    sandbox_profile: StdioSandboxProfile
    protocol_version: str = MCP_PROTOCOL_VERSION

    def __post_init__(self) -> None:
        if self.protocol_version != MCP_PROTOCOL_VERSION:
            raise ValueError(f"unsupported MCP protocol version: {self.protocol_version}")


class MCPStdioServerCaller:
    """Callable binding that proves the adapter and process use one artifact set."""

    __slots__ = ("_client", "artifact_set_digest", "server_id")

    def __init__(self, client: "MCPStdioClient", profile: MCPServerProfile) -> None:
        self._client = client
        self.artifact_set_digest = client.config.sandbox_profile.artifact_set_digest
        self.server_id = profile.server_id

    def __call__(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        return self._client.call(request)


@dataclass(frozen=True, slots=True)
class _ReaderFailure:
    reason_code: str
    message: str


class MCPStdioClient:
    """One-process synchronous MCP stdio client with bounded background readers."""

    def __init__(
        self,
        config: MCPStdioClientConfig,
        *,
        sandbox_backend: StdioSandboxBackend | None = None,
        attestation_verifier: AttestationVerifier | None = None,
        server_message_handler=None,  # noqa: ANN001
    ) -> None:
        self.config = config
        self._sandbox_backend = sandbox_backend or DenyUnisolatedSandboxBackend()
        self._attestation_verifier = attestation_verifier
        self._server_message_handler = server_message_handler
        self._process: subprocess.Popen[bytes] | None = None
        self._stdout_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._messages: queue.Queue[Any] = queue.Queue(config.sandbox_profile.max_pending_messages)
        self._reader_failure: _ReaderFailure | None = None
        self._reader_lock = threading.Lock()
        self._stderr = bytearray()
        self._stderr_truncated = False
        self._exchange_lock = threading.RLock()
        self._initialized = False
        self._server_capabilities: Mapping[str, Any] = {}
        self._sandbox_attestation: SandboxAttestation | None = None

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def server_capabilities(self) -> Mapping[str, Any]:
        return self._server_capabilities

    @property
    def sandbox_attestation(self) -> SandboxAttestation | None:
        return self._sandbox_attestation

    @property
    def stderr_text(self) -> str:
        clean, _ = sanitize_secrets(bytes(self._stderr).decode("utf-8", errors="replace"))
        suffix = "\n[TRUNCATED]" if self._stderr_truncated else ""
        return f"{clean}{suffix}"

    def set_server_message_handler(self, handler) -> None:  # noqa: ANN001
        self._server_message_handler = handler

    def server_caller(self, profile: MCPServerProfile) -> MCPStdioServerCaller:
        if profile.transport != "stdio":
            raise MCPStdioError(
                "MCP-STDIO-TRANSPORT-BINDING-MISMATCH",
                "stdio client requires a stdio MCP Server profile",
            )
        if profile.protocol_version != self.config.protocol_version:
            raise MCPStdioError(
                "MCP-STDIO-TRANSPORT-BINDING-MISMATCH",
                "stdio protocol version does not match the MCP Server profile",
            )
        if profile.artifact_digest != self.config.sandbox_profile.artifact_set_digest:
            raise MCPStdioError(
                "MCP-STDIO-ARTIFACT-BINDING-MISMATCH",
                "MCP Server profile is not bound to the sandbox artifact set",
            )
        return MCPStdioServerCaller(self, profile)

    def start(self) -> SandboxAttestation:
        with self._exchange_lock:
            if self.running:
                raise MCPStdioError("MCP-STDIO-ALREADY-RUNNING", "stdio server is already running")
            profile = self.config.sandbox_profile
            _verify_artifact(profile.executable)
            for artifact in profile.additional_artifacts:
                _verify_artifact(artifact)
            plan = self._sandbox_backend.prepare(profile)
            self._validate_launch_plan(plan)
            popen_arguments: dict[str, Any] = {
                "args": list(plan.argv),
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "cwd": plan.working_directory,
                "env": dict(plan.environment),
                "shell": False,
                "close_fds": True,
                "bufsize": 0,
            }
            if os.name == "posix":
                popen_arguments["start_new_session"] = True
            elif os.name == "nt":
                popen_arguments["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            try:
                process = subprocess.Popen(**popen_arguments)
            except OSError:
                raise MCPStdioError("MCP-STDIO-SPAWN-FAILED", "stdio server process failed to start") from None
            self._process = process
            self._sandbox_attestation = plan.attestation
            self._reader_failure = None
            self._stderr.clear()
            self._stderr_truncated = False
            self._messages = queue.Queue(profile.max_pending_messages)
            self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
            self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
            self._stdout_thread.start()
            self._stderr_thread.start()
            return plan.attestation

    def initialize(
        self,
        *,
        client_name: str = "agent-interlock",
        client_version: str = "0.1.0",
        capabilities: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        with self._exchange_lock:
            if self._initialized:
                raise MCPStdioError("MCP-LIFECYCLE-ALREADY-INITIALIZED", "MCP client is already initialized")
            if not self.running:
                self.start()
            request_id = "interlock-stdio-initialize"
            try:
                response = self._exchange(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": self.config.protocol_version,
                            "capabilities": dict(capabilities or {}),
                            "clientInfo": {"name": client_name, "version": client_version},
                        },
                    }
                )
                if not isinstance(response, Mapping) or response.get("id") != request_id:
                    raise MCPStdioError("MCP-LIFECYCLE-INITIALIZE-INVALID", "invalid initialize response")
                result = response.get("result")
                if not isinstance(result, Mapping):
                    raise MCPStdioError("MCP-LIFECYCLE-INITIALIZE-INVALID", "initialize result is missing")
                if result.get("protocolVersion") != self.config.protocol_version:
                    raise MCPStdioError(
                        "MCP-LIFECYCLE-VERSION-UNSUPPORTED",
                        "stdio MCP Server negotiated an unsupported protocol version",
                    )
                server_capabilities = result.get("capabilities", {})
                if not isinstance(server_capabilities, Mapping):
                    raise MCPStdioError(
                        "MCP-LIFECYCLE-CAPABILITIES-INVALID",
                        "server capabilities must be an object",
                    )
                self._server_capabilities = dict(server_capabilities)
                self._initialized = True
                self._exchange({"jsonrpc": "2.0", "method": "notifications/initialized"})
                return dict(result)
            except Exception:
                self._initialized = False
                self._server_capabilities = {}
                self._terminate_process()
                raise

    def call(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        with self._exchange_lock:
            if request.get("method") == "initialize":
                raise MCPStdioError(
                    "MCP-LIFECYCLE-INITIALIZE-API-REQUIRED",
                    "use initialize() for MCP lifecycle negotiation",
                )
            if not self._initialized or not self.running:
                raise MCPStdioError(
                    "MCP-LIFECYCLE-NOT-INITIALIZED",
                    "stdio MCP client must initialize before operation",
                )
            try:
                return self._exchange(request)
            except Exception:
                self._initialized = False
                self._terminate_process()
                raise

    def close(self) -> None:
        with self._exchange_lock:
            self._initialized = False
            self._server_capabilities = {}
            process = self._process
            if process is not None and process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            if process is not None:
                try:
                    process.wait(timeout=self.config.sandbox_profile.termination_grace_seconds)
                except subprocess.TimeoutExpired:
                    self._terminate_process()
            self._join_readers()
            if process is not None:
                self._close_process_streams(process)
            self._process = None

    def _exchange(self, message: Mapping[str, Any]) -> Mapping[str, Any] | None:
        if not _valid_jsonrpc_message(message, client_message=True):
            raise MCPStdioError("MCP-STDIO-REQUEST-INVALID", "stdio request must be one JSON-RPC message")
        expected_id = message.get("id") if "id" in message else None
        self._raise_reader_failure()
        self._write_message(message)
        if expected_id is None:
            return None
        deadline = time.monotonic() + self.config.sandbox_profile.request_timeout_seconds
        while True:
            self._raise_reader_failure()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._terminate_process()
                raise MCPStdioError("MCP-STDIO-TIMEOUT", "stdio MCP request timed out")
            try:
                item = self._messages.get(timeout=min(remaining, 0.05))
            except queue.Empty:
                process = self._process
                if process is not None and process.poll() is not None:
                    self._raise_reader_failure()
                    raise MCPStdioError("MCP-STDIO-PROCESS-EXITED", "stdio server exited before responding")
                continue
            if item is _EOF:
                self._raise_reader_failure()
                raise MCPStdioError("MCP-STDIO-PROCESS-EXITED", "stdio server closed stdout")
            if isinstance(item, _ReaderFailure):
                raise MCPStdioError(item.reason_code, item.message)
            if "method" in item:
                if "id" in item:
                    raise MCPStdioError(
                        "MCP-STDIO-SERVER-REQUEST-UNSUPPORTED",
                        "server-initiated MCP requests are not enabled",
                    )
                if self._server_message_handler is not None:
                    self._server_message_handler(item)
                continue
            if item.get("id") != expected_id:
                raise MCPStdioError("MCP-STDIO-RESPONSE-ID-MISMATCH", "stdio response id mismatch")
            return item

    def _write_message(self, message: Mapping[str, Any]) -> None:
        process = self._process
        if process is None or process.poll() is not None or process.stdin is None:
            raise MCPStdioError("MCP-STDIO-PROCESS-NOT-RUNNING", "stdio server process is not running")
        try:
            payload = json.dumps(
                message,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise MCPStdioError("MCP-STDIO-JSON-INVALID", "request is not valid JSON") from error
        if len(payload) > self.config.sandbox_profile.max_message_bytes:
            raise MCPStdioError("MCP-STDIO-MESSAGE-TOO-LARGE", "stdio request exceeds message limit")
        try:
            process.stdin.write(payload + b"\n")
            process.stdin.flush()
        except (BrokenPipeError, OSError):
            raise MCPStdioError("MCP-STDIO-WRITE-FAILED", "failed to write to stdio server") from None

    def _read_stdout(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        buffer = bytearray()
        limit = self.config.sandbox_profile.max_message_bytes
        try:
            while True:
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    if buffer:
                        self._set_reader_failure(
                            "MCP-STDIO-DELIMITER-MISSING",
                            "stdio server closed stdout with an unterminated message",
                        )
                    self._put_message(_EOF)
                    return
                buffer.extend(chunk)
                if len(buffer) > limit and b"\n" not in buffer:
                    self._set_reader_failure(
                        "MCP-STDIO-MESSAGE-TOO-LARGE",
                        "stdio response exceeds message limit",
                    )
                    return
                while b"\n" in buffer:
                    raw_line, _, remainder = buffer.partition(b"\n")
                    buffer = bytearray(remainder)
                    if raw_line.endswith(b"\r"):
                        raw_line = raw_line[:-1]
                    if not raw_line:
                        self._set_reader_failure(
                            "MCP-STDIO-STDOUT-INVALID",
                            "stdio server wrote a blank non-message to stdout",
                        )
                        return
                    if len(raw_line) > limit:
                        self._set_reader_failure(
                            "MCP-STDIO-MESSAGE-TOO-LARGE",
                            "stdio response exceeds message limit",
                        )
                        return
                    try:
                        value = json.loads(raw_line.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        self._set_reader_failure(
                            "MCP-STDIO-STDOUT-INVALID",
                            "stdio server stdout contains a non-MCP message",
                        )
                        return
                    if (
                        isinstance(value, list)
                        or not isinstance(value, Mapping)
                        or not _valid_jsonrpc_message(value, client_message=False)
                    ):
                        self._set_reader_failure(
                            "MCP-STDIO-STDOUT-INVALID",
                            "stdio server stdout must contain JSON-RPC objects",
                        )
                        return
                    if not self._put_message(dict(value)):
                        self._set_reader_failure(
                            "MCP-STDIO-PENDING-LIMIT",
                            "stdio server exceeded the pending message limit",
                        )
                        return
        except OSError:
            if self.running:
                self._set_reader_failure("MCP-STDIO-READ-FAILED", "failed to read stdio server stdout")

    def _read_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        limit = self.config.sandbox_profile.max_stderr_bytes
        try:
            while True:
                chunk = os.read(process.stderr.fileno(), 4096)
                if not chunk:
                    return
                remaining = limit - len(self._stderr)
                if remaining > 0:
                    self._stderr.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self._stderr_truncated = True
        except OSError:
            return

    def _validate_launch_plan(self, plan: SandboxLaunchPlan) -> None:
        profile = self.config.sandbox_profile
        if not plan.argv or not os.path.isabs(plan.argv[0]):
            raise MCPStdioError("MCP-STDIO-LAUNCH-PLAN-INVALID", "sandbox launch argv is invalid")
        _validate_arguments(plan.argv)
        if _resolved_directory(plan.working_directory) != profile.working_directory:
            raise MCPStdioError(
                "MCP-STDIO-LAUNCH-PLAN-INVALID",
                "sandbox backend changed the approved working directory",
            )
        if dict(plan.environment) != dict(profile.environment):
            raise MCPStdioError(
                "MCP-STDIO-LAUNCH-PLAN-INVALID",
                "sandbox backend changed the approved environment",
            )
        attestation = plan.attestation
        if (
            attestation.profile_digest != profile.profile_digest
            or attestation.artifact_set_digest != profile.artifact_set_digest
            or not attestation.backend_id
            or not attestation.evidence_reference
        ):
            raise MCPStdioError(
                "MCP-STDIO-SANDBOX-ATTESTATION-INVALID",
                "sandbox attestation does not match the approved profile",
            )
        missing = (
            not attestation.filesystem_restricted
            or (not profile.allow_network and not attestation.network_restricted)
            or (not profile.allow_child_processes and not attestation.child_process_restricted)
        )
        if missing and not profile.allow_unenforced_test_mode:
            raise MCPStdioSandboxUnavailable("sandbox backend does not enforce all required controls")
        if profile.allow_unenforced_test_mode and attestation.backend_id != "test-only-unenforced" and missing:
            raise MCPStdioError(
                "MCP-STDIO-SANDBOX-ATTESTATION-INVALID",
                "partial sandbox attestation cannot use the test-only exception",
            )
        if self._attestation_verifier is not None and not profile.allow_unenforced_test_mode:
            if not self._attestation_verifier.verify(attestation):
                raise MCPStdioError(
                    "MCP-STDIO-SANDBOX-ATTESTATION-UNSIGNED",
                    "sandbox attestation is not signed by a trusted backend key",
                )

    def _set_reader_failure(self, reason_code: str, message: str) -> None:
        with self._reader_lock:
            if self._reader_failure is None:
                self._reader_failure = _ReaderFailure(reason_code, message)
        process = self._process
        if process is not None and process.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
            except (ProcessLookupError, OSError):
                pass

    def _raise_reader_failure(self) -> None:
        with self._reader_lock:
            failure = self._reader_failure
        if failure is not None:
            raise MCPStdioError(failure.reason_code, failure.message)

    def _put_message(self, value: Any) -> bool:
        try:
            self._messages.put_nowait(value)
            return True
        except queue.Full:
            return False

    def _terminate_process(self) -> None:
        process = self._process
        if process is None:
            return
        if process.poll() is None:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.terminate()
            except (ProcessLookupError, OSError):
                pass
            try:
                process.wait(timeout=self.config.sandbox_profile.termination_grace_seconds)
            except subprocess.TimeoutExpired:
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except (ProcessLookupError, OSError):
                    pass
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        self._close_process_streams(process)
        self._join_readers()

    @staticmethod
    def _close_process_streams(process: subprocess.Popen[bytes]) -> None:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def _join_readers(self) -> None:
        current = threading.current_thread()
        for thread in (self._stdout_thread, self._stderr_thread):
            if thread is not None and thread is not current:
                thread.join(timeout=1)


def sha256_file(path: str) -> str:
    resolved = _resolved_regular_file(path)
    digest = hashlib.sha256()
    with open(resolved, "rb") as stream:
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _verify_artifact(pin: StdioArtifactPin) -> None:
    before = os.stat(pin.path, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise MCPStdioError("L1-M4-ARTIFACT-INVALID", "approved stdio artifact is not a regular file")
    observed = sha256_file(pin.path)
    after = os.stat(pin.path, follow_symlinks=False)
    if (
        observed != pin.digest
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        raise MCPStdioError("L1-M4-ARTIFACT-DIGEST-MISMATCH", "stdio artifact digest changed")


def _resolved_regular_file(value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("artifact path must be absolute")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError("artifact path must be a regular file")
    return str(resolved)


def _resolved_directory(value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("working and writable paths must be absolute")
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("path must be an existing directory")
    return str(resolved)


def _resolved_existing_path(value: str) -> str:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("sandbox paths must be absolute")
    return str(path.resolve(strict=True))


def _validate_arguments(values: Sequence[str]) -> None:
    if any(
        not isinstance(item, str)
        or not item
        or "\x00" in item
        or "\r" in item
        or "\n" in item
        or len(item) > 4096
        for item in values
    ):
        raise ValueError("process arguments must be bounded strings without control delimiters")


def _validated_environment(value: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ValueError("environment must be a mapping")
    output: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or not isinstance(item, str)
            or not key
            or "=" in key
            or "\x00" in key
            or "\x00" in item
            or "\r" in item
            or "\n" in item
            or len(key) > 256
            or len(item) > 4096
            or _DANGEROUS_ENV.fullmatch(key)
        ):
            raise ValueError("environment contains a dangerous or invalid entry")
        output[key] = item
    if contains_secret(output):
        raise ValueError("environment must not contain inline secrets")
    return output


def _paths_overlap(left: str, right: str) -> bool:
    try:
        common = os.path.commonpath((left, right))
    except ValueError:
        return False
    return common in {left, right}


def _valid_jsonrpc_message(value: Mapping[str, Any], *, client_message: bool) -> bool:
    if value.get("jsonrpc") != "2.0":
        return False
    request_id = value.get("id")
    if "id" in value and (
        not isinstance(request_id, (str, int)) or isinstance(request_id, bool)
    ):
        return False
    if "method" in value:
        if not isinstance(value.get("method"), str) or not value["method"]:
            return False
        if "params" in value and not isinstance(value["params"], Mapping):
            return False
        return True
    if client_message or "id" not in value:
        return False
    if ("result" in value) == ("error" in value):
        return False
    return "error" not in value or isinstance(value["error"], Mapping)
