"""M4 exact-destination egress guard and reference receipt backend.

The guard is the policy point in front of an egress proxy/broker. The included
in-memory backend opens no real socket; it produces deterministic SIMULATION
evidence. A production backend implements the same protocol and must pin DNS
and the connected IP at the actual network boundary.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlsplit

from .canonical import canonical_digest
from .models import ControlDecision, FailureMode, PolicyMode

if TYPE_CHECKING:
    from .architecture import CompiledArchitecture


REASON_EGRESS_DENIED = "L1-M4-EGRESS-DENIED"
REASON_EGRESS_BINDING_MISMATCH = "L1-M4-EGRESS-BINDING-MISMATCH"
REASON_EGRESS_BACKEND_INVALID = "L1-M4-EGRESS-BACKEND-INVALID"
REASON_PROCESS_TERMINATION_FAILED = "L1-M4-PROCESS-TERMINATION-FAILED"

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$")


def _require_digest(value: str, name: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name} must be a sha256 digest")


def _require_identifier(value: str, name: str) -> None:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} is invalid")


def canonical_network_destination(value: str) -> str:
    """Canonicalize one credential-free HTTPS origin with an explicit port."""
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port or 443
    except (UnicodeError, ValueError) as error:
        raise ValueError("network destination is invalid") from error
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("network destination must be an HTTPS origin")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError("private or non-global IP destinations are forbidden")
    display_host = f"[{host}]" if ":" in host else host
    return f"https://{display_host}:{port}"


@dataclass(frozen=True, slots=True)
class DestinationEgressPolicy:
    policy_id: str
    tenant_id: str
    allowed_workload_ids: frozenset[str]
    allowed_destinations: frozenset[str]
    allowed_artifact_digests: frozenset[str]
    allowed_provenance_digests: frozenset[str]
    allowed_sandbox_profile_digests: frozenset[str]

    def __post_init__(self) -> None:
        _require_identifier(self.policy_id, "policy_id")
        _require_identifier(self.tenant_id, "tenant_id")
        if not all(
            (
                self.allowed_workload_ids,
                self.allowed_destinations,
                self.allowed_artifact_digests,
                self.allowed_provenance_digests,
                self.allowed_sandbox_profile_digests,
            )
        ):
            raise ValueError("egress policy allowlists must not be empty")
        for item in self.allowed_workload_ids:
            _require_identifier(item, "allowed_workload_ids")
        object.__setattr__(
            self,
            "allowed_destinations",
            frozenset(canonical_network_destination(item) for item in self.allowed_destinations),
        )
        for name in (
            "allowed_artifact_digests",
            "allowed_provenance_digests",
            "allowed_sandbox_profile_digests",
        ):
            values = getattr(self, name)
            for value in values:
                _require_digest(value, name)

    def canonical_value(self) -> dict[str, Any]:
        return {
            "policyId": self.policy_id,
            "tenantId": self.tenant_id,
            "allowedWorkloadIds": sorted(self.allowed_workload_ids),
            "allowedDestinations": sorted(self.allowed_destinations),
            "allowedArtifactDigests": sorted(self.allowed_artifact_digests),
            "allowedProvenanceDigests": sorted(self.allowed_provenance_digests),
            "allowedSandboxProfileDigests": sorted(self.allowed_sandbox_profile_digests),
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_value())


def compile_destination_egress_policy(
    compiled: CompiledArchitecture,
    edge_id: str,
    *,
    tenant_id: str,
    artifact_digest: str,
    provenance_digest: str,
    sandbox_profile_digest: str,
    allowed_ports: frozenset[int] = frozenset({443}),
) -> DestinationEgressPolicy:
    """Compile a box/edge REL-07 declaration into an executable egress policy."""
    edge = next((item for item in compiled.graph.edges if item.id == edge_id), None)
    if edge is None or edge.relationship_id != "REL-07" or edge.relationship != "SENDS":
        raise ValueError("edge_id must identify a compiled REL-07 SENDS edge")
    if edge.policy.mode is not PolicyMode.ENFORCE or edge.policy.failure_mode is not FailureMode.FAIL_CLOSED:
        raise ValueError("runtime egress policy requires ENFORCE and FAIL_CLOSED")
    target = compiled.actors[edge.target]
    if not target.allowed_domains:
        raise ValueError("REL-07 target must declare allowed domains")
    if not allowed_ports or any(
        not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in allowed_ports
    ):
        raise ValueError("allowed_ports must contain valid TCP ports")
    destinations = frozenset(
        canonical_network_destination(f"https://{domain}:{port}")
        for domain in target.allowed_domains
        for port in allowed_ports
    )
    return DestinationEgressPolicy(
        policy_id=edge.policy.id,
        tenant_id=tenant_id,
        allowed_workload_ids=frozenset({edge.source}),
        allowed_destinations=destinations,
        allowed_artifact_digests=frozenset({artifact_digest}),
        allowed_provenance_digests=frozenset({provenance_digest}),
        allowed_sandbox_profile_digests=frozenset({sandbox_profile_digest}),
    )


@dataclass(frozen=True, slots=True)
class EgressRequest:
    tenant_id: str
    workload_id: str
    destination: str
    artifact_digest: str
    provenance_digest: str
    sandbox_profile_digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.tenant_id, "tenant_id")
        _require_identifier(self.workload_id, "workload_id")
        _require_digest(self.artifact_digest, "artifact_digest")
        _require_digest(self.provenance_digest, "provenance_digest")
        _require_digest(self.sandbox_profile_digest, "sandbox_profile_digest")


@dataclass(frozen=True, slots=True)
class NetworkConnectionEvidence:
    backend_id: str
    connection_id: str
    canonical_destination: str
    socket_count: int
    connected_address: str = ""


class NetworkEgressBackend(Protocol):
    backend_id: str

    def connect(
        self,
        request: EgressRequest,
        canonical_destination: str,
    ) -> NetworkConnectionEvidence: ...


class EgressBackendError(RuntimeError):
    """Fail-closed backend failure; the guard converts it to a BLOCK receipt."""


class PinnedSocketEgressBackend:
    """Real TCP egress boundary: resolve DNS once, connect to that exact
    address, verify the connected peer, and hand the pinned socket to the
    caller.

    Pinning model: the destination host is resolved through ``resolver``
    exactly once, the socket is connected by IP (never by name, so a
    rebinding re-resolution cannot occur), and the kernel-reported peer
    address must equal the pinned address or the connection is torn down.
    Resolved non-global addresses are refused by default — a public name
    answering with a private address is the classic rebinding/SSRF move.
    The caller collects the connected socket with :meth:`take` (one-time)
    and owns its lifecycle; :meth:`close_all` abandons anything not taken.
    """

    backend_id = "pinned-socket-egress-v1"

    def __init__(
        self,
        *,
        resolver: Callable[..., list[tuple[Any, ...]]] | None = None,
        require_global_addresses: bool = True,
        connect_timeout_seconds: float = 5.0,
    ) -> None:
        if not 0 < connect_timeout_seconds <= 60:
            raise ValueError("connect_timeout_seconds must be within (0, 60]")
        self._resolver = resolver or socket.getaddrinfo
        self._require_global_addresses = require_global_addresses
        self._connect_timeout_seconds = connect_timeout_seconds
        self._active: dict[str, socket.socket] = {}
        self._lock = threading.RLock()

    def connect(
        self,
        request: EgressRequest,
        canonical_destination: str,
    ) -> NetworkConnectionEvidence:
        parsed = urlsplit(canonical_destination)
        host = (parsed.hostname or "").strip("[]")
        port = parsed.port or 443
        try:
            resolved = self._resolver(host, port, type=socket.SOCK_STREAM)
        except OSError as error:
            raise EgressBackendError("destination did not resolve") from error
        if not resolved:
            raise EgressBackendError("destination did not resolve")
        family, _, _, _, address = resolved[0]
        pinned_ip = str(address[0])
        if self._require_global_addresses and not ipaddress.ip_address(pinned_ip).is_global:
            raise EgressBackendError("destination resolved to a non-global address")
        connection = socket.socket(family, socket.SOCK_STREAM)
        try:
            connection.settimeout(self._connect_timeout_seconds)
            connection.connect((pinned_ip, port))
            peer = connection.getpeername()
            if str(peer[0]) != pinned_ip or int(peer[1]) != port:
                raise EgressBackendError("connected peer does not match the pinned address")
        except (OSError, EgressBackendError) as error:
            connection.close()
            if isinstance(error, EgressBackendError):
                raise
            raise EgressBackendError("pinned connection failed") from error
        connection_id = str(uuid.uuid4())
        with self._lock:
            self._active[connection_id] = connection
        return NetworkConnectionEvidence(
            backend_id=self.backend_id,
            connection_id=connection_id,
            canonical_destination=canonical_destination,
            socket_count=1,
            connected_address=f"{pinned_ip}:{port}",
        )

    def take(self, connection_id: str) -> socket.socket:
        """One-time handoff of the pinned, connected socket to its caller."""
        with self._lock:
            connection = self._active.pop(connection_id, None)
        if connection is None:
            raise EgressBackendError("connection is unknown or already taken")
        return connection

    def close_all(self) -> None:
        with self._lock:
            abandoned = list(self._active.values())
            self._active.clear()
        for connection in abandoned:
            connection.close()


class InMemoryNetworkEgressBackend:
    """SIMULATION backend: records one logical connection and opens no socket."""

    backend_id = "simulation-egress-v1"

    def __init__(self) -> None:
        self._connections: list[NetworkConnectionEvidence] = []
        self._lock = threading.RLock()

    @property
    def connections(self) -> tuple[NetworkConnectionEvidence, ...]:
        with self._lock:
            return tuple(self._connections)

    @property
    def socket_count(self) -> int:
        with self._lock:
            return sum(item.socket_count for item in self._connections)

    def connect(
        self,
        request: EgressRequest,
        canonical_destination: str,
    ) -> NetworkConnectionEvidence:
        evidence = NetworkConnectionEvidence(
            backend_id=self.backend_id,
            connection_id=str(uuid.uuid4()),
            canonical_destination=canonical_destination,
            socket_count=1,
        )
        with self._lock:
            self._connections.append(evidence)
        return evidence


@dataclass(frozen=True, slots=True)
class EgressReceipt:
    receipt_id: str
    decision: ControlDecision
    reason_codes: tuple[str, ...]
    tenant_id: str
    workload_id: str
    requested_destination: str
    canonical_destination: str | None
    artifact_digest: str
    provenance_digest: str
    sandbox_profile_digest: str
    policy_digest: str
    backend_id: str
    connection_id: str | None
    socket_count: int | None
    process_terminated: bool
    connected_address: str | None = None

    def evidence(self) -> Mapping[str, Any]:
        return {
            "receiptId": self.receipt_id,
            "decision": self.decision.value,
            "reasonCodes": list(self.reason_codes),
            "tenantId": self.tenant_id,
            "workloadId": self.workload_id,
            "requestedDestination": self.requested_destination,
            "canonicalDestination": self.canonical_destination,
            "artifactDigest": self.artifact_digest,
            "provenanceDigest": self.provenance_digest,
            "sandboxProfileDigest": self.sandbox_profile_digest,
            "policyDigest": self.policy_digest,
            "backendId": self.backend_id,
            "connectionId": self.connection_id,
            "socketCount": self.socket_count,
            "processTerminated": self.process_terminated,
            "connectedAddress": self.connected_address,
        }


class DestinationEgressGuard:
    """Fail closed before backend connect and terminate a denied workload."""

    def __init__(
        self,
        policy: DestinationEgressPolicy,
        backend: NetworkEgressBackend,
        *,
        terminate_workload: Callable[[str], bool],
    ) -> None:
        self.policy = policy
        self.backend = backend
        self._terminate_workload = terminate_workload
        self._receipts: list[EgressReceipt] = []
        self._lock = threading.RLock()

    @property
    def receipts(self) -> tuple[EgressReceipt, ...]:
        with self._lock:
            return tuple(self._receipts)

    def execute(self, request: EgressRequest) -> EgressReceipt:
        try:
            destination = canonical_network_destination(request.destination)
        except ValueError:
            return self._blocked(request, None, (REASON_EGRESS_DENIED,))
        if request.tenant_id != self.policy.tenant_id or request.workload_id not in self.policy.allowed_workload_ids:
            return self._blocked(request, destination, (REASON_EGRESS_BINDING_MISMATCH,))
        if destination not in self.policy.allowed_destinations:
            return self._blocked(request, destination, (REASON_EGRESS_DENIED,))
        if (
            request.artifact_digest not in self.policy.allowed_artifact_digests
            or request.provenance_digest not in self.policy.allowed_provenance_digests
            or request.sandbox_profile_digest not in self.policy.allowed_sandbox_profile_digests
        ):
            return self._blocked(request, destination, (REASON_EGRESS_BINDING_MISMATCH,))
        try:
            evidence = self.backend.connect(request, destination)
        except Exception:
            return self._blocked(
                request,
                destination,
                (REASON_EGRESS_BACKEND_INVALID,),
                socket_count=None,
            )
        if (
            evidence.backend_id != self.backend.backend_id
            or evidence.canonical_destination != destination
            or evidence.socket_count != 1
            or not evidence.connection_id
        ):
            return self._blocked(
                request,
                destination,
                (REASON_EGRESS_BACKEND_INVALID,),
                socket_count=evidence.socket_count,
                connection_id=evidence.connection_id or None,
            )
        return self._record(
            EgressReceipt(
                receipt_id=str(uuid.uuid4()),
                decision=ControlDecision.ALLOW,
                reason_codes=(),
                tenant_id=request.tenant_id,
                workload_id=request.workload_id,
                requested_destination=request.destination,
                canonical_destination=destination,
                artifact_digest=request.artifact_digest,
                provenance_digest=request.provenance_digest,
                sandbox_profile_digest=request.sandbox_profile_digest,
                policy_digest=self.policy.digest,
                backend_id=evidence.backend_id,
                connection_id=evidence.connection_id,
                socket_count=evidence.socket_count,
                process_terminated=False,
                connected_address=evidence.connected_address or None,
            )
        )

    def _blocked(
        self,
        request: EgressRequest,
        destination: str | None,
        reasons: tuple[str, ...],
        *,
        socket_count: int | None = 0,
        connection_id: str | None = None,
    ) -> EgressReceipt:
        try:
            terminated = self._terminate_workload(request.workload_id) is True
        except Exception:
            terminated = False
        if not terminated:
            reasons = (*reasons, REASON_PROCESS_TERMINATION_FAILED)
        return self._record(
            EgressReceipt(
                receipt_id=str(uuid.uuid4()),
                decision=ControlDecision.BLOCK,
                reason_codes=reasons,
                tenant_id=request.tenant_id,
                workload_id=request.workload_id,
                requested_destination=request.destination,
                canonical_destination=destination,
                artifact_digest=request.artifact_digest,
                provenance_digest=request.provenance_digest,
                sandbox_profile_digest=request.sandbox_profile_digest,
                policy_digest=self.policy.digest,
                backend_id=self.backend.backend_id,
                connection_id=connection_id,
                socket_count=socket_count,
                process_terminated=terminated,
            )
        )

    def _record(self, receipt: EgressReceipt) -> EgressReceipt:
        with self._lock:
            self._receipts.append(receipt)
        return receipt
