"""PinnedSocketEgressBackend: real-socket egress with DNS/connect-IP pinning."""

from __future__ import annotations

import socket
import threading
import time
import unittest

from agent_interlock import (
    ControlDecision,
    DestinationEgressGuard,
    DestinationEgressPolicy,
    EgressBackendError,
    EgressRequest,
    PinnedSocketEgressBackend,
)

DIGEST = "sha256:" + "a" * 64
TENANT = "tenant-a"
WORKLOAD = "workload-1"


class FixtureServer:
    """Accepts real TCP connections on 127.0.0.1 and records payloads."""

    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.settimeout(0.2)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.received: list[bytes] = []
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            connection.settimeout(2)
            try:
                data = connection.recv(65536)
                if data:
                    self.received.append(data)
            except OSError:
                pass
            finally:
                connection.close()

    def close(self) -> None:
        self._stop.set()
        self.listener.close()
        self._thread.join(timeout=5)


def resolver_to(ip: str, calls: list[str]):
    def resolve(host: str, port: int, **_kwargs):
        calls.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    return resolve


def policy(port: int) -> DestinationEgressPolicy:
    return DestinationEgressPolicy(
        policy_id="egress-live",
        tenant_id=TENANT,
        allowed_workload_ids=frozenset({WORKLOAD}),
        allowed_destinations=frozenset({f"https://trusted.example:{port}"}),
        allowed_artifact_digests=frozenset({DIGEST}),
        allowed_provenance_digests=frozenset({DIGEST}),
        allowed_sandbox_profile_digests=frozenset({DIGEST}),
    )


def request(port: int) -> EgressRequest:
    return EgressRequest(
        tenant_id=TENANT,
        workload_id=WORKLOAD,
        destination=f"https://trusted.example:{port}",
        artifact_digest=DIGEST,
        provenance_digest=DIGEST,
        sandbox_profile_digest=DIGEST,
    )


class PinnedSocketEgressTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = FixtureServer()
        self.addCleanup(self.fixture.close)
        self.terminated: list[str] = []

    def guard(self, backend: PinnedSocketEgressBackend, port: int) -> DestinationEgressGuard:
        def terminate(workload_id: str) -> bool:
            self.terminated.append(workload_id)
            return True

        return DestinationEgressGuard(policy(port), backend, terminate_workload=terminate)

    def test_allowed_destination_connects_pinned_and_hands_off_the_socket(self):
        calls: list[str] = []
        backend = PinnedSocketEgressBackend(resolver=resolver_to("127.0.0.1", calls), require_global_addresses=False)
        self.addCleanup(backend.close_all)
        receipt = self.guard(backend, self.fixture.port).execute(request(self.fixture.port))
        self.assertEqual(receipt.decision, ControlDecision.ALLOW)
        self.assertEqual(receipt.socket_count, 1)
        self.assertEqual(receipt.connected_address, f"127.0.0.1:{self.fixture.port}")
        self.assertEqual(receipt.evidence()["connectedAddress"], f"127.0.0.1:{self.fixture.port}")
        self.assertEqual(calls, ["trusted.example"])  # DNS resolved exactly once

        connection = backend.take(receipt.connection_id)
        connection.sendall(b"hello-through-pinned-egress")
        connection.close()
        deadline = time.monotonic() + 5
        while not self.fixture.received and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(self.fixture.received, [b"hello-through-pinned-egress"])

        with self.assertRaises(EgressBackendError):
            backend.take(receipt.connection_id)  # handoff is one-time

    def test_private_resolution_is_refused_fail_closed(self):
        calls: list[str] = []
        backend = PinnedSocketEgressBackend(resolver=resolver_to("10.0.0.7", calls))
        receipt = self.guard(backend, self.fixture.port).execute(request(self.fixture.port))
        self.assertEqual(receipt.decision, ControlDecision.BLOCK)
        self.assertIn("L1-M4-EGRESS-BACKEND-INVALID", receipt.reason_codes)
        self.assertTrue(receipt.process_terminated)
        self.assertEqual(self.terminated, [WORKLOAD])
        self.assertEqual(self.fixture.connections, 0)

    def test_connection_refused_blocks_and_terminates(self):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()
        backend = PinnedSocketEgressBackend(resolver=resolver_to("127.0.0.1", []), require_global_addresses=False)
        receipt = self.guard(backend, closed_port).execute(request(closed_port))
        self.assertEqual(receipt.decision, ControlDecision.BLOCK)
        self.assertIn("L1-M4-EGRESS-BACKEND-INVALID", receipt.reason_codes)
        self.assertTrue(receipt.process_terminated)

    def test_denied_destination_never_reaches_dns_or_socket(self):
        calls: list[str] = []
        backend = PinnedSocketEgressBackend(resolver=resolver_to("127.0.0.1", calls), require_global_addresses=False)
        denied = EgressRequest(
            tenant_id=TENANT,
            workload_id=WORKLOAD,
            destination="https://attacker.example:443",
            artifact_digest=DIGEST,
            provenance_digest=DIGEST,
            sandbox_profile_digest=DIGEST,
        )
        receipt = self.guard(backend, self.fixture.port).execute(denied)
        self.assertEqual(receipt.decision, ControlDecision.BLOCK)
        self.assertIn("L1-M4-EGRESS-DENIED", receipt.reason_codes)
        self.assertEqual(calls, [])
        self.assertEqual(self.fixture.connections, 0)

    def test_timeout_bounds_are_validated(self):
        for value in (0, -1, 61):
            with self.assertRaises(ValueError):
                PinnedSocketEgressBackend(connect_timeout_seconds=value)


if __name__ == "__main__":
    unittest.main()
