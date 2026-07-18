"""Sandbox process supervisor: health telemetry, backoff restart, attestation binding."""

from __future__ import annotations

import unittest

from agent_interlock import (
    InMemoryLedger,
    SandboxAttestation,
    SandboxHealth,
    SandboxSupervisor,
)

TENANT = "tenant-a"


def attestation(backend_id="linux-bubblewrap-v1", profile_digest="sha256:" + "a" * 64):
    return SandboxAttestation(
        backend_id=backend_id,
        evidence_reference="ref",
        profile_digest=profile_digest,
        artifact_set_digest="sha256:" + "b" * 64,
        filesystem_restricted=True,
        network_restricted=True,
        child_process_restricted=True,
    )


class FakeProcess:
    """Scriptable supervised process. ``crash()`` kills it; start() returns the
    scripted attestation for that (re)start."""

    def __init__(self, attestations):
        self._attestations = list(attestations)
        self._starts = 0
        self.running = False
        self.closes = 0

    def start(self) -> SandboxAttestation:
        if self._starts >= len(self._attestations):
            raise RuntimeError("no scripted attestation for this start")
        att = self._attestations[self._starts]
        self._starts += 1
        if att is None:  # a scripted failed start
            raise RuntimeError("scripted start failure")
        self.running = True
        return att

    def close(self) -> None:
        self.closes += 1
        self.running = False

    def crash(self) -> None:
        self.running = False


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def health_events(ledger, trace_id):
    return [
        event.payload["control"]["status"]
        for event in ledger.trace(TENANT, trace_id)
        if event.event_type == "CONTROL_HEALTH_CHANGED"
    ]


def make(process, ledger=None, clock=None, **kw):
    return SandboxSupervisor(
        process,
        ledger=ledger or InMemoryLedger(),
        tenant_id=TENANT,
        source_actor_id="agent.support",
        clock=clock or Clock(),
        **kw,
    )


class SupervisorHealthTests(unittest.TestCase):
    def test_start_pins_attestation_and_emits_healthy(self):
        process = FakeProcess([attestation()])
        supervisor = make(process)
        att = supervisor.start()
        self.assertEqual(att.backend_id, "linux-bubblewrap-v1")
        self.assertEqual(supervisor.state, SandboxHealth.HEALTHY)
        self.assertEqual(health_events(supervisor.ledger, supervisor._trace_id), ["HEALTHY"])

    def test_crash_emits_unhealthy_then_recovers_after_restart(self):
        process = FakeProcess([attestation(), attestation()])
        clock = Clock()
        supervisor = make(process, clock=clock)
        supervisor.start()
        process.crash()
        clock.advance(10)  # past any backoff
        state = supervisor.check()
        self.assertEqual(state, SandboxHealth.HEALTHY)
        self.assertEqual(process.closes >= 1, True)
        self.assertEqual(
            health_events(supervisor.ledger, supervisor._trace_id),
            ["HEALTHY", "UNHEALTHY", "RECOVERED"],
        )

    def test_backoff_prevents_immediate_second_restart(self):
        # start ok, restart#1 fails, then within backoff no further restart.
        process = FakeProcess([attestation(), None, attestation()])
        clock = Clock()
        supervisor = make(process, clock=clock, backoff_base_seconds=5.0)
        supervisor.start()
        process.crash()
        supervisor.check()  # restart #1 attempted, fails, schedules backoff
        starts_after_first = process._starts
        supervisor.check()  # still within backoff window -> no new start
        self.assertEqual(process._starts, starts_after_first)
        clock.advance(6.0)  # past backoff
        supervisor.check()  # restart #2 -> success
        self.assertEqual(supervisor.state, SandboxHealth.HEALTHY)

    def test_restart_exhaustion_degrades(self):
        # start ok, then every restart fails -> DEGRADED after max_restarts.
        process = FakeProcess([attestation(), None, None])
        clock = Clock()
        supervisor = make(process, clock=clock, max_restarts=2, backoff_base_seconds=1.0)
        supervisor.start()
        process.crash()
        for _ in range(6):
            clock.advance(100)
            supervisor.check()
        self.assertEqual(supervisor.state, SandboxHealth.DEGRADED)
        self.assertIn("DEGRADED", health_events(supervisor.ledger, supervisor._trace_id))
        degraded = [
            event
            for event in supervisor.ledger.trace(TENANT, supervisor._trace_id)
            if event.event_type == "CONTROL_HEALTH_CHANGED"
            and "L1-SUP-RESTART-EXHAUSTED" in event.payload["control"]["reasonCodes"]
        ]
        self.assertTrue(degraded)

    def test_attestation_swap_on_restart_is_refused_fail_closed(self):
        # restart returns a DIFFERENT sandbox: supply-chain swap.
        swapped = attestation(backend_id="test-only-unenforced", profile_digest="sha256:" + "c" * 64)
        process = FakeProcess([attestation(), swapped])
        clock = Clock()
        supervisor = make(process, clock=clock)
        supervisor.start()
        process.crash()
        clock.advance(10)
        state = supervisor.check()
        self.assertEqual(state, SandboxHealth.DEGRADED)
        drift = [
            event
            for event in supervisor.ledger.trace(TENANT, supervisor._trace_id)
            if event.event_type == "CONTROL_HEALTH_CHANGED"
            and "L1-SUP-ATTESTATION-DRIFT" in event.payload["control"]["reasonCodes"]
        ]
        self.assertTrue(drift)
        self.assertEqual(drift[0].severity, "HIGH")
        # the swapped process was closed and no further restart happens
        self.assertGreaterEqual(process.closes, 1)
        clock.advance(100)
        self.assertEqual(supervisor.check(), SandboxHealth.DEGRADED)

    def test_health_probe_failure_marks_unhealthy_even_if_process_runs(self):
        process = FakeProcess([attestation(), attestation()])
        probe_ok = {"value": True}
        supervisor = make(process, health_probe=lambda: probe_ok["value"])
        supervisor.start()
        probe_ok["value"] = False  # process still running, but app is unhealthy
        state = supervisor.check()
        self.assertIn(state, (SandboxHealth.UNHEALTHY, SandboxHealth.HEALTHY))
        self.assertIn("UNHEALTHY", health_events(supervisor.ledger, supervisor._trace_id))

    def test_events_carry_supervisor_policy_and_sandbox_relationship(self):
        process = FakeProcess([attestation()])
        supervisor = make(process)
        supervisor.start()
        event = [
            e for e in supervisor.ledger.trace(TENANT, supervisor._trace_id)
            if e.event_type == "CONTROL_HEALTH_CHANGED"
        ][0]
        self.assertEqual(event.payload["control"]["policyId"], "sandbox-supervisor")
        self.assertEqual(event.relationship_id, "REL-11")
        self.assertEqual(event.relationship_type, "SUPERVISES")
        self.assertEqual(event.payload["control"]["backendId"], "linux-bubblewrap-v1")


if __name__ == "__main__":
    unittest.main()
