"""Long-running sandbox process supervisor with health telemetry.

A sandboxed stdio server is a long-lived process. This supervisor probes its
liveness (and an optional application health check), restarts it with bounded
exponential backoff, and emits a ``CONTROL_HEALTH_CHANGED`` event on every
state transition so a control-health dashboard sees unhealthy/recovered/degraded
signals.

Restart is bound to attestation: a restarted process must re-attest the SAME
sandbox (backend id + profile digest). A mismatch means the process came back as
a different sandbox — a supply-chain swap — so the supervisor refuses it fail
closed (closes it, stops restarting, emits an attestation-drift health event)
rather than silently keep a weaker sandbox running.
"""

from __future__ import annotations

import contextlib
import threading
import time
import uuid
from collections.abc import Callable
from enum import StrEnum
from typing import Protocol

from .ledger import InMemoryLedger, Ledger
from .mcp_stdio import SandboxAttestation

SUPERVISOR_POLICY_ID = "sandbox-supervisor"
SUPERVISOR_POLICY_VERSION = "1.0.0"

REASON_UNHEALTHY = "L1-SUP-SANDBOX-UNHEALTHY"
REASON_RECOVERED = "L1-SUP-SANDBOX-RECOVERED"
REASON_RESTART_EXHAUSTED = "L1-SUP-RESTART-EXHAUSTED"
REASON_ATTESTATION_DRIFT = "L1-SUP-ATTESTATION-DRIFT"


class SandboxHealth(StrEnum):
    STARTING = "STARTING"
    HEALTHY = "HEALTHY"
    UNHEALTHY = "UNHEALTHY"
    RECOVERED = "RECOVERED"
    DEGRADED = "DEGRADED"


class SupervisedProcess(Protocol):
    """The lifecycle surface the supervisor drives (``MCPStdioClient`` satisfies it)."""

    @property
    def running(self) -> bool: ...

    def start(self) -> SandboxAttestation: ...

    def close(self) -> None: ...


class SandboxSupervisor:
    """Supervises one long-running sandbox process with health telemetry."""

    def __init__(
        self,
        process: SupervisedProcess,
        *,
        ledger: Ledger | None = None,
        tenant_id: str,
        source_actor_id: str,
        target_actor_id: str = "sandbox",
        health_probe: Callable[[], bool] | None = None,
        max_restarts: int = 5,
        backoff_base_seconds: float = 0.5,
        backoff_cap_seconds: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_restarts < 0:
            raise ValueError("max_restarts must not be negative")
        if backoff_base_seconds <= 0 or backoff_cap_seconds < backoff_base_seconds:
            raise ValueError("backoff bounds must be positive with cap >= base")
        self._process = process
        self._ledger = ledger or InMemoryLedger()
        self._tenant_id = tenant_id
        self._source_actor_id = source_actor_id
        self._target_actor_id = target_actor_id
        self._health_probe = health_probe
        self._max_restarts = max_restarts
        self._backoff_base = backoff_base_seconds
        self._backoff_cap = backoff_cap_seconds
        self._clock = clock
        self._trace_id = f"supervisor-{uuid.uuid4()}"
        self._lock = threading.RLock()
        self._state = SandboxHealth.STARTING
        self._restart_count = 0
        self._next_restart_at = 0.0
        self._expected: tuple[str, str] | None = None
        self._attestation: SandboxAttestation | None = None

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    @property
    def state(self) -> SandboxHealth:
        with self._lock:
            return self._state

    @property
    def attestation(self) -> SandboxAttestation | None:
        with self._lock:
            return self._attestation

    @property
    def restart_count(self) -> int:
        with self._lock:
            return self._restart_count

    def start(self) -> SandboxAttestation:
        """Start the supervised process and record its attestation as the pin."""
        with self._lock:
            attestation = self._process.start()
            self._expected = (attestation.backend_id, attestation.profile_digest)
            self._attestation = attestation
            self._state = SandboxHealth.HEALTHY
            self._emit(SandboxHealth.HEALTHY)
            return attestation

    def check(self) -> SandboxHealth:
        """Probe health once; emit on transition and restart under backoff."""
        with self._lock:
            if self._healthy_now():
                if self._state in (SandboxHealth.UNHEALTHY, SandboxHealth.DEGRADED):
                    self._recover()
                else:
                    self._state = SandboxHealth.HEALTHY
                return self._state

            if self._state not in (SandboxHealth.UNHEALTHY, SandboxHealth.DEGRADED):
                self._emit(SandboxHealth.UNHEALTHY, REASON_UNHEALTHY)
            self._state = SandboxHealth.UNHEALTHY

            if self._restart_count >= self._max_restarts:
                self._emit(SandboxHealth.DEGRADED, REASON_RESTART_EXHAUSTED)
                self._state = SandboxHealth.DEGRADED
                return self._state
            if self._clock() < self._next_restart_at:
                return self._state

            self._restart()
            if self._state != SandboxHealth.DEGRADED and self._healthy_now():
                self._recover()
            return self._state

    def stop(self) -> None:
        # stopping must not raise
        with self._lock, contextlib.suppress(Exception):
            self._process.close()

    # ------------------------------------------------------------------ #

    def _healthy_now(self) -> bool:
        if not self._process.running:
            return False
        if self._health_probe is None:
            return True
        try:
            return bool(self._health_probe())
        except Exception:  # noqa: BLE001 - a throwing probe means unhealthy
            return False

    def _recover(self) -> None:
        self._state = SandboxHealth.HEALTHY
        self._restart_count = 0
        self._emit(SandboxHealth.RECOVERED, REASON_RECOVERED)

    def _restart(self) -> None:
        self._restart_count += 1
        with contextlib.suppress(Exception):
            self._process.close()
        try:
            attestation = self._process.start()
        except Exception:  # noqa: BLE001 - failed restart: back off and retry later
            self._schedule_backoff()
            return
        if (attestation.backend_id, attestation.profile_digest) != self._expected:
            # The process came back as a different sandbox: a supply-chain swap.
            self._emit(SandboxHealth.DEGRADED, REASON_ATTESTATION_DRIFT, severity="HIGH")
            self._state = SandboxHealth.DEGRADED
            self._restart_count = self._max_restarts  # stop restarting into a swap
            with contextlib.suppress(Exception):
                self._process.close()
            return
        self._attestation = attestation
        self._schedule_backoff()

    def _schedule_backoff(self) -> None:
        exponent = max(0, self._restart_count - 1)
        delay = min(self._backoff_cap, self._backoff_base * (2**exponent))
        self._next_restart_at = self._clock() + delay

    def _emit(self, health: SandboxHealth, *reason_codes: str, severity: str | None = None) -> None:
        backend_id = self._expected[0] if self._expected else ""
        profile_digest = self._expected[1] if self._expected else ""
        self._ledger.append(
            "CONTROL_HEALTH_CHANGED",
            tenant_id=self._tenant_id,
            trace_id=self._trace_id,
            span_id=f"supervisor-{uuid.uuid4()}",
            source_actor_id=self._source_actor_id,
            target_actor_id=self._target_actor_id,
            payload={
                "control": {
                    "policyId": SUPERVISOR_POLICY_ID,
                    "policyVersion": SUPERVISOR_POLICY_VERSION,
                    "status": health.value,
                    "reasonCodes": list(reason_codes),
                    "restartCount": self._restart_count,
                    "backendId": backend_id,
                    "profileDigest": profile_digest,
                }
            },
            relationship_type="SUPERVISES",
            relationship_id="REL-11",
            severity=severity or ("HIGH" if health in (SandboxHealth.UNHEALTHY, SandboxHealth.DEGRADED) else "INFO"),
        )
