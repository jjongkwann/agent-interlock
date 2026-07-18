"""Emit CONTROL_HEALTH_CHANGED for observability-layer control failures.

docs/08 requires that trace sampling gaps and Audit Sink failures surface as
control-health signals rather than being swallowed. This reporter turns a
telemetry import result (its issues, and interactions that were control-checked
but never observed) and an Audit Sink seal failure into ``CONTROL_HEALTH_CHANGED``
events, so a control-health view sees a degraded observability plane.
"""

from __future__ import annotations

import uuid
from typing import Any

from .architecture import RuntimeGraphDiff
from .ledger import InMemoryLedger, Ledger
from .telemetry import RuntimeTelemetryImport

TELEMETRY_HEALTH_POLICY_ID = "telemetry-health"
TELEMETRY_HEALTH_POLICY_VERSION = "1.0.0"

REASON_TELEMETRY_IMPORT_ISSUES = "L1-HEALTH-TELEMETRY-IMPORT-ISSUES"
REASON_TELEMETRY_SAMPLING_GAP = "L1-HEALTH-TELEMETRY-SAMPLING-GAP"
REASON_AUDIT_SINK_FAILURE = "L1-HEALTH-AUDIT-SINK-FAILURE"

STATUS_HEALTHY = "HEALTHY"
STATUS_DEGRADED = "DEGRADED"


class ControlHealthReporter:
    """Records observability-plane control health to a ledger."""

    def __init__(
        self,
        *,
        ledger: Ledger | None = None,
        tenant_id: str,
        source_actor_id: str = "observability",
        target_actor_id: str = "control-plane",
    ) -> None:
        self._ledger = ledger or InMemoryLedger()
        self._tenant_id = tenant_id
        self._source_actor_id = source_actor_id
        self._target_actor_id = target_actor_id

    @property
    def ledger(self) -> Ledger:
        return self._ledger

    def report_telemetry_import(
        self, result: RuntimeTelemetryImport, *, diff: RuntimeGraphDiff | None = None
    ) -> str | None:
        """Emit a health event if the import carried issues or a sampling gap.

        A ``diff`` with control-bypass interactions means a request was seen
        without its control span (or vice versa) — a sampling/telemetry gap that
        must not be read as "no control evaluated". Returns the emitted event id,
        or ``None`` when the plane is healthy.
        """
        reasons: list[str] = []
        evidence: dict[str, Any] = {"format": result.format, "issueCount": len(result.issues)}
        if result.issues:
            reasons.append(REASON_TELEMETRY_IMPORT_ISSUES)
            evidence["issueCodes"] = sorted({issue.code for issue in result.issues})
        if diff is not None and diff.control_bypass_interactions:
            reasons.append(REASON_TELEMETRY_SAMPLING_GAP)
            evidence["controlBypassInteractions"] = list(diff.control_bypass_interactions)
        if not reasons:
            return None
        return self._emit(STATUS_DEGRADED, reasons, evidence)

    def report_audit_sink_failure(self, detail: str, *, event_id: str | None = None) -> str:
        """Emit a health event when the Audit Sink could not seal an event."""
        evidence: dict[str, Any] = {"detail": detail}
        if event_id:
            evidence["failedEventId"] = event_id
        return self._emit(STATUS_DEGRADED, [REASON_AUDIT_SINK_FAILURE], evidence)

    def report_healthy(self, detail: str = "") -> str:
        return self._emit(STATUS_HEALTHY, [], {"detail": detail} if detail else {})

    def _emit(self, status: str, reasons: list[str], evidence: dict[str, Any]) -> str:
        event = self._ledger.append(
            "CONTROL_HEALTH_CHANGED",
            tenant_id=self._tenant_id,
            trace_id=f"health-{uuid.uuid4()}",
            span_id=f"health-{uuid.uuid4()}",
            source_actor_id=self._source_actor_id,
            target_actor_id=self._target_actor_id,
            payload={
                "control": {
                    "policyId": TELEMETRY_HEALTH_POLICY_ID,
                    "policyVersion": TELEMETRY_HEALTH_POLICY_VERSION,
                    "status": status,
                    "reasonCodes": reasons,
                },
                "health": evidence,
            },
            relationship_type="LOGS_TO",
            relationship_id="REL-12",
            severity="HIGH" if status != STATUS_HEALTHY else "INFO",
        )
        return event.event_id
