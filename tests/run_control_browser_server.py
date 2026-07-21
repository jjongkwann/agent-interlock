"""Test-only Run Control server for manual Chrome Studio E2E.

This process injects deterministic adapters only because it lives under
``tests/``. Product wiring must provide real transports to RunControlService.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading

from test_run_control import OPERATOR_TOKEN, RunningRunControl

from agent_interlock import (
    CallableTaskAdapter,
    DataSource,
    InMemoryLedger,
    TaskExecutionInput,
    TaskExecutionResult,
    TaskTransport,
)


def _record_success(ledger: InMemoryLedger, value: TaskExecutionInput) -> None:
    """Emit gateway-shaped SIMULATION evidence for this browser-only adapter."""
    a2a = value.task.transport == TaskTransport.A2A
    interaction_id = f"{value.run_id}:{value.task.id}:{value.attempt}"
    common = {
        "tenant_id": value.tenant_id,
        "trace_id": value.trace_id,
        "span_id": f"task-{value.run_id}-{value.task.id}-{value.attempt}",
        "interaction_id": interaction_id,
        "source_actor_id": value.task.source_actor_id,
        "target_actor_id": value.task.target_actor_id,
        "relationship_type": "DELEGATES" if a2a else "INVOKES",
        "relationship_id": "REL-06" if a2a else "REL-05",
        "data_source": DataSource.SIMULATION,
    }
    ledger.append(
        "INTERACTION_REQUESTED",
        payload={"invocation": {"purpose": value.task.purpose}, "testOnly": True},
        **common,
    )
    ledger.append(
        "CONTROL_EVALUATED",
        payload={
            "control": {
                "policyId": "POL-TEST-BROWSER-E2E",
                "policyVersion": "1.0.0",
                "mode": "ENFORCE",
                "decision": "ALLOW",
                "reasonCodes": [],
                "actualEnforced": True,
            }
        },
        **common,
    )
    ledger.append(
        "ACTION_EXECUTED",
        payload={"result": "COMPLETED", "connectorExecutionId": f"exec-{interaction_id}"},
        **common,
    )
    ledger.append(
        "SECURITY_OUTCOME_SET",
        payload={"securityOutcome": "SUCCEEDED"},
        **common,
    )


def _adapter_provider(ledger: InMemoryLedger):
    def provider(_compiled):  # noqa: ANN001
        def research(value: TaskExecutionInput):
            _record_success(ledger, value)
            return TaskExecutionResult(
                output={"evidenceIds": ["browser-evidence-test-only"]},
                metadata={"accepted": True},
            )

        def tool(value: TaskExecutionInput):
            _record_success(ledger, value)
            return TaskExecutionResult(
                output={"receiptId": "browser-receipt-test-only", "status": "TEST_ONLY"},
                metadata={"accepted": True},
            )

        return {
            TaskTransport.A2A: CallableTaskAdapter(research),
            TaskTransport.MCP: CallableTaskAdapter(tool),
        }

    return provider


def main() -> None:
    activate_default = os.environ.get("AGENT_INTERLOCK_TEST_EMPTY_DEPLOYMENT") != "1"
    origins = frozenset(
        {
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3001",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        }
    )
    ledger = InMemoryLedger()
    with tempfile.TemporaryDirectory() as root, RunningRunControl(
        root,
        _adapter_provider(ledger),
        activate=activate_default,
        allowed_origins=origins,
        ledger=ledger,
    ) as plane:
        print(  # noqa: T201 - human-operated test fixture announces its endpoint
            json.dumps(
                {
                    "url": f"http://127.0.0.1:{plane.server.server_address[1]}",
                    "token": OPERATOR_TOKEN,
                    "data": "TEST_ONLY",
                    "activeDefault": activate_default,
                }
            ),
            flush=True,
        )
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            return


if __name__ == "__main__":
    main()
