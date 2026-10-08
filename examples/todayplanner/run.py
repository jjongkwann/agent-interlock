"""Run with: PYTHONPATH=src python -m examples.todayplanner.run --todayplanner ../todayPlanner."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from agent_interlock.effects import reconcile_effects
from agent_interlock.managed_runtime import build_managed_tools
from agent_interlock.orchestration import OrchestrationEngine, WorkflowRunState
from agent_interlock.sqlite_ledger import SQLiteLedger
from agent_interlock.workflow_store import SQLiteWorkflowRunStore

from .client import PlannerClient, fingerprint, local_fixture
from .workflow import SOURCE, TENANT, adapters, architecture, bindings, resolver


def _engine(compiled, client, store, ledger, *, fault=None):
    return OrchestrationEngine(compiled, run_store=store, ledger=ledger,
        bundle_digest=compiled.bundle_digest, adapters=adapters(compiled, client, store, ledger, fault=fault),
        approval_provider=lambda tenant, run, task, _: task.id in store.get(tenant_id=tenant, run_id=run).approvals)


def _assert_blocked(function, expected):
    try:
        function()
    except Exception as error:
        assert expected in str(error), str(error)
        return expected
    raise AssertionError("forbidden call unexpectedly succeeded")


def run_demo(project: Path, evidence_directory: Path):
    evidence_directory.mkdir(parents=True, exist_ok=True)
    store = SQLiteWorkflowRunStore(evidence_directory / "runs.sqlite3")
    ledger = SQLiteLedger(evidence_directory / "ledger.sqlite3")
    with local_fixture(project) as fixture:
        client = PlannerClient(fixture["base"], fixture["token"])
        other = PlannerClient(fixture["base"], fixture["otherToken"])
        readonly = PlannerClient(fixture["base"], fixture["readOnlyToken"])
        original = client.state()
        args = {"taskId": fixture["taskId"], "expectedRevision": original["revision"], "patch": {"startMinute": 660}}
        compiled = architecture(660)
        unauthorized_calls = []
        for purpose, approve, expected in [("UPDATE_SCHEDULE", None, "INTERLOCK-APPROVAL-REQUIRED"),
                                            ("DELETE_SCHEDULE", lambda *_: "operator", "PURPOSE")]:
            binding = bindings(client, send=lambda _: unauthorized_calls.append(True), write_purpose=purpose)[1]
            _, guarded = build_managed_tools(compiled, bindings=[binding], tenant_id=TENANT,
                source_actor_id=SOURCE, ledger=ledger, approver="reviewed-policy", approve=approve)
            _assert_blocked(lambda: guarded[0].call(args), expected)
        assert unauthorized_calls == []
        _assert_blocked(lambda: readonly.update(args, "readonly-probe-001"), "403")
        _assert_blocked(lambda: other.update({**args, "expectedRevision": 0}, "foreign-account-probe-001"), "404")
        assert other.state()["tasks"] == []
        assert client.state() == original

        reports = []
        for fault, minute in [("after_commit", 660), ("before_commit", 720)]:
            prior_state = client.state()
            arguments = {"taskId": fixture["taskId"], "expectedRevision": prior_state["revision"],
                         "patch": {"startMinute": minute}}
            compiled = architecture(minute)
            engine = _engine(compiled, client, store, ledger, fault=fault)
            run = engine.start(tenant_id=TENANT, workflow_input={"change": arguments}, run_id=fault)
            assert run.state == WorkflowRunState.WAITING_APPROVAL, run
            assert client.state() == prior_state, "unapproved workflow changed the product"
            before_dispatch = client.write_attempts
            store.approve(tenant_id=TENANT, run_id=run.id, task_id="change", approved_by="fixture-human")
            failed = engine.resume(tenant_id=TENANT, run_id=run.id)
            assert failed.state == WorkflowRunState.FAILED and failed.error_code == "RUN-EFFECT-UNCERTAIN", failed
            checkpoint = failed.tasks["change"].effect_checkpoint
            assert checkpoint and checkpoint["state"] == "STARTED"
            assert client.write_attempts == before_dispatch + 1
            assert client.state()["revision"] == prior_state["revision"] + (fault == "after_commit")

            # Restore both run and ledger from disk; no in-memory receipt is authoritative.
            store.close()
            store = SQLiteWorkflowRunStore(evidence_directory / "runs.sqlite3")
            ledger = SQLiteLedger(evidence_directory / "ledger.sqlite3")
            failed = store.get(tenant_id=TENANT, run_id=run.id)
            other_result, other_reports = reconcile_effects(store, ledger, run=failed, resolver=resolver(other))
            assert other_reports["change"]["status"] == "UNKNOWN"
            assert other_result.state == WorkflowRunState.FAILED
            if fault == "after_commit":
                _assert_blocked(lambda: client.receipt(checkpoint["idempotencyKey"], "0" * 64), "409")
            recovered, resolution = reconcile_effects(store, ledger, run=other_result, resolver=resolver(client))
            missing_status = resolution["change"]["status"]
            if fault == "before_commit":
                assert missing_status == "UNKNOWN" and recovered.state == WorkflowRunState.FAILED
                recovered, resolution = reconcile_effects(store, ledger, run=recovered,
                                                         resolver=resolver(client, seal=True))
                assert resolution["change"]["status"] == "NOT_EXECUTED"
                _assert_blocked(lambda: client.update(arguments, checkpoint["idempotencyKey"]),
                                "OPERATION_NOT_EXECUTED")
                assert client.state() == prior_state
            else:
                assert missing_status == "COMPLETED"
            assert recovered.state == WorkflowRunState.PENDING
            assert recovered.approvals == failed.approvals
            resumed_dispatch = client.write_attempts
            finished = _engine(compiled, client, store, ledger).resume(tenant_id=TENANT, run_id=run.id)
            assert finished.state == WorkflowRunState.COMPLETED, finished
            assert client.write_attempts == resumed_dispatch + (fault == "before_commit")
            final = client.state()
            assert final["revision"] == prior_state["revision"] + 1, "duplicate write changed revision twice"
            assert len(final["tasks"]) == 1 and final["tasks"][0]["startMinute"] == minute
            current_checkpoint = finished.tasks["change"].effect_checkpoint
            assert current_checkpoint["sequence"] == (2 if fault == "before_commit" else 1)
            result = client.update(arguments, current_checkpoint["idempotencyKey"])
            assert result == finished.tasks["change"].output and client.state() == final
            _assert_blocked(lambda: client.update({**arguments, "patch": {"startMinute": minute + 5}},
                                                  current_checkpoint["idempotencyKey"]), "OPERATION_CONFLICT")
            assert client.state() == final
            events = ledger.trace(TENANT, finished.trace_id)
            assert any(event.payload.get("effectPhase") == "reconciled" for event in events)
            reports.append({"fault": fault, "runId": run.id, "traceId": finished.trace_id,
                "states": ["WAITING_APPROVAL", "RUN-EFFECT-UNCERTAIN", resolution["change"]["status"], "COMPLETED"],
                "initialLookup": missing_status, "crossAccountLookup": "UNKNOWN",
                "initialRevision": prior_state["revision"], "finalRevision": final["revision"],
                "startMinute": minute, "effectGeneration": current_checkpoint["sequence"],
                "idempotencyKey": current_checkpoint["idempotencyKey"],
                "requestFingerprint": fingerprint(arguments), "duplicateReplayChangedState": False,
                "evidenceEvents": len(events),
                "tasks": {key: value.state.value for key, value in finished.tasks.items()},
                "taskOutcomes": {key: {"goalMet": value.goal_met, "securityMet": value.security_met}
                                 for key, value in finished.tasks.items()}})
        store.close()
        return {"product": "todayPlanner", "backend": "actual Express/OAuth/SQLite with disposable synthetic accounts",
                "injectedFaults": "real loopback HTTP connection drops",
                "unapprovedDispatches": len(unauthorized_calls),
                "outOfPolicyDispatches": 0, "readOnlyWriteHTTP": 403, "foreignAccountWriteHTTP": 404,
                "scenarios": reports, "evidenceDirectory": str(evidence_directory.resolve()),
                "boundaries": ["local API and persisted workflow only", "no production deployment",
                               "no browser, mobile sync or notification verification"]}


def main():
    parser = argparse.ArgumentParser(description="Verify approved real todayPlanner writes under dropped HTTP replies")
    parser.add_argument("--todayplanner", type=Path, default=Path(__file__).resolve().parents[3] / "todayPlanner")
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    if args.evidence_dir:
        report = run_demo(args.todayplanner, args.evidence_dir)
        (args.evidence_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    else:
        with TemporaryDirectory(prefix="interlock-planner-") as temporary:
            report = run_demo(args.todayplanner, Path(temporary))
            report["evidenceDirectory"] = "temporary evidence removed; use --evidence-dir to retain"
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
