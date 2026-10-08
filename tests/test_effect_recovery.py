"""Lost acknowledgements must reconcile before an approved write can resume."""
import json
import sqlite3
import tempfile
import time
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

from test_configurable_runtime import engine, graph
from test_workflow_store import sample_run

from agent_interlock.effects import EffectJournal, EffectResolution, EffectStatus, reconcile_effects
from agent_interlock.orchestration import OrchestrationError, WorkflowRunState
from agent_interlock.workflow_store import SQLiteWorkflowRunStore


class EffectRecoveryTests(unittest.TestCase):
    def setup_run(self, *, before_commit=False):
        self.calls, self.committed = [], []

        def request(_endpoint, _method, body, headers, **_):
            self.calls.append(headers["Idempotency-Key"])
            if before_commit and len(self.calls) == 1:
                raise TimeoutError("request lost before arrival")
            self.committed.append(json.loads(body))
            if len(self.calls) == 1:
                raise TimeoutError("response lost after commit")
            return 200, {"Content-Type": "application/json"}, body

        value = graph(http=True)
        value = replace(value, orchestration=replace(value.orchestration, tasks=(
            replace(value.orchestration.tasks[0], max_attempts=1),)))
        self.runner, self.store, self.ledger = engine(value, http_request=request)
        held = self.runner.start(tenant_id="tenant", workflow_input={"tasks": {"transform": {"name": "Ada"}}})
        self.assertEqual(held.state, WorkflowRunState.WAITING_APPROVAL)
        self.assertEqual(self.calls, [])
        pending = held.tasks["transform"].pending_call
        self.store.approve(tenant_id="tenant", run_id=held.id,
                           task_id="transform:" + pending["requestId"], approved_by="human")
        self.run = self.runner.resume(tenant_id="tenant", run_id=held.id)
        self.assertEqual(self.run.error_code, "RUN-EFFECT-UNCERTAIN")
        self.assertEqual(len(self.calls), 1, "generic task retry must not repeat a write")
        self.checkpoint = self.run.tasks["transform"].effect_checkpoint
        self.assertEqual(self.checkpoint["state"], "STARTED")

    def resolve(self, status, **kwargs):
        return reconcile_effects(self.store, self.ledger, run=self.run, resolver=lambda *_: EffectResolution(
            status, self.checkpoint["idempotencyKey"], self.checkpoint["invocationDigest"],
            "external receipt", **kwargs))

    def test_committed_receipt_restores_output_without_second_write(self):
        self.setup_run()
        recovered, report = self.resolve(EffectStatus.COMPLETED, result={"name": "Ada"})
        self.assertEqual(report["transform"]["status"], "COMPLETED")
        self.assertEqual(recovered.approvals, self.run.approvals)
        self.assertEqual(recovered.tasks["transform"].attempts, 0)
        completed = self.runner.resume(tenant_id="tenant", run_id=self.run.id)
        self.assertEqual(completed.state, WorkflowRunState.COMPLETED)
        self.assertEqual(completed.tasks["transform"].output, {"name": "Ada"})
        self.assertEqual(self.committed, [{"name": "Ada"}])
        self.assertEqual(len(self.calls), 1)
        phases = {e.payload.get("effectPhase") for e in self.ledger.trace("tenant", completed.trace_id)}
        self.assertTrue({"dispatch", "reconciled", "restore", "completed"} <= phases)

    def test_authoritatively_fenced_nonexecution_uses_new_key_same_approval(self):
        self.setup_run(before_commit=True)
        recovered, report = self.resolve(EffectStatus.NOT_EXECUTED, fenced=True)
        self.assertEqual(report["transform"]["status"], "NOT_EXECUTED")
        self.assertEqual(recovered.approvals, self.run.approvals)
        completed = self.runner.resume(tenant_id="tenant", run_id=self.run.id)
        self.assertEqual(completed.state, WorkflowRunState.COMPLETED)
        self.assertEqual(len(set(self.calls)), 2)
        self.assertEqual(self.committed, [{"name": "Ada"}])

    def test_unknown_missing_fence_and_mismatched_receipt_never_revive(self):
        for status, options in ((EffectStatus.UNKNOWN, {}), (EffectStatus.NOT_EXECUTED, {}),
                                (EffectStatus.NOT_EXECUTED, {"fenced": "false"}),
                                (EffectStatus.NOT_EXECUTED, {"fenced": 1}),
                                (EffectStatus.COMPLETED, {"result": {"name": object()}}),
                                (EffectStatus.COMPLETED, {})):
            with self.subTest(status=status):
                self.setup_run()
                failed, reports = self.resolve(status, **options)
                self.assertEqual(failed.state, WorkflowRunState.FAILED)
                self.assertEqual(reports["transform"]["status"], "UNKNOWN")
                self.runner.resume(tenant_id="tenant", run_id=self.run.id)
                self.assertEqual(len(self.calls), 1)
        self.setup_run()
        failed, reports = reconcile_effects(self.store, self.ledger, run=self.run, resolver=lambda *_:
            EffectResolution(EffectStatus.COMPLETED, "wrong-key", self.checkpoint["invocationDigest"],
                             "receipt", result={"name": "Ada"}))
        self.assertEqual(failed.state, WorkflowRunState.FAILED)
        self.assertEqual(reports["transform"]["status"], "UNKNOWN")

    def test_restored_result_still_passes_output_policy(self):
        self.setup_run()
        self.resolve(EffectStatus.COMPLETED, result={"wrong": "schema"})
        result = self.runner.resume(tenant_id="tenant", run_id=self.run.id)
        self.assertEqual(result.tasks["transform"].output,
                         {"quarantined": True, "reason": "result schema validation failed"})
        self.assertEqual(len(self.calls), 1)

    def test_canceled_run_and_concurrent_state_change_cannot_be_revived(self):
        self.setup_run()
        canceled = replace(self.run, state=WorkflowRunState.CANCELED)
        self.store.recover_effects(self.run, canceled)
        with self.assertRaises(OrchestrationError):
            self.resolve(EffectStatus.COMPLETED, result={"name": "Ada"})
        with self.assertRaises(OrchestrationError):
            reconcile_effects(self.store, self.ledger, run=canceled, resolver=lambda *_: None)

    def test_expired_or_reused_run_input_cannot_dispatch_an_effect(self):
        self.setup_run()
        journal = EffectJournal(self.store, self.ledger)
        for deadline, generation, reason in (
            (time.time() - 1, self.run.created_at, "ORCH-TASK-DEADLINE"),
            (time.time() + 10, "previous-run-generation", "RUN-EFFECT-GENERATION-MISMATCH"),
        ):
            value = SimpleNamespace(tenant_id="tenant", run_id=self.run.id, run_generation=generation,
                                    deadline_epoch=deadline)
            with self.assertRaises(OrchestrationError) as caught:
                journal.execute(value, self.checkpoint["invocation"], lambda *_: self.fail("must not dispatch"))
            self.assertEqual(caught.exception.reason_code, reason)

    def test_sqlite_v2_migration_preserves_input_output_and_approval(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "runs.db"
            run = replace(sample_run(), approvals={"task": "human"})
            raw = asdict(run)
            del raw["tasks"]["task"]["effect_checkpoint"]
            with sqlite3.connect(path) as connection:
                connection.execute("CREATE TABLE workflow_runs (tenant_id TEXT,run_id TEXT,state TEXT,"
                                   "updated_at TEXT,body TEXT,revision INTEGER NOT NULL DEFAULT 7,"
                                   "PRIMARY KEY(tenant_id,run_id))")
                connection.execute("INSERT INTO workflow_runs VALUES (?,?,?,?,?,7)",
                                   (run.tenant_id, run.id, run.state, run.updated_at, json.dumps(raw)))
                connection.execute("PRAGMA user_version=2")
            store = SQLiteWorkflowRunStore(path)
            self.assertEqual(store.get(tenant_id=run.tenant_id, run_id=run.id), run)
            with sqlite3.connect(path) as connection:
                self.assertEqual(connection.execute("SELECT revision FROM workflow_runs").fetchone()[0], 7)
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)

    def test_parallel_effect_checkpoints_survive_wave_save(self):
        import threading
        value = graph(http=True)
        first = value.orchestration.tasks[0]
        second = replace(first, id="second")
        value = replace(value, orchestration=replace(value.orchestration, tasks=(first, second),
            run_policy=replace(value.orchestration.run_policy, max_parallelism=2)))
        barrier = threading.Barrier(2)
        keys = []

        def request(_endpoint, _method, body, headers, **_):
            keys.append(headers["Idempotency-Key"])
            barrier.wait(timeout=5)
            return 200, {"Content-Type": "application/json"}, body

        runner, store, _ = engine(value, http_request=request)
        run = runner.start(tenant_id="tenant", workflow_input={"tasks": {
            "transform": {"name": "Ada"}, "second": {"name": "Grace"}}})
        for key, task in run.tasks.items():
            store.approve(tenant_id="tenant", run_id=run.id, approved_by="human",
                          task_id=key + ":" + task.pending_call["requestId"])
        completed = runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(completed.state, WorkflowRunState.COMPLETED)
        self.assertEqual(len(set(keys)), 2)
        self.assertTrue(all(t.effect_checkpoint["state"] == "COMPLETED" for t in completed.tasks.values()))


if __name__ == "__main__":
    unittest.main()
