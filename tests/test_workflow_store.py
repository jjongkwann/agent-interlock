import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from test_run_control import CRYPTO_AVAILABLE, activate_bundle

from agent_interlock import (
    CallableTaskAdapter,
    GitBundleStore,
    InMemoryWorkflowRunStore,
    RunControlService,
    SQLiteWorkflowRunStore,
    TaskExecutionResult,
    TaskTransport,
    WorkflowRun,
    WorkflowRunState,
    WorkflowTaskRun,
    WorkflowTaskState,
)
from agent_interlock.orchestration import OrchestrationError


def sample_run():
    return WorkflowRun(
        "run-1",
        "architecture",
        "1",
        "tenant-a",
        "trace-1",
        WorkflowRunState.PENDING,
        {"request": "resume me"},
        {"task": WorkflowTaskRun("task")},
        "2026-09-11T00:00:00Z",
        "2026-09-11T00:00:00Z",
        bundle_digest="sha256:reviewed",
    )


class WorkflowPersistenceTests(unittest.TestCase):
    def test_restart_approval_tenant_capacity_and_explicit_retention(self):
        with tempfile.TemporaryDirectory() as root:
            for store in (
                InMemoryWorkflowRunStore(max_runs=1),
                SQLiteWorkflowRunStore(Path(root) / "runs.db", max_runs=1),
            ):
                with self.subTest(store=type(store).__name__):
                    run = sample_run()
                    store.create(run)
                    with self.assertRaises(OrchestrationError):
                        store.get(tenant_id="other", run_id=run.id)
                    store.approve(tenant_id=run.tenant_id, run_id=run.id, task_id="task", approved_by="reviewer")
                    store.save(replace(run, state=WorkflowRunState.WAITING_APPROVAL))
                    if isinstance(store, SQLiteWorkflowRunStore):
                        store = SQLiteWorkflowRunStore(store.path, max_runs=1)
                    self.assertEqual(store.get(tenant_id=run.tenant_id, run_id=run.id).approvals, {"task": "reviewer"})
                    self.assertEqual(store.prune(tenant_id=run.tenant_id, before="2027-01-01T00:00:00Z"), 0)
                    store.save(replace(run, state=WorkflowRunState.CANCELED))
                    store.save(replace(run, state=WorkflowRunState.RUNNING))
                    self.assertEqual(store.get(tenant_id=run.tenant_id, run_id=run.id).state, WorkflowRunState.CANCELED)
                    store.create(replace(run, id="run-2"))
                    self.assertEqual(len(store.list(tenant_id=run.tenant_id)), 2)
                    self.assertEqual(store.prune(tenant_id=run.tenant_id, before="2027-01-01T00:00:00Z"), 1)

    @unittest.skipUnless(CRYPTO_AVAILABLE, "Ed25519 backend required")
    def test_run_control_recovers_binding_approvals_and_marks_interrupted_work(self):
        with tempfile.TemporaryDirectory() as root:
            deployment = GitBundleStore(Path(root) / "deploy")
            bundle = activate_bundle(deployment)
            runs = SQLiteWorkflowRunStore(Path(root) / "runs.db")
            adapter = CallableTaskAdapter(lambda _: TaskExecutionResult({}))
            provider = lambda _: {transport: adapter for transport in TaskTransport}
            first = RunControlService(deployment, provider, run_store=runs)
            with patch.object(first, "_resume_async_locked"):
                first.create(tenant_id="tenant-a", workflow_input={}, run_id="waiting")
                first.create(tenant_id="tenant-a", workflow_input={}, run_id="interrupted")
            waiting = runs.get(tenant_id="tenant-a", run_id="waiting")
            runs.save(replace(waiting, state=WorkflowRunState.WAITING_APPROVAL, approvals={"task.reply": "human"}))
            interrupted = runs.get(tenant_id="tenant-a", run_id="interrupted")
            runs.save(
                replace(
                    interrupted,
                    state=WorkflowRunState.RUNNING,
                    tasks={
                        key: replace(task, state=WorkflowTaskState.RUNNING) for key, task in interrupted.tasks.items()
                    },
                )
            )
            second = RunControlService(deployment, provider, run_store=SQLiteWorkflowRunStore(runs.path))
            recovered = second.get(tenant_id="tenant-a", run_id="waiting")
            self.assertEqual(recovered["bundleDigest"], bundle.bundle_digest)
            self.assertEqual(recovered["approvals"], {"task.reply": "human"})
            self.assertEqual(second.get(tenant_id="tenant-a", run_id="interrupted")["errorCode"], "RUN-INTERRUPTED")
            with patch.object(deployment, "active", return_value=None):
                self.assertEqual(set(second.edge_modes(tenant_id="tenant-a", run_id="waiting").values()), {"ENFORCE"})
