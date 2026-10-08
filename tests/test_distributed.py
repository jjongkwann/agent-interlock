"""Durable whole-run leases, conservative recovery, and real configured execution."""

import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path

from test_candidate_compare import graph

from agent_interlock.architecture import ArchitectureCompiler
from agent_interlock.configurable_runtime import configurable_adapter_provider
from agent_interlock.distributed import DistributedCoordinator
from agent_interlock.ledger import Event, InMemoryLedger, build_event
from agent_interlock.ledger_http import LedgerAPIError, LedgerAPIPrincipal
from agent_interlock.orchestration import OrchestrationEngine, WorkflowRunState
from agent_interlock.studio_deploy import DeploymentBundle, GitBundleStore, compile_review_bundle, deployed_architecture
from agent_interlock.workflow_store import SQLiteWorkflowRunStore, _decode


class DistributedTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.store = SQLiteWorkflowRunStore(self.path / "runs.sqlite3")
        self.bundles = GitBundleStore(self.path / "bundles", tenant_id="tenant-a")
        self.ledger = InMemoryLedger()
        self.worker = LedgerAPIPrincipal("worker", "tenant-a", frozenset({"worker:execute"}))
        self.queue = self.coordinator()

    def coordinator(self):
        return DistributedCoordinator(
            SQLiteWorkflowRunStore(self.path / "runs.sqlite3"),
            self.bundles,
            self.ledger,
            worker_projects={"worker": frozenset({"comparison"})},
            lease_seconds=30,
        )

    def create(self, run_id="run", *, approval=False):
        value = graph()
        if approval:
            value = replace(
                value,
                orchestration=replace(
                    value.orchestration, tasks=(replace(value.orchestration.tasks[0], approval_required=True),)
                ),
            )
        bundle = DeploymentBundle.from_compile_output(compile_review_bundle(value))
        self.bundles.propose(bundle)
        compiled = replace(
            ArchitectureCompiler().compile(deployed_architecture(bundle.body, "ENFORCE")),
            bundle_digest=bundle.bundle_digest,
        )
        engine = OrchestrationEngine(
            compiled, run_store=self.store, ledger=self.ledger, bundle_digest=bundle.bundle_digest
        )
        run = engine.create(tenant_id="tenant-a", workflow_input={"name": "Ada"}, run_id=run_id)
        self.queue.enqueue("tenant-a", run.id)
        return run

    def claim(self, session="session", queue=None):
        return (queue or self.queue).api(self.worker, "claim", {"sessionId": session, "credentialRefs": []})["claim"]

    def call(self, claim, action, **extra):
        return self.queue.api(
            self.worker,
            action,
            {"runId": claim["runId"], "sessionId": claim["owner"], "fence": claim["fence"], **extra},
        )

    def save(self, claim, **changes):
        snapshot = self.call(claim, "get")
        snapshot["run"].update(changes)
        return self.call(claim, "save", **snapshot)

    def expire(self, run_id="run"):
        with self.store._transaction() as connection:
            connection.execute("UPDATE workflow_dispatch SET expires=0 WHERE run_id=?", (run_id,))

    def test_atomic_claim_and_generation_survive_restart_and_prune(self):
        self.create()
        other = self.coordinator()
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(pool.map(lambda item: self.claim(*item), [("one", self.queue), ("two", other)]))
        lease = next(claim for claim in claims if claim)
        self.assertEqual(sum(claim is not None for claim in claims), 1)
        self.assertIsNone(self.claim("third", self.coordinator()))
        self.expire()
        new = self.claim("new")
        self.assertGreater(new["fence"], lease["fence"])
        with self.assertRaisesRegex(LedgerAPIError, "lease"):
            self.call(lease, "start")
        self.call(new, "start")
        self.save(new, state="COMPLETED")
        # Prune may race a terminal worker's final ledger events before finish().
        self.assertEqual(self.store.prune(tenant_id="tenant-a", before="2999-01-01T00:00:00Z"), 1)
        self.create()
        with self.assertRaises(LedgerAPIError):
            self.call(new, "get")
        reused = self.claim(new["owner"])
        self.assertGreater(reused["fence"], new["fence"])
        with self.assertRaises(LedgerAPIError):
            self.call(new, "get")

    def test_started_expiry_and_orphan_running_are_never_replayed(self):
        run = self.create()
        lease = self.claim()
        self.call(lease, "start")
        self.expire()
        self.queue = self.coordinator()
        self.assertIsNone(self.claim("replacement"))
        failed = self.store.get(tenant_id="tenant-a", run_id=run.id)
        self.assertEqual(failed.error_code, "RUN-EFFECT-UNCERTAIN")
        self.assertEqual(failed.state, WorkflowRunState.FAILED)
        with self.assertRaises(LedgerAPIError):
            self.call(lease, "save", revision=lease["revision"], run=lease["run"])
        self.queue.enqueue("tenant-a", run.id)
        self.assertIsNone(self.claim("retry"))
        self.create("orphan")
        run = self.store.get(tenant_id="tenant-a", run_id="orphan")
        self.store.save(replace(run, state=WorkflowRunState.RUNNING))
        with self.store._transaction() as connection:
            connection.execute("DELETE FROM workflow_dispatch WHERE run_id='orphan'")
        self.coordinator()
        self.assertEqual(self.store.get(tenant_id="tenant-a", run_id="orphan").error_code, "RUN-EFFECT-UNCERTAIN")

    def test_cas_immutable_approvals_and_wakeup_finish_race(self):
        self.create(approval=True)
        lease = self.claim()
        self.call(lease, "start")
        snapshot = self.call(lease, "get")
        for changed in (
            {"workflow_input": {"secret": "replacement"}},
            {"approvals": {"transform": "worker"}},
            {"tasks": {}},
            {"trace_id": "other-trace"},
        ):
            with self.subTest(changed=changed), self.assertRaises(LedgerAPIError):
                self.call(lease, "save", revision=snapshot["revision"], run={**snapshot["run"], **changed})
        snapshot["run"]["state"] = "WAITING_APPROVAL"
        snapshot["run"]["tasks"]["transform"]["state"] = "WAITING_APPROVAL"
        saved = self.call(lease, "save", **snapshot)
        self.store.approve(tenant_id="tenant-a", run_id="run", task_id="transform", approved_by="human")
        self.queue.enqueue("tenant-a", "run")
        with self.assertRaises(LedgerAPIError) as conflict:
            self.call(lease, "save", **saved)
        self.assertEqual(conflict.exception.code, "WORKER-REVISION-CONFLICT")
        fresh = self.call(lease, "get")
        self.assertEqual(fresh["run"]["approvals"], {"transform": "human"})
        self.call(lease, "finish")
        self.assertEqual(self.claim("resumed")["run"]["approvals"], {"transform": "human"})

    def test_cancellation_dominates_and_finishing_lease_retains_final_evidence(self):
        run = self.create()
        lease = self.claim()
        self.call(lease, "start")
        self.store.save(replace(run, state=WorkflowRunState.CANCELED))
        self.assertTrue(self.call(lease, "heartbeat")["canceled"])
        with self.assertRaises(LedgerAPIError):
            self.call(lease, "start")
        snapshot = self.call(lease, "get")
        snapshot["run"]["state"] = "COMPLETED"
        self.assertEqual(self.call(lease, "save", **snapshot)["run"]["state"], WorkflowRunState.CANCELED)
        self.call(lease, "finish")
        with self.assertRaises(LedgerAPIError):
            self.call(lease, "heartbeat")

    def test_approval_wakeup_is_atomic_and_session_registry_is_bounded(self):
        self.create(approval=True)
        lease = self.claim("leased")
        self.call(lease, "start")
        snapshot = self.call(lease, "get")
        snapshot["run"]["state"] = "WAITING_APPROVAL"
        snapshot["run"]["tasks"]["transform"]["state"] = "WAITING_APPROVAL"
        self.call(lease, "save", **snapshot)
        for index in range(20):
            self.assertIsNone(self.claim(f"idle-{index}"))
        self.assertEqual(len(self.queue._workers), 2)
        self.call(lease, "finish")
        self.store.approve(tenant_id="tenant-a", run_id="run", task_id="transform", approved_by="human")
        # Simulate coordinator exit before the caller reaches enqueue().
        restarted = self.coordinator()
        resumed = self.claim("after-restart", restarted)
        self.assertEqual(resumed["run"]["approvals"], {"transform": "human"})

    def test_real_configured_engine_and_guarded_ledger_through_fenced_api(self):
        self.create()
        claim = self.claim()
        self.call(claim, "start")
        test = self

        class RemoteStore:
            def get(self, **_):
                response = test.call(claim, "get")
                self.revision = response["revision"]
                return _decode(json.dumps(response["run"]))

            def save(self, run):
                response = test.call(claim, "save", run=asdict(run), revision=self.revision)
                self.revision = response["revision"]

        class RemoteLedger:
            def append(self, event_type, **fields):
                fields.pop("idempotency_key", None)
                event = build_event(event_type, **fields)
                return Event(**test.call(claim, "append", event=event.to_dict())["event"])

            def trace(self, *_):
                return tuple(Event(**value) for value in test.call(claim, "trace")["events"])

        compiled = replace(
            ArchitectureCompiler().compile(deployed_architecture(claim["bundle"], "ENFORCE")),
            bundle_digest=claim["bundleDigest"],
        )
        store, ledger = RemoteStore(), RemoteLedger()
        engine = OrchestrationEngine(
            compiled,
            run_store=store,
            ledger=ledger,
            adapters=configurable_adapter_provider(ledger, store, {})(compiled),
            bundle_digest=claim["bundleDigest"],
        )
        result = engine.resume(tenant_id="tenant-a", run_id="run")
        self.assertEqual(result.state, WorkflowRunState.COMPLETED, result)
        self.assertEqual(result.tasks["transform"].output, {"name": "Ada"})
        self.assertTrue(result.tasks["transform"].security_met)
        types = {event["event_type"] for event in self.call(claim, "trace")["events"]}
        self.assertTrue({"DATA_FLOW_OBSERVED", "SECURITY_OUTCOME_SET", "WORKFLOW_RUN_COMPLETED"} <= types, types)
        forged = build_event(
            "WORKFLOW_TASK_APPROVED",
            tenant_id="tenant-a",
            trace_id=result.trace_id,
            span_id="fake",
            source_actor_id="agent",
            payload={"runId": "run"},
        )
        with self.assertRaises(LedgerAPIError):
            self.call(claim, "append", event=forged.to_dict())
        self.call(claim, "finish")
        with self.assertRaises(LedgerAPIError):
            self.call(claim, "trace")

    def test_worker_scope_readiness_and_additive_migration(self):
        self.assertFalse(self.queue.status("tenant-a")["workers"][0]["online"])
        self.assertFalse(self.queue.readiness(graph())["ready"])
        self.claim()
        self.assertTrue(self.queue.readiness(graph())["ready"])
        for principal in (
            replace(self.worker, scopes=frozenset()),
            replace(self.worker, tenant_id="another"),
            replace(self.worker, subject="other"),
        ):
            with self.subTest(principal=principal), self.assertRaises(LedgerAPIError):
                self.queue.api(principal, "claim", {"sessionId": "session", "credentialRefs": []})
        legacy = self.path / "legacy.sqlite3"
        run = self.create()
        with sqlite3.connect(legacy) as connection:
            connection.execute(
                "CREATE TABLE workflow_runs (tenant_id TEXT,run_id TEXT,state TEXT,updated_at TEXT,"
                "body TEXT,PRIMARY KEY(tenant_id,run_id))"
            )
            connection.execute(
                "INSERT INTO workflow_runs VALUES (?,?,?,?,?)",
                (run.tenant_id, run.id, run.state.value, run.updated_at, json.dumps(asdict(run))),
            )
            connection.execute("PRAGMA user_version=1")
        migrated = SQLiteWorkflowRunStore(legacy)
        self.assertEqual(migrated.get(tenant_id="tenant-a", run_id=run.id), run)
        with sqlite3.connect(legacy) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertEqual(connection.execute("SELECT revision FROM workflow_runs").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
