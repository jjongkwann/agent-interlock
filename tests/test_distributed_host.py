"""Real HTTP and separate worker processes share one durable coordinator."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import test_local_host
from test_candidate_compare import bundle, graph
from test_run_control import CRYPTO_AVAILABLE

from agent_interlock.local_host import _local_principals, bootstrap, serve_local
from agent_interlock.studio_deploy import GitBundleStore, TrustedApprovalKey, sign_deployment_approval

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(CRYPTO_AVAILABLE, "Ed25519 backend required")
class DistributedHostTests(unittest.TestCase):
    request = staticmethod(test_local_host.LocalHostTests.request)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        bootstrap(self.path)
        self.token = (self.path / "operator.token").read_text().strip()
        workers = [{"subject": f"worker-{n}", "tokenEnv": f"INTERLOCK_DIST_TEST_{n}", "projects": ["comparison"]}
                   for n in (1, 2)]
        config = self.path / "workers.json"
        config.write_text(json.dumps(workers))
        config.chmod(0o600)
        self.tokens = {f"INTERLOCK_DIST_TEST_{n}": f"distributed-worker-{n}-test-only" for n in (1, 2)}
        self.environment = patch.dict(os.environ, self.tokens)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.store = GitBundleStore(self.path / "bundles", tenant_id="tenant-local")

    def promote(self, *, approval=False):
        architecture = graph()
        if approval:
            architecture = replace(architecture, orchestration=replace(architecture.orchestration,
                tasks=(replace(architecture.orchestration.tasks[0], approval_required=True),)))
        value = bundle(architecture)
        self.store.propose(value)
        public = json.loads((self.path / "trusted-approvers.json").read_text())
        trusted = {key: TrustedApprovalKey(item["approverId"], bytes.fromhex(item["publicKeyHex"]))
                   for key, item in public.items()}
        approvals = [sign_deployment_approval(value, from_digest=None, to_mode="ENFORCE",
            target_id=self.store.target_id, tenant_id=self.store.tenant_id, approver_id=key, key_id=key,
            key=bytes.fromhex((self.path / "reviewers" / f"{key}.key").read_text().strip())) for key in public]
        self.store.promote(value.bundle_digest, approvals, trusted_approvers=trusted)

    def worker(self, server, number):
        return subprocess.Popen([sys.executable, "-m", "agent_interlock", "worker", "--coordinator",
            f"http://127.0.0.1:{server.server_port}", "--token-env", f"INTERLOCK_DIST_TEST_{number}",
            "--target-id", self.store.target_id, "--tenant", self.store.tenant_id, "--once", "--allow-loopback-http"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def finish(self, process):
        try:
            output, error = process.communicate(timeout=20)
            self.assertEqual(process.returncode, 0, output + error)
            for token in self.tokens.values():
                self.assertNotIn(token, output + error)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)

    def test_two_processes_compete_without_duplicate_execution_and_restart_preserves_result(self):
        self.promote()
        with serve_local(self.path, port=0, dispatch="remote") as server:
            status, _, created = self.request(server, "POST", "/v1/runs", token=self.token,
                                             body={"input": {"message": "distributed"}, "runId": "race"})
            self.assertEqual(status, 202, created)
            self.assertEqual(created["run"]["state"], "PENDING")
            processes = [self.worker(server, n) for n in (1, 2)]
            for process in processes:
                self.finish(process)
            result = self.request(server, "GET", "/v1/runs/race", token=self.token)[2]["run"]
            self.assertEqual(result["state"], "COMPLETED", result)
            self.assertEqual(result["tasks"]["transform"]["output"], {"message": "distributed"})
            events = self.request(server, "GET", "/v1/runs/race/events", token=self.token)[2]["events"]
            self.assertEqual(sum(event["event_type"] == "WORKFLOW_RUN_STARTED" for event in events), 1)
            diagnostics = self.request(server, "GET", "/v1/runtime/status", token=self.token)[2]
            self.assertEqual(diagnostics["capabilities"]["scheduler"], "REMOTE_WORKERS")
            self.assertEqual(len(diagnostics["distributed"]["workers"]), 2)
            for token in self.tokens.values():
                self.assertNotIn(token, json.dumps(diagnostics))
        with serve_local(self.path, port=0, dispatch="remote") as server:
            result = self.request(server, "GET", "/v1/runs/race", token=self.token)[2]["run"]
            self.assertEqual(result["state"], "COMPLETED")
            self.finish(self.worker(server, 2))

    def test_approval_handoff_to_another_worker_and_scope_separation(self):
        self.promote(approval=True)
        with serve_local(self.path, port=0, dispatch="remote") as server:
            self.assertEqual(self.request(server, "POST", "/v1/workers/claim", token=self.token,
                body={"sessionId": "operator-must-not-execute", "credentialRefs": []})[0], 403)
            worker_token = self.tokens["INTERLOCK_DIST_TEST_1"]
            self.assertEqual(self.request(server, "GET", "/v1/runs", token=worker_token)[0], 403)
            self.assertEqual(self.request(server, "POST", "/v1/runs", token=self.token,
                body={"input": {"message": "approved"}, "runId": "handoff"})[0], 202)
            self.finish(self.worker(server, 1))
            run = self.request(server, "GET", "/v1/runs/handoff", token=self.token)[2]["run"]
            self.assertEqual(run["state"], "WAITING_APPROVAL", run)
            status, _, value = self.request(server, "POST", "/v1/runs/handoff/tasks/transform/approve",
                                             token=self.token, body={})
            self.assertEqual(status, 202, value)
            self.finish(self.worker(server, 2))
            run = self.request(server, "GET", "/v1/runs/handoff", token=self.token)[2]["run"]
            self.assertEqual(run["state"], "COMPLETED", run)
            self.assertEqual(run["approvals"], {"transform": "local-operator"})

    def test_worker_tokens_and_private_enrollment_cannot_impersonate_operator(self):
        path = self.path / "workers.json"
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "0600"):
            _local_principals(self.path, self.store.tenant_id, self.token, remote=True)
        path.chmod(0o600)
        entries = json.loads(path.read_text())
        entries[0]["subject"] = "local-operator"
        path.write_text(json.dumps(entries))
        with self.assertRaisesRegex(ValueError, "distinct"):
            _local_principals(self.path, self.store.tenant_id, self.token, remote=True)
