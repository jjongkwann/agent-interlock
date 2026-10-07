"""Promoted bundle -> actual callable -> digest-bound evidence and persisted operator approval."""
from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path

from agent_interlock import InMemoryLedger
from agent_interlock.__main__ import main
from agent_interlock.managed_runtime import build_managed_tools, load_promoted_architecture
from agent_interlock.run_control import RunControlService
from agent_interlock.signing import ed25519_public_key_bytes
from agent_interlock.studio_deploy import DeploymentBundle, GitBundleStore, TrustedApprovalKey, sign_deployment_approval
from agent_interlock.workflow_store import SQLiteWorkflowRunStore

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from examples.support_agent.build import BINDINGS, TENANT_ID  # noqa: E402
from examples.support_agent.host import single_owner  # noqa: E402
from examples.support_agent.managed import adapter_provider, build, manifest  # noqa: E402
from examples.support_agent.tools import OUTBOX  # noqa: E402


class ManagedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.ledger = InMemoryLedger()
        OUTBOX.clear()
        if self._testMethodName in {"test_local_missing_provenance_and_export_estimate", "test_single_host_lock"}:
            return
        root = Path(self.directory.name)
        path = root / "manifest.json"
        path.write_text(json.dumps(manifest()))
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["architecture", "compile", "--shadow", str(path)]), 0)
        self.bundle = DeploymentBundle.from_compile_output(json.loads(output.getvalue()))
        self.store = GitBundleStore(root / "review")
        self.store.propose(self.bundle)
        trusted, approvals = {}, []
        for index in (1, 2):
            key = bytes([index]) * 32
            name = f"reviewer-{index}"
            trusted[name] = TrustedApprovalKey(name, ed25519_public_key_bytes(key))
            approvals.append(sign_deployment_approval(
                self.bundle, from_digest=None, to_mode="ENFORCE", approver_id=name, key_id=name, key=key,
                target_id=self.store.target_id, tenant_id=self.store.tenant_id,
            ))
        self.store.promote(self.bundle.bundle_digest, tuple(approvals), trusted_approvers=trusted)

    @unittest.skipUnless(importlib.util.find_spec("cryptography"), "cryptography ('jwt' extra) is required")
    def test_exact_bundle_allowed_denied_and_hooks(self):
        gateway, tools = build(store=self.store, ledger=self.ledger, approve=lambda _args, _decision: "human")
        self.assertEqual(json.loads(tools[0].call({"order_id": "1001"}))["order_id"], "1001")
        with self.assertRaises(Exception):
            tools[1].call({"to": "attacker@evil.example", "subject": "Status", "body": "Hello"})
        self.assertEqual(OUTBOX, [])
        tools[1].call({"to": "dana@customer.example", "subject": "Status", "body": "Hello"})
        self.assertEqual(len(OUTBOX), 1)
        controls = [event.payload for event in self.ledger.all() if "installedHooks" in event.payload]
        self.assertTrue(controls)
        self.assertTrue(all(value["bundleDigest"] == self.bundle.bundle_digest for value in controls))
        self.assertTrue(all(all(value["installedHooks"].values()) for value in controls))
        completed = [e.payload for e in self.ledger.all() if e.event_type == "INTERACTION_COMPLETED"]
        self.assertEqual(completed[0]["provenance"]["dataClasses"], ["D3"])
        self.assertIsNotNone(gateway.actor("user.customer"))
        bad = replace(BINDINGS[0], definition=replace(BINDINGS[0].definition, description="Changed description"))
        with self.assertRaisesRegex(ValueError, "digest"):
            build_managed_tools(load_promoted_architecture(self.store), bindings=[bad], tenant_id=TENANT_ID,
                                source_actor_id="agent.support", ledger=self.ledger, approver="reviewer")
        missing = replace(BINDINGS[0], result_provenance=None)
        with self.assertRaisesRegex(ValueError, "hooks"):
            build_managed_tools(load_promoted_architecture(self.store), bindings=[missing], tenant_id=TENANT_ID,
                                source_actor_id="agent.support", ledger=self.ledger, approver="reviewer")

    @unittest.skipUnless(importlib.util.find_spec("cryptography"), "cryptography ('jwt' extra) is required")
    def test_run_waits_for_human_and_resumes_actual_callable(self):
        runs = SQLiteWorkflowRunStore(Path(self.directory.name) / "runs.db")
        self.addCleanup(runs.close)
        service = RunControlService(self.store, adapter_provider(self.ledger, runs), ledger=self.ledger, run_store=runs)
        self.addCleanup(service.close)
        run = service.create(tenant_id=TENANT_ID, workflow_input={
            "lookup_order": {"order_id": "1001"},
            "send_email": {"to": "dana@customer.example", "subject": "Status", "body": "Your order shipped"},
        })
        def wait_for(state):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                current = service.get(tenant_id=TENANT_ID, run_id=run["id"])
                if current["state"] == state:
                    return current
                time.sleep(.01)
            self.fail(str(current))
        wait_for("WAITING_APPROVAL")
        self.assertEqual(OUTBOX, [])
        service.approve(tenant_id=TENANT_ID, run_id=run["id"], task_id="send-email", approved_by="actual-operator")
        wait_for("COMPLETED")
        self.assertEqual(len(OUTBOX), 1)
        self.assertEqual(runs.get(tenant_id=TENANT_ID, run_id=run["id"]).approvals["send-email"], "actual-operator")

    def test_local_missing_provenance_and_export_estimate(self):
        from examples.support_agent.build import build as build_local
        binding = replace(BINDINGS[0], result_provenance=None)
        gateway, tools = build_local(bindings=[binding, BINDINGS[1]], ledger=self.ledger)
        tools[0].call({"order_id": "1001"})
        completed = [e for e in self.ledger.all() if e.event_type == "INTERACTION_COMPLETED"]
        self.assertEqual(completed[0].payload["provenance"], {"classificationStatus": "UNCLASSIFIED"})
        policy = gateway.link_policy("agent.support", binding.actor_id)
        gateway.connect("agent.support", binding.actor_id, replace(policy, max_export_bytes=1))
        with self.assertRaises(Exception):
            tools[0].call({"order_id": "1001"})
        controls = [e.payload["control"] for e in self.ledger.all() if "control" in e.payload]
        self.assertTrue(any("L1-M9-VOLUME-EXCEEDED" in item["reasonCodes"] for item in controls))

    def test_single_host_lock(self):
        path = Path(self.directory.name) / "host.lock"
        with single_owner(path), self.assertRaisesRegex(RuntimeError, "another managed host"):
            with single_owner(path):
                pass
