"""Offline worker checks use the real configured execution and guarded ledger flow."""
import json
import threading
import time
import unittest
from dataclasses import asdict, replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from test_configurable_runtime import graph

from agent_interlock.architecture import (
    ArchitectureCompiler,
    AssuranceLevel,
    ControlTiming,
    EnforcementPoint,
    SecurityControl,
    SecurityObjective,
)
from agent_interlock.canonical import canonical_digest
from agent_interlock.ledger import Event, build_event, workflow_evidence_scope
from agent_interlock.orchestration import OrchestrationEngine, WorkflowRunState
from agent_interlock.remote_worker import (
    CoordinatorClient,
    RemoteLedger,
    RemoteRunStore,
    RemoteWorker,
    WorkerError,
    _Lease,
)
from agent_interlock.workflow_store import _decode


class Coordinator:
    def __init__(self, *, http=False):
        value = graph(http=http)
        control = SecurityControl("guard", SecurityObjective.PREVENT, ControlTiming.PRE_EXECUTION,
                                  EnforcementPoint.MCP_GATEWAY, AssuranceLevel.ENFORCED)
        value = replace(value, edges=tuple(replace(edge, controls=(control,),
            policy=replace(edge.policy, allowed_data_classes=frozenset({"D3"}))) for edge in value.edges))
        if http:
            value = replace(value, orchestration=replace(value.orchestration, tasks=(replace(
                value.orchestration.tasks[0], approval_required=True),)))
        self.bundle = {"architecture": value.to_manifest()}
        digest = canonical_digest(self.bundle)
        compiled = replace(ArchitectureCompiler().compile(value), bundle_digest=digest)
        self.run = OrchestrationEngine(compiled, bundle_digest=digest).create(
            tenant_id="tenant", workflow_input={"tasks": {"transform": {"name": "Ada"}}})
        self.revision, self.calls, self.events = 0, [], []
        self.fail = None
        self.owner = None

    def call(self, operation, body):
        self.calls.append((operation, body))
        if operation == self.fail:
            raise WorkerError("acknowledgement lost")
        if operation == "claim":
            self.owner = body["sessionId"]
            return {"claim": {"tenantId": "tenant", "runId": self.run.id, "owner": self.owner, "fence": 1,
                "revision": self.revision, "expiresAt": time.time()+30, "leaseSeconds": 30,
                "targetId": "target", "bundleDigest": self.run.bundle_digest, "bundle": self.bundle,
                "run": asdict(self.run)}}
        assert body["sessionId"] == self.owner and body["fence"] == 1 and body["runId"] == self.run.id
        if operation == "save":
            assert body["revision"] == self.revision
            self.run = _decode(json.dumps(body["run"]))
            self.revision += 1
        if operation in {"save", "get"}:
            return {"run": asdict(self.run), "revision": self.revision}
        if operation == "append":
            self.events.append(Event(**body["event"]))
            return {"event": body["event"]}
        if operation == "trace":
            return {"events": [event.to_dict() for event in self.events]}
        return {}


class RemoteWorkerTests(unittest.TestCase):
    def test_complete_remote_run_and_http_approval_handoff(self):
        coordinator = Coordinator()
        worker = RemoteWorker(coordinator, target_id="target", tenant_id="tenant", credentials={"local": "never-send"})
        self.assertTrue(worker.run_once())
        self.assertEqual(coordinator.run.state, WorkflowRunState.COMPLETED)
        self.assertEqual(coordinator.run.tasks["transform"].output, {"name": "Ada"})
        self.assertEqual(coordinator.calls[0][1]["credentialRefs"], ["local"])
        self.assertNotIn("never-send", json.dumps(coordinator.calls))
        self.assertEqual(coordinator.calls[-1][0], "finish")
        evidence = [event for event in coordinator.events if event.event_type == "INTERACTION_COMPLETED"]
        self.assertEqual(evidence[0].payload["workflowTaskId"], "transform")
        self.assertEqual(evidence[0].payload["workflowRunId"], coordinator.run.id)
        coordinator = Coordinator(http=True)
        effects = []

        def request(_endpoint, _method, body, _headers, **_):
            effects.append(json.loads(body))
            return 200, {"content-type": "application/json"}, body

        first = RemoteWorker(coordinator, target_id="target", tenant_id="tenant", credentials={}, http_request=request)
        first.run_once()
        self.assertEqual(coordinator.run.state, WorkflowRunState.WAITING_APPROVAL)
        self.assertEqual(effects, [])
        coordinator.run = replace(coordinator.run, approvals={"transform": "reviewer"})
        coordinator.revision += 1
        second = RemoteWorker(coordinator, target_id="target", tenant_id="tenant", credentials={}, http_request=request)
        self.assertNotEqual(first.session_id, second.session_id)
        second.run_once()
        self.assertEqual(coordinator.run.state, WorkflowRunState.COMPLETED)
        self.assertEqual(effects, [{"name": "Ada"}])

    def test_start_loss_wrong_context_and_ledger_loss_do_not_execute(self):
        for failure in ("start", "append"):
            coordinator = Coordinator()
            coordinator.fail = failure
            worker = RemoteWorker(coordinator, target_id="target", tenant_id="tenant", credentials={})
            with self.assertRaises(WorkerError):
                worker.run_once()
            operations = [call[0] for call in coordinator.calls]
            self.assertNotIn("finish", operations)
            failed_at = operations.index(failure)
            self.assertEqual(operations[failed_at+1:], [])
        coordinator = Coordinator()
        with self.assertRaisesRegex(WorkerError, "pinned"):
            RemoteWorker(coordinator, target_id="wrong", tenant_id="tenant", credentials={}).run_once()
        self.assertEqual([item[0] for item in coordinator.calls], ["claim"])
        coordinator = Coordinator()
        real = coordinator.call

        def changed(operation, body):
            response = real(operation, body)
            if operation == "claim":
                response["claim"]["bundle"] = {}
            return response

        coordinator.call = changed
        with self.assertRaisesRegex(WorkerError, "pinned"):
            RemoteWorker(coordinator, target_id="target", tenant_id="tenant", credentials={}).run_once()

    def test_heartbeat_and_expiry_latch_and_preserve_local_event_scope(self):
        coordinator = Coordinator()
        claim = coordinator.call("claim", {"sessionId":"session", "credentialRefs":[]})["claim"]
        lease = _Lease(coordinator, claim, "session")
        ledger = RemoteLedger(lease, coordinator.run.trace_id)
        with workflow_evidence_scope("tenant", coordinator.run.trace_id, coordinator.run.id, "task"):
            event = ledger.append("CUSTOM", tenant_id="tenant", trace_id=coordinator.run.trace_id,
                                  span_id="span", source_actor_id="agent.worker", payload={})
        self.assertEqual(event.payload["workflowTaskId"], "task")
        coordinator.fail = "heartbeat"
        with self.assertRaises(WorkerError):
            lease.call("heartbeat")
        count = len(coordinator.calls)
        with self.assertRaises(WorkerError):
            lease.call("get")
        self.assertEqual(len(coordinator.calls), count)
        expired = _Lease(coordinator, claim, "session")
        expired.deadline = time.monotonic()-1
        with self.assertRaises(WorkerError):
            expired.call("get")
        bad = build_event("BAD", tenant_id="other", trace_id=coordinator.run.trace_id,
                          span_id="span", source_actor_id="agent.worker", payload={})
        with self.assertRaisesRegex(WorkerError, "out-of-scope"):
            ledger._event(bad.to_dict())

    def test_conflicting_save_preserves_approval_and_server_event_identity(self):
        coordinator = Coordinator()
        claim = coordinator.call("claim", {"sessionId":"session", "credentialRefs":[]})["claim"]
        lease = _Lease(coordinator, {**claim, "expiresAt": 1}, "session")
        lease.check()  # A skewed worker clock never interprets the server's epoch as local time.
        store = RemoteRunStore(lease)
        before = store.get(tenant_id="tenant", run_id=coordinator.run.id)
        original = coordinator.call
        conflicted = False

        def call(operation, body):
            nonlocal conflicted
            if operation == "save" and not conflicted:
                conflicted = True
                coordinator.run = replace(coordinator.run, approvals={"transform":"reviewer"})
                coordinator.revision += 1
                raise WorkerError("conflict", status=409, code="WORKER-REVISION-CONFLICT")
            result = original(operation, body)
            if operation == "append":
                event = {**result["event"], "event_id":"server-generated"}
                event.pop("integrity_hash")
                result = {"event": {**event, "integrity_hash":canonical_digest(event)}}
            return result

        coordinator.call = call
        pending = {"arguments":{"name":"Ada"}, "requestId":"exact-call"}
        store.save(replace(before, tasks={"transform":replace(before.tasks["transform"], pending_call=pending)}))
        self.assertEqual(coordinator.run.approvals, {"transform":"reviewer"})
        self.assertEqual(coordinator.run.tasks["transform"].pending_call, pending)
        ledger = RemoteLedger(lease, coordinator.run.trace_id)
        event = ledger.append("CUSTOM", tenant_id="tenant", trace_id=coordinator.run.trace_id,
                              span_id="span", source_actor_id="agent.worker", payload={})
        self.assertEqual(event.event_id, "server-generated")
        lease.call("start")
        with self.assertRaises(KeyError):
            lease.call("heartbeat")  # A missing expiry acknowledgement never extends execution authority.
        self.assertTrue(lease.failed)

    def test_http_client_requires_explicit_loopback_and_never_redirects_credentials(self):
        seen = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                seen.append((self.path, self.headers.get("Authorization")))
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(302)
                self.send_header("Location", "/stolen")
                self.end_headers()

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        origin = f"http://127.0.0.1:{server.server_port}"
        for url in (origin, "http://remote.example", "https://user:pass@example.com", "https://example.com?secret=x"):
            with self.assertRaises(ValueError):
                CoordinatorClient(url, "private")
        client = CoordinatorClient(origin, "private", allow_loopback_http=True)
        with self.assertRaisesRegex(WorkerError, "HTTP 302"):
            client.call("claim", {})
        self.assertEqual(seen, [("/v1/workers/claim", "Bearer private")])
        with patch.dict("os.environ", {"WORKER_TOKEN": "private"}):
            from agent_interlock.remote_worker import main
            with patch("agent_interlock.remote_worker.RemoteWorker.run_once", return_value=False):
                self.assertEqual(main(["--coordinator", origin, "--token-env", "WORKER_TOKEN", "--target-id", "target",
                                       "--tenant", "tenant", "--allow-loopback-http", "--once"]), 0)
