"""Real coordinator HTTP and offline Anthropic SDK preserve multi-tool approval handoff."""

import importlib.util
import json
import threading
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import test_distributed_host
from test_configurable_runtime import graph

from agent_interlock.architecture import (
    AssuranceLevel,
    ControlTiming,
    EnforcementPoint,
    SecurityControl,
    SecurityObjective,
)
from agent_interlock.configurable_runtime import RUNTIME_KEY, configured_definition, prepare_runtime_graph
from agent_interlock.local_host import serve_local
from agent_interlock.models import SideEffect
from agent_interlock.remote_worker import CoordinatorClient, RemoteWorker
from agent_interlock.studio_deploy import (
    DeploymentBundle,
    TrustedApprovalKey,
    compile_review_bundle,
    sign_deployment_approval,
)


@unittest.skipUnless(importlib.util.find_spec("anthropic") and test_distributed_host.CRYPTO_AVAILABLE,
                     "Anthropic SDK and Ed25519 backend required")
class DistributedModelTests(unittest.TestCase):
    def test_model_multi_tool_exact_approval_moves_between_worker_sessions(self):
        import anthropic

        host = test_distributed_host.DistributedHostTests()
        host.setUp()
        self.addCleanup(host.doCleanups)
        value = graph(model=True)
        source, read_tool, provider = value.nodes
        write_tool = replace(read_tool, actor=replace(read_tool.actor, id="tool.write",
            side_effects=frozenset({SideEffect.EXTERNAL_WRITE})), annotations={RUNTIME_KEY: {
                "kind": "HTTP_JSON", "purpose": "TRANSFORM", "dataClasses": ["D3"],
                "endpoint": "https://service.example/api", "method": "POST"}})
        source = replace(source, annotations={RUNTIME_KEY: {**source.annotations[RUNTIME_KEY],
            "toolActorIds": [read_tool.id, write_tool.id]}})
        guard = SecurityControl("guard", SecurityObjective.PREVENT, ControlTiming.PRE_EXECUTION,
                                EnforcementPoint.MCP_GATEWAY, AssuranceLevel.ENFORCED)
        value = prepare_runtime_graph(replace(value, id="comparison", nodes=(source, read_tool, provider, write_tool),
            edges=tuple(replace(edge, controls=(replace(guard, id=f"guard-{edge.id}",
                enforcement_point=EnforcementPoint.EGRESS_GATEWAY if edge.relationship_id == "REL-07"
                else EnforcementPoint.MCP_GATEWAY),), policy=replace(edge.policy,
                allowed_data_classes=frozenset({"D3"}))) for edge in
                (*value.edges, replace(value.edges[0], id="write", target=write_tool.id)))))
        compiled = compile_review_bundle(value)
        self.assertTrue(compiled["deployable"], compiled["findings"])
        bundle = DeploymentBundle.from_compile_output(compiled)
        host.store.propose(bundle)
        public = json.loads((host.path / "trusted-approvers.json").read_text())
        trusted = {key: TrustedApprovalKey(item["approverId"], bytes.fromhex(item["publicKeyHex"]))
                   for key, item in public.items()}
        approvals = tuple(sign_deployment_approval(bundle, from_digest=None, to_mode="ENFORCE",
            target_id=host.store.target_id, tenant_id=host.store.tenant_id, approver_id=key, key_id=key,
            key=bytes.fromhex((host.path / "reviewers" / f"{key}.key").read_text().strip())) for key in public)
        host.store.promote(bundle.bundle_digest, approvals, trusted_approvers=trusted)

        read_name, write_name = (configured_definition(node).tool_name for node in (read_tool, write_tool))
        replies = [
            [{"type": "tool_use", "id": "read-1", "name": read_name, "input": {"name": "Ada"}}],
            [{"type": "tool_use", "id": "write-1", "name": write_name, "input": {"name": "Grace"}}],
            [{"type": "text", "text": "Done."}],
        ]
        received, effects = [], []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                content = replies.pop(0)
                body = json.dumps({"id": "fixture-message", "type": "message", "role": "assistant",
                    "model": "fixture-model", "content": content,
                    "stop_reason": "end_turn" if content[0]["type"] == "text" else "tool_use",
                    "stop_sequence": None, "usage": {"input_tokens": 5, "output_tokens": 5}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        model_server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=model_server.serve_forever, daemon=True).start()
        self.addCleanup(model_server.server_close)
        self.addCleanup(model_server.shutdown)

        def model_client(key, *, timeout):
            return anthropic.Anthropic(api_key=key, max_retries=0, timeout=timeout,
                                       base_url=f"http://127.0.0.1:{model_server.server_port}")

        def http_request(_endpoint, _method, body, _headers, **_kwargs):
            effects.append(json.loads(body))
            return 200, {"Content-Type": "application/json"}, body

        with serve_local(host.path, port=0, dispatch="remote") as server:
            workers = [RemoteWorker(CoordinatorClient(f"http://127.0.0.1:{server.server_port}",
                host.tokens[f"INTERLOCK_DIST_TEST_{number}"], allow_loopback_http=True),
                target_id=host.store.target_id, tenant_id=host.store.tenant_id, credentials={"fixture": "offline"},
                http_request=http_request, anthropic_client_factory=model_client) for number in (1, 2)]
            status, _, created = host.request(server, "POST", "/v1/runs", token=host.token,
                body={"runId": "model-handoff", "input": {"tasks": {"transform": {"prompt": "Process names"}}}})
            self.assertEqual(status, 202, created)
            self.assertTrue(workers[0].run_once())
            run = host.request(server, "GET", "/v1/runs/model-handoff", token=host.token)[2]["run"]
            self.assertEqual(run["state"], "WAITING_APPROVAL", run)
            pending = run["tasks"]["transform"]["pendingCall"]
            self.assertEqual(pending["targetActorId"], write_tool.id)
            self.assertEqual(pending["arguments"], {"name": "Grace"})
            self.assertEqual(pending["continuation"]["toolUseId"], "write-1")
            self.assertEqual(len(received), 2)
            self.assertEqual(effects, [])
            status, _, approved = host.request(server, "POST", "/v1/runs/model-handoff/tasks/transform/approve",
                                               token=host.token, body={"requestId": pending["requestId"]})
            self.assertEqual(status, 202, approved)
            self.assertNotEqual(workers[0].session_id, workers[1].session_id)
            self.assertTrue(workers[1].run_once())
            run = host.request(server, "GET", "/v1/runs/model-handoff", token=host.token)[2]["run"]
            self.assertEqual(run["state"], "COMPLETED", run)
            self.assertEqual(run["tasks"]["transform"]["output"], {"text": "Done."})
            self.assertEqual(effects, [{"name": "Grace"}])
            self.assertEqual(len(received), 3)
            self.assertEqual(received[2]["messages"][-1]["content"][0]["tool_use_id"], "write-1")
            self.assertEqual({tool["name"] for tool in received[0]["tools"]}, {read_name, write_name})
            events = host.request(server, "GET", "/v1/runs/model-handoff/events", token=host.token)[2]["events"]
            requested = [event for event in events if event["event_type"] == "INTERACTION_REQUESTED"]
            self.assertEqual(sum(event["target_actor_id"] == "provider" for event in requested), 3)
            self.assertEqual(sum(event["target_actor_id"] == read_tool.id for event in requested), 1)
            self.assertTrue(any(event["event_type"] == "WORKFLOW_TASK_APPROVED"
                                and event["payload"]["requestId"] == pending["requestId"] for event in events))


if __name__ == "__main__":
    unittest.main()
