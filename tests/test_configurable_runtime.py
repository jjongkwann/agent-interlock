"""Config-only tools and model calls execute through the existing guarded runtime."""
import importlib.util
import json
import socket
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agent_interlock.architecture import (
    ArchitectureCompiler,
    ArchitectureEdge,
    ArchitectureGraph,
    ArchitectureNode,
    OrchestrationDefinition,
    OrchestrationPattern,
    OrchestrationTask,
    TaskFailureAction,
    TaskTransport,
)
from agent_interlock.configurable_runtime import (
    RUNTIME_KEY,
    _request,
    configurable_adapter_provider,
    configured_definition,
    http_json,
    map_json,
    prepare_runtime_graph,
    runtime_status,
)
from agent_interlock.egress import PinnedSocketEgressBackend
from agent_interlock.intent import derive_intent
from agent_interlock.ledger import InMemoryLedger, workflow_evidence_scope
from agent_interlock.models import ActorSpec, ActorType, LinkPolicy, SideEffect
from agent_interlock.orchestration import (
    CallableTaskAdapter,
    InMemoryWorkflowRunStore,
    OrchestrationEngine,
    WorkflowRunState,
)


def graph(*, model=False, http=False):
    source = ArchitectureNode(ActorSpec("agent.worker", ActorType.AGENT, "owner", "worker",
                                       data_access=frozenset({"D3"})))
    tool = ArchitectureNode(ActorSpec(
        "tool.transform", ActorType.TOOL, "owner", "transform", data_access=frozenset({"D3"}),
        allowed_domains=frozenset({"service.example"}),
        side_effects=frozenset({SideEffect.EXTERNAL_WRITE if http else SideEffect.READ}),
        input_schema={"type": "object", "properties": {"name": {"type": "string"}},
                      "required": ["name"], "additionalProperties": False},
        output_schema={"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]},
    ), annotations={RUNTIME_KEY: {
        "kind": "HTTP_JSON" if http else "JSON_TRANSFORM", "purpose": "TRANSFORM", "dataClasses": ["D3"],
        **({"endpoint": "https://service.example/api", "method": "POST"} if http
           else {"template": {"name": {"$path": "arguments.name"}}}),
    }})
    policy = LinkPolicy(allowed_purposes=frozenset({"TRANSFORM"}), max_export_bytes=100000,
                        max_export_records=100, require_explicit_destination=http)
    nodes = [source, tool]
    edges = [ArchitectureEdge("invoke", "REL-05", source.id, tool.id, "INVOKES", policy)]
    if model:
        nodes[0] = replace(source, annotations={RUNTIME_KEY: {
            "kind": "ANTHROPIC", "model": "fixture-model", "systemPrompt": "Process the request.",
            "maxTokens": 100, "maxSteps": 4, "credentialRef": "fixture", "providerActorId": "provider",
            "purpose": "MODEL_INFERENCE", "dataClasses": ["D3"],
        }})
        nodes.append(ArchitectureNode(ActorSpec("provider", ActorType.EXTERNAL, "owner", "provider",
            data_access=frozenset({"D3"}), allowed_domains=frozenset({"api.anthropic.com"}),
            side_effects=frozenset({SideEffect.READ}))))
        edges.append(ArchitectureEdge("inference", "REL-07", source.id, "provider", "SENDS", replace(
            policy, id="inference", allowed_purposes=frozenset({"MODEL_INFERENCE"}), relationship="SENDS",
            source_types=frozenset({ActorType.AGENT}), target_types=frozenset({ActorType.EXTERNAL}),
            require_explicit_destination=True, require_active_definition=False, require_digest_pin=False)))
    task = OrchestrationTask("transform", "Transform", source.id, tool.id, TaskTransport.LOCAL, "TRANSFORM")
    return prepare_runtime_graph(ArchitectureGraph("configured", "1", tuple(nodes), tuple(edges),
        orchestration=OrchestrationDefinition(coordinator_actor_id=source.id,
                                             pattern=OrchestrationPattern.STATE_GRAPH, tasks=(task,))))


def engine(value, **kwargs):
    compiled = replace(ArchitectureCompiler().compile(value, reject_critical=False), bundle_digest="reviewed-bundle")
    ledger, store = InMemoryLedger(), InMemoryWorkflowRunStore()
    adapters = configurable_adapter_provider(ledger, store, {"fixture": "test"}, **kwargs)(compiled)
    return OrchestrationEngine(compiled, adapters=adapters, ledger=ledger, run_store=store), store, ledger


class ConfigurableRuntimeTests(unittest.TestCase):
    def test_shared_actor_task_evidence_is_isolated_in_sequence_and_parallel(self):
        for parallel in (False, True):
            with self.subTest(parallel=parallel):
                value = graph()
                first = replace(value.orchestration.tasks[0], id="blocked", on_failure=TaskFailureAction.CONTINUE)
                second = replace(first, id="allowed", depends_on=() if parallel else (first.id,))
                value = replace(value, orchestration=replace(value.orchestration, tasks=(first, second)))
                runner, _, ledger = engine(value)
                if parallel:
                    original = runner.adapters[TaskTransport.LOCAL]
                    barrier = threading.Barrier(2)

                    def execute(value):
                        try:
                            return original.execute(value)
                        finally:
                            barrier.wait(timeout=5)

                    runner.adapters[TaskTransport.LOCAL] = CallableTaskAdapter(execute)
                run = runner.start(tenant_id="tenant", workflow_input={
                    "tasks": {"blocked": {"name": 7}, "allowed": {"name": "Ada"}},
                })
                self.assertFalse(run.tasks["blocked"].security_met)
                self.assertEqual(run.tasks["allowed"].output, {"name": "Ada"})
                self.assertTrue(run.tasks["allowed"].security_met)
                requested = [event for event in ledger.trace(run.tenant_id, run.trace_id)
                             if event.event_type == "INTERACTION_REQUESTED"]
                self.assertEqual({event.payload["workflowTaskId"] for event in requested}, {"blocked", "allowed"})
                self.assertTrue(all(event.payload["workflowRunId"] == run.id for event in requested))

    def test_evidence_context_is_thread_local_and_resets_nested_scopes_on_error(self):
        ledger = InMemoryLedger()
        barrier = threading.Barrier(2)

        def append(trace="trace"):
            return ledger.append("INTERACTION_REQUESTED", tenant_id="tenant", trace_id=trace,
                                 span_id="span", source_actor_id="actor", payload={"taskId": "adapter-metadata"})

        def worker(task_id):
            with workflow_evidence_scope("tenant", "trace", "run", task_id):
                barrier.wait(timeout=5)
                outer = append()
                with self.assertRaises(ValueError):
                    with workflow_evidence_scope("tenant", "trace", "nested-run", "nested-task"):
                        nested = append()
                        raise ValueError("adapter failure")
                restored = append()
                unrelated = append("unrelated")
            outside = append()
            return outer, nested, restored, unrelated, outside

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(worker, ("first", "second")))
        for task_id, (outer, nested, restored, unrelated, outside) in zip(("first", "second"), results, strict=True):
            self.assertEqual(outer.payload["workflowTaskId"], task_id)
            self.assertEqual(restored.payload["workflowTaskId"], task_id)
            self.assertEqual(nested.payload["workflowRunId"], "nested-run")
            self.assertEqual(nested.payload["workflowTaskId"], "nested-task")
            for event in (outer, nested, restored, unrelated, outside):
                self.assertEqual(event.payload["taskId"], "adapter-metadata")
                self.assertTrue(ledger.verify(event))
            self.assertNotIn("workflowTaskId", unrelated.payload)
            self.assertNotIn("workflowTaskId", outside.payload)

    def test_mapping_digest_and_manifest_roundtrip(self):
        value = graph()
        self.assertEqual(ArchitectureGraph.from_dict(value.to_manifest()).nodes, value.nodes)
        before = value.nodes[1].actor.definition_digest
        node = value.nodes[1]
        config = {**node.annotations[RUNTIME_KEY], "template": {"name": "changed"}}
        changed = prepare_runtime_graph(replace(value, nodes=(value.nodes[0], replace(
            node, annotations={RUNTIME_KEY: config}))))
        self.assertNotEqual(before, changed.nodes[1].actor.definition_digest)
        self.assertEqual(map_json({"$path": "dependencies.prior.items.0"},
                                 {"dependencies": {"prior": {"items": [4]}}}), 4)
        for path in ("input.__class__()", "input[a]", "env.SECRET"):
            with self.assertRaises(ValueError):
                map_json({"$path": path}, {})
        self.assertTrue(runtime_status(value)["nodes"][1]["configured"])

    def test_readiness_handles_incomplete_drafts_and_mixed_input_shapes(self):
        value = graph()
        missing = replace(value, nodes=(value.nodes[0], replace(value.nodes[1], annotations={})))
        self.assertFalse(runtime_status(missing)["ready"])
        source, first = value.nodes
        source = replace(source, actor=replace(source.actor,
            input_schema={"type": "object", "properties": {"message": {"type": "string"}}}))
        second = replace(first, actor=replace(first.actor, id="tool.second"))
        first = replace(first, annotations={RUNTIME_KEY: {**first.annotations[RUNTIME_KEY],
            "arguments": {"name": {"$path": "input.message"}}}})
        task = value.orchestration.tasks[0]
        mixed = prepare_runtime_graph(replace(value, nodes=(source, first, second),
            edges=(*value.edges, replace(value.edges[0], id="second-edge", target=second.id)),
            orchestration=replace(value.orchestration, tasks=(task, replace(task, id="second",
                target_actor_id=second.id, depends_on=(task.id,))))))
        status = runtime_status(mixed)
        self.assertTrue(status["ready"], status)
        self.assertEqual(set(status["runInputSchema"]["properties"]), {"message", "tasks"})
        self.assertEqual(set(status["runInputSchema"]["properties"]["tasks"]["properties"]), {"second"})
        unavailable = runtime_status(graph(model=True), ())
        self.assertFalse(unavailable["ready"])
        self.assertIn("credential", " ".join(unavailable["tasks"][0]["problems"]))

    @unittest.skipUnless(importlib.util.find_spec("anthropic"), "Anthropic extra is required for model readiness")
    def test_model_tool_selection_readiness(self):
        value = graph(model=True)
        source, tool, provider = value.nodes
        other = replace(tool, actor=replace(tool.actor, id="tool.other"))
        source = replace(source, annotations={RUNTIME_KEY: {**source.annotations[RUNTIME_KEY],
            "toolActorIds": [tool.id, other.id]}})
        value = prepare_runtime_graph(replace(value, nodes=(source, tool, provider, other),
            edges=(*value.edges, replace(value.edges[0], id="other", target=other.id))))
        self.assertTrue(runtime_status(value, ("fixture",))["ready"])
        for ids in ([], [tool.id, tool.id], ["missing"], [provider.id], [None], ["x" * 257],
                    [str(i) for i in range(21)]):
            with self.subTest(ids=ids):
                bad = replace(source, annotations={RUNTIME_KEY: {
                    **source.annotations[RUNTIME_KEY], "toolActorIds": ids}})
                status = runtime_status(replace(value, nodes=(bad, tool, provider, other)), ("fixture",))
                self.assertFalse(status["ready"])
        self.assertFalse(runtime_status(replace(value, edges=value.edges[:-1]), ("fixture",))["ready"])
        denied = replace(value.edges[-1], policy=replace(value.edges[-1].policy, allowed_purposes=frozenset()))
        self.assertFalse(runtime_status(replace(value, edges=(*value.edges[:-1], denied)), ("fixture",))["ready"])
        other = replace(other, actor=replace(other.actor, data_access=frozenset({"D4"})),
            annotations={RUNTIME_KEY: {**other.annotations[RUNTIME_KEY], "dataClasses": ["D4"]}})
        status = runtime_status(replace(value, nodes=(source, tool, provider, other)), ("fixture",))
        self.assertIn("selected tool", " ".join(status["tasks"][0]["problems"]))

    @unittest.skipUnless(importlib.util.find_spec("anthropic"), "Anthropic extra is required for model readiness")
    def test_host_model_readiness_checks_intended_enforced_deployment(self):
        from agent_interlock.control_plane import ControlPlaneAPI
        from agent_interlock.models import PolicyMode

        value = graph(model=True)
        reviewed = replace(value, edges=tuple(replace(edge, policy=replace(edge.policy, mode=PolicyMode.SHADOW))
                                              for edge in value.edges))
        host = object.__new__(ControlPlaneAPI)
        host.run_service = None
        host.credential_refs = ("fixture",)
        host.configurable_runtime = True
        self.assertFalse(runtime_status(reviewed, host.credential_refs)["ready"])
        self.assertTrue(host._runtime_readiness(reviewed)["ready"])

    def test_non_idempotent_retries_are_rejected_and_timeout_executes_once(self):
        for value in (graph(model=True), graph(http=True)):
            task = replace(value.orchestration.tasks[0], max_attempts=2)
            value = replace(value, orchestration=replace(value.orchestration, tasks=(task,)))
            self.assertIn("maxAttempts to 1", " ".join(runtime_status(value, ("fixture",))["tasks"][0]["problems"]))
            with self.assertRaisesRegex(ValueError, "maxAttempts to 1"):
                engine(value)
        calls = []

        def request(_endpoint, _method, body, _headers, **_):
            calls.append(json.loads(body))
            raise TimeoutError("response lost after commit")

        runner, store, _ = engine(graph(http=True), http_request=request)
        run = runner.create(tenant_id="tenant", workflow_input={"tasks": {"transform": {"name": "Ada"}}})
        held = runner.resume(tenant_id="tenant", run_id=run.id)
        pending = held.tasks["transform"].pending_call
        store.approve(tenant_id="tenant", run_id=run.id,
                      task_id="transform:" + pending["requestId"], approved_by="human")
        failed = runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(failed.state, WorkflowRunState.FAILED)
        runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(calls, [{"name": "Ada"}])

    def test_deterministic_task_and_dependency_mapping(self):
        value = graph()
        one = value.orchestration.tasks[0]
        two = replace(one, id="dependent", depends_on=(one.id,))
        node = value.nodes[1]
        config = {**node.annotations[RUNTIME_KEY], "arguments": {"name": {"$path": "input.name"}}}
        value = prepare_runtime_graph(replace(value, nodes=(value.nodes[0], replace(node,
            annotations={RUNTIME_KEY: config})), orchestration=replace(value.orchestration, tasks=(one, two))))
        runner, _, ledger = engine(value)
        run = runner.create(tenant_id="tenant", workflow_input={"name": "Ada"})
        result = runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(result.state, WorkflowRunState.COMPLETED, result.to_dict())
        self.assertEqual(result.tasks["dependent"].output, {"name": "Ada"})
        self.assertTrue(any(event.event_type == "INTERACTION_COMPLETED" for event in ledger.all()))

    def test_one_json_execution_has_one_complete_interaction(self):
        runner, _, ledger = engine(graph())
        run = runner.create(tenant_id="tenant", workflow_input={"tasks": {"transform": {"name": "Ada"}}})
        result = runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(result.state, WorkflowRunState.COMPLETED, result.to_dict())
        requested = [event for event in ledger.all() if event.event_type == "INTERACTION_REQUESTED"]
        completed = [event for event in ledger.all() if event.event_type == "INTERACTION_COMPLETED"]
        self.assertEqual(len(requested), 1)
        self.assertEqual(len(completed), 1)
        self.assertEqual(requested[0].interaction_id, completed[0].interaction_id)

    def test_fixed_http_destination_and_no_dynamic_host(self):
        value = graph(http=True)
        definition = configured_definition(value.nodes[1])
        self.assertEqual(derive_intent({"name": "Ada"}, definition.input_schema, definition.annotations).destinations,
                         ("https://service.example/api",))
        calls = []

        def request(endpoint, method, body, headers, **_):
            calls.append((endpoint, method, json.loads(body), headers))
            return 200, {"Content-Type": "application/json"}, body

        config = value.nodes[1].annotations[RUNTIME_KEY]
        self.assertEqual(http_json(config, {"name": "Ada"}, {}, request=request), {"name": "Ada"})
        self.assertEqual(calls[0][0], "https://service.example/api")
        with self.assertRaises(ValueError):
            http_json({**config, "endpoint": "https://127.0.0.1/api"}, {}, {}, request=request)

    def test_http_pending_call_does_not_execute_until_exact_approval(self):
        calls = []

        def request(_endpoint, _method, body, _headers, **_):
            calls.append(json.loads(body))
            return 200, {"Content-Type": "application/json"}, body

        runner, store, _ = engine(graph(http=True), http_request=request)
        run = runner.create(tenant_id="tenant", workflow_input={"tasks": {"transform": {"name": "Ada"}}})
        held = runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(held.state, WorkflowRunState.WAITING_APPROVAL, held.to_dict())
        self.assertEqual(calls, [])
        pending = held.tasks["transform"].pending_call
        self.assertEqual(pending["arguments"], {"name": "Ada"})
        store.approve(tenant_id="tenant", run_id=run.id,
                      task_id="transform:" + pending["requestId"], approved_by="human")
        completed = runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(completed.state, WorkflowRunState.COMPLETED, completed.to_dict())
        self.assertEqual(calls, [{"name": "Ada"}])

    def test_installed_anthropic_runner_holds_each_exact_call_and_resumes(self):
        try:
            import anthropic
        except ImportError:
            self.skipTest("anthropic extra is not installed")
        value = graph(model=True, http=True)
        source, first_tool, provider = value.nodes
        other = replace(first_tool, actor=replace(first_tool.actor, id="tool.other"))
        source = replace(source, annotations={RUNTIME_KEY: {**source.annotations[RUNTIME_KEY],
            "toolActorIds": [first_tool.id, other.id]}})
        value = prepare_runtime_graph(replace(value, nodes=(source, first_tool, provider, other),
            edges=(*value.edges, replace(value.edges[0], id="other", target=other.id))))
        name = configured_definition(first_tool).tool_name
        other_name = configured_definition(other).tool_name
        responses = [
            [{"type": "tool_use", "id": "call_1", "name": name, "input": {"name": "Ada"}}],
            [{"type": "tool_use", "id": "call_2", "name": name, "input": {"name": "Ada"}}],
            [{"type": "tool_use", "id": "call_3", "name": other_name, "input": {"name": "Grace"}}],
            [{"type": "text", "text": "Done."}],
        ]
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                content = responses.pop(0)
                body = json.dumps({"id": "message", "type": "message", "role": "assistant",
                    "model": "fixture-model", "content": content,
                    "stop_reason": "tool_use" if content[0]["type"] == "tool_use" else "end_turn",
                    "stop_sequence": None, "usage": {"input_tokens": 5, "output_tokens": 5}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        calls = []

        def request(_endpoint, _method, body, _headers, **_):
            calls.append(json.loads(body))
            return 200, {"Content-Type": "application/json"}, body

        def client(key, *, timeout):
            return anthropic.Anthropic(api_key=key, base_url=f"http://127.0.0.1:{server.server_port}",
                                       max_retries=0, timeout=timeout)

        runner, store, ledger = engine(value, http_request=request, anthropic_client_factory=client)
        run = runner.create(tenant_id="tenant", workflow_input={"tasks": {"transform": {"prompt": "Process Ada"}}})
        store.save(replace(run, approvals={"transform": "blanket"}))
        first = runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(first.state, WorkflowRunState.WAITING_APPROVAL, first.to_dict())
        self.assertEqual(calls, [])
        first_pending = first.tasks["transform"].pending_call
        store.approve(tenant_id="tenant", run_id=run.id,
                      task_id="transform:" + first_pending["requestId"], approved_by="human")
        second = runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(second.state, WorkflowRunState.WAITING_APPROVAL, second.to_dict())
        second_pending = second.tasks["transform"].pending_call
        self.assertNotEqual(first_pending["requestId"], second_pending["requestId"])
        self.assertEqual(calls, [{"name": "Ada"}])
        store.approve(tenant_id="tenant", run_id=run.id,
                      task_id="transform:" + second_pending["requestId"], approved_by="human")
        third = runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(third.state, WorkflowRunState.WAITING_APPROVAL, third.to_dict())
        third_pending = third.tasks["transform"].pending_call
        self.assertEqual(third_pending["targetActorId"], other.id)
        self.assertEqual(third_pending["toolName"], other_name)
        self.assertEqual(third_pending["definitionDigest"], value.nodes[-1].actor.definition_digest)
        self.assertEqual(third_pending["arguments"], {"name": "Grace"})
        self.assertEqual(third_pending["continuation"]["toolUseId"], "call_3")
        self.assertNotEqual(second_pending["requestId"], third_pending["requestId"])
        self.assertEqual(calls, [{"name": "Ada"}, {"name": "Ada"}])
        store.approve(tenant_id="tenant", run_id=run.id,
                      task_id="transform:" + third_pending["requestId"], approved_by="human")
        completed = runner.resume(tenant_id="tenant", run_id=run.id)
        self.assertEqual(completed.state, WorkflowRunState.COMPLETED, completed.to_dict())
        self.assertEqual(completed.tasks["transform"].output, {"text": "Done."})
        self.assertEqual(calls, [{"name": "Ada"}, {"name": "Ada"}, {"name": "Grace"}])
        self.assertEqual(len(received), 4)
        self.assertEqual({tool["name"] for tool in received[0]["tools"]}, {name, other_name})
        self.assertTrue(any(e.target_actor_id == "provider" and e.event_type == "CONTROL_EVALUATED"
                            and e.payload.get("bundleDigest") == "reviewed-bundle" for e in ledger.all()))

        responses.extend([
            [{"type": "tool_use", "id": "read_1", "name": name, "input": {"name": "Ada"}}],
            [{"type": "text", "text": "Read."}],
        ])
        read_runner, _, read_ledger = engine(graph(model=True), anthropic_client_factory=client)
        read_run = read_runner.create(
            tenant_id="tenant", workflow_input={"tasks": {"transform": {"prompt": "Read Ada"}}})
        read_result = read_runner.resume(tenant_id="tenant", run_id=read_run.id)
        self.assertEqual(read_result.state, WorkflowRunState.COMPLETED, read_result.to_dict())
        tool_events = [event for event in read_ledger.all() if event.target_actor_id == "tool.transform"]
        self.assertEqual(sum(event.event_type == "INTERACTION_REQUESTED" for event in tool_events), 1)
        self.assertEqual(sum(event.event_type == "INTERACTION_COMPLETED" for event in tool_events), 1)

    def test_actual_http_transport_pinned_socket_and_response_limits(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302 if self.path == "/redirect" else 200)
                body = b"x" * 1_048_577 if self.path == "/large" else b'{"ok":true}'
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        resolver = lambda host, port, **_: socket.getaddrinfo("127.0.0.1", port, type=socket.SOCK_STREAM)
        backend = PinnedSocketEgressBackend(resolver=resolver, require_global_addresses=False)

        class LocalTLS:
            def wrap_socket(self, raw, *, server_hostname):
                self.hostname = server_hostname
                return raw

        tls = LocalTLS()
        url = f"https://fixture.example:{server.server_port}"
        self.assertEqual(_request(url + "/", "GET", None, {}, backend=backend, tls_context=tls)[0], 200)
        self.assertEqual(tls.hostname, "fixture.example")
        with self.assertRaisesRegex(ValueError, "redirects"):
            _request(url + "/redirect", "GET", None, {}, backend=backend, tls_context=tls)
        with self.assertRaisesRegex(ValueError, "exceeds 1 MiB"):
            _request(url + "/large", "GET", None, {}, backend=backend, tls_context=tls)
        with self.assertRaisesRegex(Exception, "non-global"):
            _request(url, "GET", None, {}, backend=PinnedSocketEgressBackend(resolver=resolver), tls_context=tls)


if __name__ == "__main__":
    unittest.main()
