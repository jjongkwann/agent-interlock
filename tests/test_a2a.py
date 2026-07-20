from __future__ import annotations

import json
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from agent_interlock.a2a import (
    A2AAgentCard,
    A2AAgentSkill,
    A2AArtifact,
    A2ABroker,
    A2AHandlerResult,
    A2AJSONRPCRouter,
    A2AMessage,
    A2AMessageRole,
    A2APart,
    A2APolicyError,
    A2APrincipal,
    A2ASendContext,
    A2ATaskState,
)
from agent_interlock.a2a_http import (
    A2AHTTPConfig,
    StaticBearerA2AAuthenticator,
    create_a2a_http_server,
)
from agent_interlock.architecture import ArchitectureCompiler, ArchitectureGraph, ArchitectureLinter, TaskTransport
from agent_interlock.ledger import InMemoryLedger
from agent_interlock.orchestration import (
    A2AOrchestrationAdapter,
    OrchestrationEngine,
    WorkflowRunState,
    WorkflowTaskState,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "secure_multi_agent_architecture.json"


def boundary_manifest() -> dict:
    value = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    value["spec"]["trustZones"] = [
        {
            "id": "zone.control",
            "label": "Control zone",
            "kind": "INTERNAL",
            "bounds": {"x": 0, "y": 0, "width": 500, "height": 600},
        },
        {
            "id": "zone.worker",
            "label": "Worker zone",
            "kind": "INTERNAL",
            "bounds": {"x": 500, "y": 0, "width": 500, "height": 600},
        },
    ]
    worker_ids = {"agent.research", "rag.support-knowledge"}
    for node in value["spec"]["nodes"]:
        node["trustZone"] = "INTERNAL"
        node["trustZoneId"] = "zone.worker" if node["id"] in worker_ids else "zone.control"
    value["spec"]["trustBoundaries"] = [
        {
            "id": "boundary.control-worker-a2a",
            "label": "Control to worker A2A",
            "sourceZoneId": "zone.control",
            "targetZoneId": "zone.worker",
            "enforcementPoint": "A2A_BROKER",
            "allowedRelationships": ["DELEGATES"],
            "allowedDataClasses": ["D2", "D3", "D7"],
            "deniedDataClasses": ["D5", "D8"],
            "mode": "ENFORCE",
            "failureMode": "FAIL_CLOSED",
            "requireIdentity": True,
            "requireTenantBinding": True,
            "maxPayloadBytes": 32768,
        }
    ]
    for edge in value["spec"]["edges"]:
        edge.pop("boundaryId", None)
    delegation = next(edge for edge in value["spec"]["edges"] if edge["relationshipId"] == "REL-06")
    delegation["boundaryId"] = "boundary.control-worker-a2a"
    return value


def orchestration_manifest(*, approval_required: bool = False) -> dict:
    value = boundary_manifest()
    value["spec"]["orchestration"] = {
        "coordinatorActorId": "agent.support",
        "pattern": "HIERARCHICAL",
        "runPolicy": {
            "maxParallelism": 2,
            "maxTasks": 10,
            "maxDurationSeconds": 30,
            "maxMessages": 10,
            "failFast": True,
        },
        "tasks": [
            {
                "id": "task.research",
                "label": "Research the support question",
                "sourceActorId": "agent.support",
                "targetActorId": "agent.research",
                "transport": "A2A",
                "purpose": "SUPPORT_RESEARCH",
                "dataClasses": ["D2", "D3"],
                "acceptanceCriteria": ["Answer contains grounded evidence"],
                "maxAttempts": 2,
                "timeoutSeconds": 5,
                "position": {"x": 100, "y": 100},
            },
            {
                "id": "task.verify",
                "label": "Verify the research answer",
                "sourceActorId": "agent.support",
                "targetActorId": "agent.research",
                "transport": "A2A",
                "purpose": "SUPPORT_RESEARCH",
                "dependsOn": ["task.research"],
                "dataClasses": ["D2", "D3"],
                "acceptanceCriteria": ["Answer is safe to use"],
                "approvalRequired": approval_required,
                "maxAttempts": 1,
                "timeoutSeconds": 5,
                "position": {"x": 380, "y": 100},
            },
        ],
    }
    return value


def broker_fixture(value: dict | None = None):
    compiled = ArchitectureCompiler().compile(ArchitectureGraph.from_dict(value or boundary_manifest()))
    ledger = InMemoryLedger()
    broker = A2ABroker(compiled, ledger=ledger)
    calls = []

    def handler(task, message, context):
        calls.append((task.id, context.purpose))
        return A2AHandlerResult(
            state=A2ATaskState.COMPLETED,
            message=A2AMessage(
                role=A2AMessageRole.AGENT,
                parts=(A2APart.text_part("research complete"),),
            ),
            artifacts=(
                A2AArtifact(
                    artifact_id="artifact.research",
                    name="Research result",
                    parts=(A2APart.data_part({"answer": "grounded"}),),
                ),
            ),
        )

    broker.register_agent(
        "agent.research",
        A2AAgentCard(
            actor_id="agent.research",
            name="Research agent",
            description="Finds tenant-scoped support knowledge",
            url="https://agents.example/a2a/research",
            version="1.0.0",
            skills=(
                A2AAgentSkill(
                    id="KNOWLEDGE_SEARCH",
                    name="Knowledge search",
                    description="Searches approved support knowledge",
                ),
            ),
        ),
        handler,
    )
    principal = A2APrincipal.for_edge(
        tenant_id="tenant-a",
        subject="workflow-run-1",
        source_actor_id="agent.support",
        target_actor_id="agent.research",
        target_identity=compiled.actors["agent.research"].identity,
        delegation_depth=1,
    )
    return broker, ledger, calls, principal


def request_message() -> A2AMessage:
    return A2AMessage(
        role=A2AMessageRole.USER,
        parts=(A2APart.data_part({"question": "How do I reset the device?"}),),
    )


def send_context(principal: A2APrincipal, *, key: str = "run-1:research") -> A2ASendContext:
    return A2ASendContext(
        principal=principal,
        source_actor_id="agent.support",
        target_actor_id="agent.research",
        purpose="SUPPORT_RESEARCH",
        data_classes=frozenset({"D2", "D3"}),
        idempotency_key=key,
        trace_id="trace-a2a",
    )


class ArchitectureBoundaryTests(unittest.TestCase):
    def test_cross_zone_edge_compiles_with_directional_boundary(self):
        compiled = ArchitectureCompiler().compile(ArchitectureGraph.from_dict(boundary_manifest()))
        edge = compiled.edge_for("agent.support", "agent.research", "REL-06")
        self.assertIsNotNone(edge)
        self.assertEqual(compiled.boundary_for(edge).id, "boundary.control-worker-a2a")

    def test_cross_zone_edge_without_boundary_is_critical(self):
        value = boundary_manifest()
        delegation = next(edge for edge in value["spec"]["edges"] if edge["relationshipId"] == "REL-06")
        delegation.pop("boundaryId")
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertIn("ARCH-BOUNDARY-MISSING", codes)

    def test_wrong_boundary_direction_is_critical(self):
        value = boundary_manifest()
        boundary = value["spec"]["trustBoundaries"][0]
        boundary["sourceZoneId"], boundary["targetZoneId"] = boundary["targetZoneId"], boundary["sourceZoneId"]
        codes = {item.code for item in ArchitectureLinter().lint(ArchitectureGraph.from_dict(value))}
        self.assertIn("ARCH-BOUNDARY-DIRECTION-MISMATCH", codes)


class A2ABrokerTests(unittest.TestCase):
    def test_message_runs_through_rel06_and_boundary(self):
        broker, ledger, calls, principal = broker_fixture()
        task = broker.send_message(request_message(), send_context(principal))
        self.assertEqual(task.status.state, A2ATaskState.COMPLETED)
        self.assertEqual(task.artifacts[0].parts[0].data, {"answer": "grounded"})
        self.assertEqual(len(calls), 1)
        events = ledger.trace("tenant-a", "trace-a2a")
        requested = next(event for event in events if event.event_type == "INTERACTION_REQUESTED")
        self.assertEqual(requested.relationship_id, "REL-06")
        self.assertEqual(requested.payload["boundaryId"], "boundary.control-worker-a2a")
        self.assertTrue(any(event.event_type == "CONTROL_EVALUATED" for event in events))

    def test_same_idempotency_request_returns_same_task_without_reexecution(self):
        broker, _, calls, principal = broker_fixture()
        message = request_message()
        first = broker.send_message(message, send_context(principal))
        second = broker.send_message(message, send_context(principal))
        self.assertEqual(first.id, second.id)
        self.assertEqual(len(calls), 1)

    def test_idempotency_key_cannot_bind_another_message(self):
        broker, _, _, principal = broker_fixture()
        broker.send_message(request_message(), send_context(principal))
        other = A2AMessage(role=A2AMessageRole.USER, parts=(A2APart.text_part("different"),))
        with self.assertRaisesRegex(Exception, "idempotency"):
            broker.send_message(other, send_context(principal))

    def test_wrong_audience_is_blocked_before_handler(self):
        broker, _, calls, principal = broker_fixture()
        wrong = A2APrincipal(
            tenant_id=principal.tenant_id,
            subject=principal.subject,
            actor_id=principal.actor_id,
            audience="spiffe://wrong",
            resource=principal.resource,
            delegation_depth=principal.delegation_depth,
        )
        with self.assertRaises(A2APolicyError) as raised:
            broker.send_message(request_message(), send_context(wrong, key="wrong-audience"))
        self.assertIn("A2A-AUDIENCE-MISMATCH", raised.exception.reason_codes)
        self.assertEqual(calls, [])

    def test_denied_data_class_is_blocked_at_boundary(self):
        broker, _, calls, principal = broker_fixture()
        context = send_context(principal, key="secret-data")
        context = A2ASendContext(
            principal=context.principal,
            source_actor_id=context.source_actor_id,
            target_actor_id=context.target_actor_id,
            purpose=context.purpose,
            data_classes=frozenset({"D5"}),
            idempotency_key=context.idempotency_key,
        )
        with self.assertRaises(A2APolicyError) as raised:
            broker.send_message(request_message(), context)
        self.assertIn("A2A-BOUNDARY-DATA-CLASS-DENIED", raised.exception.reason_codes)
        self.assertEqual(calls, [])

    def test_task_visibility_is_tenant_and_participant_bound(self):
        broker, _, _, principal = broker_fixture()
        task = broker.send_message(request_message(), send_context(principal))
        outsider = A2APrincipal(
            tenant_id="tenant-a",
            subject="outsider",
            actor_id="agent.unknown",
            audience="",
            resource="",
        )
        with self.assertRaisesRegex(Exception, "not visible"):
            broker.get_task(principal=outsider, task_id=task.id)


class A2AJSONRPCRouterTests(unittest.TestCase):
    def test_a2a_v1_send_get_and_cancel_methods(self):
        broker, _, _, principal = broker_fixture()
        router = A2AJSONRPCRouter(broker, target_actor_id="agent.research")
        send = router.handle(
            {
                "jsonrpc": "2.0",
                "id": "rpc-1",
                "method": "SendMessage",
                "params": {
                    "message": request_message().to_dict(),
                    "metadata": {
                        "interlock.dev/purpose": "SUPPORT_RESEARCH",
                        "interlock.dev/dataClasses": ["D2", "D3"],
                        "interlock.dev/idempotencyKey": "rpc-research-1",
                    },
                },
            },
            principal,
        )
        self.assertEqual(send["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED")
        task_id = send["result"]["task"]["id"]
        get = router.handle(
            {"jsonrpc": "2.0", "id": "rpc-2", "method": "GetTask", "params": {"id": task_id}},
            principal,
        )
        self.assertEqual(get["result"]["task"]["id"], task_id)
        cancel = router.handle(
            {"jsonrpc": "2.0", "id": "rpc-3", "method": "CancelTask", "params": {"id": task_id}},
            principal,
        )
        self.assertEqual(cancel["error"]["code"], -32002)

    def test_input_required_task_accepts_follow_up_message(self):
        broker, _, calls, principal = broker_fixture()
        responses = 0

        def multi_turn_handler(task, message, context):
            nonlocal responses
            responses += 1
            calls.append((task.id, context.purpose))
            state = A2ATaskState.INPUT_REQUIRED if responses == 1 else A2ATaskState.COMPLETED
            return A2AHandlerResult(
                state=state,
                message=A2AMessage(
                    role=A2AMessageRole.AGENT,
                    parts=(A2APart.text_part("More detail required" if responses == 1 else "Complete"),),
                ),
            )

        broker.register_agent(
            "agent.research",
            broker.agent_card("agent.research"),
            multi_turn_handler,
        )
        first = broker.send_message(request_message(), send_context(principal, key="multi-turn-1"))
        self.assertEqual(first.status.state, A2ATaskState.INPUT_REQUIRED)
        follow_up = A2AMessage(
            role=A2AMessageRole.USER,
            parts=(A2APart.text_part("The device is model X"),),
            task_id=first.id,
            context_id=first.context_id,
        )
        completed = broker.send_message(follow_up, send_context(principal, key="multi-turn-2"))
        self.assertEqual(completed.status.state, A2ATaskState.COMPLETED)
        self.assertEqual(len(completed.history), 4)

    def test_input_required_task_can_be_canceled(self):
        broker, _, _, principal = broker_fixture()

        def input_required_handler(task, message, context):
            return A2AHandlerResult(
                state=A2ATaskState.INPUT_REQUIRED,
                message=A2AMessage(
                    role=A2AMessageRole.AGENT,
                    parts=(A2APart.text_part("More detail required"),),
                ),
            )

        broker.register_agent(
            "agent.research",
            broker.agent_card("agent.research"),
            input_required_handler,
        )
        task = broker.send_message(request_message(), send_context(principal, key="cancelable-1"))
        response = A2AJSONRPCRouter(broker, target_actor_id="agent.research").handle(
            {"jsonrpc": "2.0", "id": "rpc-cancel", "method": "CancelTask", "params": {"id": task.id}},
            principal,
        )
        self.assertEqual(response["result"]["task"]["status"]["state"], "TASK_STATE_CANCELED")

    def test_a2a_v03_aliases_remain_available_when_version_is_explicit(self):
        broker, _, _, principal = broker_fixture()
        response = A2AJSONRPCRouter(broker, target_actor_id="agent.research").handle(
            {
                "jsonrpc": "2.0",
                "id": "rpc-legacy",
                "method": "message/send",
                "params": {
                    "message": request_message().to_dict(protocol_version="0.3"),
                    "purpose": "SUPPORT_RESEARCH",
                    "dataClasses": ["D2", "D3"],
                    "idempotencyKey": "rpc-legacy-1",
                },
            },
            principal,
            protocol_version="0.3",
        )
        self.assertEqual(response["result"]["status"]["state"], "completed")

    def test_unknown_method_is_fail_closed(self):
        broker, _, _, principal = broker_fixture()
        response = A2AJSONRPCRouter(broker, target_actor_id="agent.research").handle(
            {"jsonrpc": "2.0", "id": "rpc-1", "method": "admin/delete", "params": {}},
            principal,
        )
        self.assertEqual(response["error"]["code"], -32601)


class A2AHTTPTests(unittest.TestCase):
    def setUp(self):
        broker, _, _, self.principal = broker_fixture()
        router = A2AJSONRPCRouter(broker, target_actor_id="agent.research")
        self.server = create_a2a_http_server(
            "127.0.0.1",
            0,
            router=router,
            authenticator=StaticBearerA2AAuthenticator({"test-token": self.principal}),
            config=A2AHTTPConfig(allowed_origins=frozenset({"https://studio.example"})),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_public_agent_card_and_authenticated_message_send(self):
        with urlopen(f"{self.base_url}/.well-known/agent-card.json", timeout=2) as response:
            card = json.loads(response.read())
        self.assertEqual(card["supportedInterfaces"][0]["protocolVersion"], "1.0")
        self.assertEqual(card["supportedInterfaces"][0]["protocolBinding"], "JSONRPC")

        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": "http-rpc-1",
                "method": "SendMessage",
                "params": {
                    "message": request_message().to_dict(),
                    "metadata": {
                        "interlock.dev/purpose": "SUPPORT_RESEARCH",
                        "interlock.dev/dataClasses": ["D2", "D3"],
                        "interlock.dev/idempotencyKey": "http-research-1",
                    },
                },
            }
        ).encode()
        request = Request(
            f"{self.base_url}/a2a",
            data=payload,
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/json",
                "Origin": "https://studio.example",
                "A2A-Version": "1.0",
            },
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            result = json.loads(response.read())
            self.assertEqual(response.headers["Access-Control-Allow-Origin"], "https://studio.example")
        self.assertEqual(result["result"]["task"]["status"]["state"], "TASK_STATE_COMPLETED")

    def test_authenticated_rpc_rejects_missing_or_unsupported_version(self):
        payload = json.dumps({"jsonrpc": "2.0", "id": "1", "method": "GetExtendedAgentCard"}).encode()
        request = Request(
            f"{self.base_url}/a2a",
            data=payload,
            headers={"Authorization": "Bearer test-token", "Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as error:
            urlopen(request, timeout=2)
        self.assertEqual(error.exception.code, 400)

    def test_rpc_requires_authentication_and_denies_unknown_browser_origin(self):
        payload = json.dumps({"jsonrpc": "2.0", "id": "1", "method": "agent/getCard", "params": {}}).encode()
        unauthenticated = Request(
            f"{self.base_url}/a2a",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(HTTPError) as unauth_error:
            urlopen(unauthenticated, timeout=2)
        self.assertEqual(unauth_error.exception.code, 401)

        bad_origin = Request(
            f"{self.base_url}/a2a",
            data=payload,
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/json",
                "Origin": "https://evil.example",
            },
            method="POST",
        )
        with self.assertRaises(HTTPError) as origin_error:
            urlopen(bad_origin, timeout=2)
        self.assertEqual(origin_error.exception.code, 403)


class OrchestrationEngineTests(unittest.TestCase):
    @staticmethod
    def _engine(*, approval_required=False, approval_provider=None):
        broker, _, calls, _ = broker_fixture(
            orchestration_manifest(approval_required=approval_required)
        )

        def principal_provider(task, tenant_id, run_id):
            return A2APrincipal.for_edge(
                tenant_id=tenant_id,
                subject=run_id,
                source_actor_id=task.source_actor_id,
                target_actor_id=task.target_actor_id,
                target_identity=broker.architecture.actors[task.target_actor_id].identity,
                delegation_depth=1,
            )

        adapter = A2AOrchestrationAdapter(broker, principal_provider)
        engine = OrchestrationEngine(
            broker.architecture,
            adapters={TaskTransport.A2A: adapter},
            approval_provider=approval_provider,
        )
        return engine, calls

    def test_dependency_graph_executes_a2a_tasks_to_completion(self):
        engine, calls = self._engine()
        run = engine.start(
            tenant_id="tenant-a",
            workflow_input={"question": "How do I reset the device?"},
            run_id="workflow-1",
            trace_id="trace-workflow-1",
        )
        self.assertEqual(run.state, WorkflowRunState.COMPLETED)
        self.assertEqual(run.tasks["task.research"].state, WorkflowTaskState.COMPLETED)
        self.assertEqual(run.tasks["task.verify"].state, WorkflowTaskState.COMPLETED)
        self.assertEqual(run.messages_used, 2)
        self.assertEqual(len(calls), 2)

    def test_approval_gate_pauses_and_resume_does_not_replay_completed_task(self):
        approved = {"value": False}

        def approval_provider(tenant_id, run_id, task, context):
            return approved["value"]

        engine, calls = self._engine(approval_required=True, approval_provider=approval_provider)
        paused = engine.start(
            tenant_id="tenant-a",
            workflow_input={"question": "Reset?"},
            run_id="workflow-approval",
        )
        self.assertEqual(paused.state, WorkflowRunState.WAITING_APPROVAL)
        self.assertEqual(paused.tasks["task.research"].state, WorkflowTaskState.COMPLETED)
        self.assertEqual(paused.tasks["task.verify"].state, WorkflowTaskState.WAITING_APPROVAL)
        self.assertEqual(len(calls), 1)

        approved["value"] = True
        completed = engine.resume(tenant_id="tenant-a", run_id=paused.id)
        self.assertEqual(completed.state, WorkflowRunState.COMPLETED)
        self.assertEqual(completed.tasks["task.verify"].state, WorkflowTaskState.COMPLETED)
        self.assertEqual(completed.messages_used, 2)
        self.assertEqual(len(calls), 2)

    def test_missing_transport_adapter_fails_closed(self):
        broker, _, _, _ = broker_fixture(orchestration_manifest())
        run = OrchestrationEngine(broker.architecture).start(
            tenant_id="tenant-a",
            workflow_input={"question": "Reset?"},
            run_id="workflow-no-adapter",
        )
        self.assertEqual(run.state, WorkflowRunState.FAILED)
        self.assertEqual(run.tasks["task.research"].error_code, "ORCH-ADAPTER-MISSING")


if __name__ == "__main__":
    unittest.main()
