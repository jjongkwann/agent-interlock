"""Fake-data platform E2E: design -> deploy -> A2A/MCP -> runtime evidence."""

from __future__ import annotations

import io
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from agent_interlock import (
    A2AAgentCard,
    A2AAgentSkill,
    A2AArtifact,
    A2ABroker,
    A2AHandlerResult,
    A2AHTTPConfig,
    A2AJSONRPCRouter,
    A2AMessage,
    A2AMessageRole,
    A2APart,
    A2APrincipal,
    A2ATaskState,
    ArchitectureCompiler,
    ArchitectureGraph,
    ArchitectureLinter,
    CallableTaskAdapter,
    DataSource,
    DeploymentBundle,
    Environment,
    GitBundleStore,
    InMemoryLedger,
    InvocationIntent,
    MCPInvocationContext,
    MCPServerProfile,
    MCPToolGateway,
    MCPTransportAdapter,
    OrchestrationEngine,
    OrchestrationError,
    SideEffect,
    SigningBackendUnavailable,
    StaticBearerA2AAuthenticator,
    TaskExecutionInput,
    TaskExecutionResult,
    TaskTransport,
    TrustedApprovalKey,
    WorkflowRunState,
    WorkflowTaskState,
    compare_runtime,
    create_a2a_http_server,
    deployed_architecture,
    ed25519_public_key_bytes,
    sign_deployment_approval,
    summarize_security_statistics,
)
from agent_interlock.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "secure_multi_agent_architecture.json"
FAKE_DATA = ROOT / "tests" / "fixtures" / "platform_e2e" / "fake_customer_support.json"

INPUT_SCHEMA = {
    "type": "object",
    "required": ["to", "subject", "body"],
    "properties": {
        "to": {"type": "string"},
        "subject": {"type": "string"},
        "body": {"type": "string"},
    },
    "additionalProperties": False,
}
OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["status", "receiptId"],
    "properties": {"status": {"type": "string"}, "receiptId": {"type": "string"}},
    "additionalProperties": False,
}


class FakeMCPMailServer:
    """In-process MCP server that never opens a network connection."""

    def __init__(self, delivery: dict[str, str]) -> None:
        self.delivery = delivery
        self.call_count = 0
        self.last_arguments: dict[str, Any] | None = None
        self.tools = [
            {
                "name": "send_email",
                "title": "Fake support mail sender",
                "description": "Records a simulated support email receipt without external delivery.",
                "inputSchema": INPUT_SCHEMA,
                "outputSchema": OUTPUT_SCHEMA,
                "annotations": {"destructiveHint": False},
            }
        ]

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        if request["method"] == "tools/list":
            return {"jsonrpc": "2.0", "id": request["id"], "result": {"tools": self.tools}}
        if request["method"] == "tools/call":
            self.call_count += 1
            self.last_arguments = dict(request["params"]["arguments"])
            structured = {
                "status": self.delivery["status"],
                "receiptId": self.delivery["receiptId"],
            }
            return {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "content": [{"type": "text", "text": json.dumps(structured)}],
                    "structuredContent": structured,
                    "isError": False,
                },
            }
        raise AssertionError(f"unexpected fake MCP method: {request['method']}")


class A2AHTTPWorkflowAdapter:
    """Drive the orchestration A2A task through the real local HTTP carrier."""

    def __init__(self, endpoint: str, token: str, origin: str) -> None:
        self.endpoint = endpoint
        self.token = token
        self.origin = origin

    def execute(self, value: TaskExecutionInput) -> TaskExecutionResult:
        message = A2AMessage(
            role=A2AMessageRole.USER,
            parts=(
                A2APart.data_part(
                    {
                        "runId": value.run_id,
                        "taskId": value.task.id,
                        "objective": value.task.label,
                        "input": dict(value.workflow_input),
                        "dependencies": {key: dict(item) for key, item in value.dependency_outputs.items()},
                    }
                ),
            ),
            context_id=value.run_id,
            metadata={"interlock.dev/orchestrationTaskId": value.task.id},
        )
        payload = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": f"{value.run_id}:{value.task.id}:{value.attempt}",
                "method": "SendMessage",
                "params": {
                    "message": message.to_dict(),
                    "metadata": {
                        "interlock.dev/purpose": value.task.purpose,
                        "interlock.dev/dataClasses": sorted(value.task.data_classes),
                        "interlock.dev/idempotencyKey": f"{value.run_id}:{value.task.id}:{value.attempt}",
                        "interlock.dev/traceId": value.trace_id,
                    },
                },
            }
        ).encode()
        request = Request(
            self.endpoint,
            data=payload,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Origin": self.origin,
                "A2A-Version": "1.0",
            },
            method="POST",
        )
        with urlopen(request, timeout=max(0.1, value.deadline_epoch - time.time())) as response:
            result = json.loads(response.read())
        if "error" in result:
            raise OrchestrationError("ORCH-A2A-HTTP", result["error"]["message"])
        task = result["result"]["task"]
        if task["status"]["state"] != "TASK_STATE_COMPLETED":
            raise OrchestrationError("ORCH-A2A-TASK-INCOMPLETE", task["status"]["state"])
        return TaskExecutionResult(
            output={
                "a2aTaskId": task["id"],
                "artifacts": task["artifacts"],
                "message": task["status"].get("message"),
            },
            external_task_id=task["id"],
            metadata={"accepted": True, "transport": "A2A-HTTP"},
        )


class FakeMCPWorkflowAdapter:
    def __init__(
        self,
        transport: MCPTransportAdapter,
        gateway: MCPToolGateway,
        fake_data: dict[str, Any],
    ) -> None:
        self.transport = transport
        self.gateway = gateway
        self.fake_data = fake_data

    def execute(self, value: TaskExecutionInput) -> TaskExecutionResult:
        arguments = {
            "to": self.fake_data["customer"]["email"],
            "subject": "Simulated support reply",
            "body": self.fake_data["research"]["answer"],
        }
        approval = self.gateway.grant_approval(
            tenant_id=value.tenant_id,
            arguments=arguments,
            source_actor_id=value.task.source_actor_id,
            revision_id=self.gateway.registry.active_for("fake/support-mail:send_email").revision_id,
            intent=InvocationIntent(purpose=value.task.purpose, data_classes=value.task.data_classes,
                                    destinations=(arguments["to"],), estimated_side_effect=SideEffect.EXTERNAL_WRITE),
            approver="fake-human-reviewer",
        )
        response = self.transport.handle_client_message(
            {
                "jsonrpc": "2.0",
                "id": f"{value.run_id}:{value.task.id}:{value.attempt}",
                "method": "tools/call",
                "params": {"name": "send_email", "arguments": arguments},
            },
            context=MCPInvocationContext(
                tenant_id=value.tenant_id,
                source_actor_id=value.task.source_actor_id,
                purpose=value.task.purpose,
                data_classes=value.task.data_classes,
                destinations=(arguments["to"],),
                estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                approval_id=approval.approval_id,
                trace_id=value.trace_id,
                idempotency_key=f"{value.run_id}:{value.task.id}:{value.attempt}",
                environment=Environment.DEV,
                data_source=DataSource.SIMULATION,
            ),
        )
        if response is None or "error" in response:
            raise OrchestrationError("ORCH-MCP-FAILED", repr(response))
        return TaskExecutionResult(
            output=dict(response["result"]["structuredContent"]),
            metadata={"accepted": True, "transport": "MCP-FAKE"},
        )


def compile_shadow(path: Path) -> dict[str, Any]:
    output = io.StringIO()
    with redirect_stdout(output):
        code = main(["architecture", "compile", "--shadow", str(path)])
    if code != 0:
        raise AssertionError(output.getvalue())
    return json.loads(output.getvalue())


@unittest.skipUnless(shutil.which("git"), "git is required for the deployment E2E")
class FakePlatformE2ETests(unittest.TestCase):
    def test_design_deploy_execute_observe_and_fail_closed(self) -> None:
        fake_data = json.loads(FAKE_DATA.read_text(encoding="utf-8"))
        manifest_path = Path(os.environ.get("AGENT_INTERLOCK_PLATFORM_E2E_MANIFEST", MANIFEST))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        orchestration = manifest["spec"]["orchestration"]
        research_task = next(item for item in orchestration["tasks"] if item["transport"] == "A2A")
        reply_task = next(item for item in orchestration["tasks"] if item["transport"] == "MCP")
        support_actor_id = orchestration["coordinatorActorId"]
        research_actor_id = research_task["targetActorId"]
        mail_actor_id = reply_task["targetActorId"]
        ledger = InMemoryLedger()

        # Discover the fake Tool first, then pin that exact digest into the design.
        fake_mcp = FakeMCPMailServer(fake_data["delivery"])
        gateway = MCPToolGateway(ledger=ledger)
        mcp_transport = MCPTransportAdapter(
            gateway,
            MCPServerProfile(
                tenant_id=fake_data["tenantId"],
                server_id="fake/support-mail",
                endpoint="https://mcp.example.invalid/mcp",
                publisher="e2e-fixture",
                artifact_digest="sha256:" + "f" * 64,
            ),
            fake_mcp,
        )
        discovery = mcp_transport.handle_client_message(
            {"jsonrpc": "2.0", "id": "discover-fake-mail", "method": "tools/list", "params": {}}
        )
        self.assertEqual(discovery["result"]["tools"], [])
        revision = mcp_transport.observed_revisions[0]
        mail_actor = next(item for item in manifest["spec"]["nodes"] if item["id"] == mail_actor_id)
        mail_actor["definitionDigest"] = revision.canonical_digest
        mail_actor["allowedDomains"] = ["example.invalid"]

        with tempfile.TemporaryDirectory(prefix="interlock-platform-e2e-") as temporary:
            root = Path(temporary)
            manifest_path = root / "fake-architecture.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            # Compile and prove that the reviewed digest now covers boundaries and workflow.
            bundle_value = compile_shadow(manifest_path)
            self.assertTrue(bundle_value["deployable"])
            protected_spec = bundle_value["architecture"]["spec"]
            self.assertEqual(len(protected_spec["trustBoundaries"]), len(manifest["spec"]["trustBoundaries"]))
            self.assertEqual(
                len(protected_spec["orchestration"]["tasks"]),
                len(orchestration["tasks"]),
            )
            bundle = DeploymentBundle.from_compile_output(bundle_value)

            try:
                key_a = bytes.fromhex("11" * 32)
                key_b = bytes.fromhex("22" * 32)
                trusted = {
                    "fake-key-a": TrustedApprovalKey("fake-security-reviewer", ed25519_public_key_bytes(key_a)),
                    "fake-key-b": TrustedApprovalKey("fake-platform-reviewer", ed25519_public_key_bytes(key_b)),
                }
            except SigningBackendUnavailable:
                self.skipTest("Ed25519 backend is required for the deployment E2E")
            store = GitBundleStore(root / "deployment")
            store.propose(bundle)
            approvals = (
                sign_deployment_approval(
                    bundle,
                    from_digest=None,
                    to_mode="ENFORCE",
                    target_id=store.target_id, tenant_id=store.tenant_id,
                    approver_id="fake-security-reviewer",
                    key_id="fake-key-a",
                    key=key_a,
                ),
                sign_deployment_approval(
                    bundle,
                    from_digest=None,
                    to_mode="ENFORCE",
                    target_id=store.target_id, tenant_id=store.tenant_id,
                    approver_id="fake-platform-reviewer",
                    key_id="fake-key-b",
                    key=key_b,
                ),
            )
            store.promote(bundle.bundle_digest, approvals, trusted_approvers=trusted)
            self.assertEqual(store.active()["mode"], "ENFORCE")

            # Reconstruct the exact promoted architecture, with the deployment record's mode
            # applied to every edge, rather than using an unreviewed object.
            deployed_graph = deployed_architecture(bundle.body, store.active()["mode"])
            compiled = ArchitectureCompiler().compile(deployed_graph)
            mcp_transport.bind_compiled_architecture(
                compiled,
                tool_bindings={"send_email": mail_actor_id},
                approver="fake-tool-reviewer",
            )

            research_calls: list[str] = []
            broker = A2ABroker(compiled, ledger=ledger)

            def fake_research_handler(task, message, context):  # noqa: ANN001
                research_calls.append(task.id)
                return A2AHandlerResult(
                    state=A2ATaskState.COMPLETED,
                    message=A2AMessage(
                        role=A2AMessageRole.AGENT,
                        parts=(A2APart.text_part("Simulated tenant-scoped research completed."),),
                    ),
                    artifacts=(
                        A2AArtifact(
                            artifact_id="artifact-fake-research-001",
                            name="Fake grounded research",
                            parts=(A2APart.data_part(fake_data["research"]),),
                        ),
                    ),
                )

            broker.register_agent(
                research_actor_id,
                A2AAgentCard(
                    actor_id=research_actor_id,
                    name="Fake research agent",
                    description="Returns deterministic E2E fixture data.",
                    url="http://127.0.0.1/a2a",
                    version="1.0.0",
                    skills=(
                        A2AAgentSkill(
                            id="KNOWLEDGE_SEARCH",
                            name="Fake knowledge search",
                            description="Searches fixture-only knowledge.",
                        ),
                    ),
                ),
                fake_research_handler,
            )
            principal = A2APrincipal.for_edge(
                tenant_id=fake_data["tenantId"],
                subject=fake_data["runId"],
                source_actor_id=support_actor_id,
                target_actor_id=research_actor_id,
                target_identity=compiled.actors[research_actor_id].identity,
                delegation_depth=1,
            )
            router = A2AJSONRPCRouter(
                broker,
                target_actor_id=research_actor_id,
                environment=Environment.DEV,
                data_source=DataSource.SIMULATION,
            )
            origin = "https://studio.example.invalid"
            token = "fake-e2e-bearer"
            server = create_a2a_http_server(
                "127.0.0.1",
                0,
                router=router,
                authenticator=StaticBearerA2AAuthenticator({token: principal}),
                config=A2AHTTPConfig(allowed_origins=frozenset({origin})),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()

            def stop_a2a_server() -> None:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            self.addCleanup(stop_a2a_server)

            approved = {"value": False}
            engine = OrchestrationEngine(
                compiled,
                adapters={
                    TaskTransport.A2A: A2AHTTPWorkflowAdapter(
                        f"http://127.0.0.1:{server.server_address[1]}/a2a",
                        token,
                        origin,
                    ),
                    TaskTransport.MCP: CallableTaskAdapter(
                        FakeMCPWorkflowAdapter(mcp_transport, gateway, fake_data).execute
                    ),
                },
                approval_provider=lambda tenant_id, run_id, task, context: approved["value"],
                ledger=ledger,
            )
            paused = engine.start(
                tenant_id=fake_data["tenantId"],
                run_id=fake_data["runId"],
                trace_id=fake_data["traceId"],
                workflow_input={
                    "customerId": fake_data["customer"]["id"],
                    **fake_data["request"],
                },
            )
            self.assertEqual(paused.state, WorkflowRunState.WAITING_APPROVAL)
            self.assertEqual(paused.tasks[research_task["id"]].state, WorkflowTaskState.COMPLETED)
            self.assertEqual(paused.tasks[reply_task["id"]].state, WorkflowTaskState.WAITING_APPROVAL)
            self.assertEqual(len(research_calls), 1)
            self.assertEqual(fake_mcp.call_count, 0)

            approved["value"] = True
            completed = engine.resume(tenant_id=fake_data["tenantId"], run_id=fake_data["runId"])
            self.assertEqual(completed.state, WorkflowRunState.COMPLETED)
            self.assertEqual(completed.tasks[reply_task["id"]].output, fake_data["delivery"])
            self.assertEqual(len(research_calls), 1, "resume must not replay a completed A2A task")
            self.assertEqual(fake_mcp.call_count, 1)
            self.assertEqual(fake_mcp.last_arguments["to"], fake_data["customer"]["email"])

            # Happy-path runtime evidence conforms to the promoted design.
            runtime = compare_runtime(deployed_graph, ledger.all())
            self.assertTrue(runtime.conforms)
            self.assertEqual(runtime.undeclared_edges, ())
            self.assertEqual(runtime.control_bypass_interactions, ())
            statistics = summarize_security_statistics(event.to_dict() for event in ledger.all())
            simulation = next(item for item in statistics["partitions"] if item["dataSource"] == "SIMULATION")
            self.assertEqual(simulation["counters"]["interactionCount"], 2)
            self.assertEqual(simulation["counters"]["executionAttemptCount"], 2)
            self.assertEqual(simulation["counters"]["executionSuccessCount"], 2)

            # A forbidden D5 request is rejected at the A2A boundary before the handler.
            blocked_request = Request(
                f"http://127.0.0.1:{server.server_address[1]}/a2a",
                data=json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "blocked-d5",
                        "method": "SendMessage",
                        "params": {
                            "message": A2AMessage(
                                role=A2AMessageRole.USER,
                                parts=(A2APart.data_part({"fake": "sensitive"}),),
                            ).to_dict(),
                            "metadata": {
                                "interlock.dev/purpose": "SUPPORT_RESEARCH",
                                "interlock.dev/dataClasses": ["D5"],
                                "interlock.dev/idempotencyKey": "blocked-d5",
                                "interlock.dev/traceId": fake_data["traceId"],
                            },
                        },
                    }
                ).encode(),
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                    "Origin": origin,
                    "A2A-Version": "1.0",
                },
                method="POST",
            )
            with urlopen(blocked_request, timeout=2) as response:
                blocked = json.loads(response.read())
            self.assertEqual(blocked["error"]["code"], -32099)
            self.assertIn("A2A-BOUNDARY-DATA-CLASS-DENIED", blocked["error"]["data"]["reasonCodes"])
            self.assertEqual(len(research_calls), 1)
            blocked_statistics = summarize_security_statistics(event.to_dict() for event in ledger.all())
            simulation = next(
                item for item in blocked_statistics["partitions"] if item["dataSource"] == "SIMULATION"
            )
            self.assertEqual(simulation["counters"]["enforcedBlockCount"], 1)

            # An undeclared, uncontrolled fake call is visible as both drift and bypass.
            rogue_interaction = "interaction-fake-rogue-001"
            ledger.append(
                "INTERACTION_REQUESTED",
                tenant_id=fake_data["tenantId"],
                trace_id=fake_data["traceId"],
                span_id="span-fake-rogue-001",
                interaction_id=rogue_interaction,
                source_actor_id=support_actor_id,
                target_actor_id="external.rogue-fake",
                relationship_type="SENDS",
                relationship_id="REL-07",
                payload={"fixture": True},
                environment=Environment.DEV,
                data_source=DataSource.SIMULATION,
            )
            drift = compare_runtime(deployed_graph, ledger.all())
            self.assertEqual(len(drift.undeclared_edges), 1)
            self.assertEqual(drift.control_bypass_interactions, (rogue_interaction,))

    def test_missing_boundary_blocks_before_deployment(self) -> None:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        delegation = next(item for item in manifest["spec"]["edges"] if item["relationshipId"] == "REL-06")
        delegation.pop("boundaryId")
        graph = ArchitectureGraph.from_dict(manifest)
        codes = {finding.code for finding in ArchitectureLinter().lint(graph)}
        self.assertIn("ARCH-BOUNDARY-MISSING", codes)


if __name__ == "__main__":
    unittest.main()
