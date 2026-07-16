from __future__ import annotations

import unittest

from agent_interlock import (
    ArchitectureCompiler,
    ArchitectureGraph,
    DefinitionState,
    MCPArchitectureBindingError,
    MCPInvocationContext,
    MCPServerProfile,
    MCPToolGateway,
    MCPTransportAdapter,
    SideEffect,
)


INPUT_SCHEMA = {
    "type": "object",
    "required": ["to", "body"],
    "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
    "additionalProperties": False,
}
OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["status"],
    "properties": {"status": {"type": "string"}},
    "additionalProperties": False,
}


def mcp_tool(description: str = "Send an approved customer support reply.") -> dict:
    return {
        "name": "send_email",
        "title": "Send email",
        "description": description,
        "inputSchema": INPUT_SCHEMA,
        "outputSchema": OUTPUT_SCHEMA,
        "annotations": {"destructiveHint": False},
        "execution": {"taskSupport": "forbidden"},
    }


class FakeMCPServer:
    def __init__(self) -> None:
        self.tools = [mcp_tool()]
        self.call_count = 0
        self.result = {
            "content": [{"type": "text", "text": '{"status":"sent"}'}],
            "structuredContent": {"status": "sent"},
            "isError": False,
        }

    def __call__(self, request):
        method = request["method"]
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request["id"], "result": {"tools": self.tools}}
        if method == "tools/call":
            self.call_count += 1
            return {"jsonrpc": "2.0", "id": request["id"], "result": self.result}
        raise AssertionError(f"unexpected method: {method}")


def architecture_for(digest: str) -> ArchitectureGraph:
    return ArchitectureGraph.from_dict(
        {
            "apiVersion": "interlock.dev/v1alpha1",
            "kind": "Architecture",
            "metadata": {"id": "mcp-vertical-slice", "version": "1.0.0"},
            "spec": {
                "nodes": [
                    {
                        "id": "agent.support",
                        "type": "AGENT",
                        "owner": "support",
                        "identity": "spiffe://prod.example/agent/support",
                        "dataAccess": ["D2", "D3", "D7"],
                    },
                    {
                        "id": "tool.send-email",
                        "type": "TOOL",
                        "owner": "messaging",
                        "identity": "spiffe://prod.example/tool/send-email",
                        "dataAccess": ["D2", "D3", "D7"],
                        "sideEffects": ["EXTERNAL_WRITE"],
                        "allowedDomains": ["customer.example"],
                        "definitionDigest": digest,
                    },
                ],
                "edges": [
                    {
                        "id": "edge.support-email",
                        "relationshipId": "REL-05",
                        "source": "agent.support",
                        "target": "tool.send-email",
                        "relationship": "INVOKES",
                        "policy": {
                            "id": "support-email",
                            "mode": "ENFORCE",
                            "allowedPurposes": ["SUPPORT_REPLY"],
                            "externalWriteRequiresApproval": False,
                            "failureMode": "FAIL_CLOSED",
                        },
                        "controls": [
                            {
                                "id": "mcp-call-guard",
                                "objective": "PREVENT",
                                "timing": "PRE_EXECUTION",
                                "enforcementPoint": "MCP_GATEWAY",
                                "assurance": "ENFORCED",
                            },
                            {
                                "id": "mcp-audit",
                                "objective": "EVIDENCE",
                                "timing": "POST_EXECUTION",
                                "enforcementPoint": "AUDIT_SINK",
                                "assurance": "OBSERVED",
                            },
                        ],
                    }
                ],
            },
        }
    )


def list_request(request_id=1):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": {}}


def call_request(body: str = "hello", request_id=2):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {"name": "send_email", "arguments": {"to": "a@customer.example", "body": body}},
    }


def invocation_context() -> MCPInvocationContext:
    return MCPInvocationContext(
        tenant_id="tenant-a",
        source_actor_id="agent.support",
        purpose="SUPPORT_REPLY",
        destinations=("a@customer.example",),
        estimated_side_effect=SideEffect.EXTERNAL_WRITE,
        trace_id="trace-mcp-vertical",
    )


def discovered_adapter():
    server = FakeMCPServer()
    gateway = MCPToolGateway()
    adapter = MCPTransportAdapter(
        gateway,
        MCPServerProfile(
            tenant_id="tenant-a",
            server_id="tenant-a/prod/trusted-mail",
            endpoint="https://mcp.example.com/mcp",
            publisher="platform-team",
            artifact_digest="sha256:" + "a" * 64,
        ),
        server,
    )
    first = adapter.handle_client_message(list_request())
    return adapter, gateway, server, first


def bound_adapter():
    adapter, gateway, server, first = discovered_adapter()
    revision = adapter.observed_revisions[0]
    compiled = ArchitectureCompiler().compile(architecture_for(revision.canonical_digest))
    adapter.bind_compiled_architecture(
        compiled,
        tool_bindings={"send_email": "tool.send-email"},
        approver="security-reviewer",
    )
    return adapter, gateway, server, first, revision


class MCPTransportVerticalSliceTests(unittest.TestCase):
    def test_profile_rejects_unimplemented_protocol_version(self):
        with self.assertRaises(ValueError):
            MCPServerProfile(
                tenant_id="tenant-a",
                server_id="tenant-a/prod/test",
                endpoint="https://mcp.example.com/mcp",
                protocol_version="2025-06-18",
            )

    def test_discovery_is_hidden_until_exact_architecture_digest_is_bound(self):
        adapter, _, _, first = discovered_adapter()
        revision = adapter.observed_revisions[0]
        self.assertEqual(first["result"]["tools"], [])
        self.assertEqual(revision.state, DefinitionState.DISCOVERED)

        compiled = ArchitectureCompiler().compile(architecture_for(revision.canonical_digest))
        activated = adapter.bind_compiled_architecture(
            compiled,
            tool_bindings={"send_email": "tool.send-email"},
            approver="security-reviewer",
        )
        visible = adapter.handle_client_message(list_request(2))
        self.assertEqual(activated[0].state, DefinitionState.ACTIVE)
        self.assertEqual([tool["name"] for tool in visible["result"]["tools"]], ["send_email"])
        self.assertNotIn("execution", visible["result"]["tools"][0])

    def test_architecture_digest_mismatch_cannot_activate_tool(self):
        adapter, gateway, _, _ = discovered_adapter()
        compiled = ArchitectureCompiler().compile(architecture_for("sha256:" + "0" * 64))
        with self.assertRaises(MCPArchitectureBindingError):
            adapter.bind_compiled_architecture(
                compiled,
                tool_bindings={"send_email": "tool.send-email"},
                approver="security-reviewer",
            )
        self.assertEqual(adapter.observed_revisions[0].state, DefinitionState.DISCOVERED)
        self.assertIsNone(gateway.registry.active_for(adapter.observed_revisions[0].tool_id))

    def test_tools_call_runs_through_policy_and_result_guard(self):
        adapter, _, server, _, _ = bound_adapter()
        response = adapter.handle_client_message(call_request(), context=invocation_context())
        self.assertEqual(server.call_count, 1)
        self.assertEqual(response["result"]["structuredContent"], {"status": "sent"})
        self.assertEqual(response["result"]["_meta"]["interlock"]["decision"], "ALLOW")
        self.assertIn("UNTRUSTED_TOOL_RESULT", response["result"]["_meta"]["interlock"]["labels"])

    def test_definition_drift_blocks_before_downstream_tools_call(self):
        adapter, _, server, _, _ = bound_adapter()
        server.tools = [mcp_tool("Changed definition after approval.")]
        response = adapter.handle_client_message(call_request(), context=invocation_context())
        self.assertEqual(response["error"]["code"], -32001)
        self.assertIn("L1-M2-DEFINITION-DRIFT", response["error"]["data"]["reasonCodes"])
        self.assertEqual(server.call_count, 0)

    def test_secret_argument_is_blocked_and_never_dispatched(self):
        adapter, gateway, server, _, _ = bound_adapter()
        canary = "api_key=sk_live_1234567890abcdefghijkl"
        response = adapter.handle_client_message(call_request(canary), context=invocation_context())
        self.assertEqual(response["error"]["code"], -32001)
        self.assertIn("L1-M8-CREDENTIAL-DETECTED", response["error"]["data"]["reasonCodes"])
        self.assertEqual(server.call_count, 0)
        self.assertNotIn(canary, repr(gateway.ledger.all()))

    def test_mcp_structured_result_schema_and_secret_guard(self):
        adapter, _, server, _, _ = bound_adapter()
        server.result = {
            "content": [{"type": "text", "text": "api_key=abcd1234secretvalue"}],
            "structuredContent": {"unexpected": True},
            "isError": False,
        }
        response = adapter.handle_client_message(call_request(), context=invocation_context())
        self.assertTrue(response["result"]["isError"])
        labels = response["result"]["_meta"]["interlock"]["labels"]
        self.assertIn("D5_REDACTED", labels)
        self.assertIn("SCHEMA_INVALID", labels)
        self.assertNotIn("abcd1234secretvalue", repr(response))

    def test_missing_trusted_context_and_jsonrpc_batch_fail_closed(self):
        adapter, _, server, _, _ = bound_adapter()
        missing = adapter.handle_client_message(call_request())
        batch = adapter.handle_client_message([call_request()])
        self.assertEqual(missing["error"]["data"]["reasonCode"], "INTERLOCK-TRUSTED-CONTEXT-MISSING")
        self.assertEqual(batch["error"]["data"]["reasonCode"], "MCP-BATCH-NOT-SUPPORTED")
        self.assertEqual(server.call_count, 0)

    def test_cross_tenant_context_is_rejected_before_refresh_or_dispatch(self):
        adapter, _, server, _, _ = bound_adapter()
        context = MCPInvocationContext(
            tenant_id="tenant-b",
            source_actor_id="agent.support",
            purpose="SUPPORT_REPLY",
        )
        response = adapter.handle_client_message(call_request(), context=context)
        self.assertEqual(response["error"]["data"]["reasonCode"], "INTERLOCK-TENANT-MISMATCH")
        self.assertEqual(server.call_count, 0)

    def test_unapproved_request_meta_cannot_bypass_argument_policy(self):
        adapter, _, server, _, _ = bound_adapter()
        request = call_request()
        request["params"]["_meta"] = {"authorization": "api_key=sk_live_1234567890abcdefghijkl"}
        response = adapter.handle_client_message(request, context=invocation_context())
        self.assertEqual(response["error"]["data"]["reasonCode"], "INTERLOCK-MCP-META-DENIED")
        self.assertEqual(server.call_count, 0)

    def test_list_changed_refresh_quarantines_removed_active_tool(self):
        adapter, gateway, server, _, revision = bound_adapter()
        server.tools = []
        notification = adapter.handle_server_message(
            {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
        )
        self.assertEqual(notification["method"], "notifications/tools/list_changed")
        self.assertEqual(gateway.registry.get(revision.revision_id).state, DefinitionState.QUARANTINED)
        self.assertIn(
            "L1-M2-DEFINITION-REMOVED",
            gateway.registry.get(revision.revision_id).reason_codes,
        )


if __name__ == "__main__":
    unittest.main()
