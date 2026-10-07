"""Architecture manifest to enforced MCP tools/call vertical slice."""

from __future__ import annotations

import json
from pathlib import Path

from agent_interlock import (
    ArchitectureCompiler,
    ArchitectureGraph,
    InvocationIntent,
    MCPInvocationContext,
    MCPServerProfile,
    MCPToolGateway,
    MCPTransportAdapter,
    SideEffect,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "secure_multi_agent_architecture.json"


class DemoMCPServer:
    def __init__(self) -> None:
        self.tools = [
            {
                "name": "send_email",
                "title": "Send email",
                "description": "Send an approved customer support reply.",
                "inputSchema": {
                    "type": "object",
                    "required": ["to", "body"],
                    "properties": {
                        "to": {"type": "string"},
                        "body": {"type": "string", "maxLength": 1000},
                    },
                    "additionalProperties": False,
                },
                "outputSchema": {
                    "type": "object",
                    "required": ["status"],
                    "properties": {"status": {"type": "string"}},
                    "additionalProperties": False,
                },
                "annotations": {"destructiveHint": False},
            }
        ]
        self.receipts = 0

    def __call__(self, request):
        if request["method"] == "tools/list":
            return {"jsonrpc": "2.0", "id": request["id"], "result": {"tools": self.tools}}
        if request["method"] == "tools/call":
            self.receipts += 1
            return {
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": {
                    "content": [{"type": "text", "text": '{"status":"sent"}'}],
                    "structuredContent": {"status": "sent"},
                    "isError": False,
                },
            }
        raise ValueError(f"unsupported demo method: {request['method']}")


server = DemoMCPServer()
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

# 1. Discovery observes D1, but does not expose an unapproved Tool to the model.
hidden = adapter.handle_client_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
assert hidden["result"]["tools"] == []
revision = adapter.observed_revisions[0]

# 2. A reviewed manifest pins the exact observed digest and compiles REL-05 controls.
manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
tool_node = next(node for node in manifest["spec"]["nodes"] if node["id"] == "tool.send-email")
tool_node["definitionDigest"] = revision.canonical_digest
compiled = ArchitectureCompiler().compile(ArchitectureGraph.from_dict(manifest))
adapter.bind_compiled_architecture(
    compiled,
    tool_bindings={"send_email": "tool.send-email"},
    approver="security-reviewer",
)

# 3. External write approval is bound to the exact arguments and destination.
arguments = {"to": "a@customer.example", "body": "Your case is resolved."}
approval = gateway.grant_approval(
    tenant_id="tenant-a",
    arguments=arguments,
    source_actor_id="agent.support",
    revision_id=revision.revision_id,
    intent=InvocationIntent(purpose="SUPPORT_REPLY", destinations=(arguments["to"],),
                            estimated_side_effect=SideEffect.EXTERNAL_WRITE),
    approver="support-operator",
)
response = adapter.handle_client_message(
    {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "send_email", "arguments": arguments},
    },
    context=MCPInvocationContext(
        tenant_id="tenant-a",
        source_actor_id="agent.support",
        purpose="SUPPORT_REPLY",
        destinations=(arguments["to"],),
        estimated_side_effect=SideEffect.EXTERNAL_WRITE,
        approval_id=approval.approval_id,
        trace_id="trace-mcp-vertical-slice",
    ),
)

print(json.dumps(response, indent=2, ensure_ascii=False))
print(f"downstream receipts: {server.receipts}")
print(f"ledger events: {len(gateway.ledger.all())}")
