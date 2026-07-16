"""Run with: PYTHONPATH=src python3 examples/secure_email.py"""

from agent_interlock import (
    ActorSpec,
    ActorType,
    InvocationIntent,
    LinkPolicy,
    MCPToolGateway,
    SideEffect,
    ToolDefinition,
)

input_schema = {
    "type": "object",
    "required": ["to", "body"],
    "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
    "additionalProperties": False,
}
definition = ToolDefinition(
    server_id="demo/dev/mail",
    tool_name="send_email",
    title="Send email",
    description="Send a message to an approved recipient.",
    input_schema=input_schema,
    output_schema={"type": "object"},
    endpoint="https://mcp.example.com",
    publisher="demo-team",
)

gateway = MCPToolGateway()
revision = gateway.observe_definition(definition, tenant_id="demo")
gateway.registry.approve(revision.revision_id, "demo-reviewer")
revision = gateway.registry.activate(revision.revision_id)

agent = ActorSpec(
    id="agent.support",
    type=ActorType.AGENT,
    owner="support",
    identity="spiffe://demo/agent/support",
)
tool = ActorSpec(
    id="tool.send-email",
    type=ActorType.TOOL,
    owner="messaging",
    identity="spiffe://demo/tool/send-email",
    side_effects=frozenset({SideEffect.EXTERNAL_WRITE}),
    input_schema=input_schema,
    output_schema={"type": "object"},
    allowed_domains=frozenset({"customer.example"}),
    definition_digest=revision.canonical_digest,
)
gateway.register_actor(agent)
gateway.register_actor(tool, tool_id=revision.tool_id)
gateway.connect(agent.id, tool.id, LinkPolicy(external_write_requires_approval=False))

result = gateway.invoke(
    tenant_id="demo",
    source_actor_id=agent.id,
    revision_id=revision.revision_id,
    intent=InvocationIntent(
        purpose="support-reply",
        destinations=("person@customer.example",),
        estimated_side_effect=SideEffect.EXTERNAL_WRITE,
    ),
    arguments={"to": "person@customer.example", "body": "Your case is resolved."},
    connector=lambda arguments: {"status": "sent", "to": arguments["to"]},
    idempotency_key="demo-message-1",
)

print(result.value)
print([event.event_type for event in gateway.ledger.trace("demo", result.decision.trace_id)])
