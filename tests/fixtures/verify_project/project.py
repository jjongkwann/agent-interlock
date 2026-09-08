"""A minimal project built to the ``interlock verify`` contract.

Two tools -- a read-only case lookup and an outbound mailer -- wired to the manifest next to this
file. Nothing here touches the network: both callables return canned values. The point is that the
module exposes the five names ``interlock verify`` needs and that ``build()`` is the only place the
gateway is assembled, so a scenario can rebuild the whole project with one binding mutated.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from agent_interlock import (
    ArchitectureGraph,
    MCPToolGateway,
    SideEffect,
    ToolBinding,
    ToolDefinition,
    bind_architecture,
)
from agent_interlock.adapters.anthropic_tools import guard_tools
from agent_interlock.canonical import canonical_digest

MANIFEST = Path(__file__).with_name("architecture.json")
TENANT_ID = "tenant-a"
SOURCE_ACTOR_ID = "agent.support"
APPROVER = "security-reviewer"
SERVER_ID = "tenant-a/prod/support"

# The manifest parser carries no maxExportRecords field (docs/04 section 4), so the volume cap is
# set here, on the compiled policy, exactly as that section tells a project to do it.
MAX_EXPORT_RECORDS = 10

CASE_INPUT_SCHEMA = {
    "type": "object",
    "required": ["case_id"],
    "properties": {"case_id": {"type": "string"}},
    "additionalProperties": False,
}
CASE_OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["note"],
    "properties": {"note": {"type": "string"}},
    "additionalProperties": False,
}
EMAIL_INPUT_SCHEMA = {
    "type": "object",
    "required": ["to", "body"],
    "properties": {
        "to": {"type": "string", "format": "email"},
        "body": {"type": "string", "maxLength": 1000},
    },
    "additionalProperties": False,
}
EMAIL_OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["status"],
    "properties": {"status": {"type": "string"}},
    "additionalProperties": False,
}

LOOKUP_CASE = ToolDefinition(
    server_id=SERVER_ID,
    tool_name="lookup_case",
    title="Look up case",
    description="Return the current note for one support case, by its identifier.",
    input_schema=CASE_INPUT_SCHEMA,
    output_schema=CASE_OUTPUT_SCHEMA,
    annotations={"readOnlyHint": True},
)
SEND_EMAIL = ToolDefinition(
    server_id=SERVER_ID,
    tool_name="send_email",
    title="Send email",
    description="Send an approved customer support reply.",
    input_schema=EMAIL_INPUT_SCHEMA,
    output_schema=EMAIL_OUTPUT_SCHEMA,
    annotations={"destructiveHint": False},
)


def lookup_case(arguments: dict[str, Any]) -> dict[str, str]:
    return {"note": f"case {arguments['case_id']} is open"}


def send_email(arguments: dict[str, Any]) -> dict[str, str]:
    return {"status": "sent"}


BINDINGS: tuple[ToolBinding, ...] = (
    ToolBinding(LOOKUP_CASE, lookup_case, "tool.lookup-case", "CASE_LOOKUP"),
    ToolBinding(SEND_EMAIL, send_email, "tool.send-email", "SUPPORT_REPLY"),
)


def build(bindings: tuple[ToolBinding, ...] = BINDINGS, *, ledger: Any = None):
    """Compile the manifest, bind it into a gateway, and guard every tool.

    The manifest ships without ``definitionDigest`` on its TOOL nodes and the digests are pinned
    here from the definitions being guarded, so the reviewed manifest stays readable and a project
    cannot ship a pin that disagrees with the code. ``guard_tools`` raises when a definition does
    not reach ACTIVE, which is how a poisoned or drifted definition stops the process rather than
    reaching the model.
    """
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    digests = {binding.actor_id: canonical_digest(binding.definition.canonical_value()) for binding in bindings}
    for node in manifest["spec"]["nodes"]:
        if node["id"] in digests and not node.get("definitionDigest"):
            node["definitionDigest"] = digests[node["id"]]

    gateway = MCPToolGateway(ledger=ledger)
    bind_architecture(gateway, ArchitectureGraph.from_dict(manifest), approver=APPROVER)
    for binding in bindings:
        actor = gateway.actor(binding.actor_id)
        policy = gateway.link_policy(SOURCE_ACTOR_ID, binding.actor_id)
        if policy is None or actor is None or SideEffect.EXTERNAL_WRITE not in actor.side_effects:
            continue  # a cap on a read-only lookup would arm a control with nothing to count
        gateway.connect(SOURCE_ACTOR_ID, binding.actor_id, replace(policy, max_export_records=MAX_EXPORT_RECORDS))
    tools = guard_tools(
        gateway,
        tenant_id=TENANT_ID,
        source_actor_id=SOURCE_ACTOR_ID,
        bindings=bindings,
        approver=APPROVER,
    )
    return gateway, tools
