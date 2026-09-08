---
title: Adding Agent Interlock to an Agent
date: 2026-09-08
version: 1.0
status: active
---

# Adding Agent Interlock to an Agent

> 한국어 원문: [16-adding-interlock-to-an-agent.ko.md](16-adding-interlock-to-an-agent.ko.md)

This is the ten-minute path from an existing tool-using agent to one whose every tool call is
judged, recorded and verifiable. It uses the Anthropic Python SDK Tool Runner; the agent loop
stays the SDK's, the tools stay yours, and Agent Interlock sits between the two.

## 1. What you declare

Three things, and only three:

1. **A manifest** (`architecture.json`): the Actors (your agent, each tool, the external systems
   they reach) and the edges between them with their policies. Draw it in the Studio or write it
   by hand; `interlock architecture lint` tells you what is missing.
2. **A `ToolDefinition` per tool**: name, description, input and output JSON Schema, MCP
   annotations. Mark destination-carrying properties with `format: "email"`, `format: "uri"`,
   `format: "hostname"` or `x-interlock-destination: true`; mark read-only tools with
   `readOnlyHint: true`. The schema subset is `type`, `required`, `properties`,
   `additionalProperties`, `items`, `enum`, `maxLength`, `pattern`; any other keyword is refused
   at definition time so nothing passes unvalidated.
3. **A `ToolBinding` per tool**: the definition, the Python function that implements it, the
   manifest node it belongs to, and the purpose it serves.

## 2. The project module

`interlock architecture skeleton <manifest> --out-dir .` writes this for you; a hand-written one
looks the same:

```python
import json
from pathlib import Path
from agent_interlock import (
    ArchitectureGraph, MCPToolGateway, ToolBinding, ToolDefinition, bind_architecture, guard_tools,
)

MANIFEST = Path(__file__).with_name("architecture.json")
TENANT_ID = "tenant-dev"
SOURCE_ACTOR_ID = "agent.support"

send_email_definition = ToolDefinition(
    server_id="tool.send-email", tool_name="send_email", title="Send email",
    description="Send a support reply to the customer.",
    input_schema={"type": "object", "required": ["to", "body"], "additionalProperties": False,
                  "properties": {"to": {"type": "string", "format": "email"},
                                 "body": {"type": "string", "maxLength": 2000}}},
    output_schema={"type": "object", "required": ["status"],
                   "properties": {"status": {"type": "string"}}},
)

def send_email(arguments):
    ...  # your implementation
    return {"status": "sent"}

BINDINGS = (ToolBinding(send_email_definition, send_email, "tool.send-email", "SUPPORT_REPLY"),)

def build(bindings=BINDINGS, *, ledger=None):
    gateway = MCPToolGateway(ledger=ledger)
    graph = ArchitectureGraph.from_dict(json.loads(MANIFEST.read_text()))
    bind_architecture(gateway, graph,
                      tool_bindings={b.definition.tool_name: b.actor_id for b in bindings},
                      approver="platform-review")
    tools = guard_tools(gateway, tenant_id=TENANT_ID, source_actor_id=SOURCE_ACTOR_ID,
                        bindings=bindings, approver="platform-review")
    return gateway, tools
```

`build()` observes each definition, approves and activates it, and refuses to return a tool
whose definition was quarantined (a hidden instruction, a cross-server reference, an unsupported
schema keyword). The model never sees such a tool.

## 3. The agent loop

```python
import anthropic
gateway, tools = build()
client = anthropic.Anthropic()
runner = client.beta.messages.tool_runner(
    model="claude-opus-5", max_tokens=16000, tools=list(tools),
    messages=[{"role": "user", "content": "Where is order 1001? Email the customer."}],
)
final = runner.until_done()
```

Each guarded tool does four things on every call the model makes: derives the intent from the
arguments and the definition, asks the gateway for a verdict, runs your function only when the
verdict permits, and returns the sanitized result. A refused call reaches the model as an
`is_error` tool result carrying the reason codes, so the model can explain or retry within
policy. Nothing is raised into the loop.

**Approvals.** An edge with `externalWriteRequiresApproval: true` holds the first call with
`INTERLOCK-APPROVAL-REQUIRED`. Pass `guard_tools(..., approve=...)` a function that receives the
exact arguments the model chose and returns the approver's identity, or `None` to refuse; a grant
is bound to those arguments and destinations and the call is judged again, so an approval cannot
carry a denied destination through. An approval granted ahead of time with
`gateway.grant_approval` is found by the same exact-arguments match. The hold stays in the ledger
as an evaluation with no action, which is how the statistics tell "waited for a person" from
"blocked".

Every step is in `gateway.ledger`: `INTERACTION_REQUESTED`, `DATA_FLOW_OBSERVED`,
`CONTROL_EVALUATED` (with the coverage of every check), `ACTION_EXECUTED`,
`INTERACTION_COMPLETED`, `SECURITY_OUTCOME_SET`. `summarize_security_statistics` turns a ledger
into the statistics the Studio shows.

## 4. Verifying the project

```bash
interlock verify path/to/project.py --out report.json
```

`verify` rebuilds the project for each scenario and drives the guarded tools with a scripted
caller in place of the model: a poisoned description, a drifted definition, a cross-server
reference, a credential in a result, an undeclared destination, an undeclared side effect, a goal
hijack carried by a tool result, and memory poisoning through a read tool. The report lists each
scenario with the expected and observed outcome; exit code 1 means at least one scenario did not
hold. Run it in CI next to your own tests.

## 5. What stays yours

Your tool functions, your prompt, your loop. What Interlock owns is the judgment on each call and
the evidence of it. When the manifest changes, re-run `lint`, regenerate or edit the bindings,
and re-run `verify`.
