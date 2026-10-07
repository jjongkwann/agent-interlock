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

From the repository root, install into a Python 3.11+ environment first:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[anthropic,jwt]'
python examples/secure_email.py
```

This page's `build()` reads a local manifest. It is the SDK adoption path and does not verify a promoted deployment. For reviewed deployment execution, use `load_promoted_architecture` and `build_managed_tools` as shown in the [managed support host](managed-support-host.md).

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

Set `ANTHROPIC_API_KEY` and `ANTHROPIC_MODEL` for the API account and model you intend to use.

```python
import os
import anthropic
gateway, tools = build()
client = anthropic.Anthropic()
runner = client.beta.messages.tool_runner(
    model=os.environ["ANTHROPIC_MODEL"], max_tokens=16000, tools=list(tools),
    messages=[{"role": "user", "content": "Where is order 1001? Email the customer."}],
)
final = runner.until_done()
```

Each guarded tool does four things on every call the model makes: derives the intent from the
arguments and the definition, asks the gateway for a verdict, runs your function only when the
verdict permits, and returns the sanitized result. A refused call reaches the model as an
`is_error` tool result carrying the reason codes, so the model can explain or retry within
policy. Nothing is raised into the loop.

**Approvals.** An edge with `externalWriteRequiresApproval: true` holds an external write with `INTERLOCK-APPROVAL-REQUIRED`. Pass `guard_tools(..., approve=...)` a callback returning the reviewer identity, or `None` to refuse. The adapter binds the grant to tenant, source/target, active revision, installed policy, full derived intent and exact arguments, then evaluates again. `gateway.grant_approval` takes `tenant_id`, `source_actor_id`, `revision_id`, `intent`, `arguments` and `approver`; it resolves the target and installed policy from that revision. An arguments-only grant is not valid. A grant is consumed atomically before execution and cannot authorize another operation, even if the first execution fails. A denied destination remains denied. Evaluation does not consume the grant; the hold remains in the ledger as evidence of waiting for a person.

Every step is in `gateway.ledger`: `INTERACTION_REQUESTED`, `DATA_FLOW_OBSERVED`,
`CONTROL_EVALUATED` (with the coverage of every check), `ACTION_EXECUTED`,
`INTERACTION_COMPLETED`, `SECURITY_OUTCOME_SET`. `summarize_security_statistics` turns a ledger
into the statistics the Studio shows.

A refused tool call does not stop the model from telling the user the action succeeded -- the
`is_error` result only tells the model what happened, not what it says next. `examples/*/run.py`
guards against reporting the gap silently: after the reply comes back, `check_consistency` reduces
the ledger with `reduce_interactions` and, if any interaction was `enforced_block` while the reply
carries no word suggesting refusal ("blocked", "denied", "could not", and the like), prints a
warning that the answer may not reflect the execution evidence. It is a heuristic on the reply's
wording, not a proof, so it only warns -- but it turns a silent mismatch between the ledger and
the user-facing text into something visible.

## 4. Verifying the project

```bash
interlock verify path/to/project.py --out report.json
```

`verify` rebuilds the project for each scenario and drives the guarded tools with a scripted
caller in place of the model: a poisoned description, a drifted definition, a cross-server
reference, a credential in a result, an undeclared destination, an undeclared side effect, a goal
hijack carried by a tool result, and memory poisoning through a read tool. The report lists each
scenario with the expected and observed outcome, plus `verified`, `notApplicable`, and `failed`
counts at the top level: NOT-APPLICABLE means the scenario found no subject to test in this
project (no read-only tool, no destination-marked property, no volume cap) and is not the same
claim as a control that ran and held. Exit code 1 means `failed` is non-zero; pass `--strict` to
also fail on any NOT-APPLICABLE scenario, for a project that claims every scenario was actually
exercised. Run it in CI next to your own tests.

## 5. What stays yours

Your tool functions, your prompt, your loop. What Interlock owns is the judgment on each call and
the evidence of it. When the manifest changes, re-run `lint`, regenerate or edit the bindings,
and re-run `verify`.

## Binding and operating limits

`ToolBinding` accepts `classify`, `estimate_export` and `result_provenance` hooks. The application supplies these from trusted data and records their installation; a control drawn in the manifest is only authored intent. Installed hooks and an observed `CONTROL_EVALUATED` event are separate evidence. The managed helper requires all three hooks and verifies each tool's pinned definition digest against the promoted bundle. A local binding without classification uses the conservative D3 input default; missing result provenance remains `UNCLASSIFIED`.

The skeleton also emits `<architecture>_edge_coverage.json`: static TOOL invocations from its first source are `WIRED`; other sources, dynamic selectors and other relationships are `MANUAL` with reasons. Complete each handler before claiming runtime coverage.

Use PostgreSQL Ledger for durable event evidence. Gateway invocation approvals and idempotency results remain process-local; durable ledger events do not make tool execution exactly-once across restarts. Workflow cancellation is cooperative, and an in-process adapter's timeout cannot undo or forcibly stop an external side effect. The [managed host](managed-support-host.md) documents a dedicated deployment owner, restart recovery and explicit resume; it is not a shared multi-tenant deployment service.
