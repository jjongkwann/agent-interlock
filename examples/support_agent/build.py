"""Wire the manifest to the two real tools and hand back what the tool runner needs.

``build()`` is the whole contract a project has with Interlock, and it is the same contract
``interlock architecture skeleton`` generates and ``interlock verify`` imports:

    MANIFEST, TENANT_ID, SOURCE_ACTOR_ID, BINDINGS, build(bindings=BINDINGS, *, ledger=None)
      -> (gateway, tools)

``tools`` goes straight into ``client.beta.messages.tool_runner(tools=list(tools), ...)``; the
gateway is the evidence trail for everything the model then did.

**Digest pinning.** The manifest ships no ``definitionDigest`` on either TOOL node, because the
digest belongs to the definition in ``tools.py`` and nobody should have to keep a hash in two files
in sync by hand. ``build()`` computes it the way :class:`~agent_interlock.registry.DefinitionRegistry`
does -- ``canonical_digest(definition.canonical_value())`` -- and writes it into the graph *before*
compiling, which is what makes the compile pass ``ARCH-TOOL-DIGEST-UNPINNED``. A node that already
carries a pin is left exactly as authored: a pin that disagrees with the definition is M2 drift and
has to be reported by ``L1-M2-DEFINITION-DRIFT`` at call time, not quietly corrected here.

**The approval step.** The email edge keeps ``externalWriteRequiresApproval: true``, so the first
time the model asks to send, the gateway holds the call with ``INTERLOCK-APPROVAL-REQUIRED`` and
the guarded tool hands the exact arguments to the ``approve`` hook ``build()`` was given. When the
hook returns an approver identity, an approval bound to those arguments and destinations is
granted and the call is judged again; every other control still has to clear on that pass. The
demo approver in ``run.py`` stands in for the operator screen: it approves recipients under
``customer.example`` and prints what it approved. Without a hook the send stays held, which is
what ``interlock verify`` sees when it imports this module.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from agent_interlock import (
    ArchitectureGraph,
    Ledger,
    MCPToolGateway,
    ToolBinding,
    bind_architecture,
    guard_tools,
)
from agent_interlock.adapters.anthropic_tools import Approver, GuardedAsyncTool, GuardedTool
from agent_interlock.canonical import canonical_digest

from .tools import LOOKUP_ORDER, SEND_EMAIL, lookup_order, send_email

MANIFEST = Path(__file__).with_name("architecture.json")
TENANT_ID = "tenant-acme"
SOURCE_ACTOR_ID = "agent.support"
APPROVER = "security-reviewer"

BINDINGS: tuple[ToolBinding, ...] = (
    ToolBinding(LOOKUP_ORDER, lookup_order, "tool.lookup-order", "SUPPORT_LOOKUP"),
    ToolBinding(SEND_EMAIL, send_email, "tool.send-email", "SUPPORT_REPLY"),
)


def _pin_definitions(graph: ArchitectureGraph, bindings: Sequence[ToolBinding]) -> ArchitectureGraph:
    """Give every unpinned TOOL node the digest of the definition bound to it."""
    digests = {binding.actor_id: canonical_digest(binding.definition.canonical_value()) for binding in bindings}
    nodes = tuple(
        node
        if node.id not in digests or node.actor.definition_digest is not None
        else replace(node, actor=replace(node.actor, definition_digest=digests[node.id]))
        for node in graph.nodes
    )
    return replace(graph, nodes=nodes)


def build(
    bindings: Sequence[ToolBinding] = BINDINGS,
    *,
    ledger: Ledger | None = None,
    approve: Approver | None = None,
) -> tuple[MCPToolGateway, tuple[GuardedTool | GuardedAsyncTool, ...]]:
    """Compile the manifest, admit the definitions, and return ``(gateway, guarded tools)``.

    ``bindings`` is a parameter so a test can swap a function or a definition without a second copy
    of the wiring; ``ledger`` so a project can keep its evidence somewhere durable; ``approve`` is
    the operator hook a held external write is offered to (see the module docstring).
    """
    graph = ArchitectureGraph.from_dict(json.loads(MANIFEST.read_text(encoding="utf-8")))
    compiled = _pin_definitions(graph, bindings)
    gateway = MCPToolGateway(ledger=ledger)
    bind_architecture(
        gateway,
        compiled,
        tool_bindings={binding.definition.tool_name: binding.actor_id for binding in bindings},
        approver=APPROVER,
    )
    tools = guard_tools(
        gateway,
        tenant_id=TENANT_ID,
        source_actor_id=SOURCE_ACTOR_ID,
        bindings=list(bindings),
        approver=APPROVER,
        approve=approve,
    )
    return gateway, tools
