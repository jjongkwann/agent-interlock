"""Wire the manifest to the three real tools and hand back what the tool runner needs.

``build()`` is the whole contract a project has with Interlock, and it is the same contract
``interlock architecture skeleton`` generates and ``interlock verify`` imports:

    MANIFEST, TENANT_ID, SOURCE_ACTOR_ID, BINDINGS, build(bindings=BINDINGS, *, ledger=None, approve=None)
      -> (gateway, tools)

``tools`` goes straight into ``client.beta.messages.tool_runner(tools=list(tools), ...)``; the
gateway is the evidence trail for everything the model then did.

**Generated, then hand-edited.** ``interlock architecture skeleton architecture.json --out-dir .``
wrote the first draft of this module: every import, ``MANIFEST``, ``_pin_definitions``, and the
``bind_architecture``/``guard_tools`` sequence in ``build()`` are exactly what it emitted. Five
things needed a human afterwards: (1) the three handler bodies, which the generator can only stub
with ``NotImplementedError``; (2) the three tool descriptions, which it can only stub with a TODO;
(3) ``TENANT_ID``, generated as the placeholder ``"tenant-dev"``; (4) ``APPROVER``, generated as a
placeholder string asking who signed off the definitions; (5) ``build()``'s signature and body,
which needed an ``approve`` parameter threaded through to ``guard_tools`` -- the generator has no
notion of an approval hook because a generated project has no edge that could hold on one until a
human names an approver. Everything else -- the wiring a project owes Interlock -- came from the
manifest with no hand-editing at all.

**Digest pinning.** The manifest ships no ``definitionDigest`` on any TOOL node, because the digest
belongs to the definition in ``tools.py`` and nobody should have to keep a hash in two files in sync
by hand. ``build()`` computes it the way :class:`~agent_interlock.registry.DefinitionRegistry` does
-- ``canonical_digest(definition.canonical_value())`` -- and writes it into the graph *before*
compiling, which is what makes the compile pass ``ARCH-TOOL-DIGEST-UNPINNED``.

**Why ``tool.issue-refund`` declares ``EXTERNAL_WRITE``, not ``PAYMENT``.** The manifest could
equally well tag this edge's side effect with ``SideEffect.PAYMENT`` -- issuing a refund is a
payment action, and ``PAYMENT`` ranks above ``EXTERNAL_WRITE`` in ``intent.side_effect_rank``. But
the policy check table (``agent_interlock.policy``) has no approval gate keyed to ``PAYMENT``:
``_approval`` -- the check ``externalWriteRequiresApproval`` arms -- refuses to fire on anything
other than ``estimated_side_effect == SideEffect.EXTERNAL_WRITE``, and ``_destructive_write``
likewise only fires on ``DESTRUCTIVE_WRITE``. A tool actor whose declared side effects are strongest
at ``PAYMENT`` is judged only by ``_side_effect_declared`` (is ``PAYMENT`` in the actor's own
declared set, yes or no), which is a capability check, not a hold-for-a-human gate. So a manifest
that tagged this edge ``PAYMENT`` with ``externalWriteRequiresApproval: true`` would compile clean
and then silently never hold: the field the edge sets is never consulted for that side effect. To
get the amount-cap approval this example demonstrates (see ``run.py``) actually enforced by
Interlock rather than by application code the model could route around, the TOOL node here declares
``EXTERNAL_WRITE`` and the edge sets ``requireExplicitDestination: false`` (there is no destination
in this call, only an order id and an amount). This is a real gap in the shipped check table --
``PAYMENT`` has no approval semantics of its own even though it outranks every side effect that
does -- and is reported as a follow-up rather than fixed here, since fixing the policy table is a
``src/`` change outside this project's scope.

**The approval step.** The issue-refund edge keeps ``externalWriteRequiresApproval: true``, so the
first time the model asks to issue a refund, the gateway holds the call with
``INTERLOCK-APPROVAL-REQUIRED`` and the guarded tool hands the exact arguments to the ``approve``
hook ``build()`` was given. When the hook returns an approver identity, an approval bound to those
arguments is granted and the call is judged again; every other control still has to clear on that
pass. The demo approver in ``run.py`` stands in for the operator screen: it approves refunds at or
under a cap and prints what it did. Without a hook the issue stays held, which is what
``interlock verify`` sees when it imports this module. ``tool.notify-customer`` sets
``externalWriteRequiresApproval: false`` -- the refund is the approved step; the notification is
bounded by ``allowedDomains`` alone.
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

from .tools import ISSUE_REFUND, LOOKUP_ORDER, NOTIFY_CUSTOMER, issue_refund, lookup_order, notify_customer

MANIFEST = Path(__file__).with_name("architecture.json")
TENANT_ID = "tenant-acme-refunds"
SOURCE_ACTOR_ID = "agent.refund"
APPROVER = "refund-reviewer"

BINDINGS: tuple[ToolBinding, ...] = (
    ToolBinding(LOOKUP_ORDER, lookup_order, "tool.lookup-order", "REFUND_LOOKUP"),
    ToolBinding(ISSUE_REFUND, issue_refund, "tool.issue-refund", "REFUND_ISSUE"),
    ToolBinding(NOTIFY_CUSTOMER, notify_customer, "tool.notify-customer", "REFUND_NOTIFY"),
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
    the operator hook a held refund is offered to (see the module docstring).
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
