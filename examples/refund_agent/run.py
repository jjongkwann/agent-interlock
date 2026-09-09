"""Run the refund agent against Claude with all three tools guarded.

    PYTHONPATH=src python3 -m examples.refund_agent.run "Refund order 2001 and let the customer know."

The Anthropic SDK resolves credentials itself (``ANTHROPIC_API_KEY``), so nothing here reads the
environment. Without credentials this module still imports -- ``anthropic`` is imported inside
:func:`main` -- and ``tests/test_example_refund_agent.py`` drives the same code path by handing
``main`` a client pointed at a local server replaying ``recorded/*.json``.

Every ``tool_use`` block the model emits reaches the real function only through
``GuardedTool.call``, so the trace printed at the end is the Ledger's account of what the model was
allowed to do, not a log the tools wrote about themselves.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import Any

from agent_interlock import MCPToolGateway
from agent_interlock.analytics import reduce_interactions
from agent_interlock.models import PolicyDecisionRecord

from .build import Approver, build

MODEL = "claude-opus-5"
MAX_TOKENS = 16000
REFUND_APPROVAL_CAP = 100.0
_FAILURE_WORDS = ("blocked", "denied", "refused", "could not", "unable", "error", "not allowed", "failed")


def check_consistency(gateway: MCPToolGateway, reply: str) -> str | None:
    """Flag a reply that reads as success when the ledger shows a blocked tool call.

    A heuristic, not a proof: the model may have legitimately rephrased a refusal without using
    any of these words. It exists to surface the gap between the ledger's account and what the
    user was told, not to grade the model's prose.
    """
    records = reduce_interactions(event.to_dict() for event in gateway.ledger.all())
    blocked = sum(1 for record in records if record.enforced_block)
    if blocked == 0 or any(word in reply.lower() for word in _FAILURE_WORDS):
        return None
    return (
        f"⚠ The model's answer may not reflect the execution evidence: {blocked} tool call(s) "
        "were blocked but the reply does not mention it."
    )


def approve_refund(arguments: Mapping[str, Any], decision: PolicyDecisionRecord) -> str | None:
    """The demo stand-in for an operator screen.

    The gateway held the call with ``INTERLOCK-APPROVAL-REQUIRED``; this sees the exact arguments
    the model chose and either names the approver or refuses. A real deployment shows the same
    arguments to a person. The cap is enforced here, in application code -- Interlock's own
    approval gate only knows to hold the call, not what amount a person should be willing to wave
    through (see ``build.py`` for why this gate exists at all on a ``PAYMENT``-shaped action).
    """
    amount = float(arguments.get("amount", 0))
    if amount <= REFUND_APPROVAL_CAP:
        print(f"operator approved refund of {amount} ({decision.decision.value} -> approved)")
        return "refund-operator"
    print(f"operator refused refund of {amount} (above the {REFUND_APPROVAL_CAP} cap)")
    return None


def main(
    prompt: str, client: object | None = None, *, approve: Approver | None = approve_refund
) -> tuple[MCPToolGateway, str, str | None]:
    """Run one prompt to completion and print the reply and the evidence trail."""
    import anthropic

    gateway, tools = build(approve=approve)
    if client is None:
        client = anthropic.Anthropic()
    runner = client.beta.messages.tool_runner(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        tools=list(tools),
        messages=[{"role": "user", "content": prompt}],
    )
    final = runner.until_done()
    reply = "\n".join(block.text for block in final.content if block.type == "text")
    print(reply)
    print("ledger:", " ".join(event.event_type for event in gateway.ledger.all()))
    warning = check_consistency(gateway, reply)
    if warning is not None:
        print(warning)
    return gateway, reply, warning


if __name__ == "__main__":
    main(" ".join(sys.argv[1:]) or "Refund order 2001 and let the customer know.")
