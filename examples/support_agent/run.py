"""Run the support agent against Claude with both tools guarded.

    PYTHONPATH=src python3 -m examples.support_agent.run "Where is order 1001? Email the customer."

The Anthropic SDK resolves credentials itself (``ANTHROPIC_API_KEY``), so nothing here reads the
environment. Without credentials this module still imports -- ``anthropic`` is imported inside
:func:`main` -- and ``tests/test_example_support_agent.py`` drives the same code path by handing
``main`` a client pointed at a local server replaying ``recorded/*.json``.

Every ``tool_use`` block the model emits reaches the real function only through
``GuardedTool.call``, so the trace printed at the end is the Ledger's account of what the model was
allowed to do, not a log the tools wrote about themselves.
"""

from __future__ import annotations

import sys

from agent_interlock import MCPToolGateway

from .build import build

MODEL = "claude-opus-5"
MAX_TOKENS = 16000


def main(prompt: str, client: object | None = None) -> tuple[MCPToolGateway, str]:
    """Run one prompt to completion and print the reply and the evidence trail."""
    import anthropic

    gateway, tools = build()
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
    return gateway, reply


if __name__ == "__main__":
    main(" ".join(sys.argv[1:]) or "Where is order 1001? Email the customer.")
