"""Live Claude Code structured decisions, explicitly distinct from native provider tool use.

Uses existing Claude Code authentication without inspecting or copying credentials. Each turn runs
in an empty temporary directory in safe mode (no CLAUDE.md, skills, plugins, hooks, MCP or memory),
with every built-in tool removed and no saved session. Only Claude Code's StructuredOutput tool may
appear. The parent evaluator alone dispatches proposed tools.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from typing import Any

PROTOCOL_TOOL = "StructuredOutput"


class ClaudeCodeDecisionRunner:
    mode = "live-cli-structured-decisions"

    def __init__(self, model: str, *, timeout: float = 120, executable: str = "claude") -> None:
        if not model:
            raise ValueError("an explicit Claude Code model is required")
        self.model, self.timeout, self.executable = model, timeout, executable

    def complete(self, *, system: str, messages: list, tools: list) -> dict[str, Any]:
        schema = {
            "type": "object", "additionalProperties": False, "required": ["calls", "text", "refusal"],
            "properties": {
                "calls": {"type": "array", "items": {"anyOf": [
                    {"type": "object", "additionalProperties": False, "required": ["name", "input"],
                     "properties": {"name": {"type": "string", "enum": [tool["name"]]},
                                    "input": tool["input_schema"]}}
                    for tool in tools
                ]}},
                "text": {"type": "string"}, "refusal": {"type": "boolean"},
            },
        }
        command = [self.executable, "-p", "--safe-mode", "--tools", "", "--strict-mcp-config",
                   "--disable-slash-commands", "--no-session-persistence", "--model", self.model,
                   "--output-format", "stream-json", "--verbose", "--json-schema", json.dumps(schema),
                   "--system-prompt",
                   system + "\nReturn only your NEXT decision as structured JSON. The synthetic tools in the "
                   "user message are dispatched by the evaluation host after your response. calls=[] ends the "
                   "task. Do not predict a tool result. Set refusal=true only if refusing the task."]
        with tempfile.TemporaryDirectory(prefix="interlock-model-eval-") as directory:
            result = subprocess.run(
                command, input=json.dumps({"tools": tools, "messages": messages}), cwd=directory,
                text=True, capture_output=True, timeout=self.timeout,
            )
        events = []
        for line in result.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
        # A CLI session that offers or uses anything beyond the proposal protocol is invalid evidence.
        init = next((event for event in events if event.get("type") == "system"
                     and event.get("subtype") == "init"), None)
        tool_names = [block.get("name") for event in events if event.get("type") == "assistant"
                      for block in event.get("message", {}).get("content", []) if block.get("type") == "tool_use"]
        if (init is None or init.get("tools") != [PROTOCOL_TOOL] or init.get("mcp_servers")
                or any(name != PROTOCOL_TOOL for name in tool_names)):
            raise RuntimeError("Claude Code offered or used a tool outside the evaluation protocol")
        final = next((event for event in reversed(events) if event.get("type") == "result"), None)
        if result.returncode or final is None or final.get("is_error"):
            raise RuntimeError(f"Claude Code evaluation failed (exit {result.returncode}, "
                               f"{final.get('subtype') if final else 'no result'})")
        answer = final.get("structured_output")
        if (not isinstance(answer, dict) or set(answer) != {"calls", "text", "refusal"}
                or type(answer["refusal"]) is not bool or not isinstance(answer["calls"], list)):
            raise ValueError("invalid Claude Code decision response")
        # Prefix ids with the number of prior turns because the CLI processes each turn afresh.
        calls = [{"type": "tool_use", "id": f"cli-{len(messages)}-{index}", **call}
                 for index, call in enumerate(answer["calls"])]
        return {"content": calls or [{"type": "text", "text": answer["text"]}],
                "stopReason": "refusal" if answer["refusal"] else "tool_use" if calls else "end_turn",
                "usage": final.get("usage", {}), "model": self.model, "structuredDecision": answer,
                "eventTypes": [event.get("type") for event in events], "toolNames": tool_names}
