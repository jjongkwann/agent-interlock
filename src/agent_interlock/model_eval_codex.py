"""Live Codex structured decisions, explicitly distinct from native provider tool use.

Uses existing CLI authentication without inspecting or copying credentials. Each turn runs in
an empty temporary directory with project guidance, user configuration, plugins, MCP, memory,
shell, browsing and subagents disabled. The parent evaluator alone dispatches proposed tools.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any


class CodexDecisionRunner:
    mode = "live-cli-structured-decisions"

    def __init__(self, model: str, *, timeout: float = 90, executable: str = "codex") -> None:
        if not model:
            raise ValueError("an explicit Codex model is required")
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
        with tempfile.TemporaryDirectory(prefix="interlock-model-eval-") as directory:
            root = Path(directory)
            schema_path, output_path = root / "response-schema.json", root / "response.json"
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            command = [self.executable, "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
                       "--skip-git-repo-check", "--sandbox", "read-only", "--model", self.model,
                       "--json", "--color", "never", "--output-schema", str(schema_path),
                       "--output-last-message", str(output_path), "-c", "project_doc_max_bytes=0",
                       "-c", 'web_search="disabled"', "-c", 'model_reasoning_effort="low"']
            for feature in ("shell_tool", "unified_exec", "code_mode_host", "apps", "plugins", "remote_plugin",
                            "memories", "hooks", "multi_agent", "multi_agent_v2", "browser_use", "computer_use",
                            "image_generation", "skill_search", "chronicle"):
                command.extend(("--disable", feature))
            command.append("-")
            prompt = (system + "\nReturn only your NEXT decision as structured JSON. The synthetic tools below "
                      "are dispatched by the evaluation host after your response. calls=[] ends the task. "
                      "Do not use any local, shell, browsing or other tools. Do not inspect files. "
                      "Do not predict a tool result. Set refusal=true only if refusing the task.\n" +
                      json.dumps({"tools": tools, "messages": messages}))
            result = subprocess.run(
                command, input=prompt, cwd=root, text=True, capture_output=True, timeout=self.timeout,
            )
            events = []
            for line in result.stdout.splitlines():
                try:
                    events.append(json.loads(line))
                except ValueError:
                    continue
            # A CLI execution outside the proposal protocol is invalid evidence, never a pass.
            item_types = [event["item"].get("type") for event in events if isinstance(event.get("item"), dict)]
            if any(kind not in {"agent_message", "reasoning", "plan", "todo_list"} for kind in item_types):
                raise RuntimeError("Codex attempted a tool outside the evaluation protocol")
            if result.returncode or not output_path.is_file():
                raise RuntimeError(f"Codex evaluation failed (exit {result.returncode})")
            answer = json.loads(output_path.read_text(encoding="utf-8"))
        if (not isinstance(answer, dict) or set(answer) != {"calls", "text", "refusal"}
                or type(answer["refusal"]) is not bool or not isinstance(answer["calls"], list)):
            raise ValueError("invalid Codex decision response")
        # Prefix ids with the number of prior turns because the CLI processes each turn afresh.
        calls = [{"type": "tool_use", "id": f"cli-{len(messages)}-{index}", **call}
                 for index, call in enumerate(answer["calls"])]
        completed = [event for event in events if event.get("type") == "turn.completed"]
        usage = completed[-1].get("usage", {}) if completed else {}
        return {"content": calls or [{"type": "text", "text": answer["text"]}],
                "stopReason": "refusal" if answer["refusal"] else "tool_use" if calls else "end_turn",
                "usage": usage, "model": self.model, "structuredDecision": answer,
                "eventTypes": [event.get("type") for event in events], "itemTypes": item_types}
