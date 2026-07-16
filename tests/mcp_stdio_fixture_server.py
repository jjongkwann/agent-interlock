from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


MODE = sys.argv[1] if len(sys.argv) > 1 else "normal"
MARKER = Path(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] != "-" else None
CHILD_PID = Path(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] != "-" else None


def send(value: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
    sys.stdout.flush()


if MODE == "startup-write" and MARKER is not None:
    MARKER.write_text("process-started", encoding="utf-8")

if MODE == "noise":
    sys.stdout.write("not-an-mcp-message\n")
    sys.stdout.flush()

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if method == "initialize":
        sys.stderr.write("fixture log api_key=abcd1234secretvalue\n")
        sys.stderr.flush()
        if MODE == "oversized":
            send(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "result": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "padding": "x" * 8192,
                    },
                }
            )
            continue
        send(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "stdio-fixture", "version": "1.0.0"},
                },
            }
        )
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        response = {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "result": {
                "tools": [
                    {
                        "name": "echo",
                        "description": "Return an approved value.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"value": {"type": "string"}},
                            "additionalProperties": False,
                        },
                        "outputSchema": {
                            "type": "object",
                            "required": ["value"],
                            "properties": {"value": {"type": "string"}},
                            "additionalProperties": False,
                        },
                    }
                ]
            },
        }
        if MODE == "notification":
            send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        send(response)
    elif method == "tools/call":
        if MARKER is not None:
            with MARKER.open("a", encoding="utf-8") as stream:
                stream.write("call\n")
        if MODE == "hang":
            time.sleep(60)
            continue
        if MODE == "child-hang":
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if CHILD_PID is not None:
                CHILD_PID.write_text(str(child.pid), encoding="ascii")
            time.sleep(60)
            continue
        if MODE == "server-request":
            send({"jsonrpc": "2.0", "id": "server-1", "method": "roots/list", "params": {}})
            continue
        arguments = message.get("params", {}).get("arguments", {})
        if MODE == "environment":
            value = "present" if "INTERLOCK_PARENT_SECRET" in os.environ else "absent"
        else:
            value = str(arguments.get("value", ""))
        send(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "result": {
                    "content": [{"type": "text", "text": value}],
                    "structuredContent": {"value": value},
                    "isError": False,
                },
            }
        )
    else:
        send(
            {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32601, "message": "unknown method"},
            }
        )
