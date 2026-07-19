"""Local adversarial MCP Streamable HTTP server used by integration tests."""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from http_test_server import QuietThreadingHTTPServer

INPUT_SCHEMA = {
    "type": "object",
    "required": ["to", "body"],
    "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
    "additionalProperties": False,
}
OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["status"],
    "properties": {"status": {"type": "string"}},
    "additionalProperties": False,
}


def tool_definition(
    description: str = "Send an approved customer support reply.",
) -> dict[str, Any]:
    return {
        "name": "send_email",
        "title": "Send email",
        "description": description,
        "inputSchema": INPUT_SCHEMA,
        "outputSchema": OUTPUT_SCHEMA,
        "annotations": {"destructiveHint": False},
    }


class AdversarialMCPHTTPServer:
    def __init__(self) -> None:
        self.tools = [tool_definition()]
        self.result: dict[str, Any] = {
            "content": [{"type": "text", "text": '{"status":"sent"}'}],
            "structuredContent": {"status": "sent"},
            "isError": False,
        }
        self.expected_authorization = "Bearer downstream-only"
        self.session_id = "test-session-7f82b4"
        self.response_mode = "json"
        self.redirect_location: str | None = None
        self.oversized_response_bytes = 0
        self.response_delay_seconds = 0.0
        self.expire_session = False
        self.emit_list_changed = False
        self.call_count = 0
        self.call_attempt_count = 0
        self.list_count = 0
        self.received_authorizations: list[str | None] = []
        self.received_protocol_versions: list[str | None] = []
        self.received_sessions: list[str | None] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def endpoint(self) -> str:
        if self._server is None:
            raise RuntimeError("fixture is not running")
        return f"http://127.0.0.1:{self._server.server_port}/mcp"

    def start(self) -> AdversarialMCPHTTPServer:
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                headers = {key.casefold(): value for key, value in self.headers.items()}
                fixture.received_authorizations.append(headers.get("authorization"))
                fixture.received_protocol_versions.append(headers.get("mcp-protocol-version"))
                fixture.received_sessions.append(headers.get("mcp-session-id"))
                if self.path != "/mcp":
                    self._write(404)
                    return
                if headers.get("authorization") != fixture.expected_authorization:
                    self._write(401, headers={"WWW-Authenticate": 'Bearer resource_metadata="/metadata"'})
                    return
                try:
                    message = json.loads(body.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self._write(400)
                    return
                method = message.get("method")
                if method == "tools/call":
                    fixture.call_attempt_count += 1
                if fixture.redirect_location and method != "initialize":
                    self._write(302, headers={"Location": fixture.redirect_location})
                    return
                if method == "initialize":
                    response = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "result": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": {"tools": {"listChanged": True}},
                            "serverInfo": {"name": "adversarial-fixture", "version": "1.0.0"},
                        },
                    }
                    self._json(response, headers={"MCP-Session-Id": fixture.session_id})
                    return
                if fixture.expire_session:
                    self._write(404)
                    return
                if fixture.response_delay_seconds:
                    time.sleep(fixture.response_delay_seconds)
                if headers.get("mcp-protocol-version") != "2025-11-25":
                    self._write(400)
                    return
                if headers.get("mcp-session-id") != fixture.session_id:
                    self._write(400)
                    return
                if method == "notifications/initialized":
                    self._write(202)
                    return
                if fixture.oversized_response_bytes:
                    payload = b"x" * fixture.oversized_response_bytes
                    self._write(200, payload, {"Content-Type": "application/json"})
                    return
                if method == "tools/list":
                    fixture.list_count += 1
                    response = {
                        "jsonrpc": "2.0",
                        "id": message.get("id"),
                        "result": {"tools": fixture.tools},
                    }
                    self._mcp_response(response)
                    return
                if method == "tools/call":
                    fixture.call_count += 1
                    response = {"jsonrpc": "2.0", "id": message.get("id"), "result": fixture.result}
                    self._mcp_response(response)
                    return
                response = {
                    "jsonrpc": "2.0",
                    "id": message.get("id"),
                    "error": {"code": -32601, "message": "unknown method"},
                }
                self._json(response)

            def do_GET(self) -> None:
                headers = {key.casefold(): value for key, value in self.headers.items()}
                fixture.received_authorizations.append(headers.get("authorization"))
                fixture.received_protocol_versions.append(headers.get("mcp-protocol-version"))
                fixture.received_sessions.append(headers.get("mcp-session-id"))
                if (
                    headers.get("authorization") != fixture.expected_authorization
                    or headers.get("mcp-protocol-version") != "2025-11-25"
                    or headers.get("mcp-session-id") != fixture.session_id
                ):
                    self._write(401)
                    return
                notification = {
                    "jsonrpc": "2.0",
                    "method": "notifications/tools/list_changed",
                }
                payload = self._sse_payload([notification])
                self._write(200, payload, {"Content-Type": "text/event-stream"})

            def do_DELETE(self) -> None:
                headers = {key.casefold(): value for key, value in self.headers.items()}
                if headers.get("mcp-session-id") != fixture.session_id:
                    self._write(400)
                    return
                self._write(204)

            def _mcp_response(self, response: dict[str, Any]) -> None:
                if fixture.response_mode == "sse":
                    events = []
                    if fixture.emit_list_changed:
                        events.append({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
                    events.append(response)
                    self._write(200, self._sse_payload(events), {"Content-Type": "text/event-stream"})
                    return
                self._json(response)

            @staticmethod
            def _sse_payload(events: list[dict[str, Any]]) -> bytes:
                chunks = ["id: prime\ndata:\n\n"]
                for index, event in enumerate(events, start=1):
                    data = json.dumps(event, separators=(",", ":"))
                    chunks.append(f"id: event-{index}\ndata: {data}\n\n")
                return "".join(chunks).encode("utf-8")

            def _json(self, value: dict[str, Any], headers: dict[str, str] | None = None) -> None:
                payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
                self._write(200, payload, {"Content-Type": "application/json", **(headers or {})})

            def _write(
                self,
                status: int,
                payload: bytes = b"",
                headers: dict[str, str] | None = None,
            ) -> None:
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if payload:
                    try:
                        self.wfile.write(payload)
                    except (BrokenPipeError, ConnectionResetError):
                        return

            def log_message(self, fmt: str, *args: Any) -> None:
                return

        self._server = QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=0.01),
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None

    def __enter__(self) -> AdversarialMCPHTTPServer:
        return self.start()

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        self.stop()
