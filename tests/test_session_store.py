from __future__ import annotations

import json
import unittest

from agent_interlock import (
    InMemorySessionStore,
    MCPHTTPGatewayConfig,
    MCPHTTPPrincipal,
    MCPHTTPRequest,
    MCPStreamableHTTPGatewayCarrier,
)

PRINCIPAL = MCPHTTPPrincipal("tenant-a", "agent.support", "host-user-1")
LIST_CHANGED = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
MESSAGE_NOTE = {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info"}}


class _StubAdapter:
    def handle_client_message(self, message, *, context=None):
        return {"jsonrpc": "2.0", "id": message.get("id"), "result": {"tools": []}}


def make_carrier(store):
    return MCPStreamableHTTPGatewayCarrier(
        _StubAdapter(),
        MCPHTTPGatewayConfig(
            allowed_origins=frozenset({"https://app.example"}),
            allowed_hosts=frozenset({"127.0.0.1"}),
            require_origin=True,
        ),
        authenticator=lambda value: PRINCIPAL if value == "Bearer inbound-host" else None,
        context_resolver=lambda principal, message: None,
        session_store=store,
    )


def headers(*, protocol=True, session_id=None, last_event_id=None):
    value = {
        "Host": "127.0.0.1",
        "Authorization": "Bearer inbound-host",
        "Origin": "https://app.example",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if protocol:
        value["MCP-Protocol-Version"] = "2025-11-25"
    if session_id:
        value["MCP-Session-Id"] = session_id
    if last_event_id is not None:
        value["Last-Event-ID"] = str(last_event_id)
    return value


def post(carrier, message, *, protocol=True, session_id=None):
    return carrier.handle(
        MCPHTTPRequest(
            "POST",
            "/mcp",
            headers(protocol=protocol, session_id=session_id),
            json.dumps(message).encode(),
        )
    )


def get(carrier, *, session_id=None, last_event_id=None):
    return carrier.handle(
        MCPHTTPRequest("GET", "/mcp", headers(session_id=session_id, last_event_id=last_event_id), b"")
    )


def open_session(carrier) -> str:
    init = {
        "jsonrpc": "2.0",
        "id": "init-1",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "1"},
        },
    }
    response = post(carrier, init, protocol=False)
    assert response.status == 200, response.status
    session_id = response.headers["MCP-Session-Id"]
    ack = post(carrier, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_id=session_id)
    assert ack.status == 202, ack.status
    return session_id


class SessionLifecycleTests(unittest.TestCase):
    def test_initialize_issues_session_and_ready_gates_tools(self):
        carrier = make_carrier(InMemorySessionStore())
        session_id = open_session(carrier)
        self.assertTrue(session_id)
        listed = post(
            carrier,
            {"jsonrpc": "2.0", "id": "tl", "method": "tools/list", "params": {}},
            session_id=session_id,
        )
        self.assertEqual(listed.status, 200)

    def test_tools_call_without_session_is_not_ready(self):
        carrier = make_carrier(InMemorySessionStore())
        open_session(carrier)
        listed = post(carrier, {"jsonrpc": "2.0", "id": "tl", "method": "tools/list", "params": {}})
        body = json.loads(listed.body)
        self.assertEqual(body["error"]["data"]["reasonCode"], "MCP-LIFECYCLE-NOT-INITIALIZED")

    def test_initialized_without_matching_session_is_rejected(self):
        carrier = make_carrier(InMemorySessionStore())
        # notifications/initialized referencing an unknown session id
        ack = post(
            carrier,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            session_id="not-a-real-session",
        )
        body = json.loads(ack.body)
        self.assertEqual(body["error"]["data"]["reasonCode"], "MCP-LIFECYCLE-ORDER-INVALID")


class ResumableSSETests(unittest.TestCase):
    def test_get_replays_buffered_notifications(self):
        carrier = make_carrier(InMemorySessionStore())
        session_id = open_session(carrier)
        self.assertEqual(carrier.enqueue_server_notification(session_id, PRINCIPAL, LIST_CHANGED), 1)
        self.assertEqual(carrier.enqueue_server_notification(session_id, PRINCIPAL, MESSAGE_NOTE), 2)
        response = get(carrier, session_id=session_id)
        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers["Content-Type"], "text/event-stream")
        text = response.body.decode()
        self.assertIn("id: 1", text)
        self.assertIn("id: 2", text)
        self.assertIn("notifications/tools/list_changed", text)

    def test_last_event_id_resumes_after_the_cursor(self):
        carrier = make_carrier(InMemorySessionStore())
        session_id = open_session(carrier)
        carrier.enqueue_server_notification(session_id, PRINCIPAL, LIST_CHANGED)
        carrier.enqueue_server_notification(session_id, PRINCIPAL, MESSAGE_NOTE)
        response = get(carrier, session_id=session_id, last_event_id=1)
        text = response.body.decode()
        self.assertNotIn("id: 1", text)
        self.assertIn("id: 2", text)
        self.assertIn("notifications/message", text)

    def test_server_push_must_be_a_notification(self):
        carrier = make_carrier(InMemorySessionStore())
        session_id = open_session(carrier)
        from agent_interlock import MCPHTTPError

        with self.assertRaises(MCPHTTPError):
            carrier.enqueue_server_notification(
                session_id, PRINCIPAL, {"jsonrpc": "2.0", "id": "x", "method": "server/request"}
            )

    def test_delete_removes_the_session(self):
        carrier = make_carrier(InMemorySessionStore())
        session_id = open_session(carrier)
        deleted = carrier.handle(MCPHTTPRequest("DELETE", "/mcp", headers(session_id=session_id), b""))
        self.assertEqual(deleted.status, 200)
        self.assertEqual(get(carrier, session_id=session_id).status, 404)


class MultiInstanceTests(unittest.TestCase):
    def test_session_initialized_on_one_carrier_is_usable_on_another(self):
        store = InMemorySessionStore()
        carrier_a = make_carrier(store)
        carrier_b = make_carrier(store)
        session_id = open_session(carrier_a)
        # Server push buffered on A is replayable from B (shared store).
        carrier_a.enqueue_server_notification(session_id, PRINCIPAL, LIST_CHANGED)
        replay = get(carrier_b, session_id=session_id)
        self.assertEqual(replay.status, 200)
        self.assertIn("notifications/tools/list_changed", replay.body.decode())
        # A ready session on the shared store also serves tools on B.
        listed = post(
            carrier_b,
            {"jsonrpc": "2.0", "id": "tl", "method": "tools/list", "params": {}},
            session_id=session_id,
        )
        self.assertEqual(listed.status, 200)


class BackwardCompatibilityTests(unittest.TestCase):
    def test_without_session_store_get_is_405(self):
        carrier = MCPStreamableHTTPGatewayCarrier(
            _StubAdapter(),
            MCPHTTPGatewayConfig(
                allowed_origins=frozenset({"https://app.example"}),
                allowed_hosts=frozenset({"127.0.0.1"}),
                require_origin=True,
            ),
            authenticator=lambda value: PRINCIPAL if value == "Bearer inbound-host" else None,
            context_resolver=lambda principal, message: None,
        )
        self.assertEqual(get(carrier, session_id="anything").status, 405)


if __name__ == "__main__":
    unittest.main()
