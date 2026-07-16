from __future__ import annotations

import http.client
import json
import threading
import unittest
from pathlib import Path

from agent_interlock import (
    ArchitectureCompiler,
    ArchitectureGraph,
    MCPHTTPError,
    MCPHTTPGatewayConfig,
    MCPHTTPPrincipal,
    MCPHTTPRequest,
    MCPHTTPSessionExpired,
    MCPHTTPStatusError,
    MCPInvocationContext,
    MCPServerProfile,
    MCPStreamableHTTPClient,
    MCPStreamableHTTPClientConfig,
    MCPStreamableHTTPGatewayCarrier,
    MCPToolGateway,
    MCPTransportAdapter,
    SideEffect,
    create_mcp_http_server,
)
from mcp_http_fixture import AdversarialMCPHTTPServer, tool_definition


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "examples" / "secure_multi_agent_architecture.json"


def configured_client(server: AdversarialMCPHTTPServer, **overrides):
    config = MCPStreamableHTTPClientConfig(
        endpoint=server.endpoint,
        allow_loopback_http=True,
        **overrides,
    )
    client = MCPStreamableHTTPClient(
        config,
        authorization_provider=lambda: "Bearer downstream-only",
    )
    client.initialize(client_name="interlock-test", client_version="1.0.0")
    return client


def compiled_architecture(digest: str):
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    tool = next(item for item in manifest["spec"]["nodes"] if item["id"] == "tool.send-email")
    tool["definitionDigest"] = digest
    edge = next(item for item in manifest["spec"]["edges"] if item["relationshipId"] == "REL-05")
    edge["policy"]["externalWriteRequiresApproval"] = False
    return ArchitectureCompiler().compile(ArchitectureGraph.from_dict(manifest))


def bound_http_stack(server: AdversarialMCPHTTPServer):
    client = configured_client(server)
    gateway = MCPToolGateway()
    adapter = MCPTransportAdapter(
        gateway,
        MCPServerProfile(
            tenant_id="tenant-a",
            server_id="tenant-a/prod/trusted-mail",
            endpoint=server.endpoint,
            publisher="platform-team",
            artifact_digest="sha256:" + "a" * 64,
        ),
        client.call,
    )
    client.set_server_message_handler(adapter.handle_server_message)
    hidden = adapter.handle_client_message(
        {"jsonrpc": "2.0", "id": "discover", "method": "tools/list", "params": {}}
    )
    if hidden["result"]["tools"]:
        raise AssertionError("unapproved Tool was exposed")
    revision = adapter.observed_revisions[0]
    adapter.bind_compiled_architecture(
        compiled_architecture(revision.canonical_digest),
        tool_bindings={"send_email": "tool.send-email"},
        approver="security-reviewer",
    )
    return client, gateway, adapter


def principal() -> MCPHTTPPrincipal:
    return MCPHTTPPrincipal("tenant-a", "agent.support", "host-user-1")


def invocation_context(_principal, message):
    arguments = message.get("params", {}).get("arguments", {})
    destination = arguments.get("to", "")
    return MCPInvocationContext(
        tenant_id="tenant-a",
        source_actor_id="agent.support",
        purpose="SUPPORT_REPLY",
        destinations=(destination,) if destination else (),
        estimated_side_effect=SideEffect.EXTERNAL_WRITE,
        trace_id="trace-http-carrier",
    )


def make_carrier(adapter, *, resolver=invocation_context):
    return MCPStreamableHTTPGatewayCarrier(
        adapter,
        MCPHTTPGatewayConfig(
            allowed_origins=frozenset({"https://app.example"}),
            allowed_hosts=frozenset({"127.0.0.1"}),
            require_origin=True,
        ),
        authenticator=lambda value: principal() if value == "Bearer inbound-host" else None,
        context_resolver=resolver,
    )


def host_headers(*, protocol: bool = True):
    headers = {
        "Host": "127.0.0.1",
        "Authorization": "Bearer inbound-host",
        "Origin": "https://app.example",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if protocol:
        headers["MCP-Protocol-Version"] = "2025-11-25"
    return headers


def http_post(port: int, message, *, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    connection.request("POST", "/mcp", body=payload, headers=headers or host_headers())
    response = connection.getresponse()
    body = response.read()
    result = (response.status, dict(response.headers), json.loads(body) if body else None)
    connection.close()
    return result


def initialize_host(port: int):
    initialize = {
        "jsonrpc": "2.0",
        "id": "host-init",
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "test-host", "version": "1.0.0"},
        },
    }
    status, _, response = http_post(port, initialize, headers=host_headers(protocol=False))
    if status != 200 or response["result"]["protocolVersion"] != "2025-11-25":
        raise AssertionError("host initialization failed")
    status, _, _ = http_post(
        port,
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    )
    if status != 202:
        raise AssertionError("host initialized notification failed")


class StreamableHTTPClientTests(unittest.TestCase):
    def test_initialize_negotiates_version_and_binds_secure_session(self):
        with AdversarialMCPHTTPServer() as server:
            client = configured_client(server)
            response = client.call(
                {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
            )
            self.assertEqual(client.session_id, server.session_id)
            self.assertEqual(response["result"]["tools"][0]["name"], "send_email")
            self.assertEqual(server.received_sessions[0], None)
            self.assertTrue(all(item == "2025-11-25" for item in server.received_protocol_versions[1:]))
            self.assertTrue(all(item == "Bearer downstream-only" for item in server.received_authorizations))

    def test_sse_response_dispatches_notification_and_returns_matching_response(self):
        with AdversarialMCPHTTPServer() as server:
            notifications = []
            client = configured_client(server)
            client.set_server_message_handler(notifications.append)
            server.response_mode = "sse"
            server.emit_list_changed = True
            response = client.call(
                {"jsonrpc": "2.0", "id": "sse-list", "method": "tools/list", "params": {}}
            )
            self.assertEqual(response["id"], "sse-list")
            self.assertEqual(notifications[0]["method"], "notifications/tools/list_changed")

    def test_get_sse_listener_tracks_notification_event(self):
        with AdversarialMCPHTTPServer() as server:
            notifications = []
            client = configured_client(server)
            client.set_server_message_handler(notifications.append)
            count = client.listen_once()
            self.assertEqual(count, 1)
            self.assertEqual(notifications[0]["method"], "notifications/tools/list_changed")

    def test_redirect_is_not_followed(self):
        with AdversarialMCPHTTPServer() as server:
            client = configured_client(server)
            server.redirect_location = "http://127.0.0.1:9/steal"
            with self.assertRaises(MCPHTTPStatusError) as raised:
                client.call({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
            self.assertEqual(raised.exception.status, 302)

    def test_oversized_response_fails_closed(self):
        with AdversarialMCPHTTPServer() as server:
            client = configured_client(server, max_response_bytes=512)
            server.oversized_response_bytes = 513
            with self.assertRaises(MCPHTTPError) as raised:
                client.call({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
            self.assertEqual(raised.exception.reason_code, "MCP-HTTP-RESPONSE-TOO-LARGE")

    def test_timeout_does_not_retry_mutating_request(self):
        with AdversarialMCPHTTPServer() as server:
            client = configured_client(server, timeout_seconds=0.05)
            server.response_delay_seconds = 0.2
            with self.assertRaises(MCPHTTPError) as raised:
                client.call(
                    {
                        "jsonrpc": "2.0",
                        "id": "slow-call",
                        "method": "tools/call",
                        "params": {"name": "send_email", "arguments": {}},
                    }
                )
            self.assertEqual(raised.exception.reason_code, "MCP-HTTP-TIMEOUT")
            self.assertEqual(server.call_attempt_count, 1)

    def test_session_404_requires_reinitialization_without_replay(self):
        with AdversarialMCPHTTPServer() as server:
            client = configured_client(server)
            server.expire_session = True
            with self.assertRaises(MCPHTTPSessionExpired):
                client.call({"jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {}})
            self.assertFalse(client.initialized)
            self.assertIsNone(client.session_id)

    def test_endpoint_requires_https_except_explicit_loopback_test_profile(self):
        with self.assertRaises(ValueError):
            MCPStreamableHTTPClientConfig(endpoint="http://mcp.example.com/mcp")
        with self.assertRaises(ValueError):
            MCPStreamableHTTPClientConfig(
                endpoint="http://127.0.0.1/mcp",
                allow_loopback_http=True,
            )


class StreamableHTTPGatewayIntegrationTests(unittest.TestCase):
    def test_actual_http_gateway_enforces_policy_without_token_passthrough(self):
        with AdversarialMCPHTTPServer() as downstream:
            client, gateway, adapter = bound_http_stack(downstream)
            carrier = make_carrier(adapter)
            server = create_mcp_http_server(carrier)
            thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
            thread.start()
            try:
                initialize_host(server.server_port)
                request = {
                    "jsonrpc": "2.0",
                    "id": "host-call",
                    "method": "tools/call",
                    "params": {
                        "name": "send_email",
                        "arguments": {"to": "a@customer.example", "body": "hello"},
                    },
                }
                status, _, response = http_post(server.server_port, request)
                self.assertEqual(status, 200)
                self.assertEqual(response["result"]["structuredContent"], {"status": "sent"})
                self.assertEqual(response["result"]["_meta"]["interlock"]["decision"], "ALLOW")
                self.assertEqual(downstream.call_count, 1)
                self.assertNotIn("Bearer inbound-host", downstream.received_authorizations)
                self.assertTrue(
                    all(item == "Bearer downstream-only" for item in downstream.received_authorizations)
                )
                self.assertGreaterEqual(len(gateway.ledger.all()), 8)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                client.close_session()

    def test_actual_http_drift_is_blocked_before_downstream_call(self):
        with AdversarialMCPHTTPServer() as downstream:
            client, _, adapter = bound_http_stack(downstream)
            carrier = make_carrier(adapter)
            server = create_mcp_http_server(carrier)
            thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
            thread.start()
            try:
                initialize_host(server.server_port)
                downstream.tools = [tool_definition("Changed after architecture approval.")]
                request = {
                    "jsonrpc": "2.0",
                    "id": "drift-call",
                    "method": "tools/call",
                    "params": {
                        "name": "send_email",
                        "arguments": {"to": "a@customer.example", "body": "hello"},
                    },
                }
                status, _, response = http_post(server.server_port, request)
                self.assertEqual(status, 200)
                self.assertEqual(response["error"]["code"], -32001)
                self.assertIn("L1-M2-DEFINITION-DRIFT", response["error"]["data"]["reasonCodes"])
                self.assertEqual(downstream.call_count, 0)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
                client.close_session()

    def test_origin_auth_accept_protocol_and_lifecycle_fail_closed(self):
        with AdversarialMCPHTTPServer() as downstream:
            client, _, adapter = bound_http_stack(downstream)
            carrier = make_carrier(adapter)
            base_message = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}

            before_initialize = carrier.handle(
                MCPHTTPRequest("POST", "/mcp", host_headers(), json.dumps(base_message).encode())
            )
            self.assertEqual(before_initialize.status, 400)
            self.assertEqual(
                json.loads(before_initialize.body)["error"]["data"]["reasonCode"],
                "MCP-LIFECYCLE-NOT-INITIALIZED",
            )

            invalid_origin = carrier.handle(
                MCPHTTPRequest(
                    "POST",
                    "/mcp",
                    {**host_headers(), "Origin": "https://evil.example"},
                    json.dumps(base_message).encode(),
                )
            )
            self.assertEqual(invalid_origin.status, 403)

            invalid_auth = carrier.handle(
                MCPHTTPRequest(
                    "POST",
                    "/mcp",
                    {**host_headers(), "Authorization": "Bearer attacker"},
                    json.dumps(base_message).encode(),
                )
            )
            self.assertEqual(invalid_auth.status, 401)
            self.assertEqual(invalid_auth.headers["WWW-Authenticate"], "Bearer")

            missing_accept = carrier.handle(
                MCPHTTPRequest(
                    "POST",
                    "/mcp",
                    {**host_headers(), "Accept": "application/json"},
                    json.dumps(base_message).encode(),
                )
            )
            self.assertEqual(missing_accept.status, 406)

            wrong_protocol = carrier.handle(
                MCPHTTPRequest(
                    "POST",
                    "/mcp",
                    {**host_headers(), "MCP-Protocol-Version": "2025-06-18"},
                    json.dumps(base_message).encode(),
                )
            )
            self.assertEqual(wrong_protocol.status, 400)
            client.close_session()

    def test_context_must_match_authenticated_principal(self):
        with AdversarialMCPHTTPServer() as downstream:
            client, _, adapter = bound_http_stack(downstream)

            def mismatched_context(_principal, _message):
                return MCPInvocationContext("tenant-b", "agent.attacker", "SUPPORT_REPLY")

            carrier = make_carrier(adapter, resolver=mismatched_context)
            initialize = {
                "jsonrpc": "2.0",
                "id": "init",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "host", "version": "1"},
                },
            }
            carrier.handle(
                MCPHTTPRequest(
                    "POST", "/mcp", host_headers(protocol=False), json.dumps(initialize).encode()
                )
            )
            carrier.handle(
                MCPHTTPRequest(
                    "POST",
                    "/mcp",
                    host_headers(),
                    json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode(),
                )
            )
            call = {
                "jsonrpc": "2.0",
                "id": "mismatch",
                "method": "tools/call",
                "params": {"name": "send_email", "arguments": {}},
            }
            response = carrier.handle(
                MCPHTTPRequest("POST", "/mcp", host_headers(), json.dumps(call).encode())
            )
            self.assertEqual(
                json.loads(response.body)["error"]["data"]["reasonCode"],
                "INTERLOCK-PRINCIPAL-CONTEXT-MISMATCH",
            )
            self.assertEqual(downstream.call_count, 0)
            client.close_session()

    def test_jsonrpc_shape_and_endpoint_query_are_rejected(self):
        with AdversarialMCPHTTPServer() as downstream:
            client, _, adapter = bound_http_stack(downstream)
            carrier = make_carrier(adapter)
            malformed = {"jsonrpc": "2.0", "id": True, "method": "tools/list", "params": {}}
            response = carrier.handle(
                MCPHTTPRequest("POST", "/mcp", host_headers(), json.dumps(malformed).encode())
            )
            self.assertEqual(response.status, 400)
            self.assertEqual(
                json.loads(response.body)["error"]["data"]["reasonCode"],
                "MCP-JSONRPC-ID-INVALID",
            )
            query = carrier.handle(
                MCPHTTPRequest("POST", "/mcp?debug=1", host_headers(), b"{}")
            )
            self.assertEqual(query.status, 404)
            client.close_session()


if __name__ == "__main__":
    unittest.main()
