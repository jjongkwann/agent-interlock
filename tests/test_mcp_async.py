"""Server-initiated request router + async task registry (cancellation/replay)."""

from __future__ import annotations

import unittest

from agent_interlock import (
    AsyncTaskRegistry,
    MCPAsyncError,
    ServerRequestRouter,
    TaskState,
)

PRINCIPAL = ("tenant-a", "agent-1", "subject-1")
OTHER = ("tenant-a", "agent-2", "subject-2")


def request(method, request_id="r1", params=None):
    msg = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


class ServerRequestRouterTests(unittest.TestCase):
    def test_allowed_method_is_handled(self):
        router = ServerRequestRouter({"roots/list": lambda params: {"roots": []}})
        response = router.handle(request("roots/list"))
        self.assertEqual(response["result"], {"roots": []})
        self.assertEqual(response["id"], "r1")
        self.assertEqual(router.audit_log, (("roots/list", "handled"),))

    def test_unknown_method_is_denied_fail_closed(self):
        router = ServerRequestRouter({"roots/list": lambda params: {"roots": []}})
        response = router.handle(request("sampling/createMessage"))
        self.assertEqual(response["error"]["code"], -32601)
        self.assertIn("not allowed", response["error"]["message"])
        self.assertEqual(router.audit_log, (("sampling/createMessage", "denied"),))

    def test_empty_router_denies_everything(self):
        router = ServerRequestRouter()
        self.assertEqual(router.allowed_methods, frozenset())
        self.assertEqual(router.handle(request("anything"))["error"]["code"], -32601)

    def test_invalid_request_shape_is_rejected(self):
        router = ServerRequestRouter({"m": lambda p: {}})
        bad = {"jsonrpc": "2.0", "method": "m"}  # no id
        self.assertEqual(router.handle(bad)["error"]["code"], -32600)

    def test_throwing_handler_is_contained(self):
        def boom(params):
            raise RuntimeError("handler blew up")

        router = ServerRequestRouter({"m": boom})
        response = router.handle(request("m"))
        self.assertEqual(response["error"]["code"], -32603)
        self.assertEqual(router.audit_log, (("m", "error"),))

    def test_handler_must_return_a_mapping(self):
        router = ServerRequestRouter({"m": lambda p: "not a mapping"})
        self.assertEqual(router.handle(request("m"))["error"]["code"], -32603)

    def test_allow_registers_a_method(self):
        router = ServerRequestRouter()
        router.allow("roots/list", lambda p: {"roots": ["/x"]})
        self.assertEqual(router.handle(request("roots/list"))["result"], {"roots": ["/x"]})


class AsyncTaskRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = AsyncTaskRegistry()

    def test_lifecycle_pending_running_completed_consume(self):
        self.registry.create("t1", PRINCIPAL)
        self.assertEqual(self.registry.state("t1", PRINCIPAL), TaskState.PENDING)
        self.registry.start("t1", PRINCIPAL)
        self.assertEqual(self.registry.state("t1", PRINCIPAL), TaskState.RUNNING)
        self.registry.complete("t1", PRINCIPAL, {"value": 42})
        self.assertEqual(self.registry.consume("t1", PRINCIPAL), {"value": 42})

    def test_result_consume_is_one_time_replay_refused(self):
        self.registry.create("t1", PRINCIPAL)
        self.registry.complete("t1", PRINCIPAL, {"value": 1})
        self.registry.consume("t1", PRINCIPAL)
        with self.assertRaises(MCPAsyncError) as raised:
            self.registry.consume("t1", PRINCIPAL)
        self.assertEqual(raised.exception.reason_code, "MCP-TASK-RESULT-REPLAY")

    def test_cancel_is_idempotent(self):
        self.registry.create("t1", PRINCIPAL)
        self.registry.start("t1", PRINCIPAL)
        self.assertTrue(self.registry.cancel("t1", PRINCIPAL))
        self.assertEqual(self.registry.state("t1", PRINCIPAL), TaskState.CANCELLED)
        self.assertFalse(self.registry.cancel("t1", PRINCIPAL))  # already terminal

    def test_cannot_complete_a_cancelled_task(self):
        self.registry.create("t1", PRINCIPAL)
        self.registry.cancel("t1", PRINCIPAL)
        with self.assertRaises(MCPAsyncError) as raised:
            self.registry.complete("t1", PRINCIPAL, {"value": 1})
        self.assertEqual(raised.exception.reason_code, "MCP-TASK-STATE-INVALID")

    def test_consume_before_completion_is_refused(self):
        self.registry.create("t1", PRINCIPAL)
        self.registry.start("t1", PRINCIPAL)
        with self.assertRaises(MCPAsyncError) as raised:
            self.registry.consume("t1", PRINCIPAL)
        self.assertEqual(raised.exception.reason_code, "MCP-TASK-NOT-COMPLETED")

    def test_principal_binding_hides_other_principals_task(self):
        self.registry.create("t1", PRINCIPAL)
        self.registry.complete("t1", PRINCIPAL, {"value": 1})
        self.assertIsNone(self.registry.state("t1", OTHER))
        with self.assertRaises(MCPAsyncError):
            self.registry.consume("t1", OTHER)

    def test_duplicate_task_id_is_rejected(self):
        self.registry.create("t1", PRINCIPAL)
        with self.assertRaises(MCPAsyncError) as raised:
            self.registry.create("t1", PRINCIPAL)
        self.assertEqual(raised.exception.reason_code, "MCP-TASK-DUPLICATE")

    def test_capacity_bound_is_enforced(self):
        registry = AsyncTaskRegistry(max_tasks=1)
        registry.create("t1", PRINCIPAL)
        with self.assertRaises(MCPAsyncError) as raised:
            registry.create("t2", PRINCIPAL)
        self.assertEqual(raised.exception.reason_code, "MCP-TASK-CAPACITY")

    def test_failed_task_has_no_consumable_result(self):
        self.registry.create("t1", PRINCIPAL)
        self.registry.fail("t1", PRINCIPAL, {"code": "boom"})
        self.assertEqual(self.registry.state("t1", PRINCIPAL), TaskState.FAILED)
        with self.assertRaises(MCPAsyncError):
            self.registry.consume("t1", PRINCIPAL)


class HTTPClientServerRequestWiringTests(unittest.TestCase):
    """The downstream HTTP client routes server-initiated requests via the
    router when configured, and stays fail-closed otherwise."""

    def _client(self):
        from agent_interlock import MCPStreamableHTTPClient, MCPStreamableHTTPClientConfig

        return MCPStreamableHTTPClient(MCPStreamableHTTPClientConfig(endpoint="https://mcp.example.com/rpc"))

    def test_without_router_server_request_is_rejected(self):
        from agent_interlock import MCPHTTPError

        client = self._client()
        server_request = {"jsonrpc": "2.0", "id": "s1", "method": "roots/list"}
        with self.assertRaises(MCPHTTPError) as raised:
            client._dispatch_server_messages((server_request,), expected_id=None)
        self.assertEqual(raised.exception.reason_code, "MCP-SSE-SERVER-REQUEST-UNSUPPORTED")

    def test_router_handles_and_responder_receives_response(self):
        client = self._client()
        delivered = []
        router = ServerRequestRouter({"roots/list": lambda params: {"roots": ["/allowed"]}})
        client.set_server_request_router(router, responder=delivered.append)
        server_request = {"jsonrpc": "2.0", "id": "s1", "method": "roots/list"}
        # must not raise; the response is handed to the responder
        client._dispatch_server_messages((server_request,), expected_id=None)
        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0]["result"], {"roots": ["/allowed"]})
        self.assertEqual(delivered[0]["id"], "s1")

    def test_router_denies_unknown_server_method(self):
        client = self._client()
        delivered = []
        client.set_server_request_router(ServerRequestRouter(), responder=delivered.append)
        server_request = {"jsonrpc": "2.0", "id": "s1", "method": "sampling/createMessage"}
        client._dispatch_server_messages((server_request,), expected_id=None)
        self.assertEqual(delivered[0]["error"]["code"], -32601)


if __name__ == "__main__":
    unittest.main()
