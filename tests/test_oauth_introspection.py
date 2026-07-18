from __future__ import annotations

import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http_test_server import QuietThreadingHTTPServer
from urllib.parse import parse_qs

from agent_interlock import (
    InMemoryOAuthTransactionStore,
    MCPOAuthError,
    MCPOAuthHTTPStatusError,
    MCPTokenIntrospectionVerifier,
    OAuthAuthorizationTransaction,
    OAuthSecurityProfile,
    VerifiedAccessTokenClaims,
)

VALID_TOKEN = "downstream-token-secret"
BASIC = "Basic Y2xpZW50OnNlY3JldA=="  # client:secret


class FakeIntrospectionServer:
    def __init__(self, *, audience="https://mcp.example/mcp", include_act=True, aud_list=False):
        self.audience = audience
        self.include_act = include_act
        self.aud_list = aud_list
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.saw_authorization: list[str | None] = []

    @property
    def endpoint(self) -> str:
        assert self._server is not None
        return f"http://127.0.0.1:{self._server.server_port}/introspect"

    def __enter__(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                fixture.saw_authorization.append(self.headers.get("Authorization"))
                if self.path != "/introspect":
                    return self._write(404)
                if self.headers.get("Authorization") is None:
                    return self._write(401)
                length = int(self.headers.get("Content-Length", "0"))
                form = parse_qs(self.rfile.read(length).decode("ascii"))
                token = form.get("token", [""])[0]
                if token != VALID_TOKEN:
                    return self._json({"active": False})
                claims = {
                    "active": True,
                    "iss": "https://idp.example/issuer",
                    "sub": "user-1",
                    "aud": [fixture.audience] if fixture.aud_list else fixture.audience,
                    "resource": fixture.audience,
                    "scope": "mcp.read mcp.call",
                    "exp": int(time.time()) + 300,
                }
                if fixture.include_act:
                    claims["act"] = {"sub": "agent.support"}
                self._json(claims)

            def _json(self, value):
                payload = json.dumps(value).encode("utf-8")
                self._write(200, payload, {"Content-Type": "application/json"})

            def _write(self, status, payload=b"", headers=None):
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if payload:
                    self.wfile.write(payload)

            def log_message(self, *_args):
                return

        self._server = QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=lambda: self._server.serve_forever(poll_interval=0.01), daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_args):
        assert self._server is not None
        self._server.shutdown()
        self._server.server_close()
        assert self._thread is not None
        self._thread.join(timeout=2)


def profile():
    return OAuthSecurityProfile(
        allowed_authorization_server_hosts=frozenset({"127.0.0.1"}),
        allow_loopback_http=True,
        resolve_dns=False,
        max_redirect_hops=0,
    )


def verifier(server, *, with_auth=True):
    return MCPTokenIntrospectionVerifier(
        server.endpoint,
        profile(),
        client_authentication_provider=(lambda: {"Authorization": BASIC}) if with_auth else None,
    )


class IntrospectionVerifierTests(unittest.TestCase):
    def test_active_token_maps_to_verified_claims(self):
        with FakeIntrospectionServer() as server:
            claims = verifier(server)(VALID_TOKEN)
            self.assertIsInstance(claims, VerifiedAccessTokenClaims)
            self.assertEqual(claims.issuer, "https://idp.example/issuer")
            self.assertEqual(claims.subject, "user-1")
            self.assertEqual(claims.actor, "agent.support")  # from act.sub
            self.assertEqual(claims.audience, "https://mcp.example/mcp")
            self.assertEqual(claims.resource, "https://mcp.example/mcp")
            self.assertEqual(claims.scopes, frozenset({"mcp.read", "mcp.call"}))
            self.assertGreater(claims.expires_at_epoch, time.time())
            self.assertEqual(server.saw_authorization[0], BASIC)

    def test_inactive_token_is_rejected(self):
        with FakeIntrospectionServer() as server:
            with self.assertRaises(MCPOAuthError) as raised:
                verifier(server)("revoked-token")
            self.assertEqual(raised.exception.reason_code, "MCP-OAUTH-TOKEN-INACTIVE")

    def test_missing_client_authentication_fails_closed(self):
        with FakeIntrospectionServer() as server:
            with self.assertRaises(MCPOAuthHTTPStatusError) as raised:
                verifier(server, with_auth=False)(VALID_TOKEN)
            self.assertEqual(raised.exception.status, 401)

    def test_actor_falls_back_to_subject_without_act_claim(self):
        with FakeIntrospectionServer(include_act=False) as server:
            claims = verifier(server)(VALID_TOKEN)
            self.assertEqual(claims.actor, "user-1")

    def test_single_element_audience_list_is_accepted(self):
        with FakeIntrospectionServer(aud_list=True) as server:
            claims = verifier(server)(VALID_TOKEN)
            self.assertEqual(claims.audience, "https://mcp.example/mcp")

    def test_endpoint_outside_trust_boundary_is_refused(self):
        with self.assertRaises(MCPOAuthError):
            MCPTokenIntrospectionVerifier("https://evil.example/introspect", profile())


class OAuthTransactionStoreTests(unittest.TestCase):
    def _transaction(self, state="state-123"):
        return OAuthAuthorizationTransaction(
            client_id="client-1",
            redirect_uri="https://app.example/callback",
            resource="https://mcp.example/mcp",
            scopes=("mcp.read",),
            state=state,
            code_verifier="v" * 43,
            authorization_uri="https://idp.example/authorize",
            expires_at_epoch=time.time() + 300,
        )

    def test_consume_is_one_time(self):
        store = InMemoryOAuthTransactionStore()
        transaction = self._transaction()
        store.put(transaction)
        self.assertIs(store.consume("state-123"), transaction)
        self.assertIsNone(store.consume("state-123"))  # replay finds nothing

    def test_duplicate_state_is_rejected(self):
        store = InMemoryOAuthTransactionStore()
        store.put(self._transaction())
        with self.assertRaises(MCPOAuthError) as raised:
            store.put(self._transaction())
        self.assertEqual(raised.exception.reason_code, "MCP-OAUTH-STATE-DUPLICATE")

    def test_shared_store_prevents_cross_instance_replay(self):
        shared = InMemoryOAuthTransactionStore()
        instance_a = shared
        instance_b = shared  # a second gateway process would hold the same backend
        instance_a.put(self._transaction("cross"))
        self.assertIsNotNone(instance_b.consume("cross"))
        self.assertIsNone(instance_a.consume("cross"))

    def test_delete_removes_pending_transaction(self):
        store = InMemoryOAuthTransactionStore()
        store.put(self._transaction("gone"))
        store.delete("gone")
        self.assertIsNone(store.consume("gone"))


if __name__ == "__main__":
    unittest.main()
