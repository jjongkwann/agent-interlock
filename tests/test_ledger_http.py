from __future__ import annotations

import http.client
import json
import threading
import unittest
from collections.abc import Mapping
from typing import Any

from agent_interlock import (
    InMemoryLedger,
    LedgerAPIPrincipal,
    LedgerHTTPAPI,
    LedgerHTTPConfig,
    LedgerIdempotencyConflict,
    StaticBearerAuthenticator,
    create_ledger_http_server,
)

TOKEN_A = "tenant-a-ledger-token-canary"
TOKEN_B = "tenant-b-ledger-token-canary"


def event_body(*, tenant_id: str = "tenant-a", trace_id: str = "trace-api", marker: str = "one"):
    return {
        "event_type": "INTERACTION_REQUESTED",
        "tenant_id": tenant_id,
        "trace_id": trace_id,
        "span_id": f"span-{marker}",
        "source_actor_id": "agent.support",
        "target_actor_id": "tool.mail",
        "relationship_type": "INVOKES",
        "relationship_id": "REL-05",
        "payload": {"marker": marker},
    }


class RunningLedgerServer:
    def __init__(self, *, config: LedgerHTTPConfig | None = None):
        self.ledger = InMemoryLedger()
        self.authenticator = StaticBearerAuthenticator.from_tokens(
            {
                TOKEN_A: LedgerAPIPrincipal(
                    "writer-a",
                    "tenant-a",
                    frozenset({"events:read", "events:write"}),
                    frozenset({"agent.support", "gateway"}),
                ),
                TOKEN_B: LedgerAPIPrincipal(
                    "reader-b",
                    "tenant-b",
                    frozenset({"events:read"}),
                    frozenset({"agent.support"}),
                ),
            }
        )
        self.api = LedgerHTTPAPI(self.ledger, self.authenticator, config=config)
        self.server = create_ledger_http_server(self.api)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = TOKEN_A,
        tenant_id: str | None = "tenant-a",
        body: Mapping[str, Any] | bytes | None = None,
        idempotency_key: str | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> tuple[int, Mapping[str, Any], Mapping[str, str]]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        headers: dict[str, str] = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if tenant_id is not None:
            headers["X-Interlock-Tenant-Id"] = tenant_id
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        encoded: bytes | None
        if isinstance(body, Mapping):
            encoded = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        else:
            encoded = body
        if extra_headers:
            headers.update(extra_headers)
        try:
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            value = json.loads(raw) if raw else {}
            return (
                response.status,
                value,
                {key.casefold(): item for key, item in response.getheaders()},
            )
        finally:
            connection.close()


class InMemoryLedgerContractTests(unittest.TestCase):
    def test_idempotency_is_bound_to_the_sanitized_event(self):
        ledger = InMemoryLedger()
        common = dict(
            tenant_id="tenant-a",
            trace_id="trace-idempotent",
            span_id="span-one",
            source_actor_id="agent.support",
            idempotency_key="event-one",
        )
        first = ledger.append(
            "INTERACTION_REQUESTED",
            payload={"authorization": "Bearer downstream-secret"},
            **common,
        )
        replay = ledger.append(
            "INTERACTION_REQUESTED",
            payload={"authorization": "Bearer another-secret"},
            **common,
        )
        self.assertEqual(first.event_id, replay.event_id)
        self.assertEqual(first.payload["authorization"], "[REDACTED]")
        with self.assertRaises(LedgerIdempotencyConflict):
            ledger.append(
                "INTERACTION_REQUESTED",
                payload={"marker": "different"},
                **common,
            )

    def test_security_signal_exceptions_require_exact_safe_types(self):
        ledger = InMemoryLedger()
        event = ledger.append(
            "CONTROL_EVALUATED",
            tenant_id="tenant-a",
            trace_id="trace-signals",
            span_id="span-signals",
            source_actor_id="gateway",
            payload={
                "credentialFingerprint": "raw-credential-canary",
                "secretDetected": "raw-secret-canary",
                "tokenPassthrough": "raw-token-canary",
                "nested": {
                    "credentialFingerprint": "sha256:" + "a" * 64,
                    "secretDetected": True,
                    "tokenPassthrough": False,
                },
            },
        )
        self.assertEqual(event.payload["credentialFingerprint"], "[REDACTED]")
        self.assertEqual(event.payload["secretDetected"], "[REDACTED]")
        self.assertEqual(event.payload["tokenPassthrough"], "[REDACTED]")
        self.assertEqual(event.payload["nested"]["credentialFingerprint"], "sha256:" + "a" * 64)
        self.assertIs(event.payload["nested"]["secretDetected"], True)
        self.assertIs(event.payload["nested"]["tokenPassthrough"], False)

    def test_trace_cursor_is_tenant_scoped_and_bounded(self):
        ledger = InMemoryLedger()
        for marker in ("one", "two", "three"):
            ledger.append(
                "INTERACTION_REQUESTED",
                tenant_id="tenant-a",
                trace_id="trace-page",
                span_id=f"span-{marker}",
                source_actor_id="agent.support",
                payload={"marker": marker},
            )
        first = ledger.query_trace("tenant-a", "trace-page", limit=2)
        self.assertEqual(len(first.events), 2)
        self.assertIsNotNone(first.next_cursor)
        second = ledger.query_trace(
            "tenant-a",
            "trace-page",
            limit=2,
            cursor=first.next_cursor,
        )
        self.assertEqual(len(second.events), 1)
        self.assertIsNone(second.next_cursor)
        self.assertEqual(ledger.query_trace("tenant-b", "trace-page").events, ())
        with self.assertRaises(ValueError):
            ledger.query_trace("tenant-a", "trace-page", cursor="not-a-cursor")


class LedgerHTTPAPITests(unittest.TestCase):
    def test_auth_tenant_scope_and_origin_fail_closed_before_ingest(self):
        with RunningLedgerServer() as running:
            status, value, headers = running.request(
                "POST",
                "/v1/events",
                token=None,
                body=event_body(),
                idempotency_key="auth-missing",
            )
            self.assertEqual(status, 401)
            self.assertIn("bearer", headers["www-authenticate"].casefold())
            self.assertEqual(value["error"]["code"], "LEDGER-AUTH-INVALID")

            status, _, _ = running.request(
                "POST",
                "/v1/events",
                tenant_id="tenant-b",
                body=event_body(),
                idempotency_key="tenant-mismatch",
            )
            self.assertEqual(status, 403)

            forged_source = event_body()
            forged_source["source_actor_id"] = "agent.unowned"
            status, value, _ = running.request(
                "POST",
                "/v1/events",
                body=forged_source,
                idempotency_key="source-actor-denied",
            )
            self.assertEqual(status, 403)
            self.assertEqual(value["error"]["code"], "LEDGER-SOURCE-ACTOR-DENIED")

            status, _, _ = running.request(
                "POST",
                "/v1/events",
                token=TOKEN_B,
                tenant_id="tenant-b",
                body=event_body(tenant_id="tenant-b"),
                idempotency_key="scope-denied",
            )
            self.assertEqual(status, 403)

            status, _, _ = running.request(
                "POST",
                "/v1/events",
                body=event_body(),
                idempotency_key="origin-denied",
                extra_headers={"Origin": "https://evil.example"},
            )
            self.assertEqual(status, 403)
            self.assertEqual(running.ledger.all(), ())

    def test_ingest_redacts_secrets_and_replay_is_exact(self):
        with RunningLedgerServer() as running:
            body = event_body()
            body["payload"] = {
                "authorization": "Bearer downstream-token-secret",
                "message": "api_key=abcd1234secretvalue",
            }
            first_status, first, _ = running.request(
                "POST",
                "/v1/events",
                body=body,
                idempotency_key="event-ingest-1",
            )
            replay_status, replay, _ = running.request(
                "POST",
                "/v1/events",
                body=body,
                idempotency_key="event-ingest-1",
            )
            self.assertEqual((first_status, replay_status), (201, 201))
            self.assertEqual(first["event"]["event_id"], replay["event"]["event_id"])
            self.assertEqual(
                first["event"]["payload"]["_interlock"]["producerSubject"],
                "writer-a",
            )
            serialized = json.dumps(first)
            self.assertNotIn("downstream-token-secret", serialized)
            self.assertNotIn("abcd1234secretvalue", serialized)
            self.assertEqual(len(running.ledger.all()), 1)

            changed = event_body(marker="changed")
            status, value, _ = running.request(
                "POST",
                "/v1/events",
                body=changed,
                idempotency_key="event-ingest-1",
            )
            self.assertEqual(status, 409)
            self.assertEqual(value["error"]["code"], "LEDGER-IDEMPOTENCY-CONFLICT")
            self.assertEqual(len(running.ledger.all()), 1)

            reserved = event_body(marker="reserved")
            reserved["payload"] = {"_interlock": {"producerSubject": "forged"}}
            status, value, _ = running.request(
                "POST",
                "/v1/events",
                body=reserved,
                idempotency_key="reserved-payload",
            )
            self.assertEqual(status, 400)
            self.assertEqual(value["error"]["code"], "LEDGER-PAYLOAD-RESERVED")
            self.assertEqual(len(running.ledger.all()), 1)

    def test_trace_query_paginates_without_cross_tenant_disclosure(self):
        with RunningLedgerServer() as running:
            for marker in ("one", "two", "three"):
                status, _, _ = running.request(
                    "POST",
                    "/v1/events",
                    body=event_body(trace_id="trace-query", marker=marker),
                    idempotency_key=f"query-{marker}",
                )
                self.assertEqual(status, 201)

            status, first, headers = running.request(
                "GET",
                "/v1/traces/trace-query?limit=2",
            )
            self.assertEqual(status, 200)
            self.assertEqual(len(first["events"]), 2)
            self.assertTrue(first["next_cursor"])
            self.assertEqual(headers["cache-control"], "no-store")

            status, second, _ = running.request(
                "GET",
                f"/v1/traces/trace-query?limit=2&cursor={first['next_cursor']}",
            )
            self.assertEqual(status, 200)
            self.assertEqual(len(second["events"]), 1)
            self.assertIsNone(second["next_cursor"])

            status, other_tenant, _ = running.request(
                "GET",
                "/v1/traces/trace-query",
                token=TOKEN_B,
                tenant_id="tenant-b",
            )
            self.assertEqual(status, 200)
            self.assertEqual(other_tenant["events"], [])

            status, value, _ = running.request(
                "GET",
                "/v1/traces/trace-query?cursor=invalid",
            )
            self.assertEqual(status, 400)
            self.assertEqual(value["error"]["code"], "LEDGER-REQUEST-INVALID")

    def test_body_limit_and_reference_bind_restriction(self):
        with RunningLedgerServer(config=LedgerHTTPConfig(max_request_bytes=128)) as running:
            status, value, _ = running.request(
                "POST",
                "/v1/events",
                body=b"{" + b"x" * 256 + b"}",
                idempotency_key="too-large",
                extra_headers={"Content-Type": "application/json"},
            )
            self.assertEqual(status, 413)
            self.assertEqual(value["error"]["code"], "LEDGER-BODY-TOO-LARGE")
            self.assertEqual(running.ledger.all(), ())

            status, value, _ = running.request(
                "POST",
                "/v1/events",
                body=event_body(),
                idempotency_key="expect-denied",
                extra_headers={"Expect": "100-continue"},
            )
            self.assertEqual(status, 417)
            self.assertEqual(value["error"]["code"], "LEDGER-EXPECTATION-DENIED")
            self.assertEqual(running.ledger.all(), ())

        with RunningLedgerServer() as running:
            duplicate_tenant = (
                b'{"event_type":"INTERACTION_REQUESTED","tenant_id":"tenant-a",'
                b'"tenant_id":"tenant-b","trace_id":"trace-duplicate",'
                b'"span_id":"span-duplicate","source_actor_id":"agent","payload":{}}'
            )
            status, value, _ = running.request(
                "POST",
                "/v1/events",
                body=duplicate_tenant,
                idempotency_key="duplicate-json-key",
                extra_headers={"Content-Type": "application/json"},
            )
            self.assertEqual(status, 400)
            self.assertEqual(value["error"]["code"], "LEDGER-REQUEST-INVALID")
            self.assertEqual(running.ledger.all(), ())
        with self.assertRaises(ValueError):
            create_ledger_http_server(
                LedgerHTTPAPI(InMemoryLedger(), StaticBearerAuthenticator({})),
                host="0.0.0.0",
            )

    def test_authenticator_does_not_retain_or_render_plaintext_tokens(self):
        authenticator = StaticBearerAuthenticator.from_tokens(
            {TOKEN_A: LedgerAPIPrincipal("subject", "tenant-a", frozenset())}
        )
        self.assertNotIn(TOKEN_A, repr(authenticator))
        self.assertNotIn(TOKEN_A, repr(authenticator.__dict__))


if __name__ == "__main__":
    unittest.main()
