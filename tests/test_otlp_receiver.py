from __future__ import annotations

import http.client
import json
import threading
import unittest
from typing import Any, Mapping

from agent_interlock import (
    InMemoryLedger,
    LedgerAPIPrincipal,
    LedgerHTTPAPI,
    StaticBearerAuthenticator,
    create_ledger_http_server,
)

TELEMETRY_TOKEN = "tenant-a-telemetry-token-canary"
NO_SCOPE_TOKEN = "tenant-a-events-only-token-canary"


def _attr(key: str, string: str | None = None, boolean: bool | None = None) -> dict[str, Any]:
    if boolean is not None:
        return {"key": key, "value": {"boolValue": boolean}}
    return {"key": key, "value": {"stringValue": string}}


def otlp_payload(*, with_context: bool = True) -> dict[str, Any]:
    attributes = [
        _attr("gen_ai.operation.name", "execute_tool"),
        _attr("mcp.method.name", "tools/call"),
    ]
    if with_context:
        attributes += [
            _attr("interlock.source.actor.id", "agent.support"),
            _attr("interlock.target.actor.id", "tool.send-email"),
            _attr("interlock.relationship.type", "INVOKES"),
            _attr("interlock.relationship.id", "REL-05"),
            _attr("interlock.interaction.id", "interaction-1"),
            _attr("interlock.control.evaluated", boolean=True),
        ]
    return {
        "resourceSpans": [
            {"scopeSpans": [{"spans": [{"spanId": "span-1", "attributes": attributes}]}]}
        ]
    }


class RunningTelemetryServer:
    def __init__(self):
        self.ledger = InMemoryLedger()
        self.authenticator = StaticBearerAuthenticator.from_tokens(
            {
                TELEMETRY_TOKEN: LedgerAPIPrincipal(
                    "collector-a", "tenant-a", frozenset({"telemetry:write"})
                ),
                NO_SCOPE_TOKEN: LedgerAPIPrincipal(
                    "writer-a", "tenant-a", frozenset({"events:write"})
                ),
            }
        )
        self.api = LedgerHTTPAPI(self.ledger, self.authenticator)
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

    def post_traces(
        self,
        body: Mapping[str, Any] | bytes,
        *,
        token: str | None = TELEMETRY_TOKEN,
        tenant_id: str | None = "tenant-a",
    ) -> tuple[int, Mapping[str, Any]]:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        headers: dict[str, str] = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if tenant_id is not None:
            headers["X-Interlock-Tenant-Id"] = tenant_id
        if isinstance(body, Mapping):
            encoded: bytes = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        else:
            encoded = body
            headers["Content-Type"] = "application/json"
        try:
            connection.request("POST", "/v1/traces", body=encoded, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            return response.status, (json.loads(raw) if raw else {})
        finally:
            connection.close()


class OTLPReceiverTests(unittest.TestCase):
    def test_receiver_decodes_otlp_into_observations(self):
        with RunningTelemetryServer() as running:
            status, value = running.post_traces(otlp_payload())
            self.assertEqual(status, 200)
            self.assertEqual(value["format"], "OTLP_JSON")
            self.assertEqual(len(value["observations"]), 1)
            edge = value["observations"][0]
            self.assertEqual(edge["source_actor_id"], "agent.support")
            self.assertEqual(edge["target_actor_id"], "tool.send-email")
            self.assertEqual(edge["relationship_id"], "REL-05")
            self.assertEqual(value["control_evaluated_interactions"], ["interaction-1"])
            self.assertEqual(value["issues"], [])

    def test_tracked_span_without_interlock_context_is_flagged(self):
        with RunningTelemetryServer() as running:
            status, value = running.post_traces(otlp_payload(with_context=False))
            self.assertEqual(status, 200)
            self.assertEqual(value["observations"], [])
            codes = [issue["code"] for issue in value["issues"]]
            self.assertIn("TELEMETRY_SECURITY_CONTEXT_MISSING", codes)

    def test_non_otlp_body_is_rejected(self):
        with RunningTelemetryServer() as running:
            status, value = running.post_traces({"events": []})
            self.assertEqual(status, 400)
            self.assertEqual(value["error"]["code"], "LEDGER-OTLP-INVALID")

    def test_scope_is_required(self):
        with RunningTelemetryServer() as running:
            status, value = running.post_traces(otlp_payload(), token=NO_SCOPE_TOKEN)
            self.assertEqual(status, 403)
            self.assertEqual(value["error"]["code"], "LEDGER-SCOPE-DENIED")

    def test_auth_is_required(self):
        with RunningTelemetryServer() as running:
            status, value = running.post_traces(otlp_payload(), token=None)
            self.assertEqual(status, 401)
            self.assertEqual(value["error"]["code"], "LEDGER-AUTH-INVALID")


if __name__ == "__main__":
    unittest.main()
