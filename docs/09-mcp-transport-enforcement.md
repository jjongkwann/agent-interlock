---
title: Agent Interlock MCP Transport Enforcement Adapter
tags: [agent-interlock, mcp, architecture, enforcement, json-rpc]
date: 2026-07-17
version: 1.3
status: implemented-reference
---

# Agent Interlock MCP Transport Enforcement Adapter

> 한국어 원문: [09-mcp-transport-enforcement.ko.md](09-mcp-transport-enforcement.ko.md)

## 1. Implementation Result

`MCPTransportAdapter` connects the `REL-05 Agent → Tool` policy compiled from the Architecture manifest to actual MCP JSON-RPC messages. The applicable baseline is the latest stable MCP specification, `2025-11-25`.

```text
Architecture JSON
  → lint/compile
  → exact Tool digest binding
  → tools/list discovery guard
  → tools/call policy + argument binding
  → downstream MCP Server
  → result schema/DLP/taint guard
  → Ledger
```

`MCPTransportAdapter` is not tied to any HTTP framework or subprocess implementation. The actual wire boundary is bridged by `MCPStreamableHTTPClient` and `MCPStreamableHTTPGatewayCarrier`. The Client handles downstream JSON/SSE responses and sessions, while the Gateway Carrier terminates inbound HTTP security and the MCP lifecycle before forwarding only Tool messages to the Adapter.

When an `ArtifactAdmissionPolicy` is injected into the Adapter, the MCP Server profile must pass signature verification for the publisher, artifact digest, source repository/revision, and the entire build ID. If any of these is missing or mismatched, it is quarantined as an `MCPServerAdmissionError` at Adapter construction time, resulting in zero Server requests.

```text
MCP Host
  → inbound Streamable HTTP Carrier
      Origin / Host / Bearer / Accept / protocol / lifecycle
  → MCPTransportAdapter
      Architecture / LinkPolicy / D1·D3·D4 guard
  → downstream Streamable HTTP Client
      separate credential / session / JSON or SSE
  → MCP Server
```

## 2. MCP Specification Compliance

Based on the official [MCP Tools 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) and [Transports 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), the following contracts are enforced.

| Spec contract | Implementation |
|---|---|
| JSON-RPC 2.0 single message | batch rejected, UTF-8/JSON/size validated |
| `tools/list`, pagination | page/Tool count limit, cursor loop blocked, full refresh |
| Recommended Tool name character set (1–128 chars) | `[A-Za-z0-9_.-]` enforced by profile |
| `inputSchema` object | null/non-object rejected |
| `outputSchema` and `structuredContent` | structured content validated in the Result Guard |
| `notifications/tools/list_changed` | full list re-fetched before delivery, drift/deletion quarantined |
| Tool annotations untrusted | included in the approval digest, not exposed to the model before approval |
| Tool results untrusted | secret scrubbing, schema isolation, `UNTRUSTED_TOOL_RESULT` taint |
| Streamable HTTP POST | independent POST per request, receives both JSON and SSE responses |
| HTTP `Accept` | JSON and SSE media type contracts validated inbound and downstream |
| `MCP-Protocol-Version` | only `2025-11-25` allowed after initialize |
| `MCP-Session-Id` | established only in the initialize response, bound to subsequent requests, expires without retry on 404 |
| SSE event | UTF-8, event ID, retry, event count/response ID validated |
| `Origin` and `Host` | inbound allowlist, 403/421 on mismatch |
| HTTP authentication | inbound principal combined with trusted context, kept separate from downstream credentials |

Additional Tool fields such as `icons`, `execution`, and `_meta` are included in the digest but stripped from the default model-visible D1. If any of them changes after approval, it becomes a new revision and is blocked as `DRIFTED`. `params._meta` in a client request can also become a bypass egress outside D3, so it is denied by default, and only the keys listed in `MCPServerProfile.allowed_request_meta_keys` are forwarded. Even within allowed metadata, credential-like values are blocked.

## 2.1 Wire Carrier Security Defaults

- Only HTTPS is allowed for the downstream endpoint. Loopback HTTP on an explicit port is allowed only in the test profile.
- HTTP redirects are not followed automatically. OAuth/authorization redirects are validated separately in the next Identity Guard stage.
- The inbound bearer becomes an `MCPHTTPPrincipal` after authentication and is never copied into downstream requests.
- Downstream Authorization is obtained only from a separate `authorization_provider`.
- Timeouts, request/response byte counts, and SSE event counts are limited, with no automatic retry.
- The reference HTTP server binds to loopback only by default. Public exposure requires a TLS reverse proxy and a distributed lifecycle store.

A Tool call timeout does not mean the block succeeded. The request may have reached downstream with only the response cut off, so the carrier does not automatically retry mutations and leaves an `UNKNOWN` outcome in the Gateway. The final state must be confirmed through the idempotency key, the downstream receipt, and reconciliation.

## 3. Connecting Architecture to Actual Enforcement

`bind_compiled_architecture()` activates a Tool only when all of the following conditions hold.

1. The Tool has actually been observed in `tools/list`.
2. The Architecture Tool node's `definitionDigest` matches the observed digest exactly.
3. The revision state is one of `DISCOVERED`, `APPROVED`, or `ACTIVE`. Definitions `QUARANTINED` due to poisoning are not auto-approved.
4. A `REL-05` edge targeting the Tool node exists.
5. Architecture lint has passed the `MCP_GATEWAY/ENFORCED` and `AUDIT_SINK` controls.

When binding multiple Tools at once, every item is validated first. If a digest mismatch or a missing edge is found, the entire request is rejected before activation. If a `REL-07 Tool → External` is declared, the External node's domain allowlist is composed into the effective destination boundary of the Tool call.

Steps 4 and 5 -- registering the actors, composing the `REL-07` domains, approving and activating the revision, and installing the compiled link policy on each `REL-05` pair -- live in the module-level `bind_gateway_actors()`, not in the adapter. The Anthropic Tool Runner adapter (`adapters/anthropic_tools.bind_architecture`) binds a compiled architecture through the same function, so the two enforcement paths cannot register a graph differently. What stays in the transport adapter is what only it knows: that the Tool was observed in `tools/list`, and that the observed digest matches the Architecture pin. The Tool Runner path observes definitions after the graph is registered, so it passes no revision and pins the actor itself; a pin that disagrees with the observation is left alone there and judged as `L1-M2-DEFINITION-DRIFT` at call time, whereas the transport adapter refuses to bind at all.

## 4. Security Order at Call Time

`tools/list` is fully re-fetched on every `tools/call`. Because the last cached list alone is not trusted, definition changes or deletions made after approval are caught before the actual dispatch.

```text
trusted Host context + tools/call D3
  → current D1 refresh
  → ACTIVE + pinned digest check
  → schema / purpose / data class / destination / side effect / approval evaluation
  → argument hash combined with decision
  → downstream tools/call
  → content + structuredContent secret scrubbing
  → outputSchema validation
  → _meta.interlock evidence returned
```

`MCPInvocationContext` carries tenant, source actor, purpose, data class, destination, expected side effect, approval, and credential claims. These values are never inferred from the MCP Server response or the Tool description. `MCPServerProfile.tenant_id` is likewise declared explicitly rather than inferred from the `server_id` string, and is blocked as `INTERLOCK-TENANT-MISMATCH` if it differs from the calling tenant. If the Host has no trusted execution context, the call fails closed as `INTERLOCK-TRUSTED-CONTEXT-MISSING`.

Policy blocks are returned as JSON-RPC error `-32001` with a stable reason code. A downstream receipt is generated only when the policy is `ALLOW`. In `SHADOW`, risk verdicts are recorded but execution can still proceed under the existing Gateway semantics, so a production carrier must explicitly check the Architecture policy mode.

## 5. Usage

Full runnable example:

```bash
PYTHONPATH=src python3 examples/mcp_transport_vertical_slice.py
```

Core API:

```python
adapter = MCPTransportAdapter(gateway, server_profile, call_server)
adapter.refresh_definitions()
adapter.bind_compiled_architecture(
    compiled,
    tool_bindings={"send_email": "tool.send-email"},
    approver="security-reviewer",
)
response = adapter.handle_client_message(request, context=trusted_context)
```

Real downstream HTTP connection:

```python
client = MCPStreamableHTTPClient(
    MCPStreamableHTTPClientConfig(endpoint="https://mcp.example.com/mcp"),
    authorization_provider=downstream_credential_provider,
)
client.initialize()
adapter = MCPTransportAdapter(gateway, server_profile, client.call)
client.set_server_message_handler(adapter.handle_server_message)
```

Real inbound endpoint:

```python
carrier = MCPStreamableHTTPGatewayCarrier(
    adapter,
    MCPHTTPGatewayConfig(
        allowed_origins=frozenset({"https://agent.example"}),
        allowed_hosts=frozenset({"interlock.internal"}),
        require_origin=True,
    ),
    authenticator=verify_inbound_bearer,
    context_resolver=resolve_trusted_intent,
)
server = create_mcp_http_server(carrier)  # reference: loopback only
```

The Tool approval procedure is `tools/list → confirm observed digest → reviewed manifest pin → compile → bind`. A newly observed `DISCOVERED` Tool is not visible to the model.

## 6. Verification Scope

`tests/test_mcp_transport.py` automatically verifies the following.

- Tools not exposed before approval, and exact-digest activation
- State unchanged on architecture digest mismatch
- Policy, Result Guard, and Ledger pass for a normal `tools/call`
- Definition drift and Tool deletion blocked before dispatch
- D3 secrets blocked with zero downstream receipts
- `structuredContent` output schema errors quarantined
- D4 secret redaction and taint
- Missing trusted context and JSON-RPC batches blocked
- Cross-tenant invocation context blocked
- Argument policy bypass via request `_meta` outside the allowlist blocked

`tests/test_mcp_http.py` and `tests/mcp_http_fixture.py` additionally verify the following over a real loopback HTTP socket.

- initialize → initialized lifecycle and protocol version negotiation
- Session header establishment, binding to subsequent requests, and 404 expiry
- JSON responses, POST SSE responses, GET SSE notifications
- Inbound `SessionStore` principal binding, READY transition, GET SSE, `Last-Event-ID` replay, DELETE
- Session lifecycle continuity across carrier instances sharing a single store
- No redirect following, timeout/response size boundaries
- Origin/Host/authentication/Accept/content type validation
- Combining the authenticated principal with the trusted invocation context
- Separation of inbound/downstream bearers with zero token passthrough
- Zero Tool drift dispatch over the real HTTP path
- Exact publisher provenance profile binding and zero server calls on admission failure

## 7. Remaining Operational Boundaries

A persistent Definition Registry (`PostgreSQLRevisionStore`, migration 0003), a PostgreSQL `SessionStore` (`postgres_stores.py`, migration 0002), and macOS Seatbelt/Linux bwrap seccomp live sandboxes are implemented. To extend the current carrier to production operation and the remaining execution boundaries, the following still remain.

1. A production attestation issuer/key rotation and external KMS/HSM integration
2. An OTLP gRPC Collector and durable WORM Audit Sink export via S3 Object Lock
3. Event retention/backpressure, multi-instance failure recovery, and HA operation

Server-initiated requests and asynchronous tasks/cancellation/replay are provided by `mcp_async.py`. `ServerRequestRouter` rejects server requests outside the allowlist fail-closed (handler exceptions are quarantined as internal-error, and every decision is audited), and `AsyncTaskRegistry` provides task lifecycle, one-time result consumption (replay rejected), and idempotent cancel bound to the principal. The downstream HTTP client continues to reject server requests fail-closed until the router is enabled via `set_server_request_router`.

The token passthrough prohibited by the official [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) and [Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices) is blocked from the discovery/token exchange stage onward by [10 OAuth Identity Guard](10-mcp-oauth-identity-guard.md). The stdio process and sandbox attestation follow [11 stdio Sandbox/Receipt](11-mcp-stdio-sandbox-receipts.md).

The downstream Client can receive both POST SSE and GET SSE. When a `SessionStore` is injected, the inbound reference Server sends GET SSE for the session bound to the authenticated principal and resends events after `Last-Event-ID`; without a store it fails closed with 405. The default `InMemorySessionStore` is a single-process reference; multi-instance deployments should inject a `PostgreSQLSessionStore` (migration 0002, RLS/tenant binding) implementing the same protocol. Server-initiated JSON-RPC requests fail closed unless the allowlist router is enabled via `set_server_request_router`.
