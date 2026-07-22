---
title: MCP OAuth Identity Guard
date: 2026-07-17
version: 1.1.0
status: active
---

# MCP OAuth Identity Guard

> 한국어 원문: [10-mcp-oauth-identity-guard.ko.md](10-mcp-oauth-identity-guard.ko.md)

This document defines the security contract by which an MCP 2025-11-25 Streamable HTTP client discovers an OAuth protected resource, obtains user consent, and exchanges for a token usable only against the target MCP Server. The implementation is in `src/agent_interlock/mcp_oauth.py`; attack fixtures and regression tests are in `tests/mcp_oauth_fixture.py` and `tests/test_mcp_oauth.py`.

## 1. Applied Result

```text
┌──────────────────┐   401/403 challenge   ┌──────────────────────┐
│ MCP HTTP Client  │ ─────────────────────> │ OAuth Identity Guard │
└────────┬─────────┘                        └──────────┬───────────┘
         │                                             │
         │                               allowlist + DNS/IP + hop verification
         │                                             │
         │                         ┌───────────────────┴──────────────────┐
         │                         │                                      │
         │               ┌─────────▼─────────┐                  ┌─────────▼────────┐
         │               │ Protected Resource│                  │ Authorization     │
         │               │ Metadata          │                  │ Server Metadata   │
         │               └─────────┬─────────┘                  └─────────┬────────┘
         │                         │ exact resource                       │ issuer + S256
         │                         └───────────────────┬──────────────────┘
         │                                             │
         │                                   ┌─────────▼─────────┐
         │                                   │ Browser/User Auth │
         │                                   │ state + PKCE S256 │
         │                                   └─────────┬─────────┘
         │                                             │ one-time code
         │                                   ┌─────────▼─────────┐
         │                                   │ Token Endpoint    │
         │                                   │ resource required │
         │                                   └─────────┬─────────┘
         │                                             │
         │                           signature/introspection verifier
         │                           issuer/aud/resource/actor/scope/exp
         │                                             │
         │                                   ┌─────────▼─────────┐
         └──── Authorization: Bearer ────────│ MCPAccessToken    │
                                             └───────────────────┘
```

The inbound Host Bearer token is not an input to this flow. `MCPAccessToken` supplies `MCPStreamableHTTPClient.authorization_provider` only with a downstream token that has passed both the authorization code exchange and a trusted claims verifier. MCP requests are never automatically retried behind a 401, so write-Tool calls are never duplicated either.

## 2. Implemented Controls

| Boundary | Control | Failure Behavior |
|---|---|---|
| `WWW-Authenticate` | Bearer challenge, quoted value, duplicate-parameter, CR/LF check | challenge rejected |
| Protected Resource discovery | challenge's `resource_metadata`, endpoint-path well-known, root well-known order | only 404 advances to the next candidate |
| Resource Metadata | `resource` matches the canonical MCP endpoint exactly, AS host and optional exact-issuer allowlist | mismatch blocked |
| AS Metadata | issuer path discovery order, exact issuer match, authorization/token endpoint re-verification | mismatch blocked |
| PKCE | metadata must explicitly state `S256`, 43–128 character verifier, SHA-256 base64url challenge | authorization start blocked |
| Authorization request | exact match to the registered redirect URI, binds `state`, `resource`, and challenge scope | transaction issuance blocked |
| Callback | scheme/authority/path, state, code/error exclusivity, expiry, one-time consume | transaction discarded |
| Consent adapter | loopback-only callback listener, exact one-time callback with an explicit browser opener | timeout · second-callback rejected |
| Token request | `resource`, identical redirect URI, code verifier required, redirect prohibited, one-time consume | re-exchange · redirect blocked |
| Opaque token verification | RFC 7662 introspection, client auth, redirect/SSRF/size limits, `active` and claim-shape check | token supply blocked |
| JWT verification | JWKS-based RS256/ES256/EdDSA via the optional `jwt` extra, alg · kid · iss · exp/nbf check | token supply blocked |
| Transaction state | a replaceable one-time `OAuthTransactionStore`, single-node in-memory reference | no transaction on replay |
| Token handling | redacted `repr` for the access token and PKCE/state, only the token fingerprint stored in `CredentialClaims` | raw token never stored in the ledger |
| SSRF | HTTPS by default, host allowlist, userinfo/fragment blocked, non-public IPs blocked in DNS results | blocked before fetch |
| Development profile | only loopback HTTP on an explicit port, as a separate opt-in | blocked in the default profile |

When the challenge provides a `scope`, it is treated as the authority of the current request. If the authorization request narrows or widens it, the request is blocked with `MCP-OAUTH-CHALLENGE-SCOPE-MISMATCH`. After token verification, the existing `LinkPolicy` makes one more pass judging `CredentialClaims.exchanged`, audience, resource, actor, and delegation depth.

## 3. Discovery Order

If the MCP endpoint is `https://mcp.example/tenant/mcp`, the Protected Resource Metadata candidates are as follows.

1. The `resource_metadata` specified by the Bearer challenge
2. `https://mcp.example/.well-known/oauth-protected-resource/tenant/mcp`
3. `https://mcp.example/.well-known/oauth-protected-resource`

If the issuer is `https://auth.example/tenant`, the Authorization Server Metadata candidates are as follows.

1. `https://auth.example/.well-known/oauth-authorization-server/tenant`
2. `https://auth.example/.well-known/openid-configuration/tenant`
3. `https://auth.example/tenant/.well-known/openid-configuration`

Advancing to the next candidate is allowed only on `404 Not Found`. Malformed JSON, resource/issuer mismatch, unsafe URLs, and 401/403/5xx are all treated as discovery failure, so an attacker cannot use fallback to lower the trust boundary.

## 4. Usage Contract

```python
profile = OAuthSecurityProfile(
    allowed_authorization_server_hosts=frozenset({"auth.example"}),
    allowed_authorization_server_issuers=frozenset({"https://auth.example/tenant-a"}),
    allowed_metadata_hosts=frozenset({"mcp.example"}),
)

discovery = MCPProtectedResourceDiscovery(mcp_endpoint, profile).discover(
    mcp_http_status_error.www_authenticate
)
flow = MCPAuthorizationCodeFlow(
    discovery,
    profile,
    client_id="pre-registered-client",
    registered_redirect_uris=frozenset({"https://console.example/oauth/callback"}),
)
transaction = flow.begin(redirect_uri="https://console.example/oauth/callback")

# Open transaction.authorization_uri in the user's browser, then pass in the callback.
code = flow.validate_callback(transaction, callback_uri)

token_provider = MCPAuthorizationCodeTokenClient(
    discovery,
    profile,
    expected_client_id="pre-registered-client",
    expected_actor="agent.support",
    claims_verifier=verify_signature_or_introspect,
).exchange(transaction, code)

client = MCPStreamableHTTPClient(
    MCPStreamableHTTPClientConfig(endpoint=mcp_endpoint),
    authorization_provider=token_provider,
)
trusted_credential_claims = token_provider.credential
```

`verify_signature_or_introspect` must be built from `MCPJWKSVerifier`, `MCPTokenIntrospectionVerifier`, or an IdP adapter under the same contract, and it must return `VerifiedAccessTokenClaims`. A plain decoded JWT payload must never be passed into this interface. The loopback installed-app flow can open the authorization URI with `LoopbackCallbackReceiver` and `run_consent` and receive the exact callback URI. Pass `trusted_credential_claims` into `MCPInvocationContext.credential` to enforce the same actor/resource binding as the Gateway policy.

## 5. Redirect and SSRF Operational Standards

- Metadata redirects default to `max_redirect_hops=0`. Open it to a small value only when organizational policy requires it, and re-run the scheme, host allowlist, and DNS/IP checks on every hop.
- For a multi-tenant Authorization Server, do not rely on the host allowlist alone; pin the tenant path exactly with `allowed_authorization_server_issuers`.
- Token endpoint redirects are always rejected, eliminating any possibility of the authorization code or PKCE verifier being delivered to a different endpoint.
- `resolve_dns=True` is the default and blocks private, loopback, link-local, multicast, reserved, and unspecified addresses. loopback HTTP is allowed only in the test profile.
- A DNS TOCTOU window remains between the Python reference client's checks and the actual connection. Production deployments must enforce the same allowlist with a fixed egress proxy, DNS pinning, or a service-mesh policy.

## 6. Reference Scope and Remaining Operational Components

The reference core provides a loopback callback receiver, a browser-opener contract, an RFC 7662 introspection verifier, an optional JWKS/JWT verifier, and a one-time transaction store. Deployments that need atomic multi-instance replay prevention inject `PostgreSQLOAuthTransactionStore` (`postgres_stores.py`, migration 0002) instead of `InMemoryOAuthTransactionStore`, which blocks cross-instance callback replay via DELETE-consume. DNS pinning and enforcement of the actual connect IP are provided by `egress.py` `PinnedSocketEgressBackend` (single DNS resolution → pinned connect IP → peer verification → non-global-address fail-closed). The following operational components are not yet included.

- Organization-specific login/consent UI, a public HTTPS callback service, and a consent audit workflow
- Per-IdP JWKS cache · rotation · failure policy and the introspection credential lifecycle
- Client registration/secret storage and Dynamic Client Registration/Client ID Metadata Document
- Encrypted storage · rotation · revocation of refresh tokens
- DPoP, mTLS sender-constrained token
- External KMS/HSM key issuance · rotation · revocation and production IdP/Secret Store integration

The current state, therefore, is a complete OAuth protocol guard and token-binding reference implementation — it does not mean a production identity adapter wired to a specific IdP is complete.

## 7. Verification

`tests/test_mcp_oauth.py` uses a real loopback HTTP Authorization Server fixture to automatically verify the following.

- challenge and scope parsing
- protected resource/issuer path discovery order
- resource/issuer mismatch and missing-S256 rejection
- credential URL, link-local SSRF, and untrusted-redirect rejection
- default redirect-hop rejection and opt-in hop re-verification
- redirect URI, state, PKCE, callback/code one-time binding
- token request's resource · verifier · redirect binding
- token endpoint redirect and audience/actor/scope mismatch rejection
- access token non-exposure and `CredentialClaims.exchanged=True`

`tests/test_oauth_introspection.py`, `tests/test_mcp_jwt.py`, and `tests/test_oauth_consent.py` additionally verify introspection client-auth · claim mapping · one-time store, JWKS signature and algorithm-confusion rejection, and loopback callback one-time · timeout. `tests/test_l1_matrix.py` runs the M5 scope broadening/state replay and M6 private redirect/safe consent paths under L1 tracking IDs.

The baseline specifications are [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices), [RFC 9728 OAuth Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728), [RFC 8707 Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707), and [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636).
