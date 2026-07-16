---
title: MCP OAuth Identity Guard
date: 2026-07-16
version: 1.0.0
status: active
---

# MCP OAuth Identity Guard

이 문서는 MCP 2025-11-25 Streamable HTTP client가 OAuth protected resource를 발견하고, 사용자 승인을 거쳐, 대상 MCP Server에만 쓸 수 있는 토큰을 교환하는 보안 계약을 정의한다. 구현은 `src/agent_interlock/mcp_oauth.py`, 공격 fixture와 회귀 시험은 `tests/mcp_oauth_fixture.py`, `tests/test_mcp_oauth.py`에 있다.

## 1. 적용 결과

```text
┌──────────────────┐   401/403 challenge   ┌──────────────────────┐
│ MCP HTTP Client  │ ─────────────────────> │ OAuth Identity Guard │
└────────┬─────────┘                        └──────────┬───────────┘
         │                                             │
         │                               allowlist + DNS/IP + hop 검증
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

인바운드 Host Bearer token은 이 흐름의 입력이 아니다. `MCPAccessToken`은 authorization code 교환과 신뢰할 수 있는 claims verifier를 모두 통과한 다운스트림 token만 `MCPStreamableHTTPClient.authorization_provider`에 공급한다. MCP 요청을 401 뒤에 자동 재실행하지 않으므로 쓰기 Tool의 중복 실행도 만들지 않는다.

## 2. 구현된 통제

| 경계 | 통제 | 실패 시 동작 |
|---|---|---|
| `WWW-Authenticate` | Bearer challenge, quoted value, 중복 parameter, CR/LF 검사 | challenge 거부 |
| Protected Resource discovery | challenge의 `resource_metadata`, endpoint path well-known, root well-known 순서 | 404만 다음 후보로 이동 |
| Resource Metadata | `resource`가 canonical MCP endpoint와 정확히 일치, AS host 및 선택적 exact issuer allowlist | 불일치 차단 |
| AS Metadata | issuer path discovery 순서, issuer 정확 일치, authorization/token endpoint 재검증 | 불일치 차단 |
| PKCE | metadata에 `S256` 명시 필수, 43–128자 verifier, SHA-256 base64url challenge | authorization 시작 차단 |
| Authorization request | 등록 redirect URI 정확 일치, `state`, `resource`, challenge scope 결합 | transaction 발급 차단 |
| Callback | scheme/authority/path, state, code/error 배타성, 만료, one-time consume | transaction 폐기 |
| Token request | `resource`, 동일 redirect URI, code verifier 필수, redirect 금지, one-time consume | 재교환·redirect 차단 |
| Token verification | 외부 signature verifier 또는 introspection 결과로 issuer/audience/resource/actor/scope/expiry 검사 | token 공급 차단 |
| Token handling | access token과 PKCE/state의 `repr` 정제, token fingerprint만 `CredentialClaims`에 저장 | 원장에 raw token 미저장 |
| SSRF | HTTPS 기본, host allowlist, userinfo/fragment 차단, DNS 결과의 non-public IP 차단 | fetch 전 차단 |
| 개발 profile | 명시적 port의 loopback HTTP만 별도 opt-in | 기본 profile에서는 차단 |

challenge가 `scope`를 제공하면 현재 요청의 권한으로 취급한다. authorization request가 이를 줄이거나 늘리면 `MCP-OAUTH-CHALLENGE-SCOPE-MISMATCH`로 차단한다. Token 검증 후에는 기존 `LinkPolicy`가 `CredentialClaims.exchanged`, audience, resource, actor, delegation depth를 한 번 더 판정한다.

## 3. Discovery 순서

MCP endpoint가 `https://mcp.example/tenant/mcp`라면 Protected Resource Metadata 후보는 다음과 같다.

1. Bearer challenge가 지정한 `resource_metadata`
2. `https://mcp.example/.well-known/oauth-protected-resource/tenant/mcp`
3. `https://mcp.example/.well-known/oauth-protected-resource`

issuer가 `https://auth.example/tenant`라면 Authorization Server Metadata 후보는 다음과 같다.

1. `https://auth.example/.well-known/oauth-authorization-server/tenant`
2. `https://auth.example/.well-known/openid-configuration/tenant`
3. `https://auth.example/tenant/.well-known/openid-configuration`

후보 이동은 `404 Not Found`에만 허용한다. 잘못된 JSON, resource/issuer 불일치, 안전하지 않은 URL, 401/403/5xx는 discovery 실패로 처리해 공격자가 fallback을 이용해 신뢰 경계를 낮출 수 없게 한다.

## 4. 사용 계약

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

# transaction.authorization_uri를 사용자 browser에서 연 뒤 callback을 전달한다.
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

`verify_signature_or_introspect`는 access token 서명 검증 또는 Authorization Server introspection을 수행하고 `VerifiedAccessTokenClaims`를 반환해야 한다. 단순 JWT payload decode 결과는 이 인터페이스에 넣으면 안 된다. `trusted_credential_claims`는 `MCPInvocationContext.credential`에 전달해 Gateway 정책과 동일한 actor/resource binding을 집행한다.

## 5. Redirect와 SSRF 운영 기준

- Metadata redirect는 기본 `max_redirect_hops=0`이다. 조직 정책상 필요할 때만 작은 값으로 열며 모든 hop에 scheme, host allowlist, DNS/IP 검사를 다시 수행한다.
- Multi-tenant Authorization Server에서는 host allowlist만 쓰지 말고 `allowed_authorization_server_issuers`로 tenant path까지 정확히 고정한다.
- Token endpoint redirect는 항상 거부한다. Authorization code와 PKCE verifier가 다른 endpoint로 전달될 가능성을 없앤다.
- `resolve_dns=True`가 기본이며 private, loopback, link-local, multicast, reserved, unspecified 주소를 차단한다. loopback HTTP는 시험 profile에서만 허용한다.
- Python reference client의 검사와 실제 연결 사이에는 DNS TOCTOU 가능성이 남는다. 운영 배포에서는 고정 egress proxy, DNS pinning 또는 service mesh 정책으로 같은 allowlist를 집행해야 한다.

## 6. 의도적으로 포함하지 않은 운영 구성요소

다음은 보안상 중요하지만 외부 의존성이 없는 reference core가 안전하게 대신 구현할 수 없는 영역이다.

- 사용자 로그인·동의 browser UI와 callback HTTP endpoint
- JWKS cache, JWT 알고리즘 정책, 서명 검증 또는 RFC 7662 introspection client
- client 등록·secret 저장소와 Dynamic Client Registration/Client ID Metadata Document
- refresh token 암호화 저장·회전·폐기
- DPoP, mTLS sender-constrained token
- 분산 transaction/state store와 다중 instance replay 방지
- egress proxy에서의 DNS pinning과 실제 연결 IP 강제

따라서 현재 상태는 OAuth protocol guard와 token binding reference 구현 완료이며, 특정 IdP와 연결하는 production identity adapter 완료를 뜻하지 않는다.

## 7. 검증

`tests/test_mcp_oauth.py`는 실제 loopback HTTP Authorization Server fixture를 사용해 다음을 자동 검증한다.

- challenge와 scope parsing
- protected resource/issuer path discovery 순서
- resource·issuer mismatch와 S256 누락 차단
- credential URL, link-local SSRF, untrusted redirect 차단
- redirect hop 기본 차단과 opt-in hop 재검증
- redirect URI, state, PKCE, callback/code one-time binding
- token request의 resource·verifier·redirect 결합
- token endpoint redirect와 audience/actor/scope mismatch 차단
- access token 비노출과 `CredentialClaims.exchanged=True`

기준 명세는 [MCP Authorization 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization), [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices), [RFC 9728 OAuth Protected Resource Metadata](https://www.rfc-editor.org/rfc/rfc9728), [RFC 8707 Resource Indicators](https://www.rfc-editor.org/rfc/rfc8707), [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636)다.
