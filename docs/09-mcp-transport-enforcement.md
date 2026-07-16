---
title: Agent Interlock MCP Transport 집행 어댑터
tags: [agent-interlock, mcp, architecture, enforcement, json-rpc]
date: 2026-07-16
version: 1.1
status: implemented-reference
---

# Agent Interlock MCP Transport 집행 어댑터

## 1. 구현 결과

`MCPTransportAdapter`는 Architecture manifest에서 컴파일된 `REL-05 Agent → Tool` 정책과 실제 MCP JSON-RPC 메시지를 연결한다. 적용 기준은 최신 안정 MCP 명세 `2025-11-25`다.

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

`MCPTransportAdapter`는 HTTP 프레임워크나 subprocess 구현에 종속되지 않는다. 실제 wire 경계는 `MCPStreamableHTTPClient`와 `MCPStreamableHTTPGatewayCarrier`가 연결한다. Client는 downstream JSON·SSE 응답과 session을 처리하고, Gateway Carrier는 inbound HTTP 보안과 MCP lifecycle을 종료한 뒤 Tool 메시지만 Adapter로 전달한다.

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

## 2. MCP 명세 대응

공식 [MCP Tools 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)와 [Transports 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)를 기준으로 다음 계약을 적용한다.

| 명세 계약 | 구현 |
|---|---|
| JSON-RPC 2.0 단일 메시지 | batch 거부, UTF-8/JSON/크기 검증 |
| `tools/list`, pagination | page·Tool 수 제한, cursor loop 차단, 전체 refresh |
| Tool name 1–128자 권고 문자 집합 | `[A-Za-z0-9_.-]` profile 강제 |
| `inputSchema` object | null/비객체 거부 |
| `outputSchema`와 `structuredContent` | Result Guard에서 structured content 검증 |
| `notifications/tools/list_changed` | 전달 전 전체 목록 재조회와 drift/삭제 격리 |
| Tool annotation 비신뢰 | 승인 digest에 포함하고 승인 전 모델 비노출 |
| Tool 결과 비신뢰 | secret 정제, schema 격리, `UNTRUSTED_TOOL_RESULT` taint |
| Streamable HTTP POST | 요청마다 독립 POST, JSON 응답과 SSE 응답 모두 수신 |
| HTTP `Accept` | inbound·downstream에서 JSON과 SSE media type 계약 검증 |
| `MCP-Protocol-Version` | initialize 이후 `2025-11-25`만 허용 |
| `MCP-Session-Id` | initialize 응답에서만 수립, 후속 요청 binding, 404 시 재실행 없이 만료 |
| SSE event | UTF-8, event ID, retry, event 수·응답 ID 검증 |
| `Origin`과 `Host` | inbound allowlist, 불일치 시 403/421 |
| HTTP 인증 | inbound principal과 trusted context 결합, downstream credential과 분리 |

`icons`, `execution`, `_meta` 등 추가 Tool 필드는 digest에는 포함하지만 기본 model-visible D1에서는 제거한다. 승인 이후 하나라도 바뀌면 새로운 revision이 되어 `DRIFTED`로 차단된다. Client request의 `params._meta`도 D3 밖의 우회 egress가 될 수 있으므로 기본 거부하며, `MCPServerProfile.allowed_request_meta_keys`에 명시된 키만 전달한다. 허용된 metadata에서도 credential-like 값은 차단한다.

## 2.1 Wire carrier 보안 기본값

- downstream endpoint는 HTTPS만 허용한다. 명시적 port의 loopback HTTP는 test profile에서만 허용한다.
- HTTP redirect는 자동 추적하지 않는다. OAuth·authorization redirect는 다음 Identity Guard 단계에서 별도 검증한다.
- inbound bearer는 인증 후 `MCPHTTPPrincipal`로 바뀌며 downstream 요청에 복사되지 않는다.
- downstream Authorization은 별도 `authorization_provider`에서만 가져온다.
- timeout, request/response byte, SSE event 수를 제한하며 자동 retry하지 않는다.
- reference HTTP server는 기본적으로 loopback에만 bind한다. 외부 공개 시 TLS reverse proxy와 distributed lifecycle store가 필요하다.

Tool 호출 timeout은 차단 성공을 의미하지 않는다. 요청이 downstream에 도착한 뒤 응답만 끊겼을 수 있으므로 carrier는 mutation을 자동 재시도하지 않고 Gateway에 `UNKNOWN` outcome을 남긴다. 최종 상태는 idempotency key, downstream receipt와 reconciliation으로 확인해야 한다.

## 3. Architecture에서 실제 집행으로 연결

`bind_compiled_architecture()`는 다음 조건을 모두 만족해야 Tool을 활성화한다.

1. Tool이 실제 `tools/list`에서 관측됐다.
2. Architecture Tool node의 `definitionDigest`가 관측 digest와 정확히 일치한다.
3. revision 상태가 `DISCOVERED`, `APPROVED`, `ACTIVE` 중 하나다. poisoning으로 `QUARANTINED`된 정의는 자동 승인하지 않는다.
4. Tool node를 대상으로 하는 `REL-05` edge가 존재한다.
5. Architecture lint가 `MCP_GATEWAY/ENFORCED`와 `AUDIT_SINK` control을 통과했다.

여러 Tool을 한 번에 bind할 때 모든 항목을 먼저 검증한다. digest mismatch나 edge 누락이 있으면 activation 전에 전체 요청을 거부한다. `REL-07 Tool → External`이 선언된 경우 External node의 domain allowlist를 Tool 호출의 유효 destination 경계에 합성한다.

## 4. 호출 시 보안 순서

`tools/call`마다 `tools/list`를 전체 재조회한다. 마지막 목록만 믿지 않기 때문에 승인 뒤 definition 변경 또는 삭제가 실제 dispatch 전에 발견된다.

```text
trusted Host context + tools/call D3
  → current D1 refresh
  → ACTIVE + pinned digest 확인
  → schema / purpose / data class / destination / side effect / approval 평가
  → argument hash와 decision 결합
  → downstream tools/call
  → content + structuredContent secret 정제
  → outputSchema 검증
  → _meta.interlock evidence 반환
```

`MCPInvocationContext`는 tenant, source actor, purpose, data class, destination, 예상 side effect, approval, credential claims를 담는다. 이 값은 MCP Server 응답이나 Tool description에서 추론하지 않는다. `MCPServerProfile.tenant_id`도 `server_id` 문자열에서 추론하지 않고 명시하며, 호출 tenant와 다르면 `INTERLOCK-TENANT-MISMATCH`로 차단한다. Host의 신뢰 실행 문맥이 없으면 `INTERLOCK-TRUSTED-CONTEXT-MISSING`으로 fail closed한다.

정책 차단은 JSON-RPC error `-32001`과 안정적인 reason code로 반환한다. downstream receipt는 정책이 `ALLOW`일 때만 생성된다. `SHADOW`에서는 위험 판정을 기록하되 기존 Gateway 의미대로 실행할 수 있으므로 production carrier는 Architecture policy mode를 명시적으로 확인해야 한다.

## 5. 사용법

전체 실행 예제:

```bash
PYTHONPATH=src python3 examples/mcp_transport_vertical_slice.py
```

핵심 API:

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

실제 downstream HTTP 연결:

```python
client = MCPStreamableHTTPClient(
    MCPStreamableHTTPClientConfig(endpoint="https://mcp.example.com/mcp"),
    authorization_provider=downstream_credential_provider,
)
client.initialize()
adapter = MCPTransportAdapter(gateway, server_profile, client.call)
client.set_server_message_handler(adapter.handle_server_message)
```

실제 inbound endpoint:

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

Tool 승인 절차는 `tools/list → observed digest 확인 → reviewed manifest pin → compile → bind` 순서다. 처음 관측된 `DISCOVERED` Tool은 모델에 보이지 않는다.

## 6. 검증 범위

`tests/test_mcp_transport.py`가 다음을 자동 검증한다.

- 승인 전 Tool 비노출과 exact digest activation
- architecture digest mismatch 시 상태 불변
- 정상 `tools/call`의 정책·Result Guard·Ledger 통과
- definition drift와 Tool 삭제의 dispatch 전 차단
- D3 secret 차단과 downstream receipt 0
- `structuredContent` output schema 오류 격리
- D4 secret redaction과 taint
- trusted context 누락 및 JSON-RPC batch 차단
- cross-tenant invocation context 차단
- allowlist 밖 request `_meta`를 통한 argument policy 우회 차단

`tests/test_mcp_http.py`와 `tests/mcp_http_fixture.py`는 실제 loopback HTTP socket에서 다음을 추가 검증한다.

- initialize → initialized lifecycle과 protocol version 협상
- session header 수립·후속 요청 binding·404 만료
- JSON 응답, POST SSE 응답, GET SSE notification
- redirect 미추적, timeout/response size 경계
- Origin·Host·authentication·Accept·content type 검증
- authenticated principal과 trusted invocation context 결합
- inbound/downstream bearer 분리와 token passthrough 0
- 실제 HTTP 경로에서 Tool drift dispatch 0

## 7. 남은 운영 경계

현재 carrier를 production 운영과 나머지 실행 경계로 확장하려면 다음이 필요하다.

1. platform별 production OS sandbox backend와 signed attestation verifier
2. persistent Definition Registry·PostgreSQL Ledger와 OTLP Collector export
3. inbound GET SSE 송신, resumable event store와 multi-instance lifecycle/session store
4. server-initiated request, 비동기 task, cancellation/replay 정책

공식 [MCP Authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)과 [Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)가 금지하는 token passthrough는 [10 OAuth Identity Guard](10-mcp-oauth-identity-guard.md)가 discovery·token exchange 단계부터 차단한다. stdio process와 sandbox attestation은 [11 stdio Sandbox·Receipt](11-mcp-stdio-sandbox-receipts.md)를 따른다.

downstream Client는 POST SSE와 GET SSE를 수신할 수 있다. inbound reference Server는 동기 JSON 응답만 반환하고 GET SSE에는 405를 반환한다. 이는 명세가 허용하는 non-listening endpoint 동작이지만 server push가 필요한 배포는 resumable SSE event store를 추가해야 한다. server-initiated JSON-RPC request는 현재 fail closed한다.
