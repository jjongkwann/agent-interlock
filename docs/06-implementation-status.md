---
title: Agent Interlock 구현 상태
date: 2026-07-16
version: 0.2.0
status: active
---

# Agent Interlock 구현 상태

이 문서는 설계 계약과 현재 코드 사이의 추적표다. 구현되지 않은 항목을 완료된 것처럼 간주하지 않도록 release마다 갱신한다.

## 구현 기준

- 언어: Python 3.11
- 배포 형태: 외부 의존성이 없는 reference core
- 기준 명세: `03`–`05` version 1.1
- 구현 모드: 메모리 Registry/Ledger와 동기 Connector

## 계약 추적

| 계약 | 구현 | 검증 |
|---|---|---|
| Actor `define` / `connect` / `wrap` | `src/agent_interlock/sdk.py` | `SDKTests` |
| 정적 설계·단일 trace graph 데이터 | `Interlock.design_graph`, `runtime_graph` | `test_define_connect_wrap_and_graph` |
| Canonical/raw definition digest | `canonical.py`, `registry.py` | `CanonicalizationTests`, `RegistryTests` |
| Definition 상태와 digest pin | `DefinitionRegistry` | M2 drift 회귀 시험 |
| D1 metadata instruction·cross-server reference | `DefinitionRegistry._inspect` | M1·M3 회귀 시험 |
| D3 schema·secret·목적지·부작용 판정 | `policy.py`, `security.py` | M8·M9 회귀 시험 |
| Token audience/resource/actor binding·passthrough 금지 | `policy.py` | M5 회귀 시험 |
| Hash·destination-bound 승인 | `MCPToolGateway.grant_approval` | 승인 변경 회귀 시험 |
| Hash-bound·멱등 Connector 실행 | `execute_approved_call` | mutation·중복 실행 회귀 시험 |
| Result secret 정제·taint·schema 검사 | `inspect_result` | result D5 회귀 시험 |
| 사후 receipt reconciliation | `reconcile_transaction` | 미선언 egress 회귀 시험 |
| 판정·집행·결과 분리 이벤트 | `InMemoryLedger`, `gateway.py` | 이벤트 순서·무결성 시험 |
| PostgreSQL partition·RLS·append-only | `migrations/postgresql` | PostgreSQL 16 임시 DB 적용 검증 |
| Architecture-as-Code manifest | `architecture.py`, `architecture.schema.json` | `ArchitectureModelTests` |
| 보안 보장 수준과 Architecture lint | `ArchitectureLinter` | `ArchitectureSecurityLintTests` |
| Dynamic Sub-Agent Edge 계약 | `DynamicTargetSelector` | dynamic instance 회귀 시험 |
| Design/Runtime drift·bypass 비교 | `compare_runtime` | `RuntimeGraphDiffTests` |
| 박스 기반 보안 설계 편집기 | `studio/app/page.tsx` | Studio build·rendered HTML 계약 시험 |
| Ledger·OTLP JSON runtime import | `telemetry.py`, `studio/app/runtime.ts` | `RuntimeTelemetryImportTests`, Studio parser 시험 |
| Runtime Graph·Drift reconciliation 화면 | `studio/app/page.tsx` | OTLP drift demo·render 시험 |
| MCP JSON-RPC Tool transport 집행 | `mcp_transport.py` | `MCPTransportVerticalSliceTests` |
| Architecture exact digest runtime binding | `bind_compiled_architecture` | mismatch·drift·삭제 회귀 시험 |
| Streamable HTTP JSON/SSE downstream client | `mcp_http.py` | lifecycle·session·SSE·redirect·size 시험 |
| Inbound MCP HTTP 보안 carrier | `MCPStreamableHTTPGatewayCarrier` | 실제 socket Origin·auth·token 분리 시험 |
| OAuth Protected Resource·AS discovery | `mcp_oauth.py` | well-known 순서·resource/issuer mismatch 시험 |
| PKCE·redirect·token resource binding | `MCPAuthorizationCodeFlow`, `MCPAuthorizationCodeTokenClient` | 실제 OAuth fixture·SSRF·replay·audience 시험 |

## 현재 자동화된 L1 범위

`tests/test_core.py`는 M1 metadata instruction, M2 definition drift, M3 cross-server reference, M5 token mismatch/passthrough, M6 authorization URL, M8 인수·결과 secret, M9 Unicode 목적지·미선언 부작용·사후 egress를 검증한다. 정상 호출, SHADOW 비집행, 승인 binding, idempotency도 함께 검증한다. `tests/test_architecture.py`는 Architecture compile, 보안 lint, Dynamic Edge와 runtime drift를 검증한다. `tests/test_mcp_transport.py`는 실제 MCP JSON-RPC D1/D3/D4 경계, exact digest binding, drift·삭제, trusted context와 dispatch 0을 검증한다. `tests/test_mcp_http.py`는 로컬 실제 HTTP socket으로 lifecycle, JSON/SSE, session, Origin, 인증, timeout, redirect와 token 분리를 검증한다. `tests/test_mcp_oauth.py`는 실제 OAuth HTTP fixture로 protected resource/AS discovery, PKCE, SSRF, redirect, callback replay와 token claim binding을 검증한다.

이는 [05 검증 계획](05-l1-security-validation-plan.md)의 전체 M1–M9 matrix 완료를 뜻하지 않는다. 특히 다음 항목은 통합 fixture가 필요하다.

- inbound resumable GET SSE 송신과 multi-instance session/lifecycle store
- IdP별 JWT/JWKS 또는 introspection verifier와 browser consent adapter
- process/filesystem/network Connector sandbox
- RAG/config/file canary corpus와 fake external receipt store
- PostgreSQL Ledger adapter와 CORE-SIM-TENANT 전체 CI
- HTTP API, streaming OpenTelemetry Collector adapter, Incident/response service
- Studio의 저장소·Git review·policy deployment 연동

## 다음 구현 순서

1. stdio Connector sandbox와 fake external receipt store
2. PostgreSQL Ledger adapter와 `/v1/events`, trace query API
3. `05`의 M1–M9 전체 test ID 자동화
4. Studio export → review → compile → SHADOW 배포 workflow
5. OTLP Collector receiver와 signed Audit Sink evidence 검증
6. inbound resumable SSE와 multi-instance session store
7. production IdP verifier·browser consent·분산 OAuth transaction store
