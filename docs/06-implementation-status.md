---
title: Agent Interlock 구현 상태
date: 2026-07-16
version: 0.4.0
status: active
---

# Agent Interlock 구현 상태

이 문서는 설계 계약과 현재 코드 사이의 추적표다. 구현되지 않은 항목을 완료된 것처럼 간주하지 않도록 release마다 갱신한다.

## 구현 기준

- 언어: Python 3.11
- 배포 형태: 외부 의존성이 없는 reference core + optional psycopg PostgreSQL adapter
- 기준 명세: `03`–`05` version 1.1
- 구현 모드: 메모리 Registry, 메모리/PostgreSQL Ledger와 동기 Connector

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
| PostgreSQL Ledger adapter·hash 재검증 | `PostgreSQLLedger` | 실제 psycopg append·replay·query live 시험 |
| Event ingest·trace query HTTP API | `LedgerHTTPAPI`, `ledger-api.openapi.yaml` | 실제 socket tenant·scope·idempotency·pagination 시험 |
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
| stdio JSONL·process lifecycle carrier | `MCPStdioClient` | 실제 subprocess lifecycle·noise·size·timeout·group kill 시험 |
| stdio artifact·sandbox attestation binding | `StdioSandboxProfile`, `MCPStdioServerCaller` | digest mismatch·backend 누락·Architecture binding 시험 |
| Fake external receipt·reconciliation | `FakeExternalReceiptStore`, contextual Connector | receipt 0/1·hidden egress·idempotency·compensation 시험 |
| L1-SIM M1–M9 matrix·canary corpus·불변식 runner | `tests/test_l1_matrix.py`, `tests/l1_harness.py` | 34 test ID(22 구현·12 명시적 skip), TEST_EXECUTED SIMULATION |
| M9 volume/DLP 사전 차단 | `policy.py` `max_export_records`/`max_export_bytes` | `L1-SIM-M9-003` 사전 BLOCK 시험 |
| Canonical keyed 서명 helper | `signing.py` `sign_canonical`/`verify_canonical` | round-trip·tamper·wrong-key 시험 |
| Signed Audit Sink evidence | `audit_sink.py` `SignedAuditSink` | seal·verify·integrity·swap 거부 시험 |
| OTLP/HTTP JSON receiver | `ledger_http.py` `POST /v1/traces` | 실제 socket OTLP decode·context 누락·scope 시험 |
| 서명 sandbox attestation verifier | `mcp_stdio.py` `sign_attestation`·`AttestationVerifier` | 서명·wrong-key·미서명·tamper·client 강제 시험 |
| Inbound resumable SSE·SessionStore | `mcp_http.py` `SessionStore`·`InMemorySessionStore` | 세션 발급·READY·Last-Event-ID replay·multi-instance·DELETE 시험 |
| RFC7662 introspection verifier·OAuth TransactionStore | `mcp_oauth.py` `MCPTokenIntrospectionVerifier`·`InMemoryOAuthTransactionStore` | active/claim 매핑·client-auth·SSRF·one-time consume 시험 |
| Studio compile → SHADOW 배포 번들 | `__main__.py` `architecture compile --shadow` | golden 라운드트립·SHADOW 강제·digest·CRITICAL 리뷰 게이트 시험 |
| M7 agent-config guard (read·deploy·drift) | `config_guard.py` `ConfigGuard`·`InMemoryConfigStore`·`RuntimeConfigProbe` | role 최소화·2인 서명 배포·CAS·drift·M7-001..004 매트릭스 시험 |
| JWKS/JWT 서명 verifier (optional `jwt` extra) | `mcp_jwt.py` `MCPJWKSVerifier` | RS256/ES256/EdDSA 검증·alg 혼동 거부·kid·exp/nbf/iss 시험 |
| Loopback OAuth consent | `oauth_consent.py` `LoopbackCallbackReceiver`·`run_consent` | 콜백 캡처·one-time·timeout·loopback-only 시험 |
| Bubblewrap OS sandbox backend | `mcp_stdio.py` `BubblewrapSandboxBackend` | argv 구성·정직한 attestation 비트(fs/net True, child False)·child-거부 fail-closed·unsafe mount 거부·서명 시험 |

## 현재 자동화된 L1 범위

`tests/test_core.py`는 M1 metadata instruction, M2 definition drift, M3 cross-server reference, M5 token mismatch/passthrough, M6 authorization URL, M8 인수·결과 secret, M9 Unicode 목적지·미선언 부작용·사후 egress를 검증한다. 정상 호출, SHADOW 비집행, 승인 binding, idempotency도 함께 검증한다. `tests/test_architecture.py`는 Architecture compile, 보안 lint, Dynamic Edge와 runtime drift를 검증한다. `tests/test_mcp_transport.py`는 실제 MCP JSON-RPC D1/D3/D4 경계, exact digest binding, drift·삭제, trusted context와 dispatch 0을 검증한다. `tests/test_mcp_http.py`는 로컬 실제 HTTP socket으로 lifecycle, JSON/SSE, session, Origin, 인증, timeout, redirect와 token 분리를 검증한다. `tests/test_mcp_oauth.py`는 실제 OAuth HTTP fixture로 protected resource/AS discovery, PKCE, SSRF, redirect, callback replay와 token claim binding을 검증한다. `tests/test_mcp_stdio.py`와 `tests/test_receipts.py`는 실제 subprocess stdio 경계와 외부 전송 없는 transaction reconciliation을 검증한다. `tests/test_ledger_http.py`와 `tests/test_postgres_ledger.py`는 event/trace API와 DB role tenant binding을 검증하며, PostgreSQL 16 live 시험은 DSN이 있는 CI에서 실행된다.

`tests/test_l1_matrix.py`는 [05 검증 계획](05-l1-security-validation-plan.md)의 L1-SIM-M1..M9 34개 test ID를 SIMULATION으로 자동화한다(22개 구현, 12개는 담당 workstream으로 명시적 skip). 전체 matrix 완료는 아니며, 다음 항목은 아직 통합 fixture나 신규 서브시스템이 필요하다.

- BubblewrapSandboxBackend live 실행 시험(Linux+bwrap+런타임 클로저 필요, argv·attestation은 단위 검증됨)과 seccomp 기반 child-process 강제(현재는 정직하게 child=False, `allow_child_processes=False` 프로파일 거부)
- M4 per-destination network egress allowlist(bwrap는 network namespace 전체 격리라 all-or-nothing)과 M5-002 downscope·M5-004 state replay의 matrix 편입
- PostgreSQL CORE-SIM-TENANT 전체 CI와 자동 partition/retention 운영
- streaming OTLP gRPC(:4317)와 vendor(Langfuse/LangSmith) trace adapter, Incident/response service
- Studio의 저장소·Git review·policy deployment 연동

## 다음 구현 순서

doc-06 §다음 순서의 10개 통합 항목을 모두 구현했다: (a) M1–M9 test ID 자동화와 canary corpus, (b) canonical 서명 helper, (c) OTLP/HTTP JSON receiver와 signed Audit Sink, (d) 서명 sandbox attestation verifier, (e) inbound resumable SSE와 SessionStore, (f) RFC7662 introspection verifier와 OAuth TransactionStore, (g) Studio `compile --shadow`, (h) M7 agent-config guard, (i) JWKS/JWT verifier(optional `jwt` extra)와 loopback consent, (j) Bubblewrap OS sandbox backend.

남은 것은 프로덕션 인프라·플랫폼 연동이다.

1. 분산 SessionStore/OAuth TransactionStore/ConfigStore backend(Redis/Postgres)와 studio 저장소·Git review·remote deploy 연동
2. BubblewrapSandboxBackend Linux live 시험과 seccomp child-process 강제, macOS Seatbelt backend
3. optional gateway config-guard preflight(기본 비활성)과 M4 per-destination egress·M5-002/004 matrix 편입
