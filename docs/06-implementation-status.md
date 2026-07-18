---
title: Agent Interlock 구현 상태
date: 2026-07-17
version: 0.7.0
status: active
---

# Agent Interlock 구현 상태

이 문서는 설계 계약과 현재 코드 사이의 추적표다. 구현되지 않은 항목을 완료된 것처럼 간주하지 않도록 release마다 갱신한다.

## 구현 기준

- 언어: Python 3.11
- 배포 형태: 외부 의존성이 없는 reference core + optional psycopg PostgreSQL adapter
- 기준 명세: `03`–`05` version 1.1
- 구현 모드: 메모리 Registry, 메모리/PostgreSQL Session·OAuth·Config Store, 메모리/PostgreSQL Ledger와 동기 Connector

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
| L1-SIM M1–M9 matrix·canary corpus·불변식 runner | `tests/test_l1_matrix.py`, `tests/l1_harness.py` | 34 test ID 전부 실행, TEST_EXECUTED SIMULATION |
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
| Publisher provenance admission | `supply_chain.py` `ArtifactAdmissionPolicy`·`MCPServerProfile` binding | untrusted/unsigned·repository·tamper 격리, server call 0, signed control 시험 |
| 목적지별 egress broker | `egress.py` `DestinationEgressGuard`·`compile_destination_egress_policy` | tenant/workload/artifact/provenance/sandbox exact binding, deny socket 0·kill, allow receipt 1 시험 |
| 분산 PostgreSQL Session/OAuth/Config store | `postgres_stores.py` `PostgreSQLSessionStore`·`PostgreSQLOAuthTransactionStore`·`PostgreSQLConfigStore`, `migrations/postgresql/0002` | RLS·revision 불변 trigger 계약, 직렬화 round-trip·tamper 거부, CAS stale, DSN 게이트 multi-instance live 시험 |
| Gateway config-guard preflight (opt-in) | `gateway.py` `_config_preflight` | 기본 비활성, drift → QUARANTINE 합성, guard 자체 CONTROL_EVALUATED trace 시험 |
| Seatbelt OS sandbox backend (macOS) | `mcp_stdio.py` `SeatbeltSandboxBackend` | policy 구성·정직 비트(fs/net/child 전부 집행 시 True)·unsafe path·SBPL 주입 거부·서명 + **macOS live 집행 시험**(홈/쓰기/fork/네트워크 차단) |
| 실 소켓 egress backend (DNS·IP pinning) | `egress.py` `PinnedSocketEgressBackend` | DNS 1회 해석·연결 IP 고정·peer 검증·비전역 주소 fail-closed·one-time 소켓 handoff, 실 127.0.0.1 fixture 시험 |
| 비대칭 publisher 서명 검증 (KMS 어댑터 지점) | `supply_chain.py` `PublisherVerifier`·`Ed25519PublisherVerifier`·`HMACPublisherVerifier`, `signing.py` `sign/verify_canonical_ed25519` | Ed25519 승인·교차키 거부·tamper·KMS 스타일 커스텀 verifier·HMAC 하위호환 시험 |
| bwrap seccomp child-process 강제 (Linux) | `mcp_stdio.py` `build_no_subprocess_seccomp`·`BubblewrapSandboxBackend(seccomp_child_denial=True)` | fork/vfork/clone3·비스레드 clone→EPERM, 스레드 clone·execve→ALLOW BPF 시뮬 검증, child=True 정직 attest, **bwrap live CI 집행** |
| 분산 PostgreSQL DefinitionRegistry | `registry.py` `RevisionStore`·`InMemoryRevisionStore`, `postgres_stores.py` `PostgreSQLRevisionStore`, `migrations/postgresql/0003` | store 추출로 상태머신 단일화, RLS·identity 불변 trigger·digest 재검증·multi-node live 시험 |
| Langfuse/LangSmith trace 어댑터 | `vendor_telemetry.py` `langfuse_traces_to_otlp`·`langsmith_runs_to_otlp`·`import_*` | vendor metadata→OTLP 속성 매핑 후 import_runtime_telemetry 재사용, edge 재구성·불완전 컨텍스트 issue 시험 |
| WORM audit 보존 store | `audit_sink.py` `WORMAuditStore`·`InMemoryWORMAuditStore` | append-only·해시체인, write-once 중복 거부·삭제/치환/재정렬 chain 파손 탐지 시험 |
| Studio git 배포 워크플로 | `studio_deploy.py` `GitBundleStore`·`sign_deployment_approval` | 실 git repo propose→2인 서명 SHADOW→ENFORCE 승격→rollback, 단일승인·위조서명·digest tamper 거부 시험 |
| PostgreSQL live 프로비저닝 | `ci/docker-compose.postgres.yml`·`ci/postgres_provision.sql`·`ci/run_postgres_live.sh`, `.github/workflows/ci.yml` | postgres:16 + 0001-0003 migration + 2 tenant role 매핑, live store/ledger 6개 시험 실행 |
| artifact 검사–실행 TOCTOU 제거 (fd 실행) | `mcp_stdio.py` `_open_verified_artifact`·`SandboxLaunchPlan.executable_digest`, client `/proc/self/fd` exec | fd 위 digest 검증·변조/swap 거부·비정규 파일 거부, backend별 argv[0] pin, Linux CI에서 fd-exec 실행 |

## 현재 자동화된 L1 범위

`tests/test_core.py`는 M1 metadata instruction, M2 definition drift, M3 cross-server reference, M5 token mismatch/passthrough, M6 authorization URL, M8 인수·결과 secret, M9 Unicode 목적지·미선언 부작용·사후 egress를 검증한다. 정상 호출, SHADOW 비집행, 승인 binding, idempotency도 함께 검증한다. `tests/test_architecture.py`는 Architecture compile, 보안 lint, Dynamic Edge와 runtime drift를 검증한다. `tests/test_mcp_transport.py`는 실제 MCP JSON-RPC D1/D3/D4 경계, exact digest binding, drift·삭제, trusted context와 dispatch 0을 검증한다. `tests/test_mcp_http.py`는 로컬 실제 HTTP socket으로 lifecycle, JSON/SSE, session, Origin, 인증, timeout, redirect와 token 분리를 검증한다. `tests/test_mcp_oauth.py`는 실제 OAuth HTTP fixture로 protected resource/AS discovery, PKCE, SSRF, redirect, callback replay와 token claim binding을 검증한다. `tests/test_mcp_stdio.py`와 `tests/test_receipts.py`는 실제 subprocess stdio 경계와 외부 전송 없는 transaction reconciliation을 검증한다. `tests/test_ledger_http.py`와 `tests/test_postgres_ledger.py`는 event/trace API와 DB role tenant binding을 검증하며, PostgreSQL 16 live 시험은 DSN이 있는 CI에서 실행된다.

`tests/test_l1_matrix.py`는 [05 검증 계획](05-l1-security-validation-plan.md)의 L1-SIM-M1..M9 34개 test ID를 모두 SIMULATION으로 자동화한다. M4 publisher admission·목적지 egress deny/allow, M5 scope broadening·callback replay와 M6 private-IP redirect·response size·safe consent 경로도 독립 matrix 시험과 `TEST_EXECUTED` 증거를 남긴다. 다음 항목은 reference 검증 이후의 프로덕션 통합 경계다.

2026-07-17 기본 전체 회귀는 356개 test를 수집해 `OK (skipped=9)`다. 무설정 skip은 Linux+bwrap live(seccomp 포함 6개)와 DSN 없는 PostgreSQL live(6개) 계열이며, macOS + 실 postgres:16 + `cryptography`를 붙이면 skip은 bwrap-live 3개까지 줄고 나머지(분산 store·registry·ledger live 6개 포함)는 모두 실행된다. seccomp BPF 로직은 in-test classic-BPF 인터프리터로, 실 커널 집행은 CI `sandbox-live` job으로 검증한다.

- Sigstore/Rekor 네트워크 검증(비대칭 서명·KMS 어댑터 지점은 구현됨)과 실제 egress proxy/sidecar sidecar의 socket·kill telemetry 운영 배선(DNS·연결 IP pinning은 `PinnedSocketEgressBackend`로 구현됨)
- OTLP gRPC(:4317) streaming receiver(HTTP JSON receiver와 Langfuse/LangSmith 어댑터는 구현됨), Incident/response service
- PostgreSQL 자동 partition/retention 운영과 connection pool·HA(live CI·프로비저닝은 구현됨)
- WORM 보존의 S3 Object-Lock 내구 backend(Protocol·append-only 해시체인 impl은 구현됨), 원격 Git host PR 리뷰 배선(로컬 git propose/promote/rollback은 구현됨)
- 고급 MCP 비동기 task·cancellation, IdP key rotation·DPoP/mTLS sender-constrained token

## 다음 구현 순서

doc-06 §다음 순서의 10개 통합 항목을 모두 구현했다: (a) M1–M9 test ID 자동화와 canary corpus, (b) canonical 서명 helper, (c) OTLP/HTTP JSON receiver와 signed Audit Sink, (d) 서명 sandbox attestation verifier, (e) inbound resumable SSE와 SessionStore, (f) RFC7662 introspection verifier와 OAuth TransactionStore, (g) Studio `compile --shadow`, (h) M7 agent-config guard, (i) JWKS/JWT verifier(optional `jwt` extra)와 loopback consent, (j) Bubblewrap OS sandbox backend.

이후 다음 프로덕션 통합 항목을 추가로 구현했다: 분산 PostgreSQL store(Session/OAuth/Config `0002`, DefinitionRegistry `0003`), opt-in gateway config-guard preflight, macOS Seatbelt·Linux bwrap seccomp sandbox(live 집행), 실 소켓 egress backend(DNS·IP pinning), 비대칭 publisher 서명(Ed25519·KMS 지점), Langfuse/LangSmith trace 어댑터, WORM audit store, Studio git 배포(propose→2인 승격→rollback), PostgreSQL live CI 프로비저닝과 GitHub Actions.

남은 것은 두 갈래다. 하나는 외부 서비스·인프라 없이 이 저장소 안에서 구현 가능한 **내부 구현 작업**, 다른 하나는 외부 SaaS·서비스·플랫폼과의 **연동 작업**이다.

**내부 구현 작업 (저장소 안에서 가능):**

1. 장기 process supervisor와 sandbox health telemetry
2. OTLP semantic convention 버전 호환 어댑터, sampling 누락·Audit Sink 장애를 `CONTROL_HEALTH_CHANGED`로 연결
3. MCP server-initiated request, 비동기 task와 cancellation/replay 정책
4. PostgreSQL migration runner 정리와 자동 partition/retention job, connection pool/factory
5. WORM store의 파일 기반 append-only 영속화(S3 이전 단계)

(완료: artifact digest 검사와 exec 사이 TOCTOU 제거 — fd 실행)

**외부 연동 작업 (외부 서비스·플랫폼 필요):**

1. Sigstore/Rekor 네트워크 검증, 외부 KMS/HSM key 발급·회전·폐기, 프로덕션 IdP·Secret Store 연동
2. 실 egress sidecar의 socket 전달·차단·kill telemetry, S3 Object-Lock 기반 내구 WORM export
3. OTLP gRPC(:4317) streaming receiver·Collector queue/backpressure, Incident/response service
4. PostgreSQL HA·failover·distributed rate limit·TLS termination
5. 원격 GitHub/GitLab PR 리뷰·배포 연결
6. IdP JWKS cache·key rotation·장애 정책, DPoP/mTLS sender-constrained token, 운영 consent UI·HTTPS callback·refresh-token 수명주기

gVisor·Kata·Kubernetes sandbox backend는 Bubblewrap/Seatbelt를 대체해야 하는 배포 환경에서만 필요한 선택 항목이다.
