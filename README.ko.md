# Agent Interlock

> English version: [README.md](README.md)

> Define actors. Secure interactions. See the whole graph.

[![CI](https://github.com/jjongkwann/agent-interlock/actions/workflows/ci.yml/badge.svg)](https://github.com/jjongkwann/agent-interlock/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

Agent Interlock는 AI Agent 시스템의 Actor를 선언적으로 정의하고, 각 Actor의 외부를 SDK·Proxy로 감싸며, Actor 간 통신과 데이터 이동을 관측·판정·차단하는 **Agentic AI Security Framework**다. 안전공학의 interlock — 선언된 조건이 충족되지 않으면 동작 자체가 불가능한 장치 — 를 Agent 간 상호작용에 적용한다: 선언된 경로만 연동을 허가하고, ENFORCE 승격에는 서명된 2인 승인을 요구하며, 모든 판정을 append-only Ledger에 남긴다.

도입 계층(adoption layer)은 이것이 실제 Agent에 닿는 경로다: Anthropic Tool Runner adapter로 자신의 Tool을 guard하고, Architecture manifest에서 실행 가능한 프로젝트 모듈을 생성하고, 배포하기 전에 프레임워크의 fixture가 아니라 자신의 프로젝트에 대고 `interlock verify`를 실행한다.

## 무엇을 막는가

MCP·Tool 위협 M1–M9 전체를 데이터 흐름 단위로 집행한다. 각 위협의 상세 명세는 [docs/03 §6](docs/03-l1-mcp-tool-security-profile.ko.md), 재현 시나리오와 34개 추적 ID는 [docs/05](docs/05-l1-security-validation-plan.ko.md)·`tests/test_l1_matrix.py`에 있다.

| ID | 위협 | 공격자가 조작하는 것 | 기본 판정 |
|---|---|---|---|
| `M1` | Tool Poisoning | Tool description/schema 속 숨은 지시 | `QUARANTINE`/`BLOCK` |
| `M2` | Rug Pull | 승인 뒤 정의·endpoint·command 교체 | `QUARANTINE` |
| `M3` | Tool Shadowing | 다른 Server/Tool을 조종하는 설명 | `BLOCK`/`HOLD` |
| `M4` | Poisoned Tool Publish | package/image/Remote MCP 자체 | `QUARANTINE` |
| `M5` | Confused Deputy / Token Passthrough | 토큰의 audience·scope·사용 주체 | `BLOCK` |
| `M6` | MCP Server → Host Compromise | auth URL·redirect·result payload | `BLOCK`/`KILL` |
| `M7` | Agent Config Discovery/Modification | Agent 구성 열거·수정 | `BLOCK`/`CHALLENGE` |
| `M8` | Credential Harvesting | RAG/구성/결과 속 자격증명 | `SANITIZE`/`BLOCK` |
| `M9` | Data Exfiltration | 호출 목적지·업무 데이터 payload | `BLOCK`/`HOLD` |

판정은 관측(OBSERVE) → 그림자 집행(SHADOW) → 실집행(ENFORCE)으로 단계 승격하며, 차단뿐 아니라 증거를 남긴다: 모든 상호작용은 요청·판정·조치·결과가 분리된 이벤트로 Ledger에 기록되고, 설계 그래프와 런타임 trace의 drift가 비교된다.

## 빠른 시작

저장소 루트에서 Python 3.11+ 가상환경을 만들고 adapter를 설치한 다음 예제를 실행한다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[anthropic,jwt]'
python examples/secure_email.py
interlock architecture lint examples/secure_multi_agent_architecture.json
interlock architecture compile examples/secure_multi_agent_architecture.json --shadow > bundle.json
```

로컬 email 예제는 외부 부작용이 없다. 실제 Claude Tool Runner를 실행하려면 `ANTHROPIC_API_KEY`를 설정한 뒤 실행한다.

```bash
python -m examples.support_agent.run "Where is order 1001? Email the customer."
```

실행 시 Anthropic API를 호출한다. API 키 없이 녹화된 호출을 재생하려면 같은 저장소 루트에서 시험을 실행한다.

```bash
python -m pip install pytest
python -m pytest -q tests/test_example_support_agent.py tests/test_platform_e2e.py tests/test_run_control.py
```

Studio는 저장소 루트에서 별도 터미널을 열어 실행한다(Node 22.13+).

```bash
cd studio
npm ci
npm run dev
```

Studio에서 설정만으로 만들고 실행하려면 [Studio builder 시작 가이드](docs/studio-builder.ko.md)를 따른다. `interlock serve --data-dir PATH --origin http://localhost:3102`로 로컬 host를 준비하면 JSON 변환, 고정 HTTPS JSON 요청, Anthropic 도구 사용 agent를 구성하고 컴파일·브라우저 서명·배포·실행할 수 있다. Model task는 명시적으로 선택한 여러 도구를 사용할 수 있으며, 임의의 업무 코드나 다른 protocol에는 별도 adapter가 필요하다. 여러 실행 서버는 [원격 worker 운영 가이드](docs/distributed-workers.ko.md)에 따라 `--dispatch remote`와 `interlock worker`로 연결한다.

기존 Python agent를 보호하려면 [SDK 도입](docs/16-adding-interlock-to-an-agent.ko.md), 직접 작성한 업무 도구와 PostgreSQL을 연결하려면 [managed support host](docs/managed-support-host.md)를 따른다.

## 제품 구성

| 구성요소 | 역할 |
|---|---|
| Interlock SDK | ActorSpec 선언, 기존 코드 wrap, trace·event 생성 — **및 집행**: `wrap()`이 gateway의 check 21개 중 19개를 in-process로 실행하고 `ENFORCE`에서는 `GatewayError`를 raise한다 |
| Interlock Runtime | Actor 간 통신 가로채기와 정책 집행 |
| Interlock Orchestrator | 검증된 Task DAG와 A2A·MCP·Human transport 실행 |
| Interlock A2A Broker | Agent Card·Task 처리와 REL-06·Trust Boundary 사전 집행 |
| Interlock Ledger | 요청·데이터 흐름·판정·조치·결과 저장 |
| Interlock Graph | 정적 관계·런타임 호출·공격 경로 시각화 |
| Interlock Studio | 편집기, 프로젝트(신규/열기/저장, manifest import), 통계, 배포, run |
| Interlock Adapter | Anthropic Tool Runner adapter: `guard_tools`/`bind_architecture`로 자신의 Tool을 guard |
| Interlock Verify | `interlock verify`가 자신의 프로젝트의 guarded tool에 L1 corpus를 실행 |

## 핵심 개념

```text
ActorSpec       Actor의 신원·능력·입출력·권한·부작용 선언
ActorGuard      Agent·Tool·RAG·Memory 코드를 감싸는 보안 Wrapper
InterlockLink   Actor 간 허용 관계
LinkPolicy      관계별 데이터·목적지·승인·예산·차단 정책
InteractionEvent 요청·데이터 흐름·판정·조치·결과 이벤트
InterlockLedger 보안 이벤트 원장
InterlockGraph  설계·실행·공격 경로 그래프
```

## 문서

- [외부 실행 복구](docs/effect-recovery.ko.md): 영수증 확인, 미실행 확정, 승인 보존 재개
- [모델 도구 사용 평가](docs/model-evaluation.ko.md): 선택·인수·순서·승인 판단·업무 성공의 독립 평가
- [Provider 운영 정책](docs/provider-operations.ko.md): 오류별 재시도·전환·차단과 호출 지연·사용량

- [`docs/00-document-map.md`](docs/00-document-map.ko.md): 문서별 책임, 권장 읽기 순서, ID와 변경 원칙
- [`docs/01-project-plan.md`](docs/01-project-plan.ko.md): 이벤트 DB, 탐지·차단 플랫폼, PostgreSQL DDL, 구현 로드맵
- [`docs/02-developer-framework-design.md`](docs/02-developer-framework-design.ko.md): SDK, Actor Wrapper, LinkPolicy, Graph 중심 개발자 경험
- [`docs/03-l1-mcp-tool-security-profile.md`](docs/03-l1-mcp-tool-security-profile.ko.md): L1 M1–M9의 데이터 흐름, 공격 예시, 관측·통제 매핑
- [`docs/04-mcp-tool-gateway-spec.md`](docs/04-mcp-tool-gateway-spec.ko.md): MCP Tool Gateway의 컴포넌트, 상태, 정책, 이벤트, API 계약
- [`docs/05-l1-security-validation-plan.md`](docs/05-l1-security-validation-plan.ko.md): M1–M9 공격 재현, 기대 판정, 증거, 운영 승격 기준
- [`docs/06-implementation-status.md`](docs/06-implementation-status.ko.md): 설계 계약과 현재 코드·시험 추적표
- [`docs/07-security-architecture-studio-design.md`](docs/07-security-architecture-studio-design.ko.md): 박스 기반 Architecture-as-Code와 Studio 사용법
- [`docs/08-runtime-telemetry-reconciliation.md`](docs/08-runtime-telemetry-reconciliation.ko.md): Ledger·OTLP 실행 trace와 Design/Runtime drift 계약
- [`docs/09-mcp-transport-enforcement.md`](docs/09-mcp-transport-enforcement.ko.md): Architecture manifest와 MCP JSON-RPC 집행을 연결하는 어댑터
- [`docs/10-mcp-oauth-identity-guard.md`](docs/10-mcp-oauth-identity-guard.ko.md): OAuth discovery, PKCE, SSRF/redirect와 token identity binding
- [`docs/11-mcp-stdio-sandbox-receipts.md`](docs/11-mcp-stdio-sandbox-receipts.ko.md): stdio process sandbox attestation과 fake external receipt reconciliation
- [`docs/12-postgresql-ledger-api.md`](docs/12-postgresql-ledger-api.ko.md): PostgreSQL RLS·append-only Ledger adapter와 event/trace API
- [`docs/13-a2a-orchestration-platform.md`](docs/13-a2a-orchestration-platform.ko.md): Trust Boundary에서 A2A Broker·Task workflow·오케스트레이션까지의 실행 계약
- [`docs/14-fake-platform-e2e-scenario.md`](docs/14-fake-platform-e2e-scenario.ko.md): 가짜 고객 데이터로 설계→승격→A2A→승인→MCP→증거·drift를 검증하는 전체 시나리오
- [`docs/16-adding-interlock-to-an-agent.md`](docs/16-adding-interlock-to-an-agent.ko.md): 기존 tool-사용 Agent를 guard된 Agent로 바꾸는 10분 경로
- [`docs/specs/2026-09-08-adoption-layer.md`](docs/specs/2026-09-08-adoption-layer.md): 도입 계층 설계와 결정 사항

## 기본 구현 전략

1. 단일 Agent 서비스에서 User→Agent, Agent→RAG, Agent→Tool, Agent→External 관측
2. PostgreSQL 기반 Interaction Ledger 구축
3. OBSERVE → SHADOW → ENFORCE 단계적 승격
4. ActorSpec·LinkPolicy를 코드와 manifest로 지원
5. 정적 설계 그래프와 런타임 trace 그래프 제공
6. 방향성 Trust Boundary와 A2A·Scheduler·Sandbox를 함께 compile하고 집행

## 현재 구현

문서의 최초 구현 순서에 맞춘 Python 3.11 reference core가 포함되어 있다. Core는 외부 런타임 의존성이 없고 adapter는 optional `postgres`, `anthropic`, `jwt` extra를 사용한다.

**SDK·Gateway 정책 코어**

- `ActorSpec`, `LinkPolicy`, `define_actor()`, `connect()`, `wrap()` SDK
- MCP Tool 정의 canonical/raw digest와 `DISCOVERED` → `APPROVED` → `ACTIVE` 상태 전이
- definition drift, metadata instruction, cross-server reference 격리
- 호출 인수 schema, 데이터 등급, secret, 목적지, token binding, 선언 부작용 정책
- Gateway와 SDK의 일회성 호출 승인: tenant, source/target, definition revision, 설치된 policy, intent, 정확한 인자에 결합하고 실행 직전에 원자적으로 소비한다. [docs/02 §4.2](docs/02-developer-framework-design.ko.md) 참고.
- 집행점 셋 전부의 뒤에 있는 단일 `Check` 표(check 29개)와 각 집행점이 선택하는 `Profile`: MCP gateway 21, SDK 19, A2A broker 17. **공유되는 것은 메커니즘이지 커버리지가 아니다** — broker는 gateway와 check 9개만 공유하며 egress·용량·taint 통제가 없다
- `OBSERVE`, `SHADOW`, `ENFORCE` 모드
- Tool result secret 정제, `UNTRUSTED_TOOL_RESULT` taint, schema 격리

**MCP transport·신원**

- MCP `tools/list`/`tools/call`/`notifications/tools/list_changed` JSON-RPC 집행과 Architecture digest binding
- MCP 2025-11-25 Streamable HTTP JSON/SSE client, session binding, inbound Origin·auth·lifecycle carrier
- inbound resumable GET SSE와 교체 가능한 `SessionStore` 계약
- MCP OAuth discovery, PKCE S256, exact callback, resource-bound token exchange, RFC 7662 introspection
- optional JWKS/JWT verifier와 loopback OAuth consent·one-time transaction store
- MCP stdio JSONL client, artifact pin, 서명 sandbox attestation, Bubblewrap launch plan, timeout·process-group kill

**공급망·샌드박스·egress**

- publisher·repository·revision·build·artifact digest를 결합한 서명 provenance admission
- Architecture REL-07/External allowed domain을 compile하는 목적지별 egress guard와 SIMULATION receipt backend
- contextual Connector와 외부 전송 없는 fake receipt·compensation reconciliation
- 사후 downstream receipt reconciliation과 `REVOKE` 증거

**Ledger·증거**

- 판정·집행·결과가 분리된 append-only Ledger와 정적/trace graph 데이터
- PostgreSQL partition, `session_user` 기반 FORCE RLS, append-only migration·adapter
- tenant·scope·idempotency가 결합된 `POST /v1/events`, OTLP/HTTP JSON `POST /v1/traces`, cursor 기반 `GET /v1/traces/{trace_id}`
- canonical keyed 서명 helper와 detached `SignedAuditSink` 증거

**아키텍처 계약·drift**

- 박스/연결선 기반 `ArchitectureGraph`와 실행 가능한 JSON Schema
- PREVENT·DETECT·RESPOND·EVIDENCE 및 DECLARED·OBSERVED·ENFORCED·RECONCILED 보장 수준
- Multi-Agent Dynamic Edge Contract와 설계/런타임 drift 비교
- 방향성 INTERNAL/EXTERNAL Trust Boundary와 cross-zone Edge compile·fail-closed lint

**A2A·오케스트레이션**

- A2A 1.0 Agent Card·Message·Part·Task·Artifact, `SendMessage`/`GetTask`/`CancelTask` JSON-RPC core
- 실제 HTTP socket A2A carrier의 Origin·auth·body size·`A2A-Version` 집행과 0.3 명시 호환 profile
- REL-06 actor/audience/resource/token/delegation/data/schema와 Trust Boundary를 함께 집행하는 A2A Broker
- coordinator·dependency·A2A/MCP/LOCAL/HUMAN transport·retry·timeout·approval·budget 기반 Task workflow engine
- active ENFORCE bundle에 결합된 tenant-scoped Run Control API와 Studio Runs 운영 화면

**운영 루프**

- Ledger·OTLP JSON runtime import와 미선언 관계·통제 우회 분석
- M7 Agent config read·2인 승인 deploy·runtime drift guard
- Studio manifest를 검토 가능한 SHADOW 배포 번들로 compile하는 CLI

**도입 계층(Adoption layer)**

- Anthropic Tool Runner adapter(`GuardedTool`/`GuardedAsyncTool`, `guard_tools`, `bind_architecture`), 공유 승인 구현에 도달하는 `approve=` hook
- 인수와 MCP tool annotation에서 도출한 intent를 선언과 비교 판정(`INTERLOCK-INTENT-ARGUMENT-MISMATCH`)
- `interlock verify`: 프레임워크 fixture가 아니라 프로젝트 자신의 guarded tool에 L1 시나리오 9개 실행
- `interlock architecture skeleton`이 내는 프로젝트 모듈 계약(`MANIFEST`/`TENANT_ID`/`SOURCE_ACTOR_ID`/`APPROVER`/`BINDINGS`/`build()`)
- acceptance-criteria 문법과 task별 결과 3종(`executed`/`goalMet`/`securityMet`)
- 배포 모드 단일화: 저작된 manifest가 아니라 배포 기록의 mode가 실행을 지배
- SDK가 gateway의 실행 후 처리와 승인 구현을 공유
- 지원하지 않는 JSON Schema keyword를 정의 시점에 거부
- Studio 프로젝트: 신규/열기/저장, 편집 가능한 id/version, manifest import

주요 경로는 다음과 같다.

| 경로 | 내용 |
|---|---|
| `src/agent_interlock/` | SDK, Registry, 정책, Gateway, Ledger |
| `src/agent_interlock/adapters/` | Anthropic Tool Runner adapter(`guard_tools`, `bind_architecture`) |
| `src/agent_interlock/verify.py` | `interlock verify`: 프로젝트 자신의 guarded tool에 L1 corpus 실행 |
| `schemas/` | Actor와 Event Envelope JSON Schema |
| `schemas/architecture.schema.json` | Canvas와 compiler가 공유하는 Architecture 계약 |
| `schemas/ledger-api.openapi.yaml` | Event ingest·trace query OpenAPI 계약 |
| `migrations/postgresql/` | PostgreSQL 초기 schema와 partition helper |
| `tests/test_core.py` | L1 핵심 공격·정상 회귀 시험 |
| `tests/test_mcp_http.py` | 실제 HTTP socket 기반 MCP lifecycle·JSON/SSE·보안 carrier 시험 |
| `tests/test_mcp_oauth.py` | 실제 OAuth fixture 기반 discovery·PKCE·SSRF·token binding 시험 |
| `tests/test_mcp_stdio.py` | 실제 subprocess 기반 stdio lifecycle·sandbox·timeout 시험 |
| `tests/test_supply_chain.py` | publisher 서명·provenance·MCP profile admission binding 시험 |
| `tests/test_egress.py` | Architecture-bound 목적지별 egress·socket/종료 receipt 시험 |
| `tests/test_l1_matrix.py` | L1-SIM M1–M9의 34개 추적 ID와 canary·receipt 불변식 시험 |
| `tests/test_config_guard.py` | M7 config 최소 권한·2인 승인·CAS·runtime drift 시험 |
| `tests/test_otlp_receiver.py` | 인증된 OTLP/HTTP JSON receiver 시험 |
| `tests/test_audit_sink.py` | signed audit record seal·tamper 검증 시험 |
| `tests/test_receipts.py` | fake external transaction·receipt 0/1·reconciliation 시험 |
| `tests/test_ledger_http.py` | 실제 socket 기반 tenant·scope·idempotency·pagination 시험 |
| `tests/test_postgres_ledger.py` | DB role binding과 선택적 PostgreSQL 16 live 시험 |
| `tests/test_a2a.py` | Trust Boundary, A2A 1.0/0.3 wire, 실제 HTTP socket, orchestration, acceptance 결과 시험 |
| `tests/test_anthropic_adapter.py` | Anthropic Tool Runner adapter: guarded 동기/비동기 호출, 차단, 승인 hook 시험 |
| `tests/test_verify.py` | `interlock verify` 시나리오별 pass/fail, NOT-APPLICABLE, canary, exit code 시험 |
| `tests/test_platform_e2e.py` | fake data로 compile·2인 승격·실제 localhost A2A·승인·MCP·Runtime/Statistics/Drift 전체 시험 |
| `tests/fixtures/platform_e2e/` | `.invalid` 주소와 결정적 fake 고객·지식·receipt fixture |
| `examples/secure_email.py` | 최소 실행 예제 |
| `examples/secure_multi_agent_architecture.json` | Multi-Agent 보안 아키텍처 예제 |
| `examples/runtime_drift_otlp.json` | OpenTelemetry GenAI/MCP runtime drift 예제 |
| `examples/mcp_transport_vertical_slice.py` | Architecture manifest를 MCP 호출 집행으로 연결하는 실행 예제 |
| `examples/a2a_orchestration_vertical_slice.py` | Boundary→A2A→workflow→Ledger 전체 실행 예제 |
| `examples/support_agent/` | 녹화-재생 시험을 갖춘 실행 가능한 Anthropic Tool Runner 프로젝트 |
| `studio/` | Actor topology·Task workflow·Trust Boundary 편집 및 manifest export UI |

현재 구현은 [04 MCP Tool Gateway 명세](docs/04-mcp-tool-gateway-spec.ko.md)의 정책 코어, [09 MCP Transport 집행](docs/09-mcp-transport-enforcement.ko.md)의 JSON-RPC·resumable Streamable HTTP carrier와 publisher admission, [10 OAuth Identity Guard](docs/10-mcp-oauth-identity-guard.ko.md)의 discovery·PKCE·introspection/JWKS·loopback consent, [11 stdio Sandbox·Receipt](docs/11-mcp-stdio-sandbox-receipts.ko.md)의 서명 attestation·Bubblewrap·Seatbelt·목적지 egress reference 경계, [12 PostgreSQL Ledger API](docs/12-postgresql-ledger-api.ko.md)의 tenant별 저장·조회와 signed audit reference, [13 A2A Orchestration](docs/13-a2a-orchestration-platform.ko.md)의 방향성 Trust Boundary·A2A Broker·Task workflow engine을 포함한다.

프로덕션 통합으로 추가된 것: persistent PostgreSQL DefinitionRegistry와 분산 Session/OAuth/Config store(RLS·migration 0002/0003), macOS Seatbelt·Linux bwrap seccomp sandbox(live 집행 시험), 실 소켓 egress backend의 DNS·IP pinning, Ed25519 publisher·Studio 승인 서명, Langfuse/LangSmith trace 어댑터, append-only WORM audit store, PostgreSQL live CI와 GitHub Actions. 제품 폐쇄 루프에는 tenant+interaction 전체 lifecycle 기반 보안 통계(Python·Studio Unicode golden 파리티), `GET /v1/statistics`, manifest→SDK skeleton·보안테스트, 공개키 검증 기반 2인 승격·rollback Control Plane, Studio 통계·배포 뷰와 read-only Live Attach가 포함된다.

아직 배포되지 않은 것은 외부 연동 작업이 아니다: LangGraph adapter, Claude Agent SDK adapter, sidecar proxy, server-side MCP connector interception(API의 `mcp_servers`는 Anthropic 쪽에서 tool을 실행해 가로챌 수 없으므로 범위 밖), LLM-judge acceptance evaluator(문법은 구조적 평가만 함), [Control Coverage Statistics](docs/specs/2026-07-27-control-coverage-statistics.md)의 열린 질문으로 남아 있는 `BYPASSED` 의미론, PyPI 업로드. 이를 넘어서면 진짜 외부 연동 작업(Sigstore/Rekor·KMS/HSM·IdP·Secret Store, 실 egress sidecar와 S3 Object-Lock, OTLP gRPC·Collector·Incident 서비스, PostgreSQL HA·분산 rate limit·TLS, 원격 Git host PR 리뷰·배포, DPoP/mTLS·JWKS rotation·운영 consent/refresh-token)이 남는다. 자세한 계약 추적과 분류는 [06 구현 상태](docs/06-implementation-status.ko.md)를 따른다.

## 운영 계약

Managed host는 전용 배포 owner와 scheduler 하나를 둔다. Tenant별 run/ledger API가 공유 SaaS tenant별 독립 배포를 제공하지는 않는다. SQLite run snapshot은 원래 bundle과 workflow 승인을 보존한다. 재시작 시 진행 중인 RUNNING 작업은 부작용 재실행 없이 `RUN-INTERRUPTED`로 중단되고, 대기·준비 작업은 명시적으로 resume한다. Terminal run은 직접 prune할 때까지 조회할 수 있다.

PostgreSQL Ledger는 이벤트 증거를 영속화한다. Gateway 호출 승인·결과·멱등 cache는 process-local이다. 임의의 in-process adapter timeout은 외부 동작을 강제 중단하거나 되돌리지 못하며 취소는 협력적이다. 저작된 control, 설치된 classification·export·provenance hook, 관측된 판정은 서로 다른 증거다. 자세한 경계는 [구현 상태](docs/06-implementation-status.ko.md)와 [managed host](docs/managed-support-host.md)를 참고한다.
