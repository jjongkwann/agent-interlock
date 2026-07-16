# Agent Interlock

> Define actors. Secure interactions. See the whole graph.

Agent Interlock는 AI Agent 시스템의 Actor를 선언적으로 정의하고, 각 Actor의 외부를 SDK·Proxy로 감싸며, Actor 간 통신과 데이터 이동을 관측·판정·차단하는 **Agentic AI Security Framework**다.

## 제품 구성

| 구성요소 | 역할 |
|---|---|
| Interlock SDK | ActorSpec 선언, 기존 코드 wrap, trace·event 생성 |
| Interlock Runtime | Actor 간 통신 가로채기와 정책 집행 |
| Interlock Ledger | 요청·데이터 흐름·판정·조치·결과 저장 |
| Interlock Graph | 정적 관계·런타임 호출·공격 경로 시각화 |
| Interlock Console | 정책·Incident·통제 상태 운영 |

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

- [`docs/00-document-map.md`](docs/00-document-map.md): 문서별 책임, 권장 읽기 순서, ID와 변경 원칙
- [`docs/01-project-plan.md`](docs/01-project-plan.md): 이벤트 DB, 탐지·차단 플랫폼, PostgreSQL DDL, 구현 로드맵
- [`docs/02-developer-framework-design.md`](docs/02-developer-framework-design.md): SDK, Actor Wrapper, LinkPolicy, Graph 중심 개발자 경험
- [`docs/03-l1-mcp-tool-security-profile.md`](docs/03-l1-mcp-tool-security-profile.md): L1 M1–M9의 데이터 흐름, 공격 예시, 관측·통제 매핑
- [`docs/04-mcp-tool-gateway-spec.md`](docs/04-mcp-tool-gateway-spec.md): MCP Tool Gateway의 컴포넌트, 상태, 정책, 이벤트, API 계약
- [`docs/05-l1-security-validation-plan.md`](docs/05-l1-security-validation-plan.md): M1–M9 공격 재현, 기대 판정, 증거, 운영 승격 기준
- [`docs/06-implementation-status.md`](docs/06-implementation-status.md): 설계 계약과 현재 코드·시험 추적표
- [`docs/07-security-architecture-studio-design.md`](docs/07-security-architecture-studio-design.md): 박스 기반 Architecture-as-Code와 Studio 사용법
- [`docs/08-runtime-telemetry-reconciliation.md`](docs/08-runtime-telemetry-reconciliation.md): Ledger·OTLP 실행 trace와 Design/Runtime drift 계약
- [`docs/09-mcp-transport-enforcement.md`](docs/09-mcp-transport-enforcement.md): Architecture manifest와 MCP JSON-RPC 집행을 연결하는 어댑터
- [`docs/10-mcp-oauth-identity-guard.md`](docs/10-mcp-oauth-identity-guard.md): OAuth discovery, PKCE, SSRF/redirect와 token identity binding

## 기본 구현 전략

1. 단일 Agent 서비스에서 User→Agent, Agent→RAG, Agent→Tool, Agent→External 관측
2. PostgreSQL 기반 Interaction Ledger 구축
3. OBSERVE → SHADOW → ENFORCE 단계적 승격
4. ActorSpec·LinkPolicy를 코드와 manifest로 지원
5. 정적 설계 그래프와 런타임 trace 그래프 제공
6. A2A·Memory·Scheduler·Sandbox로 확장

## 현재 구현

문서의 최초 구현 순서에 맞춘 Python 3.11 reference core가 포함되어 있다. 외부 런타임 의존성 없이 다음 기능을 실행할 수 있다.

- `ActorSpec`, `LinkPolicy`, `define_actor()`, `connect()`, `wrap()` SDK
- MCP Tool 정의 canonical/raw digest와 `DISCOVERED` → `APPROVED` → `ACTIVE` 상태 전이
- definition drift, metadata instruction, cross-server reference 격리
- 호출 인수 schema, 데이터 등급, secret, 목적지, token binding, 선언 부작용 정책
- hash·목적지에 결합된 승인과 hash-bound connector 실행
- `OBSERVE`, `SHADOW`, `ENFORCE` 모드
- Tool result secret 정제, `UNTRUSTED_TOOL_RESULT` taint, schema 격리
- MCP `tools/list`/`tools/call`/`notifications/tools/list_changed` JSON-RPC 집행과 Architecture digest binding
- MCP 2025-11-25 Streamable HTTP JSON/SSE client, session binding, inbound Origin·auth·lifecycle carrier
- MCP OAuth Protected Resource/Authorization Server discovery, PKCE S256, exact callback, resource-bound token exchange
- 사후 downstream receipt reconciliation과 `REVOKE` 증거
- 판정·집행·결과가 분리된 append-only Ledger와 정적/trace graph 데이터
- PostgreSQL partition, RLS, append-only migration
- 박스/연결선 기반 `ArchitectureGraph`와 실행 가능한 JSON Schema
- PREVENT·DETECT·RESPOND·EVIDENCE 및 DECLARED·OBSERVED·ENFORCED·RECONCILED 보장 수준
- Multi-Agent Dynamic Edge Contract와 설계/런타임 drift 비교
- Ledger·OTLP JSON runtime import와 미선언 관계·통제 우회 분석

```bash
# 별도 설치 없이 테스트
PYTHONPATH=src python3 -m unittest discover -s tests -v

# 안전한 email Tool 호출 예제
PYTHONPATH=src python3 examples/secure_email.py

# Architecture → MCP transport → Ledger 수직 슬라이스
PYTHONPATH=src python3 examples/mcp_transport_vertical_slice.py

# 보안 아키텍처 lint·compile
PYTHONPATH=src python3 -m agent_interlock architecture lint examples/secure_multi_agent_architecture.json
PYTHONPATH=src python3 -m agent_interlock architecture compile examples/secure_multi_agent_architecture.json
PYTHONPATH=src python3 -m agent_interlock architecture runtime-diff examples/secure_multi_agent_architecture.json examples/runtime_drift_otlp.json

# 박스 기반 Security Architecture Studio
cd studio
npm install
npm run dev

# editable install을 원하는 경우
python3 -m pip install -e .
```

주요 경로는 다음과 같다.

| 경로 | 내용 |
|---|---|
| `src/agent_interlock/` | SDK, Registry, 정책, Gateway, Ledger |
| `schemas/` | Actor와 Event Envelope JSON Schema |
| `schemas/architecture.schema.json` | Canvas와 compiler가 공유하는 Architecture 계약 |
| `migrations/postgresql/` | PostgreSQL 초기 schema와 partition helper |
| `tests/test_core.py` | L1 핵심 공격·정상 회귀 시험 |
| `tests/test_mcp_http.py` | 실제 HTTP socket 기반 MCP lifecycle·JSON/SSE·보안 carrier 시험 |
| `tests/test_mcp_oauth.py` | 실제 OAuth fixture 기반 discovery·PKCE·SSRF·token binding 시험 |
| `examples/secure_email.py` | 최소 실행 예제 |
| `examples/secure_multi_agent_architecture.json` | Multi-Agent 보안 아키텍처 예제 |
| `examples/runtime_drift_otlp.json` | OpenTelemetry GenAI/MCP runtime drift 예제 |
| `examples/mcp_transport_vertical_slice.py` | Architecture manifest를 MCP 호출 집행으로 연결하는 실행 예제 |
| `studio/` | Actor 박스·관계 보안 편집 및 manifest export UI |

현재 구현은 [04 MCP Tool Gateway 명세](docs/04-mcp-tool-gateway-spec.md)의 정책 코어, [09 MCP Transport 집행](docs/09-mcp-transport-enforcement.md)의 JSON-RPC·Streamable HTTP carrier, [10 OAuth Identity Guard](docs/10-mcp-oauth-identity-guard.md)의 discovery·PKCE·token binding을 포함한다. IdP별 서명 검증/browser adapter, stdio OS process/network sandbox, inbound resumable SSE store, PostgreSQL adapter와 운영 API는 다음 통합 단계다.
