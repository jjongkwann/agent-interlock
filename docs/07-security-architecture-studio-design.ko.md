---
title: Agent Interlock Security Architecture Studio 설계
date: 2026-07-20
version: 0.3.0
status: active
---

# Agent Interlock Security Architecture Studio 설계

> English version: [07-security-architecture-studio-design.md](07-security-architecture-studio-design.md)

## 1. 목표

Security Architecture Studio는 Agent 시스템을 구현하기 전에 User, Agent, Sub-Agent, Scheduler, RAG, Memory, Tool, External을 정의하고 관계별 보안과 task 실행 순서를 선언하는 Architecture-as-Code 계층이다. Design에는 Actor topology와 Task workflow 두 surface가 있으며 JSON Architecture manifest가 source of truth다.

```text
Actor topology + Task workflow → Architecture manifest → Security lint → Compiler
       → ActorSpec·LinkPolicy → SDK/Gateway → Runtime Ledger
       → Declared/Observed Graph diff
```

UI에서 프로덕션 정책을 직접 변경하지 않는다. 변경은 versioned manifest와 diff로 만들고 review, simulation, approval, rollback을 거쳐 배포한다.

## 2. 네 가지 그래프

| 그래프 | 생성 근거 | 용도 |
|---|---|---|
| Design Graph | Architecture manifest | 의도한 Actor·관계·보안 설계 |
| Task Workflow | Architecture manifest | coordinator·task·dependency·transport·approval·budget 설계 |
| Compiled Control Graph | ActorSpec·LinkPolicy·adapter 설정 | 실제 배치할 집행점 확인 |
| Runtime Graph | Ledger·OpenTelemetry | 실제 호출과 우회·drift 확인 |

Runtime에서 발견된 Edge를 Design Graph에 자동 승인하지 않는다. 먼저 `UNDECLARED_RELATIONSHIP`으로 처리하고 운영자 승인을 거쳐 manifest revision으로 반영한다.

## 3. 보안 통제 계약

모든 Control은 네 축을 가진다.

```yaml
id: delegation-binding
objective: PREVENT
timing: PRE_EXECUTION
enforcementPoint: A2A_BROKER
assurance: ENFORCED
```

### 3.1 Objective

- `PREVENT`: 실행 전에 차단
- `DETECT`: 실행 전후 위반 탐지
- `RESPOND`: revoke, kill, quarantine, compensation
- `EVIDENCE`: 판정·집행·결과 증거 보존

### 3.2 Assurance

- `DECLARED`: 설계에만 존재
- `OBSERVED`: 실행 사실을 관측
- `ENFORCED`: 집행점이 실행 전에 강제
- `RECONCILED`: downstream receipt까지 대사

Canvas는 assurance를 색과 배지로 표시한다. `DECLARED`를 `ENFORCED`처럼 보이게 표시해서는 안 된다.

### 3.3 Enforcement Point

`SANDBOX`는 REL-05 로컬 Tool의 filesystem·network·child-process 격리 profile과 attestation을 조작하는 집행점이다. `MCP_GATEWAY`의 definition/call 정책과 별도 Control로 두어 프로토콜 허용과 OS process 격리를 각각 표시한다.

## 4. Dynamic Edge Contract

Sub-Agent가 실행 중 생성되면 모든 instance ID를 설계 시점에 알 수 없다. Dynamic Edge는 허용되는 target 집합을 계약으로 선언한다.

```yaml
dynamic: true
targetSelector:
  types: [SUBAGENT]
  requiredCapabilities: [KNOWLEDGE_SEARCH]
  idPattern: agent.research*
  sameTenant: true
policy:
  maxDelegationDepth: 2
  requireActorBinding: true
  requireAudience: true
  requireResource: true
```

실제 Sub-Agent instance는 admission 단계에서 selector와 Agent identity를 확인하고, 실행 단계에서 delegation token과 depth·budget을 다시 검사한다.

## 5. 현재 Security lint

- 관계별 필수 집행점 누락
- Control 없는 관계
- audit evidence 누락
- `DECLARED` only 통제
- 실행 후 `PREVENT`로 잘못 표시한 통제
- D5 credential data 허용
- 고위험 Edge의 OBSERVE only·FAIL_OPEN
- RAG tenant optional
- Tool digest pin 누락
- A2A actor/audience/resource binding 약화
- Actor보다 큰 delegation depth
- cross-tenant dynamic delegation
- capability가 비어 있거나 ID pattern이 무제한인 dynamic delegation
- delegation cycle
- Egress 목적지 allowlist·명시 목적지 누락
- Actor의 정확한 Trust Zone 소속 누락
- cross-zone Edge의 방향성 Trust Boundary·enforcement·data contract 누락
- A2A boundary의 identity·tenant binding·fail-closed 누락
- workflow task의 transport Edge·acceptance criteria·고위험 승인·DAG·budget 누락

CRITICAL finding이 있으면 compiler는 ActorSpec·LinkPolicy 생성을 거부한다.

## 6. 실행 방법

```bash
PYTHONPATH=src python3 -m agent_interlock architecture lint \
  examples/secure_multi_agent_architecture.json

PYTHONPATH=src python3 -m agent_interlock architecture compile \
  examples/secure_multi_agent_architecture.json

PYTHONPATH=src python3 -m agent_interlock architecture graph \
  examples/secure_multi_agent_architecture.json
```

JSON 계약은 `schemas/architecture.schema.json`, Python 구현은 `src/agent_interlock/architecture.py`를 기준으로 한다.

## 7. 현재 Studio 구현

`studio/`에는 로컬에서 실행할 수 있는 Canvas MVP가 포함되어 있다.

- User, Agent, Sub-Agent, Scheduler, RAG, Tool, Memory, External 박스와 Manifest에 저장되는 INTERNAL/EXTERNAL trust zone
- Trust zone 추가·선택·이름/분류/설명 편집·이동·크기 조절과 `trustZoneId` 기반 Actor 소속 관리
- Zone 이동 시 소속 Actor 동반 이동, Actor의 Zone 간 drag/drop·Inspector 재배치, 소속 Actor 기준 Zone 맞춤
- source zone→target zone 방향성 Trust Boundary 생성·선택·편집과 cross-zone Edge의 `boundaryId` 결합
- Boundary별 enforcement point, relationship/data 계약, identity·tenant binding, payload limit, mode/failure 편집
- 박스 추가·이동, 선택한 박스 간 Edge 생성
- Edge별 OBSERVE/SHADOW/ENFORCE, failure mode, data class, 승인 조건 편집
- Dynamic Sub-Agent의 same-tenant와 delegation depth 편집
- Control별 DECLARED/OBSERVED/ENFORCED/RECONCILED 변경
- Tool definition digest, External domain allowlist, Actor tenant/delegation boundary 편집
- 위험한 D5, FAIL_OPEN, OBSERVE-only, 미고정 Tool, 무제한 Egress 등의 즉시 finding
- Python compiler와 같은 `interlock.dev/v1alpha1` manifest 다운로드
- Ledger·OTLP JSON import와 실제 Runtime Graph 생성
- 미선언 관계, unobserved Design Edge, control bypass를 분리한 Drift 화면
- Ledger interaction 통계 화면(오프라인 import + read-only Live Attach, data source·mode·관계·Actor·정책·사유별 집계)
- CLI `architecture compile --shadow`의 CRITICAL review gate·전 Edge SHADOW 강제·안정적 bundle digest
- manifest 기반 Python SDK skeleton·보안테스트 생성
- Ed25519 2인 승인 기반 propose→promote→과거 active bundle rollback CLI와 Control Plane 연동
- REL-07의 source Tool·External `allowedDomains`·LinkPolicy를 tenant/artifact/provenance/sandbox-bound egress 정책으로 compile하는 runtime adapter
- Canvas에 포인터가 있을 때 일반 wheel과 macOS `Command + =/-`, Windows `Ctrl + =/-`로 graph만 확대/축소하며 브라우저 페이지 zoom과 분리
- Design 내부 `Actor topology`/`Task workflow` 전환과 A2A/MCP/LOCAL/HUMAN task palette
- Task별 source/target, dependency, data, acceptance, retry, timeout, on-failure, approval 편집과 workflow budget 설정

```bash
cd studio
npm install
npm run dev
```

다운로드한 JSON은 배포 입력이 아니라 draft다. root CLI의 `lint`와 `compile`을 통과한 뒤 review와 SHADOW 검증을 거쳐야 한다.

## 8. 다음 단계

1. 원격 GitHub/GitLab PR review와 hosted deploy 연결
2. Python 외 framework별 skeleton generator
3. OTLP/gRPC Collector와 trace 운영 저장소
4. A2A SSE streaming·push notification과 signed Agent Card admission
5. durable A2A task/workflow run store와 분산 scheduler
6. 대용량 통계 사전집계와 지속형 pending approval store

Trust Boundary부터 A2A Broker와 Task workflow 실행까지의 전체 계약은 [13 A2A 오케스트레이션 플랫폼](13-a2a-orchestration-platform.ko.md)을 따른다.
