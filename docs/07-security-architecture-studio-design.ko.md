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

`ArchitectureLinter`는 39개 코드를 방출한다. 권위 있는 정의는 `architecture.py`이며, 아래 표들은 이 판본 기준 전체 집합을 영역별로 묶은 것이다.

### 5.1 Trust Zone과 Boundary

| 코드 | 심각도 | 조건 |
|---|---|---|
| `ARCH-NODE-ZONE-MISSING` | CRITICAL | Zone이 선언된 상태에서 Actor가 명시적 Trust Zone에 속하지 않음 |
| `ARCH-BOUNDARY-MISSING` | CRITICAL | Edge가 Zone을 넘는데 Trust Boundary가 없음 |
| `ARCH-BOUNDARY-DIRECTION-MISMATCH` | CRITICAL | Edge 방향이 참조된 Boundary와 불일치 |
| `ARCH-BOUNDARY-RELATIONSHIP-DENIED` | CRITICAL | Boundary가 해당 Edge의 relationship을 허용하지 않음 |
| `ARCH-BOUNDARY-DATA-CLASS-DENIED` | CRITICAL | Edge policy가 Boundary data contract 밖의 data class를 허용 |
| `ARCH-BOUNDARY-ENFORCEMENT-MISMATCH` | CRITICAL | Boundary가 요구된 집행점에서 집행되지 않음 |
| `ARCH-BOUNDARY-FAIL-OPEN` | CRITICAL | Trust Zone Boundary가 FAIL_OPEN으로 설정됨 |
| `ARCH-A2A-BOUNDARY-BINDING-WEAK` | CRITICAL | A2A Boundary 교차가 identity와 tenant를 모두 bind하지 않음 |
| `ARCH-BOUNDARY-OBSERVE-ONLY` | HIGH | Trust Zone 교차가 OBSERVE only |
| `ARCH-BOUNDARY-UNNECESSARY` | WARNING | Edge가 Boundary를 참조하지만 두 Actor가 같은 Zone에 있음 |

### 5.2 Control과 집행점

| 코드 | 심각도 | 조건 |
|---|---|---|
| `ARCH-CONTROL-MISSING` | CRITICAL | 관계에 선언된 보안 통제가 없음 |
| `ARCH-ENFORCEMENT-POINT-MISSING` | CRITICAL | 관계별 필수 집행점이 없거나 `enforced` assurance가 아님 |
| `ARCH-PREVENT-AFTER-EXECUTION` | CRITICAL | 실행 후 통제가 `PREVENT`로 표시됨 |
| `ARCH-RELATIONSHIP-ID-MISMATCH` | CRITICAL | `relationshipId`와 선언된 relationship이 불일치 |
| `ARCH-RELATIONSHIP-TYPE-MISMATCH` | CRITICAL | 해당 `relationshipId`에 대해 source/target Actor type이 잘못됨 |
| `ARCH-AUDIT-GAP` | WARNING | 관계에 명시적 audit evidence 통제가 없음 |
| `ARCH-DECLARED-ONLY` | WARNING | 통제가 `DECLARED`이고 runtime assurance가 없음 |

### 5.3 Data class

| 코드 | 심각도 | 조건 |
|---|---|---|
| `ARCH-CREDENTIAL-DATA-ALLOWED` | CRITICAL | 관계에서 credential data class D5를 허용 |
| `ARCH-DATA-CLASS-EXCEEDS-ACTOR` | CRITICAL | `edge.policy.allowedDataClasses`가 target Actor의 `dataAccess`의 부분집합이 아님 |
| `ARCH-RAG-TENANT-OPTIONAL` | CRITICAL | RAG security boundary가 tenant를 요구하지 않음 |

### 5.4 위험 태세·Tool pin·Egress

| 코드 | 심각도 | 조건 |
|---|---|---|
| `ARCH-HIGH-RISK-FAIL-OPEN` | CRITICAL | 고위험 관계가 fail open |
| `ARCH-TOOL-DIGEST-UNPINNED` | CRITICAL | Tool 관계가 digest pin을 요구하지만 Tool에 definition digest가 없음 |
| `ARCH-EGRESS-DESTINATION-UNBOUNDED` | CRITICAL | 외부 목적지에 allowed domain 경계가 없음 |
| `ARCH-EGRESS-DESTINATION-IMPLICIT` | CRITICAL | 외부 쓰기가 명시 목적지를 요구하지 않음 |
| `ARCH-HIGH-RISK-OBSERVE-ONLY` | HIGH | 고위험 관계가 OBSERVE only |

### 5.5 Delegation

| 코드 | 심각도 | 조건 |
|---|---|---|
| `ARCH-DELEGATION-DISABLED` | CRITICAL | delegation Edge의 `maxDelegationDepth`가 1 미만 |
| `ARCH-DELEGATION-DEPTH-EXCEEDS-ACTOR` | CRITICAL | LinkPolicy delegation depth가 source Actor 한도를 초과 |
| `ARCH-DELEGATION-BINDING-WEAK` | CRITICAL | delegation이 actor·audience·resource를 bind하지 않음 |
| `ARCH-DYNAMIC-CAPABILITY-UNBOUNDED` | CRITICAL | dynamic delegation selector에 required capability 경계가 없음 |
| `ARCH-DYNAMIC-TARGET-UNBOUNDED` | CRITICAL | dynamic delegation target ID pattern이 무제한 |
| `ARCH-DYNAMIC-DELEGATION-CROSS-TENANT` | CRITICAL | dynamic delegation이 source tenant 밖의 target을 허용 |
| `ARCH-DYNAMIC-DELEGATION-TYPE` | CRITICAL | dynamic delegation selector가 non-Agent Actor type을 포함 |
| `ARCH-DYNAMIC-CAPABILITY-TEMPLATE-MISMATCH` | CRITICAL | dynamic selector capability가 target template에 선언되어 있지 않음 |
| `ARCH-DELEGATION-CYCLE` | HIGH | delegation cycle 발견 |

### 5.6 Orchestration

| 코드 | 심각도 | 조건 |
|---|---|---|
| `ARCH-ORCHESTRATOR-TYPE` | CRITICAL | orchestration coordinator가 Agent·Sub-Agent·Scheduler가 아님 |
| `ARCH-TASK-TRANSPORT-EDGE-MISSING` | CRITICAL | task에 해당 relationship의 transport Edge 선언이 없음 |
| `ARCH-TASK-DATA-CLASS-DENIED` | CRITICAL | task가 Edge policy 밖의 data class를 사용 |
| `ARCH-TASK-APPROVAL-MISSING` | CRITICAL | 고위험 task에 승인 게이트가 없음 |
| `ARCH-TASK-ACCEPTANCE-MISSING` | WARNING | task에 명시적 acceptance criteria가 없음 |

CRITICAL finding이 있으면 compiler는 ActorSpec·LinkPolicy 생성을 거부한다(`ArchitectureLinter.compile`이 `ArchitectureCompileError`를 raise하며, `reject_critical` 기본값은 `True`).

이 목록이 다루지 **않는** 두 가지. workflow task의 의존 **DAG**와 message **budget**은 lint finding이 아니다. orchestration 의존 cycle은 linter가 돌기 전에 `_validate_acyclic_tasks`가 던지는 parse 시점 `ValueError`이고, message budget은 설계 시점에 전혀 검사되지 않고 실행 시점에 `orchestration.py`가 집행한다(`ORCH-MESSAGE-BUDGET`).

### 5.7 Studio는 `ARCH-DATA-CLASS-EXCEEDS-ACTOR`를 드러낼 수 없다

`ARCH-DATA-CLASS-EXCEEDS-ACTOR`는 `edge.policy.allowedDataClasses`를 target Actor의 `dataAccess`와 비교하며, **`dataAccess`가 비어 있는 Actor는 건너뛴다** — data access를 선언하지 않은 Actor는 "아무것도 보유하지 않는다고 선언한 것"이 아니라 "선언하지 않은 것"이기 때문이다.

Studio canvas는 이 필드를 모델링하지 않는다. `grep -rn dataAccess studio/`는 정확히 한 건, `studio/app/page.tsx:1106`만 반환하며, 그것은 `exportManifest()`의 `nodes.map(...)` 안에 리터럴로 박힌 `dataAccess: []`다. 따라서 **모든** Studio export의 **모든** Actor가 빈 grant를 실어 보내고, 규칙은 설계상 전부 건너뛴다. 현재 Studio 작성자가 grant를 표현할 방법도, "아무것도 보유하지 않음"을 표현할 방법도 없다.

그 결과 두 표면이 갈라진다. **Studio의 보안 검사를 통과한 초안이 CLI에서는 거부될 수 있으며**, 그 CRITICAL은 UI가 보여줄 수 없었던 것이다. 작성 표면이 `dataAccess`를 모델링하기 전까지 이 규칙의 권위는 Studio 패널이 아니라 `interlock architecture lint`다.

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
- Ledger interaction 통계 화면(오프라인 import + read-only Live Attach, data source·mode·관계·Actor·정책·사유별 집계; 계약에는 `byCheck`(check id별 coverage)와 `byEdge`/`unattributed`도 있지만 Studio UI는 아직 이 둘을 렌더링하지 않는다)
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
