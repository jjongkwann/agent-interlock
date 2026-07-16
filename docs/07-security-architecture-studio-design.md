---
title: Agent Interlock Security Architecture Studio 설계
date: 2026-07-16
version: 0.2.0
status: active
---

# Agent Interlock Security Architecture Studio 설계

## 1. 목표

Security Architecture Studio는 Agent 시스템을 구현하기 전에 User, Agent, Sub-Agent, RAG, Memory, Tool, External을 박스로 정의하고 관계별 보안을 연결선에 선언하는 Architecture-as-Code 계층이다. Canvas UI는 이 계약의 편집기이며 JSON Architecture manifest가 source of truth다.

```text
Canvas → Architecture manifest → Security lint → Compiler
       → ActorSpec·LinkPolicy → SDK/Gateway → Runtime Ledger
       → Declared/Observed Graph diff
```

UI에서 프로덕션 정책을 직접 변경하지 않는다. 변경은 versioned manifest와 diff로 만들고 review, simulation, approval, rollback을 거쳐 배포한다.

## 2. 세 가지 그래프

| 그래프 | 생성 근거 | 용도 |
|---|---|---|
| Design Graph | Architecture manifest | 의도한 Actor·관계·보안 설계 |
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

- User, Agent, Sub-Agent, RAG, Tool, Memory, External 박스와 trust zone
- 박스 추가·이동, 선택한 박스 간 Edge 생성
- Edge별 OBSERVE/SHADOW/ENFORCE, failure mode, data class, 승인 조건 편집
- Dynamic Sub-Agent의 same-tenant와 delegation depth 편집
- Control별 DECLARED/OBSERVED/ENFORCED/RECONCILED 변경
- Tool definition digest, External domain allowlist, Actor tenant/delegation boundary 편집
- 위험한 D5, FAIL_OPEN, OBSERVE-only, 미고정 Tool, 무제한 Egress 등의 즉시 finding
- Python compiler와 같은 `interlock.dev/v1alpha1` manifest 다운로드
- Ledger·OTLP JSON import와 실제 Runtime Graph 생성
- 미선언 관계, unobserved Design Edge, control bypass를 분리한 Drift 화면

```bash
cd studio
npm install
npm run dev
```

다운로드한 JSON은 배포 입력이 아니라 draft다. root CLI의 `lint`와 `compile`을 통과한 뒤 review와 SHADOW 검증을 거쳐야 한다.

## 8. 다음 단계

1. manifest Git diff와 approval workflow
2. framework별 skeleton generator
3. OTLP Collector receiver와 trace query API
4. A2A Agent Card admission adapter
5. Architecture manifest 기반 security fixture generator
6. policy bundle 배포와 SHADOW simulation
