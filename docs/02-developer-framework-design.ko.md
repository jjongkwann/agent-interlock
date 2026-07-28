---
title: Agent Interlock 개발자 프레임워크 및 그래프 설계
date: 2026-07-15
version: 1.0
status: planning
---

# Agent Interlock 개발자 프레임워크 및 그래프 설계 v1

> English version: [02-developer-framework-design.md](02-developer-framework-design.md)

## 1. 목적

Agent Interlock는 보안팀이 운영 로그를 사후 분석하는 제품에 머물지 않는다. 개발자가 Agent, Tool, RAG, Memory, Scheduler, External Service를 만들 때부터 다음 내용을 선언하도록 한다.

- 이 Actor는 누구인가
- 무엇을 할 수 있는가
- 어떤 데이터를 읽고 쓸 수 있는가
- 누구와 어떤 관계로 연결될 수 있는가
- 어떤 행동이 외부 부작용을 만드는가
- 어떤 조건에서 승인·차단·격리가 필요한가
- 장애 시 fail-open, fail-closed, read-only 중 무엇을 선택하는가

Runtime은 이 선언을 실제 호출에 강제하고, Ledger는 판정과 결과를 기록하며, Graph는 선언된 관계와 실제 실행의 차이를 보여준다.

**예외가 하나 있고, 이 예외는 구조적으로 중요하다.** ActorSpec의 `dataAccess`는 런타임에 집행되지 **않는다**. SDK가 마지막 런타임 소비자였는데, 판정 엔진이 통합된 뒤로 데이터 등급 check는 intent의 등급을 대상 Actor의 허용 범위가 아니라 *link policy*의 `allowedDataClasses`/`deniedDataClasses`와 비교한다. 이제 `ActorSpec.data_access`를 읽는 곳은 설계 시점 linter(`ARCH-DATA-CLASS-EXCEEDS-ACTOR`)와 `scaffold.py`의 테스트 생성기뿐이다. 그래도 선언해야 한다 — linter가 이 값을 필요로 하고, link policy가 대상 Actor의 범위를 넘어 넓어지는 것을 막는 유일한 수단이다 — 다만 여기서 런타임 차단을 기대해서는 안 된다.

## 2. 개발자 경험

```mermaid
flowchart LR
    DEV["Developer"] --> SPEC["ActorSpec"]
    SPEC --> GUARD["ActorGuard"]
    GUARD --> ACTOR["Agent·Tool·RAG·Memory"]
    ACTOR --> LINK["InterlockLink"]
    LINK --> POLICY["LinkPolicy"]
    POLICY --> RUNTIME["Interlock Runtime"]
    RUNTIME --> LEDGER["Interlock Ledger"]
    LEDGER --> GRAPH["Interlock Graph"]
```

개발자가 수행할 핵심 작업은 `define`, `wrap`, `connect` 세 가지다.

```typescript
const supportAgent = interlock.defineActor({
  id: "agent.support",
  type: "AGENT",
  owner: "customer-platform",
  tenantMode: "REQUIRED",
  capabilities: ["CUSTOMER_LOOKUP", "SUPPORT_REPLY"],
  dataAccess: ["D2", "D3", "D7"],
  maxDelegationDepth: 2,
});

const emailTool = interlock.defineActor({
  id: "tool.send-email",
  type: "TOOL",
  inputSchema: SendEmailSchema,
  outputSchema: SendEmailResultSchema,
  sideEffects: ["EXTERNAL_WRITE"],
  capabilities: ["EMAIL_SEND"],
});

export const secureSendEmail = emailTool.wrap(sendEmail);

supportAgent.connect(emailTool, {
  relationship: "INVOKES",
  allowedPurposes: ["SUPPORT_REPLY", "REFUND_NOTICE"],
  allowedDataClasses: ["D2", "D3"],
  deniedDataClasses: ["D5", "D8"],
  requireExplicitDestination: true,
  newDestinationAction: "HOLD",
  externalWriteRequiresApproval: true,
  failureMode: "FAIL_CLOSED"
});
```

이 예시를 읽을 때 유의할 점이 둘 있다.

**데이터 등급은 `D1`–`D9` 코드**이지 상징적인 이름이 아니다. `allowedDataClasses`와 `deniedDataClasses`는 `InvocationIntent.data_classes`와 집합으로 비교되며, 이 비교는 문자 그대로의 집합 연산이다 — `CUSTOMER_PII` 같은 상징적인 값은 대상 Actor가 보유하지 않은 등급일 뿐이다. 배포된 `examples/secure_multi_agent_architecture.json`에 상징적 어휘를 대입하면 깨끗하던 lint가 **CRITICAL `ARCH-DATA-CLASS-EXCEEDS-ACTOR` 4건**으로 바뀌고, 이어서 `interlock architecture compile`이 그래프를 거부한다. 코드 정의는 [03 L1 보안 프로파일](03-l1-mcp-tool-security-profile.ko.md)을 참고한다.

**이것은 의도한 TypeScript 표면이며, 아직 존재하지 않는다.** 배포된 SDK는 Python(`src/agent_interlock/sdk.py`)이고 `defineActor`는 저장소 어디에도 없다. 위 필드 이름은 예시를 schema에 대조해 검증할 수 있도록 실제 `LinkPolicy` 필드의 JSON 표기(`architecture.py`의 `_policy_value`)를 쓴 것이지만, 이전 판본에 있던 `destinationPolicy`, `approvalRequiredWhen`, `maxCallsPerTrace`는 `LinkPolicy` 필드가 아니며 한 번도 아니었다.

## 3. ActorSpec

### 3.1 필수 필드

| 필드 | 설명 |
|---|---|
| `id` | 환경 전체에서 안정적인 Actor ID |
| `type` | USER, AGENT, SUBAGENT, TOOL, RAG, MEMORY, SCHEDULER, EXTERNAL 등 |
| `owner` | 운영·사고대응 책임 팀 |
| `identity` | workload identity 또는 인증 subject |
| `capabilities` | 수행 가능한 행동 |
| `dataAccess` | 읽기·쓰기 가능한 데이터 등급 |
| `sideEffects` | 외부 쓰기, 삭제, 송금, 권한 변경 등 |
| `inputSchema` | 허용 입력 구조 |
| `outputSchema` | 허용 출력 구조 |
| `tenantMode` | REQUIRED, OPTIONAL, GLOBAL |
| `failureMode` | FAIL_OPEN, FAIL_CLOSED, DEGRADE_READ_ONLY |

### 3.2 선택 필드

- 허용 모델과 Tool
- credential scope와 audience
- 호출·token·비용·시간 예산
- 동시 실행과 재시도 한도
- 위임 가능 여부와 최대 깊이
- 원문 증거 보관 여부
- 데이터 보존기간
- heartbeat와 health SLO
- 배포 artifact digest와 provenance

### 3.3 Manifest 표현

```yaml
apiVersion: interlock.dev/v1alpha1
kind: Actor
metadata:
  id: tool.send-email
  owner: customer-platform
spec:
  type: TOOL
  identity: spiffe://prod.example/tool/send-email
  capabilities: [EMAIL_SEND]
  dataAccess: [D2, D3]
  sideEffects: [EXTERNAL_WRITE]
  tenantMode: REQUIRED
  schemas:
    input: schemas/send-email-input.json
    output: schemas/send-email-output.json
  limits:
    callsPerTrace: 3
    timeoutMs: 5000
  failureMode: FAIL_CLOSED
```

loader가 받아들이는 버전은 `interlock.dev/v1alpha1` 하나뿐이다. `ArchitectureGraph.from_dict`(`architecture.py:333-334`)는 그 외의 값을 `ValueError`로 거부하며, [04 MCP Tool Gateway 명세](04-mcp-tool-gateway-spec.ko.md)도 전체에서 같은 문자열을 쓴다. `schemas/actor.schema.json`은 `interlock.dev/v1`도 허용하지만 `src/`에서 이 schema를 읽는 곳이 없으므로 그것으로 `v1`이 로드되지는 않는다.

## 4. ActorGuard

ActorGuard는 기존 비즈니스 로직의 앞뒤에서 다음 처리를 수행한다.

```text
입력 수신
→ 호출 Actor 인증
→ tenant·relationship 검증
→ schema·민감정보·taint 검사
→ LinkPolicy 판정
→ ALLOW/BLOCK/HOLD/SANITIZE
→ 원래 Actor 실행
→ 출력·부작용 검사
→ Action Result·Security Outcome 기록
```

### 4.1 지원 형태

| 형태 | 대상 | 특징 |
|---|---|---|
| In-process SDK | 직접 개발하는 Agent·Tool | 가장 풍부한 내부 단계 관측 |
| Framework Adapter | LangGraph 등 Agent runtime | 낮은 도입 비용 |
| Sidecar Proxy | 수정하기 어려운 서비스 | 네트워크 경계 관측·차단 |
| Gateway | MCP, A2A, RAG, Egress | 중앙 정책과 강제력 |

SDK가 없어도 Proxy로 통신은 관측할 수 있지만, plan step·memory provenance·sub-agent tree 같은 의미는 SDK가 있어야 정확히 수집할 수 있다.

### 4.2 `wrap()`은 집행하지만 승인할 수는 없다

`wrap()`은 관측 전용이 아니다. `PolicyMode.ENFORCE`에서는 `SDK_PROFILE`의 check 16개를 실행하고(`sdk.py:152`), 종합 판정이 거부면 `GatewayError`를 raise한다(`sdk.py:199`). 호출은 일어나지 않는다. gateway의 check 18개 중 16개가 여기서 실행되며, 빠지는 것은 M2 definition check 2개뿐이다. SDK는 `ToolRevision`을 보유하지 않기 때문이다.

**`wrap()`으로 감싼 Tool은 기본 `LinkPolicy`에서 외부 쓰기를 수행할 수 없다.** `external_write_requires_approval`의 기본값이 `True`이므로 `approval_valid`가 설정되지 않는 한 모든 `EXTERNAL_WRITE` intent에서 `INTERLOCK-APPROVAL-REQUIRED`가 발생하는데, SDK 경로는 이 값을 설정하지 않는다. `CheckContext.approval_valid`의 기본값은 `False`이고(`policy.py:81`), `_invoke`는 이 값을 전달하지 않으며, `Interlock`도 `Actor`도 승인 API를 노출하지 않는다. `grant_approval`은 `MCPToolGateway`에만 있다(`gateway.py:140`).

모든 것을 올바로 선언해도 — 승인된 목적지, 선언된 부작용, taint 없음 — 여기에 도달한다.

```python
agent.connect(tool, LinkPolicy(id="p", version="1", mode=PolicyMode.ENFORCE))
send = tool.wrap(send_email)
send({"to": "user@customer.example"}, source=agent, tenant_id="t",
     intent=InvocationIntent(purpose="reply",
                             destinations=("user@customer.example",),
                             estimated_side_effect=SideEffect.EXTERNAL_WRITE))
# GatewayError: actor invocation blocked: INTERLOCK-APPROVAL-REQUIRED
```

동작은 fail-closed이고 방향은 옳지만, 승인 경로는 단순히 미구현인 것이 아니라 **설계상 도달할 수 없다**. SDK에 승인 표면이 생기기 전까지 in-process 외부 쓰기에는 둘 중 하나가 필요하다. 통제를 내려놓는 명시적이고 감사 가능한 결정인 `LinkPolicy(external_write_requires_approval=False)`를 쓰거나, 승인을 보유할 수 있는 `MCPToolGateway`를 경유하는 것이다. 부작용을 `EXTERNAL_WRITE`가 아닌 다른 값으로 선언해 우회해서는 안 된다. 그렇게 하면 눈에 보이는 차단을 잘해야 조용한 `L1-UNDECLARED-SIDE-EFFECT`로, 최악의 경우 탐지되지 않은 외부 쓰기로 바꾸는 것이다.

## 5. InterlockLink와 LinkPolicy

보안 정책은 Actor 노드가 아니라 Actor 사이 Edge에 배치한다.

```mermaid
flowchart LR
    U["User"] -->|"REQUESTS<br/>InputPolicy"| A["Support Agent"]
    A -->|"READS<br/>TenantPolicy"| R["Customer RAG"]
    A -->|"INVOKES<br/>ToolPolicy"| T["Email Tool"]
    T -->|"SENDS<br/>EgressPolicy"| E["Customer"]
```

### 5.1 LinkPolicy 필드

| 영역 | 옵션 |
|---|---|
| 신원 | source/target type, workload ID, tenant |
| 행동 | 허용 operation·capability·purpose |
| 데이터 | 허용 등급, taint 전달, 마스킹 |
| 목적지 | domain, account, region, network zone |
| 위임 | actor/audience binding, hop, depth, TTL |
| 부작용 | read/write/delete/payment/permission |
| 승인 | 위험조건, 승인자, 만료, 2인 승인 |
| 예산 | 호출·token·비용·시간·fan-out |
| 증거 | metadata/hash/redacted/raw-encrypted |
| 장애 | fail policy, timeout, fallback |

## 6. Interlock Runtime

Runtime은 Policy Decision Point와 Policy Enforcement Point를 분리한다.

```mermaid
sequenceDiagram
    participant A as Source Actor
    participant G as ActorGuard/Gateway
    participant P as Policy Engine
    participant T as Target Actor
    participant L as Ledger

    A->>G: interaction request
    G->>P: actor + link + data + context
    P-->>G: decision + reason codes
    G->>L: CONTROL_EVALUATED
    alt ALLOW
        G->>T: invoke
        T-->>G: result
        G->>L: ACTION_RESULT + OUTCOME
    else HOLD/BLOCK
        G-->>A: denied or approval required
        G->>L: ACTION_RESULT
    end
```

정책 엔진 장애 시의 동작은 Runtime이 임의로 선택하지 않고 LinkPolicy의 `failureMode`를 따른다.

**현재 배포된 구현에서는 이 말이 들리는 것보다 범위가 좁다.** `src/`에서 `LinkPolicy.failure_mode`를 읽는 런타임 코드는 정확히 하나, `FAIL_CLOSED` 여부를 검사하는 `egress.py:145`뿐이다. 정책 판정 경로는 어디에서도 이 값을 참조하지 않으며, `DEGRADE_READ_ONLY`는 소비자가 아예 없다. 그 밖에 이 필드가 등장하는 곳은 모두 설계 시점 lint(`ARCH-BOUNDARY-FAIL-OPEN`, `ARCH-HIGH-RISK-FAIL-OPEN`) 아니면 manifest 직렬화다. `FAIL_CLOSED`를 선언하는 것은 여전히 옳고 linter가 요구하는 바이기도 하다. 다만 아직 엔진 전체에 걸친 런타임 스위치로 읽어서는 안 된다.

## 7. Interlock Ledger

Ledger는 다음 이벤트를 분리한다.

| 이벤트 | 의미 |
|---|---|
| Interaction Requested | 무엇을 요청했는가 |
| Data Flow Observed | 어떤 데이터가 이동했는가 |
| Control Evaluated | 어떤 통제가 무엇을 판정했는가 |
| Action Executed | 차단·격리·회수가 실행됐는가 |
| Interaction Completed | 대상 호출이 완료됐는가 |
| Security Outcome Set | 공격이 최종 성공했는가 |

`decision=BLOCK`, `action_result=FAILED`, `security_outcome=SUCCEEDED`를 별개 값으로 유지해야 탐지는 했지만 막지 못한 사고를 찾을 수 있다.

## 8. Interlock Graph

### 8.1 정적 설계 그래프

ActorSpec과 LinkPolicy에서 생성한다.

- 등록된 Actor와 owner
- 선언된 연결과 금지된 연결
- capability와 데이터 접근 범위
- 승인·예산·실패 정책
- 통제가 없는 Edge
- 과도한 권한과 순환 위임
- 단일 장애점

### 8.2 런타임 실행 그래프

Ledger의 trace에서 생성한다.

- 실제 호출 순서와 latency
- Agent → Sub-agent fan-out
- Tool·RAG·Memory 접근
- 데이터 민감도와 taint 전파
- 정책 판정과 차단 지점
- 부분 실행과 외부 부작용
- token·비용·재시도

### 8.3 공격 경로 그래프

```mermaid
flowchart LR
    D["악성 문서"] -->|"tainted"| R["RAG"]
    R --> A["Agent"]
    A -->|"PII READ"| C["CRM Tool"]
    C --> A
    A -->|"BLOCKED"| X["Unknown External"]

    classDef risk fill:#ffebee,stroke:#c62828
    classDef blocked fill:#e8f5e9,stroke:#2e7d32
    class D,R,A,C risk
    class X blocked
```

Edge를 선택하면 다음 정보를 제공한다.

- source/target Actor
- relationship과 operation
- 전달 데이터 등급과 크기
- 적용 Policy와 버전
- decision·reason code
- action result·security outcome
- 관련 trace·Incident·TG·ATLAS·ASI

### 8.4 선언과 실행의 차이

가장 중요한 탐지는 “실제 호출이 선언 그래프에 존재하는가”이다.

```text
Declared Edge 없음 + Runtime Call 있음  → UNDECLARED_RELATIONSHIP
Declared Tool digest ≠ Runtime digest    → ACTOR_DRIFT
Declared data class 초과                 → DATA_SCOPE_VIOLATION
Declared budget 초과                     → BUDGET_VIOLATION
Gateway event 없음 + Target event 있음   → CONTROL_BYPASS
```

## 9. Console 화면

1. **Inventory:** Actor, owner, identity, capability, health
2. **Design Graph:** 선언 관계와 통제 공백
3. **Live Graph:** 현재 trace와 실시간 판정
4. **Incidents:** 공격 경로, 영향 Actor, 대응 상태
5. **Policies:** LinkPolicy 작성·시뮬레이션·승격
6. **Controls:** Gateway·ActorGuard 상태와 우회율
7. **Data Flows:** 민감 데이터 이동과 목적지
8. **Tests:** red-team·simulation 결과와 회귀

## 10. 구현 우선순위

### 1단계 — SDK 최소 기능

- TypeScript 또는 Python ActorSpec
- `wrap()`과 `connect()`
- JSON Schema 입출력 검증
- OpenTelemetry trace 연동
- Event Envelope 생성

### 2단계 — Runtime과 Ledger

- Tool/RAG/Egress Gateway
- OBSERVE·SHADOW·ENFORCE
- PostgreSQL 이벤트 저장
- 판정–조치–결과 분리

### 3단계 — Graph

- ActorSpec 기반 정적 그래프
- trace 기반 런타임 그래프
- 미선언 Edge와 drift 탐지
- Incident 공격 경로 표시

### 4단계 — 다중 Agent 확장

- A2A Broker
- delegation lineage
- Memory provenance·rollback
- Scheduler·Sandbox
- 중앙 Console과 조직 단위 policy

## 11. MVP 완료 기준

- 개발자가 Actor 두 개를 선언하고 `connect()`로 관계를 만들 수 있다.
- 기존 Tool을 `wrap()`해 호출 전 정책을 집행할 수 있다. *(충족. 단 막다른 길이 하나 있다 — 외부 쓰기는 SDK에서 승인할 수 없다. §4.2 참고.)*
- 모든 호출에 trace와 Interaction Event가 생성된다.
- 선언되지 않은 Actor 관계를 탐지한다.
- 비신뢰 입력이 외부 쓰기 Tool로 전달될 때 HOLD/BLOCK한다.
- 정적 설계 그래프와 단일 trace 실행 그래프를 표시한다.
- 차단 판정과 실제 집행 결과를 별도로 조회한다.
- Runtime 장애 시 관계별 failureMode가 동작한다. *(부분 충족 — §6 참고. 현재 이 값을 읽는 곳은 `egress.py`뿐이다.)*

## 12. 제품 명명 체계

```text
제품              Agent Interlock
개발자 SDK         Interlock SDK
Actor 선언         ActorSpec
보안 Wrapper       ActorGuard
관계               InterlockLink
관계 정책          LinkPolicy
실행 계층          Interlock Runtime
이벤트 원장        Interlock Ledger
그래프              Interlock Graph
운영 UI            Interlock Console
```

공식 설명은 **“AI Agent 상호작용 보안 프레임워크”**로 사용한다.

