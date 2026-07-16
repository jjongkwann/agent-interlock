---
title: Agent Interlock MCP Tool Gateway 기술 명세
tags: [agent-interlock, mcp, gateway, policy, event-contract]
date: 2026-07-17
version: 1.2
status: proposed
---

# Agent Interlock MCP Tool Gateway 기술 명세

> 대상: Runtime, Policy Engine, SDK, Connector, Ledger 구현자<br>
> 범위: `tools/list`, `tools/list_changed`, `tools/call`, Tool result, OAuth/credential, Connector 실행 경계

## 1. 책임과 비책임

MCP Tool Gateway는 MCP Host/Client와 Server 사이의 정책 집행점이다. 다음을 책임진다.

- Server와 Tool의 안정적인 Actor identity 부여
- Tool 정의 정규화, digest, 승인 상태와 drift 관리
- 호출 인수의 schema·데이터·목적지·부작용 판정
- hop별 credential binding과 token passthrough 차단
- Connector의 URL·process·filesystem·network 제한
- 반환 데이터의 schema·taint·secret 검사
- 판정, 집행, 결과를 분리한 Ledger 이벤트 생성

Gateway는 LLM malware detector, 범용 endpoint security, package scanner 전체를 대체하지 않는다. Remote Server 내부의 보이지 않는 행동은 downstream audit와 egress reconciliation으로 보완한다.

## 2. 논리 컴포넌트

| 컴포넌트 | 입력 | 출력 | 주요 위협 |
|---|---|---|---|
| Server Registry | endpoint, publisher, transport, artifact | server actor, trust state | M2, M4, M7 |
| Definition Registry | `tools/list` D1 | canonical definition, digest, state | M1–M3 |
| Tool Discovery Guard | raw D1 | model-visible sanitized D1 | M1, M3 |
| Tool Call Guard | D2, D3, Actor/LinkPolicy | decision, sanitized args | M1, M3, M8, M9 |
| Identity Guard | D5 claims, link context | bound/downscoped credential | M5 |
| Connector Sandbox | URL, command, request | constrained execution evidence | M4, M6 |
| Result Guard | D4 | sanitized/tainted result | M1, M6, M8 |
| Egress/Transaction Guard | destination, D7, side effect | allow/hold/block, receipt | M9 |
| Ledger Adapter | all stages | normalized events | M1–M9 |

## 3. 안정적인 식별자

```text
server_id = tenant/environment/registry-key
tool_id   = server_id + ":" + tool_name
definition_revision_id = tool_id + "@" + canonical_digest
```

표시 이름, title, endpoint만으로 Actor를 식별하지 않는다. Server가 같은 이름의 Tool을 제공해도 namespace가 다르면 다른 Actor다.

## 4. Tool 정의의 정규화와 상태

### 4.1 Canonical definition

Digest에는 최소 다음 필드를 포함한다.

```yaml
serverId: tenant-a/prod/trusted-mail
toolName: send_email
title: Send email
description: Send a message to approved recipients.
inputSchema: { canonical-json-schema: true }
outputSchema: { canonical-json-schema: true }
annotations: {}
endpoint: https://mcp.example.com
transport: streamable-http
publisher: platform-team
artifactDigest: sha256:...
```

- JSON object key를 정렬하고 숫자·Unicode·line ending을 정규화한다.
- 보안 의미가 있는 description 공백·비가시 문자를 제거하지 않은 raw digest도 별도로 보존한다.
- secret이 포함될 수 있는 값은 원문 대신 암호화된 evidence reference 또는 hash를 저장한다.
- canonicalizer 버전을 digest 입력에 포함해 버전 변경을 감사할 수 있게 한다.

### 4.2 상태 머신

```mermaid
stateDiagram-v2
    [*] --> DISCOVERED
    DISCOVERED --> QUARANTINED: policy evaluation
    QUARANTINED --> APPROVED: review/signature accepted
    APPROVED --> ACTIVE: policy deployed
    ACTIVE --> DRIFTED: effective digest changed
    DRIFTED --> QUARANTINED: automatic isolation
    QUARANTINED --> REJECTED: review denied
    QUARANTINED --> APPROVED: new revision approved
    ACTIVE --> REVOKED: incident or publisher revocation
```

`ACTIVE` revision만 호출할 수 있다. `tools/list_changed`는 자동 승인 신호가 아니라 새 `DISCOVERED` revision 생성 신호다.

## 5. ActorSpec 확장

기본 ActorSpec에 MCP 전용 필드를 추가한다.

```yaml
apiVersion: interlock.dev/v1alpha1
kind: Actor
metadata:
  id: tool.trusted-mail.send-email
  owner: customer-platform
  tenant: tenant-a
spec:
  type: TOOL
  identity: spiffe://prod.example/mcp/trusted-mail/send-email
  capabilities: [EMAIL_SEND]
  dataAccess: [CUSTOMER_NAME, CUSTOMER_EMAIL]
  sideEffects: [EXTERNAL_WRITE]
  tenantMode: REQUIRED
  failureMode: FAIL_CLOSED
  mcp:
    serverId: tenant-a/prod/trusted-mail
    toolName: send_email
    transport: streamable-http
    endpoint: https://mcp.example.com
    publisher: platform-team
    artifactDigest: sha256:...
    definitionDigest: sha256:...
    credentialMode: TOKEN_EXCHANGE
    sandboxProfile: remote-mcp-restricted
  destinations:
    allowedDomains: [customer.example]
  schemas:
    input: schemas/send-email-input.json
    output: schemas/send-email-output.json
```

`definitionDigest`는 승인 revision을 가리킨다. 실제 `tools/list`에서 관측된 digest는 Registry가 관리하고 실행 전에 둘을 비교한다.

## 6. LinkPolicy 확장

```yaml
apiVersion: interlock.dev/v1alpha1
kind: LinkPolicy
metadata:
  id: mcp-tool-invoke-default
  version: 1.0.0
spec:
  sourceTypes: [AGENT, SUBAGENT]
  targetTypes: [TOOL]
  relationship: INVOKES
  mode: SHADOW
  toolDefinition:
    requireState: ACTIVE
    requireDigestPin: true
    allowCrossServerReferences: false
  data:
    allowedClasses: [D2, D3, D7]
    deniedClasses: [D5, D8]
    propagateTaint: true
    secretAction: BLOCK
  destination:
    requireExplicit: true
    newDestinationAction: HOLD
  authorization:
    tokenPassthrough: false
    requireAudience: true
    requireResource: true
    requireActorBinding: true
    maxDelegationDepth: 1
  sideEffects:
    externalWrite: REQUIRE_APPROVAL
    destructiveWrite: BLOCK
    undeclared: BLOCK        # 관측된 부작용이 ActorSpec 선언 집합에 없으면 차단
  failureMode: FAIL_CLOSED
```

정책은 Tool description이 안전하다고 판정했더라도 D3와 실제 목적지를 독립적으로 평가한다. `mode`는 `OBSERVE`, `SHADOW`, `ENFORCE` 중 하나이며 이벤트에는 평가 모드와 실제 집행 여부를 모두 기록한다.

## 7. 처리 파이프라인

### 7.1 `tools/list`

```text
Server 인증 → raw 응답 크기·schema 제한 → Tool별 namespace 부여
→ raw/canonical digest 계산 → 기존 승인 revision 비교
→ metadata injection·cross-server reference·권한 과장 검사
→ 상태 결정 → model-visible D1 생성 → Registry·Ledger 기록
```

규칙 위반 Tool만 격리할 수 있으나 응답 전체의 무결성이 의심되거나 Server identity가 불명확하면 Server 전체를 격리한다.

### 7.2 `tools/call`

```text
D2 purpose·provenance 수신 → source/target Actor resolve
→ ACTIVE/approved digest 확인 → D3 schema 검증
→ taint·secret·데이터 등급 분류 → 목적지 canonicalization
→ token binding·scope 검증 → side effect·approval 판정
→ Ledger에 CONTROL_EVALUATED 기록
→ ALLOW 시 Connector 실행 → ACTION_EXECUTED 기록
```

판정 후 실제 전송 전까지 D3가 바뀌지 않도록 `arguments_hash`를 Connector에 결합한다. 승인도 같은 hash와 destination set에 결합하며 인수가 바뀌면 승인을 무효화한다.

### 7.3 Tool result

```text
응답 크기·content type 제한 → output schema 검증
→ URL/resource 안전성 검사 → secret·PII·instruction-like content 탐지
→ provenance·taint 부여 → 허용 필드만 Host에 반환
→ INTERACTION_COMPLETED와 DATA_FLOW_OBSERVED 기록
```

Tool result를 다음 모델 turn에 넣을 때 `UNTRUSTED_TOOL_RESULT` taint를 유지한다. 결과 안의 지시는 정책이나 시스템 명령으로 승격되지 않는다.

### 7.4 OAuth와 authorization URL

- authorization endpoint는 등록 metadata와 일치해야 한다.
- `https` 이외 scheme은 기본 거부한다. loopback은 명시된 local 개발 profile에서만 허용한다.
- redirect chain마다 scheme, host, port, resolved IP를 다시 검증한다.
- URL은 shell command로 조립하지 않으며 argument array 또는 OS 안전 API를 사용한다.
- token은 hop별 교환하고 audience/resource가 다른 downstream에 그대로 전달하지 않는다.

### 7.5 선언–관측 대사 (declaration reconciliation)

Gateway는 개발자가 선언한 ActorSpec을 무조건 신뢰하지 않는다. 관측한 행동이 선언 집합의 부분집합인지 검사하되, **집행 시점을 반드시 구분한다.** 실행 전에 예측 가능한 초과만 사전 차단할 수 있고, 실행 후에야 드러나는 초과는 탐지·회수·보상 대상이다. "관측했으니 막았다"로 뭉치면 이미 나간 외부 쓰기를 못 막은 사건을 숨긴다.

| 시점 | 근거 | 초과 시 처리 |
|---|---|---|
| 실행 전 (`estimatedSideEffect`, D3 기준) | `tools/call` 평가 단계(§7.2) | `BLOCK` — dispatch 안 되므로 receipt 0 |
| 실행 후 (`observed`/`completed`, downstream receipt) | 결과·reconciliation 단계(§8.1) | `DETECTION_RAISED` → `REVOKE`/`KILL`/보상 — 외부 쓰기가 이미 발생했을 수 있음 |

```text
estimated sideEffect  ⊄ ActorSpec.sideEffects  (실행 전) → L1-UNDECLARED-SIDE-EFFECT / BLOCK
estimated destination ⊄ ActorSpec.destinations (실행 전) → L1-M9-NEW-DESTINATION / HOLD
observed  sideEffect  ⊄ ActorSpec.sideEffects  (실행 후) → L1-UNDECLARED-SIDE-EFFECT / REVOKE·보상
```

- 실행 전 estimated 초과는 `tools/list` 정의 검사(§7.1)를 통과했더라도 평가 단계(§7.2)에서 막는다. `ExecuteApprovedCall`(§10)이 유효 decision 없이는 dispatch하지 않으므로 receipt는 0이다.
- Remote Server 내부의 보이지 않는 egress는 실행 전에 못 보므로(§1) **사전 차단을 보장할 수 없다.** downstream receipt reconciliation(§8.1)으로 사후 탐지하고 토큰 회수·보상 트랜잭션으로 처리한다.
- 이 대사가 없으면 미선언(under-declaration)이 통제 우회 경로가 된다. 신뢰 근거는 "무엇을 사전에 막고 무엇을 사후에 회수하는지"를 분리해 기록하는 것이다.

## 8. 이벤트 계약

공통 Envelope는 [01 프로젝트 기획](01-project-plan.md#61-공통-event-envelope)을 따른다. MCP payload 최소 필드는 다음과 같다.

```yaml
payload:
  mcp:
    protocolVersion: "2025-11-25"
    serverId: tenant-a/prod/trusted-mail
    transport: streamable-http
    method: tools/call
  toolDefinition:
    toolId: tenant-a/prod/trusted-mail:send_email
    revisionId: "...@sha256:..."
    observedDigest: sha256:...
    approvedDigest: sha256:...
    state: ACTIVE
  invocation:
    callId: call-...
    purpose: customer-case-reply
    argumentsHash: sha256:...
    destinationIds: [email:customer@example.com]
    dataClasses: [D3, D7]
    sensitivity: CONFIDENTIAL
    estimatedSideEffect: EXTERNAL_WRITE
  authorization:
    credentialFingerprint: sha256:...
    issuer: https://idp.example
    subject: user-123
    actor: agent.support
    audience: https://mail-api.example
    resource: mail
    scopes: [mail.send]
    delegationParentId: null
  control:
    policyId: mcp-tool-invoke-default
    policyVersion: 1.0.0
    mode: ENFORCE
    decision: HOLD
    reasonCodes: [L1-M9-NEW-DESTINATION]
  action:
    result: COMPLETED
    connectorExecutionId: null
  outcome:
    securityOutcome: BLOCKED
    downstreamTransactionId: null
```

### 8.1 이벤트 시퀀스

| 단계 | 이벤트 | 완료 조건 |
|---|---|---|
| 요청 접수 | `INTERACTION_REQUESTED` | toolId, revision, D3 hash 존재 |
| 데이터 경계 통과 | `DATA_FLOW_OBSERVED` | source, destination, data class, taint 존재 |
| 정책 평가 | `CONTROL_EVALUATED` | policy version, decision, reason code 존재 |
| 실제 집행 | `ACTION_EXECUTED` | action result와 connector ID 존재 |
| 호출 완료 | `INTERACTION_COMPLETED` | protocol status, latency, result hash 존재 |
| 보안 결과 | `SECURITY_OUTCOME_SET` | 공격 성공/차단/부분 실행 여부 확정 |

동일 `interaction_id`로 묶고, Server 내부 transaction은 `downstream_transaction_id`로 reconciliation한다.

## 9. Reason code

| Code | 조건 | 기본 판정 |
|---|---|---|
| `L1-M1-METADATA-INSTRUCTION` | D1에 기능과 무관한 명령·데이터 접근 요구 | `QUARANTINE` |
| `L1-M2-DEFINITION-DRIFT` | observed와 approved digest 불일치 | `QUARANTINE` |
| `L1-M3-CROSS-SERVER-REFERENCE` | D1이 다른 namespace Tool을 조종 | `BLOCK` |
| `L1-M4-UNTRUSTED-PUBLISHER` | provenance/signature 정책 실패 | `QUARANTINE` |
| `L1-M4-SIGNATURE-INVALID` | trusted publisher의 provenance 서명 누락·불일치 | `QUARANTINE` |
| `L1-M4-PROVENANCE-DENIED` | repository·revision·build provenance 정책 실패 | `QUARANTINE` |
| `L1-M4-EGRESS-DENIED` | runtime 목적지가 exact egress allowlist 밖 | `BLOCK`+workload 종료 |
| `L1-M4-EGRESS-BINDING-MISMATCH` | tenant·workload·artifact·provenance·sandbox profile 불일치 | `BLOCK`+workload 종료 |
| `L1-M4-PROCESS-TERMINATION-FAILED` | egress 차단 뒤 workload 종료 확인 실패 | `BLOCK`+Incident |
| `L1-M5-TOKEN-AUDIENCE-MISMATCH` | token audience/resource 불일치 | `BLOCK` |
| `L1-M5-TOKEN-PASSTHROUGH` | 교환 없는 downstream 전달 | `BLOCK` |
| `L1-M6-UNSAFE-AUTH-URL` | scheme/host/redirect/IP 정책 실패 | `BLOCK` |
| `L1-M7-CONFIG-DRIFT` | runtime과 승인 config digest 불일치 | `BLOCK` |
| `L1-M8-CREDENTIAL-DETECTED` | D3/D4/context에서 D5 fingerprint 탐지 | `SANITIZE`/`BLOCK` |
| `L1-M9-NEW-DESTINATION` | 승인되지 않은 외부 목적지 | `HOLD` |
| `L1-M9-SENSITIVE-EGRESS` | 민감 D7이 외부 쓰기로 이동 | `BLOCK`/`HOLD` |
| `L1-UNDECLARED-SIDE-EFFECT` | 부작용이 ActorSpec 선언 sideEffects를 초과 | 실행 전 `BLOCK` · 실행 후 `REVOKE`+보상 |

`L1-Mn-*`는 특정 위협에 묶인 코드이고, `L1-UNDECLARED-*`처럼 여러 위협에 걸치는 교차 코드는 `L1-*` 형식을 쓴다. Reason code는 안정적인 분석 키다. 사람용 설명은 별도 필드로 지역화하며 code 의미를 재사용해 바꾸지 않는다.

## 10. 내부 API 경계

```text
RegisterServer(serverSpec) -> serverId, trustState
ObserveDefinitions(serverId, rawToolsList) -> revisions[], decisions[]
EvaluateInvocation(actor, toolRevision, intent, arguments, credentialRef) -> decision
ExecuteApprovedCall(decisionId, argumentsHash) -> connectorExecutionId
InspectResult(connectorExecutionId, rawResult) -> sanitizedResult, labels[]
ReconcileTransaction(connectorExecutionId, downstreamReceipt) -> securityOutcome
```

- `ExecuteApprovedCall`은 만료되지 않은 decision과 동일 `argumentsHash`가 없으면 실행하지 않는다.
- 호출자는 credential 원문을 Policy Engine에 보내지 않고 Identity Guard의 opaque reference를 사용한다.
- 모든 mutation API는 idempotency key와 tenant를 요구한다.

## 11. 장애와 우회 방지

| 실패 | 기본 동작 | 필수 이벤트 |
|---|---|---|
| Policy Engine timeout | 고위험/외부 쓰기 `FAIL_CLOSED` | `CONTROL_HEALTH_CHANGED`, `CONTROL_EVALUATED(ERROR)` |
| Ledger 지연·중단 | 읽기만 제한 허용, 외부 쓰기 `DEGRADE_READ_ONLY` | local spool 상태 |
| Definition Registry 불가 | 새 Tool·변경 Tool 차단, cache된 ACTIVE만 TTL 내 허용 | cache revision/age |
| Identity Provider 불가 | token 재사용 확대 금지, 쓰기 차단 | issuer health |
| Connector sandbox 실패 | 실행 금지 | sandbox start error |
| 결과 검사 실패 | 결과를 모델에 주입하지 않고 격리 | result evidence ref |

Gateway를 우회한 direct Server 연결은 네트워크 정책과 SDK trace gap 규칙으로 탐지한다. Agent 로그는 있는데 Gateway `INTERACTION_REQUESTED`가 없으면 bypass incident를 생성한다.

## 12. 개인정보와 증거

- D5 원문, 전체 prompt, 전체 D7 payload를 기본 Ledger에 저장하지 않는다.
- hash만으로 분석할 수 없는 사례는 암호화 evidence store에 TTL과 접근 승인을 두고 reference만 기록한다.
- URL query, header, error message도 credential 가능성이 있으므로 redaction 후 저장한다.
- 목적지 email·account는 운영 검색용 tokenization과 forensic 암호화를 분리한다.
- canonical digest 재현에 필요한 원본은 접근 통제된 registry evidence에 저장한다.

## 13. 구현 순서

1. Definition Registry와 canonical digest, `ACTIVE/DRIFTED` gate
2. `tools/call` schema·목적지·side effect 판정과 이벤트
3. Identity Guard와 token exchange/binding
4. URL validator와 Connector sandbox
5. Result Guard, taint, secret DLP
6. downstream receipt reconciliation과 Graph 상관분석

각 단계는 [05 L1 검증 계획](05-l1-security-validation-plan.md)의 해당 시험이 자동화된 뒤 `ENFORCE`로 승격한다.
