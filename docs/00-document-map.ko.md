---
title: Agent Interlock 문서 맵
date: 2026-07-21
version: 1.7
status: active
---

# Agent Interlock 문서 맵

> English version: [00-document-map.md](00-document-map.md)

이 문서는 프로젝트 문서의 입구다. 같은 개념을 여러 문서에서 서로 다르게 정의하지 않도록 각 문서의 책임과 읽기 순서를 고정한다.

## 1. 목적별 읽기 경로

| 독자·목적 | 먼저 읽을 문서 | 이어서 읽을 문서 |
|---|---|---|
| 제품 범위와 로드맵 파악 | [01 프로젝트 기획](01-project-plan.ko.md) | [02 개발자 프레임워크](02-developer-framework-design.ko.md) |
| Agent·Tool 연동 개발 | [02 개발자 프레임워크](02-developer-framework-design.ko.md) | [04 MCP Tool Gateway 명세](04-mcp-tool-gateway-spec.ko.md) |
| L1 위협과 공격 흐름 이해 | [03 L1 보안 프로파일](03-l1-mcp-tool-security-profile.ko.md) | [05 L1 검증 계획](05-l1-security-validation-plan.ko.md) |
| 정책·Gateway 구현 | [04 MCP Tool Gateway 명세](04-mcp-tool-gateway-spec.ko.md) | [01 프로젝트 기획](01-project-plan.ko.md#11-정책-판정과-집행) |
| 보안 시험과 운영 승격 | [05 L1 검증 계획](05-l1-security-validation-plan.ko.md) | [03 L1 보안 프로파일](03-l1-mcp-tool-security-profile.ko.md) |
| 설계 대비 현재 구현 확인 | [06 구현 상태](06-implementation-status.ko.md) | [04 MCP Tool Gateway 명세](04-mcp-tool-gateway-spec.ko.md) |
| 박스 기반 보안 아키텍처 설계 | [07 Security Architecture Studio](07-security-architecture-studio-design.ko.md) | [02 개발자 프레임워크](02-developer-framework-design.ko.md) |
| 실행 trace와 설계 drift 분석 | [08 Runtime Telemetry](08-runtime-telemetry-reconciliation.ko.md) | [07 Security Architecture Studio](07-security-architecture-studio-design.ko.md) |
| Architecture를 MCP 호출에 집행 | [09 MCP Transport 집행](09-mcp-transport-enforcement.ko.md) | [04 MCP Tool Gateway 명세](04-mcp-tool-gateway-spec.ko.md) |
| MCP OAuth discovery·token binding 구현 | [10 MCP OAuth Identity Guard](10-mcp-oauth-identity-guard.ko.md) | [09 MCP Transport 집행](09-mcp-transport-enforcement.ko.md) |
| 로컬 MCP process와 부작용 증거 구현 | [11 MCP stdio Sandbox·Receipt](11-mcp-stdio-sandbox-receipts.ko.md) | [09 MCP Transport 집행](09-mcp-transport-enforcement.ko.md) |
| PostgreSQL Ledger와 event/trace API 운영 | [12 PostgreSQL Ledger API](12-postgresql-ledger-api.ko.md) | [01 프로젝트 기획](01-project-plan.ko.md#9-postgresql-mvp-ddl) |
| Trust Boundary 기반 A2A·오케스트레이션 구현 | [13 A2A 오케스트레이션 플랫폼](13-a2a-orchestration-platform.ko.md) | [07 Security Architecture Studio](07-security-architecture-studio-design.ko.md) |
| 전체 플랫폼을 안전하게 E2E 검증 | [14 가짜 데이터 플랫폼 E2E](14-fake-platform-e2e-scenario.ko.md) | [13 A2A 오케스트레이션 플랫폼](13-a2a-orchestration-platform.ko.md) |
| 수동 Chrome E2E 화면 증거 확인 | [15 수동 브라우저 E2E 증거](15-manual-browser-e2e-evidence.ko.md) | [14 가짜 데이터 플랫폼 E2E](14-fake-platform-e2e-scenario.ko.md) |

## 2. 문서별 책임

| 문서 | 이 문서가 결정하는 것 | 이 문서가 결정하지 않는 것 |
|---|---|---|
| `01-project-plan.md` | 제품 목표, 공통 이벤트, DB, 탐지·대응 운영 모델 | MCP 프로토콜별 처리 절차 |
| `02-developer-framework-design.md` | ActorSpec, ActorGuard, LinkPolicy, Runtime, Graph 개발자 경험 | 위협별 세부 공격 재현 |
| `03-l1-mcp-tool-security-profile.md` | M1–M9의 경계·데이터·공격·통제와 제품 매핑 | API 세부 구현과 테스트 실행법 |
| `04-mcp-tool-gateway-spec.md` | MCP Gateway의 입력·출력·상태·정책·이벤트 계약 | 모든 L2/L3 관계의 구현 |
| `05-l1-security-validation-plan.md` | M1–M9 시험 절차, 기대 결과, 필수 증거, 승격 기준 | 프로덕션 Incident 대응 전 과정 |
| `06-implementation-status.md` | 설계 계약과 코드·시험의 현재 추적 상태 | 미구현 항목의 상세 설계 |
| `07-security-architecture-studio-design.md` | Architecture-as-Code, 보안 통제 보장 수준, Dynamic Edge, Canvas MVP | 운영 배포·승인 workflow의 세부 구현 |
| `08-runtime-telemetry-reconciliation.md` | Ledger·OTLP import/HTTP receiver, Interlock span 속성, drift와 signed evidence 신뢰 경계 | OTLP gRPC Collector·vendor adapter의 배포 설정 |
| `09-mcp-transport-enforcement.md` | Architecture compile, MCP JSON-RPC, Streamable HTTP, resumable SSE와 publisher provenance admission | 분산 session backend·고급 비동기 MCP 운영 구현 |
| `10-mcp-oauth-identity-guard.md` | OAuth discovery, PKCE, redirect/SSRF, introspection/JWKS, loopback consent와 token binding | IdP별 key/cache·UI·분산 transaction 저장소 운영 |
| `11-mcp-stdio-sandbox-receipts.md` | stdio 제한, 서명 attestation, Bubblewrap, Architecture-bound egress와 fake receipt reference | platform별 live sandbox·seccomp·egress proxy 설치·운영 정책 |
| `12-postgresql-ledger-api.md` | PostgreSQL adapter, RLS·append-only migration, `/v1/events`·trace API와 signed audit reference | HA proxy·pool·partition scheduler·외부 KMS/mTLS/WORM 운영 |
| `13-a2a-orchestration-platform.md` | 방향성 Trust Boundary, A2A 1.0 core, Task workflow와 runtime orchestration 계약 | 외부 IdP·분산 queue/store·streaming/push 운영 배포 |
| `14-fake-platform-e2e-scenario.md` | test-only fixture로 설계·승격·A2A·Run Control·승인·MCP·증거·Chrome E2E를 재현하는 절차와 합격 기준 | 실제 고객 데이터·외부 메일 전송·운영 adapter/queue/store 구성 |
| `15-manual-browser-e2e-evidence.md` | Chrome 브라우저 프레임을 제거한 1600×900 수동 E2E 화면 증거와 실행 결과 | 자동 회귀 시험의 합격 판정이나 운영 telemetry 무결성 보증 |

## 3. 추적 ID

문서와 코드, 이벤트, 시험 결과가 같은 대상을 가리키도록 다음 ID를 사용한다.

| 종류 | 형식 | 예시 |
|---|---|---|
| 위협 | `M1`–`M9` | `M2` Rug Pull |
| 관계 | `REL-nn` | `REL-05` Agent → Tool |
| 탐지 규칙 | `DET-nnn` | `DET-005` definition digest 불일치 |
| 사유 코드 | `L1-Mn-*` · 교차 `L1-*` · `INTERLOCK-*` · `A2A-*` · `MCP-*` | `L1-M5-TOKEN-AUDIENCE-MISMATCH`, `L1-UNDECLARED-SIDE-EFFECT`, `INTERLOCK-DATA-CLASS-DENIED`, `A2A-AUDIENCE-MISMATCH`, `MCP-OAUTH-CHALLENGE-SCOPE-MISMATCH` |
| 설계 시점 finding | `ARCH-*`(linter) · `ORCH-*`(workflow runtime) | `ARCH-DATA-CLASS-EXCEEDS-ACTOR`, `ORCH-MESSAGE-BUDGET` |
| 시험 | `L1-SIM-Mn-nnn`, 코어 `CORE-SIM-*` | `L1-SIM-M6-001`, `CORE-SIM-TENANT-001` |
| 정책 | 의미 있는 kebab-case ID | `mcp-tool-invoke-default` |

`M1–M9`는 연구·위협 분류 ID이고 `DET-*`는 구현된 탐지 규칙이다. 하나의 위협이 여러 규칙으로 구현될 수 있으므로 두 ID를 같은 것으로 취급하지 않는다.

사유 코드는 **집행점별**이다. 같은 통제가 MCP gateway에서는 `L1-M5-TOKEN-AUDIENCE-MISMATCH`를, A2A broker에서는 `A2A-AUDIENCE-MISMATCH`를 방출하므로 사유 코드 단위 집계는 집행점 사이에서 비교할 수 없다. 비교 가능한 것은 `policy.py`의 `CHECKS` 표에 있는 정본 check id다. `CORE-SIM-*`와 `L1-SIM-*`는 명세 ID이며 이를 구현하는 시험은 이 ID를 달고 있지 않다 — 특히 `CORE-SIM`은 `docs/` 밖의 어떤 파일에도 나타나지 않는다.

## 4. 데이터와 결과의 기준 정의

- 데이터 등급 `D1–D8`, 통과 지점 `P1–P7`, 위협 정의 `M1–M9`는 [03 L1 보안 프로파일](03-l1-mcp-tool-security-profile.ko.md)을 기준으로 한다.
- 공통 Event Envelope와 `CONTROL_DECISION`, `ACTION_RESULT`, `SECURITY_OUTCOME`은 [01 프로젝트 기획](01-project-plan.ko.md#6-이벤트-분류-체계)을 기준으로 한다.
- MCP 전용 payload와 reason code는 [04 MCP Tool Gateway 명세](04-mcp-tool-gateway-spec.ko.md)를 기준으로 한다.
- 공격 재현의 합격·불합격 판정은 [05 L1 검증 계획](05-l1-security-validation-plan.ko.md)을 기준으로 한다.

판정, 집행, 보안 결과는 반드시 분리한다. 예를 들어 정책이 `BLOCK`을 반환했더라도 집행이 `FAILED`이고 외부 전송이 성공했다면 최종 결과는 `SUCCEEDED`다.

## 5. 원전과 프로젝트 문서의 관계

이 프로젝트 문서는 다음 연구 문서를 제품 구현 관점으로 변환한 것이다.

- `agentic-위협매트릭스-통합-최종-v3-2026-07.md` v3.3: 전체 위협 분류와 관계·통제 기준
- `agentic-l1-mcp-tool-위협-기술명세-v1-2026-07.md` v1.0: L1 M1–M9의 조사 근거와 공격 상세

원전은 위협의 근거와 범위를 설명하고, 이 저장소는 Agent Interlock가 무엇을 수집·판정·집행·검증해야 하는지 정의한다. 연구 문서가 갱신되면 바로 구현을 바꾸지 않고 다음 순서로 반영한다.

1. `03`의 위협·데이터 흐름 변경 여부를 검토한다.
2. 변경된 통제가 있으면 `04`의 정책·이벤트 계약 버전을 올린다.
3. `05`에 회귀 시험을 추가한다.
4. 구현과 운영 정책이 배포된 뒤 문서 상태를 `active`로 바꾼다.

## 6. 문서 상태

| 상태 | 의미 |
|---|---|
| `planning` | 제품 방향이며 구현 계약으로 사용하지 않음 |
| `draft` | 리뷰 가능한 초안, 호환성 보장 없음 |
| `proposed` | 구현 후보 계약, 승인 전 |
| `active` | 코드·정책·시험이 따라야 하는 기준 |
| `deprecated` | 새 문서로 대체, 신규 구현 금지 |

현재 `03`–`05`는 최초 구현 전의 `proposed` 문서다. 구현 시 실제 타입·JSON Schema·정책 번들과 함께 버전을 고정해야 한다.
