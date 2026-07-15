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

## 기본 구현 전략

1. 단일 Agent 서비스에서 User→Agent, Agent→RAG, Agent→Tool, Agent→External 관측
2. PostgreSQL 기반 Interaction Ledger 구축
3. OBSERVE → SHADOW → ENFORCE 단계적 승격
4. ActorSpec·LinkPolicy를 코드와 manifest로 지원
5. 정적 설계 그래프와 런타임 trace 그래프 제공
6. A2A·Memory·Scheduler·Sandbox로 확장
