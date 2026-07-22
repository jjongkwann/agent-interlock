---
title: 가짜 데이터 기반 플랫폼 E2E 시나리오
date: 2026-07-21
version: 1.1
status: active
---

# 가짜 데이터 기반 플랫폼 E2E 시나리오

> English version: [14-fake-platform-e2e-scenario.md](14-fake-platform-e2e-scenario.md)

## 1. 목표와 안전 경계

이 시나리오는 Agent Interlock의 전체 폐쇄 루프를 하나의 자동화된 시험으로 검증한다. 가짜 고객 데이터와 transport adapter는 이 시험 경로에서만 사용하며 Studio와 제품 runtime에는 내장 demo 실행이나 fake 성공 fallback을 두지 않는다.

```text
Design manifest
  → lint / SHADOW compile
  → git propose / Ed25519 2인 승인 / ENFORCE
  → Orchestration Engine
  → 실제 localhost A2A HTTP carrier
  → A2A Broker / Trust Boundary
  → Human approval pause / resume
  → MCP Transport / Gateway
  → fake connector receipt
  → Ledger / Runtime Graph / Statistics / Drift
```

모든 고객·테넌트·지식·영수증은 [`tests/fixtures/platform_e2e/fake_customer_support.json`](../tests/fixtures/platform_e2e/fake_customer_support.json)에 고정한다. 주소는 IANA 예약 TLD인 `.invalid`를 사용하며, fake MCP server는 process 안에서 응답할 뿐 DNS·메일·외부 API를 호출하지 않는다. A2A만 OS가 할당한 `127.0.0.1` 임시 포트에서 실제 HTTP carrier를 통과한다.

## 2. 정상 시나리오

| 단계 | 실행 | 합격 증거 |
|---|---|---|
| 1. 설계 | Support Agent, Research Sub-Agent, Send Email Tool, zone, 방향성 boundary, task DAG를 읽는다. | Architecture parser와 linter가 critical finding 없이 통과한다. |
| 2. Tool admission | fake `tools/list` 결과를 발견하고 exact canonical digest를 manifest에 pin한다. | 승인 전 Tool은 노출되지 않고 observed revision digest가 생성된다. |
| 3. Compile | `architecture compile --shadow`를 실행한다. | bundle digest가 Actor·Edge뿐 아니라 전체 Architecture, boundary 3개와 task 2개를 포함한다. |
| 4. Deploy | 임시 git store에 propose하고 서로 다른 두 Ed25519 identity가 승인한다. | active bundle이 `ENFORCE`, approver가 2명이며 digest 재계산이 일치한다. |
| 5. A2A 실행 | Engine이 `task.research`를 실제 localhost HTTP `SendMessage`로 전송한다. | Origin·bearer·A2A-Version과 REL-06/boundary가 handler 전에 검사되고 A2A Task가 완료된다. |
| 6. 승인 정지 | 후속 `task.send-reply`는 human approval을 요구한다. | run은 `WAITING_APPROVAL`, fake MCP 호출 횟수는 0이다. |
| 7. Resume | 가짜 승인 후 같은 run을 resume한다. | 완료된 A2A task는 replay되지 않고 MCP fake send가 정확히 1회 실행된다. |
| 8. 관측 | Ledger를 Runtime·Statistics reducer에 넣는다. | 설계 drift 0, bypass 0, SIMULATION interaction 2·실행 시도 2·성공 2다. |

## 3. 실패 시나리오

두 가지 fail-closed 경로를 같은 시험에 포함한다.

1. `D5` 데이터를 Research Sub-Agent로 보내면 방향성 A2A boundary가 handler 실행 전에 `A2A-BOUNDARY-DATA-CLASS-DENIED`로 차단한다. handler 호출 횟수는 늘지 않고 `enforcedBlockCount`가 1 증가해야 한다.
2. 선언되지 않은 `agent.support → external.rogue-fake` 이벤트를 SIMULATION Ledger에 넣으면 Runtime 비교가 undeclared edge 1개와 control bypass interaction ID를 정확히 보고해야 한다.

별도 회귀 시험은 REL-06 Edge에서 `boundaryId`를 제거했을 때 배포 전에 `ARCH-BOUNDARY-MISSING`이 발생하는지도 확인한다.

## 4. 실행 방법

```bash
# 플랫폼 E2E만 빠르게 실행
.venv/bin/python -m pytest -q tests/test_platform_e2e.py

# 실제 Control Plane HTTP route 기반 run 생성·승인·취소 시험
.venv/bin/python -m pytest -q tests/test_run_control.py

# Chrome Studio에서 export한 바로 그 revision으로 같은 E2E 실행
AGENT_INTERLOCK_PLATFORM_E2E_MANIFEST="$HOME/Downloads/agent-interlock-architecture.json" \
  .venv/bin/python -m pytest -q tests/test_platform_e2e.py::FakePlatformE2ETests::test_design_deploy_execute_observe_and_fail_closed

# 전체 Python 회귀
.venv/bin/python -m pytest -q

# Studio 계약·UI 회귀
cd studio
npm run lint
npm test
npm run build
```

자동화 본체는 [`tests/test_platform_e2e.py`](../tests/test_platform_e2e.py)다. 임시 git repository, 임시 A2A socket, in-memory Ledger를 매 실행마다 새로 만들므로 반복 실행해도 실제 운영 상태를 변경하지 않는다.

기본 자동 회귀는 checked-in reference manifest를 사용한다. `AGENT_INTERLOCK_PLATFORM_E2E_MANIFEST`를 지정하면 Studio에서 export한 revision을 그대로 읽고 coordinator, A2A target, MCP target과 task ID를 manifest에서 찾아 같은 시나리오를 실행한다. 따라서 Studio 기본 예제처럼 외부 RAG boundary가 하나 더 있는 revision도 별도 코드 수정 없이 전체 실행 계약을 검증할 수 있다.

## 5. Studio 수동 확인표

| 화면 | 조작 | 기대 결과 |
|---|---|---|
| Design / Task workflow | A2A task 추가 | task/A2A 수가 증가하고 acceptance criteria 누락 warning이 나타난다. |
| Inspector | fake acceptance criteria 입력 | warning이 사라지고 posture가 정상화된다. |
| Dependency | cycle을 만드는 dependency 선택 | 선택 버튼이 비활성화된다. |
| Security check | 검사 실행 | 현재 draft의 finding 수가 명시적으로 표시된다. |
| Graph canvas | mouse wheel, macOS `Command+=/-`, Windows `Ctrl+=/-` | graph zoom만 바뀌고 Chrome page zoom은 바뀌지 않는다. canvas 밖 shortcut은 브라우저 기본 동작을 유지한다. |
| Runtime | telemetry 없이 진입 | Design을 복사하지 않고 관측 사실이 없음을 표시한다. |
| Runs | test-only Control Plane에 연결해 run 시작·승인 | active ENFORCE digest가 표시되고 WAITING_APPROVAL task 승인 후 COMPLETED가 된다. |
| Drift | 시험 세션에서 `studio/tests/fixtures/drift-demo.json` import | undeclared edge와 control bypass가 구분되어 표시된다. |
| Statistics | SIMULATION Ledger import | production과 분리된 interaction lifecycle 통계가 표시된다. |
| Deploy | bundle/control-plane 상태 조회 | 브라우저에는 개인키가 없고 compile·서명·승격은 외부 CLI/Control Plane 책임으로 남는다. |

Studio의 Runs 탭은 `POST/GET /v1/runs`와 approve/resume/cancel/events route에 직접 연결된다. 브라우저 E2E에서는 CORS가 허용된 loopback test Control Plane을 사용하고, test fixture와 adapter는 그 서버 프로세스에서만 주입한다. 실제 배포에서는 host가 운영 A2A/MCP/LOCAL/HUMAN adapter와 durable store를 주입해야 한다.
