---
title: 기존 Agent에 Agent Interlock 붙이기
date: 2026-09-08
version: 1.0
status: active
---

# 기존 Agent에 Agent Interlock 붙이기

> English: [16-adding-interlock-to-an-agent.md](16-adding-interlock-to-an-agent.md)

도구를 쓰는 기존 agent를, 모든 도구 호출이 판정되고 기록되고 검증 가능한 agent로 바꾸는 10분짜리
경로입니다. Anthropic Python SDK의 Tool Runner를 씁니다. agent 루프는 SDK의 것이고, 도구는 여러분의
것이며, Agent Interlock은 그 사이에 섭니다.

먼저 저장소 루트에서 Python 3.11+ 가상환경을 만들고 설치합니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[anthropic,jwt]'
python examples/secure_email.py
```

이 페이지의 `build()`는 로컬 manifest를 읽는 SDK 도입 경로이며, 승격된 배포를 검증하지 않습니다. 검토된 배포를 실행하려면 [managed support host](managed-support-host.md)의 `load_promoted_architecture`, `build_managed_tools` 경로를 사용합니다.

## 1. 선언하는 것

세 가지뿐입니다.

1. **manifest** (`architecture.json`): Actor(여러분의 agent, 각 도구, 그 도구가 닿는 외부 시스템)와
   그 사이의 edge 및 정책. Studio에서 그리거나 직접 씁니다. `interlock architecture lint`가 빠진 것을
   알려줍니다.
2. **도구별 `ToolDefinition`**: 이름, 설명, 입력·출력 JSON Schema, MCP annotations. 목적지를 담는
   속성에는 `format: "email"`, `format: "uri"`, `format: "hostname"` 또는
   `x-interlock-destination: true`를, 읽기 전용 도구에는 `readOnlyHint: true`를 표시합니다. 지원하는
   스키마 키워드는 `type`, `required`, `properties`, `additionalProperties`, `items`, `enum`,
   `maxLength`, `pattern`이며, 그 밖의 키워드는 정의 시점에 거부됩니다. 검사되지 않고 통과하는 것은
   없습니다.
3. **도구별 `ToolBinding`**: 정의, 그것을 구현하는 Python 함수, manifest에서의 노드 id, 호출 목적.

## 2. 프로젝트 모듈

`interlock architecture skeleton <manifest> --out-dir .`가 이 파일을 생성합니다. 직접 써도 같은
모양입니다.

```python
import json
from pathlib import Path
from agent_interlock import (
    ArchitectureGraph, MCPToolGateway, ToolBinding, ToolDefinition, bind_architecture, guard_tools,
)

MANIFEST = Path(__file__).with_name("architecture.json")
TENANT_ID = "tenant-dev"
SOURCE_ACTOR_ID = "agent.support"

send_email_definition = ToolDefinition(
    server_id="tool.send-email", tool_name="send_email", title="Send email",
    description="Send a support reply to the customer.",
    input_schema={"type": "object", "required": ["to", "body"], "additionalProperties": False,
                  "properties": {"to": {"type": "string", "format": "email"},
                                 "body": {"type": "string", "maxLength": 2000}}},
    output_schema={"type": "object", "required": ["status"],
                   "properties": {"status": {"type": "string"}}},
)

def send_email(arguments):
    ...  # 실제 구현
    return {"status": "sent"}

BINDINGS = (ToolBinding(send_email_definition, send_email, "tool.send-email", "SUPPORT_REPLY"),)

def build(bindings=BINDINGS, *, ledger=None):
    gateway = MCPToolGateway(ledger=ledger)
    graph = ArchitectureGraph.from_dict(json.loads(MANIFEST.read_text()))
    bind_architecture(gateway, graph,
                      tool_bindings={b.definition.tool_name: b.actor_id for b in bindings},
                      approver="platform-review")
    tools = guard_tools(gateway, tenant_id=TENANT_ID, source_actor_id=SOURCE_ACTOR_ID,
                        bindings=bindings, approver="platform-review")
    return gateway, tools
```

`build()`는 각 정의를 관찰하고 승인·활성화하며, 격리된 정의(숨은 지시, 다른 서버 참조, 미지원 스키마
키워드)의 도구는 돌려주지 않습니다. 모델은 그런 도구를 보지 못합니다.

## 3. agent 루프

사용할 API 계정과 모델에 맞춰 `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`을 설정합니다.

```python
import os
import anthropic
gateway, tools = build()
client = anthropic.Anthropic()
runner = client.beta.messages.tool_runner(
    model=os.environ["ANTHROPIC_MODEL"], max_tokens=16000, tools=list(tools),
    messages=[{"role": "user", "content": "Where is order 1001? Email the customer."}],
)
final = runner.until_done()
```

보호된 도구는 모델이 호출할 때마다 네 가지를 합니다. 인자와 정의에서 intent를 도출하고, 게이트웨이에
판정을 요청하고, 허용될 때만 여러분의 함수를 실행하고, 정제된 결과를 돌려줍니다. 거부된 호출은
사유 코드를 담은 `is_error` tool result로 모델에 전달되어 모델이 정책 안에서 설명하거나 재시도할 수
있습니다. 루프 밖으로 예외가 던져지지 않습니다.

**승인.** `externalWriteRequiresApproval: true`인 edge는 외부 쓰기를 `INTERLOCK-APPROVAL-REQUIRED`로 보류합니다. `guard_tools(..., approve=...)`에 reviewer 신원을 반환하거나 `None`으로 거부하는 callback을 넘깁니다. Adapter는 tenant, source·target, active revision, 설치된 policy, 전체 derived intent, 정확한 인자에 승인을 결합하고 다시 판정합니다. `gateway.grant_approval`은 `tenant_id`, `source_actor_id`, `revision_id`, `intent`, `arguments`, `approver`를 받고 revision에서 target과 설치된 policy를 찾습니다. 인자만으로 승인할 수 없습니다. 승인은 실행 직전에 원자적으로 소비되어, 실행이 실패해도 다른 동작에 재사용할 수 없습니다. 거부된 목적지는 승인으로 우회되지 않습니다. 판정만으로는 승인을 소비하지 않으며 보류는 사람을 기다렸다는 증거로 ledger에 남습니다.

모든 단계가 `gateway.ledger`에 남습니다. `INTERACTION_REQUESTED`, `DATA_FLOW_OBSERVED`,
`CONTROL_EVALUATED`(모든 체크의 coverage 포함), `ACTION_EXECUTED`, `INTERACTION_COMPLETED`,
`SECURITY_OUTCOME_SET`. `summarize_security_statistics`가 ledger를 Studio가 보여주는 통계로
바꿉니다.

거부된 도구 호출이라고 해서 모델이 사용자에게 "성공했다"고 말하지 못하는 것은 아닙니다 --
`is_error` 결과는 무슨 일이 있었는지를 모델에게 알릴 뿐, 모델이 다음에 뭐라고 답할지는 알려주지
않습니다. `examples/*/run.py`는 이 간극이 조용히 넘어가지 않도록 막습니다. 응답이 돌아오면
`check_consistency`가 `reduce_interactions`로 ledger를 환원하고, 어떤 상호작용이든
`enforced_block`인데 응답에 거부를 암시하는 단어("blocked", "denied", "could not" 등)가 하나도
없으면 응답이 실행 증거를 반영하지 않을 수 있다는 경고를 출력합니다. 응답 문구에 대한 휴리스틱일
뿐 증명이 아니라서 경고만 하지만, ledger와 사용자에게 보인 문구 사이의 조용한 불일치를 눈에 보이게
만듭니다.

## 4. 프로젝트 검증

```bash
interlock verify path/to/project.py --out report.json
```

`verify`는 시나리오마다 프로젝트를 다시 빌드하고, 모델 대신 스크립트 호출자로 보호된 도구를
구동합니다. 오염된 설명, 드리프트된 정의, 다른 서버 참조, 결과 속 자격증명, 미선언 목적지, 미선언
부작용, 도구 결과로 전달되는 목표 탈취, 읽기 도구를 통한 메모리 오염. 보고서는 시나리오별 기대값과
관측값을 나열하고, 최상위에 `verified`, `notApplicable`, `failed` 개수도 담습니다.
NOT-APPLICABLE은 이 프로젝트에 테스트할 대상이 없었다는 뜻이지(읽기 전용 도구 없음, 목적지로
표시된 속성 없음, 볼륨 상한 없음), 통제가 작동해서 막았다는 뜻이 아닙니다. 종료 코드 1은 `failed`가
0이 아니라는 뜻이고, `--strict`를 주면 모든 시나리오가 실제로 실행되었다고 주장하는 프로젝트를 위해
NOT-APPLICABLE도 실패로 셉니다. CI에서 여러분의 테스트 옆에 두고 돌리세요.

## 5. 여러분의 것으로 남는 것

도구 함수, 프롬프트, 루프. Interlock이 맡는 것은 각 호출에 대한 판정과 그 증거입니다. manifest가
바뀌면 `lint`를 다시 돌리고, 바인딩을 다시 생성하거나 고치고, `verify`를 다시 돌립니다.

## 연결과 운영 경계

`ToolBinding`은 `classify`, `estimate_export`, `result_provenance` hook을 받습니다. Application이 신뢰 가능한 데이터로 구현하고 설치 여부를 기록합니다. Manifest에 그린 control은 저작된 의도이며, 설치된 hook과 관측된 `CONTROL_EVALUATED` 이벤트는 별도의 증거입니다. Managed helper는 세 hook을 모두 요구하고 tool definition digest를 승격된 bundle과 비교합니다. 로컬 binding에 classification이 없으면 보수적인 D3 입력 기본값을 쓰고, 결과 provenance가 없으면 `UNCLASSIFIED`로 남깁니다.

Skeleton은 `<architecture>_edge_coverage.json`도 생성합니다. 첫 source의 정적 TOOL 호출은 `WIRED`, 다른 source·동적 selector·다른 관계는 이유와 함께 `MANUAL`입니다. 실제 runtime coverage를 주장하려면 handler를 구현해야 합니다.

이벤트 증거를 영속화하려면 PostgreSQL Ledger를 사용합니다. Gateway 호출 승인과 멱등 결과는 process-local이며, ledger 저장만으로 재시작을 넘는 exactly-once tool 실행이 보장되지는 않습니다. Workflow 취소는 협력적이고, in-process adapter timeout은 외부 부작용을 되돌리거나 강제로 중단하지 못합니다. [Managed host](managed-support-host.md)는 전용 배포 owner, 재시작 복구와 명시적 resume을 설명하며 공유 multi-tenant 배포 서비스가 아닙니다.
