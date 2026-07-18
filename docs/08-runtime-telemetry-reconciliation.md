---
title: Runtime Telemetry와 Design/Runtime Reconciliation
date: 2026-07-17
version: 0.2.0
status: active
---

# Runtime Telemetry와 Design/Runtime Reconciliation

## 1. 목적

Architecture manifest의 의도와 실제 Agent 실행을 비교해 다음을 찾는다.

- 설계에 없는 Actor 관계
- 실행 증거가 없는 Design Edge
- `CONTROL_EVALUATED` 없이 실행된 interaction
- 보안 상관분석에 필요한 context가 빠진 GenAI/MCP span

Studio와 CLI는 Interlock Ledger event 배열 및 OTLP/HTTP JSON `resourceSpans`를 입력으로 받는다. Ledger HTTP API의 인증된 `POST /v1/traces`도 같은 OTLP/HTTP JSON을 받아 runtime observation과 import issue로 decode한다. 이 reference endpoint는 Ledger event를 append하지 않는다.

## 2. OpenTelemetry 기준

OpenTelemetry의 GenAI semantic convention은 별도 [GenAI Semantic Conventions 저장소](https://github.com/open-telemetry/semantic-conventions-genai)로 이동했다. Agent span 규격은 현재 `Development` 상태이므로 Interlock importer는 버전 변경을 전제로 격리한다.

분류에는 공식 [GenAI Agent Span](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md)과 [MCP Span](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/mcp.md)의 다음 속성을 사용한다.

| 속성 | 용도 |
|---|---|
| `gen_ai.operation.name` | `invoke_agent`, `execute_tool`, `retrieval`, memory operation 구분 |
| `gen_ai.agent.id`, `gen_ai.agent.name` | Agent 식별·표시 |
| `gen_ai.tool.name` | 실행 Tool 표시 |
| `mcp.method.name` | `tools/call` 등 MCP method 구분 |

표준 속성만으로는 Interlock Architecture의 source Actor, target Actor, REL ID, 통제 집행 여부를 확정할 수 없다. importer는 이름이나 span parent만으로 보안 사실을 추론하지 않는다.

## 3. Interlock OTLP 확장 계약

정확한 reconciliation을 원하는 span은 다음 속성을 함께 기록한다.

```text
interlock.source.actor.id
interlock.target.actor.id
interlock.relationship.id
interlock.relationship.type
interlock.interaction.id
interlock.control.evaluated
```

`interlock.interaction.id`가 없으면 `spanId`를 correlation fallback으로 사용한다. tracked GenAI/MCP operation에 관계 context가 없으면 `TELEMETRY_SECURITY_CONTEXT_MISSING`을 생성하고 관계를 임의 생성하지 않는다.

## 4. 신뢰 경계

`interlock.control.evaluated=true`는 OTLP payload에 기록된 주장이다. 신뢰되지 않은 Agent가 직접 보낸 span이라면 집행 증명이 아니다. 프로덕션에서는 다음 조건을 추가해야 `ENFORCED` 또는 `RECONCILED` 증거로 승격할 수 있다.

1. Gateway 또는 별도 Audit Sink가 속성을 생성한다.
2. tenant·workload identity와 transport 인증을 검증한다.
3. policy decision ID와 action receipt를 interaction에 결합한다.
4. append-only Ledger의 integrity hash 또는 서명 검증을 통과한다.
5. sampling으로 security span이 누락되지 않도록 별도 보존 정책을 사용한다.

현재 importer는 payload 정규화와 drift 탐지 계층이며 OTLP 송신자의 진위를 증명하지 않는다.
Interlock Ledger event에 `integrity_hash`가 포함되어 있으면 Python importer는 canonical hash를 검증하고 불일치 event를 관계 분석에서 제외한다. 브라우저 Studio는 hash를 검증하지 않고 `TELEMETRY_INTEGRITY_UNVERIFIED`를 표시하므로 신뢰 판정은 CLI에서 다시 수행한다.

## 5. 실행

```bash
PYTHONPATH=src python3 -m agent_interlock architecture runtime-diff \
  examples/secure_multi_agent_architecture.json \
  examples/runtime_drift_otlp.json
```

drift가 있거나 import issue가 있으면 종료 코드는 `3`이다. 결과에는 `undeclaredRelationships`, `unobservedEdgeIds`, `controlBypassInteractions`, `importIssues`가 분리되어 나온다.

Studio의 `Runtime graph` 또는 `Drift` 탭에서 같은 JSON을 가져올 수 있다. 브라우저 importer는 최대 5 MB만 받고 파일을 서버로 전송하지 않는다.

## 6. 현재 제한과 다음 통합

- OTLP/HTTP JSON 파일 import와 인증된 HTTP receiver는 구현되어 있다. OTLP/gRPC `:4317`, 표준 Collector 배포 설정과 backpressure·queue는 아직 없다.
- `SignedAuditSink`는 integrity 검증을 통과한 event를 symmetric keyed signature로 seal하는 reference다. 비대칭 서명은 `signing.py`의 Ed25519(`sign/verify_canonical_ed25519`)와 `supply_chain.py`의 `Ed25519PublisherVerifier`로 제공하며, append-only 해시체인 보존은 `audit_sink.py` `WORMAuditStore`(`InMemoryWORMAuditStore`와 파일 백엔드 `FileWORMAuditStore`)로 제공한다. `FileWORMAuditStore`는 JSONL append+fsync로 영속하고 열 때 체인을 재검증하며 write-once dedupe가 재시작 후에도 유지된다. 외부 KMS/HSM key 운영, workload mTLS, S3 Object-Lock 기반 내구 WORM export는 아직 없다.
- Langfuse·LangSmith vendor trace adapter는 `vendor_telemetry.py`(`langfuse_traces_to_otlp`·`langsmith_runs_to_otlp`·`import_langfuse_traces`·`import_langsmith_runs`)로 구현되어 있다. vendor metadata의 interlock/gen_ai 컨텍스트를 OTLP 속성으로 올린 뒤 `import_runtime_telemetry`를 재사용한다.
- 표준 attribute 변경을 흡수할 semantic convention version adapter는 `otlp_semconv.py` `normalize_otlp_semconv`/`SEMCONV_ALIASES`로 제공한다. legacy(`llm.*`, `gen_ai.operation`, snake_case `interlock.*`) 별칭을 canonical 이름으로 정규화한 뒤 `import_runtime_telemetry`에 넘긴다(canonical 값이 별칭보다 우선).
- Dynamic Sub-Agent instance가 다시 source가 되는 관계는 admission identity registry와 함께 검증해야 한다.
- trace sampling 누락과 Audit Sink 장애는 `control_health.py` `ControlHealthReporter`가 `CONTROL_HEALTH_CHANGED`(REL-12)로 연결한다. import issue·`RuntimeGraphDiff`의 control-bypass interaction(=sampling gap)·seal 실패를 각각 별도 reason code로 방출한다.
- prompt, tool arguments, retrieval query 등 민감 content attribute는 기본 import 대상이 아니다.
