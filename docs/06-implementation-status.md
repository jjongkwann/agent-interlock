---
title: Agent Interlock 구현 상태
date: 2026-07-15
version: 0.1.0
status: active
---

# Agent Interlock 구현 상태

이 문서는 설계 계약과 현재 코드 사이의 추적표다. 구현되지 않은 항목을 완료된 것처럼 간주하지 않도록 release마다 갱신한다.

## 구현 기준

- 언어: Python 3.11
- 배포 형태: 외부 의존성이 없는 reference core
- 기준 명세: `03`–`05` version 1.1
- 구현 모드: 메모리 Registry/Ledger와 동기 Connector

## 계약 추적

| 계약 | 구현 | 검증 |
|---|---|---|
| Actor `define` / `connect` / `wrap` | `src/agent_interlock/sdk.py` | `SDKTests` |
| 정적 설계·단일 trace graph 데이터 | `Interlock.design_graph`, `runtime_graph` | `test_define_connect_wrap_and_graph` |
| Canonical/raw definition digest | `canonical.py`, `registry.py` | `CanonicalizationTests`, `RegistryTests` |
| Definition 상태와 digest pin | `DefinitionRegistry` | M2 drift 회귀 시험 |
| D1 metadata instruction·cross-server reference | `DefinitionRegistry._inspect` | M1·M3 회귀 시험 |
| D3 schema·secret·목적지·부작용 판정 | `policy.py`, `security.py` | M8·M9 회귀 시험 |
| Token audience/resource/actor binding·passthrough 금지 | `policy.py` | M5 회귀 시험 |
| Hash·destination-bound 승인 | `MCPToolGateway.grant_approval` | 승인 변경 회귀 시험 |
| Hash-bound·멱등 Connector 실행 | `execute_approved_call` | mutation·중복 실행 회귀 시험 |
| Result secret 정제·taint·schema 검사 | `inspect_result` | result D5 회귀 시험 |
| 사후 receipt reconciliation | `reconcile_transaction` | 미선언 egress 회귀 시험 |
| 판정·집행·결과 분리 이벤트 | `InMemoryLedger`, `gateway.py` | 이벤트 순서·무결성 시험 |
| PostgreSQL partition·RLS·append-only | `migrations/postgresql` | PostgreSQL 16 임시 DB 적용 검증 |

## 현재 자동화된 L1 범위

`tests/test_core.py`는 M1 metadata instruction, M2 definition drift, M3 cross-server reference, M5 token mismatch/passthrough, M6 authorization URL, M8 인수·결과 secret, M9 Unicode 목적지·미선언 부작용·사후 egress를 검증한다. 정상 호출, SHADOW 비집행, 승인 binding, idempotency도 함께 검증한다.

이는 [05 검증 계획](05-l1-security-validation-plan.md)의 전체 M1–M9 matrix 완료를 뜻하지 않는다. 특히 다음 항목은 통합 fixture가 필요하다.

- 실제 MCP transport의 `tools/list`, `notifications/tools/list_changed`, `tools/call`
- OAuth authorization server와 token exchange provider
- process/filesystem/network Connector sandbox
- RAG/config/file canary corpus와 fake external receipt store
- PostgreSQL Ledger adapter와 CORE-SIM-TENANT 전체 CI
- HTTP API, OpenTelemetry adapter, Incident/response service

## 다음 구현 순서

1. PostgreSQL Ledger adapter와 `/v1/events`, trace query API
2. MCP transport adapter와 동적 adversarial Server fixture
3. OAuth token exchange·redirect-hop validator
4. Connector sandbox와 fake external receipt store
5. `05`의 M1–M9 전체 test ID 자동화

