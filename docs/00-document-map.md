---
title: Agent Interlock Document Map
date: 2026-07-21
version: 1.7
status: active
---

# Agent Interlock Document Map

> 한국어 원문: [00-document-map.ko.md](00-document-map.ko.md)

This document is the entry point for the project's documentation. It fixes each document's responsibility and reading order so the same concept is never defined differently across documents.

## 1. Reading Paths by Purpose

| Reader/Purpose | Read First | Then Read |
|---|---|---|
| Understand product scope and roadmap | [01 Project Plan](01-project-plan.md) | [02 Developer Framework](02-developer-framework-design.md) |
| Develop Agent-Tool integrations | [02 Developer Framework](02-developer-framework-design.md) | [04 MCP Tool Gateway Spec](04-mcp-tool-gateway-spec.md) |
| Understand L1 threats and attack flows | [03 L1 Security Profile](03-l1-mcp-tool-security-profile.md) | [05 L1 Validation Plan](05-l1-security-validation-plan.md) |
| Implement policy and Gateway | [04 MCP Tool Gateway Spec](04-mcp-tool-gateway-spec.md) | [01 Project Plan](01-project-plan.md#11-policy-decision-and-enforcement) |
| Security testing and production promotion | [05 L1 Validation Plan](05-l1-security-validation-plan.md) | [03 L1 Security Profile](03-l1-mcp-tool-security-profile.md) |
| Check current implementation against design | [06 Implementation Status](06-implementation-status.md) | [04 MCP Tool Gateway Spec](04-mcp-tool-gateway-spec.md) |
| Design box-based security architecture | [07 Security Architecture Studio](07-security-architecture-studio-design.md) | [02 Developer Framework](02-developer-framework-design.md) |
| Analyze execution traces and design drift | [08 Runtime Telemetry](08-runtime-telemetry-reconciliation.md) | [07 Security Architecture Studio](07-security-architecture-studio-design.md) |
| Enforce Architecture on MCP calls | [09 MCP Transport Enforcement](09-mcp-transport-enforcement.md) | [04 MCP Tool Gateway Spec](04-mcp-tool-gateway-spec.md) |
| Implement MCP OAuth discovery and token binding | [10 MCP OAuth Identity Guard](10-mcp-oauth-identity-guard.md) | [09 MCP Transport Enforcement](09-mcp-transport-enforcement.md) |
| Implement local MCP process and side-effect evidence | [11 MCP stdio Sandbox/Receipts](11-mcp-stdio-sandbox-receipts.md) | [09 MCP Transport Enforcement](09-mcp-transport-enforcement.md) |
| Operate PostgreSQL Ledger and event/trace API | [12 PostgreSQL Ledger API](12-postgresql-ledger-api.md) | [01 Project Plan](01-project-plan.md#9-postgresql-mvp-ddl) |
| Implement Trust Boundary-based A2A orchestration | [13 A2A Orchestration Platform](13-a2a-orchestration-platform.md) | [07 Security Architecture Studio](07-security-architecture-studio-design.md) |
| Safely validate the full platform end-to-end | [14 Fake Data Platform E2E](14-fake-platform-e2e-scenario.md) | [13 A2A Orchestration Platform](13-a2a-orchestration-platform.md) |
| Review manual Chrome E2E screen evidence | [15 Manual Browser E2E Evidence](15-manual-browser-e2e-evidence.md) | [14 Fake Data Platform E2E](14-fake-platform-e2e-scenario.md) |
| Add Interlock to an existing agent | [16 Adding Agent Interlock to an Agent](16-adding-interlock-to-an-agent.md) | [02 Developer Framework §2](02-developer-framework-design.md#2-developer-experience), [05 Validation Plan §11](05-l1-security-validation-plan.md#11-per-project-verification-interlock-verify) |

## 2. Responsibility by Document

| Document | What this document decides | What this document does not decide |
|---|---|---|
| `01-project-plan.md` | Product goals, common events, database, detection/response operating model | Protocol-specific MCP processing procedures |
| `02-developer-framework-design.md` | ActorSpec, ActorGuard, LinkPolicy, Runtime, Graph developer experience | Detailed attack reproduction per threat |
| `03-l1-mcp-tool-security-profile.md` | M1–M9 boundaries, data, attacks, controls, and product mapping | Detailed API implementation and test execution procedures |
| `04-mcp-tool-gateway-spec.md` | MCP Gateway input/output/state/policy/event contracts | Implementation of all L2/L3 relationships |
| `05-l1-security-validation-plan.md` | M1–M9 test procedures, expected results, required evidence, promotion criteria | The full production incident response process |
| `06-implementation-status.md` | Current tracking status of design contracts against code and tests | Detailed design of unimplemented items |
| `07-security-architecture-studio-design.md` | Architecture-as-Code, security control assurance levels, Dynamic Edge, Canvas MVP | Detailed implementation of production deployment/approval workflow |
| `08-runtime-telemetry-reconciliation.md` | Ledger/OTLP import/HTTP receiver, Interlock span attributes, drift and the signed evidence trust boundary | Deployment configuration of the OTLP gRPC Collector and vendor adapters |
| `09-mcp-transport-enforcement.md` | Architecture compilation, MCP JSON-RPC, Streamable HTTP, resumable SSE, and publisher provenance admission | Implementation of distributed session backends and advanced asynchronous MCP operations |
| `10-mcp-oauth-identity-guard.md` | OAuth discovery, PKCE, redirect/SSRF, introspection/JWKS, loopback consent, and token binding | Operation of per-IdP key/cache, UI, and distributed transaction stores |
| `11-mcp-stdio-sandbox-receipts.md` | stdio restrictions, signed attestation, Bubblewrap, Architecture-bound egress, and fake receipt references | Per-platform installation and operating policy for live sandbox, seccomp, and egress proxy |
| `12-postgresql-ledger-api.md` | PostgreSQL adapter, RLS/append-only migration, `/v1/events`/trace API, and signed audit references | Operation of HA proxy, pooling, partition scheduler, and external KMS/mTLS/WORM |
| `13-a2a-orchestration-platform.md` | Directional Trust Boundary, A2A 1.0 core, Task workflow, and the runtime orchestration contract | Production deployment of external IdP, distributed queue/store, and streaming/push |
| `14-fake-platform-e2e-scenario.md` | Procedures and pass criteria for reproducing design, promotion, A2A, Run Control, approval, MCP, evidence, and Chrome E2E using test-only fixtures | Real customer data, external email delivery, and production adapter/queue/store configuration |
| `15-manual-browser-e2e-evidence.md` | 1600×900 manual E2E screen evidence and execution results with the Chrome browser frame removed | Pass/fail determination for automated regression tests or assurance of production telemetry integrity |
| `16-adding-interlock-to-an-agent.md` | The ten-minute path from an existing tool-using agent to one whose calls are judged, recorded, and verified via the Anthropic Tool Runner adapter | Framework internals; see `02`/`04` for those |
| `specs/` | In-progress design and specifications, updated in the same PR as the code — currently [Control Coverage Statistics](specs/2026-07-27-control-coverage-statistics.md) and [Adoption Layer](specs/2026-09-08-adoption-layer.md) | Anything already promoted into `00`–`16` |

## 3. Tracking IDs

Use the following IDs so that documents, code, events, and test results all refer to the same subject.

| Kind | Format | Example |
|---|---|---|
| Threat | `M1`–`M9` | `M2` Rug Pull |
| Relationship | `REL-nn` | `REL-05` Agent → Tool |
| Detection rule | `DET-nnn` | `DET-005` definition digest mismatch |
| Reason code | `L1-Mn-*` · cross-cutting `L1-*` · `INTERLOCK-*` · `A2A-*` · `MCP-*` | `L1-M5-TOKEN-AUDIENCE-MISMATCH`, `L1-UNDECLARED-SIDE-EFFECT`, `INTERLOCK-DATA-CLASS-DENIED`, `A2A-AUDIENCE-MISMATCH`, `MCP-OAUTH-CHALLENGE-SCOPE-MISMATCH` |
| Design-time finding | `ARCH-*` (linter) · `ORCH-*` (workflow runtime) | `ARCH-DATA-CLASS-EXCEEDS-ACTOR`, `ORCH-MESSAGE-BUDGET` |
| Test | `L1-SIM-Mn-nnn`, core `CORE-SIM-*` | `L1-SIM-M6-001`, `CORE-SIM-TENANT-001` |
| Policy | Meaningful kebab-case ID | `mcp-tool-invoke-default` |

`M1–M9` are research/threat classification IDs, while `DET-*` are implemented detection rules. A single threat can be implemented by multiple rules, so the two IDs are not treated as equivalent.

Reason codes are **per enforcement point**. The same control emits `L1-M5-TOKEN-AUDIENCE-MISMATCH` at the MCP gateway and `A2A-AUDIENCE-MISMATCH` at the A2A broker, so a reason-code aggregate is not comparable across points; the canonical check id in `policy.py`'s `CHECKS` table is. `CORE-SIM-*` and `L1-SIM-*` are specification IDs and are not carried by the tests that implement them — `CORE-SIM` in particular appears in no file outside `docs/`.

## 4. Baseline Definitions for Data and Results

- Data classes `D1–D8`, checkpoints `P1–P7`, and threat definitions `M1–M9` are governed by [03 L1 Security Profile](03-l1-mcp-tool-security-profile.md).
- The common Event Envelope and `CONTROL_DECISION`, `ACTION_RESULT`, `SECURITY_OUTCOME` are governed by [01 Project Plan](01-project-plan.md#6-event-classification-system).
- MCP-specific payloads and reason codes are governed by [04 MCP Tool Gateway Spec](04-mcp-tool-gateway-spec.md).
- Pass/fail determination for attack reproduction is governed by [05 L1 Validation Plan](05-l1-security-validation-plan.md).

Verdict, enforcement, and security outcome must always be kept separate. For example, even if the policy returns `BLOCK`, if enforcement `FAILED` and the external transmission succeeded, the final outcome is `SUCCEEDED`.

## 5. Relationship Between Source Research and Project Documents

These project documents translate the following research documents into a product implementation perspective.

- `agentic-위협매트릭스-통합-최종-v3-2026-07.md` v3.3: The full threat classification and relationship/control baseline
- `agentic-l1-mcp-tool-위협-기술명세-v1-2026-07.md` v1.0: Research basis and attack details for L1 M1–M9

The source documents explain the rationale and scope of the threats, while this repository defines what Agent Interlock must collect, adjudicate, enforce, and validate. When the research documents are updated, the implementation is not changed immediately; instead, the update is applied in the following order.

1. Review whether the threats and data flows in `03` need to change.
2. If any controls change, bump the policy/event contract version in `04`.
3. Add regression tests to `05`.
4. After the implementation and production policy are deployed, change the document status to `active`.

## 6. Document Status

| Status | Meaning |
|---|---|
| `planning` | Product direction; not used as an implementation contract |
| `draft` | Reviewable draft with no compatibility guarantee |
| `proposed` | Candidate implementation contract, pending approval |
| `active` | The baseline that code, policy, and tests must follow |
| `deprecated` | Superseded by a new document; no new implementation |

Currently, `03`–`05` are `proposed` documents that precede initial implementation. At implementation time, the version must be pinned together with the actual types, JSON Schema, and policy bundle.
