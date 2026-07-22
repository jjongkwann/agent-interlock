---
title: Agent Interlock Security Architecture Studio Design
date: 2026-07-20
version: 0.3.0
status: active
---

# Agent Interlock Security Architecture Studio Design

> 한국어 원문: [07-security-architecture-studio-design.ko.md](07-security-architecture-studio-design.ko.md)

## 1. Goals

The Security Architecture Studio is an Architecture-as-Code layer that, before an Agent system is implemented, defines the User, Agent, Sub-Agent, Scheduler, RAG, Memory, Tool, and External actors and declares the security of each relationship and the task execution order. Design has two surfaces — Actor topology and Task workflow — and the JSON Architecture manifest is the source of truth.

```text
Actor topology + Task workflow → Architecture manifest → Security lint → Compiler
       → ActorSpec·LinkPolicy → SDK/Gateway → Runtime Ledger
       → Declared/Observed Graph diff
```

The UI never changes production policy directly. Changes are made as a versioned manifest and diff, then deployed through review, simulation, approval, and rollback.

## 2. The Four Graphs

| Graph | Derived From | Purpose |
|---|---|---|
| Design Graph | Architecture manifest | Intended Actor · relationship · security design |
| Task Workflow | Architecture manifest | coordinator · task · dependency · transport · approval · budget design |
| Compiled Control Graph | ActorSpec · LinkPolicy · adapter configuration | Confirms the enforcement points to actually deploy |
| Runtime Graph | Ledger · OpenTelemetry | Confirms actual calls and bypass/drift |

An Edge discovered at runtime is never auto-approved into the Design Graph. It is first flagged as `UNDECLARED_RELATIONSHIP`, and only after operator approval is it folded into a manifest revision.

## 3. Security Control Contract

Every Control has four axes.

```yaml
id: delegation-binding
objective: PREVENT
timing: PRE_EXECUTION
enforcementPoint: A2A_BROKER
assurance: ENFORCED
```

### 3.1 Objective

- `PREVENT`: blocks before execution
- `DETECT`: detects violations before or after execution
- `RESPOND`: revoke, kill, quarantine, compensation
- `EVIDENCE`: preserves verdict · enforcement · result evidence

### 3.2 Assurance

- `DECLARED`: exists only in the design
- `OBSERVED`: observes that execution occurred
- `ENFORCED`: an enforcement point enforces it before execution
- `RECONCILED`: reconciled all the way to the downstream receipt

The Canvas displays assurance with color and a badge. `DECLARED` must never be displayed in a way that makes it look like `ENFORCED`.

### 3.3 Enforcement Point

`SANDBOX` is the enforcement point that operates the filesystem · network · child-process isolation profile and attestation for the REL-05 local Tool. It is kept as a separate Control from the `MCP_GATEWAY` definition/call policy so that protocol permission and OS process isolation are each shown independently.

## 4. Dynamic Edge Contract

When a Sub-Agent is created at runtime, not every instance ID can be known at design time. A Dynamic Edge declares the allowed target set as a contract.

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

At admission, the actual Sub-Agent instance is checked against the selector and Agent identity; at execution, the delegation token and depth · budget are checked again.

## 5. Current Security Lint

- Missing required enforcement point per relationship
- A relationship with no Control
- Missing audit evidence
- `DECLARED`-only control
- A post-execution control mislabeled as `PREVENT`
- D5 credential data allowed
- OBSERVE-only · FAIL_OPEN on a high-risk Edge
- RAG tenant left optional
- Missing Tool digest pin
- Weakened A2A actor/audience/resource binding
- Delegation depth greater than the Actor's
- cross-tenant dynamic delegation
- Dynamic delegation with an empty capability or an unbounded ID pattern
- delegation cycle
- Missing egress destination allowlist · explicit destination
- Missing exact Trust Zone membership for the Actor
- Missing directional Trust Boundary · enforcement · data contract on a cross-zone Edge
- Missing identity · tenant binding · fail-closed on an A2A boundary
- Missing transport Edge · acceptance criteria · high-risk approval · DAG · budget on a workflow task

If there is a CRITICAL finding, the compiler refuses to generate ActorSpec/LinkPolicy.

## 6. How to Run

```bash
PYTHONPATH=src python3 -m agent_interlock architecture lint \
  examples/secure_multi_agent_architecture.json

PYTHONPATH=src python3 -m agent_interlock architecture compile \
  examples/secure_multi_agent_architecture.json

PYTHONPATH=src python3 -m agent_interlock architecture graph \
  examples/secure_multi_agent_architecture.json
```

The JSON contract is authoritative in `schemas/architecture.schema.json`, and the Python implementation is authoritative in `src/agent_interlock/architecture.py`.

## 7. Current Studio Implementation

`studio/` contains a Canvas MVP that can be run locally.

- User, Agent, Sub-Agent, Scheduler, RAG, Tool, Memory, and External boxes, plus INTERNAL/EXTERNAL trust zones stored in the manifest
- Trust zone add · select · name/classification/description editing · move · resize, and `trustZoneId`-based Actor membership management
- Member Actors move together when a Zone moves, Actor drag/drop between Zones · Inspector reassignment, and Zone fitting based on member Actors
- Creating · selecting · editing a directional source-zone→target-zone Trust Boundary, and binding cross-zone Edges to a `boundaryId`
- Editing per-Boundary enforcement point, relationship/data contract, identity · tenant binding, payload limit, and mode/failure
- Adding/moving boxes, creating Edges between selected boxes
- Editing per-Edge OBSERVE/SHADOW/ENFORCE, failure mode, data class, and approval condition
- Editing same-tenant and delegation depth for Dynamic Sub-Agents
- Changing DECLARED/OBSERVED/ENFORCED/RECONCILED per Control
- Editing Tool definition digest, External domain allowlist, and Actor tenant/delegation boundary
- Immediate findings for dangerous D5, FAIL_OPEN, OBSERVE-only, unpinned Tools, unbounded Egress, and the like
- Downloading the same `interlock.dev/v1alpha1` manifest the Python compiler uses
- Ledger · OTLP JSON import and real Runtime Graph generation
- A Drift view that separates undeclared relationships, unobserved Design Edges, and control bypasses
- A Ledger interaction statistics view (offline import + read-only Live Attach, aggregated by data source · mode · relationship · Actor · policy · reason)
- The CLI `architecture compile --shadow`'s CRITICAL review gate · all-Edge SHADOW enforcement · stable bundle digest
- Manifest-based Python SDK skeleton · security-test generation
- An Ed25519 two-person-approval propose→promote→rollback-to-a-past-active-bundle CLI, integrated with the Control Plane
- A runtime adapter that compiles REL-07's source Tool/External `allowedDomains`/LinkPolicy into a tenant/artifact/provenance/sandbox-bound egress policy
- Zooming only the graph — separate from browser page zoom — via the regular wheel and macOS `Command + =/-`/Windows `Ctrl + =/-` while the pointer is over the Canvas
- Switching between `Actor topology`/`Task workflow` within Design, and an A2A/MCP/LOCAL/HUMAN task palette
- Editing per-Task source/target, dependency, data, acceptance, retry, timeout, on-failure, and approval, plus workflow budget configuration

```bash
cd studio
npm install
npm run dev
```

The downloaded JSON is a draft, not a deployment input. It must pass the root CLI's `lint` and `compile`, then go through review and SHADOW verification.

## 8. Next Steps

1. Remote GitHub/GitLab PR review and hosted-deploy integration
2. Skeleton generators for frameworks other than Python
3. OTLP/gRPC Collector and a production trace store
4. A2A SSE streaming · push notification and signed Agent Card admission
5. A durable A2A task/workflow run store and a distributed scheduler
6. Large-scale statistics pre-aggregation and a persistent pending-approval store

The full contract from Trust Boundary through A2A Broker and Task workflow execution follows [13 A2A Orchestration Platform](13-a2a-orchestration-platform.md).
