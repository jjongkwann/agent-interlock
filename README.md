# Agent Interlock

> Define actors. Secure interactions. See the whole graph.

> 한국어 버전: [README.ko.md](README.ko.md) · Design docs are available in both English (`docs/*.md`) and Korean (`docs/*.ko.md`).

[![CI](https://github.com/jjongkwann/agent-interlock/actions/workflows/ci.yml/badge.svg)](https://github.com/jjongkwann/agent-interlock/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

Agent Interlock is an **Agentic AI Security Framework** that declaratively defines the Actors of an AI agent system, wraps each Actor's surface with an SDK/Proxy, and observes, adjudicates, and blocks the communication and data movement between them. It applies the safety-engineering notion of an interlock — a mechanism that makes operation physically impossible unless declared conditions hold — to agent-to-agent interaction: only declared paths are permitted to connect, promotion to ENFORCE requires two signed approvals, and every verdict lands in an append-only Ledger.

The adoption layer is how this reaches a real agent: guard your own tools with the Anthropic Tool Runner adapter, generate a runnable project module from an Architecture manifest, and run `interlock verify` against your own project — not just the framework's fixtures — before you ship.

## What it blocks

The full MCP/Tool threat set M1–M9 is enforced at the data-flow level. Per-threat specifications live in [docs/03 §6](docs/03-l1-mcp-tool-security-profile.md); reproduction scenarios and the 34 tracked test IDs live in [docs/05](docs/05-l1-security-validation-plan.md) and `tests/test_l1_matrix.py`.

| ID | Threat | What the attacker manipulates | Default verdict |
|---|---|---|---|
| `M1` | Tool Poisoning | Hidden instructions in tool descriptions/schemas | `QUARANTINE`/`BLOCK` |
| `M2` | Rug Pull | Definition/endpoint/command swapped after approval | `QUARANTINE` |
| `M3` | Tool Shadowing | Descriptions that steer other servers/tools | `BLOCK`/`HOLD` |
| `M4` | Poisoned Tool Publish | The package/image/remote MCP itself | `QUARANTINE` |
| `M5` | Confused Deputy / Token Passthrough | Token audience, scope, acting principal | `BLOCK` |
| `M6` | MCP Server → Host Compromise | Auth URLs, redirects, result payloads | `BLOCK`/`KILL` |
| `M7` | Agent Config Discovery/Modification | Enumerating or mutating agent configuration | `BLOCK`/`CHALLENGE` |
| `M8` | Credential Harvesting | Credentials inside RAG/config/results | `SANITIZE`/`BLOCK` |
| `M9` | Data Exfiltration | Call destinations and business-data payloads | `BLOCK`/`HOLD` |

Verdicts are promoted in stages — observe (OBSERVE) → shadow enforcement (SHADOW) → live enforcement (ENFORCE) — and the framework leaves evidence, not just blocks: every interaction is recorded in the Ledger as separate request/verdict/action/outcome events, and the design graph is diffed against runtime traces for drift.

## Quick start

From the repository root, create a Python 3.11+ environment and install the adapter before running examples:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[anthropic,jwt]'
python examples/secure_email.py
interlock architecture lint examples/secure_multi_agent_architecture.json
interlock architecture compile examples/secure_multi_agent_architecture.json --shadow > bundle.json
```

The local email example has no external side effects. For a live Claude Tool Runner run, configure `ANTHROPIC_API_KEY` and then run:

```bash
python -m examples.support_agent.run "Where is order 1001? Email the customer."
```

The live example calls the Anthropic API. For recorded replay without an API key, install the test runner and run the reference tests from the same repository root:

```bash
python -m pip install pytest
python -m pytest -q tests/test_example_support_agent.py tests/test_platform_e2e.py tests/test_run_control.py
```

Open a separate terminal at the repository root for Studio (Node 22.13+):

```bash
cd studio
npm ci
npm run dev
```

For configuration-based authoring and execution, follow the [Studio builder guide (Korean)](docs/studio-builder.ko.md). Start a local host with `interlock serve --data-dir PATH --origin http://localhost:3102`, then configure JSON transforms, fixed HTTPS JSON requests, or Anthropic tool-using agents in Studio. Compile, review, sign in browser memory, promote, and run from the UI. Model tasks can use multiple explicitly selected reviewed tools; custom business logic and other protocols still need an adapter. Connect multiple execution servers with `--dispatch remote` and `interlock worker`, following the [remote worker guide (Korean)](docs/distributed-workers.ko.md).

Use [SDK adoption](docs/16-adding-interlock-to-an-agent.md) for an existing Python agent, or the [managed support host](docs/managed-support-host.md) for custom business tools and PostgreSQL.

## Product components

| Component | Role |
|---|---|
| Interlock SDK | Declare ActorSpecs, wrap existing code, generate traces/events — **and enforce**: `wrap()` runs 19 of the gateway's 21 checks in-process and raises `GatewayError` under `ENFORCE` |
| Interlock Runtime | Intercept inter-Actor communication and enforce policy |
| Interlock Orchestrator | Execute verified Task DAGs over A2A/MCP/Human transports |
| Interlock A2A Broker | Handle Agent Cards/Tasks with REL-06 and Trust Boundary pre-enforcement |
| Interlock Ledger | Store requests, data flows, verdicts, actions, outcomes |
| Interlock Graph | Visualize static relationships, runtime calls, attack paths |
| Interlock Studio | Editor, projects (new/open/save, manifest import), statistics, deploy, runs |
| Interlock Adapter | Anthropic Tool Runner adapter: guard your own tools with `guard_tools`/`bind_architecture` |
| Interlock Verify | `interlock verify` runs the L1 corpus against your own project's guarded tools |

## Core concepts

```text
ActorSpec       Declares an Actor's identity, capabilities, I/O, permissions, side effects
ActorGuard      Security wrapper around Agent/Tool/RAG/Memory code
InterlockLink   Permitted relationship between Actors
LinkPolicy      Per-relationship data, destination, approval, budget, blocking policy
InteractionEvent Request, data-flow, verdict, action, outcome events
InterlockLedger Ledger of security events
InterlockGraph  Design, execution, and attack-path graphs
```

## Documentation

- [External-effect recovery (Korean)](docs/effect-recovery.ko.md): receipt reconciliation, fenced non-execution, approval-preserving resume, and a real todayPlanner fault demo
- [Model tool-use evaluation (Korean)](docs/model-evaluation.ko.md): independent selection, argument, order, approval, and task-success scores
- [Provider operations (Korean)](docs/provider-operations.ko.md): reviewed retries/failover, policy preservation, latency, and usage

Design docs are English-first; each has a Korean original alongside it (`*.ko.md`).

- [`docs/00-document-map.md`](docs/00-document-map.md): Doc responsibilities, recommended reading order, IDs, change rules
- [`docs/01-project-plan.md`](docs/01-project-plan.md): Event DB, detection/blocking platform, PostgreSQL DDL, implementation roadmap
- [`docs/02-developer-framework-design.md`](docs/02-developer-framework-design.md): SDK, Actor Wrapper, LinkPolicy, graph-centric developer experience
- [`docs/03-l1-mcp-tool-security-profile.md`](docs/03-l1-mcp-tool-security-profile.md): L1 M1–M9 data flows, attack examples, observation/control mapping
- [`docs/04-mcp-tool-gateway-spec.md`](docs/04-mcp-tool-gateway-spec.md): MCP Tool Gateway components, state, policy, events, API contract
- [`docs/05-l1-security-validation-plan.md`](docs/05-l1-security-validation-plan.md): M1–M9 attack reproduction, expected verdicts, evidence, promotion criteria
- [`docs/06-implementation-status.md`](docs/06-implementation-status.md): Design contracts traced to current code and tests
- [`docs/07-security-architecture-studio-design.md`](docs/07-security-architecture-studio-design.md): Box-based Architecture-as-Code and Studio usage
- [`docs/08-runtime-telemetry-reconciliation.md`](docs/08-runtime-telemetry-reconciliation.md): Ledger/OTLP execution traces and the design/runtime drift contract
- [`docs/09-mcp-transport-enforcement.md`](docs/09-mcp-transport-enforcement.md): Adapter binding architecture manifests to MCP JSON-RPC enforcement
- [`docs/10-mcp-oauth-identity-guard.md`](docs/10-mcp-oauth-identity-guard.md): OAuth discovery, PKCE, SSRF/redirect, token identity binding
- [`docs/11-mcp-stdio-sandbox-receipts.md`](docs/11-mcp-stdio-sandbox-receipts.md): stdio process sandbox attestation and fake external receipt reconciliation
- [`docs/12-postgresql-ledger-api.md`](docs/12-postgresql-ledger-api.md): PostgreSQL RLS, append-only Ledger adapter, event/trace API
- [`docs/13-a2a-orchestration-platform.md`](docs/13-a2a-orchestration-platform.md): Execution contract from Trust Boundary through A2A Broker, Task workflows, orchestration
- [`docs/14-fake-platform-e2e-scenario.md`](docs/14-fake-platform-e2e-scenario.md): Full design→promotion→A2A→approval→MCP→evidence/drift scenario on fake customer data
- [`docs/16-adding-interlock-to-an-agent.md`](docs/16-adding-interlock-to-an-agent.md): The ten-minute path from an existing tool-using agent to a guarded one
- [`docs/specs/2026-09-08-adoption-layer.md`](docs/specs/2026-09-08-adoption-layer.md): Adoption-layer design and decisions

## Implementation strategy

1. Observe User→Agent, Agent→RAG, Agent→Tool, Agent→External in a single-agent service
2. Build the PostgreSQL-based Interaction Ledger
3. Promote in stages: OBSERVE → SHADOW → ENFORCE
4. Support ActorSpec/LinkPolicy in both code and manifests
5. Provide the static design graph and the runtime trace graph
6. Compile and enforce directional Trust Boundaries together with A2A, Scheduler, Sandbox

## Current implementation

The repository includes a Python 3.11 reference core following the docs' original implementation order. The core has zero external runtime dependencies; adapters use optional `postgres`, `anthropic` and `jwt` extras.

**SDK / Gateway policy core**

- `ActorSpec`, `LinkPolicy`, `define_actor()`, `connect()`, `wrap()` SDK
- Canonical/raw digests for MCP tool definitions with `DISCOVERED` → `APPROVED` → `ACTIVE` state transitions
- Isolation of definition drift, metadata instructions, cross-server references
- Call-argument schema, data classification, secret, destination, token-binding, declared-side-effect policy
- One-use invocation approvals in gateway and SDK: tenant, source/target, definition revision, installed policy, intent and exact arguments are bound together; consumed atomically before execution. See [docs/02 §4.2](docs/02-developer-framework-design.md).
- One `Check` table (29 checks) behind all three enforcement points, each selecting a `Profile`: MCP gateway 21, SDK 19, A2A broker 17. **The mechanism is shared; the coverage is not** — the broker shares only 9 checks with the gateway and has no egress, volume or taint control
- `OBSERVE`, `SHADOW`, `ENFORCE` modes
- Tool-result secret sanitization, `UNTRUSTED_TOOL_RESULT` taint, schema isolation

**MCP transport / identity**

- MCP `tools/list`/`tools/call`/`notifications/tools/list_changed` JSON-RPC enforcement with architecture digest binding
- MCP 2025-11-25 Streamable HTTP JSON/SSE client, session binding, inbound Origin/auth/lifecycle carrier
- Inbound resumable GET SSE with a pluggable `SessionStore` contract
- MCP OAuth discovery, PKCE S256, exact callback, resource-bound token exchange, RFC 7662 introspection
- Optional JWKS/JWT verifier plus loopback OAuth consent and one-time transaction store
- MCP stdio JSONL client, artifact pinning, signed sandbox attestation, Bubblewrap launch plan, timeout/process-group kill

**Supply chain / sandbox / egress**

- Signed provenance admission binding publisher, repository, revision, build, artifact digests
- Per-destination egress guard compiled from Architecture REL-07/External allowed domains, plus a SIMULATION receipt backend
- Contextual connectors with fake receipt/compensation reconciliation and no external transmission
- After-the-fact downstream receipt reconciliation with `REVOKE` evidence

**Ledger / evidence**

- Append-only Ledger separating verdict, enforcement, and outcome, plus static/trace graph data
- PostgreSQL partitioning, `session_user`-based FORCE RLS, append-only migrations/adapter
- `POST /v1/events` with tenant/scope/idempotency, OTLP/HTTP JSON `POST /v1/traces`, cursor-based `GET /v1/traces/{trace_id}`
- Canonical keyed signing helper and detached `SignedAuditSink` evidence

**Architecture contract / drift**

- Box-and-edge `ArchitectureGraph` with an executable JSON Schema
- PREVENT·DETECT·RESPOND·EVIDENCE and DECLARED·OBSERVED·ENFORCED·RECONCILED assurance levels
- Multi-agent Dynamic Edge Contract with design/runtime drift comparison
- Directional INTERNAL/EXTERNAL Trust Boundaries with cross-zone edge compilation and fail-closed lint

**A2A / orchestration**

- A2A 1.0 Agent Card/Message/Part/Task/Artifact with `SendMessage`/`GetTask`/`CancelTask` JSON-RPC core
- Real HTTP-socket A2A carrier enforcing Origin, auth, body size, `A2A-Version`, with an explicit 0.3 compatibility profile
- A2A Broker enforcing REL-06 actor/audience/resource/token/delegation/data/schema together with Trust Boundaries
- Task workflow engine with coordinator, dependencies, A2A/MCP/LOCAL/HUMAN transports, retry, timeout, approval, budget
- Tenant-scoped Run Control API bound to the active ENFORCE bundle, plus the Studio Runs operations screen

**Operations loop**

- Ledger/OTLP JSON runtime import with undeclared-relationship and control-bypass analysis
- M7 agent-config read guard, two-person-approved deploy, runtime drift guard
- CLI compiling Studio manifests into reviewable SHADOW deployment bundles

**Adoption layer**

- Anthropic Tool Runner adapter (`GuardedTool`/`GuardedAsyncTool`, `guard_tools`, `bind_architecture`), with an `approve=` hook reaching the shared approval implementation
- Intent derived from arguments and MCP tool annotations, judged against the declaration (`INTERLOCK-INTENT-ARGUMENT-MISMATCH`)
- `interlock verify`: nine L1 scenarios run against a project's own guarded tools, not a framework fixture
- Project-module contract (`MANIFEST`/`TENANT_ID`/`SOURCE_ACTOR_ID`/`APPROVER`/`BINDINGS`/`build()`) emitted by `interlock architecture skeleton`
- Acceptance-criteria grammar and three recorded outcomes per task (`executed`/`goalMet`/`securityMet`)
- One deployment mode: the deployment record's mode, not the authored manifest, governs a run
- SDK sharing the gateway's post-execution handling and approval implementation
- Unsupported JSON Schema keywords rejected at definition time
- Studio projects: new/open/save, editable id/version, manifest import

Key paths:

| Path | Contents |
|---|---|
| `src/agent_interlock/` | SDK, registry, policy, gateway, Ledger |
| `src/agent_interlock/adapters/` | Anthropic Tool Runner adapter (`guard_tools`, `bind_architecture`) |
| `src/agent_interlock/verify.py` | `interlock verify`: L1 corpus run against a project's own guarded tools |
| `schemas/` | Actor and Event Envelope JSON Schemas |
| `schemas/architecture.schema.json` | Architecture contract shared by the canvas and compiler |
| `schemas/ledger-api.openapi.yaml` | Event ingest / trace query OpenAPI contract |
| `migrations/postgresql/` | Initial PostgreSQL schema and partition helpers |
| `tests/test_core.py` | L1 core attack and benign regression tests |
| `tests/test_mcp_http.py` | Real HTTP-socket MCP lifecycle, JSON/SSE, security carrier tests |
| `tests/test_mcp_oauth.py` | Real OAuth-fixture discovery, PKCE, SSRF, token-binding tests |
| `tests/test_mcp_stdio.py` | Real-subprocess stdio lifecycle, sandbox, timeout tests |
| `tests/test_supply_chain.py` | Publisher signature, provenance, MCP profile admission binding tests |
| `tests/test_egress.py` | Architecture-bound per-destination egress and socket/termination receipt tests |
| `tests/test_l1_matrix.py` | 34 tracked L1-SIM M1–M9 IDs with canary/receipt invariant tests |
| `tests/test_config_guard.py` | M7 config least-privilege, two-person approval, CAS, runtime drift tests |
| `tests/test_otlp_receiver.py` | Authenticated OTLP/HTTP JSON receiver tests |
| `tests/test_audit_sink.py` | Signed audit record seal/tamper verification tests |
| `tests/test_receipts.py` | Fake external transaction, receipt 0/1, reconciliation tests |
| `tests/test_ledger_http.py` | Real-socket tenant/scope/idempotency/pagination tests |
| `tests/test_postgres_ledger.py` | DB role binding and optional PostgreSQL 16 live tests |
| `tests/test_a2a.py` | Trust Boundary, A2A 1.0/0.3 wire, real HTTP socket, orchestration, acceptance-outcome tests |
| `tests/test_anthropic_adapter.py` | Anthropic Tool Runner adapter: guarded sync/async calls, blocking, approval hook tests |
| `tests/test_verify.py` | `interlock verify` per-scenario pass/fail, NOT-APPLICABLE, canary, exit-code tests |
| `tests/test_platform_e2e.py` | Full fake-data compile, two-person promotion, real localhost A2A, approval, MCP, runtime/statistics/drift tests |
| `tests/fixtures/platform_e2e/` | Deterministic fake customer/knowledge/receipt fixtures with `.invalid` addresses |
| `examples/secure_email.py` | Minimal runnable example |
| `examples/secure_multi_agent_architecture.json` | Multi-agent security architecture example |
| `examples/runtime_drift_otlp.json` | OpenTelemetry GenAI/MCP runtime drift example |
| `examples/mcp_transport_vertical_slice.py` | Runnable example binding an architecture manifest to MCP call enforcement |
| `examples/a2a_orchestration_vertical_slice.py` | Full Boundary→A2A→workflow→Ledger runnable example |
| `examples/support_agent/` | Runnable Anthropic Tool Runner project with recorded-replay tests |
| `studio/` | Actor topology, Task workflow, Trust Boundary editing and manifest export UI |

The current implementation covers the policy core of the [04 MCP Tool Gateway spec](docs/04-mcp-tool-gateway-spec.md); the JSON-RPC and resumable Streamable HTTP carriers plus publisher admission of [09 MCP Transport Enforcement](docs/09-mcp-transport-enforcement.md); discovery, PKCE, introspection/JWKS, and loopback consent from [10 OAuth Identity Guard](docs/10-mcp-oauth-identity-guard.md); signed attestation, Bubblewrap, Seatbelt, and per-destination egress reference boundaries from [11 stdio Sandbox & Receipts](docs/11-mcp-stdio-sandbox-receipts.md); per-tenant storage/query and signed audit reference from [12 PostgreSQL Ledger API](docs/12-postgresql-ledger-api.md); and the directional Trust Boundary, A2A Broker, and Task workflow engine of [13 A2A Orchestration](docs/13-a2a-orchestration-platform.md).

Production-integration additions: a persistent PostgreSQL DefinitionRegistry and distributed Session/OAuth/Config stores (RLS, migrations 0002/0003), macOS Seatbelt and Linux bwrap+seccomp sandboxes (live-enforced in tests), a real-socket egress backend with DNS/IP pinning, Ed25519 publisher and Studio approval signatures, Langfuse/LangSmith trace adapters, an append-only WORM audit store, and PostgreSQL live CI on GitHub Actions. The product closed loop includes tenant+interaction full-lifecycle security statistics (Python/Studio Unicode golden parity), `GET /v1/statistics`, manifest→SDK skeleton and security-test generation, a public-key-verified two-person promotion/rollback Control Plane, and Studio statistics/deploy views with read-only Live Attach.

What remains is not shipped, and is not external-integration work: a LangGraph adapter, a Claude Agent SDK adapter, a sidecar proxy, server-side MCP connector interception (the API's `mcp_servers` executes tools on Anthropic's side and cannot be intercepted, so it stays out of scope), an LLM-judge acceptance evaluator (the grammar is structural only), `BYPASSED` semantics (the open question in [Control Coverage Statistics](docs/specs/2026-07-27-control-coverage-statistics.md)), PyPI upload. Beyond that, what remains is genuine external-integration work (Sigstore/Rekor, KMS/HSM, IdP/Secret Store, a real egress sidecar and S3 Object-Lock, OTLP gRPC/Collector/Incident services, PostgreSQL HA, distributed rate limiting, TLS, remote Git-host PR review/deploy, DPoP/mTLS, JWKS rotation, operational consent/refresh tokens). Detailed contract tracing and classification follow [06 Implementation Status](docs/06-implementation-status.md).

## Operating contract

The managed host has one deployment owner and one scheduler. Tenant-scoped run/ledger APIs do not provide independent shared-SaaS tenant deployments. SQLite run snapshots retain their original bundle and workflow approvals; restart marks interrupted RUNNING work `RUN-INTERRUPTED` without replaying side effects, while waiting/pending work resumes explicitly. Terminal runs remain queryable until explicit pruning.

PostgreSQL Ledger makes event evidence durable. Gateway invocation approvals and result/idempotency caches stay process-local. An arbitrary in-process adapter's timeout cannot stop or undo an external effect; cancellation is cooperative. Authored controls, installed classification/export/provenance hooks and observed evaluations are separate evidence. See [implementation status](docs/06-implementation-status.md) and the [managed host](docs/managed-support-host.md) for the full boundaries.
