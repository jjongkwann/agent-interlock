---
title: Agent Interlock Implementation Status
date: 2026-07-21
version: 0.10.0
status: active
---

# Agent Interlock Implementation Status

> 한국어 원문: [06-implementation-status.ko.md](06-implementation-status.ko.md)

This document is the traceability map between the design contract and the current code. It is updated with every release so that unimplemented items are never treated as done.

## Implementation Baseline

- Language: Python 3.11
- Deployment form: dependency-free reference core + optional psycopg PostgreSQL adapter
- Baseline specification: `03`–`05` version 1.1
- Implementation modes: in-memory/PostgreSQL Registry (`InMemoryRevisionStore` · `PostgreSQLRevisionStore`), in-memory/PostgreSQL Session·OAuth·Config Store, in-memory/PostgreSQL Ledger, A2A Broker with bounded task orchestration

## Contract Traceability

| Contract | Implementation | Verification |
|---|---|---|
| Actor `define` / `connect` / `wrap` | `src/agent_interlock/sdk.py` | `SDKTests` (**one** test — `define`/`connect`/graph wiring only), `tests/test_sdk_profile.py` (14 tests: the 16 checks `wrap()` runs, its rename map, and its execution gate) |
| Unified check table · profiles | `policy.py` `Check`·`CheckScope`·`Profile`·`CheckContext`·`CHECKS`(26)·`run_checks` | `tests/test_check_table.py` (20 tests: table construction, the three coverage states, per-check `armed`, duplicate-id rejection) |
| Per-enforcement-point profiles | `GATEWAY_PROFILE`(18) · `SDK_PROFILE`(16) · `A2A_PROFILE`(16) → `A2A_LINK_PROFILE`(11)·`A2A_BOUNDARY_PROFILE`(5) | each profile's **whole** rename map pinned, not just the code set it yields; static audit that every emittable reason key is mapped |
| Decision severity ordering | `models.py` `_DECISION_RANK` (all 11 `ControlDecision` members, no fallback; `RuntimeError` at import if not total) | `tests/test_decision_ranking.py` (12 tests: totality, distinctness naming the colliding pair, `BYPASSED` below `ALLOW`, `ERROR` below `QUARANTINE`) |
| Execution permit, aggregated apart from severity | `policy.execution_permitted`, `PolicyDecisionRecord.execution_permitted` ANDed into `permits_execution` | `tests/test_execution_permit.py` (10 tests; pins that `[ALLOW, BYPASSED]` does **not** permit execution) |
| Mode-independent "policy objected" | `PolicyDecisionRecord.would_block`, derived from `_DECISION_RANK` rather than `!= ALLOW` | `tests/test_decision_ranking.py`; disagrees with the five remaining `!= ALLOW` predicates on `BYPASSED` **by design** |
| Credential verification is not credential presence | `CredentialClaims.authenticated` (defaults `False`); `_credential_missing` requires it | `tests/test_check_table.py`, `tests/test_sdk_profile.py` — an unverified claims blob is `L1-M5-CREDENTIAL-MISSING`, not a clean M5 pass |
| Link data classes bounded by the target Actor's grant | `architecture.py:806-818` `ARCH-DATA-CLASS-EXCEEDS-ACTOR` (CRITICAL, blocks compile) | `tests/test_architecture.py`; **skips Actors with empty `dataAccess`, which is every Studio export** — see [07 §5.7](07-security-architecture-studio-design.md) |
| Pre-merge behaviour pinned before restructuring | — | `tests/test_policy_characterization.py`, `tests/test_a2a_characterization.py` (the 25 previously-uncovered reason codes) |
| Static design · single trace graph data | `Interlock.design_graph`, `runtime_graph` | `test_define_connect_wrap_and_graph` |
| Canonical/raw definition digest | `canonical.py`, `registry.py` | `CanonicalizationTests`, `RegistryTests` |
| Definition state and digest pin | `DefinitionRegistry` | M2 drift regression test |
| D1 metadata instruction · cross-server reference | `DefinitionRegistry._inspect` | M1·M3 regression tests |
| D3 schema · secret · destination · side-effect verdict | `policy.py`, `security.py` | M8·M9 regression tests |
| Token audience/resource/actor binding · passthrough prohibition | `policy.py` | M5 regression test |
| Hash- and destination-bound approval | `MCPToolGateway.grant_approval` | approval-change regression test |
| Hash-bound, idempotent Connector execution | `execute_approved_call` | mutation · duplicate-execution regression test |
| Result secret redaction · taint · schema check | `inspect_result` | result D5 regression test |
| Post-hoc receipt reconciliation | `reconcile_transaction` | undeclared egress regression test |
| Verdict/enforcement/result separated events | `InMemoryLedger`, `gateway.py` | event ordering · integrity test |
| PostgreSQL partitioning · RLS · append-only | `migrations/postgresql` | verified applied against ephemeral PostgreSQL 16 DB |
| PostgreSQL Ledger adapter · hash re-verification | `PostgreSQLLedger` | live tests with real psycopg append · replay · query |
| Event ingest · trace query HTTP API | `LedgerHTTPAPI`, `ledger-api.openapi.yaml` | real-socket tenant · scope · idempotency · pagination tests |
| Architecture-as-Code manifest | `architecture.py`, `architecture.schema.json` | `ArchitectureModelTests` |
| Security assurance levels and Architecture lint | `ArchitectureLinter` | `ArchitectureSecurityLintTests` |
| Directional Trust Boundary and cross-zone compile | `ArchitectureBoundary`, `CompiledArchitecture.boundary_for` | `ArchitectureBoundaryTests`, Studio manifest compile |
| A2A 1.0 protocol core · Agent Card · Task | `a2a.py` `A2ABroker`·`A2AJSONRPCRouter` | v1 `SendMessage/GetTask/CancelTask`, explicit v0.3 compatibility, policy/idempotency tests |
| Authenticated A2A HTTP carrier | `a2a_http.py` | real-socket Origin · auth · version · body-limit · well-known Agent Card tests |
| Multi-Agent Task workflow engine | `orchestration.py` `OrchestrationEngine` | A2A dependency, approval pause/resume, missing-adapter fail-closed tests |
| Deployment-bound Run Control API | `run_control.py`, `control_plane.py` `/v1/runs` | actual ENFORCE bundle binding, scope/tenant isolation, approval/cancel, missing-adapter fail-closed HTTP tests |
| Dynamic Sub-Agent Edge contract | `DynamicTargetSelector` | dynamic-instance regression test |
| Design/Runtime drift · bypass comparison | `compare_runtime` | `RuntimeGraphDiffTests` |
| Box-based security design editor | `studio/app/page.tsx` | Studio build · rendered-HTML contract test |
| Ledger · OTLP JSON runtime import | `telemetry.py`, `studio/app/runtime.ts` | `RuntimeTelemetryImportTests`, Studio parser test |
| Runtime Graph · Drift reconciliation view | `studio/app/page.tsx` | OTLP fixture import · render test; no built-in product demo path |
| Studio Runs operations view | `studio/app/panels.tsx` | Run Control create/list/get/approve/resume/cancel/events route contract and Studio build test |
| MCP JSON-RPC Tool transport enforcement | `mcp_transport.py` | `MCPTransportVerticalSliceTests` |
| Architecture exact digest runtime binding | `bind_compiled_architecture` | mismatch · drift · deletion regression test |
| Streamable HTTP JSON/SSE downstream client | `mcp_http.py` | lifecycle · session · SSE · redirect · size tests |
| Inbound MCP HTTP security carrier | `MCPStreamableHTTPGatewayCarrier` | real-socket Origin · auth · token separation test |
| OAuth Protected Resource · AS discovery | `mcp_oauth.py` | well-known ordering · resource/issuer mismatch test |
| PKCE · redirect · token resource binding | `MCPAuthorizationCodeFlow`, `MCPAuthorizationCodeTokenClient` | real OAuth fixture · SSRF · replay · audience tests |
| stdio JSONL · process lifecycle carrier | `MCPStdioClient` | real-subprocess lifecycle · noise · size · timeout · group-kill test |
| stdio artifact · sandbox attestation binding | `StdioSandboxProfile`, `MCPStdioServerCaller` | digest mismatch · missing-backend · Architecture binding test |
| Fake external receipt · reconciliation | `FakeExternalReceiptStore`, contextual Connector | receipt 0/1 · hidden-egress · idempotency · compensation test |
| L1-SIM M1–M9 matrix · canary corpus · invariant runner | `tests/test_l1_matrix.py`, `tests/l1_harness.py` | all 34 test IDs executed, TEST_EXECUTED SIMULATION |
| M9 volume/DLP pre-emptive block | `policy.py` `max_export_records`/`max_export_bytes` | `L1-SIM-M9-003` pre-emptive BLOCK test |
| Canonical keyed signing helper | `signing.py` `sign_canonical`/`verify_canonical` | round-trip · tamper · wrong-key test |
| Signed Audit Sink evidence | `audit_sink.py` `SignedAuditSink` | seal · verify · integrity · swap-rejection test |
| OTLP/HTTP JSON receiver | `ledger_http.py` `POST /v1/traces` | real-socket OTLP decode · missing-context · scope test |
| Signed sandbox attestation verifier | `mcp_stdio.py` `sign_attestation`·`AttestationVerifier` | signed · wrong-key · unsigned · tamper · client-enforcement test |
| Inbound resumable SSE · SessionStore | `mcp_http.py` `SessionStore`·`InMemorySessionStore` | session issuance · READY · Last-Event-ID replay · multi-instance · DELETE test |
| RFC7662 introspection verifier · OAuth TransactionStore | `mcp_oauth.py` `MCPTokenIntrospectionVerifier`·`InMemoryOAuthTransactionStore` | active/claim mapping · client-auth · SSRF · one-time-consume test |
| Studio compile → SHADOW deployment bundle | `__main__.py` `architecture compile --shadow` | golden round-trip · SHADOW enforcement · digest · CRITICAL review-gate test |
| M7 agent-config guard (read · deploy · drift) | `config_guard.py` `ConfigGuard`·`InMemoryConfigStore`·`RuntimeConfigProbe` | role minimization · two-person signed deployment · CAS · drift · M7-001..004 matrix test |
| JWKS/JWT signature verifier (optional `jwt` extra) | `mcp_jwt.py` `MCPJWKSVerifier` | RS256/ES256/EdDSA verification · alg-confusion rejection · kid · exp/nbf/iss test |
| Loopback OAuth consent | `oauth_consent.py` `LoopbackCallbackReceiver`·`run_consent` | callback capture · one-time · timeout · loopback-only test |
| Bubblewrap OS sandbox backend | `mcp_stdio.py` `BubblewrapSandboxBackend` | argv construction · honest attestation bits (fs/net True, child False) · child-rejection fail-closed · unsafe-mount rejection · signature test |
| Publisher provenance admission | `supply_chain.py` `ArtifactAdmissionPolicy`·`MCPServerProfile` binding | untrusted/unsigned · repository · tamper isolation, server call 0, signed control test |
| Per-destination egress broker | `egress.py` `DestinationEgressGuard`·`compile_destination_egress_policy` | tenant/workload/artifact/provenance/sandbox exact binding, deny socket 0 · kill, allow receipt 1 test |
| Distributed PostgreSQL Session/OAuth/Config store | `postgres_stores.py` `PostgreSQLSessionStore`·`PostgreSQLOAuthTransactionStore`·`PostgreSQLConfigStore`, `migrations/postgresql/0002` | RLS · revision-immutability trigger contract, serialization round-trip · tamper rejection, CAS stale, DSN-gated multi-instance live test |
| Gateway config-guard preflight (opt-in) | `gateway.py` `_config_preflight` | disabled by default, drift → synthesized QUARANTINE, guard's own CONTROL_EVALUATED trace test |
| Seatbelt OS sandbox backend (macOS) | `mcp_stdio.py` `SeatbeltSandboxBackend` | policy construction · honest bits (fs/net/child all True when enforced) · unsafe-path · SBPL-injection rejection · signature + **macOS live enforcement test** (home/write/fork/network blocked) |
| Real-socket egress backend (DNS · IP pinning) | `egress.py` `PinnedSocketEgressBackend` | single DNS resolution · pinned connect IP · peer verification · non-global-address fail-closed · one-time socket handoff, real 127.0.0.1 fixture test |
| Asymmetric publisher signature verification (KMS adapter point) | `supply_chain.py` `PublisherVerifier`·`Ed25519PublisherVerifier`·`HMACPublisherVerifier`, `signing.py` `sign/verify_canonical_ed25519` | Ed25519 approval · cross-key rejection · tamper · KMS-style custom verifier · HMAC backward-compatibility test |
| bwrap seccomp child-process enforcement (Linux) | `mcp_stdio.py` `build_no_subprocess_seccomp`·`BubblewrapSandboxBackend(seccomp_child_denial=True)` | fork/vfork · non-thread clone → EPERM, clone3 → ENOSYS (glibc falls back to a clone it can flag-check — pthreads survive), thread clone · execve → ALLOW BPF simulation verification, honest child=True attestation, **bwrap live CI enforcement passing** (real-kernel verification of fork/subprocess rejection · thread allowance) |
| Distributed PostgreSQL DefinitionRegistry | `registry.py` `RevisionStore`·`InMemoryRevisionStore`, `postgres_stores.py` `PostgreSQLRevisionStore`, `migrations/postgresql/0003` | state machine unified via store extraction, RLS · identity-immutability trigger · digest re-verification · multi-node live test |
| Langfuse/LangSmith trace adapters | `vendor_telemetry.py` `langfuse_traces_to_otlp`·`langsmith_runs_to_otlp`·`import_*` | maps vendor metadata → OTLP attributes then reuses import_runtime_telemetry, edge reconstruction · incomplete-context issue test |
| WORM audit retention store | `audit_sink.py` `WORMAuditStore`·`InMemoryWORMAuditStore`·`FileWORMAuditStore` | append-only · hash chain, write-once duplicate rejection · deletion/substitution/reordering chain-break detection, file backend JSONL append · fsync · post-restart chain re-verification · persistent dedupe · tamper/deletion open-time detection test |
| Studio git deployment workflow | `studio_deploy.py` `GitBundleStore`·`sign_deployment_approval` | Ed25519 private-key approval / public-key verification, real git propose→two-person SHADOW→ENFORCE, rollback to a past active bundle only with fresh two-person approval, rejection test for two identities sharing one public key · forgery · digest tamper |
| PostgreSQL live provisioning | `ci/docker-compose.postgres.yml`·`ci/postgres_provision.sql`·`ci/run_postgres_live.sh`, `.github/workflows/ci.yml` | postgres:16 + migrations 0001–0003 + mapping of 2 tenant roles, runs 6 live store/ledger tests |
| Eliminating artifact verify-then-exec TOCTOU (fd exec) | `mcp_stdio.py` `_open_verified_artifact`·`SandboxLaunchPlan.executable_digest`, client `/proc/self/fd` exec | digest verification on the fd · tamper/swap rejection · non-regular-file rejection, per-backend argv[0] pinning, fd-exec execution on Linux CI |
| Sandbox process supervisor · health telemetry | `sandbox_supervisor.py` `SandboxSupervisor`·`SandboxHealth`·`SupervisedProcess` | liveness/health probe, bounded-backoff restart, attestation re-verification on restart (swap fail-closed), test emitting `CONTROL_HEALTH_CHANGED` (REL-11) on every transition |
| OTLP semantic convention adapter · telemetry health | `otlp_semconv.py` `normalize_otlp_semconv`·`SEMCONV_ALIASES`, `control_health.py` `ControlHealthReporter` | normalizes legacy (`llm.*` · snake_case) aliases → canonical form, canonical takes priority; test wiring import issues · sampling gaps · Audit Sink failure to `CONTROL_HEALTH_CHANGED` (REL-12) |
| server-initiated request · async task · cancellation/replay | `mcp_async.py` `ServerRequestRouter`·`AsyncTaskRegistry`·`TaskState`, `mcp_http.py` `set_server_request_router` | allowlist fail-closed routing · unknown-method rejection · handler isolation, task lifecycle · one-time consume (replay rejection) · idempotent cancel · principal binding · capacity, HTTP client wiring test |
| PostgreSQL migration runner · partition/retention · pool | `postgres_ops.py` `PostgreSQLMigrationRunner`·`PartitionMaintenance`·`PostgreSQLConnectionPool` | idempotent apply · checksum-drift rejection · legacy-file skip, monthly partition ensure · DETACH + ingest-key prune then drop, bounded pool reuse/capacity, admin-DSN-gated live round-trip test |
| Security statistics contract · interaction reducer | `analytics.py`, `schemas/security-statistics.schema.json`, `schemas/fixtures/analytics-*.json` | joins tenant_id+interaction_id state (REQUESTED→CONTROL→ACTION→OUTCOME), counts a denied `control.executionPermitted` as a block even when every decision reduces to ALLOW (absent key = permitted), requires both completed enforcement action and final BLOCKED evidence, per-mode aggregation, golden fixture · real gateway reduction test |
| Studio TS reducer parity (cross-language golden) | `studio/app/analytics.mjs`(+`.d.ts`) | **byte-identical** sort-key serialization against Python on the same fixture, decision rank map mirroring `models._DECISION_RANK` member for member, Unicode code-point ordering · bare-array/`{events}`-wrapper parity (`studio/tests/analytics-contract.test.mjs`) |
| Control coverage channel (which controls looked, not only which fired) | `policy.py` `CheckOutcome`·`coverage_declaration`·`control_coverage`, `models.py` `ControlCoverage` | `armed`/`ran`/`flagged` beside the verdict; `armed` may read only the link-constant half of `CheckContext`, pinned by varying exactly the per-invocation fields over all 28 checks; empty-subject rule (`None`, never `()`) audited with each non-empty twin; profile membership pinned whole |
| `CONTROL_COVERAGE_DECLARED` event · four-place vocabulary | `ledger.py` `declare_coverage`, `ledger_http.py` `_EVENT_TYPES`, `schemas/event-envelope.schema.json`, `schemas/ledger-api.openapi.yaml`, `migrations/postgresql/0004_control_coverage.sql` | declared once per digest, carries no `interaction_id`; digest covers the whole body so a reader can recompute it; test asserts all four registrations agree **and** that each of the three text parsers found something |
| Coverage statistics (`byCheck`·`byEdge`·`unattributed`) | `analytics.py` `CheckCoverage`·`_by_check`·`_by_edge`, `schemas/security-statistics.schema.json` | four states per canonical check id across all three enforcement points, edge cross-tabulation keyed on (source, target, policyId), all-ABSENT rows omitted per edge, `noControlRecordCount` in every counters block, unresolvable digest contributes nothing |
| SDK event shape conformance (identical to gateway) | `sdk.py` (`payload.control` nesting · connector `connectorExecutionId`) | verified via scaffold-generated tests that SDK-wrapped actors are captured in statistics |
| Ledger interaction range query · statistics API | `ledger.py`/`postgres_ledger.py` `interaction_lifecycles_started_between`, `ledger_http.py` `GET /v1/statistics`, `ledger-api.openapi.yaml` | selects in-range REQUESTED then joins the full lifecycle **plus every coverage declaration before `end`** (they carry no `interaction_id`, so the interaction filter alone returns a window where every check reads ABSENT), `statistics:read` scope, dataSource, 422 on limit exceeded, PG tenant-scoped SQL test |
| Manifest skeleton · security-test generator | `scaffold.py`, `interlock architecture skeleton` | example manifest output verified for import · `build()` wiring · **passing its own generated security tests** (verdicts asserted via the statistics reducer) |
| Studio promotion CLI | `__main__.py` `interlock studio propose/approve/promote/rollback/status` | compile→propose→Ed25519 two-person approval→promote→fresh-approved rollback E2E, private key from env · verification key from a public-only file |
| Run Control Plane (privileged deployment command API) | `control_plane.py` `ControlPlaneAPI` | server holds only approver-bound public keys, signature verified on submission, promote/rollback two-person gate, rejects rollback of a never-promoted bundle, `deploy:*` scope test |
| API CORS (Studio read-only Live Attach) | `ledger_http.py`·`control_plane.py` | pre-auth origin rejection, preflight OPTIONS, allowed-origin echo, loopback-http development-origin allowance test |
| Studio statistics · deployment views | `studio/app/panels.tsx` (`StatsPanel`·`DeployPanel`), `page.tsx` stats/deploy views | offline ledger-import aggregation + live `/v1/statistics` fetch, control-plane promotion panel (signing keys stay outside the browser), build · lint · contract test |
| Full fake-data platform E2E | `tests/test_platform_e2e.py`, `tests/fixtures/platform_e2e/` | full manifest digest→git propose→Ed25519 two-person ENFORCE→real localhost A2A→approval pause/resume→one fake MCP call→Ledger Runtime/Statistics/Drift + D5 block · undeclared-bypass test |

## Currently Automated L1 Scope

`tests/test_core.py` verifies M1 metadata instruction, M2 definition drift, M3 cross-server reference, M5 token mismatch/passthrough, M6 authorization URL, M8 argument/result secrets, and M9 Unicode destination · undeclared side effect · post-hoc egress. It also verifies normal calls, SHADOW non-enforcement, approval binding, and idempotency. `tests/test_architecture.py` verifies Architecture compile, security lint, Dynamic Edge, and runtime drift. `tests/test_mcp_transport.py` verifies real MCP JSON-RPC D1/D3/D4 boundaries, exact digest binding, drift/deletion, trusted context, and zero dispatch. `tests/test_mcp_http.py` verifies lifecycle, JSON/SSE, session, Origin, authentication, timeout, redirect, and token separation over a local real HTTP socket. `tests/test_mcp_oauth.py` verifies protected resource/AS discovery, PKCE, SSRF, redirect, callback replay, and token claim binding using real OAuth HTTP fixtures. `tests/test_mcp_stdio.py` and `tests/test_receipts.py` verify real subprocess stdio boundaries and transaction reconciliation without external transport. `tests/test_ledger_http.py` and `tests/test_postgres_ledger.py` verify the event/trace API and DB role tenant binding, and the PostgreSQL 16 live tests run in CI when a DSN is present.

`tests/test_l1_matrix.py` automates all 34 L1-SIM-M1..M9 test IDs from [05 Validation Plan](05-l1-security-validation-plan.md) as SIMULATION. M4 publisher admission · destination egress deny/allow, M5 scope broadening · callback replay, and M6 private-IP redirect · response size · safe consent paths also leave independent matrix-test and `TEST_EXECUTED` evidence. The following items are the production-integration boundary beyond reference verification.

The current full regression: **`Ran 597 tests, OK (skipped=12)`** on the CI path (`PYTHONPATH=src:tests python3 -m unittest discover -s tests`), plus 8 Studio tests (`npm test`, including build · golden · Unicode · boundary/orchestration contracts). The control-coverage work added `test_control_coverage.py`. The unified-judgment-engine work added six test files — `test_policy_characterization.py`, `test_a2a_characterization.py`, `test_check_table.py`, `test_sdk_profile.py`, `test_decision_ranking.py`, `test_execution_permit.py` — and extended `test_core.py`, `test_architecture.py`, `test_l1_matrix.py` and `test_scaffold.py`. The previously published figure of 454 predates all of it and was measured on the `pytest` path, which collects differently; quote the `unittest` number, since a checkout without the optional extras under-collects under `pytest`. Current skips are the Linux+bwrap live and DSN-less PostgreSQL live families; the seccomp BPF logic is verified in-test with a classic-BPF interpreter, while real-kernel enforcement is verified by the CI `sandbox-live` job.

- Sigstore/Rekor network verification (asymmetric signing · KMS adapter point are implemented) and real egress proxy/sidecar socket · kill-telemetry operational wiring (DNS · connect-IP pinning is implemented via `PinnedSocketEgressBackend`)
- OTLP gRPC (:4317) streaming receiver (the HTTP JSON receiver and Langfuse/LangSmith adapters are implemented), Incident/response service
- PostgreSQL automated partition/retention operations and connection pool · HA (live CI · provisioning are implemented)
- S3 Object-Lock durable backend for WORM retention (the Protocol · append-only hash-chain implementation is implemented), remote Git host PR review wiring (local git propose/promote/rollback is implemented)
- Advanced MCP async task · cancellation, IdP key rotation · DPoP/mTLS sender-constrained tokens
- A2A durable task/run store, signed Agent Card registry, SSE/subscription/push, distributed scheduler/worker lease

## Next Implementation Order

All 10 integration items from doc-06 §Next Order have been implemented: (a) M1–M9 test ID automation and canary corpus, (b) canonical signing helper, (c) OTLP/HTTP JSON receiver and signed Audit Sink, (d) signed sandbox attestation verifier, (e) inbound resumable SSE and SessionStore, (f) RFC7662 introspection verifier and OAuth TransactionStore, (g) Studio `compile --shadow`, (h) M7 agent-config guard, (i) JWKS/JWT verifier (optional `jwt` extra) and loopback consent, (j) Bubblewrap OS sandbox backend.

The following additional production-integration items have since been implemented: distributed PostgreSQL stores (Session/OAuth/Config `0002`, DefinitionRegistry `0003`), opt-in gateway config-guard preflight, macOS Seatbelt · Linux bwrap seccomp sandboxes (live enforcement), real-socket egress backend (DNS · IP pinning), asymmetric publisher signing (Ed25519 · KMS point), Langfuse/LangSmith trace adapters, WORM audit store, Studio git deployment (propose→two-person promotion→rollback), PostgreSQL live CI provisioning and GitHub Actions.

What remains falls into two categories: one is **internal implementation work** that can be built inside this repository without external services or infrastructure, and the other is **integration work** with external SaaS, services, and platforms.

**Internal implementation work: all complete.** This repository has implemented and verified: eliminating the TOCTOU window between artifact digest verification and exec (fd exec), a long-running process supervisor and sandbox health telemetry, the OTLP semantic convention adapter and wiring sampling gaps/Audit Sink failures to `CONTROL_HEALTH_CHANGED`, MCP server-initiated requests · async tasks · cancellation/replay, the PostgreSQL migration runner · automated partition/retention · connection pool, and file-based append-only persistence for the WORM store.

**The 2026-07-19 product closed-loop (design→contract→development→SHADOW execution→evidence→statistics/drift→promotion) connective layer is also complete.** Statistics are not event counts but a join over tenant+interaction state, reading the full lifecycle of interactions whose REQUESTED event falls in range. A successful enforcement requires both a completed enforcement action and final BLOCKED evidence, and the cross-language golden contract pins even the Unicode ordering identically between the Python API and Studio's offline import. Promotion/rollback approval is an Ed25519 statement that includes the approver identity, and the Control Plane holds only the public key. Known v1 limits: statistics time series render as a table, control-plane pending approvals are in-memory (resubmission required after restart), large ranges are defended with a 422 rather than pre-aggregation, and OTLP import cannot be aggregated into statistics (raw ledger events are required).

**The 2026-07-20 Trust Boundary→A2A→orchestration vertical slice is also complete.** Studio's Actor topology and Task workflow are stored in a single manifest, and the compiler validates cross-zone boundaries and task transport together. The A2A 1.0 JSON-RPC core enforces REL-06 and boundaries before handler execution, and the workflow engine applies dependency · retry · timeout · approval · budget. Operational limits: an in-memory task/run store, a single-process scheduler, and a non-streaming A2A core.

What remains is only external service/platform integration (below).

**External integration work (requires external services/platforms):**

1. Sigstore/Rekor network verification, external KMS/HSM key issuance · rotation · revocation, production IdP · Secret Store integration
2. Real egress sidecar socket forwarding · blocking · kill telemetry, S3 Object-Lock–based durable WORM export
3. OTLP gRPC (:4317) streaming receiver · Collector queue/backpressure, Incident/response service
4. PostgreSQL HA · failover · distributed rate limiting · TLS termination
5. Remote GitHub/GitLab PR review · deployment connection
6. IdP JWKS cache · key rotation · failure policy, DPoP/mTLS sender-constrained tokens, production consent UI · HTTPS callback · refresh-token lifecycle
7. A2A signed Agent Card registry, durable task/run store, SSE · push, distributed queue · worker HA

gVisor · Kata · Kubernetes sandbox backends are optional items needed only in deployment environments that must replace Bubblewrap/Seatbelt.
