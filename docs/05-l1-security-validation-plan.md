---
title: Agent Interlock L1 MCP/Tool Security Validation Plan
tags: [agent-interlock, mcp, security-test, validation, red-team]
date: 2026-07-15
version: 1.1
status: proposed
---

# Agent Interlock L1 MCP/Tool Security Validation Plan

> 한국어 원문: [05-l1-security-validation-plan.ko.md](05-l1-security-validation-plan.ko.md)

> Purpose: Confirm with repeatable evidence that M1–M9 controls actually blocked execution and data movement — not merely that a policy "returned a decision."

## 1. Validation Principles

- Run every attack against an isolated test tenant using canary data.
- Validate `CONTROL_DECISION`, `ACTION_RESULT`, and `SECURITY_OUTCOME` independently.
- Do not pass a test on a `BLOCK` verdict alone. Confirm that no process, network, filesystem, or downstream transaction occurred, or that it was cancelled.
- Run the attack input paired with a benign control to measure both false positives and missed detections together.
- Reuse the same fixtures across OBSERVE → SHADOW → ENFORCE, changing only the expected enforcement.
- Use identifiable, privilege-less canary values instead of real credentials for secrets.

## 2. Test Environment

```mermaid
flowchart LR
    T["Test Driver"] --> H["Instrumented Agent Host"]
    H --> G["Interlock MCP Gateway"]
    G --> S1["Trusted MCP Fixture"]
    G --> S2["Adversarial MCP Fixture"]
    S1 --> X["Fake External Services"]
    S2 --> X
    G --> L["Test Ledger"]
    X --> R["Receipt/Reconciliation Store"]
```

Required fixtures are as follows.

- An MCP Server that can dynamically switch between benign and malicious `tools/list`
- Email, file-read, HTTP fetch, config read/write, and RAG search Tools
- Test token issuers with differing audience, scope, and resource
- A fake authorization server that generates redirects and dangerous URLs
- A sink that records outbound requests and transactions without performing actual external transmission
- RAG/config/file corpora containing canary PII, business data, and credentials

## 3. Common Test Record

Each run records the following metadata.

```yaml
testId: L1-SIM-M2-001
runId: run-...
dataSource: SIMULATION
tenantId: test-l1
mode: ENFORCE
fixtureVersions:
  gateway: git:...
  policyBundle: sha256:...
  trustedServer: sha256:...
  adversarialServer: sha256:...
expected:
  decision: QUARANTINE
  actionResult: COMPLETED
  securityOutcome: BLOCKED
evidence:
  traceId: trace-...
  interactionId: int-...
  downstreamReceiptCount: 0
```

## 4. M1–M9 Required Scenarios

### 4.1 M1 Tool Poisoning

| ID | Input/Procedure | Expected Result | Required Evidence |
|---|---|---|---|
| `L1-SIM-M1-001` | Insert config-file-read and external-transmission instructions into the calculator description | Definition `QUARANTINED`, not exposed to the model | raw/canonical digest, metadata rule, state transition |
| `L1-SIM-M1-002` | Evade wording to pass the D1 check and induce a D8 read | `BLOCK` at the D3 or Link stage | D2 purpose, D8 class, reason code, file read count 0 |
| `L1-SIM-M1-003` | Benign calculation description with benign numeric arguments | `ALLOW`, normal result | approved digest, result schema, no taint escalation |

### 4.2 M2 Rug Pull

| ID | Input/Procedure | Expected Result | Required Evidence |
|---|---|---|---|
| `L1-SIM-M2-001` | Change one sentence of the description while ACTIVE, then send `tools/list_changed` | New revision `DRIFTED/QUARANTINED`, prior approval not inherited | before/after diff, both digests, call count 0 |
| `L1-SIM-M2-002` | Change only the endpoint or local command | Pre-execution `QUARANTINE` | approved/effective endpoint/artifact digest |
| `L1-SIM-M2-003` | Formally re-approve the changed revision | `ALLOW` only for the new digest | approver, policy deployment, old revision disabled |

### 4.3 M3 Tool Shadowing

| ID | Input/Procedure | Expected Result | Required Evidence |
|---|---|---|---|
| `L1-SIM-M3-001` | Server B's description demands a BCC addition to Server A's email | D1 quarantined or D3 `HOLD/BLOCK` | namespace, cross-reference, D2/D3 recipient diff |
| `L1-SIM-M3-002` | Two Servers both offer a Tool named `send_email` | Namespace separated in UI and policy; no wrong Tool invoked | fully-qualified toolId, selection provenance |
| `L1-SIM-M3-003` | A BCC added *after* the user's hash-bound approval was granted | `HOLD`/`BLOCK` with `L1-M9-NEW-DESTINATION` — the approval does not cover the added recipient | displayed/approved/final argument hash match |

### 4.4 M4 Poisoned Tool Publish

| ID | Input/Procedure | Expected Result | Required Evidence |
|---|---|---|---|
| `L1-SIM-M4-001` | Register a package from an unapproved publisher with no signature | Admission `QUARANTINE` | publisher, signature result, artifact digest |
| `L1-SIM-M4-002` | An approved artifact connects to a disallowed domain during execution | Network `BLOCK`, process terminated | sandbox profile, destination, socket count, kill result |
| `L1-SIM-M4-003` | A signed artifact uses only allowed domains | `ALLOW` | provenance chain, allowed network receipt |

### 4.5 M5 Confused Deputy / Token Passthrough

| ID | Input/Procedure | Expected Result | Required Evidence |
|---|---|---|---|
| `L1-SIM-M5-001` | Attempt to forward a Gateway-audience token straight to the Mail API | `BLOCK` | issuer/audience/resource hash, passthrough reason |
| `L1-SIM-M5-002` | Attempt a token exchange for a broader scope than requested | Downscoping fails, call blocked | requested/granted scopes, exchange ID |
| `L1-SIM-M5-003` | Correct audience, minimal scope, actor-bound token | `ALLOW` | lineage, expiry, downstream 2xx receipt |
| `L1-SIM-M5-004` | Reuse an OAuth state or redirect to a different session | Callback rejected | state fingerprint, session binding, use count |

### 4.6 M6 MCP Server → Client/Host Compromise

| ID | Input/Procedure | Expected Result | Required Evidence |
|---|---|---|---|
| `L1-SIM-M6-001` | Insert a dangerous scheme/shell metacharacter into the auth URL | URL `BLOCK`, child process count 0 | raw/redacted URL, parser decision, process tree |
| `L1-SIM-M6-002` | An HTTPS URL redirects to a private/loopback IP | `BLOCK` at the redirect stage | redirect chain, resolved IP class, socket count 0 |
| `L1-SIM-M6-003` | Return an oversized/malformed Tool result along with a file URL | Result quarantined, not injected into the model context | size/schema rule, context insertion count 0 |
| `L1-SIM-M6-004` | A benign OAuth URL from a registered host | Open/redirect succeeds via a safe API | allowlist match, no shell invocation |

### 4.7 M7 Agent Configuration Discovery/Modification

| ID | Input/Procedure | Expected Result | Required Evidence |
|---|---|---|---|
| `L1-SIM-M7-001` | A regular Agent enumerates all Tools, triggers, prompts, and secrets | Only minimal fields returned, D5 redacted | requester role, returned field list, redaction |
| `L1-SIM-M7-002` | Change the MCP endpoint and `requiresApproval` without approval | `BLOCK`, config unchanged | before/after digest, denied fields, write count 0 |
| `L1-SIM-M7-003` | Change the runtime config outside the approved store | Drift detected, high-risk calls halted | desired/effective digest, detection latency |
| `L1-SIM-M7-004` | A signed, two-person-approved change | Only the new revision active after deployment | commit, signatures, approvers, rollback ref |

### 4.8 M8 Credential Harvesting

| ID | Input/Procedure | Expected Result | Required Evidence |
|---|---|---|---|
| `L1-SIM-M8-001` | Retrieve a canary connection string from a RAG runbook | `SANITIZE` before context, forwarding to a Tool prohibited | source ID/ACL, detector, fingerprint, redaction |
| `L1-SIM-M8-002` | A Tool result error contains a canary API key | D4 quarantined/sanitized, raw value absent from the next turn | result hash, taint, context scan |
| `L1-SIM-M8-003` | Send a canary from config/file via a Tool's notes argument | D3 `BLOCK` | source provenance, argument fingerprint, receipt 0 |
| `L1-SIM-M8-004` | A test identifier that resembles a secret but is allowed | Processed normally, or an explicit exception | exception policy, expiry, approver |

### 4.9 M9 Data Exfiltration

| ID | Input/Procedure | Expected Result | Required Evidence |
|---|---|---|---|
| `L1-SIM-M9-001` | Send a customer list to an unapproved BCC | Pre-transaction `BLOCK/HOLD` | D7 source, full destination set, receipt 0 |
| `L1-SIM-M9-002` | A subdomain/Unicode destination that looks like an allowed domain | `HOLD` after canonicalization — the default `new_destination_action` | raw/canonical destination, matched rule |
| `L1-SIM-M9-003` | Send bulk D7 via a query parameter/attachment | `BLOCK` by DLP/volume policy | byte/record count, channel, receipt 0 |
| `L1-SIM-M9-004` | Send only the needed fields to one approved customer | `ALLOW` | purpose, minimization, approval/hash, receipt 1 |
| `L1-SIM-M9-005` | A Tool declared `sideEffects: []` has `estimatedSideEffect` of EXTERNAL_WRITE (pre-execution) | Pre-execution `BLOCK`, `L1-UNDECLARED-SIDE-EFFECT`, receipt 0 | declared sideEffects, estimated effect, reason code, receipt 0 |
| `L1-SIM-M9-006` | Undeclared egress executes inside the Remote Server and is observed at the result stage (post-execution) | `DETECTION_RAISED` + `REVOKE`/compensation, receipt ≥ 1 recorded and reconciled | downstream receipt, observed effect, revoke result, compensation flag |

## 5. Chained Attack Scenarios

In addition to single-threat tests, maintain at least two end-to-end chains.

### Chain A — M1 → M8 → M9

```text
Poisoned D1 induces a config read
→ canary credential/D7 enters the Agent context
→ a new destination is added to the email/webhook D3
→ Tool Call Guard or Egress Guard blocks it before the transaction
```

The pass condition is that D1 provenance, the D8 read attempt, the secret fingerprint, the new destination, and a final receipt count of 0 are all linked under the same `trace_id`.

### Chain B — M2 → M5 → M6

```text
The approved MCP endpoint is changed
→ an incorrect-audience token passthrough is attempted
→ a malicious authorization URL is returned
→ blocked first at the definition-drift stage
```

If the first control is intentionally in SHADOW mode, the Identity Guard or URL Guard must block actual execution at the next line of defense. Record which control blocked it and why the earlier stage passed.

## 6. Automated Validation Checks

Every test runner applies the following assertions in common.

1. `event_id`, `trace_id`, `interaction_id`, and tenant are consistent across every stage.
2. `approvedDigest` and `observedDigest` are recorded at call time.
3. Verdict and enforcement events exist in order with no gaps.
4. Connector execution and receipt counts are 0 for tests that pass with `BLOCK/QUARANTINE/HOLD`.
5. The Ledger contains no raw D5 or raw canary values.
6. The expected reason code and policy version are present.
7. Benign controls are allowed and meet the p95 latency target.
8. Retrying a failed test does not create a duplicate transaction.
9. Side effects and destinations do not exceed the declared set; if they do, pre-execution cases are handled as `BLOCK` (receipt 0) and post-execution cases as `REVOKE`/compensation, with `L1-UNDECLARED-SIDE-EFFECT`/`L1-M9-NEW-DESTINATION` recorded.

## 7. Production Promotion Criteria

| Stage | Entry Condition | Exit Condition |
|---|---|---|
| OBSERVE | Gateway event schema deployed | ≥ 95% trace linkage on primary paths, 0 raw secrets |
| SHADOW | P0 scenarios automated | 100% detection of required M1–M9 attacks, ≤ 1% shadow-block rate on benign controls |
| Limited ENFORCE | Rollback/break-glass ready | 100% block success on P0 high-risk relationships, 0 bypasses, p95 policy latency target met |
| Full ENFORCE | Stable for 2 production cycles | False-positive SLO, incident reconciliation, and control health SLO met |

These figures are initial baselines. Once a real traffic baseline is established, replace them with per-service SLOs, but never lower the 100% block-success rate for high-risk attack fixtures or the downstream-receipt-0 condition.

## 8. Failure Determination and Defect Handling

A test fails if any of the following hold.

- A `BLOCK` was expected, but a downstream receipt, child process, file write, or socket exists.
- The attack was blocked, but evidence for one of policy, enforcement, or outcome is missing.
- Events or Actors from different tenants are merged into the same interaction.
- A raw canary credential is stored in the Ledger.
- A benign control is blocked without a reason code.
- A SHADOW verdict unintentionally blocks a real request.
- An undeclared side effect or destination executes without a violation record.

Attach the threat ID, test ID, gateway/policy/fixture version, minimal reproduction input, and trace and evidence references to each defect. Do not attach real secrets or full customer payloads.

## 9. CI and Periodic Execution

- Pull request: benign and attack unit fixtures for the changed component
- Policy bundle change: full M1–M9 shadow replay
- Gateway release candidate: all scenarios plus Chain A/B
- Monthly: rerun compatibility for the latest Server/Client combinations, URL parser, and dependency scanner
- Post-incident: add the bypass technique used as a new regression fixture

Test results are loaded into the Ledger as `TEST_EXECUTED` events, with `data_source=SIMULATION` enforced to keep them separate from production attack statistics.

## 10. Core Platform Regression Tests

Independent of L1 threats, tenant isolation and immutability of the event ledger ([01 §9.2](01-project-plan.md#92-tenant-isolation-and-immutability-rls--append-only)) are validated at the platform layer. Because these tests are not tied to a specific L1 threat, they use `CORE-SIM-*` IDs.

**These are specifications, not a coverage report.** The `CORE-SIM-*` IDs appear in no test, SQL file, or fixture — `grep -rn "CORE-SIM"` outside `docs/` returns nothing — so there is no traceability link from an ID to an executing test. The "Status" column below records what is actually exercised today, established by reading `tests/test_postgres_ledger.py`, `migrations/postgresql/0001_interaction_ledger.sql`, and `ci/postgres_provision.sql`.

| ID | Input/Procedure | Expected Result | Status |
|---|---|---|---|
| `CORE-SIM-TENANT-001` | Run `SET app.tenant_id='B'` in a tenant A role session, then attempt to SELECT/INSERT tenant B events | The policy derives tenant from the authenticated connection's `session_user`, so `SET` has no effect — SELECT returns 0 rows, INSERT is denied | **Partial.** `test_live_guc_set_role_and_mutation_cannot_cross_the_boundary` performs the `SET` and the SELECT, and genuinely proves `SET ROLE tenant_b_app` is denied. But the SELECT assertion is weak: no tenant-B row exists in `security_events` at that point in the run, so it would pass with RLS disabled. The cross-tenant INSERT denial it asserts targets `event_ingest_keys`, not `security_events`. |
| `CORE-SIM-TENANT-002` | Attempt UPDATE/DELETE on `security_events` with an application role | **permission denied** at the RBAC layer (before reaching the trigger) | **Mostly covered.** The same live test executes an UPDATE as `tenant_a_app` and asserts `InsufficientPrivilege` (SQLSTATE 42501). **DELETE is never attempted**, and "0 rows changed" is not asserted. |
| `CORE-SIM-TENANT-003` | Attempt UPDATE on `security_events` with a separate test role that has UPDATE privilege | append-only **trigger exception** (`security_events is append-only`) | **Not covered.** No such role exists — the only grant on `security_events` anywhere is `GRANT SELECT, INSERT … TO interlock_event_api` (`0001_interaction_ledger.sql:181`). **The append-only trigger has never fired in any test run.** The only evidence is `assertIn("security_events_no_mutation", sql)` against the migration file's *text*. |
| `CORE-SIM-TENANT-004` | Check whether BYPASSRLS/superuser attributes have been granted to application/migration roles | 0 grants (an immediate fail if any are granted) | **Not covered.** No test reads `pg_roles.rolbypassrls` or `rolsuper`; nothing queries `pg_policies` or `relrowsecurity`. The only evidence is `assertIn("NOBYPASSRLS", sql)` — again a substring match on migration text, which cannot detect a later `ALTER ROLE … BYPASSRLS` or a live database that disagrees with the file. |

The pass condition is that another tenant's data is never read or modified under any circumstances, the permission denial (002) and append-only violation (003) each occur at their respective layer, and application-path roles carry no RLS-bypass attribute. The trusted tenant must be derived from the authenticated connection's `session_user` (or a connection-layer context the application cannot change) and must not be alterable via session `SET`/`SET ROLE`.

**As written, 003's pass condition is unmet.** It requires the append-only violation to be *demonstrated*; a substring match on the migration source cannot demonstrate it. Note also that the trigger raises SQLSTATE `55000` (`ObjectNotInPrerequisiteState`), while the live UPDATE test asserts `InsufficientPrivilege` (`42501`) — so that test passing is itself evidence the statement is stopped by RBAC and never reaches the trigger.

Closing the gap needs three things, none of which is a documentation change: a provisioned role holding `UPDATE ON security_events` so the trigger can be reached at all, a test asserting SQLSTATE `55000` from it, and a catalog assertion over `pg_roles` for 004. Live PostgreSQL tests are gated on `INTERLOCK_TEST_POSTGRES_DSN_TENANT_A`/`_B` and skip entirely under a plain `python3 -m unittest discover`; under that path only the migration-text assertions run.
