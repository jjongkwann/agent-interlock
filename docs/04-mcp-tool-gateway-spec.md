---
title: Agent Interlock MCP Tool Gateway Technical Specification
tags: [agent-interlock, mcp, gateway, policy, event-contract]
date: 2026-07-17
version: 1.2
status: proposed
---

# Agent Interlock MCP Tool Gateway Technical Specification

> 한국어 원문: [04-mcp-tool-gateway-spec.ko.md](04-mcp-tool-gateway-spec.ko.md)

> Audience: Implementers of Runtime, Policy Engine, SDK, Connector, Ledger<br>
> Scope: `tools/list`, `tools/list_changed`, `tools/call`, Tool result, OAuth/credential, Connector execution boundary

## 1. Responsibilities and Non-Responsibilities

The MCP Tool Gateway is the policy enforcement point between the MCP Host/Client and the Server. It is responsible for the following:

- Assigning stable Actor identity to Servers and Tools
- Managing Tool definition canonicalization, digest, approval state, and drift
- Rendering verdicts on call arguments' schema, data, destination, and side effects
- Per-hop credential binding and blocking token passthrough
- Restricting the Connector's URL, process, filesystem, and network
- Inspecting returned data's schema, taint, and secrets
- Generating Ledger events that separate verdict, enforcement, and outcome

The Gateway does not replace LLM malware detectors, general-purpose endpoint security, or package scanners entirely. Invisible behavior inside the Remote Server is compensated for with downstream audit and egress reconciliation.

## 2. Logical Components

| Component | Input | Output | Key Threats |
|---|---|---|---|
| Server Registry | endpoint, publisher, transport, artifact | server actor, trust state | M2, M4, M7 |
| Definition Registry | `tools/list` D1 | canonical definition, digest, state | M1–M3 |
| Tool Discovery Guard | raw D1 | model-visible sanitized D1 | M1, M3 |
| Tool Call Guard | D2, D3, Actor/LinkPolicy | decision, sanitized args | M1, M3, M8, M9 |
| Identity Guard | D5 claims, link context | bound/downscoped credential | M5 |
| Connector Sandbox | URL, command, request | constrained execution evidence | M4, M6 |
| Result Guard | D4 | sanitized/tainted result | M1, M6, M8 |
| Egress/Transaction Guard | destination, D7, side effect | allow/hold/block, receipt | M9 |
| Ledger Adapter | all stages | normalized events | M1–M9 |

## 3. Stable Identifiers

```text
server_id = tenant/environment/registry-key
tool_id   = server_id + ":" + tool_name
definition_revision_id = tool_id + "@" + canonical_digest
```

Actors are not identified solely by display name, title, or endpoint. Even if a Server offers a Tool with the same name, it is a different Actor if the namespace differs.

## 4. Tool Definition Canonicalization and State

### 4.1 Canonical definition

The digest includes at minimum the following fields:

```yaml
serverId: tenant-a/prod/trusted-mail
toolName: send_email
title: Send email
description: Send a message to approved recipients.
inputSchema: { canonical-json-schema: true }
outputSchema: { canonical-json-schema: true }
annotations: {}
endpoint: https://mcp.example.com
transport: streamable-http
publisher: platform-team
artifactDigest: sha256:...
```

- Sort JSON object keys and normalize numbers, Unicode, and line endings.
- Also separately retain a raw digest that does not strip security-relevant whitespace or invisible characters from the description.
- For values that might contain secrets, store an encrypted evidence reference or hash instead of the raw value.
- Include the canonicalizer version in the digest input so version changes can be audited.

### 4.2 State Machine

```mermaid
stateDiagram-v2
    [*] --> DISCOVERED
    DISCOVERED --> QUARANTINED: policy evaluation
    QUARANTINED --> APPROVED: review/signature accepted
    APPROVED --> ACTIVE: policy deployed
    ACTIVE --> DRIFTED: effective digest changed
    DRIFTED --> QUARANTINED: automatic isolation
    QUARANTINED --> REJECTED: review denied
    QUARANTINED --> APPROVED: new revision approved
    ACTIVE --> REVOKED: incident or publisher revocation
```

Only an `ACTIVE` revision can be called. `tools/list_changed` is not an automatic-approval signal; it is a signal that a new `DISCOVERED` revision has been created.

## 5. ActorSpec Extension

MCP-specific fields are added to the base ActorSpec.

```yaml
apiVersion: interlock.dev/v1alpha1
kind: Actor
metadata:
  id: tool.trusted-mail.send-email
  owner: customer-platform
  tenant: tenant-a
spec:
  type: TOOL
  identity: spiffe://prod.example/mcp/trusted-mail/send-email
  capabilities: [EMAIL_SEND]
  dataAccess: [D2, D3, D7]
  sideEffects: [EXTERNAL_WRITE]
  tenantMode: REQUIRED
  failureMode: FAIL_CLOSED
  mcp:
    serverId: tenant-a/prod/trusted-mail
    toolName: send_email
    transport: streamable-http
    endpoint: https://mcp.example.com
    publisher: platform-team
    artifactDigest: sha256:...
    definitionDigest: sha256:...
    credentialMode: TOKEN_EXCHANGE
    sandboxProfile: remote-mcp-restricted
  destinations:
    allowedDomains: [customer.example]
  schemas:
    input: schemas/send-email-input.json
    output: schemas/send-email-output.json
```

`definitionDigest` points to the approved revision. The digest actually observed from `tools/list` is managed by the Registry, and the two are compared before execution.

`dataAccess` uses the `D1`–`D9` codes from [03 §4](03-l1-mcp-tool-security-profile.md), the same vocabulary as the LinkPolicy `data.allowedClasses` below. It must be a **superset** of every link policy that targets this Actor, or `ARCH-DATA-CLASS-EXCEEDS-ACTOR` refuses the compile. Note it is a design-time declaration only: no runtime check reads `ActorSpec.data_access`.

## 6. LinkPolicy Extension

```yaml
apiVersion: interlock.dev/v1alpha1
kind: LinkPolicy
metadata:
  id: mcp-tool-invoke-default
  version: 1.0.0
spec:
  sourceTypes: [AGENT, SUBAGENT]
  targetTypes: [TOOL]
  relationship: INVOKES
  mode: SHADOW
  toolDefinition:
    requireState: ACTIVE
    requireDigestPin: true
    allowCrossServerReferences: false
  data:
    allowedClasses: [D2, D3, D7]
    deniedClasses: [D5, D8]
    propagateTaint: true
    secretAction: BLOCK
  destination:
    requireExplicit: true
    newDestinationAction: HOLD
  authorization:
    tokenPassthrough: false
    requireAudience: true
    requireResource: true
    requireActorBinding: true
    maxDelegationDepth: 1
  sideEffects:
    externalWrite: REQUIRE_APPROVAL
    destructiveWrite: BLOCK
    undeclared: BLOCK        # Block if the observed side effect is not in the ActorSpec's declared set
  failureMode: FAIL_CLOSED
```

Even if the Tool description asserts it is safe, the policy independently evaluates D3 and the actual destination. `mode` is one of `OBSERVE`, `SHADOW`, or `ENFORCE`, and events record both the evaluation mode and whether enforcement actually occurred.

> **Which of these the loader actually reads.** There is no `kind: LinkPolicy` manifest loader in `src/`. The only path from a document to a `LinkPolicy` is an Architecture manifest's `edge.policy` block, parsed by `_parse_edge` (`architecture.py:1236-1261`), and it reads a fixed key list: `id`, `version`, `mode`, `relationship`, `allowedPurposes`, `allowedDataClasses`, `deniedDataClasses`, `requireActiveDefinition`, `requireDigestPin`, `requireExplicitDestination`, `newDestinationAction`, `tokenPassthrough`, `requireAudience`, `requireResource`, `requireActorBinding`, `maxDelegationDepth`, `externalWriteRequiresApproval`, `failureMode`, `decisionTtlSeconds`.
>
> Everything else in the YAML above is **silently ignored** — `data.secretAction`, `data.propagateTaint`, `toolDefinition.allowCrossServerReferences`, and the whole `sideEffects` block. Those controls exist and run, but only at their Python defaults (`secret_action=BLOCK`, `destructive_write_action=BLOCK`, `undeclared_side_effect_action=BLOCK`), and the volume caps `max_export_records`/`max_export_bytes` default to `0`, which leaves two checks **disarmed** on any policy built from a manifest: `L1-M9-VOLUME-EXCEEDED` (records) and `L1-M9-VOLUME-BYTES-EXCEEDED` (bytes). Writing `secretAction: ALLOW` here does not disable the secret control, and writing `undeclared: BLOCK` does not enable anything that was not already on. Set these by constructing `LinkPolicy` in Python until the parser and `schemas/architecture.schema.json` carry them.

## 7. Processing Pipeline

### 7.1 `tools/list`

```text
Authenticate Server → limit raw response size/schema → assign per-Tool namespace
→ compute raw/canonical digest → compare against existing approved revision
→ check for metadata injection, cross-server reference, capability exaggeration
→ determine state → generate model-visible D1 → record to Registry/Ledger
```

Only the rule-violating Tool can be quarantined individually, but if the integrity of the entire response is suspect or the Server identity is unclear, the entire Server is quarantined.

### 7.2 `tools/call`

```text
Receive D2 purpose/provenance → resolve source/target Actor
→ verify ACTIVE/approved digest → validate D3 schema
→ classify taint/secret/data class → canonicalize destination
→ verify token binding/scope → render side effect/approval verdict
→ record CONTROL_EVALUATED to the Ledger
→ on ALLOW, execute Connector → record ACTION_EXECUTED
```

The `arguments_hash` is bound to the Connector so that D3 cannot change between the verdict and the actual transmission. Approval is likewise bound to the same hash and destination set, and the approval is invalidated if the arguments change.

### 7.3 Tool result

```text
Limit response size/content type → validate output schema
→ check URL/resource safety → detect secret/PII/instruction-like content
→ attach provenance/taint → return only the allowed fields to the Host
→ record INTERACTION_COMPLETED and DATA_FLOW_OBSERVED
```

When the Tool result is placed into the next model turn, the `UNTRUSTED_TOOL_RESULT` taint is retained. Instructions inside the result are never promoted to policy or system commands.

### 7.4 OAuth and Authorization URL

- The authorization endpoint must match the registered metadata.
- Schemes other than `https` are denied by default. loopback is allowed only in an explicitly designated local development profile.
- scheme, host, port, and resolved IP are re-validated at every redirect in the chain.
- URLs are never assembled via shell commands; an argument array or an OS-safe API is used instead.
- Tokens are exchanged per hop and are never passed through as-is to a downstream with a different audience/resource.

### 7.5 Declaration–Observation Reconciliation (declaration reconciliation)

The Gateway does not unconditionally trust the ActorSpec declared by the developer. It checks whether the observed behavior is a subset of the declared set, but **it must distinguish the point of enforcement.** Only predictable excesses can be pre-blocked before execution; excesses that only surface after execution are subject to detection, revocation, and compensation. Lumping these together as "observed it, so we blocked it" hides incidents where an external write that had already gone out could not be stopped.

| Point | Basis | Handling on Excess |
|---|---|---|
| Pre-execution (`estimatedSideEffect`, based on D3) | `tools/call` evaluation stage (§7.2) | `BLOCK` — receipt is 0 since dispatch never happens |
| Post-execution (`observed`/`completed`, downstream receipt) | Result/reconciliation stage (§8.1) | `DETECTION_RAISED` → `REVOKE`/`KILL`/compensation — the external write may have already occurred |

```text
estimated sideEffect  ⊄ ActorSpec.sideEffects  (pre-execution)  → L1-UNDECLARED-SIDE-EFFECT / BLOCK
estimated destination ⊄ ActorSpec.destinations (pre-execution)  → L1-M9-NEW-DESTINATION / HOLD
observed  sideEffect  ⊄ ActorSpec.sideEffects  (post-execution) → L1-UNDECLARED-SIDE-EFFECT / REVOKE + compensation
```

- A pre-execution estimated excess is blocked at the evaluation stage (§7.2) even if it passed the `tools/list` definition check (§7.1). Since `ExecuteApprovedCall` (§10) does not dispatch without a valid decision, the receipt is 0.
- Invisible egress inside the Remote Server cannot be seen before execution (§1), so **pre-execution blocking cannot be guaranteed.** It is detected after the fact through downstream receipt reconciliation (§8.1) and handled via token revocation and compensating transactions.
- Without this reconciliation, under-declaration becomes a control-bypass path. The basis for trust is recording, separately, "what is blocked in advance and what is revoked after the fact."

## 8. Event Contract

The common Envelope follows [01 Project Plan](01-project-plan.md#61-common-event-envelope). The minimum MCP payload fields are as follows:

```yaml
payload:
  mcp:
    protocolVersion: "2025-11-25"
    serverId: tenant-a/prod/trusted-mail
    transport: streamable-http
    method: tools/call
  toolDefinition:
    toolId: tenant-a/prod/trusted-mail:send_email
    revisionId: "...@sha256:..."
    observedDigest: sha256:...
    approvedDigest: sha256:...
    state: ACTIVE
  invocation:
    callId: call-...
    purpose: customer-case-reply
    argumentsHash: sha256:...
    destinationIds: [email:customer@example.com]
    dataClasses: [D3, D7]
    sensitivity: CONFIDENTIAL
    estimatedSideEffect: EXTERNAL_WRITE
  authorization:
    credentialFingerprint: sha256:...
    issuer: https://idp.example
    subject: user-123
    actor: agent.support
    audience: https://mail-api.example
    resource: mail
    scopes: [mail.send]
    delegationParentId: null
  control:
    policyId: mcp-tool-invoke-default
    policyVersion: 1.0.0
    mode: ENFORCE
    decision: HOLD
    reasonCodes: [L1-M9-NEW-DESTINATION]
  action:
    result: COMPLETED
    connectorExecutionId: null
  outcome:
    securityOutcome: BLOCKED
    downstreamTransactionId: null
```

### 8.1 Event Sequence

| Stage | Event | Completion Condition |
|---|---|---|
| Request received | `INTERACTION_REQUESTED` | toolId, revision, D3 hash present |
| Data boundary crossed | `DATA_FLOW_OBSERVED` | source, destination, data class, taint present |
| Policy evaluated | `CONTROL_EVALUATED` | policy version, decision, reason code present |
| Actual enforcement | `ACTION_EXECUTED` | action result and connector ID present |
| Call completed | `INTERACTION_COMPLETED` | protocol status, latency, result hash present |
| Security outcome | `SECURITY_OUTCOME_SET` | Attack success/block/partial-execution status finalized |

Events are grouped by the same `interaction_id`, and internal Server transactions are reconciled via `downstream_transaction_id`.

## 9. Reason Codes

### 9.1 Emitted by the gateway's policy engine

These are the complete set `GATEWAY_PROFILE` can put on the wire — 21 checks producing 20 codes (`policy.py`); the check count grew, the wire code count did not. "Default verdict" is what the check returns under a default `LinkPolicy`; where an operator-configurable `LinkPolicy` action field governs it, that field is named in its Python spelling, because most of them cannot be set from a manifest at all (see §6).

| Code | Condition | Default Verdict |
|---|---|---|
| `INTERLOCK-ACTOR-TYPE-DENIED` | Source or target Actor type is outside `sourceTypes`/`targetTypes` | `BLOCK` |
| `INTERLOCK-PURPOSE-DENIED` | Purpose is outside `allowedPurposes` (armed only when that set is non-empty) | `BLOCK` |
| `L1-M2-DEFINITION-NOT-ACTIVE` | Revision is not `ACTIVE`; forwards `revision.reason_codes` when it carries any | `QUARANTINE` |
| `L1-M2-DEFINITION-DRIFT` | Mismatch between observed and approved digest | `QUARANTINE` |
| `INTERLOCK-INPUT-SCHEMA-INVALID` | Arguments fail the revision's input schema, falling back to `ActorSpec.input_schema` | `BLOCK` |
| `INTERLOCK-DATA-CLASS-DENIED` | Intent carries a denied class, or one outside `allowedDataClasses` | `BLOCK` |
| `L1-M9-SENSITIVE-EGRESS` | Same check as above, emitted instead when the *denied* class is `D7` | `BLOCK` |
| `L1-M8-CREDENTIAL-DETECTED` | D5 fingerprint detected in the arguments | `secret_action` (`BLOCK`) |
| `L1-M9-NEW-DESTINATION` | Destination unparseable, outside the target's `allowedDomains`, or absent when required | `new_destination_action` (`HOLD`) |
| `INTERLOCK-INTENT-ARGUMENT-MISMATCH` | The declared intent does not cover what the arguments say: a destination named by a property the input schema marks (`format: email`/`uri`/`hostname`, or `x-interlock-destination`) is outside `intent.destinations`, or the side effect the tool's MCP annotations assert outranks `estimatedSideEffect` | `BLOCK`, unconditional |
| `L1-M9-VOLUME-EXCEEDED` | Estimated records exceed the cap (armed solely by `max_export_records`) | `volume_action` (`BLOCK`) |
| `L1-M9-VOLUME-BYTES-EXCEEDED` | Estimated bytes exceed the cap (armed solely by `max_export_bytes`); renamed onto the `L1-M9-VOLUME-EXCEEDED` wire code | `volume_action` (`BLOCK`) |
| `L1-UNDECLARED-SIDE-EFFECT` | Side effect exceeds the ActorSpec's declared `sideEffects` | `undeclared_side_effect_action` (`BLOCK`) |
| `INTERLOCK-DESTRUCTIVE-WRITE` | Intent is a `DESTRUCTIVE_WRITE` | `destructive_write_action` (`BLOCK`) |
| `INTERLOCK-TAINTED-EXTERNAL-WRITE` | Taint labels present on an `EXTERNAL_WRITE` | `BLOCK`, unconditional |
| `INTERLOCK-APPROVAL-REQUIRED` | `EXTERNAL_WRITE` with no valid approval (armed by `externalWriteRequiresApproval`) | `HOLD` |
| `L1-M5-CREDENTIAL-MISSING` | Intent expects an audience or resource and no **authenticated** credential is present | `BLOCK` |
| `L1-M5-TOKEN-PASSTHROUGH` | Downstream forwarding without exchange (armed when `tokenPassthrough` is false) | `BLOCK` |
| `L1-M5-TOKEN-AUDIENCE-MISMATCH` | Token audience mismatch (armed solely by `requireAudience`) | `BLOCK` |
| `L1-M5-TOKEN-RESOURCE-MISMATCH` | Token resource mismatch (armed solely by `requireResource`); renamed onto the `L1-M5-TOKEN-AUDIENCE-MISMATCH` wire code | `BLOCK` |
| `L1-M5-TOKEN-ACTOR-MISMATCH` | Acting subject not bound to the source Actor (armed by `requireActorBinding`) | `BLOCK` |
| `L1-M5-DELEGATION-DEPTH` | Delegation depth exceeds `maxDelegationDepth` | `BLOCK` |

Three things this table encodes that are easy to get wrong:

- **`INTERLOCK-DATA-CLASS-DENIED` and `L1-M9-SENSITIVE-EGRESS` are one check**, `_data_classes`, choosing between two reason keys. It selects `L1-M9-SENSITIVE-EGRESS` **iff `D7` is in `deniedDataClasses`** — it never reads `estimated_side_effect`, so "sensitive data moving via an external write" is not its condition. Under the default `LinkPolicy`, `D7` is in *allowed* and not in denied, which means **`L1-M9-SENSITIVE-EGRESS` is unreachable out of the box.** A deployment that wants D7 egress caught must put `D7` in `deniedDataClasses` explicitly.
- **`L1-M5-TOKEN-AUDIENCE-MISMATCH`/`L1-M5-TOKEN-RESOURCE-MISMATCH` and `L1-M9-VOLUME-EXCEEDED`/`L1-M9-VOLUME-BYTES-EXCEEDED` are now two independently-armed check ids apiece**, split precisely because arming one flag armed both controls and the off one reported RAN_CLEAN. The wire is unchanged: each new check id renames onto the historical code (`L1-M5-TOKEN-AUDIENCE-MISMATCH`, `L1-M9-VOLUME-EXCEEDED`).
- **`L1-M2-DEFINITION-NOT-ACTIVE` forwards arbitrary registry strings** from `revision.reason_codes`, so the emitted key set for that row is not closed.

### 9.2 Emitted elsewhere in the MCP path

These are part of the gateway's overall enforcement story but are produced by other components, not by any `Check` in the shared table.

**Three of them still reach `payload.control.reasonCodes`, by forwarding.** `registry.py` writes `L1-M1-METADATA-INSTRUCTION`, `L1-M1-SCHEMA-KEYWORD-UNSUPPORTED`, and `L1-M3-CROSS-SERVER-REFERENCE` into `ToolRevision.reason_codes`, and `_definition_state` forwards that tuple verbatim whenever the revision is not `ACTIVE` — so a quarantined revision yields `reasonCodes: ["L1-M1-METADATA-INSTRUCTION"]` under check id `L1-M2-DEFINITION-NOT-ACTIVE`. The remaining codes in this table are emitted on their own paths and never appear in a `CONTROL_EVALUATED` control block.

The forwarding has a consequence for statistics: the emitted key can differ from the check id that produced it, and the key set is **unbounded** — it is whatever the registry wrote. A profile's `reason_codes` map renames such a string blindly if it happens to collide with a rename key. Join coverage to reason codes through `Profile.reason_codes`, never by matching the string against this table.

| Code | Producer | Condition | Default Verdict |
|---|---|---|---|
| `L1-M1-METADATA-INSTRUCTION` | `registry.py` | D1 requests commands or data access unrelated to its function | `QUARANTINE` |
| `L1-M1-SCHEMA-KEYWORD-UNSUPPORTED` | `registry.py` | D1's input or output schema uses a JSON Schema keyword outside the subset `validate_schema` enforces | `QUARANTINE` |
| `L1-M3-CROSS-SERVER-REFERENCE` | `registry.py` | D1 manipulates a Tool in another namespace | `BLOCK` |
| `L1-M4-UNTRUSTED-PUBLISHER` | `supply_chain.py` | provenance/signature policy failure | `QUARANTINE` |
| `L1-M4-SIGNATURE-INVALID` | `supply_chain.py` | Missing or mismatched provenance signature from a trusted publisher | `QUARANTINE` |
| `L1-M4-PROVENANCE-DENIED` | `supply_chain.py` | repository/revision/build provenance policy failure | `QUARANTINE` |
| `L1-M4-EGRESS-DENIED` | `egress.py` | Runtime destination is outside the exact egress allowlist | `BLOCK`+workload termination |
| `L1-M4-EGRESS-BINDING-MISMATCH` | `egress.py` | Mismatch among tenant/workload/artifact/provenance/sandbox profile | `BLOCK`+workload termination |
| `L1-M4-PROCESS-TERMINATION-FAILED` | `egress.py` | Failure to confirm workload termination after egress block | `BLOCK`+Incident |
| `L1-M6-UNSAFE-AUTH-URL` | `security.py` | scheme/host/redirect/IP policy failure | `BLOCK` |
| `L1-M7-CONFIG-DRIFT` | `config_guard.py` | Mismatch between runtime and approved config digest | `BLOCK` |
| `MCP-OAUTH-CHALLENGE-SCOPE-MISMATCH` | `mcp_oauth.py` | Challenge requests a scope broader than the one held | rejected at challenge time |

### 9.3 Namespaces and stability

`L1-Mn-*` codes are tied to a specific threat, while cross-cutting codes spanning multiple threats, like `L1-UNDECLARED-*`, use the `L1-*` format. `INTERLOCK-*` codes are enforcement-engine findings not mapped to a single L1 threat. Reason codes are stable analytic keys. Human-readable descriptions are localized in a separate field, and the meaning of a code is never reused or changed.

**Reason codes are per-enforcement-point and are not comparable across points.** The A2A broker emits the same controls under `A2A-*` names — `L1-M5-TOKEN-AUDIENCE-MISMATCH` there is `A2A-AUDIENCE-MISMATCH`, and both `INTERLOCK-DATA-CLASS-DENIED` and `L1-M9-SENSITIVE-EGRESS` collapse to `A2A-DATA-CLASS-DENIED`. The SDK emits the gateway's names except that it folds `L1-M9-SENSITIVE-EGRESS` into `INTERLOCK-DATA-CLASS-DENIED` and never emits the two M2 codes. Aggregate on the canonical check id for cross-point comparison, and join to reason codes only through `Profile.reason_codes`.

## 10. Internal API Boundary

```text
RegisterServer(serverSpec) -> serverId, trustState
ObserveDefinitions(serverId, rawToolsList) -> revisions[], decisions[]
EvaluateInvocation(actor, toolRevision, intent, arguments, credentialRef) -> decision
ExecuteApprovedCall(decisionId, argumentsHash) -> connectorExecutionId
InspectResult(connectorExecutionId, rawResult) -> sanitizedResult, labels[]
ReconcileTransaction(connectorExecutionId, downstreamReceipt) -> securityOutcome
```

- `ExecuteApprovedCall` does not execute unless there is a non-expired decision with the same `argumentsHash`.
- Callers do not send the raw credential to the Policy Engine; they use an opaque reference from the Identity Guard.
- All mutation APIs require an idempotency key and tenant.

## 11. Failure and Bypass Prevention

| Failure | Default Behavior | Required Event |
|---|---|---|
| Policy Engine timeout | `FAIL_CLOSED` for high-risk/external writes | `CONTROL_HEALTH_CHANGED`, `CONTROL_EVALUATED(ERROR)` |
| Ledger delay/outage | Allow reads only in limited form; `DEGRADE_READ_ONLY` for external writes | local spool status |
| Definition Registry unavailable | Block new/changed Tools; allow only cached ACTIVE within TTL | cache revision/age |
| Identity Provider unavailable | Prohibit expanded token reuse; block writes | issuer health |
| Connector sandbox failure | Execution prohibited | sandbox start error |
| Result inspection failure | Quarantine the result instead of injecting it into the model | result evidence ref |

Direct Server connections that bypass the Gateway are detected via network policy and SDK trace-gap rules. If an Agent log exists but there is no Gateway `INTERACTION_REQUESTED`, a bypass incident is generated.

## 12. Privacy and Evidence

- The raw D5, the full prompt, and the full D7 payload are not stored in the default Ledger.
- For cases that cannot be analyzed by hash alone, only a reference is recorded, with the actual data held in an encrypted evidence store under TTL and access approval.
- URL queries, headers, and error messages may also contain credentials, so they are stored after redaction.
- Destination email/account values separate operational-search tokenization from forensic encryption.
- The originals needed to reproduce the canonical digest are stored in access-controlled registry evidence.

## 13. Implementation Order

1. Definition Registry, canonical digest, and the `ACTIVE/DRIFTED` gate
2. `tools/call` schema, destination, and side-effect verdicts and events
3. Identity Guard and token exchange/binding
4. URL validator and Connector sandbox
5. Result Guard, taint, secret DLP
6. downstream receipt reconciliation and Graph correlation analysis

Each stage is promoted to `ENFORCE` after its corresponding test in the [05 L1 Security Validation Plan](05-l1-security-validation-plan.md) has been automated.
