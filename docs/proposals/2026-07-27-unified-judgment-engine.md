# Unified Judgment Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge the three divergent judgment engines into one declarative check table with a profile per enforcement point, without changing any reason code the system emits.

**Architecture:** A `Check` is declared once, holding a canonical id, a scope, an `armed(policy)` predicate and a `run(policy, context)` predicate. A `Profile` names which check ids an enforcement point runs and how it renames their reason keys on the way out. `policy.evaluate()` becomes a loop over the profile's checks. The SDK and the A2A broker stop carrying their own inlined logic and call the same loop with their own profile.

**Tech Stack:** Python 3.11+, stdlib only, `unittest` test classes run under `pytest` via `uv run pytest`.

**Spec:** `docs/specs/2026-07-27-control-coverage-statistics.md`

## Global Constraints

- Every reason code emitted today must still be emitted, byte for byte. `A2A-*` strings stay `A2A-*`; `INTERLOCK-*` and `L1-*` stay as they are. Ledger history, the `docs/05` L1-SIM ids, and existing assertions must not break.
- Canonical reason keys are the existing gateway strings. Profiles rename on emit; nothing renames in the table.
- `policy.py` must not import from `architecture.py`. `architecture.py:13` imports `sdk`, and this plan makes `sdk` import `policy`; a boundary import would close the cycle. Use a `typing.Protocol`.
- No new dependencies. `pyproject.toml` dev group is `pytest>=9.1.1`, `ruff>=0.15.22`.
- Line length 120 (`[tool.ruff]` in `pyproject.toml`). Run `uv run ruff check src tests` before each commit.
- Baseline that must never regress: **459 passed, 12 skipped, 15 subtests passed**.
- Branch: `control-coverage-statistics`, already created, spec already committed.
- This plan covers the engine only. Coverage telemetry and the statistics contract are Plan 2 and are not implemented here.

---

### Task 1: Characterization tests for `policy.evaluate`

Ten of the eighteen reason codes `policy.py` emits appear in no test file. They must be pinned before the table replaces the branches that produce them.

**Files:**
- Create: `tests/test_policy_characterization.py`

**Interfaces:**
- Consumes: `agent_interlock.policy.evaluate`, `agent_interlock.policy.EvaluationInput`
- Produces: `clean_case()` returning `(LinkPolicy, EvaluationInput)` with no findings — Tasks 3–7 reuse this as the RAN_CLEAN baseline.

- [ ] **Step 1: Write the failing test**

```python
"""Pins every reason code policy.evaluate can emit, before the check table replaces its branches."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime

from agent_interlock import (
    ActorSpec,
    ActorType,
    ControlDecision,
    CredentialClaims,
    DefinitionState,
    InvocationIntent,
    LinkPolicy,
    SideEffect,
    ToolDefinition,
    ToolRevision,
)
from agent_interlock.policy import EvaluationInput, evaluate

DIGEST = "sha256:characterization"


def clean_case() -> tuple[LinkPolicy, EvaluationInput]:
    """An evaluation that trips nothing. Every test below perturbs exactly one field."""
    definition = ToolDefinition(
        server_id="server-1",
        tool_name="lookup",
        title="Lookup",
        description="Reads a support record",
        input_schema={},
    )
    revision = ToolRevision(
        revision_id="rev-1",
        tool_id=definition.tool_id,
        definition=definition,
        canonical_digest=DIGEST,
        raw_digest=DIGEST,
        canonicalizer_version="1",
        state=DefinitionState.ACTIVE,
        reason_codes=(),
        observed_at=datetime(2026, 7, 27, tzinfo=UTC),
    )
    source = ActorSpec(id="agent-1", type=ActorType.AGENT, owner="team", identity="spiffe://agent-1")
    target = ActorSpec(
        id="tool-1",
        type=ActorType.TOOL,
        owner="team",
        identity="spiffe://tool-1",
        definition_digest=DIGEST,
    )
    credential = CredentialClaims(
        reference="ref-1",
        issuer="issuer",
        subject="subject",
        actor="agent-1",
        audience="",
        resource="",
        exchanged=True,
        delegation_depth=0,
    )
    context = EvaluationInput(
        source=source,
        target=target,
        revision=revision,
        intent=InvocationIntent(purpose="SUPPORT_LOOKUP"),
        arguments={},
        credential=credential,
        approval_valid=True,
        interaction_id="interaction-1",
        trace_id="trace-1",
        span_id="span-1",
    )
    return LinkPolicy(), context


class PolicyCharacterizationTests(unittest.TestCase):
    def test_clean_case_produces_no_findings(self):
        policy, context = clean_case()
        record = evaluate(policy, context)
        self.assertEqual(record.reason_codes, ())
        self.assertEqual(record.decision, ControlDecision.ALLOW)

    def test_every_reason_code_is_reachable(self):
        policy, context = clean_case()
        cases = [
            (
                "INTERLOCK-ACTOR-TYPE-DENIED",
                policy,
                replace(context, source=replace(context.source, type=ActorType.USER)),
            ),
            (
                "INTERLOCK-PURPOSE-DENIED",
                replace(policy, allowed_purposes=frozenset({"SUPPORT_LOOKUP"})),
                replace(context, intent=InvocationIntent(purpose="EXFILTRATE")),
            ),
            (
                "L1-M2-DEFINITION-NOT-ACTIVE",
                policy,
                replace(context, revision=replace(context.revision, state=DefinitionState.QUARANTINED)),
            ),
            (
                "L1-M2-DEFINITION-DRIFT",
                policy,
                replace(context, target=replace(context.target, definition_digest="sha256:other")),
            ),
            (
                "INTERLOCK-INPUT-SCHEMA-INVALID",
                policy,
                replace(
                    context,
                    revision=replace(
                        context.revision,
                        definition=replace(
                            context.revision.definition,
                            input_schema={"type": "object", "required": ["ticket"]},
                        ),
                    ),
                ),
            ),
            (
                "L1-M9-SENSITIVE-EGRESS",
                replace(policy, denied_data_classes=frozenset({"D7"})),
                replace(context, intent=InvocationIntent(purpose="SUPPORT_LOOKUP", data_classes=frozenset({"D7"}))),
            ),
            (
                "INTERLOCK-DATA-CLASS-DENIED",
                policy,
                replace(context, intent=InvocationIntent(purpose="SUPPORT_LOOKUP", data_classes=frozenset({"D5"}))),
            ),
            (
                "L1-M8-CREDENTIAL-DETECTED",
                policy,
                replace(context, arguments={"note": "AKIAIOSFODNN7EXAMPLE"}),
            ),
            (
                "L1-M5-CREDENTIAL-MISSING",
                policy,
                replace(
                    context,
                    credential=None,
                    intent=InvocationIntent(purpose="SUPPORT_LOOKUP", expected_audience="spiffe://tool-1"),
                ),
            ),
            (
                "L1-M5-TOKEN-PASSTHROUGH",
                policy,
                replace(context, credential=replace(context.credential, exchanged=False)),
            ),
            (
                "L1-M5-TOKEN-ACTOR-MISMATCH",
                policy,
                replace(context, credential=replace(context.credential, actor="agent-9")),
            ),
            (
                "L1-M5-TOKEN-AUDIENCE-MISMATCH",
                policy,
                replace(
                    context,
                    intent=InvocationIntent(purpose="SUPPORT_LOOKUP", expected_audience="spiffe://tool-1"),
                    credential=replace(context.credential, audience="spiffe://other"),
                ),
            ),
            (
                "L1-M5-DELEGATION-DEPTH",
                policy,
                replace(context, credential=replace(context.credential, delegation_depth=5)),
            ),
            (
                "L1-M9-NEW-DESTINATION",
                policy,
                replace(
                    context,
                    intent=InvocationIntent(purpose="SUPPORT_LOOKUP", destinations=("https://evil.example",)),
                ),
            ),
            (
                "L1-M9-VOLUME-EXCEEDED",
                replace(policy, max_export_records=10),
                replace(
                    context,
                    intent=InvocationIntent(purpose="SUPPORT_LOOKUP", estimated_record_count=99),
                ),
            ),
            (
                "L1-UNDECLARED-SIDE-EFFECT",
                policy,
                replace(
                    context,
                    intent=InvocationIntent(
                        purpose="SUPPORT_LOOKUP",
                        estimated_side_effect=SideEffect.INTERNAL_WRITE,
                    ),
                ),
            ),
            (
                "INTERLOCK-DESTRUCTIVE-WRITE",
                policy,
                replace(
                    context,
                    intent=InvocationIntent(
                        purpose="SUPPORT_LOOKUP",
                        estimated_side_effect=SideEffect.DESTRUCTIVE_WRITE,
                    ),
                ),
            ),
            (
                "INTERLOCK-APPROVAL-REQUIRED",
                policy,
                replace(
                    context,
                    approval_valid=False,
                    intent=InvocationIntent(
                        purpose="SUPPORT_LOOKUP",
                        estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                    ),
                ),
            ),
        ]
        for code, case_policy, case_context in cases:
            with self.subTest(code=code):
                record = evaluate(case_policy, case_context)
                self.assertIn(code, record.reason_codes)


if __name__ == "__main__":
    unittest.main()
```

Note: each case asserts *membership*, not exclusivity. Several perturbations trip more than one check — `DESTRUCTIVE_WRITE` also trips `L1-UNDECLARED-SIDE-EFFECT`, `EXTERNAL_WRITE` also trips `L1-M9-NEW-DESTINATION`. Membership is what characterizes the behaviour; exclusivity would over-specify it.

- [ ] **Step 2: Run the test to see which cases do not yet hold**

Run: `uv run pytest tests/test_policy_characterization.py -v`

Expected: `test_clean_case_produces_no_findings` PASSES. `test_every_reason_code_is_reachable` may report subtest failures — each one means the perturbation does not actually reach that branch. Fix the *perturbation*, never `policy.py`. This task changes no production code.

- [ ] **Step 3: Confirm the full suite is unchanged**

Run: `uv run pytest -q`
Expected: `459 passed, 12 skipped` plus the new subtests.

- [ ] **Step 4: Lint**

Run: `uv run ruff check tests/test_policy_characterization.py`
Expected: no findings.

- [ ] **Step 5: Commit**

```bash
git add tests/test_policy_characterization.py
git commit -m "test: pin every reason code policy.evaluate emits

Ten of the eighteen appeared in no test file, including four of the six M5
credential checks. Pins them before the check table replaces the branches."
```

---

### Task 2: Characterization tests for the A2A broker's findings

Fifteen of the seventeen A2A policy findings appear in no test file. Same reasoning as Task 1, different engine.

**Files:**
- Create: `tests/test_a2a_characterization.py`

**Interfaces:**
- Consumes: `broker_fixture`, `send_context`, `request_message`, `boundary_manifest` from `tests/test_a2a.py:133,192,185` — import them rather than duplicating the setup.
- Produces: nothing later tasks depend on; this is a guard.

- [ ] **Step 1: Write the failing test**

```python
"""Pins every A2A link and boundary finding before they move into the shared check table.

Operational A2AError codes (A2A-TASK-NOT-FOUND, A2A-IDEMPOTENCY-CONFLICT and
similar) are deliberately not covered: they are not policy findings and are not
moving.
"""

from __future__ import annotations

import unittest
from dataclasses import replace

from agent_interlock import A2APolicyError, A2APrincipal, A2ASendContext
from test_a2a import boundary_manifest, broker_fixture, request_message, send_context


def rejected_codes(manifest=None, *, principal_changes=None, context_changes=None) -> tuple[str, ...]:
    """Send one message through a perturbed broker and return the reason codes it was rejected with."""
    broker, _, _, principal = broker_fixture(manifest)
    if principal_changes:
        principal = replace(principal, **principal_changes)
    context = send_context(principal)
    if context_changes:
        context = A2ASendContext(
            principal=principal,
            source_actor_id=context.source_actor_id,
            target_actor_id=context.target_actor_id,
            purpose=context_changes.get("purpose", context.purpose),
            data_classes=context_changes.get("data_classes", context.data_classes),
            idempotency_key=context.idempotency_key,
        )
    try:
        broker.send_message(request_message(), context)
    except A2APolicyError as error:
        return error.reason_codes
    return ()


class A2ACharacterizationTests(unittest.TestCase):
    def test_clean_send_is_not_rejected(self):
        self.assertEqual(rejected_codes(), ())

    def test_link_findings_are_reachable(self):
        cases = [
            ("A2A-IDENTITY-BINDING-MISMATCH", {"principal_changes": {"authenticated": False}}),
            ("A2A-ACTOR-BINDING-MISMATCH", {"principal_changes": {"actor_id": "agent.support"}}),
            ("A2A-AUDIENCE-MISMATCH", {"principal_changes": {"audience": "spiffe://wrong"}}),
            ("A2A-RESOURCE-MISMATCH", {"principal_changes": {"resource": "a2a://wrong"}}),
            ("A2A-TOKEN-PASSTHROUGH", {"principal_changes": {"exchanged": False}}),
            ("A2A-DELEGATION-DEPTH", {"principal_changes": {"delegation_depth": 9}}),
            ("A2A-PURPOSE-DENIED", {"context_changes": {"purpose": "EXFILTRATE"}}),
            ("A2A-DATA-CLASS-DENIED", {"context_changes": {"data_classes": frozenset({"D8"})}}),
        ]
        for code, kwargs in cases:
            with self.subTest(code=code):
                self.assertIn(code, rejected_codes(**kwargs))

    def test_boundary_findings_are_reachable(self):
        cases = [
            ("A2A-BOUNDARY-DATA-CLASS-DENIED", {"context_changes": {"data_classes": frozenset({"D5"})}}),
            ("A2A-BOUNDARY-TENANT-REQUIRED", {"principal_changes": {"tenant_id": ""}}),
            ("A2A-BOUNDARY-IDENTITY-REQUIRED", {"principal_changes": {"authenticated": False}}),
        ]
        for code, kwargs in cases:
            with self.subTest(code=code):
                self.assertIn(code, rejected_codes(**kwargs))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test and complete the remaining cases**

Run: `uv run pytest tests/test_a2a_characterization.py -v`

Expected: `test_clean_send_is_not_rejected` PASSES. Subtest failures mean the perturbation does not reach the branch — fix the perturbation.

Five findings are not yet covered by the cases above and must be added before this task is complete. Each needs a perturbed manifest rather than a perturbed principal, so build it by mutating the dict `boundary_manifest()` returns and passing it as the first argument to `rejected_codes`:

- `A2A-ACTOR-TYPE-DENIED` — change the edge policy's `sourceTypes` or `targetTypes` so the declared actors no longer qualify.
- `A2A-INPUT-SCHEMA-INVALID` — give `agent.research` an `inputSchema` with a required property that `request_message()` does not supply.
- `A2A-BOUNDARY-RELATIONSHIP-DENIED` — remove the edge's relationship from the boundary's `allowedRelationships`.
- `A2A-BOUNDARY-PAYLOAD-TOO-LARGE` — set the boundary's `maxPayloadBytes` to `1`.
- `A2A-CREDENTIAL-DETECTED` — send a message whose data part carries a value matching a secret pattern, e.g. `A2APart.data_part({"key": "AKIAIOSFODNN7EXAMPLE"})`.

`A2A-PAYLOAD-INVALID` fires only when `payload_bytes < 1`, which a well-formed message cannot produce; note that in a comment and leave it uncovered.

- [ ] **Step 3: Confirm the full suite is unchanged**

Run: `uv run pytest -q`
Expected: `459 passed, 12 skipped` plus the new subtests.

- [ ] **Step 4: Lint**

Run: `uv run ruff check tests/test_a2a_characterization.py`

- [ ] **Step 5: Commit**

```bash
git add tests/test_a2a_characterization.py
git commit -m "test: pin the A2A broker's link and boundary findings

Fifteen of seventeen appeared in no test file. Pins them before they move
into the shared check table."
```

---

### Task 3: The check table, with one check transposed

Introduce the types and prove the shape end to end on a single check before moving the other nineteen.

**Files:**
- Modify: `src/agent_interlock/policy.py`
- Create: `tests/test_check_table.py`

**Interfaces:**
- Produces:
  - `CheckScope` — `StrEnum` with `ACTOR`, `PAYLOAD`, `PAIR`, `BOUNDARY`
  - `Findings = tuple[tuple[str, ControlDecision], ...]`
  - `Check(id: str, scope: CheckScope, armed: Callable[[LinkPolicy], bool], run: Callable[[LinkPolicy, CheckContext], Findings | None])`
  - `Profile(enforcement_point: str, checks: tuple[str, ...], reason_codes: Mapping[str, str])`
  - `CheckContext` — the existing `EvaluationInput` fields with `revision: ToolRevision | None = None`, plus `boundary: BoundaryLike | None = None`, `payload_bytes: int = 0`, `relationship: str = ""`
  - `EvaluationInput = CheckContext` — alias so `gateway.py:221` needs no change
  - `CHECKS: dict[str, Check]` — the table, keyed by check id
  - `GATEWAY_PROFILE: Profile`
  - `run_checks(policy, context, profile) -> tuple[list[str], list[ControlDecision], set[str]]` returning emitted reason codes, decisions, and the ids that ran

- [ ] **Step 1: Write the failing test**

```python
"""The check table mechanism: three coverage states, and profile renaming."""

from __future__ import annotations

import unittest

from dataclasses import replace

from agent_interlock.models import ActorType, ControlDecision
from agent_interlock.policy import CHECKS, GATEWAY_PROFILE, CheckScope, Profile, run_checks
from test_policy_characterization import clean_case


class CheckTableTests(unittest.TestCase):
    def test_actor_type_check_is_registered_with_pair_scope(self):
        check = CHECKS["INTERLOCK-ACTOR-TYPE-DENIED"]
        self.assertEqual(check.scope, CheckScope.PAIR)

    def test_clean_case_runs_the_check_and_finds_nothing(self):
        policy, context = clean_case()
        reasons, _, ran = run_checks(policy, context, GATEWAY_PROFILE)
        self.assertEqual(reasons, [])
        self.assertIn("INTERLOCK-ACTOR-TYPE-DENIED", ran)

    def test_profile_renames_the_emitted_reason_code(self):
        policy, context = clean_case()
        context = replace(context, source=replace(context.source, type=ActorType.USER))
        profile = Profile(
            enforcement_point="A2A_BROKER",
            checks=("INTERLOCK-ACTOR-TYPE-DENIED",),
            reason_codes={"INTERLOCK-ACTOR-TYPE-DENIED": "A2A-ACTOR-TYPE-DENIED"},
        )
        reasons, decisions, _ = run_checks(policy, context, profile)
        self.assertEqual(reasons, ["A2A-ACTOR-TYPE-DENIED"])
        self.assertEqual(decisions, [ControlDecision.BLOCK])

    def test_a_check_absent_from_the_profile_does_not_run(self):
        policy, context = clean_case()
        profile = Profile(enforcement_point="SDK", checks=(), reason_codes={})
        _, _, ran = run_checks(policy, context, profile)
        self.assertEqual(ran, set())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_check_table.py -v`
Expected: FAIL with `ImportError: cannot import name 'CHECKS'`.

- [ ] **Step 3: Add the types and the first check**

In `src/agent_interlock/policy.py`, above `evaluate`:

```python
class CheckScope(StrEnum):
    ACTOR = "ACTOR"
    PAYLOAD = "PAYLOAD"
    PAIR = "PAIR"
    BOUNDARY = "BOUNDARY"


class BoundaryLike(Protocol):
    """Structural view of ArchitectureBoundary.

    policy.py must not import architecture.py: architecture imports sdk, and sdk
    imports policy, so a direct import would close the cycle.
    """

    allowed_relationships: frozenset[str]
    allowed_data_classes: frozenset[str]
    denied_data_classes: frozenset[str]
    require_identity: bool
    require_tenant_binding: bool
    max_payload_bytes: int
    mode: PolicyMode


Findings = tuple[tuple[str, ControlDecision], ...]


@dataclass(frozen=True, slots=True)
class Check:
    id: str
    scope: CheckScope
    armed: Callable[[LinkPolicy], bool]
    run: Callable[[LinkPolicy, "CheckContext"], Findings | None]


@dataclass(frozen=True, slots=True)
class Profile:
    enforcement_point: str
    checks: tuple[str, ...]
    reason_codes: Mapping[str, str] = field(default_factory=dict)
```

Change `EvaluationInput` to `CheckContext` with the new optional fields and keep the old name as an alias:

```python
@dataclass(frozen=True, slots=True)
class CheckContext:
    source: ActorSpec
    target: ActorSpec
    intent: InvocationIntent
    arguments: Mapping[str, Any]
    interaction_id: str
    trace_id: str
    span_id: str
    revision: ToolRevision | None = None
    credential: CredentialClaims | None = None
    approval_valid: bool = False
    boundary: BoundaryLike | None = None
    payload_bytes: int = 0
    relationship: str = ""


EvaluationInput = CheckContext
```

`gateway.py:221` passes every field by keyword, so reordering is safe.

Add the first check and the table:

```python
def _actor_type(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.source.type in policy.source_types and context.target.type in policy.target_types:
        return ()
    return (("INTERLOCK-ACTOR-TYPE-DENIED", ControlDecision.BLOCK),)


CHECKS: dict[str, Check] = {
    check.id: check
    for check in (
        Check(
            id="INTERLOCK-ACTOR-TYPE-DENIED",
            scope=CheckScope.PAIR,
            armed=lambda policy: True,
            run=_actor_type,
        ),
    )
}


def run_checks(
    policy: LinkPolicy,
    context: CheckContext,
    profile: Profile,
) -> tuple[list[str], list[ControlDecision], set[str]]:
    """Run a profile's checks. Returns emitted reason codes, decisions, and the ids that ran."""
    reasons: list[str] = []
    decisions: list[ControlDecision] = []
    ran: set[str] = set()
    for check_id in profile.checks:
        check = CHECKS[check_id]
        if not check.armed(policy):
            continue
        findings = check.run(policy, context)
        if findings is None:
            continue
        ran.add(check_id)
        for key, decision in findings:
            reasons.append(profile.reason_codes.get(key, key))
            decisions.append(decision)
    return reasons, decisions, ran


GATEWAY_PROFILE = Profile(enforcement_point="MCP_GATEWAY", checks=("INTERLOCK-ACTOR-TYPE-DENIED",))
```

Add `Callable`, `Protocol`, `field` and `StrEnum` to the existing imports at the top of `policy.py`.

Then delete the actor-type branch at `policy.py:46-48` and call the table from `evaluate` before the remaining inline branches:

```python
def evaluate(policy: LinkPolicy, value: CheckContext) -> PolicyDecisionRecord:
    reasons, decisions, _ = run_checks(policy, value, GATEWAY_PROFILE)
    arguments_hash = canonical_digest(value.arguments)
    # ... the remaining inline branches follow unchanged
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_check_table.py tests/test_policy_characterization.py -v`
Expected: PASS.

- [ ] **Step 5: Confirm nothing else moved**

Run: `uv run pytest -q && uv run ruff check src tests`
Expected: `459 passed, 12 skipped` plus new subtests; no lint findings.

- [ ] **Step 6: Commit**

```bash
git add src/agent_interlock/policy.py tests/test_check_table.py
git commit -m "feat: add the check table with the actor-type check transposed

Check/Profile/CheckContext plus run_checks. EvaluationInput stays as an alias
so gateway.py is untouched. One check moved to prove the shape."
```

---

### Task 4: Transpose the remaining gateway checks

**Files:**
- Modify: `src/agent_interlock/policy.py`

**Interfaces:**
- Consumes: `Check`, `Profile`, `run_checks`, `CHECKS` from Task 3.
- Produces: `GATEWAY_PROFILE.checks` containing all twenty check ids; `evaluate()` reduced to `run_checks` plus record assembly.

- [ ] **Step 1: Confirm the guard is in place**

Run: `uv run pytest tests/test_policy_characterization.py -q`
Expected: PASS. This test is the only thing standing between this task and a silent regression. Do not proceed if it fails.

- [ ] **Step 2: Move each branch, one at a time**

For each remaining branch in `evaluate` (`policy.py:49-141`), write a module-level function and register it. The `armed` predicate carries the policy-level enable flag that currently guards the branch; the `run` body carries the rest.

Worked example — the digest pin, currently `policy.py:55-59`:

```python
def _definition_drift(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.revision is None:
        return None
    approved = context.target.definition_digest
    if approved and approved == context.revision.canonical_digest:
        return ()
    return (("L1-M2-DEFINITION-DRIFT", ControlDecision.QUARANTINE),)
```

registered as:

```python
Check(
    id="L1-M2-DEFINITION-DRIFT",
    scope=CheckScope.ACTOR,
    armed=lambda policy: policy.require_digest_pin,
    run=_definition_drift,
),
```

Rules that apply to every transposition:

- `armed` reads **only** `policy`. Anything that depends on the invocation belongs in `run`.
- `run` returns `None` when the invocation does not engage the check — a missing `revision`, an empty `destinations` tuple, an intent that declares no audience. It returns `()` when it engaged and found nothing.
- The reason key in the returned findings is the **existing gateway string**, unchanged.
- Decisions that today come from a policy field (`policy.secret_action`, `policy.new_destination_action`, `policy.volume_action`, `policy.undeclared_side_effect_action`, `policy.destructive_write_action`) keep coming from that field.

Scope assignment:

| Scope | Checks |
| --- | --- |
| `ACTOR` | `L1-M2-DEFINITION-NOT-ACTIVE`, `L1-M2-DEFINITION-DRIFT`, `L1-M9-NEW-DESTINATION` |
| `PAYLOAD` | `INTERLOCK-INPUT-SCHEMA-INVALID`, `L1-M8-CREDENTIAL-DETECTED`, `L1-M9-VOLUME-EXCEEDED`, `L1-M9-SENSITIVE-EGRESS`, `INTERLOCK-DATA-CLASS-DENIED`, `INTERLOCK-DESTRUCTIVE-WRITE`, `L1-UNDECLARED-SIDE-EFFECT`, `INTERLOCK-APPROVAL-REQUIRED` |
| `PAIR` | `INTERLOCK-ACTOR-TYPE-DENIED`, `INTERLOCK-PURPOSE-DENIED`, and all five M5 credential checks |

`L1-M9-NEW-DESTINATION` is `ACTOR` scope because the allowlist it consults is `target.allowed_domains`, a property of the target actor.

The three branches that today emit `L1-M9-NEW-DESTINATION` (`policy.py:74-92`) collapse into **one** check that returns up to three findings.

After each move: run `uv run pytest tests/test_policy_characterization.py -q`. It must stay green after every single move.

- [ ] **Step 3: Reduce `evaluate` to the loop**

```python
def evaluate(policy: LinkPolicy, value: CheckContext) -> PolicyDecisionRecord:
    reasons, decisions, _ = run_checks(policy, value, GATEWAY_PROFILE)
    canonical_destinations = _canonical_destinations(value.intent.destinations)
    return PolicyDecisionRecord(
        decision_id=str(uuid.uuid4()),
        decision=strongest_decision(decisions),
        reason_codes=tuple(dict.fromkeys(reasons)),
        policy_id=policy.id,
        policy_version=policy.version,
        mode=policy.mode,
        arguments_hash=canonical_digest(value.arguments),
        canonical_destinations=canonical_destinations,
        expires_at_epoch=time.time() + policy.decision_ttl_seconds,
        enforced=policy.mode == PolicyMode.ENFORCE,
        interaction_id=value.interaction_id,
        trace_id=value.trace_id,
        span_id=value.span_id,
    )
```

`canonical_destinations` was previously accumulated inside the destination branch and is still needed on the record, so extract it into a helper that both the check and `evaluate` call. It must not raise: the current loop catches `ValueError` and turns it into a finding.

- [ ] **Step 4: Run the full suite**

Run: `uv run pytest -q && uv run ruff check src tests`
Expected: `459 passed, 12 skipped` plus new subtests; no lint findings.

- [ ] **Step 5: Commit**

```bash
git add src/agent_interlock/policy.py
git commit -m "refactor: move all twenty gateway checks into the table

evaluate() is now run_checks plus record assembly. No reason code changed."
```

---

### Task 5: Route the SDK through the table

**Files:**
- Modify: `src/agent_interlock/sdk.py:30-50,107-182`
- Create: `tests/test_sdk_profile.py`

**Interfaces:**
- Consumes: `CHECKS`, `Profile`, `run_checks`, `CheckContext` from Tasks 3–4.
- Produces: `agent_interlock.policy.SDK_PROFILE`; `Actor.wrap()`'s `guarded()` gains `credential: CredentialClaims | None = None`.

- [ ] **Step 1: Write the failing test**

```python
"""The SDK reaches the same verdict as the gateway for the checks it shares."""

from __future__ import annotations

import unittest

from agent_interlock import ActorSpec, ActorType, InvocationIntent, LinkPolicy, PolicyMode, SideEffect
from agent_interlock.gateway import GatewayError
from agent_interlock.sdk import Interlock


def wired(policy: LinkPolicy):
    interlock = Interlock()
    source = interlock.define_actor(
        ActorSpec(id="agent-1", type=ActorType.AGENT, owner="team", identity="spiffe://agent-1")
    )
    target = interlock.define_actor(
        ActorSpec(
            id="tool-1",
            type=ActorType.TOOL,
            owner="team",
            identity="spiffe://tool-1",
            allowed_domains=frozenset({"good.example"}),
        )
    )
    source.connect(target, policy)
    return interlock, source, target


class SDKProfileTests(unittest.TestCase):
    def test_secret_in_arguments_is_now_detected(self):
        _, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE))
        guarded = target.wrap(lambda arguments: {"ok": True})
        with self.assertRaises(GatewayError) as raised:
            guarded(
                {"note": "AKIAIOSFODNN7EXAMPLE"},
                source=source,
                tenant_id="tenant-a",
                intent=InvocationIntent(purpose="SUPPORT_LOOKUP"),
            )
        self.assertIn("L1-M8-CREDENTIAL-DETECTED", str(raised.exception))

    def test_undeclared_destination_is_now_detected(self):
        _, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE))
        guarded = target.wrap(lambda arguments: {"ok": True})
        with self.assertRaises(GatewayError) as raised:
            guarded(
                {},
                source=source,
                tenant_id="tenant-a",
                intent=InvocationIntent(
                    purpose="SUPPORT_LOOKUP",
                    destinations=("https://evil.example",),
                    estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                ),
            )
        self.assertIn("L1-M9-NEW-DESTINATION", str(raised.exception))

    def test_clean_call_still_executes(self):
        _, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE))
        guarded = target.wrap(lambda arguments: {"ok": True})
        result = guarded(
            {},
            source=source,
            tenant_id="tenant-a",
            intent=InvocationIntent(purpose="SUPPORT_LOOKUP"),
        )
        self.assertEqual(result, {"ok": True})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_sdk_profile.py -v`
Expected: the first two FAIL — the SDK does not check secrets or destinations today. The third PASSES.

- [ ] **Step 3: Define the SDK profile and rewire `_invoke`**

In `policy.py`, add the profile. It runs every check except the two that need a `ToolRevision`, and adds the SDK-only taint check, which must first be registered in `CHECKS`:

```python
def _tainted_external_write(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.intent.estimated_side_effect != SideEffect.EXTERNAL_WRITE:
        return None
    if not context.intent.taint_labels:
        return ()
    return (("INTERLOCK-TAINTED-EXTERNAL-WRITE", ControlDecision.BLOCK),)
```

registered with `scope=CheckScope.PAYLOAD` and `armed=lambda policy: True`, and added to `GATEWAY_PROFILE.checks` as well — the spec promotes it to a shared check, so the gateway gains it.

```python
SDK_PROFILE = Profile(
    enforcement_point="SDK",
    checks=tuple(
        check_id
        for check_id in GATEWAY_PROFILE.checks
        if check_id not in {"L1-M2-DEFINITION-NOT-ACTIVE", "L1-M2-DEFINITION-DRIFT"}
    ),
)
```

The M2 checks are excluded from the profile rather than left to return `None`, because the SDK structurally has no revision — that is an ABSENT control, not an inapplicable one, and Plan 2 depends on the distinction.

In `sdk.py`, replace lines 148-157 with:

```python
reasons, decisions, _ = run_checks(
    policy,
    CheckContext(
        source=source.spec,
        target=target.spec,
        intent=intent,
        arguments=arguments,
        interaction_id=interaction,
        trace_id=trace,
        span_id=span,
        credential=credential,
        relationship=policy.relationship,
        payload_bytes=len(canonical_json(dict(arguments))),
    ),
    SDK_PROFILE,
)
decision = strongest_decision(decisions)
```

and change `if reasons and enforced:` at `sdk.py:175` to `if decision != ControlDecision.ALLOW and enforced:`.

Add `credential: CredentialClaims | None = None` to `guarded()`'s keyword arguments at `sdk.py:32-39` and thread it into `_invoke`.

Import `run_checks`, `SDK_PROFILE`, `CheckContext`, `strongest_decision` from `.policy` and `canonical_json` from `.canonical`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_sdk_profile.py -v`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `uv run pytest -q && uv run ruff check src tests`

Expected: some existing SDK tests may now fail, because calls that used to pass the four-check gate now face eighteen. **Each such failure is the defect this plan exists to fix, not a regression.** For each one, confirm the new finding is correct, then update the test fixture to declare what it actually needs — an `allowed_domains` entry, a `credential`, a wider `allowed_data_classes`. Do not weaken the profile to make a test pass.

- [ ] **Step 6: Commit**

```bash
git add src/agent_interlock/policy.py src/agent_interlock/sdk.py tests/test_sdk_profile.py
git commit -m "feat: route the SDK through the shared check table

wrap() gained a credential argument and now runs eighteen checks instead of
four. M2 is excluded from the SDK profile: it has no revision to pin."
```

---

### Task 6: Route the A2A broker through the table

**Files:**
- Modify: `src/agent_interlock/a2a.py:602-620,806-870`
- Modify: `src/agent_interlock/policy.py`

**Interfaces:**
- Consumes: everything from Tasks 3–5.
- Produces: `agent_interlock.policy.A2A_PROFILE`; `a2a.py` no longer holds judgment predicates.

- [ ] **Step 1: Confirm the guard is in place**

Run: `uv run pytest tests/test_a2a_characterization.py -q`
Expected: PASS.

- [ ] **Step 2: Add the boundary checks to the table**

Five checks with `scope=CheckScope.BOUNDARY`, each returning `None` when `context.boundary is None`. Canonical keys are the existing A2A strings, since the gateway has no equivalent to rename from:

```python
def _boundary_payload_size(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.boundary is None:
        return None
    if context.payload_bytes <= context.boundary.max_payload_bytes:
        return ()
    return (("A2A-BOUNDARY-PAYLOAD-TOO-LARGE", ControlDecision.BLOCK),)
```

The other four follow the same shape from `a2a.py:858-869`.

- [ ] **Step 3: Define the A2A profile**

```python
A2A_PROFILE = Profile(
    enforcement_point="A2A_BROKER",
    checks=(
        "INTERLOCK-ACTOR-TYPE-DENIED",
        "INTERLOCK-PURPOSE-DENIED",
        "INTERLOCK-DATA-CLASS-DENIED",
        "L1-M8-CREDENTIAL-DETECTED",
        "L1-M5-TOKEN-ACTOR-MISMATCH",
        "L1-M5-TOKEN-AUDIENCE-MISMATCH",
        "L1-M5-TOKEN-PASSTHROUGH",
        "L1-M5-DELEGATION-DEPTH",
        "INTERLOCK-INPUT-SCHEMA-INVALID",
        "A2A-IDENTITY-BINDING-MISMATCH",
        "A2A-PAYLOAD-INVALID",
        "A2A-RESOURCE-MISMATCH",
        "A2A-BOUNDARY-RELATIONSHIP-DENIED",
        "A2A-BOUNDARY-DATA-CLASS-DENIED",
        "A2A-BOUNDARY-IDENTITY-REQUIRED",
        "A2A-BOUNDARY-TENANT-REQUIRED",
        "A2A-BOUNDARY-PAYLOAD-TOO-LARGE",
    ),
    reason_codes={
        "INTERLOCK-ACTOR-TYPE-DENIED": "A2A-ACTOR-TYPE-DENIED",
        "INTERLOCK-PURPOSE-DENIED": "A2A-PURPOSE-DENIED",
        "INTERLOCK-DATA-CLASS-DENIED": "A2A-DATA-CLASS-DENIED",
        "L1-M8-CREDENTIAL-DETECTED": "A2A-CREDENTIAL-DETECTED",
        "L1-M5-TOKEN-ACTOR-MISMATCH": "A2A-ACTOR-BINDING-MISMATCH",
        "L1-M5-TOKEN-AUDIENCE-MISMATCH": "A2A-AUDIENCE-MISMATCH",
        "L1-M5-TOKEN-PASSTHROUGH": "A2A-TOKEN-PASSTHROUGH",
        "L1-M5-DELEGATION-DEPTH": "A2A-DELEGATION-DEPTH",
        "INTERLOCK-INPUT-SCHEMA-INVALID": "A2A-INPUT-SCHEMA-INVALID",
    },
)
```

`A2A-IDENTITY-BINDING-MISMATCH` and `A2A-PAYLOAD-INVALID` keep their own ids: no gateway check corresponds to them.

> ⚠️ **The map above is incomplete as written and must not be copied.** The map is
> keyed on the **emitted reason key**, not the check id, and a check may emit more
> than one key. Two entries are missing here and were added before this landed:
>
> ```python
>         "L1-M9-SENSITIVE-EGRESS": "A2A-DATA-CLASS-DENIED",
>         "L1-M5-TOKEN-RESOURCE-MISMATCH": "A2A-RESOURCE-MISMATCH",
> ```
>
> Without the first, a denied D7 puts the gateway-namespace string
> `L1-M9-SENSITIVE-EGRESS` on the A2A wire, because `reason_codes.get(key, key)`
> passes unmapped keys through unchanged. Without the second, the audience check —
> which task 4 merged with the resource check into one id emitting two keys —
> raises `KeyError`. The gateway and SDK profiles instead map
> `L1-M5-TOKEN-RESOURCE-MISMATCH` **to** `L1-M5-TOKEN-AUDIENCE-MISMATCH`, which
> preserves their historical collapse byte for byte.

**The audience and resource comparisons genuinely differ** and are the only non-mechanical part of this task. The broker compares `principal.audience` against `target.identity`, the gateway compares `credential.audience` against `intent.expected_audience`. Resolve it in the check by preferring the declared expectation and falling back to the target's identity:

```python
def _audience(policy: LinkPolicy, context: CheckContext) -> Findings | None:
    if context.credential is None:
        return None
    expected = context.intent.expected_audience or context.target.identity
    if not expected:
        return None
    if context.credential.audience == expected:
        return ()
    return (("L1-M5-TOKEN-AUDIENCE-MISMATCH", ControlDecision.BLOCK),)
```

Resource follows the same shape with `context.intent.expected_resource or f"a2a://{context.target.id}"`. Both branches need their own test asserting the gateway path and the broker path each still reach the verdict they reached before.

- [ ] **Step 4: Rewire `send_message`**

Replace `_link_reasons` and `_boundary_reasons` (`a2a.py:806-870`) with two `run_checks` calls against `A2A_PROFILE`, split so the mode composition at `a2a.py:616-619` survives intact:

```python
context_for_checks = CheckContext(
    source=self.architecture.actors[context.source_actor_id],
    target=target,
    intent=InvocationIntent(purpose=context.purpose, data_classes=context.data_classes),
    arguments=message.to_dict(),
    interaction_id=interaction_id,
    trace_id=trace_id,
    span_id=span_id,
    credential=_credential_from(context.principal),
    boundary=boundary,
    payload_bytes=payload_bytes,
    relationship=edge.relationship,
)
link_profile = replace(A2A_PROFILE, checks=tuple(
    check_id for check_id in A2A_PROFILE.checks if CHECKS[check_id].scope is not CheckScope.BOUNDARY
))
boundary_profile = replace(A2A_PROFILE, checks=tuple(
    check_id for check_id in A2A_PROFILE.checks if CHECKS[check_id].scope is CheckScope.BOUNDARY
))
link_reasons, link_decisions, _ = run_checks(edge.policy, context_for_checks, link_profile)
boundary_reasons, boundary_decisions, _ = run_checks(edge.policy, context_for_checks, boundary_profile)
```

`enforced` at `a2a.py:616-619` stays exactly as written: link findings answer to `edge.policy.mode`, boundary findings answer to `boundary.mode`. This is existing correct behaviour and must not be collapsed into a single mode.

`_credential_from(principal)` is a new module-level helper in `a2a.py` mapping `A2APrincipal` onto `CredentialClaims`: `actor_id`→`actor`, and `audience`, `resource`, `exchanged`, `delegation_depth` straight across.

Note the guard at `a2a.py:853-856`: when `edge.boundary_id` is set but no boundary compiled, the broker emits `A2A-BOUNDARY-NOT-COMPILED`. That is a wiring error, not a policy finding — keep it as an explicit check in `send_message` before the profile runs.

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/test_a2a_characterization.py tests/test_a2a.py -v`
Expected: PASS with identical reason codes.

- [ ] **Step 6: Run the full suite**

Run: `uv run pytest -q && uv run ruff check src tests`
Expected: `459 passed, 12 skipped` plus new subtests. `tests/test_platform_e2e.py` and `tests/test_l1_matrix.py` exercise the broker end to end; both must be green.

- [ ] **Step 7: Commit**

```bash
git add src/agent_interlock/policy.py src/agent_interlock/a2a.py
git commit -m "feat: route the A2A broker through the shared check table

The broker keeps emitting A2A-* strings via the profile's reason_codes map,
so ledger history and the docs/05 test ids are unaffected. Link and boundary
findings stay separated so each still answers to its own PolicyMode."
```

---

### Task 7: Fix the decision ranking and add `would_block`

**Files:**
- Modify: `src/agent_interlock/policy.py:160-171`
- Modify: `src/agent_interlock/models.py:237-239`
- Create: `tests/test_decision_ranking.py`

**Interfaces:**
- Produces: `PolicyDecisionRecord.would_block` — Plan 2 uses it as the source for `shadowWouldBlockCount`.

- [ ] **Step 1: Write the failing test**

```python
"""BYPASSED must rank weakest and the rank map must be total."""

from __future__ import annotations

import unittest

from agent_interlock.models import ControlDecision
from agent_interlock.policy import strongest_decision


class DecisionRankingTests(unittest.TestCase):
    def test_bypassed_is_weaker_than_block(self):
        self.assertEqual(strongest_decision([ControlDecision.BYPASSED, ControlDecision.BLOCK]), ControlDecision.BLOCK)

    def test_bypassed_alone_is_not_promoted(self):
        self.assertEqual(strongest_decision([ControlDecision.BYPASSED]), ControlDecision.BYPASSED)

    def test_error_outranks_block(self):
        self.assertEqual(strongest_decision([ControlDecision.BLOCK, ControlDecision.ERROR]), ControlDecision.ERROR)

    def test_challenge_is_weaker_than_block(self):
        self.assertEqual(strongest_decision([ControlDecision.CHALLENGE, ControlDecision.BLOCK]), ControlDecision.BLOCK)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_decision_ranking.py -v`
Expected: `test_bypassed_is_weaker_than_block` and `test_challenge_is_weaker_than_block` FAIL — both currently rank 3, tying with `BLOCK`, and `max` returns the first of a tie.

- [ ] **Step 3: Make the rank map total**

```python
_DECISION_RANK = {
    ControlDecision.BYPASSED: 0,
    ControlDecision.ALLOW: 1,
    ControlDecision.SANITIZE: 2,
    ControlDecision.DEGRADE: 3,
    ControlDecision.CHALLENGE: 4,
    ControlDecision.HOLD: 5,
    ControlDecision.BLOCK: 6,
    ControlDecision.QUARANTINE: 7,
    ControlDecision.REVOKE: 8,
    ControlDecision.KILL: 9,
    ControlDecision.ERROR: 10,
}

assert set(_DECISION_RANK) == set(ControlDecision), "decision rank map must cover every ControlDecision"


def strongest_decision(decisions: list[ControlDecision]) -> ControlDecision:
    if not decisions:
        return ControlDecision.ALLOW
    return max(decisions, key=lambda item: _DECISION_RANK[item])
```

`ERROR` ranks highest because an evaluation error means the verdict is unknown and `FailureMode.FAIL_CLOSED` is the default.

- [ ] **Step 4: Add `would_block`**

> ⚠️ **This step was written wrong and was NOT implemented as shown. Do not copy
> it.** Kept struck through because the reason it was wrong is the point.
>
> ~~```python~~
> ~~    @property~~
> ~~    def would_block(self) -> bool:~~
> ~~        """Whether the policy found grounds to block, regardless of enforcement mode.~~
> ~~        permits_execution answers "may this run now", which is False in SHADOW~~
> ~~        even for a BLOCK verdict. This answers "did the policy object".~~
> ~~        """~~
> ~~        return self.decision != ControlDecision.ALLOW~~
> ~~```~~
>
> Two errors. `BYPASSED` ranks **below** `ALLOW`, so `!= ALLOW` reports a
> deliberately bypassed control as "the policy found grounds to block" — and Plan
> 2 wires `shadowWouldBlockCount` to this property, so the lie would land in the
> statistic this effort exists to make trustworthy. Reverting to this body fails
> exactly one test in the suite. And `permits_execution` is `True` in SHADOW, not
> `False`; the docstring had it backwards.

What shipped derives the predicate from the rank map so the two cannot drift, in
`models.py` after `permits_execution`:

```python
    @property
    def would_block(self) -> bool:
        """Whether the verdict is more severe than ALLOW, regardless of enforcement mode."""
        return _DECISION_RANK[self.decision] > _DECISION_RANK[ControlDecision.ALLOW]
```

See `docs/specs/2026-07-27-control-coverage-statistics.md` §6, which supersedes
this document.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/test_decision_ranking.py -v`
Expected: PASS.

- [ ] **Step 6: Run the full suite**

Run: `uv run pytest -q && uv run ruff check src tests`
Expected: `459 passed, 12 skipped` plus new subtests.

- [ ] **Step 7: Commit**

```bash
git add src/agent_interlock/policy.py src/agent_interlock/models.py tests/test_decision_ranking.py
git commit -m "fix: rank every ControlDecision explicitly and add would_block

order.get(item, 3) tied CHALLENGE, DEGRADE and BYPASSED with BLOCK, all
reachable through the five unconstrained LinkPolicy action fields. The map is
now total and asserted at import."
```

---

## Write set

Files this plan is permitted to touch:

- `src/agent_interlock/policy.py`
- `src/agent_interlock/sdk.py`
- `src/agent_interlock/a2a.py`
- `src/agent_interlock/models.py`
- `tests/test_policy_characterization.py` (new)
- `tests/test_a2a_characterization.py` (new)
- `tests/test_check_table.py` (new)
- `tests/test_sdk_profile.py` (new)
- `tests/test_decision_ranking.py` (new)
- Existing test fixtures that Task 5 shows to be under-declared, and only to declare what they already needed.

Not touched by this plan: `gateway.py` (the `EvaluationInput` alias keeps it working), `analytics.py`, `ledger*.py`, `architecture.py`, `schemas/`, `studio/`.

## Follow-on

Plan 2 covers `enforcementPoint` and `evaluatedProfile` on the wire, the
`CONTROL_COVERAGE_DECLARED` event, the statistics schema and reducer, the Studio
port and golden fixtures, then Studio verification, independent review and
documentation. It depends on the canonical check ids this plan defines.
