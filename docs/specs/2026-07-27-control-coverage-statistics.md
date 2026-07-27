# Control Coverage Statistics

Status: proposed
Date: 2026-07-27

## Problem

The platform's promotion loop is: design a multi-agent graph in Studio, observe
inter-actor traffic, read the statistics, promote a link from SHADOW to ENFORCE.
That loop currently reads a number it cannot justify, for two reasons.

### Two judgment engines that disagree

`policy.evaluate()` runs twenty checks: actor type, purpose, definition state
(M2), digest pin (M2), input schema, denied data classes and sensitive egress
(M9), secret detection (M8), destination canonicalisation, destination
allowlist, explicit-destination requirement, export volume (M9), undeclared side
effect, destructive write, approval requirement, and six credential checks (M5).

`Interlock._invoke()` (`src/agent_interlock/sdk.py:148-157`) runs four: input
schema, data-class subset, undeclared side effect, and tainted external write.

These are not in a subset relationship. `INTERLOCK-TAINTED-EXTERNAL-WRITE` is
emitted only by the SDK and is unknown to `policy.py`. M5, M8, and M9 are absent
from the SDK entirely. Both paths write byte-identical `payload.control` shapes
into the ledger — deliberately, per the comment at `src/agent_interlock/sdk.py:161-162`
— so nothing downstream can tell them apart.

`wrap()` is not a demo surface. `README.md:129` lists it as an SDK feature and
`docs/02-developer-framework-design.md:336` states that an existing Tool can be
wrapped "to enforce policy before the call".

### Statistics record firing, not coverage

A check that passes appends nothing. There is no record that a control was armed
and ran clean, so "this control never ran" and "this control ran and found
nothing" are the same silence in the ledger and the same green tile in Studio.

Combined with the first defect: a link guarded only by the SDK shows no M5, M8,
or M9 findings because those controls were never consulted, and that absence is
rendered as safety. Promotion to ENFORCE is then decided on it.

## Goal

Per segment of the declared graph, the statistics answer two distinct questions:

1. **Coverage** — which controls were armed, which were applicable, which ran.
2. **Firing** — of those that ran, which flagged.

And the two execution paths reach the same verdict for the same input.

## Non-goals and explicit limits

**This work measures coverage. It does not measure safety.** Every number in
this system is the system's own judgment of its own inputs. Recording coverage
fixes "a control we have did not run". It does nothing for "a control we do not
have". An attack outside the threat model produces zero findings, correctly from
the system's point of view and wrongly from reality's.

A fully green coverage dashboard therefore means *every control we thought of
ran*. It does not mean the deployment is safe. False negatives are measurable
only against an external corpus with independent ground truth; that is separate
work and is not delivered here.

This limit must survive into the Studio surface. A coverage figure presented
without it is more dangerous than the current ambiguity, because it reads as
stronger evidence while carrying the same blind spot.

## Design

### 1. Checks become data

The twenty inline branches in `evaluate()` become a declarative table.

```python
class CheckScope(StrEnum):
    ACTOR   = "ACTOR"     # property of the target actor; same verdict for every caller
    PAYLOAD = "PAYLOAD"   # property of the arguments or intent
    PAIR    = "PAIR"      # genuinely about this source -> target link


@dataclass(frozen=True, slots=True)
class Check:
    id: str
    scope: CheckScope
    armed: Callable[[LinkPolicy], bool]
    run: Callable[[LinkPolicy, EvaluationInput], Findings | None]
```

The two callables answer questions at different scopes, which is what makes the
three coverage states well defined:

- `armed(policy)` is a property of the policy alone, stable across invocations.
  A policy with `require_digest_pin=False`, `require_audience=False`,
  `max_export_records=0` or an empty `allowed_purposes` has genuinely switched
  those controls off. Such a check is **ABSENT**.
- `run(policy, value)` is per invocation and returns:
  - `None` — armed, but this invocation did not engage it (**INAPPLICABLE**);
    for example no destinations were declared, or the intent expects no audience
  - `()` — **RAN_CLEAN**
  - non-empty — **RAN_FLAGGED**; a tuple of `(reason_code, ControlDecision)`

Because `armed` depends only on the policy, the ABSENT set is a function of
`(policyId, policyVersion)` and can be declared once instead of per event.

`evaluate()` becomes a loop over the table. Three-state coverage is derived from
the return value, so there is no separate bookkeeping to keep in sync, and a
check that is not in the table does not run at all. Adding check twenty-one
cannot silently escape the coverage record.

Check ids are stable and distinct from reason codes, and the two do not map one
to one in either direction. Twenty checks emit eighteen distinct reason codes:
the destination checks share `L1-M9-NEW-DESTINATION` across three branches, the
audience and resource checks share `L1-M5-TOKEN-AUDIENCE-MISMATCH`, and the
definition-state check forwards whatever `revision.reason_codes` carries.

`CheckScope` exists to stop a single actor-scoped failure from lighting up every
link that points at that actor. A tool whose definition has drifted is one
finding on one actor, not twelve findings on twelve edges. Consumers group by
scope; the reducer only has to carry it.

### 2. The two paths converge on one engine

- `EvaluationInput.revision` and `EvaluationInput.credential` become optional.
- With `revision=None`, the M2 checks (definition state, digest pin) return
  `None` — INAPPLICABLE, not passing — and schema validation reads
  `ActorSpec.input_schema` instead of `revision.definition.input_schema`. An SDK
  link therefore shows M2 as INAPPLICABLE on one hundred percent of its
  interactions, which is the readable signal that this engine supplies no
  definition to pin. It is deliberately not reported as ABSENT: ABSENT means the
  policy switched the control off, which is a different fact.
- `Actor.wrap()`'s returned `guarded()` gains a `credential: CredentialClaims | None`
  keyword argument, defaulting to `None`.
- `src/agent_interlock/sdk.py:148-157` is deleted; `_invoke` calls `evaluate()`.
- `INTERLOCK-TAINTED-EXTERNAL-WRITE` is promoted into the shared table, so the
  gateway and broker paths gain it.

The regression guard is an equivalence test: for the same actors, policy, intent
and arguments, the SDK path and the gateway path produce the same decision and
the same reason codes.

### 3. Coverage on the wire

Two fields are added to `payload.control` on `CONTROL_EVALUATED`:

| Field | Value |
| --- | --- |
| `enforcementPoint` | `SDK` \| `MCP_GATEWAY` \| `A2A_BROKER` — the existing `EnforcementPoint` enum (`src/agent_interlock/architecture.py:31-47`), which is currently computed at lint time and never reaches runtime |
| `evaluatedProfile` | `canonical_digest` of the set of check ids that actually ran on this invocation |

Both are short strings. Coverage costs O(1) per event, not a twenty-element list.

A new event type `CONTROL_COVERAGE_DECLARED` is appended the first time a given
digest is seen:

```json
{
  "profileDigest": "…",
  "enforcementPoint": "SDK",
  "policyId": "…",
  "policyVersion": "…",
  "armed": [{"id": "…", "scope": "PAIR"}],
  "evaluated": ["…"]
}
```

The reducer derives the three states: in `evaluated` is RAN; in `armed` but not
`evaluated` is INAPPLICABLE; in the catalogue but not `armed` is ABSENT. The
catalogue is the union of all `armed` sets observed in the ledger, so the
reducer stays a pure function of the event stream and the Studio TypeScript port
needs no access to Python.

No separate `armedProfile` field: the armed set is a function of
`(enforcementPoint, policyId, policyVersion)`, all already on the event.

### 4. Statistics contract

Added to each partition in `schemas/security-statistics.schema.json`:

- **`byEdge`** — keyed by `(sourceActorId, targetActorId, policyId)`. All three
  are already present in `InteractionRecord` (`src/agent_interlock/analytics.py:46-91`);
  `target_actor_id` is currently used by no grouping. **No new instrumentation.**
  The graph permits several edges between the same actor pair —
  `ArchitectureGraph.edges` is a tuple and uniqueness is enforced on edge ids
  only (`src/agent_interlock/architecture.py:277,293`) — so the pair alone is not
  a key. Including `policyId` splits precisely where the armed check set can
  differ; two edges sharing a pair and a policy have identical coverage by
  definition. Studio holds the ArchitectureGraph and maps the triple back to an
  edge label locally.
- **`byCheck`** — per check id, carrying `scope` and counts for RAN_CLEAN,
  RAN_FLAGGED, INAPPLICABLE, ABSENT.
- **`byEdge[].byCheck[]`** — the cross-tabulation. This is the deliverable: on
  this segment, which controls applied and what happened. Entries whose state is
  ABSENT for every interaction on that edge are omitted to bound the payload.
- **`unattributed`** — interactions that match no declared edge, kept as an
  explicit bucket rather than dropped.

`byReasonCode` is retained; it remains the right view for "what fired".

The schema sets `additionalProperties: false` throughout, so every addition is a
synchronised change across the schema, `studio/app/analytics.mjs`, and the golden
fixtures. The existing byte-identical parity test covers the new fields.

### 5. Ancillary correctness fixes

**`strongest_decision`** (`src/agent_interlock/policy.py:160-171`) ranks six of
the eleven `ControlDecision` values and falls back to `order.get(item, 3)`. Five
`LinkPolicy` fields — `secret_action`, `new_destination_action`, `volume_action`,
`destructive_write_action`, `undeclared_side_effect_action` — are unconstrained
`ControlDecision` values (`src/agent_interlock/models.py:140-152`), so the
fallback is reachable by configuration: `CHALLENGE` and `DEGRADE` rank equal to
`BLOCK`, and `BYPASSED` — which should be weakest — also ranks equal to `BLOCK`.

Fix: rank all eleven explicitly (`BYPASSED` lowest, `ERROR` highest, since an
evaluation error means the verdict is unknown and the default failure mode is
FAIL_CLOSED), drop the `.get` fallback, and assert at import time that the map
covers `ControlDecision` exactly. A twelfth decision value then fails on load
rather than being silently ranked mid-table.

**`PolicyDecisionRecord.would_block`** — a two-line property returning
`self.decision != ControlDecision.ALLOW`. `permits_execution` keeps its name and
semantics; its sole consumer is `src/agent_interlock/gateway.py:286` and its
behaviour in SHADOW is correct by definition. What is missing is a
mode-independent reading for callers that need one, and a first-class source for
`shadowWouldBlockCount`.

### 6. Mode composition

`PolicyMode` is attached in two independent places: `edge.policy.mode` and
`boundary.mode` (`src/agent_interlock/architecture.py:425,1401`). Both greps land
in lint code, so whether `boundary.mode` affects runtime behaviour is unresolved.

This spec does not invent a composition rule. The requirement is that
`CONTROL_EVALUATED` records both inputs and the effective value, so no operator
has to compose them from memory. If investigation shows `boundary.mode` is
design-time only, `effectiveMode` equals the edge mode and that fact is written
down rather than left implicit.

## Out of scope

- **False-negative measurement.** Requires an external corpus. Separate work.
- **Undeclared-path detection.** The `unattributed` bucket only. Proper handling
  belongs to `compare_observed_runtime`
  (`src/agent_interlock/architecture.py:1071-1091`), which already finds observed
  interactions with no declared edge. Wiring that into the statistics is a
  follow-on cycle.
- **`ArchitectureEdge.id` propagation to runtime events.** The
  `(source, target, policyId)` triple is sufficient; edge identity would require
  instrumenting three execution paths for a distinction that does not change
  coverage.
- **Orchestration workflow steps.** `WORKFLOW_*` events carry no `interaction_id`
  (`src/agent_interlock/orchestration.py:602-633`) and are excluded from the
  reducer. Unchanged here.
- **Trust-zone boundaries in the MCP path.** `a2a.py` emits `payload.boundary`
  and the reducer discards it; `gateway.py` has no boundary concept. Unchanged
  here.

## Testing

**Characterization tests land before the restructure.** Of the eighteen reason
codes `policy.py` emits, ten appear in no test file: `INTERLOCK-ACTOR-TYPE-DENIED`,
`INTERLOCK-APPROVAL-REQUIRED`, `INTERLOCK-DESTRUCTIVE-WRITE`,
`INTERLOCK-INPUT-SCHEMA-INVALID`, `INTERLOCK-PURPOSE-DENIED`,
`L1-M2-DEFINITION-NOT-ACTIVE`, `L1-M5-CREDENTIAL-MISSING`,
`L1-M5-DELEGATION-DEPTH`, `L1-M5-TOKEN-ACTOR-MISMATCH`, and
`L1-M9-SENSITIVE-EGRESS`. Four of the six M5 credential checks are unprotected.
This is a string-presence proxy, not line coverage — it bounds the risk from
below — but restructuring the judgment engine against it as-is means a broken
check passes 459 green tests.

The characterization test is one table: each reason code with a triggering input
and a non-triggering input. After the restructure the same table also asserts the
three coverage states, since the non-triggering cases distinguish INAPPLICABLE
from RAN_CLEAN.

Additional tests:

- SDK/gateway verdict equivalence for identical inputs.
- Import-time assertion that the decision-rank map is total.
- Golden-fixture parity across the Python reducer and `studio/app/analytics.mjs`,
  extended to the new fields.

Baseline before any change: 459 passed, 12 skipped, 15 subtests passed.

## Risks

- **The restructure touches the file the whole platform trusts.** Mitigated by
  characterization tests first, and by the table being a mechanical transposition
  of existing branches rather than a rewrite of their logic.
- **Payload growth in the statistics document.** Bounded by omitting
  all-ABSENT entries and by digesting coverage rather than listing it per event.
- **A coverage number read as a safety number.** Mitigated only by the limits
  section above being carried into the Studio surface, not just this document.

## Sequence

1. Characterization tests for `policy.evaluate`.
2. Check table; `evaluate()` becomes a loop. Tests stay green.
3. `EvaluationInput` optional fields; SDK routed through `evaluate()`; equivalence
   test.
4. `enforcementPoint`, `evaluatedProfile`, `CONTROL_COVERAGE_DECLARED`.
5. Statistics schema, reducer, Studio port, golden fixtures.
6. `strongest_decision` and `would_block`.
7. Mode composition investigation and `effectiveMode`.
8. Studio verification, full sweep, independent review, documentation.
