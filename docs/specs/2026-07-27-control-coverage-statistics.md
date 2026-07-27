# Control Coverage Statistics

Status: Plan 1 complete, Plan 2 not started
Date: 2026-07-27

## Problem

The platform's promotion loop is: design a multi-agent graph in Studio, observe
inter-actor traffic, read the statistics, promote a link from SHADOW to ENFORCE.
That loop reads a number it cannot justify, for two reasons.

### Three judgment engines that disagree

| Engine | Site | Checks | Reason-code namespace |
| --- | --- | --- | --- |
| MCP gateway | `policy.evaluate()` | 20 | `INTERLOCK-*`, `L1-*` |
| SDK | `sdk.py:148-157` | 4 | `INTERLOCK-*`, `L1-*` |
| A2A broker | `a2a.py:806-870` | 12 link + 5 boundary | `A2A-*` |

`policy.evaluate()` is the only one reached through `EvaluationInput`, and
`gateway.py:221` is its only construction site. Neither the SDK nor the A2A
broker calls it.

These are not in a subset relationship.

- `INTERLOCK-TAINTED-EXTERNAL-WRITE` is emitted only by the SDK and is unknown
  to the other two.
- M9 (destination allowlist, export volume) and M2 (definition state, digest
  pin) exist only in the gateway.
- Trust-boundary checks exist only in the A2A broker.
- Roughly ten checks are duplicated between the gateway and the broker under
  different names: `INTERLOCK-ACTOR-TYPE-DENIED` / `A2A-ACTOR-TYPE-DENIED`,
  `L1-M5-TOKEN-PASSTHROUGH` / `A2A-TOKEN-PASSTHROUGH`,
  `L1-M8-CREDENTIAL-DETECTED` / `A2A-CREDENTIAL-DETECTED`, and so on.

Seven of those duplicates are the *same predicate* over a differently named
credential object — `A2ASendContext.principal` and `CredentialClaims` carry the
same fields. Two differ substantively: the broker compares audience against
`target.identity` and resource against `a2a://{target.id}`, where the gateway
compares against `intent.expected_audience` and `intent.expected_resource`.

The consequence for statistics is that **no aggregate keyed on reason code is
comparable across paths**. Agent-to-agent traffic — the whole subject of a
multi-agent design — runs entirely through the broker, so the segment the
operator most wants to inspect is the one speaking a different language.

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

And a control means the same thing at every enforcement point, whatever string
that point emits into the ledger.

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

### 1. One check table, one profile per enforcement point

A check is declared once. An enforcement point selects which checks it runs and
what it calls them.

```python
class CheckScope(StrEnum):
    ACTOR    = "ACTOR"     # property of the target actor; same verdict for every caller
    PAYLOAD  = "PAYLOAD"   # property of the arguments or message
    PAIR     = "PAIR"      # genuinely about this source -> target link
    BOUNDARY = "BOUNDARY"  # about the trust-zone crossing, not the link


@dataclass(frozen=True, slots=True)
class Check:
    id: str                                          # canonical reason key
    scope: CheckScope
    armed: Callable[[LinkPolicy], bool]              # policy only — keeps the ABSENT set stable
    run: Callable[[LinkPolicy, CheckContext], Findings | None]


@dataclass(frozen=True, slots=True)
class Profile:
    enforcement_point: str                           # EnforcementPoint value; a str, see below
    checks: tuple[str, ...]                          # check ids this point runs
    reason_codes: Mapping[str, str]                  # reason key -> emitted reason code
```

Two details that look cosmetic and are not:

`reason_codes` is keyed on the **reason key a check emits**, not on the check id.
The two coincide for most checks and diverge for the ones that emit more than one
code: the data-class check emits `L1-M9-SENSITIVE-EGRESS` or
`INTERLOCK-DATA-CLASS-DENIED` depending on the class, and the definition-state
check forwards whatever `revision.reason_codes` carries. Keying on check id
cannot express those, and a profile that renames must map **every** key its
checks can produce — a missed key passes through unrenamed and puts a
gateway-namespace string on the broker's wire.

`enforcement_point` is a `str`, not the `EnforcementPoint` enum, because the enum
lives in `architecture.py` and importing it would close the cycle described in §3.

**Scale up** — a point gains a control by adding its id to that profile's tuple.
**Scale out** — a new enforcement point is a new `Profile`. Neither touches the
engine or any existing check.

`reason_codes` is what makes the merge non-breaking. The broker keeps emitting
`A2A-AUDIENCE-MISMATCH`; the gateway keeps emitting
`L1-M5-TOKEN-AUDIENCE-MISMATCH`. Ledger history, the `docs/05` L1-SIM test IDs,
and existing assertions all stay valid. The canonical check id is what
statistics aggregate on, so the same control correlates across paths without
anyone claiming the two implementations are byte-identical.

Where the predicates genuinely differ — audience and resource comparison targets
— the difference becomes a parameter of the check, resolved from `CheckContext`,
not a second check.

### 2. Three coverage states, and why two callables

- `armed(policy)` reads the policy only, and the profile decides membership, so
  neither depends on the individual invocation. A policy with
  `require_digest_pin=False` or an empty `allowed_purposes` has switched that
  control off; a profile that omits the check id never had it. Either way:
  **ABSENT**.

  Two things `armed` does **not** currently catch, both measured. First, a check
  id that bundles two independently-switchable controls: `armed` for
  `L1-M5-TOKEN-AUDIENCE-MISMATCH` is `require_audience or require_resource`, so
  with `require_audience=False`, `require_resource=True` and a wrong audience the
  check reports **RAN_CLEAN** — the audience control is off, the audience is
  wrong, and the statistic says the check ran and found nothing.
  `L1-M9-VOLUME-EXCEEDED` (`max_export_records or max_export_bytes`) is the same
  shape. Second, arming inputs the signature cannot reach at all: boundary
  switches (`require_identity`, `require_tenant_binding`), actor properties
  (`target.input_schema`, which `_input_schema` and `_message_parts_schema` gate
  on) and edge structure (`boundary is None`, which all five boundary checks gate
  on) are each constant for the link yet report INAPPLICABLE rather than ABSENT.
  See the open questions — these must be settled before the statistic ships.
- `run(context)` is per invocation:
  - `None` — armed, but this invocation did not engage it (**INAPPLICABLE**);
    no destinations were declared, or the intent expects no audience
  - `()` — **RAN_CLEAN**
  - non-empty — **RAN_FLAGGED**; `(reason_code, ControlDecision)` pairs

Because `armed` does not depend on the invocation, the ABSENT set is a function
of `(enforcementPoint, policyId, policyVersion)` and is declared once rather than
recorded per event.

`CheckScope` stops one actor-scoped failure from lighting up every link that
points at that actor. A tool whose definition has drifted is one finding on one
actor, not twelve findings on twelve edges. Consumers group by scope; the
reducer only carries it.

### 3. Normalized input

`EvaluationInput` is replaced by `CheckContext`, which all three points build:

| Field | Gateway | SDK | Broker |
| --- | --- | --- | --- |
| `source`, `target` | `ActorSpec` | `ActorSpec` | `architecture.actors[...]` |
| `credential` | `CredentialClaims \| None` | new `wrap()` argument | built from `context.principal` |
| `intent` | given | given | built from `context.purpose`, `context.data_classes` |
| `payload` | `arguments` | `arguments` | `message.to_dict()` |
| `payload_bytes` | `len(canonical_json(...))` | same | already computed |
| `revision` | `ToolRevision` | `None` | `None` |
| `boundary` | `None` | `None` | `architecture.boundary_for(edge)` |
| `relationship` | `policy.relationship` | `policy.relationship` | `edge.relationship` |
| `approval_valid` | computed | `False` | `False` |

`A2ASendContext.principal` maps field-for-field onto `CredentialClaims`
(`actor_id`→`actor`, plus `audience`, `resource`, `exchanged`,
`delegation_depth`), so the broker builds a real credential rather than a
special case.

With `revision=None` the M2 checks return `None` rather than passing, and schema
validation falls back to `ActorSpec.input_schema`.

At the SDK the M2 pair is **ABSENT, not INAPPLICABLE** — `SDK_PROFILE` omits both
ids. An earlier draft of this section said the opposite and called it deliberate;
that contradicted §2 above and the shipped code, and §2 is right. INAPPLICABLE is
a per-invocation fact — armed, but *this* call did not engage it. The SDK has no
`ToolRevision` on *any* call, so "no definition to pin" is a property of the
enforcement point, not of an invocation, and recording it per event would stamp a
constant onto every one. ABSENT is declared once per
`(enforcementPoint, policyId, policyVersion)`, which is exactly the right shape.

**Import cycle.** `architecture.py:13` imports `sdk`, and after unification `sdk`
imports `policy`, so `policy` importing `ArchitectureBoundary` from
`architecture` would close a cycle. `policy.py` therefore declares a
`typing.Protocol` naming only the boundary fields it reads
(`allowed_relationships`, `allowed_data_classes`, `denied_data_classes`,
`require_identity`, `require_tenant_binding`, `max_payload_bytes`, `mode`).
`ArchitectureBoundary` already satisfies it structurally; no change to
`architecture.py` and no runtime dependency.

### 4. Coverage on the wire

Two fields are added to `payload.control` on `CONTROL_EVALUATED`:

| Field | Value |
| --- | --- |
| `enforcementPoint` | `SDK` \| `MCP_GATEWAY` \| `A2A_BROKER` — the existing `EnforcementPoint` enum (`architecture.py:31-47`), currently computed at lint time and never reaching runtime |
| `evaluatedProfile` | `canonical_digest` of the check ids that actually ran on this invocation |

Both are short strings; coverage costs O(1) per event, not a list of twenty.

A new event type `CONTROL_COVERAGE_DECLARED` is appended the first time a digest
is seen:

```json
{
  "profileDigest": "…",
  "enforcementPoint": "A2A_BROKER",
  "policyId": "…",
  "policyVersion": "…",
  "armed": [{"id": "L1-M5-TOKEN-AUDIENCE-MISMATCH", "scope": "PAIR"}],
  "evaluated": ["L1-M5-TOKEN-AUDIENCE-MISMATCH"]
}
```

Check ids **are** the gateway reason strings — there is no second id namespace.
An earlier draft of this example used `"M5-AUDIENCE"`, which does not exist;
copying it would have invented one and `byCheck` would never have joined.

Note the ids on the wire are the *check* ids, which at the SDK and broker are not
the emitted reason codes: a denied D7 runs under check id
`INTERLOCK-DATA-CLASS-DENIED` while emitting `L1-M9-SENSITIVE-EGRESS` at the
gateway and `A2A-DATA-CLASS-DENIED` at the broker. Any join from coverage to
reason codes must go through `Profile.reason_codes`, never a string match.

The reducer derives the three states: in `evaluated` is RAN; in `armed` but not
`evaluated` is INAPPLICABLE; in the catalogue but not `armed` is ABSENT. The
catalogue is the union of all `armed` sets seen in the ledger, so the reducer
stays a pure function of the event stream and the Studio TypeScript port needs no
access to Python.

No separate `armedProfile` field: the armed set is a function of
`(enforcementPoint, policyId, policyVersion)`, all already on the event.

### 5. Statistics contract

Added to each partition in `schemas/security-statistics.schema.json`:

- **`byEdge`** — keyed by `(sourceActorId, targetActorId, policyId)`. All three
  are already in `InteractionRecord` (`analytics.py:46-91`); `target_actor_id` is
  currently used by no grouping. **No new instrumentation.** The graph permits
  several edges between one actor pair — `ArchitectureGraph.edges` is a tuple and
  uniqueness is enforced on edge ids only (`architecture.py:277,293`) — so the
  pair alone is not a key. `policyId` splits precisely where the armed set can
  differ. Studio holds the ArchitectureGraph and maps the triple to an edge label
  locally.
- **`byCheck`** — per canonical check id, carrying `scope` and counts for
  RAN_CLEAN, RAN_FLAGGED, INAPPLICABLE, ABSENT. This is the aggregate that now
  spans all three enforcement points.
- **`byEdge[].byCheck[]`** — the cross-tabulation, and the deliverable: on this
  segment, which controls applied and what happened. Entries ABSENT for every
  interaction on that edge are omitted to bound the payload.
- **`unattributed`** — interactions matching no declared edge, kept as an
  explicit bucket rather than dropped.

`byReasonCode` is retained; it remains the right view for "what fired", and it is
the only view that preserves the per-point wording.

The schema sets `additionalProperties: false` throughout, so every addition is a
synchronised change across the schema, `studio/app/analytics.mjs`, and the golden
fixtures in `schemas/fixtures/`. The existing byte-identical parity test
(`tests/test_analytics.py`) is the mechanism, but it does **not** cover these
fields yet — `byEdge`, `byCheck` and `unattributed` appear nowhere in the schema,
the reducer or the Studio port. Extending it is Plan 2's work, not something
already in place.

### 6. Ancillary correctness fixes

*Line references in this document point at `main`, the state being fixed, unless
marked otherwise. Where a symbol moved, the shipped location is given inline.*

**`strongest_decision`** ranked six of eleven `ControlDecision` values and fell
back to `order.get(item, 3)`. Five `LinkPolicy` fields — `secret_action`,
`new_destination_action`, `volume_action`, `destructive_write_action`,
`undeclared_side_effect_action` — are unconstrained `ControlDecision` values, so
the fallback was reachable by configuration: `CHALLENGE` and `DEGRADE` ranked
equal to `BLOCK`, and `BYPASSED` — which should be weakest — also ranked equal to
`BLOCK`. Because `max` is first-wins on a tie, **which check ran first decided
the emitted verdict**. A sixth path exists that the original analysis missed:
`architecture.py:1238` builds `new_destination_action` from an architecture
document with `ControlDecision(str(...))` and no validation, even though
`schemas/architecture.schema.json:159` already declares the four-member enum.

The rank map ships in `models.py`, not `policy.py`: it is a total function of
`ControlDecision`, so it belongs beside the enum where whoever adds a twelfth
member meets the map and the coverage check on one screen. `strongest_decision`
itself stays in `policy.py` and imports it.

Rank all eleven explicitly, drop the fallback, and **raise** at import time if the
map does not cover `ControlDecision` exactly. A twelfth value then fails on load
rather than being silently ranked mid-table. An `assert` will not do: `python -O`
strips it, and the guarantee would then be conditional on an optimisation flag.

Cover *totality* at import and *distinctness* behaviourally, not both at import.
Non-totality fails as an unhandled `KeyError` inside the enforcement path at first
use, so failing at load is strictly better. Non-injectivity produces a
running-but-wrong total order — fully observable, and precisely the defect class
this document exists to eliminate — so it belongs in a test that can name the
colliding pair. Raising on it at import would kill collection and destroy that
diagnostic.

`BYPASSED` ranks lowest — below `ALLOW`. `ERROR` ranks above `BLOCK` but **below**
`QUARANTINE`, not highest. FAIL_CLOSED only requires `ERROR > ALLOW`: at any rank
above `ALLOW`, every `!= ALLOW` predicate in `src/` denies. Ranking it above
`KILL` would buy nothing further and would cost `strongest_decision([KILL, ERROR])
== ERROR` — one check erroring erasing a definite `KILL` from the emitted
decision, so a consumer routing on it takes the "unknown, retry, page ops" path
instead of "terminate this agent." That is this document's own thesis inverted:
*we could not determine* made indistinguishable from, and stronger than, *we
determined the worst possible thing*. This is a deliberate severity judgement,
not a neutral consequence of making the map total.

Two members are ranked here without being defined anywhere. `BYPASSED` and
`ERROR` have no producer in `src/`, no docstring and no definition in this
document; they are reachable only through operator configuration of the five
`LinkPolicy` action fields. Plan 2 must define both before wiring any statistic
to them — see the open question in §11.

**`PolicyDecisionRecord.would_block`** — a mode-independent reading of whether the
policy objected, and the first-class source for `shadowWouldBlockCount`.
`permits_execution` keeps its name and semantics; its sole consumer is
`gateway.py:286` and its behaviour in SHADOW is correct by definition.

Derive the predicate **from the rank map** — `_DECISION_RANK[decision] >
_DECISION_RANK[ALLOW]` — not from a restatement of the rule. The obvious body,
`self.decision != ControlDecision.ALLOW`, is wrong: `BYPASSED` ranks below
`ALLOW`, so a bypassed control would report as "the policy found grounds to
block." Wiring `shadowWouldBlockCount` to that would put this document's own
pathology into the statistic it exists to make trustworthy. Deriving from the map
means a future member ranked below `ALLOW` inherits the right answer with no edit.

Note that `would_block` is the *only* one of six such predicates that gets this
right. `analytics.py:69` (`block_decision`, feeding `shadow_would_block` and
`shadowWouldBlockCount`), `sdk.py:189`, `gateway.py:259/315/530` and
`config_guard.py:412` all test `!= ALLOW` and therefore all disagree with
`would_block` on `BYPASSED`. Plan 2 inherits six predicates of the same shape
with two different answers, and must reconcile them rather than add a seventh.

### 7. Mode composition

`PolicyMode` is attached in two places, `edge.policy.mode` and `boundary.mode`,
and `a2a.py:616-619` shows the runtime rule:

```python
enforced = bool(
    (link_reasons and edge.policy.mode == PolicyMode.ENFORCE)
    or (boundary_reasons and boundary is not None and boundary.mode == PolicyMode.ENFORCE)
)
```

Neither mode wins. **Each reason set is enforced against its own mode**: link
findings answer to the edge, boundary findings answer to the boundary. This is
already correct behaviour and is not being changed; it is written down here
because it was previously discoverable only by reading the broker, and because
`CheckScope.BOUNDARY` is what lets the unified engine preserve it.

`CONTROL_EVALUATED` records both modes and the resulting `actualEnforced` so no
operator has to compose them from memory.

## Out of scope

- **False-negative measurement.** Requires an external corpus. Separate work.
- **Undeclared-path detection.** The `unattributed` bucket only. Proper handling
  belongs to `compare_observed_runtime` (`architecture.py:1071-1091`), which
  already finds observed interactions with no declared edge. Wiring it into the
  statistics is a follow-on cycle.
- **`ArchitectureEdge.id` propagation to runtime events.** The
  `(source, target, policyId)` triple is sufficient.
- **Orchestration workflow steps.** `WORKFLOW_*` events carry no `interaction_id`
  (`orchestration.py:602-633`) and are excluded from the reducer. Unchanged.
- **A2A operational errors.** The seventeen `A2AError` codes that are not policy
  findings — `A2A-TASK-NOT-FOUND`, `A2A-IDEMPOTENCY-CONFLICT`,
  `A2A-HANDLER-FAILED` and similar — stay where they are. Only the twelve link
  and five boundary findings move into the table.

## Testing

**Characterization tests land before any restructure.** Of the eighteen reason
codes `policy.py` emits, ten appear in no test file:
`INTERLOCK-ACTOR-TYPE-DENIED`, `INTERLOCK-APPROVAL-REQUIRED`,
`INTERLOCK-DESTRUCTIVE-WRITE`, `INTERLOCK-INPUT-SCHEMA-INVALID`,
`INTERLOCK-PURPOSE-DENIED`, `L1-M2-DEFINITION-NOT-ACTIVE`,
`L1-M5-CREDENTIAL-MISSING`, `L1-M5-DELEGATION-DEPTH`,
`L1-M5-TOKEN-ACTOR-MISMATCH`, `L1-M9-SENSITIVE-EGRESS`. Four of the six M5
credential checks are unprotected.

Of the seventeen A2A policy findings, fifteen appear in no test file — only
`A2A-AUDIENCE-MISMATCH` and `A2A-BOUNDARY-DATA-CLASS-DENIED` are asserted
anywhere.

Twenty-five reason codes therefore needed characterization before the merge. This
is a string-presence proxy, not line coverage — it bounds the risk from below —
but restructuring three judgment engines against it as-is would have meant a
broken check passing 459 green tests.

**Everything above this line describes the state before Plan 1 and is retained as
the record of why it was necessary. It is no longer true.** All twenty-five are
characterized; the suite is now 503 passed / 12 skipped / 72 subtests on the
pytest path and `Ran 515, OK` on the CI `unittest` path.

The characterization test is one table per engine: each reason code with a
triggering input and a non-triggering input. After the merge the same tables
assert the three coverage states, since the non-triggering cases distinguish
INAPPLICABLE from RAN_CLEAN.

Additional tests:

- Verdict equivalence across enforcement points for the checks they share, given
  equivalent inputs.
- Reason-code stability: each profile emits exactly the strings it emitted before
  the merge.
- Import-time assertion that the decision-rank map is total.
- Golden-fixture parity between the Python reducer and `studio/app/analytics.mjs`,
  extended to the new fields.

Baseline before any change: 459 passed, 12 skipped, 15 subtests passed — measured
with the optional extras installed. A fresh checkout without them under-collects:
run `uv sync --extra jwt`, or use the CI path
(`PYTHONPATH=src:tests python3 -m unittest discover -s tests`), which is
unaffected.

## Risks

- **Three judgment paths change at once.** Mitigated by characterization first,
  by profiles preserving every emitted reason code, and by the merge being a
  transposition of existing predicates rather than a rewrite of their logic.
- **Two predicates genuinely differ** (audience, resource). These are the only
  places where transposition is not mechanical and they get dedicated tests.
- **Payload growth in the statistics document.** Bounded by omitting all-ABSENT
  entries and by digesting coverage rather than listing it per event.
- **A coverage number read as a safety number.** Mitigated only by the limits
  section being carried into the Studio surface, not just this document.

## Open questions for Plan 2

These surfaced during Plan 1 and are recorded here because Plan 1 could not
settle them without shipping an undocumented decision.

- **What does `BYPASSED` mean?** It has no producer in `src/`, no docstring and
  no definition here, yet Plan 1 ranks it lowest. Everywhere else this codebase
  treats a bypass as an alarm: `RuntimeGraphDiff.control_bypass_interactions`
  makes a graph *not clean* (`architecture.py:1045`) and
  `analytics.partial_or_bypass` counts it as an anomaly. At rank 0 it is
  annihilated by every other member, so a ledger of "one control bypassed, the
  rest allowed" reduces to plain `ALLOW` — *the control was bypassed* becomes
  indistinguishable from *the control ran and allowed*, which is verbatim the
  defect class this document exists to eliminate. The underlying problem is that
  "skipped" and "ran clean" are not weaker and stronger versions of one thing;
  they are different axes, and forcing them into one total order is lossy in the
  under-reporting direction. Coverage is already modelled as its own channel
  here — `BYPASSED` probably belongs there rather than as a decision value.
  Settle this before wiring `shadowWouldBlockCount`, or that statistic silently
  under-counts exactly the interactions where a control was skipped.
- **`would_block` and `permits_execution` disagree on `BYPASSED`** — the former
  says "no grounds to block", the latter denies execution under ENFORCE. Both are
  defensible in isolation and the pair is fail-closed, but it is undocumented and
  falls straight out of the previous question.
- **Six `!= ALLOW` predicates, two answers.** See §6. Reconcile; do not add a
  seventh.
- **`ActorSpec.data_access` has no enforcement reader — partly mitigated, and the
  residual is measured.** The merge moved the data-class judgement onto the link
  policy's `allowed`/`denied_data_classes`; before it, `sdk.py` judged against the
  *actor's* grant. Different subjects, so a control change rather than a rename,
  and **bidirectional**: over 4,096 `(grant, allowed, intent)` combinations run
  through the real SDK at both revisions, 671 cells went denied→allowed (control
  loss) and 671 allowed→denied (new strictness on *declared* traffic).

  The remedy shipped is the design-time lint `ARCH-DATA-CLASS-EXCEEDS-ACTOR`
  (`edge.policy.allowed_data_classes ⊆ target.data_access`), chosen over a runtime
  change so nothing in the enforcement path moves.

  **What it closes, measured — and note this is the opposite of what the proposal
  claimed.** Restricted to lint-clean cells: **control loss 0, unreachable**;
  **new strictness 369 of 1,296, still fully reachable**. Lint-clean
  counterexample: `grant={D1,D2,D3,D7}`, `allowed={D2,D3,D7}`, `intent={D1}` →
  `main` ALLOW, HEAD BLOCK. The commit message of `ef19f88` carries the inverted
  claim; this paragraph supersedes it. The outcome is nonetheless the better one —
  the security-relevant half is the half that closes, and the surviving strictness
  is the SDK converging on the gateway's own semantics.

  **What it cannot reach.** The rule skips actors with an empty `data_access`,
  because the schema makes the field optional and `_parse_node` defaults it to
  `frozenset()` while edge `allowedDataClasses` defaults *non-empty* — so treating
  empty as a grant fires on every actor that omits it. That population is **61% of
  the measured control-loss cases**, including 102 of the 278 ENFORCE-mode
  fail-open flips. Worse, `studio/app/page.tsx:1106` hardcodes `dataAccess: []`
  and is the **only occurrence of the field in the entire `studio/` tree**, so the
  UI cannot express the input the rule reads and every Studio-authored graph is
  unprotected. Plan 2 should treat this as an authoring-surface gap, not a lint
  gap: there is currently no way for an author to say "holds nothing," while
  `docs/02-developer-framework-design.md` §3.1 lists `dataAccess` as a required
  field.
- **`LinkPolicy` validates nothing at construction.** It has no `__post_init__`,
  so `allowed_data_classes` and `denied_data_classes` may overlap; only
  `ArchitectureBoundary` checks that disjointness. Found via a generated security
  test that a lint-clean graph could still fail.
- **The action fields accept members the schema forbids.**
  `schemas/architecture.schema.json:159` already declares
  `{"enum": ["ALLOW", "BLOCK", "HOLD", "QUARANTINE"]}` for `newDestinationAction`,
  but that schema is referenced only from `tests/test_studio_compile.py` and the
  Studio canvas — nothing in `src/` enforces it, and `architecture.py:1238` does
  an unvalidated `ControlDecision(str(...))`. Constraining the five `LinkPolicy`
  action fields to that four-member subset would have made Plan 1's tie-break
  unreachable in the first place, and is the general fix for this bug class.

### Carried into Plan 2

Plan 1's execution ledger
(`.superpowers/sdd/2026-07-27-unified-judgment-engine/progress.md`) has the full
reasoning and measurements. These are the items Plan 2 cannot start without.

**Blocking — the coverage states are not yet trustworthy.** `run_checks` returns
`ran`, and all three call sites in `src/` discard it, so within Plan 1 the three
states have zero observable effect. Wiring telemetry to `ran` as it stands
under-reports:

1. **A check whose subject is empty must return `None` (INAPPLICABLE), never `()`
   (RAN_CLEAN).** State the rule once and audit all 26 against it rather than
   patching case by case. Three known instances: `_data_classes` and
   `_boundary_data_classes` (empty `data_classes`), and `_secret`, whose
   `contains_secret` returns `False` vacuously for an argument map holding no
   strings — that one is in all three profiles, and `clean_case()` itself, the
   fixture used to prove the same bug in `_input_schema`, demonstrates it.
   Weaker fourth: `_volume` on a zero estimate.
2. **`armed`'s blind spots are four distinct shapes**, only one of which a wider
   signature fixes. See §2. Note the spec's own
   `(enforcementPoint, policyId, policyVersion)` ABSENT key cannot express actor
   properties or edge structure.
3. **Split the two multi-control check ids** — `L1-M5-TOKEN-AUDIENCE-MISMATCH`
   and `L1-M9-VOLUME-EXCEEDED` — or accept that those two `byCheck` rows are
   unreliable.
4. **Pick one coverage convention for the three side-effect checks.**
   `_tainted_external_write` returns `None` for a non-matching side effect while
   `_destructive_write` and `_approval` return `()`. Read-only traffic would show
   one at ~100% RAN_CLEAN (a working control) and the other at ~100% INAPPLICABLE
   — same situation, opposite statistic.
5. **The reducer must not read a missing `CONTROL_EVALUATED` as clean.**
6. **Two A2A controls are unsatisfiable** and would count as passing:
   `A2A-BOUNDARY-TENANT-REQUIRED` (`A2APrincipal.__post_init__` rejects an empty
   tenant first) and `A2A-PAYLOAD-INVALID` (`A2AMessage.__post_init__` requires
   at least one part, so `payload_bytes >= 2`).
7. **`assertNotIn(id, ran)` passes vacuously** if that id is dropped from the
   profile entirely — audit profile membership, not just the predicate.

**Reconcile before adding consumers.** Six predicates test `!= ALLOW` and so
disagree with `would_block` on `BYPASSED`: `analytics.py:69`, `sdk.py:189`,
`gateway.py:259/315/530`, `config_guard.py:412`. Separately, `analytics.py:147`
picks `chosen` as the first control matching the strongest decision and takes
`policyId`, `mode` and `actualEnforced` from it — **Plan 1's re-ranking already
moves shipped statistics through that path, untested and with no fixture.**

**Known and accepted.** `_definition_state` forwards arbitrary registry strings
as reason keys, an unbounded key set that `Profile.reason_codes` renames blindly.
`A2APrincipal.authenticated` still defaults `True` and `for_edge` does not accept
it, so the value `_identity_binding` reads is fail-open on the live path.
`ArchitectureLinter._lint_boundaries` skips three CRITICAL checks for same-zone
edges that the broker enforces unconditionally. `_message_parts_schema` couples
`policy.py` to the A2A wire shape and its multi-part arity branch is uncovered in
the fail-open direction; the remedy is a typed projection on `CheckContext`, not
a Protocol.

**The static emitted-key audit is weaker than it reads.** It covers
`A2A_PROFILE` only, and its blindness has three structural causes: the walk's
`isinstance` ladder terminates on any type outside a fixed set; `co_names`
resolves only against module globals, so function-local imports and
`__defaults__` are invisible; and runtime string construction escapes entirely.
Twenty distinct mutants pass. Several are ordinary refactors — most notably a
`StrEnum` of reason keys, which is arguably the most idiomatic possible spelling
of exactly the hoist the guard exists to catch, and which `policy.py` already
uses for `CheckScope`. `_REASON_KEY` is also a three-namespace allowlist against
six live namespaces. This does not affect Plan 1, whose 26 checks are all
correctly audited. **It matters because Plan 2 adds checks.**

## Sequence

Delivered as two plans. The first produces a working, fully tested unified engine;
the second adds the telemetry that depends on the check ids the first defines.

**Plan 1 — unified judgment engine** *(complete)*

1. Characterization tests for the twenty-five uncovered reason codes.
2. `Check`, `Profile`, `CheckScope`, `CheckContext`; boundary `Protocol`.
3. Gateway checks transposed into the table; `evaluate()` becomes a loop.
4. SDK routed through the table via `Profile(SDK)`.
5. Broker routed through the table via `Profile(A2A_BROKER)`.
6. `strongest_decision` and `would_block`.

Plan 1 was drafted as "no observable behaviour change." It is not, and the
differences are deliberate rather than accidental. Recorded here because the
final review found them only by differencing against `main` — every per-task
differential compared one task to the previous one, so a change introduced in a
later task was never measured against the starting point.

- **The MCP gateway gained a blocking control.** `INTERLOCK-TAINTED-EXTERNAL-WRITE`
  existed only in `sdk.py`; promoting it to a shared check put it in
  `GATEWAY_PROFILE`. It is production-reachable — `mcp_transport.py:148` forwards
  caller-supplied `taint_labels` into the intent — so a tainted external write
  that used to pass at the gateway now blocks.
- **The SDK gained thirteen reason codes**, the M5/M8/M9 families it never ran.
  That was the point of the merge: the SDK checked four things while the gateway
  checked twenty, and a statistic spanning both was not comparable.
- **The SDK's execution predicate now honours the operator's action fields.** It
  previously hard-coded `BLOCK` for its findings; it now takes the configured
  decision, so `secret_action=ALLOW` and friends genuinely disable enforcement.
  Net across the measured grid: 2,075 newly blocked, 498 newly executed.
- **`CredentialClaims.authenticated` now defaults `False`.** `True` was fail-open:
  it made "nobody authenticated this" read as "authentication passed."
- **The `strongest_decision` re-ranking** changes the emitted decision for
  configurations that mix severities — 31 of 110 ordered pairs, plus 3 more from
  moving `ERROR`. No reason code moves in content or order at any point.

Reason codes themselves held: zero movement at the gateway across 32,610 cases,
and zero divergence at the broker across the 12,871 reachable cases of an 18,402
grid (the remaining 5,531 require an empty `ActorSpec.identity`, which
`__post_init__` forbids).

Two changes the branch made **accidentally** and has since reverted. Both were
found only by differencing against `main`, and both are recorded because the way
they escaped matters more than the fixes.

- **The SDK began emitting `L1-M9-SENSITIVE-EGRESS`** where it had always emitted
  `INTERLOCK-DATA-CLASS-DENIED` — a pre-existing control changing its emitted
  string, the one thing this work forbids. It escaped because
  `SDK_PROFILE.reason_codes` **was** `GATEWAY_PROFILE.reason_codes`, the same
  object, so the divergence could not even be expressed; and because the static
  key audit covered `A2A_PROFILE` alone, having been written for a hazard that was
  routed and caught on that engine while the identical one on the SDK went
  unwatched. The SDK now owns its map, and the audit covers every profile and all
  26 checks.
- **A malformed `allowed_domains` entry raised `UnicodeError` out of `wrap()`**
  after two ledger events and before `CONTROL_EVALUATED`, leaving 1,349
  interactions with no control record at all — this document's own defect class,
  newly created in production, filed at the time as a minor because nobody
  measured which way it failed. `_canonical_domains` now drops what does not
  encode, mirroring `_canonical_destinations`. The result is better than either
  revision: `main` denied *by crashing* (2,459 cases, firing even where no egress
  was declared, which is not a control), and the fix denies by decision with zero
  new silent permits on either surface.

A residual is accepted: a malformed allowlist entry has **no runtime signal** until
a destination is declared. Returning `()` there would manufacture the
empty-subject `RAN_CLEAN` this document exists to eliminate. It belongs in the
linter as an `allowedDomains` well-formedness rule.

**Plan 2 — coverage telemetry and statistics**

7. `enforcementPoint`, `evaluatedProfile`, `CONTROL_COVERAGE_DECLARED`.
8. Statistics schema, reducer, Studio port, golden fixtures.
9. Studio verification, full sweep, independent review, documentation.
