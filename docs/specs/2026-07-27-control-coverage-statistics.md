# Control Coverage Statistics

Status: Plan 1 and Plan 2 complete. Remaining open questions are listed and none blocks the
statistic; see the two sections at the end.
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

**A third field, which this section originally omitted.** The reducer was to
derive RAN from `evaluated` -- but RAN splits into RAN_CLEAN and RAN_FLAGGED, and
nothing on the wire said which. Joining `reasonCodes` back to check ids is not
available: `Profile.reason_codes` is not injective, since
`L1-M9-SENSITIVE-EGRESS` and `INTERLOCK-DATA-CLASS-DENIED` both reach
`A2A-DATA-CLASS-DENIED`, so a code cannot name the check that produced it.
`payload.control.flaggedChecks` therefore carries check ids directly. It costs
O(flagged), which is zero on the overwhelming majority of events.

**The digest covers the whole declaration body, not only `evaluated`.** Two links
can run the same checks with different sets armed -- one arming a control that
stays INAPPLICABLE -- and keying on the evaluated set alone would let whichever
declaration was seen first speak for both. Since the digest is over everything the
payload says, a reader can recompute it from the event, and a producer emitting
two different bodies under one digest is not expressible.

**"Once per digest", not "once per link" -- and the dedup key is not the digest.**
`evaluated` is per invocation: an argument map holding no strings gives the secret
scan no subject, and that is a different coverage shape from one that does. Distinct
shapes are far fewer than invocations, which is the compression; the set of shapes
seen is capped and cleared rather than left to grow for the life of the process,
since a repeat declaration is a no-op for the reducer.

The dedup key is `(tenant_id, environment, data_source, digest)`. `tenant_id` is the
load-bearing part: it is a per-invocation argument while the seen-set lives on the
enforcement point, and both ledgers filter declarations by tenant. Keyed on the
digest alone, the first tenant through a link declares and every other tenant's
`CONTROL_EVALUATED` then names a digest absent from its own stream -- **measured on
the real gateway: tenant A got 16 `byCheck` rows and tenant B got none**, a
dashboard reporting that no control ever looked at a fully instrumented tenant. The
key is recorded only after the append returns, so one transient sink failure cannot
suppress a declaration for the life of the process while every control record keeps
referencing its digest. A restart re-declares, deliberately.

**The declaration carries no `interaction_id`.** What is armed belongs to the
link. Stamping it with one call's id would file a link-level fact under a single
interaction, and `reduce_interactions` -- which groups on `interaction_id` -- would
then have to special-case it out again.

The reducer derives the four states: in `flaggedChecks` is RAN_FLAGGED; otherwise
in `evaluated` is RAN_CLEAN; in `armed` but not `evaluated` is INAPPLICABLE; in the
catalogue but not `armed` is ABSENT. The catalogue is the union of all `armed` sets
seen in the ledger, so the reducer stays a pure function of the event stream and
the Studio TypeScript port needs no access to Python. A digest the stream never
declared contributes nothing: missing evidence is not a clean bill.

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
- **`unattributed`** — interactions that cannot be placed on the byEdge grid,
  kept as an explicit bucket rather than dropped. **Narrower than this section
  first said**, and necessarily so: "matching no *declared* edge" needs the
  ArchitectureGraph, which the reducer does not have and must not have, or the
  Studio port stops being a pure function of the event stream. What the reducer
  can see is an incomplete triple -- no target actor, or no `CONTROL_EVALUATED`
  and therefore no `policyId`. The `dataSource` filter applies to declarations as
  well as to interactions, or a PRODUCTION window unions the catalogue of every
  SIMULATION and TEST link and reports each of their checks ABSENT across
  production traffic -- coverage gaps that do not exist, in the one number this
  document exists to make trustworthy. Detecting traffic on an *undeclared* edge remains
  `compare_observed_runtime`'s job, as **Out of scope** already says.
- **`noControlRecordCount`** in every `counters` block. An interaction with no
  `CONTROL_EVALUATED` reduces to `ALLOW` with an empty reason list, which is
  shape-identical to a control that ran and allowed. It is a counter rather than
  only a partition-level bucket because the blind spot is per row: `byActor`
  reading "40 calls, 0 blocked" must not hide that nothing looked at them.

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
`permits_execution` keeps its name; its consumer is `gateway.py:286` and its
behaviour in SHADOW is correct by definition. Its *body* did not survive Plan 1
unamended — see §6a, which is what happens when the ranking below is read as an
execution permit.

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

**Amended by §6a — five, not six.** `sdk.py:189` has left the list. It was the
one of the six that *gated execution*, and an execution gate is not a `!= ALLOW`
question at all; it now calls `policy.execution_permitted`. The five that remain
are `analytics.py:69`, `gateway.py:259/315/530` and `config_guard.py:412`, and
none of them decides whether a call runs.

**Amended again by §6c — and the summary of those five was wrong about one of
them.** They do not all "set severity, outcome or log level". `gateway.py:259`
is an *admission* gate: `_config_preflight` returns the config guard's verdict
only when it is not `ALLOW`, so that predicate decides whether a second decision
source reaches the record at all. It is fail-closed in the direction that matters
— any sub-`ALLOW` member is admitted, `BYPASSED` included — but it is the one of
the five whose answer changes what the record contains rather than how it is
labelled, and §6c is what stops that admission from widening a permit.
`gateway.py:315` sets the security outcome, `gateway.py:530` the event severity,
`config_guard.py:412` the config event's severity, and `analytics.py:69` feeds
the block counters — see §6c for a second, independent reason that last one must
change.

### 6a. Execution permission is aggregated separately from severity

*Added after Plan 1 shipped, closing a High finding from an independent review.*

Ranking `BYPASSED` below `ALLOW` is right for severity and wrong as an execution
permit, and §6 conflated the two. `max` over `_DECISION_RANK` annihilates rank 0,
so `strongest_decision([ALLOW, BYPASSED])` is `ALLOW`; reading the permit off that
reduction meant `LinkPolicy(mode=ENFORCE, secret_action=ALLOW,
undeclared_side_effect_action=BYPASSED)` **executed** on arguments carrying an AWS
key and an undeclared side effect. `main` hard-coded `BLOCK` whenever its
undeclared-side-effect branch fired, so that configuration was strictly less safe
than the engine this table replaced. `BYPASSED` *alone* was already refused and
pinned as refused; it became permission only in company, which is why the pin held
and the hole was still open.

`_DECISION_RANK` does not change — `would_block` and Plan 2's coverage axis are
built on it. Severity and permission are different aggregations over the same
findings, and one reduction cannot answer both:

```python
permitted = all(decision == ControlDecision.ALLOW for decision in decisions)
```

`policy.execution_permitted` computes it. `sdk.py` gates on it directly.
`evaluate()` carries it onto `PolicyDecisionRecord.execution_permitted`, because
the gateway gates from the record and `decision` cannot express it.
`permits_execution` **ANDs** the new field with the existing `decision == ALLOW`,
so the field can only ever narrow a permit and a record built without it behaves
exactly as it did before. `strongest_decision` still supplies the emitted
`decision`: a denied invocation can therefore record `ALLOW`, which is correct —
the two answer different questions — and no reason code moves in content or order.

Exactly one class of configuration changes: findings containing at least one
`BYPASSED` and at least one `ALLOW` and nothing stronger. Every other multiset
already agreed, because `BYPASSED` is the only member ranked below `ALLOW`.

This does not settle §11's *what does `BYPASSED` mean*. It stops an undefined
verdict from granting permission while that question stays open.

### 6b. The M5 presence check reads authentication, not object identity

*Added in the same pass, closing the review's other High finding.*

`CredentialClaims.authenticated` was introduced by Plan 1 as a fail-closed
default (see the changes-vs-`main` list) and then read by the A2A broker only.
Every other field on the record is caller-supplied, so the gateway's and the SDK's
M5 checks — presence, then equality between self-asserted fields — passed on a
credential nobody had verified. Concretely at the SDK: no credential blocked with
`L1-M5-CREDENTIAL-MISSING`, while a forged one (attacker-chosen issuer, `actor`
set to the source id, `audience` set to what the intent expects) **executed**, with
all five M5 checks in `ran` and an empty reason list — *checked and clean*.
Presenting a forged credential was strictly better for an attacker than presenting
none.

`_credential_missing` now requires `credential is not None and
credential.authenticated`. **No new reason code**: `L1-M5-CREDENTIAL-MISSING`
carries the unverified case, and carrying it is the remedy rather than a
compromise, because the two cases reaching the same verdict under the same code is
exactly what removes the asymmetry. To M5, an unverified claims blob is not a
credential that is present.

The check is shared, so this lands at the gateway as well as the SDK. At the
gateway it closes a weakness inherited from `main`, which had no `authenticated`
field at all; at the SDK it closes one Plan 1 created, by giving `wrap()` M5 checks
that read only self-asserted fields.

**Corrected: the coverage claim held for this check and not for its family.** The
sentence that stood here — "the three coverage states stay honest and the
unverified case is `RAN_FLAGGED`" — was true of `_credential_missing` alone. Its
four siblings (`_token_passthrough`, `_token_audience`, `_token_actor`,
`_delegation_depth`) still keyed on `credential is None`, each deferring to a
definition that had just changed underneath it, so the fix *widened* the
asymmetry it was closing: an absent credential left those four INAPPLICABLE while
a forged one made them `RAN_CLEAN`, and the forgery therefore read as **better
examined** than the absence in the coverage channel. See §6d.

The only producer in `src/` that legitimately sets the flag is
`MCPAuthorizationCodeTokenClient.exchange` (`mcp_oauth.py`), which runs the claims
verifier first. `A2APrincipal.authenticated` still defaults `True` — see *Known and
accepted* — but that value reaches `_identity_binding` only, on `A2A_PROFILE`,
which does not carry `L1-M5-CREDENTIAL-MISSING`.

### 6c. The permit crosses the merge site, and the ledger records it

*Added after §6a shipped, closing two findings from the same review pass.*

**The merge site.** `evaluate()` is not the gateway's only decision source.
`gateway.py:236-240` merges the config guard's verdict into the finished record
with `replace(...)`, updating `decision` and `reason_codes` — and, before this
change, not `execution_permitted`. That is §6a's defect verbatim at the one place
a decision is composed outside `evaluate()`: a config verdict of `BYPASSED`
merged into an `ALLOW` record produced `decision = ALLOW`,
`execution_permitted = True`, `permits_execution = True`, and the connector ran.

The safety that held in practice was not structural. It rested on
`ConfigGuard.check_runtime` (`config_guard.py:386`) happening to emit
`QUARANTINE` for drift and nothing ranked below `ALLOW` — a fact about a
different module, asserted nowhere, and false for any future producer. The merge
now ANDs `policy.execution_permitted` over the merged verdict, so a config
verdict can only ever *narrow* the permit. It is deliberately **not** written as
`config_decision.decision != ALLOW` and deliberately does **not** lean on
`_config_preflight` already filtering `ALLOW`: relying on the filter is the same
unasserted cross-module fact one line further up.

`tests/test_execution_permit.py` pins it with a duck-typed config guard that
returns each `ControlDecision` in turn, so the property is a property of the
merge and not of today's producer, and with a source-level audit that fails on
any `replace(...)` rewriting a decision record without carrying the permit.

**The ledger.** §6a left the control record self-contradictory. On its own
reproduction the call is denied and `SECURITY_OUTCOME_SET` records `BLOCKED`,
while `CONTROL_EVALUATED` records `decision: "ALLOW", actualEnforced: true` — and
the payload carried nothing that said the invocation was refused. Before §6a that
configuration executed, so `ALLOW`/`SUCCEEDED` was consistent; the fix created a
record no reader can reconcile. Both shared enforcement points now emit
`control.executionPermitted` beside `actualEnforced`. Purely additive: no reason
code moves, and a reader that does not know the key sees what it saw before. The
A2A broker does not emit it — it derives `decision` from `reasons` and never
produces a sub-`ALLOW` verdict, so its record was never contradictory, and a
reducer must read a missing key as `true`, matching
`PolicyDecisionRecord.execution_permitted`'s default.

**What Plan 2 had to do, because `analytics.py` was outside this plan's write
set — done.** The ledger carried the evidence and the reducer ignored it. On the
reproduction `summarize_security_statistics` reported `blockDecisionCount: 0`,
`enforcedBlockCount: 0`, `shadowWouldBlockCount: 0` for a real enforced block;
the identical scenario with plain `BLOCK` actions reported `1 / 1 / 0`. All five
edits below shipped, and fixture interaction `ia-7` is that reproduction: an
`ALLOW` decision with `executionPermitted: false`, an enforcement
`ACTION_EXECUTED`, no connector attempt, outcome `BLOCKED`. It now reduces to
`blockDecision` and `enforcedBlock`, and reverting either language's predicate
fails the golden contract test.

1. `InteractionRecord` gains an `execution_permitted` field, reduced as the AND
   of `control.executionPermitted` over every `CONTROL_EVALUATED` in the
   interaction, **defaulting `True` when the key is absent** so A2A records and
   every event written before this change are unaffected.
2. `analytics.py:69` `block_decision` becomes
   `decision != ALLOW or not execution_permitted`. `enforced_block` and
   `shadow_would_block` are derived from it and need no further edit. This is the
   same predicate §6 already flags as disagreeing with `would_block` on
   `BYPASSED`; the two reasons are independent and one change settles both.
3. `studio/app/analytics.mjs:158-161` mirrors it, plus the `actualEnforced`
   typedef in `analytics.mjs:23` and `analytics.d.ts:18` — the offline importer
   must produce byte-identical statistics, which is a golden contract test on
   both sides.
4. `schemas/security-statistics.schema.json:132,137` describes both counters as
   "Non-ALLOW decisions"; that wording stops being accurate the moment (2) lands.
5. The shared fixture pair `schemas/fixtures/analytics-events.json` /
   `analytics-statistics.json` needs a row carrying a denied permit under an
   `ALLOW` decision, or the parity test cannot see the new field at all.

**A sixth edit, found while making the third.** `studio/app/analytics.mjs`
carried its own six-member `DECISION_RANK` — `ALLOW < SANITIZE < HOLD < BLOCK <
QUARANTINE < KILL`, the map as it stood before Plan 1 — and its `controlDecision`
fails unknown strings closed to `BLOCK`. So the five members Plan 1 added or
moved (`BYPASSED`, `DEGRADE`, `CHALLENGE`, `REVOKE`, `ERROR`) all collapsed to
`BLOCK` there while Python ranked each distinctly: `BYPASSED` below `ALLOW` on
one side and above it on the other, and `strongestDecision` picking a different
`chosen` control, so `policyId` and `mode` came off the wrong event. The
byte-identical claim was false for any ledger carrying one of the five, and the
golden fixture carried none of them. The map now mirrors `models._DECISION_RANK`
member for member, and fixture interaction `ia-8` straddles it with a `CHALLENGE`
and a `HOLD` control under different policy ids — Python picks `HOLD`, the old
map picked whichever came first. This is the fixture the "reconcile before adding
consumers" note below says `analytics.py:147` never had.

### 6d. The M5 family shares one definition of a usable credential

*Added in the same pass, closing the asymmetry §6b widened.*

`_usable_credential(credential)` — presented, and marked `authenticated` by a
producer that ran a verifier — is now the single definition the whole M5 family
reads. The four comparison checks return `None` (INAPPLICABLE) when it is false:
on a credential nobody verified, `actor`, `audience`, `resource`,
`delegation_depth` and `exchanged` are all attacker-chosen, so those checks can
only compare a forgery against itself, and reporting that as `RAN_CLEAN` is the
"checked and clean" lie this document exists to eliminate. Absence and forgery now
produce identical coverage vectors.

Deferring is only honest if somebody still owns the verdict, so
`_credential_missing` was widened to own it wherever a credential is presented,
not only when the intent named an audience or resource. Without that half, a
forged credential under an intent naming neither would have been refused solely
by whichever sibling its attacker-chosen fields happened to trip — which is the
attacker declining to set a field, not a control — and the coverage fix would have
handed back a permit. `A2A_PROFILE` does not carry `L1-M5-CREDENTIAL-MISSING`;
there `_identity_binding` owns it and already flagged an unauthenticated
credential, so it does not defer. `tests/test_check_table.py` asserts per profile
that an unusable credential still emits a code, rather than assuming the
cross-profile fact.

**No new reason code and no code renamed or reordered.** What does change is which
code an unverified credential trips: `L1-M5-CREDENTIAL-MISSING` now, in place of
whichever sibling the forged fields happened to hit. That is the point — the
family reaches one verdict for one condition — and the invocation is denied either
way.

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
- **Six `!= ALLOW` predicates, two answers — now four, and one of the four grew a
  second disjunct.** See §6, §6a and §6c.
  `sdk.py` left the list by becoming an explicit execution-permit aggregate, and
  `analytics.py` left it by reading the permit alongside the decision. The four
  that remain are `gateway.py:273` (admits the config guard's verdict into the
  record), `gateway.py:329` (outcome label) and `config_guard.py:412` (severity
  label); none of them gates execution. The gateway's own `CONTROL_EVALUATED`
  severity now reads `decision != ALLOW or not execution_permitted`, matching
  `block_decision` -- severity is what the alerting path and every
  `severity >= HIGH` query read, and keyed on the decision alone that column said
  `INFO` for an invocation the statistics count as an enforced block. Reconcile
  the rest; do not add a fifth.
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

**Blocking — the coverage states were not trustworthy. All eight are closed;
what each one turned out to require is recorded beside it.** `run_checks` returned
`ran` and all three call sites in `src/` discarded it, so within Plan 1 the three
states had zero observable effect. Wiring telemetry to `ran` as it stood would have
under-reported:

1. ~~**A check whose subject is empty must return `None`.**~~ **Done.** The rule is
   stated once in `EmptySubjectTests` and every case is asserted with its non-empty
   twin beside it, so the audit also fails if a check stops running when it should.
   All four instances were real. `_secret` needed a new `has_scannable_text` in
   `security.py`: `contains_secret` answers a security question and must stay a
   plain bool for `sanitize_secrets`' callers, so the traversal is mirrored rather
   than folded in. The fourth was not weak — `InvocationIntent` estimates **zero
   bytes** by default, so out of the box a link capping bytes had a size control
   reporting a clean pass over a size nobody supplied, on every call.
2. ~~**`armed`'s blind spots are four distinct shapes.**~~ **Done, and the note
   about the ABSENT key was the thing to fix.** `armed` now takes the context and
   may read only its **link-constant** half — `policy`, `source`, `target`,
   `boundary`, `revision`, `relationship`. That covers all four shapes: item 3's
   bundling, the boundary switches, the actor property (`target.input_schema`,
   shared with `run` through `_effective_schema` so the two cannot disagree about
   whether a schema exists) and the edge structure (`boundary is None`, which all
   five boundary checks now arm on).

   Widening the signature is only safe because the ABSENT key stopped being
   `(enforcementPoint, policyId, policyVersion)`: `CONTROL_COVERAGE_DECLARED`
   carries the armed set **explicitly**, keyed by a digest over the whole body, so
   the armed set no longer has to be derivable from fields already on the event.
   The constraint that remains is that it must not vary *per invocation*, and a
   test varies exactly the per-invocation fields across all 28 checks and fails if
   any armed verdict moves. That test is the whole safety margin for the wider
   signature.
3. ~~**Split the two multi-control check ids.**~~ **Done — split, not accepted.**
   Each half now arms on its own policy flag: `L1-M5-TOKEN-RESOURCE-MISMATCH` on
   `require_resource` and `L1-M9-VOLUME-BYTES-EXCEEDED` on `max_export_bytes`. The
   wire is unchanged: both new keys were already renamed (or are now) onto the code
   their point has always emitted, and each split id sits immediately after its
   sibling in every profile, so reason-code order does not move either. The check
   table is 28 checks; 26 controls became 28 because two were always two.
4. ~~**Pick one coverage convention for the three side-effect checks.**~~ **Done.**
   The side effect a check governs *is* its subject, so a different one is
   INAPPLICABLE for all three. `_destructive_write` and `_approval` moved to
   `_tainted_external_write`'s convention rather than the reverse, because the
   alternative reports a destructive-write control as exercised by traffic that
   never wrote anything.
5. ~~**The reducer must not read a missing `CONTROL_EVALUATED` as clean.**~~
   **Done**, as `noControlRecordCount` in every `counters` block plus the
   `unattributed` bucket — see §5. Fixture interaction `ia-9` is a call that
   executed successfully with no control record at all; without it the counter's
   cross-language parity was vacuous, which a mutation of the Studio port measured
   before the row existed.
6. ~~**Two A2A controls are unsatisfiable and would count as passing.**~~
   **Recorded, not deleted.** Both are kept: the constructor is what enforces the
   invariant today, and a second producer building a `CheckContext` directly meets
   no guard at all — deleting a fail-closed check because a different module
   happens to prevent its input is the unasserted cross-module assumption §6c
   exists to stop. What is fixed is the reading. Their `byCheck` rows are 100%
   RAN_CLEAN because nothing can trip them, which means *the constructor held*,
   not *this control was exercised*, and both halves of that sentence are asserted
   in `UnsatisfiableControlTests` rather than left to a docstring.
7. ~~**`assertNotIn(id, ran)` passes vacuously.**~~ **Done.** Each profile's check
   tuple is pinned whole in `ProfileMembershipTests`, so an id leaving a profile
   fails there loudly instead of turning every "did not run" assertion elsewhere
   into a tautology. The two scoped A2A profiles are additionally asserted to
   partition `A2A_PROFILE` exactly.
8. ~~**The reducer must count a denied permit as a block.**~~ **Done.**
   `InteractionRecord` carries `execution_permitted` / `executionPermitted`,
   reduced as the AND over the interaction's `CONTROL_EVALUATED` events with an
   absent key reading as `True`; `block_decision` is now `decision != ALLOW or
   not execution_permitted`, and `shadow_would_block` / `enforced_block` /
   `partial_or_bypass` follow it unchanged. Both languages, the schema wording
   and the fixture pair moved together (§6c), and the stale Studio rank map found
   in the same pass moved with them. No new counter: the refusal is folded into
   the existing three rather than reported beside them.

**Reconcile before adding consumers.** Six predicates tested `!= ALLOW` and so
disagreed with `would_block` on `BYPASSED`. Two have left: §6a's `sdk.py`, which
became an explicit execution-permit aggregate, and item 8's `block_decision`,
which now reads the permit as well as the decision — the change §6 asked for and
the change the reducer needed, arrived at from both ends. The four that remain
are `gateway.py:273`, `gateway.py:329`, `gateway.py:544` and
`config_guard.py:412`; §6c corrects what they do — `gateway.py:273` admits a
second decision source into the record rather than setting a label. Separately,
`analytics.py` picks `chosen` as the first control matching the strongest
decision and takes `policyId`, `mode` and `actualEnforced` from it. Plan 1's
re-ranking moves shipped statistics through that path; §6c's sixth edit gives it
the fixture (`ia-8`) it had none of, and syncing the Studio rank map is what that
fixture caught.

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
  it made "nobody authenticated this" read as "authentication passed." §6b then
  wired the flag into `_credential_missing`, so the gateway and the SDK reject an
  unverified credential instead of comparing its self-asserted fields to
  themselves. Against `main` this is strictly more blocking at the gateway: any
  caller presenting a credential no verifier produced now gets
  `L1-M5-CREDENTIAL-MISSING` where `main` had no notion of verification at all.
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
