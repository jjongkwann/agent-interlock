"""The check table mechanism: three coverage states, and profile renaming."""

from __future__ import annotations

import importlib
import pkgutil
import re
import sys
import unittest
from dataclasses import replace
from types import CodeType, FunctionType
from unittest.mock import patch

from test_policy_characterization import clean_case

import agent_interlock
from agent_interlock import policy as policy_module
from agent_interlock.architecture import ArchitectureBoundary, EnforcementPoint
from agent_interlock.models import ActorType, ControlDecision, CredentialClaims
from agent_interlock.policy import (
    A2A_PROFILE,
    CHECKS,
    GATEWAY_PROFILE,
    SDK_PROFILE,
    Check,
    CheckScope,
    Profile,
    evaluate,
    run_checks,
)

# Every reason key in the table is an upper-case, hyphenated string in one of three namespaces.
# Narrow enough that a check's docstring or a data-class literal like "D7" cannot match it, wide
# enough that a key added to any namespace is picked up without editing this pattern.
_REASON_KEY = re.compile(r"^(?:INTERLOCK|L1|A2A)-[A-Z0-9-]+$")


def _cells(function) -> tuple:
    return tuple(cell.cell_contents for cell in function.__closure__ or ())


def reason_keys(run) -> set[str]:
    """The reason keys a check's `run` can emit, read statically out of everything it can reach.

    Static rather than behavioural on purpose: a key only reachable down a branch no fixture
    happens to take -- or down a branch that does not exist yet -- is exactly the one that slips
    past a profile's rename map, and no behavioural test can reach either.

    Reading `co_consts` alone is not enough, and the gap is silent rather than loud: a key written
    as a module-level constant, pulled out into a helper, or looked up from a module-level dict
    leaves *no* literal in the check's own constants, so the scan returns the check's other keys
    and looks like it worked. So this also resolves each code object's `co_names` and walks what it
    finds -- strings, containers, and functions inside the package -- plus closure cells and nested
    code objects (comprehensions, lambdas).

    A name resolves against the globals of the module its code object came from, so the namespace
    travels *with* each item rather than being captured once from the entry check. Carrying one
    namespace reopened the same one-refactor hole a module over: a helper in `security.py` reading
    a constant of `security.py` had that name looked up in `policy.py`'s globals, where it does not
    exist, and the key went invisible again while a helper returning the same string as a literal
    was caught.

    Over-approximation is the safe direction here: a key reached this way but never emitted still
    has to be mapped, and a wrong extra key fails loudly. What remains invisible, measured rather
    than assumed: a key that leaves no literal matching `_REASON_KEY` anywhere the walk reaches,
    of which the known shape is `"L1-M9-{}".format(x)`; and anything reached only through a module
    outside the `agent_interlock` package, which the walk does not enter. Building a key by
    concatenation or by f-string is *not* invisible: constant folding leaves a literal
    concatenation whole, and an f-string with a runtime piece still leaves its `"L1-M9-"` prefix
    behind, which matches `_REASON_KEY` and is reported as an unmapped key. That residue is what
    the pinned EMITTED_KEYS snapshot backstops -- and only in one direction: because the pin is a
    hand-written literal, it makes a pinned key *disappearing* from this scan a failure, but it
    cannot make a brand-new key *arriving* invisibly one. A key that is added and built by `%`, or
    held in a module-level dict, is absent from both the scan and the pin, and the two agree.
    """
    found: set[str] = set()
    seen: set[int] = set()
    # (value, namespace) pairs: `namespace` is the globals `value`'s names resolve against. Strings
    # and containers just inherit their parent's -- only code objects resolve names, and a function
    # brings its own module's globals with it. `seen` is keyed on the value alone, which is enough:
    # a code object belongs to exactly one module, and nothing else consults the namespace. It is
    # also what terminates the walk on self-recursive and mutually recursive helpers.
    stack: list[tuple[object, dict]] = [(run.__code__, run.__globals__)]
    stack.extend((cell, run.__globals__) for cell in _cells(run))
    while stack:
        item, namespace = stack.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, str):
            if _REASON_KEY.match(item):
                found.add(item)
        elif isinstance(item, (tuple, list, set, frozenset)):
            stack.extend((value, namespace) for value in item)
        elif isinstance(item, dict):
            stack.extend((value, namespace) for value in item.values())
        elif isinstance(item, CodeType):
            stack.extend((const, namespace) for const in item.co_consts)
            stack.extend((namespace[name], namespace) for name in item.co_names if name in namespace)
        elif isinstance(item, FunctionType) and getattr(item, "__module__", "").startswith("agent_interlock"):
            stack.append((item.__code__, item.__globals__))
            stack.extend((cell, item.__globals__) for cell in _cells(item))
    return found


def a2a_case():
    """clean_case() dressed the way A2ABroker.send_message dresses a CheckContext -- a compiled
    boundary, a payload size, the edge relationship, and the audience/resource expectations the
    broker derives from its target -- while still tripping nothing. Every recipe below perturbs
    exactly one field of it."""
    policy, context = clean_case()
    policy = replace(policy, allowed_purposes=frozenset({context.intent.purpose}))
    boundary = ArchitectureBoundary(
        id="boundary.control-worker",
        label="Control to worker",
        source_zone_id="zone.control",
        target_zone_id="zone.worker",
        enforcement_point=EnforcementPoint.A2A_BROKER,
        allowed_relationships=frozenset({"DELEGATES"}),
    )
    context = replace(
        context,
        target=replace(context.target, input_schema={"type": "object", "required": ["question"]}),
        intent=replace(
            context.intent,
            expected_audience=context.target.identity,
            expected_resource=f"a2a://{context.target.id}",
        ),
        arguments={"parts": [{"data": {"question": "how do I reset the device?"}}]},
        credential=replace(
            context.credential,
            audience=context.target.identity,
            resource=f"a2a://{context.target.id}",
            tenant_id="tenant-a",
            authenticated=True,
        ),
        boundary=boundary,
        payload_bytes=64,
        relationship="DELEGATES",
    )
    return policy, context


# The M5 checks that defer to whoever owns the "this credential is not usable" verdict rather than
# reaching a verdict of their own. Every one of them compares self-asserted fields against each
# other, so on a credential no producer verified they can only compare a forgery with itself.
M5_CREDENTIAL_SIBLINGS = (
    "L1-M5-TOKEN-PASSTHROUGH",
    "L1-M5-TOKEN-AUDIENCE-MISMATCH",
    "L1-M5-TOKEN-ACTOR-MISMATCH",
    "L1-M5-DELEGATION-DEPTH",
)


def _credential(**changes):
    return lambda policy, context: (policy, replace(context, credential=replace(context.credential, **changes)))


def _context(**changes):
    return lambda policy, context: (policy, replace(context, **changes))


def _intent(**changes):
    return lambda policy, context: (policy, replace(context, intent=replace(context.intent, **changes)))


# The reason keys each check in the table can emit, pinned. reason_keys() must reproduce this map
# exactly, which is what makes a key *disappearing* from the scan a failure rather than a quieter
# scan: emptiness is not the only way to under-audit, and a check that still yields its other keys
# looks like a scan that worked. Written out in full, including the entries whose only key is the
# check id, so the pin is a literal record and not something derived from the thing it pins.
#
# Covers every check in CHECKS, not just the ones A2A_PROFILE happens to route. Scoping it to one
# profile is what let SDK_PROFILE emit a key it had never emitted: the hazard is a property of the
# (check body, profile map) pair, and every profile has one.
EMITTED_KEYS = {
    "INTERLOCK-ACTOR-TYPE-DENIED": frozenset({"INTERLOCK-ACTOR-TYPE-DENIED"}),
    "INTERLOCK-PURPOSE-DENIED": frozenset({"INTERLOCK-PURPOSE-DENIED"}),
    "L1-M2-DEFINITION-NOT-ACTIVE": frozenset({"L1-M2-DEFINITION-NOT-ACTIVE"}),
    "L1-M2-DEFINITION-DRIFT": frozenset({"L1-M2-DEFINITION-DRIFT"}),
    "INTERLOCK-INPUT-SCHEMA-INVALID": frozenset({"INTERLOCK-INPUT-SCHEMA-INVALID"}),
    "INTERLOCK-DATA-CLASS-DENIED": frozenset({"INTERLOCK-DATA-CLASS-DENIED", "L1-M9-SENSITIVE-EGRESS"}),
    "L1-M8-CREDENTIAL-DETECTED": frozenset({"L1-M8-CREDENTIAL-DETECTED"}),
    "L1-M9-NEW-DESTINATION": frozenset({"L1-M9-NEW-DESTINATION"}),
    "INTERLOCK-INTENT-ARGUMENT-MISMATCH": frozenset({"INTERLOCK-INTENT-ARGUMENT-MISMATCH"}),
    "L1-M9-VOLUME-EXCEEDED": frozenset({"L1-M9-VOLUME-EXCEEDED"}),
    "L1-M9-VOLUME-BYTES-EXCEEDED": frozenset({"L1-M9-VOLUME-BYTES-EXCEEDED"}),
    "L1-UNDECLARED-SIDE-EFFECT": frozenset({"L1-UNDECLARED-SIDE-EFFECT"}),
    "INTERLOCK-DESTRUCTIVE-WRITE": frozenset({"INTERLOCK-DESTRUCTIVE-WRITE"}),
    "INTERLOCK-TAINTED-EXTERNAL-WRITE": frozenset({"INTERLOCK-TAINTED-EXTERNAL-WRITE"}),
    "INTERLOCK-APPROVAL-REQUIRED": frozenset({"INTERLOCK-APPROVAL-REQUIRED"}),
    "L1-M5-CREDENTIAL-MISSING": frozenset({"L1-M5-CREDENTIAL-MISSING"}),
    "L1-M5-TOKEN-PASSTHROUGH": frozenset({"L1-M5-TOKEN-PASSTHROUGH"}),
    "L1-M5-TOKEN-AUDIENCE-MISMATCH": frozenset({"L1-M5-TOKEN-AUDIENCE-MISMATCH"}),
    "L1-M5-TOKEN-RESOURCE-MISMATCH": frozenset({"L1-M5-TOKEN-RESOURCE-MISMATCH"}),
    "L1-M5-TOKEN-ACTOR-MISMATCH": frozenset({"L1-M5-TOKEN-ACTOR-MISMATCH"}),
    "L1-M5-DELEGATION-DEPTH": frozenset({"L1-M5-DELEGATION-DEPTH"}),
    "A2A-IDENTITY-BINDING-MISMATCH": frozenset({"A2A-IDENTITY-BINDING-MISMATCH"}),
    "A2A-INPUT-SCHEMA-INVALID": frozenset({"A2A-INPUT-SCHEMA-INVALID"}),
    "A2A-PAYLOAD-INVALID": frozenset({"A2A-PAYLOAD-INVALID"}),
    "A2A-BOUNDARY-RELATIONSHIP-DENIED": frozenset({"A2A-BOUNDARY-RELATIONSHIP-DENIED"}),
    "A2A-BOUNDARY-DATA-CLASS-DENIED": frozenset({"A2A-BOUNDARY-DATA-CLASS-DENIED"}),
    "A2A-BOUNDARY-IDENTITY-REQUIRED": frozenset({"A2A-BOUNDARY-IDENTITY-REQUIRED"}),
    "A2A-BOUNDARY-TENANT-REQUIRED": frozenset({"A2A-BOUNDARY-TENANT-REQUIRED"}),
    "A2A-BOUNDARY-PAYLOAD-TOO-LARGE": frozenset({"A2A-BOUNDARY-PAYLOAD-TOO-LARGE"}),
}

# What each profile puts on its wire, pinned as the WHOLE MAP from emitted key to wire code --
# EMITTED_KEYS restricted to the profile's checks, each key pushed through the profile's rename map.
# Pinned literally rather than derived, because the rename map is the thing under test: deriving it
# would make the assertion agree with whatever the map happens to do.
#
# Pinned as a mapping and not as a set of codes, because several keys legitimately collapse onto one
# code -- L1-M9-SENSITIVE-EGRESS and INTERLOCK-DATA-CLASS-DENIED both reach A2A-DATA-CLASS-DENIED,
# and the resource key reaches the audience code at two points. Under a set comparison, re-pointing
# one member of a collapsed group at any other code already in the set is invisible: the set is
# unchanged. Measured -- re-pointing A2A's L1-M9-SENSITIVE-EGRESS to A2A-CREDENTIAL-DETECTED left a
# set-based audit fully green. Comparing the map makes every key's destination load-bearing.
#
# These are the strings main emitted at each enforcement point, and the plan's one standing
# constraint is that they do not move. SDK_PROFILE is the load-bearing entry: main's SDK reported
# every data-class denial as INTERLOCK-DATA-CLASS-DENIED and never once emitted
# L1-M9-SENSITIVE-EGRESS, so that key must be renamed away here while the gateway keeps it.
_SELF = (
    "INTERLOCK-ACTOR-TYPE-DENIED",
    "INTERLOCK-PURPOSE-DENIED",
    "INTERLOCK-INPUT-SCHEMA-INVALID",
    "INTERLOCK-DATA-CLASS-DENIED",
    "L1-M9-SENSITIVE-EGRESS",
    "L1-M8-CREDENTIAL-DETECTED",
    "L1-M9-NEW-DESTINATION",
    "INTERLOCK-INTENT-ARGUMENT-MISMATCH",
    "L1-M9-VOLUME-EXCEEDED",
    "L1-UNDECLARED-SIDE-EFFECT",
    "INTERLOCK-DESTRUCTIVE-WRITE",
    "INTERLOCK-TAINTED-EXTERNAL-WRITE",
    "INTERLOCK-APPROVAL-REQUIRED",
    "L1-M5-CREDENTIAL-MISSING",
    "L1-M5-TOKEN-PASSTHROUGH",
    "L1-M5-TOKEN-AUDIENCE-MISMATCH",
    "L1-M5-TOKEN-ACTOR-MISMATCH",
    "L1-M5-DELEGATION-DEPTH",
)

PROFILE_EMITTED_CODES = {
    "GATEWAY_PROFILE": {
        **{key: key for key in _SELF},
        "L1-M2-DEFINITION-NOT-ACTIVE": "L1-M2-DEFINITION-NOT-ACTIVE",
        "L1-M2-DEFINITION-DRIFT": "L1-M2-DEFINITION-DRIFT",
        "L1-M5-TOKEN-RESOURCE-MISMATCH": "L1-M5-TOKEN-AUDIENCE-MISMATCH",
        "L1-M9-VOLUME-BYTES-EXCEEDED": "L1-M9-VOLUME-EXCEEDED",
    },
    "SDK_PROFILE": {
        **{key: key for key in _SELF},
        # the one divergence from the gateway, and the reason this profile needs its own map
        "L1-M9-SENSITIVE-EGRESS": "INTERLOCK-DATA-CLASS-DENIED",
        "L1-M5-TOKEN-RESOURCE-MISMATCH": "L1-M5-TOKEN-AUDIENCE-MISMATCH",
        "L1-M9-VOLUME-BYTES-EXCEEDED": "L1-M9-VOLUME-EXCEEDED",
    },
    "A2A_PROFILE": {
        "A2A-IDENTITY-BINDING-MISMATCH": "A2A-IDENTITY-BINDING-MISMATCH",
        "INTERLOCK-ACTOR-TYPE-DENIED": "A2A-ACTOR-TYPE-DENIED",
        "INTERLOCK-PURPOSE-DENIED": "A2A-PURPOSE-DENIED",
        "INTERLOCK-DATA-CLASS-DENIED": "A2A-DATA-CLASS-DENIED",
        "L1-M9-SENSITIVE-EGRESS": "A2A-DATA-CLASS-DENIED",
        "L1-M8-CREDENTIAL-DETECTED": "A2A-CREDENTIAL-DETECTED",
        "L1-M5-TOKEN-ACTOR-MISMATCH": "A2A-ACTOR-BINDING-MISMATCH",
        "L1-M5-TOKEN-AUDIENCE-MISMATCH": "A2A-AUDIENCE-MISMATCH",
        "L1-M5-TOKEN-RESOURCE-MISMATCH": "A2A-RESOURCE-MISMATCH",
        "L1-M5-TOKEN-PASSTHROUGH": "A2A-TOKEN-PASSTHROUGH",
        "L1-M5-DELEGATION-DEPTH": "A2A-DELEGATION-DEPTH",
        "A2A-INPUT-SCHEMA-INVALID": "A2A-INPUT-SCHEMA-INVALID",
        "A2A-PAYLOAD-INVALID": "A2A-PAYLOAD-INVALID",
        "A2A-BOUNDARY-RELATIONSHIP-DENIED": "A2A-BOUNDARY-RELATIONSHIP-DENIED",
        "A2A-BOUNDARY-DATA-CLASS-DENIED": "A2A-BOUNDARY-DATA-CLASS-DENIED",
        "A2A-BOUNDARY-IDENTITY-REQUIRED": "A2A-BOUNDARY-IDENTITY-REQUIRED",
        "A2A-BOUNDARY-TENANT-REQUIRED": "A2A-BOUNDARY-TENANT-REQUIRED",
        "A2A-BOUNDARY-PAYLOAD-TOO-LARGE": "A2A-BOUNDARY-PAYLOAD-TOO-LARGE",
    },
    "A2A_LINK_PROFILE": {
        "A2A-IDENTITY-BINDING-MISMATCH": "A2A-IDENTITY-BINDING-MISMATCH",
        "INTERLOCK-ACTOR-TYPE-DENIED": "A2A-ACTOR-TYPE-DENIED",
        "INTERLOCK-PURPOSE-DENIED": "A2A-PURPOSE-DENIED",
        "INTERLOCK-DATA-CLASS-DENIED": "A2A-DATA-CLASS-DENIED",
        "L1-M9-SENSITIVE-EGRESS": "A2A-DATA-CLASS-DENIED",
        "L1-M8-CREDENTIAL-DETECTED": "A2A-CREDENTIAL-DETECTED",
        "L1-M5-TOKEN-ACTOR-MISMATCH": "A2A-ACTOR-BINDING-MISMATCH",
        "L1-M5-TOKEN-AUDIENCE-MISMATCH": "A2A-AUDIENCE-MISMATCH",
        "L1-M5-TOKEN-RESOURCE-MISMATCH": "A2A-RESOURCE-MISMATCH",
        "L1-M5-TOKEN-PASSTHROUGH": "A2A-TOKEN-PASSTHROUGH",
        "L1-M5-DELEGATION-DEPTH": "A2A-DELEGATION-DEPTH",
        "A2A-INPUT-SCHEMA-INVALID": "A2A-INPUT-SCHEMA-INVALID",
        "A2A-PAYLOAD-INVALID": "A2A-PAYLOAD-INVALID",
    },
    "A2A_BOUNDARY_PROFILE": {
        "A2A-BOUNDARY-RELATIONSHIP-DENIED": "A2A-BOUNDARY-RELATIONSHIP-DENIED",
        "A2A-BOUNDARY-DATA-CLASS-DENIED": "A2A-BOUNDARY-DATA-CLASS-DENIED",
        "A2A-BOUNDARY-IDENTITY-REQUIRED": "A2A-BOUNDARY-IDENTITY-REQUIRED",
        "A2A-BOUNDARY-TENANT-REQUIRED": "A2A-BOUNDARY-TENANT-REQUIRED",
        "A2A-BOUNDARY-PAYLOAD-TOO-LARGE": "A2A-BOUNDARY-PAYLOAD-TOO-LARGE",
    },
}


def module_profiles() -> dict[str, Profile]:
    """Every distinct Profile object anywhere in the agent_interlock package.

    Discovery rather than a hand-written list is what makes the audit below cover the *next* profile:
    a profile with no PROFILE_EMITTED_CODES entry fails the first assertion instead of quietly going
    unaudited, which is exactly how SDK_PROFILE escaped when the audit named A2A_PROFILE by hand.

    Every module in the package is imported and walked, not just policy.py. Scoping discovery to
    policy.py would have re-created the original defect one level up: all five profiles live there
    *today*, so a profile defined in sdk.py or a2a.py would have gone unaudited while the docstring
    claimed the next one was covered. Keyed by object identity, because sdk.py and a2a.py re-export
    policy.py's profiles -- those are the same objects under a second name, not new profiles, and
    only a genuinely new object is an unaudited one.

    The residue, stated rather than assumed: this finds profiles bound to a module attribute. One
    built at call time and never bound -- passed straight into run_checks, say -- is not reachable
    this way, and neither is a subpackage, since the package is flat and the walk does not recurse.
    """
    for info in pkgutil.iter_modules(agent_interlock.__path__):
        importlib.import_module(f"{agent_interlock.__name__}.{info.name}")
    canonical = {id(value): name for name, value in vars(policy_module).items() if isinstance(value, Profile)}
    found: dict[str, Profile] = {}
    for module_name, module in sorted(sys.modules.items()):
        if not module_name.startswith(f"{agent_interlock.__name__}."):
            continue
        for attribute, value in sorted(vars(module).items()):
            if isinstance(value, Profile):
                found[canonical.get(id(value), f"{module_name.split('.')[-1]}.{attribute}")] = value
    return found

# One recipe per reason key the A2A profile can emit, not one per check: INTERLOCK-DATA-CLASS-DENIED
# and L1-M5-TOKEN-AUDIENCE-MISMATCH each have a second branch with a second key, and a second branch
# is precisely where an unmapped gateway-namespace string hides.
A2A_RECIPES = (
    ("A2A-IDENTITY-BINDING-MISMATCH", "the credential is not authenticated", _credential(authenticated=False)),
    (
        "INTERLOCK-ACTOR-TYPE-DENIED",
        "the source actor type is outside the policy",
        lambda policy, context: (policy, replace(context, source=replace(context.source, type=ActorType.USER))),
    ),
    ("INTERLOCK-PURPOSE-DENIED", "the purpose is not allowed", _intent(purpose="EXFILTRATE")),
    ("INTERLOCK-DATA-CLASS-DENIED", "a denied data class", _intent(data_classes=frozenset({"D8"}))),
    (
        # Reaches the second branch, which is all this recipe claims: both of the branch's keys
        # rename to A2A-DATA-CLASS-DENIED, so an all-A2A- assertion cannot tell which one fired.
        # That L1-M9-SENSITIVE-EGRESS is the key on a denied D7 is pinned by
        # test_policy_characterization.py::test_every_reason_code_is_reachable, at the gateway where
        # the two keys stay distinct, and that it is *mapped* is pinned by the snapshot above.
        "INTERLOCK-DATA-CLASS-DENIED",
        "a denied D7 reaches the second branch",
        lambda policy, context: (
            replace(policy, denied_data_classes=policy.denied_data_classes | {"D7"}),
            replace(context, intent=replace(context.intent, data_classes=frozenset({"D7"}))),
        ),
    ),
    (
        "L1-M8-CREDENTIAL-DETECTED",
        "a secret in the message envelope",
        _context(arguments={"parts": [{"data": {"key": "AKIAIOSFODNN7EXAMPLE"}}]}),
    ),
    ("L1-M5-TOKEN-ACTOR-MISMATCH", "the credential names another actor", _credential(actor="agent.impersonator")),
    ("L1-M5-TOKEN-AUDIENCE-MISMATCH", "the audience does not match", _credential(audience="spiffe://wrong")),
    (
        "L1-M5-TOKEN-RESOURCE-MISMATCH",
        "the resource comparison, its own check since it carries its own policy flag",
        _credential(resource="a2a://wrong"),
    ),
    ("L1-M5-TOKEN-PASSTHROUGH", "the token was not exchanged", _credential(exchanged=False)),
    ("L1-M5-DELEGATION-DEPTH", "the delegation chain is too deep", _credential(delegation_depth=9)),
    (
        "A2A-INPUT-SCHEMA-INVALID",
        "a data Part that fails the target's input schema",
        _context(arguments={"parts": [{"data": {"wrong": 1}}]}),
    ),
    ("A2A-PAYLOAD-INVALID", "an empty payload", _context(payload_bytes=0)),
    ("A2A-BOUNDARY-RELATIONSHIP-DENIED", "a relationship the boundary denies", _context(relationship="OBSERVES")),
    ("A2A-BOUNDARY-DATA-CLASS-DENIED", "a data class the boundary denies", _intent(data_classes=frozenset({"D5"}))),
    ("A2A-BOUNDARY-IDENTITY-REQUIRED", "an unauthenticated credential", _credential(authenticated=False)),
    ("A2A-BOUNDARY-TENANT-REQUIRED", "a credential with no tenant binding", _credential(tenant_id="")),
    (
        "A2A-BOUNDARY-PAYLOAD-TOO-LARGE",
        "a payload over the boundary ceiling",
        lambda policy, context: (policy, replace(context, payload_bytes=context.boundary.max_payload_bytes + 1)),
    ),
)


class CheckTableTests(unittest.TestCase):
    def test_actor_type_check_is_registered_with_pair_scope(self):
        check = CHECKS["INTERLOCK-ACTOR-TYPE-DENIED"]
        self.assertEqual(check.scope, CheckScope.PAIR)

    def test_clean_case_runs_the_check_and_finds_nothing(self):
        policy, context = clean_case()
        outcome = run_checks(policy, context, GATEWAY_PROFILE)
        self.assertEqual(outcome.reasons, [])
        self.assertIn("INTERLOCK-ACTOR-TYPE-DENIED", outcome.ran)

    def test_profile_renames_the_emitted_reason_code(self):
        policy, context = clean_case()
        context = replace(context, source=replace(context.source, type=ActorType.USER))
        profile = Profile(
            enforcement_point="A2A_BROKER",
            checks=("INTERLOCK-ACTOR-TYPE-DENIED",),
            reason_codes={"INTERLOCK-ACTOR-TYPE-DENIED": "A2A-ACTOR-TYPE-DENIED"},
        )
        outcome = run_checks(policy, context, profile)
        self.assertEqual(outcome.reasons, ["A2A-ACTOR-TYPE-DENIED"])
        self.assertEqual(outcome.decisions, [ControlDecision.BLOCK])
        self.assertIn("INTERLOCK-ACTOR-TYPE-DENIED", outcome.ran)

    def test_a_check_absent_from_the_profile_does_not_run(self):
        policy, context = clean_case()
        profile = Profile(enforcement_point="SDK", checks=(), reason_codes={})
        outcome = run_checks(policy, context, profile)
        self.assertEqual(outcome.ran, set())

    def test_unarmed_and_inapplicable_checks_are_both_excluded_from_ran(self):
        """The three-way split (ran / armed-but-skipped / unarmed) is the whole point of
        run_checks: an unarmed check and a check that opts out by returning None must both
        be absent from `ran`, not merely absent from `reasons`."""
        stub_checks = {
            "STUB-UNARMED": Check(
                id="STUB-UNARMED",
                scope=CheckScope.ACTOR,
                armed=lambda policy, context: False,
                run=lambda policy, context: (("STUB-UNARMED", ControlDecision.BLOCK),),
            ),
            "STUB-INAPPLICABLE": Check(
                id="STUB-INAPPLICABLE",
                scope=CheckScope.ACTOR,
                armed=lambda policy, context: True,
                run=lambda policy, context: None,
            ),
        }
        profile = Profile(enforcement_point="TEST", checks=("STUB-UNARMED", "STUB-INAPPLICABLE"))
        policy, context = clean_case()
        with patch.dict(policy_module.CHECKS, stub_checks):
            outcome = run_checks(policy, context, profile)
        self.assertEqual(outcome.reasons, [])
        self.assertEqual(outcome.decisions, [])
        self.assertEqual(outcome.ran, set())
        # `ran` cannot tell the two apart -- that is what `armed` is for. ABSENT and INAPPLICABLE
        # are different facts about a control, and collapsing them is the defect this branch exists
        # to remove.
        self.assertEqual(outcome.armed, ("STUB-INAPPLICABLE",))
        self.assertEqual(outcome.flagged, set())

    def test_build_check_table_raises_on_duplicate_id(self):
        """Task 4 registers nineteen more checks into a table keyed by id; a collision must
        raise, not silently drop a control."""
        duplicate = Check(
            id="DUP", scope=CheckScope.ACTOR, armed=lambda policy: True, run=lambda policy, context: None
        )
        with self.assertRaises(ValueError):
            policy_module._build_check_table((duplicate, duplicate))

    def test_evaluate_emits_no_actor_type_finding_when_the_table_check_is_disabled(self):
        """Guards against Task 4 moving a branch into the table without deleting the original:
        if this fails, an inline branch is still emitting a reason code the table's own
        coverage says never ran."""
        policy, context = clean_case()
        context = replace(context, source=replace(context.source, type=ActorType.USER))
        empty_profile = Profile(enforcement_point="MCP_GATEWAY", checks=())
        with patch.object(policy_module, "GATEWAY_PROFILE", empty_profile):
            record = evaluate(policy, context)
        self.assertEqual(record.reason_codes, ())

    def test_checks_that_do_not_apply_stay_out_of_ran(self):
        """`ran` is the only place the None-vs-() distinction is visible: reason_codes and decision
        are identical either way, so without this test any of these `return None`s could become
        `return ()` and the whole suite would stay green -- while Plan 2's coverage statistic
        started reporting a control as run-and-passed on invocations it never examined."""
        policy, context = clean_case()
        outcome = run_checks(policy, replace(context, revision=None), GATEWAY_PROFILE)
        self.assertNotIn("L1-M2-DEFINITION-NOT-ACTIVE", outcome.ran)
        self.assertNotIn("L1-M2-DEFINITION-DRIFT", outcome.ran)
        self.assertNotIn("INTERLOCK-INPUT-SCHEMA-INVALID", outcome.ran)
        # clean_case()'s tool ships input_schema={}, and validate_schema short-circuits on an empty
        # schema -- so the schema check must stay out of `ran` here too, revision or no revision.
        outcome = run_checks(policy, context, GATEWAY_PROFILE)
        self.assertNotIn("INTERLOCK-INPUT-SCHEMA-INVALID", outcome.ran)
        self.assertIn("L1-M2-DEFINITION-DRIFT", outcome.ran)  # not vacuous: the same check runs when it applies

    def test_a_malformed_allowlist_entry_denies_the_destination_instead_of_raising(self):
        """A target whose allowed_domains holds something that is not a domain must still reach a
        verdict. _new_destination IDNA-encodes the allowlist, and an over-long DNS label raises
        UnicodeError straight out of the check -- past every caller, since neither evaluate() nor
        the SDK wraps it -- leaving an interaction with no control record at all. That is the exact
        defect class this plan exists to remove, so the check canonicalises the allowlist the way it
        already canonicalises destinations: encode what encodes, drop what does not.

        Dropping is the fail-closed direction and needs no new reason code. canonical_destination
        runs the same .encode("idna") on the destination host, so an entry that cannot be encoded
        could never have matched anything on the wire; removing it cannot turn a deny into a permit,
        and the destination it was meant to permit is simply not allowed.
        """
        policy, context = clean_case()
        context = replace(
            context,
            target=replace(context.target, allowed_domains=frozenset({"x" * 70})),
            intent=replace(context.intent, destinations=("https://evil.example",)),
        )
        outcome = run_checks(policy, context, GATEWAY_PROFILE)
        self.assertEqual(outcome.reasons, ["L1-M9-NEW-DESTINATION"])
        self.assertIn("L1-M9-NEW-DESTINATION", outcome.ran)

    def test_a_malformed_allowlist_entry_does_not_disarm_its_well_formed_siblings(self):
        """Dropping the bad entry has to be entry-scoped, not check-scoped. Discarding the whole
        allowlist would deny every destination -- fail-closed but wrong, and it would move a reason
        code onto traffic main allowed. Discarding the whole check would permit every destination,
        which is the silent permit the fix exists to prevent. The sibling entry still allows."""
        policy, context = clean_case()
        context = replace(
            context,
            target=replace(context.target, allowed_domains=frozenset({"x" * 70, "good.example"})),
            intent=replace(context.intent, destinations=("https://good.example",)),
        )
        outcome = run_checks(policy, context, GATEWAY_PROFILE)
        self.assertEqual(outcome.reasons, [])
        self.assertIn("L1-M9-NEW-DESTINATION", outcome.ran)  # not vacuous: the check ran and cleared it

    def test_a_malformed_allowlist_with_no_destination_declared_stays_inapplicable(self):
        """No destination declared means the destination control has no subject, malformed
        allowlist or not, so it stays out of `ran` -- returning () here would manufacture exactly
        the empty-subject RAN_CLEAN this plan is trying to eliminate, and reporting a finding would
        deny an invocation that declares no egress at all. The residual cost is that a malformed
        allowlist entry goes unnoticed until a destination is declared, which is a lint concern and
        not a runtime-enforcement one."""
        policy, context = clean_case()
        context = replace(context, target=replace(context.target, allowed_domains=frozenset({"x" * 70})))
        outcome = run_checks(policy, context, GATEWAY_PROFILE)
        self.assertEqual(outcome.reasons, [])
        self.assertNotIn("L1-M9-NEW-DESTINATION", outcome.ran)

    def test_a_resolved_revision_shadows_the_actor_schema_even_when_it_declares_none(self):
        """_input_schema falls back to ActorSpec.input_schema only when no revision is resolved.
        Written as a ternary rather than `or` for exactly this case: an empty revision schema is a
        tool that declares nothing to validate, so the check is INAPPLICABLE. An `or` would reach
        past it to the actor's schema and re-validate gateway traffic against an unapproved
        definition -- and no other fixture can tell the two forms apart, because clean_case()
        leaves both operands empty."""
        policy, context = clean_case()
        context = replace(
            context,
            target=replace(context.target, input_schema={"type": "object", "required": ["ticket"]}),
            arguments={"wrong": 1},
        )
        self.assertEqual(context.revision.definition.input_schema, {})  # the discriminating operand
        outcome = run_checks(policy, context, GATEWAY_PROFILE)
        self.assertNotIn("INTERLOCK-INPUT-SCHEMA-INVALID", outcome.ran)
        self.assertNotIn("INTERLOCK-INPUT-SCHEMA-INVALID", outcome.reasons)

    def test_a_credential_that_declares_no_authentication_reads_as_unauthenticated(self):
        """CredentialClaims.authenticated defaults to False, and a producer that did not verify the
        principal must not be able to reach the same state as one that did. clean_case()'s
        credential is authenticated and names the right actor, so stripping the flag is the only
        difference between the two halves of this test and the binding half cannot mask it."""
        policy, context = clean_case()
        self.assertEqual(context.credential.actor, context.source.id)  # not vacuous
        bare = CredentialClaims(reference="", issuer="", subject="", actor="", audience="", resource="")
        self.assertFalse(bare.authenticated)  # the class default, not the fixture's
        profile = replace(A2A_PROFILE, checks=("A2A-IDENTITY-BINDING-MISMATCH",))
        unauthenticated = replace(context, credential=replace(context.credential, authenticated=False))
        outcome = run_checks(policy, unauthenticated, profile)
        self.assertEqual(outcome.reasons, ["A2A-IDENTITY-BINDING-MISMATCH"])
        self.assertEqual(run_checks(policy, context, profile).reasons, [])

    def test_the_m5_presence_check_reads_authentication_not_the_object(self):
        """All three coverage states of L1-M5-CREDENTIAL-MISSING, at both shared enforcement points.

        The check asks whether this invocation has a credential it can rely on, and every field on
        CredentialClaims other than `authenticated` is whatever the caller wrote. So a credential no
        producer verified answers that question with "no": the sibling M5 checks can only compare a
        forged credential against itself, and reporting them clean is the defect this effort exists
        to remove. Only mcp_oauth.MCPAuthorizationCodeTokenClient.exchange, which runs the claims
        verifier, sets the flag.

        The unauthenticated row is the one that used to be RAN_CLEAN while the SDK executed the
        call. RAN_FLAGGED is the honest replacement -- returning None would swap one lie for
        another -- so each row pins membership in `ran` as well as the emitted codes.
        """
        policy, context = clean_case()
        bound = replace(context, intent=replace(context.intent, expected_audience=context.target.identity))
        cases = (
            ("INAPPLICABLE: the intent names no audience or resource", context, False, []),
            ("RAN_FLAGGED: nothing presented", replace(bound, credential=None), True, ["L1-M5-CREDENTIAL-MISSING"]),
            (
                "RAN_FLAGGED: presented but unverified",
                replace(bound, credential=replace(bound.credential, authenticated=False)),
                True,
                ["L1-M5-CREDENTIAL-MISSING"],
            ),
            ("RAN_CLEAN: presented and verified", bound, True, []),
        )
        for profile in (GATEWAY_PROFILE, SDK_PROFILE):
            for label, case, expected_ran, expected_reasons in cases:
                with self.subTest(enforcement_point=profile.enforcement_point, case=label):
                    single = replace(profile, checks=("L1-M5-CREDENTIAL-MISSING",))
                    outcome = run_checks(policy, case, single)
                    self.assertEqual(outcome.reasons, expected_reasons)
                    self.assertEqual("L1-M5-CREDENTIAL-MISSING" in outcome.ran, expected_ran)

    def test_a_forged_credential_does_not_permit_execution_at_the_gateway(self):
        """The check is shared, so the SDK's hole and the gateway's close together.

        main had no `authenticated` field at all, so at the gateway this closes a weakness inherited
        from before the branch; at the SDK it closes one the branch created, by giving wrap() M5
        checks that read only self-asserted fields. Asserted on permits_execution rather than on the
        reason code alone: the code reaching the record is not the same claim as the invocation
        being denied.
        """
        policy, context = clean_case()
        forged = replace(
            context,
            intent=replace(
                context.intent,
                expected_audience=context.target.identity,
                expected_resource=f"a2a://{context.target.id}",
            ),
            credential=replace(
                context.credential,
                issuer="https://attacker.example",
                audience=context.target.identity,
                resource=f"a2a://{context.target.id}",
                authenticated=False,
            ),
        )
        record = evaluate(policy, forged)
        self.assertEqual(record.reason_codes, ("L1-M5-CREDENTIAL-MISSING",))
        self.assertFalse(record.permits_execution)
        verified = replace(forged, credential=replace(forged.credential, authenticated=True))
        self.assertEqual(evaluate(policy, verified).reason_codes, ())

    def test_the_whole_m5_family_agrees_on_what_a_usable_credential_is(self):
        """A forged credential must not read as *more checked* than no credential at all.

        The presence check reads `authenticated`; its four siblings used to key on `credential is
        None`, each deferring to "nothing presented, _credential_missing owns that verdict" -- a
        definition that had changed underneath them. The measured result was that absence made the
        four INAPPLICABLE while a forgery made them RAN_CLEAN, in the coverage channel this branch
        exists to make trustworthy: the forgery came out looking better examined than the absence.

        Asserted as equality between the two coverage vectors rather than against a literal, so the
        property is the *agreement* and not one hard-coded answer. A fix that made the absent case
        RAN_CLEAN would satisfy a literal and fails here on the third assertion.
        """
        policy, base = clean_case()
        bound = replace(base, intent=replace(base.intent, expected_audience=base.target.identity))
        forged = replace(
            bound, credential=replace(bound.credential, audience=base.target.identity, authenticated=False)
        )
        absent = replace(bound, credential=None)
        for check_id in M5_CREDENTIAL_SIBLINGS:
            with self.subTest(check=check_id):
                single = replace(GATEWAY_PROFILE, checks=(check_id,))
                forged_ran = check_id in run_checks(policy, forged, single).ran
                absent_ran = check_id in run_checks(policy, absent, single).ran
                self.assertEqual(forged_ran, absent_ran)
                self.assertFalse(forged_ran)  # a check with nothing to examine is INAPPLICABLE ...
                verified = replace(bound, credential=replace(forged.credential, authenticated=True))
                self.assertIn(check_id, run_checks(policy, verified, single).ran)  # ... and not always

    def test_no_enforcement_point_loses_its_verdict_on_an_unusable_credential(self):
        """The siblings defer, so somebody in every profile that carries them has to own the verdict.

        Making the four INAPPLICABLE is only honest if an unverified credential is still refused --
        otherwise the coverage fix hands back a permit, which is the same trade this branch exists to
        refuse. The gateway and the SDK own it with L1-M5-CREDENTIAL-MISSING; A2A_PROFILE does not
        carry that check at all and owns it with A2A-IDENTITY-BINDING-MISMATCH. Behavioural per
        profile rather than a membership test over profile.checks, because what matters is that a
        code comes out, not that a named check is listed.
        """
        policy, base = clean_case()
        unusable = replace(base, credential=replace(base.credential, authenticated=False))
        for profile in (GATEWAY_PROFILE, SDK_PROFILE):
            with self.subTest(enforcement_point=profile.enforcement_point):
                outcome = run_checks(policy, unusable, profile)
                self.assertEqual(outcome.reasons, ["L1-M5-CREDENTIAL-MISSING"])
        a2a_policy, a2a_context = a2a_case()
        a2a_unusable = replace(a2a_context, credential=replace(a2a_context.credential, authenticated=False))
        outcome = run_checks(a2a_policy, a2a_unusable, A2A_PROFILE)
        self.assertEqual(outcome.reasons, ["A2A-IDENTITY-BINDING-MISMATCH", "A2A-BOUNDARY-IDENTITY-REQUIRED"])

    def test_a_forged_credential_is_refused_even_when_the_intent_names_nothing(self):
        """The case where deferring would otherwise open a permit.

        With no expected audience or resource the presence check used to be INAPPLICABLE, so a
        forged credential was refused only by whichever sibling its attacker-chosen fields happened
        to trip -- here the delegation depth. Those fields are attacker-chosen, so that refusal was
        never a control; it was the attacker declining to set a field. The presence check now owns
        an unverified credential wherever one is presented, and the siblings can defer without
        anything falling through.
        """
        policy, base = clean_case()
        forged = replace(base, credential=replace(base.credential, authenticated=False, delegation_depth=9))
        self.assertEqual(forged.intent.expected_audience, "")  # not vacuous: nothing is expected
        self.assertEqual(forged.intent.expected_resource, "")
        record = evaluate(policy, forged)
        self.assertEqual(record.reason_codes, ("L1-M5-CREDENTIAL-MISSING",))
        self.assertIs(record.permits_execution, False)
        # An attacker who sets nothing else at all reaches the same verdict, which is the property:
        # no combination of self-asserted fields buys anything over presenting no credential.
        quiet = replace(base, credential=replace(base.credential, authenticated=False))
        self.assertEqual(evaluate(policy, quiet).reason_codes, ("L1-M5-CREDENTIAL-MISSING",))

    def test_the_resource_comparison_renames_apart_at_each_enforcement_point(self):
        """_token_audience emits one key for the audience comparison and another for the resource
        comparison, because the A2A broker has always reported them as two codes and reason_codes
        is keyed on the emitted key. The gateway and the SDK have always reported one code for
        both, so their profiles have to map the resource key back -- unmapped, an internal key no
        enforcement point has ever emitted would reach the gateway's wire."""
        policy, context = clean_case()
        context = replace(
            context,
            intent=replace(context.intent, expected_audience="aud", expected_resource="res"),
            credential=replace(context.credential, audience="aud", resource="wrong"),
        )
        for profile in (GATEWAY_PROFILE, SDK_PROFILE):
            with self.subTest(enforcement_point=profile.enforcement_point):
                outcome = run_checks(policy, context, profile)
                self.assertEqual(outcome.reasons, ["L1-M5-TOKEN-AUDIENCE-MISMATCH"])
        a2a_only = replace(
            A2A_PROFILE, checks=("L1-M5-TOKEN-AUDIENCE-MISMATCH", "L1-M5-TOKEN-RESOURCE-MISMATCH")
        )
        outcome = run_checks(policy, context, a2a_only)
        self.assertEqual(outcome.reasons, ["A2A-RESOURCE-MISMATCH"])

    def test_every_check_emits_exactly_the_reason_keys_pinned_for_it(self):
        """The emitted-key domain of the whole table, pinned.

        The audit has to run over the *emitted-key domain*, which is why it reads the keys back out
        of the check bodies: reason_codes is keyed on the emitted key, and two checks emit two keys
        each -- INTERLOCK-DATA-CLASS-DENIED also emits L1-M9-SENSITIVE-EGRESS on a denied D7, and
        L1-M5-TOKEN-AUDIENCE-MISMATCH also emits the resource key. A second branch is precisely
        where a key a profile has to rename hides.

        The scanned set is compared against a pinned snapshot before any profile uses it, because an
        audit that quietly stops seeing things reports the same green as one that looked and found
        nothing -- this plan's own pathology, in the machinery built to detect it. Asserting only
        that the scan found *something* per check is not enough: a check keeping its existing keys
        while a new one moves out of reach is partial blindness, and partial blindness passes a
        non-emptiness test. Comparing whole sets makes a key vanishing as loud as a key appearing.
        """
        scanned = {check_id: reason_keys(check.run) for check_id, check in CHECKS.items()}
        # Reported per check and per direction rather than as two whole dicts: comparing the maps
        # directly is just as loud but truncates to "Diff is 1250 characters long", which tells the
        # next reader nothing about which key moved or which way.
        drift = {}
        for check_id in set(scanned) | set(EMITTED_KEYS):
            found, pinned = scanned.get(check_id, set()), set(EMITTED_KEYS.get(check_id, ()))
            if found != pinned:
                drift[check_id] = {
                    "scanned but not pinned": sorted(found - pinned),
                    "pinned but not scanned": sorted(pinned - found),
                }
        self.assertEqual(drift, {})

    def test_every_profile_maps_every_key_its_checks_can_emit(self):
        """Every profile's wire codes, pinned -- the plan's one standing constraint, as an assertion.

        This audit used to name A2A_PROFILE and only A2A_PROFILE, with a docstring stating the
        invariant for it alone ("a missed key would put a gateway-namespace string on the A2A wire")
        while the identical hazard on SDK_PROFILE went unaudited. It duly caught the A2A instance
        before it landed and missed the SDK one: SDK_PROFILE reused GATEWAY_PROFILE's map object, so
        a denied D7 -- which main's SDK reported as INTERLOCK-DATA-CLASS-DENIED -- started reaching
        the ledger as L1-M9-SENSITIVE-EGRESS, splitting one byReasonCode bucket into two.

        So the profiles are discovered from the package, not listed here: the next profile added is
        covered by construction rather than by someone remembering this file exists. A profile with
        no pinned entry fails the first assertion.

        The comparison is over the whole key-to-code map, not the set of codes it produces. Several
        keys legitimately collapse onto one code, and under a set comparison re-pointing one member
        of a collapsed group at another code already in the set is invisible -- which is how a
        set-based version of this audit lost the only guard on A2A's L1-M9-SENSITIVE-EGRESS entry.
        """
        profiles = module_profiles()
        self.assertEqual(sorted(profiles), sorted(PROFILE_EMITTED_CODES))
        for name, profile in sorted(profiles.items()):
            with self.subTest(profile=name):
                emitted = {
                    key: profile.reason_codes.get(key, key)
                    for check_id in profile.checks
                    for key in EMITTED_KEYS[check_id]
                }
                self.assertEqual(emitted, PROFILE_EMITTED_CODES[name])

    def test_every_condition_the_a2a_profile_can_trip_emits_an_a2a_reason_code(self):
        """The behavioural half of the same invariant: trip each condition in turn and read what
        comes back out. The static audit above cannot see a key built at runtime; this cannot see a
        branch no recipe reaches. Together they cover both.

        A check in the profile with no recipe fails the first assertion rather than being skipped --
        a condition nobody can trip is a finding of its own, not a gap to paper over. The base case
        is asserted clean and fully engaged first, so a finding below can only come from its own
        recipe and not from fixture noise.

        What comes back is compared against the pinned map rather than against the prefix "A2A-".
        A prefix test accepts any code in the namespace, so re-pointing a key at a *different* A2A
        code passes it; that left the whole A2A wire mapping resting on one static assertion. The
        pin is hand-written, so this stays an independent check on the profile's map and not a
        restatement of it.
        """
        policy, context = a2a_case()
        outcome = run_checks(policy, context, A2A_PROFILE)
        self.assertEqual(outcome.reasons, [])
        self.assertEqual(outcome.ran, set(A2A_PROFILE.checks))
        self.assertEqual(set(A2A_PROFILE.checks) - {check_id for check_id, _, _ in A2A_RECIPES}, set())
        pinned = PROFILE_EMITTED_CODES["A2A_PROFILE"]
        for check_id, condition, perturb in A2A_RECIPES:
            with self.subTest(check=check_id, condition=condition):
                policy, context = perturb(*a2a_case())
                outcome = run_checks(policy, context, replace(A2A_PROFILE, checks=(check_id,)))
                self.assertEqual(outcome.ran, {check_id})  # armed and applicable ...
                self.assertNotEqual(outcome.reasons, [])  # ... and the recipe still trips it
                # every code this check is pinned to be able to emit, and nothing else
                self.assertEqual(set(outcome.reasons) - {pinned[key] for key in EMITTED_KEYS[check_id]}, set())

    def test_evaluate_with_revision_none_under_default_policy_is_a_known_silent_allow(self):
        """Documents a known gap, does not bless it: default LinkPolicy() has both M2 gates
        (require_active_definition, require_digest_pin) enabled, and CheckContext.revision is
        optional (Tasks 5-7 build one before a revision is resolved). With revision=None, both
        M2 gates are skipped rather than crashing (see policy.py's guarded dereferences) -- but
        that skip is indistinguishable from "ran and found nothing" in the record returned here:
        evaluate() emits a clean ALLOW. Plan 2's coverage layer is what will make "did not apply"
        visible; this test pins the exact silent-allow shape until then, so any drift shows up
        as a diff instead of silently changing behaviour again.
        """
        policy, context = clean_case()
        context = replace(context, revision=None)
        record = evaluate(policy, context)
        self.assertEqual(record.decision, ControlDecision.ALLOW)
        self.assertEqual(record.reason_codes, ())


if __name__ == "__main__":
    unittest.main()
