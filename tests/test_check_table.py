"""The check table mechanism: three coverage states, and profile renaming."""

from __future__ import annotations

import unittest
from dataclasses import replace
from unittest.mock import patch

from test_policy_characterization import clean_case

from agent_interlock import policy as policy_module
from agent_interlock.models import ActorType, ControlDecision
from agent_interlock.policy import CHECKS, GATEWAY_PROFILE, Check, CheckScope, Profile, evaluate, run_checks


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
        reasons, decisions, ran = run_checks(policy, context, profile)
        self.assertEqual(reasons, ["A2A-ACTOR-TYPE-DENIED"])
        self.assertEqual(decisions, [ControlDecision.BLOCK])
        self.assertIn("INTERLOCK-ACTOR-TYPE-DENIED", ran)

    def test_a_check_absent_from_the_profile_does_not_run(self):
        policy, context = clean_case()
        profile = Profile(enforcement_point="SDK", checks=(), reason_codes={})
        _, _, ran = run_checks(policy, context, profile)
        self.assertEqual(ran, set())

    def test_unarmed_and_inapplicable_checks_are_both_excluded_from_ran(self):
        """The three-way split (ran / armed-but-skipped / unarmed) is the whole point of
        run_checks: an unarmed check and a check that opts out by returning None must both
        be absent from `ran`, not merely absent from `reasons`."""
        stub_checks = {
            "STUB-UNARMED": Check(
                id="STUB-UNARMED",
                scope=CheckScope.ACTOR,
                armed=lambda policy: False,
                run=lambda policy, context: (("STUB-UNARMED", ControlDecision.BLOCK),),
            ),
            "STUB-INAPPLICABLE": Check(
                id="STUB-INAPPLICABLE",
                scope=CheckScope.ACTOR,
                armed=lambda policy: True,
                run=lambda policy, context: None,
            ),
        }
        profile = Profile(enforcement_point="TEST", checks=("STUB-UNARMED", "STUB-INAPPLICABLE"))
        policy, context = clean_case()
        with patch.dict(policy_module.CHECKS, stub_checks):
            reasons, decisions, ran = run_checks(policy, context, profile)
        self.assertEqual(reasons, [])
        self.assertEqual(decisions, [])
        self.assertEqual(ran, set())

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
        _, _, ran = run_checks(policy, replace(context, revision=None), GATEWAY_PROFILE)
        self.assertNotIn("L1-M2-DEFINITION-NOT-ACTIVE", ran)
        self.assertNotIn("L1-M2-DEFINITION-DRIFT", ran)
        self.assertNotIn("INTERLOCK-INPUT-SCHEMA-INVALID", ran)
        # clean_case()'s tool ships input_schema={}, and validate_schema short-circuits on an empty
        # schema -- so the schema check must stay out of `ran` here too, revision or no revision.
        _, _, ran = run_checks(policy, context, GATEWAY_PROFILE)
        self.assertNotIn("INTERLOCK-INPUT-SCHEMA-INVALID", ran)
        self.assertIn("L1-M2-DEFINITION-DRIFT", ran)  # not vacuous: the same check runs when it applies

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
        reasons, _, ran = run_checks(policy, context, GATEWAY_PROFILE)
        self.assertNotIn("INTERLOCK-INPUT-SCHEMA-INVALID", ran)
        self.assertNotIn("INTERLOCK-INPUT-SCHEMA-INVALID", reasons)

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
