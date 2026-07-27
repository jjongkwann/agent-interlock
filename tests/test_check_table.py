"""The check table mechanism: three coverage states, and profile renaming."""

from __future__ import annotations

import unittest
from dataclasses import replace

from test_policy_characterization import clean_case

from agent_interlock.models import ActorType, ControlDecision
from agent_interlock.policy import CHECKS, GATEWAY_PROFILE, CheckScope, Profile, run_checks


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
