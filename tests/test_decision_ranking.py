"""Every ControlDecision is ranked, so the verdict no longer depends on which check ran first.

The five members with no producer in ``src/`` -- CHALLENGE, DEGRADE, REVOKE, ERROR, BYPASSED --
are reachable through the five unconstrained LinkPolicy action fields, so the missing ranks were
an operator-reachable defect rather than a dead one.
"""

from __future__ import annotations

import itertools
import unittest
from dataclasses import replace

from test_policy_characterization import clean_case

from agent_interlock import ControlDecision, InvocationIntent, PolicyMode, SideEffect
from agent_interlock.models import _DECISION_RANK, PolicyDecisionRecord
from agent_interlock.policy import evaluate, strongest_decision


def decided(decision: ControlDecision, *, enforced: bool) -> PolicyDecisionRecord:
    return PolicyDecisionRecord(
        decision_id="decision-1",
        decision=decision,
        reason_codes=(),
        policy_id="policy-1",
        policy_version="1",
        mode=PolicyMode.ENFORCE if enforced else PolicyMode.SHADOW,
        arguments_hash="sha256:ranking",
        canonical_destinations=(),
        expires_at_epoch=0.0,
        enforced=enforced,
        interaction_id="interaction-1",
        trace_id="trace-1",
        span_id="span-1",
    )


class DecisionRankingTests(unittest.TestCase):
    def test_every_control_decision_has_a_rank(self):
        self.assertEqual(set(_DECISION_RANK), set(ControlDecision))

    def test_no_pair_of_decisions_depends_on_argument_order(self):
        """The property Task 4's review routed here: order must reorder reason codes, nothing else."""
        disagreements = [
            f"{left.value}/{right.value}"
            for left, right in itertools.combinations(ControlDecision, 2)
            if strongest_decision([left, right]) is not strongest_decision([right, left])
        ]
        self.assertEqual(disagreements, [])

    def test_bypassed_is_weaker_than_allow(self):
        self.assertEqual(strongest_decision([ControlDecision.BYPASSED, ControlDecision.ALLOW]), ControlDecision.ALLOW)
        self.assertEqual(strongest_decision([ControlDecision.ALLOW, ControlDecision.BYPASSED]), ControlDecision.ALLOW)

    def test_bypassed_alone_is_not_promoted(self):
        self.assertEqual(strongest_decision([ControlDecision.BYPASSED]), ControlDecision.BYPASSED)

    def test_error_outranks_block(self):
        self.assertEqual(strongest_decision([ControlDecision.BLOCK, ControlDecision.ERROR]), ControlDecision.ERROR)
        self.assertEqual(strongest_decision([ControlDecision.ERROR, ControlDecision.BLOCK]), ControlDecision.ERROR)

    def test_challenge_is_weaker_than_block(self):
        self.assertEqual(strongest_decision([ControlDecision.CHALLENGE, ControlDecision.BLOCK]), ControlDecision.BLOCK)
        self.assertEqual(strongest_decision([ControlDecision.BLOCK, ControlDecision.CHALLENGE]), ControlDecision.BLOCK)

    def test_no_decisions_is_allow(self):
        self.assertEqual(strongest_decision([]), ControlDecision.ALLOW)

    def test_configured_actions_outrank_by_severity_not_by_check_slot(self):
        """L1-M8-CREDENTIAL-DETECTED sits before INTERLOCK-DESTRUCTIVE-WRITE in GATEWAY_PROFILE.
        With secret_action=CHALLENGE the earlier slot used to win the tie and emit CHALLENGE."""
        policy, context = clean_case()
        policy = replace(policy, secret_action=ControlDecision.CHALLENGE)
        context = replace(
            context,
            arguments={"note": "AKIAIOSFODNN7EXAMPLE"},
            target=replace(context.target, side_effects=frozenset({SideEffect.DESTRUCTIVE_WRITE})),
            intent=InvocationIntent(purpose="SUPPORT_LOOKUP", estimated_side_effect=SideEffect.DESTRUCTIVE_WRITE),
        )
        record = evaluate(policy, context)
        self.assertEqual(record.decision, ControlDecision.BLOCK)
        self.assertEqual(record.reason_codes, ("L1-M8-CREDENTIAL-DETECTED", "INTERLOCK-DESTRUCTIVE-WRITE"))


class WouldBlockTests(unittest.TestCase):
    def test_only_allow_and_bypassed_are_not_blocks(self):
        """BYPASSED means the control was deliberately bypassed, not that the policy objected."""
        permissive = {item for item in ControlDecision if not decided(item, enforced=True).would_block}
        self.assertEqual(permissive, {ControlDecision.ALLOW, ControlDecision.BYPASSED})

    def test_would_block_ignores_enforcement_mode(self):
        shadow = decided(ControlDecision.BLOCK, enforced=False)
        self.assertTrue(shadow.permits_execution)
        self.assertTrue(shadow.would_block)


if __name__ == "__main__":
    unittest.main()
