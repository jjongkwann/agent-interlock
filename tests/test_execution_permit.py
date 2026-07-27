"""A final execution permit requires every contributing decision to be affirmative.

``strongest_decision`` reduces by severity, and ``max`` over ``_DECISION_RANK`` annihilates every
member ranked below ``ALLOW``. Reading the permit off that reduction let ``[ALLOW, BYPASSED]``
execute under ENFORCE: a control the operator deliberately bypassed became permission the moment an
unrelated check was configured to ``ALLOW``. ``BYPASSED`` alone was already pinned as insufficient
permission, so the hole opened only in company.

Severity and permission are two different aggregations over the same findings. ``_DECISION_RANK``
answers the first and is deliberately left alone here -- ``would_block`` and Plan 2's coverage axis
depend on it. This file pins the second.
"""

from __future__ import annotations

import unittest

from l1_harness import TENANT, build_gateway
from test_l1_matrix import BENIGN_ARGS

from agent_interlock import (
    ActorSpec,
    ActorType,
    ControlDecision,
    InvocationIntent,
    LinkPolicy,
    PolicyMode,
    SideEffect,
)
from agent_interlock.gateway import GatewayError, InvocationBlocked
from agent_interlock.policy import execution_permitted, strongest_decision
from agent_interlock.sdk import Interlock

# The reproduction's configuration, verbatim: one check configured to ALLOW, one to BYPASSED.
PERMISSIVE = dict(
    secret_action=ControlDecision.ALLOW,
    undeclared_side_effect_action=ControlDecision.BYPASSED,
)
# An AWS key in the arguments trips the secret check; READ is not among the target's declared side
# effects, so the undeclared-side-effect check trips too.
SECRET_ARGS = {"note": "AKIAIOSFODNN7EXAMPLE"}
UNDECLARED_READ = InvocationIntent(purpose="SUPPORT_LOOKUP", estimated_side_effect=SideEffect.READ)


def sdk_call(mode: PolicyMode):
    """Run the reproduction through wrap(). Returns (interlock, calls, error)."""
    interlock = Interlock()
    source = interlock.define_actor(
        ActorSpec(id="agent-1", type=ActorType.AGENT, owner="team", identity="spiffe://agent-1")
    )
    target = interlock.define_actor(
        ActorSpec(id="tool-1", type=ActorType.TOOL, owner="team", identity="spiffe://tool-1")
    )
    source.connect(target, LinkPolicy(mode=mode, **PERMISSIVE))
    calls: list = []
    guarded = target.wrap(lambda arguments: calls.append(arguments) or {"ok": True})
    error = None
    try:
        guarded(SECRET_ARGS, source=source, tenant_id="tenant-a", intent=UNDECLARED_READ)
    except GatewayError as raised:
        error = raised
    return interlock, calls, error


def control_record(interlock):
    events = [event for event in interlock.ledger.all() if event.event_type == "CONTROL_EVALUATED"]
    return events[-1].payload["control"]


class ExecutionPermitTests(unittest.TestCase):
    def test_one_bypassed_contribution_denies_however_many_allows_accompany_it(self):
        """The aggregation, stated directly. Argument order is irrelevant, which is what makes this
        a property of the multiset rather than of which check happens to hold the earlier slot."""
        self.assertFalse(execution_permitted([ControlDecision.ALLOW, ControlDecision.BYPASSED]))
        self.assertFalse(execution_permitted([ControlDecision.BYPASSED, ControlDecision.ALLOW]))
        self.assertFalse(
            execution_permitted([ControlDecision.ALLOW, ControlDecision.ALLOW, ControlDecision.BYPASSED])
        )
        self.assertFalse(execution_permitted([ControlDecision.BYPASSED]))

    def test_only_affirmative_contributions_permit(self):
        """A permit needs every contributor to say ALLOW, and nothing else in the enum may stand in
        for one. Written over the whole enum so a member added later cannot default into permission,
        and so a fix that special-cased BYPASSED alone fails here."""
        permitting = {item for item in ControlDecision if execution_permitted([ControlDecision.ALLOW, item])}
        self.assertEqual(permitting, {ControlDecision.ALLOW})

    def test_no_findings_at_all_is_permitted(self):
        """The overwhelmingly common case: no check had anything to say. `all` over an empty list is
        vacuously true and that is the wanted answer, but it is the answer this whole gate hangs on,
        so it is pinned rather than left to a Python idiom."""
        self.assertTrue(execution_permitted([]))
        self.assertTrue(execution_permitted([ControlDecision.ALLOW]))

    def test_the_severity_reduction_the_permit_replaces_is_left_untouched(self):
        """The two halves of the ruling in one place. _DECISION_RANK keeps BYPASSED below ALLOW --
        would_block and Plan 2's coverage axis are built on that and must not move -- and the permit
        is aggregated separately instead. If someone 'fixes' this by re-ranking BYPASSED, the first
        assertion fails and points at the reason not to."""
        self.assertEqual(
            strongest_decision([ControlDecision.ALLOW, ControlDecision.BYPASSED]), ControlDecision.ALLOW
        )
        self.assertFalse(execution_permitted([ControlDecision.ALLOW, ControlDecision.BYPASSED]))


class SDKExecutionPermitTests(unittest.TestCase):
    def test_a_bypassed_control_beside_an_allow_does_not_execute_under_enforce(self):
        """The reproduction. On main this configuration was blocked -- its undeclared-side-effect
        branch hard-coded BLOCK -- so an ENFORCE link that executed here was strictly less safe than
        the engine this table replaced."""
        _, calls, error = sdk_call(PolicyMode.ENFORCE)
        self.assertIsNotNone(error)
        self.assertEqual(calls, [])
        self.assertIn("L1-UNDECLARED-SIDE-EFFECT", str(error))

    def test_the_emitted_decision_and_reason_codes_do_not_move(self):
        """Denying execution must not rewrite what the ledger says. strongest_decision still supplies
        the decision, so the record reads ALLOW while the invocation is refused -- the two answer
        different questions -- and the reason codes keep their content and their profile order."""
        interlock, _, _ = sdk_call(PolicyMode.ENFORCE)
        control = control_record(interlock)
        self.assertEqual(control["decision"], "ALLOW")
        self.assertEqual(control["reasonCodes"], ["L1-M8-CREDENTIAL-DETECTED", "L1-UNDECLARED-SIDE-EFFECT"])
        self.assertIs(control["actualEnforced"], True)

    def test_a_non_enforcing_mode_still_executes(self):
        """The gate is ANDed with enforcement, so tightening it must not turn SHADOW or OBSERVE into
        an enforcing mode. Both would otherwise start blocking on the very findings they exist to
        observe without acting on."""
        for mode in (PolicyMode.SHADOW, PolicyMode.OBSERVE):
            with self.subTest(mode=mode.value):
                _, calls, error = sdk_call(mode)
                self.assertIsNone(error)
                self.assertEqual(calls, [SECRET_ARGS])


class GatewayExecutionPermitTests(unittest.TestCase):
    """The gateway reads the permit off the record rather than off a decision list, so the same
    aggregation has to survive the trip through PolicyDecisionRecord."""

    def invoked(self, mode: PolicyMode):
        gateway, revision, source, _ = build_gateway(
            policy=LinkPolicy(mode=mode, external_write_requires_approval=False, **PERMISSIVE),
        )
        calls: list = []
        return gateway, revision, source, calls

    def test_the_same_configuration_is_blocked_at_the_gateway(self):
        gateway, revision, source, calls = self.invoked(PolicyMode.ENFORCE)
        with self.assertRaises(InvocationBlocked) as raised:
            gateway.invoke(
                tenant_id=TENANT,
                source_actor_id=source.id,
                revision_id=revision.revision_id,
                intent=InvocationIntent(purpose="reply", estimated_side_effect=SideEffect.READ),
                arguments={**BENIGN_ARGS, "body": "AKIAIOSFODNN7EXAMPLE"},
                connector=lambda args: calls.append(args),
                idempotency_key="permit-1",
            )
        self.assertEqual(calls, [])
        record = raised.exception.decision
        self.assertEqual(record.decision, ControlDecision.ALLOW)
        self.assertEqual(record.reason_codes, ("L1-M8-CREDENTIAL-DETECTED", "L1-UNDECLARED-SIDE-EFFECT"))
        self.assertFalse(record.permits_execution)

    def test_a_shadow_link_with_the_same_configuration_still_executes(self):
        gateway, revision, source, calls = self.invoked(PolicyMode.SHADOW)
        result = gateway.invoke(
            tenant_id=TENANT,
            source_actor_id=source.id,
            revision_id=revision.revision_id,
            intent=InvocationIntent(purpose="reply", estimated_side_effect=SideEffect.READ),
            arguments={**BENIGN_ARGS, "body": "AKIAIOSFODNN7EXAMPLE"},
            connector=lambda args: calls.append(args) or {"messageId": "m-1"},
            idempotency_key="permit-2",
        )
        self.assertEqual(len(calls), 1)
        self.assertFalse(result.decision.execution_permitted)  # denied, but not enforced
        self.assertTrue(result.decision.permits_execution)


if __name__ == "__main__":
    unittest.main()
