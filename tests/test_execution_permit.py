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

import ast
import unittest
import uuid
from pathlib import Path

from l1_harness import TENANT, build_gateway
from test_decision_ranking import decided
from test_l1_matrix import BENIGN_ARGS

import agent_interlock
from agent_interlock import (
    ActorSpec,
    ActorType,
    ConfigDecision,
    ControlDecision,
    InMemoryLedger,
    InvocationIntent,
    LinkPolicy,
    MCPToolGateway,
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


class StubConfigGuard:
    """A config guard that returns the verdict it was built with.

    Duck-typed rather than a ConfigGuard subclass, and nothing in ``src/`` is mutated to reach it:
    ``MCPToolGateway`` takes the guard as a constructor argument and only ever calls
    ``check_runtime`` on it. That is the point -- the merge site must be safe for *any* producer,
    not only for the one ``ConfigGuard`` happens to be today.
    """

    def __init__(self, decision: ControlDecision, codes: tuple[str, ...] = ("STUB-CONFIG-VERDICT",)) -> None:
        self._decision = decision
        self._codes = codes

    def check_runtime(self, principal, config_id, probe, *, trace_id=None) -> ConfigDecision:
        return ConfigDecision(self._decision, self._codes, {}, interaction_id=str(uuid.uuid4()))


class StubConfigProbe:
    def effective(self, tenant_id, config_id):
        return None


def config_merged_record(verdict: ControlDecision, *, connector=None):
    """Evaluate one clean invocation through a gateway whose config guard returns ``verdict``.

    The invocation itself trips nothing, so every non-ALLOW state on the record comes from the
    merge. Returns (record, calls, gateway).
    """
    calls: list = []
    guarded = MCPToolGateway(
        ledger=InMemoryLedger(),
        config_guard=StubConfigGuard(verdict),
        config_probe=StubConfigProbe(),
        agent_config_ids={"agent.support": "cfg-support"},
    )
    gateway, revision, source, _ = build_gateway(gateway=guarded)
    record = gateway.evaluate_invocation(
        tenant_id=TENANT,
        source_actor_id=source.id,
        revision_id=revision.revision_id,
        intent=InvocationIntent(purpose="reply"),
        arguments=BENIGN_ARGS,
    )
    if connector is not None:
        try:
            gateway.execute_approved_call(
                record.decision_id, BENIGN_ARGS, connector(calls), idempotency_key=f"merge-{verdict.value}"
            )
        except InvocationBlocked:
            pass
    return record, calls, gateway


def last_policy_control(ledger):
    """The last CONTROL_EVALUATED the policy engine wrote.

    Keyed on ``actualEnforced``, which only the enforcement record carries: the config guard emits
    its own CONTROL_EVALUATED on the same trace and definition admission emits a third, and neither
    is the record under test here.
    """
    return next(
        event.payload["control"]
        for event in reversed(ledger.all())
        if event.event_type == "CONTROL_EVALUATED" and "actualEnforced" in event.payload.get("control", {})
    )


def decision_rewrite_sites() -> dict[str, list[str]]:
    """Every ``replace(...)`` in the package that rewrites a decision record's verdict.

    Keyed on the ``decision=`` keyword, which only ``PolicyDecisionRecord`` has -- the revision and
    config-revision rewrites elsewhere in ``src/`` pass ``state=``. Read out of the source rather
    than reached behaviourally because the hazard is a *site* that no fixture visits: the merge below
    went unwatched for exactly as long as nothing enumerated it.
    """
    sites: dict[str, list[str]] = {}
    for path in sorted(Path(agent_interlock.__file__).parent.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call) or getattr(node.func, "id", "") != "replace":
                continue
            keywords = sorted(keyword.arg for keyword in node.keywords if keyword.arg)
            if "decision" in keywords:
                sites[f"{path.name}:{node.lineno}"] = keywords
    return sites


class DecisionMergePermitTests(unittest.TestCase):
    """The gateway's second decision source: the config-guard verdict merged into the record.

    ``evaluate()`` aggregates the permit over its own findings, but the config guard's verdict never
    passes through it -- ``gateway.py`` merges that verdict into the finished record with
    ``replace()``. Updating ``decision`` there and not ``execution_permitted`` reopens H2 verbatim at
    the one place a decision is merged outside ``evaluate()``.
    """

    def test_a_bypassed_config_verdict_cannot_become_an_execution_permit(self):
        """H2, at the merge. ``strongest_decision`` annihilates BYPASSED against the invocation's own
        ALLOW, so the merged record reads ALLOW -- and before the permit was carried through the
        merge, it executed."""
        record, calls, _ = config_merged_record(
            ControlDecision.BYPASSED, connector=lambda calls: lambda arguments: calls.append(arguments)
        )
        self.assertIs(record.execution_permitted, False)
        self.assertIs(record.permits_execution, False)
        self.assertEqual(calls, [])

    def test_only_a_verdict_the_preflight_filters_out_leaves_the_permit_standing(self):
        """Written over the whole enum, because the current safety is a fact about a *different*
        module: ``ConfigGuard.check_runtime`` happens to emit QUARANTINE and never anything ranked
        below ALLOW. A profile-independent merge must narrow for every member, so the only verdict
        that leaves the permit standing is ALLOW -- and only because ``_config_preflight`` returns
        None for it, so it never reaches the merge at all."""
        permitting = {
            item for item in ControlDecision if config_merged_record(item)[0].execution_permitted
        }
        self.assertEqual(permitting, {ControlDecision.ALLOW})

    def test_the_merge_moves_neither_the_decision_nor_the_reason_codes(self):
        """The constraint the fix must not break, in the same file as the fix. Narrowing the permit
        must not be implemented by re-ranking BYPASSED or by rewriting what the ledger says: the
        record still reads ALLOW while the invocation is refused, and the config guard's codes still
        arrive after the invocation's own, in the order the merge appends them."""
        record, _, _ = config_merged_record(ControlDecision.BYPASSED)
        self.assertEqual(record.decision, ControlDecision.ALLOW)
        self.assertEqual(record.reason_codes, ("STUB-CONFIG-VERDICT",))
        quarantined, _, _ = config_merged_record(ControlDecision.QUARANTINE)
        self.assertEqual(quarantined.decision, ControlDecision.QUARANTINE)
        self.assertEqual(quarantined.reason_codes, ("STUB-CONFIG-VERDICT",))

    def test_every_site_that_rewrites_a_decision_record_carries_the_permit_through(self):
        """The audit, as an assertion. One unwatched merge is the finding; the second one nobody
        writes yet is the same finding again, so this fails on the site rather than on a symptom."""
        missing = {
            site: keywords for site, keywords in decision_rewrite_sites().items()
            if "execution_permitted" not in keywords
        }
        self.assertEqual(missing, {})
        self.assertNotEqual(decision_rewrite_sites(), {})  # not vacuous: there is a site to audit


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

    def test_a_record_carrying_no_permit_evidence_still_permits_an_allow(self):
        """PolicyDecisionRecord.execution_permitted defaults True, and that default is load-bearing.

        permits_execution ANDs the field with the severity test, which is what makes the documented
        claim true: the field can only ever *narrow* a permit, so a record built outside evaluate()
        behaves exactly as it did before the field existed. Flip the default to False and every such
        record silently stops permitting execution -- a real behaviour change for anyone
        constructing one. It fails closed, so nothing else in the suite objects, which is precisely
        why it needs its own pin: a mutation run found the default unguarded.
        """
        record = decided(ControlDecision.ALLOW, enforced=True)
        self.assertTrue(record.execution_permitted)
        self.assertTrue(record.permits_execution)

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

    def test_the_control_record_carries_the_permit_that_denied_the_call(self):
        """The ledger has to stop contradicting itself.

        On this configuration the call is denied and SECURITY_OUTCOME_SET says BLOCKED, while the
        control record says `decision: ALLOW, actualEnforced: true` -- the two answer different
        questions, and before the permit was aggregated separately that pair was consistent, because
        the call really did execute. The fix created a record no reader can reconcile: nothing in the
        payload said the invocation was refused. Additive, so no reason code moves.
        """
        interlock, _, _ = sdk_call(PolicyMode.ENFORCE)
        control = control_record(interlock)
        self.assertIs(control.get("executionPermitted"), False)
        self.assertEqual(control["decision"], "ALLOW")  # the severity reading, unmoved

    def test_a_clean_call_records_an_affirmative_permit(self):
        """Not vacuous: the key is a permit and not a constant. A record that always said False
        would satisfy the test above and tell a reducer nothing."""
        interlock = Interlock()
        source = interlock.define_actor(
            ActorSpec(id="agent-1", type=ActorType.AGENT, owner="team", identity="spiffe://agent-1")
        )
        target = interlock.define_actor(
            ActorSpec(id="tool-1", type=ActorType.TOOL, owner="team", identity="spiffe://tool-1")
        )
        source.connect(target, LinkPolicy(mode=PolicyMode.ENFORCE))
        guarded = target.wrap(lambda arguments: {"ok": True})
        guarded({}, source=source, tenant_id="tenant-a", intent=InvocationIntent(purpose="SUPPORT_LOOKUP"))
        self.assertIs(control_record(interlock).get("executionPermitted"), True)

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

    def test_the_gateway_control_record_carries_the_permit_too(self):
        """The same contradiction at the gateway, and the same additive remedy. A reader joining
        CONTROL_EVALUATED to SECURITY_OUTCOME_SET sees `ALLOW` against `BLOCKED` here; without this
        key nothing in the interaction explains which one is the enforcement fact."""
        gateway, revision, source, calls = self.invoked(PolicyMode.ENFORCE)
        with self.assertRaises(InvocationBlocked):
            gateway.invoke(
                tenant_id=TENANT,
                source_actor_id=source.id,
                revision_id=revision.revision_id,
                intent=InvocationIntent(purpose="reply", estimated_side_effect=SideEffect.READ),
                arguments={**BENIGN_ARGS, "body": "AKIAIOSFODNN7EXAMPLE"},
                connector=lambda args: calls.append(args),
                idempotency_key="permit-ledger-1",
            )
        control = last_policy_control(gateway.ledger)
        self.assertIs(control.get("executionPermitted"), False)
        self.assertEqual(control["decision"], "ALLOW")
        self.assertEqual(control["reasonCodes"], ["L1-M8-CREDENTIAL-DETECTED", "L1-UNDECLARED-SIDE-EFFECT"])

    def test_a_config_guard_verdict_reaches_the_control_record_as_a_denied_permit(self):
        """The merge site's own record. The config guard's BYPASSED verdict is annihilated in
        `decision`, so the permit key is the only thing in the payload that reports the denial."""
        _, _, gateway = config_merged_record(ControlDecision.BYPASSED)
        control = last_policy_control(gateway.ledger)
        self.assertIs(control.get("executionPermitted"), False)
        self.assertEqual(control["decision"], "ALLOW")

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
