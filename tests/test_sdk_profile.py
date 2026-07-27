"""The SDK reaches the same verdict as the gateway for the checks it shares."""

from __future__ import annotations

import unittest
from dataclasses import replace

from agent_interlock import ActorSpec, ActorType, CredentialClaims, InvocationIntent, LinkPolicy, PolicyMode, SideEffect
from agent_interlock.gateway import GatewayError
from agent_interlock.policy import GATEWAY_PROFILE, SDK_PROFILE, CheckContext, run_checks
from agent_interlock.sdk import Interlock


def wired(policy: LinkPolicy, input_schema: dict | None = None, allowed_domains: frozenset | None = None):
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
            allowed_domains=frozenset({"good.example"}) if allowed_domains is None else allowed_domains,
            input_schema=input_schema or {},
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

    def test_actor_input_schema_is_validated_without_a_revision(self):
        """The SDK never builds a ToolRevision, so _input_schema has to fall back to
        ActorSpec.input_schema -- reading only the revision made wrap() stop validating
        arguments entirely."""
        _, source, target = wired(
            LinkPolicy(mode=PolicyMode.ENFORCE),
            input_schema={"type": "object", "required": ["ticket"]},
        )
        guarded = target.wrap(lambda arguments: {"ok": True})
        with self.assertRaises(GatewayError) as raised:
            guarded(
                {"wrong": 1},
                source=source,
                tenant_id="tenant-a",
                intent=InvocationIntent(purpose="SUPPORT_LOOKUP"),
            )
        self.assertIn("INTERLOCK-INPUT-SCHEMA-INVALID", str(raised.exception))

    def test_empty_actor_input_schema_keeps_the_check_out_of_ran(self):
        """The fallback must not turn a schema-less tool into a clean pass: nothing was
        validated, so the check is INAPPLICABLE and stays out of `ran`."""
        policy = LinkPolicy(mode=PolicyMode.ENFORCE)
        _, source, target = wired(policy)
        _, _, ran = run_checks(
            policy,
            CheckContext(
                source=source.spec,
                target=target.spec,
                intent=InvocationIntent(purpose="SUPPORT_LOOKUP"),
                arguments={"wrong": 1},
                interaction_id="i",
                trace_id="t",
                span_id="s",
            ),
            SDK_PROFILE,
        )
        self.assertNotIn("INTERLOCK-INPUT-SCHEMA-INVALID", ran)

    def test_repeated_findings_are_de_duplicated_in_the_ledger(self):
        """_new_destination emits one finding per offending destination, so without the same
        dict.fromkeys() evaluate() applies, a reducer would see the SDK and the gateway disagree
        on reason-code cardinality for identical inputs."""
        interlock, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE))
        guarded = target.wrap(lambda arguments: {"ok": True})
        with self.assertRaises(GatewayError):
            guarded(
                {},
                source=source,
                tenant_id="tenant-a",
                intent=InvocationIntent(
                    purpose="SUPPORT_LOOKUP",
                    destinations=("https://evil.example", "https://worse.example"),
                    estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                ),
            )
        evaluated = next(event for event in interlock.ledger.all() if event.event_type == "CONTROL_EVALUATED")
        reasons = evaluated.payload["control"]["reasonCodes"]
        self.assertEqual(reasons.count("L1-M9-NEW-DESTINATION"), 1)

    def test_profile_is_the_gateway_order_minus_the_two_m2_checks(self):
        """The M2 pair is ABSENT at this enforcement point, not inapplicable to the call: the SDK
        has no ToolRevision. Everything else keeps GATEWAY_PROFILE's order so the two points emit
        reason codes in the same order; since _DECISION_RANK became total *and injective* the
        order no longer moves the verdict. Totality alone would not be enough -- a total map with
        two members sharing a rank is still order-dependent, which is why distinctness is guarded
        behaviourally by test_decision_ranking rather than at import."""
        self.assertEqual(
            SDK_PROFILE.checks,
            tuple(item for item in GATEWAY_PROFILE.checks if not item.startswith("L1-M2-")),
        )
        self.assertIn("INTERLOCK-TAINTED-EXTERNAL-WRITE", SDK_PROFILE.checks)

    def test_taint_check_survived_the_move_into_the_table(self):
        """The one control the SDK owned that the gateway did not; the table is now its only
        implementation, so its exact reason code needs a test of its own."""
        _, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE))
        guarded = target.wrap(lambda arguments: {"ok": True})
        with self.assertRaises(GatewayError) as raised:
            guarded(
                {},
                source=source,
                tenant_id="tenant-a",
                intent=InvocationIntent(
                    purpose="SUPPORT_LOOKUP",
                    destinations=("https://good.example",),
                    estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                    taint_labels=frozenset({"UNTRUSTED_INPUT"}),
                ),
            )
        self.assertIn("INTERLOCK-TAINTED-EXTERNAL-WRITE", str(raised.exception))

    def test_a_denied_d7_keeps_emitting_the_code_this_point_has_always_emitted(self):
        """The SDK's data-class control is one of the four it has always had, and it has always
        reported every denial as INTERLOCK-DATA-CLASS-DENIED -- main's wrap() had no second branch.
        Routing it through the shared check gained that branch, so a denied D7 started reaching the
        ledger as L1-M9-SENSITIVE-EGRESS and any reducer keyed on the SDK's byReasonCode silently
        split one bucket into two. The gateway keeps L1-M9-SENSITIVE-EGRESS; only this point renames
        it back, which is why SDK_PROFILE needs a rename map of its own rather than the gateway's.
        """
        policy = LinkPolicy(mode=PolicyMode.ENFORCE)
        policy = replace(policy, denied_data_classes=policy.denied_data_classes | {"D7"})
        interlock, source, target = wired(policy)
        guarded = target.wrap(lambda arguments: {"ok": True})
        with self.assertRaises(GatewayError):
            guarded(
                {},
                source=source,
                tenant_id="tenant-a",
                intent=InvocationIntent(purpose="SUPPORT_LOOKUP", data_classes=frozenset({"D7"})),
            )
        evaluated = next(event for event in interlock.ledger.all() if event.event_type == "CONTROL_EVALUATED")
        self.assertEqual(evaluated.payload["control"]["reasonCodes"], ["INTERLOCK-DATA-CLASS-DENIED"])

    def test_the_gateway_still_emits_the_sensitive_egress_code_for_the_same_input(self):
        """The other half of the rename: the SDK's map must not be the gateway's. Written as a
        direct comparison of the two profiles' output on one context, because the failure being
        guarded is a shared mutable map -- fixing the SDK by editing the object both profiles point
        at would satisfy the test above and silently move the gateway's wire code instead."""
        policy = LinkPolicy(mode=PolicyMode.ENFORCE)
        policy = replace(policy, denied_data_classes=policy.denied_data_classes | {"D7"})
        _, source, target = wired(policy)
        context = CheckContext(
            source=source.spec,
            target=target.spec,
            intent=InvocationIntent(purpose="SUPPORT_LOOKUP", data_classes=frozenset({"D7"})),
            arguments={},
            interaction_id="i",
            trace_id="t",
            span_id="s",
        )
        self.assertEqual(run_checks(policy, context, GATEWAY_PROFILE)[0], ["L1-M9-SENSITIVE-EGRESS"])
        self.assertEqual(run_checks(policy, context, SDK_PROFILE)[0], ["INTERLOCK-DATA-CLASS-DENIED"])

    def test_a_malformed_allowlist_entry_still_produces_a_control_record(self):
        """main's SDK never read allowed_domains; routing wrap() through the shared table made it
        IDNA-encode the allowlist, and an over-long DNS label raised UnicodeError out of wrap()
        after INTERACTION_REQUESTED and DATA_FLOW_OBSERVED and before CONTROL_EVALUATED. That
        leaves a ledger interaction with no control record at all -- Plan 2's reducer reads it as
        un-evaluated, which is the defect class this plan exists to eliminate, newly created in
        production code. Every invocation that reaches the policy layer must produce a verdict.
        """
        interlock, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE), allowed_domains=frozenset({"x" * 70}))
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
        types = [event.event_type for event in interlock.ledger.all()]
        self.assertIn("CONTROL_EVALUATED", types)

    def test_a_malformed_allowlist_entry_is_not_a_silent_permit(self):
        """The fail-closed direction, stated on the surface that decides whether the call runs. A
        malformed allowlist entry must never let the wrapped function execute: the entry allows
        nothing, so the destination it named is simply not allowed.

        The raised exception is asserted on its reason code, not merely on its type. This intent is
        an EXTERNAL_WRITE, so L1-UNDECLARED-SIDE-EFFECT and INTERLOCK-APPROVAL-REQUIRED also fire and
        a bare assertRaises(GatewayError) passes even when the destination control has been made to
        fail open -- the test would have been satisfied by controls it is not about."""
        _, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE), allowed_domains=frozenset({"x" * 70}))
        calls = []
        guarded = target.wrap(lambda arguments: calls.append(arguments) or {"ok": True})
        with self.assertRaises(GatewayError) as raised:
            guarded(
                {},
                source=source,
                tenant_id="tenant-a",
                intent=InvocationIntent(
                    purpose="SUPPORT_LOOKUP",
                    destinations=("https://x" + "x" * 69 + "/",),
                    estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                ),
            )
        self.assertIn("L1-M9-NEW-DESTINATION", str(raised.exception))
        self.assertEqual(calls, [])

    def test_credential_keyword_reaches_the_m5_checks(self):
        """The keyword still reaches M5, and only an *authenticated* credential executes.

        This test used to build the credential without setting `authenticated` and expect the call
        to run. That expectation blessed a hole. `CredentialClaims.authenticated` defaults to False
        and every other field on it is whatever the caller wrote, so the M5 checks -- which compared
        those self-asserted fields against each other and against the intent -- passed on a
        credential nobody had verified. A caller who forged one got a clean pass where a caller who
        presented nothing got L1-M5-CREDENTIAL-MISSING.

        What it pins now: passing a credential object is not passing a credential. Only a producer
        that ran a verifier says so -- MCPAuthorizationCodeTokenClient.exchange is the only one in
        src/ -- and the presence half of M5 reads that flag, not the object's existence.
        """
        _, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE))
        guarded = target.wrap(lambda arguments: {"ok": True})
        intent = InvocationIntent(
            purpose="SUPPORT_LOOKUP",
            expected_audience="https://tool-1.example",
            expected_resource="https://tool-1.example/records",
        )
        with self.assertRaises(GatewayError) as raised:
            guarded({}, source=source, tenant_id="tenant-a", intent=intent)
        self.assertIn("L1-M5-CREDENTIAL-MISSING", str(raised.exception))
        result = guarded(
            {},
            source=source,
            tenant_id="tenant-a",
            intent=intent,
            credential=CredentialClaims(
                reference="vault://token",
                issuer="https://issuer.example",
                subject="user-1",
                actor="agent-1",
                audience="https://tool-1.example",
                resource="https://tool-1.example/records",
                authenticated=True,
            ),
        )
        self.assertEqual(result, {"ok": True})

    def test_a_forged_credential_is_no_better_than_presenting_none(self):
        """Every field here is attacker-chosen and internally consistent: the actor names the
        source, the audience and resource name what the intent expects, and the issuer is the
        attacker's own. Only `authenticated` -- which no caller can honestly set -- says otherwise.

        The property is the asymmetry, not just the block: presenting a forged credential must not
        buy an attacker anything over presenting none. Both are asserted against the same literal
        verdict so that a fix which merely blocks *differently* still fails.
        """
        interlock, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE))
        calls = []
        guarded = target.wrap(lambda arguments: calls.append(arguments) or {"ok": True})
        intent = InvocationIntent(
            purpose="SUPPORT_LOOKUP",
            expected_audience="https://tool-1.example",
            expected_resource="https://tool-1.example/records",
        )
        forged = CredentialClaims(
            reference="vault://token",
            issuer="https://attacker.example",
            subject="whoever",
            actor="agent-1",
            audience="https://tool-1.example",
            resource="https://tool-1.example/records",
        )
        with self.assertRaises(GatewayError) as raised:
            guarded({}, source=source, tenant_id="tenant-a", intent=intent, credential=forged)
        self.assertIn("L1-M5-CREDENTIAL-MISSING", str(raised.exception))
        self.assertEqual(calls, [])
        with self.assertRaises(GatewayError):
            guarded({}, source=source, tenant_id="tenant-a", intent=intent)
        forged_record, absent_record = (
            event.payload["control"]
            for event in interlock.ledger.all()
            if event.event_type == "CONTROL_EVALUATED"
        )
        self.assertEqual(forged_record["reasonCodes"], ["L1-M5-CREDENTIAL-MISSING"])
        self.assertEqual(forged_record["decision"], "BLOCK")
        self.assertEqual(forged_record, absent_record)


if __name__ == "__main__":
    unittest.main()
