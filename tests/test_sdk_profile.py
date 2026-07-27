"""The SDK reaches the same verdict as the gateway for the checks it shares."""

from __future__ import annotations

import unittest

from agent_interlock import ActorSpec, ActorType, CredentialClaims, InvocationIntent, LinkPolicy, PolicyMode, SideEffect
from agent_interlock.gateway import GatewayError
from agent_interlock.policy import GATEWAY_PROFILE, SDK_PROFILE
from agent_interlock.sdk import Interlock


def wired(policy: LinkPolicy):
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
            allowed_domains=frozenset({"good.example"}),
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

    def test_profile_is_the_gateway_order_minus_the_two_m2_checks(self):
        """The M2 pair is ABSENT at this enforcement point, not inapplicable to the call: the SDK
        has no ToolRevision. Everything else keeps GATEWAY_PROFILE's order, because
        strongest_decision still resolves ties by position."""
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

    def test_credential_keyword_reaches_the_m5_checks(self):
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
            ),
        )
        self.assertEqual(result, {"ok": True})


if __name__ == "__main__":
    unittest.main()
