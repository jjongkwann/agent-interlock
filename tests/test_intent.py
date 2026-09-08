"""Intent derivation, and the check that makes a declaration answer for it.

Two layers. `DerivationTests` pins `derive_intent` as a pure function over a schema, an argument
map and a tool's MCP annotations. `IntentMismatchCheckTests` pins the control built on it at both
enforcement points that carry it, including the three coverage states the check can report.
"""

from __future__ import annotations

import unittest
from dataclasses import replace

from l1_harness import OUTPUT_SCHEMA, TENANT, build_gateway

from agent_interlock import (
    ActorSpec,
    ActorType,
    InvocationIntent,
    LinkPolicy,
    PolicyMode,
    SideEffect,
    ToolDefinition,
)
from agent_interlock.analytics import reduce_interactions
from agent_interlock.gateway import GatewayError, InvocationBlocked
from agent_interlock.intent import DerivedIntent, derive_intent, side_effect_rank
from agent_interlock.policy import GATEWAY_PROFILE, SDK_PROFILE, CheckContext, run_checks
from agent_interlock.sdk import Interlock

CHECK_ID = "INTERLOCK-INTENT-ARGUMENT-MISMATCH"

# The email tool the rest of the suite uses, with the one thing that makes derivation possible:
# `to` is declared as an email address, so the schema itself says which argument is a destination.
MARKED_SCHEMA = {
    "type": "object",
    "required": ["to", "body"],
    "properties": {
        "to": {"type": "string", "format": "email"},
        "body": {"type": "string", "maxLength": 100_000},
    },
    "additionalProperties": False,
}


def marked_definition(*, annotations: dict | None = None, schema: dict | None = None) -> ToolDefinition:
    return ToolDefinition(
        server_id="tenant-a/prod/trusted-mail",
        tool_name="send_email",
        title="Send email",
        description="Send a message to an approved recipient.",
        input_schema=schema if schema is not None else MARKED_SCHEMA,
        output_schema=OUTPUT_SCHEMA,
        annotations=annotations or {},
        endpoint="https://mcp.example.com",
        publisher="platform-team",
        artifact_digest="sha256:" + "a" * 64,
    )


class DerivationTests(unittest.TestCase):
    def test_a_property_declared_as_an_email_names_a_destination(self):
        derived = derive_intent({"to": "a@customer.example", "body": "hi"}, MARKED_SCHEMA, {})
        self.assertEqual(derived.destinations, ("a@customer.example",))
        self.assertTrue(derived.derivable)

    def test_a_property_declared_as_a_uri_names_a_destination(self):
        schema = {"type": "object", "properties": {"hook": {"type": "string", "format": "uri"}}}
        self.assertEqual(
            derive_intent({"hook": "https://webhook.example/x"}, schema, {}).destinations,
            ("https://webhook.example/x",),
        )

    def test_a_marked_property_nested_under_another_object_is_reached(self):
        schema = {
            "type": "object",
            "properties": {
                "envelope": {
                    "type": "object",
                    "properties": {"host": {"type": "string", "format": "hostname"}},
                }
            },
        }
        arguments = {"envelope": {"host": "sink.evil.example"}}
        self.assertEqual(derive_intent(arguments, schema, {}).destinations, ("sink.evil.example",))

    def test_a_list_of_marked_strings_yields_every_entry(self):
        """The BCC shape from docs/03 section 6.9: one property, many recipients. Collecting only
        the first would let an exfiltration recipient ride behind a legitimate one."""
        schema = {
            "type": "object",
            "properties": {
                "recipients": {"type": "array", "items": {"type": "string", "format": "email"}}
            },
        }
        arguments = {"recipients": ["a@customer.example", "attacker@evil.example"]}
        self.assertEqual(
            derive_intent(arguments, schema, {}).destinations,
            ("a@customer.example", "attacker@evil.example"),
        )

    def test_the_extension_keyword_marks_a_property_format_cannot_describe(self):
        """`format` has no spelling for a channel id or a queue name, so a schema can mark one
        explicitly. security._IGNORED_SCHEMA_KEYWORDS allows the keyword through definition-time
        validation precisely so this pass can read it."""
        schema = {
            "type": "object",
            "properties": {"channel": {"type": "string", "x-interlock-destination": True}},
        }
        self.assertEqual(derive_intent({"channel": "#leaks"}, schema, {}).destinations, ("#leaks",))

    def test_a_marked_property_the_arguments_omit_still_makes_the_pass_derivable(self):
        """The mark is a property of the schema, not of the call. A call that leaves the property
        out is RAN_CLEAN -- the control looked and found no undeclared destination -- and not
        INAPPLICABLE, which would report the same call as unexamined."""
        derived = derive_intent({"body": "hi"}, MARKED_SCHEMA, {})
        self.assertEqual(derived.destinations, ())
        self.assertTrue(derived.derivable)

    def test_destructive_hint_derives_the_destructive_write(self):
        derived = derive_intent({}, {}, {"destructiveHint": True})
        self.assertEqual(derived.side_effect, SideEffect.DESTRUCTIVE_WRITE)
        self.assertTrue(derived.derivable)

    def test_read_only_hint_derives_a_read(self):
        self.assertEqual(derive_intent({}, {}, {"readOnlyHint": True}).side_effect, SideEffect.READ)

    def test_a_tool_asserting_both_hints_is_read_as_the_destructive_one(self):
        """A contradiction the tool author wrote, resolved in the fail-closed direction."""
        annotations = {"readOnlyHint": True, "destructiveHint": True}
        self.assertEqual(derive_intent({}, {}, annotations).side_effect, SideEffect.DESTRUCTIVE_WRITE)

    def test_nothing_marked_and_no_annotations_derives_nothing(self):
        derived = derive_intent({"ticket": "T-1"}, {"type": "object", "properties": {"ticket": {}}}, {})
        self.assertEqual(derived, DerivedIntent(destinations=(), side_effect=None, derivable=False))

    def test_the_rank_order_places_every_member_and_ranks_absence_below_them_all(self):
        """The check compares ranks, so a member missing from the map would raise inside a control.
        Asserted over the enum rather than over a list written here, so a new member fails."""
        ranks = [side_effect_rank(effect) for effect in SideEffect]
        self.assertEqual(len(set(ranks)), len(list(SideEffect)))
        self.assertLess(side_effect_rank(None), min(ranks))
        self.assertLess(side_effect_rank(SideEffect.NONE), side_effect_rank(SideEffect.EXTERNAL_WRITE))
        self.assertLess(
            side_effect_rank(SideEffect.EXTERNAL_WRITE), side_effect_rank(SideEffect.DESTRUCTIVE_WRITE)
        )


class IntentMismatchCheckTests(unittest.TestCase):
    def invoke(self, gateway, revision, source, intent, arguments, key="idem-intent"):
        return gateway.invoke(
            connector=lambda values: {"status": "SENT"},
            idempotency_key=key,
            tenant_id=TENANT,
            source_actor_id=source.id,
            revision_id=revision.revision_id,
            intent=intent,
            arguments=arguments,
        )

    def test_an_argument_naming_a_destination_the_intent_omits_is_blocked_at_the_gateway(self):
        """The adoption-path attack in one call: the model fills in a recipient and declares no
        destination at all, so every M9 control that reads `intent.destinations` has nothing to
        judge and the call sails through. Here the schema says `to` is a destination."""
        gateway, revision, source, _ = build_gateway(definition=marked_definition())
        with self.assertRaises(InvocationBlocked) as raised:
            self.invoke(
                gateway,
                revision,
                source,
                InvocationIntent(purpose="notify-customer"),
                {"to": "attacker@evil.example", "body": "the customer list"},
            )
        self.assertIn(CHECK_ID, str(raised.exception))

    def test_the_same_call_is_blocked_at_the_sdk(self):
        """The check is in both profiles, so wrap() refuses what the gateway refuses. The SDK
        resolves no revision, so it derives from ActorSpec.input_schema through _effective_schema."""
        interlock = Interlock()
        caller = interlock.define_actor(
            ActorSpec(id="agent-1", type=ActorType.AGENT, owner="team", identity="spiffe://agent-1")
        )
        callee = interlock.define_actor(
            ActorSpec(
                id="tool-1",
                type=ActorType.TOOL,
                owner="team",
                identity="spiffe://tool-1",
                input_schema=MARKED_SCHEMA,
                allowed_domains=frozenset({"customer.example"}),
            )
        )
        interlock.connect(caller, callee, LinkPolicy(mode=PolicyMode.ENFORCE))
        guarded = callee.wrap(lambda arguments: {"ok": True})
        with self.assertRaises(GatewayError) as raised:
            guarded(
                {"to": "attacker@evil.example", "body": "hi"},
                source=caller,
                tenant_id=TENANT,
                intent=InvocationIntent(purpose="notify-customer"),
            )
        self.assertIn(CHECK_ID, str(raised.exception))

    def test_a_declaration_that_covers_the_argument_passes(self):
        """The other half: the control must not simply deny every marked argument. Declaring the
        destination the argument names is what the control is asking for, and it is enough."""
        gateway, revision, source, _ = build_gateway(definition=marked_definition())
        result = self.invoke(
            gateway,
            revision,
            source,
            InvocationIntent(
                purpose="notify-customer",
                destinations=("a@customer.example",),
                estimated_side_effect=SideEffect.EXTERNAL_WRITE,
            ),
            {"to": "a@customer.example", "body": "hello"},
        )
        self.assertNotIn(CHECK_ID, result.decision.reason_codes)
        self.assertEqual(result.value, {"status": "SENT"})

    def test_a_destructive_tool_invoked_as_a_no_op_is_blocked(self):
        """The annotation half. `destructiveHint` is MCP's statement about every call to the tool,
        so a caller declaring NONE is contradicting the tool's own definition."""
        gateway, revision, source, _ = build_gateway(
            definition=marked_definition(annotations={"destructiveHint": True})
        )
        with self.assertRaises(InvocationBlocked) as raised:
            self.invoke(
                gateway,
                revision,
                source,
                InvocationIntent(purpose="notify-customer", destinations=("a@customer.example",)),
                {"to": "a@customer.example", "body": "hello"},
            )
        self.assertIn(CHECK_ID, str(raised.exception))

    def test_a_tool_that_marks_nothing_leaves_the_check_inapplicable(self):
        """A schema with no marked property and no annotations gives the control nothing to compare
        against. That is INAPPLICABLE -- out of `ran` -- and not a clean pass: reporting RAN_CLEAN
        here would count every schema-less tool in a fleet as covered by this control."""
        gateway, revision, source, target = build_gateway()
        context = CheckContext(
            source=source,
            target=target,
            revision=revision,
            intent=InvocationIntent(purpose="notify-customer"),
            arguments={"to": "attacker@evil.example", "body": "hi"},
            interaction_id="i",
            trace_id="t",
            span_id="s",
        )
        for profile in (GATEWAY_PROFILE, SDK_PROFILE):
            with self.subTest(enforcement_point=profile.enforcement_point):
                outcome = run_checks(LinkPolicy(), context, replace(profile, checks=(CHECK_ID,)))
                self.assertEqual(outcome.armed, (CHECK_ID,))  # armed: the tool does ship a schema
                self.assertNotIn(CHECK_ID, outcome.ran)

    def test_the_coverage_channel_reports_the_check_at_each_of_its_three_states(self):
        """`ran`/`flagged` are what the statistics read, so the check has to be visible there and
        not only in the verdict. One gateway, three calls, three states."""
        gateway, revision, source, _ = build_gateway(definition=marked_definition())
        self.invoke(
            gateway,
            revision,
            source,
            InvocationIntent(
                purpose="notify-customer",
                destinations=("a@customer.example",),
                estimated_side_effect=SideEffect.EXTERNAL_WRITE,
            ),
            {"to": "a@customer.example", "body": "hello"},
            key="idem-clean",
        )
        with self.assertRaises(InvocationBlocked):
            self.invoke(
                gateway,
                revision,
                source,
                InvocationIntent(purpose="notify-customer"),
                {"to": "attacker@evil.example", "body": "hi"},
                key="idem-flagged",
            )
        events = gateway.ledger.interaction_lifecycles_started_between(
            TENANT, "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"
        )
        records = reduce_interactions([event.to_dict() for event in events])
        self.assertTrue(all(CHECK_ID in record.coverage.armed for record in records))
        self.assertTrue(all(CHECK_ID in record.coverage.ran for record in records))
        self.assertEqual(
            sorted(CHECK_ID in record.coverage.flagged for record in records), [False, True]
        )


if __name__ == "__main__":
    unittest.main()
