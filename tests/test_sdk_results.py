"""The SDK shares the gateway's post-execution result handling and approval store (D6).

Approval was previously reachable only from `MCPToolGateway`; `CheckContext.approval_valid`
always defaulted `False` on the SDK path, so `INTERLOCK-APPROVAL-REQUIRED` was unavoidable for
any EXTERNAL_WRITE. And `_invoke` never sanitized or quarantined a tool result the way the
gateway's `inspect_result` does -- it only recorded schema errors and returned the raw value.
These tests pin both: `Interlock.grant_approval` makes the approval path reachable, and
`inspect_tool_result` (shared with `gateway.inspect_result`) is now applied to every SDK result.
"""

from __future__ import annotations

import unittest

from agent_interlock import ActorSpec, ActorType, InvocationIntent, LinkPolicy, PolicyMode, SideEffect
from agent_interlock.gateway import GatewayError
from agent_interlock.results import inspect_tool_result
from agent_interlock.sdk import Interlock
from agent_interlock.security import canonical_destination


def wired(
    policy: LinkPolicy,
    *,
    input_schema: dict | None = None,
    output_schema: dict | None = None,
    allowed_domains: frozenset | None = None,
    side_effects: frozenset | None = None,
):
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
            output_schema=output_schema or {},
            side_effects=side_effects or frozenset(),
        )
    )
    source.connect(target, policy)
    return interlock, source, target


class SDKApprovalTests(unittest.TestCase):
    def test_external_write_with_a_matching_approval_executes(self):
        interlock, source, target = wired(
            LinkPolicy(mode=PolicyMode.ENFORCE), side_effects=frozenset({SideEffect.EXTERNAL_WRITE})
        )
        guarded = target.wrap(lambda arguments: {"status": "sent"})
        arguments = {"to": "user@good.example"}
        approval = interlock.grant_approval(
            tenant_id="tenant-a",
            arguments=arguments,
            canonical_destinations=(canonical_destination("user@good.example"),),
            approver="operator",
        )
        result = guarded(
            arguments,
            source=source,
            tenant_id="tenant-a",
            intent=InvocationIntent(
                purpose="reply",
                destinations=("user@good.example",),
                estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                approval_id=approval.approval_id,
            ),
        )
        self.assertEqual(result, {"status": "sent"})

    def test_external_write_without_approval_is_blocked(self):
        _, source, target = wired(
            LinkPolicy(mode=PolicyMode.ENFORCE), side_effects=frozenset({SideEffect.EXTERNAL_WRITE})
        )
        guarded = target.wrap(lambda arguments: {"status": "sent"})
        with self.assertRaises(GatewayError) as raised:
            guarded(
                {"to": "user@good.example"},
                source=source,
                tenant_id="tenant-a",
                intent=InvocationIntent(
                    purpose="reply",
                    destinations=("user@good.example",),
                    estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                ),
            )
        self.assertIn("INTERLOCK-APPROVAL-REQUIRED", str(raised.exception))

    def test_approval_for_different_arguments_does_not_validate(self):
        interlock, source, target = wired(
            LinkPolicy(mode=PolicyMode.ENFORCE), side_effects=frozenset({SideEffect.EXTERNAL_WRITE})
        )
        guarded = target.wrap(lambda arguments: {"status": "sent"})
        approval = interlock.grant_approval(
            tenant_id="tenant-a",
            arguments={"to": "user@good.example"},
            canonical_destinations=(canonical_destination("user@good.example"),),
            approver="operator",
        )
        with self.assertRaises(GatewayError) as raised:
            guarded(
                {"to": "user@good.example", "body": "unapproved edit"},
                source=source,
                tenant_id="tenant-a",
                intent=InvocationIntent(
                    purpose="reply",
                    destinations=("user@good.example",),
                    estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                    approval_id=approval.approval_id,
                ),
            )
        self.assertIn("INTERLOCK-APPROVAL-REQUIRED", str(raised.exception))


class SDKResultInspectionTests(unittest.TestCase):
    def test_a_secret_in_the_result_is_redacted_and_labelled(self):
        _, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE))
        guarded = target.wrap(lambda arguments: {"note": "AKIAIOSFODNN7EXAMPLE"})
        result = guarded(
            {},
            source=source,
            tenant_id="tenant-a",
            intent=InvocationIntent(purpose="SUPPORT_LOOKUP"),
        )
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", result["note"])

    def test_a_secret_in_the_result_is_labelled_in_the_ledger(self):
        interlock, source, target = wired(LinkPolicy(mode=PolicyMode.ENFORCE))
        guarded = target.wrap(lambda arguments: {"note": "AKIAIOSFODNN7EXAMPLE"})
        guarded(
            {},
            source=source,
            tenant_id="tenant-a",
            intent=InvocationIntent(purpose="SUPPORT_LOOKUP"),
        )
        completed = next(event for event in interlock.ledger.all() if event.event_type == "INTERACTION_COMPLETED")
        self.assertIn("D5_REDACTED", completed.payload["labels"])
        self.assertTrue(completed.payload["secretDetected"])

    def test_a_schema_invalid_result_is_quarantined_under_enforce(self):
        interlock, source, target = wired(
            LinkPolicy(mode=PolicyMode.ENFORCE),
            output_schema={"type": "object", "required": ["status"]},
        )
        guarded = target.wrap(lambda arguments: {})
        result = guarded(
            {},
            source=source,
            tenant_id="tenant-a",
            intent=InvocationIntent(purpose="SUPPORT_LOOKUP"),
        )
        self.assertEqual(result, {"quarantined": True, "reason": "result schema validation failed"})
        completed = next(event for event in interlock.ledger.all() if event.event_type == "INTERACTION_COMPLETED")
        self.assertIn("SCHEMA_INVALID", completed.payload["labels"])
        outcome = next(event for event in interlock.ledger.all() if event.event_type == "SECURITY_OUTCOME_SET")
        self.assertEqual(outcome.payload["securityOutcome"], "SUCCEEDED")

    def test_a_schema_invalid_result_is_returned_sanitized_under_shadow(self):
        interlock, source, target = wired(
            LinkPolicy(mode=PolicyMode.SHADOW),
            output_schema={"type": "object", "required": ["status"]},
        )
        guarded = target.wrap(lambda arguments: {})
        result = guarded(
            {},
            source=source,
            tenant_id="tenant-a",
            intent=InvocationIntent(purpose="SUPPORT_LOOKUP"),
        )
        self.assertEqual(result, {})
        completed = next(event for event in interlock.ledger.all() if event.event_type == "INTERACTION_COMPLETED")
        self.assertIn("SCHEMA_INVALID", completed.payload["labels"])
        self.assertTrue(completed.payload["schemaErrors"])


class InspectToolResultTests(unittest.TestCase):
    def test_an_mcp_shaped_invalid_result_produces_an_mcp_shaped_quarantine(self):
        raw = {"content": [{"type": "text", "text": "wrong shape"}], "isError": False}
        inspection = inspect_tool_result(raw, {"type": "object", "required": ["structuredContent"]})
        self.assertIn("SCHEMA_INVALID", inspection.labels)
        self.assertEqual(
            inspection.clean,
            {
                "content": [{"type": "text", "text": "Tool result quarantined by Agent Interlock."}],
                "isError": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
