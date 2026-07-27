"""Pins every reason code policy.evaluate can emit, before the check table replaces its branches."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import UTC, datetime

from agent_interlock import (
    ActorSpec,
    ActorType,
    ControlDecision,
    CredentialClaims,
    DefinitionState,
    InvocationIntent,
    LinkPolicy,
    SideEffect,
    ToolDefinition,
    ToolRevision,
)
from agent_interlock.policy import EvaluationInput, evaluate

DIGEST = "sha256:characterization"


def clean_case() -> tuple[LinkPolicy, EvaluationInput]:
    """An evaluation that trips nothing. Every test below perturbs exactly one field."""
    definition = ToolDefinition(
        server_id="server-1",
        tool_name="lookup",
        title="Lookup",
        description="Reads a support record",
        input_schema={},
    )
    revision = ToolRevision(
        revision_id="rev-1",
        tool_id=definition.tool_id,
        definition=definition,
        canonical_digest=DIGEST,
        raw_digest=DIGEST,
        canonicalizer_version="1",
        state=DefinitionState.ACTIVE,
        reason_codes=(),
        observed_at=datetime(2026, 7, 27, tzinfo=UTC),
    )
    source = ActorSpec(id="agent-1", type=ActorType.AGENT, owner="team", identity="spiffe://agent-1")
    target = ActorSpec(
        id="tool-1",
        type=ActorType.TOOL,
        owner="team",
        identity="spiffe://tool-1",
        definition_digest=DIGEST,
    )
    credential = CredentialClaims(
        reference="ref-1",
        issuer="issuer",
        subject="subject",
        actor="agent-1",
        audience="",
        resource="",
        exchanged=True,
        delegation_depth=0,
    )
    context = EvaluationInput(
        source=source,
        target=target,
        revision=revision,
        intent=InvocationIntent(purpose="SUPPORT_LOOKUP"),
        arguments={},
        credential=credential,
        approval_valid=True,
        interaction_id="interaction-1",
        trace_id="trace-1",
        span_id="span-1",
    )
    return LinkPolicy(), context


class PolicyCharacterizationTests(unittest.TestCase):
    def test_clean_case_produces_no_findings(self):
        policy, context = clean_case()
        record = evaluate(policy, context)
        self.assertEqual(record.reason_codes, ())
        self.assertEqual(record.decision, ControlDecision.ALLOW)

    def test_every_reason_code_is_reachable(self):
        policy, context = clean_case()
        cases = [
            (
                "INTERLOCK-ACTOR-TYPE-DENIED",
                policy,
                replace(context, source=replace(context.source, type=ActorType.USER)),
            ),
            (
                "INTERLOCK-PURPOSE-DENIED",
                replace(policy, allowed_purposes=frozenset({"SUPPORT_LOOKUP"})),
                replace(context, intent=InvocationIntent(purpose="EXFILTRATE")),
            ),
            (
                "L1-M2-DEFINITION-NOT-ACTIVE",
                policy,
                replace(context, revision=replace(context.revision, state=DefinitionState.QUARANTINED)),
            ),
            (
                "L1-M2-DEFINITION-DRIFT",
                policy,
                replace(context, target=replace(context.target, definition_digest="sha256:other")),
            ),
            (
                "INTERLOCK-INPUT-SCHEMA-INVALID",
                policy,
                replace(
                    context,
                    revision=replace(
                        context.revision,
                        definition=replace(
                            context.revision.definition,
                            input_schema={"type": "object", "required": ["ticket"]},
                        ),
                    ),
                ),
            ),
            (
                "L1-M9-SENSITIVE-EGRESS",
                replace(policy, denied_data_classes=frozenset({"D7"})),
                replace(context, intent=InvocationIntent(purpose="SUPPORT_LOOKUP", data_classes=frozenset({"D7"}))),
            ),
            (
                "INTERLOCK-DATA-CLASS-DENIED",
                policy,
                replace(context, intent=InvocationIntent(purpose="SUPPORT_LOOKUP", data_classes=frozenset({"D5"}))),
            ),
            (
                "L1-M8-CREDENTIAL-DETECTED",
                policy,
                replace(context, arguments={"note": "AKIAIOSFODNN7EXAMPLE"}),
            ),
            (
                "L1-M5-CREDENTIAL-MISSING",
                policy,
                replace(
                    context,
                    credential=None,
                    intent=InvocationIntent(purpose="SUPPORT_LOOKUP", expected_audience="spiffe://tool-1"),
                ),
            ),
            (
                "L1-M5-TOKEN-PASSTHROUGH",
                policy,
                replace(context, credential=replace(context.credential, exchanged=False)),
            ),
            (
                "L1-M5-TOKEN-ACTOR-MISMATCH",
                policy,
                replace(context, credential=replace(context.credential, actor="agent-9")),
            ),
            (
                "L1-M5-TOKEN-AUDIENCE-MISMATCH",
                policy,
                replace(
                    context,
                    intent=InvocationIntent(purpose="SUPPORT_LOOKUP", expected_audience="spiffe://tool-1"),
                    credential=replace(context.credential, audience="spiffe://other"),
                ),
            ),
            (
                "L1-M5-DELEGATION-DEPTH",
                policy,
                replace(context, credential=replace(context.credential, delegation_depth=5)),
            ),
            (
                "L1-M9-NEW-DESTINATION",
                policy,
                replace(
                    context,
                    intent=InvocationIntent(purpose="SUPPORT_LOOKUP", destinations=("https://evil.example",)),
                ),
            ),
            (
                "L1-M9-VOLUME-EXCEEDED",
                replace(policy, max_export_records=10),
                replace(
                    context,
                    intent=InvocationIntent(purpose="SUPPORT_LOOKUP", estimated_record_count=99),
                ),
            ),
            (
                "L1-UNDECLARED-SIDE-EFFECT",
                policy,
                replace(
                    context,
                    intent=InvocationIntent(
                        purpose="SUPPORT_LOOKUP",
                        estimated_side_effect=SideEffect.INTERNAL_WRITE,
                    ),
                ),
            ),
            (
                "INTERLOCK-DESTRUCTIVE-WRITE",
                policy,
                replace(
                    context,
                    intent=InvocationIntent(
                        purpose="SUPPORT_LOOKUP",
                        estimated_side_effect=SideEffect.DESTRUCTIVE_WRITE,
                    ),
                ),
            ),
            (
                "INTERLOCK-APPROVAL-REQUIRED",
                policy,
                replace(
                    context,
                    approval_valid=False,
                    intent=InvocationIntent(
                        purpose="SUPPORT_LOOKUP",
                        estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                    ),
                ),
            ),
        ]
        for code, case_policy, case_context in cases:
            with self.subTest(code=code):
                record = evaluate(case_policy, case_context)
                self.assertIn(code, record.reason_codes)

    def test_unparseable_destination_emits_new_destination(self):
        """The canonical_destination ValueError path -- a destination string that cannot be parsed
        at all. It is one of the three sites emitting L1-M9-NEW-DESTINATION and the case above
        pins only the domain-allowlist site; without this the collapse into one check would be
        unguarded here."""
        policy, context = clean_case()
        context = replace(context, intent=InvocationIntent(purpose="SUPPORT_LOOKUP", destinations=("user@",)))
        record = evaluate(policy, context)
        self.assertIn("L1-M9-NEW-DESTINATION", record.reason_codes)
        self.assertEqual(record.decision, ControlDecision.HOLD)
        self.assertEqual(record.canonical_destinations, ())

    def test_missing_destination_on_external_write_emits_new_destination(self):
        """The third emission site: require_explicit_destination with nothing to point at.
        Also unpinned before this."""
        policy, context = clean_case()
        context = replace(
            context,
            intent=InvocationIntent(purpose="SUPPORT_LOOKUP", estimated_side_effect=SideEffect.EXTERNAL_WRITE),
        )
        record = evaluate(policy, context)
        self.assertIn("L1-M9-NEW-DESTINATION", record.reason_codes)


if __name__ == "__main__":
    unittest.main()
