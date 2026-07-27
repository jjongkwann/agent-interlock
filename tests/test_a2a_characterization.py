"""Pins every A2A link and boundary finding before they move into the shared check table.

Operational A2AError codes (A2A-TASK-NOT-FOUND, A2A-IDEMPOTENCY-CONFLICT and
similar) are deliberately not covered: they are not policy findings and are not
moving.
"""

from __future__ import annotations

import copy
import unittest
from dataclasses import replace

from test_a2a import boundary_manifest, broker_fixture, request_message, send_context

from agent_interlock import (
    A2AMessage,
    A2AMessageRole,
    A2APart,
    A2APolicyError,
    A2ASendContext,
)


def rejected_codes(
    manifest=None, *, principal_changes=None, context_changes=None, message=None
) -> tuple[str, ...]:
    """Send one message through a perturbed broker and return the reason codes it was rejected with."""
    broker, _, _, principal = broker_fixture(manifest)
    if principal_changes:
        principal = replace(principal, **principal_changes)
    context = send_context(principal)
    if context_changes:
        context = A2ASendContext(
            principal=principal,
            source_actor_id=context.source_actor_id,
            target_actor_id=context.target_actor_id,
            purpose=context_changes.get("purpose", context.purpose),
            data_classes=context_changes.get("data_classes", context.data_classes),
            idempotency_key=context.idempotency_key,
        )
    try:
        broker.send_message(message if message is not None else request_message(), context)
    except A2APolicyError as error:
        return error.reason_codes
    return ()


def _rel06_edge(manifest: dict) -> dict:
    return next(edge for edge in manifest["spec"]["edges"] if edge["relationshipId"] == "REL-06")


def _node(manifest: dict, actor_id: str) -> dict:
    return next(node for node in manifest["spec"]["nodes"] if node["id"] == actor_id)


def actor_type_denied_manifest() -> dict:
    """REL-06 is a dynamic edge: its `policy.target_types` is derived from the *declared* target
    node's type, not the actor the message actually resolves to (the target selector just fnmatches
    "agent.research*"). Repointing the edge at a same-zone AGENT-typed mirror node keeps the
    resolved actor (agent.research, SUBAGENT) matching the selector while making it fail the
    declared type check. Orchestration is dropped: its task.research entry expects REL-06 to still
    target agent.research directly, which no longer holds once the edge is repointed.
    """
    manifest = boundary_manifest()
    manifest["spec"].pop("orchestration", None)
    mirror = copy.deepcopy(_node(manifest, "agent.research"))
    mirror["id"] = "agent.research-mirror"
    mirror["type"] = "AGENT"
    manifest["spec"]["nodes"].append(mirror)
    _rel06_edge(manifest)["target"] = "agent.research-mirror"
    return manifest


def input_schema_invalid_manifest() -> dict:
    manifest = boundary_manifest()
    _node(manifest, "agent.research")["inputSchema"] = {"type": "object", "required": ["confirmation"]}
    return manifest


def boundary_relationship_denied_manifest() -> dict:
    """Both the compiled architecture's linter and the A2A broker check
    `edge.relationship in boundary.allowed_relationships`, but the linter only runs that check when
    the edge crosses trust zones. Moving both worker-side actors into the control zone makes the
    linter treat REL-06 as same-zone (a warning, not critical) while its boundaryId stays bound, so
    the broker's own boundary check -- which does not gate on zone-crossing -- still applies.
    """
    manifest = boundary_manifest()
    for actor_id in ("agent.research", "rag.support-knowledge"):
        _node(manifest, actor_id)["trustZoneId"] = "zone.control"
    manifest["spec"]["trustBoundaries"][0]["allowedRelationships"] = ["INVOKES"]
    return manifest


def boundary_payload_too_large_manifest() -> dict:
    manifest = boundary_manifest()
    manifest["spec"]["trustBoundaries"][0]["maxPayloadBytes"] = 1
    return manifest


def credential_message() -> A2AMessage:
    return A2AMessage(role=A2AMessageRole.USER, parts=(A2APart.data_part({"key": "AKIAIOSFODNN7EXAMPLE"}),))


class A2ACharacterizationTests(unittest.TestCase):
    def test_clean_send_is_not_rejected(self):
        self.assertEqual(rejected_codes(), ())

    def test_link_findings_are_reachable(self):
        cases = [
            ("A2A-IDENTITY-BINDING-MISMATCH", {"principal_changes": {"authenticated": False}}),
            ("A2A-ACTOR-BINDING-MISMATCH", {"principal_changes": {"actor_id": "agent.impersonator"}}),
            ("A2A-AUDIENCE-MISMATCH", {"principal_changes": {"audience": "spiffe://wrong"}}),
            ("A2A-RESOURCE-MISMATCH", {"principal_changes": {"resource": "a2a://wrong"}}),
            ("A2A-TOKEN-PASSTHROUGH", {"principal_changes": {"exchanged": False}}),
            ("A2A-DELEGATION-DEPTH", {"principal_changes": {"delegation_depth": 9}}),
            ("A2A-PURPOSE-DENIED", {"context_changes": {"purpose": "EXFILTRATE"}}),
            ("A2A-DATA-CLASS-DENIED", {"context_changes": {"data_classes": frozenset({"D8"})}}),
        ]
        for code, kwargs in cases:
            with self.subTest(code=code):
                self.assertIn(code, rejected_codes(**kwargs))

    def test_boundary_findings_are_reachable(self):
        cases = [
            ("A2A-BOUNDARY-DATA-CLASS-DENIED", {"context_changes": {"data_classes": frozenset({"D5"})}}),
            ("A2A-BOUNDARY-IDENTITY-REQUIRED", {"principal_changes": {"authenticated": False}}),
        ]
        for code, kwargs in cases:
            with self.subTest(code=code):
                self.assertIn(code, rejected_codes(**kwargs))
        # A2A-BOUNDARY-TENANT-REQUIRED fires on `context.principal.tenant_id == ""`, but
        # A2APrincipal.__post_init__ rejects an empty tenant_id unconditionally, and
        # A2ABroker.send_message's own leading guard raises A2A-TENANT-INVALID for an empty tenant
        # before boundary reasons are ever evaluated. No principal reachable through the public
        # constructor can trip this branch; left uncovered rather than contorted. See report.

    def test_manifest_perturbed_findings_are_reachable(self):
        cases = [
            ("A2A-ACTOR-TYPE-DENIED", {"manifest": actor_type_denied_manifest()}),
            ("A2A-INPUT-SCHEMA-INVALID", {"manifest": input_schema_invalid_manifest()}),
            ("A2A-BOUNDARY-RELATIONSHIP-DENIED", {"manifest": boundary_relationship_denied_manifest()}),
            ("A2A-BOUNDARY-PAYLOAD-TOO-LARGE", {"manifest": boundary_payload_too_large_manifest()}),
            ("A2A-CREDENTIAL-DETECTED", {"message": credential_message()}),
        ]
        for code, kwargs in cases:
            with self.subTest(code=code):
                self.assertIn(code, rejected_codes(**kwargs))

    # A2A-PAYLOAD-INVALID fires only when payload_bytes < 1, which no well-formed A2AMessage can
    # produce (canonical JSON encoding of even an empty message is several bytes). Left uncovered.


if __name__ == "__main__":
    unittest.main()
