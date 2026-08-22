"""The coverage channel: what `armed`, `ran` and `flagged` are allowed to mean.

Plan 1 built the three states and left them unobservable -- `run_checks` returned `ran` and every
call site discarded it. This file guards the properties Plan 2 needs before a statistic can be
wired to them, and each test names the way the property fails when nobody watches it:

- A check whose subject is empty must report INAPPLICABLE, not a clean pass over a look it never
  took. That is the difference between a coverage number and a comforting one.
- `armed` must not vary with the invocation, because the armed set is declared once per digest
  rather than recorded per event.
- A profile's membership is pinned whole, because `assertNotIn(id, ran)` passes just as well when
  the id was quietly dropped from the profile.
"""

import json
import unittest
from dataclasses import replace
from pathlib import Path

from agent_interlock.a2a import A2AMessage, A2AMessageRole, A2APart, A2APartKind, A2APrincipal
from agent_interlock.analytics import check_catalogue, coverage_declarations, reduce_interactions
from agent_interlock.canonical import canonical_digest
from agent_interlock.ledger_http import _EVENT_TYPES
from agent_interlock.models import (
    ActorSpec,
    ActorType,
    ControlDecision,
    CredentialClaims,
    InvocationIntent,
    LinkPolicy,
    SideEffect,
)
from agent_interlock.policy import (
    A2A_BOUNDARY_PROFILE,
    A2A_LINK_PROFILE,
    A2A_PROFILE,
    CHECKS,
    GATEWAY_PROFILE,
    SDK_PROFILE,
    CheckContext,
    CheckScope,
    control_coverage,
    coverage_declaration,
    run_checks,
)

FIXTURES = Path(__file__).resolve().parent.parent / "schemas" / "fixtures"


def actor(actor_id, actor_type=ActorType.TOOL, **kwargs):
    return ActorSpec(id=actor_id, type=actor_type, identity=f"spiffe://{actor_id}", owner="team", **kwargs)


SOURCE = actor("agent.a", ActorType.AGENT)
TARGET = actor("tool.b", allowed_domains=frozenset({"crm.example"}))


def credential(**kwargs):
    base = dict(
        reference="ref",
        issuer="issuer",
        subject="subject",
        actor="agent.a",
        audience="aud",
        resource="res",
        authenticated=True,
    )
    base.update(kwargs)
    return CredentialClaims(**base)


def context(**kwargs):
    base = dict(
        source=SOURCE,
        target=TARGET,
        intent=InvocationIntent(purpose="lookup"),
        arguments={"q": "hello"},
        interaction_id="ia",
        trace_id="tr",
        span_id="sp",
        relationship="INVOKES",
    )
    base.update(kwargs)
    return CheckContext(**base)


class EmptySubjectTests(unittest.TestCase):
    """One rule, stated once and applied to every check that has an emptiable subject.

    A check whose subject is empty returns None (INAPPLICABLE); it never returns () (RAN_CLEAN).
    `()` there is the defect this whole branch exists to remove: a fleet of tools that ship no
    input schema, or traffic that declares no data classes, would report near-total coverage of
    nothing. The cases below are the four the audit found, each with the non-empty case beside it
    so the test also fails if a check stops running when it should.
    """

    def assert_inapplicable_when_empty(self, check_id, empty, populated):
        check = CHECKS[check_id]
        self.assertIsNone(check.run(LinkPolicy(), empty), f"{check_id}: empty subject must be INAPPLICABLE")
        self.assertIsNotNone(check.run(LinkPolicy(), populated), f"{check_id}: populated subject must run")

    def test_data_classes_without_a_declared_class(self):
        self.assert_inapplicable_when_empty(
            "INTERLOCK-DATA-CLASS-DENIED",
            context(intent=InvocationIntent(purpose="p", data_classes=frozenset())),
            context(intent=InvocationIntent(purpose="p", data_classes=frozenset({"D2"}))),
        )

    def test_boundary_data_classes_without_a_declared_class(self):
        boundary = _Boundary()
        self.assert_inapplicable_when_empty(
            "A2A-BOUNDARY-DATA-CLASS-DENIED",
            context(boundary=boundary, intent=InvocationIntent(purpose="p", data_classes=frozenset())),
            context(boundary=boundary, intent=InvocationIntent(purpose="p", data_classes=frozenset({"D2"}))),
        )

    def test_the_secret_scan_over_arguments_holding_no_strings(self):
        # contains_secret returns False both for "scanned, clean" and for "nothing to scan". Only
        # the first is a control that ran. An arguments map of numbers is the second.
        self.assert_inapplicable_when_empty(
            "L1-M8-CREDENTIAL-DETECTED",
            context(arguments={"count": 3, "flags": [True, None]}),
            context(arguments={"note": "plain text"}),
        )

    def test_the_volume_cap_on_a_zero_estimate(self):
        # InvocationIntent estimates one record and zero bytes by default, so out of the box a
        # link that caps bytes has a byte control with nothing to measure. That is INAPPLICABLE;
        # () would report a size limit enforced over a size nobody supplied.
        policy = LinkPolicy(max_export_records=10, max_export_bytes=1000)
        for check_id, field in (
            ("L1-M9-VOLUME-EXCEEDED", "estimated_record_count"),
            ("L1-M9-VOLUME-BYTES-EXCEEDED", "estimated_byte_count"),
        ):
            with self.subTest(check=check_id):
                check = CHECKS[check_id]
                zero = InvocationIntent(purpose="p", estimated_record_count=0, estimated_byte_count=0)
                self.assertIsNone(check.run(policy, context(intent=zero)))
                self.assertEqual(check.run(policy, context(intent=replace(zero, **{field: 1}))), ())

    def test_the_input_schema_check_on_a_tool_that_ships_none(self):
        self.assertIsNone(CHECKS["INTERLOCK-INPUT-SCHEMA-INVALID"].run(LinkPolicy(), context()))
        schema = {"type": "object", "required": ["q"]}
        self.assertEqual(
            CHECKS["INTERLOCK-INPUT-SCHEMA-INVALID"].run(LinkPolicy(), context(target=actor("t", input_schema=schema))),
            (),
        )

    def test_the_three_side_effect_checks_share_one_convention(self):
        """Read-only traffic must not show one of these near 100% RAN_CLEAN and another near 100%
        INAPPLICABLE. The side effect a check governs is its subject, so a different one is
        INAPPLICABLE for all three."""
        read_only = context(intent=InvocationIntent(purpose="p", estimated_side_effect=SideEffect.READ))
        governed = (
            "INTERLOCK-DESTRUCTIVE-WRITE",
            "INTERLOCK-TAINTED-EXTERNAL-WRITE",
            "INTERLOCK-APPROVAL-REQUIRED",
        )
        for check_id in governed:
            with self.subTest(check=check_id):
                self.assertIsNone(CHECKS[check_id].run(LinkPolicy(), read_only))


class _Boundary:
    """Minimal BoundaryLike; policy.py reads it structurally and must not import architecture.py."""

    allowed_relationships = frozenset({"INVOKES"})
    allowed_data_classes = frozenset({"D2"})
    denied_data_classes = frozenset({"D5"})
    require_identity = True
    require_tenant_binding = True
    max_payload_bytes = 1024
    mode = None


class ArmedInvarianceTests(unittest.TestCase):
    def test_armed_reads_only_the_link_constant_half_of_the_context(self):
        """`armed` may read policy, source, target, boundary, revision and relationship, and
        nothing else. The armed set is declared once per coverage digest rather than stamped onto
        every event, so a check arming on the invocation would make the declaration a lie for every
        call that shares the digest. Varying exactly the per-invocation fields is what pins it --
        widening `armed`'s signature to the whole context is safe only while this test exists.
        """
        policy = LinkPolicy(max_export_records=5, max_export_bytes=50)
        link = dict(source=SOURCE, target=actor("t", input_schema={"type": "object"}), boundary=_Boundary())
        varied = (
            context(**link),
            context(
                **link,
                intent=InvocationIntent(
                    purpose="other",
                    data_classes=frozenset({"D5", "D7"}),
                    destinations=("https://x.example/y",),
                    estimated_side_effect=SideEffect.EXTERNAL_WRITE,
                    taint_labels=frozenset({"web"}),
                    expected_audience="aud",
                    expected_resource="res",
                    estimated_record_count=99,
                    estimated_byte_count=99,
                ),
                arguments={"secret": "AKIAIOSFODNN7EXAMPLE"},
                credential=credential(),
                approval_valid=True,
                payload_bytes=4096,
            ),
            context(**link, interaction_id="other", trace_id="other", span_id="other"),
        )
        for check_id, check in CHECKS.items():
            with self.subTest(check=check_id):
                states = {check.armed(policy, value) for value in varied}
                self.assertEqual(len(states), 1, f"{check_id}: armed varied with the invocation")


class ProfileMembershipTests(unittest.TestCase):
    """Item 7: `assertNotIn(id, ran)` passes vacuously once the id leaves the profile.

    Pinning each profile's membership whole is what makes those assertions mean something -- a
    check silently dropped from a profile fails here loudly instead of turning every "did not run"
    assertion elsewhere into a tautology.
    """

    def test_gateway_profile_membership(self):
        self.assertEqual(
            GATEWAY_PROFILE.checks,
            (
                "INTERLOCK-ACTOR-TYPE-DENIED",
                "INTERLOCK-PURPOSE-DENIED",
                "L1-M2-DEFINITION-NOT-ACTIVE",
                "L1-M2-DEFINITION-DRIFT",
                "INTERLOCK-INPUT-SCHEMA-INVALID",
                "INTERLOCK-DATA-CLASS-DENIED",
                "L1-M8-CREDENTIAL-DETECTED",
                "L1-M9-NEW-DESTINATION",
                "L1-M9-VOLUME-EXCEEDED",
                "L1-M9-VOLUME-BYTES-EXCEEDED",
                "L1-UNDECLARED-SIDE-EFFECT",
                "INTERLOCK-DESTRUCTIVE-WRITE",
                "INTERLOCK-TAINTED-EXTERNAL-WRITE",
                "INTERLOCK-APPROVAL-REQUIRED",
                "L1-M5-CREDENTIAL-MISSING",
                "L1-M5-TOKEN-PASSTHROUGH",
                "L1-M5-TOKEN-AUDIENCE-MISMATCH",
                "L1-M5-TOKEN-RESOURCE-MISMATCH",
                "L1-M5-TOKEN-ACTOR-MISMATCH",
                "L1-M5-DELEGATION-DEPTH",
            ),
        )

    def test_sdk_profile_is_the_gateway_minus_the_two_definition_checks(self):
        self.assertEqual(
            SDK_PROFILE.checks,
            tuple(
                check_id
                for check_id in GATEWAY_PROFILE.checks
                if check_id not in {"L1-M2-DEFINITION-NOT-ACTIVE", "L1-M2-DEFINITION-DRIFT"}
            ),
        )

    def test_a2a_profile_membership(self):
        self.assertEqual(
            A2A_PROFILE.checks,
            (
                "A2A-IDENTITY-BINDING-MISMATCH",
                "INTERLOCK-ACTOR-TYPE-DENIED",
                "INTERLOCK-PURPOSE-DENIED",
                "INTERLOCK-DATA-CLASS-DENIED",
                "L1-M8-CREDENTIAL-DETECTED",
                "L1-M5-TOKEN-ACTOR-MISMATCH",
                "L1-M5-TOKEN-AUDIENCE-MISMATCH",
                "L1-M5-TOKEN-RESOURCE-MISMATCH",
                "L1-M5-TOKEN-PASSTHROUGH",
                "L1-M5-DELEGATION-DEPTH",
                "A2A-INPUT-SCHEMA-INVALID",
                "A2A-PAYLOAD-INVALID",
                "A2A-BOUNDARY-RELATIONSHIP-DENIED",
                "A2A-BOUNDARY-DATA-CLASS-DENIED",
                "A2A-BOUNDARY-IDENTITY-REQUIRED",
                "A2A-BOUNDARY-TENANT-REQUIRED",
                "A2A-BOUNDARY-PAYLOAD-TOO-LARGE",
            ),
        )

    def test_the_two_scoped_a2a_profiles_partition_the_whole_one(self):
        self.assertEqual(
            tuple(sorted((*A2A_LINK_PROFILE.checks, *A2A_BOUNDARY_PROFILE.checks))),
            tuple(sorted(A2A_PROFILE.checks)),
        )
        self.assertEqual(set(A2A_LINK_PROFILE.checks) & set(A2A_BOUNDARY_PROFILE.checks), set())

    def test_every_profile_id_exists_in_the_table(self):
        for name, profile in (("GATEWAY", GATEWAY_PROFILE), ("SDK", SDK_PROFILE), ("A2A", A2A_PROFILE)):
            with self.subTest(profile=name):
                self.assertEqual([c for c in profile.checks if c not in CHECKS], [])


class UnsatisfiableControlTests(unittest.TestCase):
    """Item 6: two A2A controls their own constructors make unreachable on the live path.

    Both are kept rather than deleted -- the constructor is what enforces the invariant today, and
    a second producer building a CheckContext directly meets no guard at all. What must not stand
    is the reading: their byCheck rows are 100% RAN_CLEAN because nothing can trip them, which is
    "the constructor held", not "this control was exercised". Both halves are asserted here so the
    docstrings on the checks are not the only record.
    """

    def test_the_message_constructor_is_what_enforces_a_non_empty_payload(self):
        with self.assertRaises(ValueError):
            A2AMessage(message_id="m", role=A2AMessageRole.USER, parts=())
        message = A2AMessage(
            message_id="m", role=A2AMessageRole.USER, parts=(A2APart(kind=A2APartKind.TEXT, text="hi"),)
        )
        self.assertGreaterEqual(len(json.dumps(message.to_dict())), 2)

    def test_the_payload_check_still_fires_on_a_context_that_did_not_come_from_a_message(self):
        self.assertEqual(
            CHECKS["A2A-PAYLOAD-INVALID"].run(LinkPolicy(), context(payload_bytes=0)),
            (("A2A-PAYLOAD-INVALID", ControlDecision.BLOCK),),
        )

    def test_the_principal_constructor_is_what_enforces_a_tenant(self):
        with self.assertRaises(ValueError):
            A2APrincipal(tenant_id="", subject="s", actor_id="a", audience="aud", resource="res")

    def test_the_tenant_check_still_fires_on_a_credential_carrying_none(self):
        value = context(
            boundary=_Boundary(),
            credential=credential(tenant_id=""),
        )
        self.assertIsNotNone(CHECKS["A2A-BOUNDARY-TENANT-REQUIRED"].run(LinkPolicy(), value))


def _gateway_declaration():
    return coverage_declaration(LinkPolicy(), GATEWAY_PROFILE, run_checks(LinkPolicy(), context(), GATEWAY_PROFILE))


class CoverageDeclarationTests(unittest.TestCase):
    def test_the_digest_covers_the_whole_body_not_just_the_evaluated_set(self):
        """Two links can run the same checks with different sets armed. Keying the declaration on
        the evaluated set alone would let whichever was seen first speak for both."""
        loose = LinkPolicy()
        # Arms the byte half of the volume cap. The default intent estimates zero bytes, so the
        # check is armed and INAPPLICABLE: the evaluated set cannot move with it.
        tight = replace(loose, max_export_bytes=1000)
        value = context()
        loose_declaration = coverage_declaration(
            loose, GATEWAY_PROFILE, run_checks(loose, value, GATEWAY_PROFILE)
        )
        tight_declaration = coverage_declaration(
            tight, GATEWAY_PROFILE, run_checks(tight, value, GATEWAY_PROFILE)
        )
        self.assertEqual(loose_declaration["evaluated"], tight_declaration["evaluated"])
        self.assertNotEqual(loose_declaration["armed"], tight_declaration["armed"])
        self.assertNotEqual(loose_declaration["profileDigest"], tight_declaration["profileDigest"])

    def test_the_digest_recomputes_from_the_payload_it_ships_with(self):
        declaration = _gateway_declaration()
        body = {key: value for key, value in declaration.items() if key != "profileDigest"}
        self.assertEqual(declaration["profileDigest"], canonical_digest(body))

    def test_armed_carries_the_scope_every_check_declares(self):
        declaration = _gateway_declaration()
        for entry in declaration["armed"]:
            self.assertEqual(entry["scope"], CHECKS[entry["id"]].scope.value)
            self.assertIn(entry["scope"], {scope.value for scope in CheckScope})

    def test_the_three_sets_nest(self):
        policy = LinkPolicy()
        value = context(intent=InvocationIntent(purpose="p", destinations=("https://evil.example/x",)))
        outcome = run_checks(policy, value, GATEWAY_PROFILE)
        self.assertTrue(outcome.flagged <= outcome.ran <= set(outcome.armed))
        self.assertTrue(outcome.flagged, "the fixture must flag something or this asserts nothing")

    def test_the_broker_declares_one_coverage_over_both_of_its_profiles(self):
        policy = LinkPolicy()
        value = context(boundary=_Boundary())
        coverage = control_coverage(
            policy,
            A2A_PROFILE,
            run_checks(policy, value, A2A_LINK_PROFILE),
            run_checks(policy, value, A2A_BOUNDARY_PROFILE),
        )
        armed = {entry["id"] for entry in coverage.declaration["armed"]}
        self.assertTrue(armed & {c for c in A2A_BOUNDARY_PROFILE.checks})
        self.assertTrue(armed & {c for c in A2A_LINK_PROFILE.checks})
        self.assertEqual(coverage.enforcement_point, "A2A_BROKER")


class FixtureConsistencyTests(unittest.TestCase):
    """The shared fixture claims to be a ledger dump, so it must be one the ledger could produce."""

    def setUp(self):
        self.events = json.loads((FIXTURES / "analytics-events.json").read_text())

    def test_every_event_type_is_one_the_ledger_vocabulary_accepts(self):
        # The vocabulary lives in four places with no Python enum to add a member to; this catches
        # a fixture (or a producer) drifting from the set the HTTP ingest and the DB will take.
        for event in self.events:
            self.assertIn(event["event_type"], _EVENT_TYPES)

    def test_every_event_carries_the_schema_version_the_ledger_writes(self):
        for event in self.events:
            self.assertEqual(event["schema_version"], "1.0")

    def test_every_declaration_digest_recomputes_from_its_own_payload(self):
        declarations = coverage_declarations(self.events)
        self.assertTrue(declarations, "the fixture must declare coverage or the reducer is untested")
        for digest, declaration in declarations.items():
            body = {key: value for key, value in declaration.items() if key != "profileDigest"}
            self.assertEqual(digest, canonical_digest(body))

    def test_declarations_carry_no_interaction_id(self):
        for event in self.events:
            if event["event_type"] == "CONTROL_COVERAGE_DECLARED":
                self.assertIsNone(event["interaction_id"])

    def test_every_flagged_check_was_evaluated_and_armed(self):
        declarations = coverage_declarations(self.events)
        for event in self.events:
            control = event["payload"].get("control") if event["event_type"] == "CONTROL_EVALUATED" else None
            if not control or "evaluatedProfile" not in control:
                continue
            declaration = declarations[control["evaluatedProfile"]]
            armed = {entry["id"] for entry in declaration["armed"]}
            self.assertTrue(set(control["flaggedChecks"]) <= set(declaration["evaluated"]) <= armed)


class EventVocabularyTests(unittest.TestCase):
    """The event-type vocabulary lives in four places and there is no Python enum to add to.

    `ledger_http._EVENT_TYPES` gates HTTP ingest, the envelope schema gates the canonical envelope,
    the OpenAPI component gates the published contract, and the CHECK constraint on
    `interlock.security_events` is the write-time gate the PostgreSQL ledger relies on -- it does no
    validation of its own. A member added to three of the four produces an event the ingest accepts
    and the table refuses, at write time, in production.
    """

    ROOT = Path(__file__).resolve().parent.parent

    def openapi_members(self):
        text = (self.ROOT / "schemas" / "ledger-api.openapi.yaml").read_text()
        members, inside = set(), False
        for line in text.splitlines():
            if line == "    EventType:":
                inside = True
                continue
            if inside:
                if line.startswith("    ") and not line.startswith("     "):
                    break  # the next component at the same indent
                if line.strip().startswith("- "):
                    members.add(line.strip()[2:])
        return members

    def migration_members(self):
        # The latest migration that restates the constraint owns the vocabulary.
        sql = sorted((self.ROOT / "migrations" / "postgresql").glob("0*.sql"))
        text = next(
            path.read_text()
            for path in reversed(sql)
            if "security_events_event_type_check" in path.read_text() or "event_type IN" in path.read_text()
        )
        clause = text.split("event_type IN (", 1)[1].split(")", 1)[0]
        return {part.strip().strip("'") for part in clause.split(",") if part.strip()}

    def envelope_members(self):
        schema = json.loads((FIXTURES.parent / "event-envelope.schema.json").read_text())
        return set(schema["properties"]["event_type"]["enum"])

    def test_all_four_registrations_carry_the_same_vocabulary(self):
        self.assertEqual(self.envelope_members(), set(_EVENT_TYPES))
        self.assertEqual(self.openapi_members(), set(_EVENT_TYPES))
        self.assertEqual(self.migration_members(), set(_EVENT_TYPES))

    def test_the_coverage_declaration_is_registered(self):
        self.assertIn("CONTROL_COVERAGE_DECLARED", _EVENT_TYPES)

    def test_each_parser_actually_found_something(self):
        # Three of the four are scraped out of text. A parser that silently returns an empty set
        # would make the agreement test above pass by comparing nothing to nothing.
        for name, members in (
            ("envelope", self.envelope_members()),
            ("openapi", self.openapi_members()),
            ("migration", self.migration_members()),
        ):
            with self.subTest(source=name):
                self.assertGreaterEqual(len(members), 12, name)


class ReducerCoverageTests(unittest.TestCase):
    def setUp(self):
        self.events = json.loads((FIXTURES / "analytics-events.json").read_text())

    def test_the_catalogue_is_the_union_of_declared_armed_sets(self):
        catalogue = check_catalogue(coverage_declarations(self.events))
        self.assertTrue(catalogue)
        for check_id, scope in catalogue.items():
            self.assertEqual(scope, CHECKS[check_id].scope.value)

    def test_an_interaction_with_no_declaration_is_absent_throughout(self):
        catalogue = check_catalogue(coverage_declarations(self.events))
        record = next(r for r in reduce_interactions(self.events) if r.policy_id == "policy.support-crm")
        self.assertEqual({record.coverage.state(check_id) for check_id in catalogue}, {"ABSENT"})

    def test_a_digest_the_stream_never_declared_contributes_nothing(self):
        """Missing evidence is not a clean bill. Inventing an armed set for an unresolvable digest
        would report coverage the ledger does not carry."""
        events = [event for event in self.events if event["event_type"] != "CONTROL_COVERAGE_DECLARED"]
        for record in reduce_interactions(events):
            # Only what the control event itself asserts survives: a flagged check demonstrably
            # ran, so it stays armed and ran. Everything the declaration would have added is gone.
            self.assertEqual(record.coverage.armed, record.coverage.flagged)
            self.assertEqual(record.coverage.ran, record.coverage.flagged)

    def test_a_flagged_checks_string_is_read_as_one_id_not_one_per_character(self):
        """`reasonCodes` already carries this guard. Without the matching one, a producer writing a
        bare id instead of a list turns a control record into twenty-odd single-character checks."""
        events = [
            _requested("ia-str"),
            _control("ia-str", {"decision": "BLOCK", "flaggedChecks": "L1-M9-NEW-DESTINATION"}),
        ]
        record = reduce_interactions(events)[0]
        self.assertEqual(record.coverage.flagged, frozenset({"L1-M9-NEW-DESTINATION"}))

    def test_a_malformed_flagged_checks_value_contributes_nothing(self):
        events = [_requested("ia-bad"), _control("ia-bad", {"decision": "BLOCK", "flaggedChecks": 7})]
        self.assertEqual(reduce_interactions(events)[0].coverage.flagged, frozenset())

    def test_the_four_states_are_disjoint_and_total(self):
        catalogue = check_catalogue(coverage_declarations(self.events))
        records = reduce_interactions(self.events)
        for check_id in catalogue:
            counts = {state: 0 for state in ("RAN_CLEAN", "RAN_FLAGGED", "INAPPLICABLE", "ABSENT")}
            for record in records:
                counts[record.coverage.state(check_id)] += 1
            self.assertEqual(sum(counts.values()), len(records), check_id)

    def test_an_interaction_with_no_control_record_is_counted_not_read_as_clean(self):
        events = [
            event
            for event in self.events
            if not (event["event_type"] == "CONTROL_EVALUATED" and event.get("interaction_id") == "ia-1")
        ]
        record = next(r for r in reduce_interactions(events) if r.interaction_id == "ia-1")
        self.assertFalse(record.control_evaluated)
        self.assertIsNone(record.edge_key)  # no policyId, so it cannot be placed on the byEdge grid


def _requested(interaction_id):
    return {
        "event_type": "INTERACTION_REQUESTED", "occurred_at": "2026-07-19T12:00:00Z",
        "tenant_id": "tenant-a", "environment": "DEV", "data_source": "PRODUCTION",
        "interaction_id": interaction_id, "source_actor_id": "agent.a",
        "target_actor_id": "tool.b", "relationship_id": "REL-05", "payload": {},
    }


def _control(interaction_id, control):
    return {**_requested(interaction_id), "event_type": "CONTROL_EVALUATED", "payload": {"control": control}}


class LiveQueryPathTests(unittest.TestCase):
    """The one production query that feeds summarize_security_statistics must see declarations.

    `interaction_lifecycles_started_between` selects events by interaction id, and a coverage
    declaration deliberately has none. Without a second branch for them the endpoint returns a
    window in which every check reads ABSENT -- a fully "uncovered" dashboard drawn from a ledger
    that recorded the coverage correctly. Caught here rather than in production, and asserted on
    both the real gateway and the real query rather than on the fixture.
    """

    def test_a_real_gateway_invocation_reaches_by_check_through_the_lifecycle_query(self):
        from l1_harness import TENANT, build_gateway

        from agent_interlock import summarize_security_statistics

        gateway, revision, source, _target = build_gateway(external_approval=False)
        gateway.invoke(
            connector=lambda arguments: {"status": "SENT"},
            idempotency_key="idem-coverage",
            tenant_id=TENANT,
            source_actor_id=source.id,
            revision_id=revision.revision_id,
            intent=InvocationIntent(purpose="notify-customer"),
            arguments={"to": "user@customer.example", "body": "hello"},
        )
        events = gateway.ledger.interaction_lifecycles_started_between(
            TENANT, "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"
        )
        types = {event.event_type for event in events}
        self.assertIn("CONTROL_COVERAGE_DECLARED", types)

        summary = summarize_security_statistics([event.to_dict() for event in events])
        partition = summary["partitions"][0]
        self.assertTrue(partition["byCheck"], "the lifecycle query dropped the coverage declaration")
        self.assertTrue(partition["byEdge"])
        # The invocation was allowed and every control that looked found nothing, so the row that
        # proves coverage is a RAN_CLEAN one -- not a flag.
        self.assertTrue(any(row["ranCleanCount"] for row in partition["byCheck"]))
        self.assertEqual(partition["counters"]["noControlRecordCount"], 0)

    def test_the_declaration_is_emitted_once_per_digest_not_once_per_call(self):
        from l1_harness import TENANT, build_gateway

        gateway, revision, source, _target = build_gateway(external_approval=False)
        for index in range(3):
            gateway.invoke(
                connector=lambda arguments: {"status": "SENT"},
                idempotency_key=f"idem-{index}",
                tenant_id=TENANT,
                source_actor_id=source.id,
                revision_id=revision.revision_id,
                intent=InvocationIntent(purpose="notify-customer"),
                arguments={"to": "user@customer.example", "body": "hello"},
            )
        events = gateway.ledger.interaction_lifecycles_started_between(
            TENANT, "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"
        )
        declared = [event for event in events if event.event_type == "CONTROL_COVERAGE_DECLARED"]
        self.assertEqual(len(declared), 1)
        self.assertIsNone(declared[0].interaction_id)

    def test_the_sdk_declares_its_own_coverage_under_its_own_enforcement_point(self):
        from agent_interlock.sdk import Interlock

        interlock = Interlock()
        caller = interlock.define_actor(SOURCE)
        callee = interlock.define_actor(TARGET)
        interlock.connect(caller, callee, LinkPolicy())
        guarded = callee.wrap(lambda arguments: {"ok": True})
        for _ in range(2):
            guarded({"q": "hi"}, source=caller, tenant_id="tenant-a", intent=InvocationIntent(purpose="p"))

        events = interlock.ledger.interaction_lifecycles_started_between(
            "tenant-a", "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"
        )
        declared = [event for event in events if event.event_type == "CONTROL_COVERAGE_DECLARED"]
        self.assertEqual(len(declared), 1)  # two calls, one coverage shape
        self.assertEqual(declared[0].payload["coverage"]["enforcementPoint"], "SDK")
        # The SDK has no ToolRevision on any call, so the two M2 checks are ABSENT at this point
        # rather than INAPPLICABLE on every invocation -- the distinction §3 turns on.
        armed = {entry["id"] for entry in declared[0].payload["coverage"]["armed"]}
        self.assertEqual(armed & {"L1-M2-DEFINITION-NOT-ACTIVE", "L1-M2-DEFINITION-DRIFT"}, set())

    def test_the_broker_declares_one_coverage_over_both_of_its_scoped_profiles(self):
        from test_a2a import broker_fixture, request_message, send_context

        broker, ledger, _calls, principal = broker_fixture()
        broker.send_message(request_message(), send_context(principal))

        declared = [
            event.payload["coverage"]
            for event in ledger._events
            if event.event_type == "CONTROL_COVERAGE_DECLARED"
        ]
        self.assertEqual(len(declared), 1)
        self.assertEqual(declared[0]["enforcementPoint"], "A2A_BROKER")
        # One event, two profiles: the broker answers link findings to the edge's mode and boundary
        # findings to the boundary's, and the union of the two disjoint check sets is A2A_PROFILE.
        armed = {entry["id"] for entry in declared[0]["armed"]}
        self.assertTrue(armed & set(A2A_LINK_PROFILE.checks))
        self.assertTrue(armed & set(A2A_BOUNDARY_PROFILE.checks))
        self.assertTrue(armed <= set(A2A_PROFILE.checks))

    def test_every_control_record_carries_the_three_coverage_fields(self):
        from l1_harness import TENANT, build_gateway

        gateway, revision, source, _target = build_gateway(external_approval=False)
        gateway.invoke(
            connector=lambda arguments: {"status": "SENT"},
            idempotency_key="idem-fields",
            tenant_id=TENANT,
            source_actor_id=source.id,
            revision_id=revision.revision_id,
            intent=InvocationIntent(purpose="notify-customer"),
            arguments={"to": "user@customer.example", "body": "hello"},
        )
        controls = [
            event.payload["control"]
            for event in gateway.ledger.interaction_lifecycles_started_between(
                TENANT, "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"
            )
            if event.event_type == "CONTROL_EVALUATED"
        ]
        self.assertTrue(controls)
        for control in controls:
            self.assertEqual(control["enforcementPoint"], "MCP_GATEWAY")
            self.assertTrue(control["evaluatedProfile"].startswith("sha256:"))
            self.assertEqual(control["flaggedChecks"], [])

    def test_the_digest_survives_the_ledger_and_still_joins_after_redaction(self):
        """The join is a digest on one event matching a digest on another, and both pass through
        redact_payload, which rewrites strings. A pattern that ate either side would leave the
        events individually plausible and the coverage permanently unresolvable."""
        from l1_harness import TENANT, build_gateway

        gateway, revision, source, _target = build_gateway(external_approval=False)
        gateway.invoke(
            connector=lambda arguments: {"status": "SENT"},
            idempotency_key="idem-join",
            tenant_id=TENANT,
            source_actor_id=source.id,
            revision_id=revision.revision_id,
            intent=InvocationIntent(purpose="notify-customer"),
            arguments={"to": "user@customer.example", "body": "hello"},
        )
        events = gateway.ledger.interaction_lifecycles_started_between(
            TENANT, "2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"
        )
        control = next(e.payload["control"] for e in events if e.event_type == "CONTROL_EVALUATED")
        declaration = next(
            e.payload["coverage"] for e in events if e.event_type == "CONTROL_COVERAGE_DECLARED"
        )
        self.assertEqual(control["evaluatedProfile"], declaration["profileDigest"])
        body = {key: value for key, value in declaration.items() if key != "profileDigest"}
        self.assertEqual(declaration["profileDigest"], canonical_digest(body))


if __name__ == "__main__":
    unittest.main()
