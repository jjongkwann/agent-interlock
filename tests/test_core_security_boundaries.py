"""Schema, audit redaction, single execution, and one-use approval boundaries."""

import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

from test_core import configured_gateway
from test_sdk_results import wired

from agent_interlock import ControlDecision, InvocationIntent, LinkPolicy, PolicyMode, SideEffect
from agent_interlock.approvals import approval_binding
from agent_interlock.canonical import canonical_digest
from agent_interlock.gateway import GatewayError, InvocationBlocked
from agent_interlock.ledger import redact_payload
from agent_interlock.security import validate_schema


class CoreSecurityBoundaryTests(unittest.TestCase):
    def test_nested_schema_keywords_apply_without_type(self):
        schema = {"required": ["rows"], "properties": {"rows": {"items": {
            "required": ["name"], "properties": {"name": {"maxLength": 2}}, "additionalProperties": False,
        }}}, "additionalProperties": {"type": "integer"}}
        self.assertEqual(validate_schema({"rows": [{"name": "ok"}], "count": 1}, schema), ())
        self.assertEqual(set(validate_schema({"rows": [{}, {"name": "long", "extra": True}], "count": "x"}, schema)), {
            "$.rows[0].name: required", "$.rows[1].name: exceeds maxLength",
            "$.rows[1].extra: additional property", "$.count: expected integer",
        })
        self.assertEqual(validate_schema({}, schema), ("$.rows: required",))
        # Object/array keywords do not imply a type restriction.
        self.assertEqual(validate_schema("anything", schema), ())

    def test_sensitive_parent_redacts_entire_structure(self):
        fingerprint = "sha256:" + "a" * 64
        self.assertEqual(redact_payload({
            "authorization": {"value": "opaque"}, "password": ["one", {"value": "two"}],
            "nested": {"credentials": ({"value": "three"},)},
            "credentialFingerprint": fingerprint, "secretDetected": True,
        }), {"authorization": "[REDACTED]", "password": "[REDACTED]",
              "nested": {"credentials": "[REDACTED]"}, "credentialFingerprint": fingerprint,
              "secretDetected": True})

    def test_concurrent_retries_share_one_execution_and_original_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                gateway, revision, source, _ = configured_gateway()
                params = dict(tenant_id="tenant-a", source_actor_id=source.id, revision_id=revision.revision_id,
                              intent=InvocationIntent(purpose="read"),
                              arguments={"to": "a@customer.example", "body": "hello"})
                decision = gateway.evaluate_invocation(**params)
                start = threading.Barrier(9)
                entered, release = threading.Event(), threading.Event()
                calls = []

                def connector(arguments):
                    calls.append(arguments)
                    entered.set()
                    if not release.wait(5):
                        raise RuntimeError("test timed out")
                    if fail:
                        raise ValueError("original connector failure")
                    return {"status": "ok"}

                def invoke(index):
                    start.wait(5)
                    if index % 2:
                        return gateway.execute_approved_call(decision.decision_id, params["arguments"], connector,
                                                             idempotency_key="same")
                    return gateway.invoke(**params, connector=connector, idempotency_key="same")

                with ThreadPoolExecutor(max_workers=8) as pool:
                    futures = [pool.submit(invoke, index) for index in range(8)]
                    start.wait(5)
                    try:
                        self.assertTrue(entered.wait(5))
                        with self.assertRaisesRegex(GatewayError, "different invocation"):
                            gateway.invoke(**{**params, "arguments": {"to": "other", "body": "changed"}},
                                           connector=connector, idempotency_key="same")
                    finally:
                        release.set()
                    if fail:
                        for future in futures:
                            with self.assertRaisesRegex(ValueError, "original connector failure"):
                                future.result(timeout=5)
                        with self.assertRaisesRegex(ValueError, "original connector failure"):
                            gateway.invoke(**params, connector=connector, idempotency_key="same")
                    else:
                        results = [future.result(timeout=5) for future in futures]
                        self.assertEqual(len({result.connector_execution_id for result in results}), 1)
                self.assertEqual(len(calls), 1)

    def test_observation_modes_sanitize_without_quarantine(self):
        for mode in (PolicyMode.OBSERVE, PolicyMode.SHADOW, PolicyMode.ENFORCE):
            with self.subTest(mode=mode):
                gateway, revision, source, _ = configured_gateway(mode=mode)
                result = gateway.invoke(tenant_id="tenant-a", source_actor_id=source.id,
                                        revision_id=revision.revision_id, intent=InvocationIntent(purpose="read"),
                                        arguments={"to": "a@customer.example", "body": "hi"},
                                        connector=lambda args: {"detail": "AKIAIOSFODNN7EXAMPLE"},
                                        idempotency_key="result")
                self.assertIn("SCHEMA_INVALID", result.labels)
                self.assertNotIn("AKIAIOSFODNN7EXAMPLE", repr(result.value))
                self.assertEqual(bool(result.value.get("quarantined")), mode == PolicyMode.ENFORCE)
                event = next(event for event in gateway.ledger.all() if event.event_type == "INTERACTION_COMPLETED")
                self.assertEqual(event.payload["resultHash"], canonical_digest(result.value))

    def test_approval_binding_covers_identity_revision_full_intent_and_policy(self):
        gateway, revision, source, target = configured_gateway(external_approval=True)
        intent = InvocationIntent(purpose="reply", destinations=("a@customer.example",),
                                  estimated_side_effect=SideEffect.EXTERNAL_WRITE)
        values = dict(tenant_id="tenant-a", source_actor_id=source.id, target_actor_id=target.id,
                      revision_id=revision.revision_id, intent=intent, arguments={"body": "hi"},
                      policy=gateway.link_policy(source.id, target.id))
        original = approval_binding(**values)
        mutations = [dict(tenant_id="other"), dict(source_actor_id="other"), dict(target_actor_id="other"),
                     dict(revision_id="other"), dict(arguments={"body": "changed"}),
                     dict(policy=replace(values["policy"], version="next")),
                     dict(policy=replace(values["policy"], max_export_records=10))]
        mutations += [dict(intent=replace(intent, **change)) for change in (
            dict(purpose="other"), dict(estimated_side_effect=SideEffect.PAYMENT),
            dict(destinations=("b@customer.example",)), dict(data_classes=frozenset({"D7"})),
            dict(estimated_record_count=20), dict(estimated_byte_count=50), dict(taint_labels=frozenset({"tainted"})),
            dict(expected_audience="other"), dict(expected_resource="other"),
        )]
        for change in mutations:
            with self.subTest(change=change):
                self.assertNotEqual(original, approval_binding(**{**values, **change}))
        self.assertEqual(original, approval_binding(**{**values, "intent": replace(intent, approval_id="ignored")}))

    def test_gateway_grant_is_consumed_once_after_permission_even_on_failure(self):
        for fail in (False, True):
            gateway, revision, source, _ = configured_gateway(external_approval=True)
            params = dict(tenant_id="tenant-a", source_actor_id=source.id, revision_id=revision.revision_id,
                          arguments={"to": "a@customer.example", "body": "hi"},
                          intent=InvocationIntent(purpose="reply", destinations=("a@customer.example",),
                                                  estimated_side_effect=SideEffect.EXTERNAL_WRITE))
            approval = gateway.grant_approval(**params, approver="operator")
            params["intent"] = replace(params["intent"], approval_id=approval.approval_id)
            first, second = (gateway.evaluate_invocation(**params) for _ in range(2))
            self.assertEqual(first.decision, ControlDecision.ALLOW)
            calls = []

            def connector(arguments):
                calls.append(arguments)
                if fail:
                    raise ValueError("failed")
                return {"status": "sent"}

            if fail:
                with self.assertRaisesRegex(ValueError, "failed"):
                    gateway.execute_approved_call(
                        first.decision_id, params["arguments"], connector, idempotency_key="1",
                    )
            else:
                gateway.execute_approved_call(first.decision_id, params["arguments"], connector, idempotency_key="1")
            with self.assertRaisesRegex(GatewayError, "already consumed"):
                gateway.execute_approved_call(second.decision_id, params["arguments"], connector, idempotency_key="2")
            self.assertIn("INTERLOCK-APPROVAL-REQUIRED", gateway.evaluate_invocation(**params).reason_codes)
            self.assertEqual(len(calls), 1)

    def test_blocked_and_observed_calls_do_not_spend_approval(self):
        for mode in (PolicyMode.ENFORCE, PolicyMode.SHADOW, PolicyMode.OBSERVE):
            gateway, revision, source, _ = configured_gateway(external_approval=True, mode=mode)
            params = dict(tenant_id="tenant-a", source_actor_id=source.id, revision_id=revision.revision_id,
                          arguments={"to": "a@customer.example", "body": "hi"},
                          intent=InvocationIntent(purpose="reply", destinations=("a@customer.example",),
                                                  data_classes=frozenset({"D5"}),
                                                  estimated_side_effect=SideEffect.EXTERNAL_WRITE))
            approval = gateway.grant_approval(**params, approver="operator")
            params["intent"] = replace(params["intent"], approval_id=approval.approval_id)
            if mode == PolicyMode.ENFORCE:
                with self.assertRaises(InvocationBlocked):
                    gateway.invoke(**params, connector=lambda args: {"status": "sent"}, idempotency_key="blocked")
            else:
                gateway.invoke(**params, connector=lambda args: {"status": "sent"}, idempotency_key="observed")
            self.assertEqual(gateway.find_approval(**params), approval)

    def test_policy_change_invalidates_pending_approval_without_spending_it(self):
        gateway, revision, source, target = configured_gateway(external_approval=True)
        params = dict(tenant_id="tenant-a", source_actor_id=source.id, revision_id=revision.revision_id,
                      arguments={"to": "a@customer.example", "body": "hi"},
                      intent=InvocationIntent(purpose="reply", destinations=("a@customer.example",),
                                              estimated_side_effect=SideEffect.EXTERNAL_WRITE))
        approval = gateway.grant_approval(**params, approver="operator")
        params["intent"] = replace(params["intent"], approval_id=approval.approval_id)
        decision = gateway.evaluate_invocation(**params)
        policy = gateway.link_policy(source.id, target.id)
        gateway.connect(source.id, target.id, replace(policy, version="next"))
        calls = []
        with self.assertRaisesRegex(GatewayError, "policy changed"):
            gateway.execute_approved_call(
                decision.decision_id, params["arguments"], calls.append, idempotency_key="old",
            )
        self.assertEqual(calls, [])
        self.assertIn("INTERLOCK-APPROVAL-REQUIRED", gateway.evaluate_invocation(**params).reason_codes)
        gateway.connect(source.id, target.id, policy)
        self.assertEqual(gateway.find_approval(**params), approval)

    def test_sdk_grant_cannot_be_reused(self):
        interlock, source, target = wired(LinkPolicy(), side_effects=frozenset({SideEffect.EXTERNAL_WRITE}))
        intent = InvocationIntent(purpose="reply", destinations=("a@good.example",),
                                  estimated_side_effect=SideEffect.EXTERNAL_WRITE)
        args = {"to": "a@good.example"}
        approval = interlock.grant_approval(tenant_id="tenant-a", source_actor_id=source.spec.id,
                                           target_actor_id=target.spec.id, intent=intent, arguments=args,
                                           approver="operator")
        intent = replace(intent, approval_id=approval.approval_id)
        guarded = target.wrap(lambda arguments: {"status": "sent"})
        self.assertEqual(guarded(args, source=source, tenant_id="tenant-a", intent=intent), {"status": "sent"})
        with self.assertRaisesRegex(GatewayError, "INTERLOCK-APPROVAL-REQUIRED"):
            guarded(args, source=source, tenant_id="tenant-a", intent=intent)
