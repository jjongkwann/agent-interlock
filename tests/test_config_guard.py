from __future__ import annotations

import unittest

from l1_harness import (
    CONFIG_TRUSTED_KEYS,
    TENANT,
    agent_config,
    config_approval,
    seed_revision,
)

from agent_interlock import (
    ConfigGuard,
    ConfigGuardError,
    ConfigPrincipal,
    ConfigRevisionState,
    ConfigRole,
    ControlDecision,
    InMemoryConfigStore,
    InMemoryRuntimeConfigProbe,
)

OPERATOR = ConfigPrincipal(TENANT, "operator", ConfigRole.OPERATOR)


class ConfigGuardBase(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryConfigStore()
        self.base = agent_config()
        self.store.seed(seed_revision(self.base))
        self.guard = ConfigGuard(self.store, trusted_keys=CONFIG_TRUSTED_KEYS)

    def changed(self, **kwargs):
        kwargs.setdefault("endpoint", "https://changed.example.com")
        kwargs.setdefault("requires_approval", False)
        return agent_config(**kwargs)

    def two_valid_approvals(self, candidate, *, commit="c1", rollback_ref=None):
        return (
            config_approval(
                candidate,
                before_digest=self.base.digest,
                commit=commit,
                rollback_ref=rollback_ref,
                approver_id="alice",
                key_id="key-a",
            ),
            config_approval(
                candidate,
                before_digest=self.base.digest,
                commit=commit,
                rollback_ref=rollback_ref,
                approver_id="bob",
                key_id="key-b",
            ),
        )


class ReadProjectionTests(ConfigGuardBase):
    def test_agent_role_read_is_minimized(self):
        view, decision = self.guard.read(
            ConfigPrincipal(TENANT, "agent.support", ConfigRole.AGENT), self.base.config_id
        )
        self.assertEqual(decision.decision, ControlDecision.SANITIZE)
        self.assertIn("L1-M7-CONFIG-READ-MINIMIZED", decision.reason_codes)
        self.assertNotIn("secretRefs", view)
        self.assertNotIn("endpoint", view["tools"][0])
        self.assertIn("secretRefs", decision.evidence["redactedFields"])

    def test_operator_sees_endpoints_and_reference_only_secrets(self):
        view, decision = self.guard.read(OPERATOR, self.base.config_id)
        self.assertIn("endpoint", view["tools"][0])
        self.assertEqual(view["secretRefs"], ["secret://mail-token"])  # opaque reference, not a value
        self.assertNotIn("digest", view)  # governance metadata still withheld
        self.assertIn("L1-M7-CONFIG-READ-MINIMIZED", decision.reason_codes)

    def test_approver_sees_full_governance_view(self):
        view, decision = self.guard.read(ConfigPrincipal(TENANT, "carol", ConfigRole.APPROVER), self.base.config_id)
        self.assertEqual(decision.decision, ControlDecision.ALLOW)
        self.assertIn("digest", view)
        self.assertIn("commit", view)
        self.assertEqual(decision.evidence["redactedFields"], [])


class DeployTests(ConfigGuardBase):
    def test_agent_cannot_deploy(self):
        with self.assertRaises(ConfigGuardError) as raised:
            self.guard.deploy(
                ConfigPrincipal(TENANT, "agent.support", ConfigRole.AGENT),
                self.changed(),
                commit="c1",
                expected_active_digest=self.base.digest,
            )
        self.assertIn("L1-M7-CONFIG-WRITE-DENIED", raised.exception.decision.reason_codes)
        self.assertEqual(self.store.write_count, 0)

    def test_single_approval_is_two_person_denied(self):
        changed = self.changed()
        approvals = (
            config_approval(
                changed,
                before_digest=self.base.digest,
                commit="c1",
                rollback_ref=None,
                approver_id="alice",
                key_id="key-a",
            ),
        )
        with self.assertRaises(ConfigGuardError) as raised:
            self.guard.deploy(
                OPERATOR,
                changed,
                commit="c1",
                approvals=approvals,
                expected_active_digest=self.base.digest,
            )
        self.assertIn("L1-M7-TWO-PERSON-APPROVAL-REQUIRED", raised.exception.decision.reason_codes)
        self.assertEqual(self.store.write_count, 0)
        self.assertEqual(self.store.active(TENANT, self.base.config_id).config_digest, self.base.digest)

    def test_two_signatures_from_one_person_are_insufficient(self):
        changed = self.changed()
        approvals = (
            config_approval(
                changed,
                before_digest=self.base.digest,
                commit="c1",
                rollback_ref=None,
                approver_id="alice",
                key_id="key-a",
            ),
            config_approval(
                changed,
                before_digest=self.base.digest,
                commit="c1",
                rollback_ref=None,
                approver_id="alice",
                key_id="key-b",
            ),
        )
        with self.assertRaises(ConfigGuardError) as raised:
            self.guard.deploy(
                OPERATOR,
                changed,
                commit="c1",
                approvals=approvals,
                expected_active_digest=self.base.digest,
            )
        self.assertIn("L1-M7-TWO-PERSON-APPROVAL-REQUIRED", raised.exception.decision.reason_codes)

    def test_forged_signature_is_rejected(self):
        changed = self.changed()
        # Signed for a different commit than the deploy actually uses.
        forged = config_approval(
            changed,
            before_digest=self.base.digest,
            commit="OTHER",
            rollback_ref=None,
            approver_id="alice",
            key_id="key-a",
        )
        good = config_approval(
            changed,
            before_digest=self.base.digest,
            commit="c1",
            rollback_ref=None,
            approver_id="bob",
            key_id="key-b",
        )
        with self.assertRaises(ConfigGuardError) as raised:
            self.guard.deploy(
                OPERATOR,
                changed,
                commit="c1",
                approvals=(good, forged),
                expected_active_digest=self.base.digest,
            )
        self.assertIn("L1-M7-CONFIG-SIGNATURE-INVALID", raised.exception.decision.reason_codes)
        self.assertEqual(self.store.write_count, 0)

    def test_stale_base_is_rejected(self):
        changed = self.changed()
        with self.assertRaises(ConfigGuardError) as raised:
            self.guard.deploy(
                OPERATOR,
                changed,
                commit="c1",
                approvals=self.two_valid_approvals(changed),
                expected_active_digest="sha256:" + "0" * 64,
            )
        self.assertIn("L1-M7-CONFIG-BASE-STALE", raised.exception.decision.reason_codes)
        self.assertEqual(self.store.write_count, 0)

    def test_two_person_deploy_supersedes_and_activates_once(self):
        changed = self.changed()
        active = self.guard.deploy(
            OPERATOR,
            changed,
            commit="c1",
            rollback_ref="rev-0",
            approvals=self.two_valid_approvals(changed, rollback_ref="rev-0"),
            expected_active_digest=self.base.digest,
        )
        self.assertEqual(active.state, ConfigRevisionState.ACTIVE)
        self.assertEqual(active.config_digest, changed.digest)
        self.assertEqual(self.store.write_count, 1)
        revisions = self.store.revisions_for(TENANT, self.base.config_id)
        self.assertEqual(len([r for r in revisions if r.state == ConfigRevisionState.ACTIVE]), 1)
        self.assertEqual(len([r for r in revisions if r.state == ConfigRevisionState.SUPERSEDED]), 1)


class DriftTests(ConfigGuardBase):
    def test_matching_runtime_is_allowed(self):
        probe = InMemoryRuntimeConfigProbe()
        probe.set(self.base)
        decision = self.guard.check_runtime(OPERATOR, self.base.config_id, probe)
        self.assertEqual(decision.decision, ControlDecision.ALLOW)

    def test_runtime_drift_quarantines(self):
        probe = InMemoryRuntimeConfigProbe()
        probe.set(self.changed())
        decision = self.guard.check_runtime(OPERATOR, self.base.config_id, probe)
        self.assertEqual(decision.decision, ControlDecision.QUARANTINE)
        self.assertIn("L1-M7-CONFIG-DRIFT", decision.reason_codes)
        self.assertEqual(decision.evidence["desiredDigest"], self.base.digest)
        self.assertEqual(decision.evidence["effectiveDigest"], self.changed().digest)


if __name__ == "__main__":
    unittest.main()
