"""Opt-in M7 config-guard preflight on the gateway invocation path."""

from __future__ import annotations

import unittest

from l1_harness import TENANT, agent_config, build_gateway, seed_revision
from test_l1_matrix import BENIGN_ARGS

from agent_interlock import (
    AgentConfig,
    ConfigGuard,
    ControlDecision,
    InMemoryConfigStore,
    InMemoryLedger,
    InMemoryRuntimeConfigProbe,
    MCPToolGateway,
)
from agent_interlock.models import InvocationIntent


def preflight_gateway(effective: AgentConfig):
    """Gateway wired with a config guard whose probe reports ``effective``."""
    ledger = InMemoryLedger()
    store = InMemoryConfigStore()
    store.seed(seed_revision(agent_config()))
    probe = InMemoryRuntimeConfigProbe()
    probe.set(effective)
    guarded = MCPToolGateway(
        ledger=ledger,
        config_guard=ConfigGuard(store, ledger),
        config_probe=probe,
        agent_config_ids={"agent.support": "cfg-support"},
    )
    return build_gateway(gateway=guarded)


def evaluate(gateway, revision, source):
    return gateway.evaluate_invocation(
        tenant_id=TENANT,
        source_actor_id=source.id,
        revision_id=revision.revision_id,
        intent=InvocationIntent(purpose="reply"),
        arguments=BENIGN_ARGS,
    )


class GatewayConfigPreflightTests(unittest.TestCase):
    def test_disabled_by_default_even_when_runtime_drifts(self):
        gateway, revision, source, _ = build_gateway()
        decision = evaluate(gateway, revision, source)
        self.assertEqual(decision.decision, ControlDecision.ALLOW)
        self.assertNotIn("L1-M7-CONFIG-DRIFT", decision.reason_codes)

    def test_matching_runtime_config_leaves_the_decision_untouched(self):
        gateway, revision, source, _ = preflight_gateway(agent_config())
        decision = evaluate(gateway, revision, source)
        self.assertEqual(decision.decision, ControlDecision.ALLOW)
        self.assertTrue(decision.permits_execution)
        self.assertIs(decision.execution_permitted, True)

    def test_runtime_drift_quarantines_the_invocation(self):
        drifted = agent_config(endpoint="https://attacker.example")
        gateway, revision, source, _ = preflight_gateway(drifted)
        decision = evaluate(gateway, revision, source)
        self.assertEqual(decision.decision, ControlDecision.QUARANTINE)
        self.assertIn("L1-M7-CONFIG-DRIFT", decision.reason_codes)
        self.assertFalse(decision.permits_execution)
        # The permit, not just the severity. On the real producer the two agree today only because
        # check_runtime emits QUARANTINE, which outranks ALLOW; the record has to say the guard
        # denied permission as well, or the merge is relying on that coincidence.
        self.assertIs(decision.execution_permitted, False)
        policy_ids = {
            event.payload["control"].get("policyId")
            for event in gateway.ledger.trace(TENANT, decision.trace_id)
            if event.event_type == "CONTROL_EVALUATED"
        }
        self.assertIn("agent-config-guard", policy_ids, "guard must self-emit on the invocation trace")

    def test_unbound_actor_skips_the_guard(self):
        drifted = agent_config(endpoint="https://attacker.example")
        ledger = InMemoryLedger()
        store = InMemoryConfigStore()
        store.seed(seed_revision(agent_config()))
        probe = InMemoryRuntimeConfigProbe()
        probe.set(drifted)
        guarded = MCPToolGateway(
            ledger=ledger,
            config_guard=ConfigGuard(store, ledger),
            config_probe=probe,
            agent_config_ids={"agent.other": "cfg-support"},
        )
        gateway, revision, source, _ = build_gateway(gateway=guarded)
        decision = evaluate(gateway, revision, source)
        self.assertEqual(decision.decision, ControlDecision.ALLOW)


if __name__ == "__main__":
    unittest.main()
