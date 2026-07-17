"""Shared harness for the L1 (M1-M9) simulation matrix in docs/05.

Everything here is SIMULATION-only: the fake sink records evidence but performs
no real external transmission. The corpus holds identifiable, NON-PRIVILEGED
canaries (never real credentials), matching the docs/05 section 2 fixture and
the section 6 universal assertions.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_interlock import (
    ActorSpec,
    ActorType,
    AgentConfig,
    ConfigApproval,
    ConfigRevision,
    ConfigRevisionState,
    ConfiguredTool,
    ControlDecision,
    DataSource,
    Environment,
    Ledger,
    LinkPolicy,
    MCPToolGateway,
    PolicyMode,
    SideEffect,
    ToolDefinition,
    config_approval_statement,
    sign_canonical,
)

# --------------------------------------------------------------------------- #
# Canary corpus (RAG / config / file). Non-privileged, identifiable markers.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class CanaryRecord:
    canary_id: str
    source: str  # "rag" | "config" | "file"
    data_class: str  # D2 benign, D5 secret, D7 customer/PII, D8 config/file body
    value: str
    # Substring that must NEVER appear raw in the Ledger (docs/05 section 8).
    secret_marker: str | None = None


# A runbook retrieved from RAG that embeds a canary password (M8-001).
RAG_RUNBOOK_SECRET = CanaryRecord(
    canary_id="CANARY-CRED-RUNBOOK-8fa21c",
    source="rag",
    data_class="D5",
    value="Restart runbook step 3: set password=CANARY-CRED-RUNBOOK-8fa21c then run ./restart.sh",
    secret_marker="CANARY-CRED-RUNBOOK-8fa21c",
)
# A config entry holding a canary API key (M8-003).
CONFIG_API_KEY = CanaryRecord(
    canary_id="CANARY-CFG-APIKEY-4b7d9e",
    source="config",
    data_class="D5",
    value="api_key=sk_live_CANARYCFG4b7d9e0000abcd",
    secret_marker="sk_live_CANARYCFG4b7d9e0000abcd",
)
# A file source holding a canary customer list (M9-001/003).
FILE_CUSTOMER_LIST = CanaryRecord(
    canary_id="CANARY-PII-CUSTOMERS-1a2b3c",
    source="file",
    data_class="D7",
    value="canary.alice@example.test;canary.bob@example.test;canary.carol@example.test",
)
# A secret-LOOKING but allowlisted public identifier (M8-004 false-positive control).
ALLOWED_TEST_IDENTIFIER = CanaryRecord(
    canary_id="CANARY-CTRL-PUBLICID-777",
    source="config",
    data_class="D2",
    value="public-demo-identifier-777-not-a-secret",
)

CANARY_CORPUS: tuple[CanaryRecord, ...] = (
    RAG_RUNBOOK_SECRET,
    CONFIG_API_KEY,
    FILE_CUSTOMER_LIST,
    ALLOWED_TEST_IDENTIFIER,
)

# --------------------------------------------------------------------------- #
# Reusable gateway builder
# --------------------------------------------------------------------------- #

INPUT_SCHEMA = {
    "type": "object",
    "required": ["to", "body"],
    "properties": {"to": {"type": "string"}, "body": {"type": "string", "maxLength": 100_000}},
    "additionalProperties": False,
}
OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["status"],
    "properties": {"status": {"type": "string"}, "detail": {"type": "string"}},
    "additionalProperties": False,
}

TENANT = "tenant-a"


def tool_definition(
    *,
    description: str = "Send a message to an approved recipient.",
    endpoint: str = "https://mcp.example.com",
    server_id: str = "tenant-a/prod/trusted-mail",
    tool_name: str = "send_email",
) -> ToolDefinition:
    return ToolDefinition(
        server_id=server_id,
        tool_name=tool_name,
        title="Send email",
        description=description,
        input_schema=INPUT_SCHEMA,
        output_schema=OUTPUT_SCHEMA,
        endpoint=endpoint,
        publisher="platform-team",
        artifact_digest="sha256:" + "a" * 64,
    )


def build_gateway(
    *,
    mode: PolicyMode = PolicyMode.ENFORCE,
    external_approval: bool = False,
    definition: ToolDefinition | None = None,
    side_effects: frozenset[SideEffect] = frozenset({SideEffect.EXTERNAL_WRITE}),
    allowed_domains: frozenset[str] = frozenset({"customer.example"}),
    policy: LinkPolicy | None = None,
    gateway: MCPToolGateway | None = None,
):
    """Return (gateway, active_revision, source_actor, target_actor).

    Mirrors the trusted-mail setup used across the suite, but parametric so the
    matrix can vary policy mode, egress limits, side effects, and destinations.
    Pass ``gateway`` to wire a pre-built gateway (e.g. with a config-guard
    preflight) into the same actor/policy topology.
    """
    gateway = gateway or MCPToolGateway()
    revision = gateway.observe_definition(definition or tool_definition(), tenant_id=TENANT)
    gateway.registry.approve(revision.revision_id, "security-reviewer")
    revision = gateway.registry.activate(revision.revision_id)
    source = ActorSpec(
        id="agent.support",
        type=ActorType.AGENT,
        owner="support",
        identity="spiffe://example/agent/support",
        data_access=frozenset({"D2", "D3", "D7"}),
    )
    target = ActorSpec(
        id="tool.send-email",
        type=ActorType.TOOL,
        owner="messaging",
        identity="spiffe://example/tool/send-email",
        data_access=frozenset({"D2", "D3", "D7"}),
        side_effects=side_effects,
        input_schema=INPUT_SCHEMA,
        output_schema=OUTPUT_SCHEMA,
        allowed_domains=allowed_domains,
        definition_digest=revision.canonical_digest,
    )
    gateway.register_actor(source)
    gateway.register_actor(target, tool_id=revision.tool_id)
    gateway.connect(
        source.id,
        target.id,
        policy or LinkPolicy(mode=mode, external_write_requires_approval=external_approval),
    )
    return gateway, revision, source, target


# --------------------------------------------------------------------------- #
# docs/05 section 6 universal assertions (composable helpers)
# --------------------------------------------------------------------------- #


def assert_events_intact_and_ordered(test, ledger: Ledger, interaction_id: str, tenant_id: str = TENANT) -> None:
    """Assertion 1/3: consistent, ordered, integrity-verified events exist."""
    events = ledger.interaction(tenant_id, interaction_id)
    test.assertTrue(events, "expected at least one ledger event for the interaction")
    test.assertTrue(all(event.tenant_id == tenant_id for event in events))
    test.assertTrue(all(ledger.verify(event) for event in events), "ledger integrity hash mismatch")
    timestamps = [event.occurred_at for event in events]
    test.assertEqual(timestamps, sorted(timestamps), "interaction events are not time-ordered")


def assert_reason_and_policy_recorded(test, ledger: Ledger, interaction_id: str, expected_reason: str, tenant_id: str = TENANT) -> None:
    """Assertion 6: expected reason code + policy version present on the decision."""
    controls = [
        event
        for event in ledger.interaction(tenant_id, interaction_id)
        if event.event_type == "CONTROL_EVALUATED" and "control" in event.payload and "policyVersion" in event.payload["control"]
    ]
    test.assertTrue(controls, "no policy CONTROL_EVALUATED event recorded")
    control = controls[-1].payload["control"]
    test.assertIn(expected_reason, control["reasonCodes"])
    test.assertTrue(control["policyVersion"], "policy version missing on decision")


def assert_no_downstream_receipt(test, receipt_store, tenant_id: str = TENANT) -> None:
    """Assertion 4: a BLOCK/QUARANTINE/HOLD produced no committed external receipt."""
    committed = [item for item in receipt_store.all(tenant_id) if item.byte_count >= 0 and item.status.value == "COMMITTED"]
    test.assertEqual(committed, [], "blocked invocation still produced an external receipt")


def assert_no_canary_secret_in_ledger(test, ledger: Ledger, canaries: tuple[CanaryRecord, ...] = CANARY_CORPUS) -> None:
    """Assertion 5: no canary credential plaintext is stored raw in the Ledger."""
    blob = repr([event.to_dict() for event in ledger.all()])
    for canary in canaries:
        if canary.secret_marker:
            test.assertNotIn(canary.secret_marker, blob, f"canary {canary.canary_id} leaked into the Ledger")


def record_test_executed(
    ledger: Ledger,
    *,
    test_id: str,
    verdict: str,
    passed: bool,
    tenant_id: str = TENANT,
    trace_id: str | None = None,
) -> None:
    """docs/05 section 9: every result is a TEST_EXECUTED event forced to SIMULATION."""
    ledger.append(
        "TEST_EXECUTED",
        tenant_id=tenant_id,
        trace_id=trace_id or f"l1-sim-{test_id}",
        span_id=f"test-{test_id}",
        source_actor_id="l1-sim-runner",
        payload={"testId": test_id, "verdict": verdict, "passed": passed},
        environment=Environment.STAGE,
        data_source=DataSource.SIMULATION,
    )


# --------------------------------------------------------------------------- #
# M7 agent-config fixtures (shared by test_config_guard and the L1 matrix)
# --------------------------------------------------------------------------- #

CONFIG_KEY_A = b"config-approver-a-key-00000000000"
CONFIG_KEY_B = b"config-approver-b-key-11111111111"
CONFIG_TRUSTED_KEYS = {"key-a": CONFIG_KEY_A, "key-b": CONFIG_KEY_B}


def configured_tool(*, endpoint: str = "https://mcp.example.com", requires_approval: bool = True) -> ConfiguredTool:
    return ConfiguredTool(
        definition=ToolDefinition(
            server_id="tenant-a/prod/trusted-mail",
            tool_name="send_email",
            title="Send email",
            description="Send a message to an approved recipient.",
            input_schema=INPUT_SCHEMA,
            endpoint=endpoint,
        ),
        requires_approval=requires_approval,
    )


def agent_config(
    *,
    endpoint: str = "https://mcp.example.com",
    requires_approval: bool = True,
    config_id: str = "cfg-support",
) -> AgentConfig:
    return AgentConfig(
        tenant_id=TENANT,
        config_id=config_id,
        agent_id="agent.support",
        tools=(configured_tool(endpoint=endpoint, requires_approval=requires_approval),),
        prompt_refs=("prompt://support-reply",),
        secret_refs=("secret://mail-token",),  # opaque reference only, never a value
    )


def seed_revision(config: AgentConfig, *, commit: str = "commit-0") -> ConfigRevision:
    return ConfigRevision(
        revision_id=f"{config.config_id}@{config.digest}",
        config=config,
        config_digest=config.digest,
        state=ConfigRevisionState.PROPOSED,
        commit=commit,
    )


def config_approval(
    candidate: AgentConfig,
    *,
    before_digest: str | None,
    commit: str,
    rollback_ref: str | None,
    approver_id: str,
    key_id: str,
) -> ConfigApproval:
    statement = config_approval_statement(
        candidate,
        before_digest=before_digest,
        commit=commit,
        rollback_ref=rollback_ref,
        approver_id=approver_id,
        key_id=key_id,
    )
    return ConfigApproval(approver_id, key_id, sign_canonical(statement, CONFIG_TRUSTED_KEYS[key_id]))


__all__ = [
    "ALLOWED_TEST_IDENTIFIER",
    "CANARY_CORPUS",
    "CONFIG_TRUSTED_KEYS",
    "agent_config",
    "config_approval",
    "configured_tool",
    "seed_revision",
    "CONFIG_API_KEY",
    "CanaryRecord",
    "FILE_CUSTOMER_LIST",
    "INPUT_SCHEMA",
    "OUTPUT_SCHEMA",
    "RAG_RUNBOOK_SECRET",
    "TENANT",
    "assert_events_intact_and_ordered",
    "assert_no_canary_secret_in_ledger",
    "assert_no_downstream_receipt",
    "assert_reason_and_policy_recorded",
    "build_gateway",
    "record_test_executed",
    "tool_definition",
]
