"""M7 agent configuration guard: role-scoped read, signed two-person deploy, drift.

Distinct control from :mod:`agent_interlock.registry`, which digest-pins TOOL
DEFINITIONS. This guards the DESIRED AGENT CONFIGURATION — which tools/prompts/
triggers an agent is deployed with, their approval flags, and opaque secret
references — with role-based read minimization, two-person signed deployment,
and desired-vs-effective drift detection. An endpoint change can legitimately
raise both L1-M2-DEFINITION-DRIFT (registry) and an M7 finding here: that is
defense-in-depth, not duplication.

Reference core stays zero-dependency and single-node: HMAC approval signatures
and an in-memory store. Distributed backends implement the same Protocols.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Mapping, Protocol

from .canonical import canonical_digest
from .ledger import InMemoryLedger, Ledger
from .models import ControlDecision, ToolDefinition
from .signing import verify_canonical

CONFIG_GUARD_POLICY_ID = "agent-config-guard"
CONFIG_GUARD_POLICY_VERSION = "1.0.0"

REASON_READ_MINIMIZED = "L1-M7-CONFIG-READ-MINIMIZED"
REASON_WRITE_DENIED = "L1-M7-CONFIG-WRITE-DENIED"
REASON_TWO_PERSON_REQUIRED = "L1-M7-TWO-PERSON-APPROVAL-REQUIRED"
REASON_SIGNATURE_INVALID = "L1-M7-CONFIG-SIGNATURE-INVALID"
REASON_DRIFT = "L1-M7-CONFIG-DRIFT"
REASON_BASE_STALE = "L1-M7-CONFIG-BASE-STALE"


class ConfigRole(StrEnum):
    AGENT = "AGENT"
    OPERATOR = "OPERATOR"
    APPROVER = "APPROVER"


class ConfigRevisionState(StrEnum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True, slots=True)
class ConfigPrincipal:
    tenant_id: str
    actor_id: str
    role: ConfigRole


@dataclass(frozen=True, slots=True)
class ConfiguredTool:
    definition: ToolDefinition
    requires_approval: bool = True

    def canonical_value(self) -> dict[str, Any]:
        return {"definition": self.definition.canonical_value(), "requiresApproval": self.requires_approval}


@dataclass(frozen=True, slots=True)
class AgentConfig:
    tenant_id: str
    config_id: str
    agent_id: str
    tools: tuple[ConfiguredTool, ...] = ()
    trigger_refs: tuple[str, ...] = ()
    prompt_refs: tuple[str, ...] = ()
    secret_refs: tuple[str, ...] = ()  # opaque references only, never secret values

    def canonical_value(self) -> dict[str, Any]:
        return {
            "tenantId": self.tenant_id,
            "configId": self.config_id,
            "agentId": self.agent_id,
            "tools": [tool.canonical_value() for tool in sorted(self.tools, key=lambda item: item.definition.tool_id)],
            "triggerRefs": sorted(self.trigger_refs),
            "promptRefs": sorted(self.prompt_refs),
            "secretRefs": sorted(self.secret_refs),
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.canonical_value())


@dataclass(frozen=True, slots=True)
class ConfigApproval:
    approver_id: str
    key_id: str
    signature: str


@dataclass(frozen=True, slots=True)
class ConfigRevision:
    revision_id: str
    config: AgentConfig
    config_digest: str
    state: ConfigRevisionState
    commit: str
    rollback_ref: str | None = None
    approvals: tuple[ConfigApproval, ...] = ()


@dataclass(frozen=True, slots=True)
class ConfigDecision:
    decision: ControlDecision
    reason_codes: tuple[str, ...]
    evidence: Mapping[str, Any]
    interaction_id: str


class ConfigGuardError(RuntimeError):
    def __init__(self, decision: ConfigDecision) -> None:
        super().__init__(f"config guard {decision.decision.value}: {', '.join(decision.reason_codes)}")
        self.decision = decision


class ConfigStoreStale(RuntimeError):
    """Raised by a ConfigStore when the CAS base digest no longer matches."""


# --------------------------------------------------------------------------- #
# Store + runtime probe contracts
# --------------------------------------------------------------------------- #


class ConfigStore(Protocol):
    def active(self, tenant_id: str, config_id: str) -> ConfigRevision | None: ...

    def revisions_for(self, tenant_id: str, config_id: str) -> tuple[ConfigRevision, ...]: ...

    def activate(self, revision: ConfigRevision, *, expected_active_digest: str | None) -> ConfigRevision: ...


class RuntimeConfigProbe(Protocol):
    def effective(self, tenant_id: str, config_id: str) -> AgentConfig | None: ...


class InMemoryConfigStore:
    """Single-node CAS config store. `write_count` proves no write on denied deploys."""

    def __init__(self) -> None:
        self._active: dict[tuple[str, str], str] = {}
        self._revisions: dict[tuple[str, str], dict[str, ConfigRevision]] = {}
        self._lock = threading.RLock()
        self.write_count = 0

    def seed(self, revision: ConfigRevision) -> ConfigRevision:
        """Bootstrap an initial ACTIVE revision without a guard deploy (test/setup only)."""
        active = replace(revision, state=ConfigRevisionState.ACTIVE)
        key = (active.config.tenant_id, active.config.config_id)
        with self._lock:
            self._revisions.setdefault(key, {})[active.revision_id] = active
            self._active[key] = active.revision_id
        return active

    def active(self, tenant_id: str, config_id: str) -> ConfigRevision | None:
        key = (tenant_id, config_id)
        with self._lock:
            revision_id = self._active.get(key)
            return self._revisions[key][revision_id] if revision_id else None

    def revisions_for(self, tenant_id: str, config_id: str) -> tuple[ConfigRevision, ...]:
        with self._lock:
            return tuple(self._revisions.get((tenant_id, config_id), {}).values())

    def activate(self, revision: ConfigRevision, *, expected_active_digest: str | None) -> ConfigRevision:
        key = (revision.config.tenant_id, revision.config.config_id)
        with self._lock:
            current = self.active(revision.config.tenant_id, revision.config.config_id)
            current_digest = current.config_digest if current else None
            if current_digest != expected_active_digest:
                raise ConfigStoreStale("active config digest does not match the CAS base")
            revisions = self._revisions.setdefault(key, {})
            if current is not None:
                revisions[current.revision_id] = replace(current, state=ConfigRevisionState.SUPERSEDED)
            active = replace(revision, state=ConfigRevisionState.ACTIVE)
            revisions[active.revision_id] = active
            self._active[key] = active.revision_id
            self.write_count += 1
            return active


class InMemoryRuntimeConfigProbe:
    """Deterministic effective-config probe for drift simulation."""

    def __init__(self) -> None:
        self._effective: dict[tuple[str, str], AgentConfig] = {}

    def set(self, config: AgentConfig) -> None:
        self._effective[(config.tenant_id, config.config_id)] = config

    def effective(self, tenant_id: str, config_id: str) -> AgentConfig | None:
        return self._effective.get((tenant_id, config_id))


# --------------------------------------------------------------------------- #
# Read projection by role
# --------------------------------------------------------------------------- #

_ALL_FIELDS = frozenset(
    {"toolEndpoints", "requiresApproval", "triggerRefs", "promptRefs", "secretRefs", "digest", "commit", "rollbackRef", "approvals"}
)


def _project(revision: ConfigRevision, role: ConfigRole) -> tuple[dict[str, Any], frozenset[str]]:
    config = revision.config
    view: dict[str, Any] = {
        "configId": config.config_id,
        "revisionId": revision.revision_id,
        "agentId": config.agent_id,
    }
    returned: set[str] = set()
    minimal_tools = [
        {"toolId": tool.definition.tool_id, "title": tool.definition.title} for tool in config.tools
    ]
    if role is ConfigRole.AGENT:
        view["tools"] = minimal_tools
    else:
        view["tools"] = [
            {**base, "endpoint": tool.definition.endpoint, "requiresApproval": tool.requires_approval}
            for base, tool in zip(minimal_tools, config.tools)
        ]
        returned |= {"toolEndpoints", "requiresApproval", "triggerRefs", "promptRefs", "secretRefs"}
        view["triggerRefs"] = list(config.trigger_refs)
        view["promptRefs"] = list(config.prompt_refs)
        view["secretRefs"] = list(config.secret_refs)  # opaque references only
    if role is ConfigRole.APPROVER:
        returned |= {"digest", "commit", "rollbackRef", "approvals"}
        view["digest"] = revision.config_digest
        view["commit"] = revision.commit
        view["rollbackRef"] = revision.rollback_ref
        view["approvals"] = [
            {"approverId": item.approver_id, "keyId": item.key_id} for item in revision.approvals
        ]
    return view, frozenset(_ALL_FIELDS - returned)


# --------------------------------------------------------------------------- #
# Guard
# --------------------------------------------------------------------------- #


class ConfigGuard:
    """Control-plane guard for agent configuration read, deploy, and drift."""

    def __init__(
        self,
        store: ConfigStore,
        ledger: Ledger | None = None,
        *,
        trusted_keys: Mapping[str, bytes] | None = None,
    ) -> None:
        self.store = store
        self.ledger = ledger or InMemoryLedger()
        self._trusted_keys = {key_id: key for key_id, key in (trusted_keys or {}).items() if key}

    def read(self, principal: ConfigPrincipal, config_id: str, *, trace_id: str | None = None) -> tuple[dict[str, Any], ConfigDecision]:
        revision = self.store.active(principal.tenant_id, config_id)
        if revision is None:
            decision = self._decision(ControlDecision.BLOCK, (REASON_WRITE_DENIED,), {"reason": "config not found"})
            self._emit(principal, config_id, decision, trace_id)
            raise ConfigGuardError(decision)
        view, redacted = _project(revision, principal.role)
        reasons = (REASON_READ_MINIMIZED,) if redacted else ()
        verdict = ControlDecision.SANITIZE if redacted else ControlDecision.ALLOW
        decision = self._decision(
            verdict,
            reasons,
            {
                "requesterRole": principal.role.value,
                "returnedFields": sorted(view),
                "redactedFields": sorted(redacted),
            },
        )
        self._emit(principal, config_id, decision, trace_id)
        return view, decision

    def deploy(
        self,
        principal: ConfigPrincipal,
        candidate: AgentConfig,
        *,
        commit: str,
        rollback_ref: str | None = None,
        approvals: tuple[ConfigApproval, ...] = (),
        expected_active_digest: str | None = None,
        trace_id: str | None = None,
    ) -> ConfigRevision:
        current = self.store.active(candidate.tenant_id, candidate.config_id)
        before_digest = current.config_digest if current else None
        after_digest = candidate.digest
        evidence: dict[str, Any] = {
            "beforeDigest": before_digest,
            "afterDigest": after_digest,
            "changedFields": sorted(_changed_fields(current.config if current else None, candidate)),
            "commit": commit,
            "rollbackRef": rollback_ref,
        }

        def reject(reason: str) -> ConfigGuardError:
            decision = self._decision(ControlDecision.BLOCK, (reason,), {**evidence, "writeCount": 0})
            self._emit(principal, candidate.config_id, decision, trace_id)
            return ConfigGuardError(decision)

        if principal.role is ConfigRole.AGENT:
            raise reject(REASON_WRITE_DENIED)

        valid: list[ConfigApproval] = []
        for approval in approvals:
            key = self._trusted_keys.get(approval.key_id)
            statement = _approval_statement(candidate, before_digest, after_digest, commit, rollback_ref, approval)
            if key is None or not verify_canonical(statement, approval.signature, key):
                raise reject(REASON_SIGNATURE_INVALID)
            valid.append(approval)
        if len({a.approver_id for a in valid}) < 2 or len({a.key_id for a in valid}) < 2:
            raise reject(REASON_TWO_PERSON_REQUIRED)
        if before_digest != expected_active_digest:
            raise reject(REASON_BASE_STALE)

        revision = ConfigRevision(
            revision_id=f"{candidate.config_id}@{after_digest}",
            config=candidate,
            config_digest=after_digest,
            state=ConfigRevisionState.APPROVED,
            commit=commit,
            rollback_ref=rollback_ref,
            approvals=tuple(valid),
        )
        try:
            active = self.store.activate(revision, expected_active_digest=expected_active_digest)
        except ConfigStoreStale:
            raise reject(REASON_BASE_STALE) from None
        decision = self._decision(
            ControlDecision.ALLOW,
            (),
            {**evidence, "approvers": sorted(a.approver_id for a in valid), "keyIds": sorted(a.key_id for a in valid)},
        )
        self._emit(principal, candidate.config_id, decision, trace_id)
        return active

    def check_runtime(
        self,
        principal: ConfigPrincipal,
        config_id: str,
        probe: RuntimeConfigProbe,
        *,
        trace_id: str | None = None,
    ) -> ConfigDecision:
        active = self.store.active(principal.tenant_id, config_id)
        desired_digest = active.config_digest if active else None
        effective = probe.effective(principal.tenant_id, config_id)
        effective_digest = effective.digest if effective else None
        evidence = {"desiredDigest": desired_digest, "effectiveDigest": effective_digest}
        if desired_digest == effective_digest:
            decision = self._decision(ControlDecision.ALLOW, (), evidence)
        else:
            decision = self._decision(ControlDecision.QUARANTINE, (REASON_DRIFT,), evidence)
        self._emit(principal, config_id, decision, trace_id)
        return decision

    def _decision(self, decision: ControlDecision, reasons: tuple[str, ...], evidence: Mapping[str, Any]) -> ConfigDecision:
        return ConfigDecision(decision, reasons, dict(evidence), interaction_id=str(uuid.uuid4()))

    def _emit(self, principal: ConfigPrincipal, config_id: str, decision: ConfigDecision, trace_id: str | None) -> None:
        self.ledger.append(
            "CONTROL_EVALUATED",
            tenant_id=principal.tenant_id,
            trace_id=trace_id or f"config-{uuid.uuid4()}",
            span_id=f"config-{uuid.uuid4()}",
            interaction_id=decision.interaction_id,
            source_actor_id=principal.actor_id,
            target_actor_id=config_id,
            relationship_type="CONFIGURES",
            relationship_id="REL-11",
            severity="HIGH" if decision.decision != ControlDecision.ALLOW else "INFO",
            payload={
                "control": {
                    "policyId": CONFIG_GUARD_POLICY_ID,
                    "policyVersion": CONFIG_GUARD_POLICY_VERSION,
                    "decision": decision.decision.value,
                    "reasonCodes": list(decision.reason_codes),
                    "requesterRole": principal.role.value,
                },
                "config": dict(decision.evidence),
            },
        )


def _approval_statement(
    candidate: AgentConfig,
    before_digest: str | None,
    after_digest: str,
    commit: str,
    rollback_ref: str | None,
    approval: ConfigApproval,
) -> dict[str, Any]:
    return {
        "purpose": "agent-config-deploy",
        "tenantId": candidate.tenant_id,
        "configId": candidate.config_id,
        "beforeDigest": before_digest,
        "afterDigest": after_digest,
        "commit": commit,
        "rollbackRef": rollback_ref,
        "approverId": approval.approver_id,
        "keyId": approval.key_id,
    }


def config_approval_statement(
    candidate: AgentConfig,
    *,
    before_digest: str | None,
    commit: str,
    rollback_ref: str | None,
    approver_id: str,
    key_id: str,
) -> dict[str, Any]:
    """Public builder for the exact statement each approver must sign."""
    return _approval_statement(
        candidate,
        before_digest,
        candidate.digest,
        commit,
        rollback_ref,
        ConfigApproval(approver_id, key_id, ""),
    )


def _changed_fields(before: AgentConfig | None, after: AgentConfig) -> frozenset[str]:
    after_value = after.canonical_value()
    if before is None:
        return frozenset(after_value)
    before_value = before.canonical_value()
    return frozenset(key for key in after_value if before_value.get(key) != after_value.get(key))
