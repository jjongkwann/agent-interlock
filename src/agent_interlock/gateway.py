"""MCP Tool Gateway reference pipeline and enforcement boundary."""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from .canonical import canonical_digest
from .config_guard import ConfigDecision, ConfigGuard, ConfigPrincipal, ConfigRole, RuntimeConfigProbe
from .ledger import InMemoryLedger, Ledger
from .models import (
    ActionResult,
    ActorSpec,
    ConnectorExecutionContext,
    ConnectorLike,
    ControlDecision,
    CredentialClaims,
    DataSource,
    Environment,
    InvocationIntent,
    InvocationResult,
    LinkPolicy,
    PolicyDecisionRecord,
    SecurityOutcome,
    SideEffect,
    ToolDefinition,
)
from .policy import EvaluationInput, evaluate, strongest_decision
from .receipts import FakeExternalReceiptStore
from .registry import DefinitionRegistry, ToolRevision
from .security import canonical_destination, destination_domain, sanitize_secrets, validate_schema


class GatewayError(RuntimeError):
    pass


class InvocationBlocked(GatewayError):
    def __init__(self, decision: PolicyDecisionRecord):
        super().__init__(f"invocation {decision.decision.value}: {', '.join(decision.reason_codes)}")
        self.decision = decision


class ArgumentBindingError(GatewayError):
    pass


class ResultRejected(GatewayError):
    pass


@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    tenant_id: str
    arguments_hash: str
    destinations: tuple[str, ...]
    expires_at_epoch: float
    approver: str


@dataclass(slots=True)
class _Pending:
    tenant_id: str
    source: ActorSpec
    target: ActorSpec
    revision: ToolRevision
    intent: InvocationIntent
    decision: PolicyDecisionRecord
    environment: Environment
    data_source: DataSource


class MCPToolGateway:
    def __init__(
        self,
        *,
        registry: DefinitionRegistry | None = None,
        ledger: Ledger | None = None,
        config_guard: ConfigGuard | None = None,
        config_probe: RuntimeConfigProbe | None = None,
        agent_config_ids: Mapping[str, str] | None = None,
    ) -> None:
        self.registry = registry or DefinitionRegistry()
        self.ledger = ledger or InMemoryLedger()
        self._config_guard = config_guard
        self._config_probe = config_probe
        self._agent_config_ids = dict(agent_config_ids or {})
        self._actors: dict[str, ActorSpec] = {}
        self._tool_actors: dict[str, ActorSpec] = {}
        self._policies: dict[tuple[str, str], LinkPolicy] = {}
        self._decisions: dict[str, _Pending] = {}
        self._approvals: dict[str, Approval] = {}
        self._idempotency: dict[tuple[str, str], tuple[str, InvocationResult]] = {}
        self._execution_decisions: dict[str, str] = {}

    def register_actor(self, actor: ActorSpec, *, tool_id: str | None = None) -> None:
        self._actors[actor.id] = actor
        if tool_id:
            self._tool_actors[tool_id] = actor

    def connect(self, source_actor_id: str, target_actor_id: str, policy: LinkPolicy) -> None:
        if source_actor_id not in self._actors or target_actor_id not in self._actors:
            raise KeyError("both actors must be registered before connect")
        self._policies[(source_actor_id, target_actor_id)] = policy

    def observe_definition(
        self,
        definition: ToolDefinition,
        *,
        tenant_id: str,
        raw_definition: bytes | str | object | None = None,
        trace_id: str | None = None,
    ) -> ToolRevision:
        revision = self.registry.observe(definition, raw_definition)
        trace = trace_id or f"definition-{uuid.uuid4()}"
        self.ledger.append(
            "CONTROL_EVALUATED",
            tenant_id=tenant_id,
            trace_id=trace,
            span_id=f"definition-{uuid.uuid4()}",
            source_actor_id=definition.server_id,
            target_actor_id=definition.tool_id,
            payload={
                "toolDefinition": {
                    "toolId": definition.tool_id,
                    "revisionId": revision.revision_id,
                    "observedDigest": revision.canonical_digest,
                    "rawDigest": revision.raw_digest,
                    "state": revision.state.value,
                },
                "control": {"decision": revision.state.value, "reasonCodes": revision.reason_codes},
            },
        )
        return revision

    def grant_approval(
        self,
        *,
        tenant_id: str,
        arguments: Mapping[str, Any],
        canonical_destinations: tuple[str, ...],
        approver: str,
        ttl_seconds: int = 300,
    ) -> Approval:
        approval = Approval(
            approval_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            arguments_hash=canonical_digest(arguments),
            destinations=canonical_destinations,
            expires_at_epoch=time.time() + ttl_seconds,
            approver=approver,
        )
        self._approvals[approval.approval_id] = approval
        return approval

    def evaluate_invocation(
        self,
        *,
        tenant_id: str,
        source_actor_id: str,
        revision_id: str,
        intent: InvocationIntent,
        arguments: Mapping[str, Any],
        credential: CredentialClaims | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
        environment: Environment = Environment.DEV,
        data_source: DataSource = DataSource.PRODUCTION,
    ) -> PolicyDecisionRecord:
        source = self._actors[source_actor_id]
        revision = self.registry.get(revision_id)
        target = self._tool_actors[revision.tool_id]
        policy = self._policies[(source.id, target.id)]
        interaction_id = str(uuid.uuid4())
        trace = trace_id or f"trace-{uuid.uuid4()}"
        span = span_id or f"span-{uuid.uuid4()}"
        approval_valid = self._approval_valid(intent, tenant_id, arguments)

        self.ledger.append(
            "INTERACTION_REQUESTED",
            tenant_id=tenant_id,
            trace_id=trace,
            span_id=span,
            interaction_id=interaction_id,
            source_actor_id=source.id,
            target_actor_id=target.id,
            payload={
                "mcp": {"serverId": revision.definition.server_id, "method": "tools/call"},
                "toolDefinition": {"toolId": revision.tool_id, "revisionId": revision.revision_id},
                "invocation": {
                    "purpose": intent.purpose,
                    "argumentsHash": canonical_digest(arguments),
                },
            },
            environment=environment,
            data_source=data_source,
        )
        self.ledger.append(
            "DATA_FLOW_OBSERVED",
            tenant_id=tenant_id,
            trace_id=trace,
            span_id=span,
            interaction_id=interaction_id,
            source_actor_id=source.id,
            target_actor_id=target.id,
            payload={
                "dataClasses": sorted(intent.data_classes),
                "destinations": list(intent.destinations),
                "taintLabels": sorted(intent.taint_labels),
                "contentHash": canonical_digest(arguments),
            },
            environment=environment,
            data_source=data_source,
        )
        decision = evaluate(
            policy,
            EvaluationInput(
                source=source,
                target=target,
                revision=revision,
                intent=intent,
                arguments=arguments,
                credential=credential,
                approval_valid=approval_valid,
                interaction_id=interaction_id,
                trace_id=trace,
                span_id=span,
            ),
        )
        config_decision = self._config_preflight(tenant_id, source.id, trace)
        if config_decision is not None:
            decision = replace(
                decision,
                decision=strongest_decision([decision.decision, config_decision.decision]),
                reason_codes=decision.reason_codes + config_decision.reason_codes,
            )
        self._decisions[decision.decision_id] = _Pending(
            tenant_id, source, target, revision, intent, decision, environment, data_source
        )
        self._append_control(decision, credential)
        return decision

    def _config_preflight(self, tenant_id: str, source_actor_id: str, trace_id: str) -> ConfigDecision | None:
        """Opt-in M7 drift preflight; disabled unless guard, probe and a config
        binding for the source actor were all provided."""
        config_id = self._agent_config_ids.get(source_actor_id)
        if self._config_guard is None or self._config_probe is None or config_id is None:
            return None
        result = self._config_guard.check_runtime(
            ConfigPrincipal(tenant_id=tenant_id, actor_id=source_actor_id, role=ConfigRole.AGENT),
            config_id,
            self._config_probe,
            trace_id=trace_id,
        )
        return None if result.decision == ControlDecision.ALLOW else result

    def execute_approved_call(
        self,
        decision_id: str,
        arguments: Mapping[str, Any],
        connector: ConnectorLike,
        *,
        idempotency_key: str,
    ) -> InvocationResult:
        pending = self._decisions.get(decision_id)
        if not pending:
            raise GatewayError("unknown decision")
        decision = pending.decision
        cache_key = (pending.tenant_id, idempotency_key)
        request_fingerprint = self._request_fingerprint(
            pending.source.id, pending.revision.revision_id, pending.intent, arguments
        )
        if cache_key in self._idempotency:
            previous_fingerprint, previous_result = self._idempotency[cache_key]
            if previous_fingerprint != request_fingerprint:
                raise GatewayError("idempotency key was already used for a different invocation")
            return previous_result
        if time.time() > decision.expires_at_epoch:
            raise GatewayError("decision expired")
        if canonical_digest(arguments) != decision.arguments_hash:
            raise ArgumentBindingError("arguments do not match the evaluated hash")
        if not decision.permits_execution:
            self._append_action(pending, ActionResult.COMPLETED, None)
            self._append_outcome(pending, SecurityOutcome.BLOCKED, None)
            raise InvocationBlocked(decision)

        execution_id = str(uuid.uuid4())
        self._execution_decisions[execution_id] = decision.decision_id
        connector_context = ConnectorExecutionContext(
            connector_execution_id=execution_id,
            tenant_id=pending.tenant_id,
            decision_id=decision.decision_id,
            interaction_id=decision.interaction_id,
            trace_id=decision.trace_id,
            arguments_hash=decision.arguments_hash,
            expected_destinations=decision.canonical_destinations,
        )
        try:
            contextual_execute = getattr(connector, "execute_with_context", None)
            raw_result = (
                contextual_execute(arguments, connector_context)
                if callable(contextual_execute)
                else connector(arguments)
            )
        except Exception as error:
            self._append_action(pending, ActionResult.FAILED, execution_id, failure=str(error))
            self._append_outcome(pending, SecurityOutcome.UNKNOWN, execution_id)
            raise
        self._append_action(pending, ActionResult.COMPLETED, execution_id)
        clean_result, labels = self.inspect_result(pending, execution_id, raw_result)
        outcome = SecurityOutcome.SUCCEEDED if decision.decision != ControlDecision.ALLOW else SecurityOutcome.UNKNOWN
        self._append_outcome(pending, outcome, execution_id)
        result = InvocationResult(clean_result, decision, execution_id, labels)
        self._idempotency[cache_key] = (request_fingerprint, result)
        return result

    def invoke(self, *, connector: ConnectorLike, idempotency_key: str, **evaluation: Any) -> InvocationResult:
        cache_key = (evaluation["tenant_id"], idempotency_key)
        request_fingerprint = self._request_fingerprint(
            evaluation["source_actor_id"],
            evaluation["revision_id"],
            evaluation["intent"],
            evaluation["arguments"],
        )
        if cache_key in self._idempotency:
            previous_fingerprint, previous_result = self._idempotency[cache_key]
            if previous_fingerprint != request_fingerprint:
                raise GatewayError("idempotency key was already used for a different invocation")
            return previous_result
        arguments = evaluation["arguments"]
        decision = self.evaluate_invocation(**evaluation)
        return self.execute_approved_call(decision.decision_id, arguments, connector, idempotency_key=idempotency_key)

    def inspect_result(
        self, pending: _Pending, connector_execution_id: str, raw_result: Any
    ) -> tuple[Any, tuple[str, ...]]:
        clean, secret_detected = sanitize_secrets(raw_result)
        schema_value = (
            clean["structuredContent"] if isinstance(clean, Mapping) and "structuredContent" in clean else clean
        )
        schema_errors = validate_schema(schema_value, pending.revision.definition.output_schema)
        labels = ["UNTRUSTED_TOOL_RESULT"]
        if secret_detected:
            labels.append("D5_REDACTED")
        if schema_errors:
            labels.append("SCHEMA_INVALID")
            if isinstance(clean, Mapping) and any(key in clean for key in ("content", "structuredContent", "isError")):
                clean = {
                    "content": [
                        {
                            "type": "text",
                            "text": "Tool result quarantined by Agent Interlock.",
                        }
                    ],
                    "isError": True,
                }
            else:
                clean = {"quarantined": True, "reason": "result schema validation failed"}
        self.ledger.append(
            "INTERACTION_COMPLETED",
            tenant_id=pending.tenant_id,
            trace_id=pending.decision.trace_id,
            span_id=pending.decision.span_id,
            interaction_id=pending.decision.interaction_id,
            source_actor_id=pending.source.id,
            target_actor_id=pending.target.id,
            payload={
                "connectorExecutionId": connector_execution_id,
                "resultHash": canonical_digest(clean),
                "labels": labels,
                "secretDetected": secret_detected,
                "schemaErrors": schema_errors,
            },
            environment=pending.environment,
            data_source=pending.data_source,
        )
        return clean, tuple(labels)

    def reconcile_transaction(
        self,
        decision_id: str,
        *,
        observed_side_effect: SideEffect,
        observed_destinations: tuple[str, ...],
        downstream_receipt_count: int,
        compensation_completed: bool = False,
        downstream_byte_count: int = 0,
        downstream_record_count: int = 0,
    ) -> SecurityOutcome:
        pending = self._decisions[decision_id]
        declared = observed_side_effect in {SideEffect.NONE, *pending.target.side_effects}
        allowed = pending.target.allowed_domains
        destinations_allowed = all(destination_domain(item) in allowed for item in observed_destinations)
        if declared and destinations_allowed:
            return SecurityOutcome.UNKNOWN
        reasons = []
        if not declared:
            reasons.append("L1-UNDECLARED-SIDE-EFFECT")
        if not destinations_allowed:
            reasons.append("L1-M9-NEW-DESTINATION")
        outcome = SecurityOutcome.PARTIALLY_EXECUTED if downstream_receipt_count else SecurityOutcome.BLOCKED
        self.ledger.append(
            "DETECTION_RAISED",
            tenant_id=pending.tenant_id,
            trace_id=pending.decision.trace_id,
            span_id=pending.decision.span_id,
            interaction_id=pending.decision.interaction_id,
            source_actor_id=pending.source.id,
            target_actor_id=pending.target.id,
            severity="HIGH",
            payload={
                "reasonCodes": reasons,
                "observedSideEffect": observed_side_effect.value,
                "observedDestinations": observed_destinations,
                "downstreamReceiptCount": downstream_receipt_count,
                "downstreamByteCount": downstream_byte_count,
                "downstreamRecordCount": downstream_record_count,
                "response": "REVOKE",
                "compensationCompleted": compensation_completed,
            },
            environment=pending.environment,
            data_source=pending.data_source,
        )
        self.ledger.append(
            "ACTION_EXECUTED",
            tenant_id=pending.tenant_id,
            trace_id=pending.decision.trace_id,
            span_id=pending.decision.span_id,
            interaction_id=pending.decision.interaction_id,
            source_actor_id=pending.source.id,
            target_actor_id=pending.target.id,
            payload={
                "actionType": "REVOKE",
                "result": ActionResult.COMPLETED.value,
                "compensationCompleted": compensation_completed,
            },
            environment=pending.environment,
            data_source=pending.data_source,
        )
        self._append_outcome(
            pending,
            outcome,
            None,
            downstream_receipt_count=downstream_receipt_count,
            compensation_completed=compensation_completed,
            downstream_byte_count=downstream_byte_count,
            downstream_record_count=downstream_record_count,
        )
        return outcome

    def reconcile_receipt_store(
        self,
        decision_id: str,
        connector_execution_id: str,
        receipt_store: FakeExternalReceiptStore,
    ) -> SecurityOutcome:
        pending = self._decisions[decision_id]
        if self._execution_decisions.get(connector_execution_id) != decision_id:
            raise GatewayError("connector execution is not bound to the decision")
        summary = receipt_store.summary(pending.tenant_id, connector_execution_id)
        if summary.decision_id is not None and (
            summary.decision_id != decision_id
            or summary.interaction_id != pending.decision.interaction_id
            or summary.arguments_hash != pending.decision.arguments_hash
        ):
            raise GatewayError("receipt binding does not match the approved invocation")
        return self.reconcile_transaction(
            decision_id,
            observed_side_effect=summary.observed_side_effect,
            observed_destinations=summary.observed_destinations,
            downstream_receipt_count=summary.downstream_receipt_count,
            compensation_completed=summary.compensation_completed,
            downstream_byte_count=summary.byte_count,
            downstream_record_count=summary.record_count,
        )

    def _approval_valid(self, intent: InvocationIntent, tenant_id: str, arguments: Mapping[str, Any]) -> bool:
        if not intent.approval_id:
            return False
        approval = self._approvals.get(intent.approval_id)
        try:
            destinations = tuple(canonical_destination(item) for item in intent.destinations)
        except ValueError:
            return False
        return bool(
            approval
            and approval.tenant_id == tenant_id
            and approval.arguments_hash == canonical_digest(arguments)
            and approval.destinations == destinations
            and approval.expires_at_epoch >= time.time()
        )

    @staticmethod
    def _request_fingerprint(
        source_actor_id: str,
        revision_id: str,
        intent: InvocationIntent,
        arguments: Mapping[str, Any],
    ) -> str:
        return canonical_digest(
            {
                "sourceActorId": source_actor_id,
                "revisionId": revision_id,
                "purpose": intent.purpose,
                "dataClasses": sorted(intent.data_classes),
                "destinations": list(intent.destinations),
                "estimatedSideEffect": intent.estimated_side_effect.value,
                "taintLabels": sorted(intent.taint_labels),
                "approvalId": intent.approval_id,
                "expectedAudience": intent.expected_audience,
                "expectedResource": intent.expected_resource,
                "argumentsHash": canonical_digest(arguments),
            }
        )

    def _append_control(self, decision: PolicyDecisionRecord, credential: CredentialClaims | None) -> None:
        pending = self._decisions[decision.decision_id]
        self.ledger.append(
            "CONTROL_EVALUATED",
            tenant_id=pending.tenant_id,
            trace_id=decision.trace_id,
            span_id=decision.span_id,
            interaction_id=decision.interaction_id,
            source_actor_id=pending.source.id,
            target_actor_id=pending.target.id,
            severity="HIGH" if decision.decision != ControlDecision.ALLOW else "INFO",
            payload={
                "toolDefinition": {
                    "toolId": pending.revision.tool_id,
                    "revisionId": pending.revision.revision_id,
                    "observedDigest": pending.revision.canonical_digest,
                    "approvedDigest": pending.target.definition_digest,
                    "state": pending.revision.state.value,
                },
                "authorization": {
                    "credentialFingerprint": credential.fingerprint if credential else None,
                    "issuer": credential.issuer if credential else None,
                    "audience": credential.audience if credential else None,
                    "resource": credential.resource if credential else None,
                },
                "control": {
                    "policyId": decision.policy_id,
                    "policyVersion": decision.policy_version,
                    "mode": decision.mode.value,
                    "decision": decision.decision.value,
                    "reasonCodes": decision.reason_codes,
                    "actualEnforced": decision.enforced,
                },
            },
            environment=pending.environment,
            data_source=pending.data_source,
        )

    def _append_action(
        self,
        pending: _Pending,
        result: ActionResult,
        connector_id: str | None,
        failure: str | None = None,
    ) -> None:
        self.ledger.append(
            "ACTION_EXECUTED",
            tenant_id=pending.tenant_id,
            trace_id=pending.decision.trace_id,
            span_id=pending.decision.span_id,
            interaction_id=pending.decision.interaction_id,
            source_actor_id=pending.source.id,
            target_actor_id=pending.target.id,
            payload={
                "result": result.value,
                "connectorExecutionId": connector_id,
                "failure": failure,
            },
            environment=pending.environment,
            data_source=pending.data_source,
        )

    def _append_outcome(
        self,
        pending: _Pending,
        outcome: SecurityOutcome,
        connector_id: str | None,
        **extra: Any,
    ) -> None:
        self.ledger.append(
            "SECURITY_OUTCOME_SET",
            tenant_id=pending.tenant_id,
            trace_id=pending.decision.trace_id,
            span_id=pending.decision.span_id,
            interaction_id=pending.decision.interaction_id,
            source_actor_id=pending.source.id,
            target_actor_id=pending.target.id,
            payload={
                "securityOutcome": outcome.value,
                "connectorExecutionId": connector_id,
                **extra,
            },
            environment=pending.environment,
            data_source=pending.data_source,
        )
