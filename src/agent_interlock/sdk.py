"""Small define/connect/wrap SDK for protecting existing Python callables."""

from __future__ import annotations

import functools
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_digest, canonical_json
from .gateway import GatewayError
from .ledger import InMemoryLedger, Ledger
from .models import ActorSpec, CredentialClaims, InvocationIntent, LinkPolicy, PolicyMode
from .policy import SDK_PROFILE, CheckContext, execution_permitted, run_checks, strongest_decision
from .security import validate_schema


class UndeclaredRelationship(GatewayError):
    pass


@dataclass(frozen=True, slots=True)
class Actor:
    spec: ActorSpec
    _interlock: Interlock

    def connect(self, target: Actor, policy: LinkPolicy) -> None:
        self._interlock.connect(self, target, policy)

    def wrap(self, function: Callable[[Mapping[str, Any]], Any]) -> Callable[..., Any]:
        @functools.wraps(function)
        def guarded(
            arguments: Mapping[str, Any],
            *,
            source: Actor,
            tenant_id: str,
            intent: InvocationIntent,
            trace_id: str | None = None,
            credential: CredentialClaims | None = None,
        ) -> Any:
            return self._interlock._invoke(
                source=source,
                target=self,
                function=function,
                arguments=arguments,
                tenant_id=tenant_id,
                intent=intent,
                trace_id=trace_id,
                credential=credential,
            )

        return guarded


class Interlock:
    def __init__(self, ledger: Ledger | None = None) -> None:
        self.ledger = ledger or InMemoryLedger()
        self._actors: dict[str, Actor] = {}
        self._links: dict[tuple[str, str], LinkPolicy] = {}

    def define_actor(self, spec: ActorSpec) -> Actor:
        if spec.id in self._actors:
            raise ValueError(f"actor already defined: {spec.id}")
        actor = Actor(spec, self)
        self._actors[spec.id] = actor
        return actor

    def connect(self, source: Actor, target: Actor, policy: LinkPolicy) -> None:
        if source.spec.id not in self._actors or target.spec.id not in self._actors:
            raise ValueError("actors must belong to this Interlock instance")
        self._links[(source.spec.id, target.spec.id)] = policy

    def design_graph(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"id": actor.spec.id, "type": actor.spec.type.value, "owner": actor.spec.owner}
                for actor in self._actors.values()
            ],
            "edges": [
                {
                    "source": source,
                    "target": target,
                    "relationship": policy.relationship,
                    "policyId": policy.id,
                    "mode": policy.mode.value,
                }
                for (source, target), policy in self._links.items()
            ],
        }

    def runtime_graph(self, tenant_id: str, trace_id: str) -> dict[str, Any]:
        events = self.ledger.trace(tenant_id, trace_id)
        nodes = sorted({item for event in events for item in (event.source_actor_id, event.target_actor_id) if item})
        return {
            "traceId": trace_id,
            "nodes": [{"id": item} for item in nodes],
            "events": [
                {
                    "eventId": event.event_id,
                    "type": event.event_type,
                    "source": event.source_actor_id,
                    "target": event.target_actor_id,
                    "payload": event.payload,
                }
                for event in events
            ],
        }

    def _invoke(
        self,
        *,
        source: Actor,
        target: Actor,
        function: Callable[[Mapping[str, Any]], Any],
        arguments: Mapping[str, Any],
        tenant_id: str,
        intent: InvocationIntent,
        trace_id: str | None,
        credential: CredentialClaims | None = None,
    ) -> Any:
        policy = self._links.get((source.spec.id, target.spec.id))
        if not policy:
            raise UndeclaredRelationship(f"undeclared relationship: {source.spec.id} -> {target.spec.id}")
        trace = trace_id or f"trace-{uuid.uuid4()}"
        span = f"span-{uuid.uuid4()}"
        interaction = str(uuid.uuid4())
        common = dict(
            tenant_id=tenant_id,
            trace_id=trace,
            span_id=span,
            interaction_id=interaction,
            source_actor_id=source.spec.id,
            target_actor_id=target.spec.id,
            relationship_type=policy.relationship,
        )
        self.ledger.append(
            "INTERACTION_REQUESTED",
            payload={"argumentsHash": canonical_digest(arguments), "purpose": intent.purpose},
            **common,
        )
        self.ledger.append(
            "DATA_FLOW_OBSERVED",
            payload={
                "dataClasses": sorted(intent.data_classes),
                "destinations": list(intent.destinations),
                "taintLabels": sorted(intent.taint_labels),
                "contentHash": canonical_digest(arguments),
            },
            **common,
        )
        reasons, decisions, _ = run_checks(
            policy,
            CheckContext(
                source=source.spec,
                target=target.spec,
                intent=intent,
                arguments=arguments,
                interaction_id=interaction,
                trace_id=trace,
                span_id=span,
                credential=credential,
                relationship=policy.relationship,
                payload_bytes=len(canonical_json(dict(arguments))),
            ),
            SDK_PROFILE,
        )
        decision = strongest_decision(decisions)
        # Same de-duplication evaluate() applies, so a reducer counting reason codes sees the same
        # cardinality from both enforcement points for identical inputs.
        reasons = list(dict.fromkeys(reasons))
        enforced = policy.mode == PolicyMode.ENFORCE
        permitted = execution_permitted(decisions)
        self.ledger.append(
            "CONTROL_EVALUATED",
            payload={
                # Same nested shape the gateway emits, so analytics reduces both.
                "control": {
                    "policyId": policy.id,
                    "policyVersion": policy.version,
                    "mode": policy.mode.value,
                    "decision": decision.value,
                    "reasonCodes": reasons,
                    "actualEnforced": enforced,
                    # See gateway._append_control: the permission aggregate beside the severity
                    # reduction, so a denied invocation does not record an unexplained ALLOW.
                    "executionPermitted": permitted,
                }
            },
            severity="HIGH" if reasons else "INFO",
            **common,
        )
        # The execution gate is the separate permission aggregate, not the severity reduction:
        # strongest_decision annihilates BYPASSED, so `decision != ALLOW` executed a call whose
        # findings were [ALLOW, BYPASSED]. `decision` above still supplies what the ledger records.
        if enforced and not permitted:
            self.ledger.append(
                "ACTION_EXECUTED",
                payload={"result": "COMPLETED", "connectorExecutionId": None},
                **common,
            )
            self.ledger.append("SECURITY_OUTCOME_SET", payload={"securityOutcome": "BLOCKED"}, **common)
            raise GatewayError(f"actor invocation blocked: {', '.join(reasons)}")
        execution_id = str(uuid.uuid4())
        try:
            result = function(arguments)
        except Exception as error:
            self.ledger.append(
                "ACTION_EXECUTED",
                payload={"result": "FAILED", "connectorExecutionId": execution_id, "failure": str(error)},
                **common,
            )
            raise
        self.ledger.append(
            "ACTION_EXECUTED",
            payload={"result": "COMPLETED", "connectorExecutionId": execution_id},
            **common,
        )
        output_errors = validate_schema(result, target.spec.output_schema)
        self.ledger.append(
            "INTERACTION_COMPLETED",
            payload={"resultHash": canonical_digest(result), "schemaErrors": output_errors},
            **common,
        )
        self.ledger.append(
            "SECURITY_OUTCOME_SET",
            payload={"securityOutcome": "SUCCEEDED" if reasons else "UNKNOWN"},
            **common,
        )
        return result
