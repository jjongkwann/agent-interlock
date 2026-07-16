"""Normalize Interlock Ledger events and OTLP JSON into runtime graph observations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .architecture import ObservedEdge
from .canonical import canonical_digest


@dataclass(frozen=True, slots=True)
class TelemetryImportIssue:
    code: str
    message: str
    span_id: str | None = None


@dataclass(frozen=True, slots=True)
class RuntimeTelemetryImport:
    format: str
    observations: tuple[ObservedEdge, ...]
    control_evaluated_interactions: frozenset[str]
    issues: tuple[TelemetryImportIssue, ...]


_TRACKED_OPERATIONS = frozenset(
    {
        "invoke_agent",
        "execute_tool",
        "retrieval",
        "search_memory",
        "create_memory",
        "update_memory",
        "upsert_memory",
        "delete_memory",
    }
)


def import_runtime_telemetry(value: Any) -> RuntimeTelemetryImport:
    """Import a Ledger event list or an OTLP/HTTP JSON traces payload.

    Standard ``gen_ai.*`` and ``mcp.*`` attributes classify operations. Exact
    security reconciliation requires ``interlock.source.actor.id``,
    ``interlock.target.actor.id``, ``interlock.relationship.id``,
    ``interlock.relationship.type``, and ``interlock.control.evaluated`` on the
    same span. ``interlock.interaction.id`` is recommended; span ID is the
    correlation fallback.
    """

    if isinstance(value, Mapping) and "resourceSpans" in value:
        return _import_otlp(value)
    if isinstance(value, Mapping) and "events" in value:
        return _import_ledger(_sequence(value.get("events"), "events"))
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return _import_ledger(value)
    raise ValueError("telemetry must be an Interlock event array or OTLP resourceSpans object")


def _import_ledger(values: Sequence[Any]) -> RuntimeTelemetryImport:
    observations: list[ObservedEdge] = []
    evaluated: set[str] = set()
    issues: list[TelemetryImportIssue] = []
    for index, value in enumerate(values):
        if not isinstance(value, Mapping):
            issues.append(
                TelemetryImportIssue(
                    "TELEMETRY_EVENT_INVALID",
                    f"event at index {index} is not an object",
                )
            )
            continue
        if "integrity_hash" in value:
            body = dict(value)
            expected = str(body.pop("integrity_hash"))
            if canonical_digest(body) != expected:
                issues.append(
                    TelemetryImportIssue(
                        "TELEMETRY_INTEGRITY_INVALID",
                        f"event at index {index} failed integrity verification",
                        _optional_string(value.get("span_id")),
                    )
                )
                continue
        event_type = str(value.get("event_type", ""))
        interaction_id = _optional_string(value.get("interaction_id"))
        if event_type == "CONTROL_EVALUATED":
            if interaction_id:
                evaluated.add(interaction_id)
            else:
                issues.append(
                    TelemetryImportIssue(
                        "TELEMETRY_CONTROL_INTERACTION_MISSING",
                        "CONTROL_EVALUATED has no interaction_id",
                        _optional_string(value.get("span_id")),
                    )
                )
            continue
        if event_type != "INTERACTION_REQUESTED":
            continue
        observation = _edge_from_mapping(value, issues, f"event at index {index}")
        if observation:
            observations.append(observation)
    return RuntimeTelemetryImport(
        "INTERLOCK_LEDGER",
        _deduplicate(observations),
        frozenset(evaluated),
        tuple(issues),
    )


def _import_otlp(value: Mapping[str, Any]) -> RuntimeTelemetryImport:
    observations: list[ObservedEdge] = []
    evaluated: set[str] = set()
    issues: list[TelemetryImportIssue] = []
    for span in _otlp_spans(value):
        attributes = _attributes(span.get("attributes", []))
        operation = str(attributes.get("gen_ai.operation.name", ""))
        mcp_method = str(attributes.get("mcp.method.name", ""))
        relationship_id = _optional_string(attributes.get("interlock.relationship.id"))
        if not relationship_id:
            if operation in _TRACKED_OPERATIONS or mcp_method == "tools/call":
                issues.append(
                    TelemetryImportIssue(
                        "TELEMETRY_SECURITY_CONTEXT_MISSING",
                        "tracked GenAI/MCP span has no interlock relationship context",
                        _optional_string(span.get("spanId")),
                    )
                )
            continue
        span_id = _optional_string(span.get("spanId"))
        interaction_id = _optional_string(attributes.get("interlock.interaction.id")) or span_id
        edge_value = {
            "source_actor_id": attributes.get("interlock.source.actor.id"),
            "target_actor_id": attributes.get("interlock.target.actor.id"),
            "relationship_type": attributes.get("interlock.relationship.type"),
            "relationship_id": relationship_id,
            "interaction_id": interaction_id,
            "span_id": span_id,
        }
        observation = _edge_from_mapping(edge_value, issues, "OTLP span")
        if observation:
            observations.append(observation)
            if _boolean(attributes.get("interlock.control.evaluated")) and interaction_id:
                evaluated.add(interaction_id)
    return RuntimeTelemetryImport(
        "OTLP_JSON",
        _deduplicate(observations),
        frozenset(evaluated),
        tuple(issues),
    )


def _edge_from_mapping(
    value: Mapping[str, Any],
    issues: list[TelemetryImportIssue],
    context: str,
) -> ObservedEdge | None:
    span_id = _optional_string(value.get("span_id"))
    fields = {
        "source_actor_id": _optional_string(value.get("source_actor_id")),
        "target_actor_id": _optional_string(value.get("target_actor_id")),
        "relationship_type": _optional_string(value.get("relationship_type")),
        "relationship_id": _optional_string(value.get("relationship_id")),
    }
    missing = [name for name, item in fields.items() if not item]
    if missing:
        issues.append(
            TelemetryImportIssue(
                "TELEMETRY_RELATIONSHIP_INCOMPLETE",
                f"{context} is missing {', '.join(missing)}",
                span_id,
            )
        )
        return None
    return ObservedEdge(
        source=fields["source_actor_id"] or "",
        target=fields["target_actor_id"] or "",
        relationship=fields["relationship_type"] or "",
        relationship_id=fields["relationship_id"] or "",
        interaction_id=_optional_string(value.get("interaction_id")) or span_id,
    )


def _otlp_spans(value: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    spans: list[Mapping[str, Any]] = []
    for resource in _sequence(value.get("resourceSpans", []), "resourceSpans"):
        if not isinstance(resource, Mapping):
            continue
        scopes = resource.get("scopeSpans", resource.get("instrumentationLibrarySpans", []))
        for scope in _sequence(scopes, "scopeSpans"):
            if not isinstance(scope, Mapping):
                continue
            for span in _sequence(scope.get("spans", []), "spans"):
                if isinstance(span, Mapping):
                    spans.append(span)
    return tuple(spans)


def _attributes(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key): item for key, item in value.items()}
    result: dict[str, Any] = {}
    for item in _sequence(value, "attributes"):
        if not isinstance(item, Mapping) or not item.get("key"):
            continue
        result[str(item["key"])] = _otlp_value(item.get("value"))
    return result


def _otlp_value(value: Any) -> Any:
    if not isinstance(value, Mapping):
        return value
    for key in ("stringValue", "boolValue", "intValue", "doubleValue", "bytesValue"):
        if key in value:
            return value[key]
    if "arrayValue" in value:
        array_value = value["arrayValue"]
        if isinstance(array_value, Mapping):
            return [_otlp_value(item) for item in _sequence(array_value.get("values", []), "values")]
    if "kvlistValue" in value:
        kvlist = value["kvlistValue"]
        if isinstance(kvlist, Mapping):
            return _attributes(kvlist.get("values", []))
    return value


def _deduplicate(values: Sequence[ObservedEdge]) -> tuple[ObservedEdge, ...]:
    unique: dict[tuple[str, str, str, str, str | None], ObservedEdge] = {}
    for value in values:
        key = (
            value.source,
            value.target,
            value.relationship,
            value.relationship_id,
            value.interaction_id,
        )
        unique.setdefault(key, value)
    return tuple(unique.values())


def _sequence(value: Any, name: str) -> Sequence[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return value
    raise ValueError(f"{name} must be an array")


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


def _boolean(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes"}
