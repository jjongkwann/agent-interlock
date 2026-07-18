"""OTLP GenAI/MCP semantic-convention version adapter.

OpenTelemetry's GenAI semantic conventions (and vendor instrumentations that
predate them) have used several spellings for the same idea — ``llm.*`` before
``gen_ai.*``, ``gen_ai.operation`` before ``gen_ai.operation.name``, snake_case
``interlock.*`` before the dotted form. ``import_runtime_telemetry`` reads only
the canonical names; this adapter renames known aliases onto them so a payload
from an older instrumentation still reconciles. Pass the result to
``import_runtime_telemetry``.
"""

from __future__ import annotations

from typing import Any, Mapping

# alias attribute key -> canonical attribute key the importer reads.
SEMCONV_ALIASES: dict[str, str] = {
    # operation name
    "gen_ai.operation": "gen_ai.operation.name",
    "llm.request.type": "gen_ai.operation.name",
    "traceloop.span.kind": "gen_ai.operation.name",
    # mcp method
    "mcp.method": "mcp.method.name",
    "mcp.request.method": "mcp.method.name",
    "rpc.method": "mcp.method.name",
    # interlock security context (legacy snake_case -> dotted)
    "interlock.source_actor_id": "interlock.source.actor.id",
    "interlock.target_actor_id": "interlock.target.actor.id",
    "interlock.relationship_type": "interlock.relationship.type",
    "interlock.relationship_id": "interlock.relationship.id",
    "interlock.interaction_id": "interlock.interaction.id",
    "interlock.control_evaluated": "interlock.control.evaluated",
}


def normalize_semconv_attributes(
    attributes: Mapping[str, Any], *, aliases: Mapping[str, str] = SEMCONV_ALIASES
) -> dict[str, Any]:
    """Rename aliased attribute keys onto their canonical names.

    A value already present under the canonical name always wins over an alias,
    so a mixed payload is never downgraded by a stale legacy key.
    """
    result: dict[str, Any] = {}
    aliased: dict[str, Any] = {}
    for key, value in attributes.items():
        canonical = aliases.get(key)
        if canonical is None:
            result[key] = value
        else:
            aliased.setdefault(canonical, value)
    for canonical, value in aliased.items():
        result.setdefault(canonical, value)
    return result


def _normalize_attribute_list(attributes: Any, aliases: Mapping[str, str]) -> Any:
    if isinstance(attributes, Mapping):
        return normalize_semconv_attributes(attributes, aliases=aliases)
    if not isinstance(attributes, list):
        return attributes
    renamed: list[Any] = []
    seen_canonical: set[str] = set()
    # Track which canonical keys already exist so an alias never overrides them.
    for item in attributes:
        if isinstance(item, Mapping) and item.get("key") in aliases:
            continue  # handled in the second pass
        if isinstance(item, Mapping):
            seen_canonical.add(str(item.get("key")))
        renamed.append(item)
    for item in attributes:
        if not isinstance(item, Mapping):
            continue
        canonical = aliases.get(item.get("key"))
        if canonical is None or canonical in seen_canonical:
            continue
        seen_canonical.add(canonical)
        renamed.append({**item, "key": canonical})
    return renamed


def normalize_otlp_semconv(
    payload: Mapping[str, Any], *, aliases: Mapping[str, str] = SEMCONV_ALIASES
) -> dict[str, Any]:
    """Return an OTLP resourceSpans payload with span attributes renamed to the
    canonical semantic-convention keys."""
    if not isinstance(payload, Mapping) or "resourceSpans" not in payload:
        raise ValueError("normalize_otlp_semconv expects an OTLP resourceSpans object")
    resource_spans = []
    for resource in payload.get("resourceSpans", []) or []:
        if not isinstance(resource, Mapping):
            resource_spans.append(resource)
            continue
        scopes_key = "scopeSpans" if "scopeSpans" in resource else "instrumentationLibrarySpans"
        scopes = []
        for scope in resource.get(scopes_key, []) or []:
            if not isinstance(scope, Mapping):
                scopes.append(scope)
                continue
            spans = []
            for span in scope.get("spans", []) or []:
                if isinstance(span, Mapping) and "attributes" in span:
                    spans.append({**span, "attributes": _normalize_attribute_list(span["attributes"], aliases)})
                else:
                    spans.append(span)
            scopes.append({**scope, "spans": spans})
        resource_spans.append({**resource, scopes_key: scopes})
    return {**payload, "resourceSpans": resource_spans}
