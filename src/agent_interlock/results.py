"""Shared post-execution result inspection.

Both enforcement points -- the gateway (``gateway.MCPToolGateway.inspect_result``) and the
SDK (``sdk.Interlock._invoke``) -- run a tool result through the same pipeline: redact
secrets, validate the (sanitized) value against the tool's output schema, label the
outcome, and, when the schema is violated, produce the quarantine value the gateway has
always emitted. Extracted so both callers make one call on the same tool result instead of
maintaining two copies of the logic.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .security import sanitize_secrets, validate_schema


@dataclass(frozen=True, slots=True)
class ToolResultInspection:
    clean: Any
    sanitized: Any
    labels: tuple[str, ...]
    secret_detected: bool
    schema_errors: tuple[str, ...]


def inspect_tool_result(raw_result: Any, output_schema: Mapping[str, Any]) -> ToolResultInspection:
    """Sanitize ``raw_result`` and validate it against ``output_schema``.

    ``sanitized`` is the secrets-redacted value with a schema-invalid result still intact --
    what a SHADOW/OBSERVE caller should return, since it does not enforce. ``clean`` is
    ``sanitized`` with a schema-invalid result replaced by the quarantine value -- what an
    ENFORCE caller should return.
    """
    sanitized, secret_detected = sanitize_secrets(raw_result)
    schema_value = (
        sanitized["structuredContent"]
        if isinstance(sanitized, Mapping) and "structuredContent" in sanitized
        else sanitized
    )
    schema_errors = validate_schema(schema_value, output_schema)
    labels = ["UNTRUSTED_TOOL_RESULT"]
    if secret_detected:
        labels.append("D5_REDACTED")
    clean = sanitized
    if schema_errors:
        labels.append("SCHEMA_INVALID")
        if isinstance(sanitized, Mapping) and any(
            key in sanitized for key in ("content", "structuredContent", "isError")
        ):
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
    return ToolResultInspection(
        clean=clean,
        sanitized=sanitized,
        labels=tuple(labels),
        secret_detected=secret_detected,
        schema_errors=tuple(schema_errors),
    )
