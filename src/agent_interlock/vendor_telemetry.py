"""Langfuse / LangSmith trace adapters into the OTLP import path.

Interlock-instrumented agents already carry the security context
(``interlock.*`` and ``gen_ai.*`` keys) in whichever metadata field the vendor
exposes — Langfuse observation ``metadata``, LangSmith run ``extra.metadata``.
These adapters lift that metadata into OTLP span attributes and reuse
``import_runtime_telemetry`` for the actual reconciliation, so there is exactly
one place that understands the interlock relationship contract.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .telemetry import RuntimeTelemetryImport, import_runtime_telemetry


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _otlp_attribute(key: str, value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": value}}
    if isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


def _otlp_span(span_id: str, attributes: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "spanId": span_id,
        "attributes": [_otlp_attribute(str(key), value) for key, value in attributes.items()],
    }


def _wrap_spans(spans: list[dict[str, Any]], scope_name: str) -> dict[str, Any]:
    return {
        "resourceSpans": [
            {"scopeSpans": [{"scope": {"name": scope_name}, "spans": spans}]}
        ]
    }


def langfuse_traces_to_otlp(payload: Any) -> dict[str, Any]:
    """Map a Langfuse trace/observation payload into OTLP resourceSpans.

    Accepts a single trace object, a list of observations, or a ``{data: [...]}``
    fetch response. Each observation's ``metadata`` carries the interlock/gen_ai
    attributes; ``id`` becomes the span id.
    """
    observations: list[Any] = []
    if isinstance(payload, Mapping):
        if "observations" in payload:
            observations = _sequence(payload.get("observations"))
        elif "data" in payload:
            observations = _sequence(payload.get("data"))
        else:
            observations = [payload]
    else:
        observations = _sequence(payload)

    spans: list[dict[str, Any]] = []
    for observation in observations:
        if not isinstance(observation, Mapping):
            continue
        span_id = str(observation.get("id") or observation.get("observationId") or "")
        metadata = observation.get("metadata")
        if span_id and isinstance(metadata, Mapping):
            spans.append(_otlp_span(span_id, metadata))
    return _wrap_spans(spans, "langfuse")


def langsmith_runs_to_otlp(payload: Any) -> dict[str, Any]:
    """Map a LangSmith run payload into OTLP resourceSpans.

    Accepts a single run, a list of runs, or a ``{runs: [...]}`` response. The
    interlock/gen_ai attributes live in ``extra.metadata`` (falling back to a
    top-level ``metadata``); ``id`` becomes the span id.
    """
    runs: list[Any] = []
    if isinstance(payload, Mapping):
        if "runs" in payload:
            runs = _sequence(payload.get("runs"))
        else:
            runs = [payload]
    else:
        runs = _sequence(payload)

    spans: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        span_id = str(run.get("id") or run.get("run_id") or "")
        extra = run.get("extra")
        metadata = extra.get("metadata") if isinstance(extra, Mapping) else None
        if not isinstance(metadata, Mapping):
            metadata = run.get("metadata")
        if span_id and isinstance(metadata, Mapping):
            spans.append(_otlp_span(span_id, metadata))
    return _wrap_spans(spans, "langsmith")


def import_langfuse_traces(payload: Any) -> RuntimeTelemetryImport:
    """Convenience: Langfuse payload straight to a RuntimeTelemetryImport."""
    return import_runtime_telemetry(langfuse_traces_to_otlp(payload))


def import_langsmith_runs(payload: Any) -> RuntimeTelemetryImport:
    """Convenience: LangSmith payload straight to a RuntimeTelemetryImport."""
    return import_runtime_telemetry(langsmith_runs_to_otlp(payload))
