---
title: Runtime Telemetry and Design/Runtime Reconciliation
date: 2026-07-17
version: 0.2.0
status: active
---

# Runtime Telemetry and Design/Runtime Reconciliation

> 한국어 원문: [08-runtime-telemetry-reconciliation.ko.md](08-runtime-telemetry-reconciliation.ko.md)

## 1. Purpose

Compare the Architecture manifest's intent against actual Agent execution to find:

- Actor relationships absent from the design
- Design Edges with no execution evidence
- Interactions executed without `CONTROL_EVALUATED`
- GenAI/MCP spans missing the context required for security correlation

Studio and the CLI accept an Interlock Ledger event array and OTLP/HTTP JSON `resourceSpans` as input. The Ledger HTTP API's authenticated `POST /v1/traces` also accepts the same OTLP/HTTP JSON and decodes it into runtime observations and import issues. This reference endpoint does not append Ledger events.

## 2. OpenTelemetry baseline

OpenTelemetry's GenAI semantic convention has moved to a separate [GenAI Semantic Conventions repository](https://github.com/open-telemetry/semantic-conventions-genai). Because the Agent span specification is currently in `Development` status, the Interlock importer isolates itself on the assumption of version changes.

Classification uses the following attributes from the official [GenAI Agent Span](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-agent-spans.md) and [MCP Span](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/mcp.md) specs.

| Attribute | Purpose |
|---|---|
| `gen_ai.operation.name` | Distinguishes `invoke_agent`, `execute_tool`, `retrieval`, and memory operations |
| `gen_ai.agent.id`, `gen_ai.agent.name` | Identifies and displays the Agent |
| `gen_ai.tool.name` | Displays the executed Tool |
| `mcp.method.name` | Distinguishes MCP methods such as `tools/call` |

The standard attributes alone cannot establish the source Actor, target Actor, REL ID, or control-enforcement status in the Interlock Architecture. The importer does not infer security facts from names or span parentage alone.

## 3. Interlock OTLP extension contract

Spans that want accurate reconciliation record the following attributes together.

```text
interlock.source.actor.id
interlock.target.actor.id
interlock.relationship.id
interlock.relationship.type
interlock.interaction.id
interlock.control.evaluated
```

If `interlock.interaction.id` is absent, `spanId` is used as the correlation fallback. If a tracked GenAI/MCP operation has no relationship context, the importer generates `TELEMETRY_SECURITY_CONTEXT_MISSING` and does not fabricate a relationship.

## 4. Trust Boundary

`interlock.control.evaluated=true` is a claim recorded in the OTLP payload. If the span is sent directly by an untrusted Agent, it is not proof of enforcement. In production, the following conditions must additionally hold before the evidence can be promoted to `ENFORCED` or `RECONCILED`.

1. A Gateway or a separate Audit Sink generates the attribute.
2. Tenant/workload identity and transport authentication are verified.
3. A policy decision ID and action receipt are bound to the interaction.
4. The append-only Ledger's integrity hash or signature verification passes.
5. A separate retention policy ensures sampling does not drop security spans.

The current importer is a payload-normalization and drift-detection layer; it does not prove the authenticity of the OTLP sender.
When an Interlock Ledger event includes `integrity_hash`, the Python importer verifies the canonical hash and excludes mismatched events from relationship analysis. The browser Studio does not verify the hash and instead displays `TELEMETRY_INTEGRITY_UNVERIFIED`, so the trust verdict must be re-performed in the CLI.

## 5. Execution

```bash
PYTHONPATH=src python3 -m agent_interlock architecture runtime-diff \
  examples/secure_multi_agent_architecture.json \
  examples/runtime_drift_otlp.json
```

The exit code is `3` when there is drift or an import issue. The result separates `undeclaredRelationships`, `unobservedEdgeIds`, `controlBypassInteractions`, and `importIssues`.

The same JSON can be imported from the `Runtime graph` or `Drift` tab in Studio. The browser importer accepts only up to 5 MB and does not send the file to a server.

## 6. Current limits and next integration

- OTLP/HTTP JSON file import and the authenticated HTTP receiver are implemented. OTLP/gRPC `:4317`, standard Collector deployment configuration, and backpressure/queueing do not exist yet.
- `SignedAuditSink` is a reference that seals events that passed integrity verification with a symmetric keyed signature. Asymmetric signing is provided by Ed25519 in `signing.py` (`sign/verify_canonical_ed25519`) and by `Ed25519PublisherVerifier` in `supply_chain.py`; append-only hash-chain retention is provided by `WORMAuditStore` in `audit_sink.py` (`InMemoryWORMAuditStore` and the file backend `FileWORMAuditStore`). `FileWORMAuditStore` persists via JSONL append+fsync, re-verifies the chain on open, and keeps write-once dedupe intact across restarts. External KMS/HSM key operations, workload mTLS, and durable WORM export backed by S3 Object Lock do not exist yet.
- Langfuse/LangSmith vendor trace adapters are implemented in `vendor_telemetry.py` (`langfuse_traces_to_otlp`, `langsmith_runs_to_otlp`, `import_langfuse_traces`, `import_langsmith_runs`). They lift the interlock/gen_ai context from vendor metadata into OTLP attributes and then reuse `import_runtime_telemetry`.
- A semantic-convention version adapter that absorbs standard attribute changes is provided by `normalize_otlp_semconv`/`SEMCONV_ALIASES` in `otlp_semconv.py`. It normalizes legacy aliases (`llm.*`, `gen_ai.operation`, snake_case `interlock.*`) to canonical names before passing them to `import_runtime_telemetry` (canonical values take priority over aliases).
- Relationships in which a Dynamic Sub-Agent instance again becomes the source must be verified together with the admission identity registry.
- Missing trace sampling and Audit Sink failures are linked by `ControlHealthReporter` in `control_health.py` to `CONTROL_HEALTH_CHANGED` (REL-12). It emits the import issue, the `RuntimeGraphDiff` control-bypass interaction (= sampling gap), and seal failure as separate reason codes.
- Sensitive content attributes such as prompts, tool arguments, and retrieval queries are not imported by default.
