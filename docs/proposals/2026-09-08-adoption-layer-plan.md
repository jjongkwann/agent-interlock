# Adoption Layer Implementation Plan

**Spec:** `docs/specs/2026-09-08-adoption-layer.md`
**Branch:** `adoption-layer`
**Baseline:** 602 passed, 12 skipped (`.venv/bin/python -m pytest -q`), `ruff check src tests` clean.

## Global constraints

- Every reason code emitted today keeps its string. New codes are added, none renamed.
- `policy.py` must not import `architecture.py` (cycle through `sdk`).
- Core stays dependency-free; `anthropic` is an optional extra imported lazily.
- Python 3.11+, line length 120, `unittest` classes run under pytest and under
  `python -m unittest discover -s tests` (CI uses the latter with `PYTHONPATH=src:tests`).
- No backward-compatibility shims: when a contract changes, change every caller.
- Each task ends with the full suite green and `ruff check src tests` clean.

## Phase 1 — enforcement consistency (T1–T3 are independent)

### T1. One mode (spec D5)
Files: `__main__.py` (`compile --shadow`), `studio_deploy.py`, `run_control.py`,
`tests/test_studio_compile.py`, `tests/test_studio_deploy.py`, `tests/test_run_control.py`,
`tests/test_platform_e2e.py`, `studio/app/panels.tsx` (deploy view label only).
- `compile --shadow` rewrites every edge policy mode to SHADOW in the emitted `architecture`
  and derives `links[].mode` from it. Bundle digest covers the rewritten body.
- Add `studio_deploy.deployed_architecture(bundle_body, mode) -> ArchitectureGraph` that
  applies `mode` to every edge policy. `run_control._engine_for_active_bundle` and the
  platform E2E use it. Run Control raises `RUN-MODE-MISMATCH` (422) if any compiled edge mode
  differs from the record after applying it (guards a future caller that skips the helper).
- Tests: promote a SHADOW bundle whose manifest edges were authored as SHADOW, start a run,
  assert `actualEnforced=True` and an enforced block in the ledger; assert the compile output's
  architecture edges all read SHADOW.

### T2. Shared post-execution and approval on the SDK path (spec D6)
Files: `security.py` or new `results.py`, `gateway.py`, `sdk.py`, `tests/test_sdk_profile.py`,
`tests/test_core.py`.
- Extract `inspect_tool_result(raw, output_schema) -> (clean, labels, secret_detected, schema_errors)`
  with the gateway's quarantine replacement; gateway and SDK call it.
- SDK: under ENFORCE a schema-invalid result is replaced by the quarantine value and
  `SECURITY_OUTCOME_SET` records `BLOCKED`-equivalent labels exactly as the gateway does; under
  SHADOW/OBSERVE the raw-but-sanitized value is returned and errors are recorded.
- Extract the approval store (`Approval`, `grant_approval`, `_approval_valid`) into a small
  `approvals.py` used by `MCPToolGateway` and `Interlock`; `Interlock.grant_approval(...)`
  returns the approval id and `_invoke` passes `approval_valid` into `CheckContext`.
- Tests: SDK external write with an approval succeeds; without it `INTERLOCK-APPROVAL-REQUIRED`;
  SDK result with a secret is redacted; schema-invalid result is quarantined under ENFORCE.
- Update `docs/02` §4.2 to describe the reachable approval path.

### T3. Reject unsupported schema keywords (spec D7)
Files: `security.py`, `models.py`, `architecture.py`, `tests/test_core.py`, `tests/test_architecture.py`.
- `unsupported_schema_keywords(schema) -> tuple[str, ...]` walks nested schemas.
- `ActorSpec.__post_init__`, `ToolDefinition.__post_init__` raise `ValueError` naming the
  keyword; the architecture linter emits `ARCH-SCHEMA-KEYWORD-UNSUPPORTED` (CRITICAL).
- Tests for `minimum`, `oneOf`, `$ref` nested under `properties` and `items`.

## Phase 2 — adapter and runnable project (sequential)

### T4. Intent derivation and the mismatch check (spec D4)
Files: new `intent.py`, `policy.py`, `gateway.py`, `sdk.py`, `tests/test_intent.py`,
`tests/test_check_table.py`, `tests/test_policy_characterization.py`, `tests/test_sdk_profile.py`,
`docs/specs/2026-07-27-control-coverage-statistics.md` (check count), `studio/app/analytics.mjs`
only if a rank map or catalogue changes.
- `derive_intent(arguments, input_schema, annotations, target: ActorSpec) -> DerivedIntent`
  (destinations, side_effect, derivable: bool).
- Check `INTERLOCK-INTENT-ARGUMENT-MISMATCH` (scope PAYLOAD, decision BLOCK): armed when the
  target has an input schema; returns None when nothing derivable; findings when declared
  destinations do not cover derived ones or declared side effect ranks below derived.
- Added to GATEWAY_PROFILE and SDK_PROFILE; A2A untouched. Coverage digests change: update
  the pinned fixtures.

### T5. Anthropic Tool Runner adapter (spec D1–D3)
Files: new `adapters/__init__.py`, `adapters/anthropic_tools.py`, `pyproject.toml`
(`anthropic` extra), `tests/test_anthropic_adapter.py`, `__init__.py` exports.
- `GuardedTool` implements `name`, `to_dict()`, `call(input)`; `GuardedAsyncTool` the async
  variant. Construction: `guard_tools(gateway, *, tenant_id, source_actor_id, tools: [(ToolDefinition|dict, callable)], approver, environment, data_source)`
  observes/approves/activates each definition, registers the tool actor from the definition
  and the manifest, and returns runnable tools.
- `call`: derive intent (T4) → `evaluate_invocation` → `execute_approved_call` with the real
  callable as connector → return `inspect_result`'s clean value serialised for the model.
  Blocks raise `anthropic.lib.tools.ToolError` with the reason codes; the runner turns it into
  `is_error`. The `anthropic` import is lazy and the tool contract is duck-typed, so tests run
  without the package and one test asserts the SDK accepts the object when installed.
- Tests use a fake tool runner that mimics the SDK: assistant turn with a `tool_use`, guard
  called, ledger checked.

### T6. Runnable example project and skeleton wiring
Files: `examples/support_agent/{architecture.json,build.py,run.py,tools.py,fake_mail_server.py,recorded/*.json}`,
`scaffold.py`, `tests/test_scaffold.py`, `tests/test_example_support_agent.py`, `README.md`.
- `build()` returns `(gateway, tools)` ready for `client.beta.messages.tool_runner`.
- `run.py` calls `claude-opus-5` with the guarded tools when credentials exist; tests replay a
  recorded assistant `tool_use` turn through the same code path with a fake client.
- `scaffold.py` emits the adapter wiring: one `ToolDefinition` per TOOL node and the
  `guard_tools` call, handlers as before.

## Phase 3 — verification and outcomes (T7 and T8 are independent)

### T7. `interlock verify` (spec D10)
Files: new `verify.py`, `__main__.py`, `tests/test_verify.py`, reuse `tests/l1_harness.py` canaries
(move the corpus into `src/agent_interlock/verify_corpus.py` so the CLI can use it).
### T8. Acceptance evaluator and three outcomes (spec D9)
Files: `orchestration.py`, `architecture.py` (lint), `run_control.py`, `ledger` payloads,
`studio/app/panels.tsx` (Runs screen), tests.

## Phase 4 — reuse proof, Studio, docs, packaging (T9–T12 independent)

### T9. Second project `examples/refund_agent` with no `src/` change; parametrised example test.
### T10. Studio multi-project: new/open/save, editable id and version, manifest import.
### T11. Docs: `docs/02` §2 and §4, `docs/06` criteria and status fields, README front door,
new `docs/16-adding-interlock-to-an-agent.md`.
### T12. Packaging: version 0.2.0, extra, local build check, `studio/tsconfig.tsbuildinfo` ignored.
