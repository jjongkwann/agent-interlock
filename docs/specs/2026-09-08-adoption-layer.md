# Adoption Layer

Status: in progress on branch `adoption-layer`. Baseline before this work: 602 passed, 12 skipped.
Date: 2026-09-08

## Problem

The platform enforces policy at three points (MCP gateway, SDK, A2A broker) and records
evidence for every judgment, but nothing connects a real agent runtime to any of them.
`src/` has no reference to an LLM SDK or an agent framework. `wrap()` is synchronous and
needs a hand-built `InvocationIntent` on every call. The skeleton generator emits graph
wiring and `NotImplementedError` handlers, not a runnable agent. The L1 matrix verifies
the framework's own checks with a simulated harness, never a user's wired project.

Four enforcement gaps would make any adapter's results untrustworthy, so they are closed
first:

1. **Mode is declared three times and they disagree.** `compile --shadow` writes
   `links[].mode = SHADOW` but leaves `architecture.edges[].policy.mode` as authored;
   promotion sets the deployment record to `ENFORCE` and rewrites neither; Run Control
   recompiles from `architecture`, so the effective per-edge mode is whatever the author
   typed. A signed promotion does not decide what runs.
2. **The SDK path returns raw results.** `sdk._invoke` records output schema errors and
   returns the original value; it never sanitizes secrets. The gateway does both
   (`gateway.inspect_result`). The SDK also has no approval path, so an external write
   under a stock `LinkPolicy` is unreachable rather than approvable.
3. **Unsupported JSON Schema keywords pass silently.** `validate_schema` implements
   `type`, `required`, `properties`, `additionalProperties`, `items`, `enum`,
   `maxLength`, `pattern`. `minimum`, `maximum`, `oneOf`, `$ref` and the rest are ignored.
4. **Judgment runs on self-declared intent.** Purpose, data classes, destinations, side
   effect and volume all come from the caller's `InvocationIntent`; nothing is derived
   from the arguments the model actually chose. An under-declared intent passes.

## Completion criterion

Two different business projects, each generated from its own manifest, run through the
same adapter against a Claude tool-use loop and pass `interlock verify`, with no change to
`src/` between the first and the second. The second project is the test.

## Decisions

**D1. First runtime: the Anthropic Python SDK Tool Runner, client-side execution.**
`client.beta.messages.tool_runner` yields each assistant turn before tools run and lets a
tool's own `call` gate execution, which is exactly where the gateway belongs. The SDK's
MCP conversion helpers connect the existing MCP transport work. The API's `mcp_servers`
server-side connector executes tools on Anthropic's side and cannot be intercepted; it is
out of scope. `anthropic` is an optional extra; the core stays dependency-free.

**D2. The adapter is a runnable tool, not a new engine.** It implements the SDK's runnable
tool contract (`name`, `to_dict()`, `call(input)`) around one `ToolDefinition` and one
callable. A block is returned to the model as `ToolError` content (an `is_error` tool
result carrying the reason codes), never raised into the loop. Async tools get the same
guard through the async contract.

**D3. Two-phase gateway path.** The adapter calls `evaluate_invocation`, runs the real
tool as the connector through `execute_approved_call`, and returns what `inspect_result`
produced. Tool definitions go through `observe_definition` → approve → activate before the
loop starts, so M1–M3 run on the real definitions the model sees.

**D4. Intent is derived from arguments, and a declared intent must cover the derivation.**
`intent.py` derives destinations from arguments using the input schema (`format: email`,
`format: uri`, `format: hostname`, or `x-interlock-destination: true` on a property),
and the side effect from MCP tool annotations (`readOnlyHint`, `destructiveHint`) and
the target actor's declared side effects. A new check `INTERLOCK-INTENT-ARGUMENT-MISMATCH`
in the shared table (GATEWAY and SDK profiles) fires when the declared destinations do
not cover the derived ones or the declared side effect is weaker than the derived one.
When nothing can be derived the check reports INAPPLICABLE through the coverage channel;
it never passes by default.

**D5. One mode.** The source of truth for a deployed run is the deployment record.
`compile --shadow` rewrites every `architecture.edges[].policy.mode` to `SHADOW` before
digesting, so the bundle is internally consistent and `links[].mode` is derived from it.
Promotion and rollback keep signing the bundle digest plus `toMode`. Anything that loads
the active bundle (`run_control`, the platform E2E, the Studio deploy view) applies the
deployment record's mode to every edge before compiling, through one helper in
`studio_deploy`. Per-edge modes in a manifest govern local runs only. Run Control refuses
to start when the applied modes and the record disagree.

**D6. The SDK shares the gateway's post-execution handling and approval store.** One
`inspect_tool_result(raw, output_schema)` helper feeds both `gateway.inspect_result` and
`sdk._invoke`. Under ENFORCE a schema-invalid result is replaced by the quarantine value
the gateway already emits; under SHADOW and OBSERVE it is recorded. Secrets are always
sanitized. `Interlock.grant_approval` reuses the gateway's approval logic, so
`approval_valid` becomes reachable from the SDK.

**D7. Unsupported schema keywords are rejected at definition time.** `validate_schema`
keeps its subset; a new `unsupported_schema_keywords(schema)` lists anything outside it,
and `ActorSpec`, `ToolDefinition` and the architecture linter refuse a schema that uses
one. Fail-closed and still dependency-free. Adding `jsonschema` was the alternative.

**D8. `BYPASSED` stays where it is.** It has no producer in `src/`, `execution_permitted`
already keeps a bypassed control from executing under ENFORCE, and moving it to the
coverage channel would change the statistics golden fixtures on both sides. It remains the
open question in `2026-07-27-control-coverage-statistics.md`.

**D9. Three outcomes per task.** `acceptanceCriteria` entries are evaluated by a
structural evaluator with a small fixed grammar: `required:<path>`, `nonempty:<path>`,
`equals:<path>=<value>`. An entry outside the grammar fails the task and the linter reports
it. A task run records `executed`, `goal_met` and `security_met` separately; the run
summary Run Control returns carries all three, and the Studio Runs screen shows them.

**D10. `interlock verify`.** `interlock verify <manifest> --entrypoint <module:function>`
imports the project's `build()` (the skeleton's contract), drives the adapter's guarded
tools with a scripted driver in place of the LLM, and runs the corpus: M1 poisoned
description, M2 definition drift, M3 cross-server reference, M8 credential in result,
M9 undeclared destination, M9 volume, undeclared side effect, goal hijack (a tool result
carrying an instruction leads the driver to a call outside the declared graph) and memory
poisoning (a RAG result carrying a canary taints the next external write). Output is a
per-project matrix (`id`, `expected`, `observed`, `passed`) as JSON plus `TEST_EXECUTED`
ledger events; exit code 1 when any row fails.

**D11. Packaging.** Version `0.2.0`, `anthropic` optional extra, wheel and sdist built
and checked locally. Upload to PyPI is a user action and is not performed here.

## Non-goals

Server-side MCP connector, LangGraph or Claude Agent SDK adapters, an LLM-based
prompt-injection classifier, PostgreSQL changes, PyPI upload.

## Task plan

`docs/proposals/2026-09-08-adoption-layer-plan.md`.
