# Agent Interlock Security Architecture Studio

> 한국어 원문: [README.ko.md](README.ko.md)

Local visual editor for Agent Interlock Architecture-as-Code manifests. It lets you add and move actor boxes, connect trust boundaries, change link policy and control assurance, import Ledger or OTLP JSON runtime telemetry, inspect drift, and export a manifest accepted by the Python compiler.

## Run locally

Requires Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

The development server selects the next available port when port 3000 is busy.

## Verify

```bash
npm test
npm run lint
```

`npm test` builds the Vinext application and verifies the rendered product shell and backend-compatible manifest contract.

The build dependencies pin `braces` to commit `97308a01d091b211cf015314a2d0696da28a5392` from [upstream PR #78](https://github.com/micromatch/braces/pull/78), with tarball integrity recorded in `package-lock.json`. The reviewed patch limits parser and AST traversal depth to address [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm). It is not yet an upstream release. Tests exercise the installed package with deeply nested patterns and direct ASTs, as well as ordinary glob behavior. The package keeps its original name and version; version-based scanners may still flag `3.0.3`. Replace this pin with a fixed official release when available, retaining the regression tests.

The `Runtime graph` and `Drift` tabs accept Interlock Ledger events or OTLP/HTTP JSON up to 5 MB. The `Statistics` tab aggregates raw Ledger events offline or reads the scoped statistics API. Imported files stay in the browser session.

## Language

Use the English / 한국어 selector in the header. Studio uses the browser language initially and remembers your choice in this browser. Project data, identifiers, API values, and exported manifests keep their original values.

## Projects

The header carries the project id and version as editable fields, used by `Export manifest`. The `Projects` menu supports several projects in one browser: `New project` clears the canvas to an empty architecture with a fresh id; `Open manifest…` loads any Architecture manifest JSON produced by `Export manifest` or accepted by the Python compiler, laying out any node or task position it omits on a grid; `Save` stores the current graph under its project id in the browser's `localStorage`, and the saved-projects list opens or deletes those entries. All of it is undoable. Saved projects never leave the browser and are lost if its storage is cleared.

## Current boundary

Architecture edits remain local drafts. Use the root Python CLI to lint and compile an exported manifest before rollout:

```bash
PYTHONPATH=../src python3 -m agent_interlock architecture lint ./agent-interlock-architecture.json
PYTHONPATH=../src python3 -m agent_interlock architecture compile ./agent-interlock-architecture.json
```

The `Deploy` tab talks only to an explicitly configured Control Plane. Approvers sign locally in the browser or with `interlock studio approve --repo <bundle-repository>`. Private keys are never sent to the server. The Control Plane verifies Ed25519 signatures bound to the approver, tenant, deployment target, bundle and active base. Promotion and rollback both require two distinct approvers and two distinct public keys; rollback targets must have been active previously.
