# Agent Interlock Security Architecture Studio

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

The `Runtime graph` and `Drift` tabs accept Interlock Ledger events or OTLP/HTTP JSON up to 5 MB. Imported files stay in the browser session.

## Current boundary

The Studio edits a local draft and downloads JSON in the browser. It does not deploy policy or mutate a runtime. Use the root Python CLI to lint and compile an exported manifest before rollout:

```bash
PYTHONPATH=../src python3 -m agent_interlock architecture lint ./agent-interlock-architecture.json
PYTHONPATH=../src python3 -m agent_interlock architecture compile ./agent-interlock-architecture.json
```
