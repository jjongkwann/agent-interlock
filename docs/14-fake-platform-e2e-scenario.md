---
title: Fake-Data Platform E2E Scenario
date: 2026-07-21
version: 1.1
status: active
---

# Fake-Data Platform E2E Scenario

> 한국어 원문: [14-fake-platform-e2e-scenario.ko.md](14-fake-platform-e2e-scenario.ko.md)

## 1. Goals and safety boundary

This scenario verifies Agent Interlock's entire closed loop with a single automated test. Fake customer data and transport adapters are used only on this test path; Studio and the product runtime carry no built-in demo execution or fake-success fallback.

```text
Design manifest
  → lint / SHADOW compile
  → git propose / Ed25519 two-person approval / ENFORCE
  → Orchestration Engine
  → real localhost A2A HTTP carrier
  → A2A Broker / Trust Boundary
  → Human approval pause / resume
  → MCP Transport / Gateway
  → fake connector receipt
  → Ledger / Runtime Graph / Statistics / Drift
```

All customer, tenant, knowledge, and receipt data are pinned to [`tests/fixtures/platform_e2e/fake_customer_support.json`](../tests/fixtures/platform_e2e/fake_customer_support.json). Addresses use the IANA-reserved TLD `.invalid`, and the fake MCP server only responds in-process; it never calls DNS, mail, or an external API. Only A2A passes through a real HTTP carrier, on an OS-assigned `127.0.0.1` ephemeral port.

## 2. Normal scenario

| Step | Action | Passing evidence |
|---|---|---|
| 1. Design | Reads the Support Agent, Research Sub-Agent, Send Email Tool, zones, directional boundary, and task DAG. | The Architecture parser and linter pass with no critical findings. |
| 2. Tool admission | Discovers the fake `tools/list` result and pins the exact canonical digest into the manifest. | The Tool is not exposed before approval, and an observed revision digest is generated. |
| 3. Compile | Runs `architecture compile --shadow`. | The bundle digest covers the full Architecture — not just Actors and Edges — including 3 boundaries and 2 tasks. |
| 4. Deploy | Proposes to a temporary git store and two distinct Ed25519 identities approve it. | The active bundle is `ENFORCE`, there are 2 approvers, and digest recomputation matches. |
| 5. A2A execution | The Engine sends `task.research` over a real localhost HTTP `SendMessage`. | Origin, bearer, and A2A-Version, along with REL-06/boundary, are checked before the handler runs, and the A2A Task completes. |
| 6. Approval pause | The follow-on `task.send-reply` requires human approval. | The run is `WAITING_APPROVAL`, and the fake MCP call count is 0. |
| 7. Resume | Resumes the same run after fake approval. | The completed A2A task is not replayed, and the MCP fake send executes exactly once. |
| 8. Observation | Feeds the Ledger into the Runtime and Statistics reducers. | Design drift is 0, bypass is 0, and SIMULATION shows 2 interactions, 2 execution attempts, and 2 successes. |

## 3. Failure scenarios

The same test includes two fail-closed paths.

1. Sending `D5` data to the Research Sub-Agent is blocked by the directional A2A boundary with `A2A-BOUNDARY-DATA-CLASS-DENIED` before the handler runs. The handler call count must not increase, and `enforcedBlockCount` must increase by 1.
2. Placing an undeclared `agent.support → external.rogue-fake` event into the SIMULATION Ledger must make the Runtime comparison correctly report 1 undeclared edge and the control-bypass interaction ID.

A separate regression test also confirms that removing `boundaryId` from the REL-06 Edge triggers `ARCH-BOUNDARY-MISSING` before deployment.

## 4. How to run

```bash
# Quickly run just the platform E2E
.venv/bin/python -m pytest -q tests/test_platform_e2e.py

# Test run creation/approval/cancellation over real Control Plane HTTP routes
.venv/bin/python -m pytest -q tests/test_run_control.py

# Run the same E2E against the exact revision exported from Chrome Studio
AGENT_INTERLOCK_PLATFORM_E2E_MANIFEST="$HOME/Downloads/agent-interlock-architecture.json" \
  .venv/bin/python -m pytest -q tests/test_platform_e2e.py::FakePlatformE2ETests::test_design_deploy_execute_observe_and_fail_closed

# Full Python regression
.venv/bin/python -m pytest -q

# Studio contract/UI regression
cd studio
npm run lint
npm test
npm run build
```

The automation itself lives in [`tests/test_platform_e2e.py`](../tests/test_platform_e2e.py). It creates a fresh temporary git repository, temporary A2A socket, and in-memory Ledger on every run, so repeated runs never change real operational state.

The default automated regression uses the checked-in reference manifest. Setting `AGENT_INTERLOCK_PLATFORM_E2E_MANIFEST` reads the exact revision exported from Studio as-is, locates the coordinator, A2A target, MCP target, and task IDs from the manifest, and runs the same scenario. So a revision with one extra external RAG boundary — like the Studio default example — can validate the full execution contract without any code changes.

## 5. Studio manual verification checklist

| Screen | Action | Expected result |
|---|---|---|
| Design / Task workflow | Add an A2A task | The task/A2A count increases and a missing-acceptance-criteria warning appears. |
| Inspector | Enter fake acceptance criteria | The warning disappears and the posture normalizes. |
| Dependency | Select a dependency that would create a cycle | The selection button becomes disabled. |
| Security check | Run the check | The current draft's finding count is displayed explicitly. |
| Graph canvas | Mouse wheel, macOS `Command+=/-`, Windows `Ctrl+=/-` | Only the graph zoom changes; Chrome page zoom does not change. Shortcuts outside the canvas keep the browser's default behavior. |
| Runtime | Enter without telemetry | Does not copy the Design and instead shows that there is no observation. |
| Runs | Connect to a test-only Control Plane and start/approve a run | The active ENFORCE digest is displayed, and after approving the WAITING_APPROVAL task the run becomes COMPLETED. |
| Drift | Import `studio/tests/fixtures/drift-demo.json` in a test session | Undeclared edges and control bypass are displayed distinctly. |
| Statistics | Import a SIMULATION Ledger | Interaction-lifecycle statistics separate from production are displayed. |
| Deploy | Query bundle/control-plane status | The browser holds no private key, and compiling, signing, and promotion remain the responsibility of the external CLI/Control Plane. |

Studio's Runs tab connects directly to `POST/GET /v1/runs` and the approve/resume/cancel/events routes. The browser E2E uses a CORS-allowed loopback test Control Plane, and test fixtures and adapters are injected only into that server process. In a real deployment, the host must inject production A2A/MCP/LOCAL/HUMAN adapters and a durable store.
