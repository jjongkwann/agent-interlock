---
title: Manual Browser E2E Screen Evidence
date: 2026-07-21
version: 1.0
status: active
---

# Manual Browser E2E Screen Evidence

> 한국어 원문: [15-manual-browser-e2e-evidence.ko.md](15-manual-browser-e2e-evidence.ko.md)

This document collects the screen evidence from manually running the [Fake-Data Platform E2E Scenario](14-fake-platform-e2e-scenario.md) in the Studio UI. Every screen was produced with a test-only Control Plane and a `SIMULATION` Ledger. It contains no real customer data or external transmission.

The images remove the Chrome tab strip, address bar, and the browser's left sidebar, keeping only the Agent Interlock homepage area. The product UI's pixels and strings were not regenerated; they were placed on a neutral-background 1600×900 documentation canvas while preserving the original aspect ratio.

## 1. Design and security contracts

### Empty Trust Zone

![Trust Zone before adding actors](images/agent-interlock-e2e/01-empty-zones-1600x900.png)

### Security Graph with actors and boundaries connected

![Design Graph connecting security relationships and Trust Boundaries](images/agent-interlock-e2e/07-security-graph-1600x900.png)

### Task Workflow flowing from A2A to MCP

![A2A and MCP task workflow](images/agent-interlock-e2e/08-workflow-graph-1600x900.png)

## 2. Deployment and execution

### ENFORCE promotion via two-person approval

![Deploy screen promoting a signed bundle to ENFORCE](images/agent-interlock-e2e/09-deployed-1600x900.png)

### Awaiting human approval before MCP execution

![MCP task awaiting-approval state](images/agent-interlock-e2e/10-run-waiting-approval-1600x900.png)

### Both tasks completed

![Run screen with completed A2A and MCP tasks](images/agent-interlock-e2e/11-run-completed-1600x900.png)

## 3. Runtime and Statistics

### Runtime reconciliation

![Runtime Graph showing 2 observed relationships and 0 bypasses](images/agent-interlock-e2e/12-runtime-conforms-1600x900.png)

### Execution evidence statistics

![Statistics screen showing 2 interactions, 2 execution attempts, and 2 successes](images/agent-interlock-e2e/13-statistics-1600x900.png)

## 4. Full capture list

| Order | Screen | File |
|---:|---|---|
| 1 | Empty Trust Zone | [01-empty-zones](images/agent-interlock-e2e/01-empty-zones-1600x900.png) |
| 2 | USER security contract | [02-user-configured](images/agent-interlock-e2e/02-user-configured-1600x900.png) |
| 3 | AGENT security contract | [03-agent-configured](images/agent-interlock-e2e/03-agent-configured-1600x900.png) |
| 4 | SUBAGENT security contract | [04-subagent-configured](images/agent-interlock-e2e/04-subagent-configured-1600x900.png) |
| 5 | TOOL security contract | [05-tool-configured](images/agent-interlock-e2e/05-tool-configured-1600x900.png) |
| 6 | EXTERNAL security contract | [06-external-configured](images/agent-interlock-e2e/06-external-configured-1600x900.png) |
| 7 | Security Graph | [07-security-graph](images/agent-interlock-e2e/07-security-graph-1600x900.png) |
| 8 | Task Workflow | [08-workflow-graph](images/agent-interlock-e2e/08-workflow-graph-1600x900.png) |
| 9 | ENFORCE deployment | [09-deployed](images/agent-interlock-e2e/09-deployed-1600x900.png) |
| 10 | Approval pending | [10-run-waiting-approval](images/agent-interlock-e2e/10-run-waiting-approval-1600x900.png) |
| 11 | Run completed | [11-run-completed](images/agent-interlock-e2e/11-run-completed-1600x900.png) |
| 12 | Runtime conforms | [12-runtime-conforms](images/agent-interlock-e2e/12-runtime-conforms-1600x900.png) |
| 13 | Statistics | [13-statistics](images/agent-interlock-e2e/13-statistics-1600x900.png) |

`Runtime conforms` means this trace has no undeclared relationships and no control bypass. This manual run invoked A2A `REL-06` and MCP `REL-05`, so Runtime observes two relationships. Design relationships that were not executed, such as USER ingress and External egress, remain as separate informational entries.
