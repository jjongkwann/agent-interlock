# Agent Interlock Security Architecture Studio

> English version: [README.md](README.md)

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

빌드 의존성 `braces`는 [upstream PR #78](https://github.com/micromatch/braces/pull/78)의 `97308a01d091b211cf015314a2d0696da28a5392` 커밋으로 고정하며, tarball 무결성 값은 `package-lock.json`에 기록합니다. 검토한 패치는 파서와 AST 순회 깊이를 제한해 [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)을 수정합니다. 아직 공식 배포 버전은 아닙니다. 테스트는 실제 설치된 패키지의 깊은 패턴·직접 AST 입력과 일반 glob 동작을 확인합니다. 패키지 이름과 버전은 그대로이므로 버전 기반 검사기는 `3.0.3`을 계속 탐지할 수 있습니다. 공식 수정 버전이 나오면 회귀 테스트를 유지하면서 이 고정을 대체합니다.

The `Runtime graph` and `Drift` tabs accept Interlock Ledger events or OTLP/HTTP JSON up to 5 MB. The `Statistics` tab aggregates raw Ledger events offline or reads the scoped statistics API. Imported files stay in the browser session.

## 화면 언어

상단의 English / 한국어 선택 메뉴에서 화면 언어를 변경할 수 있습니다. 처음에는 브라우저 언어를 따르며 선택한 언어는 이 브라우저에 저장됩니다. 프로젝트 데이터, 식별자, API 값, 내보낸 매니페스트의 값은 그대로 유지됩니다.

## Projects

The header carries the project id and version as editable fields, used by `Export manifest`. The `Projects` menu supports several projects in one browser: `New project` clears the canvas to an empty architecture with a fresh id; `Open manifest…` loads any Architecture manifest JSON produced by `Export manifest` or accepted by the Python compiler, laying out any node or task position it omits on a grid; `Save` stores the current graph under its project id in the browser's `localStorage`, and the saved-projects list opens or deletes those entries. All of it is undoable. Saved projects never leave the browser and are lost if its storage is cleared.

## Current boundary

Architecture edits remain local drafts. Use the root Python CLI to lint and compile an exported manifest before rollout:

```bash
PYTHONPATH=../src python3 -m agent_interlock architecture lint ./agent-interlock-architecture.json
PYTHONPATH=../src python3 -m agent_interlock architecture compile ./agent-interlock-architecture.json
```

The `Deploy` tab talks only to an explicitly configured Control Plane. Approval private keys never enter the browser or server: approvers sign with `interlock studio approve`, while the Control Plane verifies identity-bound Ed25519 signatures using public keys. Promotion and rollback both require two distinct approvers and two distinct public keys; rollback targets must have been active previously.
