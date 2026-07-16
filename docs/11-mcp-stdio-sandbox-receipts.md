---
title: MCP stdio Sandbox와 External Receipt
date: 2026-07-17
version: 1.2.0
status: active
---

# MCP stdio Sandbox와 External Receipt

이 문서는 로컬 MCP Server 프로세스를 시작하는 stdio transport의 보안 경계와, 실제 외부 전송 없이 부작용을 검증하는 fake external receipt 계약을 정의한다. 구현은 `src/agent_interlock/mcp_stdio.py`, `src/agent_interlock/receipts.py`와 `MCPToolGateway`의 contextual Connector 경계에 있다.

## 1. 보안 아키텍처

```text
┌────────────────────┐
│ Architecture REL-05│
│ MCP_GATEWAY        │
│ SANDBOX            │
└─────────┬──────────┘
          │ exact definition digest + artifact set digest
┌─────────▼──────────┐       ┌────────────────────────────┐
│ MCPTransportAdapter│──────>│ MCPStdioServerCaller       │
└────────────────────┘       └────────────┬───────────────┘
                                          │ same server/profile binding
                                ┌─────────▼──────────┐
                                │ MCPStdioClient     │
                                │ JSONL + lifecycle  │
                                │ size/timeout/kill  │
                                └─────────┬──────────┘
                                          │ verified launch plan
                                ┌─────────▼──────────┐
                                │ OS Sandbox Backend │
                                │ FS / network / PID │
                                └─────────┬──────────┘
                                          │ stdin/stdout
                                ┌─────────▼──────────┐
                                │ Local MCP Server   │
                                └────────────────────┘

┌────────────────────┐ contextual execution ┌────────────────────┐
│ MCPToolGateway     │──────────────────────>│ Fake External Sink │
└─────────┬──────────┘                       └─────────┬──────────┘
          │ decision/execution/argument binding        │ committed receipt
          └──────────────────────┬─────────────────────┘
                                 ▼
                         Reconciliation / REVOKE
```

Architecture 예제의 REL-05에는 `MCP_GATEWAY`와 `SANDBOX` PREVENT control이 함께 있다. Studio에서도 `SANDBOX` enforcement point와 `DECLARED`–`RECONCILED` assurance를 선택할 수 있다. 실제 stdio artifact set digest는 `MCPServerProfile.artifact_digest`와 `MCPStdioServerCaller`에서 일치해야 하므로, 박스에서 승인한 Tool definition과 실행 프로세스가 다른 artifact를 가리키면 adapter 생성 전에 실패한다.

REL-07의 source Tool, External 박스 `allowedDomains`와 LinkPolicy는 `compile_destination_egress_policy`로 tenant·workload·artifact·publisher provenance·sandbox profile에 결합된 exact HTTPS origin allowlist가 된다. `DestinationEgressGuard`는 비허용 origin을 backend 호출 전에 차단하고 workload 종료 결과와 socket count 0 receipt를 남긴다. 허용 경로만 backend receipt 1개를 반환한다.

## 2. stdio profile 통제

`StdioSandboxProfile`은 다음 값을 하나의 canonical profile digest로 결합한다.

| 영역 | 통제 |
|---|---|
| 실행 파일 | 절대 경로, regular file, SHA-256 pin, 시작 직전 재검증 |
| 추가 artifact | interpreter가 실행하는 script/config 등 기존 file argument의 digest pin 필수 |
| command | 문자열 shell이 아닌 고정 argv 배열, NUL/CR/LF와 크기 제한 |
| shell | `sh`, `bash`, `zsh`, PowerShell 등은 기본 거부, 별도 명시 승인 필요 |
| environment | 부모 env 미상속, 승인 mapping만 전달, loader/runtime injection 및 credential 계열 key 차단 |
| filesystem | read-only/writable path가 profile digest에 결합되고 backend attestation 필요 |
| network | 기본 deny, backend의 network isolation attestation 필요 |
| child process | 기본 deny, backend의 child-process isolation attestation 필요 |
| protocol | UTF-8 JSON-RPC object 한 개를 newline으로 구분, stdout noise와 batch 거부 |
| resource | request/response 크기, pending message, stderr 보관량 제한 |
| lifecycle | initialize → initialized 순서, timeout 시 자동 재시도 없이 process group 종료 |
| stderr | 계속 drain해 deadlock을 막고, 보관 범위 제한 및 secret redaction |

공식 stdio transport는 client가 subprocess를 시작하고 stdin/stdout으로 newline-delimited JSON-RPC를 교환하며, stdout에는 MCP message 외의 내용을 쓰지 못하게 한다. 구현은 이 계약을 위반한 stdout, 응답 ID 불일치, 미지원 server request를 발견하면 프로세스를 종료한다.

## 3. Sandbox attestation

`SandboxLaunchPlan`은 argv뿐 아니라 다음 `SandboxAttestation`을 반환해야 한다.

- backend ID와 evidence reference
- exact `profile_digest`
- exact `artifact_set_digest`
- filesystem restriction 집행 여부
- network restriction 집행 여부
- child-process restriction 집행 여부

기본 backend인 `DenyUnisolatedSandboxBackend`는 항상 fail closed한다. `AttestedExternalSandboxBackend`는 digest가 고정된 운영 launcher/container adapter를 연결하는 계약이며, 그 launcher 자체가 OS 격리를 실제로 집행해야 한다. 필요한 attestation bit가 하나라도 없으면 subprocess를 만들지 않는다.

`AttestationVerifier`는 backend별 신뢰 key로 canonical attestation 서명과 모든 restriction bit를 검증한다. `BubblewrapSandboxBackend`는 Linux에서 private root·mount와 network namespace를 구성하는 reference launch plan을 만들고 서명한다. 현재 계약은 seccomp FD를 전달하지 않으므로 child process 제한을 주장하지 않으며, `allow_child_processes=False` profile은 실행 전에 거부한다.

`DirectTestSandboxBackend`는 이름 그대로 시험 전용이다. `allow_unenforced_test_mode=True`가 profile digest에 명시된 경우에만 실행되며 attestation은 세 격리를 모두 `false`로 기록한다. 이 경로의 성공을 production sandbox 증거로 사용할 수 없다.

```python
sandbox_profile = StdioSandboxProfile(
    profile_id="approved-local-tool-v3",
    executable=StdioArtifactPin("/opt/interlock/bin/tool", "sha256:..."),
    additional_artifacts=(
        StdioArtifactPin("/opt/interlock/lib/tool-config.json", "sha256:..."),
    ),
    working_directory="/var/empty/interlock-tool",
    read_only_paths=("/opt/interlock/lib/tool-config.json",),
    writable_paths=("/var/empty/interlock-tool",),
    allow_network=False,
    allow_child_processes=False,
)

client = MCPStdioClient(
    MCPStdioClientConfig(sandbox_profile),
    sandbox_backend=approved_os_sandbox_backend,
)
server_profile = MCPServerProfile(
    tenant_id="tenant-a",
    server_id="tenant-a/prod/local-tool",
    endpoint="stdio://approved/local-tool",
    transport="stdio",
    artifact_digest=sandbox_profile.artifact_set_digest,
)
adapter = MCPTransportAdapter(
    gateway,
    server_profile,
    client.server_caller(server_profile),
)
```

## 4. Fake external receipt

`FakeExternalReceiptStore`는 실제 socket, email, payment 또는 외부 API를 호출하지 않는다. `FakeExternalSinkConnector`가 Gateway로부터 받은 `ConnectorExecutionContext`를 사용해 다음 증거만 append한다.

- tenant, decision, interaction, connector execution ID
- canonical arguments hash
- side effect와 canonical destination 전체
- byte/record count
- simulated transaction/receipt ID
- committed/compensated 상태

Gateway는 receipt summary의 decision, interaction, arguments hash, execution ID를 모두 대조한 뒤 `reconcile_transaction`을 실행한다. 허용되지 않은 목적지나 미선언 부작용이 이미 committed 상태라면 `PARTIALLY_EXECUTED`, `DETECTION_RAISED`, `REVOKE`를 기록한다. 정책이 실행 전에 차단되면 contextual Connector가 호출되지 않으므로 receipt 수는 0이다. 같은 idempotency key의 재호출은 동일 결과를 반환하며 transaction을 추가하지 않는다.

```python
store = FakeExternalReceiptStore()
connector = FakeExternalSinkConnector(
    store,
    side_effect=SideEffect.EXTERNAL_WRITE,
    destination_resolver=lambda arguments: (arguments["to"],),
    result_factory=lambda arguments, receipt: {"status": "simulated"},
)

result = gateway.invoke(..., connector=connector, idempotency_key="send-42")
outcome = gateway.reconcile_receipt_store(
    result.decision.decision_id,
    result.connector_execution_id,
    store,
)
```

## 5. 자동 검증

`tests/test_mcp_stdio.py`는 실제 subprocess를 사용해 다음을 검증한다.

- sandbox backend 누락 시 공격 process 시작 0
- executable/script digest mismatch 시 process 시작 0
- shell, runtime injection env, unpinned file argument 차단
- initialize/initialized, tools/list, tools/call JSONL
- 부모 environment 비상속과 stderr secret redaction
- stdout noise, oversized response, server request 차단
- timeout request 1회와 전체 process group 종료
- stdio artifact set과 Architecture/MCPServerProfile exact binding
- attestation 서명·wrong-key·tamper·미서명 거부와 client verifier 강제
- Bubblewrap argv·unsafe mount 거부·정직한 fs/network/child restriction bit

`tests/test_receipts.py`는 정상 receipt 1, 정책 차단 receipt 0, idempotent transaction 1, hidden egress의 `PARTIALLY_EXECUTED`/`REVOKE`, compensation과 cross-decision binding을 검증한다.

`tests/test_supply_chain.py`와 `tests/test_egress.py`는 publisher/repository/revision/build/artifact 서명, MCP profile admission, Architecture REL-07 compile, tenant/workload/artifact/provenance/sandbox binding, 차단 socket 0·종료와 정상 receipt 1을 검증한다. `InMemoryNetworkEgressBackend`는 실제 socket을 열지 않는 SIMULATION backend다.

기준 문서는 [MCP Transports 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)와 [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)다.

## 6. 남은 운영 경계

reference core에는 서명 attestation verifier와 Linux Bubblewrap launch-plan backend가 있다. 다만 현재 자동 검증은 argv와 증거 계약 수준이며 실제 Linux+bwrap process 격리를 CI에서 실행하지 않는다. 운영 완료를 위해서는 Bubblewrap live 시험 또는 다음 중 하나가 같은 attestation 계약을 충족해야 한다.

- Linux user/mount/network namespace와 seccomp/cgroup 정책
- gVisor, Kata Containers 또는 hardened container runtime
- macOS App Sandbox처럼 platform에서 지원하는 격리 프로파일
- Kubernetes workload sandbox와 deny-by-default NetworkPolicy

추가로 seccomp 기반 child-process 강제, 실제 egress proxy/sidecar와 DNS·연결 IP pinning, immutable artifact mount/FD execution으로 digest 검사와 exec 사이 TOCTOU 제거, macOS backend, 장기 process supervisor와 운영 sandbox health telemetry가 필요하다. reference의 publisher/attestation symmetric key는 운영에서 Sigstore 또는 KMS/HSM 발급·회전·폐기 체계로 교체해야 한다.
