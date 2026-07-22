---
title: MCP stdio Sandbox and External Receipt
date: 2026-07-17
version: 1.2.0
status: active
---

# MCP stdio Sandbox and External Receipt

> 한국어 원문: [11-mcp-stdio-sandbox-receipts.ko.md](11-mcp-stdio-sandbox-receipts.ko.md)

This document defines the security boundary of the stdio transport that launches local MCP Server processes, and the fake external receipt contract that verifies side effects without any real external transmission. The implementation lives in `src/agent_interlock/mcp_stdio.py`, `src/agent_interlock/receipts.py`, and the contextual Connector boundary of `MCPToolGateway`.

## 1. Security Architecture

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

The REL-05 in the Architecture example carries the `MCP_GATEWAY` and `SANDBOX` PREVENT controls together. Studio also lets you select the `SANDBOX` enforcement point and `DECLARED`–`RECONCILED` assurance. The actual stdio artifact set digest must match between `MCPServerProfile.artifact_digest` and `MCPStdioServerCaller`, so if the Tool definition approved in the box and the executing process point to different artifacts, it fails before the adapter is created.

The source Tool of REL-07, the External box's `allowedDomains`, and the LinkPolicy become an exact HTTPS origin allowlist bound to tenant/workload/artifact/publisher provenance/sandbox profile via `compile_destination_egress_policy`. `DestinationEgressGuard` blocks disallowed origins before the backend call and leaves a receipt recording the workload's termination result and a socket count of 0. Only the allowed path returns a single backend receipt.

## 2. stdio Profile Controls

`StdioSandboxProfile` combines the following values into a single canonical profile digest.

| Area | Control |
|---|---|
| Executable | absolute path, regular file, SHA-256 pin, re-verified immediately before launch |
| Additional artifacts | digest pin required for existing file arguments such as scripts/configs executed by the interpreter |
| command | fixed argv array rather than a shell string, NUL/CR/LF and size limits |
| shell | `sh`, `bash`, `zsh`, PowerShell, etc. denied by default, requiring separate explicit approval |
| environment | parent env not inherited, only approved mapping passed through, loader/runtime injection and credential-class keys blocked |
| filesystem | read-only/writable paths bound to the profile digest, backend attestation required |
| network | deny by default, backend network isolation attestation required |
| child process | deny by default, backend child-process isolation attestation required |
| protocol | one UTF-8 JSON-RPC object delimited by newline, stdout noise and batches rejected |
| resource | request/response size, pending messages, and stderr retention limited |
| lifecycle | initialize → initialized order, process group terminated on timeout with no automatic retry |
| stderr | continuously drained to prevent deadlock, with limited retention scope and secret redaction |

In the official stdio transport, the client launches the subprocess and exchanges newline-delimited JSON-RPC over stdin/stdout, and stdout must contain nothing other than MCP messages. The implementation terminates the process when it detects stdout that violates this contract, a response ID mismatch, or an unsupported server request.

## 3. Sandbox Attestation

`SandboxLaunchPlan` must return the following `SandboxAttestation` in addition to argv.

- backend ID and evidence reference
- exact `profile_digest`
- exact `artifact_set_digest`
- whether filesystem restriction is enforced
- whether network restriction is enforced
- whether child-process restriction is enforced

The default backend, `DenyUnisolatedSandboxBackend`, always fails closed. `AttestedExternalSandboxBackend` is a contract for connecting a digest-pinned production launcher/container adapter, and that launcher itself must actually enforce OS isolation. If even one required attestation bit is missing, the subprocess is never created.

`AttestationVerifier` verifies the canonical attestation signature and every restriction bit using a per-backend trust key. `BubblewrapSandboxBackend` builds and signs a reference launch plan that configures a private root/mount and network namespace on Linux. Because the current contract does not pass a seccomp FD, it makes no claim about child-process restriction, and an `allow_child_processes=False` profile is rejected before execution.

`DirectTestSandboxBackend` is, as its name implies, test-only. It runs only when `allow_unenforced_test_mode=True` is declared in the profile digest, and its attestation records all three isolations as `false`. Success on this path cannot be used as evidence for a production sandbox.

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

## 4. Fake External Receipt

`FakeExternalReceiptStore` never calls a real socket, email, payment, or external API. `FakeExternalSinkConnector` uses the `ConnectorExecutionContext` it receives from the Gateway to append only the following evidence.

- tenant, decision, interaction, connector execution ID
- canonical arguments hash
- side effect and the full canonical destination
- byte/record count
- simulated transaction/receipt ID
- committed/compensated status

The Gateway cross-checks the decision, interaction, arguments hash, and execution ID in the receipt summary, then runs `reconcile_transaction`. If a disallowed destination or an undeclared side effect is already in the committed state, it records `PARTIALLY_EXECUTED`, `DETECTION_RAISED`, or `REVOKE`. If the policy blocks execution beforehand, the contextual Connector is never invoked, so the receipt count is 0. A repeat call with the same idempotency key returns the same result without adding a transaction.

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

## 5. Automated Verification

`tests/test_mcp_stdio.py` uses a real subprocess to verify the following.

- zero attack processes started when the sandbox backend is missing
- zero processes started on executable/script digest mismatch
- shell, runtime injection env, and unpinned file arguments blocked
- initialize/initialized, tools/list, tools/call JSONL
- parent environment not inherited, and stderr secret redaction
- stdout noise, oversized responses, and server requests blocked
- one timeout request and full process group termination
- exact binding between the stdio artifact set and Architecture/MCPServerProfile
- attestation signature, wrong-key, tamper, and unsigned rejection, with client verifier enforcement
- Bubblewrap argv, unsafe mount rejection, and honest fs/network/child restriction bits

`tests/test_receipts.py` verifies one receipt on the normal path, zero receipts on a policy block, one idempotent transaction, `PARTIALLY_EXECUTED`/`REVOKE` for hidden egress, and compensation and cross-decision binding.

`tests/test_supply_chain.py` and `tests/test_egress.py` verify publisher/repository/revision/build/artifact signatures, MCP profile admission, Architecture REL-07 compilation, tenant/workload/artifact/provenance/sandbox binding, zero blocked sockets with termination, and one normal receipt. `InMemoryNetworkEgressBackend` is a SIMULATION backend that never opens a real socket.

The reference documents are [MCP Transports 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports) and [MCP Security Best Practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices).

## 6. Remaining Operational Boundaries

The reference core includes a signature attestation verifier, a Linux Bubblewrap backend, and a macOS Seatbelt backend (`SeatbeltSandboxBackend`). When `seccomp_child_denial=True`, Bubblewrap attaches via `--seccomp` a classic-BPF filter built by `build_no_subprocess_seccomp` (fork/vfork and non-thread clone → EPERM; clone3 → ENOSYS so glibc falls back to clone and threads survive; thread clone allowed), honestly attesting the child-process restriction, while Seatbelt enforces the same restriction with `(deny process-fork)`. Seatbelt live-enforcement tests run on a macOS host, and Bubblewrap+seccomp live enforcement runs actual isolation in the `sandbox-live` job of `.github/workflows/ci.yml` (the seccomp BPF logic is verified with an in-test classic-BPF interpreter). DNS/connect-IP pinning for a real egress proxy/sidecar is provided by `egress.py`'s `PinnedSocketEgressBackend`.

The TOCTOU window between the artifact digest check and exec has been eliminated by executing via fd. `_open_verified_artifact` opens the pinned artifact once as an fd and verifies the digest on that fd, so the verified inode stays pinned for the lifetime of the fd; on hosts that support `/proc/self/fd` (Linux), the client executes that fd via `Popen(executable=)`, guaranteeing that the verified inode and the executed inode are identical (`argv[0]` keeps the real path — if the fd path leaked into the child's `sys.executable`, grandchild spawns would break). On hosts without `/proc/self/fd` (macOS), the fd-based atomic verification only removes the reopen gap, and execution still uses the path.

The long-running process supervisor and sandbox health telemetry are provided by `sandbox_supervisor.py`'s `SandboxSupervisor`. It performs liveness/health probes and bounded-backoff restarts; if a restarted process fails to re-attest the same sandbox (backend id/profile digest), it is treated as a supply-chain swap and rejected fail-closed, and it emits `CONTROL_HEALTH_CHANGED` (REL-11) on every state transition.

The following remain for production completeness.

- gVisor, Kata Containers, or a hardened container runtime; alternative Kubernetes workload-sandbox and deny-by-default NetworkPolicy backends
- operational wiring for socket handoff/block/kill telemetry on a real egress sidecar
- replacing the reference's publisher/attestation keys (HMAC/Ed25519 in-process) with a production Sigstore/Rekor or KMS/HSM issuance/rotation/revocation scheme
