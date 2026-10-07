"""Run Control Plane: the privileged deployment command API.

Studio stays a static SPA; anything that needs credentials — proposing a
bundle, collecting approvals, promoting SHADOW→ENFORCE, rolling back — goes
through this server, which holds trusted Ed25519 public keys and the git bundle
store. Approvers sign in their browser or CLI with their own keys; the server
only verifies signatures and never receives private signing keys. The server alone
therefore cannot forge a two-person promotion.

Pending signed approvals persist in the bundle repository metadata and survive
a host restart. They are verified again against the current deployment before promotion.
Approval statements bind the CURRENT
active digest (``fromDigest``), so approvals signed before an intervening
deploy fail verification rather than promote against a stale base.
"""

from __future__ import annotations

import json
import re
import threading
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import unquote, urlsplit

from .architecture import ArchitectureGraph
from .configurable_runtime import runtime_status
from .ledger_http import (
    LedgerAPIAuthenticator,
    LedgerAPIError,
    _single_header,
)
from .project_store import ProjectConflict, SQLiteProjectStore
from .run_control import RunControlError, RunControlService
from .studio_deploy import (
    DeploymentApproval,
    DeploymentBundle,
    GitBundleStore,
    StudioDeploymentError,
    TrustedApprovalKey,
    _write_json,
    compile_review_bundle,
    verify_deployment_approval,
)

SCOPE_READ = "deploy:read"
SCOPE_PROPOSE = "deploy:propose"
SCOPE_APPROVE = "deploy:approve"
SCOPE_PROMOTE = "deploy:promote"
SCOPE_RUN_CREATE = "run:create"
SCOPE_RUN_READ = "run:read"
SCOPE_RUN_APPROVE = "run:approve"
SCOPE_RUN_CANCEL = "run:cancel"

_ERROR_STATUS = {
    "L1-STUDIO-TWO-PERSON-APPROVAL-REQUIRED": 422,
    "L1-STUDIO-APPROVAL-SIGNATURE-INVALID": 422,
    "L1-STUDIO-BUNDLE-UNKNOWN": 404,
    "L1-STUDIO-BUNDLE-DIGEST-MISMATCH": 422,
    "L1-STUDIO-ROLLBACK-TARGET-NOT-ACTIVE": 422,
}


_LOOPBACK_ORIGIN = re.compile(r"^http://(localhost|127\.0\.0\.1)(:\d{1,5})?$")
_RUN_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


@dataclass(frozen=True, slots=True)
class ControlPlaneConfig:
    max_request_bytes: int = 1024 * 1024
    request_timeout_seconds: float = 5.0
    allowed_origins: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not 1 <= self.max_request_bytes <= 5 * 1024 * 1024:
            raise ValueError("max_request_bytes must be between 1 byte and 5 MiB")
        if not 0.1 <= self.request_timeout_seconds <= 30:
            raise ValueError("request_timeout_seconds must be between 0.1 and 30")
        if any(
            not (value.startswith("https://") or _LOOPBACK_ORIGIN.fullmatch(value)) for value in self.allowed_origins
        ):
            raise ValueError("allowed browser origins must use https (loopback http is allowed for development)")


class ControlPlaneAPI:
    """HTTP application over one GitBundleStore with scope enforcement."""

    def __init__(
        self,
        store: GitBundleStore,
        authenticator: LedgerAPIAuthenticator,
        *,
        trusted_approvers: Mapping[str, TrustedApprovalKey],
        run_service: RunControlService | None = None,
        config: ControlPlaneConfig | None = None,
        runtime_credentials: Mapping[str, str] | None = None,
        credential_env: Mapping[str, str] | None = None,
        project_store: SQLiteProjectStore | None = None,
        project_permissions: Mapping[str, Mapping[str, frozenset[str]]] | None = None,
    ) -> None:
        self.store = store
        self.authenticator = authenticator
        self.trusted_approvers = dict(trusted_approvers)
        self.run_service = run_service
        self.config = config or ControlPlaneConfig()
        self.configurable_runtime = runtime_credentials is not None
        self.credential_refs = frozenset(runtime_credentials or ())
        self.credential_env = dict(credential_env or {})
        self.project_store = project_store
        self.project_permissions = ({subject: {project: frozenset(grants) for project, grants in projects.items()}
                                     for subject, projects in project_permissions.items()}
                                    if project_permissions is not None else None)
        path = self.store.approval_path()
        saved = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        if not isinstance(saved, dict):
            raise ValueError("pending approvals must be a JSON object")
        if "version" in saved:
            if type(saved["version"]) is not int or saved["version"] != 2:
                raise ValueError("unsupported pending approval storage version")
            if (set(saved) != {"version", "targetId", "tenantId", "approvals"}
                    or not isinstance(saved["approvals"], dict)):
                raise ValueError("invalid pending approval storage")
            if saved.get("targetId") != store.target_id or saved.get("tenantId") != store.tenant_id:
                raise ValueError("pending approvals belong to a different deployment target or tenant")
            saved = saved["approvals"]
        elif saved:
            if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or not isinstance(entries, list)
                   for digest, entries in saved.items()):
                raise ValueError("invalid legacy pending approval storage")
            # Preserve old signatures for audit, but require signing the new target-bound statement.
            path.replace(path.with_name(f"interlock-legacy-approvals-{uuid.uuid4().hex}.json"))
            saved = {}
        self._approvals = {
            digest: {(item["approver_id"], item["key_id"]): DeploymentApproval(**item) for item in entries}
            for digest, entries in saved.items()
        }
        self._lock = threading.RLock()
        self._save_approvals()

    def handle(self, handler: BaseHTTPRequestHandler) -> None:
        try:
            self._check_origin(handler)
            if handler.command == "OPTIONS":
                self._send_preflight(handler)
                return
            principal = self._authenticate(handler)
            parts = urlsplit(handler.path)
            if parts.query:
                raise LedgerAPIError(400, "CONTROL-QUERY-UNEXPECTED", "query parameters are not allowed")
            segments = [unquote(item, errors="strict") for item in parts.path.split("/") if item]
            if handler.command == "POST" and len(segments) == 3 and segments[:2] == ["v1", "workers"]:
                self._require_scope(principal, "worker:execute")
                dispatcher = self._require_run_service().dispatcher
                if dispatcher is None:
                    raise LedgerAPIError(503, "WORKER-DISPATCH-DISABLED", "remote dispatch is not enabled")
                result = dispatcher.api(principal, segments[2], self._read_json(handler))
                self._send_json(handler, 200, result)
                return
            if handler.command == "GET" and segments == ["v1", "runtime", "status"]:
                self._require_scope(principal, SCOPE_READ)
                with self._lock:
                    active = self.store.active()
                    if active and not self._can_bundle(principal, active["bundleDigest"], "read"):
                        active = None
                    manifest = self.store.bundle(active["bundleDigest"]).body.get("architecture") if active else None
                    readiness = self._runtime_readiness(ArchitectureGraph.from_dict(manifest)) if manifest else None
                self._send_json(
                    handler,
                    200,
                    {
                        "tenantId": self.store.tenant_id,
                        "targetId": self.store.target_id,
                        "capabilities": {"candidateComparison": "LOCAL_JSON_ONLY",
                                         "scheduler": "REMOTE_WORKERS"
                                         if self.run_service and self.run_service.dispatcher
                                         else "SINGLE_HOST",
                                         "sharedProjects": self.project_store is not None},
                        "distributed": self.run_service.dispatcher.status(principal.tenant_id)
                        if self.run_service and self.run_service.dispatcher
                        and self._can_project(principal, "*", "read") else None,
                        "storage": {
                            "runs": type(self.run_service.run_store).__name__ if self.run_service else None,
                            "ledger": type(self.run_service.ledger).__name__ if self.run_service else None,
                        },
                        "credentialRefs": sorted(self.credential_refs),
                        "credentialSetup": [
                            {"reference": ref, "environmentVariable": name, "loaded": ref in self.credential_refs}
                            for ref, name in sorted(self.credential_env.items())
                        ],
                        "trustedApprovers": self._public_approvers(),
                        "active": active,
                        "architecture": manifest,
                        "runtimeReadiness": readiness,
                    },
                )
                return
            if segments[:2] == ["v1", "projects"] and len(segments) in {2, 3}:
                if self.project_store is None:
                    raise LedgerAPIError(503, "PROJECT-STORE-UNAVAILABLE", "shared project storage is not configured")
                if handler.command == "GET":
                    self._require_scope(principal, "project:read")
                    if len(segments) == 2:
                        projects = [project for project in self.project_store.list(principal.tenant_id)
                                    if self._can_project(principal, project["id"], "read")]
                        self._send_json(handler, 200, {"projects": projects})
                    else:
                        self._require_project(principal, segments[2], "read")
                        project = self.project_store.get(principal.tenant_id, segments[2])
                        if project is None:
                            raise LedgerAPIError(404, "PROJECT-NOT-FOUND", "project not found")
                        self._send_json(handler, 200, {"project": project})
                    return
                if handler.command == "POST" and len(segments) == 3:
                    self._require_scope(principal, "project:write")
                    self._require_project(principal, segments[2], "write")
                    value = self._read_json(handler)
                    if set(value) != {"targetId", "revision", "manifest"}:
                        raise LedgerAPIError(400, "PROJECT-REQUEST-INVALID",
                                             "targetId, revision and manifest are required")
                    if value["targetId"] != self.store.target_id:
                        raise LedgerAPIError(409, "PROJECT-TARGET-CHANGED", "refresh the connected host before saving")
                    project = self.project_store.save(principal.tenant_id, segments[2], value["manifest"],
                                                      value["revision"], principal.subject)
                    self._send_json(handler, 200, {"project": project})
                    return
            if handler.command == "POST" and segments in (
                ["v1", "architectures", "compile"],
                ["v1", "runtime", "validate"],
            ):
                compiling = segments[1] == "architectures"
                self._require_scope(principal, SCOPE_PROPOSE if compiling else SCOPE_READ)
                manifest = self._read_json(handler)
                if not isinstance(manifest, Mapping):
                    raise LedgerAPIError(400, "CONTROL-REQUEST-INVALID", "Architecture must be a JSON object")
                graph = ArchitectureGraph.from_dict(manifest)
                self._require_project(principal, graph.id, "deploy" if compiling else "read")
                readiness = self._runtime_readiness(graph)
                if compiling:
                    try:
                        result = compile_review_bundle(graph)
                    except (ValueError, TypeError) as error:
                        result = {
                            "architectureId": graph.id,
                            "version": graph.version,
                            "deployable": False,
                            "findings": [
                                {"code": "RUNTIME-CONFIGURATION-INVALID", "severity": "CRITICAL", "message": str(error)}
                            ],
                        }
                    result = {
                        **result,
                        "rawBundle": json.dumps(result, ensure_ascii=False),
                        "runtimeReadiness": readiness,
                    }
                else:
                    result = readiness
                self._send_json(handler, 200, result)
                return
            if handler.command == "GET" and segments == ["v1", "runs"]:
                self._require_scope(principal, SCOPE_RUN_READ)
                service = self._require_run_service()
                runs = [run for run in service.list(tenant_id=principal.tenant_id)
                        if self._can_bundle(principal, run.get("bundleDigest"), "read")]
                self._send_json(handler, 200, {"runs": runs})
                return
            if handler.command == "POST" and segments == ["v1", "runs"]:
                self._require_scope(principal, SCOPE_RUN_CREATE)
                service = self._require_run_service()
                value = self._read_json(handler)
                if not isinstance(value, Mapping):
                    raise LedgerAPIError(400, "RUN-REQUEST-INVALID", "request must be a JSON object")
                workflow_input = value.get("input", {})
                run_id = value.get("runId")
                trace_id = value.get("traceId")
                if trace_id is not None and not self._can_project(principal, "*", "read"):
                    raise LedgerAPIError(403, "PROJECT-TRACE-ID-RESTRICTED",
                                         "project-scoped runs require a server-generated trace ID")
                if run_id is not None and (not isinstance(run_id, str) or not _RUN_IDENTIFIER.fullmatch(run_id)):
                    raise LedgerAPIError(
                        400,
                        "RUN-ID-INVALID",
                        "runId must be a safe identifier of at most 128 characters",
                    )
                if trace_id is not None and (not isinstance(trace_id, str) or not _RUN_IDENTIFIER.fullmatch(trace_id)):
                    raise LedgerAPIError(
                        400,
                        "RUN-TRACE-ID-INVALID",
                        "traceId must be a safe identifier of at most 128 characters",
                    )
                with self._lock:
                    self._require_active_project(principal, "deploy")
                    self._require_active_project(principal, "read")
                    run = service.create(
                        tenant_id=principal.tenant_id,
                        workflow_input=workflow_input,
                        run_id=run_id,
                        trace_id=trace_id,
                    )
                self._send_json(handler, 202, {"run": run})
                return
            if handler.command == "POST" and segments == ["v1", "runs", "prune"]:
                self._require_scope(principal, "run:prune")
                self._require_project(principal, "*", "deploy")
                value = self._read_json(handler)
                if set(value) != {"before"} or not isinstance(value["before"], str):
                    raise LedgerAPIError(400, "RUN-RETENTION-INVALID", "before timestamp is required")
                removed = self._require_run_service().prune(tenant_id=principal.tenant_id, before=value["before"])
                self._send_json(handler, 200, {"removed": removed})
                return
            if handler.command == "GET" and len(segments) == 3 and segments[:2] == ["v1", "runs"]:
                self._require_scope(principal, SCOPE_RUN_READ)
                service = self._require_run_service()
                run = self._require_run_project(principal, segments[2], "read")
                self._send_json(handler, 200, {"run": run})
                return
            if (
                handler.command == "POST"
                and len(segments) == 4
                and segments[:2] == ["v1", "bundles"]
                and segments[3] == "compare"
            ):
                from .candidate_compare import compare_bundles

                self._require_scope(principal, SCOPE_PROPOSE)
                value = self._read_json(handler)
                if set(value) != {"input", "baseDigest"}:
                    raise LedgerAPIError(400, "COMPARISON-REQUEST-INVALID", "input and baseDigest are required")
                with self._lock:
                    active = self.store.active()
                    self._require_bundle_project(principal, segments[2], "deploy")
                    self._require_bundle_project(principal, segments[2], "read")
                    self._require_active_project(principal, "read")
                    base = active["bundleDigest"] if active else None
                    if value["baseDigest"] != base:
                        raise LedgerAPIError(409, "COMPARISON-BASE-CHANGED",
                                             "refresh the active deployment before comparing")
                    candidate = self.store.bundle(segments[2])
                    baseline = self.store.bundle(base) if base else None
                try:
                    result = compare_bundles(candidate, baseline, value["input"], self.store.tenant_id)
                except ValueError as error:
                    raise LedgerAPIError(422, "COMPARISON-UNSUPPORTED", str(error)) from error
                self._send_json(handler, 200, {**result, "targetId": self.store.target_id,
                                              "tenantId": self.store.tenant_id})
                return
            if (
                handler.command == "GET"
                and len(segments) == 4
                and segments[:2] == ["v1", "runs"]
                and segments[3] == "events"
            ):
                self._require_scope(principal, SCOPE_RUN_READ)
                service = self._require_run_service()
                self._require_run_project(principal, segments[2], "read")
                self._send_json(
                    handler,
                    200,
                    {"events": list(service.events(tenant_id=principal.tenant_id, run_id=segments[2]))},
                )
                return
            if (
                handler.command == "POST"
                and len(segments) == 4
                and segments[:2] == ["v1", "runs"]
                and segments[3] == "resume"
            ):
                self._require_scope(principal, SCOPE_RUN_CREATE)
                service = self._require_run_service()
                self._require_run_project(principal, segments[2], "deploy")
                self._read_empty_json(handler)
                run = service.resume(tenant_id=principal.tenant_id, run_id=segments[2])
                self._send_json(handler, 202, {"run": run})
                return
            if (
                handler.command == "POST"
                and len(segments) == 4
                and segments[:2] == ["v1", "runs"]
                and segments[3] == "cancel"
            ):
                self._require_scope(principal, SCOPE_RUN_CANCEL)
                service = self._require_run_service()
                self._require_run_project(principal, segments[2], "deploy")
                self._read_empty_json(handler)
                run = service.cancel(tenant_id=principal.tenant_id, run_id=segments[2])
                self._send_json(handler, 200, {"run": run})
                return
            if (
                handler.command == "POST"
                and len(segments) == 6
                and segments[:2] == ["v1", "runs"]
                and segments[3] == "tasks"
                and segments[5] == "approve"
            ):
                self._require_scope(principal, SCOPE_RUN_APPROVE)
                service = self._require_run_service()
                self._require_run_project(principal, segments[2], "deploy")
                value = self._read_json(handler)
                if (
                    not isinstance(value, Mapping)
                    or set(value) - {"requestId"}
                    or ("requestId" in value and not isinstance(value["requestId"], str))
                ):
                    raise LedgerAPIError(
                        400, "RUN-REQUEST-INVALID", "only an optional invocation requestId is accepted"
                    )
                run = service.approve(
                    tenant_id=principal.tenant_id,
                    run_id=segments[2],
                    task_id=segments[4],
                    approved_by=principal.subject,
                    request_id=value.get("requestId"),
                )
                self._send_json(handler, 202, {"run": run})
                return
            if handler.command == "GET" and segments == ["v1", "deploy", "status"]:
                self._require_scope(principal, SCOPE_READ)
                with self._lock:
                    active = self.store.active()
                    if active and not self._can_bundle(principal, active["bundleDigest"], "read"):
                        active = None
                    status = {"active": active, "history": list(self.store.history())
                              if self._can_project(principal, "*", "read") else []}
                self._send_json(handler, 200, status)
                return
            if handler.command == "POST" and segments == ["v1", "bundles"]:
                self._require_scope(principal, SCOPE_PROPOSE)
                bundle = DeploymentBundle.from_compile_output(self._read_json(handler))
                self._require_project(principal, self._bundle_project_id(bundle), "deploy")
                with self._lock:
                    commit = self.store.propose(bundle)
                self._send_json(handler, 201, {"bundleDigest": bundle.bundle_digest, "commit": commit})
                return
            if (
                handler.command == "GET"
                and len(segments) == 4
                and segments[:2] == ["v1", "bundles"]
                and segments[3] == "diff"
            ):
                self._require_scope(principal, SCOPE_READ)
                with self._lock:
                    self._require_bundle_project(principal, segments[2], "read")
                    self._require_active_project(principal, "read")
                    difference = self.store.diff(segments[2])
                self._send_json(handler, 200, difference)
                return
            if (
                handler.command == "GET"
                and len(segments) == 4
                and segments[:2] == ["v1", "bundles"]
                and segments[3] == "approval-context"
            ):
                self._require_scope(principal, SCOPE_READ)
                with self._lock:
                    self._require_bundle_project(principal, segments[2], "read")
                    self._require_active_project(principal, "read")
                    bundle = self.store.bundle(segments[2])
                    active = self.store.active()
                    result = {
                        "statement": self.store.approval_statement(
                            bundle, from_digest=active["bundleDigest"] if active else None, to_mode="ENFORCE"
                        ),
                        "trustedApprovers": self._public_approvers(),
                        "runtimeReadiness": self._runtime_readiness(
                            ArchitectureGraph.from_dict(bundle.body["architecture"])
                        ),
                    }
                self._send_json(handler, 200, result)
                return
            if (
                handler.command == "POST"
                and len(segments) == 4
                and segments[:2] == ["v1", "bundles"]
                and segments[3] == "approvals"
            ):
                self._require_scope(principal, SCOPE_APPROVE)
                self._submit_approval(handler, segments[2], principal)
                return
            if (
                handler.command == "POST"
                and len(segments) == 4
                and segments[:2] == ["v1", "bundles"]
                and segments[3] == "promote"
            ):
                self._require_scope(principal, SCOPE_PROMOTE)
                self._promote(handler, segments[2], principal)
                return
            if handler.command == "POST" and segments == ["v1", "deploy", "rollback"]:
                self._require_scope(principal, SCOPE_PROMOTE)
                value = self._read_json(handler)
                target = value.get("targetDigest")
                if not isinstance(target, str) or not target:
                    raise LedgerAPIError(400, "CONTROL-TARGET-REQUIRED", "targetDigest is required")
                with self._lock:
                    self._require_bundle_project(principal, target, "deploy")
                    self._require_active_project(principal, "deploy")
                    self._require_runtime_ready(target)
                    approvals = tuple(self._approvals.get(target, {}).values())
                    commit = self.store.rollback(
                        target,
                        approvals,
                        trusted_approvers=self.trusted_approvers,
                    )
                    self._approvals.pop(target, None)
                    self._save_approvals()
                    active = self.store.active()
                self._send_json(handler, 200, {"active": active, "commit": commit})
                return
            raise LedgerAPIError(404, "CONTROL-ROUTE-NOT-FOUND", "route not found")
        except ProjectConflict as error:
            self._send_json(handler, 409, {"error": {"code": "PROJECT-REVISION-CONFLICT", "message": str(error)}},
                            close=True)
        except StudioDeploymentError as error:
            status = _ERROR_STATUS.get(error.reason_code, 422)
            self._send_json(handler, status, {"error": {"code": error.reason_code, "message": str(error)}}, close=True)
        except RunControlError as error:
            self._send_json(
                handler,
                error.status,
                {"error": {"code": error.code, "message": error.message}},
                close=True,
            )
        except LedgerAPIError as error:
            self._send_json(
                handler,
                error.status,
                {"error": {"code": error.code, "message": error.message}},
                close=True,
            )
        except (ValueError, UnicodeError, json.JSONDecodeError):
            self._send_json(
                handler,
                400,
                {"error": {"code": "CONTROL-REQUEST-INVALID", "message": "request is invalid"}},
                close=True,
            )
        except Exception:
            self._send_json(
                handler,
                500,
                {"error": {"code": "CONTROL-INTERNAL-ERROR", "message": "internal server error"}},
                close=True,
            )

    def _submit_approval(self, handler: BaseHTTPRequestHandler, digest: str, principal: Any) -> None:
        value = self._read_json(handler)
        approver = value.get("approverId")
        key_id = value.get("keyId")
        signature = value.get("signature")
        if not all(isinstance(item, str) and item for item in (approver, key_id, signature)):
            raise LedgerAPIError(400, "CONTROL-APPROVAL-INVALID", "approverId, keyId, and signature are required")
        with self._lock:
            self._require_bundle_project(principal, digest, "deploy")
            self._require_active_project(principal, "read")
            bundle = self.store.bundle(digest)
            active = self.store.active()
            statement = self.store.approval_statement(
                bundle,
                from_digest=active["bundleDigest"] if active else None,
                to_mode="ENFORCE",
            )
            approval = DeploymentApproval(approver, key_id, signature)
            verify_deployment_approval(statement, approval, self.trusted_approvers)
            pending = self._approvals.setdefault(digest, {})
            pending[(approver, key_id)] = approval
            self._save_approvals()
            count = len(pending)
        self._send_json(handler, 202, {"bundleDigest": digest, "pendingApprovals": count})

    def _save_approvals(self) -> None:
        _write_json(
            self.store.approval_path(),
            {"version": 2, "targetId": self.store.target_id, "tenantId": self.store.tenant_id, "approvals": {
                digest: [
                    {"approver_id": item.approver_id, "key_id": item.key_id, "signature": item.signature}
                    for item in approvals.values()
                ]
                for digest, approvals in self._approvals.items()
            }},
        )

    def _public_approvers(self) -> list[dict[str, str]]:
        return [
            {"keyId": key_id, "approverId": key.approver_id, "publicKeyHex": key.public_key.hex()}
            for key_id, key in sorted(self.trusted_approvers.items())
        ]

    def _runtime_readiness(self, graph: ArchitectureGraph) -> dict[str, Any]:
        if self.run_service is not None and self.run_service.dispatcher is not None:
            return {**self.run_service.dispatcher.readiness(graph), "hostConfigured": True}
        result = runtime_status(graph, self.credential_refs)
        if not self.configurable_runtime:
            coordinator = graph.node_map.get(graph.orchestration.coordinator_actor_id) if graph.orchestration else None
            result = {
                **result,
                "ready": None,
                "runInputSchema": dict(coordinator.actor.input_schema) if coordinator else {},
            }
        return {**result, "hostConfigured": self.configurable_runtime}

    def _require_runtime_ready(self, digest: str) -> None:
        if self.configurable_runtime:
            graph = ArchitectureGraph.from_dict(self.store.bundle(digest).body["architecture"])
            if not self._runtime_readiness(graph).get("ready", False):
                raise LedgerAPIError(
                    422,
                    "RUNTIME-NOT-READY",
                    "runtime configuration is incomplete; validate the architecture before deployment",
                )

    def _promote(self, handler: BaseHTTPRequestHandler, digest: str, principal: Any) -> None:
        content_length = _single_header(handler, "Content-Length", required=False)
        if content_length and content_length != "0":
            self._read_json(handler)  # accept and ignore an empty JSON body
        with self._lock:
            self._require_bundle_project(principal, digest, "deploy")
            self._require_active_project(principal, "deploy")
            self._require_runtime_ready(digest)
            approvals = tuple(self._approvals.get(digest, {}).values())
            commit = self.store.promote(
                digest,
                approvals,
                trusted_approvers=self.trusted_approvers,
            )
            self._approvals.pop(digest, None)
            self._save_approvals()
            active = self.store.active()
        self._send_json(handler, 200, {"active": active, "commit": commit})

    def _require_run_service(self) -> RunControlService:
        if self.run_service is None:
            raise RunControlError(503, "RUN-SERVICE-UNAVAILABLE", "run control is not configured")
        return self.run_service

    def _can_project(self, principal: Any, project_id: str, permission: str) -> bool:
        if self.project_permissions is None:
            return True
        grants = self.project_permissions.get(principal.subject, {})
        return permission in grants.get(project_id, ()) or permission in grants.get("*", ())

    def _require_project(self, principal: Any, project_id: str, permission: str) -> None:
        if not self._can_project(principal, project_id, permission):
            raise LedgerAPIError(403, "PROJECT-ACCESS-DENIED", "project permission is not authorized")

    def _can_bundle(self, principal: Any, digest: str | None, permission: str) -> bool:
        if self.project_permissions is None:
            return True
        return bool(digest) and self._can_project(principal, self._bundle_project_id(self.store.bundle(digest)),
                                                 permission)

    @staticmethod
    def _bundle_project_id(bundle: DeploymentBundle) -> str:
        architecture = bundle.body.get("architecture")
        if architecture is not None and ArchitectureGraph.from_dict(architecture).id != bundle.architecture_id:
            raise LedgerAPIError(400, "PROJECT-BUNDLE-ID-MISMATCH", "bundle and manifest project IDs must match")
        return bundle.architecture_id

    def _require_bundle_project(self, principal: Any, digest: str, permission: str) -> None:
        if not self._can_bundle(principal, digest, permission):
            raise LedgerAPIError(403, "PROJECT-ACCESS-DENIED", "project permission is not authorized")

    def _require_active_project(self, principal: Any, permission: str) -> None:
        active = self.store.active()
        if active:
            self._require_bundle_project(principal, active["bundleDigest"], permission)

    def _require_run_project(self, principal: Any, run_id: str, permission: str) -> dict[str, Any]:
        run = self._require_run_service().get(tenant_id=principal.tenant_id, run_id=run_id)
        self._require_bundle_project(principal, run.get("bundleDigest"), permission)
        self._require_bundle_project(principal, run.get("bundleDigest"), "read")
        return run

    def _read_empty_json(self, handler: BaseHTTPRequestHandler) -> None:
        value = self._read_json(handler)
        if not isinstance(value, Mapping) or value:
            raise LedgerAPIError(400, "RUN-REQUEST-INVALID", "request body must be an empty JSON object")

    def _authenticate(self, handler: BaseHTTPRequestHandler):
        value = _single_header(handler, "Authorization", required=True, unauthorized=True)
        parts = value.split(" ", 1)
        if len(parts) != 2 or parts[0].casefold() != "bearer" or not parts[1]:
            raise LedgerAPIError(401, "CONTROL-AUTH-INVALID", "bearer authentication required")
        principal = self.authenticator.authenticate(parts[1])
        if principal is None:
            raise LedgerAPIError(401, "CONTROL-AUTH-INVALID", "bearer authentication required")
        if principal.tenant_id != self.store.tenant_id:
            raise LedgerAPIError(403, "CONTROL-TENANT-DENIED", "principal does not belong to this deployment tenant")
        return principal

    def _check_origin(self, handler: BaseHTTPRequestHandler) -> None:
        origins = handler.headers.get_all("Origin", failobj=[])
        if len(origins) > 1 or (origins and origins[0] not in self.config.allowed_origins):
            raise LedgerAPIError(403, "CONTROL-ORIGIN-DENIED", "browser origin is not authorized")

    def _cors_headers(self, handler: BaseHTTPRequestHandler) -> list[tuple[str, str]]:
        origin = handler.headers.get("Origin")
        if origin and origin in self.config.allowed_origins:
            return [("Access-Control-Allow-Origin", origin), ("Vary", "Origin")]
        return []

    def _send_preflight(self, handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(204)
        for name, value in self._cors_headers(handler):
            handler.send_header(name, value)
            if name == "Access-Control-Allow-Origin":
                handler.send_header("Access-Control-Allow-Methods", "GET, POST")
                handler.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                handler.send_header("Access-Control-Max-Age", "600")
        handler.end_headers()

    @staticmethod
    def _require_scope(principal: Any, required: str) -> None:
        if required not in principal.scopes:
            raise LedgerAPIError(403, "CONTROL-SCOPE-DENIED", "scope is not authorized")

    def _read_json(self, handler: BaseHTTPRequestHandler) -> Any:
        content_type = _single_header(handler, "Content-Type", required=True)
        if content_type.split(";", 1)[0].strip().casefold() != "application/json":
            raise LedgerAPIError(415, "CONTROL-CONTENT-TYPE-INVALID", "application/json is required")
        length_value = _single_header(handler, "Content-Length", required=True)
        if not length_value.isascii() or not length_value.isdigit():
            raise LedgerAPIError(400, "CONTROL-CONTENT-LENGTH-INVALID", "Content-Length is invalid")
        length = int(length_value)
        if not 1 <= length <= self.config.max_request_bytes:
            raise LedgerAPIError(413, "CONTROL-BODY-TOO-LARGE", "request body is too large")
        raw = handler.rfile.read(length)
        if len(raw) != length:
            raise LedgerAPIError(400, "CONTROL-BODY-INCOMPLETE", "request body is incomplete")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise LedgerAPIError(400, "CONTROL-REQUEST-INVALID", "request must be a JSON object")
        return value

    def _send_json(
        self,
        handler: BaseHTTPRequestHandler,
        status: int,
        value: Mapping[str, Any],
        *,
        close: bool = False,
    ) -> None:
        body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        for name, header_value in self._cors_headers(handler):
            handler.send_header(name, header_value)
        if close:
            handler.send_header("Connection", "close")
            handler.close_connection = True
        handler.end_headers()
        handler.wfile.write(body)


class _ControlPlaneServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], api: ControlPlaneAPI):
        super().__init__(server_address, _ControlPlaneRequestHandler)
        self.api = api


class _ControlPlaneRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.api.config.request_timeout_seconds)

    def do_POST(self) -> None:
        self.server.api.handle(self)

    def do_GET(self) -> None:
        self.server.api.handle(self)

    def do_OPTIONS(self) -> None:
        self.server.api.handle(self)

    def log_message(self, _format: str, *args: Any) -> None:
        return


def create_control_plane_server(
    api: ControlPlaneAPI,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
) -> _ControlPlaneServer:
    return _ControlPlaneServer((host, port), api)
