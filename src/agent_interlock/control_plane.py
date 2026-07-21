"""Run Control Plane: the privileged deployment command API.

Studio stays a static SPA; anything that needs credentials — proposing a
bundle, collecting approvals, promoting SHADOW→ENFORCE, rolling back — goes
through this server, which holds trusted Ed25519 public keys and the git bundle
store. Approvers still sign OUTSIDE the server (CLI ``interlock studio
approve``) with their own keys; the server only verifies and executes, so no
private signing key ever reaches the server or browser. The server alone
therefore cannot forge a two-person promotion.

Pending approvals are held in memory keyed by bundle digest; a restart drops
them and approvers simply resubmit. Approval statements bind the CURRENT
active digest (``fromDigest``), so approvals signed before an intervening
deploy fail verification rather than promote against a stale base.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .ledger_http import (
    LedgerAPIAuthenticator,
    LedgerAPIError,
    _single_header,
)
from .run_control import RunControlError, RunControlService
from .studio_deploy import (
    DeploymentApproval,
    DeploymentBundle,
    GitBundleStore,
    StudioDeploymentError,
    TrustedApprovalKey,
    deployment_approval_statement,
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
    ) -> None:
        self.store = store
        self.authenticator = authenticator
        self.trusted_approvers = dict(trusted_approvers)
        self.run_service = run_service
        self.config = config or ControlPlaneConfig()
        self._approvals: dict[str, dict[tuple[str, str], DeploymentApproval]] = {}
        self._lock = threading.RLock()

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
            segments = [item for item in parts.path.split("/") if item]
            if handler.command == "GET" and segments == ["v1", "runs"]:
                self._require_scope(principal, SCOPE_RUN_READ)
                service = self._require_run_service()
                self._send_json(handler, 200, {"runs": list(service.list(tenant_id=principal.tenant_id))})
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
                run = service.create(
                    tenant_id=principal.tenant_id,
                    workflow_input=workflow_input,
                    run_id=run_id,
                    trace_id=trace_id,
                )
                self._send_json(handler, 202, {"run": run})
                return
            if handler.command == "GET" and len(segments) == 3 and segments[:2] == ["v1", "runs"]:
                self._require_scope(principal, SCOPE_RUN_READ)
                service = self._require_run_service()
                self._send_json(handler, 200, {"run": service.get(tenant_id=principal.tenant_id, run_id=segments[2])})
                return
            if (
                handler.command == "GET"
                and len(segments) == 4
                and segments[:2] == ["v1", "runs"]
                and segments[3] == "events"
            ):
                self._require_scope(principal, SCOPE_RUN_READ)
                service = self._require_run_service()
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
                self._read_empty_json(handler)
                run = service.approve(
                    tenant_id=principal.tenant_id,
                    run_id=segments[2],
                    task_id=segments[4],
                    approved_by=principal.subject,
                )
                self._send_json(handler, 202, {"run": run})
                return
            if handler.command == "GET" and segments == ["v1", "deploy", "status"]:
                self._require_scope(principal, SCOPE_READ)
                with self._lock:
                    status = {"active": self.store.active(), "history": list(self.store.history())}
                self._send_json(handler, 200, status)
                return
            if handler.command == "POST" and segments == ["v1", "bundles"]:
                self._require_scope(principal, SCOPE_PROPOSE)
                bundle = DeploymentBundle.from_compile_output(self._read_json(handler))
                with self._lock:
                    commit = self.store.propose(bundle)
                self._send_json(handler, 201, {"bundleDigest": bundle.bundle_digest, "commit": commit})
                return
            if (
                handler.command == "POST"
                and len(segments) == 4
                and segments[:2] == ["v1", "bundles"]
                and segments[3] == "approvals"
            ):
                self._require_scope(principal, SCOPE_APPROVE)
                self._submit_approval(handler, segments[2])
                return
            if (
                handler.command == "POST"
                and len(segments) == 4
                and segments[:2] == ["v1", "bundles"]
                and segments[3] == "promote"
            ):
                self._require_scope(principal, SCOPE_PROMOTE)
                self._promote(handler, segments[2])
                return
            if handler.command == "POST" and segments == ["v1", "deploy", "rollback"]:
                self._require_scope(principal, SCOPE_PROMOTE)
                value = self._read_json(handler)
                target = value.get("targetDigest")
                if not isinstance(target, str) or not target:
                    raise LedgerAPIError(400, "CONTROL-TARGET-REQUIRED", "targetDigest is required")
                with self._lock:
                    approvals = tuple(self._approvals.get(target, {}).values())
                    commit = self.store.rollback(
                        target,
                        approvals,
                        trusted_approvers=self.trusted_approvers,
                    )
                    self._approvals.pop(target, None)
                    active = self.store.active()
                self._send_json(handler, 200, {"active": active, "commit": commit})
                return
            raise LedgerAPIError(404, "CONTROL-ROUTE-NOT-FOUND", "route not found")
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

    def _submit_approval(self, handler: BaseHTTPRequestHandler, digest: str) -> None:
        value = self._read_json(handler)
        approver = value.get("approverId")
        key_id = value.get("keyId")
        signature = value.get("signature")
        if not all(isinstance(item, str) and item for item in (approver, key_id, signature)):
            raise LedgerAPIError(400, "CONTROL-APPROVAL-INVALID", "approverId, keyId, and signature are required")
        with self._lock:
            bundle = self.store.bundle(digest)
            active = self.store.active()
            statement = deployment_approval_statement(
                bundle,
                from_digest=active["bundleDigest"] if active else None,
                to_mode="ENFORCE",
            )
            approval = DeploymentApproval(approver, key_id, signature)
            verify_deployment_approval(statement, approval, self.trusted_approvers)
            pending = self._approvals.setdefault(digest, {})
            pending[(approver, key_id)] = approval
            count = len(pending)
        self._send_json(handler, 202, {"bundleDigest": digest, "pendingApprovals": count})

    def _promote(self, handler: BaseHTTPRequestHandler, digest: str) -> None:
        content_length = _single_header(handler, "Content-Length", required=False)
        if content_length and content_length != "0":
            self._read_json(handler)  # accept and ignore an empty JSON body
        with self._lock:
            approvals = tuple(self._approvals.get(digest, {}).values())
            commit = self.store.promote(
                digest,
                approvals,
                trusted_approvers=self.trusted_approvers,
            )
            self._approvals.pop(digest, None)
            active = self.store.active()
        self._send_json(handler, 200, {"active": active, "commit": commit})

    def _require_run_service(self) -> RunControlService:
        if self.run_service is None:
            raise RunControlError(503, "RUN-SERVICE-UNAVAILABLE", "run control is not configured")
        return self.run_service

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
        return json.loads(raw.decode("utf-8"))

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
