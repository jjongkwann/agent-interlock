"""Tenant-bound HTTP ingest and trace query API for the Interaction Ledger."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol
from urllib.parse import parse_qs, unquote, urlsplit

from .analytics import summarize_security_statistics
from .ledger import (
    Ledger,
    LedgerError,
    LedgerIdempotencyConflict,
    LedgerRangeTooLarge,
    parse_event_time,
)
from .models import DataSource, Environment
from .postgres_ledger import LedgerTenantMismatch
from .telemetry import import_runtime_telemetry

_EVENT_TYPES = frozenset(
    {
        "INTERACTION_REQUESTED",
        "DATA_FLOW_OBSERVED",
        "CONTROL_EVALUATED",
        "CONTROL_COVERAGE_DECLARED",
        "ACTION_EXECUTED",
        "INTERACTION_COMPLETED",
        "SECURITY_OUTCOME_SET",
        "DETECTION_RAISED",
        "INCIDENT_UPDATED",
        "CONTROL_HEALTH_CHANGED",
        "POLICY_CHANGED",
        "TEST_EXECUTED",
    }
)
_SEVERITIES = frozenset({"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
_RELATIONSHIP_ID = re.compile(r"^REL-[0-9]{2}$")
_TRACE_ROUTE = re.compile(r"^/v1/traces/([^/]+)$")
_EVENT_FIELDS = frozenset(
    {
        "event_type",
        "tenant_id",
        "trace_id",
        "span_id",
        "parent_span_id",
        "interaction_id",
        "source_actor_id",
        "target_actor_id",
        "relationship_type",
        "relationship_id",
        "severity",
        "environment",
        "data_source",
        "payload",
    }
)


class LedgerAPIError(RuntimeError):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class LedgerAPIPrincipal:
    subject: str
    tenant_id: str
    scopes: frozenset[str]
    allowed_source_actor_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.subject or not self.tenant_id:
            raise ValueError("principal subject and tenant_id are required")
        if any(not isinstance(scope, str) or not scope for scope in self.scopes):
            raise ValueError("principal scopes must be non-empty strings")
        if any(not isinstance(actor_id, str) or not actor_id for actor_id in self.allowed_source_actor_ids):
            raise ValueError("allowed source actor IDs must be non-empty strings")


class LedgerAPIAuthenticator(Protocol):
    def authenticate(self, bearer_token: str) -> LedgerAPIPrincipal | None: ...


class StaticBearerAuthenticator:
    """Small reference authenticator that retains only SHA-256 token digests."""

    def __init__(self, principals_by_token_digest: Mapping[str, LedgerAPIPrincipal]) -> None:
        values: dict[str, LedgerAPIPrincipal] = {}
        for digest, principal in principals_by_token_digest.items():
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ValueError("token digest must use sha256:<64 lowercase hex>")
            values[digest] = principal
        self._principals = values

    @classmethod
    def from_tokens(
        cls,
        principals_by_token: Mapping[str, LedgerAPIPrincipal],
    ) -> StaticBearerAuthenticator:
        values: dict[str, LedgerAPIPrincipal] = {}
        for token, principal in principals_by_token.items():
            if not isinstance(token, str) or not token or len(token) > 4096:
                raise ValueError("bearer tokens must be between 1 and 4096 characters")
            values[_token_digest(token)] = principal
        return cls(values)

    def authenticate(self, bearer_token: str) -> LedgerAPIPrincipal | None:
        return self._principals.get(_token_digest(bearer_token))

    def __repr__(self) -> str:
        return f"StaticBearerAuthenticator(principals={len(self._principals)})"


@dataclass(frozen=True, slots=True)
class LedgerHTTPConfig:
    max_request_bytes: int = 256 * 1024
    request_timeout_seconds: float = 5.0
    default_page_size: int = 100
    max_page_size: int = 500
    allowed_origins: frozenset[str] = frozenset()
    max_statistics_events: int = 100_000

    def __post_init__(self) -> None:
        if not 1 <= self.max_statistics_events <= 1_000_000:
            raise ValueError("max_statistics_events must be between 1 and 1,000,000")
        if not 1 <= self.max_request_bytes <= 5 * 1024 * 1024:
            raise ValueError("max_request_bytes must be between 1 byte and 5 MiB")
        if not 0.1 <= self.request_timeout_seconds <= 30:
            raise ValueError("request_timeout_seconds must be between 0.1 and 30")
        if not 1 <= self.default_page_size <= self.max_page_size <= 500:
            raise ValueError("page sizes must satisfy 1 <= default <= max <= 500")
        if any(
            not (value.startswith("https://") or _LOOPBACK_ORIGIN.fullmatch(value)) for value in self.allowed_origins
        ):
            raise ValueError("allowed browser origins must use https (loopback http is allowed for development)")


_LOOPBACK_ORIGIN = re.compile(r"^http://(localhost|127\.0\.0\.1)(:\d{1,5})?$")

LedgerResolver = Callable[[str], Ledger]


class LedgerHTTPAPI:
    """HTTP application with exact principal/tenant/scope enforcement."""

    def __init__(
        self,
        ledger: Ledger | LedgerResolver,
        authenticator: LedgerAPIAuthenticator,
        *,
        config: LedgerHTTPConfig | None = None,
    ) -> None:
        self._resolver: LedgerResolver = ledger if callable(ledger) else lambda _tenant: ledger
        self.authenticator = authenticator
        self.config = config or LedgerHTTPConfig()

    def handle(self, handler: BaseHTTPRequestHandler) -> None:
        try:
            self._check_origin(handler)
            if handler.command == "OPTIONS":
                self._send_preflight(handler)
                return
            principal = self._authenticate(handler)
            self._require_tenant_header(handler, principal)
            parts = urlsplit(handler.path)
            if handler.command == "POST" and parts.path == "/v1/events":
                if parts.query:
                    raise LedgerAPIError(400, "LEDGER-QUERY-UNEXPECTED", "query parameters are not allowed")
                self._require_scope(principal, "events:write")
                self._post_event(handler, principal)
                return
            if handler.command == "POST" and parts.path == "/v1/traces":
                if parts.query:
                    raise LedgerAPIError(400, "LEDGER-QUERY-UNEXPECTED", "query parameters are not allowed")
                self._require_scope(principal, "telemetry:write")
                self._post_traces(handler)
                return
            match = _TRACE_ROUTE.fullmatch(parts.path)
            if handler.command == "GET" and match is not None:
                self._require_scope(principal, "events:read")
                self._get_trace(handler, principal, match.group(1), parts.query)
                return
            if handler.command == "GET" and parts.path == "/v1/statistics":
                self._require_scope(principal, "statistics:read")
                self._get_statistics(handler, principal, parts.query)
                return
            raise LedgerAPIError(404, "LEDGER-ROUTE-NOT-FOUND", "route not found")
        except LedgerAPIError as error:
            self._send_error(handler, error)
        except LedgerIdempotencyConflict:
            self._send_error(
                handler,
                LedgerAPIError(
                    409,
                    "LEDGER-IDEMPOTENCY-CONFLICT",
                    "idempotency key is already bound to a different event",
                ),
            )
        except LedgerTenantMismatch:
            self._send_error(
                handler,
                LedgerAPIError(403, "LEDGER-TENANT-MISMATCH", "tenant access denied"),
            )
        except (ValueError, UnicodeError, json.JSONDecodeError, RecursionError):
            self._send_error(
                handler,
                LedgerAPIError(400, "LEDGER-REQUEST-INVALID", "request is invalid"),
            )
        except (LedgerError, OSError):
            self._send_error(
                handler,
                LedgerAPIError(503, "LEDGER-UNAVAILABLE", "Ledger is unavailable"),
            )
        except Exception:
            self._send_error(
                handler,
                LedgerAPIError(500, "LEDGER-INTERNAL-ERROR", "internal server error"),
            )

    def _post_event(
        self,
        handler: BaseHTTPRequestHandler,
        principal: LedgerAPIPrincipal,
    ) -> None:
        idempotency_key = _single_header(handler, "Idempotency-Key", required=True)
        if not 1 <= len(idempotency_key) <= 200 or any(not 33 <= ord(char) <= 126 for char in idempotency_key):
            raise LedgerAPIError(
                400,
                "LEDGER-IDEMPOTENCY-KEY-INVALID",
                "Idempotency-Key is invalid",
            )
        value = self._read_json(handler)
        if not isinstance(value, Mapping):
            raise LedgerAPIError(400, "LEDGER-EVENT-INVALID", "event must be an object")
        unknown = set(value) - _EVENT_FIELDS
        required = {
            "event_type",
            "tenant_id",
            "trace_id",
            "span_id",
            "source_actor_id",
            "payload",
        }
        if unknown or required - set(value):
            raise LedgerAPIError(400, "LEDGER-EVENT-INVALID", "event fields are invalid")
        if value["tenant_id"] != principal.tenant_id:
            raise LedgerAPIError(403, "LEDGER-TENANT-MISMATCH", "tenant access denied")
        event_type = _required_string(value, "event_type", maximum=64)
        if event_type not in _EVENT_TYPES:
            raise LedgerAPIError(400, "LEDGER-EVENT-TYPE-INVALID", "event type is invalid")
        severity = _optional_string(value, "severity", "INFO", maximum=16)
        if severity not in _SEVERITIES:
            raise LedgerAPIError(400, "LEDGER-SEVERITY-INVALID", "severity is invalid")
        relationship_id = _optional_string(value, "relationship_id", "REL-05", maximum=16)
        if _RELATIONSHIP_ID.fullmatch(relationship_id) is None:
            raise LedgerAPIError(
                400,
                "LEDGER-RELATIONSHIP-ID-INVALID",
                "relationship_id is invalid",
            )
        environment = Environment(_optional_string(value, "environment", "DEV", maximum=16))
        data_source = DataSource(_optional_string(value, "data_source", "PRODUCTION", maximum=16))
        payload = value["payload"]
        if not isinstance(payload, Mapping):
            raise LedgerAPIError(400, "LEDGER-PAYLOAD-INVALID", "payload must be an object")
        _validate_json_shape(payload)
        if "_interlock" in payload:
            raise LedgerAPIError(
                400,
                "LEDGER-PAYLOAD-RESERVED",
                "payload contains a reserved field",
            )
        enriched_payload = dict(payload)
        enriched_payload["_interlock"] = {"producerSubject": principal.subject}
        source_actor_id = _required_string(value, "source_actor_id", maximum=512)
        if source_actor_id not in principal.allowed_source_actor_ids:
            raise LedgerAPIError(
                403,
                "LEDGER-SOURCE-ACTOR-DENIED",
                "source actor is not authorized for this producer",
            )
        ledger = self._resolver(principal.tenant_id)
        event = ledger.append(
            event_type,
            tenant_id=principal.tenant_id,
            trace_id=_required_string(value, "trace_id", maximum=256),
            span_id=_required_string(value, "span_id", maximum=256),
            source_actor_id=source_actor_id,
            payload=enriched_payload,
            target_actor_id=_nullable_string(value, "target_actor_id", maximum=512),
            interaction_id=_nullable_string(value, "interaction_id", maximum=256),
            parent_span_id=_nullable_string(value, "parent_span_id", maximum=256),
            relationship_type=_optional_string(
                value,
                "relationship_type",
                "INVOKES",
                maximum=64,
            ),
            relationship_id=relationship_id,
            severity=severity,
            environment=environment,
            data_source=data_source,
            idempotency_key=idempotency_key,
        )
        self._send_json(handler, 201, {"event": event.to_dict()})

    def _post_traces(self, handler: BaseHTTPRequestHandler) -> None:
        """Receive an OTLP/HTTP JSON export and return decoded runtime observations.

        Identity comes from the authenticated principal, not the agent-sent spans,
        so a caller cannot forge the relationship topology's owner. The decoded
        observations feed design/runtime drift analysis; no event is written here.
        """
        value = self._read_json(handler)
        if not isinstance(value, Mapping) or "resourceSpans" not in value:
            raise LedgerAPIError(400, "LEDGER-OTLP-INVALID", "OTLP resourceSpans payload is required")
        try:
            imported = import_runtime_telemetry(value)
        except (ValueError, RecursionError) as error:
            raise LedgerAPIError(400, "LEDGER-OTLP-INVALID", "OTLP payload is invalid") from error
        self._send_json(
            handler,
            200,
            {
                "format": imported.format,
                "observations": [
                    {
                        "source_actor_id": edge.source,
                        "target_actor_id": edge.target,
                        "relationship_type": edge.relationship,
                        "relationship_id": edge.relationship_id,
                        "interaction_id": edge.interaction_id,
                    }
                    for edge in imported.observations
                ],
                "control_evaluated_interactions": sorted(imported.control_evaluated_interactions),
                "issues": [
                    {"code": issue.code, "message": issue.message, "span_id": issue.span_id}
                    for issue in imported.issues
                ],
            },
        )

    def _get_trace(
        self,
        handler: BaseHTTPRequestHandler,
        principal: LedgerAPIPrincipal,
        encoded_trace_id: str,
        query: str,
    ) -> None:
        content_length = _single_header(handler, "Content-Length", required=False)
        if content_length and content_length != "0":
            raise LedgerAPIError(400, "LEDGER-GET-BODY-DENIED", "GET request body is not allowed")
        try:
            trace_id = unquote(encoded_trace_id, encoding="utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise LedgerAPIError(400, "LEDGER-TRACE-ID-INVALID", "trace_id is invalid") from error
        if (
            not trace_id
            or len(trace_id) > 256
            or "/" in trace_id
            or "\\" in trace_id
            or any(ord(char) < 32 for char in trace_id)
        ):
            raise LedgerAPIError(400, "LEDGER-TRACE-ID-INVALID", "trace_id is invalid")
        parameters = (
            parse_qs(
                query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=2,
            )
            if query
            else {}
        )
        if set(parameters) - {"limit", "cursor"} or any(len(values) != 1 for values in parameters.values()):
            raise LedgerAPIError(400, "LEDGER-QUERY-INVALID", "query parameters are invalid")
        limit_value = parameters.get("limit", [str(self.config.default_page_size)])[0]
        if not limit_value.isascii() or not limit_value.isdigit():
            raise LedgerAPIError(400, "LEDGER-LIMIT-INVALID", "limit is invalid")
        limit = int(limit_value)
        if not 1 <= limit <= self.config.max_page_size:
            raise LedgerAPIError(400, "LEDGER-LIMIT-INVALID", "limit is invalid")
        cursor = parameters.get("cursor", [None])[0]
        ledger = self._resolver(principal.tenant_id)
        page = ledger.query_trace(
            principal.tenant_id,
            trace_id,
            limit=limit,
            cursor=cursor,
        )
        self._send_json(
            handler,
            200,
            {
                "trace_id": trace_id,
                "events": [event.to_dict() for event in page.events],
                "next_cursor": page.next_cursor,
            },
        )

    def _get_statistics(
        self,
        handler: BaseHTTPRequestHandler,
        principal: LedgerAPIPrincipal,
        query: str,
    ) -> None:
        content_length = _single_header(handler, "Content-Length", required=False)
        if content_length and content_length != "0":
            raise LedgerAPIError(400, "LEDGER-GET-BODY-DENIED", "GET request body is not allowed")
        try:
            parameters = parse_qs(query, keep_blank_values=True, strict_parsing=True, max_num_fields=3) if query else {}
        except ValueError as error:
            raise LedgerAPIError(400, "LEDGER-QUERY-INVALID", "query parameters are invalid") from error
        if set(parameters) - {"from", "to", "dataSource"} or any(len(values) != 1 for values in parameters.values()):
            raise LedgerAPIError(400, "LEDGER-QUERY-INVALID", "query parameters are invalid")
        if "from" not in parameters or "to" not in parameters:
            raise LedgerAPIError(400, "LEDGER-STATS-RANGE-REQUIRED", "from and to are required")
        start, end = parameters["from"][0], parameters["to"][0]
        try:
            if parse_event_time(start) >= parse_event_time(end):
                raise LedgerAPIError(400, "LEDGER-STATS-RANGE-INVALID", "from must be before to")
        except ValueError as error:
            raise LedgerAPIError(400, "LEDGER-STATS-RANGE-INVALID", "from/to must be ISO 8601") from error
        data_source = parameters.get("dataSource", [None])[0]
        if data_source is not None and data_source not in {item.value for item in DataSource}:
            raise LedgerAPIError(400, "LEDGER-STATS-SOURCE-INVALID", "dataSource is invalid")
        ledger = self._resolver(principal.tenant_id)
        try:
            events = ledger.interaction_lifecycles_started_between(
                principal.tenant_id,
                start,
                end,
                data_source=data_source,
                limit=self.config.max_statistics_events,
            )
        except LedgerRangeTooLarge as error:
            raise LedgerAPIError(
                422,
                "LEDGER-STATS-RANGE-TOO-LARGE",
                "time range matches too many events; narrow the range",
            ) from error
        values = (event.to_dict() for event in events)
        self._send_json(
            handler,
            200,
            {"from": start, "to": end, "statistics": summarize_security_statistics(values)},
        )

    def _read_json(self, handler: BaseHTTPRequestHandler) -> Any:
        if _single_header(handler, "Transfer-Encoding", required=False):
            raise LedgerAPIError(
                400,
                "LEDGER-TRANSFER-ENCODING-DENIED",
                "Transfer-Encoding is not supported",
            )
        content_type = _single_header(handler, "Content-Type", required=True)
        if content_type.split(";", 1)[0].strip().casefold() != "application/json":
            raise LedgerAPIError(415, "LEDGER-CONTENT-TYPE-INVALID", "application/json is required")
        length_value = _single_header(handler, "Content-Length", required=True)
        if not length_value.isascii() or not length_value.isdigit():
            raise LedgerAPIError(400, "LEDGER-CONTENT-LENGTH-INVALID", "Content-Length is invalid")
        length = int(length_value)
        if not 1 <= length <= self.config.max_request_bytes:
            raise LedgerAPIError(413, "LEDGER-BODY-TOO-LARGE", "request body is too large")
        try:
            raw = handler.rfile.read(length)
        except TimeoutError as error:
            raise LedgerAPIError(408, "LEDGER-REQUEST-TIMEOUT", "request body timed out") from error
        if len(raw) != length:
            raise LedgerAPIError(400, "LEDGER-BODY-INCOMPLETE", "request body is incomplete")
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_strict_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid JSON number")),
        )

    def _authenticate(self, handler: BaseHTTPRequestHandler) -> LedgerAPIPrincipal:
        value = _single_header(handler, "Authorization", required=True, unauthorized=True)
        parts = value.split(" ", 1)
        if len(parts) != 2 or parts[0].casefold() != "bearer" or not parts[1]:
            raise LedgerAPIError(401, "LEDGER-AUTH-INVALID", "bearer authentication required")
        token = parts[1]
        if len(token) > 4096 or any(char.isspace() for char in token):
            raise LedgerAPIError(401, "LEDGER-AUTH-INVALID", "bearer authentication required")
        principal = self.authenticator.authenticate(token)
        if principal is None:
            raise LedgerAPIError(401, "LEDGER-AUTH-INVALID", "bearer authentication required")
        return principal

    @staticmethod
    def _require_tenant_header(
        handler: BaseHTTPRequestHandler,
        principal: LedgerAPIPrincipal,
    ) -> None:
        tenant_id = _single_header(handler, "X-Interlock-Tenant-Id", required=True)
        if tenant_id != principal.tenant_id:
            raise LedgerAPIError(403, "LEDGER-TENANT-MISMATCH", "tenant access denied")

    @staticmethod
    def _require_scope(principal: LedgerAPIPrincipal, required: str) -> None:
        if required not in principal.scopes:
            raise LedgerAPIError(403, "LEDGER-SCOPE-DENIED", "scope is not authorized")

    def _check_origin(self, handler: BaseHTTPRequestHandler) -> None:
        origins = handler.headers.get_all("Origin", failobj=[])
        if len(origins) > 1 or (origins and origins[0] not in self.config.allowed_origins):
            raise LedgerAPIError(403, "LEDGER-ORIGIN-DENIED", "browser origin is not authorized")

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
                handler.send_header(
                    "Access-Control-Allow-Headers",
                    "Authorization, Content-Type, X-Interlock-Tenant-Id, Idempotency-Key",
                )
                handler.send_header("Access-Control-Max-Age", "600")
        handler.end_headers()

    def _send_json(
        self,
        handler: BaseHTTPRequestHandler,
        status: int,
        value: Mapping[str, Any],
        *,
        close: bool = False,
    ) -> None:
        body = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json; charset=utf-8")
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        for name, header_value in self._cors_headers(handler):
            handler.send_header(name, header_value)
        if close:
            handler.send_header("Connection", "close")
            handler.close_connection = True
        handler.end_headers()
        handler.wfile.write(body)

    def _send_error(self, handler: BaseHTTPRequestHandler, error: LedgerAPIError) -> None:
        if error.status == 401:
            handler.close_connection = True
            handler.send_response_only(401)
            handler.send_header("WWW-Authenticate", 'Bearer realm="agent-interlock-ledger"')
            body = json.dumps(
                {"error": {"code": error.code, "message": error.message}},
                separators=(",", ":"),
            ).encode("utf-8")
            handler.send_header("Content-Type", "application/json; charset=utf-8")
            handler.send_header("Content-Length", str(len(body)))
            handler.send_header("Cache-Control", "no-store")
            handler.send_header("X-Content-Type-Options", "nosniff")
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.wfile.write(body)
            return
        self._send_json(
            handler,
            error.status,
            {"error": {"code": error.code, "message": error.message}},
            close=True,
        )


class _LedgerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, server_address: tuple[str, int], api: LedgerHTTPAPI):
        self.api = api
        super().__init__(server_address, _LedgerRequestHandler)


class _LedgerRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.api.config.request_timeout_seconds)  # type: ignore[attr-defined]

    def do_POST(self) -> None:
        self.server.api.handle(self)  # type: ignore[attr-defined]

    def do_GET(self) -> None:
        self.server.api.handle(self)  # type: ignore[attr-defined]

    def do_OPTIONS(self) -> None:
        self.server.api.handle(self)  # type: ignore[attr-defined]

    def handle_expect_100(self) -> bool:
        self.server.api._send_error(  # type: ignore[attr-defined]
            self,
            LedgerAPIError(
                417,
                "LEDGER-EXPECTATION-DENIED",
                "Expect: 100-continue is not supported",
            ),
        )
        return False

    def log_message(self, _format: str, *args: Any) -> None:
        return


def create_ledger_http_server(
    api: LedgerHTTPAPI,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    """Create the reference server; it deliberately binds only to loopback."""

    try:
        address = ipaddress.ip_address(host)
    except ValueError as error:
        raise ValueError("the reference Ledger server requires a loopback IP literal") from error
    if not address.is_loopback:
        raise ValueError("the reference Ledger server binds only to loopback")
    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    return _LedgerHTTPServer((host, port), api)


def _single_header(
    handler: BaseHTTPRequestHandler,
    name: str,
    *,
    required: bool,
    unauthorized: bool = False,
) -> str:
    values = handler.headers.get_all(name, failobj=[])
    if len(values) != 1:
        if required:
            status = 401 if unauthorized else 400
            code = "LEDGER-AUTH-INVALID" if unauthorized else "LEDGER-HEADER-INVALID"
            raise LedgerAPIError(status, code, f"exactly one {name} header is required")
        if values:
            raise LedgerAPIError(400, "LEDGER-HEADER-INVALID", f"duplicate {name} header")
        return ""
    return values[0]


def _required_string(value: Mapping[str, Any], key: str, *, maximum: int) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item or len(item) > maximum or any(ord(char) < 32 for char in item):
        raise LedgerAPIError(400, "LEDGER-EVENT-INVALID", f"{key} is invalid")
    return item


def _optional_string(
    value: Mapping[str, Any],
    key: str,
    default: str,
    *,
    maximum: int,
) -> str:
    if key not in value:
        return default
    return _required_string(value, key, maximum=maximum)


def _nullable_string(value: Mapping[str, Any], key: str, *, maximum: int) -> str | None:
    if key not in value or value[key] is None:
        return None
    return _required_string(value, key, maximum=maximum)


def _validate_json_shape(value: Any, *, depth: int = 0, nodes: list[int] | None = None) -> None:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > 32 or nodes[0] > 10_000:
        raise LedgerAPIError(400, "LEDGER-PAYLOAD-TOO-COMPLEX", "payload is too complex")
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise LedgerAPIError(400, "LEDGER-PAYLOAD-INVALID", "payload key is invalid")
            _validate_json_shape(item, depth=depth + 1, nodes=nodes)
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_shape(item, depth=depth + 1, nodes=nodes)
        return
    if value is not None and not isinstance(value, (str, int, float, bool)):
        raise LedgerAPIError(400, "LEDGER-PAYLOAD-INVALID", "payload value is invalid")


def _token_digest(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value
