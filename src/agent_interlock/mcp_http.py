"""Secure MCP 2025-11-25 Streamable HTTP wire carrier."""

from __future__ import annotations

import ipaddress
import json
import secrets
import ssl
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from .mcp_contracts import (
    MCPHTTPError,
    SessionStore,
    _PrincipalKey,
)
from .mcp_transport import (
    MCP_PROTOCOL_VERSION,
    MCPInvocationContext,
    MCPTransportAdapter,
)
from .security import sanitize_secrets


_JSONRPC_PARSE_ERROR = -32700
_JSONRPC_INVALID_REQUEST = -32600
_JSONRPC_METHOD_NOT_FOUND = -32601
_INTERLOCK_NOT_CONFIGURED = -32002


class MCPHTTPStatusError(MCPHTTPError):
    def __init__(
        self,
        status: int,
        *,
        reason_code: str = "MCP-HTTP-UPSTREAM-STATUS",
        www_authenticate: str | None = None,
    ) -> None:
        super().__init__(reason_code, f"downstream MCP HTTP request failed with status {status}")
        self.status = status
        self.www_authenticate = www_authenticate


class MCPHTTPSessionExpired(MCPHTTPStatusError):
    def __init__(self) -> None:
        super().__init__(404, reason_code="MCP-HTTP-SESSION-EXPIRED")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


AuthorizationProvider = Callable[[], str | None]
ServerMessageHandler = Callable[[Mapping[str, Any]], Any]


@dataclass(frozen=True, slots=True)
class MCPStreamableHTTPClientConfig:
    endpoint: str
    protocol_version: str = MCP_PROTOCOL_VERSION
    timeout_seconds: float = 10.0
    max_response_bytes: int = 4_194_304
    max_sse_events: int = 1024
    allow_loopback_http: bool = False

    def __post_init__(self) -> None:
        if self.protocol_version != MCP_PROTOCOL_VERSION:
            raise ValueError(f"unsupported MCP protocol version: {self.protocol_version}")
        if self.timeout_seconds <= 0 or self.max_response_bytes <= 0 or self.max_sse_events <= 0:
            raise ValueError("HTTP client limits must be positive")
        _validate_endpoint(self.endpoint, allow_loopback_http=self.allow_loopback_http)


class MCPStreamableHTTPClient:
    """Synchronous MCP Streamable HTTP client with JSON and SSE response support."""

    def __init__(
        self,
        config: MCPStreamableHTTPClientConfig,
        *,
        authorization_provider: AuthorizationProvider | None = None,
        server_message_handler: ServerMessageHandler | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.config = config
        self._authorization_provider = authorization_provider
        self._server_message_handler = server_message_handler
        handlers: list[Any] = [_NoRedirectHandler()]
        if ssl_context is not None:
            handlers.append(HTTPSHandler(context=ssl_context))
        self._opener = build_opener(*handlers)
        self._initialized = False
        self._session_id: str | None = None
        self._last_event_id: str | None = None
        self._server_capabilities: Mapping[str, Any] = {}
        self._server_request_router: Any = None
        self._server_request_responder: Any = None

    @property
    def initialized(self) -> bool:
        return self._initialized

    @property
    def session_id(self) -> str | None:
        return self._session_id

    @property
    def server_capabilities(self) -> Mapping[str, Any]:
        return self._server_capabilities

    def set_server_message_handler(self, handler: ServerMessageHandler | None) -> None:
        self._server_message_handler = handler

    def set_server_request_router(self, router: Any, responder: Any = None) -> None:
        """Enable fail-closed handling of server-initiated requests.

        ``router`` is a ``ServerRequestRouter``; ``responder`` (optional) is
        called with the produced JSON-RPC response so a deployment can POST it
        back to the server. Without a router, server-initiated requests remain
        rejected fail-closed.
        """
        self._server_request_router = router
        self._server_request_responder = responder

    def initialize(
        self,
        *,
        client_name: str = "agent-interlock",
        client_version: str = "0.1.0",
        capabilities: Mapping[str, Any] | None = None,
    ) -> Mapping[str, Any]:
        if self._initialized:
            raise MCPHTTPError("MCP-LIFECYCLE-ALREADY-INITIALIZED", "MCP client is already initialized")
        request_id = "interlock-initialize"
        response = self._exchange(
            "POST",
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": self.config.protocol_version,
                    "capabilities": dict(capabilities or {}),
                    "clientInfo": {"name": client_name, "version": client_version},
                },
            },
            include_protocol_header=False,
        )
        try:
            if not isinstance(response, Mapping) or response.get("id") != request_id:
                raise MCPHTTPError("MCP-LIFECYCLE-INITIALIZE-INVALID", "invalid initialize response")
            result = response.get("result")
            if not isinstance(result, Mapping):
                raise MCPHTTPError("MCP-LIFECYCLE-INITIALIZE-INVALID", "initialize result is missing")
            if result.get("protocolVersion") != self.config.protocol_version:
                raise MCPHTTPError(
                    "MCP-LIFECYCLE-VERSION-UNSUPPORTED",
                    "downstream MCP Server negotiated an unsupported protocol version",
                )
            server_capabilities = result.get("capabilities", {})
            if not isinstance(server_capabilities, Mapping):
                raise MCPHTTPError(
                    "MCP-LIFECYCLE-CAPABILITIES-INVALID",
                    "server capabilities must be an object",
                )
            self._server_capabilities = dict(server_capabilities)
            self._initialized = True
            acknowledgement = self._exchange(
                "POST",
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
            )
            if acknowledgement is not None:
                raise MCPHTTPError(
                    "MCP-LIFECYCLE-INITIALIZED-ACK-INVALID",
                    "initialized notification did not receive HTTP 202",
                )
            return dict(result)
        except Exception:
            self._initialized = False
            self._session_id = None
            self._server_capabilities = {}
            raise

    def call(self, request: Mapping[str, Any]) -> Mapping[str, Any] | None:
        method = request.get("method")
        if method == "initialize":
            raise MCPHTTPError(
                "MCP-LIFECYCLE-INITIALIZE-API-REQUIRED",
                "use initialize() for MCP lifecycle negotiation",
            )
        if not self._initialized:
            raise MCPHTTPError("MCP-LIFECYCLE-NOT-INITIALIZED", "MCP client must initialize before operation")
        return self._exchange("POST", request)

    def listen_once(self, *, last_event_id: str | None = None) -> int:
        if not self._initialized:
            raise MCPHTTPError("MCP-LIFECYCLE-NOT-INITIALIZED", "MCP client must initialize before listening")
        headers = self._request_headers(accept="text/event-stream")
        resume = last_event_id or self._last_event_id
        if resume:
            headers["Last-Event-ID"] = resume
        response = self._open(Request(self.config.endpoint, method="GET", headers=headers))
        try:
            if response.status != 200:
                raise MCPHTTPStatusError(response.status)
            content_type = _media_type(response.headers.get("Content-Type"))
            if content_type != "text/event-stream":
                raise MCPHTTPError("MCP-HTTP-CONTENT-TYPE-INVALID", "GET response must be text/event-stream")
            payload = _read_limited(response, self.config.max_response_bytes)
        finally:
            response.close()
        messages = self._parse_sse(payload)
        self._dispatch_server_messages(messages, expected_id=None)
        return len(messages)

    def close_session(self) -> bool:
        if not self._session_id:
            self._initialized = False
            return False
        headers = self._request_headers(accept="application/json")
        try:
            response = self._open(Request(self.config.endpoint, method="DELETE", headers=headers))
        except MCPHTTPStatusError as error:
            if error.status != 405:
                raise
            self._session_id = None
            self._initialized = False
            return False
        try:
            supported = response.status != 405
        finally:
            response.close()
        self._session_id = None
        self._initialized = False
        return supported

    def _exchange(
        self,
        method: str,
        message: Mapping[str, Any],
        *,
        include_protocol_header: bool = True,
    ) -> Mapping[str, Any] | None:
        body = _json_bytes(message)
        headers = self._request_headers(
            accept="application/json, text/event-stream",
            include_protocol_header=include_protocol_header,
        )
        headers["Content-Type"] = "application/json"
        request = Request(self.config.endpoint, data=body, method=method, headers=headers)
        try:
            response = self._open(request)
        except MCPHTTPSessionExpired:
            self._session_id = None
            self._initialized = False
            raise
        try:
            status = response.status
            session_header = response.headers.get("MCP-Session-Id")
            if session_header is not None:
                session_header = _validated_session_id(session_header)
                if message.get("method") == "initialize":
                    self._session_id = session_header
                elif self._session_id != session_header:
                    raise MCPHTTPError(
                        "MCP-HTTP-SESSION-MISMATCH",
                        "downstream MCP Server changed the session outside initialization",
                    )
            if status == 202:
                payload = _read_limited(response, self.config.max_response_bytes)
                if payload:
                    raise MCPHTTPError("MCP-HTTP-202-BODY", "HTTP 202 response must not contain a body")
                return None
            if status != 200:
                raise MCPHTTPStatusError(status)
            content_type = _media_type(response.headers.get("Content-Type"))
            payload = _read_limited(response, self.config.max_response_bytes)
        finally:
            response.close()

        if content_type == "application/json":
            parsed = _json_object(payload)
            _validate_response_id(message, parsed)
            return parsed
        if content_type == "text/event-stream":
            messages = self._parse_sse(payload)
            return self._dispatch_server_messages(messages, expected_id=message.get("id"))
        raise MCPHTTPError(
            "MCP-HTTP-CONTENT-TYPE-INVALID",
            "downstream response must be application/json or text/event-stream",
        )

    def _parse_sse(self, payload: bytes) -> tuple[Mapping[str, Any], ...]:
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError as error:
            raise MCPHTTPError("MCP-SSE-UTF8-INVALID", "SSE response is not valid UTF-8") from error
        messages: list[Mapping[str, Any]] = []
        data_lines: list[str] = []
        event_id: str | None = None

        def flush() -> None:
            nonlocal data_lines, event_id
            if event_id is not None:
                if "\x00" in event_id or not _visible_ascii(event_id):
                    raise MCPHTTPError("MCP-SSE-EVENT-ID-INVALID", "SSE event id is invalid")
                self._last_event_id = event_id
            data = "\n".join(data_lines)
            if data:
                try:
                    value = json.loads(data)
                except json.JSONDecodeError as error:
                    raise MCPHTTPError("MCP-SSE-DATA-INVALID", "SSE data is not valid JSON") from error
                if isinstance(value, list) or not isinstance(value, Mapping) or value.get("jsonrpc") != "2.0":
                    raise MCPHTTPError("MCP-SSE-DATA-INVALID", "SSE data must be one JSON-RPC object")
                messages.append(dict(value))
                if len(messages) > self.config.max_sse_events:
                    raise MCPHTTPError("MCP-SSE-EVENT-LIMIT", "SSE event limit exceeded")
            data_lines = []
            event_id = None

        for raw_line in text.splitlines():
            if raw_line == "":
                flush()
                continue
            if raw_line.startswith(":"):
                continue
            field, separator, value = raw_line.partition(":")
            if separator and value.startswith(" "):
                value = value[1:]
            if field == "data":
                data_lines.append(value)
            elif field == "id":
                event_id = value
            elif field == "retry" and value and not value.isdigit():
                raise MCPHTTPError("MCP-SSE-RETRY-INVALID", "SSE retry must be an integer")
        if data_lines or event_id is not None:
            flush()
        return tuple(messages)

    def _dispatch_server_messages(
        self,
        messages: tuple[Mapping[str, Any], ...],
        *,
        expected_id: Any,
    ) -> Mapping[str, Any] | None:
        response: Mapping[str, Any] | None = None
        notifications: list[Mapping[str, Any]] = []
        for message in messages:
            if "method" in message:
                if "id" in message:
                    if self._server_request_router is None:
                        raise MCPHTTPError(
                            "MCP-SSE-SERVER-REQUEST-UNSUPPORTED",
                            "server-initiated MCP requests are not enabled",
                        )
                    server_response = self._server_request_router.handle(message)
                    if self._server_request_responder is not None:
                        self._server_request_responder(server_response)
                    continue
                notifications.append(message)
                continue
            if expected_id is None:
                raise MCPHTTPError(
                    "MCP-SSE-UNEXPECTED-RESPONSE",
                    "unsolicited SSE stream contained a JSON-RPC response",
                )
            if message.get("id") != expected_id or response is not None:
                raise MCPHTTPError("MCP-SSE-RESPONSE-ID-MISMATCH", "SSE response id mismatch")
            response = message
        for notification in notifications:
            if self._server_message_handler is not None:
                self._server_message_handler(notification)
        if expected_id is not None and response is None:
            raise MCPHTTPError("MCP-SSE-RESPONSE-MISSING", "SSE stream ended before the response")
        return response

    def _request_headers(
        self,
        *,
        accept: str,
        include_protocol_header: bool = True,
    ) -> dict[str, str]:
        headers = {"Accept": accept, "Cache-Control": "no-store"}
        if include_protocol_header:
            headers["MCP-Protocol-Version"] = self.config.protocol_version
        if self._session_id:
            headers["MCP-Session-Id"] = self._session_id
        if self._authorization_provider is not None:
            authorization = self._authorization_provider()
            if authorization:
                if not isinstance(authorization, str) or not _safe_header_value(authorization):
                    raise MCPHTTPError("MCP-HTTP-AUTHORIZATION-INVALID", "authorization header is invalid")
                headers["Authorization"] = authorization
        return headers

    def _open(self, request: Request):
        try:
            return self._opener.open(request, timeout=self.config.timeout_seconds)
        except HTTPError as error:
            authenticate = error.headers.get("WWW-Authenticate") if error.headers else None
            if authenticate and not _safe_header_value(authenticate):
                authenticate = None
            status = error.code
            error.close()
            if status == 404 and self._session_id:
                raise MCPHTTPSessionExpired() from error
            raise MCPHTTPStatusError(status, www_authenticate=authenticate) from error
        except URLError as error:
            raise MCPHTTPError("MCP-HTTP-CONNECTION-FAILED", "downstream MCP connection failed") from error
        except TimeoutError as error:
            raise MCPHTTPError("MCP-HTTP-TIMEOUT", "downstream MCP request timed out") from error


@dataclass(frozen=True, slots=True)
class MCPHTTPPrincipal:
    tenant_id: str
    actor_id: str
    subject: str

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.actor_id or not self.subject:
            raise ValueError("tenant_id, actor_id, and subject are required")


@dataclass(frozen=True, slots=True)
class MCPHTTPRequest:
    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes = b""
    remote_addr: str = ""


@dataclass(frozen=True, slots=True)
class MCPHTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes = b""


@dataclass(frozen=True, slots=True)
class MCPHTTPGatewayConfig:
    endpoint_path: str = "/mcp"
    protocol_version: str = MCP_PROTOCOL_VERSION
    allowed_origins: frozenset[str] = frozenset()
    allowed_hosts: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
    require_origin: bool = False
    max_request_bytes: int = 1_048_576
    allow_non_loopback_bind: bool = False

    def __post_init__(self) -> None:
        if not self.endpoint_path.startswith("/") or "?" in self.endpoint_path or "#" in self.endpoint_path:
            raise ValueError("endpoint_path must be an absolute path without query or fragment")
        if self.protocol_version != MCP_PROTOCOL_VERSION:
            raise ValueError(f"unsupported MCP protocol version: {self.protocol_version}")
        if not self.allowed_hosts or self.max_request_bytes <= 0:
            raise ValueError("allowed_hosts and a positive request limit are required")
        if self.require_origin and not self.allowed_origins:
            raise ValueError("require_origin needs at least one allowed origin")
        for origin in self.allowed_origins:
            _canonical_origin(origin)


InboundAuthenticator = Callable[[str | None], MCPHTTPPrincipal | None]
InvocationContextResolver = Callable[
    [MCPHTTPPrincipal, Mapping[str, Any]], MCPInvocationContext | None
]

@dataclass(slots=True)
class _StoredSession:
    principal_key: _PrincipalKey
    state: str
    sequence: int
    events: list[tuple[int, Mapping[str, Any]]]


class InMemorySessionStore:
    """Reference single-node SessionStore. Distributed backends mirror this contract."""

    def __init__(self) -> None:
        self._sessions: dict[str, _StoredSession] = {}
        self._lock = threading.RLock()

    def _bound(self, session_id: str, principal_key: _PrincipalKey) -> _StoredSession | None:
        session = self._sessions.get(session_id)
        if session is None or session.principal_key != principal_key:
            return None
        return session

    def create(self, session_id: str, principal_key: _PrincipalKey) -> None:
        with self._lock:
            if session_id in self._sessions:
                raise MCPHTTPError("MCP-HTTP-SESSION-DUPLICATE", "session id already exists")
            self._sessions[session_id] = _StoredSession(principal_key, "INITIALIZING", 0, [])

    def mark_ready(self, session_id: str, principal_key: _PrincipalKey) -> bool:
        with self._lock:
            session = self._bound(session_id, principal_key)
            if session is None or session.state != "INITIALIZING":
                return False
            session.state = "READY"
            return True

    def state(self, session_id: str, principal_key: _PrincipalKey) -> str | None:
        with self._lock:
            session = self._bound(session_id, principal_key)
            return session.state if session else None

    def append(self, session_id: str, principal_key: _PrincipalKey, message: Mapping[str, Any]) -> int:
        with self._lock:
            session = self._bound(session_id, principal_key)
            if session is None:
                raise MCPHTTPError("MCP-HTTP-SESSION-NOT-FOUND", "session not found")
            session.sequence += 1
            session.events.append((session.sequence, dict(message)))
            return session.sequence

    def replay(
        self, session_id: str, principal_key: _PrincipalKey, after: int | None
    ) -> tuple[tuple[int, Mapping[str, Any]], ...]:
        with self._lock:
            session = self._bound(session_id, principal_key)
            if session is None:
                return ()
            floor = after or 0
            return tuple((seq, message) for seq, message in session.events if seq > floor)

    def delete(self, session_id: str, principal_key: _PrincipalKey) -> bool:
        with self._lock:
            if self._bound(session_id, principal_key) is None:
                return False
            del self._sessions[session_id]
            return True


class MCPStreamableHTTPGatewayCarrier:
    """Inbound Streamable HTTP endpoint that terminates lifecycle and enforces Tool policy."""

    def __init__(
        self,
        adapter: MCPTransportAdapter,
        config: MCPHTTPGatewayConfig,
        *,
        authenticator: InboundAuthenticator,
        context_resolver: InvocationContextResolver,
        session_store: SessionStore | None = None,
    ) -> None:
        self.adapter = adapter
        self.config = config
        self._authenticator = authenticator
        self._context_resolver = context_resolver
        self._session_store = session_store
        self._allowed_origins = {_canonical_origin(item) for item in config.allowed_origins}
        self._allowed_hosts = {_canonical_host(item) for item in config.allowed_hosts}
        self._lifecycle: dict[tuple[str, str, str], str] = {}
        self._lifecycle_lock = threading.RLock()

    def handle(self, request: MCPHTTPRequest) -> MCPHTTPResponse:
        base_headers = {
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        }
        try:
            if request.path != self.config.endpoint_path:
                return MCPHTTPResponse(404, base_headers)
            headers = _lower_headers(request.headers)
            self._validate_host(headers)
            self._validate_origin(headers)
            principal = self._authenticate(headers)
            method = request.method.upper()
            if method == "GET":
                if self._session_store is None:
                    return MCPHTTPResponse(405, {**base_headers, "Allow": "POST, DELETE"})
                return self._handle_get_sse(headers, principal, base_headers)
            if method == "DELETE":
                if self._session_store is None:
                    return MCPHTTPResponse(405, {**base_headers, "Allow": "POST"})
                return self._handle_delete_session(headers, principal, base_headers)
            if method != "POST":
                return MCPHTTPResponse(405, {**base_headers, "Allow": "POST"})
            self._validate_post_headers(headers, len(request.body))
            try:
                message = _json_object(request.body)
            except MCPHTTPError as error:
                return _jsonrpc_http_response(
                    400,
                    None,
                    _JSONRPC_PARSE_ERROR,
                    "invalid JSON-RPC payload",
                    error.reason_code,
                    base_headers,
                )
            shape_error = _jsonrpc_shape_error(message)
            if shape_error is not None:
                return _jsonrpc_http_response(
                    400,
                    message.get("id"),
                    _JSONRPC_INVALID_REQUEST,
                    "invalid JSON-RPC request shape",
                    shape_error,
                    base_headers,
                )
            protocol_error = self._validate_protocol(message, headers)
            if protocol_error is not None:
                return protocol_error
            lifecycle = self._handle_lifecycle(message, principal, headers, base_headers)
            if lifecycle is not None:
                return lifecycle
            method_name = message.get("method")
            if method_name not in {"tools/list", "tools/call"}:
                if "id" not in message:
                    return MCPHTTPResponse(400, base_headers)
                return _jsonrpc_http_response(
                    200,
                    message.get("id"),
                    _JSONRPC_METHOD_NOT_FOUND,
                    "method not supported by the Agent Interlock Tool gateway",
                    "MCP-METHOD-NOT-SUPPORTED",
                    base_headers,
                )
            if not self._ready(principal, headers):
                return _jsonrpc_http_response(
                    400,
                    message.get("id"),
                    _JSONRPC_INVALID_REQUEST,
                    "MCP lifecycle initialization is not complete",
                    "MCP-LIFECYCLE-NOT-INITIALIZED",
                    base_headers,
                )
            context = None
            if method_name == "tools/call":
                context = self._context_resolver(principal, message)
                if context is None:
                    return _jsonrpc_http_response(
                        200,
                        message.get("id"),
                        _INTERLOCK_NOT_CONFIGURED,
                        "trusted invocation context is unavailable",
                        "INTERLOCK-TRUSTED-CONTEXT-MISSING",
                        base_headers,
                    )
                if context.tenant_id != principal.tenant_id or context.source_actor_id != principal.actor_id:
                    return _jsonrpc_http_response(
                        200,
                        message.get("id"),
                        _INTERLOCK_NOT_CONFIGURED,
                        "trusted context does not match the authenticated principal",
                        "INTERLOCK-PRINCIPAL-CONTEXT-MISMATCH",
                        base_headers,
                    )
            response = self.adapter.handle_client_message(message, context=context)
            if response is None:
                return MCPHTTPResponse(202, base_headers)
            return MCPHTTPResponse(
                200,
                {**base_headers, "Content-Type": "application/json"},
                _json_bytes(response),
            )
        except _InboundHTTPError as error:
            headers = dict(base_headers)
            if error.status == 401:
                headers["WWW-Authenticate"] = "Bearer"
            return MCPHTTPResponse(error.status, headers)

    def _validate_host(self, headers: Mapping[str, str]) -> None:
        host = headers.get("host")
        if not host:
            raise _InboundHTTPError(400)
        try:
            canonical = _canonical_host_header(host)
        except ValueError as error:
            raise _InboundHTTPError(400) from error
        if canonical not in self._allowed_hosts:
            raise _InboundHTTPError(421)

    def _validate_origin(self, headers: Mapping[str, str]) -> None:
        origin = headers.get("origin")
        if not origin:
            if self.config.require_origin:
                raise _InboundHTTPError(403)
            return
        try:
            canonical = _canonical_origin(origin)
        except ValueError as error:
            raise _InboundHTTPError(403) from error
        if canonical not in self._allowed_origins:
            raise _InboundHTTPError(403)

    def _authenticate(self, headers: Mapping[str, str]) -> MCPHTTPPrincipal:
        principal = self._authenticator(headers.get("authorization"))
        if principal is None:
            raise _InboundHTTPError(401)
        return principal

    def _validate_post_headers(self, headers: Mapping[str, str], body_length: int) -> None:
        if "transfer-encoding" in headers:
            raise _InboundHTTPError(400)
        if body_length > self.config.max_request_bytes:
            raise _InboundHTTPError(413)
        content_type = _media_type(headers.get("content-type"))
        if content_type != "application/json":
            raise _InboundHTTPError(415)
        accepted = _accepted_media_types(headers.get("accept", ""))
        if not {"application/json", "text/event-stream"}.issubset(accepted):
            raise _InboundHTTPError(406)

    def _validate_protocol(
        self,
        message: Mapping[str, Any],
        headers: Mapping[str, str],
    ) -> MCPHTTPResponse | None:
        method = message.get("method")
        header_version = headers.get("mcp-protocol-version")
        if method == "initialize":
            params = message.get("params")
            requested = params.get("protocolVersion") if isinstance(params, Mapping) else None
            if requested != self.config.protocol_version:
                return _jsonrpc_http_response(
                    400,
                    message.get("id"),
                    _JSONRPC_INVALID_REQUEST,
                    "unsupported MCP protocol version",
                    "MCP-LIFECYCLE-VERSION-UNSUPPORTED",
                    {},
                )
            if header_version is not None and header_version != self.config.protocol_version:
                raise _InboundHTTPError(400)
            return None
        if header_version != self.config.protocol_version:
            raise _InboundHTTPError(400)
        return None

    def _handle_lifecycle(
        self,
        message: Mapping[str, Any],
        principal: MCPHTTPPrincipal,
        headers: Mapping[str, str],
        base_headers: Mapping[str, str],
    ) -> MCPHTTPResponse | None:
        method = message.get("method")
        key = self._principal_key(principal)
        if method == "initialize":
            if "id" not in message:
                return _jsonrpc_http_response(
                    400,
                    None,
                    _JSONRPC_INVALID_REQUEST,
                    "initialize must be a JSON-RPC request",
                    "MCP-LIFECYCLE-INITIALIZE-ID-MISSING",
                    base_headers,
                )
            result_headers = {**base_headers, "Content-Type": "application/json"}
            if self._session_store is not None:
                session_id = _new_session_id()
                self._session_store.create(session_id, key)
                result_headers["MCP-Session-Id"] = session_id
            else:
                with self._lifecycle_lock:
                    self._lifecycle[key] = "INITIALIZING"
            result = {
                "protocolVersion": self.config.protocol_version,
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "agent-interlock", "version": "0.1.0"},
            }
            return MCPHTTPResponse(
                200,
                result_headers,
                _json_bytes({"jsonrpc": "2.0", "id": message.get("id"), "result": result}),
            )
        if method == "notifications/initialized":
            if "id" in message:
                return _jsonrpc_http_response(
                    400,
                    message.get("id"),
                    _JSONRPC_INVALID_REQUEST,
                    "initialized must be a JSON-RPC notification",
                    "MCP-LIFECYCLE-INITIALIZED-ID-PRESENT",
                    base_headers,
                )
            if self._session_store is not None:
                session_id = self._session_id_from_headers(headers)
                if session_id is None or not self._session_store.mark_ready(session_id, key):
                    return _jsonrpc_http_response(
                        400,
                        None,
                        _JSONRPC_INVALID_REQUEST,
                        "initialized notification has no matching initialize request",
                        "MCP-LIFECYCLE-ORDER-INVALID",
                        base_headers,
                    )
                return MCPHTTPResponse(202, base_headers)
            with self._lifecycle_lock:
                if self._lifecycle.get(key) != "INITIALIZING":
                    return _jsonrpc_http_response(
                        400,
                        None,
                        _JSONRPC_INVALID_REQUEST,
                        "initialized notification has no matching initialize request",
                        "MCP-LIFECYCLE-ORDER-INVALID",
                        base_headers,
                    )
                self._lifecycle[key] = "READY"
            return MCPHTTPResponse(202, base_headers)
        if method == "ping":
            if "id" not in message:
                return MCPHTTPResponse(400, base_headers)
            return MCPHTTPResponse(
                200,
                {**base_headers, "Content-Type": "application/json"},
                _json_bytes({"jsonrpc": "2.0", "id": message.get("id"), "result": {}}),
            )
        return None

    def _ready(self, principal: MCPHTTPPrincipal, headers: Mapping[str, str]) -> bool:
        key = self._principal_key(principal)
        if self._session_store is not None:
            session_id = self._session_id_from_headers(headers)
            return session_id is not None and self._session_store.state(session_id, key) == "READY"
        with self._lifecycle_lock:
            return self._lifecycle.get(key) == "READY"

    def _handle_get_sse(
        self,
        headers: Mapping[str, str],
        principal: MCPHTTPPrincipal,
        base_headers: Mapping[str, str],
    ) -> MCPHTTPResponse:
        assert self._session_store is not None
        session_id = self._session_id_from_headers(headers)
        if session_id is None:
            raise _InboundHTTPError(400)
        key = self._principal_key(principal)
        if self._session_store.state(session_id, key) is None:
            raise _InboundHTTPError(404)
        after = _parse_last_event_id(headers.get("last-event-id"))
        events = self._session_store.replay(session_id, key, after)
        body = b"".join(_sse_frame(sequence, message) for sequence, message in events)
        return MCPHTTPResponse(200, {**base_headers, "Content-Type": "text/event-stream"}, body)

    def _handle_delete_session(
        self,
        headers: Mapping[str, str],
        principal: MCPHTTPPrincipal,
        base_headers: Mapping[str, str],
    ) -> MCPHTTPResponse:
        assert self._session_store is not None
        session_id = self._session_id_from_headers(headers)
        if session_id is None:
            raise _InboundHTTPError(400)
        self._session_store.delete(session_id, self._principal_key(principal))
        return MCPHTTPResponse(200, base_headers)

    def enqueue_server_notification(
        self,
        session_id: str,
        principal: MCPHTTPPrincipal,
        message: Mapping[str, Any],
    ) -> int:
        """Buffer a server->client JSON-RPC notification for resumable SSE replay."""
        if self._session_store is None:
            raise MCPHTTPError("MCP-HTTP-SESSION-STORE-DISABLED", "server push requires a session store")
        if "id" in message or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            raise MCPHTTPError("MCP-SSE-SERVER-MESSAGE-INVALID", "server push must be a JSON-RPC notification")
        return self._session_store.append(session_id, self._principal_key(principal), dict(message))

    def _session_id_from_headers(self, headers: Mapping[str, str]) -> str | None:
        raw = headers.get("mcp-session-id")
        if raw is None:
            return None
        try:
            return _validated_session_id(raw)
        except MCPHTTPError:
            return None

    @staticmethod
    def _principal_key(principal: MCPHTTPPrincipal) -> tuple[str, str, str]:
        return principal.tenant_id, principal.actor_id, principal.subject


class _InboundHTTPError(RuntimeError):
    def __init__(self, status: int) -> None:
        super().__init__(f"inbound MCP HTTP request rejected with status {status}")
        self.status = status


def create_mcp_http_server(
    carrier: MCPStreamableHTTPGatewayCarrier,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    if not carrier.config.allow_non_loopback_bind and not _is_loopback_host(host):
        raise ValueError("the reference HTTP server binds only to loopback by default")

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._write(MCPHTTPResponse(400, {}))
                return
            if length < 0 or length > carrier.config.max_request_bytes:
                self._write(MCPHTTPResponse(413, {}))
                return
            body = self.rfile.read(length)
            self._dispatch(body)

        def do_GET(self) -> None:
            self._dispatch(b"")

        def do_DELETE(self) -> None:
            self._dispatch(b"")

        def _dispatch(self, body: bytes) -> None:
            request = MCPHTTPRequest(
                method=self.command,
                path=self.path,
                headers={key: value for key, value in self.headers.items()},
                body=body,
                remote_addr=self.client_address[0],
            )
            self._write(carrier.handle(request))

        def _write(self, response: MCPHTTPResponse) -> None:
            self.send_response(response.status)
            headers = dict(response.headers)
            headers["Content-Length"] = str(len(response.body))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            if response.body:
                self.wfile.write(response.body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    return ThreadingHTTPServer((host, port), Handler)


def _validate_endpoint(value: str, *, allow_loopback_http: bool) -> None:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid MCP endpoint") from error
    if not host or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("MCP endpoint must not contain credentials, query, or fragment")
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and allow_loopback_http and _is_loopback_host(host):
        if port is None:
            raise ValueError("loopback HTTP endpoint must use an explicit port")
        return
    raise ValueError("MCP endpoint must use HTTPS; explicit-port loopback HTTP is test-only")


def _is_loopback_host(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise MCPHTTPError("MCP-HTTP-JSON-INVALID", "value is not valid JSON") from error


def _json_object(payload: bytes) -> Mapping[str, Any]:
    try:
        parsed = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MCPHTTPError("MCP-HTTP-JSON-INVALID", "payload is not valid UTF-8 JSON") from error
    if isinstance(parsed, list) or not isinstance(parsed, Mapping) or parsed.get("jsonrpc") != "2.0":
        raise MCPHTTPError("MCP-HTTP-JSONRPC-INVALID", "payload must be one JSON-RPC 2.0 object")
    return dict(parsed)


def _jsonrpc_shape_error(message: Mapping[str, Any]) -> str | None:
    method = message.get("method")
    if not isinstance(method, str) or not method:
        return "MCP-JSONRPC-METHOD-INVALID"
    request_id = message.get("id")
    if "id" in message and (
        not isinstance(request_id, (str, int)) or isinstance(request_id, bool)
    ):
        return "MCP-JSONRPC-ID-INVALID"
    if "params" in message and not isinstance(message["params"], Mapping):
        return "MCP-JSONRPC-PARAMS-INVALID"
    return None


def _read_limited(response, limit: int) -> bytes:  # noqa: ANN001
    payload = response.read(limit + 1)
    if len(payload) > limit:
        raise MCPHTTPError("MCP-HTTP-RESPONSE-TOO-LARGE", "downstream response exceeds the size limit")
    return payload


def _validate_response_id(request: Mapping[str, Any], response: Mapping[str, Any]) -> None:
    if "id" in request and response.get("id") != request.get("id"):
        raise MCPHTTPError("MCP-HTTP-RESPONSE-ID-MISMATCH", "JSON-RPC response id mismatch")
    if "id" not in request:
        raise MCPHTTPError("MCP-HTTP-NOTIFICATION-STATUS-INVALID", "notification must receive HTTP 202")


def _validated_session_id(value: str) -> str:
    if len(value) > 1024 or not _visible_ascii(value):
        raise MCPHTTPError("MCP-HTTP-SESSION-ID-INVALID", "MCP session id must be visible ASCII")
    return value


def _new_session_id() -> str:
    return secrets.token_urlsafe(24)


def _sse_frame(event_id: int, message: Mapping[str, Any]) -> bytes:
    data = json.dumps(message, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    return f"id: {event_id}\ndata: {data}\n\n".encode("utf-8")


def _parse_last_event_id(value: str | None) -> int | None:
    if value is None:
        return None
    if not value.isascii() or not value.isdigit():
        raise _InboundHTTPError(400)
    return int(value)


def _visible_ascii(value: str) -> bool:
    return bool(value) and all(0x21 <= ord(character) <= 0x7E for character in value)


def _safe_header_value(value: str) -> bool:
    return bool(value) and len(value) <= 8192 and "\r" not in value and "\n" not in value


def _media_type(value: str | None) -> str:
    return (value or "").split(";", 1)[0].strip().casefold()


def _accepted_media_types(value: str) -> set[str]:
    return {item.split(";", 1)[0].strip().casefold() for item in value.split(",") if item.strip()}


def _lower_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(key).casefold(): str(value).strip() for key, value in headers.items()}


def _canonical_host(value: str) -> str:
    try:
        host = value.strip().rstrip(".").encode("idna").decode("ascii").casefold()
    except UnicodeError as error:
        raise ValueError("invalid host") from error
    if not host:
        raise ValueError("host is required")
    return host


def _canonical_host_header(value: str) -> str:
    parsed = urlsplit(f"//{value}")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("invalid Host header")
    return _canonical_host(parsed.hostname)


def _canonical_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("invalid Origin")
    if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("invalid Origin")
    host = _canonical_host(parsed.hostname)
    default = 443 if parsed.scheme == "https" else 80
    port = f":{parsed.port}" if parsed.port and parsed.port != default else ""
    return f"{parsed.scheme.casefold()}://{host}{port}"


def _jsonrpc_http_response(
    status: int,
    request_id: Any,
    code: int,
    message: str,
    reason_code: str,
    base_headers: Mapping[str, str],
) -> MCPHTTPResponse:
    clean_message, _ = sanitize_secrets(message)
    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": clean_message,
            "data": {"reasonCode": reason_code},
        },
    }
    return MCPHTTPResponse(
        status,
        {**base_headers, "Content-Type": "application/json"},
        _json_bytes(body),
    )
