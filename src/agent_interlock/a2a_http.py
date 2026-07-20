"""Authenticated HTTP carrier for the policy-bound A2A JSON-RPC router."""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol
from urllib.parse import urlsplit

from .a2a import A2AJSONRPCRouter, A2APrincipal


class A2AHTTPError(RuntimeError):
    def __init__(self, status: int, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.reason_code = reason_code


class A2AHTTPAuthenticator(Protocol):
    def authenticate(self, authorization: str) -> A2APrincipal: ...


class StaticBearerA2AAuthenticator:
    """Small test/dev authenticator; production adapters should verify JWTs."""

    def __init__(self, principals_by_token: Mapping[str, A2APrincipal]) -> None:
        if not principals_by_token:
            raise ValueError("at least one bearer token is required")
        self._principals = dict(principals_by_token)

    def authenticate(self, authorization: str) -> A2APrincipal:
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token:
            raise A2AHTTPError(401, "A2A-AUTH-REQUIRED", "a bearer credential is required")
        for expected, principal in self._principals.items():
            if hmac.compare_digest(token, expected):
                return principal
        raise A2AHTTPError(401, "A2A-AUTH-INVALID", "bearer credential is invalid")


@dataclass(frozen=True, slots=True)
class A2AHTTPConfig:
    rpc_path: str = "/a2a"
    agent_card_path: str = "/.well-known/agent-card.json"
    max_request_bytes: int = 1_048_576
    allowed_origins: frozenset[str] = frozenset()
    public_agent_card: bool = True
    supported_protocol_versions: frozenset[str] = frozenset({"1.0"})

    def __post_init__(self) -> None:
        if not self.rpc_path.startswith("/") or not self.agent_card_path.startswith("/"):
            raise ValueError("A2A HTTP paths must be absolute")
        if self.max_request_bytes < 1:
            raise ValueError("A2A max_request_bytes must be positive")
        if not self.supported_protocol_versions or any(
            re.fullmatch(r"[0-9]+\.[0-9]+", version) is None
            for version in self.supported_protocol_versions
        ):
            raise ValueError("A2A supported protocol versions must use Major.Minor format")
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.path not in {"", "/"}:
                raise ValueError("A2A allowed origins must be canonical HTTP origins")


class _A2AHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        router: A2AJSONRPCRouter,
        authenticator: A2AHTTPAuthenticator,
        config: A2AHTTPConfig,
    ) -> None:
        self.router = router
        self.authenticator = authenticator
        self.config = config
        super().__init__(address, _A2ARequestHandler)


class _A2ARequestHandler(BaseHTTPRequestHandler):
    server: _A2AHTTPServer

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        try:
            if urlsplit(self.path).path != self.server.config.agent_card_path:
                raise A2AHTTPError(404, "A2A-ROUTE-NOT-FOUND", "route not found")
            self._check_origin()
            if not self.server.config.public_agent_card:
                self._authenticate()
            self._send_json(200, self.server.router.broker.agent_card(self.server.router.target_actor_id).to_dict())
        except A2AHTTPError as error:
            self._send_http_error(error)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        try:
            if urlsplit(self.path).path != self.server.config.rpc_path:
                raise A2AHTTPError(404, "A2A-ROUTE-NOT-FOUND", "route not found")
            self._check_origin()
            principal = self._authenticate()
            protocol_version = self._protocol_version()
            request = self._read_json()
            if not isinstance(request, Mapping):
                raise A2AHTTPError(400, "A2A-JSONRPC-INVALID", "A2A request must be an object")
            self._send_json(
                200,
                self.server.router.handle(request, principal, protocol_version=protocol_version),
            )
        except A2AHTTPError as error:
            self._send_http_error(error)

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib handler API
        try:
            self._check_origin()
            self.send_response(204)
            self._send_common_headers(content_type=None, content_length=0)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header(
                "Access-Control-Allow-Headers",
                "Authorization, Content-Type, A2A-Version, A2A-Extensions",
            )
            self.end_headers()
        except A2AHTTPError as error:
            self._send_http_error(error)

    def _authenticate(self) -> A2APrincipal:
        return self.server.authenticator.authenticate(self.headers.get("Authorization", ""))

    def _check_origin(self) -> None:
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.config.allowed_origins:
            raise A2AHTTPError(403, "A2A-ORIGIN-DENIED", "browser origin is not allowed")

    def _protocol_version(self) -> str:
        requested = self.headers.get("A2A-Version") or "0.3"
        if requested not in self.server.config.supported_protocol_versions:
            supported = ", ".join(sorted(self.server.config.supported_protocol_versions))
            raise A2AHTTPError(
                400,
                "A2A-VERSION-NOT-SUPPORTED",
                f"A2A protocol version {requested} is not supported; supported: {supported}",
            )
        return requested

    def _read_json(self) -> Any:
        if self.headers.get("Transfer-Encoding"):
            raise A2AHTTPError(400, "A2A-TRANSFER-ENCODING-DENIED", "chunked request bodies are not accepted")
        content_type = self.headers.get_content_type()
        if content_type != "application/json":
            raise A2AHTTPError(415, "A2A-CONTENT-TYPE", "content type must be application/json")
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "")
        except ValueError as error:
            raise A2AHTTPError(411, "A2A-CONTENT-LENGTH", "a valid Content-Length is required") from error
        if length < 1 or length > self.server.config.max_request_bytes:
            raise A2AHTTPError(413, "A2A-REQUEST-TOO-LARGE", "A2A request body is outside the allowed size")
        body = self.rfile.read(length)
        if len(body) != length:
            raise A2AHTTPError(400, "A2A-BODY-INCOMPLETE", "A2A request body is incomplete")
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise A2AHTTPError(400, "A2A-JSON-INVALID", "A2A request body is not valid JSON") from error

    def _send_json(self, status: int, value: Mapping[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._send_common_headers(content_type="application/json; charset=utf-8", content_length=len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_http_error(self, error: A2AHTTPError) -> None:
        headers = {}
        if error.status == 401:
            headers["WWW-Authenticate"] = 'Bearer realm="a2a"'
        body = json.dumps(
            {"error": {"code": error.reason_code, "message": str(error)}},
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(error.status)
        self._send_common_headers(content_type="application/json; charset=utf-8", content_length=len(body))
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_common_headers(self, *, content_type: str | None, content_length: int) -> None:
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        origin = self.headers.get("Origin")
        if origin and origin in self.server.config.allowed_origins:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        protocol_version = self.headers.get("A2A-Version")
        if protocol_version in self.server.config.supported_protocol_versions:
            self.send_header("A2A-Version", protocol_version)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        return


def create_a2a_http_server(
    host: str,
    port: int,
    *,
    router: A2AJSONRPCRouter,
    authenticator: A2AHTTPAuthenticator,
    config: A2AHTTPConfig | None = None,
) -> ThreadingHTTPServer:
    """Create a threaded A2A HTTP server; the caller controls its lifecycle."""

    return _A2AHTTPServer((host, port), router, authenticator, config or A2AHTTPConfig())
