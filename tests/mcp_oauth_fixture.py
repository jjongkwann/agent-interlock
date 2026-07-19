from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

from http_test_server import QuietThreadingHTTPServer


class AdversarialOAuthServer:
    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.requested_paths: list[str] = []
        self.token_forms: list[dict[str, list[str]]] = []
        self.token_headers: list[dict[str, str]] = []
        self.resource_override: str | None = None
        self.issuer_override: str | None = None
        self.pkce_methods: list[str] | None = ["S256"]
        self.metadata_redirect_location: str | None = None
        self.token_redirect_location: str | None = None
        self.access_token = "downstream-token-secret"
        self.token_scopes = "mcp.read mcp.call"

    @property
    def base_url(self) -> str:
        if self._server is None:
            raise RuntimeError("fixture is not running")
        return f"http://127.0.0.1:{self._server.server_port}"

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/mcp"

    @property
    def issuer(self) -> str:
        return f"{self.base_url}/issuer"

    @property
    def resource_metadata_url(self) -> str:
        return f"{self.base_url}/.well-known/oauth-protected-resource/mcp"

    def start(self) -> AdversarialOAuthServer:
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                fixture.requested_paths.append(self.path)
                if self.path == "/redirect-metadata":
                    self._write(
                        302,
                        headers={"Location": fixture.metadata_redirect_location or fixture.resource_metadata_url},
                    )
                    return
                if self.path == "/.well-known/oauth-protected-resource/mcp":
                    self._json(
                        {
                            "resource": fixture.resource_override or fixture.endpoint,
                            "authorization_servers": [fixture.issuer],
                            "scopes_supported": ["mcp.read", "mcp.call"],
                        }
                    )
                    return
                if self.path == "/.well-known/oauth-protected-resource":
                    self._write(404)
                    return
                if self.path == "/.well-known/oauth-authorization-server/issuer":
                    metadata: dict[str, Any] = {
                        "issuer": fixture.issuer_override or fixture.issuer,
                        "authorization_endpoint": f"{fixture.base_url}/authorize",
                        "token_endpoint": f"{fixture.base_url}/token",
                        "scopes_supported": ["mcp.read", "mcp.call"],
                    }
                    if fixture.pkce_methods is not None:
                        metadata["code_challenge_methods_supported"] = fixture.pkce_methods
                    self._json(metadata)
                    return
                if self.path in {
                    "/.well-known/openid-configuration/issuer",
                    "/issuer/.well-known/openid-configuration",
                }:
                    self._write(404)
                    return
                self._write(404)

            def do_POST(self) -> None:
                if self.path != "/token":
                    self._write(404)
                    return
                length = int(self.headers.get("Content-Length", "0"))
                payload = self.rfile.read(length).decode("ascii")
                fixture.token_forms.append(parse_qs(payload, keep_blank_values=True))
                fixture.token_headers.append({key.casefold(): value for key, value in self.headers.items()})
                if fixture.token_redirect_location:
                    self._write(307, headers={"Location": fixture.token_redirect_location})
                    return
                self._json(
                    {
                        "access_token": fixture.access_token,
                        "token_type": "Bearer",
                        "expires_in": 300,
                        "scope": fixture.token_scopes,
                    }
                )

            def _json(self, value: dict[str, Any]) -> None:
                payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
                self._write(200, payload, {"Content-Type": "application/json"})

            def _write(
                self,
                status: int,
                payload: bytes = b"",
                headers: dict[str, str] | None = None,
            ) -> None:
                self.send_response(status)
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if payload:
                    self.wfile.write(payload)

            def log_message(self, fmt: str, *args: Any) -> None:
                return

        self._server = QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=lambda: self._server.serve_forever(poll_interval=0.01),
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self._server = None
        self._thread = None

    def __enter__(self) -> AdversarialOAuthServer:
        return self.start()

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        self.stop()
