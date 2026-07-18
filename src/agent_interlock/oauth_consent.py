"""Loopback OAuth consent helper: open the authorization URL, catch the callback.

The reference core cannot drive a user's browser, but it can host the RFC 8252
loopback redirect endpoint. `run_consent` opens ``transaction.authorization_uri``
(via ``webbrowser`` by default) and blocks on a 127.0.0.1 listener until the
browser is redirected back, returning the exact one-time callback URI to hand to
``MCPAuthorizationCodeFlow.validate_callback``. The receiver captures exactly
one callback; a second hit is refused.
"""

from __future__ import annotations

import sys
import threading
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class OAuthConsentError(RuntimeError):
    pass


class _QuietLoopbackServer(ThreadingHTTPServer):
    """Loopback server that does not print a traceback on client reset.

    A browser that closes the tab, or a refused second callback, resets the
    connection; the default handler would spew a stack trace to stderr. Real
    handler errors still propagate.
    """

    def handle_error(self, request, client_address):  # noqa: ANN001
        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)


def _bracket(host: str) -> str:
    return f"[{host}]" if ":" in host else host


class LoopbackCallbackReceiver:
    """Single-use loopback HTTP endpoint that captures one OAuth redirect."""

    def __init__(self, *, host: str = "127.0.0.1", port: int = 0, path: str = "/callback") -> None:
        if host not in {"127.0.0.1", "::1"}:
            raise ValueError("loopback callback receiver binds only to a loopback host")
        if not path.startswith("/") or "?" in path or "#" in path:
            raise ValueError("callback path must be an absolute path without query or fragment")
        self._host = host
        self._path = path
        self._captured: str | None = None
        self._event = threading.Event()
        self._lock = threading.Lock()
        receiver = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                if self.path.split("?", 1)[0] != receiver._path:
                    return self._respond(404, "not found")
                with receiver._lock:
                    if receiver._captured is not None:
                        return self._respond(409, "callback already received")
                    receiver._captured = f"http://{_bracket(receiver._host)}:{receiver.port}{self.path}"
                    receiver._event.set()
                self._respond(200, "Authorization received. You may close this window.")

            def _respond(self, status: int, message: str) -> None:
                body = message.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args) -> None:
                return

        self._server = _QuietLoopbackServer((host, port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def redirect_uri(self) -> str:
        return f"http://{_bracket(self._host)}:{self.port}{self._path}"

    def wait_for_callback(self, *, timeout: float = 300.0) -> str:
        if not self._event.wait(timeout):
            raise OAuthConsentError("timed out waiting for the OAuth callback")
        assert self._captured is not None
        return self._captured

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)

    def __enter__(self) -> "LoopbackCallbackReceiver":
        return self

    def __exit__(self, *_args) -> None:
        self.close()


def run_consent(
    authorization_uri: str,
    receiver: LoopbackCallbackReceiver,
    *,
    opener: Callable[[str], Any] = webbrowser.open,
    timeout: float = 300.0,
) -> str:
    """Open the authorization URL and return the one-time callback URI."""
    opener(authorization_uri)
    return receiver.wait_for_callback(timeout=timeout)
