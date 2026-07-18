"""Shared quiet HTTP server for test fixtures."""

from __future__ import annotations

import sys
from http.server import ThreadingHTTPServer


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that does not print a traceback on client reset.

    SSRF, redirect, and JWKS tests deliberately abort connections early; the
    default ``socketserver.handle_error`` prints a full stack trace to stderr
    for those, which is test noise rather than a failure. Genuine handler
    errors still propagate.
    """

    def handle_error(self, request, client_address):  # noqa: ANN001
        error = sys.exc_info()[1]
        if isinstance(error, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            return
        super().handle_error(request, client_address)
