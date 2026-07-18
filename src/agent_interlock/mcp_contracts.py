"""Neutral MCP state contracts shared by the transport and storage layers.

The transport carriers (``mcp_http``, ``mcp_oauth``) define the inbound session
and OAuth-transaction lifecycle; the storage adapters (``postgres_stores``)
persist it across gateway instances. Both need the same transaction shape, the
same store protocols, and the same error types. Housing those here keeps the
storage layer from importing *up* into the transport layer (a layer inversion):
transport and storage now depend on a shared, lower contract module instead.

``mcp_http`` and ``mcp_oauth`` re-export these names, so their public API — and
every ``from agent_interlock import ...`` — is unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

_PrincipalKey = tuple[str, str, str]


class MCPHTTPError(RuntimeError):
    """Fail-closed MCP HTTP transport/session error with a stable reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class MCPOAuthError(RuntimeError):
    """Fail-closed OAuth error with a stable, non-secret reason code."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(slots=True)
class OAuthAuthorizationTransaction:
    client_id: str
    redirect_uri: str
    resource: str
    scopes: tuple[str, ...]
    state: str = field(repr=False)
    code_verifier: str = field(repr=False)
    authorization_uri: str = field(repr=False)
    expires_at_epoch: float
    callback_consumed: bool = False
    callback_validated: bool = False
    exchange_consumed: bool = False
    authorization_code_digest: str | None = field(default=None, repr=False)


class SessionStore(Protocol):
    """Session lifecycle + resumable SSE event buffer, keyed by MCP-Session-Id.

    An implementation makes the inbound lifecycle and server-push replay survive
    across gateway instances. The in-process reference is single-node; a
    Redis/Postgres backend implements the same contract for multi-instance.
    """

    def create(self, session_id: str, principal_key: _PrincipalKey) -> None: ...

    def mark_ready(self, session_id: str, principal_key: _PrincipalKey) -> bool: ...

    def state(self, session_id: str, principal_key: _PrincipalKey) -> str | None: ...

    def append(self, session_id: str, principal_key: _PrincipalKey, message: Mapping[str, Any]) -> int: ...

    def replay(
        self, session_id: str, principal_key: _PrincipalKey, after: int | None
    ) -> tuple[tuple[int, Mapping[str, Any]], ...]: ...

    def delete(self, session_id: str, principal_key: _PrincipalKey) -> bool: ...


class OAuthTransactionStore(Protocol):
    """One-time-consume store for pending OAuth authorization transactions.

    A distributed implementation makes state/code callbacks single-use across
    gateway instances, so a callback cannot be replayed on a different node.
    """

    def put(self, transaction: OAuthAuthorizationTransaction) -> None: ...

    def consume(self, state: str) -> OAuthAuthorizationTransaction | None: ...

    def delete(self, state: str) -> None: ...
