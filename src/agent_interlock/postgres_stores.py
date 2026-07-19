"""PostgreSQL-backed distributed Session/OAuth-Transaction/Config stores.

Each adapter implements the corresponding in-memory Protocol so a multi-node
gateway deployment shares session lifecycle, one-time OAuth transactions and
active agent-config revisions. The tenant model mirrors ``postgres_ledger``:
every adapter instance is bound to one tenant, and the migration maps the
authenticated PostgreSQL ``session_user`` to that same tenant with FORCE ROW
LEVEL SECURITY, checked at the start of every transaction.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import UTC, datetime
from typing import Any, Iterator, Mapping

from .canonical import canonical_digest, canonical_json
from .config_guard import (
    AgentConfig,
    ConfigApproval,
    ConfigRevision,
    ConfigRevisionState,
    ConfigStoreStale,
    ConfiguredTool,
)
from .ledger import LedgerIntegrityError
from .mcp_contracts import MCPHTTPError, MCPOAuthError, OAuthAuthorizationTransaction
from .models import DefinitionState, ToolDefinition
from .postgres_ledger import Connection, ConnectionFactory, LedgerTenantMismatch, PostgreSQLDriverUnavailable
from .registry import ToolRevision

_PrincipalKey = tuple[str, str, str]


class _PostgreSQLStoreBase:
    """Shared tenant-bound connection handling for the store adapters."""

    _APPLICATION_NAME = "agent-interlock-store"

    def __init__(self, connection_factory: ConnectionFactory, *, bound_tenant_id: str) -> None:
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        if not bound_tenant_id:
            raise ValueError("bound_tenant_id is required")
        self._connection_factory = connection_factory
        self.bound_tenant_id = bound_tenant_id

    @classmethod
    def from_dsn(cls, dsn: str, *, bound_tenant_id: str, connect_timeout_seconds: int = 5):
        if not dsn:
            raise ValueError("dsn is required")
        if not 1 <= connect_timeout_seconds <= 30:
            raise ValueError("connect_timeout_seconds must be between 1 and 30")
        try:
            import psycopg
        except ImportError as error:
            raise PostgreSQLDriverUnavailable(
                f"install the 'postgres' project extra to use {cls.__name__}.from_dsn"
            ) from error

        def connect() -> Connection:
            return psycopg.connect(
                dsn,
                autocommit=False,
                connect_timeout=connect_timeout_seconds,
                application_name=cls._APPLICATION_NAME,
            )

        return cls(connect, bound_tenant_id=bound_tenant_id)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(bound_tenant_id={self.bound_tenant_id!r})"

    def _require_bound_tenant(self, tenant_id: str) -> None:
        if tenant_id != self.bound_tenant_id:
            raise LedgerTenantMismatch("requested tenant does not match the store binding")

    @contextmanager
    def _transaction(self) -> Iterator[Connection]:
        connection = self._connection_factory()
        try:
            cursor = connection.cursor()
            try:
                cursor.execute("SELECT interlock.current_tenant()")
                row = cursor.fetchone()
            finally:
                cursor.close()
            if row is None or row[0] != self.bound_tenant_id:
                raise LedgerTenantMismatch(
                    "authenticated PostgreSQL role does not match the store tenant binding"
                )
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _execute(
        self, connection: Connection, query: str, parameters: tuple[Any, ...]
    ) -> tuple[Any, ...] | None:
        cursor = connection.cursor()
        try:
            cursor.execute(query, parameters)
            return cursor.fetchone()
        finally:
            cursor.close()

    def _execute_all(
        self, connection: Connection, query: str, parameters: tuple[Any, ...]
    ) -> list[tuple[Any, ...]]:
        cursor = connection.cursor()
        try:
            cursor.execute(query, parameters)
            return cursor.fetchall()
        finally:
            cursor.close()

    def _execute_none(self, connection: Connection, query: str, parameters: tuple[Any, ...]) -> None:
        cursor = connection.cursor()
        try:
            cursor.execute(query, parameters)
        finally:
            cursor.close()


# --------------------------------------------------------------------------- #
# SessionStore
# --------------------------------------------------------------------------- #

_INSERT_SESSION = """
INSERT INTO interlock.mcp_sessions (session_id, tenant_id, actor_id, subject)
VALUES (%s, %s, %s, %s)
ON CONFLICT (session_id) DO NOTHING
RETURNING session_id
""".strip()

_SESSION_PRINCIPAL_WHERE = "session_id = %s AND tenant_id = %s AND actor_id = %s AND subject = %s"

_MARK_READY = f"""
UPDATE interlock.mcp_sessions SET state = 'READY'
WHERE {_SESSION_PRINCIPAL_WHERE} AND state = 'INITIALIZING'
RETURNING session_id
""".strip()

_SESSION_STATE = f"SELECT state FROM interlock.mcp_sessions WHERE {_SESSION_PRINCIPAL_WHERE}"

_NEXT_SEQUENCE = f"""
UPDATE interlock.mcp_sessions SET sequence = sequence + 1
WHERE {_SESSION_PRINCIPAL_WHERE}
RETURNING sequence
""".strip()

_INSERT_SESSION_EVENT = """
INSERT INTO interlock.mcp_session_events (session_id, tenant_id, event_seq, message)
VALUES (%s, %s, %s, %s::jsonb)
""".strip()

_REPLAY_EVENTS = """
SELECT event_seq, message::text FROM interlock.mcp_session_events
WHERE session_id = %s AND tenant_id = %s AND event_seq > %s
ORDER BY event_seq
""".strip()

_DELETE_SESSION = f"DELETE FROM interlock.mcp_sessions WHERE {_SESSION_PRINCIPAL_WHERE} RETURNING session_id"


class PostgreSQLSessionStore(_PostgreSQLStoreBase):
    """SessionStore backend making inbound MCP sessions survive across nodes."""

    _APPLICATION_NAME = "agent-interlock-session-store"

    def create(self, session_id: str, principal_key: _PrincipalKey) -> None:
        self._require_bound_tenant(principal_key[0])
        with self._transaction() as connection:
            row = self._execute(connection, _INSERT_SESSION, (session_id, *principal_key))
            if row is None:
                raise MCPHTTPError("MCP-HTTP-SESSION-DUPLICATE", "session id already exists")

    def mark_ready(self, session_id: str, principal_key: _PrincipalKey) -> bool:
        self._require_bound_tenant(principal_key[0])
        with self._transaction() as connection:
            return self._execute(connection, _MARK_READY, (session_id, *principal_key)) is not None

    def state(self, session_id: str, principal_key: _PrincipalKey) -> str | None:
        self._require_bound_tenant(principal_key[0])
        with self._transaction() as connection:
            row = self._execute(connection, _SESSION_STATE, (session_id, *principal_key))
        return None if row is None else str(row[0])

    def append(self, session_id: str, principal_key: _PrincipalKey, message: Mapping[str, Any]) -> int:
        self._require_bound_tenant(principal_key[0])
        with self._transaction() as connection:
            row = self._execute(connection, _NEXT_SEQUENCE, (session_id, *principal_key))
            if row is None:
                raise MCPHTTPError("MCP-HTTP-SESSION-NOT-FOUND", "session not found")
            sequence = int(row[0])
            self._execute_none(
                connection,
                _INSERT_SESSION_EVENT,
                (session_id, principal_key[0], sequence, canonical_json(dict(message)).decode("utf-8")),
            )
        return sequence

    def replay(
        self, session_id: str, principal_key: _PrincipalKey, after: int | None
    ) -> tuple[tuple[int, Mapping[str, Any]], ...]:
        self._require_bound_tenant(principal_key[0])
        with self._transaction() as connection:
            if self._execute(connection, _SESSION_STATE, (session_id, *principal_key)) is None:
                return ()
            rows = self._execute_all(
                connection, _REPLAY_EVENTS, (session_id, principal_key[0], after or 0)
            )
        return tuple((int(seq), json.loads(message)) for seq, message in rows)

    def delete(self, session_id: str, principal_key: _PrincipalKey) -> bool:
        self._require_bound_tenant(principal_key[0])
        with self._transaction() as connection:
            return self._execute(connection, _DELETE_SESSION, (session_id, *principal_key)) is not None


# --------------------------------------------------------------------------- #
# OAuthTransactionStore
# --------------------------------------------------------------------------- #

_INSERT_TRANSACTION = """
INSERT INTO interlock.oauth_transactions (state, tenant_id, transaction, expires_at)
VALUES (%s, %s, %s::jsonb, %s::timestamptz)
ON CONFLICT (state) DO NOTHING
RETURNING state
""".strip()

_CONSUME_TRANSACTION = """
DELETE FROM interlock.oauth_transactions
WHERE state = %s AND tenant_id = %s
RETURNING transaction::text
""".strip()

_DELETE_TRANSACTION = "DELETE FROM interlock.oauth_transactions WHERE state = %s AND tenant_id = %s"

_PURGE_TRANSACTIONS = """
DELETE FROM interlock.oauth_transactions
WHERE tenant_id = %s AND expires_at < %s::timestamptz
""".strip()


def _transaction_value(transaction: OAuthAuthorizationTransaction) -> dict[str, Any]:
    value = asdict(transaction)
    value["scopes"] = list(transaction.scopes)
    return value


def _transaction_from(value: Mapping[str, Any]) -> OAuthAuthorizationTransaction:
    fields = dict(value)
    fields["scopes"] = tuple(fields["scopes"])
    return OAuthAuthorizationTransaction(**fields)


class PostgreSQLOAuthTransactionStore(_PostgreSQLStoreBase):
    """One-time-consume OAuth transaction store; a callback replayed on any
    node finds the row already deleted."""

    _APPLICATION_NAME = "agent-interlock-oauth-store"

    def put(self, transaction: OAuthAuthorizationTransaction) -> None:
        expires_at = datetime.fromtimestamp(transaction.expires_at_epoch, UTC).isoformat()
        with self._transaction() as connection:
            row = self._execute(
                connection,
                _INSERT_TRANSACTION,
                (
                    transaction.state,
                    self.bound_tenant_id,
                    canonical_json(_transaction_value(transaction)).decode("utf-8"),
                    expires_at,
                ),
            )
            if row is None:
                raise MCPOAuthError("MCP-OAUTH-STATE-DUPLICATE", "OAuth state is already pending")

    def consume(self, state: str) -> OAuthAuthorizationTransaction | None:
        with self._transaction() as connection:
            row = self._execute(connection, _CONSUME_TRANSACTION, (state, self.bound_tenant_id))
        return None if row is None else _transaction_from(json.loads(row[0]))

    def delete(self, state: str) -> None:
        with self._transaction() as connection:
            self._execute_none(connection, _DELETE_TRANSACTION, (state, self.bound_tenant_id))

    def purge_expired(self, now_epoch: float) -> None:
        cutoff = datetime.fromtimestamp(now_epoch, UTC).isoformat()
        with self._transaction() as connection:
            self._execute_none(connection, _PURGE_TRANSACTIONS, (self.bound_tenant_id, cutoff))


# --------------------------------------------------------------------------- #
# ConfigStore
# --------------------------------------------------------------------------- #

_ACTIVE_REVISION = """
SELECT r.revision::text
FROM interlock.agent_config_active a
JOIN interlock.agent_config_revisions r
    ON r.tenant_id = a.tenant_id AND r.config_id = a.config_id AND r.revision_id = a.revision_id
WHERE a.tenant_id = %s AND a.config_id = %s
""".strip()

_ALL_REVISIONS = """
SELECT revision::text FROM interlock.agent_config_revisions
WHERE tenant_id = %s AND config_id = %s
ORDER BY seq
""".strip()

_LOCK_ACTIVE = """
SELECT revision_id, config_digest FROM interlock.agent_config_active
WHERE tenant_id = %s AND config_id = %s
FOR UPDATE
""".strip()

_SUPERSEDE_REVISION = """
UPDATE interlock.agent_config_revisions
SET state = 'SUPERSEDED', revision = jsonb_set(revision, '{state}', '"SUPERSEDED"')
WHERE tenant_id = %s AND config_id = %s AND revision_id = %s
""".strip()

_UPSERT_REVISION = """
INSERT INTO interlock.agent_config_revisions (tenant_id, config_id, revision_id, config_digest, state, revision)
VALUES (%s, %s, %s, %s, 'ACTIVE', %s::jsonb)
ON CONFLICT (tenant_id, config_id, revision_id)
    DO UPDATE SET state = 'ACTIVE', revision = EXCLUDED.revision
""".strip()

_UPSERT_ACTIVE = """
INSERT INTO interlock.agent_config_active (tenant_id, config_id, revision_id, config_digest)
VALUES (%s, %s, %s, %s)
ON CONFLICT (tenant_id, config_id)
    DO UPDATE SET revision_id = EXCLUDED.revision_id, config_digest = EXCLUDED.config_digest
""".strip()


def _revision_value(revision: ConfigRevision) -> dict[str, Any]:
    value = asdict(revision)
    value["state"] = revision.state.value
    return value


def _revision_from(value: Mapping[str, Any]) -> ConfigRevision:
    config = value["config"]
    revision = ConfigRevision(
        revision_id=value["revision_id"],
        config=AgentConfig(
            tenant_id=config["tenant_id"],
            config_id=config["config_id"],
            agent_id=config["agent_id"],
            tools=tuple(
                ConfiguredTool(
                    definition=ToolDefinition(**tool["definition"]),
                    requires_approval=bool(tool["requires_approval"]),
                )
                for tool in config["tools"]
            ),
            trigger_refs=tuple(config["trigger_refs"]),
            prompt_refs=tuple(config["prompt_refs"]),
            secret_refs=tuple(config["secret_refs"]),
        ),
        config_digest=value["config_digest"],
        state=ConfigRevisionState(value["state"]),
        commit=value["commit"],
        rollback_ref=value["rollback_ref"],
        approvals=tuple(ConfigApproval(**approval) for approval in value["approvals"]),
    )
    if revision.config.digest != revision.config_digest:
        raise LedgerIntegrityError("stored config revision failed digest verification")
    return revision


class PostgreSQLConfigStore(_PostgreSQLStoreBase):
    """ConfigStore backend with database-side CAS activation.

    ``write_count`` mirrors the in-memory store's evidence attribute: it counts
    successful ``activate`` calls made through this instance.
    """

    _APPLICATION_NAME = "agent-interlock-config-store"

    def __init__(self, connection_factory: ConnectionFactory, *, bound_tenant_id: str) -> None:
        super().__init__(connection_factory, bound_tenant_id=bound_tenant_id)
        self.write_count = 0

    def active(self, tenant_id: str, config_id: str) -> ConfigRevision | None:
        self._require_bound_tenant(tenant_id)
        with self._transaction() as connection:
            row = self._execute(connection, _ACTIVE_REVISION, (tenant_id, config_id))
        return None if row is None else _revision_from(json.loads(row[0]))

    def revisions_for(self, tenant_id: str, config_id: str) -> tuple[ConfigRevision, ...]:
        self._require_bound_tenant(tenant_id)
        with self._transaction() as connection:
            rows = self._execute_all(connection, _ALL_REVISIONS, (tenant_id, config_id))
        return tuple(_revision_from(json.loads(row[0])) for row in rows)

    def activate(self, revision: ConfigRevision, *, expected_active_digest: str | None) -> ConfigRevision:
        tenant_id = revision.config.tenant_id
        config_id = revision.config.config_id
        self._require_bound_tenant(tenant_id)
        active_copy = replace(revision, state=ConfigRevisionState.ACTIVE)
        with self._transaction() as connection:
            row = self._execute(connection, _LOCK_ACTIVE, (tenant_id, config_id))
            current_digest = None if row is None else str(row[1])
            if current_digest != expected_active_digest:
                raise ConfigStoreStale("active config digest does not match the CAS base")
            if row is not None:
                self._execute_none(connection, _SUPERSEDE_REVISION, (tenant_id, config_id, str(row[0])))
            self._execute_none(
                connection,
                _UPSERT_REVISION,
                (
                    tenant_id,
                    config_id,
                    active_copy.revision_id,
                    active_copy.config_digest,
                    canonical_json(_revision_value(active_copy)).decode("utf-8"),
                ),
            )
            self._execute_none(
                connection,
                _UPSERT_ACTIVE,
                (tenant_id, config_id, active_copy.revision_id, active_copy.config_digest),
            )
        self.write_count += 1
        return active_copy


# --------------------------------------------------------------------------- #
# RevisionStore (DefinitionRegistry persistence)
# --------------------------------------------------------------------------- #

_UPSERT_REVISION_RECORD = """
INSERT INTO interlock.tool_revisions
    (tenant_id, revision_id, tool_id, canonical_digest, state, revision)
VALUES (%s, %s, %s, %s, %s, %s::jsonb)
ON CONFLICT (tenant_id, revision_id)
    DO UPDATE SET state = EXCLUDED.state, revision = EXCLUDED.revision
""".strip()

_GET_REVISION = """
SELECT revision::text FROM interlock.tool_revisions
WHERE tenant_id = %s AND revision_id = %s
""".strip()

_REVISIONS_FOR_TOOL = """
SELECT revision::text FROM interlock.tool_revisions
WHERE tenant_id = %s AND tool_id = %s
ORDER BY seq
""".strip()

_ACTIVE_FOR_TOOL = """
SELECT revision::text FROM interlock.tool_revisions
WHERE tenant_id = %s AND tool_id = %s AND state = 'ACTIVE'
ORDER BY seq DESC
LIMIT 1
""".strip()


def _revision_record_value(revision: ToolRevision) -> dict[str, Any]:
    value = asdict(revision)
    value["definition"] = revision.definition.canonical_value()
    value["state"] = revision.state.value
    value["reason_codes"] = list(revision.reason_codes)
    value["observed_at"] = revision.observed_at.isoformat()
    value["approved_at"] = revision.approved_at.isoformat() if revision.approved_at else None
    return value


def _tool_definition_from(value: Mapping[str, Any]) -> ToolDefinition:
    return ToolDefinition(
        server_id=value["serverId"],
        tool_name=value["toolName"],
        title=value["title"],
        description=value["description"],
        input_schema=value["inputSchema"],
        output_schema=value["outputSchema"],
        annotations=value["annotations"],
        protocol_extensions=value["protocolExtensions"],
        endpoint=value["endpoint"],
        transport=value["transport"],
        publisher=value["publisher"],
        artifact_digest=value["artifactDigest"],
    )


def _revision_record_from(value: Mapping[str, Any]) -> ToolRevision:
    definition = _tool_definition_from(value["definition"])
    revision = ToolRevision(
        revision_id=value["revision_id"],
        tool_id=value["tool_id"],
        definition=definition,
        canonical_digest=value["canonical_digest"],
        raw_digest=value["raw_digest"],
        canonicalizer_version=value["canonicalizer_version"],
        state=DefinitionState(value["state"]),
        reason_codes=tuple(value["reason_codes"]),
        observed_at=datetime.fromisoformat(value["observed_at"]),
        approved_by=value["approved_by"],
        approved_at=datetime.fromisoformat(value["approved_at"]) if value["approved_at"] else None,
    )
    if canonical_digest(definition.canonical_value()) != revision.canonical_digest:
        raise LedgerIntegrityError("stored tool revision failed digest verification")
    return revision


class PostgreSQLRevisionStore(_PostgreSQLStoreBase):
    """Tenant-bound RevisionStore backing DefinitionRegistry across nodes.

    Wire it with ``DefinitionRegistry(store=PostgreSQLRevisionStore.from_dsn(...))``.
    The stored definition digest is re-verified on every read.
    """

    _APPLICATION_NAME = "agent-interlock-revision-store"

    def get(self, revision_id: str) -> ToolRevision | None:
        with self._transaction() as connection:
            row = self._execute(connection, _GET_REVISION, (self.bound_tenant_id, revision_id))
        return None if row is None else _revision_record_from(json.loads(row[0]))

    def save(self, revision: ToolRevision) -> ToolRevision:
        with self._transaction() as connection:
            self._execute_none(
                connection,
                _UPSERT_REVISION_RECORD,
                (
                    self.bound_tenant_id,
                    revision.revision_id,
                    revision.tool_id,
                    revision.canonical_digest,
                    revision.state.value,
                    canonical_json(_revision_record_value(revision)).decode("utf-8"),
                ),
            )
        return revision

    def revisions_for(self, tool_id: str) -> tuple[ToolRevision, ...]:
        with self._transaction() as connection:
            rows = self._execute_all(connection, _REVISIONS_FOR_TOOL, (self.bound_tenant_id, tool_id))
        return tuple(_revision_record_from(json.loads(row[0])) for row in rows)

    def active_for(self, tool_id: str) -> ToolRevision | None:
        with self._transaction() as connection:
            row = self._execute(connection, _ACTIVE_FOR_TOOL, (self.bound_tenant_id, tool_id))
        return None if row is None else _revision_record_from(json.loads(row[0]))
