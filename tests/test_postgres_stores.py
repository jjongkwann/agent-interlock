"""PostgreSQL distributed store adapters: unit fakes + gated live integration.

Live tests reuse the Ledger DSN env vars and expect
``migrations/postgresql/0002_distributed_stores.sql`` applied with the
application roles granted ``interlock_store_api``.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from agent_interlock import (
    AgentConfig,
    ConfigApproval,
    ConfigRevision,
    ConfigRevisionState,
    ConfigStoreStale,
    ConfiguredTool,
    LedgerIntegrityError,
    MCPHTTPError,
    MCPOAuthError,
    OAuthAuthorizationTransaction,
    PostgreSQLConfigStore,
    PostgreSQLDriverUnavailable,
    PostgreSQLOAuthTransactionStore,
    PostgreSQLSessionStore,
    ToolDefinition,
)
from agent_interlock.canonical import canonical_json
from agent_interlock.postgres_ledger import LedgerTenantMismatch
from agent_interlock.postgres_stores import _revision_from, _revision_value, _transaction_from, _transaction_value

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations/postgresql/0002_distributed_stores.sql"

TENANT_A = "tenant-a"
PRINCIPAL = (TENANT_A, "agent-1", "subject-1")


class ScriptedCursor:
    def __init__(self, connection: "ScriptedConnection") -> None:
        self.connection = connection

    def execute(self, query: str, parameters: tuple = ()) -> None:
        self.connection.executed.append((query, parameters))
        results = self.connection.results
        self.connection.current = results.pop(0) if results else None

    def fetchone(self):
        current = self.connection.current
        return current if isinstance(current, tuple) or current is None else None

    def fetchall(self):
        current = self.connection.current
        return current if isinstance(current, list) else []

    def close(self) -> None:
        return None


class ScriptedConnection:
    """Each execute() consumes one scripted result; the first is current_tenant."""

    def __init__(self, *results) -> None:
        self.results = list(results)
        self.executed: list[tuple[str, tuple]] = []
        self.current = None
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self) -> ScriptedCursor:
        return ScriptedCursor(self)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


def session_store(connection: ScriptedConnection) -> PostgreSQLSessionStore:
    return PostgreSQLSessionStore(lambda: connection, bound_tenant_id=TENANT_A)


def sample_transaction(state: str = "state-1") -> OAuthAuthorizationTransaction:
    return OAuthAuthorizationTransaction(
        client_id="client-1",
        redirect_uri="http://127.0.0.1:8976/callback",
        resource="https://mcp.example.com/server",
        scopes=("mcp:tools",),
        state=state,
        code_verifier="v" * 48,
        authorization_uri="https://as.example.com/authorize?x=1",
        expires_at_epoch=1_900_000_000.0,
    )


def sample_revision() -> ConfigRevision:
    config = AgentConfig(
        tenant_id=TENANT_A,
        config_id="config-1",
        agent_id="agent-1",
        tools=(
            ConfiguredTool(
                definition=ToolDefinition(
                    server_id="crm",
                    tool_name="lookup",
                    title="Lookup",
                    description="reads a record",
                    input_schema={"type": "object"},
                ),
            ),
        ),
        trigger_refs=("trigger-1",),
        secret_refs=("secret-ref-1",),
    )
    return ConfigRevision(
        revision_id=f"config-1@{config.digest}",
        config=config,
        config_digest=config.digest,
        state=ConfigRevisionState.APPROVED,
        commit="commit-1",
        approvals=(ConfigApproval(approver_id="op-1", key_id="key-a", signature="aa"),),
    )


class DriverAndBindingTests(unittest.TestCase):
    def test_from_dsn_without_psycopg_names_the_extra_not_the_dsn(self):
        for cls in (PostgreSQLSessionStore, PostgreSQLOAuthTransactionStore, PostgreSQLConfigStore):
            with patch.dict(sys.modules, {"psycopg": None}):
                with self.assertRaises(PostgreSQLDriverUnavailable) as raised:
                    cls.from_dsn("postgresql://user:hunter2@db/x", bound_tenant_id=TENANT_A)
            self.assertIn(cls.__name__, str(raised.exception))
            self.assertNotIn("hunter2", str(raised.exception))

    def test_repr_never_contains_credentials(self):
        store = session_store(ScriptedConnection())
        self.assertNotIn("hunter2", repr(store))
        self.assertIn(TENANT_A, repr(store))

    def test_requested_tenant_mismatch_opens_no_connection(self):
        def factory():
            raise AssertionError("no connection may be opened")

        store = PostgreSQLSessionStore(factory, bound_tenant_id=TENANT_A)
        with self.assertRaises(LedgerTenantMismatch):
            store.state("sid", ("tenant-b", "agent-1", "subject-1"))
        config_store = PostgreSQLConfigStore(factory, bound_tenant_id=TENANT_A)
        with self.assertRaises(LedgerTenantMismatch):
            config_store.active("tenant-b", "config-1")

    def test_db_role_mismatch_rolls_back_before_store_sql(self):
        connection = ScriptedConnection(("tenant-b",))
        with self.assertRaises(LedgerTenantMismatch):
            session_store(connection).create("sid", PRINCIPAL)
        self.assertEqual(len(connection.executed), 1)
        self.assertIn("current_tenant", connection.executed[0][0])
        self.assertTrue(connection.rolled_back)
        self.assertTrue(connection.closed)
        self.assertFalse(connection.committed)


class SessionStoreUnitTests(unittest.TestCase):
    def test_create_duplicate_session_raises(self):
        connection = ScriptedConnection((TENANT_A,), None)
        with self.assertRaises(MCPHTTPError) as raised:
            session_store(connection).create("sid", PRINCIPAL)
        self.assertEqual(raised.exception.reason_code, "MCP-HTTP-SESSION-DUPLICATE")
        self.assertTrue(connection.rolled_back)

    def test_mark_ready_is_single_shot(self):
        self.assertTrue(session_store(ScriptedConnection((TENANT_A,), ("sid",))).mark_ready("sid", PRINCIPAL))
        self.assertFalse(session_store(ScriptedConnection((TENANT_A,), None)).mark_ready("sid", PRINCIPAL))

    def test_append_missing_session_raises_not_found(self):
        connection = ScriptedConnection((TENANT_A,), None)
        with self.assertRaises(MCPHTTPError) as raised:
            session_store(connection).append("sid", PRINCIPAL, {"jsonrpc": "2.0", "method": "m"})
        self.assertEqual(raised.exception.reason_code, "MCP-HTTP-SESSION-NOT-FOUND")
        self.assertTrue(connection.rolled_back)

    def test_append_writes_canonical_message_and_returns_sequence(self):
        connection = ScriptedConnection((TENANT_A,), (3,), None)
        sequence = session_store(connection).append("sid", PRINCIPAL, {"b": 2, "a": 1})
        self.assertEqual(sequence, 3)
        insert_query, insert_params = connection.executed[2]
        self.assertIn("mcp_session_events", insert_query)
        self.assertEqual(insert_params, ("sid", TENANT_A, 3, '{"a":1,"b":2}'))

    def test_replay_unbound_returns_empty(self):
        connection = ScriptedConnection((TENANT_A,), None)
        self.assertEqual(session_store(connection).replay("sid", PRINCIPAL, None), ())

    def test_replay_parses_messages_after_floor(self):
        connection = ScriptedConnection(
            (TENANT_A,), ("READY",), [(1, '{"jsonrpc":"2.0","method":"a"}'), (2, '{"jsonrpc":"2.0","method":"b"}')]
        )
        events = session_store(connection).replay("sid", PRINCIPAL, None)
        self.assertEqual(
            events,
            ((1, {"jsonrpc": "2.0", "method": "a"}), (2, {"jsonrpc": "2.0", "method": "b"})),
        )
        replay_params = connection.executed[2][1]
        self.assertEqual(replay_params[-1], 0)


class OAuthTransactionStoreUnitTests(unittest.TestCase):
    def test_put_duplicate_state_raises(self):
        connection = ScriptedConnection((TENANT_A,), None)
        store = PostgreSQLOAuthTransactionStore(lambda: connection, bound_tenant_id=TENANT_A)
        with self.assertRaises(MCPOAuthError) as raised:
            store.put(sample_transaction())
        self.assertEqual(raised.exception.reason_code, "MCP-OAUTH-STATE-DUPLICATE")

    def test_consume_returns_none_when_missing(self):
        connection = ScriptedConnection((TENANT_A,), None)
        store = PostgreSQLOAuthTransactionStore(lambda: connection, bound_tenant_id=TENANT_A)
        self.assertIsNone(store.consume("state-1"))

    def test_transaction_round_trip_preserves_every_field(self):
        transaction = sample_transaction()
        transaction.callback_consumed = True
        transaction.authorization_code_digest = "d" * 64
        raw = canonical_json(_transaction_value(transaction)).decode("utf-8")
        restored = _transaction_from(json.loads(raw))
        self.assertEqual(_transaction_value(restored), _transaction_value(transaction))
        self.assertEqual(restored.scopes, ("mcp:tools",))


class ConfigStoreUnitTests(unittest.TestCase):
    def test_revision_round_trip_preserves_every_field(self):
        revision = sample_revision()
        raw = canonical_json(_revision_value(revision)).decode("utf-8")
        self.assertEqual(_revision_from(json.loads(raw)), revision)

    def test_tampered_stored_revision_is_rejected_on_read(self):
        value = _revision_value(sample_revision())
        value["config"]["agent_id"] = "attacker-agent"
        with self.assertRaises(LedgerIntegrityError):
            _revision_from(value)

    def test_activate_stale_base_raises_without_write(self):
        revision = sample_revision()
        connection = ScriptedConnection((TENANT_A,), ("rev-0", "sha256:" + "0" * 64))
        store = PostgreSQLConfigStore(lambda: connection, bound_tenant_id=TENANT_A)
        with self.assertRaises(ConfigStoreStale):
            store.activate(revision, expected_active_digest=None)
        self.assertEqual(store.write_count, 0)
        self.assertTrue(connection.rolled_back)
        self.assertEqual(len(connection.executed), 2)

    def test_activate_supersedes_and_upserts_active_pointer(self):
        revision = sample_revision()
        old_digest = "sha256:" + "0" * 64
        connection = ScriptedConnection((TENANT_A,), ("rev-0", old_digest), None, None, None)
        store = PostgreSQLConfigStore(lambda: connection, bound_tenant_id=TENANT_A)
        active = store.activate(revision, expected_active_digest=old_digest)
        self.assertEqual(active.state, ConfigRevisionState.ACTIVE)
        self.assertEqual(store.write_count, 1)
        queries = [query for query, _ in connection.executed]
        self.assertIn("SUPERSEDED", queries[2])
        self.assertIn("agent_config_revisions", queries[3])
        self.assertIn("agent_config_active", queries[4])
        self.assertTrue(connection.committed)


class MigrationContractTests(unittest.TestCase):
    def test_migration_has_database_side_tenant_and_immutability_controls(self):
        sql = MIGRATION.read_text(encoding="utf-8")
        for table in (
            "mcp_sessions",
            "mcp_session_events",
            "oauth_transactions",
            "agent_config_revisions",
            "agent_config_active",
        ):
            self.assertIn(f"ALTER TABLE interlock.{table} FORCE ROW LEVEL SECURITY;", sql)
            self.assertIn(f"{table}_tenant_isolation", sql)
        self.assertIn("interlock.current_tenant()", sql)
        self.assertIn("NOBYPASSRLS", sql)
        self.assertIn("ON DELETE CASCADE", sql)
        self.assertIn("deny_config_revision_mutation", sql)
        self.assertIn("state IN ('INITIALIZING', 'READY')", sql)
        self.assertNotIn("current_setting('app.tenant_id')", sql)


@unittest.skipUnless(
    os.environ.get("INTERLOCK_TEST_POSTGRES_DSN_TENANT_A")
    and os.environ.get("INTERLOCK_TEST_POSTGRES_DSN_TENANT_B"),
    "set tenant PostgreSQL DSNs to run the live store integration",
)
class PostgreSQLStoresIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn_a = os.environ["INTERLOCK_TEST_POSTGRES_DSN_TENANT_A"]
        cls.dsn_b = os.environ["INTERLOCK_TEST_POSTGRES_DSN_TENANT_B"]

    def test_session_lifecycle_survives_instances_and_hides_other_tenants(self):
        store_a = PostgreSQLSessionStore.from_dsn(self.dsn_a, bound_tenant_id="tenant_a")
        second_node = PostgreSQLSessionStore.from_dsn(self.dsn_a, bound_tenant_id="tenant_a")
        store_b = PostgreSQLSessionStore.from_dsn(self.dsn_b, bound_tenant_id="tenant_b")
        principal = ("tenant_a", "agent-live", "subject-live")
        session_id = f"live-{uuid.uuid4()}"
        store_a.create(session_id, principal)
        try:
            self.assertEqual(store_a.state(session_id, principal), "INITIALIZING")
            self.assertTrue(second_node.mark_ready(session_id, principal))
            self.assertFalse(second_node.mark_ready(session_id, principal))
            first = store_a.append(session_id, principal, {"jsonrpc": "2.0", "method": "a"})
            second = second_node.append(session_id, principal, {"jsonrpc": "2.0", "method": "b"})
            self.assertEqual((first, second), (1, 2))
            replayed = second_node.replay(session_id, principal, 1)
            self.assertEqual(replayed, ((2, {"jsonrpc": "2.0", "method": "b"}),))
            self.assertIsNone(store_b.state(session_id, ("tenant_b", "agent-live", "subject-live")))
        finally:
            self.assertTrue(store_a.delete(session_id, principal))

    def test_oauth_transaction_is_single_use_across_instances(self):
        node_1 = PostgreSQLOAuthTransactionStore.from_dsn(self.dsn_a, bound_tenant_id="tenant_a")
        node_2 = PostgreSQLOAuthTransactionStore.from_dsn(self.dsn_a, bound_tenant_id="tenant_a")
        transaction = sample_transaction(state=f"live-{uuid.uuid4()}")
        node_1.put(transaction)
        with self.assertRaises(MCPOAuthError):
            node_2.put(transaction)
        consumed = node_2.consume(transaction.state)
        self.assertIsNotNone(consumed)
        self.assertEqual(consumed.code_verifier, transaction.code_verifier)
        self.assertIsNone(node_1.consume(transaction.state))

    def test_config_cas_activation_is_database_enforced(self):
        node_1 = PostgreSQLConfigStore.from_dsn(self.dsn_a, bound_tenant_id="tenant_a")
        node_2 = PostgreSQLConfigStore.from_dsn(self.dsn_a, bound_tenant_id="tenant_a")
        config_id = f"live-{uuid.uuid4()}"
        base_config = AgentConfig(tenant_id="tenant_a", config_id=config_id, agent_id="agent-live")
        base = ConfigRevision(
            revision_id=f"{config_id}@{base_config.digest}",
            config=base_config,
            config_digest=base_config.digest,
            state=ConfigRevisionState.APPROVED,
            commit="live-commit-1",
        )
        activated = node_1.activate(base, expected_active_digest=None)
        self.assertEqual(activated.state, ConfigRevisionState.ACTIVE)
        follow_config = AgentConfig(
            tenant_id="tenant_a", config_id=config_id, agent_id="agent-live", trigger_refs=("t-1",)
        )
        follow = ConfigRevision(
            revision_id=f"{config_id}@{follow_config.digest}",
            config=follow_config,
            config_digest=follow_config.digest,
            state=ConfigRevisionState.APPROVED,
            commit="live-commit-2",
        )
        with self.assertRaises(ConfigStoreStale):
            node_2.activate(follow, expected_active_digest="sha256:" + "f" * 64)
        node_2.activate(follow, expected_active_digest=base_config.digest)
        active = node_1.active("tenant_a", config_id)
        self.assertIsNotNone(active)
        self.assertEqual(active.config_digest, follow_config.digest)
        states = [revision.state for revision in node_1.revisions_for("tenant_a", config_id)]
        self.assertEqual(states, [ConfigRevisionState.SUPERSEDED, ConfigRevisionState.ACTIVE])


if __name__ == "__main__":
    unittest.main()
