-- Agent Interlock distributed store backends for PostgreSQL 16+
-- Run as a migration owner after 0001_interaction_ledger.sql. Application
-- logins must be NOSUPERUSER and NOBYPASSRLS, inherit interlock_store_api,
-- and be mapped in interlock.role_tenant.
BEGIN;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'interlock_store_api') THEN
        CREATE ROLE interlock_store_api
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$roles$;

-- ---------------------------------------------------------------------------
-- Inbound MCP sessions + resumable SSE event buffer
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS interlock.mcp_sessions (
    session_id  text NOT NULL PRIMARY KEY CHECK (length(session_id) BETWEEN 1 AND 1024),
    tenant_id   text NOT NULL REFERENCES interlock.tenants(tenant_id),
    actor_id    text NOT NULL CHECK (length(actor_id) > 0),
    subject     text NOT NULL CHECK (length(subject) > 0),
    state       text NOT NULL DEFAULT 'INITIALIZING' CHECK (state IN ('INITIALIZING', 'READY')),
    sequence    bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (session_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS interlock.mcp_session_events (
    session_id  text NOT NULL,
    tenant_id   text NOT NULL,
    event_seq   bigint NOT NULL CHECK (event_seq >= 1),
    message     jsonb NOT NULL CHECK (jsonb_typeof(message) = 'object'),
    PRIMARY KEY (session_id, event_seq),
    FOREIGN KEY (session_id, tenant_id)
        REFERENCES interlock.mcp_sessions(session_id, tenant_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- One-time-consume OAuth authorization transactions
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS interlock.oauth_transactions (
    state       text NOT NULL PRIMARY KEY CHECK (length(state) BETWEEN 1 AND 1024),
    tenant_id   text NOT NULL REFERENCES interlock.tenants(tenant_id),
    transaction jsonb NOT NULL CHECK (jsonb_typeof(transaction) = 'object'),
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS oauth_transactions_expiry_idx
    ON interlock.oauth_transactions (tenant_id, expires_at);

-- ---------------------------------------------------------------------------
-- Agent config revisions + CAS-guarded active pointer
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS interlock.agent_config_revisions (
    tenant_id     text NOT NULL REFERENCES interlock.tenants(tenant_id),
    config_id     text NOT NULL CHECK (length(config_id) > 0),
    revision_id   text NOT NULL CHECK (length(revision_id) > 0),
    config_digest text NOT NULL CHECK (config_digest ~ '^sha256:[0-9a-f]{64}$'),
    state         text NOT NULL CHECK (state IN ('PROPOSED', 'APPROVED', 'ACTIVE', 'SUPERSEDED')),
    revision      jsonb NOT NULL CHECK (jsonb_typeof(revision) = 'object'),
    seq           bigint GENERATED ALWAYS AS IDENTITY,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, config_id, revision_id)
);

CREATE TABLE IF NOT EXISTS interlock.agent_config_active (
    tenant_id     text NOT NULL,
    config_id     text NOT NULL,
    revision_id   text NOT NULL,
    config_digest text NOT NULL CHECK (config_digest ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (tenant_id, config_id),
    FOREIGN KEY (tenant_id, config_id, revision_id)
        REFERENCES interlock.agent_config_revisions(tenant_id, config_id, revision_id)
);

-- A stored revision is immutable except for its lifecycle state.
CREATE OR REPLACE FUNCTION interlock.deny_config_revision_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, interlock
AS $function$
BEGIN
    IF NEW.config_digest IS DISTINCT FROM OLD.config_digest
        OR NEW.revision - 'state' IS DISTINCT FROM OLD.revision - 'state'
        OR NEW.seq IS DISTINCT FROM OLD.seq
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'interlock.agent_config_revisions rows are immutable except state';
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS agent_config_revisions_state_only ON interlock.agent_config_revisions;
CREATE TRIGGER agent_config_revisions_state_only
    BEFORE UPDATE ON interlock.agent_config_revisions
    FOR EACH ROW EXECUTE FUNCTION interlock.deny_config_revision_mutation();

-- ---------------------------------------------------------------------------
-- Row level security: the authenticated role's tenant, nothing else
-- ---------------------------------------------------------------------------

ALTER TABLE interlock.mcp_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE interlock.mcp_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_sessions_tenant_isolation
    ON interlock.mcp_sessions
    USING (tenant_id = interlock.current_tenant())
    WITH CHECK (tenant_id = interlock.current_tenant());

ALTER TABLE interlock.mcp_session_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE interlock.mcp_session_events FORCE ROW LEVEL SECURITY;
CREATE POLICY mcp_session_events_tenant_isolation
    ON interlock.mcp_session_events
    USING (tenant_id = interlock.current_tenant())
    WITH CHECK (tenant_id = interlock.current_tenant());

ALTER TABLE interlock.oauth_transactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE interlock.oauth_transactions FORCE ROW LEVEL SECURITY;
CREATE POLICY oauth_transactions_tenant_isolation
    ON interlock.oauth_transactions
    USING (tenant_id = interlock.current_tenant())
    WITH CHECK (tenant_id = interlock.current_tenant());

ALTER TABLE interlock.agent_config_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE interlock.agent_config_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_config_revisions_tenant_isolation
    ON interlock.agent_config_revisions
    USING (tenant_id = interlock.current_tenant())
    WITH CHECK (tenant_id = interlock.current_tenant());

ALTER TABLE interlock.agent_config_active ENABLE ROW LEVEL SECURITY;
ALTER TABLE interlock.agent_config_active FORCE ROW LEVEL SECURITY;
CREATE POLICY agent_config_active_tenant_isolation
    ON interlock.agent_config_active
    USING (tenant_id = interlock.current_tenant())
    WITH CHECK (tenant_id = interlock.current_tenant());

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------

REVOKE ALL ON interlock.mcp_sessions FROM PUBLIC;
REVOKE ALL ON interlock.mcp_session_events FROM PUBLIC;
REVOKE ALL ON interlock.oauth_transactions FROM PUBLIC;
REVOKE ALL ON interlock.agent_config_revisions FROM PUBLIC;
REVOKE ALL ON interlock.agent_config_active FROM PUBLIC;
REVOKE ALL ON FUNCTION interlock.deny_config_revision_mutation() FROM PUBLIC;

GRANT USAGE ON SCHEMA interlock TO interlock_store_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON interlock.mcp_sessions TO interlock_store_api;
GRANT SELECT, INSERT, DELETE ON interlock.mcp_session_events TO interlock_store_api;
GRANT SELECT, INSERT, DELETE ON interlock.oauth_transactions TO interlock_store_api;
GRANT SELECT, INSERT, UPDATE ON interlock.agent_config_revisions TO interlock_store_api;
GRANT SELECT, INSERT, UPDATE ON interlock.agent_config_active TO interlock_store_api;
GRANT EXECUTE ON FUNCTION interlock.current_tenant() TO interlock_store_api;

COMMIT;
