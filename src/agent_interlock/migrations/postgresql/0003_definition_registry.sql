-- Agent Interlock persistent tool-definition registry for PostgreSQL 16+
-- Run as a migration owner after 0002_distributed_stores.sql. Application
-- logins inherit interlock_store_api and are mapped in interlock.role_tenant.
BEGIN;

CREATE TABLE IF NOT EXISTS interlock.tool_revisions (
    tenant_id        text NOT NULL REFERENCES interlock.tenants(tenant_id),
    revision_id      text NOT NULL CHECK (length(revision_id) > 0),
    tool_id          text NOT NULL CHECK (length(tool_id) > 0),
    canonical_digest text NOT NULL CHECK (canonical_digest ~ '^sha256:[0-9a-f]{64}$'),
    state            text NOT NULL CHECK (state IN
        ('DISCOVERED', 'QUARANTINED', 'APPROVED', 'ACTIVE', 'DRIFTED', 'REJECTED', 'REVOKED')),
    revision         jsonb NOT NULL CHECK (jsonb_typeof(revision) = 'object'),
    seq              bigint GENERATED ALWAYS AS IDENTITY,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, revision_id)
);

CREATE INDEX IF NOT EXISTS tool_revisions_tool_idx
    ON interlock.tool_revisions (tenant_id, tool_id, seq);

-- A revision's identity (its canonical digest) is immutable; only the
-- lifecycle state and its transition metadata may change.
CREATE OR REPLACE FUNCTION interlock.deny_tool_revision_identity_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, interlock
AS $function$
BEGIN
    IF NEW.canonical_digest IS DISTINCT FROM OLD.canonical_digest
        OR NEW.tool_id IS DISTINCT FROM OLD.tool_id
        OR NEW.seq IS DISTINCT FROM OLD.seq
        OR NEW.revision -> 'canonical_digest' IS DISTINCT FROM OLD.revision -> 'canonical_digest'
        OR NEW.revision -> 'definition' IS DISTINCT FROM OLD.revision -> 'definition'
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'interlock.tool_revisions identity is immutable; only state may change';
    END IF;
    RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS tool_revisions_identity_immutable ON interlock.tool_revisions;
CREATE TRIGGER tool_revisions_identity_immutable
    BEFORE UPDATE ON interlock.tool_revisions
    FOR EACH ROW EXECUTE FUNCTION interlock.deny_tool_revision_identity_mutation();

ALTER TABLE interlock.tool_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE interlock.tool_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tool_revisions_tenant_isolation
    ON interlock.tool_revisions
    USING (tenant_id = interlock.current_tenant())
    WITH CHECK (tenant_id = interlock.current_tenant());

REVOKE ALL ON interlock.tool_revisions FROM PUBLIC;
REVOKE ALL ON FUNCTION interlock.deny_tool_revision_identity_mutation() FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON interlock.tool_revisions TO interlock_store_api;

COMMIT;
