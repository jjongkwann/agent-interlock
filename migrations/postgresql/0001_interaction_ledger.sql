-- Agent Interlock append-only event Ledger for PostgreSQL 16+
-- Run as a migration owner. Application logins must be NOSUPERUSER and
-- NOBYPASSRLS, inherit interlock_event_api, and be mapped in role_tenant.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE SCHEMA IF NOT EXISTS interlock;
REVOKE ALL ON SCHEMA interlock FROM PUBLIC;

DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'interlock_event_api') THEN
        CREATE ROLE interlock_event_api
            NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    END IF;
END
$roles$;

CREATE TABLE interlock.tenants (
    tenant_id          text PRIMARY KEY,
    name               text NOT NULL,
    retention_days     integer NOT NULL DEFAULT 90 CHECK (retention_days > 0),
    evidence_enabled   boolean NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE interlock.role_tenant (
    role_name          name PRIMARY KEY,
    tenant_id          text NOT NULL REFERENCES interlock.tenants(tenant_id),
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION interlock.current_tenant()
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, interlock
AS $function$
    SELECT tenant_id
    FROM interlock.role_tenant
    WHERE role_name = session_user
$function$;

REVOKE ALL ON FUNCTION interlock.current_tenant() FROM PUBLIC;

CREATE TABLE interlock.security_events (
    event_id            uuid NOT NULL,
    event_type          text NOT NULL CHECK (event_type IN (
        'INTERACTION_REQUESTED', 'DATA_FLOW_OBSERVED', 'CONTROL_EVALUATED',
        'ACTION_EXECUTED', 'INTERACTION_COMPLETED', 'SECURITY_OUTCOME_SET',
        'DETECTION_RAISED', 'INCIDENT_UPDATED', 'CONTROL_HEALTH_CHANGED',
        'POLICY_CHANGED', 'TEST_EXECUTED'
    )),
    schema_version      text NOT NULL CHECK (schema_version = '1.0'),
    occurred_at         timestamptz NOT NULL,
    ingested_at         timestamptz NOT NULL,
    tenant_id           text NOT NULL REFERENCES interlock.tenants(tenant_id),
    environment         text NOT NULL CHECK (environment IN ('DEV', 'STAGE', 'PROD')),
    data_source         text NOT NULL CHECK (data_source IN (
        'PRODUCTION', 'SIMULATION', 'RED_TEAM', 'TEST'
    )),
    trace_id            text NOT NULL CHECK (length(trace_id) BETWEEN 1 AND 256),
    span_id             text NOT NULL CHECK (length(span_id) BETWEEN 1 AND 256),
    parent_span_id      text,
    interaction_id      text,
    source_actor_id     text NOT NULL CHECK (length(source_actor_id) BETWEEN 1 AND 512),
    target_actor_id     text,
    relationship_type   text NOT NULL,
    relationship_id     text NOT NULL CHECK (relationship_id ~ '^REL-[0-9]{2}$'),
    severity            text NOT NULL CHECK (severity IN (
        'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    )),
    payload             jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object'),
    payload_canonical   text NOT NULL CHECK (payload = payload_canonical::jsonb),
    integrity_hash      text NOT NULL CHECK (integrity_hash ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY (occurred_at, event_id)
) PARTITION BY RANGE (occurred_at);

CREATE OR REPLACE FUNCTION interlock.deny_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, interlock
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'interlock.security_events is append-only';
END
$function$;

CREATE TRIGGER security_events_no_mutation
    BEFORE UPDATE OR DELETE ON interlock.security_events
    FOR EACH ROW EXECUTE FUNCTION interlock.deny_event_mutation();

CREATE OR REPLACE FUNCTION interlock.create_security_events_partition(p_month date)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, interlock
AS $function$
DECLARE
    month_start date;
    month_end date;
    partition_name text;
BEGIN
    month_start := date_trunc('month', p_month)::date;
    IF p_month <> month_start THEN
        RAISE EXCEPTION 'p_month must be the first day of a month';
    END IF;
    month_end := (month_start + interval '1 month')::date;
    partition_name := 'security_events_' || to_char(month_start, 'YYYY_MM');
    EXECUTE format(
        'CREATE TABLE IF NOT EXISTS interlock.%I PARTITION OF interlock.security_events '
        'FOR VALUES FROM (%L) TO (%L)',
        partition_name,
        month_start,
        month_end
    );
    RETURN partition_name;
END
$function$;

REVOKE ALL ON FUNCTION interlock.create_security_events_partition(date) FROM PUBLIC;

-- Materialize current and next month before creating the bounded fallback.
SELECT interlock.create_security_events_partition(date_trunc('month', current_date)::date);
SELECT interlock.create_security_events_partition(
    (date_trunc('month', current_date) + interval '1 month')::date
);
CREATE TABLE interlock.security_events_default
    PARTITION OF interlock.security_events DEFAULT;

CREATE INDEX security_events_trace_idx
    ON interlock.security_events (tenant_id, trace_id, occurred_at, event_id);
CREATE INDEX security_events_interaction_idx
    ON interlock.security_events (tenant_id, interaction_id, occurred_at, event_id);
CREATE INDEX security_events_actor_idx
    ON interlock.security_events (tenant_id, source_actor_id, occurred_at DESC);
CREATE INDEX security_events_type_idx
    ON interlock.security_events (tenant_id, event_type, occurred_at DESC);
CREATE INDEX security_events_payload_gin_idx
    ON interlock.security_events USING gin (payload jsonb_path_ops);

CREATE TABLE interlock.event_ingest_keys (
    tenant_id          text NOT NULL REFERENCES interlock.tenants(tenant_id),
    idempotency_key    text NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 200),
    request_hash       text NOT NULL CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
    event_id           uuid NOT NULL,
    event_occurred_at  timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, idempotency_key),
    FOREIGN KEY (event_occurred_at, event_id)
        REFERENCES interlock.security_events(occurred_at, event_id)
        DEFERRABLE INITIALLY DEFERRED
);

ALTER TABLE interlock.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE interlock.security_events FORCE ROW LEVEL SECURITY;
CREATE POLICY security_events_tenant_isolation
    ON interlock.security_events
    USING (tenant_id = interlock.current_tenant())
    WITH CHECK (tenant_id = interlock.current_tenant());

ALTER TABLE interlock.event_ingest_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE interlock.event_ingest_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY event_ingest_keys_tenant_isolation
    ON interlock.event_ingest_keys
    USING (tenant_id = interlock.current_tenant())
    WITH CHECK (tenant_id = interlock.current_tenant());

REVOKE ALL ON interlock.tenants FROM PUBLIC;
REVOKE ALL ON interlock.role_tenant FROM PUBLIC;
REVOKE ALL ON interlock.security_events FROM PUBLIC;
REVOKE ALL ON interlock.event_ingest_keys FROM PUBLIC;

GRANT USAGE ON SCHEMA interlock TO interlock_event_api;
GRANT EXECUTE ON FUNCTION interlock.current_tenant() TO interlock_event_api;
GRANT SELECT, INSERT ON interlock.security_events TO interlock_event_api;
GRANT SELECT, INSERT ON interlock.event_ingest_keys TO interlock_event_api;

COMMIT;
