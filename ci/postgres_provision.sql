-- Test-only provisioning for the Agent Interlock live PostgreSQL suites.
-- Runs AFTER 0001+0002+0003 as a migration owner. Creates two tenants, two
-- NOSUPERUSER/NOBYPASSRLS application logins, and maps each to its tenant so
-- interlock.current_tenant() resolves. Passwords are test fixtures only.
BEGIN;

INSERT INTO interlock.tenants (tenant_id, name)
VALUES ('tenant-a', 'Tenant A (test)'), ('tenant-b', 'Tenant B (test)')
ON CONFLICT (tenant_id) DO NOTHING;

DO $provision$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_a_app') THEN
        CREATE ROLE tenant_a_app LOGIN PASSWORD 'tenant_a_pw'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
            IN ROLE interlock_event_api, interlock_store_api;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_b_app') THEN
        CREATE ROLE tenant_b_app LOGIN PASSWORD 'tenant_b_pw'
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
            IN ROLE interlock_event_api, interlock_store_api;
    END IF;
END
$provision$;

INSERT INTO interlock.role_tenant (role_name, tenant_id)
VALUES ('tenant_a_app', 'tenant-a'), ('tenant_b_app', 'tenant-b')
ON CONFLICT (role_name) DO UPDATE SET tenant_id = EXCLUDED.tenant_id;

COMMIT;
