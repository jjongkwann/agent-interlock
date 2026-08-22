#!/usr/bin/env bash
# Apply migrations + provisioning to a running PostgreSQL, export the tenant
# DSNs, and run the full test suite (live PostgreSQL tests included).
#
# Assumes the compose service is up:
#   docker compose -f ci/docker-compose.postgres.yml up -d
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
HOST="${INTERLOCK_PG_HOST:-127.0.0.1}"
PORT="${INTERLOCK_PG_PORT:-55432}"
OWNER_DSN="postgresql://interlock_owner:owner_pw@${HOST}:${PORT}/interlock"

psql_owner() { psql "$OWNER_DSN" -v ON_ERROR_STOP=1 "$@"; }

echo "waiting for postgres at ${HOST}:${PORT} ..."
for _ in $(seq 1 30); do
  if psql_owner -c 'SELECT 1' >/dev/null 2>&1; then break; fi
  sleep 1
done

echo "applying migrations + provisioning ..."
# Every numbered migration in order, not a hand-kept list -- see the note in ci.yml.
for f in "$ROOT"/migrations/postgresql/0[0-9][0-9][0-9]_*.sql; do
  psql_owner -f "$f"
done
psql_owner -f "$ROOT/ci/postgres_provision.sql"

export INTERLOCK_TEST_POSTGRES_DSN_TENANT_A="postgresql://tenant_a_app:tenant_a_pw@${HOST}:${PORT}/interlock"
export INTERLOCK_TEST_POSTGRES_DSN_TENANT_B="postgresql://tenant_b_app:tenant_b_pw@${HOST}:${PORT}/interlock"

echo "running full suite with live PostgreSQL ..."
cd "$ROOT"
PYTHONPATH=src:tests python3 -m unittest discover -s tests "$@"
