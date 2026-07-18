"""PostgreSQL operations: migration runner, partition/retention, connection pool.

These are the operational pieces around the ledger/store adapters — applying the
ordered migration files idempotently, keeping the time-partitioned event table
provisioned and pruned, and pooling tenant-bound connections. Everything is
dependency-injected via the same ``ConnectionFactory`` the adapters use, so it
unit-tests against fakes and runs live against a real database.
"""

from __future__ import annotations

import hashlib
import re
import threading
from datetime import date
from pathlib import Path

from .postgres_ledger import ConnectionFactory, PostgreSQLDriverUnavailable, Connection

_MIGRATION_NAME = re.compile(r"^(\d{4})_[a-z0-9_]+\.sql$")

_MIGRATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS public.interlock_schema_migrations (
    version    text PRIMARY KEY,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)
""".strip()


class MigrationError(RuntimeError):
    pass


class PostgreSQLMigrationRunner:
    """Applies ordered ``NNNN_*.sql`` migrations idempotently.

    Applied versions are recorded in ``public.interlock_schema_migrations`` with
    the file checksum; a version whose file changed after being applied is a
    drift error (a committed migration must never be edited in place). Legacy
    3-digit files are ignored — only the 4-digit series is managed.
    """

    def __init__(self, migrations_dir: str | Path, connection_factory: ConnectionFactory) -> None:
        self._dir = Path(migrations_dir)
        self._factory = connection_factory

    def discover(self) -> list[tuple[str, str]]:
        """Return ``(version, sql)`` for every managed migration, ordered."""
        found: list[tuple[str, str]] = []
        for path in sorted(self._dir.iterdir()):
            match = _MIGRATION_NAME.match(path.name)
            if match:
                found.append((match.group(1), path.read_text(encoding="utf-8")))
        return found

    @staticmethod
    def _checksum(sql: str) -> str:
        return "sha256:" + hashlib.sha256(sql.encode("utf-8")).hexdigest()

    def applied(self, connection: Connection) -> dict[str, str]:
        cursor = connection.cursor()
        try:
            cursor.execute(_MIGRATIONS_TABLE)
            cursor.execute("SELECT version, checksum FROM public.interlock_schema_migrations")
            return {str(version): str(checksum) for version, checksum in cursor.fetchall()}
        finally:
            cursor.close()

    def apply(self) -> list[str]:
        """Apply every pending migration in order; return the versions applied."""
        connection = self._factory()
        applied_versions: list[str] = []
        try:
            recorded = self.applied(connection)
            for version, sql in self.discover():
                checksum = self._checksum(sql)
                if version in recorded:
                    if recorded[version] != checksum:
                        raise MigrationError(
                            f"migration {version} changed after being applied (checksum drift)"
                        )
                    continue
                cursor = connection.cursor()
                try:
                    cursor.execute(sql)
                    cursor.execute(
                        "INSERT INTO public.interlock_schema_migrations (version, checksum) VALUES (%s, %s)",
                        (version, checksum),
                    )
                finally:
                    cursor.close()
                applied_versions.append(version)
            connection.commit()
            return applied_versions
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @classmethod
    def from_dsn(cls, migrations_dir: str | Path, dsn: str) -> "PostgreSQLMigrationRunner":
        return cls(migrations_dir, _dsn_factory(dsn, "agent-interlock-migrate"))


class PartitionMaintenance:
    """Keeps ``interlock.security_events`` partitions provisioned and pruned."""

    def __init__(self, connection_factory: ConnectionFactory) -> None:
        self._factory = connection_factory

    def ensure_partitions(self, *, today: date, months_ahead: int = 1) -> list[str]:
        """Create the current month partition and ``months_ahead`` future ones."""
        if months_ahead < 0:
            raise ValueError("months_ahead must not be negative")
        created: list[str] = []
        connection = self._factory()
        try:
            month = date(today.year, today.month, 1)
            for _ in range(months_ahead + 1):
                cursor = connection.cursor()
                try:
                    cursor.execute("SELECT interlock.create_security_events_partition(%s::date)", (month.isoformat(),))
                    row = cursor.fetchone()
                    if row:
                        created.append(str(row[0]))
                finally:
                    cursor.close()
                month = _next_month(month)
            connection.commit()
            return created
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def drop_partitions_older_than(self, *, cutoff_month: date) -> list[str]:
        """Drop whole month partitions strictly older than ``cutoff_month``.

        The bounded ``security_events_default`` fallback is never dropped. A
        month partition holds every tenant's rows, so ``cutoff_month`` should be
        derived from the LONGEST tenant retention to avoid pruning a tenant's
        data early.
        """
        cutoff = date(cutoff_month.year, cutoff_month.month, 1)
        dropped: list[str] = []
        connection = self._factory()
        try:
            for name in self._month_partitions(connection):
                month = _partition_month(name)
                if month is None or month >= cutoff:
                    continue
                self._drop_partition(connection, name, month)
                dropped.append(name)
            connection.commit()
            return dropped
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _drop_partition(connection: Connection, name: str, month: date) -> None:
        """Detach and drop one month partition, pruning its cross-partition
        idempotency keys first so the deferred FK does not block the drop.

        Runs as a migration owner / superuser (RLS is bypassed), which retention
        requires — it prunes across all tenants at once."""
        next_month = _next_month(month)
        cursor = connection.cursor()
        try:
            cursor.execute(
                "DELETE FROM interlock.event_ingest_keys "
                "WHERE event_occurred_at >= %s::timestamptz AND event_occurred_at < %s::timestamptz",
                (month.isoformat(), next_month.isoformat()),
            )
            cursor.execute(f'ALTER TABLE interlock.security_events DETACH PARTITION interlock."{name}"')
            cursor.execute(f'DROP TABLE IF EXISTS interlock."{name}"')
        finally:
            cursor.close()

    def _month_partitions(self, connection: Connection) -> list[str]:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                SELECT child.relname
                FROM pg_inherits
                JOIN pg_class child ON child.oid = pg_inherits.inhrelid
                JOIN pg_class parent ON parent.oid = pg_inherits.inhparent
                JOIN pg_namespace ns ON ns.oid = parent.relnamespace
                WHERE ns.nspname = 'interlock' AND parent.relname = 'security_events'
                """
            )
            return [str(row[0]) for row in cursor.fetchall()]
        finally:
            cursor.close()


class PoolExhausted(RuntimeError):
    pass


class _PooledConnection:
    """Proxy whose ``close()`` returns the real connection to the pool."""

    __slots__ = ("_real", "_pool", "_released")

    def __init__(self, real: Connection, pool: "PostgreSQLConnectionPool") -> None:
        self._real = real
        self._pool = pool
        self._released = False

    def cursor(self):  # noqa: ANN201
        return self._real.cursor()

    def commit(self) -> None:
        self._real.commit()

    def rollback(self) -> None:
        self._real.rollback()

    def close(self) -> None:
        if not self._released:
            self._released = True
            self._pool._release(self._real)


class PostgreSQLConnectionPool:
    """Bounded pool of tenant-bound connections.

    ``factory`` returns a proxy whose ``close()`` returns the connection to the
    pool, so it drops in wherever a ``ConnectionFactory`` is expected
    (``PostgreSQLLedger(pool.factory, ...)``). A connection is rolled back on
    release so no operation leaks an open transaction to the next borrower.
    """

    def __init__(self, connection_factory: ConnectionFactory, *, max_size: int = 10) -> None:
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self._factory = connection_factory
        self._max_size = max_size
        self._idle: list[Connection] = []
        self._in_use = 0
        self._closed = False
        self._lock = threading.Lock()

    def factory(self) -> _PooledConnection:
        with self._lock:
            if self._closed:
                raise PoolExhausted("connection pool is closed")
            if self._idle:
                real = self._idle.pop()
            elif self._in_use < self._max_size:
                real = self._factory()
            else:
                raise PoolExhausted("connection pool is at capacity")
            self._in_use += 1
            return _PooledConnection(real, self)

    def _release(self, real: Connection) -> None:
        with self._lock:
            self._in_use -= 1
            if self._closed:
                _safe_close(real)
                return
            try:
                real.rollback()
            except Exception:  # noqa: BLE001 - a broken connection is not returned to the pool
                _safe_close(real)
                return
            self._idle.append(real)

    @property
    def in_use(self) -> int:
        with self._lock:
            return self._in_use

    @property
    def idle(self) -> int:
        with self._lock:
            return len(self._idle)

    def closeall(self) -> None:
        with self._lock:
            self._closed = True
            for real in self._idle:
                _safe_close(real)
            self._idle.clear()


def _next_month(month: date) -> date:
    return date(month.year + 1, 1, 1) if month.month == 12 else date(month.year, month.month + 1, 1)


def _partition_month(name: str) -> date | None:
    match = re.match(r"^security_events_(\d{4})_(\d{2})$", name)
    if not match:
        return None
    return date(int(match.group(1)), int(match.group(2)), 1)


def _safe_close(connection: Connection) -> None:
    try:
        connection.close()
    except Exception:  # noqa: BLE001
        pass


def _dsn_factory(dsn: str, application_name: str) -> ConnectionFactory:
    if not dsn:
        raise ValueError("dsn is required")

    def connect() -> Connection:
        try:
            import psycopg
        except ImportError as error:
            raise PostgreSQLDriverUnavailable(
                "install the 'postgres' project extra to use the PostgreSQL operations helpers"
            ) from error
        return psycopg.connect(dsn, autocommit=False, connect_timeout=5, application_name=application_name)

    return connect
