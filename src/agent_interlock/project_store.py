"""Shared Studio drafts with optimistic revisions; deployment remains a separate review."""

from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


class ProjectConflict(ValueError):
    """A newer revision exists; the caller must open it before saving again."""


class SQLiteProjectStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        with closing(sqlite3.connect(self.path)) as connection, connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, 1}:
                raise ValueError("unsupported project store version")
            connection.execute("""CREATE TABLE IF NOT EXISTS projects (
                tenant_id TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL,
                manifest TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL,
                PRIMARY KEY (tenant_id, id))""")
            connection.execute("PRAGMA user_version = 1")

    @staticmethod
    def _decode(row):
        return {"id": row[0], "revision": row[1], "manifest": json.loads(row[2]),
                "updatedAt": row[3], "updatedBy": row[4]}

    def list(self, tenant_id: str) -> list[dict]:
        with closing(sqlite3.connect(self.path)) as connection:
            return [{"id": row[0], "revision": row[1], "updatedAt": row[2], "updatedBy": row[3]}
                    for row in connection.execute(
                        "SELECT id,revision,updated_at,updated_by FROM projects "
                        "WHERE tenant_id=? ORDER BY updated_at DESC", (tenant_id,))]

    def get(self, tenant_id: str, project_id: str) -> dict | None:
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute(
                "SELECT id,revision,manifest,updated_at,updated_by FROM projects WHERE tenant_id=? AND id=?",
                (tenant_id, project_id),
            ).fetchone()
            return self._decode(row) if row else None

    def save(self, tenant_id: str, project_id: str, manifest: dict, revision: int, subject: str) -> dict:
        if (not isinstance(project_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", project_id)
                or len(project_id) > 128 or type(revision) is not int or revision < 0
                or not isinstance(manifest, dict) or not isinstance(manifest.get("metadata"), dict)
                or manifest["metadata"].get("id") != project_id):
            raise ValueError("project id must match manifest metadata.id and revision must be a nonnegative integer")
        encoded = json.dumps(manifest, ensure_ascii=False, allow_nan=False)
        if len(encoded.encode()) > 1024 * 1024:
            raise ValueError("project manifest exceeds 1 MiB")
        updated = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(self.path, timeout=10)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT revision FROM projects WHERE tenant_id=? AND id=?",
                                     (tenant_id, project_id)).fetchone()
            if revision != (row[0] if row else 0):
                raise ProjectConflict("a newer shared revision exists; open it before saving your changes")
            connection.execute(
                "INSERT INTO projects VALUES (?,?,?,?,?,?) ON CONFLICT(tenant_id,id) DO UPDATE SET "
                "revision=excluded.revision,manifest=excluded.manifest,updated_at=excluded.updated_at,"
                "updated_by=excluded.updated_by", (tenant_id, project_id, revision + 1, encoded, updated, subject),
            )
        return {"id": project_id, "revision": revision + 1, "manifest": json.loads(encoded),
                "updatedAt": updated, "updatedBy": subject}
