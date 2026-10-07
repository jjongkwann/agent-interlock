"""SQLite workflow state for a single Run Control host, including deployment and approvals."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path

from .orchestration import (
    _RUN_TERMINAL,
    OrchestrationError,
    WorkflowRun,
    WorkflowRunState,
    WorkflowTaskRun,
    WorkflowTaskState,
    _merge_run,
    _now,
)


def _decode(raw: str) -> WorkflowRun:
    value = json.loads(raw)
    value["state"] = WorkflowRunState(value["state"])
    value["tasks"] = {
        key: WorkflowTaskRun(**{**task, "state": WorkflowTaskState(task["state"])})
        for key, task in value["tasks"].items()
    }
    return WorkflowRun(**value)


class SQLiteWorkflowRunStore:
    """Durable run snapshots. Dispatch ownership belongs to one hosting process.

    Terminal runs remain readable until the operator explicitly calls ``prune``;
    only unfinished runs consume capacity. Inputs/outputs are stored for resume,
    so the database belongs on protected local storage, never a public directory.
    """

    def __init__(self, path: str | Path, *, max_runs: int = 1024) -> None:
        if max_runs < 1:
            raise ValueError("max_runs must be positive")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        self.max_runs = max_runs
        self._lock = threading.RLock()
        with self._transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, 1, 2}:
                raise ValueError(f"unsupported workflow store schema version: {version}")
            connection.execute("""CREATE TABLE IF NOT EXISTS workflow_runs (
                tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, state TEXT NOT NULL,
                updated_at TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (tenant_id, run_id))""")
            if version < 2:
                connection.execute("ALTER TABLE workflow_runs ADD COLUMN revision INTEGER NOT NULL DEFAULT 0")
            connection.execute("""CREATE TABLE IF NOT EXISTS workflow_dispatch (
                tenant_id TEXT NOT NULL, run_id TEXT NOT NULL, subject TEXT, session TEXT,
                fence INTEGER NOT NULL DEFAULT 0, expires REAL NOT NULL DEFAULT 0,
                started INTEGER NOT NULL DEFAULT 0, queued INTEGER NOT NULL DEFAULT 0,
                wakeup INTEGER NOT NULL DEFAULT 0, claimed_wakeup INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (tenant_id, run_id))""")
            connection.execute("PRAGMA user_version = 2")

    @contextmanager
    def _transaction(self):
        with self._lock:
            connection = sqlite3.connect(self.path, timeout=10)
            try:
                connection.execute("BEGIN IMMEDIATE")
                with connection:
                    yield connection
            finally:
                connection.close()

    @staticmethod
    def _get(connection, tenant_id: str, run_id: str) -> WorkflowRun:
        row = connection.execute(
            "SELECT body FROM workflow_runs WHERE tenant_id=? AND run_id=?", (tenant_id, run_id)
        ).fetchone()
        if row is None:
            raise OrchestrationError("ORCH-RUN-NOT-FOUND", "workflow run is not visible to this tenant")
        return _decode(row[0])

    @staticmethod
    def _write(connection, run: WorkflowRun) -> None:
        connection.execute(
            "UPDATE workflow_runs SET state=?, updated_at=?, body=?, revision=revision+1 "
            "WHERE tenant_id=? AND run_id=?",
            (run.state.value, run.updated_at, json.dumps(asdict(run)), run.tenant_id, run.id),
        )

    def create(self, run: WorkflowRun) -> None:
        with self._transaction() as connection:
            if connection.execute(
                "SELECT 1 FROM workflow_runs WHERE tenant_id=? AND run_id=?", (run.tenant_id, run.id)
            ).fetchone():
                raise OrchestrationError("ORCH-RUN-DUPLICATE", "workflow run id already exists")
            active = connection.execute(
                "SELECT COUNT(*) FROM workflow_runs WHERE state NOT IN ('COMPLETED','FAILED','CANCELED')"
            ).fetchone()[0]
            if active >= self.max_runs:
                raise OrchestrationError("ORCH-RUN-CAPACITY", "workflow run store is at capacity")
            connection.execute(
                "INSERT INTO workflow_runs (tenant_id,run_id,state,updated_at,body) VALUES (?,?,?,?,?)",
                (run.tenant_id, run.id, run.state.value, run.updated_at, json.dumps(asdict(run))),
            )
            connection.execute(
                "UPDATE workflow_dispatch SET subject=NULL,session=NULL,expires=0,started=0,queued=0,"
                "wakeup=0,claimed_wakeup=0,fence=fence+1 WHERE tenant_id=? AND run_id=?",
                (run.tenant_id, run.id),
            )

    def save(self, run: WorkflowRun) -> None:
        with self._transaction() as connection:
            prior = self._get(connection, run.tenant_id, run.id)
            self._write(connection, _merge_run(prior, run))

    def get(self, *, tenant_id: str, run_id: str) -> WorkflowRun:
        with self._transaction() as connection:
            return self._get(connection, tenant_id, run_id)

    def list(self, *, tenant_id: str | None = None) -> tuple[WorkflowRun, ...]:
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT body FROM workflow_runs" + (" WHERE tenant_id=?" if tenant_id is not None else ""),
                (tenant_id,) if tenant_id is not None else (),
            ).fetchall()
        return tuple(sorted((_decode(row[0]) for row in rows), key=lambda run: (run.created_at, run.id), reverse=True))

    def approve(self, *, tenant_id: str, run_id: str, task_id: str, approved_by: str) -> WorkflowRun:
        with self._transaction() as connection:
            prior = self._get(connection, tenant_id, run_id)
            run = replace(prior, approvals={**prior.approvals, task_id: approved_by}, updated_at=_now())
            self._write(connection, _merge_run(prior, run))
            if prior.state not in _RUN_TERMINAL:
                connection.execute(
                    "UPDATE workflow_dispatch SET queued=1,wakeup=wakeup+1 WHERE tenant_id=? AND run_id=?",
                    (tenant_id, run_id),
                )
            return run

    def prune(self, *, tenant_id: str, before: str) -> int:
        cutoff = datetime.fromisoformat(before.replace("Z", "+00:00"))
        if cutoff.tzinfo is None:
            raise ValueError("retention cutoff must include a timezone")
        with self._transaction() as connection:
            rows = connection.execute("SELECT body FROM workflow_runs WHERE tenant_id=?", (tenant_id,)).fetchall()
            ids = [
                run.id
                for row in rows
                if (run := _decode(row[0])).state in _RUN_TERMINAL
                and datetime.fromisoformat(run.updated_at.replace("Z", "+00:00")) < cutoff
            ]
            connection.executemany(
                "DELETE FROM workflow_runs WHERE tenant_id=? AND run_id=?", ((tenant_id, run_id) for run_id in ids)
            )
            # Retain generation tombstones: a reused run ID must never accept an old worker fence.
            return len(ids)

    def close(self) -> None:
        """Connections close after every operation; no background resources remain."""
