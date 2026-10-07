"""Dedicated single-owner Control Plane, Run Control and PostgreSQL Ledger host.

Run ``python -m examples.support_agent.host --help`` from this checkout.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import threading
from contextlib import ExitStack, contextmanager
from pathlib import Path

from agent_interlock.control_plane import ControlPlaneAPI, ControlPlaneConfig, create_control_plane_server
from agent_interlock.ledger_http import (
    LedgerAPIPrincipal,
    LedgerHTTPAPI,
    LedgerHTTPConfig,
    StaticBearerAuthenticator,
    create_ledger_http_server,
)
from agent_interlock.postgres_ledger import PostgreSQLLedger
from agent_interlock.run_control import RunControlService
from agent_interlock.studio_deploy import GitBundleStore, TrustedApprovalKey
from agent_interlock.workflow_store import SQLiteWorkflowRunStore

from .build import TENANT_ID
from .managed import adapter_provider


@contextmanager
def single_owner(path: Path):
    """The workflow store and execution permits have one process owner."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with os.fdopen(os.open(path, os.O_CREAT | os.O_RDWR, 0o600), "a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("another managed host owns this workflow database") from error
        yield


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-repo", required=True, type=Path)
    parser.add_argument("--run-db", required=True, type=Path)
    parser.add_argument("--trusted-approvers", required=True, type=Path,
                        help='JSON object: key ID -> {"approverId": "...", "publicKeyHex": "..."}')
    parser.add_argument("--principals", required=True, type=Path,
                        help="JSON list of subject, scopes, tokenEnv entries; bearer secrets remain in environment")
    parser.add_argument("--control-port", type=int, default=8787)
    parser.add_argument("--ledger-port", type=int, default=8788)
    parser.add_argument("--origin", action="append", default=[])
    args = parser.parse_args()
    dsn = os.environ.get("INTERLOCK_POSTGRES_DSN")
    if not dsn:
        parser.error("INTERLOCK_POSTGRES_DSN is required (a tenant-scoped PostgreSQL role)")
    principals = json.loads(args.principals.read_text(encoding="utf-8"))
    tokens = {}
    for item in principals:
        token = os.environ.get(item["tokenEnv"])
        if not token or token in tokens:
            parser.error("each principal needs a distinct, nonempty bearer token environment variable")
        tokens[token] = LedgerAPIPrincipal(item["subject"], TENANT_ID, frozenset(item["scopes"]))
    if not tokens:
        parser.error("at least one authenticated principal is required")
    authenticator = StaticBearerAuthenticator.from_tokens(tokens)
    trusted = {
        key: TrustedApprovalKey(value["approverId"], bytes.fromhex(value["publicKeyHex"]))
        for key, value in json.loads(args.trusted_approvers.read_text(encoding="utf-8")).items()
    }
    ledger = PostgreSQLLedger.from_dsn(dsn, bound_tenant_id=TENANT_ID)
    # Fail startup when the durable ledger cannot be reached or migrations/tenant RLS are missing.
    ledger.trace(TENANT_ID, "managed-host-startup-check")
    run_db = args.run_db.resolve()
    with single_owner(run_db.with_suffix(run_db.suffix + ".lock")), ExitStack() as stack:
        run_store = SQLiteWorkflowRunStore(run_db, max_runs=1024)
        stack.callback(run_store.close)
        deployment_store = GitBundleStore(args.bundle_repo, tenant_id=TENANT_ID)
        stack.enter_context(single_owner(deployment_store.approval_path().with_name("interlock-host.lock")))
        run_service = RunControlService(
            deployment_store, adapter_provider(ledger, run_store), ledger=ledger, run_store=run_store,
        )
        stack.callback(run_service.close)
        origins = frozenset(args.origin)
        control = create_control_plane_server(ControlPlaneAPI(
            deployment_store, authenticator, trusted_approvers=trusted, run_service=run_service,
            config=ControlPlaneConfig(allowed_origins=origins),
        ), port=args.control_port)
        stack.callback(control.server_close)
        evidence = create_ledger_http_server(LedgerHTTPAPI(
            ledger, authenticator, config=LedgerHTTPConfig(allowed_origins=origins),
        ), port=args.ledger_port)
        stack.callback(evidence.server_close)
        for server in (control, evidence):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            stack.callback(server.shutdown)
        print(f"Control Plane: http://127.0.0.1:{control.server_port}", flush=True)
        print(f"Ledger: http://127.0.0.1:{evidence.server_port}", flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
