"""Authenticated loopback host for Studio, with private local bootstrap files."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import signal
import stat
import sys
import threading
from collections.abc import Sequence
from contextlib import ExitStack, contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from .control_plane import ControlPlaneAPI, ControlPlaneConfig
from .ledger_http import (
    LedgerAPIPrincipal,
    LedgerHTTPAPI,
    LedgerHTTPConfig,
    StaticBearerAuthenticator,
    create_ledger_http_server,
)
from .project_store import SQLiteProjectStore
from .run_control import RunControlService
from .signing import ed25519_public_key_bytes
from .sqlite_ledger import SQLiteLedger
from .studio_deploy import GitBundleStore, TrustedApprovalKey, _write_json
from .workflow_store import SQLiteWorkflowRunStore

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_SCOPES = frozenset({
    "deploy:read", "deploy:propose", "deploy:approve", "deploy:promote",
    "run:create", "run:read", "run:approve", "run:cancel", "run:prune",
    "events:write", "events:read", "statistics:read", "telemetry:write",
    "project:read", "project:write",
})


@contextmanager
def single_owner(path: Path):
    """One POSIX host owns dispatch for this directory and bundle repository."""
    try:
        import fcntl
    except ImportError as error:
        raise RuntimeError("the local host requires POSIX file locks (macOS or Linux)") from error
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(f"another host owns {path.parent}") from error
        yield


def _private_text(path: Path) -> str:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or path.stat().st_mode & 0o077:
        raise ValueError(f"{path} must be a private regular file; set permissions to 0600")
    return path.read_text(encoding="utf-8")


def _create_private(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def bootstrap(data_dir: Path) -> dict:
    """Initialize once. Subsequent startup reads public trust, never private reviewer seeds."""
    config_path = data_dir / "config.json"
    if not config_path.exists():
        if any((data_dir / name).exists() for name in ("operator.token", "reviewers", "trusted-approvers.json")):
            raise ValueError("incomplete local bootstrap; preserve keys and restore config.json before restarting")
        # Require the signing extra before writing any bootstrap file.
        seeds = {f"reviewer-{number}": secrets.token_bytes(32) for number in (1, 2)}
        trusted = {
            key_id: {"approverId": key_id, "publicKeyHex": ed25519_public_key_bytes(seed).hex()}
            for key_id, seed in seeds.items()
        }
        (data_dir / "reviewers").mkdir(mode=0o700)
        for key_id, seed in seeds.items():
            _create_private(data_dir / "reviewers" / f"{key_id}.key", seed.hex() + "\n")
        _create_private(data_dir / "operator.token", secrets.token_urlsafe(32) + "\n")
        _write_json(data_dir / "trusted-approvers.json", trusted)
        _write_json(config_path, {"version": 1, "tenantId": "tenant-local", "credentialEnv": {}})
    config = json.loads(_private_text(config_path))
    if (not isinstance(config, dict) or set(config) != {"version", "tenantId", "credentialEnv"}
            or config["version"] != 1 or not isinstance(config["tenantId"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", config["tenantId"])):
        raise ValueError("config.json requires version 1, tenantId and credentialEnv")
    mapping = config["credentialEnv"]
    if not isinstance(mapping, dict) or any(
        not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", ref)
        or not isinstance(env_name, str) or not _ENV_NAME.fullmatch(env_name)
        for ref, env_name in mapping.items()
    ):
        raise ValueError("credentialEnv must map safe reference names to environment variable names")
    return config


def _local_principals(directory: Path, tenant_id: str, operator_token: str, *, remote: bool = False):
    """Resolve host-managed team tokens once, keeping project grants separate from API scopes."""
    principals = {operator_token: LedgerAPIPrincipal("local-operator", tenant_id, _SCOPES,
                                                    frozenset({"local-operator"}))}
    permissions = {"local-operator": {"*": frozenset({"read", "write", "deploy"})}}
    path = directory / "principals.json"
    members = json.loads(_private_text(path)) if path.exists() or path.is_symlink() else []
    if not isinstance(members, list):
        raise ValueError("principals.json must be a list of subject, tokenEnv, scopes and projects")
    for member in members:
        if not isinstance(member, dict) or set(member) != {"subject", "tokenEnv", "scopes", "projects"}:
            raise ValueError("each principal requires subject, tokenEnv, scopes and projects")
        subject, env, scopes, projects = (member[key] for key in ("subject", "tokenEnv", "scopes", "projects"))
        if (not isinstance(subject, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", subject)
                or subject in permissions or not isinstance(env, str) or not _ENV_NAME.fullmatch(env)
                or not isinstance(scopes, list) or any(not isinstance(scope, str) or scope not in _SCOPES
                                                      for scope in scopes)
                or not isinstance(projects, dict)):
            raise ValueError("principals require distinct subjects, valid tokenEnv, known scopes and project grants")
        grants = {}
        for project, values in projects.items():
            if (not isinstance(project, str) or project != "*" and (
                    len(project) > 128 or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", project))
                    or not isinstance(values, list)
                    or any(not isinstance(value, str) or value not in {"read", "write", "deploy"} for value in values)):
                raise ValueError("project grants require a project slug or * and read/write/deploy permissions")
            grants[project] = frozenset(values)
        if set(scopes) & {"events:read", "events:write", "statistics:read", "telemetry:write"}:
            if "read" not in grants.get("*", ()):
                raise ValueError("global ledger scopes require host-wide * read permission")
        token = os.environ.get(env)
        if (not token or len(token) > 4096 or any(character.isspace() for character in token)
                or token in principals):
            raise ValueError("principal token environment variables must contain distinct nonempty bearer tokens")
        principals[token] = LedgerAPIPrincipal(subject, tenant_id, frozenset(scopes), frozenset({subject}))
        permissions[subject] = grants
    if remote:
        path = directory / "workers.json"
        workers = json.loads(_private_text(path)) if path.exists() or path.is_symlink() else []
        if not isinstance(workers, list):
            raise ValueError("workers.json must be a list of subject, tokenEnv and projects")
        for worker in workers:
            if not isinstance(worker, dict) or set(worker) != {"subject", "tokenEnv", "projects"}:
                raise ValueError("each worker requires subject, tokenEnv and projects")
            subject, env, projects = (worker[key] for key in ("subject", "tokenEnv", "projects"))
            if (not isinstance(subject, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", subject)
                    or subject in permissions or not isinstance(env, str) or not _ENV_NAME.fullmatch(env)
                    or not isinstance(projects, list) or not projects
                    or any(not isinstance(project, str) or project != "*" and (
                        len(project) > 128 or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", project))
                           for project in projects)):
                raise ValueError("workers require distinct subjects, valid tokenEnv and project slugs or *")
            token = os.environ.get(env)
            if (not token or len(token) > 4096 or any(character.isspace() for character in token)
                    or token in principals):
                raise ValueError("worker token environment variables must contain distinct nonempty bearer tokens")
            principals[token] = LedgerAPIPrincipal(subject, tenant_id, frozenset({"worker:execute"}))
            permissions[subject] = {project: frozenset({"execute"}) for project in projects}
    return StaticBearerAuthenticator.from_tokens(principals), permissions


class _LocalAPI(LedgerHTTPAPI):
    def __init__(self, ledger, authenticator, *, control: ControlPlaneAPI, config: LedgerHTTPConfig):
        super().__init__(ledger, authenticator, config=config)
        self.control = control

    def handle(self, handler) -> None:
        path = urlsplit(handler.path).path
        if path in {"/v1/events", "/v1/traces", "/v1/statistics", "/v1/interactions"} or path.startswith("/v1/traces/"):
            super().handle(handler)
        else:
            self.control.handle(handler)


@contextmanager
def serve_local(
    data_dir: str | Path, *, port: int = 8787, origins: Sequence[str] = (), postgres_dsn_env: str | None = None,
    dispatch: str = "local", lease_seconds: float = 30, effect_resolver=None,
):
    """Start one loopback server and close dispatch within ten seconds on exit."""
    from .configurable_runtime import configurable_adapter_provider

    if not 0 <= port <= 65535:
        raise ValueError("port must be between 0 and 65535")
    if dispatch not in {"local", "remote"}:
        raise ValueError("dispatch must be local or remote")
    control_config = ControlPlaneConfig(allowed_origins=frozenset(origins))
    ledger_config = LedgerHTTPConfig(allowed_origins=frozenset(origins))
    directory = Path(data_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.stat().st_mode & 0o077:
        raise ValueError(f"{directory} must be private; set directory permissions to 0700")
    with ExitStack() as stack:
        stack.enter_context(single_owner(directory / "owner.lock"))
        config = bootstrap(directory)
        token = _private_text(directory / "operator.token").strip()
        authenticator, project_permissions = _local_principals(directory, config["tenantId"], token,
                                                              remote=dispatch == "remote")
        public = json.loads(_private_text(directory / "trusted-approvers.json"))
        if not isinstance(public, dict) or len(public) < 2:
            raise ValueError("trusted-approvers.json must contain at least two public reviewer keys")
        trusted = {}
        for key_id, item in public.items():
            if (not isinstance(key_id, str) or not isinstance(item, dict)
                    or set(item) != {"approverId", "publicKeyHex"}
                    or not isinstance(item["approverId"], str) or not item["approverId"].strip()
                    or not isinstance(item["publicKeyHex"], str)):
                raise ValueError("trusted approvers require key ID, approverId and publicKeyHex")
            trusted[key_id] = TrustedApprovalKey(item["approverId"], bytes.fromhex(item["publicKeyHex"]))
        credentials = {
            ref: os.environ[name] for ref, name in config["credentialEnv"].items() if os.environ.get(name)
        }
        if postgres_dsn_env is not None:
            from .postgres_ledger import PostgreSQLLedger

            if not _ENV_NAME.fullmatch(postgres_dsn_env) or not os.environ.get(postgres_dsn_env):
                raise ValueError("--postgres-dsn-env must name a nonempty DSN environment variable")
            ledger = PostgreSQLLedger.from_dsn(os.environ[postgres_dsn_env], bound_tenant_id=config["tenantId"])
            try:
                ledger.trace(config["tenantId"], "local-host-startup-check")
            except Exception as error:
                raise RuntimeError("PostgreSQL unavailable; verify the existing schema and tenant role") from error
        else:
            ledger = SQLiteLedger(directory / "ledger.sqlite3")
        run_store = SQLiteWorkflowRunStore(directory / "runs.sqlite3")
        stack.callback(run_store.close)
        store = GitBundleStore(directory / "bundles", tenant_id=config["tenantId"])
        stack.enter_context(single_owner(store.approval_path().with_name("interlock-host.lock")))
        dispatcher = None
        if dispatch == "remote":
            from .distributed import DistributedCoordinator

            worker_projects = {subject: frozenset(project for project, grants in projects.items()
                                                 if "execute" in grants)
                               for subject, projects in project_permissions.items()
                               if any("execute" in grants for grants in projects.values())}
            dispatcher = DistributedCoordinator(run_store, store, ledger, worker_projects=worker_projects,
                                                lease_seconds=lease_seconds)
        service = RunControlService(
            store, configurable_adapter_provider(ledger, run_store, credentials), ledger=ledger, run_store=run_store,
            dispatcher=dispatcher, effect_resolver=effect_resolver,
        )
        stack.callback(service.close, timeout=10)
        control = ControlPlaneAPI(
            store, authenticator, trusted_approvers=trusted, run_service=service,
            config=control_config, runtime_credentials=credentials, credential_env=config["credentialEnv"],
            project_store=SQLiteProjectStore(directory / "projects.sqlite3"),
            project_permissions=project_permissions,
        )
        server = create_ledger_http_server(
            _LocalAPI(ledger, authenticator, control=control, config=ledger_config), port=port,
        )
        stack.callback(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        stack.callback(thread.join, 2)
        stack.callback(server.shutdown)
        yield server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="interlock serve", description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--dispatch", choices=("local", "remote"), default="local",
                        help="execute here or dispatch to authenticated remote workers")
    parser.add_argument("--lease-seconds", type=float, default=30,
                        help="remote worker ownership lifetime; workers renew it while executing")
    parser.add_argument("--origin", action="append", default=[], help="allow this Studio Origin (repeatable)")
    parser.add_argument("--postgres-dsn-env",
                        help="read an existing tenant-scoped PostgreSQL DSN from this environment variable")
    args = parser.parse_args(argv)
    try:
        with serve_local(
            args.data_dir, port=args.port, origins=args.origin, postgres_dsn_env=args.postgres_dsn_env,
            dispatch=args.dispatch, lease_seconds=args.lease_seconds,
        ) as server:
            directory = args.data_dir.resolve()
            config = json.loads((directory / "config.json").read_text())
            stop = threading.Event()
            previous = signal.signal(signal.SIGTERM, lambda *_: stop.set())
            print(f"Studio API: http://127.0.0.1:{server.server_port}", flush=True)
            print(f"Tenant: {config['tenantId']}", flush=True)
            print(f"Dispatch: {args.dispatch}", flush=True)
            print(f"Operator token file: {directory / 'operator.token'}", flush=True)
            print(f"Reviewer key files: {directory / 'reviewers/reviewer-1.key'}, "
                  f"{directory / 'reviewers/reviewer-2.key'}",
                  flush=True)
            print("Local bootstrap: two keys held by one user do not prove two-person review.", flush=True)
            try:
                stop.wait()
            except KeyboardInterrupt:
                pass
            finally:
                signal.signal(signal.SIGTERM, previous)
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"error": {"code": "INTERLOCK-HOST-STARTUP-INVALID", "message": str(error)}}),
              file=sys.stderr)
        return 2
