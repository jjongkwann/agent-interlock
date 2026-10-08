"""Outbound whole-run worker; a lost lease never authorizes a local replay."""
from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import re
import signal
import sys
import threading
import time
import uuid
from collections.abc import Mapping
from dataclasses import asdict, replace
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .architecture import ArchitectureCompiler
from .canonical import canonical_digest
from .configurable_runtime import _anthropic_client, _request, configurable_adapter_provider
from .ledger import Event, build_event, verify_event
from .orchestration import CallableTaskAdapter, OrchestrationEngine
from .studio_deploy import deployed_architecture
from .workflow_store import _decode

MAX_RESPONSE_BYTES = 16 * 1024 * 1024
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_REF_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")


class WorkerError(RuntimeError):
    """A coordinator request or execution lease can no longer be trusted."""
    def __init__(self, message, *, status=None, code=None):
        super().__init__(message)
        self.status, self.code = status, code


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class CoordinatorClient:
    def __init__(self, url: str, token: str, *, allow_loopback_http: bool = False, timeout: float = 5):
        parsed = urlsplit(url)
        try:
            loopback = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname or "").is_loopback
        except ValueError:
            loopback = False
        if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path not in {"", "/"}
                or (parsed.scheme != "https" and not (allow_loopback_http and parsed.scheme == "http" and loopback))):
            raise ValueError("coordinator must be an HTTPS origin; loopback HTTP requires --allow-loopback-http")
        parsed.port  # Validate malformed ports before any request.
        if not token or len(token) > 8192 or any(ord(char) < 33 for char in token):
            raise ValueError("coordinator bearer token is missing or invalid")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("request timeout must be positive")
        self.url, self.token, self.timeout = url.rstrip("/"), token, timeout
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def call(self, operation: str, body: Mapping) -> dict:
        if operation not in {"claim", "start", "heartbeat", "get", "save", "append", "trace", "finish", "checkpoint"}:
            raise ValueError("unsupported worker operation")
        data = json.dumps(body, allow_nan=False, separators=(",", ":")).encode()
        if len(data) > MAX_RESPONSE_BYTES:
            raise WorkerError("worker request exceeds its size limit")
        request = Request(f"{self.url}/v1/workers/{operation}", data=data, method="POST", headers={
            "Authorization": "Bearer " + self.token, "Content-Type": "application/json", "Accept": "application/json",
        })
        try:
            deadline = time.monotonic() + self.timeout
            with self.opener.open(request, timeout=self.timeout) as response:
                content = bytearray()
                while len(content) <= MAX_RESPONSE_BYTES:
                    if time.monotonic() >= deadline:
                        raise TimeoutError
                    chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - len(content)))
                    if not chunk:
                        break
                    content.extend(chunk)
                if len(content) > MAX_RESPONSE_BYTES:
                    raise WorkerError("coordinator response exceeds its size limit")
                result = json.loads(content)
                if not isinstance(result, dict):
                    raise WorkerError("coordinator response must be a JSON object")
                return result
        except HTTPError as error:
            try:
                code = json.loads(error.read(4096)).get("error", {}).get("code")
            except Exception:
                code = None
            if not isinstance(code, str) or not re.fullmatch(r"[A-Z0-9-]{1,80}", code):
                code = None
            raise WorkerError(f"coordinator rejected worker request (HTTP {error.code})",
                              status=error.code, code=code) from None
        except WorkerError:
            raise
        except Exception:
            # Never print URLs, request headers, credentials, or untrusted response bodies.
            raise WorkerError("coordinator request failed; execution acknowledgement is unknown") from None


class _Lease:
    def __init__(self, client, claim, session_id, *, request_started=None):
        self.client, self.claim = client, claim
        self.identity = {"runId": claim["runId"], "sessionId": session_id, "fence": claim["fence"]}
        self.lock = threading.RLock()
        self.failed = False
        self.deadline = 0.0
        self.renew(claim, request_started if request_started is not None else time.monotonic())

    def renew(self, response, request_started):
        duration = float(self.claim["leaseSeconds"])
        if (not math.isfinite(float(response["expiresAt"])) or not math.isfinite(duration)
                or not 0 < duration <= 3600):
            self.failed = True
            raise WorkerError("invalid worker lease acknowledgement")
        # Server wall clocks may differ. Deduct the full request duration from its granted TTL.
        self.deadline = request_started + duration
        self.check()

    def check(self):
        if self.failed or time.monotonic() >= self.deadline:
            self.failed = True
            raise WorkerError("worker lease is no longer valid; this execution will not be retried")

    def call(self, operation, **body):
        with self.lock:
            self.check()
            try:
                request_started = time.monotonic()
                response = self.client.call(operation, {**self.identity, **body})
                self.check()
                if operation == "heartbeat":
                    if response.get("canceled"):
                        raise WorkerError("coordinator canceled the run")
                    self.renew(response, request_started)
                return response
            except WorkerError as error:
                if not (operation == "save" and error.status == 409 and error.code == "WORKER-REVISION-CONFLICT"):
                    self.failed = True
                raise
            except Exception:
                self.failed = True
                raise


class RemoteRunStore:
    """Serialize snapshots; reconcile known approval conflicts without retrying unknown acknowledgements."""
    def __init__(self, lease):
        self.lease = lease
        self.revision = lease.claim["revision"]
        self.lock = threading.RLock()

    def _scope(self, tenant_id, run_id):
        if (tenant_id, run_id) != (self.lease.claim["tenantId"], self.lease.claim["runId"]):
            raise WorkerError("run is outside this worker lease")

    def _read(self, response):
        try:
            run = _decode(json.dumps(response["run"]))
            self._scope(run.tenant_id, run.id)
            if run.bundle_digest != self.lease.claim["bundleDigest"]:
                raise WorkerError("run bundle changed during execution")
            revision = response["revision"]
            if type(revision) is not int or revision < self.revision:
                raise WorkerError("invalid coordinator run revision")
            self.revision = revision
            return run
        except Exception:
            self.lease.failed = True
            raise

    def get(self, *, tenant_id, run_id):
        with self.lock:
            self._scope(tenant_id, run_id)
            return self._read(self.lease.call("get"))

    def save(self, run):
        with self.lock:
            self._scope(run.tenant_id, run.id)
            for attempt in range(3):
                try:
                    self._read(self.lease.call("save", revision=self.revision, run=asdict(run)))
                    return
                except WorkerError as error:
                    if error.status != 409 or error.code != "WORKER-REVISION-CONFLICT" or attempt == 2:
                        self.lease.failed = True
                        raise
                    latest = self.get(tenant_id=run.tenant_id, run_id=run.id)
                    if latest.state.value in {"CANCELED", "FAILED", "COMPLETED"}:
                        return
                    run = replace(run, approvals=latest.approvals)

    def checkpoint_effect(self, *, tenant_id, run_id, task_id, checkpoint, expected):
        with self.lock:
            self._scope(tenant_id, run_id)
            self._read(self.lease.call("checkpoint", taskId=task_id, checkpoint=checkpoint, expected=expected))


class RemoteLedger:
    def __init__(self, lease, trace_id):
        self.lease, self.trace_id = lease, trace_id

    def _event(self, value):
        try:
            event = Event(**value)
            if (event.tenant_id != self.lease.claim["tenantId"] or event.trace_id != self.trace_id
                    or not verify_event(event)):
                raise WorkerError("coordinator returned invalid or out-of-scope evidence")
            return event
        except Exception:
            self.lease.failed = True
            raise

    def append(self, event_type, *, idempotency_key=None, **fields):
        if idempotency_key is not None:
            raise WorkerError("remote event append does not support caller idempotency keys")
        event = self._event(build_event(event_type, **fields).to_dict())
        stored = self._event(self.lease.call("append", event=event.to_dict())["event"])
        if (stored.event_type, stored.source_actor_id, stored.target_actor_id) != (
                event.event_type, event.source_actor_id, event.target_actor_id):
            self.lease.failed = True
            raise WorkerError("coordinator changed event routing")
        return stored

    def trace(self, tenant_id, trace_id):
        if (tenant_id, trace_id) != (self.lease.claim["tenantId"], self.trace_id):
            raise WorkerError("trace is outside this worker lease")
        return tuple(self._event(item) for item in self.lease.call("trace")["events"])


class RemoteWorker:
    def __init__(self, client, *, target_id: str, tenant_id: str, credentials: Mapping[str, str],
                 http_request=_request, anthropic_client_factory=_anthropic_client, model_http_request=_request):
        if not target_id or not tenant_id:
            raise ValueError("target and tenant pins are required")
        self.client, self.target_id, self.tenant_id = client, target_id, tenant_id
        self.credentials = dict(credentials)
        self.session_id = str(uuid.uuid4())
        self.http_request, self.anthropic_client_factory = http_request, anthropic_client_factory
        self.model_http_request = model_http_request

    def run_once(self):
        request_started = time.monotonic()
        claim = self.client.call("claim", {"sessionId": self.session_id,
                                          "credentialRefs": sorted(self.credentials)})["claim"]
        if claim is None:
            return False
        if (claim["targetId"] != self.target_id or claim["tenantId"] != self.tenant_id
                or claim["owner"] != self.session_id or type(claim["fence"]) is not int
                or claim["fence"] < 1 or canonical_digest(claim["bundle"]) != claim["bundleDigest"]):
            raise WorkerError("claimed run does not match the pinned deployment context")
        lease = _Lease(self.client, claim, self.session_id, request_started=request_started)
        store = RemoteRunStore(lease)
        run = store._read({"run": claim["run"], "revision": claim["revision"]})
        graph = deployed_architecture(claim["bundle"], "ENFORCE")
        if (graph.id, graph.version) != (run.architecture_id, run.architecture_version):
            raise WorkerError("claimed architecture does not match the run")
        compiled = replace(ArchitectureCompiler().compile(graph), bundle_digest=claim["bundleDigest"])
        ledger = RemoteLedger(lease, run.trace_id)
        lease.call("start")

        def check_run():
            current = store.get(tenant_id=run.tenant_id, run_id=run.id)
            if current.state.value in {"CANCELED", "FAILED", "COMPLETED"}:
                raise WorkerError("run is already terminal")

        def http_request(*args, **kwargs):
            check_run()
            return self.http_request(*args, **kwargs)

        def model_http_request(*args, **kwargs):
            check_run()
            return self.model_http_request(*args, **kwargs)

        def model_client(*args, **kwargs):
            client = self.anthropic_client_factory(*args, **kwargs)

            def tool_runner(**options):
                check_run()
                return client.beta.messages.tool_runner(**options)

            return SimpleNamespace(close=client.close, beta=SimpleNamespace(messages=SimpleNamespace(
                tool_runner=tool_runner)))

        adapters = configurable_adapter_provider(ledger, store, self.credentials,
            http_request=http_request, anthropic_client_factory=model_client,
            model_http_request=model_http_request)(compiled)

        activity = threading.Condition()
        active_calls = 0

        def execute(adapter, value):
            nonlocal active_calls
            with activity:
                active_calls += 1
            try:
                check_run()
                return adapter.execute(value)
            finally:
                with activity:
                    active_calls -= 1
                    activity.notify_all()

        adapters = {transport: CallableTaskAdapter(lambda value, adapter=adapter: execute(adapter, value))
                    for transport, adapter in adapters.items()}
        engine = OrchestrationEngine(compiled, adapters=adapters, run_store=store, ledger=ledger,
            bundle_digest=claim["bundleDigest"], approval_provider=lambda tenant, run_id, task, _context:
                bool(store.get(tenant_id=tenant, run_id=run_id).approvals.get(task.id)))
        done = threading.Event()

        def heartbeat():
            while not done.wait(float(claim["leaseSeconds"]) / 3):
                try:
                    lease.call("heartbeat")
                except Exception:
                    return

        thread = threading.Thread(target=heartbeat, daemon=True)
        thread.start()
        try:
            engine.resume(tenant_id=run.tenant_id, run_id=run.id)
            # The engine may time out a future before its already-started HTTP call returns.
            with activity:
                activity.wait_for(lambda: active_calls == 0)
            lease.call("finish")  # Final state and ledger events have already been acknowledged.
        finally:
            done.set()
            thread.join()
        return True


def main(argv=None):
    parser = argparse.ArgumentParser(prog="interlock worker",
                                     description="Run a trusted outbound Agent Interlock worker")
    parser.add_argument("--coordinator", required=True)
    parser.add_argument("--token-env", required=True)
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--credential-env", action="append", default=[], metavar="REF=ENV")
    parser.add_argument("--allow-loopback-http", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=2)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)
    if not _ENV_NAME.fullmatch(args.token_env) or not math.isfinite(args.poll_seconds) or args.poll_seconds <= 0:
        parser.error("use a valid token environment name and positive polling interval")
    credentials = {}
    for entry in args.credential_env:
        ref, separator, name = entry.partition("=")
        if not separator or not _REF_NAME.fullmatch(ref) or not _ENV_NAME.fullmatch(name) or ref in credentials:
            parser.error("credential mappings must use unique REF=ENV names")
        secret = os.environ.get(name)
        if not secret:
            parser.error("a configured credential environment variable is unavailable")
        credentials[ref] = secret
    try:
        client = CoordinatorClient(args.coordinator, os.environ.get(args.token_env, ""),
                                   allow_loopback_http=args.allow_loopback_http)
        worker = RemoteWorker(client, target_id=args.target_id, tenant_id=args.tenant, credentials=credentials)
    except ValueError as error:
        parser.error(str(error))
    stopping = threading.Event()
    previous = {sig: signal.signal(sig, lambda *_: stopping.set()) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        while not stopping.is_set():
            try:
                worker.run_once()
            except Exception:
                print("Worker stopped this attempt; acknowledgement or lease may be lost. No local replay.",
                      file=sys.stderr)
                if args.once:
                    return 1
            if args.once:
                return 0
            stopping.wait(args.poll_seconds)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
