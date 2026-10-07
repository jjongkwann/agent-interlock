"""A real worker death after an external POST must never replay the committed call."""
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import test_distributed_host
from test_candidate_compare import graph
from test_run_control import CRYPTO_AVAILABLE

from agent_interlock.configurable_runtime import RUNTIME_KEY
from agent_interlock.local_host import serve_local
from agent_interlock.models import SideEffect

ROOT = Path(__file__).resolve().parents[1]
WORKER = r'''
import json, os, sys
from urllib.request import Request, urlopen
from agent_interlock.remote_worker import CoordinatorClient, RemoteWorker
client = CoordinatorClient(sys.argv[1], os.environ[sys.argv[5]], allow_loopback_http=True)
original = client.call
def call(operation, body):
    result = original(operation, body)
    if operation == 'claim':
        print(json.dumps(result['claim']), flush=True)
    return result
client.call = call
def request(endpoint, method, body, headers, **kwargs):
    outgoing = Request(sys.argv[3], data=body, method='POST', headers={'Content-Type':'application/json'})
    with urlopen(outgoing, timeout=3) as response:
        content = response.read()
    if sys.argv[4] == 'crash':
        os._exit(73)
    return 200, {'content-type':'application/json'}, content
RemoteWorker(client, target_id=sys.argv[2], tenant_id='tenant-local', credentials={}, http_request=request).run_once()
'''


@unittest.skipUnless(CRYPTO_AVAILABLE, "Ed25519 backend required")
class DistributedFailureTests(unittest.TestCase):
    setUp = test_distributed_host.DistributedHostTests.setUp
    request = staticmethod(test_distributed_host.DistributedHostTests.request)
    promote = test_distributed_host.DistributedHostTests.promote

    def process(self, server, fixture_url, *, crash, worker_number=1):
        process = subprocess.Popen([sys.executable, "-c", WORKER,
            f"http://127.0.0.1:{server.server_port}", self.store.target_id, fixture_url,
            "crash" if crash else "return", f"INTERLOCK_DIST_TEST_{worker_number}"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={**os.environ})
        try:
            output, error = process.communicate(timeout=20)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
        self.assertEqual(process.returncode, 73 if crash else 0, output + error)
        for token in self.tokens.values():
            self.assertNotIn(token, output + error)
        return json.loads(output)

    def test_process_dies_after_post_is_never_reassigned_even_after_restart(self):
        effects = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                effects.append(json.loads(body))
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        fixture = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=fixture.serve_forever, daemon=True).start()
        self.addCleanup(fixture.server_close)
        self.addCleanup(fixture.shutdown)
        fixture_url = f"http://127.0.0.1:{fixture.server_port}/effect"
        architecture = graph()
        target = architecture.nodes[1]
        target = replace(target, actor=replace(target.actor, side_effects=frozenset({SideEffect.EXTERNAL_WRITE}),
            allowed_domains=frozenset({"service.example"})), annotations={RUNTIME_KEY:{
                "kind":"HTTP_JSON", "method":"POST", "endpoint":"https://service.example/effect",
                "purpose":"TRANSFORM", "dataClasses":["D3"], "arguments":{"$path":"input"}}})
        architecture = replace(architecture, nodes=(architecture.nodes[0], target))
        with patch("test_distributed_host.graph", return_value=architecture):
            self.promote(approval=True)
        with serve_local(self.path, port=0, dispatch="remote") as server:
            status, _, created = self.request(server, "POST", "/v1/runs", token=self.token,
                body={"input":{"message":"commit once"}, "runId":"ambiguous"})
            self.assertEqual(status, 202, created)
            self.process(server, fixture_url, crash=False)  # Initial task-level approval gate.
            self.assertEqual(effects, [])
            status, _, approved = self.request(server, "POST", "/v1/runs/ambiguous/tasks/transform/approve",
                                               token=self.token, body={})
            self.assertEqual(status, 202, approved)
            abandoned = self.process(server, fixture_url, crash=True)
            self.assertEqual(effects, [{"message":"commit once"}])
            future = time.time() + 3600
            with patch("agent_interlock.distributed.time.time", return_value=future):
                self.assertIsNone(self.process(server, fixture_url, crash=False, worker_number=2))
            failed = self.request(server, "GET", "/v1/runs/ambiguous", token=self.token)[2]["run"]
            self.assertEqual(failed["state"], "FAILED", failed)
            self.assertEqual(failed["errorCode"], "RUN-EFFECT-UNCERTAIN")
            stale = {"runId":"ambiguous", "sessionId":abandoned["owner"], "fence":abandoned["fence"]}
            for operation, extra in (("start", {}), ("save", {"revision":abandoned["revision"],
                                                            "run":abandoned["run"]})):
                status, _, body = self.request(server, "POST", f"/v1/workers/{operation}",
                    token=self.tokens["INTERLOCK_DIST_TEST_1"], body={**stale, **extra})
                self.assertEqual(status, 409, body)
                self.assertEqual(body["error"]["code"], "WORKER-LEASE-LOST")
        with serve_local(self.path, port=0, dispatch="remote") as server:
            persisted = self.request(server, "GET", "/v1/runs/ambiguous", token=self.token)[2]["run"]
            self.assertEqual((persisted["state"], persisted["errorCode"]), ("FAILED", "RUN-EFFECT-UNCERTAIN"))
            self.assertIsNone(self.process(server, fixture_url, crash=False, worker_number=2))
        self.assertEqual(effects, [{"message":"commit once"}])
