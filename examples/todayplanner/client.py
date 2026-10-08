"""Narrow OAuth connector for an approved schedule-time change on a local fixture."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import select
import subprocess
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlencode, urlsplit


class PlannerHTTPError(RuntimeError):
    def __init__(self, status, code):
        super().__init__(f"todayPlanner returned {status}: {code}")
        self.status, self.code = status, code


def fingerprint(arguments):
    """Match today's API parsed patch (this connector permits startMinute only)."""
    value = ["PATCH", "/api/tasks/" + arguments["taskId"], arguments["expectedRevision"], arguments["patch"]]
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()


class PlannerClient:
    def __init__(self, base, token):
        parsed = urlsplit(base)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or parsed.path:
            raise ValueError("this disposable demo only connects to a loopback fixture")
        self.port, self.token = parsed.port, token
        self.write_attempts = 0

    def request(self, method, path, body=None, *, fault=None):
        if not path.startswith("/api/") or "\r" in path or "\n" in path:
            raise ValueError("invalid planner path")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        if fault:
            headers["X-Interlock-Demo-Fault"] = fault
        try:
            connection.request(method, path, body=json.dumps(body).encode() if body is not None else None,
                               headers=headers)
            response = connection.getresponse()
            payload = json.loads(response.read())
            if not 200 <= response.status < 300:
                raise PlannerHTTPError(response.status, payload.get("code", "API_ERROR"))
            return payload
        finally:
            connection.close()

    def state(self):
        return self.request("GET", "/api/state")

    def update(self, arguments, operation_id, *, fault=None):
        self.write_attempts += 1
        return self.request("PATCH", "/api/tasks/" + arguments["taskId"], {
            "expectedRevision": arguments["expectedRevision"], "patch": arguments["patch"],
            "operationId": operation_id,
        }, fault=fault)

    def receipt(self, operation_id, request_fingerprint, *, seal=False):
        path = "/api/operations/" + operation_id
        if seal:
            return self.request("POST", path + "/resolve", {"fingerprint": request_fingerprint})
        return self.request("GET", path + "?" + urlencode({"fingerprint": request_fingerprint}))


@contextmanager
def local_fixture(project: Path):
    project = project.resolve()
    launcher = project / "node_modules/tsx/dist/cli.mjs"
    if not launcher.is_file() or not (project / "server/oauth-fixture.ts").is_file():
        raise RuntimeError("todayPlanner checkout and its npm dependencies are required")
    process = subprocess.Popen(
        ["node", str(launcher), str(Path(__file__).with_name("fixture.mts"))],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "TODAYPLANNER_ROOT": str(project)},
    )
    try:
        if not select.select([process.stdout], [], [], 20)[0]:
            raise RuntimeError("todayPlanner fixture startup exceeded 20 seconds")
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("todayPlanner fixture failed: " + process.stderr.read()[-2000:])
        yield json.loads(line)
    finally:
        if process.stdin:
            process.stdin.close()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)
        finally:
            process.stdout.close()
            process.stderr.close()
