"""Opt-in CLI-led owned workflow; real pinned ZAP, no Burp specialist execution."""

import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
from urllib.parse import parse_qsl, urlsplit
import uuid

import pytest

from bughunt.core import scanner as bughunt_scanner
from bughunt.core import exchange, job, ledger
from bughunt.integrations import burp_profile, zap, zap_active
from bughunt.core.workspace import workspace_dir
from test_gate import seed_policy

pytestmark = pytest.mark.skipif(os.environ.get("BUGHUNT_WORKBENCH_INTEGRATION") != "1",
                                reason="opt-in owned CLI workflow and actual pinned ZAP consumer")

PREFIX = "/__bughunt_lab__/"
TOKENS = {"Bearer fixture-private-owner": "owner", "Bearer fixture-private-viewer": "viewer"}


class OwnedApplication(BaseHTTPRequestHandler):
    def do_GET(self):
        actor = TOKENS.get(self.headers.get("Authorization"), "anonymous")
        self.server.wire.append({"path": self.path, "actor": actor})
        path = urlsplit(self.path).path
        if path == PREFIX + "whoami":
            principal = "wrong-person" if self.server.outcome == "invalid" and actor == "viewer" else "person-" + actor
            value = {"user": {"id": principal, "role": actor}}
            self._respond(401 if actor == "anonymous" else 200, json.dumps(value).encode(), "application/json")
        elif path == PREFIX + "records":
            permitted = actor == "owner" or (actor == "viewer" and self.server.outcome == "lead")
            body = b'{"id":7,"owned":"record"}' if permitted else b'{"error":"denied"}'
            self._respond(200 if permitted else 403, body, "application/json")
        elif path == PREFIX + "reflect":
            value = dict(parse_qsl(urlsplit(self.path).query)).get("q", "owned")
            body = ("<!doctype html><html><body><p>" + value + "</p></body></html>").encode()
            self._respond(200, body, "text/html; charset=UTF-8")
        else:
            self._respond(404, b"not owned", "text/plain")

    def _respond(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_arguments):
        pass


def cli(capsys, *arguments, expected=0):
    assert bughunt_scanner.main(list(arguments)) == expected
    output = capsys.readouterr().out
    assert "fixture-private" not in output
    return output


def json_cli(capsys, *arguments, expected=0):
    output = cli(capsys, *arguments, expected=expected)
    if output.startswith('{"starting_job_id"'):
        announcement, output = output.split("\n", 1)
        initial, result = json.loads(announcement), json.loads(output)
        assert initial["run_id"] == result["run_id"]
        assert initial["starting_job_id"] == result["job_id"]
        return result
    return json.loads(output)


def configure_actors(capsys, origin):
    for name, kind in (("owner", "owner"), ("viewer", "lower_privilege"), ("anonymous", "anonymous")):
        cli(capsys, "identity", "create", name, "--kind", kind, "--origin", origin, "--owned")
        if name != "anonymous":
            cli(capsys, "identity", "set", name, "authorization", "Bearer fixture-private-" + name)
        arguments = ["verify", "configure", name, "--url", origin + PREFIX + "whoami"]
        if name == "anonymous":
            arguments += ["--status", "401"]
        else:
            arguments += ["--principal-path", "user.id", "--expect-principal", "person-" + name,
                          "--role-path", "user.role", "--expect-role", name]
        cli(capsys, *arguments)


@pytest.fixture
def owned_workbench(monkeypatch, tmp_path, capsys):
    server = ThreadingHTTPServer(("127.0.0.1", 0), OwnedApplication)
    server.wire, server.outcome = [], "negative"
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        document = seed_policy(tmp_path)
        document.update(mission=zap_active.MISSION, limits={"requests_per_second": 5, "concurrency": 1})
        permitted = ["manual", "passive", "process", "active_scan"]
        document["permissions"] = {operation: operation in permitted for operation in document["permissions"]}
        document["assets"] = [{"id": "owned-core", "origin": origin, "methods": ["GET"],
            "operations": permitted, "paths": [PREFIX + name for name in ("whoami", "records", "reflect")]}]
        (tmp_path / "policy.json").write_text(json.dumps(document))
        (tmp_path / "scope.txt").write_text("127.0.0.1\n")
        configure_actors(capsys, origin)
        requests = {}
        for name in ("records", "reflect"):
            path = PREFIX + name + ("?q=owned" if name == "reflect" else "")
            request = f"GET {origin}{path} HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\nX-Trace: owned\r\n\r\n"
            requests[name] = tmp_path / (name + ".http")
            requests[name].write_bytes(request.encode())
        yield server, tmp_path, requests
    finally:
        server.shutdown()
        server.server_close()
        serving.join(timeout=5)
        assert not serving.is_alive()


def capture_and_select(capsys, path):
    previous = {item["run_id"] for item in json_cli(capsys, "ledger", "list")}
    cli(capsys, "repeater", str(path))
    captures = [item for item in json_cli(capsys, "ledger", "list") if item["run_id"] not in previous]
    assert len(captures) == 1 and captures[0]["finished_at"]
    value = json_cli(capsys, "exchange", "import-run", captures[0]["run_id"])
    assert value["inert"] and len(value["exchange_ids"]) == 1
    return value["exchange_ids"][0]


def differential(capsys, request, expected):
    for name in ("owner", "viewer", "anonymous"):
        cli(capsys, "identity", "use", name)
        cli(capsys, "verify", "check", name, expected=2 if expected == "invalid" and name == "viewer" else 0)
    options = [str(request), "--owner", "owner", "--lower", "viewer", "--anonymous", "anonymous"]
    preview = json_cli(capsys, "replay", *options, "--dry-run")
    assert preview["network_requests"] == 0
    result = json_cli(capsys, "replay", *options, expected=2 if expected == "invalid" else 0)
    assert result["classification"] == expected and result["automatic_finding"] is False
    assert result["positive_baseline_run_id"]
    assert "severity" not in result and "finding" not in result
    return result


def assert_sanitized(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith("_b64") and isinstance(item, str):
                assert b"fixture-private" not in base64.b64decode(item, validate=True)
            assert_sanitized(item)
    elif isinstance(value, list):
        for item in value:
            assert_sanitized(item)
    elif isinstance(value, str):
        assert "fixture-private" not in value


def managed(capsys, profile, identifier, *options):
    arguments = [profile, identifier, "--mission", zap_active.MISSION, *options]
    preview = json_cli(capsys, "engine", "dry-run", *arguments)
    assert preview["engine_plan"]["budgets"]["physical_requests"] <= 8
    result = json_cli(capsys, "engine", "start", *arguments)
    assert result["state"] == "success" and result["cleanup_confirmed"] and result["report_run_id"]
    assert json_cli(capsys, "engine", "status", result["job_id"]) == result
    return result


def new_owned_jobs(root, previous, source):
    assert workspace_dir() == root, "Fixture workspace changed during cleanup"
    identifiers = set()
    for path in (root / "jobs").glob("*"):
        if path.name in previous:
            continue
        try:
            if str(uuid.UUID(path.name)) != path.name:
                continue
            _path, metadata, capture = job._capture(path.name)
            analysis = capture.manifest["analysis"]
            if (metadata["engine_profile"] == analysis["profile_id"] == "zap-owned-active"
                    and capture.manifest["tool"] == "zap-active"
                    and analysis["source_exchange_id"] == source and analysis["image"] == zap.SUPPORTED_IMAGE
                    and analysis["actor"] == "default"):
                identifiers.add(path.name)
        except (OSError, ValueError, KeyError, TypeError):
            continue  # Incomplete metadata cannot have launched this engine yet; rescan after CLI exit.
    return identifiers


def reap_owned_container(identifier):
    assert str(uuid.UUID(identifier)) == identifier, "Invalid owned job ID"
    assert not os.environ.get("DOCKER_HOST") and not os.environ.get("DOCKER_CONTEXT"), "Docker override blocked"
    def docker(*arguments):
        value = subprocess.run(["docker", *arguments], capture_output=True, text=True, timeout=10)
        assert value.returncode == 0, "Owned container cleanup/read-back failed"
        return value.stdout.strip()
    context = docker("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
    assert context.startswith(("npipe:", "unix:")), "Remote container cleanup blocked"
    name = "whk012-" + identifier
    listing = ("ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}")
    if not docker(*listing):
        return
    containers = json.loads(docker("inspect", name))
    assert len(containers) == 1, "Container ownership mismatch"
    container = containers[0]
    assert (container["Name"] == "/" + name and container["Config"]["Image"] == zap.SUPPORTED_IMAGE
            and container["Config"]["Labels"].get("bughunt.job") == identifier), "Container ownership mismatch"
    docker("rm", "--force", name)
    assert not docker(*listing), "Owned container remains after cleanup"


def reap_failed_active(process, root, previous, source):
    """Cancel normally, then reap only this fixture's positively identified resources."""
    identifiers = set()
    errors = []
    try:
        identifiers = new_owned_jobs(root, previous, source)
        for identifier in identifiers:
            try:
                job.cancel(identifier)
            except (OSError, ValueError, KeyError, TypeError) as error:
                errors.append(type(error).__name__)
        if process.poll() is None:
            try:
                process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                pass
    finally:
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        finally:
            try:
                identifiers |= new_owned_jobs(root, previous, source)
            finally:
                for identifier in identifiers:
                    reap_owned_container(identifier)
    assert not errors, "Job cancellation failed: " + ",".join(errors)


def cancel_real_active(capsys, server, identifier):
    arguments = ["engine", "start", "zap-owned-active", identifier, "--mission", zap_active.MISSION,
                 "--owned-lab", "--technology", "Python", "--requests", "8", "--seconds", "90"]
    before, started = len(server.wire), time.monotonic()
    root = workspace_dir()
    previous = {path.name for path in (root / "jobs").glob("*")}
    reader = None
    process = subprocess.Popen([sys.executable, "-m", "bughunt", *arguments],
                               cwd=str(Path(bughunt_scanner.__file__).parents[2]),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        first_line = queue.Queue(maxsize=1)
        reader = threading.Thread(target=lambda: first_line.put(process.stdout.readline(65537)), daemon=True)
        reader.start()
        announcement = json.loads(first_line.get(timeout=10))
        reader.join(timeout=1)
        assert not reader.is_alive()
        deadline = started + 90
        while len(server.wire) == before and time.monotonic() < deadline and process.poll() is None:
            threading.Event().wait(0.01)
        assert len(server.wire) > before
        status = json_cli(capsys, "engine", "status", announcement["starting_job_id"])
        assert status["run_id"] == announcement["run_id"]
        json_cli(capsys, "engine", "cancel", announcement["starting_job_id"])
        output, errors = process.communicate(timeout=30)
        assert process.returncode == 2, (process.returncode, errors)
        result = json.loads(output)
        assert result["state"] == "cancelled" and result["classification"] == "inconclusive"
        assert result["cleanup_confirmed"] and result["report_run_id"] is None
        assert 1 <= result["admitted_count"] == len(server.wire) - before <= 8
        assert "fixture-private" not in output + errors
        return result
    finally:
        try:
            reap_failed_active(process, root, previous, identifier)
        finally:
            try:
                if reader is not None and reader.ident is not None:
                    reader.join(timeout=1)
            finally:
                try:
                    process.stdout.close()
                finally:
                    process.stderr.close()


@pytest.mark.parametrize("burp", ["unconfigured", "configured-no-use"])
def test_cli_owned_capture_analysis_active_cancel_comparison_and_export(owned_workbench, capsys, burp):
    server, root, requests = owned_workbench
    if burp == "configured-no-use":
        configured = os.environ.get("BUGHUNT_BURP_PROFILE")
        if not configured:
            pytest.skip("Optional configured-no-use comparison requires explicit BUGHUNT_BURP_PROFILE")
        profile = Path(configured)
        burp_profile.load(profile)
        (root / "burp-mcp.json").write_bytes(burp_profile.private_file(profile, ledger.CAPTURE_LIMIT))
    inventory = json_cli(capsys, "engine", "list")
    intake = next(item for item in inventory["supporting"] if item.get("profile_id") == "burp-mcp-intake")
    assert intake["available"] is (burp == "configured-no-use")
    assert intake["connected"] is False and intake["request_execution"] is False
    cli(capsys, "identity", "use", "default")
    identifier = capture_and_select(capsys, requests["reflect"])
    wire = len(server.wire)
    passive = managed(capsys, "zap-passive", identifier, "--actor", "owner", "--actor", "viewer",
                      "--actor", "anonymous", "--seconds", "90")
    assert len(server.wire) == wire and passive["admitted_count"] == 0
    active = managed(capsys, "zap-owned-active", identifier, "--owned-lab", "--technology", "Python",
                     "--requests", "8", "--seconds", "90")
    assert 1 <= active["admitted_count"] == active["attempt_count"] == len(server.wire) - wire <= 8
    cancelled = cancel_real_active(capsys, server, identifier)
    cli(capsys, "identity", "use", "owner")
    owner_capture = capture_and_select(capsys, requests["records"])
    authorization = differential(capsys, requests["records"], "negative")
    exports = [json_cli(capsys, "ledger", "export", result["run_id"])
               for result in (passive, active, cancelled, authorization)]
    reports = [json_cli(capsys, "ledger", "export", result["report_run_id"]) for result in (passive, active)]
    for report in reports:
        observations = report["artifacts"]["observations.json"]["value"]["observations"]
        assert observations and all(item["hypothesis_level"] == 1 and item["confirmed"] is False for item in observations)
    packet = {"schema_version": 1, "burp_configuration": burp, "burp_used": False,
        "source_exchanges": [identifier, owner_capture], "engine_runs": [passive, active, cancelled],
        "authorization": authorization, "exports": exports, "reports": reports, "wire_count": len(server.wire)}
    assert_sanitized(packet)
    (root / "workbench-packet.json").write_bytes(exchange.canonical(packet))
    assert all(item["path"].startswith(PREFIX) for item in server.wire)


@pytest.mark.parametrize("outcome", ["negative", "lead", "invalid"])
def test_real_server_identity_and_authorization_controls(owned_workbench, capsys, outcome):
    server, root, requests = owned_workbench
    server.outcome = outcome
    result = differential(capsys, requests["records"], outcome)
    exported = json_cli(capsys, "ledger", "export", result["run_id"])
    assert_sanitized(exported)
    if outcome == "invalid":
        assert not any(item["actor"] == "viewer" and item["path"] == PREFIX + "records" for item in server.wire)
    else:
        attempts = [item for item in server.wire if item["path"] == PREFIX + "records"]
        assert [item["actor"] for item in attempts] == ["owner", "viewer", "anonymous"]
    (root / "authorization-control.json").write_bytes(exchange.canonical(exported))
