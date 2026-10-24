"""Opt-in actual network-none Chromium with independent owned-server observations."""

from http.server import ThreadingHTTPServer
import json
import os
import threading
import time

import pytest

from bughunt.core import engine, identity, job, ledger
from bughunt.integrations import browser_actor, browser_runtime
from test_gate import seed_policy
from test_workbench_consumer import OwnedApplication, PREFIX, TOKENS, configure_actors, json_cli

pytestmark = pytest.mark.skipif(os.environ.get("BUGHUNT_BROWSER_INTEGRATION") != "1",
                                reason="opt-in actual pinned sandboxed owned-browser consumer")


class BrowserApplication(OwnedApplication):
    def do_GET(self):
        actor = TOKENS.get(self.headers.get("Authorization"), "anonymous")
        if self.path == PREFIX + "page":
            self.server.wire.append({"path": self.path, "actor": actor})
            body = ("<!doctype html><html><body>owned actor " + actor
                + '<img src="' + PREFIX + 'canary"><script src="' + PREFIX + 'browser.js"></script>'
                + "</body></html>").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "browser_marker=" + actor + "; Path=/__bughunt_lab__/; SameSite=Lax")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        elif self.path == PREFIX + "browser.js":
            self.server.wire.append({"path": self.path, "actor": actor})
            script = ("localStorage.setItem('owned-browser-marker','" + actor + "');"
                + "fetch('" + PREFIX + "records',{headers:{Authorization:'Bearer fixture-private-owner'}})"
                + ".then(r=>{document.body.append(' records:'+r.status)});"
                + "navigator.serviceWorker.register('" + PREFIX + "worker.js').catch(()=>{});"
                + "new WebSocket('ws://'+location.host+'" + PREFIX + "socket');")
            self._respond(200, script.encode(), "application/javascript")
        else:
            super().do_GET()

    def _respond(self, status, body, content_type):
        hook = getattr(self.server, "after_probe", None)
        if self.path == PREFIX + "whoami" and hook is not None:
            self.server.after_probe = None
            hook()
        super()._respond(status, body, content_type)


@pytest.fixture
def browser_lab(tmp_path, monkeypatch, capsys):
    server = ThreadingHTTPServer(("127.0.0.1", 0), BrowserApplication)
    server.wire, server.outcome = [], "negative"
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    document = seed_policy(tmp_path)
    document.update(mission=browser_actor.MISSION, limits={"requests_per_second": 10, "concurrency": 1})
    document["assets"] = [{"id": "owned-browser", "origin": origin, "paths": [PREFIX],
        "operations": ["manual", "active_scan", "process"], "methods": ["GET"]}]
    (tmp_path / "policy.json").write_text(json.dumps(document))
    (tmp_path / "scope.txt").write_text("127.0.0.1\n")
    configure_actors(capsys, origin)
    try:
        yield server, tmp_path, [origin + PREFIX + suffix for suffix in ("page", "browser.js", "records")]
    finally:
        server.shutdown()
        server.server_close()
        serving.join(timeout=5)
        assert not serving.is_alive()


@pytest.mark.parametrize("actor", ["owner", "viewer", "anonymous"])
def test_actual_browser_actor_and_all_route_contract(browser_lab, actor):
    server, root, urls = browser_lab
    plan = browser_actor.prepare(urls, actor=actor, mission=browser_actor.MISSION, owned_lab=True,
                                 requests=20, seconds=40)
    result = browser_runtime.run(plan)
    assert result["cleanup_confirmed"], result
    assert result["classification"] == "observation", (result, plan.budget.stop_path().parent)
    assert result["state"] == "success" and result["actor"] == actor
    assert result["admitted_count"] == len(server.wire) == 6, (result, server.wire)
    assert all(row["actor"] == actor for row in server.wire)
    assert {row["path"] for row in server.wire} == {PREFIX + path for path in ("page", "browser.js", "records", "whoami")}
    assert result["denied_count"] >= 1
    assert identity.selected_name() == "default"
    assert job.status(result["job_id"]) == result
    exported = ledger.export_run(result["run_id"])
    raw = json.dumps(exported)
    assert "fixture-private" not in raw and "person-" not in raw
    metadata = ledger.manifest_for(result["run_id"])
    observed = metadata["analysis"]["observation"]
    assert observed["initial_storage_empty"] is True and observed["blocked_websockets"] >= 1
    assert observed["renderers"] and all(not row["no_sandbox_flag"] for row in observed["renderers"])
    for admission in plan.budget.sent:
        manifest = ledger.manifest_for(admission["run_id"])
        assert manifest["actor"] == actor and manifest["finished_at"]


@pytest.mark.parametrize("mode", ["invalid-actor", "cap", "cancel", "revocation", "drift", "deadline", "stop-write"])
def test_actual_browser_stops_after_probe_on_invalid_authority_or_interruption(browser_lab, monkeypatch, mode):
    server, root, urls = browser_lab
    plan = engine.prepare("browser-owned", urls, actors=["viewer"], mission=browser_actor.MISSION,
                          owned_lab=True, requests=1 if mode == "cap" else 20, seconds=40)
    if mode == "invalid-actor":
        server.outcome = "invalid"
    elif mode in {"cancel", "stop-write"}:
        server.after_probe = lambda: job.cancel(plan.budget.job_id)
    elif mode == "revocation":
        server.after_probe = lambda: (root / "policy.json").unlink()
    elif mode == "drift":
        server.after_probe = lambda: (plan.budget.stop_path().parent / "input" / "browser.json").write_bytes(b"drift")
    elif mode == "deadline":
        server.after_probe = lambda: setattr(plan.budget, "deadline", time.monotonic())
    if mode == "stop-write":
        original = ledger._write_private
        def blocked_stop(path, *args, **kwargs):
            if path == plan.budget.stop_path().parent / "engine" / "rpc" / "STOP":
                raise OSError("Injected advisory STOP failure")
            return original(path, *args, **kwargs)
        monkeypatch.setattr(ledger, "_write_private", blocked_stop)
    result = engine.run(plan)
    assert result["cleanup_confirmed"] and result["classification"] == "inconclusive", result
    assert result["state"] == ("cancelled" if mode in {"cancel", "stop-write"} else "partial"), result
    assert result["admitted_count"] == len(server.wire) == 1, (result, server.wire)
    assert server.wire[0] == {"path": PREFIX + "whoami", "actor": "viewer"}
    assert job.status(result["job_id"]) == result


def test_actual_browser_cancel_immediately_after_launcher_reaps_without_requests(browser_lab, monkeypatch):
    server, _root, urls = browser_lab
    plan = engine.prepare("browser-owned", urls, actors=["owner"], mission=browser_actor.MISSION,
                          owned_lab=True, seconds=40)
    original, launched = browser_runtime.subprocess.Popen, []
    def launch(args, *arguments, **options):
        process = original(args, *arguments, **options)
        if args[:2] == ["docker", "run"]:
            launched.append(True)
            plan.budget.cancelled.set()
        return process
    monkeypatch.setattr(browser_runtime.subprocess, "Popen", launch)
    result = engine.run(plan)
    assert launched and result["state"] == "cancelled" and result["cleanup_confirmed"], result
    assert result["classification"] == "inconclusive" and result["admitted_count"] == 0
    assert server.wire == [] and job.status(result["job_id"]) == result


def test_actual_primary_cli_needs_no_burp_and_seals_browser_artifacts(browser_lab, monkeypatch, capsys):
    server, root, urls = browser_lab
    monkeypatch.setenv("BUGHUNT_BURP_PROFILE", str(root / "burp-unavailable.json"))
    value = json_cli(capsys, "engine", "start", "browser-owned", *urls, "--actor", "owner",
                     "--mission", browser_actor.MISSION, "--owned-lab", "--seconds", "40")
    assert value["state"] == "success" and value["admitted_count"] == len(server.wire) == 6
    assert json_cli(capsys, "engine", "status", value["job_id"]) == value
    directory = job._root(value["job_id"])
    for relative in ("input/browser.json", "engine/browser-result.json", "containment.json"):
        path = directory / relative
        original = path.read_bytes()
        path.write_bytes(original + b" ")
        with pytest.raises(ValueError):
            job.status(value["job_id"])
        with pytest.raises(ValueError):
            ledger.export_run(value["run_id"])
        path.write_bytes(original)
        assert job.status(value["job_id"]) == value


def test_actual_same_origin_actor_profiles_are_separate_and_do_not_switch_saved_actor(browser_lab):
    server, _root, urls = browser_lab
    identity.use_profile("viewer")
    storage, profiles = set(), set()
    for actor in ("owner", "viewer", "anonymous"):
        before = len(server.wire)
        plan = engine.prepare("browser-owned", urls, actors=[actor], mission=browser_actor.MISSION,
                              owned_lab=True, seconds=40)
        result = engine.run(plan)
        assert result["classification"] == "observation" and result["cleanup_confirmed"], result
        assert identity.selected_name() == "viewer"
        assert all(row["actor"] == actor for row in server.wire[before:])
        metadata = ledger.manifest_for(result["run_id"])
        observed = metadata["analysis"]["observation"]
        storage.add(observed["storage_sha256"])
        ready = job._load(plan.budget.stop_path().parent / "engine" / "rpc" / "READY")
        assert ready["initial_storage_empty"] is True
        profiles.add(ready["profile_directory"])
    assert len(storage) == len(profiles) == 3
