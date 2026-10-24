"""Opt-in managed passive contract against the actual pinned ZAP consumer."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time

import pytest

from bughunt.core import egress, engine, exchange, identity, job, ledger
from bughunt.integrations import zap, zap_passive, zap_passive_runtime
from bughunt.modules import engine as engine_command
from test_gate import seed_policy
from test_zap import fixture_records
from test_zap_passive_runtime import ready_metadata
from test_zap_runtime import owned_html_record

requires_zap_consumer = pytest.mark.skipif(
    os.environ.get("BUGHUNT_ZAP_PASSIVE_INTEGRATION") != "1",
    reason="opt-in managed pinned passive ZAP contract",
)


@pytest.fixture
def owned_recording(monkeypatch, tmp_path):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = b"<html><head><title>Owned passive fixture</title></head><body>owned</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_arguments):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    document = seed_policy(tmp_path)
    origin = f"http://127.0.0.1:{server.server_port}"
    document["assets"] = [
        {
            "id": "owned",
            "origin": origin,
            "paths": ["/app/"],
            "operations": ["manual", "passive", "process"],
            "methods": ["GET"],
        }
    ]
    (tmp_path / "policy.json").write_text(json.dumps(document))
    (tmp_path / "scope.txt").write_text("127.0.0.1\n")
    identity.create_profile("owner", "owner", [origin], owned=True)
    identity.set_credential("owner", "authorization", "Bearer fixture-private-secret")
    identity.create_profile("guest", "anonymous", [origin], owned=True)
    try:
        with egress.client(operation="manual") as client:
            response = client.get(
                origin + "/app/data",
                headers={"Authorization": "Bearer fixture-private-secret"},
            )
        record = exchange.from_run(response.extensions["bughunt_run_id"])
        assert requests == ["/app/data"]
        identifiers = exchange.save(
            [record], source_id="whk018-real-owned", source_bytes=b"owned", kind="raw"
        )
        requests.clear()
        plan = engine.prepare(
            "zap-passive",
            identifiers,
            actors=["owner", "guest"],
            mission=document["mission"],
        )
        yield plan, requests, identifiers
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def inject_failure(plan, monkeypatch, mode):
    if mode in {"version", "cancel", "policy"}:
        original = zap_passive_runtime._ready

        def ready(root, current_plan, name):
            path = root / "engine" / "rpc" / "READY"
            if not path.exists():
                return False
            if mode == "version":
                value = json.loads(path.read_bytes())
                value["inventory"]["version"] = "changed-owned-readiness"
                path.write_text(json.dumps(value))
            elif mode == "cancel":
                job.cancel(current_plan.budget.job_id)
            else:
                (root.parents[1] / "policy.json").unlink()
            return original(root, current_plan, name)

        monkeypatch.setattr(zap_passive_runtime, "_ready", ready)
    elif mode in {"missing-report", "malformed-report"}:
        original = zap_passive_runtime._report

        def report(current_plan, root):
            path = root / "engine" / "reports" / "passive-report.json"
            path.replace(path.with_name("original-retained.json"))
            if mode == "malformed-report":
                path.write_bytes(b"owned malformed JSON")
            return original(current_plan, root)

        monkeypatch.setattr(zap_passive_runtime, "_report", report)
    elif mode in {"nonzero", "log-cap"}:
        original = zap_passive_runtime.command

        def command(current_plan, root, name):
            arguments = original(current_plan, root, name)
            code = (
                "import runpy,sys; sys.path.insert(0,'/bughunt'); sys.argv=['/bughunt/zap_passive_consumer.py',"
                "'/bughunt/input/plan.yaml','/bughunt/input/bounds.json']; "
                "runpy.run_path(sys.argv[0],run_name='__main__'); "
            )
            code += (
                "sys.exit(7)" if mode == "nonzero" else "print('x'*2000000,flush=True)"
            )
            return arguments[:-4] + ["python", "-c", code]

        monkeypatch.setattr(zap_passive_runtime, "command", command)


def test_version_injection_handles_readiness_created_between_checks(
    tmp_path, monkeypatch
):
    readiness = tmp_path / "engine" / "rpc" / "READY"
    readiness.parent.mkdir(parents=True)
    original_exists = Path.exists
    published = False

    def publish_after_check(path):
        nonlocal published
        if path == readiness and not published:
            published = True
            readiness.write_text(json.dumps(ready_metadata()))
            return False
        return original_exists(path)

    def reject_containment(*_arguments):
        pytest.fail("Version mutation was bypassed before containment")

    monkeypatch.setattr(Path, "exists", publish_after_check)
    monkeypatch.setattr(zap_passive_runtime, "_containment", reject_containment)
    inject_failure(None, monkeypatch, "version")
    assert zap_passive_runtime._ready(tmp_path, None, "owned") is False
    assert published
    with pytest.raises(ValueError, match="Passive readiness version"):
        zap_passive_runtime._ready(tmp_path, None, "owned")


@requires_zap_consumer
@pytest.mark.parametrize(
    "mode",
    [
        "complete",
        "version",
        "nonzero",
        "missing-report",
        "malformed-report",
        "cancel",
        "deadline",
        "policy",
        "log-cap",
    ],
)
def test_native_recording_is_analyzed_without_any_additional_target_request(
    owned_recording, monkeypatch, mode
):
    plan, requests, _identifiers = owned_recording
    if mode == "deadline":
        plan = engine.prepare(
            "zap-passive",
            _identifiers,
            actors=["owner", "guest"],
            mission=plan.profile.mission,
            seconds=2,
        )
    inject_failure(plan, monkeypatch, mode)
    initial = []
    started = time.monotonic()
    result = engine.run(
        plan, on_start=lambda identifier: initial.append(job.status(identifier))
    )
    root = plan.budget.stop_path().parent
    assert (
        initial[0]["run_id"] == result["run_id"] and initial[0]["state"] == "starting"
    )
    if mode == "complete":
        assert result["state"] == "success", (
            result,
            (root / "consumer.log").read_text()[-2000:],
        )
        assert result["report_run_id"] and result["observation_count"] > 0
    else:
        assert (
            result["classification"] == "inconclusive"
            and result["report_run_id"] is None
        )
        assert result["state"] == ("cancelled" if mode == "cancel" else "failed")
    if mode == "nonzero":
        assert result["consumer_status"] == 7
    if mode == "deadline":
        assert result["reason"] == "job-deadline" and time.monotonic() - started < 20
    if mode == "log-cap":
        assert (
            result["reason"] == "consumer-log-cap"
            and (root / "consumer.log").stat().st_size == ledger.CAPTURE_LIMIT
        )
    assert (
        requests == [] and result["admitted_count"] == 0 and result["cleanup_confirmed"]
    )
    assert job.status(plan.budget.job_id) == result
    assert "fixture-private-secret" not in json.dumps(
        ledger.export_run(result["run_id"])
    )


@requires_zap_consumer
def test_console_command_launches_and_imports_without_manual_files(
    owned_recording, capsys
):
    plan, requests, identifiers = owned_recording
    assert (
        engine_command.main(
            [
                "start",
                "zap-passive",
                *identifiers,
                "--mission",
                plan.profile.mission,
                "--actor",
                "owner",
                "--actor",
                "guest",
            ]
        )
        == 0
    )
    raw = capsys.readouterr().out
    first, final = raw.split("\n", 1)
    initial, result = json.loads(first), json.loads(final)
    assert result["state"] == "success" and result["report_run_id"]
    assert result["run_id"] == initial["run_id"] and result["cleanup_confirmed"]
    assert requests == [] and "fixture-private-secret" not in raw


@requires_zap_consumer
def test_actual_managed_passive_import_and_network_containment(monkeypatch, tmp_path):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    seed_policy(tmp_path)
    (tmp_path / "scope.txt").write_text("allowed.example\n")
    records = [owned_html_record(fixture_records(tmp_path)[0])]
    document = json.loads((tmp_path / "policy.json").read_bytes())
    document["assets"][0]["operations"].append("process")
    (tmp_path / "policy.json").write_text(json.dumps(document))
    identifiers = exchange.save(
        records, source_id="whk018-owned", source_bytes=b"owned", kind="raw"
    )
    plan = zap_passive.prepare(
        identifiers, actors=["owner", "guest"], mission=document["mission"]
    )
    initial = []
    result = zap_passive_runtime.run(
        plan, on_start=lambda identifier: initial.append(job.status(identifier))
    )
    root = plan.budget.stop_path().parent
    assert result["state"] == "success", (
        result,
        (root / "consumer.log").read_text()[-4000:],
    )
    assert (
        result["classification"] == "observation"
        and result["cleanup_confirmed"] is True
    )
    assert (
        result["run_id"] == initial[0]["run_id"] and initial[0]["state"] == "starting"
    )
    assert result["admitted_count"] == 0 and result["target_network_enabled"] is False
    assert result["observation_count"] > 0
    assert job.status(plan.budget.job_id) == result
    containment = json.loads((root / "engine" / "containment.json").read_bytes())
    assert containment["network"] == "none" and containment["ports"] == []
    assert containment["image"] == zap.SUPPORTED_IMAGE.split("@", 1)[1]
    imported = ledger.export_run(result["report_run_id"])
    observations = imported["artifacts"]["observations.json"]["value"]["observations"]
    assert all(
        value["hypothesis_level"] == 1 and value["confirmed"] is False
        for value in observations
    )
    assert any(
        identifiers[0] in value["source_exchange_candidates"] for value in observations
    )
    assert "fixture-private-secret" not in json.dumps(
        ledger.export_run(result["run_id"])
    )
    assert "fixture-private-secret" not in json.dumps(imported)
