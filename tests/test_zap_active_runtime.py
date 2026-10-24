"""Offline runtime receipts survive revocation, failed launch and bad reports."""

import base64
import json
import subprocess
from types import SimpleNamespace

import pytest

import httpx

from bughunt.core import egress, exchange, job, ledger
from bughunt.integrations import zap_import, zap_runtime
from bughunt.modules import zap as zap_command
from test_gate import policy
from test_zap_active import owned, _prepare


@pytest.fixture
def cleanup_probe(tmp_path, monkeypatch):
    (tmp_path / "engine" / "rpc").mkdir(parents=True)
    clock, calls = [0.0], []
    process = SimpleNamespace(poll=lambda: 1, wait=lambda timeout: 1, kill=lambda: None)
    monkeypatch.setattr(zap_runtime.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        zap_runtime.time,
        "sleep",
        lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    )

    def run(states):
        pending = list(states)

        def docker(arguments, **options):
            calls.append((arguments, options))
            if arguments[1] != "ps":
                return SimpleNamespace(
                    returncode=1, stdout="", stderr="removal already in progress"
                )
            state = pending.pop(0) if len(pending) > 1 else pending[0]
            clock[0] += min(0.01, options["timeout"])
            if state == "timeout":
                raise subprocess.TimeoutExpired(arguments, options["timeout"])
            return SimpleNamespace(
                returncode=1 if state == "error" else 0,
                stdout="owned" if state == "present" else "",
            )

        monkeypatch.setattr(zap_runtime.subprocess, "run", docker)
        return zap_runtime._cleanup(process, "whk012-owned", tmp_path)

    return run, process, clock, calls


@pytest.mark.parametrize(
    "states", [["present", "present", "absent"], ["error", "absent"]]
)
def test_cleanup_confirms_eventual_asynchronous_container_removal(
    cleanup_probe, states
):
    run, _process, _clock, calls = cleanup_probe
    assert run(states) is True
    inspections = [arguments for arguments, _options in calls if arguments[1] == "ps"]
    assert len(inspections) == len(states)
    assert all("name=^whk012-owned$" in arguments for arguments in inspections)


@pytest.mark.parametrize("state", ["present", "error", "timeout"])
def test_cleanup_remains_false_when_absence_cannot_be_proven(cleanup_probe, state):
    run, _process, clock, calls = cleanup_probe
    assert run([state]) is False
    assert 2.9 <= clock[0] <= 3.01
    inspections = [options for arguments, options in calls if arguments[1] == "ps"]
    assert len(inspections) > 1 and all(
        0 < options["timeout"] <= 1 for options in inspections
    )


def test_cleanup_requires_process_reap_even_after_confirmed_absence(cleanup_probe):
    run, process, _clock, _calls = cleanup_probe

    def unavailable_wait(timeout):
        raise subprocess.TimeoutExpired("owned process", timeout)

    process.wait = unavailable_wait
    assert run(["absent"]) is False


def test_receipt_survives_deleted_policy(owned):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    (owned[2] / "policy.json").unlink()
    result = zap_runtime._finish(
        plan, root, [], "cancelled-expired-or-revoked", 1, True
    )
    assert result["classification"] == "inconclusive"
    assert result["cleanup_confirmed"] is True
    assert (
        ledger.manifest_for(result["analysis_run_id"])["mission"]
        == "whk012-owned-active"
    )


def test_malformed_report_retains_inconclusive_receipt(owned):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    (root / "engine" / "reports" / "active.json").write_bytes(b"not JSON")
    result = zap_runtime._finish(plan, root, [], "consumer-completed", 0, True)
    assert result["classification"] == "inconclusive"
    assert result["reason"] == "report-import-failed"
    assert zap_runtime.status(plan.budget.job_id) == result


def test_no_requests_or_report_cannot_claim_complete(owned):
    plan = _prepare(owned)
    result = zap_runtime._finish(
        plan, zap_runtime._files(plan), [], "consumer-completed", 0, True
    )
    assert result["classification"] == "inconclusive"
    assert result["reason"] == "incomplete-consumer-evidence"


def test_attempt_urls_are_private_not_default_summary(owned):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    attempts = [
        {
            "sequence": "000001",
            "sent": False,
            "url": "http://127.0.0.1/private?q=hidden-marker",
        }
    ]
    result = zap_runtime._finish(
        plan, root, attempts, "cancelled-expired-or-revoked", 1, True
    )
    exported = ledger.export_run(result["analysis_run_id"])
    assert "hidden-marker" not in json.dumps(exported)
    assert "hidden-marker" in (root / "attempts.json").read_text()
    assert exported["manifest"]["analysis"]["attempt_artifact"]["sha256"]


def test_launch_failure_still_records_status(owned, monkeypatch):
    plan = _prepare(owned)
    monkeypatch.setattr(zap_runtime, "_preflight", lambda _plan: None)

    def unavailable(*_args, **_kwargs):
        raise OSError("fixture launch failure")

    monkeypatch.setattr(zap_runtime.subprocess, "Popen", unavailable)
    result = zap_runtime.run(plan)
    assert result["reason"] == "consumer-launch-failed"
    assert result["classification"] == "inconclusive"
    assert result["cleanup_confirmed"] is True


def test_preflight_timeout_diagnostic_names_the_docker_op_and_retryable(
    owned, monkeypatch
):
    import subprocess

    plan = _prepare(owned)

    def inspect(arguments, **_options):
        if arguments[1] == "image":
            raise subprocess.TimeoutExpired(arguments, 10)
        return SimpleNamespace(returncode=0, stdout="npipe:local")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Consumer launched after preflight timeout")

    monkeypatch.setattr(zap_runtime.subprocess, "run", inspect)
    monkeypatch.setattr(zap_runtime.subprocess, "Popen", forbidden)
    result = zap_runtime.run(plan)
    assert result["reason"] == "consumer-preflight-failed"
    assert result["classification"] == "inconclusive"
    diagnostic = result["exit_diagnostic"]
    assert diagnostic != "TimeoutExpired"
    assert "docker image inspect" in diagnostic
    assert "10" in diagnostic and "retryable" in diagnostic


def test_docker_environment_override_denied_before_subprocess(owned, monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "tcp://outside.example:2375")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Docker boundary reached")

    monkeypatch.setattr(zap_runtime.subprocess, "run", forbidden)
    with pytest.raises(ValueError):
        zap_runtime._preflight(_prepare(owned))


def test_unready_consumer_cannot_get_target_response(owned, monkeypatch):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    process = SimpleNamespace(poll=lambda: 0)
    (root / "engine" / "rpc" / "000001.req").write_bytes(b"untrusted")
    attempts = []
    reason = zap_runtime._loop(process, root, plan, attempts)
    assert reason == "consumer-not-ready"
    assert attempts == [] and plan.budget.sent == []


def test_consumer_ready_drift_denies_egress(owned):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    metadata = {
        "inventory": {"version": "changed", "addons": {}},
        "proxy": {
            "enabled": True,
            "excluded": [],
            "proxy": {"host": "127.0.0.1", "port": 12345},
        },
    }
    (root / "engine" / "rpc" / "READY").write_text(json.dumps(metadata))
    with pytest.raises(ValueError):
        zap_runtime._ready(root, plan)
    assert plan.budget.sent == []


def test_oversized_unprocessed_rpc_retains_receipt(owned):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    (root / "engine" / "rpc" / "000001.req").write_bytes(b"x" * 200001)
    result = zap_runtime._finish(plan, root, [], "consumer-runtime-failed", 1, True)
    assert result["classification"] == "inconclusive"
    assert result["attempt_count"] == 1
    assert result["reason"] == "consumer-rpc-evidence-invalid"


def test_active_cli_dry_run_and_cancel_status(owned, capsys, monkeypatch):
    plan = _prepare(owned)
    code = zap_command.main(
        [
            "active",
            owned[0],
            "--mission",
            zap_runtime.zap_active.MISSION,
            "--owned-lab",
            "--technology",
            "Python",
            "--dry-run",
        ]
    )
    assert code == 0
    assert json.loads(capsys.readouterr().out)["dry_run"] is True
    plan.budget.activate()
    assert zap_command.main(["status", plan.budget.job_id]) == 0
    assert zap_command.main(["cancel", plan.budget.job_id]) == 0
    assert plan.budget.stop_path().exists()


def test_running_status_does_not_expose_query_value(owned):
    plan = _prepare(owned)
    plan.budget.activate()
    value = zap_runtime.status(plan.budget.job_id)
    assert value["job_id"] == plan.budget.job_id
    assert "q=owned" not in json.dumps(value)


def test_oversized_response_stops_stream_at_body_cap(owned):
    plan = _prepare(owned, max_bytes=16)
    raw = b"GET " + plan.url.encode() + b" HTTP/1.1\r\nHost: 127.0.0.1:45678\r\n\r\n"
    request_path = owned[2] / "000001.req"
    request_path.write_bytes(
        base64.b64encode(plan.url.encode()) + b"\n" + base64.b64encode(raw) + b"\n"
    )
    transport = httpx.MockTransport(
        lambda _request: httpx.Response(200, stream=httpx.ByteStream(b"x" * 100000))
    )
    bounded = zap_runtime._CappedTransport(
        job.Transport(plan.budget, transport), plan.max_bytes
    )
    with egress.client(operation="active_scan", transport=bounded) as client:
        result = zap_runtime.mediate(request_path, client, plan)
    assert result["error"] == "ValueError"
    response = ledger.manifest_for(result["run_id"])["response"]
    assert response["size"] < 1000


def test_cleanup_forces_exact_container_removal_after_stop_timeout(owned, monkeypatch):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    name = "whk012-" + plan.budget.job_id
    calls = []

    class Process:
        alive = True

        def poll(self):
            return None if self.alive else 1

        def kill(self):
            self.alive = False

        def wait(self, timeout):
            self.alive = False
            return 1

    def docker(arguments, **_options):
        calls.append(arguments)
        if arguments[1] == "stop":
            raise subprocess.TimeoutExpired(arguments, 10)
        return SimpleNamespace(returncode=0, stdout="")

    def unavailable_stop(_path, _value):
        raise OSError("STOP write failed")

    import subprocess

    monkeypatch.setattr(zap_runtime.ledger, "_write_private", unavailable_stop)
    monkeypatch.setattr(zap_runtime.subprocess, "run", docker)
    assert zap_runtime._cleanup(Process(), name, root) is True
    assert ["docker", "rm", "--force", name] in calls
    assert any(command[1] == "ps" and f"name=^{name}$" in command for command in calls)


def test_published_active_job_can_cancel_before_consumer_launch(
    owned, monkeypatch, capsys
):
    monkeypatch.setattr(zap_runtime, "_preflight", lambda _plan: None)

    def cancel_at_launch(*_arguments, **_options):
        announcement = json.loads(capsys.readouterr().out.strip())
        job.cancel(announcement["starting_job_id"])
        assert (owned[2] / "jobs" / announcement["starting_job_id"] / "STOP").exists()
        raise OSError("test launch cancelled")

    monkeypatch.setattr(zap_runtime.subprocess, "Popen", cancel_at_launch)
    code = zap_command.main(
        [
            "active",
            owned[0],
            "--mission",
            zap_runtime.zap_active.MISSION,
            "--owned-lab",
            "--technology",
            "Python",
        ]
    )
    assert code == 2


def test_consumer_stop_blocks_queued_rpc_before_mediation(owned, monkeypatch):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    rpc = root / "engine" / "rpc"
    (rpc / "STOP").write_bytes(b"consumer-denied\n")
    (rpc / "000001.req").write_bytes(b"queued")
    called = []
    monkeypatch.setattr(zap_runtime, "_ready", lambda _root, _plan: True)
    monkeypatch.setattr(
        zap_runtime,
        "mediate",
        lambda *_arguments: (called.append(True), {"error": "blocked"})[1],
    )
    reason = zap_runtime._loop(SimpleNamespace(poll=lambda: None), root, plan, [])
    assert reason == "consumer-stopped"
    assert called == [] and plan.budget.sent == []


def test_consumer_stop_ends_loop_without_queued_rpc(owned, monkeypatch):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    (root / "engine" / "rpc" / "STOP").write_bytes(b"consumer-denied\n")
    monkeypatch.setattr(zap_runtime, "_ready", lambda _root, _plan: True)
    polls = iter([None, 0])
    reason = zap_runtime._loop(
        SimpleNamespace(poll=lambda: next(polls)), root, plan, []
    )
    assert reason == "consumer-stopped"
    assert plan.budget.sent == []


def test_consumer_stop_is_checked_at_final_send(owned):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    rpc = root / "engine" / "rpc"
    raw = b"GET " + plan.url.encode() + b" HTTP/1.1\r\nHost: 127.0.0.1:45678\r\n\r\n"
    request_path = rpc / "000001.req"
    request_path.write_bytes(
        base64.b64encode(plan.url.encode()) + b"\n" + base64.b64encode(raw) + b"\n"
    )
    (rpc / "STOP").write_bytes(b"consumer-denied\n")
    seen = []
    transport = httpx.MockTransport(
        lambda request: (
            seen.append(request),
            httpx.Response(200, stream=httpx.ByteStream(b"owned")),
        )[1]
    )
    bounded = zap_runtime._CappedTransport(
        job.Transport(plan.budget, transport), plan.max_bytes
    )
    with egress.client(operation="active_scan", transport=bounded) as client:
        result = zap_runtime.mediate(request_path, client, plan)
    assert result["sent"] is False
    assert seen == [] and plan.budget.sent == []


def test_completed_receipt_requires_matching_admissions_and_attempts(
    owned, monkeypatch
):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    plan.budget.sent.append({"run_id": "admitted-run"})
    monkeypatch.setattr(
        zap_runtime.exchange, "from_run", lambda _run_id: {"exchange_id": "owned"}
    )
    report_id = zap_import.import_report(
        exchange.canonical(
            {"@version": "2.17.0", "created": "2026-10-14T00:00:00Z", "site": []}
        ),
        source_id="zap-active-" + plan.budget.job_id,
    )
    monkeypatch.setattr(zap_runtime, "_report", lambda *_arguments: report_id)
    attempts = [{"sequence": "000001", "sent": True, "run_id": "different-run"}]
    result = zap_runtime._finish(plan, root, attempts, "consumer-completed", 0, True)
    assert result["classification"] == "inconclusive"
    assert result["reason"] == "request-accounting-mismatch"
