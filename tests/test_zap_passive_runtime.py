"""Offline process/report controls; dummy workers do not attest ZAP behavior."""

import json
import io
from pathlib import Path
import subprocess
import time
import threading

import pytest

from bughunt.core import engine, exchange, job, ledger
from bughunt.integrations import zap, zap_passive_runtime as runtime
from test_gate import policy
from test_zap_passive import prepare_fixture


class Worker:
    def __init__(self, status=0):
        self.status = status
        self.reaped = False
        self.stdout = io.BytesIO()

    def poll(self):
        return self.status

    def wait(self, timeout):
        self.reaped = True
        return self.status

    def kill(self):
        self.status = -9


def ready_metadata():
    return {"inventory": engine.inventory(), "mode": "protect", "profile_id": "zap-passive",
        "proxy": {"enabled": True, "excluded": [], "proxy": {"host": "127.0.0.1", "port": 65535},
            "disabled": {name: True for name in ("isSocksProxyEnabled", "isHttpProxyAuthEnabled", "isUseGlobalHttpState")}}}


def report_document():
    return {"@version": zap.SUPPORTED_VERSION, "created": "2026-10-14T00:00:00Z", "site": []}


def write_output(root, *, report=None, metadata=None):
    exchange._write(root / "engine" / "rpc" / "READY", ready_metadata())
    exchange._write(root / "engine" / "plan-progress.json", {"finished": True, "errors": [], "warnings": []})
    exchange._write(root / "engine" / "consumer-metadata.json", metadata or {
        "imported_messages": 1, "unexpected_history": 0, "target_network_enabled": False})
    if report is not False:
        path = root / "engine" / "reports" / "passive-report.json"
        path.write_bytes(exchange.canonical(report_document() if report is None else report))


def inspection(plan, name):
    return [{"Name": "/" + name, "Image": zap.SUPPORTED_IMAGE.split("@", 1)[1],
        "Config": {"Labels": {"bughunt.job": plan.budget.job_id}},
        "HostConfig": {"NetworkMode": "none", "PortBindings": {}, "ReadonlyRootfs": True,
            "Memory": 2 * 1024 ** 3, "NanoCpus": 1000000000, "PidsLimit": 256,
            "Tmpfs": {"/tmp": "rw,nosuid,nodev,size=512m", "/reports": "rw,nosuid,nodev,size=16m"},
            "Privileged": False, "CapAdd": None, "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"]}}]


def dummy_consumer(monkeypatch, plan, *, status=0, report=None, change=None):
    worker = Worker(status)
    monkeypatch.setattr(runtime.zap_runtime, "_preflight_docker", lambda check, _deadline: check())
    def launch(arguments, **_options):
        root = plan.budget.stop_path().parent
        write_output(root, report=report)
        if change:
            change(root)
        return worker
    def control(arguments, **_options):
        name = "whk018-" + plan.budget.job_id
        value = json.dumps(inspection(plan, name)) if arguments[:2] == ["docker", "inspect"] else ""
        return subprocess.CompletedProcess(arguments, 0, value, "")
    monkeypatch.setattr(runtime.subprocess, "Popen", launch)
    monkeypatch.setattr(runtime.subprocess, "run", control)
    return worker


def test_success_links_one_job_and_imports_empty_report_without_negative_claim(policy, monkeypatch):
    plan = prepare_fixture(policy)
    worker = dummy_consumer(monkeypatch, plan)
    initial = []
    result = runtime.run(plan, on_start=lambda identifier: initial.append(job.status(identifier)))
    assert initial[0]["state"] == "starting" and initial[0]["run_id"] == result["run_id"]
    assert result["state"] == "success" and result["classification"] == "observation"
    assert result["observation_count"] == 0 and result["manual_controls_required"] is True
    assert result["admitted_count"] == 0 and worker.reaped
    assert job.status(plan.budget.job_id) == result
    imported = ledger.export_run(result["report_run_id"])
    assert imported["manifest"]["classification"] == "observation"
    assert "negative finding" in result["claim"]


@pytest.mark.parametrize("failure", ["nonzero", "missing", "malformed", "version", "accounting", "hooks"])
def test_failure_is_retained_inconclusive_and_reaped(policy, monkeypatch, failure):
    plan = prepare_fixture(policy)
    def change(root):
        if failure == "malformed":
            (root / "engine" / "reports" / "passive-report.json").write_bytes(b"not-json")
        elif failure == "accounting":
            exchange._write(root / "engine" / "consumer-metadata.json", {"imported_messages": 2})
        elif failure in {"version", "hooks"}:
            value = ready_metadata()
            if failure == "version":
                value["inventory"]["version"] = "2.18.0"
            else:
                value["inventory"]["addons"]["unknown-hook"] = "1"
            exchange._write(root / "engine" / "rpc" / "READY", value)
    worker = dummy_consumer(monkeypatch, plan, status=7 if failure == "nonzero" else 0,
                            report=False if failure == "missing" else None, change=change)
    result = runtime.run(plan)
    assert result["classification"] == "inconclusive" and result["state"] == "failed"
    assert result["report_run_id"] is None and result["cleanup_confirmed"] and worker.reaped
    assert job.status(plan.budget.job_id) == result


@pytest.mark.parametrize("change", ["cancel", "policy", "deadline"])
def test_prelaunch_revocation_creates_receipt_without_process(policy, monkeypatch, change):
    plan = prepare_fixture(policy)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Revoked job reached a process boundary")
    monkeypatch.setattr(runtime.subprocess, "run", forbidden)
    monkeypatch.setattr(runtime.subprocess, "Popen", forbidden)
    def revoke(identifier):
        if change == "cancel":
            job.cancel(identifier)
        elif change == "policy":
            (policy[1] / "policy.json").unlink()
        else:
            plan.budget.deadline = time.monotonic() - 1
    result = runtime.run(plan, on_start=revoke)
    assert result["state"] == ("cancelled" if change == "cancel" else "failed")
    assert result["cleanup_confirmed"] is True and result["report_run_id"] is None
    assert job.status(plan.budget.job_id) == result


def test_preflight_timeout_diagnostic_names_the_docker_op_and_retryable(policy, monkeypatch):
    plan = prepare_fixture(policy)
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Consumer launched after preflight timeout")
    monkeypatch.setattr(runtime.subprocess, "Popen", forbidden)
    def timeout(_check, _deadline):
        raise subprocess.TimeoutExpired(["docker", "image", "inspect", zap.SUPPORTED_IMAGE], 10)
    monkeypatch.setattr(runtime.zap_runtime, "_preflight_docker", timeout)
    result = runtime.run(plan)
    assert result["reason"] == "consumer-preflight-failed" and result["state"] == "failed"
    diagnostic = result["exit_diagnostic"]
    assert diagnostic != "TimeoutExpired"
    assert "docker image inspect" in diagnostic
    assert "10" in diagnostic and "retryable" in diagnostic


@pytest.mark.parametrize("field,value", [("NetworkMode", "host"), ("ReadonlyRootfs", False),
    ("Memory", 0), ("NanoCpus", 0), ("PidsLimit", 0), ("PortBindings", {"8080/tcp": []})])
def test_actual_container_bounds_are_checked_not_only_command_args(policy, monkeypatch, field, value):
    plan = prepare_fixture(policy)
    root = runtime._files(plan)
    name = "whk018-" + plan.budget.job_id
    container = inspection(plan, name)
    container[0]["HostConfig"][field] = value
    monkeypatch.setattr(runtime.subprocess, "run", lambda args, **_kwargs:
                        subprocess.CompletedProcess(args, 0, json.dumps(container), ""))
    with pytest.raises(ValueError):
        runtime._containment(plan, name)
    assert not (root / "engine" / "rpc" / "APPROVED").exists()


def test_changed_passive_artifact_blocks_status_and_export(policy, monkeypatch):
    plan = prepare_fixture(policy)
    dummy_consumer(monkeypatch, plan)
    result = runtime.run(plan)
    (plan.budget.stop_path().parent / "input" / "traffic.har").write_bytes(b"changed traffic")
    for reader, identifier in ((job.status, plan.budget.job_id), (ledger.export_run, result["run_id"])):
        with pytest.raises(ValueError):
            reader(identifier)


@pytest.mark.parametrize("extra", [0, 1, 65536])
def test_stdout_retention_has_a_hard_byte_cap(extra):
    overflow = threading.Event()
    log = io.BytesIO()
    runtime._capture_log(io.BytesIO(b"x" * (ledger.CAPTURE_LIMIT + extra)), log, overflow)
    assert len(log.getvalue()) == ledger.CAPTURE_LIMIT
    assert overflow.is_set() is (extra > 0)


@pytest.mark.parametrize("artifact", ["source.json", "observations.json", "manifest.json"])
def test_originating_job_verifies_its_linked_import_receipt(policy, monkeypatch, artifact):
    plan = prepare_fixture(policy)
    dummy_consumer(monkeypatch, plan)
    result = runtime.run(plan)
    path = ledger.runs_dir() / result["report_run_id"] / artifact
    if artifact == "manifest.json":
        value = json.loads(path.read_bytes())
        value["classification"] = "finding"
        path.write_text(json.dumps(value))
    else:
        path.write_bytes(b"changed linked report evidence")
    for reader, identifier in ((job.status, plan.budget.job_id), (ledger.export_run, result["run_id"])):
        with pytest.raises(ValueError):
            reader(identifier)


@pytest.mark.parametrize("field,value", [("actor", "attested-owner"), ("mission", "other-mission"),
    ("operation", "scan"), ("policy_version", "changed-version"),
    ("policy_verified_at", "2099-01-01T00:00:00Z"), ("policy_sha256", "0" * 64),
    ("policy_source", "other-policy"), ("new_provenance", "unsealed-claim")])
def test_linked_import_provenance_cannot_drift(policy, monkeypatch, field, value):
    plan = prepare_fixture(policy)
    dummy_consumer(monkeypatch, plan)
    result = runtime.run(plan)
    path = ledger.runs_dir() / result["report_run_id"] / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest[field] = value
    ledger._write_private(path, exchange.canonical(manifest))
    for reader, identifier in ((job.status, plan.budget.job_id), (ledger.export_run, result["run_id"])):
        with pytest.raises(ValueError):
            reader(identifier)


def test_linked_import_cleanup_marker_can_change(policy, monkeypatch):
    plan = prepare_fixture(policy)
    dummy_consumer(monkeypatch, plan)
    result = runtime.run(plan)
    path = ledger.runs_dir() / result["report_run_id"] / "manifest.json"
    manifest = json.loads(path.read_bytes())
    manifest["cleanup"] = "confirmed"
    ledger._write_private(path, exchange.canonical(manifest))
    assert job.status(plan.budget.job_id) == result
    assert ledger.export_run(result["run_id"])["manifest"]["job_result"] == result
    assert ledger.export_run(result["report_run_id"])["manifest"]["cleanup"] == "confirmed"
