"""Capability states and immutable previews never confer execution authority."""

import json
from types import SimpleNamespace

import pytest

from bughunt.core import engine, exchange, job, ledger
from bughunt.integrations import zap_runtime
from bughunt.console.cli import route_argv
from bughunt.modules import engine as engine_command
from test_gate import boundaries, policy
from test_zap_active import owned, _prepare


def test_inventory_works_without_burp_or_docker_and_does_not_probe(owned, boundaries, monkeypatch):
    monkeypatch.setattr(engine.shutil, "which", lambda _name: None)
    value = engine.capabilities()
    assert all(item["engine"] == "native" for item in value["native"])
    assert any(item["workflow"] == "exchange" and item["available"] for item in value["native"])
    supporting = value["supporting"]
    assert supporting[0]["installed"]["launcher"] == "absent"
    assert supporting[0]["unavailable_reason"]
    assert all(item["unavailable_reason"] for item in supporting)
    assert all(item["permitted"] is False for item in supporting[1:])
    assert not (owned[2] / "jobs").exists()


def test_engine_registered_in_cli_and_console_catalog():
    from bughunt.console.catalog import group_for, reference_canonical
    assert route_argv(["engine", "list"]).command == "module"
    assert reference_canonical("engine") == "engine" and group_for("engine") == "Engines"


def test_dry_run_prints_exact_bounds_and_hashes_without_boundaries(owned, boundaries, capsys):
    code = engine_command.main(["dry-run", "zap-owned-active", owned[0], "--mission", "whk012-owned-active",
                                "--owned-lab", "--technology", "Python", "--requests", "2"])
    assert code == 0
    raw = capsys.readouterr().out
    value = json.loads(raw)
    descriptor = value["engine_plan"]
    assert descriptor["budgets"]["physical_requests"] == 2
    assert descriptor["budgets"]["concurrency"] == 1
    assert descriptor["permitted_targets"][0]["query_parameter"] == "q"
    assert descriptor["actor"] == "default" and descriptor["expected_artifacts"]
    assert all(len(descriptor[name]) == 64 for name in
        ("plan_sha256", "source_sha256", "consumer_sha256", "policy_sha256", "addon_inventory_sha256"))
    assert "q=owned" not in raw and not (owned[2] / "jobs").exists()


@pytest.mark.parametrize("profile_id", ["burp-specialist", "burp-mcp-intake", "zap-passive", "arbitrary-command"])
def test_unavailable_profiles_block_before_reading_inputs(owned, boundaries, profile_id):
    with pytest.raises(ValueError):
        engine.prepare(profile_id, "not-an-exchange")
    assert not (owned[2] / "jobs").exists()


@pytest.mark.parametrize("change", ["unknown-addon", "changed-addon", "proxy-credentials"])
def test_curated_hooks_and_proxy_state_must_match_before_send(owned, boundaries, change):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    inventory = engine.inventory()
    proxy = {"enabled": True, "excluded": [], "proxy": {"host": "127.0.0.1", "port": 12345},
             "disabled": {name: True for name in
                 ("isSocksProxyEnabled", "isHttpProxyAuthEnabled", "isUseGlobalHttpState")}}
    if change == "unknown-addon":
        inventory["addons"]["unreviewed-hook"] = "1"
    elif change == "changed-addon":
        inventory["addons"]["replacer"] = "changed"
    else:
        proxy["proxy"]["password"] = "credential-canary"
    (root / "engine" / "rpc" / "READY").write_bytes(exchange.canonical({"inventory": inventory, "proxy": proxy}))
    with pytest.raises(ValueError):
        zap_runtime._ready(root, plan)
    assert plan.budget.sent == []


def test_image_version_mismatch_preserves_failure_identity_without_launch(owned, monkeypatch):
    plan = _prepare(owned)
    calls = []
    def inspect(arguments, **_options):
        calls.append(arguments)
        return SimpleNamespace(returncode=0, stdout="npipe:local" if arguments[1] == "context" else "sha256:changed")
    def forbidden(*_arguments, **_options):
        raise AssertionError("Consumer launched after mismatch")
    monkeypatch.setattr(zap_runtime.subprocess, "run", inspect)
    monkeypatch.setattr(zap_runtime.subprocess, "Popen", forbidden)
    result = engine.run(plan)
    assert result["state"] == "failed" and result["reason"] == "consumer-preflight-failed"
    assert result["exit_diagnostic"] == "Pinned ZAP image missing or changed; no automatic pull"
    assert result["cleanup_confirmed"]
    assert job.status(plan.budget.job_id) == result and len(calls) == 2
    assert ledger.manifest_for(result["run_id"])["finished_at"]


def test_cancel_from_initial_announcement_blocks_all_processes(owned, boundaries):
    plan = _prepare(owned)
    identities = []
    def cancel_before_launch(job_id):
        identities.append(job.status(job_id)["run_id"])
        job.cancel(job_id)
    result = engine.run(plan, on_start=cancel_before_launch)
    assert result["state"] == "cancelled" and result["reason"] == "job-cancelled"
    assert result["run_id"] == identities[0] and result["cleanup_confirmed"]
    assert plan.budget.sent == []


def test_revocation_from_initial_announcement_preserves_receipt(owned, boundaries):
    plan = _prepare(owned)
    result = engine.run(plan, on_start=lambda _job_id: (owned[2] / "policy.json").unlink())
    assert result["state"] == "failed" and result["cleanup_confirmed"]
    assert ledger.manifest_for(result["run_id"])["policy_version"] == plan.profile.policy_version


def test_offline_worker_timeout_reaps_actual_child(owned, monkeypatch):
    import subprocess
    import sys
    import time
    plan = _prepare(owned)
    workers = []
    launch = subprocess.Popen
    def tracked(arguments, **options):
        process = launch(arguments, **options)
        workers.append(process)
        return process
    def timeout(process, _root, running_plan, _attempts):
        assert process.poll() is None
        job.mark_running(running_plan.budget.job_id)
        running_plan.budget.deadline = time.monotonic()
        return "job-deadline"
    monkeypatch.setattr(zap_runtime, "_preflight", lambda _plan: None)
    monkeypatch.setattr(zap_runtime, "command", lambda *_arguments: [sys.executable, "-c", "import time; time.sleep(30)"])
    monkeypatch.setattr(zap_runtime, "_loop", timeout)
    monkeypatch.setattr(zap_runtime.subprocess, "Popen", tracked)
    monkeypatch.setattr(zap_runtime.subprocess, "run", lambda *_arguments, **_options:
                        SimpleNamespace(returncode=0, stdout=""))
    result = engine.run(plan)
    assert len(workers) == 1 and workers[0].poll() is not None
    assert result["state"] == "failed" and result["reason"] == "job-deadline"
    assert result["cleanup_confirmed"] and job.status(plan.budget.job_id) == result


def test_declared_consumer_hash_must_match_bound_helper_before_launch(owned, boundaries, monkeypatch):
    plan = _prepare(owned)
    describe = engine.descriptor
    def mismatched(candidate):
        return dict(describe(candidate), consumer_sha256="0" * 64)
    monkeypatch.setattr(engine, "descriptor", mismatched)
    with pytest.raises(ValueError):
        engine.run(plan)
    assert plan.budget.sent == []


def test_final_cancel_reason_matches_the_analysis_receipt(owned):
    plan = _prepare(owned)
    root = zap_runtime._files(plan)
    job.cancel(plan.budget.job_id)
    result = zap_runtime._finish(plan, root, [], "consumer-completed", 0, True)
    assert result["state"] == "cancelled"
    assert ledger.manifest_for(result["run_id"])["analysis"]["reason"] == result["reason"]
