"""Shared engine receipts retain one identity and reject changed evidence."""

import json

import pytest

from bughunt.core import job, ledger
from test_gate import policy
from test_zap_active import owned, _prepare


def start_fixture(owned):
    plan = _prepare(owned)
    plan.budget.activate()
    descriptor = {"profile_id": "owned-offline", "engine": "offline-fixture",
                  "operation": "process", "target": plan.url.split("?", 1)[0],
                  "plan_sha256": "a" * 64, "budgets": {"requests": 4, "seconds": 30}}
    run_id = job.start_engine(plan.budget, plan.profile, descriptor)
    return plan, run_id


def test_identity_exists_before_worker_and_is_preserved(owned):
    plan, run_id = start_fixture(owned)
    value = job.status(plan.budget.job_id)
    assert value["run_id"] == run_id and value["state"] == "starting"
    assert ledger.manifest_for(run_id)["classification"] == "in_progress"
    job.mark_running(plan.budget.job_id)
    assert job.status(plan.budget.job_id)["state"] == "running"
    result = job.finish_engine(plan.budget.job_id, {"owned": True},
        {"job_id": plan.budget.job_id, "classification": "observation", "cleanup_confirmed": True},
        state="success", artifacts=[])
    assert result["run_id"] == result["analysis_run_id"] == run_id
    assert result["state"] == "success" and job.status(plan.budget.job_id) == result
    analysis = ledger.export_run(run_id)["manifest"]["analysis"]
    assert analysis["owned"] is True and analysis["engine_plan"]["profile_id"] == "owned-offline"
    with pytest.raises(ValueError):
        job.mark_running(plan.budget.job_id)


@pytest.mark.parametrize("state", ["partial", "failed", "cancelled"])
def test_terminal_diagnostics_and_cancel_are_idempotent(owned, state):
    plan, run_id = start_fixture(owned)
    if state == "cancelled":
        job.cancel(plan.budget.job_id)
        assert job.status(plan.budget.job_id)["cancel_requested"] is True
    result = job.finish_engine(plan.budget.job_id, {"reason": "owned-failure"},
        {"job_id": plan.budget.job_id, "classification": "inconclusive", "cleanup_confirmed": True},
        state=state, artifacts=[])
    before = plan.budget.stop_path().exists()
    job.cancel(plan.budget.job_id)
    assert plan.budget.stop_path().exists() is before
    assert job.status(plan.budget.job_id) == result
    assert ledger.manifest_for(run_id)["job_state"] == state


@pytest.mark.parametrize("change", ["modify", "delete"])
def test_terminal_evidence_tampering_blocks_status_and_export(owned, change):
    plan, run_id = start_fixture(owned)
    root = plan.budget.stop_path().parent
    artifact = root / "consumer.log"
    artifact.write_bytes(b"private fixture diagnostics")
    result = job.finish_engine(plan.budget.job_id, {},
        {"job_id": plan.budget.job_id, "classification": "inconclusive", "cleanup_confirmed": True},
        state="failed", artifacts=["consumer.log"])
    assert ledger.manifest_for(run_id)["job_artifacts"][0]["sha256"]
    assert "private fixture" not in json.dumps(result)
    if change == "modify":
        artifact.write_bytes(b"changed diagnostics")
    else:
        artifact.unlink()
    with pytest.raises((OSError, ValueError)):
        job.status(plan.budget.job_id)
    with pytest.raises((OSError, ValueError)):
        ledger.export_run(run_id)


def test_terminal_result_must_match_ledger_receipt(owned):
    plan, run_id = start_fixture(owned)
    job.finish_engine(plan.budget.job_id, {},
        {"job_id": plan.budget.job_id, "classification": "inconclusive", "cleanup_confirmed": True},
        state="failed", artifacts=[])
    root = plan.budget.stop_path().parent
    value = json.loads((root / "result.json").read_bytes())
    value["state"] = "success"
    (root / "result.json").write_text(json.dumps(value))
    with pytest.raises(ValueError):
        job.status(plan.budget.job_id)
    with pytest.raises(ValueError):
        ledger.export_run(run_id)


@pytest.mark.parametrize("path", ["../outside.log", "/absolute.log", "engine/../consumer.log"])
def test_artifact_paths_cannot_escape_job(owned, path):
    plan, _run_id = start_fixture(owned)
    with pytest.raises(ValueError):
        job.finish_engine(plan.budget.job_id, {},
            {"job_id": plan.budget.job_id, "classification": "inconclusive", "cleanup_confirmed": True},
            state="failed", artifacts=[path])


def test_duplicate_start_cannot_rebind_run_identity(owned):
    plan, run_id = start_fixture(owned)
    with pytest.raises(ValueError):
        job.start_engine(plan.budget, plan.profile, {"profile_id": "different"})
    assert job.status(plan.budget.job_id)["run_id"] == run_id


def test_existing_completed_job_receipt_remains_readable(owned):
    plan = _prepare(owned)
    plan.budget.activate()
    result = {"job_id": plan.budget.job_id, "classification": "inconclusive", "reason": "legacy-owned-receipt"}
    (plan.budget.stop_path().parent / "result.json").write_text(json.dumps(result))
    assert job.status(plan.budget.job_id) == result


def test_cancel_cannot_follow_a_redirected_stop_file(owned, monkeypatch):
    from pathlib import Path
    plan, _run_id = start_fixture(owned)
    stop = plan.budget.stop_path()
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == stop or original(self))
    with pytest.raises(ValueError):
        job.cancel(plan.budget.job_id)
    assert not stop.exists()


def test_status_checks_the_original_plan_capture_hash(owned):
    plan, run_id = start_fixture(owned)
    job.finish_engine(plan.budget.job_id, {},
        {"job_id": plan.budget.job_id, "classification": "inconclusive", "cleanup_confirmed": True},
        state="failed", artifacts=[])
    (ledger.runs_dir() / run_id / "request.http").write_bytes(b"changed original plan")
    with pytest.raises(ValueError):
        job.status(plan.budget.job_id)


@pytest.mark.parametrize("classification", ["finding", "H5", "in_progress"])
def test_engine_completion_cannot_promote_a_finding(owned, classification):
    plan, run_id = start_fixture(owned)
    with pytest.raises(ValueError):
        job.finish_engine(plan.budget.job_id, {},
            {"job_id": plan.budget.job_id, "classification": classification, "cleanup_confirmed": True},
            state="failed", artifacts=[])
    assert ledger.manifest_for(run_id)["classification"] == "in_progress"
