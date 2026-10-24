"""Managed passive previews and authority bindings are inert and complete-only."""

import json

import httpx
import pytest

from bughunt.core import egress, exchange, identity
from bughunt.integrations import zap_passive
from bughunt.modules import engine as engine_command
from test_gate import boundaries, policy
from test_zap import fixture_records


def passive_fixture(policy):
    _document, workspace = policy
    records = fixture_records(workspace)
    document = json.loads((workspace / "policy.json").read_bytes())
    document["assets"][0]["operations"].append("process")
    (workspace / "policy.json").write_text(json.dumps(document))
    identifiers = exchange.save(records, source_id="owned-passive", source_bytes=b"owned", kind="raw")
    return identifiers, document, workspace


def prepare_fixture(policy, **options):
    identifiers, document, _workspace = passive_fixture(policy)
    return zap_passive.prepare(identifiers, actors=["owner", "guest"], mission=document["mission"], **options)


def test_preview_is_inert_bounded_and_secret_free(policy, boundaries):
    plan = prepare_fixture(policy)
    value = zap_passive.preview(plan)
    assert value["dry_run"] is True and value["target_network_enabled"] is False
    assert value["engine_plan"]["budgets"]["physical_requests"] == 0
    assert value["engine_plan"]["budgets"]["seconds"] == 120
    assert value["automation_plan"]["jobs"][1]["parameters"]["sendRequests"] is False
    assert value["automation_plan"]["env"]["vars"] == {"BUGHUNT_BUNDLE_DIR": "/bughunt/input"}
    assert "fixture-private-secret" not in json.dumps(value)
    assert not plan.budget.stop_path().parent.exists()
    assert all(b"fixture-private-secret" not in raw for raw in plan.files.values())
    with pytest.raises(egress.PolicyBlocked):
        plan.budget.admit(httpx.Request("GET", "https://allowed.example/app/data"))


@pytest.mark.parametrize("operation", ["passive", "process"])
def test_missing_permission_blocks_before_process(policy, boundaries, operation):
    identifiers, document, workspace = passive_fixture(policy)
    document["permissions"][operation] = False
    (workspace / "policy.json").write_text(json.dumps(document))
    with pytest.raises(ValueError):
        zap_passive.prepare(identifiers, actors=["owner"], mission=document["mission"])


@pytest.mark.parametrize("change", ["policy", "actor", "source", "bundle"])
def test_prepared_fingerprints_cannot_drift(policy, change):
    plan = prepare_fixture(policy)
    if change == "policy":
        (plan.budget.stop_path().parents[2] / "policy.json").write_text("{}")
    elif change == "actor":
        identity.clear_profile("owner")
    elif change == "source":
        next(iter(plan.budget.sources)).write_bytes(b"{}")
    else:
        plan.files["plan.yaml"] += b"changed"
    with pytest.raises(ValueError):
        zap_passive.preview(plan)


@pytest.mark.parametrize("seconds", [0, 301, True, 1.5])
def test_runtime_deadline_is_not_only_a_plan_setting(policy, seconds):
    with pytest.raises(ValueError):
        prepare_fixture(policy, seconds=seconds)


def test_partial_capture_and_wrong_mission_block(policy):
    identifiers, document, workspace = passive_fixture(policy)
    with pytest.raises(ValueError):
        zap_passive.prepare(identifiers, actors=["owner"], mission="another-mission")
    path = exchange._path(identifiers[0])
    value = json.loads(path.read_bytes())
    value["response"]["truncated"] = True
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        zap_passive.prepare(identifiers, actors=["owner"], mission=document["mission"])


def test_engine_cli_passive_preview_uses_existing_console_entry(policy, boundaries, capsys):
    identifiers, document, workspace = passive_fixture(policy)
    assert engine_command.main(["dry-run", "zap-passive", *identifiers, "--mission", document["mission"],
                                "--actor", "owner", "--actor", "guest", "--seconds", "90"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["engine_plan"]["profile_id"] == "zap-passive"
    assert value["engine_plan"]["budgets"]["seconds"] == 90
    assert value["engine_plan"]["budgets"]["physical_requests"] == 0
    assert "fixture-private-secret" not in json.dumps(value)
    assert not (workspace / "jobs").exists()


@pytest.mark.parametrize("active_option", [["--requests", "1"], ["--owned-lab"], ["--technology", "Python"]])
def test_passive_cli_cannot_accept_active_send_options(policy, boundaries, active_option):
    identifiers, document, workspace = passive_fixture(policy)
    assert engine_command.main(["dry-run", "zap-passive", *identifiers, "--mission", document["mission"],
                                "--actor", "owner", *active_option]) == 2
    assert not (workspace / "jobs").exists()
