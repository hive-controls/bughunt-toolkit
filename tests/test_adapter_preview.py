import socket
import subprocess

import pytest

import bughunt
from bughunt.core import exchange, ledger, route
from test_discovery import source
from test_gate import policy


@pytest.fixture
def inert(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Preview reached an external boundary")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(route, "gate", forbidden)


@pytest.mark.parametrize("explicit", [False, True])
def test_discovery_preview_validates_evidence_and_reports_real_plan(
    policy, inert, explicit
):
    record = source()
    exchange.save(
        [record], source_id="owned-preview", source_bytes=b"owned", kind="raw"
    )
    before = {p: p.read_bytes() for p in policy[1].rglob("*") if p.is_file()}
    result = bughunt.run_module(
        "discover",
        options={
            "exchange_id": record["exchange_id"],
            "header": ["X-Hidden"],
            "dry_run": not explicit,
        },
        dry_run=explicit,
    )
    assert result.status == "planned", result.to_dict()
    plan = result.artifacts[0].payload["items"][0]["attributes"]
    assert plan["planned_requests"] == 7
    assert plan["source_exchange_id"] == record["exchange_id"]
    after = {p: p.read_bytes() for p in policy[1].rglob("*") if p.is_file()}
    assert after == before
    assert result.evidence == []


def test_discovery_preview_rejects_missing_capture(policy, inert):
    result = bughunt.run_module(
        "discover",
        options={"exchange_id": "a" * 64, "header": ["X-Hidden"]},
        dry_run=True,
    )
    assert result.status == "invalid"
    assert not ledger.runs_dir().exists()


def test_engine_preview_rejects_unknown_profile_instead_of_claiming_plan(policy, inert):
    result = bughunt.run_module(
        "engine",
        operation="dry-run",
        options={
            "profile_id": "nonexistent",
            "exchange_id": ["a" * 64],
            "mission": "owned-lab",
        },
    )
    assert result.status == "invalid"
    assert not (policy[1] / "jobs").exists()
