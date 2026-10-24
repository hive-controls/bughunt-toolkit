"""The capability map is metadata, never an engine or authority registry."""

import json
from pathlib import Path
import re
import socket
import subprocess
import sys

import pytest

from bughunt.core import scanner as bughunt_scanner
from bughunt.core import engine
from bughunt.modules import engine as engine_command


def test_map_is_discoverable_through_the_primary_cli_without_network_or_process(
    monkeypatch, capsys
):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Capability metadata reached an execution boundary")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert bughunt_scanner.main(["engine", "map"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["schema_version"] == 1 and value["revision"]
    assert value["execution_authority"] is False
    assert value["physical_requests"] == 0


def test_map_covers_delivered_labs_plans_unavailable_and_excluded(capsys):
    assert engine_command.main(["map"]) == 0
    rows = json.loads(capsys.readouterr().out)["capabilities"]
    assert len({row["capability_id"] for row in rows}) == len(rows)
    assert {row["status"] for row in rows} == {
        "delivered",
        "lab-only",
        "planned",
        "unavailable",
        "excluded",
    }
    for row in rows:
        assert (
            row["mission_need"]
            and row["owner"]
            and row["tested_scope"]
            and row["remaining_gap"]
        )
        assert row["supported_versions"] and "issue" not in row
        assert re.fullmatch(r"CAP-\d{2}", row["story"])
        assert all(
            (Path(__file__).parent / test).is_file()
            for test in row["acceptance"]["tests"]
        )
        assert row["acceptance"]["tests"] or row["status"] in {
            "planned",
            "unavailable",
            "excluded",
        }


def test_map_names_actual_lab_limits_and_keeps_specialists_unavailable(capsys):
    assert engine_command.main(["map"]) == 0
    rows = {
        row["capability_id"]: row
        for row in json.loads(capsys.readouterr().out)["capabilities"]
    }
    assert rows["zap-active"]["status"] == "lab-only"
    assert "40012" in rows["zap-active"]["tested_scope"]
    assert "default" in rows["zap-active"]["tested_scope"]
    assert rows["burp-specialist"]["status"] == "unavailable"
    assert rows["burp-intake"]["status"] == "delivered"
    assert "incomplete" in rows["burp-intake"]["tested_scope"]
    assert rows["api-schema"]["status"] == "unavailable"
    assert rows["offline-triage"]["status"] == "delivered"
    assert rows["offline-triage"]["acceptance"]["tests"] == ["test_triage.py"]
    assert "not proof" in rows["offline-triage"]["remaining_gap"]
    dispatch = rows["dispatch-spacing"]
    assert dispatch["story"] == "CAP-28" and dispatch["status"] == "delivered"
    assert dispatch["acceptance"]["environment"] == {
        "BUGHUNT_RUN_DISPATCH_CONSUMER": "1"
    }
    assert (
        "opaque" in dispatch["remaining_gap"]
        and "cross-process" in dispatch["remaining_gap"]
    )
    assert rows["browser-actors"]["status"] == "lab-only"
    assert "network-none" in rows["browser-actors"]["tested_scope"]
    assert (
        "strict header spacing remains the dispatch-spacing capability"
        in rows["browser-actors"]["remaining_gap"]
    )
    assert rows["browser-actors"]["acceptance"]["environment"] == {
        "BUGHUNT_BROWSER_INTEGRATION": "1"
    }


def test_mutating_the_returned_map_cannot_enable_an_engine_profile(capsys):
    assert engine_command.main(["map"]) == 0
    value = json.loads(capsys.readouterr().out)
    next(
        row
        for row in value["capabilities"]
        if row["capability_id"] == "burp-specialist"
    )["status"] = "delivered"
    with pytest.raises(ValueError, match="Unsupported or unavailable"):
        engine.prepare("burp-specialist", "not-a-source")
    assert engine_command.main(["map"]) == 0
    fresh = json.loads(capsys.readouterr().out)
    assert (
        next(
            row
            for row in fresh["capabilities"]
            if row["capability_id"] == "burp-specialist"
        )["status"]
        == "unavailable"
    )


def test_acceptance_commands_bind_the_source_checkout_virtual_environment(capsys):
    assert engine_command.main(["map"]) == 0
    value = json.loads(capsys.readouterr().out)
    root = Path(__file__).absolute().parent.parent
    python = (
        root
        / ".venv"
        / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    )
    commands = [
        row["acceptance"] for row in value["capabilities"] if row["acceptance"]["tests"]
    ]
    commands.append(value["owned_workflow_acceptance"])
    for command in commands:
        assert command["cwd"] == str(root)
        assert command["argv"][:4] == [str(python), "-m", "pytest", "-q"]
        assert any("virtual environment" in item for item in command["prerequisites"])
    assert any("BUGHUNT_BURP_PROFILE" in item for item in commands[-1]["prerequisites"])
