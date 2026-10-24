"""Opt-in actual Community selected-source proof; approval stays in the Burp UI."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import signal
import socket
import time
from urllib.parse import parse_qsl, urlsplit

import pytest

from bughunt.core import exchange, job, ledger
from bughunt.integrations import burp, burp_intake, burp_mcp
from bughunt.modules import engine as command
from bughunt.modules.policy import example_document

pytestmark = pytest.mark.skipif(os.environ.get("BUGHUNT_BURP_INTEGRATION") != "1", reason="Owned Community consumer is opt-in")


@pytest.fixture
def owned(tmp_path, monkeypatch):
    config = Path(os.environ["BUGHUNT_BURP_PROFILE"]).absolute()
    source = Path(os.environ["BUGHUNT_BURP_XML_FIXTURE"]).absolute()
    records = burp.parse(source.read_bytes(), source_id="whk024-owned-baseline", timezone="America/Los_Angeles")
    assert len(records) == 1 and records[0]["request"]["method"] == "GET"
    request = records[0]["request"]
    parsed = urlsplit(request["url"])
    assert parsed.hostname == "127.0.0.1" and parsed.path == "/whk010/fixture"
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    (tmp_path / "scope.txt").write_text("127.0.0.1\n")
    document = example_document()
    document.update(mission="whk024-owned-intake", state="verified", verified_at=datetime.now(timezone.utc).isoformat())
    document["permissions"] = {name: name in {"passive", "process"} for name in document["permissions"]}
    document["assets"] = [{"id": "owned-recorded-route", "origin": f"{parsed.scheme}://{parsed.netloc}",
        "paths": [parsed.path], "methods": ["GET"], "operations": ["passive", "process"]}]
    document["exclusions"] = []
    (tmp_path / "policy.json").write_bytes(exchange.canonical(document))
    for _name, value in parse_qsl(parsed.query):
        ledger.remember_secret(value)
    return config, request["url"], records[0]


def test_actual_owned_doctor_proves_handshake_without_history_read(owned):
    config, url, _original = owned
    plan = burp_intake.prepare(mission="whk024-owned-intake", url=url, source_id="owned-doctor", config=config)
    result = burp_intake.run(plan, probe=True)
    assert result["state"] == "success" and result["connection"]["connected"]
    assert not result["exchange_ids"] and result["admitted_count"] == 0 and result["cleanup_confirmed"]
    assert job.status(result["job_id"]) == result


def test_actual_selected_history_respects_denied_project_data_approval(owned):
    config, url, _original = owned
    plan = burp_intake.prepare(mission="whk024-owned-intake", url=url, source_id="owned-denied",
                              config=config, offset=0, count=1, seconds=120)
    result = burp_intake.run(plan, on_start=lambda identifier: print("Deny the one owned history request in Burp:", identifier, flush=True))
    assert result["state"] == "failed" and result["classification"] == "inconclusive"
    assert not result["exchange_ids"] and result["cleanup_confirmed"] and result["admitted_count"] == 0
    source = plan.budget.stop_path().parent / "source.json"
    assert source.is_file(), "No history reply received; denial is not proved (connected=%s; cleanup=%s)" % (
        result.get("connection", {}).get("connected", False), result["cleanup_confirmed"])
    raw = source.read_bytes()
    assert "denied" in exchange.load_json(raw)["result"]["content"][0]["text"].lower()


@pytest.mark.parametrize("interruption", ["cancel", "deadline", "policy", "profile", "keyboard"])
def test_actual_handshake_bridge_is_reaped_after_injected_interruption(owned, monkeypatch, interruption):
    """PROXY mutation timing; actual Community handshake and child-process cleanup."""
    config, url, _original = owned
    workspace = Path(os.environ["BUGHUNT_SCOPE"])
    copied = workspace / "burp-mcp.json"
    copied.write_bytes(config.read_bytes())
    plan = burp_intake.prepare(mission="whk024-owned-intake", url=url, source_id="owned-interruption",
                              config=copied, seconds=15)
    clients = []
    class InterruptedClient(burp_mcp.Client):
        def handshake(self, expected_hash=None):
            connected = super().handshake(expected_hash)
            clients.append(self)
            if interruption == "cancel":
                job.cancel(plan.budget.job_id)
            elif interruption == "deadline":
                plan.budget.deadline = time.monotonic() - 1
            elif interruption == "policy":
                (workspace / "policy.json").unlink()
            elif interruption == "keyboard":
                raise KeyboardInterrupt
            else:
                copied.write_bytes(b"changed-owned-profile")
            return connected
        def history(self, *_arguments):
            pytest.fail("Interrupted probe attempted a history read")
    monkeypatch.setattr(burp_intake.burp_mcp, "Client", InterruptedClient)
    try:
        result = burp_intake.run(plan, probe=True)
    except KeyboardInterrupt:
        pytest.fail("Ctrl-C escaped after the real handshake without a terminal receipt")
    assert len(clients) == 1 and clients[0].process.poll() is not None and not clients[0].reader.is_alive()
    assert result["state"] == ("cancelled" if interruption in {"cancel", "keyboard"} else "failed")
    assert result["classification"] == "inconclusive" and result["cleanup_confirmed"]
    assert not result["exchange_ids"] and result["admitted_count"] == 0
    assert set(clients[0].receipts) == {"1", "2"} and job.status(result["job_id"]) == result


def test_actual_unbound_endpoint_is_unavailable_without_launching_bridge(owned, monkeypatch):
    """An owned non-listening port models Burp absence without stopping the user's app."""
    config, url, _original = owned
    copied = Path(os.environ["BUGHUNT_SCOPE"]) / "burp-mcp.json"
    profile = exchange.load_json(config.read_bytes())
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        profile["endpoint"] = "http://127.0.0.1:" + str(reserved.getsockname()[1])
        copied.write_bytes(exchange.canonical(profile))
        plan = burp_intake.prepare(mission="whk024-owned-intake", url=url, source_id="owned-unbound", config=copied)
        monkeypatch.setattr(burp_intake.burp_mcp, "Client", lambda *_args, **_kwargs: pytest.fail("Missing listener launched bridge"))
        result = burp_intake.run(plan, probe=True)
    assert result["state"] == "failed" and result["classification"] == "inconclusive" and result["cleanup_confirmed"]
    assert "connection" not in result and not result["exchange_ids"] and result["admitted_count"] == 0
    assert not result["artifacts"] and job.status(result["job_id"]) == result


@pytest.mark.parametrize("interruption", ["keyboard", "signal"])
def test_actual_cleanup_interruption_reaps_bridge_and_finishes_receipt(owned, monkeypatch, interruption):
    """PROXY interruption timing; real Community handshake, child wait and cleanup."""
    config, url, _original = owned
    plan = burp_intake.prepare(mission="whk024-owned-intake", url=url, source_id="owned-cleanup", config=config)
    clients, waits, previous = [], [], signal.getsignal(signal.SIGINT)
    class InterruptedCleanup(burp_mcp.Client):
        def handshake(self, expected_hash=None):
            connected = super().handshake(expected_hash)
            clients.append(self)
            original_wait = self.process.wait
            def interrupted_wait(*arguments, **options):
                waits.append(True)
                if len(waits) == 1:
                    if interruption == "keyboard":
                        raise KeyboardInterrupt
                    signal.raise_signal(signal.SIGINT)
                return original_wait(*arguments, **options)
            monkeypatch.setattr(self.process, "wait", interrupted_wait)
            return connected
        def history(self, *_arguments):
            pytest.fail("Cleanup probe attempted a history read")
    monkeypatch.setattr(burp_intake.burp_mcp, "Client", InterruptedCleanup)
    try:
        result = burp_intake.run(plan, probe=True)
    except KeyboardInterrupt:
        pytest.fail("Cleanup interruption escaped after real handshake")
    assert clients and waits and clients[0].process.poll() is not None and not clients[0].reader.is_alive()
    assert result["state"] == "cancelled" and result["classification"] == "inconclusive" and result["cleanup_confirmed"]
    assert not result["exchange_ids"] and result["admitted_count"] == 0 and job.status(result["job_id"]) == result
    assert ledger.export_run(result["run_id"])["manifest"]["job_state"] == "cancelled"
    assert signal.getsignal(signal.SIGINT) == previous


def test_actual_selected_history_cli_import_is_incomplete_and_private(owned, capsys):
    config, url, original = owned
    assert command.main(["start", "burp-mcp-intake", url, "--mission", "whk024-owned-intake",
        "--source-id", "owned-approved", "--config", str(config), "--offset", "0", "--count", "1", "--seconds", "120"]) == 0
    output = capsys.readouterr().out
    announcement, _rest = json.JSONDecoder().raw_decode(output)
    result = job.status(announcement["starting_job_id"])
    assert result["state"] == "success" and result["run_id"] == announcement["run_id"]
    assert result["incomplete_count"] == 1 and result["quarantined_count"] == 0 and result["cleanup_confirmed"]
    assert result["admitted_count"] == 0 and result["connection"]["tool_allowlist"] == ["get_proxy_http_history"]
    record = exchange.read(result["exchange_ids"][0])
    assert record["request"]["url"] == url and record["response"]["status"] == original["response"]["status"]
    assert record["request"]["truncated"] and record["sources"][0]["captured_at"] is None
    assert record["sources"][0]["actor"] is None and record["sources"][0]["run_id"] == result["run_id"]
    public = json.dumps([exchange.project(record), ledger.export_run(result["run_id"])]) + output
    for _name, value in parse_qsl(urlsplit(url).query):
        assert value not in public
