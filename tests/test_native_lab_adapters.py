import json

import httpx
import pytest

import bughunt
from bughunt.core import exchange, ledger
from bughunt.labs import race
from test_gate import boundaries, policy
import test_desync
import test_race
import test_websocket
from test_zap_active import owned


@pytest.fixture(autouse=True)
def assert_artifact_contract(monkeypatch):
    from bughunt.core import adapters

    original = bughunt.run_module

    def checked(*args, **kwargs):
        result = original(*args, **kwargs)
        if not result.dry_run:
            assert {item.kind for item in result.artifacts} <= adapters.output_kinds(
                result.module_id, result.operation
            )
        return result

    monkeypatch.setattr(bughunt, "run_module", checked)


def test_race_preview_uses_owned_plan(policy, boundaries):
    test_race.approve(policy)
    source = test_race.source()
    exchange.save([source], source_id="lab", source_bytes=b"owned", kind="raw")
    result = bughunt.run_module(
        "race",
        operation="run",
        options={
            "exchange_id": source["exchange_id"],
            "mission": "whk014-owned-race",
            "owned_lab": True,
        },
        dry_run=True,
    )
    assert result.status == "planned", result.to_dict()
    value = result.artifacts[0].payload["items"][0]["attributes"]
    assert value["request_cap"] == 4
    assert not (policy[1] / "jobs").exists()


def test_race_adapter_returns_worker_run_evidence(policy, boundaries, monkeypatch):
    test_race.approve(policy)
    source = test_race.source()
    exchange.save([source], source_id="lab", source_bytes=b"owned", kind="raw")
    original = race.execute
    monkeypatch.setattr(
        race,
        "execute",
        lambda plan: original(
            plan,
            transport_factory=lambda: httpx.MockTransport(
                lambda request: httpx.Response(200, stream=httpx.ByteStream(b"owned"))
            ),
        ),
    )
    result = bughunt.run_module(
        "race",
        operation="run",
        options={
            "exchange_id": source["exchange_id"],
            "mission": "whk014-owned-race",
            "owned_lab": True,
        },
    )
    assert result.status == "success", result.to_dict()
    value = result.artifacts[0].payload["items"][0]["attributes"]
    assert len(value["requests"]) == 4
    assert {row["run_id"] for row in value["requests"]} <= {
        row["run_id"] for row in result.evidence
    }
    assert "captured-secret" not in json.dumps(result.to_dict())


def test_desync_preview_uses_owned_plan(policy, boundaries):
    test_desync.approve(policy)
    result = bughunt.run_module(
        "desync",
        operation="dry-run",
        options={
            "front_url": test_desync.FRONT,
            "backend_url": test_desync.BACK,
            "mission": test_desync.desync.MISSION,
            "owned_lab": True,
        },
    )
    assert result.status == "planned", result.to_dict()
    value = result.artifacts[0].payload["items"][0]["attributes"]
    assert value["front"] == test_desync.FRONT
    assert not (policy[1] / "jobs").exists()


def test_websocket_preview_reads_and_validates_messages(policy, boundaries):
    test_websocket.approve(policy)
    path = policy[1] / "messages.json"
    path.write_text('["owned"]')
    result = bughunt.run_module(
        "ws",
        operation="capture",
        options={
            "target": test_websocket.URL,
            "messages": str(path),
            "mission": "whk015-owned-ws",
            "owned_lab": True,
            "dry_run": True,
        },
    )
    assert result.status == "planned", result.to_dict()
    assert result.artifacts[0].kind == "observations"
    path.write_text("[1]")
    rejected = bughunt.run_module(
        "ws",
        operation="capture",
        options={
            "target": test_websocket.URL,
            "messages": str(path),
            "mission": "whk015-owned-ws",
            "owned_lab": True,
        },
        dry_run=True,
    )
    assert rejected.status == "invalid"
    assert not (policy[1] / "jobs").exists()


def test_zap_active_preview_is_substantive(owned, boundaries):
    result = bughunt.run_module(
        "zap",
        operation="active",
        options={
            "exchange_id": owned[0],
            "mission": "whk012-owned-active",
            "owned_lab": True,
            "technology": "Python",
            "requests": 4,
        },
        dry_run=True,
    )
    assert result.status == "planned", result.to_dict()
    value = result.artifacts[0].payload["items"][0]["attributes"]
    assert value["request_cap"] == 4
    assert value["rule_ids"] == [40012]
    assert not (owned[2] / "jobs").exists()


def test_race_workers_inherit_ledger_collection(policy, boundaries):
    plan = test_race.prepare(policy)
    with ledger.collect_runs() as captured:
        result = race.execute(
            plan,
            transport_factory=lambda: httpx.MockTransport(
                lambda request: httpx.Response(200, stream=httpx.ByteStream(b"owned"))
            ),
        )
    assert len(result["requests"]) == 4
    assert {item["run_id"] for item in result["requests"]} <= set(captured)


@pytest.mark.parametrize("execute", [False, True])
def test_idor_adapter_previews_owned_field_plan(policy, boundaries, execute):
    import test_idor

    test_idor._setup()
    source = policy[1] / "idor.http"
    source.write_bytes(test_idor._source())
    result = bughunt.run_module(
        "idor",
        options={
            "request": str(source),
            "actor": "owner",
            "compare": "second/obj-second",
            "field": ["ref.id"],
            "execute": execute,
        },
        dry_run=execute,
    )
    assert result.status == "planned", result.to_dict()
    value = result.artifacts[0].payload["items"][0]["attributes"]
    assert len(value["planned_requests"]) == 2
    assert value["network_requests"] == 0
    assert not ledger.runs_dir().exists()


def test_idor_adapter_executes_without_parsing_renderer(
    policy, boundaries, monkeypatch, capsys
):
    import test_idor
    from bughunt.modules import idor

    test_idor._setup()
    source = policy[1] / "idor.http"
    original_source = test_idor._source()
    source.write_bytes(original_source)
    transport, seen = test_idor._lab()
    original = idor.execute
    monkeypatch.setattr(
        idor,
        "execute",
        lambda plan, **kwargs: original(plan, transport=transport, **kwargs),
    )
    result = bughunt.run_module(
        "idor",
        options={
            "request": str(source),
            "actor": "owner",
            "compare": "second/obj-second",
            "field": ["ref.id"],
            "execute": True,
        },
    )
    assert result.status == "success", result.to_dict()
    assert result.artifacts[0].payload["classification"] == "negative"
    assert result.evidence and seen
    assert source.read_bytes() == original_source
    assert "captured-secret" not in json.dumps(result.to_dict())
    assert capsys.readouterr().out == ""


def test_oast_adapter_prepares_and_retains_only_real_receipts(policy, boundaries):
    import test_oast

    test_oast.approve(policy)
    run_id = test_oast.origin_run()
    options = {"run_id": run_id, "provider": "collaborator", "domain": test_oast.DOMAIN}
    before = set(ledger.runs_dir().iterdir())
    planned = bughunt.run_module(
        "oast", operation="register", options=options, dry_run=True
    )
    assert planned.status == "planned", planned.to_dict()
    assert not (policy[1] / "oast").exists()
    assert set(ledger.runs_dir().iterdir()) == before
    registered = bughunt.run_module("oast", operation="register", options=options)
    assert registered.status == "success", registered.to_dict()
    assert registered.evidence
    source = policy[1] / "callbacks.json"
    source.write_text(json.dumps(test_oast.bundle()))
    options = {"file": str(source), "source_id": "owned-callbacks"}
    before = set(ledger.runs_dir().iterdir())
    planned = bughunt.run_module(
        "oast", operation="import", options=options, dry_run=True
    )
    assert planned.status == "planned", planned.to_dict()
    assert set(ledger.runs_dir().iterdir()) == before
    imported = bughunt.run_module("oast", operation="import", options=options)
    assert imported.status == "success", imported.to_dict()
    value = imported.artifacts[0].payload["items"][0]["attributes"]
    assert value["observation_count"] == 1 and value["impact_proven"] is False
    source.write_text("{}")
    assert (
        bughunt.run_module(
            "oast", operation="import", options=options, dry_run=True
        ).status
        == "invalid"
    )


def test_zap_passive_previews_validate_without_writes(policy, boundaries):
    import test_zap
    from test_zap_report import report_fixture

    records = test_zap.fixture_records(policy[1])
    exchange.save(
        records, source_id="owned-passive", source_bytes=b"fixture", kind="raw"
    )
    destination = policy[1] / "zap-bundle"
    result = bughunt.run_module(
        "zap",
        operation="export",
        options={
            "exchange_ids": [records[0]["exchange_id"]],
            "output": str(destination),
            "actor": ["owner"],
        },
        dry_run=True,
    )
    assert result.status == "planned", result.to_dict()
    assert not destination.exists()
    report = policy[1] / "zap.json"
    report.write_text(json.dumps(report_fixture()))
    options = {"report": str(report), "source_id": "owned-report"}
    result = bughunt.run_module(
        "zap", operation="import", options=options, dry_run=True
    )
    assert result.status == "planned", result.to_dict()
    assert not ledger.runs_dir().exists()
    report.write_text("{}")
    assert (
        bughunt.run_module(
            "zap", operation="import", options=options, dry_run=True
        ).status
        == "invalid"
    )
