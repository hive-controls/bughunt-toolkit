import bughunt
from bughunt.core import ledger
from scanner_oracle_support import lab, workspace
from test_native_lab_adapters import assert_artifact_contract


def test_scan_api_preserves_report_facts_and_wire_receipts(lab, capsys):
    result = bughunt.run_module(
        "scan",
        options={
            "targets": ["127.0.0.1"],
            "ports": str(lab.port),
            "http_only": True,
            "paths": "/",
            "skip_tcp": True,
            "quiet": True,
        },
    )
    assert result.status == "success", result.to_dict()
    value = result.artifacts[0].payload["items"][0]["attributes"]
    assert value["hosts"][0]["ports"][0]["hits"][0]["status"] == 200
    assert len(lab.requests) == 1
    assert result.evidence
    assert result.metrics["requests_admitted"] is None
    assert any("admissions" in warning for warning in result.warnings)
    assert next(item for item in result.artifacts if item.kind == "urls").payload[
        "urls"
    ] == [lab.base()]
    assert capsys.readouterr().out == ""


def test_scan_preview_validates_plan_without_output_directory_or_network(lab):
    result = bughunt.run_module(
        "scan",
        options={
            "targets": ["127.0.0.1"],
            "ports": str(lab.port),
            "http_only": True,
            "output_dir": str(lab.out),
            "paths": "/",
            "skip_tcp": True,
        },
        dry_run=True,
    )
    assert result.status == "planned", result.to_dict()
    value = result.artifacts[0].payload["items"][0]["attributes"]
    assert value["requests"][0]["target"] == lab.base()
    assert not lab.out.exists()
    assert not lab.requests
    assert not ledger.runs_dir().exists()


def test_scan_preview_rejects_scope_and_redirect_expansion(lab):
    result = bughunt.run_module(
        "scan",
        options={
            "targets": ["127.0.0.1"],
            "ports": str(lab.port),
            "follow_redirects": True,
        },
        dry_run=True,
    )
    assert result.status == "invalid", result.to_dict()
