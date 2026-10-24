"""Owned, inert ZAP report normalization controls."""

import copy

import pytest

from bughunt.core import exchange
from bughunt.integrations import zap_report
from test_gate import boundaries, policy


def report_fixture() -> dict:
    instance = {
        "uri": "https://allowed.example/app/item",
        "method": "GET",
        "param": "owned",
        "attack": "",
        "evidence": "owned marker",
        "otherinfo": "owned observation",
    }
    alert = {
        "pluginid": "10001",
        "alertRef": "10001-1",
        "alert": "Owned header observation",
        "name": "Owned header observation",
        "riskcode": "1",
        "confidence": "2",
        "desc": "Owned fixture description",
        "solution": "Manual review",
        "reference": "",
        "otherinfo": "",
        "cweid": "0",
        "wascid": "0",
        "sourceid": "42",
        "instances": [instance],
        "count": "1",
    }
    return {
        "@version": "2.17.0",
        "created": "2026-10-13T00:00:00Z",
        "site": [{"@name": "https://allowed.example", "alerts": [alert]}],
    }


def parse(document: dict) -> dict:
    return zap_report.parse(exchange.canonical(document), source_id="owned-zap-report")


def test_report_maps_scanner_claims_and_traceable_source_without_io(policy, boundaries):
    document = report_fixture()
    raw = exchange.canonical(document)
    result = zap_report.parse(raw, source_id="owned-zap-report")
    value = result["observations"][0]
    assert value["scanner"]["plugin_id"] == 10001
    assert value["scanner"]["alert_ref"] == "10001-1"
    assert value["scanner"]["risk"] == 1 and value["scanner"]["confidence"] == 2
    assert value["scanner"]["cwe"] == 0 and value["scanner"]["wasc"] == 0
    assert (
        value["instance"]["uri"]
        == document["site"][0]["alerts"][0]["instances"][0]["uri"]
    )
    assert (
        value["instance"]["parameter"] == "owned"
        and value["instance"]["evidence"] == "owned marker"
    )
    source = value["sources"][0]
    assert source["source_id"] == "owned-zap-report" and source[
        "report_sha256"
    ] == exchange.digest(raw)
    assert (
        source["json_pointer"] == "/site/0/alerts/0/instances/0"
        and source["scanner_source_id"] == "42"
    )
    assert result["source"]["reported_at"] == "2026-10-13T00:00:00Z"
    assert not (policy[1] / "runs").exists()


def test_scanner_confirmed_confidence_cannot_promote_imported_hypothesis(policy):
    document = report_fixture()
    alert = document["site"][0]["alerts"][0]
    alert.update(confidence="4", riskcode="3", confirmed=True, hypothesis_level=5)
    alert["instances"][0].update(confirmed=True, hypothesis_level=5)
    value = parse(document)["observations"][0]
    assert value["classification"] == "hypothesis" and value["hypothesis_level"] == 1
    assert value["manual_controls_required"] is True and value["confirmed"] is False
    assert value["scanner"]["confidence"] == 4 and value["scanner"]["risk"] == 3


@pytest.mark.parametrize("field,normalized", [("cweid", "cwe"), ("wascid", "wasc")])
@pytest.mark.parametrize("sentinel", ["-1", -1])
def test_unassigned_zap_weakness_code_remains_nullable(
    policy, field, normalized, sentinel
):
    document = report_fixture()
    document["site"][0]["alerts"][0][field] = sentinel
    scanner = parse(document)["observations"][0]["scanner"]
    assert scanner[normalized] is None


def test_duplicate_and_distinct_instances_keep_separate_source_positions(policy):
    document = report_fixture()
    instances = document["site"][0]["alerts"][0]["instances"]
    instances.extend(
        [
            copy.deepcopy(instances[0]),
            dict(instances[0], evidence="second owned marker"),
        ]
    )
    values = parse(document)["observations"]
    assert len(values) == 3
    assert values[0]["observation_id"] == values[1]["observation_id"]
    assert values[0]["sources"] != values[1]["sources"]
    assert values[2]["observation_id"] != values[0]["observation_id"]
    second = zap_report.parse(exchange.canonical(document), source_id="another-report")
    assert second["observations"][0]["observation_id"] == values[0]["observation_id"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("riskcode", "4"),
        ("riskcode", True),
        ("confidence", "5"),
        ("pluginid", "-1"),
        ("cweid", "wrong"),
        ("cweid", "-2"),
        ("instances", {}),
        ("instances", []),
        ("name", []),
        ("evidence", "x" * 16385),
    ],
)
def test_malformed_alerts_reject_whole_report(policy, boundaries, field, value):
    document = report_fixture()
    alert = document["site"][0]["alerts"][0]
    if field == "evidence":
        alert["instances"][0][field] = value
    else:
        alert[field] = value
    with pytest.raises(zap_report.ReportError):
        parse(document)
    assert not (policy[1] / "runs").exists()


@pytest.mark.parametrize(
    "field,value",
    [("@version", "2.16.0"), ("site", {}), ("created", "undated"), ("created", None)],
)
def test_unsupported_or_ambiguous_report_metadata_rejects(policy, field, value):
    document = report_fixture()
    document[field] = value
    with pytest.raises(zap_report.ReportError):
        parse(document)


@pytest.mark.parametrize(
    "uri",
    [
        "file:///tmp/report",
        "https://other.example/item",
        "https://user:password@allowed.example/item",
        "https://allowed.example/item#fragment",
        "https://allowed.example:invalid/item",
    ],
)
def test_ambiguous_or_mismatched_instance_target_rejects(policy, boundaries, uri):
    document = report_fixture()
    document["site"][0]["alerts"][0]["instances"][0]["uri"] = uri
    with pytest.raises(zap_report.ReportError):
        parse(document)


def test_offscope_report_is_inert_and_not_execution_authority(policy, boundaries):
    document = report_fixture()
    document["site"][0]["@name"] = "https://outside.example"
    document["site"][0]["alerts"][0]["instances"][0]["uri"] = (
        "https://outside.example/item"
    )
    value = parse(document)["observations"][0]
    assert value["confirmed"] is False and value["hypothesis_level"] == 1
    assert "decision" not in value and "actor" not in value
    assert not (policy[1] / "runs").exists()


def test_empty_report_preserves_provenance_without_inferring_negative(policy):
    document = report_fixture()
    document["site"][0]["alerts"] = []
    value = parse(document)
    assert (
        value["observations"] == []
        and value["source"]["source_id"] == "owned-zap-report"
    )
    assert "classification" not in value


def test_observation_bound_and_duplicate_json_keys_are_rejected(policy, monkeypatch):
    document = report_fixture()
    document["site"][0]["alerts"][0]["instances"] *= 3
    monkeypatch.setattr(zap_report, "OBSERVATION_LIMIT", 2)
    with pytest.raises(zap_report.ReportError):
        parse(document)
    with pytest.raises(zap_report.ReportError):
        zap_report.parse(b'{"site":[],"site":[]}', source_id="duplicate-json")
