"""Owned report-to-ledger fixtures; import never authorizes traffic or findings."""

import json

import pytest

from bughunt.core import exchange, ledger
from bughunt.integrations import zap_import
from bughunt.modules import zap as command
from test_gate import boundaries, policy
from test_zap_report import report_fixture


def selected_exchange(*, actor="owner", body=b"owned") -> dict:
    request = b"GET https://allowed.example/app/item HTTP/1.1\r\nHost: allowed.example\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    return exchange.raw_record(request, response, source_id="owned-source", actor=actor)


def import_fixture(*, document=None, records=None, source_id="owned-report") -> str:
    raw = exchange.canonical(document or report_fixture())
    return zap_import.import_report(raw, source_id=source_id, records=records or [])


def observations(run_id: str) -> list[dict]:
    return ledger.export_run(run_id)["artifacts"]["observations.json"]["value"]["observations"]


def test_import_has_private_hashed_evidence_and_explicit_inert_metadata(policy, boundaries):
    document = report_fixture()
    document["site"][0]["alerts"][0]["instances"][0]["evidence"] = "Authorization: Bearer report-secret"
    raw = exchange.canonical(document)
    run_id = zap_import.import_report(raw, source_id="owned-report", records=[selected_exchange()])
    manifest = ledger.manifest_for(run_id)
    assert manifest["classification"] == "hypothesis" and manifest["decision"] == "inert-import"
    assert manifest["representation"] == "external-json-observations; not HTTP capture"
    assert manifest["actor"] == "unverified-source" and manifest["operation"] == "import"
    assert manifest["request"] is None and manifest["response"] is None
    path = ledger.runs_dir() / run_id / "source.json"
    assert path.read_bytes() == raw
    assert manifest["artifacts"]["source.json"]["sha256"] == exchange.digest(raw)
    exported = ledger.export_run(run_id)
    assert "report-secret" not in json.dumps(exported)
    assert "report-secret" in path.read_text()
    assert exported["captures"] == {}
    with pytest.raises(exchange.ExchangeError):
        exchange.from_run(run_id)


def test_imported_artifact_export_redacts_session_and_csrf_values(policy, boundaries):
    document = report_fixture()
    instance = document["site"][0]["alerts"][0]["instances"][0]
    instance["uri"] = "https://allowed.example/app/item?session=REVIEW_SESSION_123&csrf=REVIEW_CSRF_456"
    instance["evidence"] = '{"csrf_token":"REVIEW_CSRF_456","session":"REVIEW_SESSION_123"}'
    document["session"] = "REVIEW_SESSION_123"
    raw = exchange.canonical(document)
    run_id = zap_import.import_report(raw, source_id="redaction-regression", records=[])
    exported = json.dumps(ledger.export_run(run_id))
    assert "REVIEW_SESSION_123" not in exported
    assert "REVIEW_CSRF_456" not in exported
    assert "[REDACTED]" in exported
    assert (ledger.runs_dir() / run_id / "source.json").read_bytes() == raw


def test_duplicate_instances_deduplicate_without_losing_provenance(policy, boundaries):
    document = report_fixture()
    instances = document["site"][0]["alerts"][0]["instances"]
    instances.extend([dict(instances[0]), dict(instances[0], evidence="different owned evidence")])
    run_id = import_fixture(document=document)
    values = observations(run_id)
    assert len(values) == 2 and len(values[0]["sources"]) == 2
    assert {source["json_pointer"] for source in values[0]["sources"]} == {
        "/site/0/alerts/0/instances/0", "/site/0/alerts/0/instances/1"}
    another = import_fixture(document=document, source_id="second-receipt")
    assert another != run_id
    assert [value["observation_id"] for value in observations(another)] == [value["observation_id"] for value in values]
    assert ledger.manifest_for(run_id)["import_metadata"]["instance_count"] == 3
    assert ledger.manifest_for(run_id)["import_metadata"]["observation_count"] == 2


def test_exchange_links_are_only_url_method_candidates_not_verified_actor_claims(policy, boundaries):
    first, second = selected_exchange(), selected_exchange(actor="guest", body=b"different")
    one = observations(import_fixture(records=[first]))[0]
    assert one["source_exchange_candidates"] == [first["exchange_id"]]
    assert one["association"] == "url-method-only; not verified capture correspondence"
    assert one["confirmed"] is False and one["hypothesis_level"] == 1
    multiple = observations(import_fixture(records=[first, second]))[0]
    assert set(multiple["source_exchange_candidates"]) == {first["exchange_id"], second["exchange_id"]}
    assert "actor" not in multiple


@pytest.mark.parametrize("state", ["offscope", "stale", "expired", "missing"])
def test_unpermitted_report_retained_as_quarantined_hypothesis(policy, boundaries, state):
    document, path = policy
    report = report_fixture()
    if state == "offscope":
        report["site"][0]["@name"] = "https://outside.example"
        report["site"][0]["alerts"][0]["instances"][0]["uri"] = "https://outside.example/item"
    elif state in {"stale", "expired"}:
        if state == "stale":
            document["state"] = "stale"
        else:
            document["verified_at"] = "2000-01-01T00:00:00+00:00"
        (path / "policy.json").write_text(json.dumps(document))
    else:
        (path / "policy.json").unlink()
    value = observations(import_fixture(document=report))[0]
    assert value["quarantined"] is True and value["current_scope"]["permitted"] is False
    assert value["classification"] == "hypothesis" and value["hypothesis_level"] == 1


def test_empty_report_does_not_assert_negative_result(policy, boundaries):
    document = report_fixture()
    document["site"][0]["alerts"] = []
    run_id = import_fixture(document=document)
    assert observations(run_id) == []
    assert ledger.manifest_for(run_id)["classification"] == "observation"


def test_bad_selected_evidence_or_late_report_entry_has_no_partial_run(policy, boundaries):
    bad = selected_exchange()
    bad["request"]["body_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        import_fixture(records=[bad])
    document = report_fixture()
    document["site"][0]["alerts"].append({"instances": []})
    with pytest.raises(ValueError):
        import_fixture(document=document)
    assert not ledger.runs_dir().exists()


@pytest.mark.parametrize("name", ["source.json", "observations.json"])
def test_artifact_tamper_blocks_export(policy, name):
    run_id = import_fixture()
    (ledger.runs_dir() / run_id / name).write_bytes(b"{}")
    with pytest.raises(ValueError, match="hash"):
        ledger.export_run(run_id)


def test_untrusted_artifact_filename_cannot_escape_run(policy):
    run_id = import_fixture()
    manifest = ledger.manifest_for(run_id)
    manifest["artifacts"]["../outside.json"] = manifest["artifacts"].pop("source.json")
    ledger._write_private(ledger.runs_dir() / run_id / "manifest.json", exchange.canonical(manifest))
    with pytest.raises(ValueError):
        ledger.export_run(run_id)


def test_invalid_redaction_config_and_normalization_amplification_fail_before_write(policy, monkeypatch):
    _document, path = policy
    (path / "redaction.json").write_text('{"patterns":[123]}')
    with pytest.raises(ValueError):
        import_fixture()
    assert not ledger.runs_dir().exists()
    (path / "redaction.json").unlink()
    monkeypatch.setattr(zap_import, "NORMALIZED_LIMIT", 64)
    with pytest.raises(ValueError):
        import_fixture()
    assert not ledger.runs_dir().exists()


def test_cli_import_show_and_export_do_not_print_credentials(policy, boundaries, capsys):
    document = report_fixture()
    document["site"][0]["alerts"][0]["instances"][0]["evidence"] = "Cookie: session=owned-secret"
    report = policy[1] / "report.json"
    report.write_bytes(exchange.canonical(document))
    assert command.main(["import", str(report), "--source-id", "owned-cli"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["classification"] == "hypothesis" and result["observation_count"] == 1
    assert command.main(["show", result["run_id"]]) == 0
    assert "owned-secret" not in capsys.readouterr().out


def test_invalid_policy_snapshot_rejects_before_artifact_writes(policy):
    with pytest.raises(ValueError):
        ledger.record_import(tool="zap", metadata={"observation_count": 1, "policy_snapshot": []},
                             artifacts={"source.json": b"{}"})
    assert not ledger.runs_dir().exists()


def test_import_artifact_cannot_shadow_run_manifest(policy):
    with pytest.raises(ValueError):
        ledger.record_import(tool="zap", metadata={"observation_count": 1},
                             artifacts={"manifest.json": b"{}"})
    assert not ledger.runs_dir().exists()


@pytest.mark.parametrize("records", [False, {}, 0])
def test_invalid_falsy_source_selection_is_not_silently_empty(policy, records):
    with pytest.raises(ValueError):
        zap_import.import_report(exchange.canonical(report_fixture()), source_id="bad-selection", records=records)
    assert not ledger.runs_dir().exists()
