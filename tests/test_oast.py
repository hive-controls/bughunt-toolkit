"""Owned callback observations; no provider service or network is contacted."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import threading

import httpx
import pytest

from bughunt.core import egress, exchange, ledger, oast
from bughunt.modules import oast as command
from test_gate import boundaries, policy

DOMAIN = "owned123.callbacks.example"


def approve(policy):
    document, path = policy
    document["callback_domains"] = [DOMAIN]
    (path / "policy.json").write_text(json.dumps(document))


def origin_run(domain=DOMAIN):
    with egress.client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"owned"))) as client:
        response = client.get("https://allowed.example/app/item", headers={"Referer": "https://" + domain + "/"})
    return response.extensions["bughunt_run_id"]


def bundle(*, provider="collaborator", **updates):
    value = {"provider": provider, "domain": DOMAIN, "payload_id": "owned123", "event_id": "owned-event-1",
             "protocol": "http", "received_at": datetime.now(timezone.utc).isoformat(),
             "raw": "GET / HTTP/1.1\r\nHost: " + DOMAIN + "\r\nAuthorization: Bearer callback-secret\r\n\r\n"}
    value.update(updates)
    return {"schema_version": 1, "events": [value]}


def observations(result):
    return ledger.export_run(result["run_id"])["artifacts"]["observations.json"]["value"]["observations"]


@pytest.mark.parametrize("provider", ["collaborator", "interactsh-selfhosted"])
def test_approved_callback_preserves_origin_and_never_promotes(policy, boundaries, provider):
    approve(policy)
    run_id = origin_run()
    registration = oast.register(run_id, provider=provider, domain=DOMAIN)
    raw = exchange.canonical(bundle(provider=provider))
    result = oast.import_callbacks(raw, source_id="owned-callback-source")
    value = observations(result)[0]
    assert value["origin_run_id"] == run_id
    assert value["registration_run_id"] == registration["receipt_run_id"]
    assert value["confirmed"] is False and value["impact_proven"] is False
    assert value["classification"] == ledger.manifest_for(result["run_id"])["classification"] == "observation"
    assert value["quarantined"] is False
    assert "callback-secret" not in json.dumps(ledger.export_run(result["run_id"]))
    assert (ledger.runs_dir() / result["run_id"] / "source.json").read_bytes() == raw
    with pytest.raises(exchange.ExchangeError):
        exchange.from_run(result["run_id"])


def test_payload_bound_once_to_origin_and_repeat_registration_is_idempotent(policy, boundaries):
    approve(policy)
    first = origin_run()
    registered = oast.register(first, provider="collaborator", domain=DOMAIN)
    assert oast.register(first, provider="collaborator", domain=DOMAIN)["receipt_run_id"] == registered["receipt_run_id"]
    with pytest.raises(ValueError):
        oast.register(origin_run(), provider="collaborator", domain=DOMAIN)


def test_concurrent_registration_cannot_rebind_payload(policy, boundaries, monkeypatch):
    approve(policy)
    first, second = origin_run(), origin_run()
    original_record = ledger.record_import
    both_recorded = threading.Barrier(2)

    def synchronized_record(**kwargs):
        receipt = original_record(**kwargs)
        both_recorded.wait(timeout=5)
        return receipt

    monkeypatch.setattr(ledger, "record_import", synchronized_record)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(oast.register, run, provider="collaborator", domain=DOMAIN)
                   for run in (first, second)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result())
            except ValueError:
                pass
    assert len(outcomes) == 1
    assert oast._registration("collaborator", DOMAIN)["origin_run_id"] == outcomes[0]["origin_run_id"]


@pytest.mark.parametrize("provider,domain", [("interactsh", DOMAIN), ("unknown", DOMAIN),
                                            ("collaborator", "different.callbacks.example"),
                                            ("collaborator", DOMAIN + ".attacker.example"),
                                            ("collaborator", "*.callbacks.example")])
def test_unapproved_domains_providers_and_suffix_confusion_reject(policy, boundaries, provider, domain):
    approve(policy)
    run_id = origin_run()
    before = len(list(ledger.runs_dir().iterdir()))
    with pytest.raises(ValueError):
        oast.register(run_id, provider=provider, domain=domain)
    assert len(list(ledger.runs_dir().iterdir())) == before


def test_exact_payload_must_exist_in_complete_initiating_request(policy, boundaries):
    approve(policy)
    for domain in ["missing.example", DOMAIN + ".attacker.example"]:
        with pytest.raises(ValueError):
            oast.register(origin_run(domain), provider="collaborator", domain=DOMAIN)


@pytest.mark.parametrize("change", ["missing", "stale", "permission", "domain", "scope"])
def test_current_policy_blocks_registration_without_extra_receipts(policy, boundaries, change):
    approve(policy)
    run_id = origin_run()
    document, path = policy
    if change == "missing":
        (path / "policy.json").unlink()
    elif change == "scope":
        (path / "scope.txt").write_text("outside.example\n")
    else:
        if change == "stale":
            document["state"] = "stale"
        elif change == "permission":
            document["permissions"]["callback"] = False
        else:
            document["callback_domains"] = ["callbacks.example"]
        (path / "policy.json").write_text(json.dumps(document))
    with pytest.raises(ValueError):
        oast.register(run_id, provider="collaborator", domain=DOMAIN)
    assert len(list(ledger.runs_dir().iterdir())) == 1


def test_revoked_domain_import_is_inert_quarantined(policy, boundaries):
    approve(policy)
    oast.register(origin_run(), provider="collaborator", domain=DOMAIN)
    document, path = policy
    document["callback_domains"] = []
    (path / "policy.json").write_text(json.dumps(document))
    result = oast.import_callbacks(exchange.canonical(bundle()), source_id="revoked-domain")
    assert observations(result)[0]["quarantined"] is True
    assert result["impact_proven"] is False


def test_dedup_keeps_source_positions_and_distinct_observations(policy, boundaries):
    approve(policy)
    oast.register(origin_run(), provider="collaborator", domain=DOMAIN)
    document = bundle()
    document["events"] += [dict(document["events"][0]), dict(document["events"][0], event_id="owned-event-2")]
    raw = exchange.canonical(document)
    first = oast.import_callbacks(raw, source_id="owned-callbacks")
    values = observations(first)
    assert len(values) == 2 and values[0]["sources"] == ["/events/0", "/events/1"]
    second = oast.import_callbacks(raw, source_id="another-receipt")
    assert second["run_id"] != first["run_id"]
    assert [row["observation_id"] for row in observations(second)] == [row["observation_id"] for row in values]


@pytest.mark.parametrize("updates", [{"payload_id": "wrong"}, {"protocol": "unknown"},
                                     {"received_at": None}, {"raw": "x" * 65537}, {"extra": True}])
def test_malformed_late_event_never_persists_partial_receipt(policy, boundaries, updates):
    approve(policy)
    oast.register(origin_run(), provider="collaborator", domain=DOMAIN)
    document = bundle()
    document["events"].append(dict(document["events"][0], **updates))
    before = len(list(ledger.runs_dir().iterdir()))
    with pytest.raises(ValueError):
        oast.import_callbacks(exchange.canonical(document), source_id="malformed")
    assert len(list(ledger.runs_dir().iterdir())) == before


def test_registration_artifact_tamper_blocks_callbacks(policy, boundaries):
    approve(policy)
    registered = oast.register(origin_run(), provider="collaborator", domain=DOMAIN)
    (ledger.runs_dir() / registered["receipt_run_id"] / "registration.json").write_bytes(b"{}")
    with pytest.raises(ValueError):
        oast.import_callbacks(exchange.canonical(bundle()), source_id="tampered")


def test_cli_import_and_show_sanitized(policy, boundaries, capsys):
    approve(policy)
    run_id = origin_run()
    assert command.main(["register", run_id, "--provider", "collaborator", "--domain", DOMAIN]) == 0
    path = policy[1] / "callbacks.json"
    path.write_bytes(exchange.canonical(bundle()))
    assert command.main(["import", str(path), "--source-id", "owned-cli"]) == 0
    output = capsys.readouterr().out
    assert "callback-secret" not in output and '"impact_proven": false' in output


def test_callback_predating_origin_is_quarantined_not_causal_evidence(policy, boundaries):
    approve(policy)
    oast.register(origin_run(), provider="collaborator", domain=DOMAIN)
    result = oast.import_callbacks(exchange.canonical(bundle(received_at="2000-01-01T00:00:00Z")), source_id="old-event")
    assert observations(result)[0]["quarantined"] is True
    assert observations(result)[0]["temporal_match"] is False


def test_import_cannot_claim_confirmed_and_unknown_registration_has_no_partial_receipt(policy, boundaries):
    with pytest.raises(ValueError):
        ledger.record_import(tool="oast", metadata={"observation_count": 1}, artifacts={"source.json": b"{}"}, classification="confirmed")
    assert not ledger.runs_dir().exists()
    approve(policy)
    oast.register(origin_run(), provider="collaborator", domain=DOMAIN)
    document = bundle()
    document["events"].append(dict(document["events"][0], provider="interactsh-selfhosted"))
    before = len(list(ledger.runs_dir().iterdir()))
    with pytest.raises((ValueError, OSError)):
        oast.import_callbacks(exchange.canonical(document), source_id="unregistered")
    assert len(list(ledger.runs_dir().iterdir())) == before
