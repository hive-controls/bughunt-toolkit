"""whk011-owned-inputs: explicit discovery without network or exploit followups."""

import json

import httpx
import pytest

from bughunt.core import discovery, exchange, identity, ledger
from bughunt.modules import MODULES, discover
from test_gate import boundaries, policy


def source(*, method="GET", headers=b"", url="https://allowed.example/app/item"):
    raw = method.encode() + b" " + url.encode() + b" HTTP/1.1\r\nHost: allowed.example\r\n" + headers + b"\r\n"
    return exchange.raw_record(raw, None, source_id="owned-discovery-source")


def owned_response(request, *, all_change=False, cache=False, unstable=False):
    query = request.url.params
    changed = ("x-hidden" in request.headers or "hidden=" in request.headers.get("cookie", "") or "hidden" in query)
    if all_change:
        changed |= bool(query) or any(name.startswith("whk_control_") for name in request.headers)
    body = b"candidate" if changed else b"baseline"
    if unstable:
        body += str(id(request)).encode()
    headers = {"Content-Type": "text/plain"}
    if cache:
        headers["X-Cache"] = "HIT"
    return httpx.Response(200, headers=headers, stream=httpx.ByteStream(body))


@pytest.mark.parametrize("candidate", [("header", "X-Hidden"), ("cookie", "hidden"), ("query", "hidden")])
def test_candidates_repeated_controls_budget_evidence_no_exploitation(policy, boundaries, candidate):
    plan = discovery.prepare(source(headers=b"Authorization: Bearer captured-secret\r\n"), [candidate])
    seen = []
    def respond(request):
        seen.append(request)
        assert "captured-secret" not in str(request.headers)
        return owned_response(request)
    result = discovery.execute(plan, transport=httpx.MockTransport(respond))
    assert result["classification"] == "lead"
    assert len(seen) == len(result["requests"]) == 7
    assert result["observations"][0]["confirmed"] is False
    assert result["observations"][0]["manual_controls_required"] is True
    assert [row["role"] for row in result["samples"]] == ["baseline", "baseline", "control", "control", "candidate", "candidate", "baseline"]
    for row in result["requests"]:
        assert ledger.manifest_for(row["run_id"])["operation"] == "fuzz"
    summary = ledger.export_run(result["run_id"])
    assert "captured-secret" not in json.dumps(summary)
    with pytest.raises(exchange.ExchangeError):
        exchange.from_run(result["run_id"])


@pytest.mark.parametrize("mode,outcome", [("negative", "negative"), ("reflection", "inconclusive"),
                                        ("cache", "inconclusive"), ("unstable", "inconclusive")])
def test_negative_cache_and_generic_reflection_controls(policy, boundaries, mode, outcome):
    name = "absent" if mode == "negative" else "hidden"
    plan = discovery.prepare(source(), [("query", name)])
    inner = httpx.MockTransport(lambda request: owned_response(request, all_change=mode == "reflection",
                                                               cache=mode == "cache", unstable=mode == "unstable"))
    result = discovery.execute(plan, transport=inner)
    assert result["classification"] == outcome
    assert len(result["requests"]) == 7


@pytest.mark.parametrize("kind,name", [("header", "Host"), ("header", "Authorization"), ("header", "Transfer-Encoding"),
                                      ("header", "X-Researcher"), ("query", "session"), ("cookie", "auth"),
                                      ("query", "bad\r\nfield"), ("unknown", "hidden")])
def test_unsafe_candidates_reject_before_runs(policy, boundaries, kind, name):
    with pytest.raises(ValueError):
        discovery.prepare(source(), [(kind, name)])
    assert not ledger.runs_dir().exists()


def test_existing_and_duplicate_candidates_reject(policy, boundaries):
    for candidates in [[("query", "hidden"), ("query", "HIDDEN")], [("header", "X-Existing")]]:
        with pytest.raises(ValueError):
            discovery.prepare(source(headers=b"X-Existing: owned\r\n"), candidates)
    with pytest.raises(ValueError):
        discovery.prepare(source(url="https://allowed.example/app/item?hidden=existing"), [("query", "hidden")])


def test_mixed_case_candidate_is_probed_verbatim(policy, boundaries):
    plan = discovery.prepare(source(), [("query", "submissionCode")])
    seen = []
    def respond(request):
        seen.append(request)
        return owned_response(request)
    discovery.execute(plan, transport=httpx.MockTransport(respond))
    assert any("submissionCode=" in str(request.url) for request in seen)
    assert not any("submissioncode=" in str(request.url) for request in seen)


def test_named_actor_does_not_allow_cookie_override(policy, boundaries):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.use_profile("owner")
    with pytest.raises(ValueError):
        discovery.prepare(source(), [("cookie", "hidden")])


@pytest.mark.parametrize("state", ["missing", "stale", "excluded", "denied", "scope"])
def test_disallowed_discovery_has_zero_sends(policy, boundaries, state):
    document, path = policy
    if state == "missing":
        (path / "policy.json").unlink()
    elif state == "scope":
        (path / "scope.txt").write_text("outside.example\n")
    else:
        if state == "stale":
            document["state"] = "stale"
        elif state == "excluded":
            document["exclusions"] = [{"id": "blocked", "origin": "https://allowed.example", "paths": ["/"]}]
        else:
            document["permissions"]["fuzz"] = False
        (path / "policy.json").write_text(json.dumps(document))
    with pytest.raises(ValueError):
        discovery.prepare(source(), [("query", "hidden")])
    assert not ledger.runs_dir().exists()


def test_insufficient_budget_and_state_changing_source_block(policy, boundaries):
    with pytest.raises(ValueError):
        discovery.prepare(source(), [("query", "hidden")], maximum=6)
    with pytest.raises(ValueError):
        discovery.prepare(source(method="POST"), [("query", "hidden")])


def test_redirect_large_encoded_responses_inconclusive(policy, boundaries):
    for status, headers, body in [(302, {"Location": "https://outside.example/"}, b""),
                                  (200, {}, b"large"), (200, {"Content-Encoding": "gzip"}, b"x")]:
        plan = discovery.prepare(source(), [("query", "hidden")], max_bytes=1)
        seen = []
        def respond(request):
            seen.append(request)
            return httpx.Response(status, headers=headers, stream=httpx.ByteStream(body))
        result = discovery.execute(plan, transport=httpx.MockTransport(respond))
        assert result["classification"] == "inconclusive"
        assert len(seen) == 7 and all(request.url.host == "allowed.example" for request in seen)


def test_failed_attempt_is_linked_and_stops_followups(policy, boundaries):
    plan = discovery.prepare(source(), [("query", "hidden")])
    def fail(request):
        raise httpx.ReadError("owned failure", request=request)
    result = discovery.execute(plan, transport=httpx.MockTransport(fail))
    assert result["classification"] == "invalid" and len(result["requests"]) == 1
    assert ledger.manifest_for(result["requests"][0]["run_id"])["classification"] == "invalid"


def test_cli_dry_run_registered_secret_safe(policy, boundaries, capsys):
    value = source(headers=b"Authorization: Bearer captured-secret\r\n")
    exchange.save([value], source_id="owned-cli", source_bytes=b"owned", kind="raw")
    assert "discover" in MODULES
    assert discover.main([source(headers=b"Authorization: Bearer captured-secret\r\n")["exchange_id"],
                          "--query", "hidden", "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "captured-secret" not in output and '"planned_requests": 7' in output
    assert not ledger.runs_dir().exists()


def test_existing_cookie_and_invalid_redaction_block_before_traffic(policy, boundaries):
    with pytest.raises(ValueError):
        discovery.prepare(source(headers=b"Cookie: hidden=existing\r\n"), [("cookie", "hidden")])
    (policy[1] / "redaction.json").write_text('{"patterns": "invalid"}')
    with pytest.raises(ValueError):
        discovery.prepare(source(), [("query", "hidden")])
    assert not ledger.runs_dir().exists()


def test_named_identity_and_response_cookies_do_not_change_next_probes(policy, boundaries):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.set_credential("owner", "authorization", "Bearer owner-secret")
    identity.use_profile("owner")
    plan = discovery.prepare(source(), [("header", "X-Hidden")])
    def respond(request):
        assert request.headers["authorization"] == "Bearer owner-secret"
        assert "cookie" not in request.headers
        result = owned_response(request)
        result.headers["Set-Cookie"] = "changed=server"
        return result
    result = discovery.execute(plan, transport=httpx.MockTransport(respond))
    assert result["classification"] == "lead"
    assert "owner-secret" not in json.dumps(result)
