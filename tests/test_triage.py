"""Offline response grouping for explicitly selected owned exchanges."""

import json

import pytest

from bughunt.core import exchange, triage
from bughunt.modules import exchange as exchange_command
from test_gate import boundaries, policy


def _capture(path: str, body: bytes, *, status: int = 200, truncated: bool = False,
             captured_at: str | None = None, actor: str = "owner") -> str:
    url = f"https://allowed.example/{path}"
    request = f"GET {url} HTTP/1.1\r\nHost: allowed.example\r\n\r\n".encode()
    response = (f"HTTP/1.1 {status} Owned\r\nContent-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body) + (10 if truncated else 0)}\r\n\r\n").encode() + body
    value = exchange.raw_record(request, response, source_id=f"owned-{path}", actor=actor,
                                captured_at=captured_at, response_truncated=truncated)
    exchange.save([value], source_id=f"batch-{path}", source_bytes=request, kind="raw")
    return value["exchange_id"]


def test_selected_exact_groups_retain_every_original_and_separate_semantics(policy, boundaries):
    first = _capture("one", b"<p>Welcome</p>")
    second = _capture("two", b"<p>Welcome</p>")
    dynamic = _capture("three", b"<p>Welcome token=owned-dynamic-secret</p>")
    unauthorized = _capture("four", b"<p>Welcome</p>", status=401)
    originals = {item: exchange.read(item) for item in (first, second, dynamic, unauthorized)}

    report = triage.response_groups([dynamic, unauthorized, second, first])

    assert report["schema_version"] == 1
    assert report["settings"] == {"normalization": "exact", "similarity": "digest-equality"}
    assert report["selected_exchange_ids"] == sorted(originals)
    assert {frozenset(group["exchange_ids"]) for group in report["groups"]} == {
        frozenset({first, second}), frozenset({dynamic}), frozenset({unauthorized})}
    assert all(group["count"] == len(group["exchange_ids"]) for group in report["groups"])
    assert all(group["representative_exchange_id"] in group["exchange_ids"] for group in report["groups"])
    assert {entry["exchange_id"] for entry in report["inputs"]} == set(originals)
    assert all(entry["source_sha256"] for entry in report["inputs"])
    assert "owned-dynamic-secret" not in json.dumps(report)
    assert {item: exchange.read(item) for item in originals} == originals


def test_explicit_whitespace_normalization_and_incomplete_singletons(policy, boundaries):
    first = _capture("one", b"<p>one  two</p>")
    second = _capture("two", b"<p>one two</p>")
    partial = _capture("partial", b"<p>one two</p>", truncated=True)
    report = triage.response_groups([first, second], normalization="ascii-whitespace")
    assert {frozenset(group["exchange_ids"]) for group in report["groups"]} == {
        frozenset({first, second})}
    report = triage.response_groups([first, second, partial], normalization="ascii-whitespace")
    assert {frozenset(group["exchange_ids"]) for group in report["groups"]} == {
        frozenset({first, second}), frozenset({partial})}
    assert any("truncated" in warning for warning in report["warnings"])

    retained = exchange.read(partial)
    retained["response"]["truncated"] = False
    (exchange.directory() / f"{partial}.json").write_bytes(exchange.canonical(retained))
    with pytest.raises(exchange.ExchangeError):
        triage.response_groups([first, second, partial], normalization="ascii-whitespace")


def test_truncated_request_cannot_join_complete_response_group(policy, boundaries):
    complete = _capture("complete", b"same")
    url = "https://allowed.example/truncated"
    request = f"GET {url} HTTP/1.1\r\nHost: allowed.example\r\n\r\n".encode()
    response = b"HTTP/1.1 200 Owned\r\nContent-Type: text/html\r\nContent-Length: 4\r\n\r\nsame"
    value = exchange.raw_record(request, response, source_id="owned-truncated",
                                actor="owner", request_truncated=True)
    exchange.save([value], source_id="batch-truncated", source_bytes=request, kind="raw")
    report = triage.response_groups([complete, value["exchange_id"]])
    assert len(report["groups"]) == 2
    assert any(item["exchange_id"] == value["exchange_id"] and item["incomplete"]
               for item in report["inputs"])


def test_cli_group_is_offline_and_redacted(policy, boundaries, capsys):
    first = _capture("one", b"password=owned-private-secret")
    second = _capture("two", b"password=owned-private-secret")

    assert exchange_command.main(["group", first, second]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["selected_exchange_ids"] == sorted((first, second))
    assert "owned-private-secret" not in json.dumps(report)
    assert exchange_command.main(["group", first, first]) == 2
    assert "blocked" in capsys.readouterr().out.lower()


def test_html_candidates_keep_provenance_without_values_or_executable_links(policy, boundaries):
    body = (b'<form action="/submit?csrf=owned-query-secret" method="POST">\n'
            b'<input name="email" value="owner@example.test">\n'
            b'<input name="password" type="password" value="owned-password-secret">\n'
            b'</form><a href="javascript:alert(1)">bad</a>\n'
            b'<a href="/dashboard?session=owned-session-secret">good</a>'
            b'<script>fetch("/must-not-run")</script>')
    exchange_id = _capture("html", body)

    report = triage.html_candidates([exchange_id])

    assert report["schema_version"] == 1 and report["inert"] is True
    assert report["position_basis"] == "captured response text, line/column; output sanitized"
    assert any("original retained html" in warning.lower() for warning in report["warnings"])
    assert {item["tag"] for item in report["candidates"]} == {"form", "input", "a"}
    assert all(item["exchange_id"] == exchange_id and item["line"] >= 1 for item in report["candidates"])
    assert len(report["candidates"]) == 5
    assert any(item["tag"] == "input" and item["display_name"] == "email" for item in report["candidates"])
    assert any(item["reference_kind"] == "unsupported" for item in report["candidates"] if item["tag"] == "a")
    serialized = json.dumps(report)
    for private in ("owner@example.test", "owned-password-secret", "owned-query-secret",
                    "owned-session-secret", "javascript:alert"):
        assert private not in serialized
    assert "<script" not in serialized


def test_html_candidates_reject_ambiguous_attributes_and_bound_output(policy, boundaries):
    body = b'<input name="one" name="two"><a href="/ok">safe</a>'
    ambiguous = _capture("ambiguous", body)
    partial = _capture("partial", body, truncated=True)
    report = triage.html_candidates([ambiguous, partial])
    assert len(report["candidates"]) == 1
    assert report["candidates"][0]["tag"] == "a"
    assert any("duplicate" in warning for warning in report["warnings"])
    assert any("truncated" in warning for warning in report["warnings"])

    many = _capture("many", b'<input name="x">' * 300)
    limited = triage.html_candidates([many])
    assert len(limited["candidates"]) == triage.MAX_CANDIDATES
    assert any("limit" in warning for warning in limited["warnings"])


def test_html_candidates_bound_duplicate_warnings_from_retained_html(policy, boundaries):
    exchange_id = _capture("many-duplicates", b'<input name="one" name="two">' * 10000)
    report = triage.html_candidates([exchange_id])
    assert report["candidates"] == []
    assert len(report["warnings"]) == 2
    assert sum("duplicate" in warning for warning in report["warnings"]) == 1
    assert len(exchange.canonical(report)) < 2000


def test_cli_candidates_are_inert_and_hash_linked(policy, boundaries, capsys):
    exchange_id = _capture("html", b'<form><input name="search" value="owned-secret"></form>')
    assert exchange_command.main(["candidates", exchange_id]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["selected_exchange_ids"] == [exchange_id]
    assert report["candidates"][0]["exchange_id"] == exchange_id
    assert "owned-secret" not in json.dumps(report)


def test_malformed_reference_is_an_inert_candidate_not_a_report_failure(policy, boundaries):
    exchange_id = _capture("malformed", b'<a href="http://[bad">broken</a>')
    report = triage.html_candidates([exchange_id])
    assert len(report["candidates"]) == 1
    assert report["candidates"][0]["reference_kind"] == "unsupported"


def test_flow_orders_known_times_and_marks_unknown_without_inferred_auth_claims(policy, boundaries):
    later = _capture("later", b"ok", captured_at="2026-10-15T12:00:02+00:00",
                     actor="<script>hostile</script>")
    earlier = _capture("earlier", b"ok", captured_at="2026-10-15T12:00:01+00:00")
    unknown = _capture("unknown", b"ok")

    report = triage.flow_summary([later, unknown, earlier])

    assert [event["exchange_id"] for event in report["events"]] == [earlier, later, unknown]
    assert report["ordering"]["unknown_timestamp_count"] == 1
    assert report["ordering"]["partial"] is True
    assert report["events"][1]["actor"] == "&lt;script&gt;hostile&lt;/script&gt;"
    assert all(event["source_sha256"] and event["request_sha256"] for event in report["events"])
    assert all(event["request_truncated"] is False and event["response_truncated"] is False
               for event in report["events"])
    assert all(event["auth_flow_hint"] is None for event in report["events"])
    assert "<script>" not in json.dumps(report)


def test_cli_flow_remains_offline_and_does_not_print_query_values(policy, boundaries, capsys):
    exchange_id = _capture("flow?token=owned-secret", b"ok")
    assert exchange_command.main(["flow", exchange_id]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["events"][0]["exchange_id"] == exchange_id
    assert "owned-secret" not in json.dumps(report)


def test_flow_marks_equal_instants_with_different_offsets_as_tied(policy, boundaries):
    first = _capture("first", b"ok", captured_at="2026-10-15T12:00:00+00:00")
    second = _capture("second", b"ok", captured_at="2026-10-15T05:00:00-07:00")
    report = triage.flow_summary([first, second])
    assert report["ordering"]["tied_timestamp_count"] == 1
    assert report["ordering"]["partial"] is True


def test_auth_flow_hints_are_explicitly_inferred_not_verified(policy, boundaries):
    oauth = _capture("oauth/authorize", b"ok")
    saml = _capture("saml/consume", b"ok")
    report = triage.flow_summary([oauth, saml])
    hints = {event["exchange_id"]: event["auth_flow_hint"] for event in report["events"]}
    assert hints[oauth] == "possible-oauth; path-only inference"
    assert hints[saml] == "possible-saml; path-only inference"
    assert all(event["actor_claim"] == "source metadata; actor verification is not asserted"
               for event in report["events"])


def test_owned_fixture_measures_distinct_groups_and_output_size(policy, boundaries):
    same = [_capture(f"same-{index}", b"<p>Welcome</p>") for index in range(2)]
    dynamic = _capture("dynamic", b"<p>Welcome token=unique</p>")
    reflected = _capture("reflected", b"<p>Welcome query=reflection</p>")
    denied = _capture("denied", b"<p>Welcome</p>", status=403)
    selected = [*same, dynamic, reflected, denied]
    originals = {exchange_id: exchange.read(exchange_id) for exchange_id in selected}

    grouped = triage.response_groups(selected)
    counts = sorted(group["count"] for group in grouped["groups"])
    output_bytes = len(exchange.canonical(grouped))

    assert counts == [1, 1, 1, 2]
    assert all(group["status"] != 403 or group["count"] == 1 for group in grouped["groups"])
    assert {exchange_id: exchange.read(exchange_id) for exchange_id in selected} == originals
    assert 0 < output_bytes < 6000
    print(json.dumps({"selected": len(selected), "distinct_groups": len(counts),
                      "largest_group": max(counts), "known_false_groups": 0,
                      "group_report_bytes": output_bytes}, sort_keys=True))
