"""Characterization oracle for addons/urlscan, part 2: the eight subcommands, error mapping, --save.

PINNED-CURRENT tests (see test_urlscan_contract.py for the legend). Presentation is FREE per the spec,
so text-mode assertions check required CONTENT (data values, link shapes, ordering that the spec
fixes) and never layout, glyphs or label wording. `--json` stdout is a machine contract and is
asserted byte-exact where the spec fixes it (indent=2, ensure_ascii=False, trailing newline).

Defects whose CORRECT behavior differs (D4 JSON purity, D5 save, D9, D15, D16 ...) are asserted in
test_urlscan_defects.py. Where a pinned test touches such an area it is written flip-invariant
(e.g. it parses stdout with json.loads, which tolerates the D4 leading blank line, instead of
comparing bytes). Live urlscan.io payloads are UNVERIFIED: every body below is invented mock data.
"""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from urlscan_harness import (  # noqa: F401  (bench is a fixture)
    DOM_URL,
    QUOTAS_FALLBACK_URL,
    QUOTAS_URL,
    RESULT_URL,
    SCAN_URL,
    SCREENSHOT_URL,
    SEARCH_BASE,
    UUID,
    WHOAMI_URL,
    TtyText,
    bench,
    reply,
)

REPLACEMENT = chr(0xFFFD)
ESC = "\x1b["
ANYTHING = lambda request, n: reply(200, {"results": []})  # noqa: E731

HIT_ONE = {
    "_id": UUID,
    "page": {
        "url": "https://www.example.com/",
        "title": " Example Domain ",
        "ip": "1.2.3.4",
        "country": "US",
        "server": "nginx",
        "asn": "AS13335",
        "asnname": "CLOUDFLARENET",
    },
    "task": {
        "time": "2026-09-07T15:24:10Z",
        "visibility": "public",
        "url": "https://www.example.com/",
    },
    "stats": {"requests": 5, "uniqIPs": 2, "dataLength": 1234},
    "verdicts": {"malicious": True},
    "sort": [1788793609074, "01a07c68-2f36-774f-b9fd-61d733d49154"],
}
HIT_TWO = {
    "task": {"uuid": "u2", "url": "https://t.example/", "visibility": "private"},
    "page": {},
    "sort": [1, "b"],
}
SEARCH_BODY = {
    "results": [HIT_ONE, HIT_TWO],
    "total": 3286,
    "took": 12,
    "has_more": True,
}

SUBMISSION = {
    "uuid": UUID,
    "url": "https://allowed.example/",
    "visibility": "private",
    "country": "us",
    "message": "Submission successful",
    "result": f"https://urlscan.io/result/{UUID}/",
    "api": f"https://urlscan.io/api/v1/result/{UUID}/",
}
RESULT = {
    "task": {
        "uuid": UUID,
        "url": "https://allowed.example/",
        "time": "2026-10-01T00:00:00Z",
        "visibility": "private",
        "method": "api",
    },
    "page": {
        "url": "https://allowed.example/home",
        "title": "Home",
        "country": "US",
        "city": "SF",
        "ip": "9.9.9.9",
        "asn": "AS1",
        "asnname": "ORG",
        "server": "nginx",
        "tlsIssuer": "LE",
        "status": 200,
    },
    "stats": {
        "requests": 11,
        "uniqIPs": 3,
        "uniqCountries": 2,
        "dataLength": 1000,
        "encodedDataLength": 800,
    },
    "lists": {
        "domains": [f"d{i}.example" for i in range(10)],
        "ips": ["1.1.1.1"],
        "asns": ["AS1"],
        "hashes": [f"h{i}" for i in range(10)],
        "urls": [f"https://u{i}.example/" for i in range(7)],
        "certificates": [f"c{i}" for i in range(6)],
    },
    "verdicts": {
        "overall": {
            "malicious": True,
            "score": 100,
            "categories": ["phishing"],
            "brands": ["paypal"],
        }
    },
}
FAST_WAIT = ["--initial-delay", "0", "--interval", "0"]


def _scan_argv(*extra, key="k", json_mode=True):
    head = ["--api-key", key] + (["--json"] if json_mode else [])
    return head + ["scan", "https://allowed.example/", "--yes", *extra]


def _query(outcome):
    return parse_qs(urlsplit(outcome.seen[0].url).query)["q"][0]


# ---------------------------------------------------------------------------------------------
# search
# ---------------------------------------------------------------------------------------------


def test_search_text_request_shape_content_and_quota_line(bench):
    url = SEARCH_BASE + "?q=page.domain%3Aexample.com+AND+date%3A%3Enow-7d&size=20"
    outcome = bench.run(
        [
            "--api-key",
            "KEY123",
            "search",
            "page.domain:example.com",
            "AND",
            "date:>now-7d",
        ],
        {
            ("GET", url): reply(
                200,
                SEARCH_BODY,
                action="search",
                window="minute",
                remaining=59,
                limit=60,
                reset_after=30,
            )
        },
    )
    assert outcome.code == 0 and not outcome.exited
    assert outcome.urls == [url]
    headers = outcome.seen[0].headers
    assert (
        headers["api-key"] == "KEY123" and headers["accept"] == "application/json, */*"
    )
    out = outcome.out
    for token in (
        "page.domain:example.com AND date:>now-7d",
        "3286",
        "has_more",
        "https://www.example.com/",
        "Example Domain",
        UUID,
        f"https://urlscan.io/result/{UUID}/",
        "2026-09-07T15:24:10Z",
        "public",
        "1.2.3.4",
        "US",
        "AS13335",
        "CLOUDFLARENET",
        "nginx",
        "https://t.example/",
        "https://urlscan.io/result/u2/",
    ):
        assert token in out, token
    assert out.index("https://www.example.com/") < out.index("https://t.example/")
    assert "--after '1,b'" in out
    assert re.search(r"quota\s+search minute 59/60 left · resets in 30s", out)


def test_search_json_is_the_body_unchanged_and_hides_notes_and_quota(bench):
    outcome = bench.run(
        ["--json", "search", "domain:x.com"],
        responder=lambda request, n: reply(
            200, SEARCH_BODY, action="search", remaining=1
        ),
    )
    assert outcome.out == json.dumps(SEARCH_BODY, indent=2, ensure_ascii=False) + "\n"
    assert outcome.err == ""


def test_search_json_keeps_non_ascii_unescaped(bench):
    body = {"results": [], "note": "café 中"}
    outcome = bench.run(
        ["--json", "search", "q"], responder=lambda request, n: reply(200, body)
    )
    assert outcome.out == json.dumps(body, indent=2, ensure_ascii=False) + "\n"
    assert "café 中" in outcome.out


def test_search_param_order_is_q_size_search_after_datasource(bench):
    url = (
        SEARCH_BASE
        + "?q=domain%3Ax.com&size=5&search_after=1%2Cabc&datasource=hostnames"
    )
    outcome = bench.run(
        [
            "search",
            "domain:x.com",
            "--size",
            "5",
            "--after",
            "1,abc",
            "--datasource",
            "hostnames",
        ],
        {("GET", url): reply(200, {"results": []})},
    )
    assert outcome.code == 0 and outcome.urls == [url]


def test_search_size_is_not_validated_client_side(bench):
    outcome = bench.run(["search", "q", "--size", "-3"], responder=ANYTHING)
    assert outcome.urls == [SEARCH_BASE + "?q=q&size=-3"]


@pytest.mark.parametrize(
    "pasted, expected",
    [
        (
            "https://evil.tld/a?b=1#frag",
            'page.domain:evil.tld OR task.domain:evil.tld OR page.url:"https://evil.tld/a?b=1" OR task.url:"https://evil.tld/a?b=1"',
        ),
        (
            "example.com/login",
            'page.domain:example.com OR task.domain:example.com OR page.url:"https://example.com/login" '
            'OR task.url:"https://example.com/login"',
        ),
        (
            "http://Sub.Example.COM./",
            'page.domain:sub.example.com OR task.domain:sub.example.com OR page.url:"http://sub.example.com" '
            'OR task.url:"http://sub.example.com"',
        ),
        (
            "HTTPS://Evil.TLD/p",
            'page.domain:evil.tld OR task.domain:evil.tld OR page.url:"https://evil.tld/p" OR task.url:"https://evil.tld/p"',
        ),
    ],
)
def test_search_rewrites_a_pasted_url_into_a_field_query(bench, pasted, expected):
    outcome = bench.run(["search", pasted], responder=ANYTHING)
    assert _query(outcome) == expected
    assert f"treated URL as search: {expected}" in outcome.out


@pytest.mark.parametrize(
    "raw",
    [
        "evil.tld",
        "domain:paypal.com",
        "page.domain:example.com AND date:>now-7d",
        "foo/bar",
        ".example.com/x",
        "example.com/login extra words",
    ],
)
def test_search_leaves_non_url_queries_alone(bench, raw):
    outcome = bench.run(["search", *raw.split(" ")], responder=ANYTHING)
    assert _query(outcome) == raw
    assert "treated URL as search" not in outcome.out


def test_search_rewrite_note_is_hidden_in_json_mode_and_header_shows_the_rewritten_query(
    bench,
):
    hidden = bench.run(["--json", "search", "https://evil.tld/"], responder=ANYTHING)
    assert "treated URL as search" not in hidden.out
    shown = bench.run(["search", "https://evil.tld/"], responder=ANYTHING)
    assert shown.out.count("page.domain:evil.tld") >= 2


def test_search_empty_query_dies_before_any_request(bench):
    outcome = bench.run(["search", "  "])
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert "empty" in outcome.err


def test_search_no_hits_says_so(bench):
    outcome = bench.run(
        ["search", "q"],
        responder=lambda request, n: reply(200, {"results": [], "total": 0}),
    )
    assert "no results" in outcome.out and "--after" not in outcome.out


def test_search_has_more_marker_only_when_the_server_says_so(bench):
    body = {"results": [HIT_TWO], "total": 9, "has_more": False}
    outcome = bench.run(["search", "q"], responder=lambda request, n: reply(200, body))
    assert "has_more" not in outcome.out


def test_search_malicious_hit_is_flagged_differently_from_a_clean_one(bench):
    clean_hit = {**HIT_ONE, "verdicts": {"malicious": False}}
    flagged = bench.run(
        ["search", "q"],
        responder=lambda request, n: reply(200, {"results": [HIT_ONE], "total": 1}),
    )
    plain = bench.run(
        ["search", "q"],
        responder=lambda request, n: reply(200, {"results": [clean_hit], "total": 1}),
    )
    assert flagged.out != plain.out


def test_search_tolerates_null_sections_and_a_non_list_sort_token(bench):
    body = {
        "results": [{"page": None, "task": None, "stats": None, "sort": "abc"}],
        "total": 1,
    }
    outcome = bench.run(["search", "q"], responder=lambda request, n: reply(200, body))
    assert outcome.code == 0 and "--after 'abc'" in outcome.out


def test_search_non_dict_and_non_json_bodies_are_wrapped_as_raw(bench):
    listing = bench.run(
        ["--json", "search", "q"], responder=lambda request, n: reply(200, b"[1,2]")
    )
    assert json.loads(listing.out) == {"raw": [1, 2]}
    text = bench.run(
        ["--json", "search", "q"], responder=lambda request, n: reply(200, b"plain")
    )
    assert json.loads(text.out) == {"raw": "plain"}
    empty = bench.run(
        ["--json", "search", "q"], responder=lambda request, n: reply(200, b"")
    )
    assert json.loads(empty.out) == {"raw": None}
    broken = bench.run(
        ["--json", "search", "q"], responder=lambda request, n: reply(200, b"\xff")
    )
    assert json.loads(broken.out) == {"raw": REPLACEMENT}


# ---------------------------------------------------------------------------------------------
# scan: gates [T]
# ---------------------------------------------------------------------------------------------


def test_scan_without_a_key_dies_before_the_scope_check(bench):
    outcome = bench.run(["scan", "https://outside.example/", "--yes"])
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert "API key" in outcome.err and "outside.example" not in outcome.err


def test_scan_out_of_scope_url_is_refused_with_the_workspace_explanation(bench):
    from bughunt.core.workspace import explain_block

    outcome = bench.run(
        ["--api-key", "k", "--json", "scan", "https://outside.example/", "--yes"]
    )
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert explain_block("outside.example") in outcome.err


def test_scan_with_no_scope_file_is_refused_with_the_no_scope_explanation(bench):
    from bughunt.core.workspace import explain_block

    (bench.workspace / "scope.txt").unlink()
    outcome = bench.run(_scan_argv())
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert explain_block("allowed.example") in outcome.err


@pytest.mark.parametrize(
    "url, reason",
    [
        ("ftp://allowed.example/", "invalid-target"),
        (" https://allowed.example/ ", "invalid-target"),
        ("https://sub.allowed.example/", "asset-unknown"),
        ("https://allowed.example:8443/", "asset-unknown"),
        ("http://localhost/", "asset-unknown"),
    ],
)
def test_scan_policy_refusals_never_reach_the_transport(bench, url, reason):
    outcome = bench.run(["--api-key", "k", "--json", "scan", url, "--yes"])
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert reason in outcome.err


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "https://allowed.example@evil.example/",
        "https://evil.example/?u=allowed.example",
    ],
)
def test_scan_scope_confusables_are_out_of_scope(bench, url):
    outcome = bench.run(["--api-key", "k", "--json", "scan", url, "--yes"])
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert "outside this engagement's scope" in outcome.err


def test_scan_schemeless_in_scope_url_is_refused_before_transport(bench):
    outcome = bench.run(
        ["--api-key", "k", "--json", "scan", "allowed.example/x", "--yes"]
    )
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert outcome.err == "error: invalid-target; no outbound action ran\n"


def test_scan_active_scan_denied_by_policy_even_though_urlscan_is_granted(bench):
    bench.edit_policy(lambda d: d["permissions"].update(active_scan=False))
    outcome = bench.run(_scan_argv())
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert "operation-disallowed" in outcome.err


def test_scan_missing_policy_fails_closed_at_the_gate(bench):
    (bench.workspace / "policy.json").unlink()
    outcome = bench.run(_scan_argv())
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert "policy-missing-or-invalid" in outcome.err


def test_scan_case_insensitive_host_and_http_origin_follow_scope_and_policy(bench):
    for url in ("https://ALLOWED.example/", "http://allowed.example/"):
        outcome = bench.run(
            ["--api-key", "k", "--json", "scan", url, "--yes"],
            {("POST", SCAN_URL): reply(200, {"uuid": "x"})},
        )
        assert outcome.code == 0, url
        assert outcome.seen[0].json()["url"] == url


# ---------------------------------------------------------------------------------------------
# scan: confirmation [T]
# ---------------------------------------------------------------------------------------------


def test_scan_without_yes_and_not_a_tty_is_not_submitted(bench):
    outcome = bench.run(["--api-key", "k", "scan", "https://allowed.example/"])
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert "not submitted" in outcome.err.lower()


@pytest.mark.parametrize("answer", ["n\n", "\n", "maybe\n", ""])
def test_scan_interactive_decline_or_eof_is_not_submitted(bench, answer):
    outcome = bench.run(
        ["--api-key", "k", "scan", "https://allowed.example/"],
        stdin_tty=True,
        stdin_text=answer,
    )
    assert outcome.exited and outcome.code == 1 and outcome.seen == []


@pytest.mark.parametrize("answer", ["y\n", "Y\n", "yes\n", "YES\n"])
def test_scan_interactive_yes_submits_and_the_prompt_names_url_and_visibility(
    bench, answer
):
    outcome = bench.run(
        [
            "--api-key",
            "k",
            "--json",
            "scan",
            "https://allowed.example/",
            "--visibility",
            "unlisted",
        ],
        {("POST", SCAN_URL): reply(200, {"uuid": "x"})},
        stdin_tty=True,
        stdin_text=answer,
    )
    assert outcome.code == 0 and len(outcome.seen) == 1
    assert (
        "urlscan.io scanners will visit https://allowed.example/ (unlisted result). Continue?"
        in outcome.err
    )
    assert json.loads(outcome.out) == {"uuid": "x"}


def test_scan_yes_flag_skips_the_prompt_but_not_the_scope_check(bench):
    ok = bench.run(_scan_argv(), {("POST", SCAN_URL): reply(200, {"uuid": "x"})})
    assert ok.code == 0 and "Continue?" not in ok.out
    refused = bench.run(["--api-key", "k", "scan", "https://outside.example/", "--yes"])
    assert refused.exited and refused.seen == []


# ---------------------------------------------------------------------------------------------
# scan: payload and output [T]/[K]
# ---------------------------------------------------------------------------------------------


def test_scan_defaults_to_private_with_exact_default_separator_bytes(bench):
    outcome = bench.run(_scan_argv(), {("POST", SCAN_URL): reply(200, {"uuid": "x"})})
    request = outcome.seen[0]
    assert request.method == "POST" and request.url == SCAN_URL
    assert (
        request.body == b'{"url": "https://allowed.example/", "visibility": "private"}'
    )
    assert request.headers["content-type"] == "application/json"
    assert request.headers["api-key"] == "k"


def test_scan_payload_with_every_flag_has_the_exact_keys_and_order(bench):
    outcome = bench.run(
        [
            "--api-key",
            "KEY",
            "--json",
            "scan",
            "https://allowed.example/p?q=1",
            "--yes",
            "--visibility",
            "public",
            "--country",
            "de",
            "--tag",
            "a",
            "--tag",
            "b",
            "--user-agent",
            "UA/1",
            "--referer",
            "https://r.example/",
            "--override-safety",
        ],
        {("POST", SCAN_URL): reply(200, {"uuid": UUID})},
    )
    assert outcome.seen[0].body == (
        b'{"url": "https://allowed.example/p?q=1", "visibility": "public", "country": "de", "tags": ["a", "b"], '
        b'"customagent": "UA/1", "referer": "https://r.example/", "overrideSafety": "true"}'
    )


@pytest.mark.parametrize(
    "flags, extra",
    [
        (["--country", "us"], b', "country": "us"'),
        (["--tag", "t1"], b', "tags": ["t1"]'),
        (["--user-agent", "UA"], b', "customagent": "UA"'),
        (["--referer", "R"], b', "referer": "R"'),
        (["--override-safety"], b', "overrideSafety": "true"'),
        (["--visibility", "unlisted"], b""),
    ],
)
def test_scan_each_optional_flag_adds_only_its_own_key(bench, flags, extra):
    outcome = bench.run(
        _scan_argv(*flags), {("POST", SCAN_URL): reply(200, {"uuid": "x"})}
    )
    visibility = b"unlisted" if flags == ["--visibility", "unlisted"] else b"private"
    expected = (
        b'{"url": "https://allowed.example/", "visibility": "'
        + visibility
        + b'"'
        + extra
        + b"}"
    )
    assert outcome.seen[0].body == expected


def test_scan_tag_count_is_not_validated_client_side(bench):
    tags = [item for n in range(12) for item in ("--tag", f"t{n}")]
    outcome = bench.run(
        _scan_argv(*tags), {("POST", SCAN_URL): reply(200, {"uuid": "x"})}
    )
    assert outcome.seen[0].json()["tags"] == [f"t{n}" for n in range(12)]


def test_scan_json_without_wait_prints_the_submission_body_only(bench):
    outcome = bench.run(
        _scan_argv(),
        {("POST", SCAN_URL): reply(200, SUBMISSION, action="private", remaining=9)},
    )
    assert outcome.out == json.dumps(SUBMISSION, indent=2, ensure_ascii=False) + "\n"
    assert len(outcome.seen) == 1


def test_scan_text_prints_the_submission_view_and_quota_line(bench):
    outcome = bench.run(
        _scan_argv(json_mode=False),
        {
            ("POST", SCAN_URL): reply(
                200, SUBMISSION, action="private", remaining=9, limit=10
            )
        },
    )
    assert outcome.code == 0
    for value in (
        UUID,
        "https://allowed.example/",
        "private",
        "us",
        "Submission successful",
        f"https://urlscan.io/result/{UUID}/",
        f"https://urlscan.io/api/v1/result/{UUID}/",
    ):
        assert value in outcome.out, value
    assert re.search(r"quota\s+private 9/10 left", outcome.out)


def test_scan_submission_error_maps_message_and_description(bench):
    outcome = bench.run(
        _scan_argv(json_mode=False),
        {
            ("POST", SCAN_URL): reply(
                400, {"message": "DNS Error", "description": "could not resolve"}
            )
        },
    )
    assert outcome.exited and outcome.code == 1
    assert outcome.err == "error: HTTP 400: DNS Error — could not resolve\n"


# ---------------------------------------------------------------------------------------------
# scan --wait / result --wait: polling [K]
# ---------------------------------------------------------------------------------------------


def test_scan_wait_polls_404s_until_the_result_arrives_json_mode(bench):
    outcome = bench.run(
        _scan_argv("--wait", *FAST_WAIT, "--wait-timeout", "50"),
        {
            ("POST", SCAN_URL): reply(200, {"uuid": UUID}),
            ("GET", RESULT_URL): [
                reply(404, {"message": "not found"}),
                reply(404, {"message": "not found"}),
                reply(200, RESULT),
            ],
        },
    )
    assert outcome.code == 0
    assert [item.method for item in outcome.seen] == ["POST", "GET", "GET", "GET"]
    assert json.loads(outcome.out) == RESULT


def test_scan_wait_text_prints_submission_then_the_result_summary_and_quota(bench):
    outcome = bench.run(
        _scan_argv("--wait", *FAST_WAIT, json_mode=False),
        {
            ("POST", SCAN_URL): reply(200, {"uuid": UUID, "message": "ok"}),
            ("GET", RESULT_URL): reply(
                200, RESULT, action="retrieve", remaining=5, limit=9
            ),
        },
    )
    assert outcome.code == 0
    assert (
        "ok" in outcome.out and "phishing" in outcome.out and "9.9.9.9" in outcome.out
    )
    assert re.search(r"quota\s+retrieve 5/9 left", outcome.out)
    assert outcome.err == ""


def test_scan_wait_without_a_uuid_dies_after_the_submission_view_and_never_polls(bench):
    outcome = bench.run(
        _scan_argv("--wait", *FAST_WAIT, json_mode=False),
        {("POST", SCAN_URL): reply(200, {"message": "hm"})},
    )
    assert outcome.exited and outcome.code == 1
    assert "hm" in outcome.out
    assert "uuid" in outcome.err
    assert [item.method for item in outcome.seen] == ["POST"]


def test_scan_wait_non_404_error_during_polling_propagates_immediately(bench):
    outcome = bench.run(
        _scan_argv("--wait", *FAST_WAIT),
        {
            ("POST", SCAN_URL): reply(200, {"uuid": UUID}),
            ("GET", RESULT_URL): reply(500, {"message": "boom"}),
        },
    )
    assert outcome.exited and outcome.code == 1
    assert outcome.err == "error: HTTP 500: boom\n"
    assert len(outcome.gets) == 1


def test_scan_wait_timeout_reports_the_specific_timeout_with_http_404(bench):
    # Fake clock + a non-zero interval makes the poll count exact and wall-clock-independent: the
    # 0.03s deadline lands on the third poll (fake ticks 0, 0.02, 0.03), so the coarse-monotonic
    # clock can neither add nor drop a poll. (interval 0 under the fake clock never advances it ->
    # infinite loop, hence 0.02.)
    bench.fake_clock()
    outcome = bench.run(
        _scan_argv(
            "--wait",
            "--initial-delay",
            "0",
            "--interval",
            "0.02",
            "--wait-timeout",
            "0.03",
        ),
        {
            ("POST", SCAN_URL): reply(200, {"uuid": UUID}),
            ("GET", RESULT_URL): reply(404, {}),
        },
    )
    assert outcome.exited and outcome.code == 1
    assert outcome.err == f"error: HTTP 404: scan {UUID} did not finish within 0s\n"
    assert len(outcome.gets) == 3


def test_scan_wait_default_timeline_is_10s_then_every_3s(bench):
    bench.fake_clock()
    outcome = bench.run(
        _scan_argv("--wait"),
        {
            ("POST", SCAN_URL): reply(200, {"uuid": UUID}),
            ("GET", RESULT_URL): [reply(404, {}), reply(404, {}), reply(200, RESULT)],
        },
    )
    assert outcome.code == 0
    post, first, second, third = (item.tick for item in outcome.seen)
    assert first - post == pytest.approx(10.0, abs=0.5)
    assert second - first == pytest.approx(3.0, abs=0.5)
    assert third - second == pytest.approx(3.0, abs=0.5)


def test_scan_wait_deadline_is_fixed_at_entry_and_sleeps_are_clamped_to_the_time_left(
    bench,
):
    bench.fake_clock()
    outcome = bench.run(
        _scan_argv(
            "--wait", "--initial-delay", "0", "--interval", "2", "--wait-timeout", "5"
        ),
        {
            ("POST", SCAN_URL): reply(200, {"uuid": UUID}),
            ("GET", RESULT_URL): reply(404, {}),
        },
    )
    assert (
        outcome.exited
        and outcome.err == f"error: HTTP 404: scan {UUID} did not finish within 5s\n"
    )
    ticks = [item.tick for item in outcome.seen if item.method == "GET"]
    gaps = [later - earlier for earlier, later in zip(ticks, ticks[1:])]
    assert max(gaps) <= 2.2
    assert ticks[-1] - outcome.seen[0].tick == pytest.approx(5.0, abs=0.5)
    assert ticks[-2] - outcome.seen[0].tick < 5.0


def test_result_wait_default_initial_delay_is_2s_and_interval_3s(bench):
    clock = bench.fake_clock()
    start = clock["now"]
    outcome = bench.run(
        ["--api-key", "k", "--json", "result", UUID, "--wait"],
        {("GET", RESULT_URL): [reply(404, {}), reply(200, RESULT)]},
    )
    assert outcome.code == 0
    first, second = (item.tick for item in outcome.seen)
    assert first - start == pytest.approx(2.0, abs=0.5)
    assert second - first == pytest.approx(3.0, abs=0.5)


def test_spinner_is_silent_unless_stderr_is_a_terminal(bench):
    bench.fake_clock()
    routes = {
        ("POST", SCAN_URL): reply(200, {"uuid": UUID}),
        ("GET", RESULT_URL): reply(200, RESULT),
    }
    quiet = bench.run(
        _scan_argv("--wait", "--initial-delay", "2", "--interval", "1"), routes
    )
    assert quiet.err == ""
    noisy = bench.run(
        _scan_argv("--wait", "--initial-delay", "2", "--interval", "1"),
        routes,
        stderr_tty=True,
    )
    assert noisy.err != ""


# ---------------------------------------------------------------------------------------------
# result [T]/[K]
# ---------------------------------------------------------------------------------------------


def test_result_text_summary_content(bench):
    outcome = bench.run(
        ["--api-key", "k", "result", UUID],
        {
            ("GET", RESULT_URL): reply(
                200, RESULT, action="retrieve", remaining=5, limit=9
            )
        },
    )
    out = outcome.out
    assert outcome.code == 0
    for token in (
        UUID,
        "https://allowed.example/",
        "https://allowed.example/home",
        "Home",
        "2026-10-01T00:00:00Z",
        "private",
        "api",
        "US",
        "SF",
        "9.9.9.9",
        "AS1",
        "ORG",
        "nginx",
        "LE",
        "200",
        "MALICIOUS",
        "score=100",
        "phishing",
        "paypal",
        "1000",
        "800",
        "1.1.1.1",
        f"https://urlscan.io/result/{UUID}/",
        f"https://urlscan.io/screenshots/{UUID}.png",
        f"https://urlscan.io/dom/{UUID}/",
    ):
        assert token in out, token
    assert re.search(r"quota\s+retrieve 5/9 left", out)


def test_result_indicator_lists_are_truncated_with_a_more_count(bench):
    out = bench.run(
        ["--api-key", "k", "result", UUID], {("GET", RESULT_URL): reply(200, RESULT)}
    ).out
    assert "d7.example" in out and "d8.example" not in out
    assert "h7" in out and "h8" not in out
    assert "https://u4.example/" in out and "https://u5.example/" not in out
    assert "c3" in out and "c4" not in out
    assert out.count("(+2 more)") == 4


def test_result_domains_fall_back_to_link_domains(bench):
    body = {"task": {"uuid": UUID}, "lists": {"linkDomains": ["link.example"]}}
    out = bench.run(
        ["--api-key", "k", "result", UUID], {("GET", RESULT_URL): reply(200, body)}
    ).out
    assert "link.example" in out


@pytest.mark.parametrize(
    "verdicts, present, absent",
    [
        (None, ["unknown"], ["MALICIOUS", "clean"]),
        ({}, ["unknown"], ["MALICIOUS", "clean"]),
        (
            {"overall": {"malicious": True, "score": 100}},
            ["MALICIOUS", "score=100"],
            ["unknown", "clean"],
        ),
        ({"overall": {"malicious": True}}, ["MALICIOUS"], ["score=", "clean"]),
        ({"engines": {"malicious": True}}, ["MALICIOUS"], ["unknown", "clean"]),
        (
            {"community": {"malicious": True}, "overall": {"score": 9}},
            ["MALICIOUS", "score=9"],
            ["clean"],
        ),
        ({"overall": {"score": 5}}, ["score=5"], ["MALICIOUS", "clean", "unknown"]),
        ({"overall": {"score": 0}}, ["clean"], ["MALICIOUS", "score=", "unknown"]),
        ({"overall": {"malicious": False}}, ["clean"], ["MALICIOUS", "unknown"]),
    ],
)
def test_result_verdict_badge_words(bench, verdicts, present, absent):
    body = {"task": {"uuid": UUID}}
    if verdicts is not None:
        body["verdicts"] = verdicts
    out = bench.run(
        ["--api-key", "k", "result", UUID], {("GET", RESULT_URL): reply(200, body)}
    ).out
    for word in present:
        assert word in out, word
    for word in absent:
        assert word not in out, word


def test_result_categories_and_brands_fall_back_to_the_urlscan_verdict(bench):
    body = {
        "task": {"uuid": UUID},
        "verdicts": {"urlscan": {"categories": ["scam"], "brands": ["acme"]}},
    }
    out = bench.run(
        ["--api-key", "k", "result", UUID], {("GET", RESULT_URL): reply(200, body)}
    ).out
    assert "scam" in out and "acme" in out


def test_result_json_is_the_body_unchanged(bench):
    outcome = bench.run(
        ["--api-key", "k", "--json", "result", UUID],
        {("GET", RESULT_URL): reply(200, RESULT)},
    )
    assert outcome.out == json.dumps(RESULT, indent=2, ensure_ascii=False) + "\n"


def test_result_uuid_is_stripped_and_case_is_preserved_in_the_url(bench):
    outcome = bench.run(
        ["--api-key", "k", "--json", "result", "  " + UUID.upper() + " "],
        responder=ANYTHING,
    )
    assert outcome.code == 0
    assert outcome.urls == [f"https://urlscan.io/api/v1/result/{UUID.upper()}/"]


@pytest.mark.parametrize("command", ["screenshot", "dom", "result"])
@pytest.mark.parametrize(
    "bad",
    [
        "../../user/username",
        "not-a-uuid",
        UUID.replace("-", ""),
        UUID + "x",
        "x" + UUID,
        UUID[:-1],
        "",
    ],
)
def test_commands_reject_a_malformed_uuid_with_no_request(bench, command, bad):
    outcome = bench.run(["--api-key", "k", command, bad])
    assert outcome.exited and outcome.code == 1 and outcome.seen == []
    assert "not a scan uuid" in outcome.err


def test_result_404_without_wait_says_not_ready_and_points_at_wait(bench):
    outcome = bench.run(
        ["--api-key", "k", "result", UUID], {("GET", RESULT_URL): reply(404, {})}
    )
    assert outcome.exited and outcome.code == 1
    assert "not ready yet (HTTP 404)" in outcome.err and "--wait" in outcome.err


def test_result_410_says_deleted(bench):
    outcome = bench.run(
        ["--api-key", "k", "result", UUID], {("GET", RESULT_URL): reply(410, {})}
    )
    assert outcome.exited and outcome.code == 1
    assert "deleted (HTTP 410)" in outcome.err


def test_result_other_errors_use_the_common_handler(bench):
    outcome = bench.run(
        ["result", UUID], {("GET", RESULT_URL): reply(403, {"message": "nope"})}
    )
    assert outcome.exited and outcome.code == 1
    assert outcome.err.startswith("error: HTTP 403: nope ")
    assert "key" in outcome.err.lower()


# ---------------------------------------------------------------------------------------------
# screenshot / dom [T]/[K]
# ---------------------------------------------------------------------------------------------

PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 20
DOM_TEXT = "<p>café 中</p>"
DOM = (
    DOM_TEXT.encode("utf-8") + b"\xff"
)  # multi-byte UTF-8 plus one invalid byte: byte count != char count
DECODED_DOM = DOM_TEXT + REPLACEMENT


def test_screenshot_defaults_to_uuid_png_in_the_cwd(bench):
    outcome = bench.run(
        ["--api-key", "k", "screenshot", UUID],
        {
            ("GET", SCREENSHOT_URL): reply(
                200, PNG, headers={"content-type": "image/png"}
            )
        },
    )
    assert outcome.code == 0 and outcome.urls == [SCREENSHOT_URL]
    assert (bench.cwd / f"{UUID}.png").read_bytes() == PNG
    assert f"{UUID}.png" in outcome.out and f"({len(PNG)} bytes)" in outcome.out


def test_screenshot_output_flag_writes_the_exact_bytes(bench):
    target = bench.cwd / "shot.png"
    outcome = bench.run(
        ["--api-key", "k", "screenshot", UUID, "-o", str(target)],
        {("GET", SCREENSHOT_URL): reply(200, PNG)},
    )
    assert target.read_bytes() == PNG
    assert str(target) in outcome.out and f"({len(PNG)} bytes)" in outcome.out
    assert not (bench.cwd / f"{UUID}.png").exists()


def test_screenshot_has_no_quota_line_and_ignores_json_and_save(bench):
    save = bench.cwd / "ignored.json"
    outcome = bench.run(
        ["--api-key", "k", "--json", "--save", str(save), "screenshot", UUID],
        {("GET", SCREENSHOT_URL): reply(200, PNG, action="x", remaining=1)},
    )
    assert outcome.code == 0 and "quota" not in outcome.out
    assert not save.exists()


def test_screenshot_missing_scan_is_an_http_error(bench):
    outcome = bench.run(
        ["--api-key", "k", "screenshot", UUID],
        {("GET", SCREENSHOT_URL): reply(404, b"")},
    )
    assert outcome.exited and outcome.code == 1 and "HTTP 404" in outcome.err
    assert not (bench.cwd / f"{UUID}.png").exists()


def test_dom_prints_decoded_text_with_a_trailing_newline(bench):
    outcome = bench.run(
        ["--api-key", "k", "dom", UUID], {("GET", DOM_URL): reply(200, DOM)}
    )
    assert outcome.code == 0 and outcome.urls == [DOM_URL]
    assert outcome.out == DECODED_DOM + "\n"


def test_dom_does_not_double_a_trailing_newline(bench):
    outcome = bench.run(
        ["--api-key", "k", "dom", UUID], {("GET", DOM_URL): reply(200, b"<p>x</p>\n")}
    )
    assert outcome.out == "<p>x</p>\n"


def test_dom_output_flag_writes_utf8_text_and_reports_the_original_byte_count(bench):
    target = bench.cwd / "d.html"
    outcome = bench.run(
        ["--api-key", "k", "dom", UUID, "-o", str(target)],
        {("GET", DOM_URL): reply(200, DOM)},
    )
    assert target.read_text(encoding="utf-8") == DECODED_DOM
    assert str(target) in outcome.out and f"({len(DOM)} bytes)" in outcome.out
    assert DOM_TEXT not in outcome.out


def test_dom_json_wraps_uuid_and_text(bench):
    outcome = bench.run(
        ["--api-key", "k", "--json", "dom", UUID], {("GET", DOM_URL): reply(200, DOM)}
    )
    assert json.loads(outcome.out) == {"uuid": UUID, "dom": DECODED_DOM}


def test_dom_output_flag_wins_over_json(bench):
    target = bench.cwd / "d.html"
    outcome = bench.run(
        ["--api-key", "k", "--json", "dom", UUID, "-o", str(target)],
        {("GET", DOM_URL): reply(200, DOM)},
    )
    assert target.exists() and "wrote" in outcome.out
    assert DOM_TEXT not in outcome.out
    with pytest.raises(json.JSONDecodeError):
        json.loads(outcome.out)


def test_dom_ignores_save(bench):
    save = bench.cwd / "ignored.json"
    bench.run(
        ["--api-key", "k", "--save", str(save), "dom", UUID],
        {("GET", DOM_URL): reply(200, DOM)},
    )
    assert not save.exists()


def test_download_destinations_are_not_confined_to_the_cwd(bench):
    outside = bench.home / "elsewhere" / "shot.png"
    outside.parent.mkdir()
    bench.run(
        ["--api-key", "k", "screenshot", UUID, "-o", str(outside)],
        {("GET", SCREENSHOT_URL): reply(200, PNG)},
    )
    assert outside.read_bytes() == PNG


# ---------------------------------------------------------------------------------------------
# quotas / whoami / fields [K]
# ---------------------------------------------------------------------------------------------

QUOTA = {
    "scope": "user-scope",
    "limits": {
        "search": {
            "minute": {"used": 7, "remaining": 53, "limit": 60, "percent": 12},
            "day": {"used": 30, "remaining": 90, "limit": 120},
        },
        "private": {"hour": {"used": 5, "remaining": 0, "limit": 5}},
        "scans": {"minute": {"used": 85, "remaining": 15, "limit": 100}},
        "queryableFields": {
            "hidden": {"minute": {"used": 777, "remaining": 777, "limit": 777}}
        },
        "queryVisibility": ["public", "unlisted"],
        "features": ["feat-a", "feat-b"],
    },
}


def _row(out, action, window):
    lines = [line for line in out.splitlines() if action in line and window in line]
    assert len(lines) == 1, (action, window, out)
    return lines[0]


def _numbers(line):
    return set(
        re.findall(r"(?<![\w;])\d+(?![\w])", re.sub(r"\x1b\[[0-9;]*m", " ", line))
    )


def test_quotas_text_rows_per_action_and_window_with_computed_percent(bench):
    outcome = bench.run(["quotas"], {("GET", QUOTAS_URL): reply(200, QUOTA)})
    out = outcome.out
    assert (
        outcome.code == 0
        and outcome.urls == [QUOTAS_URL]
        and "api-key" not in outcome.seen[0].headers
    )
    assert {"7", "53", "60", "12"} <= _numbers(_row(out, "search", "minute"))
    assert {"30", "90", "120", "25"} <= _numbers(_row(out, "search", "day"))
    assert {"5", "0", "100"} <= _numbers(_row(out, "private", "hour"))
    assert out.index("minute") < out.index("day")
    assert "777" not in out
    for token in ("user-scope", "public", "unlisted", "feat-a", "feat-b"):
        assert token in out, token


def test_quotas_accept_actions_at_the_top_level_without_a_limits_wrapper(bench):
    body = {"search": {"minute": {"used": 1, "remaining": 2, "limit": 3}}}
    out = bench.run(["quotas"], {("GET", QUOTAS_URL): reply(200, body)}).out
    assert {"1", "2", "3"} <= _numbers(_row(out, "search", "minute"))


def test_quotas_colour_red_when_exhausted_yellow_at_80_percent_else_green(bench):
    bench.monkeypatch.setenv("FORCE_COLOR", "1")
    out = bench.run(["quotas"], {("GET", QUOTAS_URL): reply(200, QUOTA)}).out
    red, yellow, green = (
        {ESC + "91m", ESC + "31m"},
        {ESC + "93m", ESC + "33m"},
        {ESC + "92m", ESC + "32m"},
    )
    assert any(code in _row(out, "private", "hour") for code in red)
    assert any(code in _row(out, "scans", "minute") for code in yellow)
    assert any(code in _row(out, "search", "day") for code in green)


def test_quotas_json_passthrough_and_ignored_save(bench):
    save = bench.cwd / "ignored.json"
    outcome = bench.run(
        ["--json", "--save", str(save), "quotas"],
        {("GET", QUOTAS_URL): reply(200, QUOTA)},
    )
    assert outcome.out == json.dumps(QUOTA, indent=2, ensure_ascii=False) + "\n"
    assert not save.exists()


@pytest.mark.parametrize("first_status", [404, 405])
def test_quotas_fall_back_to_the_user_path_only_on_404_or_405(bench, first_status):
    outcome = bench.run(
        ["--json", "quotas"],
        {
            ("GET", QUOTAS_URL): reply(first_status, {}),
            ("GET", QUOTAS_FALLBACK_URL): reply(200, {"ok": 1}),
        },
    )
    assert outcome.code == 0 and outcome.urls == [QUOTAS_URL, QUOTAS_FALLBACK_URL]
    assert json.loads(outcome.out) == {"ok": 1}


def test_quotas_other_first_errors_raise_without_trying_the_fallback(bench):
    outcome = bench.run(
        ["quotas"], {("GET", QUOTAS_URL): reply(500, {"message": "bad"})}
    )
    assert outcome.exited and outcome.code == 1 and outcome.urls == [QUOTAS_URL]
    assert outcome.err == "error: HTTP 500: bad\n"


@pytest.mark.parametrize(
    "first, second, shown",
    [(405, 500, "HTTP 500"), (404, 404, "HTTP 404"), (404, 403, "HTTP 403")],
)
def test_quotas_when_both_paths_fail_the_last_error_is_reported(
    bench, first, second, shown
):
    outcome = bench.run(
        ["quotas"],
        {
            ("GET", QUOTAS_URL): reply(first, {"message": "one"}),
            ("GET", QUOTAS_FALLBACK_URL): reply(second, {"message": "two"}),
        },
    )
    assert outcome.exited and outcome.code == 1
    assert shown in outcome.err and "two" in outcome.err and "one" not in outcome.err


def test_whoami_requires_a_key_locally(bench):
    outcome = bench.run(["whoami"])
    assert outcome.exited and outcome.code == 1 and outcome.seen == []


def test_whoami_text_shows_known_keys_in_order_then_other_scalars(bench):
    body = {
        "uuid": "U-1",
        "plan": "free",
        "username": "bob",
        "email": "b@x.example",
        "extra": "xv",
        "nested": {"a": 1},
        "listy": [1],
    }
    outcome = bench.run(
        ["--api-key", "k", "whoami"], {("GET", WHOAMI_URL): reply(200, body)}
    )
    out = outcome.out
    assert outcome.code == 0 and outcome.urls == [WHOAMI_URL]
    assert (
        out.index("bob")
        < out.index("b@x.example")
        < out.index("free")
        < out.index("U-1")
        < out.index("xv")
    )
    assert "nested" not in out and "listy" not in out
    assert "quota" not in out


def test_whoami_json_passthrough(bench):
    outcome = bench.run(
        ["--api-key", "k", "--json", "whoami"],
        {("GET", WHOAMI_URL): reply(200, {"username": "bob"})},
    )
    assert outcome.out == '{\n  "username": "bob"\n}\n'


FIELD_NAMES = [
    "page.domain",
    "domain",
    "page.ip",
    "ip",
    "asn",
    "hash",
    "filename",
    "server",
    "country",
    "task.url",
    "task.uuid",
    "task.visibility",
    "task.tags",
    "date",
    "stats.uniqIPs",
    "verdicts.malicious",
]


def test_fields_is_offline_lists_every_field_name_and_ignores_json(bench):
    plain = bench.run(["fields"])
    as_json = bench.run(["--json", "fields"])
    assert plain.code == 0 and plain.seen == []
    for name in FIELD_NAMES:
        assert re.search(rf"(?<![\w.]){re.escape(name)}:", plain.out), name
    assert as_json.out == plain.out


# ---------------------------------------------------------------------------------------------
# Error mapping and exit codes [K]/[T]
# ---------------------------------------------------------------------------------------------


def _search_error(bench, status, body, headers=None, argv=("search", "q")):
    response = reply(status, body, headers=headers)
    return bench.run(list(argv), responder=lambda request, n: response)


@pytest.mark.parametrize(
    "body, shown",
    [
        (
            {"message": "bad query", "description": "parse error"},
            "bad query — parse error",
        ),
        ({"message": "same", "description": "same"}, "same"),
        ({"message": "  ", "description": "d"}, "d"),
        ({"description": "only desc"}, "only desc"),
        ({"error": "e", "detail": "d", "warning": "w"}, "e"),
        ({"detail": "d", "warning": "w"}, "d"),
        ({"warning": "w"}, "w"),
        ({"foo": "bar"}, '{"foo": "bar"}'),
        ({"message": 5}, '{"message": 5}'),
        ("just a string", "just a string"),
        ([1, 2], "[1, 2]"),
    ],
)
def test_error_message_extraction_vectors(bench, body, shown):
    raw = json.dumps(body, separators=(", ", ": "))
    outcome = _search_error(bench, 500, raw)
    assert outcome.exited and outcome.code == 1
    assert outcome.err == f"error: HTTP 500: {shown}\n"


def test_error_message_uses_the_reason_phrase_for_an_empty_body(bench):
    outcome = _search_error(bench, 500, b"")
    assert outcome.err == "error: HTTP 500: Internal Server Error\n"


def test_error_message_for_a_non_json_body_is_clipped_to_400_chars(bench):
    outcome = _search_error(bench, 502, b"<html>" + b"x" * 600)
    prefix = "error: HTTP 502: "
    assert outcome.err.startswith(prefix) and len(outcome.err) == len(prefix) + 400 + 1
    assert outcome.err.endswith("x\n")


def test_error_hint_401_names_the_key_variable_and_flag(bench):
    outcome = _search_error(bench, 401, {"message": "no key"})
    assert outcome.err.startswith("error: HTTP 401: no key ")
    assert "URLSCAN_API_KEY" in outcome.err and "--api-key" in outcome.err


def test_error_hint_403_says_a_valid_key_is_needed(bench):
    outcome = _search_error(bench, 403, {"message": "forbidden"})
    assert (
        outcome.err.startswith("error: HTTP 403: forbidden ")
        and "key" in outcome.err.lower()
    )


def test_error_hint_400_on_search_explains_elasticsearch_syntax(bench):
    outcome = _search_error(bench, 400, {"message": "bad"})
    assert (
        outcome.err.startswith("error: HTTP 400: bad ")
        and "Elasticsearch" in outcome.err
    )


def test_error_400_on_other_commands_has_no_hint(bench):
    outcome = bench.run(
        ["--api-key", "k", "result", UUID],
        {("GET", RESULT_URL): reply(400, {"message": "bad"})},
    )
    assert outcome.err == "error: HTTP 400: bad\n"


def test_error_hint_429_with_reset_after_and_summary(bench):
    outcome = _search_error(
        bench,
        429,
        {"message": "slow down"},
        headers={
            "x-rate-limit-reset-after": "42",
            "x-rate-limit-action": "search",
            "x-rate-limit-remaining": "0",
            "x-rate-limit-limit": "60",
            "x-rate-limit-window": "minute",
        },
    )
    assert "Retry after 42s" in outcome.err
    assert "search minute 0/60 left · resets in 42s" in outcome.err


def test_error_hint_429_without_reset_after_shows_the_summary_and_without_headers_nothing(
    bench,
):
    with_summary = _search_error(
        bench,
        429,
        {"message": "slow"},
        headers={"x-rate-limit-action": "search", "x-rate-limit-remaining": "0"},
    )
    assert (
        with_summary.err.startswith("error: HTTP 429: slow ")
        and "search" in with_summary.err
    )
    assert "Retry after" not in with_summary.err
    bare = _search_error(bench, 429, {"message": "slow down"})
    assert bare.err == "error: HTTP 429: slow down\n"


@pytest.mark.parametrize(
    "headers, summary",
    [
        ({"x-rate-limit-action": "search"}, "search"),
        ({"x-rate-limit-remaining": "3"}, "3 left"),
        ({"x-rate-limit-remaining": "3", "x-rate-limit-limit": "x"}, "3 left"),
        (
            {
                "X-Rate-Limit-Action": "public",
                "X-Rate-Limit-Window": "hour",
                "X-Rate-Limit-Remaining": "7",
                "X-Rate-Limit-Limit": "10",
                "X-Rate-Limit-Reset-After": "9",
            },
            "public hour 7/10 left · resets in 9s",
        ),
    ],
)
def test_quota_line_summary_variants(bench, headers, summary):
    outcome = bench.run(
        ["--api-key", "k", "result", UUID],
        {("GET", RESULT_URL): reply(200, RESULT, headers=headers)},
    )
    assert re.search(
        r"quota\s+" + re.escape(summary) + r"\s*$", outcome.out, re.MULTILINE
    )


def test_quota_line_absent_without_rate_headers_or_in_json_mode(bench):
    plain = bench.run(
        ["--api-key", "k", "result", UUID], {("GET", RESULT_URL): reply(200, RESULT)}
    )
    assert "quota" not in plain.out
    machine = bench.run(
        ["--api-key", "k", "--json", "result", UUID],
        {("GET", RESULT_URL): reply(200, RESULT, action="x", remaining=1)},
    )
    assert "quota" not in machine.out


def test_network_errors_are_http_zero_and_exit_one(bench):
    def timeout(request, n):
        raise httpx.ReadTimeout("slow", request=request)

    outcome = bench.run(["search", "q"], responder=timeout)
    assert outcome.exited and outcome.code == 1
    assert outcome.err == "error: HTTP 0: network error: slow\n"


def test_keyboard_interrupt_becomes_exit_130_with_a_blank_line_then_interrupted(bench):
    def interrupt(request, n):
        raise KeyboardInterrupt()

    outcome = bench.run(["search", "q"], responder=interrupt)
    assert outcome.exited and outcome.code == 130
    assert outcome.err == "\nerror: interrupted\n"
    assert outcome.out == ""


@pytest.mark.parametrize(
    "argv, routes",
    [
        (
            ["search", "q"],
            {("GET", SEARCH_BASE + "?q=q&size=20"): reply(200, {"results": []})},
        ),
        (["quotas"], {("GET", QUOTAS_URL): reply(200, {})}),
        (
            ["--api-key", "k", "whoami"],
            {("GET", WHOAMI_URL): reply(200, {"username": "u"})},
        ),
        (["--api-key", "k", "result", UUID], {("GET", RESULT_URL): reply(200, {})}),
        (["--api-key", "k", "dom", UUID], {("GET", DOM_URL): reply(200, b"x")}),
        (
            ["--api-key", "k", "screenshot", UUID],
            {("GET", SCREENSHOT_URL): reply(200, PNG)},
        ),
        (
            ["--api-key", "k", "scan", "https://allowed.example/", "--yes"],
            {("POST", SCAN_URL): reply(200, {"uuid": "x"})},
        ),
        (["fields"], {}),
    ],
)
def test_every_subcommand_returns_zero_on_success(bench, argv, routes):
    outcome = bench.run(argv, routes)
    assert outcome.code == 0 and type(outcome.code) is int and not outcome.exited


# ---------------------------------------------------------------------------------------------
# --save [K] (flip-invariant parts; CRLF, escaping and OSError are D5 in test_urlscan_defects.py)
# ---------------------------------------------------------------------------------------------


def _saved(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_save_search_writes_the_body_and_names_the_file(bench):
    target = bench.cwd / "hits.json"
    outcome = bench.run(
        ["--save", str(target), "search", "q"],
        responder=lambda request, n: reply(200, SEARCH_BODY),
    )
    assert _saved(target) == SEARCH_BODY
    assert str(target) in outcome.out + outcome.err


def test_save_result_writes_the_body(bench):
    target = bench.cwd / "res.json"
    bench.run(
        ["--api-key", "k", "--save", str(target), "result", UUID],
        {("GET", RESULT_URL): reply(200, RESULT)},
    )
    assert _saved(target) == RESULT


def test_save_scan_without_wait_writes_the_submission_json(bench):
    target = bench.cwd / "sub.json"
    bench.run(
        ["--save", str(target), *_scan_argv(json_mode=False)],
        {("POST", SCAN_URL): reply(200, SUBMISSION)},
    )
    assert _saved(target) == SUBMISSION


def test_save_scan_with_wait_writes_the_result_json_not_the_submission(bench):
    target = bench.cwd / "res.json"
    bench.run(
        ["--save", str(target), *_scan_argv("--wait", *FAST_WAIT, json_mode=False)],
        {
            ("POST", SCAN_URL): reply(200, {"uuid": UUID}),
            ("GET", RESULT_URL): reply(200, RESULT),
        },
    )
    assert _saved(target) == RESULT


def test_save_in_json_mode_still_prints_the_json_to_stdout(bench):
    target = bench.cwd / "hits.json"
    outcome = bench.run(
        ["--json", "--save", str(target), "search", "q"],
        responder=lambda request, n: reply(200, SEARCH_BODY),
    )
    assert outcome.out.startswith('{\n  "results"')
    assert _saved(target) == SEARCH_BODY


def test_save_file_is_utf8_json_that_round_trips_non_ascii(bench):
    target = bench.cwd / "u.json"
    body = {"results": [], "note": "café 中"}
    bench.run(
        ["--save", str(target), "search", "q"],
        responder=lambda request, n: reply(200, body),
    )
    assert json.loads(target.read_bytes().decode("utf-8")) == body


def test_save_destination_is_not_confined_to_the_cwd(bench):
    outside = bench.home / "elsewhere"
    outside.mkdir()
    bench.run(
        ["--save", str(outside / "o.json"), "search", "q"],
        responder=lambda request, n: reply(200, SEARCH_BODY),
    )
    assert _saved(outside / "o.json") == SEARCH_BODY
