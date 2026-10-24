"""Characterization oracle for addons/urlscan, part 1: module/client/parser/catalog/key/color/egress.

PINNED-CURRENT tests. Every test here passes against the code as it stands at 2eb1935 and is meant to
stay green through the clean-room rebuild. Known defects (spec section 9) are NOT pinned here; their
CORRECT behavior lives in test_urlscan_defects.py as strict xfails. Where a defect touches a pinned
area (D1: --wait-timeout shares a dest with --timeout) the test below is written so it is invariant
under the proposed fix (it reads the wait-timeout option through its flag string, never its dest).

Tier legend follows the spec: [T] pinned by an upstream-of-this-file test, [C] consumed by other code
or docs, [K] current behavior nothing else pins. Live urlscan.io schemas are UNVERIFIED: mock-only.
"""

from __future__ import annotations

import argparse
import inspect
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

from bughunt.console import catalog_export, loader
from bughunt.core import egress
from bughunt.core import scanner as bughunt_scanner
from bughunt.core.workspace import explain_block
from urlscan_harness import (  # noqa: F401  (bench is a fixture)
    ADDON_SCRIPT,
    QUOTAS_URL,
    REPO_ROOT,
    RESULT_URL,
    SEARCH_BASE,
    UUID,
    bench,
    reply,
    write_key_file,
)

TOOL_FILE = Path(bughunt_scanner.__file__).resolve()
OK = reply(200, {})


# ---------------------------------------------------------------------------------------------
# Module surface [T]
# ---------------------------------------------------------------------------------------------


def test_module_surface(bench):
    module = bench.module
    assert callable(module.build_parser) and callable(module.scan_gate)
    assert not inspect.iscoroutinefunction(module.main)
    assert inspect.signature(module.main).parameters["argv"].default is None
    assert not inspect.signature(module.build_parser).parameters
    assert isinstance(module.build_parser(), argparse.ArgumentParser)
    assert module.API_HOSTS == frozenset({"urlscan.io"})
    assert issubclass(module.APIError, Exception)


def test_main_returns_int_zero_on_success(bench):
    outcome = bench.run(["fields"])
    assert outcome.code == 0 and type(outcome.code) is int and not outcome.exited


def test_main_with_no_argv_reads_sys_argv(bench):
    bench.monkeypatch.setattr(sys, "argv", ["bughunt urlscan", "fields"])
    outcome = bench.run(None)
    assert outcome.code == 0
    assert "page.domain" in outcome.out


def test_main_resolves_client_at_call_time_with_key_and_timeout(bench):
    calls = []
    real = bench.real_client

    def spy(api_key=None, timeout=30.0):
        calls.append((api_key, timeout))
        return real(api_key=api_key, timeout=timeout)

    bench.monkeypatch.setattr(bench.module, "Client", spy)
    outcome = bench.run(
        ["--api-key", "kk", "--timeout", "7", "fields"], keep_client=True
    )
    assert outcome.code == 0
    assert calls == [("kk", 7.0)]


def test_client_is_built_for_every_subcommand_including_offline_fields(bench):
    calls = []
    real = bench.real_client

    def spy(api_key=None, timeout=30.0):
        calls.append(api_key)
        return real(api_key=api_key, timeout=timeout)

    bench.monkeypatch.setattr(bench.module, "Client", spy)
    bench.run(["fields"], keep_client=True)
    assert calls == [None]


def test_api_error_attributes_and_string_form(bench):
    error = bench.module.APIError(418, "teapot", {"a": 1}, {"h": "v"})
    assert (error.status, error.message, error.body, error.headers) == (
        418,
        "teapot",
        {"a": 1},
        {"h": "v"},
    )
    assert str(error) == "HTTP 418: teapot"
    bare = bench.module.APIError(0, "x")
    assert bare.body is None and bare.headers == {}


def test_client_attributes_and_timeout(bench):
    client = bench.real_client(api_key="k", timeout=5)
    assert client.api_key == "k"
    assert client.last_rate is None
    assert isinstance(client.http, httpx.Client)
    assert client.http.timeout == httpx.Timeout(5.0)
    assert bench.real_client(api_key=None).http.timeout == httpx.Timeout(30.0)


# ---------------------------------------------------------------------------------------------
# Client.request [T]/[K]
# ---------------------------------------------------------------------------------------------


def test_request_returns_status_body_headers_and_builds_exact_url(bench):
    url = (
        SEARCH_BASE + "?q=page.domain%3Aexample.com+AND+date%3A%3Enow-7d&b=%2C&size=20"
    )
    client, seen = bench.client({("GET", url): reply(200, {"ok": 1}, x_extra="1")})
    status, body, headers = client.request(
        "GET",
        "/api/v1/search/",
        params={
            "q": "page.domain:example.com AND date:>now-7d",
            "gone": None,
            "b": ",",
            "size": 20,
        },
    )
    assert (status, body) == (200, {"ok": 1})
    assert headers["content-type"] == "application/json"
    assert [item.url for item in seen] == [url]


def test_request_drops_none_params_and_appends_nothing_when_all_none(bench):
    client, seen = bench.client(responder=lambda request, n: OK)
    client.request("GET", "/api/v1/quotas", params={"a": None})
    client.request("GET", "/api/v1/quotas", params={})
    assert [item.url for item in seen] == [QUOTAS_URL, QUOTAS_URL]


def test_request_sets_headers_only_the_key_when_one_exists(bench):
    client, seen = bench.client(responder=lambda request, n: OK, api_key=None)
    client.request("GET", "/x")
    keyed, seen_keyed = bench.client(responder=lambda request, n: OK, api_key="SECRET")
    keyed.request("GET", "/x")
    assert "api-key" not in seen[0].headers
    assert seen_keyed[0].headers["api-key"] == "SECRET"
    assert seen_keyed[0].headers["accept"] == "application/json, */*"
    assert "content-type" not in seen_keyed[0].headers


def test_request_wire_user_agent_is_the_policy_profile_not_the_addon_constant(bench):
    client, seen = bench.client(responder=lambda request, n: OK)
    client.request("GET", "/x")
    assert seen[0].headers["user-agent"] == egress.current_profile().user_agent
    assert "urlscan-cli" not in seen[0].headers["user-agent"]


def test_request_payload_uses_default_json_separators_and_content_type(bench):
    client, seen = bench.client(responder=lambda request, n: OK)
    client.request("POST", "/api/v1/scan/", payload={"url": "u", "n": [1, 2]})
    assert seen[0].body == b'{"url": "u", "n": [1, 2]}'
    assert seen[0].headers["content-type"] == "application/json"
    assert seen[0].method == "POST"


def test_request_extra_headers_are_merged(bench):
    client, seen = bench.client(responder=lambda request, n: OK)
    client.request("GET", "/x", extra_headers={"X-Probe": "1"})
    assert seen[0].headers["x-probe"] == "1"
    assert seen[0].headers["api-key"] == "K"


@pytest.mark.parametrize("path", ["https://evil.example/x", "api/v1/quotas", ""])
def test_request_rejects_path_without_leading_slash_before_any_request(bench, path):
    client, seen = bench.client(responder=lambda request, n: OK)
    with pytest.raises(bench.module.APIError) as caught:
        client.request("GET", path)
    assert caught.value.status == 0
    assert seen == []


def test_request_body_decoding_variants(bench):
    cases = {
        b"": None,
        b'{"a": 1}': {"a": 1},
        b"[1, 2]": [1, 2],
        b"plain": "plain",
        b"\xff\xfe": "��",
    }
    for raw, expected in cases.items():
        client, _ = bench.client(responder=lambda request, n, raw=raw: reply(200, raw))
        assert client.request("GET", "/x")[1] == expected


def test_request_raw_returns_bytes_unchanged(bench):
    payload = b"\x89PNG\r\n\x1a\n\x00\xff"
    client, _ = bench.client(responder=lambda request, n: reply(200, payload))
    assert client.request("GET", "/x", raw=True)[1] == payload


def test_request_error_status_raises_api_error_with_parsed_body_and_headers(bench):
    client, _ = bench.client(
        responder=lambda request, n: reply(429, {"message": "slow"}, remaining=0)
    )
    with pytest.raises(bench.module.APIError) as caught:
        client.request("GET", "/x")
    error = caught.value
    assert (
        error.status == 429
        and error.message == "slow"
        and error.body == {"message": "slow"}
    )
    assert error.headers["x-rate-limit-remaining"] == "0"
    assert client.last_rate is not None


def test_request_success_captures_rate_info_and_failure_before_response_does_not_crash(
    bench,
):
    client, _ = bench.client(responder=lambda request, n: reply(200, {}, remaining=3))
    assert client.last_rate is None
    client.request("GET", "/x")
    assert client.last_rate is not None


def test_request_get_follows_redirects_and_resends_headers_up_to_five_hops(bench):
    client, seen = bench.client(
        responder=lambda request, n: reply(302, headers={"location": "/loop/"})
    )
    status, body, _ = client.request("GET", "/start")
    assert status == 302 and body is None
    assert len(seen) == 6
    assert all(item.headers["api-key"] == "K" for item in seen)


def test_request_post_never_follows_redirects(bench):
    client, seen = bench.client(
        responder=lambda request, n: reply(302, headers={"location": "/elsewhere/"})
    )
    status, _, _ = client.request("POST", "/api/v1/scan/", payload={})
    assert status == 302 and len(seen) == 1


def test_request_refuses_a_redirect_to_a_foreign_host_and_sends_nothing_to_it(bench):
    client, seen = bench.client(
        responder=lambda request, n: reply(
            302, headers={"location": "https://evil.example/x"}
        )
    )
    with pytest.raises(bench.module.APIError) as caught:
        client.request("GET", "/start")
    assert caught.value.status == 0 and "refused" in caught.value.message
    assert len(seen) == 1


def test_request_network_failure_becomes_status_zero_api_error(bench):
    def boom(request, n):
        raise httpx.ConnectError("connection refused", request=request)

    client, _ = bench.client(responder=boom)
    with pytest.raises(bench.module.APIError) as caught:
        client.request("GET", "/x")
    assert caught.value.status == 0
    assert caught.value.message == "network error: connection refused"


# ---------------------------------------------------------------------------------------------
# Parser [C]  (read through dests documented in spec section 3; the wait-timeout dest is D1)
# ---------------------------------------------------------------------------------------------


def _subparser(parser, name):
    action = next(a for a in parser._actions if type(a).__name__ == "_SubParsersAction")
    return action.choices[name]


def _option(parser, flag, subcommand=None):
    target = _subparser(parser, subcommand) if subcommand else parser
    return next(a for a in target._actions if flag in a.option_strings)


def test_global_flag_dests_and_defaults(bench):
    namespace = bench.module.build_parser().parse_args(["quotas"])
    assert (
        namespace.api_key,
        namespace.timeout,
        namespace.json,
        namespace.no_color,
        namespace.save,
    ) == (None, 30.0, False, False, None)
    assert namespace.command == "quotas"


def test_global_flags_parse_before_the_subcommand(bench):
    namespace = bench.module.build_parser().parse_args(
        [
            "--api-key",
            "k",
            "--timeout",
            "9",
            "--json",
            "--no-color",
            "--save",
            "f.json",
            "quotas",
        ]
    )
    assert (
        namespace.api_key,
        namespace.timeout,
        namespace.json,
        namespace.no_color,
        namespace.save,
    ) == ("k", 9.0, True, True, "f.json")


def test_search_parser_dests_and_defaults(bench):
    namespace = bench.module.build_parser().parse_args(["search", "a", "b"])
    assert namespace.query == ["a", "b"]
    assert (namespace.size, namespace.after, namespace.datasource) == (20, None, None)
    parsed = bench.module.build_parser().parse_args(
        ["search", "q", "--size", "5", "--after", "1,x", "--datasource", "hostnames"]
    )
    assert (parsed.size, parsed.after, parsed.datasource) == (5, "1,x", "hostnames")


def test_scan_parser_dests_and_defaults(bench):
    parser = bench.module.build_parser()
    namespace = parser.parse_args(["scan", "https://x.example/"])
    assert namespace.url == "https://x.example/"
    assert (namespace.visibility, namespace.yes, namespace.country, namespace.tag) == (
        "private",
        False,
        None,
        None,
    )
    assert (namespace.user_agent, namespace.referer, namespace.override_safety) == (
        None,
        None,
        False,
    )
    assert (namespace.wait, namespace.initial_delay, namespace.interval) == (
        False,
        10.0,
        3.0,
    )
    full = parser.parse_args(
        [
            "scan",
            "u",
            "--tag",
            "a",
            "--tag",
            "b",
            "--user-agent",
            "UA",
            "--referer",
            "R",
            "--country",
            "de",
            "--override-safety",
            "--wait",
            "--yes",
            "--visibility",
            "public",
            "--initial-delay",
            "1",
            "--interval",
            "2",
        ]
    )
    assert (
        full.tag == ["a", "b"]
        and full.user_agent == "UA"
        and full.referer == "R"
        and full.country == "de"
    )
    assert (full.override_safety, full.wait, full.yes, full.visibility) == (
        True,
        True,
        True,
        "public",
    )
    assert (full.initial_delay, full.interval) == (1.0, 2.0)


def test_result_parser_dests_and_defaults(bench):
    namespace = bench.module.build_parser().parse_args(["result", UUID])
    assert namespace.uuid == UUID
    assert (namespace.wait, namespace.initial_delay, namespace.interval) == (
        False,
        2.0,
        3.0,
    )


@pytest.mark.parametrize("subcommand", ["screenshot", "dom"])
def test_download_parsers_take_uuid_and_output(bench, subcommand):
    parser = bench.module.build_parser()
    assert parser.parse_args([subcommand, UUID]).output is None
    assert parser.parse_args([subcommand, UUID, "-o", "x"]).output == "x"
    assert parser.parse_args([subcommand, UUID, "--output", "y"]).output == "y"


@pytest.mark.parametrize("subcommand", ["scan", "result"])
def test_wait_timeout_option_is_a_float_defaulting_to_120_flip_invariant(
    bench, subcommand
):
    action = _option(bench.module.build_parser(), "--wait-timeout", subcommand)
    assert action.default == 120.0 and action.type is float


def test_parser_choices_and_required_command(bench):
    parser = bench.module.build_parser()
    assert tuple(_option(parser, "--visibility", "scan").choices) == (
        "public",
        "unlisted",
        "private",
    )
    assert tuple(_option(parser, "--datasource", "search").choices) == (
        "scans",
        "hostnames",
        "incidents",
        "notifications",
        "certificates",
    )
    action = next(a for a in parser._actions if type(a).__name__ == "_SubParsersAction")
    assert action.dest == "command" and action.required is True
    assert list(action.choices) == [
        "search",
        "scan",
        "result",
        "screenshot",
        "dom",
        "quotas",
        "whoami",
        "fields",
    ]


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["bogus"],
        ["search"],
        ["--timeout", "x", "quotas"],
        ["scan"],
        ["screenshot"],
        ["dom"],
        ["result"],
        ["search", "q", "--datasource", "nope"],
        ["scan", "u", "--visibility", "x"],
        ["search", "q", "--size", "abc"],
        ["search", "q", "--json"],
        ["quotas", "--timeout", "5"],
        ["scan", "u", "--api-key", "k"],
    ],
)
def test_argparse_errors_exit_2_with_no_request(bench, argv):
    outcome = bench.run(argv)
    assert outcome.exited and outcome.code == 2
    assert outcome.seen == []
    assert "usage:" in outcome.err


def test_unrecognized_global_flag_after_subcommand_is_rejected(bench):
    outcome = bench.run(["search", "q", "--json"])
    assert outcome.code == 2 and "unrecognized arguments: --json" in outcome.err


# ---------------------------------------------------------------------------------------------
# Catalog form [C]: option NAMES are saved-settings keys
# ---------------------------------------------------------------------------------------------


def _row(name, kind, sub="", repeatable=False, default="", choices=(), required=False):
    return (name, kind, sub, repeatable, default, tuple(choices), required)


EXPECTED_FORM_ROWS = [
    _row("API_KEY", "value"),
    _row("TIMEOUT", "value", default="30.0"),
    _row("JSON", "bool"),
    _row("NO_COLOR", "bool"),
    _row("SAVE", "value"),
    _row("QUERY", "positional", "search", repeatable=True, required=True),
    _row("SIZE", "value", "search", default="20"),
    _row("AFTER", "value", "search"),
    _row(
        "DATASOURCE",
        "value",
        "search",
        choices=["scans", "hostnames", "incidents", "notifications", "certificates"],
    ),
    _row("URL", "positional", "scan", required=True),
    _row(
        "VISIBILITY",
        "value",
        "scan",
        default="private",
        choices=["public", "unlisted", "private"],
    ),
    _row("YES", "bool", "scan"),
    _row("COUNTRY", "value", "scan"),
    _row("TAG", "value", "scan", repeatable=True),
    _row("USER_AGENT", "value", "scan"),
    _row("REFERER", "value", "scan"),
    _row("OVERRIDE_SAFETY", "bool", "scan"),
    _row("WAIT", "bool", "scan"),
    _row("<wait-timeout>", "value", "scan", default="120.0"),
    _row("INITIAL_DELAY", "value", "scan", default="10.0"),
    _row("INTERVAL", "value", "scan", default="3.0"),
    _row("UUID", "positional", "result", required=True),
    _row("WAIT", "bool", "result"),
    _row("<wait-timeout>", "value", "result", default="120.0"),
    _row("INITIAL_DELAY", "value", "result", default="2.0"),
    _row("INTERVAL", "value", "result", default="3.0"),
    _row("UUID", "positional", "screenshot", required=True),
    _row("OUTPUT", "value", "screenshot"),
    _row("UUID", "positional", "dom", required=True),
    _row("OUTPUT", "value", "dom"),
    _row(
        "COMMAND",
        "positional",
        choices=[
            "search",
            "scan",
            "result",
            "screenshot",
            "dom",
            "quotas",
            "whoami",
            "fields",
        ],
        required=True,
    ),
]


def _urlscan_catalog_entry():
    data = catalog_export.export_catalog(
        tool_file=TOOL_FILE, build_parser=bughunt_scanner.build_parser
    )
    return next(
        m
        for phase in data["phases"]
        for m in phase["modules"]
        if m["name"] == "urlscan"
    )


def test_catalog_entry_and_form_snapshot_flip_invariant(bench):
    entry = _urlscan_catalog_entry()
    assert entry["summary"] == "Search, submit and fetch scans on urlscan.io."
    assert entry["when"] == "You want to search, submit or fetch scans on urlscan.io."
    assert (
        entry["aliases"] == []
        and entry["disabled"] is False
        and entry["reference"] is True
    )
    form = entry["form"]
    assert form is not None and form["command_name"] == "COMMAND"
    assert [s["name"] for s in form["subcommands"]] == [
        "search",
        "scan",
        "result",
        "screenshot",
        "dom",
        "quotas",
        "whoami",
        "fields",
    ]
    rows = []
    for option in form["options"]:
        name = option["name"]
        if option["subcommand"] in ("scan", "result") and name in (
            "TIMEOUT",
            "WAIT_TIMEOUT",
        ):
            name = "<wait-timeout>"
        rows.append(
            (
                name,
                option["kind"],
                option["subcommand"],
                option["repeatable"],
                option["default"],
                tuple(option["choices"]),
                option["required"],
            )
        )
    assert rows == EXPECTED_FORM_ROWS


def test_catalog_form_is_available_without_the_addons_env(bench):
    bench.monkeypatch.delenv("BUGHUNT_ADDONS")
    if not (
        Path(bughunt_scanner.__file__).resolve().parents[2]
        / "addons"
        / "urlscan"
        / "urlscan.py"
    ).is_file():
        pytest.skip("default addon root not applicable to an out-of-tree copy")
    assert _urlscan_catalog_entry()["form"] is not None


# ---------------------------------------------------------------------------------------------
# API key resolution [C]: flag > env > ~/.config/urlscan/api_key > ~/.urlscan_api_key
# ---------------------------------------------------------------------------------------------


def _key_on_the_wire(bench, argv=("quotas",)):
    outcome = bench.run(list(argv), responder=lambda request, n: OK)
    assert outcome.code == 0
    return outcome.seen[0].headers.get("api-key")


def _first_file(bench):
    return bench.home / ".config" / "urlscan" / "api_key"


def _second_file(bench):
    return bench.home / ".urlscan_api_key"


def test_key_none_means_no_header(bench):
    assert _key_on_the_wire(bench) is None


def test_key_flag_wins_and_is_stripped(bench):
    bench.monkeypatch.setenv("URLSCAN_API_KEY", "ENV")
    write_key_file(_first_file(bench), "FILE1\n")
    assert _key_on_the_wire(bench, ["--api-key", "  CLI  ", "quotas"]) == "CLI"


def test_key_empty_flag_falls_through_to_env(bench):
    bench.monkeypatch.setenv("URLSCAN_API_KEY", "ENV")
    assert _key_on_the_wire(bench, ["--api-key", "", "quotas"]) == "ENV"


def test_key_env_is_stripped_and_beats_files(bench):
    bench.monkeypatch.setenv("URLSCAN_API_KEY", "  ENVKEY  ")
    write_key_file(_first_file(bench), "FILE1\n")
    write_key_file(_second_file(bench), "FILE2\n")
    assert _key_on_the_wire(bench) == "ENVKEY"


def test_key_empty_env_falls_through_to_file(bench):
    bench.monkeypatch.setenv("URLSCAN_API_KEY", "")
    write_key_file(_first_file(bench), "FILE1\n")
    assert _key_on_the_wire(bench) == "FILE1"


def test_key_first_file_uses_only_its_first_line(bench):
    write_key_file(_first_file(bench), "FILEKEY\nsecond line\n")
    write_key_file(_second_file(bench), "HOMEKEY\n")
    assert _key_on_the_wire(bench) == "FILEKEY"


def test_key_blank_first_file_falls_through_to_second_file(bench):
    write_key_file(_first_file(bench), "   \n")
    write_key_file(_second_file(bench), "\nHOMEKEY\n")
    assert _key_on_the_wire(bench) == "HOMEKEY"


def test_key_unreadable_first_file_is_skipped(bench):
    _first_file(bench).mkdir(
        parents=True
    )  # a directory where the file should be: read fails with OSError
    write_key_file(_second_file(bench), "HOMEKEY\n")
    assert _key_on_the_wire(bench) == "HOMEKEY"


def test_key_file_with_non_ascii_text_after_the_first_line_is_read_as_utf8(bench):
    write_key_file(_second_file(bench), "ASCIIKEY\n# clé de test 中\n")
    assert _key_on_the_wire(bench) == "ASCIIKEY"


def test_key_value_is_never_printed(bench):
    outcome = bench.run(
        ["--api-key", "SEKRET-VALUE", "whoami"],
        responder=lambda request, n: reply(401, {"message": "bad key"}),
    )
    assert outcome.code == 1
    assert "SEKRET-VALUE" not in outcome.out + outcome.err


@pytest.mark.parametrize(
    "argv", [["whoami"], ["scan", "https://allowed.example/", "--yes"]]
)
def test_key_required_commands_refuse_locally_without_a_request(bench, argv):
    outcome = bench.run(argv)
    assert outcome.exited and outcome.code == 1
    assert outcome.seen == []
    assert outcome.err.startswith("error: ")


@pytest.mark.parametrize(
    "argv",
    [
        ["search", "q"],
        ["quotas"],
        ["result", UUID],
        ["screenshot", UUID],
        ["dom", UUID],
    ],
)
def test_keyless_commands_still_send_the_request(bench, argv):
    outcome = bench.run(argv, responder=lambda request, n: reply(200, b"{}"))
    assert outcome.seen and "api-key" not in outcome.seen[0].headers


# ---------------------------------------------------------------------------------------------
# Color [K]: --no-color > NO_COLOR > FORCE_COLOR > TTY
# ---------------------------------------------------------------------------------------------

ESC = "\x1b["


def _colored(bench, argv=("fields",), env=None, stdout_tty=False):
    for name, value in (env or {}).items():
        bench.monkeypatch.setenv(name, value)
    return ESC in bench.run(list(argv), stdout_tty=stdout_tty).out


def test_color_off_by_default_when_stdout_is_not_a_tty(bench):
    assert _colored(bench) is False


def test_color_force_color_enables(bench):
    assert _colored(bench, env={"FORCE_COLOR": "1"}) is True


def test_color_no_color_env_beats_force_color(bench):
    assert _colored(bench, env={"FORCE_COLOR": "1", "NO_COLOR": "1"}) is False


def test_color_no_color_flag_beats_force_color(bench):
    assert (
        _colored(bench, argv=("--no-color", "fields"), env={"FORCE_COLOR": "1"})
        is False
    )


def test_color_tty_enables(bench):
    assert _colored(bench, stdout_tty=True) is True


def test_color_tty_with_no_color_env_is_off(bench):
    assert _colored(bench, env={"NO_COLOR": "1"}, stdout_tty=True) is False


def test_color_empty_no_color_and_empty_force_color_count_as_unset(bench):
    assert _colored(bench, env={"NO_COLOR": "", "FORCE_COLOR": "1"}) is True
    bench.monkeypatch.setenv("FORCE_COLOR", "")
    assert _colored(bench) is False


def test_color_error_line_is_plain_when_disabled_and_painted_when_enabled(bench):
    plain = bench.run(["whoami"])
    assert plain.err.startswith("error: ") and ESC not in plain.err
    bench.monkeypatch.setenv("FORCE_COLOR", "1")
    painted = bench.run(["whoami"])
    assert ESC in painted.err and "error: " in painted.err


# ---------------------------------------------------------------------------------------------
# Egress / policy / host guard [T]/[K]
# ---------------------------------------------------------------------------------------------


def _is_blocked(outcome, reason):
    return (
        outcome.exited
        and outcome.code == 1
        and outcome.seen == []
        and reason in outcome.err
    )


def test_policy_without_urlscan_asset_blocks_the_request_before_the_transport(bench):
    bench.remove_urlscan_asset()
    outcome = bench.run(["search", "q"], responder=lambda request, n: OK)
    assert _is_blocked(outcome, "asset-unknown")
    assert (
        "error: HTTP 0: network error: asset-unknown; no outbound action ran"
        in outcome.err
    )


def test_policy_without_passive_operation_blocks_every_network_subcommand(bench):
    bench.edit_policy(lambda d: d["permissions"].update(passive=False))
    outcome = bench.run(["quotas"], responder=lambda request, n: OK)
    assert _is_blocked(outcome, "operation-disallowed")
    assert "HTTP 0" in outcome.err


def test_policy_without_post_method_blocks_scan_submission_after_the_gate_passes(bench):
    bench.set_urlscan_methods(["GET"])
    outcome = bench.run(
        ["--api-key", "k", "scan", "https://allowed.example/", "--yes"],
        responder=lambda request, n: OK,
    )
    assert _is_blocked(outcome, "asset-method-disallowed")
    assert "HTTP 0" in outcome.err


def test_missing_policy_fails_closed_for_network_subcommands_but_fields_still_runs(
    bench,
):
    (bench.workspace / "policy.json").unlink()
    blocked = bench.run(["search", "q"], responder=lambda request, n: OK)
    assert _is_blocked(blocked, "policy-missing-or-invalid")
    offline = bench.run(["fields"])
    assert offline.code == 0 and "page.domain" in offline.out and offline.seen == []


def test_get_redirect_within_the_host_is_followed_and_the_key_is_resent_every_hop(
    bench,
):
    first = reply(301, headers={"location": "/api/v1/result/other/"})
    outcome = bench.run(
        ["--api-key", "KEY", "--json", "result", UUID],
        {
            ("GET", RESULT_URL): first,
            ("GET", "https://urlscan.io/api/v1/result/other/"): reply(
                200, {"task": {"uuid": "z"}}
            ),
        },
    )
    assert outcome.code == 0
    assert [item.headers["api-key"] for item in outcome.seen] == ["KEY", "KEY"]


def test_get_redirect_to_a_granted_urlscan_subdomain_resends_the_key(bench):
    bench.grant_origin("https://img.urlscan.io")
    outcome = bench.run(
        ["--api-key", "KEY", "--json", "result", UUID],
        {
            ("GET", RESULT_URL): reply(
                302, headers={"location": "https://img.urlscan.io/r/"}
            ),
            ("GET", "https://img.urlscan.io/r/"): reply(200, {"ok": 1}),
        },
    )
    assert outcome.code == 0
    assert outcome.seen[1].url == "https://img.urlscan.io/r/"
    assert outcome.seen[1].headers["api-key"] == "KEY"


def test_get_redirect_to_a_foreign_host_is_refused_with_nothing_sent(bench):
    outcome = bench.run(
        ["search", "q"],
        responder=lambda request, n: reply(
            302, headers={"location": "https://evil.example/x"}
        ),
    )
    assert outcome.exited and outcome.code == 1
    assert len(outcome.seen) == 1
    assert "error: HTTP 0: refused:" in outcome.err and "evil.example" in outcome.err


def test_get_redirect_downgrade_to_http_is_blocked_by_policy(bench):
    outcome = bench.run(
        ["--api-key", "k", "--json", "result", UUID],
        {("GET", RESULT_URL): reply(302, headers={"location": "http://urlscan.io/x"})},
    )
    assert outcome.exited and outcome.code == 1
    assert len(outcome.seen) == 1
    assert "asset-unknown" in outcome.err


def test_get_redirect_loop_stops_after_five_hops_and_relays_the_last_3xx_body(bench):
    outcome = bench.run(
        ["--api-key", "k", "--json", "result", UUID],
        responder=lambda request, n: reply(
            302, headers={"location": "/api/v1/result/loop/"}
        ),
    )
    assert outcome.code == 0
    assert len(outcome.seen) == 6
    assert outcome.out == '{\n  "raw": null\n}\n'


def test_post_redirect_status_counts_as_success_with_a_single_request(bench):
    outcome = bench.run(
        ["--api-key", "k", "--json", "scan", "https://allowed.example/", "--yes"],
        responder=lambda request, n: reply(302, headers={"location": "/elsewhere/"}),
    )
    assert outcome.code == 0 and len(outcome.seen) == 1
    assert outcome.out == '{\n  "raw": null\n}\n'


def test_search_and_other_passive_subcommands_are_not_scope_gated(bench):
    (bench.workspace / "scope.txt").unlink()
    for argv in (["search", "evil.tld"], ["result", UUID], ["quotas"]):
        outcome = bench.run(
            argv, responder=lambda request, n: reply(200, {"results": []})
        )
        assert outcome.code == 0, argv


def test_scan_gate_function_contract_returns_none_when_allowed_and_exits_when_not(
    bench,
):
    gate = bench.module.scan_gate
    assert gate("https://allowed.example/", "private", True) is None
    for url in (
        "https://outside.example/",
        "allowed.example/x",
        "javascript:alert(1)",
        "https://allowed.example@evil.example/",
        "ftp://allowed.example/",
        " https://allowed.example/ ",
        "https://sub.allowed.example/",
        "https://allowed.example:8443/",
    ):
        with pytest.raises(SystemExit) as caught:
            gate(url, "private", True)
        assert caught.value.code == 1, url


def test_scan_gate_scope_check_is_case_insensitive_and_http_origin_follows_policy(
    bench,
):
    gate = bench.module.scan_gate
    assert gate("https://ALLOWED.example/", "private", True) is None
    assert gate("http://allowed.example/", "private", True) is None


def test_scan_gate_without_confirmation_exits_when_stdin_is_not_a_tty(bench):
    bench.monkeypatch.setattr("sys.stdin.isatty", lambda: False, raising=False)
    with pytest.raises(SystemExit) as caught:
        bench.module.scan_gate("https://allowed.example/", "private", False)
    assert caught.value.code == 1


def test_scan_gate_explains_a_scope_block_with_the_workspace_text(bench):
    with pytest.raises(SystemExit):
        bench.module.scan_gate("https://outside.example/", "private", True)
    assert explain_block("outside.example") in bench.capsys.readouterr().err


# ---------------------------------------------------------------------------------------------
# Loader contract [C]: rc mapping and sys.argv, through the console's own entry point
# ---------------------------------------------------------------------------------------------


def _through_loader(argv):
    return lambda unused: loader.run_named(
        "urlscan", list(argv), tool_file=TOOL_FILE, scan_main=bughunt_scanner.main
    )


def test_loader_runs_the_addon_and_maps_success_to_rc_zero(bench):
    outcome = bench.run(None, entry=_through_loader(["fields"]))
    assert outcome.code == 0 and "page.domain" in outcome.out


def test_loader_maps_argparse_errors_to_rc_two(bench):
    outcome = bench.run(None, entry=_through_loader(["search"]))
    assert outcome.code == 2 and "usage:" in outcome.err


def test_loader_maps_die_to_rc_one(bench):
    outcome = bench.run(
        None,
        entry=_through_loader(
            ["--api-key", "k", "scan", "https://outside.example/", "--yes"]
        ),
    )
    assert outcome.code == 1 and outcome.seen == []


def test_loader_maps_ctrl_c_to_rc_130_because_main_converts_it_first(bench):
    def interrupt(request, n):
        raise KeyboardInterrupt()

    outcome = bench.run(
        None, responder=interrupt, entry=_through_loader(["search", "q"])
    )
    assert outcome.code == 130


def test_loader_passes_argv_to_main_and_sets_sys_argv(bench):
    captured = {}
    real_main = bench.module.main

    def spy(argv=None):
        captured["argv"], captured["sys_argv"] = argv, list(sys.argv)
        return real_main(argv)

    bench.monkeypatch.setattr(bench.module, "main", spy)
    bench.run(None, entry=_through_loader(["fields"]))
    assert captured["argv"] == ["fields"]
    assert captured["sys_argv"] == ["bughunt urlscan", "fields"]


# ---------------------------------------------------------------------------------------------
# Standalone launch with the package importable (D3 covers the not-installed case)
# ---------------------------------------------------------------------------------------------


def _standalone(tmp_path, *argv):
    scope = tmp_path / "standalone-scope"
    scope.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "PYTHONPATH": str(REPO_ROOT),
        "BUGHUNT_SCOPE": str(scope),
        "PYTHONUTF8": "1",
    }
    env.pop("URLSCAN_API_KEY", None)
    return subprocess.run(
        [sys.executable, str(ADDON_SCRIPT), *argv],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_standalone_launch_with_the_package_importable_exits_zero_on_help_and_fields(
    tmp_path,
):
    helped = _standalone(tmp_path, "--help")
    assert helped.returncode == 0 and "usage:" in helped.stdout
    fields = _standalone(tmp_path, "fields")
    assert fields.returncode == 0 and "page.domain" in fields.stdout


def test_standalone_launch_maps_an_argparse_error_to_exit_two(tmp_path):
    bad = _standalone(tmp_path, "search")
    assert bad.returncode == 2 and "usage:" in bad.stderr
