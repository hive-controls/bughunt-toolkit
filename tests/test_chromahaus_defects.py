"""Characterization oracle for addons/chromahaus, part 3: the known defects D1-D22 (spec section 9).

Every defect is covered in up to two labeled forms:

  test_dNN_pinned_current_*   asserts what the base tree does TODAY, defect included. Green now. When the
                              orchestrator approves a deviation, delete the pinned test; when it does not, the
                              rebuild must keep it green (spec rule: default = reproduce tier [K]).
  test_dNN_correct_*          asserts the CORRECT behavior and is xfail(strict=True, raises=AssertionError): it
                              stays xfail while the defect exists and becomes a hard failure (XPASS) the moment
                              the defect is fixed, so the marker is removed on purpose, not by accident.

Defects with no "correct" form (D7, D11, D12, D13, D14, D20: the spec says preserve) have only the pinned test.
D19 was FIXED at the base commit (2eb1935, the M0 addon-lookup quick-win) after the spec was written at 8e3cd26,
so it is a plain regression test. D8 and D9 are not addon changes; their tests document the boundary. The
no-color half of D18 is INVALIDATED (main() resets the flag every run); only the client-snapshot half is real.
The orchestrator decisions still open (spec section 11): D1, D3, D5, D6, D10, D16, D17, name/version.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.parse
from pathlib import Path

import httpx
import pytest

from bughunt.console import catalog
from bughunt.core import scanner as bughunt_scanner

from chromahaus_support import (  # noqa: F401  (fixtures are imported so pytest registers them here)
    ADDON_DIR,
    BAZAAR,
    KEY,
    M32,
    REPO,
    SHA,
    SUBJECT,
    URLHAUS,
    ZIP,
    console_form_entry,
    feed,
    grants_without,
    json_documents,
    long_sleeps,
    machine_parse,
    no_real_network,
    poll_script,
    repl,
    reply_json,
    rig,
    sleeps,
    url_row,
    write_policy,
)

from test_gate import seed_policy

xfail_correct = pytest.mark.xfail(strict=True, raises=AssertionError)


def has_ansi(text: str) -> bool:
    return "\x1b[" in text


# ---------------------------------------------------------------------------------------------------------------
# D1: --json stdout is not machine-parseable (banner first; multi-feed commands print several documents)
# ---------------------------------------------------------------------------------------------------------------

D1_COMMANDS = [
    ["recent"],
    ["url", "http://x.example/"],
    ["hunt", SHA],
    ["hash", SHA],
    ["tag", "mozi"],
    ["family", "Mozi"],
]


def test_d01_json_stdout_contains_only_provider_documents(rig):
    rig.fake.default = reply_json({"query_status": "no_results"})
    single = rig.cli("--json", "recent")
    assert json_documents(single.out) == [{"query_status": "no_results"}]
    assert machine_parse(single.out) == [{"query_status": "no_results"}]
    multi = rig.cli("--json", "hunt", SHA)
    assert len(json_documents(multi.out)) == 3 and len(machine_parse(multi.out)) == 3


@pytest.mark.parametrize(
    "arguments",
    [
        ["feodo"],
        ["sslbl"],
        ["watch"],
        ["download", SHA, "--i-understand"],
        ["repl"],
        [],
    ],
)
def test_json_rejects_unsupported_commands_before_dispatch(rig, monkeypatch, arguments):
    dispatched = []

    def record_dispatch(*unused):
        dispatched.append(True)

    for command in ("feodo", "sslbl", "watch", "download"):
        monkeypatch.setitem(rig.module.COMMANDS, command, record_dispatch)
    monkeypatch.setattr(rig.module, "run_repl", record_dispatch)
    result = rig.cli("--json", *arguments)
    assert result.rc == 2 and result.out == ""
    assert "--json" in result.err and "not supported" in result.err
    assert dispatched == [] and rig.fake.seen == []


@pytest.mark.parametrize("argv", D1_COMMANDS, ids=lambda argv: " ".join(argv)[:30])
def test_d01_correct_json_stdout_is_exactly_one_json_document_or_json_lines(rig, argv):
    """xfail: D1 needs an orchestrator decision (no banner in --json mode; one document or one per line)."""
    rig.fake.default = reply_json({"query_status": "no_results"})
    result = rig.cli("--json", *argv)
    assert result.rc == 0
    assert machine_parse(result.out) is not None, result.out[:200]


def test_d01_json_with_export_keeps_the_notice_on_stderr(rig):
    rows = [url_row(1)]
    payload = {"query_status": "ok", "urls": rows}
    rig.fake.default = reply_json(payload)
    path = rig.cwd / "rows.json"
    result = rig.cli("--json", "--out", str(path), "recent")
    assert result.rc == 0 and machine_parse(result.out) == [payload]
    assert json.loads(path.read_text(encoding="utf-8")) == rows
    assert "wrote 1 rows" in result.err


# ---------------------------------------------------------------------------------------------------------------
# D2: the date normalizer corrupts the "UTC" suffix of real URLhaus timestamps
# ---------------------------------------------------------------------------------------------------------------


def one_dated_row(rig):
    rig.fake.default = reply_json(
        {
            "query_status": "ok",
            "urls": [url_row(1, date_added="2026-10-18 10:00:00 UTC")],
        }
    )
    return rig.cli("recent").out


def test_d02_correct_a_utc_suffixed_timestamp_keeps_its_utc_suffix(rig):
    out = one_dated_row(rig)
    assert "2026-10-18 10:00:00 UTC" in out and "U C" not in out


# ---------------------------------------------------------------------------------------------------------------
# D3: global options are accepted only BEFORE the subcommand
# ---------------------------------------------------------------------------------------------------------------

D3_AFTER = {
    "limit": ["recent", "-n", "15"],
    "json": ["recent", "--json"],
    "out": ["recent", "--out", "rows.json"],
    "key": ["recent", "--key", KEY],
    "no-color": ["recent", "--no-color"],
}


@pytest.mark.parametrize("flag", sorted(D3_AFTER))
def test_global_options_after_the_subcommand_are_accepted(rig, flag):
    argv = D3_AFTER[flag]
    result = rig.run(argv if flag == "key" else ["--key", KEY, *argv])
    assert result.rc == 0 and rig.fake.seen


def test_d03_correct_limit_after_the_subcommand_is_honored(rig):
    result = rig.cli("recent", "-n", "15")
    assert result.rc == 0 and rig.fake.urls == [f"{URLHAUS}/urls/recent/limit/15/"]


@pytest.mark.parametrize(
    "arguments, expected",
    [
        (["--limit", "9", "recent"], 9),
        (["--limit", "9", "recent", "--limit", "7"], 7),
    ],
)
def test_global_limit_uses_the_last_explicit_value(rig, arguments, expected):
    assert rig.module.build_parser().parse_args(arguments).limit == expected


def test_d03_correct_json_after_the_subcommand_is_honored(rig):
    rig.fake.default = reply_json({"query_status": "ok", "urls": []})
    result = rig.cli("recent", "--json")
    assert result.rc == 0 and json_documents(result.out) == [
        {"query_status": "ok", "urls": []}
    ]


def test_d03_correct_out_after_the_subcommand_is_honored(rig):
    rig.fake.default = reply_json({"query_status": "ok", "urls": [url_row(1)]})
    path = rig.cwd / "rows.json"
    result = rig.cli("recent", "--out", str(path))
    assert result.rc == 0 and path.is_file()


def test_d03_correct_key_and_no_color_after_the_subcommand_are_honored(rig):
    result = rig.run(["recent", "--key", "late-key", "--no-color"])
    assert result.rc == 0 and rig.fake.seen[0].headers["auth-key"] == "late-key"


# ---------------------------------------------------------------------------------------------------------------
# D4: --out is silently ignored for 7 commands, tag exports one half, empty rows write nothing, string data crashes
# ---------------------------------------------------------------------------------------------------------------


def run_with_out(rig, argv):
    path = rig.cwd / "out.json"
    result = rig.cli("--out", str(path), *argv)
    return result, path


@pytest.mark.parametrize(
    "argv",
    [["hunt", SHA], ["hash", SHA], ["family", "Mozi"], ["feodo"], ["sslbl"]],
    ids=lambda argv: argv[0],
)
def test_d04_out_without_export_data_reports_the_destination(rig, argv):
    result, path = run_with_out(rig, argv)
    assert result.rc == 0 and not path.exists()
    assert "wrote" not in result.out and "out.json" in result.err


def test_d04_download_and_watch_report_unused_output(rig, sleeps):
    rig.fake.routes[f"{URLHAUS}/download/{SHA}/"] = (200, {}, ZIP)
    result, path = run_with_out(rig, ["download", SHA, "--i-understand"])
    assert (
        result.rc == 0
        and not path.exists()
        and (rig.workspace / "samples" / f"{SHA}.zip").is_file()
    )
    rig.fake.seen.clear()
    rig.fake.handler = poll_script([feed(("1", "http://a/"))])
    result, path = run_with_out(rig, ["watch"])
    assert result.rc == 0 and not path.exists()
    assert "out.json" in result.err


@pytest.mark.parametrize("argv", [["feodo"], ["hash", SHA]], ids=lambda argv: argv[0])
def test_d04_correct_out_for_a_command_that_exports_nothing_is_not_silent(rig, argv):
    """xfail: either write the file or tell the user (spec 9: optional message)."""
    result, path = run_with_out(rig, argv)
    assert path.exists() or "out.json" in result.out + result.err


def test_d04_tag_export_includes_both_feed_results(rig):
    rig.fake.routes[f"{URLHAUS}/tag/"] = reply_json(
        {"query_status": "ok", "tag": "mozi", "urls": [url_row(1)]}
    )
    rig.fake.routes[BAZAAR] = reply_json(
        {
            "query_status": "ok",
            "data": [{"sha256_hash": SHA, "signature": "BazaarOnly"}],
        }
    )
    result, path = run_with_out(rig, ["tag", "mozi"])
    assert result.rc == 0
    assert json.loads(path.read_text(encoding="utf-8")) == [
        url_row(1),
        {"sha256_hash": SHA, "signature": "BazaarOnly"},
    ]


def test_d04_empty_rows_report_that_no_export_was_written(rig):
    rig.fake.default = reply_json({"query_status": "ok", "urls": []})
    result, path = run_with_out(rig, ["recent"])
    assert result.rc == 0 and not path.exists()
    assert "wrote" not in result.out and "out.json" in result.err


def test_d04_pinned_current_a_missing_output_directory_is_rc1_after_the_listing_printed(
    rig,
):
    rig.fake.default = reply_json({"query_status": "ok", "urls": [url_row(1)]})
    result = rig.cli("--out", str(rig.cwd / "nodir" / "x.json"), "recent")
    assert result.rc == 1 and "x.json" in result.err and url_row(1)["url"] in result.out


STRING_DATA = {
    "query_status": "no_result",
    "data": "Your search did not yield any results",
}


@pytest.mark.parametrize("name", ["out.json", "out.csv"])
def test_d04_correct_threatfox_string_data_is_treated_as_no_rows(rig, name):
    rig.fake.default = reply_json(STRING_DATA)
    path = rig.cwd / name
    result = rig.cli("--out", str(path), "fox", "x")
    assert result.rc == 0 and "no export data" in result.err and not path.exists()


# ---------------------------------------------------------------------------------------------------------------
# D5: REPL `download <sha>` always refuses and the SystemExit ends the whole REPL
# ---------------------------------------------------------------------------------------------------------------


def test_repl_download_refusal_keeps_the_session_alive(rig):
    result = repl(rig, f"download {SHA}", "recent", "quit")
    assert not result.exited and result.rc == 0
    assert "--i-understand" in result.out
    assert rig.fake.urls == [f"{URLHAUS}/urls/recent/limit/25/"]


def test_d05_correct_repl_download_refuses_without_killing_the_repl(rig):
    result = repl(rig, f"download {SHA}", "recent", "quit")
    assert not result.exited and result.rc == 0
    assert rig.fake.urls == [
        f"{URLHAUS}/urls/recent/limit/25/"
    ]  # still refused: no download request was made


# ---------------------------------------------------------------------------------------------------------------
# D6: bare REPL indicators are lowercased before they are queried
# ---------------------------------------------------------------------------------------------------------------


def test_d06_correct_a_bare_indicator_keeps_its_case(rig):
    repl(rig, "HTTP://Evil.example/Path", "quit")
    value = urllib.parse.parse_qs(rig.fake.seen[0].body.decode())["url"][0]
    assert value.endswith("Evil.example/Path")


# ---------------------------------------------------------------------------------------------------------------
# D7: a 40-character digest goes to URLhaus as sha256_hash (README claims SHA-1 support). Preserve.
# ---------------------------------------------------------------------------------------------------------------


def test_d07_pinned_current_a_40_character_digest_is_sent_to_urlhaus_as_sha256_hash(
    rig,
):
    sha1_like = "b" * 40
    assert rig.cli("hash", sha1_like).rc == 0
    assert rig.fake.seen[0].body == b"sha256_hash=" + sha1_like.encode()
    # (server-side acceptance of a SHA-1 in that field is UNVERIFIED: no live call is made here)


# ---------------------------------------------------------------------------------------------------------------
# D8: the shared policy seed has no sslbl.abuse.ch grant, so `sslbl` is denied under it (test-infrastructure gap)
# ---------------------------------------------------------------------------------------------------------------


def test_d08_pinned_current_the_shared_seed_policy_lacks_the_sslbl_origin_so_sslbl_is_denied_under_it(
    rig,
):
    """Delete this when tests/test_gate.py::seed_policy gains https://sslbl.abuse.ch (the oracle's own fixture has it)."""
    document = seed_policy(rig.workspace)
    origins = {row["origin"] for row in document["assets"]}
    assert "https://sslbl.abuse.ch" not in origins
    assert {
        "https://urlhaus-api.abuse.ch",
        "https://mb-api.abuse.ch",
        "https://threatfox-api.abuse.ch",
        "https://feodotracker.abuse.ch",
    } <= origins
    result = rig.cli("sslbl")
    assert result.rc == 1 and "asset-unknown" in result.err and rig.fake.seen == []
    assert (
        rig.cli("recent").rc == 0
    )  # the other four feeds are fine under the shared seed


# ---------------------------------------------------------------------------------------------------------------
# D9: provider Auth-Key values must not persist in run evidence.
# ---------------------------------------------------------------------------------------------------------------


def ledger_files_holding(rig, secret):
    return sorted(
        path.name
        for path in rig.evidence_files()
        if secret.encode() in path.read_bytes()
    )


def test_d09_correct_the_auth_key_is_not_stored_in_plaintext_on_disk(rig):
    secret = "LEDGER-SECRET-KEY-42"
    assert rig.run(["--key", secret, "recent"]).rc == 0
    assert rig.evidence_files()
    assert ledger_files_holding(rig, secret) == []


# ---------------------------------------------------------------------------------------------------------------
# D10: indicators are sent to abuse.ch with no scope check or confirmation (unlike phish/urlscan)
# ---------------------------------------------------------------------------------------------------------------


def test_d10_pinned_current_an_out_of_scope_indicator_is_still_sent_to_abuse_ch(rig):
    rig.scope("allowed.example\n")
    for argv in (
        ["url", "http://not-in-scope.example/x"],
        ["host", "not-in-scope.example"],
        ["hunt", "http://not-in-scope.example/x"],
    ):
        rig.fake.seen.clear()
        result = rig.cli(*argv)
        assert (
            result.rc == 0
            and rig.fake.seen
            and b"not-in-scope.example" in rig.fake.seen[0].body
        )


def test_documented_out_of_scope_lookup_contacts_only_the_provider(rig):
    rig.scope("allowed.example\n")
    assert (
        rig.cli("url", "http://allowed.example/x").rc == 0 and len(rig.fake.seen) == 1
    )
    looked_up = rig.cli("url", "http://not-in-scope.example/x")
    assert looked_up.rc == 0 and len(rig.fake.seen) == 2
    assert all(
        urllib.parse.urlsplit(request.url).hostname.endswith("abuse.ch")
        for request in rig.fake.seen
    )


# ---------------------------------------------------------------------------------------------------------------
# D11: policy denial / network errors are a generic rc 1; no preflight; multi-request commands print partially
# ---------------------------------------------------------------------------------------------------------------


def test_d11_pinned_current_a_denied_feed_midway_leaves_the_earlier_output_and_is_rc1_not_2(
    rig,
):
    rig.policy(grants_without("https://mb-api.abuse.ch"))
    rig.fake.routes[f"{URLHAUS}/payload/"] = reply_json(
        {"query_status": "ok", "md5_hash": "m" * 32, "sha256_hash": SHA}
    )
    result = rig.cli("hash", M32)
    assert (
        not result.exited and result.returned == 1
    )  # PolicyBlocked never escapes main(), so never the loader's rc 2
    assert "m" * 32 in result.out  # the first feed was already printed
    assert rig.fake.urls == [
        f"{URLHAUS}/payload/"
    ]  # the denied request never reached the transport
    assert "network error" in result.err and "asset-unknown" in result.err


# ---------------------------------------------------------------------------------------------------------------
# D12: one transient error ends watch (rc 1); the heading shows the requested interval, not the 15 s floor
# ---------------------------------------------------------------------------------------------------------------


def test_d12_pinned_current_a_transient_error_ends_watch_and_the_heading_shows_the_requested_interval(
    rig, sleeps
):
    def handler(seen, number):
        if number == 1:
            return reply_json(feed(("1", "http://a/")))
        raise httpx.ConnectError("blip", request=httpx.Request("GET", seen.url))

    rig.fake.handler = handler
    result = rig.cli("watch", "--interval", "5")
    assert result.rc == 1 and "network error" in result.err
    assert len(rig.fake.seen) == 2 and long_sleeps(sleeps) == [15]
    heading = next(
        line for line in result.out.splitlines() if re.search(r"(?<!\d)5(?!\d)", line)
    )
    assert not re.search(r"(?<!\d)15(?!\d)", heading)


# ---------------------------------------------------------------------------------------------------------------
# D13: download leftovers and leniencies. All preserved; the [T] safety properties are in test_chromahaus_behavior.py
# ---------------------------------------------------------------------------------------------------------------

DOWNLOAD_URL = f"{URLHAUS}/download/{SHA}/"


def test_d13_pinned_current_the_destination_folder_is_left_behind_when_the_download_fails(
    rig,
):
    rig.fake.routes[DOWNLOAD_URL] = (404, {}, b"no")
    rig.fake.routes[BAZAAR] = (500, {}, b"boom")
    result = rig.cli("download", SHA, "--i-understand", "--dest", "k")
    assert result.rc == 1
    assert (rig.workspace / "samples" / "k").is_dir() and not list(
        (rig.workspace / "samples").rglob("*.zip")
    )


def test_d13_pinned_current_an_existing_file_is_overwritten_silently(rig):
    target = rig.workspace / "samples" / f"{SHA}.zip"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"old")
    rig.fake.routes[DOWNLOAD_URL] = (200, {}, ZIP)
    result = rig.cli("download", SHA, "--i-understand")
    assert result.rc == 0 and target.read_bytes() == ZIP


def test_d13_pinned_current_there_is_no_zip_magic_check_so_any_long_body_is_saved(rig):
    body = b"<html>this is not a zip but is long enough</html>"
    rig.fake.routes[DOWNLOAD_URL] = (200, {}, body)
    assert rig.cli("download", SHA, "--i-understand").rc == 0
    assert (rig.workspace / "samples" / f"{SHA}.zip").read_bytes() == body


def test_d13_pinned_current_a_brace_body_that_does_not_parse_is_written_as_if_it_were_the_zip(
    rig,
):
    body = b"{broken json" + b" " * 40
    rig.fake.routes[DOWNLOAD_URL] = (200, {}, body)
    assert rig.cli("download", SHA, "--i-understand", "--dest", "n").rc == 0
    assert (rig.workspace / "samples" / "n" / f"{SHA}.zip").read_bytes() == body


# ---------------------------------------------------------------------------------------------------------------
# D14: a 3xx answer to a POST is treated as a normal response; an empty 200 body is parse_error. Preserve.
# ---------------------------------------------------------------------------------------------------------------


def test_d14_pinned_current_a_3xx_post_answer_is_success_and_is_never_followed(rig):
    rig.fake.default = (302, {"location": f"{URLHAUS}/elsewhere"}, b"")
    result = rig.cli("--json", "url", "http://x.example/")
    assert result.rc == 0 and len(rig.fake.seen) == 1
    assert json_documents(result.out) == [{"_raw": "", "query_status": "parse_error"}]


def test_d14_pinned_current_an_empty_200_body_becomes_a_parse_error_record(rig):
    rig.fake.default = (200, {"content-type": "text/plain"}, b"")
    result = rig.cli("--json", "url", "http://x.example/")
    assert result.rc == 0 and json_documents(result.out) == [
        {"_raw": "", "query_status": "parse_error"}
    ]


# ---------------------------------------------------------------------------------------------------------------
# D15: missing url/threat in the URL detail print the text "None" instead of a dash
# ---------------------------------------------------------------------------------------------------------------


def sparse_url_detail(rig):
    rig.fake.default = reply_json(
        {"query_status": "ok", "id": "1", "host": "h.example"}
    )
    return rig.cli("url", "http://x.example/").out


def test_d15_correct_missing_url_and_threat_print_a_placeholder(rig):
    assert "None" not in sparse_url_detail(rig)


# ---------------------------------------------------------------------------------------------------------------
# D16: no requirements.txt next to the addon although httpx is required
# ---------------------------------------------------------------------------------------------------------------


def test_d16_correct_the_addon_pins_the_same_httpx_as_the_project():
    """Orchestrator decision (spec 9): the addon declares httpx==0.28.1 matching pyproject.toml."""
    requirements = ADDON_DIR / "requirements.txt"
    assert requirements.is_file()
    assert "httpx==0.28.1" in requirements.read_text(encoding="utf-8").split()
    assert "httpx==0.28.1" in (REPO / "pyproject.toml").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------------------------------------------
# D17: the console form lists -V/--version as a settable value option VERSION
# ---------------------------------------------------------------------------------------------------------------


def form_option_names(monkeypatch):
    entry = console_form_entry(monkeypatch)
    assert entry["form"] is not None
    return [option["name"] for option in entry["form"]["options"]]


def test_d17_correct_the_console_form_does_not_offer_version(monkeypatch):
    assert "VERSION" not in form_option_names(monkeypatch)


# ---------------------------------------------------------------------------------------------------------------
# D18: --no-color and the cached client persist across runs in one process
# ---------------------------------------------------------------------------------------------------------------


def test_d18_invalidated_the_no_color_flag_does_not_leak_into_the_next_run(rig):
    """The spec recorded this half of D18 as ASSUMED (read, not exercised). Observed on the base tree: main() assigns
    the flag on every run, so there is no leak. Kept as a plain test so the rebuild does not introduce one."""
    rig.fake.default = reply_json({"query_status": "ok", "urls": [url_row(1)]})
    assert not has_ansi(rig.cli("--no-color", "recent", tty=True).out)
    assert has_ansi(rig.cli("recent", tty=True).out)


def test_d18_pinned_current_a_client_built_under_one_workspace_refuses_to_send_after_the_workspace_changes(
    rig, monkeypatch, tmp_path
):
    other = tmp_path / "other-workspace"
    write_policy(other)
    assert (
        rig.cli("recent").rc == 0
    )  # builds and caches the client under the first workspace
    monkeypatch.setenv("BUGHUNT_SCOPE", str(other))
    result = rig.cli("recent")
    assert (
        result.rc == 1
        and "client-workspace-changed" in result.err
        and len(rig.fake.seen) == 1
    )


# ---------------------------------------------------------------------------------------------------------------
# D19: default addon-root resolution (FIXED at base 2eb1935 by the M0 addon-lookup quick-win; regression pin)
# ---------------------------------------------------------------------------------------------------------------


def test_d19_regression_the_addon_is_found_and_has_a_console_form_without_bughunt_addons(
    monkeypatch,
):
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    tool = catalog.tool_by_command("chroma")
    tool_file = Path(bughunt_scanner.__file__).resolve()
    assert (
        catalog.locate_script(tool, tool_file).resolve()
        == (ADDON_DIR / "chromahaus.py").resolve()
    )
    from bughunt.console import catalog_export

    entry = catalog_export._module_dict(
        "chroma", tool_file=tool_file, build_parser=bughunt_scanner.build_parser
    )
    assert entry["form"] is not None and "unavailable" not in entry


# ---------------------------------------------------------------------------------------------------------------
# D20: Ctrl-C outside watch and the REPL prompt propagates
# ---------------------------------------------------------------------------------------------------------------


def test_d20_pinned_current_ctrl_c_during_a_one_shot_request_propagates_out_of_main(
    rig,
):
    def interrupt(seen, number):
        raise KeyboardInterrupt

    rig.fake.handler = interrupt
    with pytest.raises(KeyboardInterrupt):
        rig.cli("recent")


# ---------------------------------------------------------------------------------------------------------------
# D21: dead code (JA3 and ipblocklist.json constants). Behavior-neutral: no request is ever made for them.
# ---------------------------------------------------------------------------------------------------------------


def test_d21_correct_the_dead_url_constants_are_gone_from_the_source():
    source = SUBJECT.read_text(encoding="utf-8")
    assert "ja3_fingerprints.csv" not in source and "ipblocklist.json" not in source


# ---------------------------------------------------------------------------------------------------------------
# D22: the parser hard-codes prog="chromahaus", so usage lines say chromahaus, not "bughunt chroma"
# ---------------------------------------------------------------------------------------------------------------


def test_usage_names_the_invoking_console_command(rig, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["bughunt chroma", "recent"])
    assert rig.module.build_parser().prog == "bughunt chroma"


def test_d22_correct_usage_names_the_program_it_was_started_as(rig, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["bughunt chroma", "recent"])
    assert "bughunt chroma" in rig.module.build_parser().format_usage()
