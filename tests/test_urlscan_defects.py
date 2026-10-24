"""Characterization oracle for addons/urlscan, part 3: KNOWN DEFECTS, asserted at their CORRECT behavior.

XFAIL-CORRECT tests. Each test states what the addon SHOULD do and is a strict xfail because the code
at 2eb1935 does not do it yet (spec section 9). `strict=True` means the day the clean-room rebuild
fixes a defect the test XPASSes, the run goes red, and whoever lands the fix removes that one marker:
the marker list is therefore the live defect ledger. Nothing here is a statement about the pinned
(current) behavior; see test_urlscan_contract.py / test_urlscan_commands.py for that.

Defect ids follow the spec (m2-urlscan-spec.md section 9). NEW-1 is not in the spec: found while
writing the key-source tests. Decisions pending with the orchestrator: D1, D4, D5, D15 (each changes a
saved-settings key, stdout, a file format or encoding policy); D3, D9, D12, D14, D16, NEW-1 are small
corrections. The xfail reason strings say which.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from bughunt.console import catalog_export, loader
from bughunt.core import scanner as bughunt_scanner
from urlscan_harness import (  # noqa: F401  (bench is a fixture)
    ADDON_SCRIPT,
    QUOTAS_URL,
    REPO_ROOT,
    RESULT_URL,
    SCAN_URL,
    SEARCH_BASE,
    UUID,
    TtyText,
    bench,
    reply,
)
from test_urlscan_commands import (
    QUOTA,
    RESULT,
    SEARCH_BODY,
    SUBMISSION,
    _scan_argv,
    FAST_WAIT,
)


def test_provider_api_key_reaches_service_but_not_persisted_evidence(bench):
    secret = "urlscan-provider-transport-secret-42"
    outcome = bench.run(
        ["--api-key", secret, "search", "q"],
        responder=lambda request, n: reply(200, {"results": [], "echo": secret}),
    )
    assert outcome.code == 0 and outcome.seen[0].headers["api-key"] == secret
    evidence = list((bench.workspace / "runs").glob("*/*.http"))
    assert len(evidence) == 2
    assert all(secret.encode() not in path.read_bytes() for path in evidence)


TOOL_FILE = Path(bughunt_scanner.__file__).resolve()
SCAN_TARGET = "https://allowed.example/"


def defect(reason, *, raises=AssertionError, condition=True):
    return pytest.mark.xfail(condition, strict=True, raises=raises, reason=reason)


# ---------------------------------------------------------------------------------------------
# D1: --wait-timeout shares its dest with the global --timeout
# ---------------------------------------------------------------------------------------------

D1 = "D1: scan/result --wait-timeout shares dest `timeout` with global --timeout, so the subparser default (120) and the wait value overwrite the HTTP timeout (decision pending: flip + separate dest)"


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["--timeout", "5", "scan", SCAN_TARGET], 5.0),
        (["--timeout", "5", "result", UUID], 5.0),
        (["--timeout", "5", "scan", SCAN_TARGET, "--wait-timeout", "7"], 5.0),
        (["scan", SCAN_TARGET, "--wait-timeout", "7"], 30.0),
        (["scan", SCAN_TARGET], 30.0),
        (["result", UUID], 30.0),
    ],
    ids=[
        "global-5-scan",
        "global-5-result",
        "global-5-with-wait-7",
        "wait-7-keeps-http-30",
        "scan-default",
        "result-default",
    ],
)
def test_d1_global_timeout_dest_is_never_touched_by_wait_timeout(bench, argv, expected):
    assert bench.module.build_parser().parse_args(argv).timeout == expected


@pytest.mark.parametrize(
    "argv, expected",
    [
        (["--api-key", "k", "--timeout", "5", "result", UUID], 5.0),
        (
            [
                "--api-key",
                "k",
                "--timeout",
                "5",
                "scan",
                SCAN_TARGET,
                "--yes",
                "--wait-timeout",
                "9",
            ],
            5.0,
        ),
        (["--api-key", "k", "scan", SCAN_TARGET, "--yes"], 30.0),
    ],
    ids=["result", "scan-with-wait-timeout", "scan-default"],
)
def test_d1_client_gets_the_global_http_timeout(bench, argv, expected):
    outcome = bench.run(
        argv,
        responder=lambda request, n: reply(
            200, SUBMISSION if request.method == "POST" else RESULT
        ),
    )
    assert outcome.client_calls and outcome.client_calls[0]["timeout"] == expected


def test_d1_catalog_form_has_a_single_timeout_row(bench):
    data = catalog_export.export_catalog(
        tool_file=TOOL_FILE, build_parser=bughunt_scanner.build_parser
    )
    entry = next(
        m
        for phase in data["phases"]
        for m in phase["modules"]
        if m["name"] == "urlscan"
    )
    assert [o["name"] for o in entry["form"]["options"]].count("TIMEOUT") == 1


# ---------------------------------------------------------------------------------------------
# D3: standalone launch fails because the first `bughunt` import precedes the sys.path fallback
# ---------------------------------------------------------------------------------------------


def test_d3_standalone_launch_works_from_a_directory_where_bughunt_is_not_installed(
    tmp_path, standalone_python
):
    proc = subprocess.run(
        [*standalone_python, str(ADDON_SCRIPT), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr[-300:]
    assert "usage:" in proc.stdout


# ---------------------------------------------------------------------------------------------
# D4: --json stdout is not pure JSON (saved-notice line, leading blank line, TTY prompt)
# ---------------------------------------------------------------------------------------------

D4 = "D4: --json stdout carries non-JSON text (decision pending: move notices/prompt to stderr, drop the blank line)"


def test_d4_json_with_save_prints_only_the_json_on_stdout(bench):
    target = bench.cwd / "hits.json"
    outcome = bench.run(
        ["--json", "--save", str(target), "search", "q"],
        responder=lambda request, n: reply(200, SEARCH_BODY),
    )
    assert outcome.out == json.dumps(SEARCH_BODY, indent=2, ensure_ascii=False) + "\n"


def test_d4_scan_json_wait_prints_only_the_result_json_on_stdout(bench):
    outcome = bench.run(
        _scan_argv("--wait", *FAST_WAIT),
        {
            ("POST", SCAN_URL): reply(200, {"uuid": UUID}),
            ("GET", RESULT_URL): reply(200, RESULT),
        },
    )
    assert outcome.out == json.dumps(RESULT, indent=2, ensure_ascii=False) + "\n"


def test_d4_interactive_confirm_prompt_does_not_precede_the_json_on_stdout(bench):
    outcome = bench.run(
        ["--api-key", "k", "--json", "scan", SCAN_TARGET],
        {("POST", SCAN_URL): reply(200, SUBMISSION)},
        stdin_tty=True,
        stdin_text="y\n",
    )
    assert outcome.code == 0
    assert outcome.out == json.dumps(SUBMISSION, indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------------------------
# D5: --save / -o file handling
# ---------------------------------------------------------------------------------------------


def test_saved_json_round_trips_with_platform_newlines(bench):
    target = bench.cwd / "hits.json"
    bench.run(
        ["--save", str(target), "search", "q"],
        responder=lambda request, n: reply(200, SEARCH_BODY),
    )
    assert json.loads(target.read_text(encoding="utf-8")) == SEARCH_BODY
    assert os.linesep.encode() in target.read_bytes()


def test_saved_json_preserves_unicode_semantically(bench):
    target = bench.cwd / "u.json"
    bench.run(
        ["--save", str(target), "search", "q"],
        responder=lambda request, n: reply(200, {"results": [], "note": "café 中"}),
    )
    assert json.loads(target.read_text(encoding="utf-8"))["note"] == "café 中"


@pytest.mark.parametrize(
    "argv, routes",
    [
        (["--save", "{dir}", "search", "q"], None),
        (
            ["--api-key", "k", "--save", "{dir}", "result", UUID],
            {("GET", RESULT_URL): reply(200, RESULT)},
        ),
        (
            ["--save", "{dir}", *_scan_argv(json_mode=False)],
            {("POST", SCAN_URL): reply(200, SUBMISSION)},
        ),
        (
            ["--api-key", "k", "dom", UUID, "-o", "{dir}"],
            {("GET", f"https://urlscan.io/dom/{UUID}/"): reply(200, b"<p>")},
        ),
        (
            ["--api-key", "k", "screenshot", UUID, "-o", "{dir}"],
            {("GET", f"https://urlscan.io/screenshots/{UUID}.png"): reply(200, b"png")},
        ),
    ],
    ids=["search-save", "result-save", "scan-save", "dom-output", "screenshot-output"],
)
def test_d5_unwritable_destination_is_a_clean_error_not_a_traceback(
    bench, argv, routes
):
    destination = str(
        bench.cwd
    )  # a directory: opening it for writing fails with an OSError subclass everywhere
    argv = [destination if item == "{dir}" else item for item in argv]
    responder = (lambda request, n: reply(200, SEARCH_BODY)) if routes is None else None
    outcome = bench.run(argv, routes, responder=responder)
    assert outcome.exited and outcome.code == 1
    assert outcome.err.startswith("error: ")


# ---------------------------------------------------------------------------------------------
# D9: the uuid in a submission response is interpolated into the poll path unchecked
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "../../user/username",
        "abc?x=1",
        "https://evil.example/x",
        "%2e%2e%2fuser",
        UUID + "/more",
        UUID + "?x=1",
        17,
        True,
        [UUID],
        {"id": UUID},
    ],
)
def test_d9_scan_wait_refuses_a_non_uuid_from_the_submission_response(bench, hostile):
    outcome = bench.run(
        _scan_argv("--wait", *FAST_WAIT),
        responder=lambda request, n: reply(200, {"uuid": hostile}),
    )
    assert outcome.exited and outcome.code == 1
    assert outcome.gets == []
    assert "uuid" in outcome.err.lower()


@pytest.mark.parametrize("identifier", [UUID, UUID.upper(), "  " + UUID + "  "])
def test_scan_wait_accepts_valid_submission_uuid_and_preserves_case(bench, identifier):
    outcome = bench.run(
        _scan_argv("--wait", *FAST_WAIT),
        responder=lambda request, n: reply(
            200, {"uuid": identifier} if request.method == "POST" else RESULT
        ),
    )
    assert outcome.code == 0
    assert outcome.gets == [f"https://urlscan.io/api/v1/result/{identifier.strip()}/"]


# ---------------------------------------------------------------------------------------------
# D12: prog is hard-coded to urlscan.py
# ---------------------------------------------------------------------------------------------

D12 = "D12: parser prog is hard-coded 'urlscan.py', so usage shows urlscan.py under `bughunt urlscan` (FREE: omit prog like crt-scout)"


def test_d12_usage_line_uses_the_invoking_program_name(bench):
    bench.monkeypatch.setattr(sys, "argv", ["bughunt urlscan"])
    assert (
        bench.module.build_parser().format_usage().startswith("usage: bughunt urlscan ")
    )


def test_d12_argparse_error_under_the_console_shows_bughunt_urlscan(bench):
    entry = lambda unused: loader.run_named(
        "urlscan", ["search"], tool_file=TOOL_FILE, scan_main=bughunt_scanner.main
    )  # noqa: E731
    outcome = bench.run(None, entry=entry)
    assert outcome.code == 2
    assert "usage: bughunt urlscan search" in outcome.err


# ---------------------------------------------------------------------------------------------
# D14: the 400-on-search hint names a real third-party domain
# ---------------------------------------------------------------------------------------------


def test_d14_search_400_hint_uses_example_com_not_a_real_domain(bench):
    outcome = bench.run(
        ["search", "q"], responder=lambda request, n: reply(400, {"message": "bad"})
    )
    assert "hackonlinemod.com" not in outcome.err
    assert "example.com" in outcome.err


# ---------------------------------------------------------------------------------------------
# D15: non-UTF-8 stdout raises an uncaught UnicodeEncodeError
# ---------------------------------------------------------------------------------------------


def _cp1252_stdout():
    return io.TextIOWrapper(
        io.BytesIO(), encoding="cp1252", errors="strict", newline=""
    )


def test_json_on_cp1252_round_trips_non_bmp_unicode(bench):
    payload = {"results": [], "note": "café 中 🙂"}
    stream = _cp1252_stdout()
    outcome = bench.run(
        ["--json", "search", "q"],
        responder=lambda request, n: reply(200, payload),
        stdout=stream,
    )
    stream.flush()
    assert outcome.code == 0
    assert json.loads(stream.buffer.getvalue().decode("cp1252")) == payload


@pytest.mark.parametrize(
    "through_loader, shared", [(False, False), (True, False), (False, True)]
)
@pytest.mark.parametrize("mode, expected", [("ok", 0), ("usage", 2), ("export", 1)])
def test_output_encoding_policy_is_restored(
    bench, through_loader, shared, mode, expected
):
    arguments = (
        ["fields"]
        if mode == "ok"
        else ["nonsense"]
        if mode == "usage"
        else ["--save", str(bench.cwd), "search", "q"]
    )
    output = _cp1252_stdout()
    error = (
        output
        if shared
        else io.TextIOWrapper(
            io.BytesIO(), encoding="cp1252", errors="xmlcharrefreplace"
        )
    )

    def call(unused):
        bench.monkeypatch.setattr(sys, "stderr", error)
        if through_loader:
            return loader.run_named(
                "urlscan",
                arguments,
                tool_file=TOOL_FILE,
                scan_main=bughunt_scanner.main,
            )
        return bench.module.main(arguments)

    outcome = bench.run(
        None,
        entry=call,
        stdout=output,
        responder=lambda request, n: reply(200, SEARCH_BODY),
    )
    assert outcome.code == expected
    assert output.errors == "strict"
    assert error.errors == ("strict" if shared else "xmlcharrefreplace")
    print(json.dumps({"next": "🙂"}, ensure_ascii=True))
    output.flush()
    assert json.loads(output.buffer.getvalue().decode("cp1252").splitlines()[-1]) == {
        "next": "🙂"
    }


@pytest.mark.parametrize(
    "argv, routes",
    [
        (["quotas"], {("GET", QUOTAS_URL): reply(200, QUOTA)}),
        (
            ["search", "q"],
            {
                ("GET", SEARCH_BASE + "?q=q&size=20"): reply(
                    200, {"results": [{**SEARCH_BODY["results"][0]}], "total": 1}
                )
            },
        ),
        (
            ["--json", "search", "q"],
            {
                ("GET", SEARCH_BASE + "?q=q&size=20"): reply(
                    200, {"results": [], "note": "中文"}
                )
            },
        ),
    ],
    ids=["quotas-divider", "search-malicious-flag", "json-cjk"],
)
def test_d15_a_legacy_codepage_stdout_never_crashes_the_command(bench, argv, routes):
    stream = _cp1252_stdout()
    outcome = bench.run(argv, routes, stdout=stream)
    stream.flush()
    assert outcome.code == 0 and not outcome.exited
    assert stream.buffer.getvalue()


# ---------------------------------------------------------------------------------------------
# D16: result --wait timeout reuses the "not ready yet, re-run with --wait" message
# ---------------------------------------------------------------------------------------------


def test_d16_result_wait_timeout_does_not_tell_the_user_to_rerun_with_wait(bench):
    outcome = bench.run(
        [
            "--api-key",
            "k",
            "result",
            UUID,
            "--wait",
            "--wait-timeout",
            "0",
            "--initial-delay",
            "0",
        ],
        {("GET", RESULT_URL): reply(404, {})},
    )
    assert outcome.exited and outcome.code == 1
    assert "re-run with --wait" not in outcome.err.lower()
    assert "within" in outcome.err


# ---------------------------------------------------------------------------------------------
# NEW-1 (not in the spec): a non-ASCII API key crashes with a traceback
# ---------------------------------------------------------------------------------------------


def test_new1_a_non_ascii_api_key_is_a_clean_error(bench):
    key = "k" + chr(0xE9) + "y"
    outcome = bench.run(
        ["--api-key", key, "search", "q"],
        responder=lambda request, n: reply(200, {"results": []}),
    )
    assert outcome.exited and outcome.code == 2
    assert "error:" in outcome.err and outcome.seen == []
    assert key not in outcome.out + outcome.err
