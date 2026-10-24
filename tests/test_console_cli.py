"""Characterization oracle for `bughunt.console.cli` (M2 clean-room rebuild, spec sections 5.x).

Pins the 9-row route decision table, the difflib near-miss suggestions, `dispatch` exit
codes and routing, `entry`, `open_console`, and the bash/zsh completion script contracts.
Wording of help/overview prose is FREE and deliberately not asserted.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from bughunt import VERSION
from bughunt.console import catalog, cli, loader, ui
from bughunt.core import ledger, scanner

from console_support import (  # noqa: F401  (env/merged_env are pytest fixtures)
    BUILD_PARSER,
    SCANNER_FILE,
    clean_subprocess_env,
    ScanRecorder,
    TtyStdin,
    TtyText,
    env,
    find_git_bash,
    forbidden_scan,
    make_project,
    merged_env,
    run_cli,
    run_dispatch,
)

PHASE_TITLES = ["Engagement", "Recon", "Capture", "Test", "Labs", "Engines", "Intel"]
BUILTIN_ROUTE_WORDS = [
    "scan",
    "console",
    "modules",
    "commands",
    "catalog",
    "guide",
    "doctor",
    "setup",
    "examples",
    "completion",
]


# --------------------------------------------------------------------------------------
# 5.1 route_argv: the decision table (spec 12.2 vectors; evaluated top to bottom)
# --------------------------------------------------------------------------------------

ROUTE_VECTORS = [
    # row 1: empty
    ([], ("help-usage", [], False, "")),
    # row 2: `--` escape hatch (never a builtin, even when the host is named like one)
    (["--"], ("scan", [], False, "")),
    (["--", "modules"], ("scan", ["modules"], False, "")),
    (["--", "--"], ("scan", ["--"], False, "")),
    # row 3: help
    (["-h"], ("help", [], False, "")),
    (["--help"], ("help", [], False, "")),
    (["help"], ("help", [], False, "")),
    (["help", "scan"], ("help", ["scan"], False, "")),
    (["-h", "scan"], ("help", ["scan"], False, "")),
    # row 4: version
    (["-V"], ("version", [], False, "")),
    (["--version"], ("version", [], False, "")),
    (["version"], ("version", [], False, "")),
    (["version", "extra"], ("version", ["extra"], False, "")),
    # row 5: builtin words (case-sensitive); `commands` becomes `modules` but keeps its token
    (["scan", "x"], ("scan", ["x"], True, "scan")),
    (["scan"], ("scan", [], True, "scan")),
    (["console"], ("console", [], False, "console")),
    (["console", "--text"], ("console", ["--text"], False, "console")),
    (["modules"], ("modules", [], False, "modules")),
    (["modules", "recon"], ("modules", ["recon"], False, "modules")),
    (["commands"], ("modules", [], False, "commands")),
    (["catalog", "--compact"], ("catalog", ["--compact"], False, "catalog")),
    (["guide"], ("guide", [], False, "guide")),
    (["doctor"], ("doctor", [], False, "doctor")),
    (["examples"], ("examples", [], False, "examples")),
    (["completion", "bash"], ("completion", ["bash"], False, "completion")),
    (["Scan", "h"], ("scan", ["Scan", "h"], False, "")),
    # row 6: module names, reference commands and aliases (aliases are NOT canonicalised)
    (["pulse", "u.txt"], ("module", ["u.txt"], False, "pulse")),
    (["crt-scout", "x"], ("module", ["x"], False, "crt-scout")),
    (["lanternjaw"], ("module", [], False, "lanternjaw")),
    (["scope", "init"], ("module", ["init"], False, "scope")),
    (["engine", "map"], ("module", ["map"], False, "engine")),
    (["tcurl"], ("module", [], False, "tcurl")),
    (["skiff", "x"], ("module", ["x"], False, "skiff")),
    # row 7: phase titles, any case
    (["recon"], ("phase", [], False, "Recon")),
    (["Recon"], ("phase", [], False, "Recon")),
    (["RECON"], ("phase", [], False, "Recon")),
    (["  recon  "], ("phase", [], False, "Recon")),
    (["recon", "-h"], ("phase", [], False, "Recon")),
    (["recon", "--help"], ("phase", [], False, "Recon")),
    (["recon", "-h", "ignored"], ("phase", [], False, "Recon")),
    (["RECON", "scan", "h"], ("scan", ["h"], True, "scan")),
    (["recon", "scan"], ("scan", [], True, "scan")),
    (["recon", "pulse", "u"], ("module", ["u"], False, "pulse")),
    (["recon", "crt-scout", "x"], ("module", ["x"], False, "ct")),
    (
        ["labs", "pulse", "u"],
        ("module", ["u"], False, "pulse"),
    ),  # membership is not checked
    (["intel", "tcurl", "x"], ("module", ["x"], False, "tcurl")),
    (["recon", "nope"], ("phase-unknown", ["nope"], False, "Recon")),
    (["recon", "nope", "more"], ("phase-unknown", ["nope"], False, "Recon")),
    (["test"], ("phase", [], False, "Test")),
    (["intel"], ("phase", [], False, "Intel")),
    # row 9: everything else scans with the WHOLE argv
    (
        ["127.0.0.1", "--ports", "80"],
        ("scan", ["127.0.0.1", "--ports", "80"], False, ""),
    ),
    (["localhost"], ("scan", ["localhost"], False, "")),
    (["app.internal"], ("scan", ["app.internal"], False, "")),
    (["80"], ("scan", ["80"], False, "")),
    (["-l", "f.txt"], ("scan", ["-l", "f.txt"], False, "")),
    (
        ["--ports", "80", "127.0.0.1"],
        ("scan", ["--ports", "80", "127.0.0.1"], False, ""),
    ),
    (["-x"], ("scan", ["-x"], False, "")),
    (["https://example.test/"], ("scan", ["https://example.test/"], False, "")),
]


@pytest.mark.parametrize(
    "argv,expected",
    ROUTE_VECTORS,
    ids=[" ".join(v[0]) or "<empty>" for v in ROUTE_VECTORS],
)
def test_route_argv_decision_table(argv, expected):
    route = cli.route_argv(list(argv))
    command, args, scan_verb, token = expected
    assert route.command == command
    assert list(route.args) == args
    assert route.scan_verb is scan_verb
    assert route.token == token


def test_route_argv_does_not_mutate_its_input():
    argv = ["recon", "pulse", "u"]
    cli.route_argv(argv)
    assert argv == ["recon", "pulse", "u"]


def test_route_suggest_row_carries_token_args_and_suggestion():
    route = cli.route_argv(["modulez", "a", "b"])
    assert route.command == "suggest"
    assert route.token == "modulez"
    assert route.suggestion == "modules"
    assert list(route.args) == ["a", "b"]
    assert route.scan_verb is False


@pytest.mark.parametrize("word", BUILTIN_ROUTE_WORDS)
def test_every_builtin_word_routes_by_the_word_not_as_a_host(word):
    """A host named like a command never scans bare (contract 5.1); the escape hatches do."""
    assert cli.route_argv([word, "x"]).command != "scan" or word == "scan"
    assert cli.route_argv(["--", word, "x"]).command == "scan"


@pytest.mark.parametrize(
    "host",
    [
        "test",
        "labs",
        "intel",
        "capture",
        "recon",
        "engines",
        "engagement",
        "scope",
        "pulse",
        "crt-scout",
    ],
)
def test_hosts_named_like_phases_modules_or_aliases_never_scan_bare(host):
    assert cli.route_argv([host]).command != "scan"


def test_scan_escape_hatches_reach_scan_for_reserved_host_names():
    assert cli.route_argv(["scan", "modules"]).args == ["modules"]
    assert cli.route_argv(["--", "modules"]).args == ["modules"]
    assert cli.route_argv(["--", "modules"]).scan_verb is False


def test_near_miss_of_a_command_does_not_scan():
    """Contract 5.1/11.13: `bughunt scop` suggests `scope`, it does not scan a host called scop."""
    route = cli.route_argv(["scop"])
    assert (route.command, route.suggestion) == ("suggest", "scope")


# --------------------------------------------------------------------------------------
# 5.2 suggest_command
# --------------------------------------------------------------------------------------

SUGGESTIONS = [
    ("modulez", "modules"),
    ("scn", "scan"),
    ("catlog", "catalog"),
    ("docter", "doctor"),
    ("recn", "recon"),
    ("skif", "skiff"),
    ("pulsee", "pulse"),
    (
        "commandz",
        "modules",
    ),  # `commands` is in the pool but maps to the command that would run
]


@pytest.mark.parametrize("token,expected", SUGGESTIONS)
def test_suggest_command_near_misses(token, expected):
    assert cli.suggest_command(token) == expected


@pytest.mark.parametrize(
    "token",
    [
        "hlep",
        "ct",
        "tcurl",
        "localhost",
        "a.b",
        "1234",
        "-x",
        "",
        "host:80",
        "a/b",
        "10.0.0.1",
        "--version",
        "zzzzzz",
    ],
)
def test_suggest_command_leaves_hosts_flags_digits_and_exact_members_alone(token):
    assert cli.suggest_command(token) is None


def test_suggest_command_is_case_sensitive_and_never_suggests_the_token_itself():
    for exact in ("modules", "scan", "pulse", "recon", "scope"):
        assert cli.suggest_command(exact) is None


def test_suggest_command_pool_covers_builtins_modules_references_and_lowercase_phases():
    """The pool is the 11 builtin words, every module, every reference command, lower-case phases."""
    assert cli.suggest_command("capturee") == "capture"  # a lower-case phase title
    assert cli.suggest_command("engagemen") == "engagement"
    assert cli.suggest_command("intell") == "intel"
    assert cli.suggest_command("schema") is None
    assert cli.suggest_command("redirct") == "redirect"  # a builtin module
    assert cli.suggest_command("urlscn") == "urlscan"  # a reference command
    assert cli.suggest_command("completon") == "completion"  # a builtin word


def test_suggest_command_does_not_suggest_reference_aliases():
    """Aliases are routable (row 6) but are not in the typo pool: `crt-scoot` finds nothing."""
    assert cli.suggest_command("lanternjow") is None


# --------------------------------------------------------------------------------------
# 5.3 dispatch: exit codes and routing (in-process; no real module is run)
# --------------------------------------------------------------------------------------


@pytest.fixture
def run_recorder(monkeypatch):
    """Replace loader.run_named so module-routed commands are observed, never executed."""
    calls = []

    def fake_run_named(name, argv, *, tool_file, scan_main):
        calls.append((name, list(argv)))
        return 17

    monkeypatch.setattr(loader, "run_named", fake_run_named)
    return calls


EXIT_CODES = [
    ([], 2),
    (["help"], 0),
    (["-h"], 0),
    (["--help"], 0),
    (["help", "-h"], 0),
    (["help", "modules"], 0),
    (["help", "commands"], 0),
    (["help", "pulse"], 0),
    (["help", "crt-scout"], 0),
    (["help", "scope"], 0),
    (["help", "console"], 0),
    (["help", "catalog"], 0),
    (["help", "guide"], 0),
    (["help", "doctor"], 0),
    (["help", "examples"], 0),
    (["help", "completion"], 0),
    (["help", "version"], 0),
    (["help", "help"], 0),
    (["help", "nope"], 2),
    (["help", "recon"], 2),
    (["version"], 0),
    (["--version"], 0),
    (["-V"], 0),
    (["modules"], 0),
    (["commands"], 0),
    (["modules", "recon"], 0),
    (["modules", "RECON"], 0),
    (["modules", "nope"], 2),
    (["modules", "a", "b"], 2),
    (["modules", "-h"], 0),
    (["modules", "--help"], 0),
    (["catalog", "-h"], 0),
    (["guide"], 0),
    (["guide", "-h"], 0),
    (["examples"], 0),
    (["examples", "-h"], 0),
    (["doctor", "-h"], 0),
    (["completion"], 2),
    (["completion", "fish"], 2),
    (["completion", ""], 2),
    (["completion", "bash"], 0),
    (["completion", "zsh"], 0),
    (["completion", "bash", "ignored"], 0),
    (["completion", "-h"], 0),
    (["console", "-h"], 0),
    (["console", "x"], 2),
    (["console", "--text", "x"], 2),
    (["console", "--TEXT"], 2),
    (["recon"], 0),
    (["Recon", "-h"], 0),
    (["recon", "nope"], 2),
    (["modulez"], 2),
    (["help", "tcurl"], 0),
]


@pytest.mark.parametrize(
    "argv,expected", EXIT_CODES, ids=[" ".join(v[0]) or "<empty>" for v in EXIT_CODES]
)
def test_dispatch_exit_codes(env, run_recorder, monkeypatch, argv, expected):
    opened = []
    monkeypatch.setattr(
        cli, "open_console", lambda **kwargs: opened.append(kwargs) or 0
    )
    assert run_dispatch(argv) == expected
    assert run_recorder == []
    assert opened == []


def test_no_arguments_without_a_terminal_prints_overview_and_exits_2(env):
    assert run_dispatch([], interactive=False) == 2
    text = env.all_text
    assert VERSION in text
    for word in (
        "console",
        "modules",
        "catalog",
        "guide",
        "doctor",
        "examples",
        "completion",
        "version",
        "help",
    ):
        assert word in text
    for title in PHASE_TITLES:
        assert title.lower() in text.lower()


def test_help_overview_exits_0_and_lists_the_same_commands(env):
    assert run_dispatch(["help"]) == 0
    for word in (
        "console",
        "modules",
        "catalog",
        "guide",
        "doctor",
        "examples",
        "completion",
        "version",
    ):
        assert word in env.all_text


def test_unknown_help_topic_names_the_topic(env):
    assert run_dispatch(["help", "nopetopic"]) == 2
    assert "nopetopic" in env.all_text


def test_help_scan_runs_scan_help_and_returns_its_code(env):
    scan = ScanRecorder(result=0)
    assert run_dispatch(["help", "scan"], scan_main=scan) == 0
    assert scan.calls == [(["--help"], "bughunt scan")]


@pytest.mark.parametrize(
    "outcome,expected",
    [(None, 0), (0, 0), (2, 2), (7, 7), ("bye", 1), (3.5, 1)],
    ids=["none", "zero", "two", "seven", "message", "float"],
)
def test_help_scan_maps_systemexit_codes(env, outcome, expected):
    scan = ScanRecorder(raises=SystemExit(outcome))
    assert run_dispatch(["help", "scan"], scan_main=scan) == expected


def test_version_prints_exactly_the_version_line_to_stdout(env):
    assert run_dispatch(["version"]) == 0
    assert env.stdout_text == f"Bughunt {VERSION}\n"
    assert env.rich_text == ""


@pytest.mark.parametrize("argv", [["--version"], ["-V"], ["version", "extra", "args"]])
def test_version_spellings_and_extra_args(env, argv):
    assert run_dispatch(argv) == 0
    assert env.stdout_text == f"Bughunt {VERSION}\n"


def test_modules_lists_every_phase_and_every_module_and_the_search_path(env):
    assert run_dispatch(["modules"]) == 0
    text = env.rich_text
    for title, members in catalog.MODULE_GROUPS:
        assert title in text
        for member in members:
            assert member in text
    for root in catalog.addon_roots(SCANNER_FILE):
        assert str(root) in text  # the module search path, one root per line


def test_modules_group_lists_only_that_phase(env):
    assert run_dispatch(["modules", "recon"]) == 0
    text = env.rich_text
    assert "Recon" in text
    for title in PHASE_TITLES:
        if title != "Recon":
            assert re.search(rf"^{title}\b", text, re.M) is None
    for member in dict(catalog.MODULE_GROUPS)["Recon"]:
        assert member in text
    for root in catalog.addon_roots(SCANNER_FILE):
        assert (
            str(root) not in text
        )  # the search-path footer is only for the full listing


def test_modules_unknown_group_names_the_phases(env):
    assert run_dispatch(["modules", "nope"]) == 2
    for title in PHASE_TITLES:
        assert title in env.rich_text


def test_modules_group_given_a_module_name_points_at_its_phase(env):
    assert run_dispatch(["modules", "pulse"]) == 2
    assert "Recon" in env.rich_text


def test_commands_is_an_alias_of_modules(env):
    assert run_dispatch(["commands", "labs"]) == 0
    assert "Labs" in env.rich_text
    assert "race" in env.rich_text


def test_dash_h_blurbs_do_not_run_the_command(env, monkeypatch):
    from bughunt.console import doctor

    monkeypatch.setattr(
        doctor, "run", lambda tool_file: pytest.fail("doctor.run must not run for -h")
    )
    for command in (
        "doctor",
        "catalog",
        "guide",
        "examples",
        "completion",
        "console",
        "modules",
    ):
        env.rich.seek(0)
        env.rich.truncate()
        assert run_dispatch([command, "-h"]) == 0, command
        assert env.rich_text.strip(), command


def test_doctor_routes_to_doctor_run_and_returns_its_code(env, monkeypatch):
    from bughunt.console import doctor

    seen = []
    monkeypatch.setattr(doctor, "run", lambda tool_file: seen.append(tool_file) or 1)
    assert run_dispatch(["doctor"], tool_file=SCANNER_FILE) == 1
    assert seen == [SCANNER_FILE]


def test_examples_routes_to_print_examples(env, monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "print_examples", lambda: seen.append("x") or 0)
    assert run_dispatch(["examples"]) == 0
    assert seen == ["x"]


def test_print_examples_prints_something_and_returns_zero(env):
    assert cli.print_examples() == 0
    assert "bughunt" in env.rich_text


def test_guide_prints_the_walkthrough_and_returns_zero(env):
    assert run_dispatch(["guide"]) == 0
    assert env.rich_text.strip()


@pytest.mark.parametrize("command", ["tcurl"])
def test_disabled_reference_modules_exit_2_through_dispatch(env, monkeypatch, command):
    monkeypatch.setattr(loader, "DISABLED_REFERENCES", frozenset({command}))
    assert run_dispatch([command, "x"]) == 2
    assert "disabled" in env.rich_text


def test_reenabled_skiff_is_dispatched_to_its_script_not_refused(env):
    assert run_dispatch(["skiff", "--version"]) == 0
    assert "disabled" not in env.rich_text


def test_unknown_near_miss_runs_nothing_and_offers_both_paths(env, run_recorder):
    scan = ScanRecorder()
    assert run_dispatch(["modulez", "a", "b"], scan_main=scan) == 2
    assert scan.calls == [] and run_recorder == []
    text = env.rich_text
    assert "modulez" in text and "modules" in text
    assert "bughunt scan modulez" in text  # the escape hatch for a host of that name
    assert "a b" in text  # arguments that were not forwarded are listed


def test_suggest_of_a_module_shows_how_to_run_the_module(env):
    run_dispatch(["pulsee"], scan_main=ScanRecorder())
    assert "bughunt pulse" in env.rich_text


def test_phase_unknown_prints_listing_and_scan_hint(env):
    assert run_dispatch(["recon", "nope"]) == 2
    text = env.rich_text
    assert "nope" in text and "Recon" in text
    assert "bughunt scan nope" in text
    assert "silk" in text  # the phase listing follows


def test_phase_listing_shows_purpose_for_that_phase_only(env):
    assert run_dispatch(["recon"]) == 0
    assert catalog.phase_purpose("Recon") in env.rich_text
    assert catalog.phase_purpose("Intel") not in env.rich_text


# routed-to-run_named commands -------------------------------------------------------


def test_module_route_calls_run_named_with_the_typed_token(env, run_recorder):
    assert run_dispatch(["crt-scout", "example.test", "-c"]) == 17
    assert run_recorder == [("crt-scout", ["example.test", "-c"])]


def test_phase_prefixed_module_route_canonicalises_the_token(env, run_recorder):
    assert run_dispatch(["recon", "crt-scout", "x"]) == 17
    assert run_recorder == [("ct", ["x"])]


def test_run_named_receives_tool_file_and_scan_main(env, monkeypatch):
    seen = {}

    def fake(name, argv, *, tool_file, scan_main):
        seen.update(name=name, tool_file=tool_file, scan_main=scan_main)
        return 5

    monkeypatch.setattr(loader, "run_named", fake)
    scan = ScanRecorder()
    assert run_dispatch(["pulse"], scan_main=scan, tool_file=SCANNER_FILE) == 5
    assert seen == {"name": "pulse", "tool_file": SCANNER_FILE, "scan_main": scan}


# scan routing --------------------------------------------------------------------------

SCAN_ROUTES = [
    (["127.0.0.1", "--ports", "80"], ["127.0.0.1", "--ports", "80"], "bughunt"),
    (["scan", "x"], ["x"], "bughunt scan"),
    (["scan"], [], "bughunt scan"),
    (["--", "modules"], ["modules"], "bughunt"),
    (["recon", "scan", "h"], ["h"], "bughunt scan"),
    (["-l", "f.txt"], ["-l", "f.txt"], "bughunt"),
]


@pytest.mark.parametrize(
    "argv,args,prog", SCAN_ROUTES, ids=[" ".join(v[0]) for v in SCAN_ROUTES]
)
def test_scan_routes_call_scan_main_with_prog(env, argv, args, prog):
    scan = ScanRecorder(result=0)
    assert run_dispatch(argv, scan_main=scan) == 0
    assert scan.calls == [(args, prog)]


@pytest.mark.parametrize(
    "outcome,expected",
    [(None, 0), (0, 0), (2, 2), (130, 130), (-1, -1), ("usage", 1), (1.5, 1)],
)
def test_scan_systemexit_is_mapped_none_zero_int_other(env, outcome, expected):
    scan = ScanRecorder(raises=SystemExit(outcome))
    assert run_dispatch(["x.test"], scan_main=scan) == expected


def test_scan_return_value_is_the_exit_code(env):
    assert run_dispatch(["x.test"], scan_main=ScanRecorder(result=9)) == 9


def test_scan_router_never_swallows_other_exceptions(env):
    scan = ScanRecorder(raises=RuntimeError("boom"))
    with pytest.raises(RuntimeError, match="boom"):
        run_dispatch(["x.test"], scan_main=scan)


def test_scan_router_never_swallows_keyboard_interrupt(env):
    scan = ScanRecorder(raises=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        run_dispatch(["x.test"], scan_main=scan)


# ledger.CURRENT_TOOL and the sanitizing wrapper ----------------------------------------


@pytest.mark.parametrize(
    "argv,label",
    [
        (["x.test"], "scan"),
        (["scan", "x"], "scan"),
        (["--", "x"], "scan"),
        (["recon", "scan", "h"], "scan"),
    ],
)
def test_current_tool_label_is_token_else_command_during_scan(env, argv, label):
    scan = ScanRecorder()
    run_dispatch(argv, scan_main=scan)
    assert scan.tool_labels == [label]


def test_current_tool_label_for_module_and_builtin_routes(env, monkeypatch):
    labels = []

    def fake(name, argv, *, tool_file, scan_main):
        labels.append(ledger.CURRENT_TOOL.get())
        return 0

    monkeypatch.setattr(loader, "run_named", fake)
    run_dispatch(["crt-scout", "x"])
    run_dispatch(["recon", "crt-scout", "x"])
    assert labels == ["crt-scout", "ct"]


def test_current_tool_is_restored_after_dispatch(env):
    before = ledger.CURRENT_TOOL.get()
    run_dispatch(["x.test"], scan_main=ScanRecorder())
    assert ledger.CURRENT_TOOL.get() == before


def test_dispatch_label_is_bughunt_before_routing(env):
    seen = []

    class Probe:
        def __call__(self, argv, prog="bughunt"):
            seen.append(ledger.CURRENT_TOOL.get())
            return 0

    run_dispatch(["x.test"], scan_main=Probe())
    assert seen and seen[0] in {"scan", "bughunt"}


def test_dispatch_redacts_console_and_stdout_on_the_way_out(env):
    """`dispatch` is wrapped by ledger.sanitized: scan output carrying a credential is redacted."""

    def noisy_scan(argv, prog="bughunt"):
        print("Authorization: Bearer super-secret-bearer-value")
        ui.console.print("Cookie: sid=super-secret-cookie-value")
        return 0

    assert run_dispatch(["x.test"], scan_main=noisy_scan) == 0
    assert "super-secret-bearer-value" not in env.all_text
    assert "super-secret-cookie-value" not in env.all_text
    assert "[REDACTED]" in env.stdout_text and "[REDACTED]" in env.rich_text


def test_dispatch_restores_streams_after_running(env):
    env.activate()
    before_out, before_console_file = sys.stdout, ui.console._file
    run_dispatch(["x.test"], scan_main=ScanRecorder())
    assert sys.stdout is before_out and ui.console._file is before_console_file


def test_dispatch_prints_through_a_replaced_ui_console(env):
    """ui.console is read at print time (call-time lookup rule, spec 1.3)."""
    run_dispatch(["modules", "labs"])
    assert "Labs" in env.rich_text


def test_dispatch_with_argv_none_reads_sys_argv(env, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["bughunt", "scan", "from-sys-argv"])
    scan = ScanRecorder()
    assert run_dispatch(None, scan_main=scan) == 0
    assert scan.calls == [(["from-sys-argv"], "bughunt scan")]


def test_dispatch_does_not_mutate_the_callers_argv(env):
    argv = ["x.test", "--ports", "80"]
    run_dispatch(argv, scan_main=ScanRecorder())
    assert argv == ["x.test", "--ports", "80"]


# console command and the interactive decision ------------------------------------------


@pytest.fixture
def console_recorder(monkeypatch):
    opened = []

    def fake_open(**kwargs):
        opened.append(kwargs)
        return 41

    monkeypatch.setattr(cli, "open_console", fake_open)
    return opened


def test_console_command_opens_the_console_with_text_false(env, console_recorder):
    scan = ScanRecorder()
    assert run_dispatch(["console"], scan_main=scan) == 41
    (kwargs,) = console_recorder
    assert kwargs["text"] is False
    assert kwargs["tool_file"] == SCANNER_FILE
    assert kwargs["scan_main"] is scan
    assert kwargs["build_parser"] is BUILD_PARSER


def test_console_text_flag_opens_with_text_true(env, console_recorder):
    assert run_dispatch(["console", "--text"]) == 41
    assert console_recorder[0]["text"] is True


@pytest.mark.parametrize(
    "extra", [["x"], ["--text", "x"], ["--TEXT"], ["--text", "--text"]]
)
def test_console_rejects_other_arguments(env, console_recorder, extra):
    assert run_dispatch(["console", *extra]) == 2
    assert console_recorder == []
    assert "console" in env.rich_text


def test_no_arguments_interactive_true_opens_the_console(env, console_recorder):
    scan = ScanRecorder()
    assert run_dispatch([], scan_main=scan, interactive=True) == 41
    (kwargs,) = console_recorder
    assert kwargs["tool_file"] == SCANNER_FILE and kwargs["scan_main"] is scan
    assert "text" not in kwargs or kwargs["text"] is False


def test_no_arguments_interactive_false_prints_overview(env, console_recorder):
    assert run_dispatch([], interactive=False) == 2
    assert console_recorder == []


def test_interactivity_default_is_both_streams_being_terminals(
    env, console_recorder, monkeypatch
):
    env.activate()
    monkeypatch.setattr(sys, "stdin", TtyStdin())
    monkeypatch.setattr(sys, "stdout", TtyText())
    assert run_dispatch([], interactive=None) == 41
    assert len(console_recorder) == 1


@pytest.mark.parametrize(
    "stdin_tty,stdout_tty", [(True, False), (False, True), (False, False)]
)
def test_interactivity_default_needs_both_streams(
    env, console_recorder, monkeypatch, stdin_tty, stdout_tty
):
    env.activate()
    monkeypatch.setattr(sys, "stdin", TtyStdin() if stdin_tty else sys.stdin)
    monkeypatch.setattr(sys, "stdout", TtyText() if stdout_tty else sys.stdout)
    assert run_dispatch([], interactive=None) == 2
    assert console_recorder == []


def test_interactivity_probe_failure_counts_as_not_interactive(
    env, console_recorder, monkeypatch
):
    class Broken(TtyStdin):
        def isatty(self):
            raise ValueError("closed")

    env.activate()
    monkeypatch.setattr(sys, "stdin", Broken())
    assert run_dispatch([], interactive=None) == 2
    assert console_recorder == []


# --------------------------------------------------------------------------------------
# 5.5 open_console and entry
# --------------------------------------------------------------------------------------


@pytest.fixture
def typed_console(monkeypatch):
    from bughunt.console import console as repl

    calls = []
    monkeypatch.setattr(
        repl, "run_console", lambda **kwargs: calls.append(kwargs) or 23
    )
    return calls


def _fake_picker(monkeypatch, result=29):
    import types

    calls = []
    module = types.ModuleType("bughunt.console.picker")
    module.run_picker = lambda **kwargs: calls.append(kwargs) or result
    monkeypatch.setitem(sys.modules, "bughunt.console.picker", module)
    return calls


def test_open_console_uses_typed_console_when_not_a_terminal(
    env, typed_console, monkeypatch
):
    picker_calls = _fake_picker(monkeypatch)
    assert (
        cli.open_console(
            tool_file=SCANNER_FILE, scan_main=forbidden_scan, build_parser=BUILD_PARSER
        )
        == 23
    )
    assert picker_calls == []
    assert typed_console[0]["tool_file"] == SCANNER_FILE
    assert typed_console[0]["build_parser"] is BUILD_PARSER


def test_open_console_text_flag_skips_the_picker_even_on_a_terminal(
    env, typed_console, monkeypatch
):
    env.activate()
    monkeypatch.setattr(sys, "stdin", TtyStdin())
    monkeypatch.setattr(sys, "stdout", TtyText())
    picker_calls = _fake_picker(monkeypatch)
    assert (
        cli.open_console(
            tool_file=SCANNER_FILE,
            scan_main=forbidden_scan,
            build_parser=BUILD_PARSER,
            text=True,
        )
        == 23
    )
    assert picker_calls == []


def test_open_console_picker_on_a_terminal(env, typed_console, monkeypatch):
    env.activate()
    monkeypatch.setattr(sys, "stdin", TtyStdin())
    monkeypatch.setattr(sys, "stdout", TtyText())
    picker_calls = _fake_picker(monkeypatch, result=29)
    scan = ScanRecorder()
    assert (
        cli.open_console(
            tool_file=SCANNER_FILE, scan_main=scan, build_parser=BUILD_PARSER
        )
        == 29
    )
    assert typed_console == []
    (kwargs,) = picker_calls
    assert (
        kwargs["tool_file"] == SCANNER_FILE
        and kwargs["scan_main"] is scan
        and kwargs["build_parser"] is BUILD_PARSER
    )


def test_open_console_falls_back_to_typed_console_without_textual(
    env, typed_console, monkeypatch
):
    env.activate()
    monkeypatch.setattr(sys, "stdin", TtyStdin())
    monkeypatch.setattr(sys, "stdout", TtyText())
    monkeypatch.setitem(
        sys.modules, "bughunt.console.picker", None
    )  # import raises ImportError
    assert (
        cli.open_console(
            tool_file=SCANNER_FILE, scan_main=forbidden_scan, build_parser=BUILD_PARSER
        )
        == 23
    )


@pytest.fixture
def fake_scanner_main(monkeypatch):
    calls = []

    class Box:
        result = 0
        raises = None

    def fake_main(argv=None):
        calls.append(argv)
        if Box.raises is not None:
            raise Box.raises
        return Box.result

    monkeypatch.setattr(scanner, "main", fake_main)
    return Box, calls


def test_entry_always_ends_in_systemexit_with_the_return_code(fake_scanner_main):
    box, calls = fake_scanner_main
    box.result = 0
    with pytest.raises(SystemExit) as raised:
        cli.entry(["x"])
    assert raised.value.code == 0
    assert calls == [["x"]]
    box.result = 3
    with pytest.raises(SystemExit) as raised:
        cli.entry(["y"])
    assert raised.value.code == 3


def test_entry_maps_keyboard_interrupt_to_130(fake_scanner_main):
    box, _calls = fake_scanner_main
    box.raises = KeyboardInterrupt()
    with pytest.raises(SystemExit) as raised:
        cli.entry([])
    assert raised.value.code == 130


def test_entry_passes_none_through_so_sys_argv_is_used(fake_scanner_main):
    _box, calls = fake_scanner_main
    with pytest.raises(SystemExit):
        cli.entry()
    assert calls == [None]


def test_entry_does_not_swallow_other_exceptions(fake_scanner_main):
    box, _calls = fake_scanner_main
    box.raises = RuntimeError("boom")
    with pytest.raises(RuntimeError):
        cli.entry([])


def test_scanner_main_passes_its_own_file_as_tool_file(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        cli, "dispatch", lambda argv, **kwargs: seen.update(kwargs, argv=argv) or 0
    )
    assert scanner.main(["x"]) == 0
    assert seen["tool_file"] == Path(scanner.__file__).resolve()
    assert seen["scan_main"] is scanner.scan_main
    assert seen["build_parser"] is scanner.build_parser


# --------------------------------------------------------------------------------------
# End-to-end through the real entry point (`python -m bughunt`), clean environment
# --------------------------------------------------------------------------------------

SUBPROCESS_CODES = [
    ([], 2),
    (["help"], 0),
    (["help", "nope"], 2),
    (["help", "recon"], 2),
    (["version"], 0),
    (["-V"], 0),
    (["modules"], 0),
    (["modules", "recon"], 0),
    (["modules", "nope"], 2),
    (["modules", "a", "b"], 2),
    (["catalog", "-h"], 0),
    (["completion"], 2),
    (["completion", "fish"], 2),
    (["completion", "bash"], 0),
    (["console", "x"], 2),
    (["recon"], 0),
    (["recon", "nope"], 2),
    (["modulez"], 2),
    (["tcurl"], 2),
    (["skiff"], 2),
]


@pytest.mark.parametrize(
    "args,expected",
    SUBPROCESS_CODES,
    ids=[" ".join(v[0]) or "<empty>" for v in SUBPROCESS_CODES],
)
def test_python_dash_m_bughunt_exit_codes(tmp_path, args, expected):
    done = run_cli(tmp_path, args)
    assert done.returncode == expected, done.stdout[-300:] + done.stderr[-300:]
    assert "Traceback" not in done.stderr


def test_python_dash_m_version_stdout(tmp_path):
    done = run_cli(tmp_path, ["--version"])
    assert (done.returncode, done.stdout) == (0, f"Bughunt {VERSION}\n")


def test_python_dash_m_console_text_with_empty_stdin_exits_0(tmp_path):
    done = run_cli(tmp_path, ["console", "--text"], stdin="")
    assert done.returncode == 0, done.stdout[-300:] + done.stderr[-300:]
    assert VERSION in done.stdout


def test_python_dash_m_console_reads_piped_commands_and_exits_on_exit(tmp_path):
    done = run_cli(
        tmp_path, ["console", "--text"], stdin="version\nsearch pulse\nexit\nversion\n"
    )
    assert done.returncode == 0
    assert (
        done.stdout.count(f"Bughunt {VERSION}") >= 2
    )  # banner + `version`; nothing after `exit`
    assert done.stdout.count(f"Bughunt {VERSION}") <= 3


def test_entry_function_via_console_script_target(tmp_path):
    done = subprocess.run(
        [
            sys.executable,
            "-c",
            "from bughunt.console.cli import entry; entry(['version'])",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        env=clean_subprocess_env(tmp_path),
    )
    assert (done.returncode, done.stdout) == (0, f"Bughunt {VERSION}\n")


# --------------------------------------------------------------------------------------
# help <module> topic (5.3); content words are FREE, structure is not
# --------------------------------------------------------------------------------------


def test_help_for_a_builtin_module_names_it_and_shows_the_summary_and_usage(env):
    from bughunt.modules import MODULES

    assert run_dispatch(["help", "dns"]) == 0
    text = env.rich_text
    assert "dns" in text and MODULES["dns"][:30] in text
    assert "bughunt dns" in text
    assert "use dns" in text and "run" in text and "set" in text


def test_help_for_a_reference_alias_shows_aliases_and_the_program_path(env):
    assert run_dispatch(["help", "ct"]) == 0
    text = env.rich_text
    assert "crt-scout" in text
    assert "crt-scout.py" in text  # located in the source checkout


def test_help_for_a_reference_alias_token_resolves_to_the_command(env):
    assert run_dispatch(["help", "crt-scout"]) == 0
    assert "bughunt ct" in env.rich_text


def test_help_for_a_missing_program_says_so_and_names_the_env_var(env):
    tool_file = make_project(env.root)
    assert run_dispatch(["help", "pulse"], tool_file=tool_file) == 0
    assert "BUGHUNT_ADDONS" in env.rich_text
    assert "pulse/pulse.py" in env.rich_text.replace("\\", "/")


# --------------------------------------------------------------------------------------
# 5.4 completion scripts
# --------------------------------------------------------------------------------------


def _script(env, shell: str) -> str:
    env.activate()
    assert cli.print_completion(shell, BUILD_PARSER) == 0
    return env.stdout_text


def _expected_command_words() -> list[str]:
    from bughunt.modules import MODULES

    words = [
        "scan",
        "console",
        "modules",
        "commands",
        "catalog",
        "guide",
        "doctor",
        "setup",
        "examples",
        "completion",
        "version",
        "help",
        "chain",
        "pipeline",
        "schema",
    ]
    words += [title.lower() for title in PHASE_TITLES]
    words += list(MODULES)
    words += [tool.command for tool in catalog.REFERENCES]
    for tool in catalog.REFERENCES:
        words += list(tool.aliases)
    return words


def _expected_flag_words() -> list[str]:
    flags = []
    for action in BUILD_PARSER("bughunt")._actions:
        flags.extend(action.option_strings)
    return flags


def test_expected_word_lists_have_the_spec_counts():
    assert len(_expected_command_words()) == 71 == len(set(_expected_command_words()))
    assert len(_expected_flag_words()) == 65


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_completion_script_mentions_version_and_install_command(env, shell):
    script = _script(env, shell)
    assert VERSION in script.splitlines()[0] or VERSION in script.splitlines()[1]
    assert f"bughunt completion {shell}" in script


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_completion_script_is_plain_text_without_rich_markup_or_ansi(env, shell):
    script = _script(env, shell)
    assert "\x1b" not in script
    assert (
        "[info]" not in script
        and "[/" not in script.replace("[/", "[/")
        or "[/" not in script
    )
    assert env.rich_text == ""  # written to sys.stdout, not through the rich console


@pytest.mark.parametrize("shell", ["bash", "zsh"])
def test_completion_script_carries_every_command_flag_and_group_word(env, shell):
    script = _script(env, shell)
    tokens = set(re.findall(r"[^\s'\"=();{}]+", script))
    for word in _expected_command_words() + _expected_flag_words() + PHASE_TITLES:
        assert word in tokens, word


def test_bash_script_registers_a_function_for_bughunt(env):
    script = _script(env, "bash")
    assert re.search(r"^complete -F \S+ bughunt\s*$", script, re.M)


def test_zsh_script_is_a_bare_compdef_body_not_wrapped_in_a_function(env):
    script = _script(env, "zsh")
    assert script.startswith("#compdef bughunt")
    assert not re.search(r"^\s*(?:function\s+)?_?bughunt\w*\s*\(\)\s*\{", script, re.M)
    assert not re.search(r"^\s*function\b", script, re.M)


def test_completion_flags_come_from_the_scan_parser_built_with_the_bare_program_name(
    env,
):
    env.activate()
    seen = []

    def spy(prog):
        seen.append(prog)
        return BUILD_PARSER(prog)

    assert cli.print_completion("bash", spy) == 0
    assert seen == ["bughunt"]


@pytest.mark.parametrize("shell", ["fish", "", "BASH", "powershell"])
def test_unsupported_shell_returns_2_and_writes_nothing_to_stdout(env, shell):
    env.activate()
    assert cli.print_completion(shell, BUILD_PARSER) == 2
    assert env.stdout_text == ""
    assert "bash" in env.rich_text and "zsh" in env.rich_text


@pytest.fixture(scope="module")
def git_bash():
    bash = find_git_bash()
    if bash is None:
        pytest.skip("no POSIX bash available to execute the completion function")
    return bash


def _bash_complete(git_bash, tmp_path, script: str, words: list[str]) -> list[str]:
    (tmp_path / "comp.sh").write_text(script, encoding="utf-8", newline="\n")
    function = re.search(r"^complete -F (\S+) bughunt", script, re.M).group(1)
    quoted = " ".join("'" + word.replace("'", "'\\''") + "'" for word in words)
    driver = textwrap.dedent(
        f"""
        source ./comp.sh
        COMP_WORDS=({quoted})
        COMP_CWORD=$(( ${{#COMP_WORDS[@]}} - 1 ))
        {function}
        printf '%s\\n' "${{COMPREPLY[@]}}"
        """
    )
    done = subprocess.run(
        [git_bash, "-c", driver.replace("\r", "")],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 0, done.stderr
    return [line for line in done.stdout.splitlines() if line]


def test_bash_function_completes_command_words_first(env, git_bash, tmp_path):
    script = _script(env, "bash")
    assert sorted(
        _bash_complete(git_bash, tmp_path, script, ["bughunt", ""])
    ) == sorted(_expected_command_words())
    assert _bash_complete(git_bash, tmp_path, script, ["bughunt", "sca"]) == ["scan"]
    assert "recon" in _bash_complete(git_bash, tmp_path, script, ["bughunt", "re"])


def test_bash_function_completes_group_titles_after_modules_and_commands(
    env, git_bash, tmp_path
):
    script = _script(env, "bash")
    for word in ("modules", "commands"):
        assert sorted(
            _bash_complete(git_bash, tmp_path, script, ["bughunt", word, ""])
        ) == sorted(PHASE_TITLES)
    assert _bash_complete(git_bash, tmp_path, script, ["bughunt", "modules", "Re"]) == [
        "Recon"
    ]


def test_bash_function_completes_shells_after_completion(env, git_bash, tmp_path):
    script = _script(env, "bash")
    assert sorted(
        _bash_complete(git_bash, tmp_path, script, ["bughunt", "completion", ""])
    ) == ["bash", "zsh"]


def test_bash_function_completes_phase_members_for_the_second_word(
    env, git_bash, tmp_path
):
    script = _script(env, "bash")
    for title, members in catalog.MODULE_GROUPS:
        got = _bash_complete(git_bash, tmp_path, script, ["bughunt", title.lower(), ""])
        assert sorted(got) == sorted(members), title


def test_bash_function_completes_scan_flags_for_dash_words(env, git_bash, tmp_path):
    script = _script(env, "bash")
    got = _bash_complete(git_bash, tmp_path, script, ["bughunt", "127.0.0.1", "--"])
    assert sorted(got) == sorted(
        flag for flag in _expected_flag_words() if flag.startswith("--")
    )
    assert _bash_complete(
        git_bash, tmp_path, script, ["bughunt", "127.0.0.1", "--por"]
    ) == ["--ports", "--ports-file"]


# --------------------------------------------------------------------------------------
# JSON on stdout: dispatch `catalog`
# --------------------------------------------------------------------------------------


def test_catalog_compact_is_exactly_the_compact_separators(env):
    assert run_dispatch(["catalog", "--compact"]) == 0
    text = env.stdout_text
    assert text.endswith("\n") and text.count("\n") == 1
    data = json.loads(text)
    assert text == json.dumps(data, separators=(",", ":")) + "\n"


@pytest.mark.parametrize("extra", [[], ["--compact", "--x"], ["--COMPACT"]])
def test_catalog_any_other_arguments_use_indent_2(env, extra):
    assert run_dispatch(["catalog", *extra]) == 0
    text = env.stdout_text
    data = json.loads(text)
    assert text == json.dumps(data, indent=2) + "\n"
    assert text.count("\n") > 100


def test_catalog_output_is_ascii_escaped_not_utf8(env):
    """Spec 11.15: ensure_ascii is kept; the em dash in readiness copy arrives as \\u2014."""
    assert run_dispatch(["catalog", "--compact"]) == 0
    text = env.stdout_text
    assert text.isascii()
    assert "\\u2014" in text
    assert "—" in json.loads(text)["readiness"]["next_step"]["message"]


def test_catalog_goes_to_stdout_not_the_rich_console(env):
    run_dispatch(["catalog", "--compact"])
    assert env.rich_text == ""
