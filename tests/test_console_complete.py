"""Characterization oracle for `bughunt.console.complete` (M2 clean-room rebuild, spec section 7).

`complete_line` is a pure function of (prefix, word, state), so it is driven directly with a
scratch working directory and a scratch workspace. History tests inject a fake `readline`
module (the real one is absent on Windows) so the save/load/limit rules stay pinned everywhere.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from bughunt.console import complete, options
from bughunt.console.complete import CompleteState, complete_line
from bughunt.core import workspace
from bughunt.modules import MODULES

from console_support import (  # noqa: F401  (env is a pytest fixture)
    BUILD_PARSER,
    SCANNER_FILE,
    TtyStdin,
    TtyText,
    env,
)

TITLES_SORTED = ["Capture", "Engagement", "Engines", "Intel", "Labs", "Recon", "Test"]


@pytest.fixture
def cwd(monkeypatch, tmp_path):
    """Scratch cwd with urls.txt, sub/a.txt, .hidden and Zed.txt; scratch workspace; scratch home."""
    work = tmp_path / "work"
    (work / "sub").mkdir(parents=True)
    (work / "urls.txt").write_text("x", encoding="utf-8")
    (work / "sub" / "a.txt").write_text("x", encoding="utf-8")
    (work / ".hidden").write_text("x", encoding="utf-8")
    (work / "Zed.txt").write_text("x", encoding="utf-8")
    home = tmp_path / "home"
    (home / "projects").mkdir(parents=True)
    (home / "notes.txt").write_text("x", encoding="utf-8")
    monkeypatch.chdir(work)
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "workspace"))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    return work


def lines(
    prefix: str, word: str, *, active=None, saved=None, build_parser=BUILD_PARSER
) -> list[str]:
    state = CompleteState(SCANNER_FILE, build_parser, dict(saved or {}))
    state.active = active
    return complete_line(prefix, word, state)


# --------------------------------------------------------------------------------------
# 7.1 constants and small helpers
# --------------------------------------------------------------------------------------


def test_console_commands_are_the_sixteen_in_order():
    assert tuple(complete.CONSOLE_COMMANDS) == (
        "help",
        "show",
        "use",
        "set",
        "unset",
        "run",
        "back",
        "banner",
        "doctor",
        "version",
        "examples",
        "modules",
        "search",
        "history",
        "exit",
        "quit",
    )


def test_module_names_are_scan_then_modules_then_each_reference_with_its_aliases():
    names = complete.module_names()
    assert len(names) == 50
    assert names[0] == "scan"
    assert names[1 : 1 + len(MODULES)] == list(MODULES)
    assert names[1 + len(MODULES) :] == [
        "pulse",
        "ct",
        "crt-scout",
        "carve",
        "flowcarve",
        "phish",
        "lanternjaw",
        "ioc",
        "iocaw",
        "chroma",
        "chromahaus",
        "urlscan",
        "tcurl",
        "skiff",
    ]


SENSITIVE = [
    "set cookie abc",
    "set TOKEN x",
    "run --api-key=1",
    "Authorization: x",
    "eyJhbGci",
    "PASSWORD",
    "apikey",
    "api_key=1",
    "API-KEY",
    "my secret thing",
    "Set-Cookie: a",
    "xEYJx",
    "bearer token here",
    "set Password hunter2",
]
NOT_SENSITIVE = [
    "use pulse",
    "set concurrency 5",
    "show options",
    "",
    "modules recon",
    "run http://127.0.0.1/",
    "apikeyless"[:3],
]


@pytest.mark.parametrize("line", SENSITIVE)
def test_sensitive_line_matches_credential_words_anywhere_case_insensitively(line):
    assert complete.sensitive_line(line) is True


@pytest.mark.parametrize("line", NOT_SENSITIVE)
def test_sensitive_line_leaves_ordinary_lines_alone(line):
    assert complete.sensitive_line(line) is False


def test_suggest_console_vectors():
    assert complete.suggest_console("shw") == "show"
    assert complete.suggest_console("usee") == "use"
    assert complete.suggest_console("hlp") == "help"
    assert complete.suggest_console("exti") is None
    assert complete.suggest_console("zzzzzz") is None
    assert (
        complete.suggest_console("show") == "show"
    )  # an exact command is its own best match
    assert complete.suggest_console("?") is None


@pytest.mark.parametrize(
    "match,only,expected",
    [
        ("pulse", True, "pulse "),
        ("pulse", False, "pulse"),
        ("sub/", True, "sub/"),
        ("sub/", False, "sub/"),
        ("", True, ""),
        ("", False, ""),
        ("a.txt", True, "a.txt "),
    ],
)
def test_presented_match_adds_a_space_only_for_a_finished_single_match(
    match, only, expected
):
    assert complete.presented_match(match, only) == expected


# --------------------------------------------------------------------------------------
# history_path / save_history / load_history
# --------------------------------------------------------------------------------------


def test_history_path_defaults_under_the_home_directory(monkeypatch, tmp_path):
    monkeypatch.delenv("BUGHUNT_HISTORY", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert (
        complete.history_path() == tmp_path / ".local" / "share" / "bughunt" / "history"
    )


def test_history_path_env_override_is_expanded(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("BUGHUNT_HISTORY", "~/hist.txt")
    assert complete.history_path() == tmp_path / "hist.txt"


@pytest.mark.parametrize("blank", ["", "   ", "\t "])
def test_history_path_ignores_a_blank_override(monkeypatch, tmp_path, blank):
    monkeypatch.setenv("BUGHUNT_HISTORY", blank)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    assert (
        complete.history_path() == tmp_path / ".local" / "share" / "bughunt" / "history"
    )


def test_save_history_writes_kept_lines_with_a_trailing_newline(tmp_path):
    target = tmp_path / "deep" / "er" / "history"
    complete.save_history(
        target,
        ["use pulse", "", "set cookie abc", "run", "set TOKEN x", "show options"],
    )
    assert target.read_text(encoding="utf-8") == "use pulse\nrun\nshow options\n"


def test_save_history_with_nothing_to_keep_writes_an_empty_file(tmp_path):
    target = tmp_path / "history"
    complete.save_history(target, ["", "set cookie a"])
    assert target.read_text(encoding="utf-8") == ""


def test_save_history_keeps_only_the_last_thousand_lines(tmp_path):
    target = tmp_path / "history"
    candidates = [f"line {n}" for n in range(1104)]
    complete.save_history(target, candidates)
    stored = target.read_text(encoding="utf-8").splitlines()
    assert len(stored) == 1000
    assert stored[0] == "line 104" and stored[-1] == "line 1103"


def test_save_history_limit_applies_after_dropping_sensitive_and_blank_lines(tmp_path):
    target = tmp_path / "history"
    candidates = []
    for n in range(1200):
        candidates.append(f"keep {n}")
        candidates.append("set cookie nope")
        candidates.append("")
    complete.save_history(target, candidates)
    stored = target.read_text(encoding="utf-8").splitlines()
    assert stored[0] == "keep 200" and stored[-1] == "keep 1199" and len(stored) == 1000


def test_save_history_ignores_os_errors(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x", encoding="utf-8")
    complete.save_history(
        blocker / "history", ["use pulse"]
    )  # parent is a file: must not raise


def test_save_history_writes_utf8(tmp_path):
    target = tmp_path / "history"
    complete.save_history(target, ["search caf\u00e9"])
    stored = target.read_bytes().decode("utf-8")
    assert stored.replace("\r\n", "\n") == "search caf\u00e9\n"


@pytest.fixture
def fake_readline(monkeypatch):
    module = types.ModuleType("readline")
    module.added = []
    module.add_history = module.added.append
    monkeypatch.setitem(sys.modules, "readline", module)
    return module


def test_load_history_returns_kept_lines_and_feeds_readline(tmp_path, fake_readline):
    target = tmp_path / "history"
    target.write_text(
        "use pulse\n\nset cookie abc\nrun\nTOKEN x\nshow options\n", encoding="utf-8"
    )
    loaded = complete.load_history(target)
    assert loaded == ["use pulse", "run", "show options"]
    assert fake_readline.added == ["use pulse", "run", "show options"]


def test_load_history_keeps_the_last_thousand_lines(tmp_path, fake_readline):
    target = tmp_path / "history"
    target.write_text("".join(f"line {n}\n" for n in range(1104)), encoding="utf-8")
    loaded = complete.load_history(target)
    assert len(loaded) == 1000 and loaded[0] == "line 104" and loaded[-1] == "line 1103"
    assert fake_readline.added == loaded


def test_load_history_for_a_missing_file_is_empty(tmp_path, fake_readline):
    assert complete.load_history(tmp_path / "nope") == []
    assert fake_readline.added == []


def test_load_history_replaces_undecodable_bytes(tmp_path, fake_readline):
    target = tmp_path / "history"
    target.write_bytes(b"ok line\nbad \xff\xfe line\n")
    loaded = complete.load_history(target)
    assert loaded[0] == "ok line" and len(loaded) == 2 and loaded[1].startswith("bad ")


def test_load_history_needs_readline(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "readline", None)
    with pytest.raises(ImportError):
        complete.load_history(tmp_path / "history")


def test_history_round_trips(tmp_path, fake_readline):
    target = tmp_path / "history"
    complete.save_history(target, ["use pulse", "set cookie a", "run -x"])
    assert complete.load_history(target) == ["use pulse", "run -x"]


# --------------------------------------------------------------------------------------
# CompleteState and install_reader
# --------------------------------------------------------------------------------------


def test_complete_state_attributes():
    settings = {"scan": {"PORTS": "80"}}
    state = CompleteState(SCANNER_FILE, BUILD_PARSER, settings)
    assert (
        state.tool_file == SCANNER_FILE
        and state.build_parser is BUILD_PARSER
        and state.settings is settings
    )
    assert state.active is None
    state.active = "scan"
    assert state.active == "scan"


def test_complete_state_spec_loads_caches_and_degrades_to_none(monkeypatch):
    from bughunt.console import options

    calls = []
    real = options.load_spec

    def counting(name, **kwargs):
        calls.append(name)
        return real(name, **kwargs)

    monkeypatch.setattr(complete, "load_spec", counting)
    monkeypatch.setattr(options, "DISABLED_REFERENCES", frozenset({"skiff"}))
    state = CompleteState(SCANNER_FILE, BUILD_PARSER, {})
    first = state.spec("scan")
    assert first is not None and first.options
    assert state.spec("scan") is first
    assert calls == ["scan"]
    assert state.spec("") is None and state.spec(None) is None
    assert state.spec("skiff") is None  # SpecError -> None
    assert calls[:1] == ["scan"]


def _install(monkeypatch, *, stdin_tty=True, stdout_tty=True):
    monkeypatch.setattr(sys, "stdin", TtyStdin() if stdin_tty else sys.stdin)
    monkeypatch.setattr(sys, "stdout", TtyText() if stdout_tty else sys.stdout)
    return CompleteState(SCANNER_FILE, BUILD_PARSER, {})


@pytest.mark.parametrize(
    "stdin_tty,stdout_tty", [(False, True), (True, False), (False, False)]
)
def test_install_reader_needs_both_streams_to_be_terminals(
    monkeypatch, fake_readline, stdin_tty, stdout_tty
):
    state = _install(monkeypatch, stdin_tty=stdin_tty, stdout_tty=stdout_tty)
    assert complete.install_reader(state) is None


def test_install_reader_needs_readline(monkeypatch):
    monkeypatch.setitem(sys.modules, "readline", None)
    state = _install(monkeypatch)
    assert complete.install_reader(state) is None


def test_install_reader_configures_readline_and_returns_input(monkeypatch, cwd):
    module = types.ModuleType("readline")
    module.completer = None
    module.delims = None
    module.bindings = []
    module.buffer = ""
    module.begin = 0
    module.auto_history = True
    module.set_completer = lambda fn: setattr(module, "completer", fn)
    module.set_completer_delims = lambda delims: setattr(module, "delims", delims)
    module.parse_and_bind = module.bindings.append
    module.get_line_buffer = lambda: module.buffer
    module.get_begidx = lambda: module.begin
    module.set_auto_history = lambda flag: setattr(module, "auto_history", flag)
    monkeypatch.setitem(sys.modules, "readline", module)
    state = _install(monkeypatch)
    reader = complete.install_reader(state)
    import builtins

    assert reader is builtins.input
    assert module.delims == " \t\n"
    assert "tab: complete" in module.bindings
    assert module.auto_history is False
    module.buffer, module.begin = "use pu", 4
    assert (
        module.completer("pu", 0) == "pulse "
    )  # the only match: finished word gets a space
    assert module.completer("pu", 1) is None
    module.buffer, module.begin = "pulse su", 6
    assert module.completer("su", 0) == "sub/"  # a directory keeps no trailing space
    module.buffer, module.begin = "use p", 4
    first = [module.completer("p", i) for i in range(5)]
    assert first == [
        "phish",
        "policy",
        "pulse",
        None,
        None,
    ]  # several matches: no spaces


def test_install_reader_completer_swallows_errors(monkeypatch):
    module = types.ModuleType("readline")
    module.set_completer = lambda fn: setattr(module, "completer", fn)
    module.set_completer_delims = lambda delims: None
    module.parse_and_bind = lambda text: None
    module.get_line_buffer = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    module.get_begidx = lambda: 0
    monkeypatch.setitem(sys.modules, "readline", module)
    state = _install(monkeypatch)
    assert complete.install_reader(state) is not None
    assert module.completer("x", 0) is None


# --------------------------------------------------------------------------------------
# 7.2 complete_line: the spec vectors (12.2) and the rules around them
# --------------------------------------------------------------------------------------

SPEC_VECTORS = [
    ("", "us", None, None, ["use"]),
    ("use ", "p", None, None, ["phish", "policy", "pulse"]),
    ("show modules ", "", None, None, TITLES_SORTED),
    ("pulse ", "--c", None, None, ["--concurrency", "--csv"]),
    ("pulse ", "u", None, None, ["urls.txt"]),
    ("pulse ", "sub", None, None, ["sub/"]),
    ("pulse ", "./", None, None, ["./sub/", "./urls.txt", "./Zed.txt"]),
    ("scan --method ", "", None, None, ["GET", "HEAD", "OPTIONS", "POST"]),
    ("scan ", "--method=P", None, None, ["--method=POST"]),
    ("set ", "po", "scan", None, ["PORT_RANGE", "PORTS", "PORTS_FILE"]),
    ("set intel ", "", "scan", None, ["false", "true"]),
    ("set ", "intel=t", "scan", None, ["intel=true"]),
    (
        "unset ",
        "",
        "scan",
        {"scan": {"PORTS": "80", "INTEL": "true"}},
        ["all", "INTEL", "PORTS"],
    ),
    ("policy ", "", None, None, ["check", "example", "import", "status", "validate"]),
    (
        "policy check ",
        "--",
        None,
        None,
        ["--callback-domain", "--file", "--method", "--operation"],
    ),
    ("bogus ", "x", None, None, []),
    ("pulse 'unbalanced ", "x", None, None, []),
]


@pytest.mark.parametrize(
    "prefix,word,active,saved,expected",
    SPEC_VECTORS,
    ids=[f"{v[0]}|{v[1]}" for v in SPEC_VECTORS],
)
def test_complete_line_spec_vectors(cwd, prefix, word, active, saved, expected):
    assert lines(prefix, word, active=active, saved=saved) == expected


def test_first_word_offers_commands_and_module_names_without_the_question_mark(cwd):
    everything = lines("", "")
    assert len(everything) == 66 == len(set(everything))
    assert everything == sorted(everything, key=str.lower)
    assert "?" not in everything
    assert "help" in everything and "pulse" in everything and "crt-scout" in everything
    assert lines("", "?") == []
    assert lines("   ", "he") == ["help"]  # a blank prefix means no earlier tokens


def test_first_word_filter_is_case_insensitive(cwd):
    assert lines("", "HE") == ["help"]
    assert lines("", "SC") == ["scan", "scope"]


def test_use_and_search_offer_module_names(cwd):
    assert lines("use ", "") == sorted(complete.module_names(), key=str.lower)
    assert lines("use ", "PU") == ["pulse"]
    assert lines("search ", "crt") == ["crt-scout"]
    assert lines("use pulse ", "") == []
    assert lines("search pulse ", "") == []


def test_show_offers_modules_and_options_then_group_titles(cwd):
    assert lines("show ", "") == ["modules", "options"]
    assert lines("show ", "m") == ["modules"]
    assert lines("show module ", "r") == ["Recon"]
    assert lines("show MODULES ", "") == TITLES_SORTED
    assert lines("show options ", "") == []
    assert lines("show modules recon ", "") == []


def test_modules_and_commands_offer_group_titles_once(cwd):
    assert lines("modules ", "e") == ["Engagement", "Engines"]
    assert lines("commands ", "") == TITLES_SORTED
    assert lines("modules recon ", "") == []


def test_set_needs_an_active_module_with_a_spec(cwd, monkeypatch):
    monkeypatch.setattr(options, "DISABLED_REFERENCES", frozenset({"skiff"}))
    assert lines("set ", "") == []
    assert lines("set ", "", active="skiff") == []


def test_set_offers_option_names_matching_names_or_flags(cwd):
    assert lines("set ", "ra", active="scan") == [
        "PORT_RANGE",
        "RANDOM_AGENT",
    ]  # via --range, --random-agent
    assert lines("set ", "--po", active="scan") == ["PORT_RANGE", "PORTS", "PORTS_FILE"]
    assert lines("set ", "-l", active="scan") == [
        "TARGETS_FILE"
    ]  # normalised: the flag -l is L
    everything = lines("set ", "", active="scan")
    assert len(everything) == 60 and everything == sorted(everything, key=str.lower)
    assert "VERSION" not in everything


def test_set_completes_values_for_the_named_option(cwd):
    assert lines("set method ", "h", active="scan") == ["HEAD"]
    assert lines("set METHOD ", "", active="scan") == ["GET", "HEAD", "OPTIONS", "POST"]
    assert lines("set intel ", "t", active="scan") == ["true"]
    assert lines("set ports ", "", active="scan") == []
    assert lines("set ports-file ", "u", active="scan") == [
        "urls.txt"
    ]  # a *_FILE option asks for paths
    assert lines("set nope ", "", active="scan") == []
    assert (
        lines("set method head ", "", active="scan") == []
    )  # a third token has nothing to complete


def test_set_equals_form_completes_the_value_and_keeps_the_typed_name(cwd):
    assert lines("set ", "method=", active="scan") == [
        "method=GET",
        "method=HEAD",
        "method=OPTIONS",
        "method=POST",
    ]
    assert lines("set ", "METHOD=p", active="scan") == ["METHOD=POST"]
    assert lines("set ", "nope=x", active="scan") == []


def test_unset_offers_saved_names_and_all(cwd):
    assert lines("unset ", "", active="scan") == ["all"]
    assert lines("unset ", "", active=None) == ["all"]
    assert lines(
        "unset ", "p", active="scan", saved={"scan": {"PORTS": "1", "PATHS": "/"}}
    ) == ["PATHS", "PORTS"]
    assert (
        lines("unset ports ", "", active="scan", saved={"scan": {"PORTS": "1"}}) == []
    )


def test_run_completes_arguments_for_the_active_module(cwd):
    assert lines("run ", "--c", active="pulse") == ["--concurrency", "--csv"]
    assert lines("run ", "u", active="pulse") == ["urls.txt"]
    assert lines("run --method ", "", active="scan") == [
        "GET",
        "HEAD",
        "OPTIONS",
        "POST",
    ]


def test_run_without_a_module_only_offers_paths_for_a_typed_word(cwd):
    assert lines("run ", "--", active=None) == []
    assert lines("run ", "", active=None) == []
    assert lines("run ", "u", active=None) == ["urls.txt"]


def test_module_heads_and_aliases_complete_their_arguments(cwd, monkeypatch):
    monkeypatch.setattr(options, "DISABLED_REFERENCES", frozenset({"skiff"}))
    assert lines("crt-scout ", "--") == lines("ct ", "--") != []
    assert lines("scan ", "--po") == ["--ports", "--ports-file"]
    assert lines("scan ", "--PO") == []  # flag matching after "-" is case-sensitive
    assert lines("skiff ", "--") == []  # disabled -> no spec -> flags offer nothing


def test_empty_word_offers_only_long_flags_and_dash_offers_every_flag(cwd):
    long_only = lines("pulse ", "")
    assert long_only and all(flag.startswith("--") for flag in long_only)
    everything = lines("pulse ", "-")
    assert set(long_only) <= set(everything)
    assert any(not flag.startswith("--") for flag in everything)
    assert everything == sorted(everything, key=str.lower)


def test_value_flag_then_word_completes_the_flags_values(cwd):
    assert lines("scan --method ", "p") == ["POST"]
    assert lines("scan -l ", "u") == ["urls.txt"]
    assert lines("pulse -c ", "5") == []  # a plain value option has nothing to offer
    assert (
        lines("scan --dry-run ", "x") == []
    )  # a switch takes no value: falls through to paths


def test_bool_flag_values_are_true_and_false(cwd):
    assert lines("scan ", "--intel=t") == ["--intel=true"]
    assert lines("scan ", "--intel=") == ["--intel=false", "--intel=true"]


def test_equals_form_for_an_unknown_flag_offers_nothing(cwd):
    assert lines("scan ", "--bogus=x") == []


def test_subcommands_are_offered_until_one_is_chosen(cwd):
    assert lines("policy ", "s") == ["status"]
    assert lines("policy xyz ", "") == [
        "check",
        "example",
        "import",
        "status",
        "validate",
    ]
    assert (
        lines("policy ", "-") == []
    )  # subcommand-scoped flags stay hidden until a command is chosen


def test_subcommand_flags_follow_the_command_in_argv_or_the_saved_command(cwd):
    flags = ["--callback-domain", "--file", "--method", "--operation"]
    assert lines("policy check ", "") == flags
    assert lines("policy ", "--", saved={"policy": {"COMMAND": "check"}}) == flags
    assert (
        lines("run ", "--", active="policy", saved={"policy": {"COMMAND": "check"}})
        == flags
    )
    assert lines("policy status ", "--") == ["--file"]


def test_unknown_heads_and_extra_tokens_offer_nothing(cwd):
    assert lines("bogus ", "") == []
    assert lines("exit ", "") == []
    assert lines("help ", "x") == []
    assert lines("history ", "") == []


def test_unbalanced_quote_in_the_prefix_means_no_completions(cwd):
    assert lines('use "pul', "") == []
    assert lines("pulse 'x ", "-") == []


def test_windows_directory_with_a_trailing_slash_keeps_completion_available(
    cwd, monkeypatch
):
    monkeypatch.setattr(options, "sys", types.SimpleNamespace(platform="win32"))
    assert "--paths-file" in lines('scan "C:\\Temp\\" ', "--pa")


# saved-file name completion (diff / clutch show) ------------------------------------------


@pytest.fixture
def workspace_files(cwd):
    responses = workspace.responses_dir()
    requests = workspace.requests_dir()
    responses.mkdir(parents=True)
    requests.mkdir(parents=True)
    for name in ("b-resp.http", "A-resp.http", ".hidden-resp"):
        (responses / name).write_text("x", encoding="utf-8")
    (responses / "nested").mkdir()
    for name in ("req-1.http", "req-2.http"):
        (requests / name).write_text("x", encoding="utf-8")
    return responses, requests


def test_diff_offers_saved_response_names(workspace_files):
    assert lines("diff ", "") == [
        "A-resp.http",
        "b-resp.http",
    ]  # regular, non-hidden files, any case order
    assert lines("diff ", "b") == ["b-resp.http"]
    assert lines("diff a.http ", "A") == ["A-resp.http"]


def test_clutch_show_offers_saved_request_names(workspace_files):
    assert lines("clutch show ", "") == ["req-1.http", "req-2.http"]
    assert lines("clutch show ", "req-2") == ["req-2.http"]


def test_saved_names_are_not_offered_for_an_explicit_path_or_other_modules(
    workspace_files,
):
    assert lines("diff ", "./") == ["./sub/", "./urls.txt", "./Zed.txt"]
    assert lines("diff ", "sub/") == ["sub/a.txt"]
    assert "req-1.http" not in lines("clutch ", "")
    assert lines("pulse ", "req") == []


def test_saved_names_fall_back_to_long_flags_when_the_directory_is_missing_or_empty(
    cwd,
):
    offered = lines("diff ", "")
    assert offered and all(flag.startswith("--") for flag in offered)


# path completions -------------------------------------------------------------------------


def test_paths_hide_dotfiles_unless_the_partial_starts_with_a_dot(cwd):
    assert ".hidden" not in lines("pulse ", "./")
    assert lines("pulse ", ".h") == [".hidden"]
    assert lines("pulse ", "./.h") == ["./.hidden"]


def test_paths_sort_case_insensitively_and_mark_directories(cwd):
    assert lines("pulse ", "./") == ["./sub/", "./urls.txt", "./Zed.txt"]
    assert lines("pulse ", "su") == ["sub/"]
    assert lines("pulse ", "SU") == []  # partial names match case-sensitively on disk


def test_paths_into_a_subdirectory_keep_the_typed_prefix(cwd):
    assert lines("pulse ", "sub/") == ["sub/a.txt"]
    assert lines("pulse ", "sub/a") == ["sub/a.txt"]
    assert lines("pulse ", "./su") == ["./sub/"]


def test_paths_that_do_not_exist_complete_to_nothing(cwd):
    assert lines("pulse ", "nope/") == []
    assert lines("pulse ", "nonexistent") == []


def test_absolute_paths_stay_absolute(cwd):
    typed = (cwd / "su").as_posix()
    found = lines("pulse ", typed)
    assert [Path(item) for item in found] == [cwd / "sub"]
    assert found[0].replace("\\", "/").endswith("/sub/")
    folder = cwd.as_posix() + "/"
    assert sorted(Path(item).name for item in lines("pulse ", folder)) == [
        "Zed.txt",
        "sub",
        "urls.txt",
    ]


def test_home_relative_paths_keep_the_tilde_prefix(cwd):
    assert lines("pulse ", "~/pro") == ["~/projects/"]
    assert lines("pulse ", "~/n") == ["~/notes.txt"]


def test_dotdot_paths_are_kept_as_typed(cwd):
    assert lines("pulse ", "../w") == ["../work/"]
