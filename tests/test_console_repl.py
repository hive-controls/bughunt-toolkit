"""Characterization oracle for `bughunt.console.console` (M2 clean-room rebuild, spec section 6).

The typed console is driven through its injectable seams (`read_line`, `run_module`,
`merge_argv`) so no module ever runs. Output wording is FREE and mostly not asserted; the
grammar, state transitions, prompt rules, banner selection and echo/exit-code lines are.
"""

from __future__ import annotations

import builtins
import re
import shlex
import sys
import types

import pytest

from bughunt import VERSION
from bughunt.console import catalog, complete, guide, options, readiness, ui
from bughunt.console import console as repl
from bughunt.modules import MODULES

from console_support import (  # noqa: F401  (env is a pytest fixture)
    BUILD_PARSER,
    SCANNER_FILE,
    TtyText,
    env,
    forbidden_scan,
    make_project,
    run_session,
)

TITLES = ["Engagement", "Recon", "Capture", "Test", "Labs", "Engines", "Intel"]


@pytest.fixture(autouse=True)
def plain_prompt(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")


def history_numbers(text: str) -> list[tuple[int, str]]:
    found = []
    for line in text.splitlines():
        match = re.match(r"^\s*(\d+)\s{2}(.*)$", line)
        if match:
            found.append((int(match.group(1)), match.group(2)))
    return found


# --------------------------------------------------------------------------------------
# 6.1 run_console: loop mechanics
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("leave", ["exit", "quit"])
def test_exit_and_quit_leave_with_zero(env, leave):
    session = run_session(env, [leave, "version"])
    assert session.rc == 0
    assert len(session.prompts) == 1


def test_end_of_input_leaves_with_zero_and_prints_a_blank_line(env):
    session = run_session(env, [EOFError()])
    assert session.rc == 0
    assert session.chunk(0) == "\n"


def test_running_out_of_scripted_lines_is_end_of_input(env):
    assert run_session(env, ["version"]).rc == 0


def test_a_none_line_leaves_with_zero(env):
    session = run_session(env, [None, "version"])
    assert session.rc == 0 and len(session.prompts) == 1


def test_keyboard_interrupt_prints_a_hint_and_keeps_going(env):
    session = run_session(env, [KeyboardInterrupt(), "version", "exit"])
    assert session.rc == 0
    assert "exit" in session.chunk(0)
    assert f"Bughunt {VERSION}" in session.chunk(1)


def test_blank_and_comment_lines_are_ignored_and_not_remembered(env):
    session = run_session(
        env,
        [
            "",
            "   ",
            "# a comment",
            "  # indented comment",
            "version",
            "history",
            "exit",
        ],
    )
    assert history_numbers(session.chunk(5)) == [(1, "version")]
    assert (
        session.chunk(0)
        == session.chunk(1)
        == session.chunk(2)
        == session.chunk(3)
        == ""
    )


def test_an_unparseable_line_reports_the_error_and_is_not_remembered(env):
    session = run_session(env, ["use 'unbalanced", "version", "history", "exit"])
    assert "parse" in session.chunk(0).lower()
    assert history_numbers(session.chunk(2)) == [(1, "version")]


def test_lines_are_split_with_shell_quoting_rules(env):
    session = run_session(env, ["pulse 'a b' \"c d\" e\\ f", "exit"])
    assert session.runner_calls == [("pulse", ["a b", "c d", "e f"])]


@pytest.mark.parametrize(
    "typed,expected",
    [
        (r"C:\Temp\paths.txt", r"C:\Temp\paths.txt"),
        ('"C:\\Temp Folder\\paths.txt"', r"C:\Temp Folder\paths.txt"),
        ('"C:\\Temp Folder\\"', "C:\\Temp Folder\\"),
        (r"\\server\share\paths.txt", r"\\server\share\paths.txt"),
        ('"\\\\server\\shared folder\\paths.txt"', r"\\server\shared folder\paths.txt"),
        ("C:/Temp/paths.txt", "C:/Temp/paths.txt"),
    ],
)
def test_windows_paths_reach_the_runner_unchanged(env, monkeypatch, typed, expected):
    monkeypatch.setattr(
        options, "sys", types.SimpleNamespace(platform="win32"), raising=False
    )
    session = run_session(
        env, [f"scan 127.0.0.1 --paths-file {typed} --dry-run", "exit"]
    )
    assert session.runner_calls == [
        ("scan", ["127.0.0.1", "--paths-file", expected, "--dry-run"])
    ]


def test_windows_paths_work_in_saved_and_explicit_equals_options(env, monkeypatch):
    monkeypatch.setattr(
        options, "sys", types.SimpleNamespace(platform="win32"), raising=False
    )
    session = run_session(
        env,
        [
            "use pulse",
            r"set FILE C:\Temp\urls.txt",
            "run",
            r"scan --paths-file=C:\Temp\paths.txt",
            "exit",
        ],
    )
    assert session.runner_calls == [
        ("pulse", [r"C:\Temp\urls.txt"]),
        ("scan", [r"--paths-file=C:\Temp\paths.txt"]),
    ]


def test_history_command_without_history_says_so(env):
    session = run_session(env, ["history", "exit"])
    assert session.chunk(0).strip()
    assert history_numbers(session.chunk(0)) == []


def test_history_numbers_are_absolute_and_limited_to_the_last_forty(env):
    session = run_session(env, ["version"] * 45 + ["history", "exit"])
    shown = history_numbers(session.chunk(45))
    assert [n for n, _ in shown] == list(range(6, 46))
    assert {line for _, line in shown} == {"version"}


def test_history_keeps_the_raw_stripped_line_and_skips_sensitive_ones(env):
    session = run_session(
        env,
        ["  use pulse  ", "set COOKIE hunter2", "set FILE urls.txt", "history", "exit"],
    )
    assert history_numbers(session.chunk(3)) == [
        (1, "use pulse"),
        (2, "set FILE urls.txt"),
    ]


def test_history_shows_markup_characters_literally(env):
    session = run_session(env, ["search [bold]x[/bold]", "history", "exit"])
    assert history_numbers(session.chunk(1)) == [(1, "search [bold]x[/bold]")]


# --------------------------------------------------------------------------------------
# 6.3 prompt
# --------------------------------------------------------------------------------------


def test_plain_prompt_shows_the_active_module(env):
    session = run_session(
        env, ["use pulse", "use crt-scout", "back", "use scan", "exit"]
    )
    assert session.prompts == [
        "Bughunt > ",
        "Bughunt pulse > ",
        "Bughunt ct > ",
        "Bughunt > ",
        "Bughunt scan > ",
    ]


def test_prompt_marks_a_running_job_before_the_arrow(env, monkeypatch):
    from bughunt.modules import snare

    monkeypatch.setattr(snare, "job_tag", lambda: "snare:8080")
    monkeypatch.setattr(snare, "stop_listener", lambda **kwargs: 0)
    session = run_session(env, ["use pulse", "exit"])
    assert session.prompts == [
        "Bughunt [snare:8080] > ",
        "Bughunt pulse [snare:8080] > ",
    ]


def _colored_prompts(env, monkeypatch, *, term, no_color, tty):
    env.activate()
    monkeypatch.delenv("NO_COLOR", raising=False)
    if no_color:
        monkeypatch.setenv("NO_COLOR", "1")
    if term is None:
        monkeypatch.delenv("TERM", raising=False)
    else:
        monkeypatch.setenv("TERM", term)
    if tty:
        monkeypatch.setattr(sys, "stdout", TtyText())
    return run_session(env, ["use pulse", "exit"]).prompts


ANSI_MARKERS = re.compile(r"\x01\x1b\[[0-9;]*m\x02")


def test_prompt_is_colored_only_on_a_terminal_with_a_real_term_and_no_no_color(
    env, monkeypatch
):
    prompts = _colored_prompts(
        env, monkeypatch, term="xterm-256color", no_color=False, tty=True
    )
    assert prompts[0] != "Bughunt > " and prompts[1] != "Bughunt pulse > "
    assert "\x01" in prompts[0] and "\x1b[" in prompts[0] and "\x02" in prompts[0]
    assert ANSI_MARKERS.sub("", prompts[0]) == "Bughunt > "
    assert ANSI_MARKERS.sub("", prompts[1]) == "Bughunt pulse > "


@pytest.mark.parametrize(
    "term,no_color,tty",
    [
        ("xterm", True, True),
        ("dumb", False, True),
        ("", False, True),
        (None, False, True),
        ("xterm", False, False),
    ],
    ids=["NO_COLOR", "TERM=dumb", "TERM=empty", "TERM-unset", "not-a-tty"],
)
def test_prompt_stays_plain_otherwise(env, monkeypatch, term, no_color, tty):
    prompts = _colored_prompts(env, monkeypatch, term=term, no_color=no_color, tty=tty)
    assert prompts == ["Bughunt > ", "Bughunt pulse > "]


def test_colored_prompt_marks_the_job_tag_too(env, monkeypatch):
    from bughunt.modules import snare

    monkeypatch.setattr(snare, "job_tag", lambda: "snare:9")
    monkeypatch.setattr(snare, "stop_listener", lambda **kwargs: 0)
    prompts = _colored_prompts(env, monkeypatch, term="xterm", no_color=False, tty=True)
    assert ANSI_MARKERS.sub("", prompts[0]) == "Bughunt [snare:9] > "


# --------------------------------------------------------------------------------------
# startup and shutdown wiring (snare redraw hook, history)
# --------------------------------------------------------------------------------------


@pytest.fixture
def snare_spy(monkeypatch):
    from bughunt.modules import snare

    spy = types.SimpleNamespace(attached=[], stops=[], tag="")
    monkeypatch.setattr(
        snare, "attach_console", lambda redraw: spy.attached.append(redraw)
    )
    monkeypatch.setattr(
        snare, "stop_listener", lambda **kwargs: spy.stops.append(kwargs) or 0
    )
    monkeypatch.setattr(snare, "job_tag", lambda: spy.tag)
    return spy


def test_snare_redraw_hook_is_attached_then_detached_and_the_listener_stopped_quietly(
    env, snare_spy
):
    run_session(env, ["exit"])
    assert len(snare_spy.attached) == 2
    assert callable(snare_spy.attached[0]) and snare_spy.attached[1] is None
    assert snare_spy.stops == [{"quiet": True}]


def test_a_live_job_is_stopped_loudly_on_exit(env, snare_spy):
    snare_spy.tag = "snare:8080"
    run_session(env, ["exit"])
    assert snare_spy.stops == [{}]


def test_shutdown_runs_even_when_the_reader_blows_up(env, snare_spy):
    from console_support import run_session as drive

    with pytest.raises(RuntimeError, match="reader exploded"):
        drive(env, [RuntimeError("reader exploded")])
    assert snare_spy.attached[-1] is None and len(snare_spy.stops) == 1


def test_the_redraw_hook_prints_a_line_to_stdout_when_not_interactive(env, snare_spy):
    run_session(env, ["exit"])
    snare_spy.attached[0]("job says hi")
    assert env.stdout_text == "job says hi\n"


def test_history_is_loaded_and_saved_only_when_a_line_reader_was_installed(
    env, monkeypatch, tmp_path
):
    readline = types.ModuleType("readline")
    readline.added = []
    readline.add_history = readline.added.append
    monkeypatch.setitem(sys.modules, "readline", readline)
    history = tmp_path / "history"
    history.write_text(
        "old command\nset cookie nope\nolder command\n", encoding="utf-8"
    )
    monkeypatch.setenv("BUGHUNT_HISTORY", str(history))
    lines = iter(["version", "set TOKEN x", "history", "exit"])
    prompts = []

    def scripted_input(prompt=""):
        prompts.append(prompt)
        return next(lines)

    def fake_install(state):
        return scripted_input

    # whichever binding the console uses for the installer, one of these takes effect
    monkeypatch.setattr(complete, "install_reader", fake_install)
    monkeypatch.setattr(repl, "install_reader", fake_install, raising=False)
    env.activate()
    rc = repl.run_console(
        tool_file=SCANNER_FILE, scan_main=forbidden_scan, build_parser=BUILD_PARSER
    )
    assert rc == 0
    assert prompts[0] == "Bughunt > "
    shown = history_numbers(env.rich_text)
    assert shown == [
        (1, "old command"),
        (2, "older command"),
        (3, "version"),
    ]  # preloaded, then this session
    # every accepted, non-sensitive line is remembered, `exit` included
    assert readline.added == [
        "old command",
        "older command",
        "version",
        "history",
        "exit",
    ]
    saved = history.read_text(encoding="utf-8").splitlines()
    assert saved == ["old command", "older command", "version", "history", "exit"]


def test_without_an_installed_reader_the_builtin_input_is_used_and_history_is_untouched(
    env, monkeypatch, tmp_path
):
    history = tmp_path / "history"
    history.write_text("keep me\n", encoding="utf-8")
    monkeypatch.setenv("BUGHUNT_HISTORY", str(history))
    lines = iter(["version", "exit"])
    monkeypatch.setattr(builtins, "input", lambda prompt="": next(lines))
    monkeypatch.setattr(complete, "install_reader", lambda state: None)
    monkeypatch.setattr(repl, "install_reader", lambda state: None, raising=False)
    env.activate()
    assert (
        repl.run_console(
            tool_file=SCANNER_FILE, scan_main=forbidden_scan, build_parser=BUILD_PARSER
        )
        == 0
    )
    assert history.read_text(encoding="utf-8") == "keep me\n"


# --------------------------------------------------------------------------------------
# 6.4 banners and listings
# --------------------------------------------------------------------------------------


def art_block(art: str) -> str:
    return "\n".join(line.rstrip() for line in art.strip("\n").splitlines())


def banner_shown(chunk: str) -> int | None:
    flattened = "\n".join(line.rstrip() for line in chunk.splitlines())
    for index, art in enumerate(repl.BANNERS):
        if art_block(art) in flattened:
            return index
    return None


def test_banners_are_a_tuple_of_at_least_two_multiline_strings():
    assert isinstance(repl.BANNERS, tuple) and len(repl.BANNERS) >= 2
    for art in repl.BANNERS:
        assert isinstance(art, str) and len(art.strip("\n").splitlines()) >= 2


def test_startup_prints_a_banner_then_the_version_line_then_a_readiness_line(env):
    session = run_session(env, ["exit"])
    startup = env.rich_text[: session.marks[0]]
    assert banner_shown(startup) is not None
    assert f"Bughunt {VERSION}" in startup
    for word in ("help", "show modules", "use", "set", "exit"):
        assert word in startup


def test_banner_command_never_repeats_the_previous_banner(env):
    session = run_session(env, ["banner"] * 40 + ["exit"])
    shown = [banner_shown(env.rich_text[: session.marks[0]])] + [
        banner_shown(session.chunk(n)) for n in range(40)
    ]
    assert None not in shown
    assert all(a != b for a, b in zip(shown, shown[1:]))
    assert len(set(shown)) >= 2


def test_banner_command_keeps_the_console_running(env):
    session = run_session(env, ["banner", "version", "exit"])
    assert session.rc == 0 and f"Bughunt {VERSION}" in session.chunk(1)


def _banner_width_run(env, width: int) -> str:
    env.activate()
    ui.console.__init__(
        file=env.rich, theme=ui.THEME, highlight=False, width=width
    )  # re-size in place
    session = run_session(env, ["exit"])
    return env.rich_text[: session.marks[0]]


def test_banner_art_needs_two_columns_more_than_its_widest_line(env):
    widest = max(len(line) for art in repl.BANNERS for line in art.splitlines())
    narrowest_widest = min(
        max(len(line) for line in art.splitlines()) for art in repl.BANNERS
    )
    roomy = _banner_width_run(env, widest + 2)
    assert banner_shown(roomy) is not None
    env.rich.seek(0)
    env.rich.truncate()
    cramped = _banner_width_run(env, narrowest_widest + 1)
    assert banner_shown(cramped) is None
    assert "BUGHUNT" in cramped
    assert f"Bughunt {VERSION}" in cramped  # the rest of the banner still prints


class FakeReadiness:
    def __init__(self, module, message, blocks=None):
        self._step = (module, message)
        self._blocks = blocks or {}

    def next_step(self):
        return self._step

    def phase_block(self, title):
        return self._blocks.get(title, "")


def test_banner_readiness_line_uses_a_check_mark_when_ready(env, monkeypatch):
    monkeypatch.setattr(
        readiness, "gather", lambda: FakeReadiness("", "All set marker.")
    )
    session = run_session(env, ["exit"])
    line = next(
        line
        for line in env.rich_text[: session.marks[0]].splitlines()
        if "All set marker." in line
    )
    assert "✓" in line and "⚠" not in line


def test_banner_readiness_line_uses_a_warning_mark_when_not_ready(env, monkeypatch):
    monkeypatch.setattr(
        readiness, "gather", lambda: FakeReadiness("scope", "Declare scope marker.")
    )
    session = run_session(env, ["exit"])
    line = next(
        line
        for line in env.rich_text[: session.marks[0]].splitlines()
        if "Declare scope marker." in line
    )
    assert "⚠" in line and "✓" not in line


def _listing(
    env, group=None, *, tool_file=SCANNER_FILE, guide_hints=True
) -> tuple[bool, str]:
    env.activate()
    ok = repl.print_loadable(tool_file, group, guide=guide_hints)
    return ok, env.rich_text


def test_print_loadable_lists_every_phase_with_purpose_and_indented_member_rows(env):
    ok, text = _listing(env)
    assert ok is True
    previous = -1
    for title, members in catalog.MODULE_GROUPS:
        heading = re.search(rf"^{title}\b", text, re.M)
        assert heading is not None and heading.start() > previous
        previous = heading.start()
        assert catalog.phase_purpose(title) in text
        for member in members:
            assert re.search(rf"^  {re.escape(member)}\b", text, re.M), member


def test_print_loadable_separates_phases_with_a_blank_line(env):
    _ok, text = _listing(env, guide_hints=False)
    lines = text.splitlines()
    for title in TITLES[1:]:
        position = next(
            i for i, line in enumerate(lines) if re.match(rf"^{title}\b", line)
        )
        assert lines[position - 1].strip() == ""


def test_print_loadable_member_rows_carry_summary_aliases_and_missing_program_notes(
    env,
):
    ok, text = _listing(env, tool_file=make_project(env.root))
    assert ok
    ct_row = next(line for line in text.splitlines() if re.match(r"^  ct\b", line))
    assert catalog.REFERENCES[1].summary[:25] in ct_row
    assert "crt-scout" in ct_row and "not on disk" in ct_row
    scope_row = next(
        line for line in text.splitlines() if re.match(r"^  scope\b", line)
    )
    assert MODULES["scope"][:25] in scope_row and "not on disk" not in scope_row


def test_print_loadable_does_not_flag_programs_that_are_on_disk(env):
    _ok, text = _listing(env)
    assert "not on disk" not in text


def test_print_loadable_group_lists_only_that_phase(env):
    ok, text = _listing(env, "RECON")
    assert ok is True
    assert re.search(r"^Recon\b", text, re.M)
    for title in TITLES:
        if title != "Recon":
            assert re.search(rf"^{title}\b", text, re.M) is None


def test_print_loadable_hint_lines_only_when_guide_is_true_and_no_group(env):
    _ok, without = _listing(env, guide_hints=False)
    env.rich.seek(0)
    env.rich.truncate()
    _ok2, with_hints = _listing(env, guide_hints=True)
    assert "show modules" in with_hints and "show modules" not in without
    assert len(with_hints) > len(without)
    env.rich.seek(0)
    env.rich.truncate()
    _ok3, group_only = _listing(env, "Recon", guide_hints=True)
    assert "show modules" not in group_only  # a named group never gets the hint lines


def test_print_loadable_unknown_group_returns_false_and_lists_the_phases(env):
    ok, text = _listing(env, "nope")
    assert ok is False
    for title in TITLES:
        assert title in text
    assert "nope" in text


def test_print_loadable_unknown_group_that_is_a_module_names_its_phase(env):
    ok, text = _listing(env, "pulse")
    assert ok is False and "Recon" in text
    env.rich.seek(0)
    env.rich.truncate()
    ok, text = _listing(env, "crt-scout")
    assert ok is False and "Recon" in text


def test_print_loadable_marks_blocked_phases_from_readiness(env, monkeypatch):
    monkeypatch.setattr(
        readiness,
        "gather",
        lambda: FakeReadiness(
            "scope",
            "x",
            {"Recon": "needs gate marker one", "Test": "needs gate marker two"},
        ),
    )
    _ok, text = _listing(env)
    recon = next(line for line in text.splitlines() if re.match(r"^Recon\b", line))
    test = next(line for line in text.splitlines() if re.match(r"^Test\b", line))
    capture = next(line for line in text.splitlines() if re.match(r"^Capture\b", line))
    assert "needs gate marker one" in recon and "needs gate marker two" in test
    assert "needs" not in capture


def test_module_facts_shapes(env):
    summary, aliases, reference = repl._module_facts("scan")
    assert summary.strip() and aliases == () and reference is False
    assert repl._module_facts("scope") == (MODULES["scope"], (), False)
    for tool in catalog.REFERENCES:
        assert repl._module_facts(tool.command) == (tool.summary, tool.aliases, True)
    assert repl._module_facts("ct")[1] == ("crt-scout",)
    assert repl._module_facts("nope") == ("", (), False)
    assert repl._module_facts("crt-scout") == (
        "",
        (),
        False,
    )  # aliases are not facts keys


def test_canonical_module(env):
    assert repl.canonical_module("scan") == "scan"
    assert repl.canonical_module("pulse") == "pulse"
    assert repl.canonical_module("crt-scout") == "ct"
    assert repl.canonical_module("scope") == "scope"
    assert repl.canonical_module("nope") is None
    assert repl.canonical_module("modules") is None


# --------------------------------------------------------------------------------------
# 6.2 command grammar
# --------------------------------------------------------------------------------------


def test_help_and_question_mark_print_a_guide_and_name_the_selected_module(env):
    session = run_session(env, ["help", "?", "use jwt", "help", "exit"])
    assert session.chunk(0).strip() and session.chunk(0) == session.chunk(1)
    assert "jwt" not in session.chunk(0)
    assert "jwt" in session.chunk(3) and len(session.chunk(3)) > len(session.chunk(0))


@pytest.mark.parametrize(
    "query,expect_names",
    [
        ("pulse", ["pulse"]),
        ("PULSE", ["pulse"]),
        ("crt-scout", ["ct"]),
        ("whois", ["whois"]),
        ("scan", ["scan"]),
    ],
)
def test_search_matches_names_and_aliases_case_insensitively(env, query, expect_names):
    session = run_session(env, [f"search {query}", "exit"])
    out = session.chunk(0)
    for name in expect_names:
        assert re.search(rf"^{re.escape(name)}\b", out, re.M), (name, out)


def test_search_rows_name_the_owning_phase_and_the_summary(env):
    session = run_session(env, ["search pulse", "exit"])
    row = next(
        line for line in session.chunk(0).splitlines() if line.startswith("pulse")
    )
    assert "Recon" in row and catalog.tool_by_command("pulse").summary[:25] in row


def test_search_matches_summaries_too(env):
    needle = "robots.txt"
    expected = [
        name
        for name, summary in MODULES.items()
        if needle in summary.lower() or needle in name
    ]
    session = run_session(env, [f"search {needle}", "exit"])
    rows = [line.split()[0] for line in session.chunk(0).splitlines() if line.strip()]
    for name in expected:
        assert name in rows


def test_search_joins_multiple_words_into_one_needle(env):
    session = run_session(
        env,
        [
            "search workspace URL",
            "search workspace   URL",
            'search "workspace  URL"',
            "exit",
        ],
    )
    assert re.search(r"^scope\b", session.chunk(0), re.M)
    assert re.search(
        r"^scope\b", session.chunk(1), re.M
    )  # unquoted words are re-joined with ONE space
    assert not re.search(
        r"^scope\b", session.chunk(2), re.M
    )  # a quoted double space is kept as typed


def test_search_without_a_match_or_without_a_word_prints_a_hint(env):
    session = run_session(env, ["search zzqqxx", "search", "exit"])
    assert "zzqqxx" in session.chunk(0)
    assert session.chunk(1).strip()
    assert not re.search(r"^pulse\b", session.chunk(1), re.M)


def test_show_without_a_topic_lists_modules(env):
    session = run_session(
        env, ["show", "show modules", "show module", "modules", "commands", "exit"]
    )
    for index in range(5):
        for title in TITLES:
            assert re.search(rf"^{title}\b", session.chunk(index), re.M), (index, title)
        assert "show modules" in session.chunk(
            index
        )  # the hint lines are on for the console listing


def test_show_modules_takes_an_optional_group(env):
    session = run_session(
        env,
        [
            "show modules recon",
            "modules labs",
            "commands intel",
            "show modules nope",
            "exit",
        ],
    )
    assert re.search(r"^Recon\b", session.chunk(0), re.M) and not re.search(
        r"^Labs\b", session.chunk(0), re.M
    )
    assert re.search(r"^Labs\b", session.chunk(1), re.M) and not re.search(
        r"^Recon\b", session.chunk(1), re.M
    )
    assert re.search(r"^Intel\b", session.chunk(2), re.M)
    assert "nope" in session.chunk(3)


def test_show_modules_rejects_extra_group_names(env):
    session = run_session(
        env, ["show modules recon labs", "modules recon labs", "exit"]
    )
    for index in (0, 1):
        assert "group" in session.chunk(index).lower()
        assert not re.search(r"^Recon\b", session.chunk(index), re.M)


def test_show_options_needs_an_active_module(env):
    session = run_session(env, ["show options", "show nonsense", "exit"])
    assert session.chunk(0).strip() and session.chunk(1).strip()
    assert "COOKIE" not in session.chunk(0)


def test_show_options_prints_the_active_modules_table(env):
    session = run_session(env, ["use redirect", "show options", "exit"])
    out = session.chunk(1)
    assert "redirect options" in out
    assert re.search(r"^COOKIE\b", out, re.M) and "--cookie" in out


def test_show_options_reflects_saved_values(env):
    session = run_session(env, ["use redirect", "set LIMIT 7", "show options", "exit"])
    limit = next(
        line for line in session.chunk(2).splitlines() if line.startswith("LIMIT")
    )
    assert "7" in limit.split()


def test_use_selects_a_module_and_shows_its_guidance_line(env):
    session = run_session(env, ["use pulse", "use crt-scout", "use scan", "exit"])
    assert "pulse" in session.chunk(0) and catalog.module_when(
        "pulse"
    ) in session.chunk(0)
    assert "ct" in session.chunk(1) and catalog.module_when("ct") in session.chunk(1)
    assert "scan" in session.chunk(2) and catalog.module_when("scan") in session.chunk(
        2
    )
    assert session.prompts[-1] == "Bughunt scan > "


def test_use_with_the_wrong_number_of_arguments_changes_nothing(env):
    session = run_session(env, ["use pulse", "use", "use scan scope", "exit"])
    assert session.chunk(1).strip() and session.chunk(2).strip()
    assert session.prompts[3] == "Bughunt pulse > "


def test_use_unknown_module_offers_a_did_you_mean_when_a_module_is_close(env):
    session = run_session(
        env, ["use pulse", "use pulsee", "use zzqqxx", "use modulez", "exit"]
    )
    assert (
        "pulsee" in session.chunk(1)
        and "Did you mean" in session.chunk(1)
        and "pulse" in session.chunk(1)
    )
    assert "zzqqxx" in session.chunk(2) and "Did you mean" not in session.chunk(2)
    assert "modulez" in session.chunk(3) and "Did you mean" not in session.chunk(
        3
    )  # `modules` is not a module
    assert (
        session.prompts[-1] == "Bughunt pulse > "
    )  # the selection survives every failed use


def test_back_clears_the_selection_and_says_so_when_there_was_none(env):
    session = run_session(env, ["back", "use pulse", "back", "exit"])
    assert session.chunk(0).strip()
    assert session.chunk(2) == ""
    assert session.prompts[3] == "Bughunt > "


def test_set_and_unset_and_run_need_a_selection(env):
    session = run_session(env, ["set FILE x", "set", "unset FILE", "run", "exit"])
    for index in range(4):
        assert session.chunk(index).strip(), index
    assert session.runner_calls == []


def test_set_forms(env):
    session = run_session(
        env,
        [
            "use pulse",
            "set FILE urls.txt",
            "set concurrency=5",
            "set FILE",
            "set FILE=",
            "set",
            "set CONCURRENCY 6 7",
            "set",
            "exit",
        ],
    )
    assert "FILE => urls.txt" in session.chunk(1)
    assert "CONCURRENCY => 5" in session.chunk(2)
    assert (
        session.chunk(3).strip() and session.chunk(4).strip()
    )  # usage hints, nothing stored
    assert history_numbers(
        session.chunk(5)
    ) == [] and "FILE => urls.txt" in session.chunk(5)
    assert "CONCURRENCY => 6 7" in session.chunk(
        6
    )  # the remaining words are joined with spaces
    saved = session.chunk(7)
    assert (
        saved.splitlines()[0].startswith("CONCURRENCY") and "FILE => urls.txt" in saved
    )


def test_set_splits_name_equals_value_at_the_first_equals(env):
    session = run_session(env, ["use scan", "set paths=/a=b", "set", "exit"])
    assert "PATHS => /a=b" in session.chunk(1)


def test_set_with_no_saved_options_names_the_module(env):
    session = run_session(env, ["use pulse", "set", "exit"])
    assert "pulse" in session.chunk(1)


def test_set_rejects_unknown_option_names(env):
    session = run_session(env, ["use pulse", "set NOPE 1", "set", "exit"])
    assert "NOPE" in session.chunk(1)
    assert "NOPE" not in session.chunk(2)


def test_unset_forgets_one_option_or_all(env):
    session = run_session(
        env,
        [
            "use pulse",
            "set FILE a.txt",
            "set concurrency 3",
            "unset file",
            "set",
            "unset all",
            "set",
            "unset",
            "exit",
        ],
    )
    assert "FILE" in session.chunk(3)
    assert "FILE =>" not in session.chunk(4) and "CONCURRENCY => 3" in session.chunk(4)
    assert "FILE =>" not in session.chunk(6) and "CONCURRENCY =>" not in session.chunk(
        6
    )
    assert session.chunk(7).strip()  # usage hint


def test_saved_options_survive_back_and_are_per_module(env):
    session = run_session(
        env,
        [
            "use pulse",
            "set FILE a.txt",
            "back",
            "use scan",
            "set",
            "use pulse",
            "set",
            "exit",
        ],
    )
    assert "FILE =>" not in session.chunk(4)
    assert "FILE => a.txt" in session.chunk(6)


def test_run_merges_saved_options_ahead_of_the_explicit_line(env):
    session = run_session(
        env, ["use pulse", "set FILE urls.txt", "set concurrency=5", "run", "exit"]
    )
    assert session.runner_calls == [("pulse", ["--concurrency", "5", "urls.txt"])]
    assert session.merge_calls == [
        ("pulse", [], {"FILE": "urls.txt", "CONCURRENCY": "5"})
    ]


def test_run_arguments_beat_saved_options(env):
    session = run_session(
        env, ["use pulse", "set concurrency 5", "run --concurrency 9 a.txt", "exit"]
    )
    assert session.runner_calls == [("pulse", ["--concurrency", "9", "a.txt"])]


def test_scan_settings_are_saved_under_the_scan_key(env):
    session = run_session(env, ["use scan", "set ports 80", "run 127.0.0.1", "exit"])
    assert session.merge_calls == [("scan", ["127.0.0.1"], {"PORTS": "80"})]
    assert session.runner_calls == [("scan", ["--ports", "80", "127.0.0.1"])]


def test_a_module_name_runs_it_once_and_keeps_the_selection(env):
    session = run_session(
        env,
        [
            "use scope",
            "pulse a.txt -c 3",
            "crt-scout example.test",
            "scan 127.0.0.1 --ports 80",
            "exit",
        ],
    )
    assert session.runner_calls == [
        ("pulse", ["a.txt", "-c", "3"]),
        ("ct", ["example.test"]),
        ("scan", ["127.0.0.1", "--ports", "80"]),
    ]
    assert session.prompts[-1] == "Bughunt scope > "


def test_a_module_run_by_name_uses_that_modules_saved_options_not_the_selected_ones(
    env,
):
    session = run_session(
        env, ["use pulse", "set concurrency 4", "use scope", "pulse a.txt", "exit"]
    )
    assert session.runner_calls == [("pulse", ["--concurrency", "4", "a.txt"])]


def test_the_runner_receives_tool_file_and_scan_main(env):
    seen = {}

    def runner(name, argv, *, tool_file, scan_main):
        seen.update(name=name, tool_file=tool_file, scan_main=scan_main)
        return 0

    run_session(env, ["pulse"], runner=runner, scan_main=forbidden_scan)
    assert seen == {
        "name": "pulse",
        "tool_file": SCANNER_FILE,
        "scan_main": forbidden_scan,
    }


def test_the_merge_hook_receives_tool_file_and_build_parser(env):
    seen = {}

    def merger(name, argv, saved, *, tool_file, build_parser):
        seen.update(tool_file=tool_file, build_parser=build_parser)
        return ["merged", *argv]

    from console_support import run_session as drive

    session = drive(env, ["pulse a"], merger=merger)
    assert seen == {"tool_file": SCANNER_FILE, "build_parser": BUILD_PARSER}
    assert session.runner_calls == [("pulse", ["merged", "a"])]


def test_invoke_echoes_the_merged_command_as_plain_text_only_when_there_is_one(env):
    session = run_session(env, ["pulse 'a b' [bold]x", "pulse", "exit"])
    assert "bughunt pulse " + shlex.join(["a b", "[bold]x"]) in session.chunk(0)
    assert "bughunt pulse" not in session.chunk(1)


def test_invoke_prints_the_exit_code_only_when_it_is_not_zero(env):
    codes = iter([0, 3])
    session = run_session(
        env, ["pulse a", "pulse b", "exit"], runner=lambda name, argv, **kw: next(codes)
    )
    assert "exit 0" not in session.chunk(0)
    assert "exit 3" in session.chunk(1)


def test_invoke_reports_an_interrupted_run_as_exit_130(env):
    def runner(name, argv, **kwargs):
        raise KeyboardInterrupt

    session = run_session(env, ["pulse a", "version", "exit"], runner=runner)
    assert "Interrupted" in session.chunk(0) and "exit 130" in session.chunk(0)
    assert f"Bughunt {VERSION}" in session.chunk(1)  # the console keeps running


def test_invoke_suggests_follow_on_modules_after_a_run(env):
    expected = guide.follow_ons("scope")
    assert expected, "the guide must have a follow-on for scope"
    session = run_session(env, ["scope", "exit"])
    out = session.chunk(0)
    assert "Next you might" in out
    for module, why in expected:
        assert re.search(rf"^\s+{re.escape(module)}\s", out, re.M)
        assert why in out


def test_follow_ons_are_keyed_by_the_canonical_module_name(env):
    expected = guide.follow_ons("ct")
    session = run_session(env, ["crt-scout x", "exit"])
    for module, why in expected:
        assert why in session.chunk(0)


def test_no_follow_on_block_for_a_module_without_chains(env):
    quiet = next(name for name in MODULES if not guide.follow_ons(name))
    session = run_session(env, [quiet, "exit"])
    assert "Next you might" not in session.chunk(0)


def test_version_doctor_and_examples_commands(env, monkeypatch):
    from bughunt.console import cli, doctor

    seen = []
    monkeypatch.setattr(
        doctor, "run", lambda tool_file: seen.append(("doctor", tool_file)) or 0
    )
    monkeypatch.setattr(cli, "print_examples", lambda: seen.append(("examples",)) or 0)
    session = run_session(env, ["version", "doctor", "examples", "exit"])
    assert f"Bughunt {VERSION}" in session.chunk(0)
    assert seen == [("doctor", SCANNER_FILE), ("examples",)]


def test_unknown_commands_suggest_close_console_and_cli_words(env):
    session = run_session(env, ["shw", "docter", "modulez", "exit"])
    for index, (typed, wanted) in enumerate(
        [("shw", "show"), ("docter", "doctor"), ("modulez", "modules")]
    ):
        out = session.chunk(index)
        assert typed in out and "Did you mean" in out and wanted in out, (typed, out)
    assert session.runner_calls == []


def test_unknown_commands_without_a_guess_point_at_help_or_run(env):
    session = run_session(env, ["zzqqxx", "use pulse", "zzqqxx", "exit"])
    assert "zzqqxx" in session.chunk(0) and "help" in session.chunk(0)
    assert (
        "zzqqxx" in session.chunk(2)
        and "run" in session.chunk(2)
        and "pulse" in session.chunk(2)
    )
    assert "Did you mean" not in session.chunk(0) + session.chunk(2)


def test_commands_are_case_sensitive(env):
    session = run_session(env, ["Pulse a", "EXIT", "exit"])
    assert session.runner_calls == []
    assert len(session.prompts) == 3  # EXIT did not leave


def test_default_runner_and_merge_run_the_real_pipeline(env):
    """No run_module/merge_argv injected: saved options are merged and `policy` really runs."""
    session = run_session(
        env, ["use policy", "set command status", "run", "exit"], real_pipeline=True
    )
    assert session.rc == 0
    out = session.chunk(2)
    assert (
        "bughunt policy status" in out
    )  # the real prepare_argv rendered the saved subcommand
    assert (
        "exit 2" in out
    )  # the real run_named ran the module: no verified policy in the scratch workspace
