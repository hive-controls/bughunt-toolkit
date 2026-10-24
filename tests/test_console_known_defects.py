"""Known defects of the console component, labelled (M2 clean-room rebuild, spec section 11).

Two kinds of test live here, on purpose kept apart from the ordinary oracle:

* ``xfail(strict=True)`` tests assert the CORRECT behavior and fail against today's code. They go
  red as XPASS the moment a rebuild fixes the defect, forcing a conscious "remove the marker"
  decision instead of a silent change. Reproducing the defect keeps the suite green.
* "PIN-CURRENT" tests assert today's behavior where the spec's recommended default is to
  reproduce it and file a follow-up. They go red if a rebuild silently changes it.

Spec item numbers refer to section 11 of the M2 console spec. Items marked NEW are findings made
while writing this oracle that section 11 does not list.
"""

from __future__ import annotations

import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

from bughunt.console import catalog, loader, options
from bughunt.console import console as repl
from bughunt.core import egress, ledger

from console_support import (  # noqa: F401  (env/merged_env are pytest fixtures)
    BUILD_PARSER,
    SCANNER_FILE,
    build_env,
    env,
    forbidden_scan,
    make_project,
    merged_env,
    run_cli,
    run_dispatch,
    run_session,
)

SECRET = "sekret-cookie-value-1234"
PROMPT = re.compile(r"Bughunt(?: redirect)? > ")


# --------------------------------------------------------------------------------------
# Item 7 (SECURITY): credential views mask values before the renderer or ledger wrapper.
# Real piped-process checks cover Windows Rich's independently flushed styled segments.
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def piped_outputs(tmp_path_factory):
    """One in-process piped session (prompt written to the same stream, redaction on).

    Returns the output of each command, in order: use, set COOKIE, bare set, show options, run.
    """
    mp = pytest.MonkeyPatch()
    try:
        env = build_env(mp, tmp_path_factory.mktemp("piped-leak"), merged=True)
        env.activate()
        with ledger.sanitized_output():
            run_session(
                env,
                [
                    "use redirect",
                    f"set COOKIE {SECRET}",
                    "set",
                    "show options",
                    "run http://127.0.0.1/",
                    "exit",
                ],
                write_prompt=True,
            )
        yield PROMPT.split(env.stdout_text)[1:]
    finally:
        mp.undo()


def test_the_leak_session_really_ran_through_every_surface(piped_outputs):
    """Guards the xfails below against passing for the wrong reason (nothing was printed at all)."""
    assert len(piped_outputs) >= 6
    assert "COOKIE" in piped_outputs[1] and "COOKIE" in piped_outputs[2]
    assert "redirect options" in piped_outputs[3]
    assert "bughunt redirect" in piped_outputs[4] and "--cookie" in piped_outputs[4]


def test_show_options_redacts_saved_credentials(piped_outputs):
    assert SECRET not in piped_outputs[3]


def test_run_echo_redacts_saved_credentials(piped_outputs):
    assert SECRET not in piped_outputs[4]


def test_set_echo_and_bare_set_are_redacted_when_the_console_writes_whole_lines(
    piped_outputs,
):
    """Control: the `NAME => value` shape IS caught by the ledger when the line arrives in one piece.

    This is why the spec says to keep the exact `NAME => value` shape. (A real piped Windows process
    defeats it; see the end-to-end tests below.)
    """
    assert SECRET not in piped_outputs[1]
    assert SECRET not in piped_outputs[2]
    assert "[REDACTED]" in piped_outputs[1] and "[REDACTED]" in piped_outputs[2]


@pytest.fixture(scope="module")
def process_outputs(tmp_path_factory):
    """`bughunt console --text` as a real process fed through a pipe."""
    tmp_path = tmp_path_factory.mktemp("process-leak")
    done = run_cli(
        tmp_path,
        ["console", "--text"],
        stdin=f"use redirect\nset COOKIE {SECRET}\nset\nshow options\nexit\n",
    )
    assert done.returncode == 0, done.stderr[-400:]
    return PROMPT.split(done.stdout)


def test_the_process_session_ran(process_outputs):
    assert len(process_outputs) >= 6 and "redirect options" in process_outputs[4]
    assert "COOKIE" in process_outputs[2]


def test_piped_process_set_echo_redacts_saved_credentials(process_outputs):
    assert SECRET not in process_outputs[2]


def test_piped_process_bare_set_redacts_saved_credentials(process_outputs):
    assert SECRET not in process_outputs[3]


def test_piped_process_show_options_redacts_saved_credentials(process_outputs):
    assert SECRET not in process_outputs[4]


def test_sensitive_lines_stay_out_of_the_history_transcript(env):
    session = run_session(
        env, ["use redirect", f"set COOKIE {SECRET}", "history", "exit"]
    )
    assert SECRET not in session.chunk(2)


def test_credential_rendering_is_safe_without_the_ledger_wrapper(env):
    session = run_session(
        env,
        [
            "use redirect",
            f"set COOKIE {SECRET}",
            "set",
            "show options",
            "run http://127.0.0.1/",
            "exit",
        ],
    )
    assert SECRET not in env.all_text
    assert SECRET in session.runner_calls[0][1]


def test_credential_defaults_are_redacted_before_rendering():
    spec = options.load_spec(
        "redirect", tool_file=SCANNER_FILE, build_parser=BUILD_PARSER
    )
    row = next(row for row in spec.options if row.name == "COOKIE")._replace(
        default=SECRET
    )
    assert SECRET not in options._value_cell(row, {}).plain


@pytest.mark.parametrize(
    "module_name,key,value,echo",
    [
        ("scan", "AUTHORIZED", "true", "AUTHORIZED => true"),
        ("redirect", "COOKIE", "true", "COOKIE => ***"),
        ("redirect", "COOKIE", "false", "COOKIE => ***"),
    ],
)
def test_typed_boolean_assertions_remain_visible_while_secret_strings_are_masked(
    env, module_name, key, value, echo
):
    saved = {}
    assert options.set_option(
        module_name,
        saved,
        key,
        value,
        tool_file=SCANNER_FILE,
        build_parser=BUILD_PARSER,
    )
    assert saved[key] == value
    assert env.rich_text.strip() == echo


def test_bare_settings_keep_public_authorization_assertions_visible(env):
    session = run_session(env, ["use scan", "set AUTHORIZED true", "set", "exit"])
    assert "AUTHORIZED => true" in session.chunk(2)


@pytest.mark.parametrize(
    "command", [f"session set cookie {SECRET}", f"identity set owner cookie {SECRET}"]
)
def test_credential_command_echo_masks_positional_values_but_execution_keeps_them(
    env, command
):
    session = run_session(env, [command, "exit"])
    assert SECRET not in session.chunk(0)
    assert SECRET in session.runner_calls[0][1]


def test_saved_session_value_is_redacted_in_all_console_views(env):
    session = run_session(
        env,
        [
            "use session",
            "set COMMAND set",
            "set KIND cookie",
            f"set VALUE {SECRET}",
            "set",
            "show options",
            "run",
            "exit",
        ],
    )
    assert SECRET not in env.all_text
    assert session.runner_calls == [("session", ["set", "cookie", SECRET])]


def test_generic_credential_value_assignment_is_omitted_from_history(env):
    secret = "opaque-private-4821"
    session = run_session(
        env,
        [
            "use session",
            "set COMMAND set",
            "set KIND cookie",
            f"set VALUE {secret}",
            "history",
            "exit",
        ],
    )
    assert secret not in session.chunk(4)


# --------------------------------------------------------------------------------------
# Item 3: addon_roots raises IndexError for a shallow tool_file. Spec recommends tolerating it.
# --------------------------------------------------------------------------------------


def _shallow_tool_files() -> list[Path]:
    anchor = Path(Path.cwd().anchor)
    return [anchor / "x.py", anchor / "a" / "x.py"]


@pytest.mark.parametrize(
    "tool_file", _shallow_tool_files(), ids=["root-level", "one-folder-deep"]
)
def test_addon_roots_tolerates_a_shallow_tool_file(monkeypatch, tool_file):
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    assert catalog.addon_roots(tool_file) == []


def test_addon_roots_keeps_the_env_root_for_a_shallow_tool_file(monkeypatch, tmp_path):
    monkeypatch.setenv("BUGHUNT_ADDONS", str(tmp_path / "custom"))
    assert catalog.addon_roots(_shallow_tool_files()[0])[0] == tmp_path / "custom"


# --------------------------------------------------------------------------------------
# Item 4: `--version` surfaces as a settable VERSION value option. PIN-CURRENT (reproduce).
# --------------------------------------------------------------------------------------


def test_version_action_is_not_a_settable_value_option(env):
    spec = options.load_spec("scan", tool_file=SCANNER_FILE, build_parser=BUILD_PARSER)
    assert "VERSION" not in {option.name for option in spec.options}


def test_version_action_is_not_a_catalog_option():
    from bughunt.console.catalog_export import export_catalog

    data = export_catalog(tool_file=SCANNER_FILE, build_parser=BUILD_PARSER)
    scan = next(m for p in data["phases"] for m in p["modules"] if m["name"] == "scan")
    assert "VERSION" not in {option["name"] for option in scan["form"]["options"]}


# --------------------------------------------------------------------------------------
# Item 11: dispatch(interactive=...) only gates the no-argument decision. PIN-CURRENT (reproduce).
# --------------------------------------------------------------------------------------


def test_pin_current_interactive_flag_is_not_forwarded_to_open_console(
    env, monkeypatch
):
    """interactive=True with non-terminal real streams still opens the TYPED console, never the picker."""
    picker = types.ModuleType("bughunt.console.picker")
    picker.run_picker = lambda **kwargs: pytest.fail(
        "the picker must not open: open_console re-derives interactivity"
    )
    monkeypatch.setitem(sys.modules, "bughunt.console.picker", picker)
    typed = []
    monkeypatch.setattr(
        repl, "run_console", lambda **kwargs: typed.append(kwargs) or 37
    )
    assert run_dispatch([], interactive=True) == 37
    assert len(typed) == 1


# --------------------------------------------------------------------------------------
# Item 6: the choices error prints literal markup tags.
# --------------------------------------------------------------------------------------


def test_choices_error_does_not_print_markup_tags(env):
    options.set_option(
        "scan", {}, "method", "patch", tool_file=SCANNER_FILE, build_parser=BUILD_PARSER
    )
    text = env.rich_text
    assert "[info]" not in text and "[/info]" not in text
    assert "GET, HEAD, OPTIONS, POST" in text and "METHOD" in text


# --------------------------------------------------------------------------------------
# Item 8: run_named does not catch PolicyBlocked on the non-Python program branch.
# --------------------------------------------------------------------------------------


@pytest.fixture
def enabled_program_tool(env, monkeypatch):
    """A non-Python `tcurl` (extensionless script) on disk; tcurl itself is Python now, so this stands in for a program tool."""
    monkeypatch.setattr(catalog, "DISABLED_REFERENCES", frozenset())
    monkeypatch.setattr(loader, "DISABLED_REFERENCES", frozenset(), raising=False)
    monkeypatch.setitem(
        catalog._TOOL_INDEX,
        "tcurl",
        catalog.tool_by_command("tcurl")._replace(script="tcurl"),
    )
    env.activate()
    return make_project(env.root, {"tcurl": "#!/bin/bash\necho hi\n"})


def test_program_branch_maps_policy_blocked_to_exit_2(enabled_program_tool):
    # empty scratch workspace -> no usable policy -> the egress guard raises before subprocess
    assert (
        loader.run_named(
            "tcurl", [], tool_file=enabled_program_tool, scan_main=forbidden_scan
        )
        == 2
    )


def test_the_policy_guard_itself_is_in_place_on_the_program_branch(
    enabled_program_tool, monkeypatch
):
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **k: pytest.fail("subprocess must not run without a policy"),
    )
    try:
        outcome = loader.run_named(
            "tcurl", [], tool_file=enabled_program_tool, scan_main=forbidden_scan
        )
    except egress.PolicyBlocked:
        return  # today's behavior (item 8)
    assert outcome == 2  # the corrected behavior


# --------------------------------------------------------------------------------------
# NEW (not in spec section 11): render_argv duplicates the subcommand when argv names a subcommand
# that has positionals of its own. Spec 3.6 step 2 (tokens fill the visible positionals in order)
# makes `check` fill policy's TARGET positional, so the saved COMMAND is not seen as supplied.
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "saved_target,typed_target,expected_target",
    [
        (None, [], []),
        ("https://saved.example", [], ["https://saved.example"]),
        ("https://saved.example", ["https://typed.example"], ["https://typed.example"]),
    ],
)
def test_typed_subcommand_with_positionals_is_not_duplicated_by_the_saved_command(
    saved_target, typed_target, expected_target
):
    spec = options.load_spec("policy", tool_file=SCANNER_FILE, build_parser=None)
    saved = {"COMMAND": "check", "OPERATION": "manual"}
    if saved_target:
        saved["TARGET"] = saved_target
    merged = options.render_argv(
        spec,
        saved,
        ["check", "--operation", "scan", *typed_target],
    )
    assert merged == ["check", "--operation", "scan", *expected_target]


@pytest.mark.parametrize(
    "typed,expected",
    [
        ([], ["check", "--operation", "manual", "https://saved.example"]),
        (
            ["https://typed.example"],
            ["check", "--operation", "manual", "https://typed.example"],
        ),
        (
            ["--operation", "scan", "https://typed.example"],
            ["check", "--operation", "scan", "https://typed.example"],
        ),
        (
            ["--operation", "scan"],
            ["check", "--operation", "scan", "https://saved.example"],
        ),
    ],
)
def test_saved_command_keeps_typed_child_positionals_ahead_of_saved_values(
    typed, expected
):
    spec = options.load_spec("policy", tool_file=SCANNER_FILE, build_parser=None)
    saved = {
        "COMMAND": "check",
        "OPERATION": "manual",
        "TARGET": "https://saved.example",
    }
    assert options.render_argv(spec, saved, typed) == expected


# --------------------------------------------------------------------------------------
# Output hygiene (M6): untrusted text reaching the shared render helpers is neutralized.
# --------------------------------------------------------------------------------------

from bughunt.console import cli as console_cli  # noqa: E402
from bughunt.core import termio  # noqa: E402


def _suggest(token: str) -> int:
    route = console_cli.Route("suggest", [], token=token, suggestion="modules")
    return console_cli._cmd_suggest(route, None)


def test_neutralize_makes_every_control_character_visible():
    cleaned = termio.neutralize("a\x1b[2Jb\x1b]0;pwned\x07c\rd\x00e\x7f\x9bf")
    assert not re.search(r"[\x00-\x1f\x7f-\x9f]", cleaned)
    assert "\\x1b[2J" in cleaned and "\\x0d" in cleaned


def test_neutralize_keep_lines_leaves_only_tab_and_newline():
    assert (
        termio.neutralize("a\tb\nc\x1bd\re", keep_lines=True) == "a\tb\nc\\x1bd\\x0de"
    )


@pytest.mark.parametrize("token", ["\x1b[2Jnope", "\x1b]0;title\x07zzz"])
def test_unknown_command_echo_carries_no_terminal_escape(env, token):
    _suggest(token)
    assert "\x1b" not in env.rich_text and "\x07" not in env.rich_text


def test_unknown_command_echo_keeps_markup_in_untrusted_data_literal(env):
    _suggest("[/err][bold]x")
    assert "[/err][bold]x" in env.rich_text


def test_app_own_markup_still_styles_trusted_strings(env):
    _suggest("plain")
    assert "[err]" not in env.rich_text and "Unknown command plain" in env.rich_text


def test_redactor_masks_secret_flags_headers_and_userinfo():
    argv = [
        "--cookie",
        "s3",
        "--token=abc",
        "-H",
        "Authorization: Bearer xyz",
        "https://u:pw@h.test/",
        "--limit",
        "5",
    ]
    masked = termio.redact_argv(argv)
    joined = " ".join(masked)
    assert (
        "s3" not in joined
        and "abc" not in joined
        and "xyz" not in joined
        and "pw@" not in joined
    )
    assert masked[-2:] == ["--limit", "5"]


@pytest.mark.parametrize(
    "header",
    [
        "Auth-Key",
        "X-Phishunt-Deep-Token",
        "X-Custom-Session",
        "X-API-Key",
        "Cookie",
        "Authorization",
    ],
)
def test_terminal_redaction_covers_credential_named_header_values(header):
    secret = "opaque-private-4821"
    line = f"{header}: {secret}"
    assert secret not in termio.redact_text(line)
    assert secret not in " ".join(termio.redact_argv(["-H", line]))
    assert termio.redact_text("X-Request-ID: keep-me") == "X-Request-ID: keep-me"


def test_supported_auth_key_credentials_are_not_retained_in_console_history(env):
    secret = "opaque-private-4821"
    session = run_session(
        env, [f"identity set owner auth-key {secret}", "history", "exit"]
    )
    assert secret not in session.chunk(1)


@pytest.mark.parametrize(
    "username", ["cookie", "auth-user", "session-user", "ordinary"]
)
def test_url_userinfo_is_masked_even_when_username_looks_like_a_secret_header(username):
    raw = f"https://{username}:opaque-private-4821@host.test/path"
    assert termio.redact_text(raw) == "https://***@host.test/path"


@pytest.mark.parametrize("header", ["Auth-Key", "Cookie"])
def test_compact_header_argument_redacts_value_and_preserves_following_flags(header):
    masked = termio.redact_argv([f"-H{header}:opaque-private-4821", "--limit", "5"])
    assert "opaque-private-4821" not in " ".join(masked)
    assert masked[-2:] == ["--limit", "5"]
