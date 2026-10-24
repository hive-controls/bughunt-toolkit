"""Characterization oracle for `bughunt.console.doctor` and `bughunt.console.ui`
(M2 clean-room rebuild, spec section 8).
"""

from __future__ import annotations

import builtins
import collections
import io
import os
import re
import stat
import sys
from pathlib import Path

import pytest
from rich.console import Console

from bughunt import VERSION
from bughunt.console import catalog, doctor, ui
from bughunt.modules import MODULES

from console_support import (  # noqa: F401  (env is a pytest fixture)
    SCANNER_FILE,
    TtyStdin,
    env,
    make_project,
)

SHIPPED_CONSOLE = ui.console  # captured at import, before any fixture swaps it

_FakeVersion = collections.namedtuple(
    "_FakeVersion", "major minor micro releaselevel serial"
)

CHECK_NAMES = [
    "python",
    "rich",
    "httpx",
    "playwright",
    "aiohttp",
    "requests",
    "urllib3",
    "colorama",
    "mitmproxy",
    "socksio",
    "tor",
    "reference clones",
    "built-in modules",
    "bughunt",
]
REQUIRED = {"python", "rich", "httpx"}


def check(name="x", ok=True, detail="detail", required=False):
    return doctor.Check(name=name, ok=ok, detail=detail, required=required)


def by_name(checks):
    return {c.name: c for c in checks}


def row_tokens(text: str, name: str) -> list[str]:
    """Whitespace/box-drawing separated tokens of the table row that starts with `name`."""
    for line in text.splitlines():
        tokens = [
            token for token in re.split(r"[\s\u2502|\u2503\u2551]+", line) if token
        ]
        if tokens and tokens[0] == name:
            return tokens
    raise AssertionError(f"no row for {name!r} in:\n{text}")


# --------------------------------------------------------------------------------------
# 8.1 collect_checks
# --------------------------------------------------------------------------------------


def test_checks_come_in_the_documented_order(env):
    assert [c.name for c in doctor.collect_checks(SCANNER_FILE)] == CHECK_NAMES


def test_only_python_rich_and_httpx_are_required():
    checks = doctor.collect_checks(SCANNER_FILE)
    assert {c.name for c in checks if c.required} == REQUIRED


def test_check_records_expose_name_ok_detail_required():
    for c in doctor.collect_checks(SCANNER_FILE):
        assert (
            isinstance(c.name, str)
            and isinstance(c.ok, bool)
            and isinstance(c.detail, str)
            and isinstance(c.required, bool)
        )
        assert c.detail.strip(), c.name


def test_python_check_reports_version_and_interpreter():
    python = by_name(doctor.collect_checks(SCANNER_FILE))["python"]
    v = sys.version_info
    assert python.ok is True
    assert python.detail == f"{v.major}.{v.minor}.{v.micro}  ({sys.executable})"


@pytest.mark.parametrize("minor", [9, 10, 11])
def test_python_older_than_3_12_fails_the_required_check(monkeypatch, minor):
    monkeypatch.setattr(sys, "version_info", _FakeVersion(3, minor, 18, "final", 0))
    python = by_name(doctor.collect_checks(SCANNER_FILE))["python"]
    assert python.ok is False and python.required is True
    assert python.detail.startswith(f"3.{minor}.18  (")


def test_python_3_12_exactly_passes(monkeypatch):
    monkeypatch.setattr(sys, "version_info", _FakeVersion(3, 12, 0, "final", 0))
    assert by_name(doctor.collect_checks(SCANNER_FILE))["python"].ok is True


def test_installed_required_distributions_report_a_version():
    checks = by_name(doctor.collect_checks(SCANNER_FILE))
    for name in ("rich", "httpx"):
        assert checks[name].ok is True
        assert re.fullmatch(r"\d+(\.\d+)*\S*", checks[name].detail), checks[name].detail


def test_a_missing_distribution_is_reported_not_installed(monkeypatch):
    import importlib.metadata as metadata

    real = metadata.version

    def fake(dist):
        if dist == "aiohttp":
            raise metadata.PackageNotFoundError(dist)
        return real(dist)

    monkeypatch.setattr(metadata, "version", fake)
    aiohttp = by_name(doctor.collect_checks(SCANNER_FILE))["aiohttp"]
    assert (
        aiohttp.ok is False
        and aiohttp.detail == "not installed"
        and aiohttp.required is False
    )


def test_playwright_detail_mentions_screenshots_and_the_browser_install(monkeypatch):
    import importlib.metadata as metadata

    real = metadata.version
    monkeypatch.setattr(
        metadata,
        "version",
        lambda dist: "9.9.9" if dist == "playwright" else real(dist),
    )
    detail = by_name(doctor.collect_checks(SCANNER_FILE))["playwright"].detail
    assert detail.startswith("9.9.9")
    assert "--screenshots" in detail and "playwright install chromium" in detail


def _fake_bin(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        target = directory / f"{name}.cmd"
        target.write_text("@echo off\n", encoding="utf-8")
    else:
        target = directory / name
        target.write_text("#!/bin/sh\n", encoding="utf-8")
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


def test_binaries_are_looked_up_on_path(monkeypatch, tmp_path):
    bin_dir = tmp_path / "bin"
    found = _fake_bin(bin_dir, "tor")
    monkeypatch.setenv("PATH", str(bin_dir))
    checks = by_name(doctor.collect_checks(SCANNER_FILE))
    assert (
        checks["tor"].ok is True
        and Path(checks["tor"].detail).resolve() == found.resolve()
    )
    assert "curl" not in checks and "torsocks" not in checks
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    missing = by_name(doctor.collect_checks(SCANNER_FILE))["tor"]
    assert missing.ok is False and missing.required is False
    assert "PATH" in missing.detail and "tcurl" in missing.detail


def test_socksio_is_an_optional_distribution_for_the_tor_route(monkeypatch):
    check = by_name(doctor.collect_checks(SCANNER_FILE))["socksio"]
    assert check.required is False
    if not check.ok:
        assert "bughunt[tor]" in check.detail


def test_reference_clone_count_for_the_source_checkout():
    detail = by_name(doctor.collect_checks(SCANNER_FILE))["reference clones"]
    assert detail.ok is True
    assert detail.detail.startswith(
        f"{len(catalog.REFERENCES)} of {len(catalog.REFERENCES)} "
    )


def test_reference_clone_count_uses_the_tool_file_roots(monkeypatch, tmp_path):
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    nothing = make_project(tmp_path / "none")
    two = make_project(tmp_path / "two", {"pulse": "x = 1\n", "urlscan": "x = 1\n"})
    assert by_name(doctor.collect_checks(nothing))[
        "reference clones"
    ].detail.startswith("0 of 9 ")
    assert by_name(doctor.collect_checks(two))["reference clones"].detail.startswith(
        "2 of 9 "
    )
    assert by_name(doctor.collect_checks(two))["reference clones"].ok is True


def test_built_in_modules_check_lists_every_module_comma_separated():
    detail = by_name(doctor.collect_checks(SCANNER_FILE))["built-in modules"]
    assert detail.ok is True and detail.detail == ", ".join(MODULES)


def test_bughunt_check_reports_version_and_tool_file():
    detail = by_name(doctor.collect_checks(SCANNER_FILE))["bughunt"]
    assert detail.ok is True
    assert detail.detail == f"{VERSION}  ({SCANNER_FILE})"


def test_informational_checks_are_always_ok():
    checks = by_name(doctor.collect_checks(SCANNER_FILE))
    for name in ("reference clones", "built-in modules", "bughunt"):
        assert checks[name].ok is True and checks[name].required is False


# --------------------------------------------------------------------------------------
# render / run: the table and the return-code rule
# --------------------------------------------------------------------------------------


def test_render_all_ok_returns_zero_and_prints_the_table(env):
    assert (
        doctor.render(
            [check("python", True, "3.14", True), check("curl", True, "/usr/bin/curl")]
        )
        == 0
    )
    text = env.rich_text
    assert "bughunt doctor" in text and VERSION in text
    for header in ("Check", "Status", "Detail"):
        assert header in text
    assert "python" in text and "3.14" in text and "/usr/bin/curl" in text
    assert "ok" in row_tokens(text, "python")[1:2]
    assert "pip install" not in text


def test_render_required_failure_returns_one_and_names_the_install_command(env):
    assert (
        doctor.render(
            [check("rich", False, "not installed", True), check("curl", True, "x")]
        )
        == 1
    )
    text = env.rich_text
    assert "missing" in row_tokens(text, "rich")[1:2]
    assert "ok" in row_tokens(text, "curl")[1:2]
    assert "pip install -r requirements.txt" in text


def test_render_optional_failure_is_only_a_warning(env):
    assert (
        doctor.render(
            [
                check("playwright", False, "not installed", False),
                check("python", True, "3.14", True),
            ]
        )
        == 0
    )
    text = env.rich_text
    assert "optional" in row_tokens(text, "playwright")[1:2]
    assert "missing" not in text
    assert "pip install" not in text


def test_render_one_required_failure_among_many_is_enough(env):
    checks = [check(f"c{n}", True, "d", True) for n in range(5)] + [
        check("bad", False, "d", True)
    ]
    assert doctor.render(checks) == 1


def test_render_empty_check_list_is_a_pass(env):
    assert doctor.render([]) == 0


def test_render_prints_every_check_in_order(env):
    doctor.render([check("zz-first"), check("aa-second"), check("mm-third")])
    text = env.rich_text
    assert text.index("zz-first") < text.index("aa-second") < text.index("mm-third")


def test_render_does_not_interpret_markup_in_details(env):
    doctor.render([check("odd", True, "[bold]raw[/bold]")])
    assert "raw" in env.rich_text


def test_run_collects_renders_and_returns_the_code(env):
    assert (
        doctor.run(SCANNER_FILE) == 0
    )  # rich and httpx are installed in the test environment
    text = env.rich_text
    for name in CHECK_NAMES:
        assert name in text


def test_run_fails_when_python_is_too_old(env, monkeypatch):
    monkeypatch.setattr(sys, "version_info", _FakeVersion(3, 9, 0, "final", 0))
    assert doctor.run(SCANNER_FILE) == 1
    assert "missing" in row_tokens(env.rich_text, "python")[1:2]


# --------------------------------------------------------------------------------------
# 8.2 ui
# --------------------------------------------------------------------------------------


def test_theme_defines_the_six_style_names_the_modules_use():
    for name in ("ok", "warn", "err", "info", "muted", "brand"):
        assert name in ui.THEME.styles, name


def test_shipped_console_is_a_real_rich_console_with_the_theme():
    assert isinstance(SHIPPED_CONSOLE, Console)
    for name in ("ok", "warn", "err", "info", "muted", "brand"):
        SHIPPED_CONSOLE.get_style(name)  # raises MissingStyle when the theme lacks it


def test_shipped_console_keeps_automatic_highlighting_off():
    """Module output must stay verbatim: numbers and URLs get no highlight spans."""
    rendered = SHIPPED_CONSOLE.render_str("1234 http://example.test/a 10.0.0.1")
    assert rendered.plain == "1234 http://example.test/a 10.0.0.1"
    assert list(rendered.spans) == []


def test_ui_console_can_be_swapped_and_the_framework_prints_through_the_swap(env):
    from bughunt.console import options

    options.print_settings("pulse", {"FILE": "u.txt"})
    assert "FILE => u.txt" in env.rich_text


def test_confirm_with_assume_yes_never_reads_input(monkeypatch):
    monkeypatch.setattr(
        builtins, "input", lambda prompt="": pytest.fail("input must not be read")
    )
    assert ui.confirm("Send?", assume_yes=True) is True


def test_confirm_when_stdin_is_not_a_terminal_is_no(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("y\n"))
    monkeypatch.setattr(
        builtins, "input", lambda prompt="": pytest.fail("input must not be read")
    )
    assert ui.confirm("Send?") is False


@pytest.mark.parametrize(
    "answer,expected",
    [
        ("y", True),
        ("YES", True),
        (" yes ", True),
        ("Y", True),
        ("n", False),
        ("", False),
        ("maybe", False),
        ("yess", False),
        ("no", False),
    ],
)
def test_confirm_answers(monkeypatch, answer, expected):
    prompts = []
    monkeypatch.setattr(sys, "stdin", TtyStdin())
    monkeypatch.setattr(
        builtins, "input", lambda prompt="": prompts.append(prompt) or answer
    )
    assert ui.confirm("Share the target?") is expected
    assert prompts == ["Share the target? [y/N] "]


def test_confirm_treats_end_of_input_as_no(monkeypatch):
    def eof(prompt=""):
        raise EOFError

    monkeypatch.setattr(sys, "stdin", TtyStdin())
    monkeypatch.setattr(builtins, "input", eof)
    assert ui.confirm("Send?") is False


def test_confirm_assume_yes_is_keyword_only():
    with pytest.raises(TypeError):
        ui.confirm("Send?", True)


def test_confirm_can_keep_the_prompt_off_machine_stdout(monkeypatch, capsys):
    prompts = []
    monkeypatch.setattr(sys, "stdin", TtyStdin())
    monkeypatch.setattr(
        builtins, "input", lambda prompt="": prompts.append(prompt) or "y"
    )
    assert ui.confirm("Send?", stream=sys.stderr) is True
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == "Send? [y/N] "
    assert prompts == [""]
