"""Shared helpers for the console characterization oracle (M2 clean-room rebuild).

Not a test module. The `test_console_*.py` files import fixtures and helpers from here.
Everything is hermetic: a scratch BUGHUNT_SCOPE, no BUGHUNT_ADDONS/BUGHUNT_HISTORY, no network,
no real module run unless a test says so.

Only the public surface from the M2 console spec section 1.2 is used, plus the
names section 3.1/5.1/8.1 declare as contract attributes.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import pytest
from rich.console import Console

from bughunt.console import catalog, ui
from bughunt.core import scanner

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNER_FILE = Path(scanner.__file__).resolve()
BUILD_PARSER = scanner.build_parser

# Reference commands that ship in the repo checkout (the 9 spec REFERENCES minus nothing).
REFERENCE_COMMANDS = [tool.command for tool in catalog.REFERENCES]


@dataclass
class Env:
    """Captured streams plus the scratch directories for one test."""

    root: Path
    scope: Path
    out: io.StringIO
    err: io.StringIO
    rich: io.StringIO
    monkeypatch: object = None
    activated: bool = False

    def activate(self) -> "Env":
        """Point sys.stdout/sys.stderr at the buffers (idempotent: only the first call acts).

        Must run inside the test body: pytest's capture re-points sys.stdout/sys.stderr at
        the start of the call phase, which would undo a fixture-time replacement. A test that
        installs its own sys.stdout calls `activate()` first so the helpers never override it.
        """
        if not self.activated:
            self.monkeypatch.setattr(sys, "stdout", self.out)
            self.monkeypatch.setattr(sys, "stderr", self.err)
            self.activated = True
        return self

    @property
    def rich_text(self) -> str:
        return self.rich.getvalue()

    @property
    def stdout_text(self) -> str:
        return self.out.getvalue()

    @property
    def stderr_text(self) -> str:
        return self.err.getvalue()

    @property
    def all_text(self) -> str:
        return self.rich_text + self.stdout_text


def _install_streams(monkeypatch, *, merged: bool) -> tuple[io.StringIO, io.StringIO, io.StringIO]:
    out, err = io.StringIO(), io.StringIO()
    rich_stream = out if merged else io.StringIO()
    monkeypatch.setattr(
        ui, "console", Console(file=rich_stream, theme=ui.THEME, highlight=False, width=200)
    )
    return out, err, rich_stream


def build_env(monkeypatch, tmp_path: Path, *, merged: bool = False) -> Env:
    scope = tmp_path / "scope"
    scope.mkdir(exist_ok=True)
    for name in list(os.environ):
        if name.startswith("BUGHUNT_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BUGHUNT_SCOPE", str(scope))
    monkeypatch.setenv("BUGHUNT_HISTORY", str(tmp_path / "history"))
    out, err, rich_stream = _install_streams(monkeypatch, merged=merged)
    created = Env(tmp_path, scope, out, err, rich_stream, monkeypatch)
    ACTIVE_ENV.append(created)
    return created


ACTIVE_ENV: list[Env] = []


def _activate_current() -> None:
    if ACTIVE_ENV:
        ACTIVE_ENV[-1].activate()


@pytest.fixture
def env(monkeypatch, tmp_path):
    """Scratch scope, replaced ui.console; call `env.activate()` (or run_dispatch/run_session)
    in the test body to also capture sys.stdout/sys.stderr in separate buffers."""
    created = build_env(monkeypatch, tmp_path)
    yield created
    ACTIVE_ENV.clear()


@pytest.fixture
def merged_env(monkeypatch, tmp_path):
    """Like `env`, but ui.console and sys.stdout share ONE buffer (the real piped layout)."""
    created = build_env(monkeypatch, tmp_path, merged=True)
    yield created
    ACTIVE_ENV.clear()


class ScanRecorder:
    """A stand-in for scanner.scan_main: records (args, prog) and returns/raises on cue."""

    def __init__(self, result=0, raises: BaseException | None = None) -> None:
        self.calls: list[tuple[list[str], str]] = []
        self.result = result
        self.raises = raises
        self.tool_labels: list[str] = []

    def __call__(self, argv, prog="bughunt"):
        from bughunt.core import ledger

        self.calls.append((list(argv), prog))
        self.tool_labels.append(ledger.CURRENT_TOOL.get())
        if self.raises is not None:
            raise self.raises
        return self.result


def forbidden_scan(*args, **kwargs):
    raise AssertionError("scan_main must not be reached by this command")


def run_dispatch(
    argv,
    *,
    scan_main: Callable | None = None,
    build_parser=BUILD_PARSER,
    tool_file: Path = SCANNER_FILE,
    interactive: bool | None = False,
) -> int:
    from bughunt.console import cli

    _activate_current()
    return cli.dispatch(
        argv,
        scan_main=scan_main or forbidden_scan,
        build_parser=build_parser,
        tool_file=tool_file,
        interactive=interactive,
    )


def make_project(root: Path, addons: dict[str, str] | None = None) -> Path:
    """A fake source tree `<root>/proj` and the tool_file inside it.

    `addons` maps a REFERENCES command to the Python source of its script. The script is
    written to `<root>/proj/addons/<folder>/<script>` so the post-M0 `addon_roots` anchor
    (`tool_file.resolve().parents[2]`) finds it. Returns `<root>/proj/bughunt/core/scanner.py`.
    """
    project = root / "proj"
    tool_file = project / "bughunt" / "core" / "scanner.py"
    tool_file.parent.mkdir(parents=True, exist_ok=True)
    tool_file.write_text("# fake scanner\n", encoding="utf-8")
    for command, source in (addons or {}).items():
        tool = catalog.tool_by_command(command)
        assert tool is not None, command
        script = project / "addons" / tool.folder / tool.script
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text(source, encoding="utf-8")
    return tool_file


class TtyText(io.StringIO):
    """A StringIO that claims to be a terminal."""

    def isatty(self) -> bool:
        return True


class TtyStdin(io.StringIO):
    def isatty(self) -> bool:
        return True


@dataclass
class Session:
    rc: int = 0
    prompts: list[str] = field(default_factory=list)
    marks: list[int] = field(default_factory=list)
    runner_calls: list[tuple] = field(default_factory=list)
    merge_calls: list[tuple] = field(default_factory=list)
    env: Env | None = None

    def chunk(self, index: int) -> str:
        """Console output produced by the command read at prompt `index` (0-based)."""
        text = self.env.rich_text if self.env.rich is not self.env.out else self.env.stdout_text
        return text[self.marks[index]:self.marks[index + 1]]


def run_session(
    env: Env,
    lines: list,
    *,
    runner: Callable | None = None,
    merger: Callable | None = None,
    tool_file: Path = SCANNER_FILE,
    build_parser=BUILD_PARSER,
    write_prompt: bool = False,
    scan_main: Callable | None = None,
    real_pipeline: bool = False,
) -> Session:
    """Drive `run_console` with an injected reader.

    `lines` items are strings, `EOFError`/`KeyboardInterrupt` instances (raised), or `None`.
    The reader records every prompt. With `write_prompt` it also writes the prompt to
    sys.stdout, exactly as the builtin `input()` does when stdin is a pipe.
    Running past the last line raises EOFError (end of piped input).
    """
    from bughunt.console import console as repl

    env.activate()
    session = Session(env=env)
    pending = list(lines)
    stream = env.out if env.rich is env.out else env.rich

    def reader(prompt: str):
        session.prompts.append(prompt)
        session.marks.append(len(stream.getvalue()))
        if write_prompt:
            sys.stdout.write(prompt)
            sys.stdout.flush()
        if not pending:
            raise EOFError
        item = pending.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def default_runner(name, argv, *, tool_file, scan_main):
        session.runner_calls.append((name, list(argv)))
        return 0

    def default_merger(name, argv, saved, *, tool_file, build_parser):
        session.merge_calls.append((name, list(argv), dict(saved)))
        from bughunt.console import options

        return options.prepare_argv(name, argv, saved, tool_file=tool_file, build_parser=build_parser)

    def recording_runner(name, argv, *, tool_file, scan_main):
        session.runner_calls.append((name, list(argv)))
        return runner(name, argv, tool_file=tool_file, scan_main=scan_main)

    session.rc = repl.run_console(
        tool_file=tool_file,
        scan_main=scan_main or forbidden_scan,
        read_line=reader,
        run_module=None if real_pipeline else (recording_runner if runner else default_runner),
        build_parser=build_parser,
        merge_argv=None if real_pipeline else (merger or default_merger),
    )
    session.marks.append(len(stream.getvalue()))
    return session


def find_git_bash() -> str | None:
    """A POSIX bash that can run completion functions, or None (never the WSL launcher)."""
    candidates: list[str] = []
    if os.environ.get("BASH"):
        candidates.append(os.environ["BASH"])
    found = shutil.which("bash")
    if found:
        candidates.append(found)
    exepath = os.environ.get("EXEPATH")
    if exepath:
        candidates.append(str(Path(exepath) / "bash.exe"))
    for candidate in candidates:
        lowered = candidate.lower().replace("/", "\\")
        if "\\windows\\system32\\" in lowered or "\\windowsapps\\" in lowered:
            continue
        if not Path(candidate).is_file():
            continue
        try:
            probe = subprocess.run(
                [candidate, "-c", "type compgen >/dev/null && echo ok"],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0 and probe.stdout.strip() == "ok":
            return candidate
    return None


def clean_subprocess_env(tmp_path: Path) -> dict[str, str]:
    """Environment for `python -m bughunt` runs: no BUGHUNT_* leakage, scratch scope."""
    clean = {key: value for key, value in os.environ.items() if not key.startswith("BUGHUNT_")}
    clean["PYTHONPATH"] = str(REPO_ROOT)
    clean["BUGHUNT_SCOPE"] = str(tmp_path / "scope")
    clean["BUGHUNT_HISTORY"] = str(tmp_path / "history")
    clean["PYTHONIOENCODING"] = "utf-8"
    clean["NO_COLOR"] = "1"
    return clean


def run_cli(tmp_path: Path, args: list[str], *, stdin: str = "", timeout: int = 120):
    return subprocess.run(
        [sys.executable, "-m", "bughunt", *args],
        input=stdin, cwd=tmp_path, env=clean_subprocess_env(tmp_path),
        capture_output=True, text=True, encoding="utf-8", timeout=timeout,
    )
