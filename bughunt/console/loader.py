"""Running modules by name: built-in modules, reference tools, and the scanner itself.

``run_named`` is the single door every front-end (command line, typed console, picker) goes
through. It resolves a name, runs the tool in this process, and reduces whatever happens to a
process-style exit code.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import importlib.util
import inspect
import subprocess
import sys
import traceback
from pathlib import Path
from typing import Callable

from rich.markup import escape
from rich.text import Text

from bughunt.console import ui
from bughunt.console.catalog import (
    DISABLED_REFERENCES,
    ReferenceTool,
    locate_script,
    reference_canonical,
    tool_by_command,
)
from bughunt.core import egress

ScanMain = Callable[..., int]

_FIRST_LINE_LIMIT = 200


def exit_code(raised: SystemExit) -> int:
    """Reduce a SystemExit to a process exit code."""
    status = raised.code
    if isinstance(status, int):
        return status
    return 0 if status is None else 1


def _first_line(path: Path) -> str:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        return handle.readline(_FIRST_LINE_LIMIT)


def _mentions_python(line: str) -> bool:
    return "python" in line.lower()


def _report_crash(headline: str) -> int:
    """Print a one-line failure notice, then the traceback of the exception being handled; exit code 1."""
    ui.console.print(f"[err]{headline}[/err]")
    traceback.print_exc()
    return 1


def _complain(text: str) -> None:
    ui.console.print(Text(text, style="err"))


def looks_like_python(candidate: Path) -> bool:
    """True for a .py file, or for any file whose first line names python (a shebang)."""
    if candidate.suffix.lower() == ".py":
        return True
    try:
        return _mentions_python(_first_line(candidate))
    except OSError:
        return False


# --------------------------------------------------------------------------------------
# importing a script from an arbitrary folder
# --------------------------------------------------------------------------------------


def _module_key(resolved: Path) -> str:
    digest = hashlib.sha1(str(resolved).encode()).hexdigest()[:12]
    return f"bughunt_tools.{resolved.stem.replace('-', '_')}_{digest}"


@contextlib.contextmanager
def _folder_on_path(folder: str):
    """Put ``folder`` on sys.path for the duration, unless it is already there."""
    added = folder not in sys.path
    if added:
        sys.path.insert(0, folder)
    try:
        yield
    finally:
        if added and folder in sys.path:
            sys.path.remove(folder)


def _execute_fresh(resolved: Path, key: str):
    """Run the file as a new module registered under ``key``; a failed run leaves no registry entry."""
    found = importlib.util.spec_from_file_location(key, resolved)
    source_loader = getattr(found, "loader", None)
    if source_loader is None:
        raise ImportError(f"cannot load {resolved}")
    fresh = importlib.util.module_from_spec(found)
    with contextlib.ExitStack() as rollback:
        sys.modules[key] = fresh
        rollback.callback(sys.modules.pop, key, None)
        with _folder_on_path(str(resolved.parent)):
            source_loader.exec_module(fresh)
        rollback.pop_all()
    return fresh


def import_script(source: Path):
    """Import a tool script by file path. One module object per resolved path, cached across calls."""
    resolved = Path(source).resolve()
    key = _module_key(resolved)
    existing = sys.modules.get(key)
    if getattr(existing, "__file__", None) == str(resolved):
        return existing
    return _execute_fresh(resolved, key)


# --------------------------------------------------------------------------------------
# calling main()
# --------------------------------------------------------------------------------------

_POSITIONAL_KINDS = frozenset(
    {
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.VAR_POSITIONAL,
    }
)


def _accepts_positional(function: Callable) -> bool:
    declared_kinds = {
        parameter.kind for parameter in inspect.signature(function).parameters.values()
    }
    return not declared_kinds.isdisjoint(_POSITIONAL_KINDS)


def _result_code(result) -> int:
    """An int return value is the exit code; anything else (None, bool, str, float) means success."""
    is_plain_int = isinstance(result, int) and not isinstance(result, bool)
    return result if is_plain_int else 0


def _invoke_main(entry: Callable, arguments: list[str]):
    outcome = entry(list(arguments)) if _accepts_positional(entry) else entry()
    if inspect.iscoroutine(outcome):
        outcome = asyncio.run(outcome)
    return outcome


@contextlib.contextmanager
def _argv_as(program: str, arguments: list[str]):
    """Show ``program`` and ``arguments`` as sys.argv for the duration, then put the old argv back."""
    previous = sys.argv
    sys.argv = [program, *arguments]
    try:
        yield
    finally:
        sys.argv = previous


def _call_main(module, arguments: list[str], canonical: str, origin: Path) -> int:
    entry = getattr(module, "main", None)
    if not callable(entry):
        ui.console.print(
            f"[err]{escape(canonical)} has no main() to call in {escape(str(origin))}.[/err]"
        )
        return 2
    with (
        _argv_as(f"bughunt {canonical}", arguments),
        _folder_on_path(str(Path(origin).resolve().parent)),
    ):
        try:
            return _result_code(_invoke_main(entry, arguments))
        except SystemExit as exit_request:
            return exit_code(exit_request)


def _guarded_call(module, arguments: list[str], canonical: str, origin: Path) -> int:
    """_call_main plus the failure policy shared by built-in modules and reference tools."""
    try:
        return _call_main(module, arguments, canonical, origin)
    except egress.PolicyBlocked as blocked:
        ui.console.print(Text(str(blocked)))
        return 2
    except Exception:
        return _report_crash(f"{escape(canonical)} failed.")


# --------------------------------------------------------------------------------------
# programs that are not Python
# --------------------------------------------------------------------------------------

_LOCAL_PROCESS_TARGET = "http://localhost/"


@egress.guarded("process", lambda bound: [_LOCAL_PROCESS_TARGET])
def _run_program(program: Path, arguments: list[str], canonical: str) -> int:
    try:
        shebang = _first_line(program)
    except OSError as exc:
        _complain(f"Could not read {canonical} at {program}: {exc}")
        return 1
    interpreter = sys.executable if _mentions_python(shebang) else "bash"
    try:
        completed = subprocess.run([interpreter, str(program), *arguments], check=False)
    except OSError as exc:
        _complain(f"Could not start {canonical}: {exc}")
        return 1
    return int(completed.returncode or 0)


# --------------------------------------------------------------------------------------
# run_named
# --------------------------------------------------------------------------------------


def _run_builtin(canonical: str, arguments: list[str]) -> int:
    from bughunt import modules

    try:
        module = modules.load_builtin(canonical)
    except Exception:
        return _report_crash(f"{escape(canonical)} could not be loaded.")
    origin = getattr(module, "__file__", None) or canonical
    return _guarded_call(module, arguments, canonical, Path(origin))


def _report_missing_program(
    typed: str, canonical: str, tool: ReferenceTool, dropped: list[str]
) -> None:
    label = typed if typed == canonical else f"{typed} ({canonical})"
    ui.console.print(
        f"[err]No program was found for {escape(label)}; nothing was run.[/err]"
    )
    ui.console.print(Text(f"Looked for {tool.folder}/{tool.script} under:"))
    for place in ("$BUGHUNT_ADDONS (when set)", "./addons", "../addons"):
        ui.console.print(Text(f"  {place}"))
    if dropped:
        ui.console.print(
            Text(
                f"Arguments that were not forwarded: {' '.join(dropped)}", style="muted"
            )
        )
    ui.console.print(
        Text(f"To scan a host that is literally named {typed}: bughunt scan {typed}")
    )


def _run_python_tool(canonical: str, script: Path, arguments: list[str]) -> int:
    try:
        module = import_script(script)
    except ModuleNotFoundError as exc:
        package = exc.name or str(exc)
        ui.console.print(
            f"[err]{escape(canonical)} could not start: the Python package {escape(package)} is missing.[/err]"
        )
        ui.console.print(
            f"Install the requirements for {escape(canonical)} and try again."
        )
        return 2
    except Exception:
        return _report_crash(
            f"{escape(canonical)} could not be loaded from {escape(str(script))}."
        )
    return _guarded_call(module, arguments, canonical, script)


def run_named(
    module_name: str, arguments: list[str], *, tool_file: Path, scan_main: ScanMain
) -> int:
    if module_name == "scan":
        try:
            return scan_main(list(arguments), prog="bughunt scan")
        except SystemExit as exit_request:
            return exit_code(exit_request)
    from bughunt.modules import MODULES

    canonical = reference_canonical(module_name)
    if canonical in MODULES:
        return _run_builtin(canonical, arguments)
    tool = tool_by_command(canonical) if canonical else None
    if tool is None:
        ui.console.print(
            f"[err]Unknown module {escape(module_name)}.[/err] Run bughunt modules to see what exists."
        )
        return 2
    if canonical in DISABLED_REFERENCES:
        ui.console.print(
            f"[warn]{escape(canonical)} is disabled until its network path is scope audited.[/warn]"
        )
        return 2
    script = locate_script(tool, tool_file)
    if script is None:
        _report_missing_program(module_name, canonical, tool, arguments)
        return 2
    if not looks_like_python(script):
        try:
            return _run_program(script, arguments, canonical)
        except egress.PolicyBlocked as blocked:
            ui.console.print(Text(str(blocked)))
            return 2
    return _run_python_tool(canonical, script, arguments)
