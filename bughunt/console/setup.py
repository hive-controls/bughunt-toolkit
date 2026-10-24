"""``bughunt setup``: bootstrap a source checkout (venv, pinned install, optional Chromium, workspace).

Stdlib only at import time, because it must run before any dependency is installed. Setup's
downloads (pip, playwright) are bootstrap traffic, not target traffic, and are not governed by
the mission policy gate. The subprocess use here is the installer, never a scan or gate path.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import venv
from pathlib import Path

LOCK_FILE = "requirements-hardened.txt"
_FALLBACK_MIN_PYTHON = (3, 12)
_VENV_HINT = (
    "The venv module could not finish. On Debian/Ubuntu install it first:\n"
    "  sudo apt install python3-venv   (or python3.X-venv for your Python), then re-run `bughunt setup`."
)


def _say(message: str = "") -> None:
    print(message, flush=True)


def _minimum_python() -> tuple[int, int]:
    try:
        from bughunt.console.doctor import _MIN_PYTHON
    except ImportError:
        return _FALLBACK_MIN_PYTHON
    return _MIN_PYTHON


def checkout_root() -> Path:
    return Path(__file__).resolve().parents[2]


def is_source_checkout(root: Path) -> bool:
    return (root / LOCK_FILE).is_file()


def venv_python(venv_dir: Path) -> Path:
    if sys.platform == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _run_command(command: list[str], cwd: Path | None) -> int:
    return subprocess.run(command, cwd=cwd, check=False).returncode


def _create_venv(venv_dir: Path) -> None:
    venv.EnvBuilder(with_pip=True).create(venv_dir)


def _run_stage(label: str, command: list[str], cwd: Path | None) -> int:
    _say(f"[{label}] $ " + " ".join(command))
    code = _run_command(command, cwd)
    if code != 0:
        _say(f"[{label}] FAILED (exit {code}): " + " ".join(command))
    return code


def _ensure_venv(venv_dir: Path) -> Path | None:
    interpreter = venv_python(venv_dir)
    if interpreter.exists():
        _say(f"[venv] reusing existing venv at {venv_dir}")
        return interpreter
    _say(f"[venv] creating {venv_dir}")
    try:
        _create_venv(venv_dir)
    except (subprocess.CalledProcessError, ImportError, OSError) as failure:
        _say(f"[venv] FAILED: {failure}")
        _say(_VENV_HINT)
        return None
    return interpreter


def _install_stage(interpreter: Path, root: Path) -> int:
    steps = (
        [str(interpreter), "-m", "pip", "install", "-r", str(root / LOCK_FILE)],
        [str(interpreter), "-m", "pip", "install", "-e", str(root)],
    )
    for command in steps:
        code = _run_stage("install", command, root)
        if code != 0:
            return code
    return 0


def _self_check(interpreter: str, cwd: Path | None) -> int:
    for word in ("version", "doctor"):
        code = _run_stage("check", [interpreter, "-m", "bughunt", word], cwd)
        if code != 0:
            return code
    return 0


def _workspace_stage() -> None:
    from bughunt.core.workspace import init_workspace

    _say(f"[workspace] ready at {init_workspace()}")


def _next_step_line() -> None:
    try:
        from bughunt.console import readiness

        _say(readiness.gather().next_step()[1])
    except ImportError:
        _say("Next: bughunt guide")


def _build_environment(args: argparse.Namespace, root: Path) -> tuple[str, int]:
    """Return (interpreter, exit code); a nonzero code means a stage failed and was reported."""
    if not is_source_checkout(root):
        _say(f"[install] no {LOCK_FILE} beside the package: already installed, skipping the install stage")
        return sys.executable, 0
    if sys.version_info < _minimum_python():
        wanted = ".".join(map(str, _minimum_python()))
        _say(f"[python] FAILED: Python {wanted}+ is required, this is {sys.version.split()[0]}")
        return "", 1
    if args.no_venv:
        _say("[venv] --no-venv: installing into the current interpreter")
        interpreter = Path(sys.executable)
    else:
        found = _ensure_venv(Path(args.venv) if args.venv else root / ".venv")
        if found is None:
            return "", 1
        interpreter = found
    code = _install_stage(interpreter, root)
    return str(interpreter), code


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="bughunt setup", description="Bootstrap a source checkout.")
    parser.add_argument("--venv", metavar="DIR", help="virtualenv location (default: .venv in the checkout)")
    parser.add_argument("--no-venv", action="store_true", help="install into the current interpreter")
    parser.add_argument("--browser", action="store_true", help="also download Chromium (for scan --screenshots)")
    parser.add_argument("--no-workspace", action="store_true", help="do not create the workspace files")
    return parser.parse_args(argv)


def run(argv: list[str]) -> int:
    try:
        args = _parse(list(argv))
    except SystemExit as request:
        return request.code if isinstance(request.code, int) else 0
    root = checkout_root()
    interpreter, code = _build_environment(args, root)
    if code != 0:
        return code
    if args.browser:
        code = _run_stage("browser", [interpreter, "-m", "playwright", "install", "chromium"], None)
        if code != 0:
            return code
    else:
        _say("[browser] skipped (add --browser to download Chromium for scan --screenshots)")
    code = _self_check(interpreter, root if is_source_checkout(root) else None)
    if code != 0:
        return code
    if args.no_workspace:
        _say("[workspace] skipped (--no-workspace)")
    else:
        _workspace_stage()
    _next_step_line()
    return 0
