"""`bughunt doctor`: report what this machine has for the toolkit to lean on.

Only Python itself, rich and httpx are required. Everything else unlocks an optional feature, so
its absence is shown as a note and never fails the run.
"""

from __future__ import annotations

import importlib.metadata as metadata
import shutil
import sys
from pathlib import Path
from typing import NamedTuple

from rich.table import Table
from rich.text import Text

from bughunt import VERSION
from bughunt.console import ui
from bughunt.console.catalog import REFERENCES, locate_script
from bughunt.core import route, route_probe
from bughunt.modules import MODULES

_MIN_PYTHON = (3, 12)

# (distribution, required, hint appended to the detail)
_DISTRIBUTIONS = (
    ("rich", True, ""),
    ("httpx", True, ""),
    ("playwright", False, "powers --screenshots; run `playwright install chromium` once"),
    ("aiohttp", False, ""),
    ("requests", False, ""),
    ("urllib3", False, ""),
    ("colorama", False, ""),
    ("mitmproxy", False, ""),
    ("socksio", False, "needed by tcurl for the Tor SOCKS5 route; pip install \"bughunt[tor]\""),
)
_PROGRAMS = ("tor",)


class Check(NamedTuple):
    name: str
    ok: bool
    detail: str
    required: bool = False


def _python_check() -> Check:
    version = sys.version_info
    detail = f"{version.major}.{version.minor}.{version.micro}  ({sys.executable})"
    return Check("python", tuple(version[:2]) >= _MIN_PYTHON, detail, True)


def _distribution_check(name: str, required: bool, hint: str) -> Check:
    try:
        installed = metadata.version(name)
    except metadata.PackageNotFoundError:
        return Check(name, False, "not installed" if not hint else f"not installed  ({hint})", required)
    return Check(name, True, f"{installed}  ({hint})" if hint else installed, required)


def _program_check(name: str) -> Check:
    path = shutil.which(name)
    if path:
        return Check(name, True, path)
    return Check(name, False, f"not on PATH (tcurl needs a running {name} daemon; this only looks for the program)")


def _reference_check(tool_file: Path) -> Check:
    found = sum(1 for tool in REFERENCES if locate_script(tool, tool_file) is not None)
    return Check("reference clones", True, f"{found} of {len(REFERENCES)} visible to bughunt modules")


def _route_checks() -> list[Check]:
    """One offline row, only when a route config is found; never required, never evaluates the route."""
    located = route.locate_config()
    if located is None:
        return []
    try:
        policy = route.load_config(located)
    except route.ConfigError as error:
        return [Check("route gate", False, f"{located}  (invalid: {error})")]
    try:
        backend = f"backend {type(route_probe.default_probe()).__name__}"
    except (route_probe.ProbeError, OSError, ValueError) as error:
        backend = f"backend unavailable: {error}"
    protects = ", ".join(policy.protect) or "report only"
    return [Check("route gate", True, f"{located}  (protects: {protects}; {backend})")]


def collect_checks(tool_file: Path) -> list[Check]:
    checks = [_python_check()]
    checks.extend(_distribution_check(*row) for row in _DISTRIBUTIONS)
    checks.extend(_program_check(program) for program in _PROGRAMS)
    checks.append(_reference_check(tool_file))
    checks.append(Check("built-in modules", True, ", ".join(MODULES)))
    checks.append(Check("bughunt", True, f"{VERSION}  ({tool_file})"))
    checks.extend(_route_checks())
    return checks


def _status_cell(check: Check) -> Text:
    if check.ok:
        return Text("ok", style="ok")
    if check.required:
        return Text("missing", style="err")
    return Text("optional", style="warn")


def render(checks: list[Check]) -> int:
    table = Table(title=f"bughunt doctor  {VERSION}")
    table.add_column("Check", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail")
    for check in checks:
        table.add_row(Text(check.name), _status_cell(check), Text(check.detail))
    ui.console.print(table)
    if any(check.required and not check.ok for check in checks):
        ui.console.print("[err]A required check failed.[/err] Install the packages with: pip install -r requirements.txt")
        return 1
    ui.console.print("[ok]Every required check passed.[/ok]")
    return 0


def run(tool_file: Path) -> int:
    return render(collect_checks(tool_file))
