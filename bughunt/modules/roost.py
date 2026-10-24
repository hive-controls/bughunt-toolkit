"""Show the engagement at a glance: scope, counts, and URL hosts outside scope.

Read-only. Nothing is written to the workspace and nothing is contacted.
"""

from __future__ import annotations

import dataclasses
import sys
from argparse import ArgumentParser
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path

from bughunt.core import banner, cli, identity, ledger, termio
from bughunt.core.session import load_session
from bughunt.core.workspace import (
    allowed,
    hostname_of,
    read_entries,
    read_urls,
    requests_dir,
    scope_is_active,
)

_SUMMARY = "Show scope, counts, and URL hosts that fall outside scope."


_NAMEPLATE = "roost"
_TAGLINE = "the perch above this engagement"
# (columns of indent, glyphs); backslashes are escaped.
_ART = (
    (12, "___"),
    (9, ".-'   `-."),
    (8, "/   roost  \\"),
    (8, "|  (o) (o) |"),
    (9, "\\    ^    /"),
    (10, "'-----'"),
    (9, "===[ ]==="),
)


def format_banner(color: bool) -> str:
    return banner.render_banner(banner.art_rows(_ART), _NAMEPLATE, _TAGLINE, color)


_Names = tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class Report:
    entries: _Names | None
    urls: int
    requests: int
    runs: int
    cookie: bool
    authorization: bool
    outside: _Names


def _count_files(directory: Path) -> int:
    if not directory.is_dir():
        return 0
    return sum(child.is_file() for child in directory.iterdir())


def _count_runs(directory: Path) -> int:
    if not directory.is_dir():
        return 0
    return sum(
        (child / "manifest.json").is_file()
        for child in directory.iterdir()
        if child.is_dir()
    )


def _hosts_outside(urls: Iterable[str], is_allowed: Callable[[str], bool]) -> _Names:
    hosts = {hostname_of(url) for url in urls} - {""}
    return tuple(sorted(host for host in hosts if not is_allowed(host)))


def gather() -> Report:
    listed = read_urls()
    saved = load_session()
    snapshot = (
        tuple(read_entries()) if scope_is_active() else None,
        len(listed),
        _count_files(requests_dir()),
        _count_runs(ledger.runs_dir()),
        "cookie" in saved,
        "authorization" in saved,
        _hosts_outside(listed, allowed),
    )
    return Report(*snapshot)


# kind -> (plain template, coloured template) for a line of text; "pair" lines go through banner.format_pair.
_LAYOUT = {
    "heading": ("{text}", banner.ANSI.wrap("magenta", "{text}")),
    "plain": ("  {text}", "  " + banner.ANSI.wrap("white", "{text}")),
    "warn": ("  {text}", "  " + banner.ANSI.wrap("yellow", "{text}")),
}

_Item = tuple[str, str, str]


def _items(kind: str, texts: Iterable[str]) -> list[_Item]:
    return [(kind, text, "") for text in texts]


def _scope_section(entries: _Names | None) -> list[_Item]:
    if entries is None:
        body = _items("warn", ["no scope file"])
    else:
        body = _items("plain", entries or ["no entries"])
    return [("heading", "scope", ""), *body]


def _outside_section(hosts: _Names) -> list[_Item]:
    body = _items("warn", hosts) if hosts else _items("plain", ["none"])
    return [("heading", "outside", ""), *body]


def _held(flag: bool) -> str:
    return "saved" if flag else "empty"


def _line(kind: str, text: str, value: str, color: bool) -> str:
    if kind == "pair":
        return banner.format_pair(text, value, color)
    return _LAYOUT[kind][int(color)].format(text=text)


def format_report(report: Report, color: bool) -> str:
    session_text = (
        f"cookie {_held(report.cookie)}, authorization {_held(report.authorization)}"
    )
    items = [
        *_scope_section(report.entries),
        ("pair", "urls", str(report.urls)),
        ("pair", "requests", str(report.requests)),
        ("pair", "runs", str(report.runs)),
        ("pair", "session", session_text),
        *_outside_section(report.outside),
    ]
    return "".join(
        _line(kind, text, value, color) + "\n" for kind, text, value in items
    )


def build_parser() -> ArgumentParser:
    return cli.build_parser("bughunt roost", _SUMMARY, [cli.PLAIN])


def main(argv: Sequence[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    colour = termio.open_output(options.plain, format_banner)
    try:
        report = gather()
    except identity.IdentityError as problem:
        termio.say(str(problem))
        return 2
    sys.stdout.write(format_report(report, colour))
    return 0
