"""List the raw requests snare saved, or print one with its secrets blanked.

Files are only read. Nothing here touches the network.
"""

from __future__ import annotations

import dataclasses
import sys
from argparse import ArgumentParser, Namespace
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from bughunt.core import banner, cli, termio
from bughunt.core.workspace import allowed, fold_host, requests_dir
from bughunt.modules import MODULES
from bughunt.modules.repeater import endpoint, parse_raw, path_and_query

_SIZE_LIMIT = 1_000_000
_BLANKED_HEADERS = frozenset({"cookie", "authorization", "proxy-authorization"})
_BLANK = "[blank]"
_SHOW_HINT = "clutch show <name> prints one."
_EMPTY_NOTICE = (
    "no saved requests",
    "snare writes requests/example.com-snare-0001.http while it listens.",
    _SHOW_HINT,
)
_BAD_NAME = "Give the file name inside the requests directory."
_ACKNOWLEDGED = "Saved request {}. repeater can send that file again."


# ---- terminal layer -------------------------------------------------------------------------

_NAMEPLATE = "clutch"
_TAGLINE = "requests held in the talons"
# "|" is the left margin of the picture; backslashes are literal.
_PICTURE = r"""
|            \\   //
|             \\ //
|              \V/
|          .--------.
|          | clutch |
|          '--------'
|            [held]
"""
_ART = [line[1:] for line in _PICTURE.strip("\n").splitlines()]


def format_banner(color: bool) -> str:
    return banner.render_banner(_ART, _NAMEPLATE, _TAGLINE, color)


# ---- classifying saved requests -----------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Held:
    name: str
    method: str
    host: str
    path: str
    scope: str


def _unreadable(name: str, reason: str) -> Held:
    return Held(name, "?", "?", "?", reason)


def _scope_label(host: str) -> str:
    if host:
        return "in scope" if allowed(host) else "outside"
    return "no host"


def _describe(name: str, request: Any) -> Held:
    host = fold_host(endpoint(request, None)[0])
    return Held(
        name, request.method, host or "-", path_and_query(request), _scope_label(host)
    )


def _classify(path: Path) -> Held:
    if path.stat().st_size > _SIZE_LIMIT:
        return _unreadable(path.name, "too large")
    try:
        request = parse_raw(path.read_bytes())
        return _describe(path.name, request)
    except (ValueError, OSError):
        return _unreadable(path.name, "unreadable")


def _saved_files() -> list[Path]:
    folder = requests_dir()
    entries = folder.iterdir() if folder.is_dir() else ()
    return sorted(
        (entry for entry in entries if entry.is_file()),
        key=lambda entry: entry.name.lower(),
    )


def list_requests() -> list[Held]:
    return [_classify(path) for path in _saved_files()]


def _blank_userinfo(target: str) -> str:
    parts = urlsplit(target)
    if "@" not in parts.netloc:
        return target
    host = parts.netloc.rpartition("@")[2]
    return urlunsplit(parts._replace(netloc=f"{_BLANK}@{host}"))


def redact(data: bytes) -> str:
    request = parse_raw(data)
    lines = [f"{request.method} {_blank_userinfo(request.target)} {request.version}"]
    lines += [
        f"{name}: {_BLANK if name.lower() in _BLANKED_HEADERS else value}"
        for name, value in request.headers
    ]
    return "\r\n".join(lines) + "\r\n\r\n" + request.body.decode("latin-1", "replace")


def format_row(row: Held, color: bool) -> str:
    row = Held(*(termio.neutralize(cell) for cell in dataclasses.astuple(row)))
    if color:
        hues = banner.ANSI
        method = hues.wrap("cyan", f"{row.method:<6}")
        target = hues.wrap("white", f"{row.host} {row.path}")
        scope = hues.wrap("white" if row.scope == "in scope" else "yellow", row.scope)
        return f"  {method} {target}  {scope}  {hues.wrap('dim', row.name)}"
    return "\t".join(dataclasses.astuple(row))


# ---- verbs ------------------------------------------------------------------------------------


def _request_file(name: str) -> Path:
    if not name or name in (".", "..") or name != Path(name).name:
        raise cli.CommandExit(2, _BAD_NAME)
    located = requests_dir() / name
    if not located.is_file():
        raise cli.CommandExit(2, f"No saved request named {Path(name).name}.")
    if located.stat().st_size > _SIZE_LIMIT:
        raise cli.CommandExit(2, f"{located.name} is larger than {_SIZE_LIMIT} bytes.")
    return located


def request_text(name: str) -> str:
    saved = _request_file(name)
    try:
        text = redact(saved.read_bytes())
    except ValueError as unparsable:
        raise cli.CommandExit(1, str(unparsable)) from unparsable
    except OSError as unreadable:
        raise cli.CommandExit(1, f"Could not read {saved.name}.") from unreadable
    text = "\r\n".join(
        termio.neutralize(part, keep_lines=True) for part in text.split("\r\n")
    )
    return text


def _show(args: Namespace, color: bool) -> None:
    text = request_text(args.name)
    sys.stdout.write(text if text.endswith("\n") else text + "\n")
    termio.say(_ACKNOWLEDGED.format(args.name))


def _footer(listing: list[Held]) -> tuple[str, ...]:
    return (
        (f"{len(listing)} saved request(s)", _SHOW_HINT) if listing else _EMPTY_NOTICE
    )


def _list(args: Namespace, color: bool) -> None:
    listing = list_requests()
    if listing:
        print("\n".join(format_row(row, color) for row in listing))
    for line in _footer(listing):
        termio.say(line)


# Declaration order is the order the console and the catalog show.
_SUBS = {
    "list": cli.Verb("List saved requests.", _list),
    "show": cli.Verb(
        "Print one saved request with secrets blanked.",
        _show,
        ((("name",), {"help": "File name inside the requests directory."}),),
    ),
}
_DEFAULT_SUB = "list"


def build_parser() -> ArgumentParser:
    root = cli.build_parser("bughunt clutch", MODULES["clutch"], [cli.PLAIN])
    cli.add_verbs(root, _SUBS)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    colour = termio.open_output(options.plain, format_banner)
    return cli.run(_SUBS[options.command or _DEFAULT_SUB].run, options, colour)
