"""Compare two responses: saved files, names in responses/, or in-scope http(s) URLs.

Files are read locally. A URL is fetched with one GET, only after the scope check,
through the shared HTTP client (so the egress policy and saved session apply).
"""

from __future__ import annotations

import contextlib
import difflib
import re
import sys
from argparse import ArgumentParser, Namespace
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from bughunt.core import cli, termio
from bughunt.core import http as core_http
from bughunt.core.workspace import allowed, explain_target, responses_dir
from bughunt.modules import MODULES

_BODY_CAP = 200_000
_IGNORED_HEADERS = frozenset({"date"})
_SEPARATORS = frozenset("/\\")
_SOURCE_HELP = "Response file, a name in responses/, or an http(s) URL."
_NO_FILE = "No file named {}."
_BAD_TIMEOUT = "Timeout must be greater than 0."

_Headers = dict[str, str]


@dataclass
class Side:
    label: str
    status: str
    headers: _Headers = field(default_factory=dict)
    body: str = ""
    truncated: bool = False
    body_size: int | None = None


# ---- reading one side ---------------------------------------------------------------------


def _status_of(first_line: str) -> str:
    first = first_line.strip()
    shouted = first.upper()
    if shouted.startswith("HTTP/"):
        fields = first.split()
        return fields[1] if len(fields) > 1 else first
    return first if " HTTP/" in shouted else ""


def _header_map(lines: list[str]) -> _Headers:
    merged: _Headers = {}
    for line in lines:
        name, colon, value = line.partition(":")
        if not colon:
            continue
        key, value = name.strip().lower(), value.strip()
        merged[key] = f"{merged[key]}, {value}" if key in merged else value
    return merged


def _split_message(text: str) -> tuple[str, _Headers, str]:
    head, gap, body = text.replace("\r\n", "\n").partition("\n\n")
    if not gap:
        return "", {}, text
    first, *header_lines = head.split("\n")
    return _status_of(first), _header_map(header_lines), body


def parse_saved(data: bytes) -> tuple[str, _Headers, str, bool]:
    text = data[:_BODY_CAP].decode("utf-8", errors="replace")
    return (*_split_message(text), len(data) > _BODY_CAP)


def _is_bare_name(value: str) -> bool:
    plain = value not in ("", ".", "..") and Path(value).name == value
    return plain and _SEPARATORS.isdisjoint(value)


def _saved_file(value: str) -> Path | None:
    candidates = [Path(value)]
    if _is_bare_name(value):
        candidates.append(responses_dir() / value)
    return next((path for path in candidates if path.is_file()), None)


def _is_http_url(value: str) -> bool:
    parts = urlsplit(value.strip()) if "://" in value else None
    if parts is not None and parts.scheme in ("http", "https"):
        authority = parts.netloc.rsplit("@", 1)[-1]
        suffix = authority.partition("]")[2] if "]" in authority else ""
        if authority.endswith(":") or (suffix and not suffix.startswith(":")):
            raise ValueError("invalid port or bracketed host suffix")
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError("destination port must be 1 through 65535")
    return (
        parts is not None and parts.scheme in ("http", "https") and bool(parts.hostname)
    )


def _fetch_side(url: str, http: httpx.Client) -> Side:
    with http.stream("GET", url) as response:
        raw = core_http.read_body(response, _BODY_CAP + 1)
        headers = {name.lower(): value for name, value in response.headers.items()}
        status = str(response.status_code)
    body = raw[:_BODY_CAP].decode("utf-8", errors="replace")
    return Side(url, status, headers, body, len(raw) > _BODY_CAP, len(raw[:_BODY_CAP]))


def load_side(value: str, http: httpx.Client | None) -> Side:
    source = _saved_file(value)
    if source is not None:
        data = source.read_bytes()
        bounded = data[:_BODY_CAP]
        boundary = re.search(rb"\r?\n\r?\n", bounded)
        body_size = len(bounded) - (boundary.end() if boundary else 0)
        return Side(value, *parse_saved(data), body_size=body_size)
    if _is_http_url(value) and http is not None:
        return _fetch_side(value, http)
    raise FileNotFoundError(_NO_FILE.format(value))


# ---- rendering: each section turns the two sides into report lines ---------------------------


def _shown(status: str) -> str:
    return status or "(none)"


def _status_lines(left: Side, right: Side) -> list[str]:
    before, after = _shown(left.status), _shown(right.status)
    unchanged = left.status == right.status
    return [f"status: {before}" if unchanged else f"status: {before} -> {after}"]


def _header_lines(left: Side, right: Side) -> list[str]:
    old, new = left.headers, right.headers
    lines = []
    for name in sorted((old.keys() | new.keys()) - _IGNORED_HEADERS):
        if name not in new:
            lines.append(f"header {name}: removed {old[name]}")
        elif name not in old:
            lines.append(f"header {name}: added {new[name]}")
        elif old[name] != new[name]:
            lines.append(f"header {name}: {old[name]} -> {new[name]}")
    return lines


def _truncation_lines(left: Side, right: Side) -> list[str]:
    capped = left.truncated or right.truncated
    return [f"body compared at the first {_BODY_CAP} bytes"] if capped else []


def _unified(left: Side, right: Side) -> Iterator[str]:
    texts = [side.body.splitlines(keepends=True) for side in (left, right)]
    patch = difflib.unified_diff(*texts, fromfile=left.label, tofile=right.label)
    return (line.rstrip("\n") for line in patch)


def _body_lines(left: Side, right: Side) -> list[str]:
    if left.body != right.body:
        if "\x00" in left.body or "\x00" in right.body:
            sizes = [
                side.body_size
                if side.body_size is not None
                else len(side.body.encode("utf-8"))
                for side in (left, right)
            ]
            return [f"body: {sizes[0]} bytes -> {sizes[1]} bytes"]
        return ["body:", *_unified(left, right)]
    return ["body: unchanged"]


_SECTIONS = (_status_lines, _header_lines, _truncation_lines, _body_lines)


def render_diff(left: Side, right: Side) -> str:
    lines = [
        termio.neutralize(line)
        for section in _SECTIONS
        for line in section(left, right)
    ]
    return "\n".join([*lines, ""])


# ---- the command --------------------------------------------------------------------------


def _remote_sources(args: Namespace) -> list[str]:
    return [
        item
        for item in (args.left, args.right)
        if _is_http_url(item) and not Path(item).is_file()
    ]


def _vet_fetches(args: Namespace) -> list[str]:
    limit = args.timeout
    if limit <= 0:
        raise cli.CommandExit(2, _BAD_TIMEOUT)
    try:
        urls = _remote_sources(args)
    except ValueError as problem:
        raise cli.CommandExit(2, f"Invalid response URL: {problem}") from problem
    blocked = next((url for url in urls if not allowed(url)), None)
    if blocked is not None:
        raise cli.CommandExit(2, explain_target(blocked))
    return urls


def _session_for(
    args: Namespace, urls: list[str]
) -> contextlib.AbstractContextManager[httpx.Client | None]:
    if not urls:
        return contextlib.nullcontext()
    http = core_http.client(
        args.timeout,
        insecure=args.insecure,
        cookie=args.cookie,
        authorization=args.authorization,
    )
    return contextlib.closing(http)


def _load_sides(args: Namespace, urls: list[str]) -> tuple[Side, Side]:
    try:
        with _session_for(args, urls) as http:
            left = load_side(args.left, http)
            if http is not None:
                http.cookies.clear()
            return left, load_side(args.right, http)
    except FileNotFoundError as missing:
        raise cli.CommandExit(2, str(missing)) from missing
    except httpx.HTTPError as failure:
        raise cli.CommandExit(
            1, f"Could not fetch: {type(failure).__name__}"
        ) from failure


_ARGUMENTS = (
    (("left",), {"help": _SOURCE_HELP}),
    (("right",), {"help": _SOURCE_HELP}),
    (
        ("--timeout",),
        {"type": float, "default": 10.0, "help": "Seconds for each fetch. Default 10."},
    ),
    cli.INSECURE,
    *cli.SESSION_OPTIONS,
)


def build_parser() -> ArgumentParser:
    return cli.build_parser("bughunt diff", MODULES["diff"], _ARGUMENTS)


def _compare(options: Namespace) -> int:
    sys.stdout.write(render_diff(*_load_sides(options, _vet_fetches(options))))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return cli.run(_compare, build_parser().parse_args(argv))
