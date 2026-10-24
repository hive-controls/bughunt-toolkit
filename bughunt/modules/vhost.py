"""Request one in-scope address once per Host name.

The connection always goes to the one address. Only the Host header changes, so the
status, size, and title show which names the server treats differently.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

from bughunt.core import cli, termio
from bughunt.core.http import client, read_body
from bughunt.core.workspace import (
    allowed,
    authority,
    explain_block,
    explain_target,
    fold_host,
    parse_ip,
    read_entries,
    scope_is_active,
)

_BODY_CAP = 1_000_000
_NAME_BUDGET = 50
_TITLE_WIDTH = 80
_TITLE_TAG = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_DEFAULT_PORTS = {"http": 80, "https": 443}
_COLUMNS = ("host", "status", "bytes", "title")


@dataclass(frozen=True)
class _Roster:
    """Which names get a request, how many were left out of scope, and whether the limit cut in."""

    chosen: list[str]
    skipped: int
    stopped: bool


_ARGUMENTS = (
    (("url",), {"help": "Address to connect to, such as http://127.0.0.1:8080/."}),
    (
        ("names",),
        {
            "nargs": "*",
            "help": "Host names. With none, hostnames from the scope file are used.",
        },
    ),
    (("--names",), {"dest": "names_file", "help": "File of host names, one per line."}),
    (
        ("--limit",),
        {
            "type": int,
            "default": _NAME_BUDGET,
            "help": "Maximum names to request. Default 50.",
        },
    ),
    (
        ("--timeout",),
        {
            "type": float,
            "default": 10.0,
            "help": "Seconds for each request. Default 10.",
        },
    ),
    cli.INSECURE,
    *cli.SESSION_OPTIONS,
)


def build_parser() -> argparse.ArgumentParser:
    return cli.build_parser(
        "bughunt vhost",
        "Request one in-scope address once per Host name. Prints status, size, and title.",
        _ARGUMENTS,
    )


def _tabbed(cells: Iterable[object]) -> str:
    return "\t".join(termio.neutralize(str(cell)) for cell in cells)


def _unique(names: Iterable[str]) -> list[str]:
    earliest: dict[str, str] = {}
    for spelling in (name.strip().rstrip(".") for name in names):
        earliest.setdefault(spelling.lower(), spelling)
    return [spelling for key, spelling in earliest.items() if key]


def _plain_hostname(entry: str) -> bool:
    return not entry.startswith("*.") and "/" not in entry and parse_ip(entry) is None


def _names_in_file(file_name: str) -> list[str]:
    text = Path(file_name).read_text(encoding="utf-8", errors="replace")
    return [
        entry for line in text.splitlines() if (entry := line.split("#", 1)[0].strip())
    ]


def collect_names(words: list[str], file_name: str | None) -> list[str]:
    given = [*words, *(_names_in_file(file_name) if file_name else ())]
    return _unique(
        given or (entry for entry in read_entries() if _plain_hostname(entry))
    )


def canonical_target(value: str) -> str | None:
    stripped = value.strip()
    try:
        url = urlsplit(stripped if "://" in stripped else f"http://{stripped}")
        if url.scheme not in _DEFAULT_PORTS or not url.hostname:
            return None
        netloc = authority(
            fold_host(url.hostname), url.port, omit=(_DEFAULT_PORTS[url.scheme],)
        )
    except ValueError:
        return None
    return urlunsplit((url.scheme, netloc, url.path or "/", url.query, ""))


def host_header(name: str, port: int | None, scheme: str) -> str:
    host = name.strip().rstrip(".")
    if ":" in host and parse_ip(host) is None:
        return host
    return authority(host, port or None, omit=(_DEFAULT_PORTS.get(scheme, 80),))


def page_title(text: str) -> str:
    found = _TITLE_TAG.search(text)
    return " ".join(found[1].split())[:_TITLE_WIDTH] if found else ""


def fetch_one(http: httpx.Client, url: str, host: str) -> tuple[int, int, str]:
    with http.stream("GET", url, headers={"Host": host}) as reply:
        body = read_body(reply, _BODY_CAP)
        return (
            reply.status_code,
            len(body),
            page_title(body.decode("utf-8", errors="replace")),
        )


def _admit(ordered: list[str], limit: int) -> _Roster:
    enforce = scope_is_active()
    picked: list[str] = []
    refused = 0
    for candidate in ordered:
        if len(picked) == limit:
            break
        if enforce and not allowed(candidate):
            refused += 1
            continue
        picked.append(candidate)
    return _Roster(picked, refused, len(ordered) - refused > limit)


def _measure(
    http: httpx.Client, target: str, names: list[str]
) -> Iterator[tuple[tuple[object, ...], bool]]:
    """One table row per name, with a flag for rows that carry an error instead of a response."""
    url = urlsplit(target)
    for candidate in names:
        header = host_header(candidate, url.port, url.scheme)
        try:
            row, errored = (header, *fetch_one(http, target, header)), False
        except httpx.HTTPError as failure:
            row, errored = (header, "error", 0, type(failure).__name__), True
        yield row, errored


def _probe(parsed: argparse.Namespace, target: str, names: list[str]) -> int:
    errors = 0
    try:
        with client(
            parsed.timeout,
            insecure=parsed.insecure,
            cookie=parsed.cookie,
            authorization=parsed.authorization,
        ) as http:
            for row, errored in _measure(http, target, names):
                print(_tabbed(row))
                errors += errored
    except httpx.HTTPError as failure:
        raise cli.CommandExit(
            1, f"Could not connect: {type(failure).__name__}"
        ) from failure
    return errors


def _requested_names(parsed: argparse.Namespace) -> list[str]:
    try:
        names = collect_names(parsed.names, parsed.names_file)
    except OSError as failure:
        raise cli.CommandExit(1, f"Could not read names: {failure}") from failure
    if names:
        return names
    raise cli.CommandExit(
        2, "Pass host names, or add hostnames with bughunt scope add."
    )


def _vet(parsed: argparse.Namespace) -> tuple[str, list[str]]:
    if parsed.limit < 1 or parsed.timeout <= 0:
        raise cli.CommandExit(2, "Limit and timeout must be greater than 0.")
    target = canonical_target(parsed.url)
    if not target:
        raise cli.CommandExit(
            2, "Give an http or https URL, such as http://127.0.0.1:8080/."
        )
    if allowed(target):
        return target, _requested_names(parsed)
    raise cli.CommandExit(2, explain_target(target))


def _run(parsed: argparse.Namespace) -> int:
    target, names = _vet(parsed)
    roster = _admit(_unique([urlsplit(target).hostname or "", *names]), parsed.limit)
    if not roster.chosen:
        raise cli.CommandExit(2, explain_block(names[0]))
    print(_tabbed(_COLUMNS))
    errors = _probe(parsed, target, roster.chosen)
    if roster.skipped:
        termio.say(f"{roster.skipped} name(s) outside scope")
    if roster.stopped:
        termio.say(f"Stopped after {parsed.limit} names.")
    return int(errors > 0 and errors == len(roster.chosen))


def main(argv: list[str] | None = None) -> int:
    return cli.run(_run, build_parser().parse_args(argv))
