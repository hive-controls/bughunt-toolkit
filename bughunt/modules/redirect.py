"""Follow redirects on one in-scope URL, one request per hop.

The chain goes to stdout and every message to stderr. The walk ends when a hop would leave the
starting hostname, so the foreign address is printed but never requested.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterator
from dataclasses import dataclass
from itertools import islice
from urllib.parse import urlsplit

import httpx

from bughunt.core import pagefetch, termio
from bughunt.core.http import client, redirect_target, stream_hop
from bughunt.core.workspace import allowed, explain_target

_HOPS_DEFAULT = 10
_HOPS_CEILING = 20
_BOUNDS_MESSAGE = "Limit must be 1 through 20. Timeout must be greater than 0."
_SHAPE_MESSAGE = "Give an http or https URL, such as http://127.0.0.1/."

_OPTIONS = (
    (("url",), {"help": "In-scope URL to start from."}),
    (("--limit",), {"type": int, "default": _HOPS_DEFAULT, "help": "Maximum hops. Default 10."}),
    (("--timeout",), {"type": float, "default": 10.0, "help": "Seconds for each hop. Default 10."}),
    (("--insecure",), {"action": "store_true", "help": "Do not verify TLS certificates."}),
    (("--cookie",), {"help": "Cookie for this run. Replaces the saved session cookie."}),
    (("--authorization",), {"help": "Authorization for this run. Replaces the saved session value."}),
)


def build_parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        prog="bughunt redirect",
        description="Follow redirects and stop when a hop leaves the host or scope.",
    )
    for flags, settings in _OPTIONS:
        cli.add_argument(*flags, **settings)
    return cli


def _host_key(url: str) -> str:
    return (urlsplit(url).hostname or "").rstrip(".")


def _fetch_failure(url: str, error: Exception) -> str:
    return f"Could not fetch {url}: {type(error).__name__}"


@dataclass(frozen=True)
class _Hop:
    url: str
    status: int
    onward: str

    def render(self) -> str:
        tail = f" -> {self.onward}" if self.onward else ""
        return f"{self.status} {self.url}{tail}"


class _HopFailed(Exception):
    """A hop could not be fetched; the message is already phrased for stderr."""


def _probe(http: httpx.Client, url: str, came_from: str | None = None) -> _Hop:
    try:
        with stream_hop(http, "GET", url, came_from=came_from) as reply:
            return _Hop(url, reply.status_code, redirect_target(url, reply))
    except httpx.HTTPError as error:
        raise _HopFailed(_fetch_failure(url, error)) from error


def _chain(http: httpx.Client, start: str, origin: str) -> Iterator[_Hop]:
    """Hops from `start`, ending with one that has nowhere to go or heads for another host."""
    url = start
    previous = None
    while True:
        hop = _probe(http, url, previous)
        yield hop
        if not hop.onward or _host_key(hop.onward) != origin:
            return
        previous, url = url, hop.onward


def _closing_notice(last: _Hop | None, origin: str, limit: int) -> str:
    if last is None or not last.onward:
        return ""
    if _host_key(last.onward) != origin:
        return f"Stopped. {last.onward} is not on {origin}."
    return f"Stopped after {limit} hops."


def _refusal(options: argparse.Namespace, start: str) -> str:
    """Why this run cannot begin, or an empty string when it can."""
    if not 1 <= options.limit <= _HOPS_CEILING or options.timeout <= 0:
        return _BOUNDS_MESSAGE
    if not pagefetch.is_web_url(start):
        return _SHAPE_MESSAGE
    return "" if allowed(start) else explain_target(start)


def _follow(options: argparse.Namespace, start: str) -> int:
    origin = _host_key(start)
    last: _Hop | None = None
    try:
        with client(options.timeout, insecure=options.insecure, cookie=options.cookie,
                    authorization=options.authorization) as http:
            for last in islice(_chain(http, start, origin), options.limit):
                print(last.render())
    except _HopFailed as failure:
        termio.say(str(failure))
        return 1
    except httpx.HTTPError as error:
        termio.say(_fetch_failure(start, error))
        return 1
    notice = _closing_notice(last, origin, options.limit)
    if notice:
        termio.say(notice)
    return 0


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    start = options.url.strip()
    refusal = _refusal(options, start)
    if refusal:
        termio.say(refusal)
        return 2
    return _follow(options, start)
