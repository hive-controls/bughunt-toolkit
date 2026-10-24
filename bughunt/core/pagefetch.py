"""Fetching one page for the content commands, and the stderr reporting that goes with it.

forms, robots, silk, decode and redirect all read pages the same way: an http(s) URL inside the
engagement scope, one plain GET, a capped body. The scope and fetch errors, the URL check, the
redirect-following fetch and the client settings live here. A caller keeps its own failure wording
(``describe``) and decides whether the saved session credentials are sent.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any
from urllib.parse import SplitResult, urlsplit

import httpx
from rich.console import Console
from rich.markup import escape

from bughunt import VERSION
from bughunt.console import ui
from bughunt.core import cli, egress
from bughunt.core.http import read_body, redirect_target, stream_hop
from bughunt.core.session import apply_headers
from bughunt.core.workspace import allowed, explain_block, hostname_of

WEB_SCHEMES = ("http", "https")
WEB_ONLY = "Only http and https URLs can be fetched."
PAGE_BYTES = 1_000_000
SKIM_BYTES = 65_536
FOLLOWS = 3


class ScopeError(Exception):
    """A URL outside the engagement scope; ``host`` is what the refusal should explain."""

    def __init__(self, host: str) -> None:
        super().__init__(host)

    @property
    def host(self) -> str:
        return self.args[0]


class FetchError(Exception):
    """A fetch that cannot proceed; the message is ready for stderr."""


class RedirectLimitError(FetchError):
    """A document was not reached within the redirect budget."""


def web_parts(url: str) -> SplitResult | None:
    """The split URL when it is http(s) with a host; surrounding space is ignored."""
    split = urlsplit(url.strip())
    return split if split.scheme in WEB_SCHEMES and split.hostname else None


def is_web_url(candidate: str) -> bool:
    return web_parts(candidate) is not None


def vet_target(url: str) -> None:
    """Raise ScopeError for an out-of-scope URL, FetchError for one that is not http(s)."""
    if not allowed(url):
        raise ScopeError(hostname_of(url) or url)
    if not is_web_url(url):
        raise FetchError(WEB_ONLY)


def _class_name(problem: Exception) -> str:
    return type(problem).__name__


def _pull(
    client: httpx.Client, url: str, *, may_follow: bool, came_from: str | None = None
) -> tuple[bytes, str]:
    """The page bytes and, when this response redirects and following is allowed, where it points."""
    with stream_hop(client, "GET", url, came_from=came_from) as stream:
        onward = redirect_target(url, stream) if may_follow else ""
        return read_body(stream, SKIM_BYTES if onward else PAGE_BYTES), onward


def fetch_document(
    client: httpx.Client,
    url: str,
    *,
    describe: Callable[[Exception], str] = _class_name,
) -> tuple[str, str]:
    """The decoded page and the URL it came from, following up to FOLLOWS in-scope redirects.

    Every hop is vetted before it is requested. ``describe`` turns a transport error into the
    detail shown after "Could not fetch <url>:" (the exception's class name unless told otherwise).
    """
    current = url
    previous = None
    follows_left = FOLLOWS
    while True:
        vet_target(current)
        try:
            payload, onward = _pull(
                client, current, may_follow=True, came_from=previous
            )
        except httpx.HTTPError as problem:
            raise FetchError(
                f"Could not fetch {current}: {describe(problem)}"
            ) from problem
        if not onward:
            return payload.decode("utf-8", errors="replace"), current
        if follows_left == 0:
            raise RedirectLimitError(f"Could not fetch {current}: too many redirects")
        previous, current, follows_left = current, onward, follows_left - 1


def crawl_client(
    operation: str,
    timeout: float,
    *,
    headers: dict[str, str] | None = None,
    cookie: str | None = None,
    authorization: str | None = None,
    with_session: bool = True,
) -> httpx.Client:
    """A guarded client for one-GET page reads: no redirect following, no proxy settings from the environment.

    ``headers`` ride along with the standard pair. Unless ``with_session`` is off, the saved
    session credentials are applied, with ``cookie`` / ``authorization`` replacing them for this run.
    """
    sent = {
        "User-Agent": f"Bughunt/{VERSION}",
        "Accept-Encoding": "identity",
        **(headers or {}),
    }
    if with_session:
        sent = apply_headers(sent, cookie=cookie, authorization=authorization)
    return egress.client(
        operation=operation,
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
        headers=sent,
    )


# --- reporting on stderr, through Rich ---------------------------------------------------------------------


def stderr_console(*, detect_terminal: bool = False) -> Console:
    """A Rich console on the current stderr. It never colours unless ``detect_terminal`` is on."""
    return Console(
        file=sys.stderr,
        theme=ui.THEME,
        highlight=False,
        force_terminal=None if detect_terminal else False,
    )


def report_error(message: str, *, detect_terminal: bool = False) -> None:
    stderr_console(detect_terminal=detect_terminal).print(
        f"[err]{escape(message)}[/err]"
    )


def report_note(message: str) -> None:
    stderr_console().print(message, markup=False, highlight=False)


class Halt(cli.CommandExit):
    """Ends a command with an outcome already decided: ``report`` says ``message``, then ``code`` is returned."""

    def __init__(self, code: int, report: Callable[[str], None], message: str) -> None:
        super().__init__(code, message)
        self.report = report


def halt_for(
    problem: ScopeError | FetchError,
    *,
    scope_report: Callable[[str], None] = report_note,
    fetch_report: Callable[[str], None] = report_error,
) -> Halt:
    """The Halt for a failed fetch: a scope refusal explained (exit 2), or the fetch error itself (exit 1)."""
    if isinstance(problem, ScopeError):
        return Halt(2, scope_report, explain_block(problem.host))
    return Halt(1, fetch_report, str(problem))


def run_halting(entry: Callable[..., int | None], *arguments: Any) -> int:
    """Call ``entry(*arguments)`` and return its exit code; a Halt is reported its own way first."""
    try:
        return entry(*arguments) or 0
    except Halt as halt:
        halt.report(halt.message)
        return halt.code
