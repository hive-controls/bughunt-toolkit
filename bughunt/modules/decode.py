"""Print one page with non-image base64 blocks shown as text.

The page is a local file or one in-scope URL. Data URIs are always considered; bare base64 runs
only when they are long enough. Images stay encoded and are counted.
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
from bisect import bisect_right
from collections.abc import Iterable, Iterator
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import httpx

from bughunt.core import banner, pagefetch, termio
from bughunt.core.http import client, read_body, redirect_target, stream_hop
from bughunt.core.workspace import allowed, explain_block, explain_target, hostname_of

_BARE_LENGTH_DEFAULT = 64
_BARE_LENGTH_FLOOR = 16
_NUMBERS_MESSAGE = "Timeout must be greater than 0, and --min must be 16 or more."
_NOT_A_TARGET = "Give an http or https URL, or a file that exists."
_TRUNCATED_NOTE = "The page was truncated."


# '-' stays last so it is a literal inside a character class.
_B64 = "A-Za-z0-9+/_-"
_STANDARD_ONLY = frozenset("+/")
_URLSAFE_ONLY = frozenset("-_")
_DATA_URI = re.compile(
    rf"data:(?P<mime>[^,;\s]*)(?:;[^,;\s]+)*;base64,(?P<payload>[\r\n{_B64}]+=*)", re.I
)
_BARE_RUN = re.compile(rf"[{_B64}]{{40,}}(?:[ \t\r\n]+[{_B64}]{{4,}})*={{0,2}}")
_CHARSET = re.compile(r"""charset=["']?(?P<name>[\w.:+-]+)""", re.I | re.A)

# Each row is (left margin, glyphs); the picture is pinned, so only its construction is ours.
_ART_ROWS = (
    (8, ".------."),
    (6, ".'        '."),
    (5, "/   decode   \\"),
    (4, "|    (    )    |"),
    (5, "\\   '----'   /"),
    (6, "'.        .'"),
    (8, "'------'"),
)
_NAMEPLATE = "decode"
_TAGLINE = "page source, with non-image base64 written out as text"

_IMAGE_RULES = (
    lambda data: data.startswith(
        (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")
    ),
    lambda data: len(data) >= 12 and data.startswith(b"RIFF") and data[8:12] == b"WEBP",
    lambda data: (
        len(data) >= 8 and data.startswith((b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"))
    ),
    lambda data: len(data) >= 14 and data.startswith(b"BM") and not any(data[6:10]),
)


@dataclass(frozen=True, slots=True)
class Unfolded:
    """A page after unfolding: its text, and how many blocks were decoded or left as images."""

    text: str
    decoded: int
    images: int


ScopeStop = pagefetch.ScopeError


class HostStop(Exception):
    def __init__(self, url: str, origin: str) -> None:
        super().__init__(url, origin)

    url = property(lambda self: self.args[0])
    origin = property(lambda self: self.args[1])

    def __str__(self) -> str:
        return self.url


_OPTIONS = (
    (("target",), {"help": "In-scope http(s) URL, or a local file."}),
    (
        ("--timeout",),
        {
            "type": float,
            "default": 10.0,
            "help": "Seconds for the request. Default 10.",
        },
    ),
    (
        ("--min",),
        {
            "type": int,
            "default": _BARE_LENGTH_DEFAULT,
            "help": "Shortest unmarked base64 block to decode. Default 64. "
            "Data URIs are always considered.",
        },
    ),
    (
        ("--insecure",),
        {"action": "store_true", "help": "Do not verify TLS certificates."},
    ),
    (
        ("--cookie",),
        {"help": "Cookie for this run. Replaces the saved session cookie."},
    ),
    (
        ("--authorization",),
        {"help": "Authorization for this run. Replaces the saved session value."},
    ),
    (
        ("--plain",),
        {
            "action": "store_true",
            "help": "Skip the banner and leave decoded text uncolored.",
        },
    ),
)


def build_parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        prog="bughunt decode",
        description="Print one page with non-image base64 blocks shown as text.",
    )
    for flags, settings in _OPTIONS:
        cli.add_argument(*flags, **settings)
    return cli


# --- recognising and reading base64 -----------------------------------------------------------------------


def _is_image(data: bytes) -> bool:
    return any(rule(data) for rule in _IMAGE_RULES)


def _undecodable(chars: str) -> bool:
    kinds = set(chars)
    mixed_alphabets = bool(kinds & _STANDARD_ONLY) and bool(kinds & _URLSAFE_ONLY)
    return not chars or len(chars) % 4 == 1 or mixed_alphabets


def _b64_to_bytes(payload: str) -> bytes | None:
    chars = "".join(payload.split())
    if _undecodable(chars):
        return None
    decoder = (
        base64.urlsafe_b64decode if _URLSAFE_ONLY & set(chars) else base64.b64decode
    )
    with suppress(ValueError):
        return decoder(chars + "=" * (-len(chars) % 4))
    return None


def _looks_textual(text: str) -> bool:
    if not text or "\x00" in text or text.isspace():
        return False
    unprintable = sum(
        1 for char in text if char not in "\t\n\r" and not char.isprintable()
    )
    return unprintable * 10 <= len(text)


def _as_text(data: bytes) -> str | None:
    text = ""
    with suppress(UnicodeDecodeError):
        text = data.decode("utf-8")
    return text if _looks_textual(text) else None


@dataclass(frozen=True, slots=True)
class _Reading:
    kind: str  # "text", "image" or "opaque"
    text: str = ""


_OPAQUE = _Reading("opaque")
_IMAGE = _Reading("image")


def _read_block(payload: str, mime: str = "") -> _Reading:
    if mime.startswith("image/"):
        return _IMAGE
    data = _b64_to_bytes(payload)
    if data is None:
        return _OPAQUE
    if _is_image(data):
        return _IMAGE
    text = _as_text(data)
    return _OPAQUE if text is None else _Reading("text", text)


@dataclass(frozen=True, slots=True)
class _Block:
    start: int
    end: int
    payload: str
    mime: str = ""


class _Spans:
    """Disjoint [start, end) intervals added in increasing order."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._ends: list[int] = []

    def add(self, start: int, end: int) -> None:
        self._starts.append(start)
        self._ends.append(end)

    def overlaps(self, start: int, end: int) -> bool:
        first = bisect_right(self._ends, start)
        return first < len(self._starts) and self._starts[first] < end


def _data_uri_blocks(text: str) -> Iterator[_Block]:
    for found in _DATA_URI.finditer(text):
        yield _Block(
            found.start(), found.end(), found["payload"], found["mime"].lower()
        )


def _bare_blocks(text: str, taken: _Spans, minimum: int) -> Iterator[_Block]:
    for found in _BARE_RUN.finditer(text):
        compact = "".join(found.group().split())
        if len(compact) >= minimum and not taken.overlaps(found.start(), found.end()):
            yield _Block(found.start(), found.end(), compact)


def _splice(text: str, edits: Iterable[tuple[int, int, str]]) -> str:
    """Replace each (start, end) span, given in increasing order and disjoint, by its new text."""
    kept: list[str] = []
    resume = 0
    for start, end, replacement in edits:
        kept += (text[resume:start], replacement)
        resume = end
    return "".join(kept) + text[resume:]


def unfold(
    text: str, *, minimum: int = _BARE_LENGTH_DEFAULT, color: bool = False
) -> Unfolded:
    taken = _Spans()
    blocks = list(_data_uri_blocks(text))
    for block in blocks:
        taken.add(block.start, block.end)
    blocks += _bare_blocks(text, taken, minimum)
    readings = [
        (block, _read_block(block.payload, block.mime))
        for block in sorted(blocks, key=lambda b: b.start)
    ]
    edits = [
        (block.start, block.end, banner.ink(color).wrap("green", read.text))
        for block, read in readings
        if read.kind == "text"
    ]
    return Unfolded(
        _splice(text, edits),
        len(edits),
        sum(read.kind == "image" for _, read in readings),
    )


def format_banner(color: bool) -> str:
    # This tagline is cyan; every other banner's is dim.
    return banner.render_banner(
        banner.art_rows(_ART_ROWS), _NAMEPLATE, _TAGLINE, color, tagline_hue="cyan"
    )


# --- fetching ---------------------------------------------------------------------------------------------


def _stay_inside(url: str, origin: str) -> None:
    if not allowed(url):
        raise ScopeStop(hostname_of(url) or url)
    if hostname_of(url) != origin:
        raise HostStop(url, origin)


@dataclass(frozen=True, slots=True)
class _Reply:
    status: int
    content_type: str
    onward: str
    body: bytes


def _get_once(
    http: httpx.Client, url: str, *, may_follow: bool, came_from: str | None = None
) -> _Reply:
    with stream_hop(http, "GET", url, came_from=came_from) as stream:
        onward = redirect_target(url, stream)
        cap = (
            pagefetch.SKIM_BYTES if onward and may_follow else pagefetch.PAGE_BYTES + 1
        )
        return _Reply(
            stream.status_code,
            stream.headers.get("content-type", ""),
            onward,
            read_body(stream, cap),
        )


def fetch_page(http: httpx.Client, url: str) -> tuple[bytes, str, str, bool, int]:
    origin = hostname_of(url)
    current = url
    previous = None
    for hops_left in range(pagefetch.FOLLOWS, -1, -1):
        _stay_inside(current, origin)
        reply = _get_once(http, current, may_follow=hops_left > 0, came_from=previous)
        if not reply.onward:
            return (
                reply.body[: pagefetch.PAGE_BYTES],
                reply.content_type,
                current,
                len(reply.body) > pagefetch.PAGE_BYTES,
                reply.status,
            )
        if hops_left == 0:
            break
        previous, current = current, reply.onward
    raise RuntimeError(f"Stopped after {pagefetch.FOLLOWS} redirects.")


def _page_text(body: bytes, content_type: str) -> str:
    declared = _CHARSET.search(content_type)
    with suppress(LookupError):
        return body.decode(declared["name"] if declared else "utf-8", errors="replace")
    return body.decode("utf-8", errors="replace")


# --- command ----------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Stop:
    """The run ends early: an exit code and, optionally, one line for stderr."""

    code: int
    message: str = ""


@dataclass(frozen=True, slots=True)
class _Page:
    text: str
    truncated: bool
    status_line: str = ""


def _read_local(path: str) -> _Page | _Stop:
    try:
        raw = Path(path).read_bytes()
    except OSError as problem:
        return _Stop(1, f"Could not read {path}: {type(problem).__name__}")
    cut_short = len(raw) > pagefetch.PAGE_BYTES
    return _Page(
        raw[: pagefetch.PAGE_BYTES].decode("utf-8", errors="replace"), cut_short
    )


def _remote_refusal(target: str) -> _Stop | None:
    if not pagefetch.is_web_url(target):
        return _Stop(2, _NOT_A_TARGET)
    return None if allowed(target) else _Stop(2, explain_target(target))


def _stop_for(error: Exception, target: str) -> _Stop:
    match error:
        case ScopeStop():
            return _Stop(2, explain_block(error.host))
        case HostStop():
            return _Stop(0, f"Stopped. {error.url} leaves {error.origin}.")
        case httpx.HTTPError():
            return _Stop(1, f"Could not fetch {target}: {type(error).__name__}")
        case _:
            return _Stop(1, str(error))


def _read_remote(options: argparse.Namespace, target: str) -> _Page | _Stop:
    try:
        with client(
            options.timeout,
            insecure=options.insecure,
            cookie=options.cookie,
            authorization=options.authorization,
        ) as http:
            fetched = fetch_page(http, target)
    except (ScopeStop, HostStop, httpx.HTTPError, RuntimeError) as error:
        return _stop_for(error, target)
    body, content_type, final_url, cut_short, status = fetched
    return _Page(_page_text(body, content_type), cut_short, f"{status} {final_url}")


def _obtain(options: argparse.Namespace, target: str) -> _Page | _Stop:
    is_file = Path(target).is_file()
    if not is_file:
        refusal = _remote_refusal(target)
        if refusal:
            return refusal
    if not options.plain:
        termio.show_banner(format_banner)
    return _read_local(target) if is_file else _read_remote(options, target)


def _summary(result: Unfolded) -> str:
    line = f"decoded {result.decoded} block(s)"
    if result.images:
        line += f", left {result.images} image block(s) encoded"
    return banner.ink(termio.color_enabled(sys.stderr)).wrap("green", line)


def _emit(options: argparse.Namespace, page: _Page) -> None:
    if page.status_line:
        termio.say(page.status_line)
    result = unfold(
        page.text, minimum=options.min, color=termio.stdout_color(options.plain)
    )
    print(result.text, end="" if result.text.endswith("\n") else "\n", flush=True)
    if page.truncated:
        termio.say(_TRUNCATED_NOTE)
    termio.say(_summary(result))


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    if options.timeout <= 0 or options.min < _BARE_LENGTH_FLOOR:
        termio.say(_NUMBERS_MESSAGE)
        return 2
    outcome = _obtain(options, options.target.strip())
    if isinstance(outcome, _Stop):
        if outcome.message:
            termio.say(outcome.message)
        return outcome.code
    _emit(options, outcome)
    return 0
