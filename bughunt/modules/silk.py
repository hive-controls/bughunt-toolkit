"""Spider one site for endpoints, robots.txt, and sitemaps.

Breadth-first over a single origin (scheme, host and port): links, forms, scripts, stylesheets,
robots.txt and sitemaps. Paths that robots.txt names are listed, never requested.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import deque
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from bughunt.core import banner, crawlhints, identity, ledger, pagefetch, termio
from bughunt.core.crawlhints import sitemap_locs
from bughunt.core.http import REDIRECT_STATUSES, read_body, redirect_target
from bughunt.core.pagefetch import FetchError, Halt, ScopeError
from bughunt.core.workspace import (
    allowed,
    authority,
    explain_target,
    hostname_of,
    remember_urls,
    scope_is_active,
    urls_path,
)

_DEFAULT_PORTS = {"http": 80, "https": 443}
_ENDPOINT_CAP = 500
_REFERENCE_CAP = 200
_CODE_WINDOW = 200_000
_SITEMAP_SLOTS = 8
_NOT_A_PATH = ("#", "//")
_ACCEPT_MARKUP = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_NUMBERS_MESSAGE = "Depth must be 0 or more. Limit and timeout must be greater than 0."
_SHAPE_MESSAGE = "Give an http or https URL, such as http://127.0.0.1/."
_DESCRIPTION = (
    "Discover endpoints with a bounded crawl of one permitted origin, using page links "
    "and published robots and sitemap hints."
)

_BINARY_EXTENSION_GROUPS = (
    "png jpg jpeg gif webp svg ico bmp avif",  # images
    "woff woff2 ttf eot otf",  # fonts
    "mp3 mp4 wav webm ogg",  # media
    "pdf zip gz tgz rar 7z tar bz2",  # documents and archives
    "wasm map",  # build output
)
_PAGE_EXTENSION_GROUPS = (
    "html htm xhtml xml",  # markup
    "php asp aspx jsp",  # server pages
    "js mjs css",  # code
    "txt json",  # plain data
)
_BINARY_EXTENSIONS = frozenset(
    word for group in _BINARY_EXTENSION_GROUPS for word in group.split()
)
_PAGE_EXTENSIONS = frozenset(
    word for group in _PAGE_EXTENSION_GROUPS for word in group.split()
)


_ROW_STYLES = {
    "start": "1;95",
    "link": "1;96",
    "form": "1;93",
    "script": "1;94",
    "style": "1;92",
    "robots": "1;32",
    "sitemap": "1;33",
    "asset": "2",
}
_FALLBACK_ROW_STYLE = "1;96"

# Each row is (left margin, glyphs); the picture is pinned, so only its construction is ours.
_SPIDER_ROWS = (
    (9, "\\    ^    /"),
    (7, ".  \\   |   /  ."),
    (5, "(     \\  |  /     )"),
    (6, "' .   --+--   . '"),
    (9, "/    |    \\"),
    (8, "/     |     \\"),
    (11, "silk"),
)
_NAMEPLATE = "silk"
_TAGLINE = "spins pages, robots.txt, and sitemaps into endpoints"

_ROOT_PATH = r"/(?!/)[A-Za-z0-9._~%+\-/]{1,200}"
_QUOTE_STOPS = "'\""
_ABSOLUTE_QUOTED = rf"https?://[^{_QUOTE_STOPS}\s<>]{{1,500}}"
_ABSOLUTE_CSS = rf"https?://[^){_QUOTE_STOPS}\s<>]{{1,500}}"
_QUOTED_REFERENCE = re.compile(rf"""['"]({_ABSOLUTE_QUOTED}|{_ROOT_PATH})['"]""")
_CSS_URL = re.compile(
    rf"""url\(\s*['"]?({_ABSOLUTE_CSS}|{_ROOT_PATH})['"]?\s*\)""", re.I
)
_META_REFRESH_URL = re.compile(r"""url\s*=\s*['"]?([^'";\s>]+)""", re.I)


@dataclass
class Response:
    status: int
    content_type: str
    body: str
    url: str
    left: bool


@dataclass
class Job:
    url: str
    depth: int
    source: str
    kind: str


@dataclass
class Result:
    """What a crawl found, how much it fetched, and why it stopped."""

    endpoints: list[tuple[str, str]] = field(default_factory=list)
    # counters
    fetched: int = 0
    off_host: int = 0
    left_server: int = 0
    # notices
    stopped: str = ""
    robots_missing: bool = False
    sitemap_missing: bool = False


_OPTIONS = (
    (("url",), {"help": "Page to start from. Loopback is always in scope."}),
    (
        ("--depth",),
        {"type": int, "default": 2, "help": "Link depth to follow. Default: 2."},
    ),
    (
        ("--limit",),
        {
            "type": int,
            "default": 40,
            "help": "Maximum pages to fetch, including robots.txt and sitemaps. Default: 40.",
        },
    ),
    (
        ("--timeout",),
        {
            "type": float,
            "default": 10.0,
            "help": "Seconds for each request. Default: 10.",
        },
    ),
    (("--save",), {"help": "Also write the URL list to this file."}),
    (
        ("--no-workspace",),
        {"action": "store_true", "help": "Leave the scope URL list unchanged."},
    ),
    (
        ("--plain",),
        {"action": "store_true", "help": "Print one URL per line and skip the spider."},
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
        ("--actor",),
        {
            "help": "Crawl as this owned, origin-bound actor. Sends its credentials and "
            "companion headers; not combinable with --cookie or --authorization."
        },
    ),
)

_ACTOR_CONFLICT_MESSAGE = "Use --actor, or --cookie/--authorization, but not both."
_ACTOR_UNKNOWN_PREFIX = "No usable actor named "


def build_parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(prog="bughunt silk", description=_DESCRIPTION)
    for flags, settings in _OPTIONS:
        cli.add_argument(*flags, **settings)
    return cli


# --- addresses --------------------------------------------------------------------------------------------


def canonicalize(url: str) -> str | None:
    split = pagefetch.web_parts(url)
    if split is None:
        return None
    host = (split.hostname or "").rstrip(".")
    shown_host = authority(host, split.port, omit=(_DEFAULT_PORTS[split.scheme],))
    path = split.path if split.path.startswith("/") else f"/{split.path}"
    return f"{split.scheme}://{shown_host}{path}" + (
        f"?{split.query}" if split.query else ""
    )


def origin_key(url: str) -> tuple[str, str, int] | None:
    split = pagefetch.web_parts(url)
    if split is None:
        return None
    return (
        split.scheme,
        (split.hostname or "").rstrip("."),
        split.port or _DEFAULT_PORTS[split.scheme],
    )


def origin_of(url: str) -> str | None:
    split = urlsplit(url.strip())
    return (
        f"{split.scheme}://{split.netloc}"
        if split.scheme in pagefetch.WEB_SCHEMES and split.netloc
        else None
    )


def _absolutize(value: str, base: str) -> str | None:
    reference = value.strip()
    if not reference or reference.startswith(_NOT_A_PATH):
        return None
    try:
        return canonicalize(urljoin(base, reference))
    except ValueError:
        return None


def _suffix_of(url: str) -> str:
    leaf = urlsplit(url).path.rsplit("/", 1)[-1]
    return leaf.rpartition(".")[2].lower() if "." in leaf else ""


def _worth_fetching(url: str) -> bool:
    suffix = _suffix_of(url)
    return not suffix or suffix in _PAGE_EXTENSIONS


# --- reading what a page says -----------------------------------------------------------------------------

_LINK_TAGS = {
    "a": ("href", "link"),
    "area": ("href", "link"),
    "form": ("action", "form"),
    "button": ("formaction", "form"),
    "input": ("formaction", "form"),
    "iframe": ("src", "link"),
    "frame": ("src", "link"),
    **{tag: ("src", "asset") for tag in ("img", "source", "video", "audio", "track")},
}


@dataclass
class _References:
    base_href: str = ""
    found: list[tuple[str, str]] = field(default_factory=list)


class _ReferenceScanner(HTMLParser):
    """Gathers (reference, source) pairs and the first non-empty <base href>."""

    def __init__(self) -> None:
        super().__init__()
        self.refs = _References()
        self._reading = ""
        self._code: list[str] = []
        self._special: dict[str, Callable[[dict[str, str]], None]] = {
            "base": self._on_base,
            "script": self._on_script,
            "style": self._on_style,
            "link": self._on_link,
            "meta": self._on_meta,
        }

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value or "" for key, value in attrs}
        if tag in _LINK_TAGS:
            attribute, source = _LINK_TAGS[tag]
            self._record(attributes.get(attribute, ""), source)
        elif tag in self._special:
            self._special[tag](attributes)

    def handle_endtag(self, tag: str) -> None:
        if tag == self._reading:
            for reference in extract_code("".join(self._code)):
                self._record(reference, tag)
            self._reading = ""
            self._code.clear()

    def handle_data(self, data: str) -> None:
        if self._reading:
            self._code.append(data)

    def _record(self, value: str, source: str) -> None:
        reference = value.strip()
        if reference and len(self.refs.found) < _REFERENCE_CAP:
            self.refs.found.append((reference, source))

    def _on_base(self, attributes: dict[str, str]) -> None:
        if not self.refs.base_href:
            self.refs.base_href = attributes.get("href", "").strip()

    def _on_script(self, attributes: dict[str, str]) -> None:
        self._record(attributes.get("src", ""), "script")
        self._reading = "script"

    def _on_style(self, _attributes: dict[str, str]) -> None:
        self._reading = "style"

    def _on_link(self, attributes: dict[str, str]) -> None:
        stylesheet = "stylesheet" in attributes.get("rel", "").lower()
        self._record(attributes.get("href", ""), "style" if stylesheet else "link")

    def _on_meta(self, attributes: dict[str, str]) -> None:
        if attributes.get("http-equiv", "").lower() == "refresh":
            target = _META_REFRESH_URL.search(attributes.get("content", ""))
            if target:
                self._record(target.group(1), "link")


def extract_html(text: str) -> tuple[str, list[tuple[str, str]]]:
    scanner = _ReferenceScanner()
    scanner.feed(text)
    scanner.close()
    return scanner.refs.base_href, scanner.refs.found[:_REFERENCE_CAP]


def extract_code(text: str) -> list[str]:
    window = text[:_CODE_WINDOW]
    captured = (
        hit.group(1)
        for pattern in (_QUOTED_REFERENCE, _CSS_URL)
        for hit in pattern.finditer(window)
    )
    return list(dict.fromkeys(captured))[:_REFERENCE_CAP]


def parse_robots(text: str) -> tuple[list[str], list[str]]:
    rule_paths, sitemap_values = [], []
    for key, value in crawlhints.directives(text):
        if key == "sitemap" and value:
            sitemap_values.append(value)
        elif key in ("allow", "disallow") and (path := crawlhints.rule_path(value)):
            rule_paths.append(path)
    return rule_paths, sitemap_values


@dataclass(frozen=True)
class _Sniffer:
    """True when the first `window` characters of a text (leading space ignored) hold any marker."""

    window: int
    markers: tuple[str, ...]

    def __call__(self, text: str) -> bool:
        sample = text.lstrip()[: self.window].lower()
        return any(marker in sample for marker in self.markers)


_SNIFF_HTML = _Sniffer(
    600, ("<!doctype", "<html", "<a ", "<a>", "<form", "<script", "<head", "<body")
)
_SNIFF_SITEMAP = _Sniffer(800, ("<urlset", "<sitemapindex", "<loc"))
_SNIFF_ROBOTS = _Sniffer(1000, ("user-agent", "disallow", "allow:", "sitemap:"))


def _is_robots_text(text: str) -> bool:
    return not text.lstrip().startswith("<") and _SNIFF_ROBOTS(text)


_KIND_RULES: tuple[tuple[Callable[[str, str, str], bool], str], ...] = (
    (
        lambda path, ctype, body: (
            "javascript" in ctype
            or "css" in ctype
            or path.endswith((".js", ".mjs", ".css"))
        ),
        "code",
    ),
    (
        lambda path, ctype, body: (
            _SNIFF_SITEMAP(body)
            and ("xml" in ctype or path.endswith(".xml") or "sitemap" in path)
        ),
        "sitemap",
    ),
    (lambda path, ctype, body: "html" in ctype or _SNIFF_HTML(body), "html"),
)


def _classify(url: str, content_type: str, body: str) -> str:
    path, ctype = urlsplit(url).path.lower(), content_type.lower()
    return next(
        (kind for applies, kind in _KIND_RULES if applies(path, ctype, body)), "other"
    )


# --- fetching ---------------------------------------------------------------------------------------------


@dataclass
class _Reply:
    status: int
    content_type: str
    body: bytes
    redirecting: bool
    onward: str


def _request(client: httpx.Client, url: str, *, follow: bool) -> _Reply:
    try:
        with client.stream("GET", url) as stream:
            redirecting = follow and stream.status_code in REDIRECT_STATUSES
            onward = redirect_target(url, stream) if redirecting else ""
            payload = read_body(
                stream, pagefetch.SKIM_BYTES if redirecting else pagefetch.PAGE_BYTES
            )
            return _Reply(
                stream.status_code,
                stream.headers.get("content-type", ""),
                payload,
                redirecting,
                onward,
            )
    except httpx.HTTPError as failure:
        raise FetchError(
            f"Could not fetch {url}: {type(failure).__name__}"
        ) from failure


def _conclude(
    reply: _Reply, current: str, origin: tuple[str, str, int]
) -> Response | str:
    """The finished Response for this hop, or the URL to request next."""
    if not reply.redirecting:
        text = reply.body.decode("utf-8", errors="replace")
        return Response(reply.status, reply.content_type, text, current, False)
    if not reply.onward:
        return Response(reply.status, reply.content_type, "", current, False)
    leaves = origin_key(reply.onward) != origin or not allowed(reply.onward)
    return (
        Response(reply.status, reply.content_type, "", current, True)
        if leaves
        else reply.onward
    )


def _chase(
    client: httpx.Client, current: str, follows_left: int, origin: tuple[str, str, int]
) -> Response:
    outcome = _conclude(_request(client, current, follow=True), current, origin)
    if isinstance(outcome, Response):
        return outcome
    if follows_left == 0:
        raise pagefetch.RedirectLimitError(
            f"Could not fetch {current}: too many redirects"
        )
    return _chase(client, outcome, follows_left - 1, origin)


def fetch_page(
    client: httpx.Client, url: str, origin: tuple[str, str, int]
) -> Response:
    if origin_key(url) != origin:
        return Response(0, "", "", url, True)
    if allowed(url):
        return _chase(client, url, pagefetch.FOLLOWS, origin)
    raise ScopeError(hostname_of(url) or url)


# --- the spider -------------------------------------------------------------------------------------------


class _Spider:
    """Breadth-first walk of one origin. Pages, robots.txt and sitemaps share one fetch budget."""

    def __init__(
        self, client: httpx.Client, origin: tuple[str, str, int], depth: int, limit: int
    ) -> None:
        self.client = client
        self.origin = origin
        self.max_depth = depth
        self.limit = limit
        self.result = Result()
        self.backlog: deque[Job] = deque()
        self.queued: set[str] = set()
        self.listed: set[str] = set()
        self.sitemap_slots = _SITEMAP_SLOTS
        self.tried_sitemap = False
        self._digesters = {
            "page": self._digest_page,
            "seed-robots": self._digest_robots,
            "seed-sitemap": self._digest_sitemap,
        }
        self._body_handlers = {
            "html": self._take_html,
            "code": self._take_code,
            "sitemap": self._take_listing,
        }

    def run(self, start: str) -> Result:
        self._seed(start)
        while self.backlog:
            reason = self._exhaustion()
            if reason:
                self._halt(reason)
                break
            job = self.backlog.popleft()
            self.tried_sitemap = self.tried_sitemap or job.kind == "seed-sitemap"
            reply = self._fetch(job)
            if reply is not None:
                self._digest(job, reply)
        found = self.result.endpoints
        self.result.sitemap_missing = self.tried_sitemap and all(
            source != "sitemap" for _url, source in found
        )
        return self.result

    def _halt(self, reason: str) -> None:
        self.result.stopped = self.result.stopped or reason

    def _exhaustion(self) -> str:
        """Why no further page may be fetched, or an empty string."""
        if self.result.fetched >= self.limit:
            return f"Stopped after {self.limit} pages."
        if len(self.result.endpoints) >= _ENDPOINT_CAP:
            return f"Stopped after {_ENDPOINT_CAP} endpoints."
        return ""

    def _seed(self, start: str) -> None:
        self.list_url(start, "start")
        site = origin_of(start) or ""
        seeds = (
            (start, "start", "page"),
            (canonicalize(site + "/robots.txt"), "robots", "seed-robots"),
            (canonicalize(site + "/sitemap.xml"), "sitemap", "seed-sitemap"),
        )
        for url, source, kind in seeds:
            self.enqueue(url, 0, source, kind)

    def list_url(self, url: str, source: str) -> None:
        if url in self.listed:
            return
        if len(self.result.endpoints) >= _ENDPOINT_CAP:
            self._halt(f"Stopped after {_ENDPOINT_CAP} endpoints.")
            return
        self.listed.add(url)
        self.result.endpoints.append((url, source))

    def enqueue(self, url: str | None, hop: int, source: str, kind: str) -> None:
        eligible = (
            bool(url)
            and url not in self.queued
            and origin_key(url) == self.origin
            and allowed(url)
        )
        needs_slot = kind == "seed-sitemap"
        if not eligible or (needs_slot and self.sitemap_slots <= 0):
            return
        if needs_slot:
            self.sitemap_slots -= 1
        self.queued.add(url)
        self.backlog.append(Job(url, hop, source, kind))

    def _fetch(self, job: Job) -> Response | None:
        try:
            return fetch_page(self.client, job.url, self.origin)
        except pagefetch.RedirectLimitError:
            raise
        except FetchError as failure:
            if self.result.fetched == 0 and job.source == "start":
                raise failure
            self.result.robots_missing |= job.kind == "seed-robots"
            return None

    def _digest(self, job: Job, reply: Response) -> None:
        self.result.fetched += 1
        if reply.left:
            self.result.left_server += 1
            return
        self._digesters[job.kind](job, reply, canonicalize(reply.url) or job.url)

    def _digest_robots(self, _job: Job, reply: Response, final: str) -> None:
        if reply.status != 200 or not _is_robots_text(reply.body):
            self.result.robots_missing = True
            return
        self.list_url(final, "robots")
        self._take_robots(reply.body, final)

    def _digest_sitemap(self, job: Job, reply: Response, final: str) -> None:
        if reply.status == 200 and _SNIFF_SITEMAP(reply.body):
            self.list_url(final, "sitemap")
            self._take_sitemap(reply.body, final, job.depth)

    def _digest_page(self, job: Job, reply: Response, final: str) -> None:
        if job.url != final:
            self.list_url(final, job.source)
        if reply.status < 400 and reply.body:
            handler = self._body_handlers.get(
                _classify(final, reply.content_type, reply.body)
            )
            if handler is not None:
                handler(reply, final, job)

    def _take_html(self, reply: Response, page: str, job: Job) -> None:
        declared, refs = extract_html(reply.body)
        self._take_refs(refs, _absolutize(declared, page) or page, job.depth)

    def _take_code(self, reply: Response, page: str, job: Job) -> None:
        styled = (
            urlsplit(page).path.lower().endswith(".css")
            or "css" in reply.content_type.lower()
        )
        label = "style" if styled else "script"
        self._take_refs(
            [(ref, label) for ref in extract_code(reply.body)], page, job.depth
        )

    def _take_listing(self, reply: Response, page: str, job: Job) -> None:
        self._take_sitemap(reply.body, page, job.depth)

    def _take_refs(self, refs: list[tuple[str, str]], base: str, hop: int) -> None:
        absolute = (
            (url, source)
            for raw, source in refs
            if (url := _absolutize(raw, base)) is not None
        )
        for url, source in absolute:
            if origin_key(url) != self.origin:
                self.result.off_host += 1
            elif allowed(url):
                self.list_url(
                    url, "asset" if _suffix_of(url) in _BINARY_EXTENSIONS else source
                )
                if hop < self.max_depth and _worth_fetching(url):
                    self.enqueue(url, hop + 1, source, "page")

    def _same_origin(self, raw: str, base: str, *, count_foreign: bool) -> str | None:
        """The canonical URL if it belongs to the crawled origin and scope; otherwise None."""
        absolute = _absolutize(raw, base)
        if absolute is None or origin_key(absolute) != self.origin:
            self.result.off_host += int(count_foreign and absolute is not None)
            return None
        return absolute if allowed(absolute) else None

    def _take_robots(self, text: str, page: str) -> None:
        root = origin_of(page) or page
        rule_paths, sitemap_values = parse_robots(text)
        for path in rule_paths:
            url = self._same_origin(path, root, count_foreign=False)
            if url:
                self.list_url(url, "robots")
        for value in sitemap_values:
            url = self._same_origin(value, root, count_foreign=True)
            if url:
                self.enqueue(url, 0, "sitemap", "seed-sitemap")

    def _take_sitemap(self, text: str, page: str, hop: int) -> None:
        is_index = crawlhints.is_sitemap_index(text)
        for raw in sitemap_locs(text)[:_REFERENCE_CAP]:
            url = self._same_origin(raw, page, count_foreign=True)
            if not url:
                continue
            self.list_url(url, "sitemap")
            if is_index:
                self.enqueue(url, hop, "sitemap", "seed-sitemap")
            elif hop < self.max_depth and _worth_fetching(url):
                self.enqueue(url, hop + 1, "sitemap", "page")


def crawl(
    client: httpx.Client,
    start: str,
    origin: tuple[str, str, int],
    *,
    depth: int,
    limit: int,
) -> Result:
    return _Spider(client, origin, depth, limit).run(start)


# --- output -----------------------------------------------------------------------------------------------


def format_row(source: str, url: str, color: bool) -> str:
    style = banner.sgr(_ROW_STYLES.get(source, _FALLBACK_ROW_STYLE))
    return (
        f"  {style}{source:<8}{banner.ANSI.reset} {banner.ANSI.wrap('white', url)}"
        if color
        else url
    )


def format_banner(color: bool) -> str:
    return banner.render_banner(
        banner.art_rows(_SPIDER_ROWS), _NAMEPLATE, _TAGLINE, color
    )


def _say(message: str) -> None:
    pagefetch.report_error(message, detect_terminal=True)


# --- command ----------------------------------------------------------------------------------------------


def _bind_companions(client: httpx.Client, actor: str) -> None:
    """Send the actor's allowlisted companion headers on each in-origin request, redacted."""

    def supplement(request: httpx.Request) -> None:
        for header, value in identity.companion_supplements(
            actor, str(request.url)
        ).items():
            request.headers[header] = value
            ledger.remember_secret(value)

    client.event_hooks["request"].append(supplement)


def _spider_site(
    options: argparse.Namespace, start: str, *, show_banner: bool = True
) -> Result:
    if show_banner and not options.plain:
        termio.show_banner(format_banner)
    actor = options.actor
    binding = identity.actor_context(actor) if actor else nullcontext()
    try:
        with (
            binding,
            pagefetch.crawl_client(
                "crawl",
                options.timeout,
                headers={"Accept": _ACCEPT_MARKUP},
                cookie=options.cookie,
                authorization=options.authorization,
                with_session=not actor,
            ) as http,
        ):
            if actor:
                _bind_companions(http, actor)
            return crawl(
                http, start, origin_key(start), depth=options.depth, limit=options.limit
            )
    except (ScopeError, FetchError) as problem:
        raise pagefetch.halt_for(
            problem, scope_report=termio.say, fetch_report=_say
        ) from problem


def _summary_line(result: Result, fresh: int | None) -> str:
    notes = (
        (result.off_host, f"{result.off_host} left this server"),
        (result.left_server, f"{result.left_server} redirect(s) stayed put"),
        (result.robots_missing, "no robots.txt"),
        (result.sitemap_missing, "no sitemap.xml"),
    )
    pieces = [
        f"{len(result.endpoints)} endpoint(s)",
        f"{result.fetched} page(s)",
        *(text for present, text in notes if present),
    ]
    if fresh is not None:
        pieces.append(f"{fresh} new in {urls_path().name}")
    line = "  ".join(pieces)
    return (
        f"{banner.ANSI.wrap('magenta', 'silk')}  {line}"
        if termio.color_enabled(sys.stderr)
        else line
    )


def _save_list(destination: str, urls: list[str]) -> None:
    try:
        Path(destination).write_text(
            "".join(f"{url}\n" for url in urls), encoding="utf-8"
        )
    except OSError as problem:
        raise Halt(1, _say, f"Could not write {destination}: {problem}") from problem


def _publish(options: argparse.Namespace, result: Result) -> None:
    painted = termio.stdout_color(options.plain)
    for url, source in result.endpoints:
        print(format_row(source, url, painted))
    urls = [url for url, _source in result.endpoints]
    if options.save:
        _save_list(options.save, urls)
    scoped = scope_is_active() and not options.no_workspace
    fresh = remember_urls([url for url in urls if allowed(url)]) if scoped else None
    for line in (_summary_line(result, fresh), result.stopped):
        if line:
            termio.say(line)


def _check_identity(options: argparse.Namespace) -> None:
    """Refuse an actor combined with ad-hoc credentials, and fail fast on an unusable actor name."""
    if not options.actor:
        return
    if options.cookie is not None or options.authorization is not None:
        raise Halt(2, _say, _ACTOR_CONFLICT_MESSAGE)
    try:
        identity.read_profile(options.actor)
    except identity.IdentityError as problem:
        raise Halt(2, _say, f"{_ACTOR_UNKNOWN_PREFIX}{options.actor}.") from problem


def _starting_point(options: argparse.Namespace) -> str:
    if options.limit < 1 or options.depth < 0 or options.timeout <= 0:
        raise Halt(2, _say, _NUMBERS_MESSAGE)
    _check_identity(options)
    start = canonicalize(options.url.strip())
    if not start:
        raise Halt(2, _say, _SHAPE_MESSAGE)
    if allowed(start):
        return start
    raise Halt(2, termio.say, explain_target(start))


def _run(options: argparse.Namespace) -> None:
    start = _starting_point(options)
    _publish(options, _spider_site(options, start))


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    return pagefetch.run_halting(_run, options)
