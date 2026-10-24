"""urlscan.io command-line client for Bughunt.

Eight subcommands cover the urlscan.io workflow: search past scans, submit a scan, fetch a
result, download a scan's screenshot or DOM snapshot, show API quotas, show the account behind
the API key, and print a cheat-sheet of searchable fields.

Every request travels through the guarded API client: fixed host allow-list (urlscan.io and its
subdomains), `passive` egress policy, no ambient proxy, redirects followed manually and checked
hop by hop. The one active capability is `scan`, which asks urlscan.io's own scanners to visit a
target URL, so that URL must be in workspace scope, authorised for `active_scan` by the policy,
and confirmed (or passed with --yes).

Requires the `bughunt` package to be importable, httpx and rich. Run it as `bughunt urlscan ...`
or `python urlscan.py ...`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode, urlsplit

import httpx

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bughunt.console import ui
from bughunt.core import egress, ledger, workspace
from bughunt.core.http import HostNotAllowed, api_client, get_following

API_HOSTS = frozenset({"urlscan.io"})
SERVICE_ORIGIN = "https://urlscan.io"
REDIRECT_HOPS = 5
KEY_ENV_VARIABLE = "URLSCAN_API_KEY"
SCAN_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
ERROR_TEXT_LIMIT = 400


# --------------------------------------------------------------------------------------------
# Terminal output: styling, errors, JSON, quota line
# --------------------------------------------------------------------------------------------

_SGR_CODES = {
    "bold": 1,
    "dim": 2,
    "red": 31,
    "green": 32,
    "yellow": 33,
    "blue": 34,
    "magenta": 35,
    "cyan": 36,
    "hi_red": 91,
    "hi_green": 92,
    "hi_yellow": 93,
    "hi_magenta": 95,
    "hi_cyan": 96,
    "hi_white": 97,
}


class Ink:
    """Wraps text in ANSI SGR sequences, one sequence per style name, when switched on."""

    def __init__(self) -> None:
        self.enabled = False

    def __call__(self, text: str, *styles: str) -> str:
        if not (self.enabled and styles and text):
            return text
        opening = "".join(f"\x1b[{_SGR_CODES[name]}m" for name in styles)
        return f"{opening}{text}\x1b[0m"


ink = Ink()


def is_terminal(stream) -> bool:
    probe = getattr(stream, "isatty", None)
    return bool(probe and probe())


def color_wanted(disabled_by_flag: bool) -> bool:
    """--no-color beats NO_COLOR beats FORCE_COLOR beats "stdout is a terminal"."""
    if disabled_by_flag or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return is_terminal(sys.stdout)


def die(message: str, status: int = 1):
    print(ink(f"error: {message}", "bold", "hi_red"), file=sys.stderr)
    raise SystemExit(status)


def emit_json(data) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    try:
        text.encode(sys.stdout.encoding or "utf-8")
    except UnicodeEncodeError:
        text = json.dumps(data, indent=2, ensure_ascii=True, default=str)
    print(text)


def save_json(destination: str, data, *, notice_stream=None) -> None:
    with open(destination, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(data, indent=2))
    print(ink(f"  saved {destination}", "dim"), file=notice_stream)


def labeled_lines(pairs, width: int = 13) -> None:
    """Print `label  value` rows, skipping pairs whose value is missing or blank."""
    for label, value in pairs:
        if value is None or value == "":
            continue
        print(f"  {ink(label.ljust(width), 'dim')} {value}")


def joined(*parts) -> str:
    return " ".join(str(part) for part in parts if part not in (None, ""))


def section(parent, key: str) -> dict:
    value = parent.get(key) if isinstance(parent, dict) else None
    return value if isinstance(value, dict) else {}


# --------------------------------------------------------------------------------------------
# Errors and rate-limit headers
# --------------------------------------------------------------------------------------------


class APIError(Exception):
    """A failed call. `status` 0 means the request never produced an HTTP response."""

    def __init__(self, status: int, message: str, body=None, headers=None) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message
        self.body = body
        self.headers = headers if headers is not None else {}


def whole_number(raw) -> int | None:
    try:
        return int(str(raw).strip())
    except ValueError:
        return None


@dataclass(frozen=True)
class RateLimit:
    """Quota information urlscan.io reports in `X-Rate-Limit-*` response headers."""

    scope: str | None = None
    action: str | None = None
    window: str | None = None
    limit: int | None = None
    remaining: int | None = None
    reset_after: int | None = None

    @classmethod
    def from_headers(cls, headers) -> "RateLimit":
        folded = {str(name).lower(): value for name, value in headers.items()}

        def text(suffix: str) -> str | None:
            return str(folded.get("x-rate-limit-" + suffix, "")).strip() or None

        return cls(
            scope=text("scope"),
            action=text("action"),
            window=text("window"),
            limit=whole_number(text("limit")),
            remaining=whole_number(text("remaining")),
            reset_after=whole_number(text("reset-after")),
        )

    @property
    def present(self) -> bool:
        return bool(self.action) or self.remaining is not None

    def summary(self) -> str:
        words = [word for word in (self.action, self.window) if word]
        if self.remaining is not None:
            words.append(
                f"{self.remaining}/{self.limit} left"
                if self.limit is not None
                else f"{self.remaining} left"
            )
        text = " ".join(words)
        if self.reset_after is not None:
            text += f"{' · ' if text else ''}resets in {self.reset_after}s"
        return text


def show_quota_line(client: "Client") -> None:
    if client.last_rate is not None:
        print(ink(f"  quota  {client.last_rate.summary()}", "dim"))


def decode_body(content: bytes):
    """Empty -> None; JSON when it parses; otherwise the UTF-8 text with bad bytes replaced."""
    if not content:
        return None
    text = content.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


_MESSAGE_FIELDS = ("message", "description", "error", "detail", "warning")


def _filled(value) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def explain_failure(body, raw_text: str, reason: str) -> str:
    """Pick the most informative one-line explanation out of an error response."""
    if isinstance(body, dict):
        for field in _MESSAGE_FIELDS:
            chosen = _filled(body.get(field))
            if chosen is None:
                continue
            extra = _filled(body.get("description"))
            if field == "message" and extra and extra != chosen:
                return f"{chosen} — {extra}"
            return chosen
    elif _filled(body):
        return _filled(body)[:ERROR_TEXT_LIMIT]
    return raw_text.strip()[:ERROR_TEXT_LIMIT] or reason


def failure_hint(error: APIError, command: str) -> str:
    """Advice appended to an error line; empty when there is nothing useful to add."""
    if error.status == 429:
        rate = RateLimit.from_headers(error.headers)
        if rate.reset_after is not None:
            return f"Retry after {rate.reset_after}s ({rate.summary()})."
        return f"{rate.summary()}." if rate.present else ""
    if error.status == 401:
        return f"Check the key: set {KEY_ENV_VARIABLE} or pass --api-key."
    if error.status == 403:
        return (
            "Result and DOM endpoints need a valid API key (--api-key or "
            + KEY_ENV_VARIABLE
            + ")."
        )
    if error.status == 400 and command == "search":
        return (
            "The search box takes Elasticsearch query-string syntax, not a pasted URL; "
            "try: page.domain:example.com AND date:>now-7d (see `fields`)."
        )
    return ""


# --------------------------------------------------------------------------------------------
# HTTP client
# --------------------------------------------------------------------------------------------


def as_mapping(body) -> dict:
    return body if isinstance(body, dict) else {"raw": body}


def pause(seconds: float, label: str) -> None:
    """Sleep, drawing a small ticker on stderr when stderr is a terminal."""
    if seconds <= 0:
        return
    if not is_terminal(sys.stderr):
        time.sleep(seconds)
        return
    frames = "-\\|/"
    end = time.monotonic() + seconds
    step = 0
    while (left := end - time.monotonic()) > 0.001:
        sys.stderr.write(
            f"\r  {frames[step % len(frames)]} {label} ({left:.0f}s left)   "
        )
        sys.stderr.flush()
        time.sleep(min(0.12, left))
        step += 1
    sys.stderr.write("\r" + " " * (len(label) + 24) + "\r")
    sys.stderr.flush()


class Client:
    """Thin urlscan.io API wrapper. Every request goes through `self.http`, looked up per call."""

    def __init__(self, api_key: str | None = None, timeout: float = 30.0) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self.last_rate: RateLimit | None = None
        self.http = api_client(API_HOSTS, timeout=timeout)

    def request(
        self, method, path, *, params=None, payload=None, raw=False, extra_headers=None
    ):
        """Return (status, body, headers); raise APIError on HTTP >= 400 or transport failure."""
        if not path.startswith("/"):
            raise APIError(0, f"request path must start with '/': {path!r}")
        url = SERVICE_ORIGIN + path
        pairs = [
            (name, value) for name, value in (params or {}).items() if value is not None
        ]
        if pairs:
            url += "?" + urlencode(pairs)
        headers = {"Accept": "application/json, */*"}
        if self.api_key:
            headers["API-Key"] = self.api_key
            ledger.remember_secret(self.api_key, redact_at_rest=True)
        content = None
        if payload is not None:
            content = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        headers.update(extra_headers or {})

        response = self._send(method, url, headers, content)
        header_map = dict(response.headers)
        rate = RateLimit.from_headers(header_map)
        self.last_rate = rate if rate.present else None
        if response.status_code >= 400:
            text = response.content.decode("utf-8", errors="replace")
            body = decode_body(response.content)
            message = explain_failure(body, text, response.reason_phrase)
            raise APIError(response.status_code, message, body, header_map)
        return (
            response.status_code,
            response.content if raw else decode_body(response.content),
            header_map,
        )

    def _send(self, method: str, url: str, headers: dict, content: bytes | None):
        try:
            if method.upper() == "GET":
                return get_following(
                    self.http, url, limit=REDIRECT_HOPS, headers=headers
                )
            return self.http.request(method, url, headers=headers, content=content)
        except HostNotAllowed as refusal:
            raise APIError(0, f"refused: {refusal}") from refusal
        except httpx.HTTPError as failure:
            raise APIError(0, f"network error: {failure}") from failure

    def search(
        self,
        query: str,
        size: int = 20,
        after: str | None = None,
        datasource: str | None = None,
    ):
        params = {
            "q": query,
            "size": size,
            "search_after": after,
            "datasource": datasource,
        }
        return as_mapping(self.request("GET", "/api/v1/search/", params=params)[1])

    def submit(self, payload: dict) -> dict:
        return as_mapping(self.request("POST", "/api/v1/scan/", payload=payload)[1])

    def result(self, uuid: str) -> dict:
        return as_mapping(self.request("GET", f"/api/v1/result/{uuid}/")[1])

    def quotas(self) -> dict:
        try:
            return as_mapping(self.request("GET", "/api/v1/quotas")[1])
        except APIError as first_failure:
            if first_failure.status not in (404, 405):
                raise
        return as_mapping(self.request("GET", "/user/quotas/")[1])

    def whoami(self) -> dict:
        return as_mapping(self.request("GET", "/user/username")[1])

    def download(self, path: str) -> bytes:
        return self.request("GET", path, raw=True)[1]

    def wait_for_result(
        self, uuid: str, timeout: float, initial_delay: float, interval: float
    ) -> dict:
        """Poll until the scan result exists (HTTP 404 means "still running")."""
        deadline = time.monotonic() + timeout
        pause(initial_delay, "waiting for scan")
        while True:
            try:
                return self.result(uuid)
            except APIError as pending:
                if pending.status != 404:
                    raise
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise APIError(
                        404, f"scan {uuid} did not finish within {timeout:.0f}s"
                    ) from pending
            pause(min(interval, remaining), "polling")


# --------------------------------------------------------------------------------------------
# Inputs: API key, scan ids, search queries, scan gate
# --------------------------------------------------------------------------------------------


def first_line(path: Path) -> str | None:
    try:
        lines = path.read_text(encoding="utf-8").strip().splitlines()
    except (OSError, ValueError):
        return None
    return lines[0].strip() if lines else None


def resolve_api_key(flag_value: str | None) -> str | None:
    """--api-key, then $URLSCAN_API_KEY, then ~/.config/urlscan/api_key, then ~/.urlscan_api_key."""
    for candidate in (
        (flag_value or "").strip(),
        os.environ.get(KEY_ENV_VARIABLE, "").strip(),
    ):
        if candidate:
            return candidate
    home = Path.home()
    for key_file in (
        home / ".config" / "urlscan" / "api_key",
        home / ".urlscan_api_key",
    ):
        stored = first_line(key_file)
        if stored:
            return stored
    return None


def checked_uuid(raw: str) -> str:
    if not isinstance(raw, str):
        die(f"not a scan uuid: {raw!r}")
    candidate = raw.strip()
    if not SCAN_UUID.fullmatch(candidate):
        die(f"not a scan uuid: {candidate!r}")
    return candidate


def looks_like_url(text: str) -> bool:
    if text.lower().startswith(("http://", "https://")):
        return True
    if "/" not in text or "://" in text or " " in text or ":" in text:
        return False
    host_part = text.split("/", 1)[0]
    return "." in host_part and not host_part.startswith(".")


def normalize_search_query(raw: str) -> tuple[str, str | None]:
    """Turn a pasted URL into a field query; anything else passes through untouched."""
    text = raw.strip()
    if not looks_like_url(text):
        return text, None
    try:
        parts = urlsplit(text if "://" in text else "https://" + text)
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        return text, None
    if not host:
        return text, None
    path = "" if parts.path == "/" else parts.path
    exact = f"{parts.scheme}://{host}{path}" + (
        f"?{parts.query}" if parts.query else ""
    )
    rewritten = " OR ".join(
        [
            f"page.domain:{host}",
            f"task.domain:{host}",
            f'page.url:"{exact}"',
            f'task.url:"{exact}"',
        ]
    )
    return rewritten, rewritten


def scan_gate(
    url: str, visibility: str, assume_yes: bool, *, prompt_stream=None
) -> None:
    """Refuse (SystemExit) unless the URL is in scope, policy-authorised and confirmed."""
    try:
        host = urlsplit(url).hostname or url
    except ValueError:
        host = url
    if not workspace.allowed(url):
        die(workspace.explain_block(host))
    try:
        egress.authorize(url, "active_scan")
    except egress.PolicyBlocked as blocked:
        die(str(blocked))
    question = f"urlscan.io scanners will visit {url} ({visibility} result). Continue?"
    if not ui.confirm(question, assume_yes=assume_yes, stream=prompt_stream):
        die("not submitted; answer y or pass --yes when not interactive")


# --------------------------------------------------------------------------------------------
# Views
# --------------------------------------------------------------------------------------------


def cursor_token(hit: dict) -> str | None:
    marker = hit.get("sort")
    if isinstance(marker, (list, tuple)):
        return ",".join(str(piece) for piece in marker) or None
    return str(marker) if marker not in (None, "") else None


def render_hit(position: int, hit: dict) -> None:
    page, task, stats = (
        section(hit, "page"),
        section(hit, "task"),
        section(hit, "stats"),
    )
    flagged = section(hit, "verdicts").get("malicious")
    headline = f"{position:>3}. {page.get('url') or task.get('url') or '-'}"
    print(headline + (ink("  ⚠ malicious", "bold", "hi_red") if flagged else ""))
    title = str(page.get("title") or "").strip()
    if title:
        print(f"     {ink(title, 'bold')}")
    facts = [
        task.get("time") or hit.get("indexedAt"),
        task.get("visibility"),
        joined(page.get("ip"), page.get("country")),
        joined(page.get("asn"), page.get("asnname")),
        page.get("server"),
    ]
    counts = [
        f"{label} {stats[key]}"
        for label, key in (
            ("req", "requests"),
            ("ips", "uniqIPs"),
            ("bytes", "dataLength"),
        )
        if stats.get(key) is not None
    ]
    for items in (facts, counts):
        line = " · ".join(str(item) for item in items if item)
        if line:
            print(f"     {ink(line, 'dim')}")
    ident = hit.get("_id") or task.get("uuid")
    if ident:
        print(f"     {ink(str(ident), 'cyan')}  {SERVICE_ORIGIN}/result/{ident}/")


def render_search(query: str, body: dict) -> None:
    hits = [hit for hit in (body.get("results") or []) if isinstance(hit, dict)]
    total = body.get("total")
    print(f"{ink('search', 'bold')} {ink(query, 'hi_cyan')}")
    summary = f"showing {len(hits)}" + (f" of {total}" if total is not None else "")
    summary += " + (has_more)" if body.get("has_more") else ""
    summary += f" · took {body['took']} ms" if body.get("took") is not None else ""
    print(ink(summary, "dim"))
    print()
    if not hits:
        print(ink("no results", "dim"))
        return
    for position, hit in enumerate(hits, start=1):
        render_hit(position, hit)
    token = cursor_token(hits[-1])
    if token:
        print(f"\nnext page:  --after '{token}'")


def render_submission(data: dict) -> None:
    labeled_lines(
        [
            (key, data.get(key))
            for key in (
                "uuid",
                "url",
                "visibility",
                "country",
                "message",
                "result",
                "api",
            )
        ]
    )


def verdict_badge(verdicts) -> str:
    if not isinstance(verdicts, dict) or not verdicts:
        return ink("unknown", "dim")
    score = section(verdicts, "overall").get("score")
    if any(
        section(verdicts, name).get("malicious")
        for name in ("overall", "engines", "community")
    ):
        return ink(
            "MALICIOUS" + (f" score={score}" if score is not None else ""),
            "bold",
            "hi_red",
        )
    if score:
        return ink(f"score={score}", "hi_yellow")
    return ink("clean", "hi_green")


def verdict_labels(verdicts, key: str) -> str:
    for source in ("overall", "urlscan"):
        values = section(verdicts, source).get(key)
        if values:
            return (
                ", ".join(str(value) for value in values)
                if isinstance(values, list)
                else str(values)
            )
    return ""


_INDICATOR_ROWS = (  # (label, keys tried in order, how many to show)
    ("domains", ("domains", "linkDomains"), 8),
    ("ips", ("ips",), 8),
    ("asns", ("asns",), 8),
    ("hashes", ("hashes",), 8),
    ("urls", ("urls",), 5),
    ("certificates", ("certificates",), 4),
)


def render_indicators(lists: dict) -> None:
    for label, keys, shown in _INDICATOR_ROWS:
        values = next(
            (
                lists[key]
                for key in keys
                if isinstance(lists.get(key), list) and lists[key]
            ),
            None,
        )
        if not values:
            continue
        extra = len(values) - shown
        tail = f" (+{extra} more)" if extra > 0 else ""
        print(
            f"  {ink(label.ljust(13), 'dim')} {', '.join(str(item) for item in values[:shown])}{tail}"
        )


def render_result(data: dict) -> None:
    task, page, stats = (
        section(data, "task"),
        section(data, "page"),
        section(data, "stats"),
    )
    verdicts = data.get("verdicts")
    uuid = task.get("uuid")
    tls = page.get("tlsIssuer") or (
        f"valid {page['tlsValidDays']} days" if page.get("tlsValidDays") else None
    )
    labeled_lines(
        [
            ("uuid", uuid),
            ("task url", task.get("url")),
            ("final url", page.get("url")),
            ("title", page.get("title")),
            ("time", task.get("time")),
            ("visibility", task.get("visibility")),
            ("method", task.get("method")),
            ("where", joined(page.get("country"), page.get("city"))),
            ("ip", page.get("ip")),
            ("asn", joined(page.get("asn"), page.get("asnname"))),
            ("server", page.get("server")),
            ("tls", tls),
            ("status", page.get("status")),
            ("verdict", verdict_badge(verdicts)),
            ("categories", verdict_labels(verdicts, "categories")),
            ("brands", verdict_labels(verdicts, "brands")),
        ]
    )
    figures = [
        f"{name} {stats[key]}"
        for name, key in (
            ("requests", "requests"),
            ("unique IPs", "uniqIPs"),
            ("countries", "uniqCountries"),
            ("data", "dataLength"),
            ("encoded", "encodedDataLength"),
        )
        if stats.get(key) is not None
    ]
    labeled_lines([("stats", " · ".join(figures))])
    render_indicators(section(data, "lists"))
    if uuid:
        labeled_lines(
            [
                ("report", f"{SERVICE_ORIGIN}/result/{uuid}/"),
                ("screenshot", f"{SERVICE_ORIGIN}/screenshots/{uuid}.png"),
                ("dom", f"{SERVICE_ORIGIN}/dom/{uuid}/"),
            ]
        )


_QUOTA_WINDOWS = ("minute", "hour", "day")
_NOT_QUOTA_ACTIONS = frozenset({"features", "queryVisibility", "queryableFields"})
_QUOTA_WRAPPERS = ("limits", "data", "quotas")


def quota_actions(node) -> dict:
    if not isinstance(node, dict):
        return {}
    return {
        name: spans
        for name, spans in node.items()
        if name not in _NOT_QUOTA_ACTIONS
        and isinstance(spans, dict)
        and any(isinstance(spans.get(window), dict) for window in _QUOTA_WINDOWS)
    }


def quota_row(action: str, window: str, span: dict) -> str:
    def count(key):
        value = span.get(key)
        return (
            value
            if isinstance(value, (int, float)) and not isinstance(value, bool)
            else None
        )

    used, remaining, limit, percent = (
        count("used"),
        count("remaining"),
        count("limit"),
        count("percent"),
    )
    if percent is None and used is not None and limit:
        percent = round(used * 100 / limit)
    if limit and remaining == 0:
        tone = "hi_red"
    elif percent is not None and percent >= 80:
        tone = "hi_yellow"
    else:
        tone = "hi_green"

    def cell(value, suffix="") -> str:
        return f"{value:g}{suffix}" if value is not None else "-"

    spare = f"{cell(remaining):>7}{cell(limit):>7}{cell(percent, '%'):>7}"
    return f"  {action:<12}{window:<8}{cell(used):>7}{ink(spare, tone)}"


def render_quotas(data: dict) -> None:
    actions, home = quota_actions(data), data
    for wrapper in _QUOTA_WRAPPERS:
        if actions:
            break
        actions, home = quota_actions(data.get(wrapper)), data.get(wrapper)
    print(ink("API quotas", "bold"))
    if data.get("scope"):
        print(f"  scope {data['scope']}")
    print(ink("═" * 46, "dim"))
    if not actions:
        print(ink("  no per-action quota data in the response", "dim"))
    else:
        print(
            ink(
                f"  {'action':<12}{'window':<8}{'used':>7}{'left':>7}{'limit':>7}{'share':>7}",
                "dim",
            )
        )
    for action, spans in actions.items():
        for window in _QUOTA_WINDOWS:
            if isinstance(spans.get(window), dict):
                print(quota_row(action, window, spans[window]))
    for label, key in (
        ("query visibility", "queryVisibility"),
        ("features", "features"),
    ):
        extra = (
            home.get(key)
            if isinstance(home, dict) and home.get(key) is not None
            else data.get(key)
        )
        if extra:
            print(
                f"  {label}: {', '.join(map(str, extra)) if isinstance(extra, list) else extra}"
            )


_IDENTITY_FIELDS = (
    "username",
    "email",
    "name",
    "role",
    "plan",
    "subscription",
    "team",
    "uuid",
)


def render_identity(data: dict) -> None:
    named = [key for key in _IDENTITY_FIELDS if key in data]
    others = [
        key
        for key, value in data.items()
        if key not in _IDENTITY_FIELDS and not isinstance(value, (dict, list))
    ]
    labeled_lines([(key, data[key]) for key in named + others])


_FIELD_GUIDE = (
    ("page.domain", "host of the page that finally loaded"),
    ("domain", "any host contacted while the page loaded"),
    ("page.ip", "IP address serving the main page"),
    ("ip", "any IP address contacted during the scan"),
    ("asn", "autonomous system of the main page, e.g. AS64500"),
    ("hash", "SHA-256 of a downloaded resource"),
    ("filename", "file name of a requested resource"),
    ("server", "Server header of the main page"),
    ("country", "country code the main page's IP is located in"),
    ("task.url", "URL exactly as it was submitted"),
    ("task.uuid", "scan identifier"),
    ("task.visibility", "public, unlisted or private"),
    ("task.tags", "tags attached when the scan was submitted"),
    ("date", "when the scan ran; accepts ranges such as >now-7d"),
    ("stats.uniqIPs", "number of distinct IPs the page contacted"),
    ("verdicts.malicious", "true when urlscan or an engine flagged the scan"),
)
_FIELD_EXAMPLES = (
    ("scans of one site this week", "page.domain:example.com AND date:>now-7d"),
    (
        "pages that load a resource from a host",
        "domain:cdn.example.net AND NOT page.domain:cdn.example.net",
    ),
    (
        "flagged scans from your own tagged batch",
        "verdicts.malicious:true AND task.tags:campaign-42",
    ),
    ("busy pages on one network", "asn:AS64500 AND country:DE AND stats.uniqIPs:>20"),
)


def render_fields() -> None:
    print(ink("Searchable fields", "bold"))
    print("  Write field:value; combine with AND, OR, NOT and parentheses.")
    print(
        '  Quote values holding spaces or punctuation, e.g. task.url:"https://example.com/a b".'
    )
    print(
        '  A backslash escapes the reserved characters  + - = & | > < ! ( ) { } [ ] ^ " ~ * ? : \\ /'
    )
    print()
    for name, meaning in _FIELD_GUIDE:
        print(f"  {ink((name + ':').ljust(21), 'hi_cyan')} {meaning}")
    print(f"\n{ink('Example queries', 'bold')}")
    for purpose, query in _FIELD_EXAMPLES:
        print(f"  {ink(purpose, 'dim')}\n    {query}")
    print(f"\n  Full syntax reference: {SERVICE_ORIGIN}/docs/search/")


# --------------------------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------------------------


def save_if_asked(args, data) -> None:
    if args.save:
        save_json(args.save, data, notice_stream=sys.stderr if args.json else None)


def print_result(args, client: Client, data: dict) -> None:
    if args.json:
        emit_json(data)
    else:
        render_result(data)
        show_quota_line(client)


def run_search(client: Client, args, *, structured=False):
    raw_query = " ".join(args.query).strip()
    if not raw_query:
        die("search query is empty")
    query, note = normalize_search_query(raw_query)
    body = client.search(query, args.size, args.after, args.datasource)
    if structured:
        save_if_asked(args, body)
        return body
    if args.json:
        emit_json(body)
    else:
        if note:
            print(ink(f"treated URL as search: {query}", "dim"))
            print()
        render_search(query, body)
        show_quota_line(client)
    save_if_asked(args, body)


def scan_payload(args) -> dict:
    payload = {"url": args.url, "visibility": args.visibility}
    optional = (
        ("country", args.country),
        ("tags", args.tag),
        ("customagent", args.user_agent),
        ("referer", args.referer),
        ("overrideSafety", "true" if args.override_safety else None),
    )
    payload.update({key: value for key, value in optional if value})
    return payload


def run_scan(client: Client, args, *, structured=False):
    if not client.api_key:
        die(
            f"scanning needs an API key: set {KEY_ENV_VARIABLE}, pass --api-key, or store it in "
            "~/.config/urlscan/api_key"
        )
    scan_gate(
        args.url,
        args.visibility,
        args.yes,
        prompt_stream=sys.stderr if args.json else None,
    )
    submission = client.submit(scan_payload(args))
    if structured:
        data = submission
        if args.wait:
            data = client.wait_for_result(
                checked_uuid(submission.get("uuid")),
                args.wait_timeout,
                args.initial_delay,
                args.interval,
            )
        save_if_asked(args, data)
        return data
    if not args.wait:
        if args.json:
            emit_json(submission)
        else:
            render_submission(submission)
            show_quota_line(client)
        save_if_asked(args, submission)
        return
    if not args.json:
        render_submission(submission)
    uuid = submission.get("uuid")
    if not uuid:
        die("urlscan.io did not return a uuid, so there is nothing to wait for")
    uuid = checked_uuid(uuid)
    if not args.json:
        print()
    finished = client.wait_for_result(
        uuid, args.wait_timeout, args.initial_delay, args.interval
    )
    print_result(args, client, finished)
    save_if_asked(args, finished)


def run_result(client: Client, args, *, structured=False):
    uuid = checked_uuid(args.uuid)
    try:
        if args.wait:
            data = client.wait_for_result(
                uuid, args.wait_timeout, args.initial_delay, args.interval
            )
        else:
            data = client.result(uuid)
    except APIError as failure:
        if failure.status == 404 and not args.wait:
            die(
                f"scan {uuid} is not ready yet (HTTP 404); re-run with --wait to poll until it finishes"
            )
        if failure.status == 410:
            die(f"scan {uuid} was deleted (HTTP 410)")
        raise
    if structured:
        save_if_asked(args, data)
        return data
    print_result(args, client, data)
    save_if_asked(args, data)


def run_screenshot(client: Client, args, *, structured=False):
    uuid = checked_uuid(args.uuid)
    image = client.download(f"/screenshots/{uuid}.png")
    destination = args.output or f"{uuid}.png"
    with open(destination, "wb") as handle:
        handle.write(image)
    if structured:
        return {
            "uuid": uuid,
            "bytes": len(image),
            "saved": True,
            "media_type": "image/png",
        }
    print(ink(f"wrote {destination} ({len(image)} bytes)", "hi_green"))


def run_dom(client: Client, args, *, structured=False):
    uuid = checked_uuid(args.uuid)
    raw_bytes = client.download(f"/dom/{uuid}/")
    markup = raw_bytes.decode("utf-8", errors="replace")
    if structured:
        if args.output:
            Path(args.output).write_text(markup, encoding="utf-8")
        return {"uuid": uuid, "dom": markup, "saved": bool(args.output)}
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(markup)
        print(ink(f"wrote {args.output} ({len(raw_bytes)} bytes)", "hi_green"))
    elif args.json:
        emit_json({"uuid": uuid, "dom": markup})
    else:
        print(markup, end="" if markup.endswith("\n") else "\n")


def run_quotas(client: Client, args, *, structured=False):
    data = client.quotas()
    if structured:
        return data
    emit_json(data) if args.json else render_quotas(data)


def run_whoami(client: Client, args, *, structured=False):
    if not client.api_key:
        die(f"whoami needs an API key: set {KEY_ENV_VARIABLE} or pass --api-key")
    data = client.whoami()
    if structured:
        return data
    emit_json(data) if args.json else render_identity(data)


def run_fields(client: Client, args, *, structured=False):
    if structured:
        return {
            "fields": [list(row) for row in _FIELD_GUIDE],
            "examples": [list(row) for row in _FIELD_EXAMPLES],
        }
    render_fields()


COMMANDS = {
    "search": run_search,
    "scan": run_scan,
    "result": run_result,
    "screenshot": run_screenshot,
    "dom": run_dom,
    "quotas": run_quotas,
    "whoami": run_whoami,
    "fields": run_fields,
}


def run_structured(args, *, dry_run=False):
    import math
    from bughunt.core.addon_adapters import document, effect, external, planned

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError("Timeout must be finite and positive")
    if hasattr(args, "uuid"):
        checked_uuid(args.uuid)
    if args.command == "search" and (not " ".join(args.query).strip() or args.size < 1):
        raise ValueError("Nonempty query and positive size required")
    if args.command == "scan":
        if not args.yes:
            raise ValueError("Embedding a scan requires --yes disclosure consent")
        scan_gate(args.url, args.visibility, True, prompt_stream=sys.stderr)
    if getattr(args, "wait", False):
        values = (args.wait_timeout, args.initial_delay, args.interval)
        if (
            any(not math.isfinite(value) or value < 0 for value in values)
            or args.interval == 0
        ):
            raise ValueError("Wait timing must be finite with a positive interval")
    if dry_run:
        return planned("urlscan", args.command)
    client = Client(api_key=resolve_api_key(args.api_key), timeout=args.timeout)
    args.json = True
    data = COMMANDS[args.command](client, args, structured=True)
    output = external("urlscan", args.command, data)
    if args.command == "dom":
        document(output, data["dom"], "text/html")
    if args.command == "screenshot" or getattr(args, "output", None) or args.save:
        effect(output, "urlscan-export", "write")
    return output


# --------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------

_EPILOG = """\
Global options go BEFORE the subcommand (urlscan.py --json search ...).

API key, first match wins: --api-key, $URLSCAN_API_KEY, ~/.config/urlscan/api_key,
~/.urlscan_api_key. `scan` and `whoami` need one; the other subcommands try without.

examples:
  urlscan.py search page.domain:example.com AND date:>now-7d
  urlscan.py search https://example.com/login          (a pasted URL becomes a field query)
  urlscan.py scan https://app.example.org/ --wait      (scope + policy + confirmation apply)
  urlscan.py --json result 0196d976-07f6-7aae-8a57-aa019145f31c | jq .verdicts
  urlscan.py screenshot 0196d976-07f6-7aae-8a57-aa019145f31c -o shot.png
  urlscan.py fields

exit status: 0 ok, 1 error or refusal, 2 bad command line, 130 interrupted.
"""


def _add_global_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--api-key",
        dest="api_key",
        metavar="KEY",
        help="urlscan.io API key (see below)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="HTTP timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the API response as JSON instead of the formatted view",
    )
    parser.add_argument(
        "--no-color", dest="no_color", action="store_true", help="never use ANSI colors"
    )
    parser.add_argument(
        "--save",
        metavar="FILE",
        help="also write the JSON response to FILE (search, scan and result only)",
    )


def _add_search_command(commands) -> None:
    sub = commands.add_parser(
        "search",
        help="search finished scans",
        description="Search urlscan.io; words are joined with spaces.",
    )
    sub.add_argument(
        "query", nargs="+", help="query-string search, or a URL to look up"
    )
    sub.add_argument(
        "--size", type=int, default=20, help="hits per page (default: %(default)s)"
    )
    sub.add_argument(
        "--after", help="cursor from a previous page (printed as `next page`)"
    )
    sub.add_argument(
        "--datasource",
        choices=("scans", "hostnames", "incidents", "notifications", "certificates"),
        help="index to search (default: scans)",
    )


def _add_wait_options(sub, initial_delay: float, with_help: bool) -> None:
    def note(text: str) -> str | None:
        return text if with_help else None

    sub.add_argument(
        "--wait", action="store_true", help="poll until the result is available"
    )
    sub.add_argument(
        "--wait-timeout",
        dest="wait_timeout",
        type=float,
        default=120.0,
        metavar="SECONDS",
        help="give up waiting after this long (default: %(default)s)",
    )
    sub.add_argument(
        "--initial-delay",
        dest="initial_delay",
        type=float,
        default=initial_delay,
        metavar="SECONDS",
        help=note("pause before the first poll (default: %(default)s)"),
    )
    sub.add_argument(
        "--interval",
        type=float,
        default=3.0,
        metavar="SECONDS",
        help=note("pause between polls (default: %(default)s)"),
    )


def _add_scan_command(commands) -> None:
    sub = commands.add_parser(
        "scan",
        help="ask urlscan.io to scan a URL (in scope, policy-checked, confirmed)",
        description="Submit a URL for scanning. urlscan.io's scanners, not this machine, visit the "
        "target; it must be in scope, allowed for active_scan, and confirmed.",
    )
    sub.add_argument("url", help="http(s) URL to scan")
    sub.add_argument(
        "--visibility",
        choices=("public", "unlisted", "private"),
        default="private",
        help="who can see the scan on urlscan.io (default: %(default)s)",
    )
    sub.add_argument(
        "--yes", action="store_true", help="skip the confirmation question"
    )
    sub.add_argument("--country", help="two-letter country to scan from")
    sub.add_argument(
        "--tag",
        action="append",
        metavar="TAG",
        help="tag the scan (repeatable; urlscan allows 10)",
    )
    sub.add_argument(
        "--user-agent",
        dest="user_agent",
        help="browser User-Agent the scanner presents",
    )
    sub.add_argument("--referer", help="Referer the scanner presents")
    sub.add_argument(
        "--override-safety",
        dest="override_safety",
        action="store_true",
        help="ask urlscan.io to scan despite its safety checks",
    )
    _add_wait_options(sub, initial_delay=10.0, with_help=True)


def _add_result_command(commands) -> None:
    sub = commands.add_parser(
        "result",
        help="show a finished scan",
        description="Fetch a scan result by its uuid.",
    )
    sub.add_argument("uuid", help="scan uuid (8-4-4-4-12 hex)")
    _add_wait_options(sub, initial_delay=2.0, with_help=False)


def _add_download_commands(commands) -> None:
    shot = commands.add_parser(
        "screenshot",
        help="download a scan's screenshot",
        description="Download the screenshot PNG of a scan.",
    )
    shot.add_argument("uuid", help="scan uuid")
    shot.add_argument(
        "-o",
        "--output",
        help="file to write (default: <uuid>.png in the current directory)",
    )
    dom = commands.add_parser(
        "dom",
        help="download a scan's DOM snapshot",
        description="Print or save the DOM snapshot of a scan.",
    )
    dom.add_argument("uuid", help="scan uuid")
    dom.add_argument("-o", "--output", help="file to write (default: print to stdout)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name,
        description="Search, submit and retrieve scans on urlscan.io.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_global_options(parser)
    commands = parser.add_subparsers(dest="command", required=True, title="subcommands")
    _add_search_command(commands)
    _add_scan_command(commands)
    _add_result_command(commands)
    _add_download_commands(commands)
    commands.add_parser(
        "quotas",
        help="show API rate limits and usage",
        description="Show the rate limits and usage of the API key.",
    )
    commands.add_parser(
        "whoami",
        help="show the account behind the API key",
        description="Show the account the API key belongs to (needs a key).",
    )
    commands.add_parser(
        "fields",
        help="print a cheat-sheet of search fields (offline)",
        description="Print the searchable fields and example queries; sends nothing.",
    )
    return parser


@contextmanager
def _legacy_output():
    previous = []
    try:
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                previous.append((stream, stream.errors))
                stream.reconfigure(errors="backslashreplace")
        yield
    finally:
        for stream, errors in reversed(previous):
            stream.reconfigure(errors=errors)


@_legacy_output()
def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    ink.enabled = color_wanted(args.no_color)
    api_key = resolve_api_key(args.api_key)
    if api_key is not None:
        try:
            api_key.encode("ascii")
        except UnicodeEncodeError:
            parser.error("API key must contain only ASCII characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in api_key):
            parser.error("API key must not contain control characters")
    client = Client(api_key=api_key, timeout=args.timeout)
    try:
        COMMANDS[args.command](client, args)
    except APIError as failure:
        hint = failure_hint(failure, args.command)
        die(f"HTTP {failure.status}: {failure.message}" + (f" {hint}" if hint else ""))
    except OSError as failure:
        die(f"could not write output: {failure}")
    except KeyboardInterrupt:
        print(file=sys.stderr)
        die("interrupted", 130)
    return 0


if __name__ == "__main__":
    sys.exit(main())
