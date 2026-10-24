"""Lanternjaw: a read-only command-line client for the public phishunt.io feed.

phishunt.io publishes phishing detections as open data. Lanternjaw browses and
filters that feed, summarizes it, pivots on shared infrastructure, follows
campaign clusters, checks a local indicator list against it, polls for new
detections, snapshots and diffs the feed, and writes a Markdown brief.

Every request is a GET to phishunt.io made through the guarded client in
``bughunt.core.http``, so the engagement policy and the host allow-list apply
to each hop. Two subcommands, ``analyze`` and ``deep``, hand a URL to phishunt;
they are additionally gated by scope, an ``active_scan`` grant and a
confirmation. Lanternjaw itself never contacts the URL it submits.

Screen output (tables, panels, notices) goes to stderr. Machine output (JSON,
``--values`` lines, raw feed text, the Markdown report) goes to stdout.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import sys
import time
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import quote, urlsplit

import httpx
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bughunt.console.ui import confirm
from bughunt.core import egress, ledger, workspace
from bughunt.core.http import HostNotAllowed, api_client, get_following

# --------------------------------------------------------------------------------------------
# Identity, endpoints and limits
# --------------------------------------------------------------------------------------------

NAME = "Lanternjaw"
VERSION = "1.0.0"
BASE = "https://phishunt.io"
DOCS = BASE + "/api/"
USER_AGENT = f"{NAME}/{VERSION} (+{DOCS}; read-only threat-intel client)"
ACCEPT = "application/json, text/csv, text/plain;q=0.8, */*;q=0.5"
API_HOSTS = frozenset({"phishunt.io"})
LANDING_HOSTS = frozenset({"phishunt.io", "www.phishunt.io"})

CACHE_TTL = 600  # seconds the active-feed cache stays fresh
RATE = 8.0  # requests per second this client allows itself
ATTEMPTS = 4  # tries per request
RETRY_STEP = 1.2  # seconds added per failed attempt
THROTTLE_CEILING = 90.0  # longest 429 wait that is honored
BULK_TIMEOUT = 90.0  # feeds and blocklists are large
PAGE_ROWS = 1000  # rows per /api/v1/domains page
OFFSET_CEILING = 10000  # the domains API stops paging past this offset
MAX_URL_LENGTH = 2048

ABSENT = "—"  # shown in place of an empty value

# --------------------------------------------------------------------------------------------
# Data tables
# --------------------------------------------------------------------------------------------

SOURCE_KEYS = ("google", "openphish", "phishtank", "tweetfeed", "urlscan")
SOURCE_FIELDS = tuple(f"malicious_{key}" for key in SOURCE_KEYS)
SOURCE_GLYPHS = "GOPTU"
SOURCE_LABELS = (
    "Google Safe Browsing",
    "OpenPhish",
    "PhishTank",
    "TweetFeed",
    "urlscan.io",
)

VERDICT_CHOICES = ("critical", "high", "medium", "low", "noise")
SORT_CHOICES = ("first_seen", "score", "sources", "brand")
FEED_KINDS = ("json", "csv", "txt", "stix")
BLOCKLIST_FILES = {
    "domains": "domains.txt",
    "hosts": "hosts.txt",
    "adblock": "adblock.txt",
    "dnsmasq": "dnsmasq.conf",
    "unbound": "unbound.conf",
    "rpz": "rpz.zone",
}
PIVOT_FIELDS = ("ip", "asn", "org", "cert", "country", "company", "registrar")
SERVER_FIELDS = (
    "company",
    "since",
    "contains",
    "tier",
    "asn",
    "org",
    "registrar",
    "cert",
    "country",
    "ip",
)

CSV_COLUMNS = (
    "uuid",
    "first_seen",
    "date",
    "verdict",
    "score",
    "company",
    "domain",
    "url",
    "ip",
    "country",
    "asn",
    "org",
    "cert",
) + SOURCE_FIELDS

# Hosting platforms that give anyone a subdomain; a phishing page on one of them is cheap to stand up.
SHARED_PLATFORM_SUFFIXES = frozenset(
    (
        "pages.dev",
        "workers.dev",
        "r2.dev",
        "web.app",
        "firebaseapp.com",
        "vercel.app",
        "netlify.app",
        "github.io",
        "glitch.me",
        "herokuapp.com",
        "blogspot.com",
        "webflow.io",
        "myshopify.com",
        "square.site",
        "teachable.com",
        "godaddysites.com",
        "azurewebsites.net",
    )
)
# Words that make a URL path read like a sign-in or account page.
CREDENTIAL_WORDS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "secure",
    "wallet",
    "account",
    "password",
    "update",
)

UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
SLUG_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

# --------------------------------------------------------------------------------------------
# Palette and screen state
# --------------------------------------------------------------------------------------------

THEME = Theme(
    {
        "lj.head": "bold cyan",
        "lj.label": "dim cyan",
        "lj.muted": "dim",
        "lj.warn": "yellow",
        "lj.bad": "bold red",
        "lj.good": "green",
        "lj.border": "cyan",
        "lj.alert": "red",
    }
)
TIER_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
    "noise": "dim",
    "phishing": "bold red",
    "likely_phishing": "red",
    "suspicious": "yellow",
    "minimal": "dim",
}
SCORE_BANDS = ((80, "bold red"), (60, "red"), (40, "yellow"), (1, "green"))

BANNER = (
    "   .-.    LANTERNJAW  v{version}\n"
    "  (o.o)   read-only phishunt.io threat intel\n"
    "   |=|    screen output is defanged; stdout is for machines\n"
    "  _|_|_"
)

SCREEN = Console(stderr=True, highlight=False, theme=THEME)
DISPLAY = SimpleNamespace(json=False, live=False)


class PhishuntError(RuntimeError):
    """Any refusal, API failure, network failure or unusable response."""

    def __init__(self, message, status=None, payload=None):
        super().__init__(message)
        self.status = status
        self.payload = payload


def note(message):
    """A muted notice for people; machine mode stays quiet."""
    if not DISPLAY.json:
        SCREEN.print(lit(message), style="lj.muted", soft_wrap=True)


def caution(message):
    if not DISPLAY.json:
        SCREEN.print(message, style="lj.warn", soft_wrap=True)


def emit_json(payload):
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    try:
        text.encode(sys.stdout.encoding or "utf-8")
    except UnicodeEncodeError:
        text = json.dumps(payload, indent=2, ensure_ascii=True)
    print(text)


def emit_raw(text):
    """Write already-formatted text to stdout, making sure it ends with a newline."""
    sys.stdout.write(text if text.endswith("\n") else text + "\n")


def untrusted(value):
    """Keep API-supplied text literal when embedded in styled markup."""
    return escape(str(value))


def lit(value):
    """API or user text rendered exactly as received."""
    return Text(str(value))


# --------------------------------------------------------------------------------------------
# Small pure rules
# --------------------------------------------------------------------------------------------


def flag(value):
    """Truth of a source flag: booleans, non-zero numbers and 1/true/yes/y strings."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y"}
    return False


def source_flags(row):
    return [flag(row.get(field)) for field in SOURCE_FIELDS]


def source_count(row):
    return sum(source_flags(row))


def site_score(row):
    for key in ("score", "phishunt_score", "url_risk_score"):
        raw = row.get(key)
        if raw is None or raw == "":
            continue
        try:
            return int(float(raw))
        except (TypeError, ValueError, OverflowError):
            continue
    return 0


def verdict_of(row):
    for key in ("verdict", "url_risk"):
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ABSENT


def to_int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError, OverflowError):
        return 0


def median(values):
    ordered = sorted(values)
    if not ordered:
        return None
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def short_time(value):
    text = str(value or "")
    return text.replace("T", " ")[:16] if text else ABSENT


def tiny_time(value):
    full = short_time(value)
    return full if full == ABSENT else full[5:]


def stamp_key(value):
    return str(value or "").replace("Z", "+00:00")[:19]


_MASKS = (
    ("https://", "hxxps://"),
    ("http://", "hxxp://"),
    ("https:", "hxxps:"),
    ("http:", "hxxp:"),
)
_UNMASKS = (
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("hxxps:", "https:"),
    ("hxxp:", "http:"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
)


def defang(text):
    """Neutralize links for screen output: masked schemes and bracketed dots."""
    out = str(text)
    for plain, masked in _MASKS:
        out = out.replace(plain, masked)
    return out.replace("[.]", ".").replace(".", "[.]")


def refang(text):
    """Undo common defanging and strip whitespace and wrapping quotes."""
    out = str(text).strip().strip("\"'")
    for masked, plain in _UNMASKS:
        out = out.replace(masked, plain)
    return out


def host_of(text):
    plain = refang(text).rstrip(".")
    if "://" not in plain and ("/" in plain or "?" in plain):
        plain = "http://" + plain
    if "://" in plain:
        try:
            return (urlsplit(plain).hostname or "").lower()
        except ValueError:
            return ""
    return plain.lower().split("/")[0].split("?")[0]


def looks_like_ipv4(text):
    parts = text.split(".")
    return len(parts) == 4 and all(
        part.isascii() and part.isdigit() and int(part) <= 255 for part in parts
    )


def valid_uuid(text):
    return isinstance(text, str) and bool(UUID_PATTERN.fullmatch(text))


def detail_link(row):
    company, uuid = str(row.get("company") or ""), str(row.get("uuid") or "")
    if SLUG_PATTERN.fullmatch(company) and valid_uuid(uuid):
        return f"{BASE}/suspicious/{company}/{uuid}/"
    return ""


def shown(value, network=False):
    """Display text for a value: a dash when empty, defanged for indicators unless --live."""
    text = ABSENT if value in (None, "") else str(value)
    return defang(text) if network and not DISPLAY.live else text


def decode_json(text):
    """Parse a body only when it looks like a JSON object or array."""
    stripped = text.lstrip()
    if stripped[:1] not in ("{", "["):
        return None
    try:
        return json.loads(stripped)
    except ValueError:
        return None


def finite_number(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


# --------------------------------------------------------------------------------------------
# The HTTP seam: every request in this program goes through Client.request
# --------------------------------------------------------------------------------------------


class Client:
    """Guarded, paced, retrying GET client for phishunt.io."""

    def __init__(self, timeout=45.0, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
        self.min_interval = 1.0 / RATE
        self._last_attempt = None
        self.session = api_client(
            API_HOSTS,
            timeout=timeout,
            headers={"Accept": ACCEPT, "User-Agent": USER_AGENT},
        )

    def request(self, path, params=None, *, headers=None, timeout=None):
        if not path.startswith("/"):
            raise PhishuntError("API path must start with /", status=400)
        url = BASE + path
        query = {
            key: val
            for key, val in (params or {}).items()
            if val is not None and val != ""
        }
        budget = self.timeout if timeout is None else timeout
        for attempt in range(1, ATTEMPTS + 1):
            self._pace()
            try:
                response = get_following(
                    self.session,
                    url,
                    params=query or None,
                    headers=headers,
                    timeout=budget,
                )
            except egress.PolicyBlocked as denial:
                raise PhishuntError(str(denial), status=400) from denial
            except HostNotAllowed as refusal:
                raise PhishuntError(
                    f"refusing to follow a redirect off phishunt.io: {refusal}"
                ) from refusal
            except httpx.HTTPError as failure:
                if attempt == ATTEMPTS:
                    raise PhishuntError(
                        f"network error talking to phishunt: {failure}"
                    ) from failure
                time.sleep(RETRY_STEP * attempt)
                continue
            self._check_landing(response)
            settled = self._settle(response, attempt)
            if settled is not None:
                return settled
        raise PhishuntError("request failed after every retry")

    def get_json(self, path, params=None, **options):
        response = self.request(path, params, **options)
        try:
            payload = response.json()
        except ValueError as bad:
            raise PhishuntError(f"invalid JSON from {response.url}: {bad}") from bad
        if (
            path.startswith("/api/v1/") or path == "/stix/bundle.json"
        ) and not isinstance(payload, dict):
            raise PhishuntError(f"expected a JSON object from {response.url}")
        return payload

    def get_text(self, path, params=None, **options):
        response = self.request(path, params, **options)
        if not response.charset_encoding:
            response.encoding = "utf-8"
        return response.text, response

    def _pace(self):
        if self._last_attempt is not None:
            wait = self.min_interval - (time.monotonic() - self._last_attempt)
            if wait > 0:
                time.sleep(wait)
        self._last_attempt = time.monotonic()

    @staticmethod
    def _check_landing(response):
        landed = response.url.host
        if landed not in LANDING_HOSTS:
            raise PhishuntError(
                f"refusing to follow a redirect off phishunt.io: it ended on {landed}"
            )

    def _settle(self, response, attempt):
        """Return the response, None to retry (after waiting), or raise for a final failure."""
        code = response.status_code
        if self.verbose:
            SCREEN.print(Text(f"GET {code} {response.url}"), soft_wrap=True)
        if code == 429:
            wait = self._throttle_wait(response, attempt)
            if wait > THROTTLE_CEILING or attempt == ATTEMPTS:
                raise self._http_error(response)
            SCREEN.print(
                Text(f"429 rate limited - sleeping {wait:g}s"), style="lj.warn"
            )
            time.sleep(wait)
            return None
        if code >= 500 and attempt < ATTEMPTS:
            time.sleep(RETRY_STEP * attempt)
            return None
        if code >= 400:
            raise self._http_error(response)
        return response

    @staticmethod
    def _throttle_wait(response, attempt):
        body = decode_json(response.text)
        hinted = body.get("retry_after") if isinstance(body, dict) else None
        for hint in (response.headers.get("retry-after", "").strip(), hinted):
            seconds = finite_number(hint)
            if seconds is not None:
                return max(0.0, seconds)
        return min(30.0, 2.0 ** (attempt - 1))

    @staticmethod
    def _http_error(response):
        code = response.status_code
        payload = decode_json(response.text)
        detail = ""
        if isinstance(payload, dict):
            detail = str(payload.get("error") or payload.get("message") or "")
        if not detail:
            detail = response.text.replace("\r", " ").replace("\n", " ")[:180]
        if not detail and code == 403:
            detail = "no detail given (API routes expect this client's User-Agent to be accepted)"
        extras = []
        if isinstance(payload, dict):
            if payload.get("budget") is not None:
                extras.append(f"budget={payload['budget']}")
            if payload.get("retry_after") is not None:
                extras.append(f"retry_after={payload['retry_after']}s")
        suffix = f" ({', '.join(extras)})" if extras else ""
        return PhishuntError(
            f"HTTP {code} - {detail}{suffix}", status=code, payload=payload
        )


# --------------------------------------------------------------------------------------------
# Feed cache, server filters, paging
# --------------------------------------------------------------------------------------------


def cache_file():
    root = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(root) / "lanternjaw" / "feed.json"


def read_cache():
    """(rows, age in seconds) when a fresh, readable cache exists; otherwise None."""
    path = cache_file()
    try:
        age = time.time() - path.stat().st_mtime
        if age > CACHE_TTL:
            return None
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    rows = stored.get("sites") if isinstance(stored, dict) else stored
    return (rows, int(age)) if isinstance(rows, list) else None


def write_cache(rows):
    path = cache_file()
    envelope = {"saved_at": now_iso(), "count": len(rows), "sites": rows}
    scratch = path.with_name(path.name + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        scratch.write_text(json.dumps(envelope, ensure_ascii=False), encoding="utf-8")
        os.replace(scratch, path)
    except OSError as problem:
        caution(f"could not write the feed cache: {escape(str(problem))}")


def fetch_feed(client):
    if SCREEN.is_terminal and not DISPLAY.json:
        with SCREEN.status("downloading the active feed"):
            data = client.get_json("/feed.json", timeout=BULK_TIMEOUT)
    else:
        data = client.get_json("/feed.json", timeout=BULK_TIMEOUT)
    if not isinstance(data, list):
        raise PhishuntError("feed.json was not a JSON array")
    return data


def load_feed(client, fresh=False):
    """The active feed: the cache while it is young, otherwise a download (which refreshes the cache)."""
    cache_enabled = getattr(client, "cache_enabled", True)
    if not fresh and cache_enabled:
        cached = read_cache()
        if cached is not None:
            rows, age = cached
            note(f"cache: {len(rows)} active rows, {age}s old (--fresh to reload)")
            return rows
    rows = fetch_feed(client)
    if cache_enabled:
        write_cache(rows)
    note(f"{len(rows)} active rows")
    return rows


def contains_term(raw):
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "", str(raw))
    if not 3 <= len(cleaned) <= 80:
        raise PhishuntError(
            "--contains must be 3-80 characters of letters, digits, '.', '_' or '-' once cleaned",
            status=400,
        )
    return cleaned


def object_rows(rows):
    selected = [row for row in rows if isinstance(row, dict)]
    skipped = len(rows) - len(selected)
    if skipped:
        SCREEN.print(
            Text(f"skipped {skipped} non-object feed rows", style="lj.warn"),
            soft_wrap=True,
        )
    return selected


_SERVER_CLEANERS = {
    "company": lambda raw: str(raw).strip().lower(),
    "asn": lambda raw: re.sub(r"^[Aa][Ss]", "", str(raw).strip()),
    "contains": contains_term,
}


def server_params(args):
    """The filters phishunt can apply itself, in wire order, normalized."""
    params = {}
    for name in SERVER_FIELDS:
        raw = getattr(args, name, None)
        if not raw:
            continue
        value = _SERVER_CLEANERS.get(name, lambda item: item)(raw)
        if value:
            params[name] = value
    return params


def fetch_domains_page(client, params, limit, offset):
    return client.get_json(
        "/api/v1/domains", {**params, "limit": limit, "offset": offset}
    )


def page_domains(client, params):
    """Every row matching `params`, paging 1000 at a time and de-duplicating by uuid."""
    rows, seen, offset, total = [], set(), 0, None
    while True:
        page = fetch_domains_page(client, params, PAGE_ROWS, offset)
        batch = page.get("results") or []
        if isinstance(page.get("total"), int):
            total = page["total"]
        added = 0
        for row in batch:
            key = row.get("uuid")
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            rows.append(row)
            added += 1
        offset += len(batch)
        if (
            not added
            or (total is not None and offset >= total)
            or len(batch) < PAGE_ROWS
            or offset > OFFSET_CEILING
        ):
            break
    if total is not None and len(rows) < total:
        caution(
            f"fetched {len(rows)} of {total} matches; the domains API caps offset at {OFFSET_CEILING}. "
            "Use `feed json` for the unfiltered full set."
        )
    return rows, total


def apply_client_filters(rows, args):
    verdict = getattr(args, "verdict", None)
    min_score = getattr(args, "min_score", None)
    min_sources = getattr(args, "min_sources", None)
    if verdict:
        rows = [row for row in rows if verdict_of(row).lower() == verdict.lower()]
    if min_score is not None:
        rows = [row for row in rows if site_score(row) >= min_score]
    if min_sources is not None:
        rows = [row for row in rows if source_count(row) >= min_sources]
    return rows


_SORT_KEYS = {
    "first_seen": lambda row: str(row.get("first_seen") or ""),
    "score": lambda row: (
        site_score(row),
        source_count(row),
        str(row.get("first_seen") or ""),
    ),
    "sources": lambda row: (
        source_count(row),
        site_score(row),
        str(row.get("first_seen") or ""),
    ),
    "brand": lambda row: (
        str(row.get("company") or ""),
        str(row.get("first_seen") or ""),
    ),
}


def sort_rows(rows, how="first_seen"):
    """Largest first; rows that tie keep the order they arrived in."""
    return sorted(
        rows,
        key=_SORT_KEYS.get(how or "first_seen", _SORT_KEYS["first_seen"]),
        reverse=True,
    )


def clip(rows, limit, default):
    return rows[: (limit or default)]


def gather(client, args):
    """The working set for a command: (rows, label). Server filters use the domains API, else the active feed."""
    params = server_params(args)
    offset = getattr(args, "offset", None)
    if offset and not params:
        raise PhishuntError("--offset requires a server filter", status=400)
    total = None
    if params and offset:
        page = fetch_domains_page(client, params, args.limit or 100, offset)
        rows, total = page.get("results") or [], page.get("total")
        kind = "page"
    elif params:
        rows, total = page_domains(client, params)
        kind = "domains"
    else:
        rows, kind = load_feed(client, args.fresh), "feed"
    rows = sort_rows(
        apply_client_filters(object_rows(rows), args), getattr(args, "sort", None)
    )
    return rows, slice_label(kind, len(rows), offset, total)


def slice_label(kind, count, offset, total):
    if kind == "feed":
        return f"active feed, {count} rows"
    if kind == "page":
        return (
            f"api/v1/domains page at offset {offset}, {count} rows of {total} matches"
        )
    return f"api/v1/domains, {count} matches"


def _same_text(field):
    return lambda wanted: lambda row: str(row.get(field) or "") == wanted


_NARROWERS = {
    "company": lambda wanted: (
        lambda row: str(row.get("company") or "").lower() == wanted
    ),
    "country": _same_text("country"),
    "org": _same_text("org"),
    "cert": _same_text("cert"),
    "ip": _same_text("ip"),
    "registrar": _same_text("registrar"),
    "asn": lambda wanted: (
        lambda row: re.sub(r"^[Aa][Ss]", "", str(row.get("asn") or "")) == wanted
    ),
    "contains": lambda wanted: (
        lambda row: (
            wanted.lower()
            in f"{row.get('url') or ''} {row.get('domain') or ''}".lower()
        )
    ),
    "since": lambda wanted: (
        lambda row: (
            not row.get("first_seen")
            or stamp_key(row["first_seen"]) >= stamp_key(wanted)
        )
    ),
}


def narrow_rows(rows, args, side):
    """Apply the server-style filters locally (a snapshot cannot be queried) plus the client filters."""
    params = server_params(args)
    if getattr(args, "tier", None):
        caution(f"--tier cannot be applied to the {side}; ignored there")
    tests = [
        _NARROWERS[name](value) for name, value in params.items() if name in _NARROWERS
    ]
    return apply_client_filters(
        [row for row in rows if all(test(row) for test in tests)], args
    )


# --------------------------------------------------------------------------------------------
# Summaries
# --------------------------------------------------------------------------------------------


def network_key(row):
    number = re.sub(r"^[Aa][Ss]", "", str(row.get("asn") or "").strip())
    return f"AS{number}  {row.get('org') or ''}".rstrip() if number else ABSENT


def on_shared_platform(domain):
    labels = domain.lower().split(".")
    return any(
        ".".join(labels[start:]) in SHARED_PLATFORM_SUFFIXES
        for start in range(len(labels))
    )


def summarize(rows):
    """Counters and shape measures over a slice of detections (dashboard, brief and `feed json`)."""
    tallies = {
        name: Counter()
        for name in (
            "verdicts",
            "brands",
            "countries",
            "networks",
            "certs",
            "sources",
            "consensus",
        )
    }
    shape = Counter()
    scores = []
    for row in rows:
        verdict, flagged = verdict_of(row), source_flags(row)
        tallies["verdicts"][verdict] += 1
        tallies["brands"][row.get("company") or ABSENT] += 1
        tallies["countries"][row.get("country") or ABSENT] += 1
        tallies["networks"][network_key(row)] += 1
        tallies["certs"][row.get("cert") or ABSENT] += 1
        tallies["consensus"][sum(flagged)] += 1
        for label, hit in zip(SOURCE_LABELS, flagged):
            if hit:
                tallies["sources"][label] += 1
        scores.append(site_score(row))
        domain, url = str(row.get("domain") or ""), str(row.get("url") or "").lower()
        shape["noise_flagged"] += verdict.lower() in ("noise", ABSENT) and any(flagged)
        shape["punycode"] += "xn--" in domain.lower()
        shape["paas_suffix"] += on_shared_platform(domain)
        shape["credential_path"] += any(word in url for word in CREDENTIAL_WORDS)
    firsts = [str(row["first_seen"]) for row in rows if row.get("first_seen")]
    checks = [str(row["date"]) for row in rows if row.get("date")]
    return {
        **tallies,
        **{
            key: shape[key]
            for key in ("noise_flagged", "punycode", "paas_suffix", "credential_path")
        },
        "count": len(rows),
        "median_score": median(scores),
        "newest": sort_rows(rows, "first_seen")[:8],
        "hottest": sort_rows(rows, "score")[:8],
        "first": min(firsts) if firsts else "",
        "last": max(firsts) if firsts else "",
        "checked": max(checks) if checks else "",
    }


def pulse_payload(summary):
    top = lambda counter, limit: [list(pair) for pair in counter.most_common(limit)]  # noqa: E731
    return {
        "count": summary["count"],
        "verdicts": dict(summary["verdicts"].most_common()),
        "brands": top(summary["brands"], 30),
        "countries": top(summary["countries"], 20),
        "asns": top(summary["networks"], 20),
        "certs": top(summary["certs"], 15),
        "sources": {
            label: summary["sources"][label]
            for label in SOURCE_LABELS
            if summary["sources"][label]
        },
        "noise_flagged": summary["noise_flagged"],
        "punycode": summary["punycode"],
        "paas_suffix": summary["paas_suffix"],
        "credential_path": summary["credential_path"],
        "median_score": summary["median_score"],
    }


# --------------------------------------------------------------------------------------------
# Rendering primitives (everything below writes to the stderr console)
# --------------------------------------------------------------------------------------------


def band_style(score):
    for floor, style in SCORE_BANDS:
        if score >= floor:
            return style
    return "dim"


def score_cell(score):
    return Text(f"{score:>3}", style=band_style(score))


def score_bar(score, width=8):
    filled = round(width * max(0, min(100, score)) / 100)
    return Text("█" * filled + "░" * (width - filled), style=band_style(score))


def glyph_cell(flags):
    """Five source glyphs; bright when that source flagged the row, dim when it did not."""
    cell = Text()
    for glyph, hit in zip(SOURCE_GLYPHS, flags):
        cell.append(glyph, style="bold green" if hit else "dim")
    return cell


def glyph_string(row):
    return "".join(
        glyph if hit else glyph.lower()
        for glyph, hit in zip(SOURCE_GLYPHS, source_flags(row))
    )


def yes_no(value):
    return ABSENT if value is None else ("yes" if flag(value) else "no")


def table_of(headers, *, right=(), keep=(), title=None):
    table = Table(
        box=box.SIMPLE_HEAD,
        show_edge=False,
        pad_edge=False,
        header_style="lj.head",
        title=title,
        title_justify="left",
        title_style="lj.head",
    )
    for header in headers:
        table.add_column(
            header,
            justify="right" if header in right else "left",
            no_wrap=header in keep,
            overflow="fold",
        )
    return table


def facts(pairs):
    """A two-column label/value grid. Values are Text (literal) or str (markup)."""
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="lj.label", no_wrap=True)
    grid.add_column(overflow="fold")
    for label, value in pairs:
        grid.add_row(label, ABSENT if value in (None, "") else value)
    return grid


def panel(body, title, subtitle=None, style="lj.border"):
    return Panel(
        body,
        title=title,
        subtitle=subtitle,
        title_align="left",
        subtitle_align="left",
        border_style=style,
    )


def lines_text(lines):
    return Text("\n").join(lit(line) for line in lines)


def site_table(rows):
    wide = SCREEN.width >= 110
    headers = (
        ["seen", "score", "brand", "domain"] + (["ip / geo"] if wide else []) + ["src"]
    )
    table = table_of(headers, right=("score",), keep=("seen", "score", "src"))
    for row in rows:
        cells = [
            lit(tiny_time(row.get("first_seen"))),
            score_cell(site_score(row)),
            lit(shown(row.get("company"))),
            lit(shown(row.get("domain"), True)),
        ]
        if wide:
            cells.append(
                lit(f"{shown(row.get('ip'), True)} {shown(row.get('country'))}")
            )
        table.add_row(*cells, glyph_cell(source_flags(row)))
    return table


def print_sites(rows, title=None):
    if title:
        SCREEN.print(Text(title, style="lj.head"))
    SCREEN.print(site_table(rows))
    SCREEN.print(
        "src G/O/P/T/U = google, openphish, phishtank, tweetfeed, urlscan - bright = flagged, dim != clean",
        style="lj.muted",
    )


def counter_table(title, counter, limit):
    table = table_of(["name", "n", ""], right=("n",), title=title)
    peak = max(counter.values(), default=1)
    for name, count in counter.most_common(limit):
        style = TIER_STYLES.get(str(name).lower(), "lj.border")
        table.add_row(
            lit(shown(name)),
            lit(count),
            Text("█" * max(1, round(18 * count / peak)), style=style),
        )
    return table


# --------------------------------------------------------------------------------------------
# Views: pulse dashboard and detection cards
# --------------------------------------------------------------------------------------------

DISCLAIMER = (
    "scores are heuristics, not verdicts; false positives happen.",
    "a source flag that is false means 'not flagged when last checked', not 'clean'.",
)


def pulse_headline(summary, label):
    median_text = (
        ABSENT if summary["median_score"] is None else f"{summary['median_score']:g}"
    )
    return lines_text(
        (
            f"{summary['count']} active detections - median score {median_text} - {len(summary['brands'])} brands, "
            f"{len(summary['countries'])} countries, {len(summary['networks'])} networks",
            f"slice: {label}",
            f"first seen {shown(summary['first'])} .. {shown(summary['last'])} - last check {shown(summary['checked'])}",
            *DISCLAIMER,
        )
    )


def shape_panel(summary):
    consensus = ", ".join(
        f"{src} src x {rows}" for src, rows in sorted(summary["consensus"].items())
    )
    return panel(
        facts(
            [
                ("consensus", lit(consensus or ABSENT)),
                ("noise-tier but feed-flagged", lit(summary["noise_flagged"])),
                ("punycode hosts", lit(summary["punycode"])),
                ("shared-platform suffixes", lit(summary["paas_suffix"])),
                ("credential-ish paths", lit(summary["credential_path"])),
            ]
        ),
        "shape of the slice",
    )


def render_pulse(summary, label):
    SCREEN.print(panel(pulse_headline(summary, label), "pulse"))
    for title, key, limit in (
        ("verdict tiers", "verdicts", 8),
        ("targeted brands", "brands", 12),
        ("hosting countries", "countries", 8),
        ("networks", "networks", 8),
        ("certificate issuers", "certs", 6),
        ("external feeds that flagged", "sources", 5),
    ):
        SCREEN.print(counter_table(title, summary[key], limit))
    SCREEN.print(shape_panel(summary))
    print_sites(summary["hottest"], "hottest")
    print_sites(summary["newest"], "newest")


def signals_table(items, title, limit=8):
    """Scoring signals from a detection or an analysis. Cells are handed to rich as markup (see `untrusted`)."""
    table = table_of(
        ["signal", "kind", "points", "detail"], right=("points",), title=title
    )
    for item in (items or [])[:limit]:
        points = (
            item.get("points")
            if item.get("points") is not None
            else item.get("score_contribution")
        )
        detail = [
            str(item["label"]) if item.get("label") else "",
            f"value {item['value']}" if "value" in item else "",
            f"w {item['weight']}" if "weight" in item else "",
        ]
        table.add_row(
            untrusted(item.get("signal") or item.get("signal_id") or ABSENT),
            untrusted(item.get("kind") or item.get("category") or ABSENT),
            lit(shown(points)),
            untrusted(" - ".join(part for part in detail if part) or ABSENT),
        )
    return table


def card_facts(row):
    return facts(
        [
            ("uuid", lit(shown(row.get("uuid")))),
            ("brand", lit(shown(row.get("company")))),
            ("verdict", lit(verdict_of(row))),
            ("score", lit(site_score(row))),
            ("first seen", lit(shown(row.get("first_seen")))),
            ("last check", lit(shown(row.get("date")))),
            ("ip", lit(shown(row.get("ip"), True))),
            ("country", lit(shown(row.get("country")))),
            ("asn", lit(shown(row.get("asn")))),
            ("org", lit(shown(row.get("org")))),
            ("cert", lit(shown(row.get("cert")))),
            ("registrar", lit(shown(row.get("registrar")))),
            ("sources", lit(glyph_string(row))),
            ("phishunt page", lit(shown(detail_link(row)))),
            ("sans_score", lit(shown(row.get("sans_score")))),
            ("sans_scorereason", lit(shown(row.get("sans_scorereason")))),
        ]
    )


def render_site_card(row, title):
    lead = (
        f"[bold]{untrusted(shown(row.get('url') or row.get('domain'), True))}[/bold]\n"
        f"domain {untrusted(shown(row.get('domain'), True))}"
    )
    SCREEN.print(panel(lead, title))
    SCREEN.print(card_facts(row))
    if row.get("top_signals"):
        SCREEN.print(signals_table(row["top_signals"], "top signals"))


# --------------------------------------------------------------------------------------------
# Views: analyze and deep
# --------------------------------------------------------------------------------------------


def analyze_pairs(data, live, score):
    query = data.get("query") or {}
    return [
        ("url", lit(shown(query.get("url"), True))),
        ("host", lit(shown(query.get("host"), True))),
        ("apex", lit(shown(query.get("apex"), True))),
        ("brand match", lit(shown(live.get("brand_match")))),
        ("keyword score", lit(shown(live.get("kw_score")))),
        ("url_risk (score)", lit(f"{shown(live.get('url_risk'))} ({score})")),
        ("allowlisted", lit(yes_no(live.get("allowlisted")))),
        ("impersonation", lit(shown(live.get("impersonation")))),
        ("adjudicated verdict", lit(shown(data.get("verdict")))),
        ("verdict confidence", lit(shown(data.get("verdict_confidence")))),
        (
            "verdict basis",
            lit("; ".join(map(str, data.get("verdict_basis") or [])) or ABSENT),
        ),
    ]


def shape_signal_table(live):
    table = table_of(
        ["signal", "value"], right=("value",), title="non-zero shape signals"
    )
    for group in ("url_signals", "path_signals"):
        for name, number in (live.get(group) or {}).items():
            if (
                isinstance(number, (int, float))
                and not isinstance(number, bool)
                and number > 0
            ):
                table.add_row(untrusted(f"{group}.{name}"), lit(f"{number:.2f}"))
    return table


def stored_pairs(known):
    record = known.get("record") or {}
    pairs = [
        ("in active feed", lit(yes_no(known.get("in_active_feed")))),
        ("previously active", lit(yes_no(known.get("previously_active")))),
        (
            "in new-registration feed",
            lit(yes_no(known.get("in_new_registration_feed"))),
        ),
    ]
    if record:
        sources = (
            record.get("sources") if isinstance(record.get("sources"), dict) else {}
        )
        pairs += [
            ("stored brand", lit(shown(record.get("company")))),
            ("stored score", lit(shown(record.get("phishunt_score")))),
            ("stored verdict", lit(shown(record.get("verdict")))),
            ("first seen", lit(shown(record.get("first_seen")))),
            ("phishunt page", lit(shown(record.get("detail_url")))),
            (
                "sources flagged",
                lit(
                    ", ".join(name for name, hit in sources.items() if flag(hit))
                    or ABSENT
                ),
            ),
        ]
    return pairs


def history_pairs(data):
    history, external, action = (
        data.get("history") or {},
        data.get("external_feeds") or {},
        data.get("action") or {},
    )
    brands = ", ".join(
        f"{item.get('company')} ({item.get('count')})"
        for item in history.get("brands_targeted") or []
    )
    return [
        ("prior detections on apex", lit(shown(history.get("apex_prior_detections")))),
        ("apex first seen", lit(shown(history.get("apex_first_seen")))),
        ("apex last seen", lit(shown(history.get("apex_last_seen")))),
        ("brands targeted", lit(brands or ABSENT)),
        ("openphish", lit(yes_no(external.get("openphish")))),
        ("phishtank", lit(yes_no(external.get("phishtank")))),
        ("tweetfeed", lit(yes_no(external.get("tweetfeed")))),
        ("listed", lit(yes_no(external.get("listed")))),
        ("feed status", lit(shown(external.get("status")))),
        ("queued for analysis", lit(yes_no(action.get("queued_for_analysis")))),
        ("queue reason", lit(shown(action.get("reason")))),
    ]


def render_analyze(data, heading="PASSIVE ANALYZE", subtitle=None):
    live = data.get("live_analysis") or {}
    score = to_int(live.get("url_risk_score"))
    verdict = str(data.get("verdict") or ABSENT)
    summary = Text.assemble(
        Text(verdict, style=TIER_STYLES.get(verdict.lower(), "")),
        "  ",
        score_bar(score),
        f"  {score}",
    )
    SCREEN.print(panel(summary, heading, subtitle))
    SCREEN.print(facts(analyze_pairs(data, live, score)))
    if live.get("why"):
        SCREEN.print(signals_table(live["why"], "why this score"))
    shape = shape_signal_table(live)
    if shape.row_count:
        SCREEN.print(shape)
    known = data.get("known") or {}
    SCREEN.print(panel(facts(stored_pairs(known)), "what phishunt already stored"))
    model_note = (known.get("record") or {}).get("ai") or {}
    if model_note.get("summary"):
        body = untrusted(model_note["summary"]) + (
            f"\nthreat type: {untrusted(model_note['threat_type'])}"
            if model_note.get("threat_type")
            else ""
        )
        SCREEN.print(panel(body, "untrusted model note", style="lj.warn"))
    SCREEN.print(panel(facts(history_pairs(data)), "history and external lists"))
    if (data.get("meta") or {}).get("note"):
        SCREEN.print(f"note: {untrusted(data['meta']['note'])}", style="lj.muted")
    SCREEN.print(
        "this URL was sent to phishunt and is logged there; prefer a bare domain if it carries tokens.",
        style="lj.muted",
    )


def fired_signals(deep):
    fired = [
        item
        for item in deep.get("signals") or []
        if item.get("detected")
        or (finite_number(item.get("score_contribution")) or 0) > 0
    ]
    return sorted(
        fired,
        key=lambda item: finite_number(item.get("score_contribution")) or 0.0,
        reverse=True,
    )


def deep_signal_table(deep):
    table = table_of(
        ["signal", "category", "points", "description", "value"],
        right=("points",),
        title="signals that fired",
    )
    for item in fired_signals(deep)[:8]:
        table.add_row(
            untrusted(item.get("signal_id") or ABSENT),
            untrusted(item.get("category") or ABSENT),
            lit(shown(item.get("score_contribution"))),
            untrusted(shown(item.get("description"))),
            untrusted(shown(item.get("normalized_value"))),
        )
    return table


def failure_lines(deep):
    failures = deep.get("analysis_failures") or []
    if isinstance(failures, dict):
        lines = [f"{key}: {value}" for key, value in failures.items()]
    else:
        lines = [
            ", ".join(f"{k}: {v}" for k, v in item.items())
            if isinstance(item, dict)
            else str(item)
            for item in failures
        ]
    for item in deep.get("signals") or []:
        lines += [
            f"{item.get('signal_id')}: {error}" for error in item.get("errors") or []
        ]
    return lines[:25]


def render_deep(data):
    SCREEN.print(
        panel(
            lines_text(
                (
                    "phishunt fetched this URL on your behalf; the target saw phishunt, not you.",
                    "a low score is not a clean result: it only means no detector fired.",
                    "values below can echo attacker-controlled content; treat them as untrusted.",
                )
            ),
            "ACTIVE MODE",
            style="lj.alert",
        )
    )
    render_analyze(data, "DEEP ANALYZE", "phishunt contacted this URL")
    deep = data.get("deep_analysis") or {}
    layers = ", ".join(
        f"{name} {score}" for name, score in (deep.get("layer_scores") or {}).items()
    )
    SCREEN.print(
        panel(
            facts(
                [
                    ("detector version", lit(shown(deep.get("detector_version")))),
                    ("risk score", lit(shown(deep.get("risk_score")))),
                    ("verdict", lit(shown(deep.get("verdict")))),
                    ("classification", lit(shown(deep.get("classification")))),
                    ("layer scores", lit(layers or ABSENT)),
                ]
            ),
            "deep analysis",
        )
    )
    SCREEN.print(deep_signal_table(deep))
    if failure_lines(deep):
        SCREEN.print(
            panel(
                lines_text(failure_lines(deep)), "not fully evaluated", style="lj.warn"
            )
        )
    if deep.get("adjustments"):
        SCREEN.print(
            panel(lines_text(map(str, deep["adjustments"][:8])), "adjustments")
        )
    budget = data.get("budget") or {}
    SCREEN.print(
        f"budget: used {budget.get('used', ABSENT)}, remaining {budget.get('remaining', ABSENT)}, "
        f"limit {budget.get('limit', ABSENT)}",
        style="lj.muted",
    )


# --------------------------------------------------------------------------------------------
# Views: campaigns
# --------------------------------------------------------------------------------------------


def join_text(items):
    return ", ".join(map(str, items or [])) or ABSENT


def render_campaign_list(payload):
    rows = payload.get("results") or []
    status = payload.get("data_status")
    SCREEN.print(
        panel(
            lines_text(
                (
                    f"{payload.get('count', len(rows))} on this page - {shown(payload.get('total'))} matched",
                    f"algorithm {shown(payload.get('algorithm_version'))} - generated {shown(payload.get('generated_at'))} - "
                    f"data status {shown(status)}",
                )
            ),
            "campaigns",
        )
    )
    if status and status != "ok":
        SCREEN.print(
            Text.assemble(
                "data status is ", lit(status), ": campaign data may be stale"
            ),
            style="lj.warn",
        )
    table = table_of(
        ["key", "confidence", "size", "active", "brands", "evidence", "last activity"],
        right=("size", "active"),
    )
    for row in rows:
        lead = row.get("top_evidence") or {}
        evidence = f"{lead.get('type', '')} {lead.get('coverage', '')}".strip()
        shade = (
            "yellow" if str(row.get("confidence", "")).startswith("possible") else "dim"
        )
        table.add_row(
            untrusted(shown(row.get("key"))),
            f"[{shade}]{untrusted(shown(row.get('confidence')))}[/]",
            lit(shown(row.get("size"))),
            lit(shown(row.get("active_count"))),
            untrusted(join_text(row.get("brands"))),
            lit(evidence or ABSENT),
            lit(short_time(row.get("last_activity"))),
        )
    SCREEN.print(table)
    SCREEN.print("use `campaign KEY` for the full cluster", style="lj.muted")


def campaign_pairs(data):
    lead = data.get("top_evidence") or {}
    confidence = shown(data.get("confidence") or data.get("label"))
    return [
        ("key", lit(shown(data.get("key")))),
        ("legacy id", lit(shown(data.get("id")))),
        ("state", lit(shown(data.get("state")))),
        ("end state", lit(shown(data.get("end_state")))),
        ("successors", lit(join_text(data.get("successors")))),
        (
            "confidence",
            lit(f"{confidence} (score {shown(data.get('confidence_score'))})"),
        ),
        ("size", lit(shown(data.get("size")))),
        ("hosts", lit(shown(data.get("host_count")))),
        ("active members", lit(shown(data.get("active_count")))),
        ("brands", lit(join_text(data.get("brands")))),
        ("first seen", lit(shown(data.get("first_seen") or data.get("first_tracked")))),
        (
            "last activity",
            lit(shown(data.get("last_activity") or data.get("last_seen"))),
        ),
        (
            "top evidence",
            lit(
                f"{lead.get('type', '')} ({lead.get('coverage', '')})"
                if lead
                else ABSENT
            ),
        ),
        ("algorithm", lit(shown(data.get("algorithm_version")))),
        ("generated", lit(shown(data.get("generated_at")))),
        ("data status", untrusted(shown(data.get("data_status")))),
        ("page", lit(shown(data.get("url")))),
    ]


def campaign_evidence_table(data):
    table = table_of(
        ["type", "value", "members matching"],
        right=("members matching",),
        title="evidence",
    )
    for item in (data.get("evidence_summary") or [])[:20]:
        table.add_row(
            lit(shown(item.get("type"))),
            lit(shown(str(item.get("value") or "")[:140], True)),
            lit(shown(item.get("members_matching"))),
        )
    return table


def campaign_members_table(members):
    table = table_of(
        ["status", "score", "brand", "domain", "ip", "src"],
        right=("score",),
        title=f"members ({len(members)})",
    )
    for member in members[:40]:
        table.add_row(
            lit(shown(member.get("status"))),
            lit(shown(member.get("score"))),
            lit(shown(member.get("company"))),
            lit(shown(member.get("domain"), True)),
            lit(shown(member.get("ip"), True)),
            glyph_cell(source_flags(member)),
        )
    return table


def campaign_pairs_table(data):
    table = table_of(
        ["domain a", "domain b", "score", "tier"],
        right=("score",),
        title="strongest pairs",
    )
    for pair in (data.get("relationships") or [])[:12]:
        table.add_row(
            lit(shown(pair.get("domain_a"), True)),
            lit(shown(pair.get("domain_b"), True)),
            lit(shown(pair.get("score"))),
            untrusted(shown(pair.get("tier"))),
        )
    return table


def delta_text(sign, names):
    return ", ".join(f"{sign}{shown(name, True)}" for name in names or []) or ABSENT


def campaign_history_table(data):
    table = table_of(
        ["time", "event", "size", "joined", "left"], right=("size",), title="history"
    )
    for step in (data.get("history") or [])[:8]:
        table.add_row(
            lit(short_time(step.get("at"))),
            lit(shown(step.get("event"))),
            lit(f"size {shown(step.get('size'))}"),
            lit(delta_text("+", step.get("joined"))),
            lit(delta_text("-", step.get("left"))),
        )
    return table


def render_campaign(data):
    SCREEN.print(panel(facts(campaign_pairs(data)), "campaign"))
    SCREEN.print(campaign_evidence_table(data))
    members = data.get("members") or []
    SCREEN.print(campaign_members_table(members))
    if len(members) > 40:
        SCREEN.print(
            f"showing the first 40 of {len(members)} members; --json lists them all",
            style="lj.muted",
        )
    SCREEN.print(campaign_pairs_table(data))
    if data.get("relationships_truncated"):
        SCREEN.print(
            "strongest relationships only - the list is capped by phishunt",
            style="lj.muted",
        )
    SCREEN.print(campaign_history_table(data))
    SCREEN.print(
        "members share infrastructure; that is not attribution to any actor.",
        style="lj.muted",
    )


# --------------------------------------------------------------------------------------------
# Views: related, enrich, brand, cert, STIX, raw-text previews, about
# --------------------------------------------------------------------------------------------


def render_related(data):
    cluster = data.get("cluster")
    pairs = [
        ("domain", lit(shown(data.get("domain"), True))),
        ("algorithm", lit(shown(data.get("algorithm_version")))),
        ("generated", lit(shown(data.get("generated_at")))),
    ]
    if cluster:
        pairs += [
            ("cluster", lit(shown(cluster.get("key")))),
            ("cluster size", lit(shown(cluster.get("size")))),
            ("cluster hosts", lit(shown(cluster.get("host_count")))),
            ("cluster page", lit(shown(cluster.get("url")))),
        ]
    else:
        pairs.append(("cluster", lit("not currently in a surfaced cluster")))
    SCREEN.print(panel(facts(pairs), "related"))
    results = data.get("results") or []
    if not results:
        SCREEN.print("no related indicators at this threshold.", style="lj.muted")
        return
    table = table_of(
        ["score", "status", "brand", "domain", "evidence"], right=("score",)
    )
    for item in results:
        table.add_row(
            lit(shown(item.get("relationship_score"))),
            lit(shown(item.get("status"))),
            lit(shown(item.get("company"))),
            lit(shown(item.get("domain"), True)),
            lit(join_text(e.get("type") for e in item.get("evidence") or [])),
        )
    SCREEN.print(table)
    SCREEN.print(
        "related hosts share infrastructure; that is not attribution.", style="lj.muted"
    )


def lookup_panel(title, block, wanted, network_keys=()):
    pairs = []
    for key, label in wanted:
        value = block.get(key)
        text = (
            join_text(value)
            if isinstance(value, list)
            else shown(value, key in network_keys)
        )
        pairs.append((label, lit(text)))
    SCREEN.print(panel(facts(pairs), title))


def render_enrich(data):
    whois, ipinfo = data.get("whois"), data.get("ipinfo")
    if isinstance(whois, dict):
        lookup_panel(
            "whois",
            whois,
            (
                ("registrar", "registrar"),
                ("created", "created"),
                ("updated", "updated"),
                ("expires", "expires"),
                ("status", "status"),
                ("error", "lookup error"),
            ),
        )
    if isinstance(ipinfo, dict):
        lookup_panel(
            "ip geolocation",
            ipinfo,
            (
                ("city", "city"),
                ("region", "region"),
                ("country", "country"),
                ("postal", "postal"),
                ("loc", "location"),
                ("hostname", "hostname"),
                ("error", "lookup error"),
            ),
            network_keys=("hostname",),
        )
    SCREEN.print(
        "registrar strings and geolocation are leads, not identity.", style="lj.muted"
    )


def render_brand(data):
    vertical = data.get("vertical") or data.get("category")
    SCREEN.print(
        panel(
            facts(
                [
                    ("name", lit(shown(data.get("name")))),
                    ("slug", lit(shown(data.get("slug")))),
                    ("sector", lit(shown(data.get("sector")))),
                    ("vertical", untrusted(shown(vertical))),
                    ("domain", lit(shown(data.get("domain")))),
                    ("active phishings", lit(shown(data.get("active_phishings")))),
                    ("notes", lit(shown(data.get("notes")))),
                    ("page", lit(shown(data.get("url")))),
                ]
            ),
            "brand",
        )
    )


def render_cert(data):
    SCREEN.print(
        panel(
            facts(
                [
                    ("issuer", lit(shown(data.get("cert")))),
                    ("operator", lit(shown(data.get("operator")))),
                    ("root ca", lit(shown(data.get("root_ca")))),
                    ("since", lit(shown(data.get("since")))),
                    ("key type", lit(shown(data.get("key_type")))),
                    ("use case", lit(shown(data.get("use_case")))),
                    ("related", lit(join_text(data.get("related")))),
                    ("active phishings", lit(shown(data.get("active_phishings")))),
                    ("notes", lit(shown(data.get("notes")))),
                    ("page", lit(shown(data.get("url")))),
                ]
            ),
            "certificate issuer",
        )
    )
    SCREEN.print(
        "a free CA on a phishing site is common and says little by itself.",
        style="lj.muted",
    )


def render_stix(bundle):
    objects = bundle.get("objects") or []
    indicators = [item for item in objects if item.get("type") == "indicator"]
    scores = [
        item["confidence"]
        for item in indicators
        if isinstance(item.get("confidence"), (int, float))
        and not isinstance(item.get("confidence"), bool)
    ]
    spread = (
        f"min {min(scores):g}, median {median(scores):g}, max {max(scores):g}"
        if scores
        else "no confidence values"
    )
    SCREEN.print(
        panel(
            lines_text(
                (
                    f"{len(indicators)} indicators, {len(objects)} bundle objects",
                    f"confidence present on {len(scores)} ({spread})",
                    "published as TLP:CLEAR",
                )
            ),
            "STIX bundle",
        )
    )
    labels = Counter(label for item in indicators for label in item.get("labels") or [])
    SCREEN.print(counter_table("top labels", labels, 12))


def screen_line(line):
    """One raw line for the screen: defanged unless --live."""
    SCREEN.print(Text(line if DISPLAY.live else defang(line)), soft_wrap=True)


def usable_lines(text):
    return [
        line
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "!"))
    ]


def render_feed_text(text, limit):
    lines = text.splitlines()
    SCREEN.print(
        f"{len(lines)} lines, {len(text.encode('utf-8'))} bytes", style="lj.muted"
    )
    for line in lines[:limit]:
        screen_line(line)
    if len(lines) > limit:
        SCREEN.print(f"{len(lines) - limit} more lines", style="lj.muted")


def render_blocklist(kind, text, limit):
    lines = usable_lines(text)
    SCREEN.print(
        panel(
            lines_text(
                (
                    f"{kind}: {len(lines)} usable lines, {len(text.encode('utf-8'))} bytes",
                    "shared hosts such as Blogspot stay listed at the phishing hostname.",
                )
            ),
            "blocklist",
        )
    )
    for line in lines[:limit]:
        screen_line(line)
    SCREEN.print(
        "lists change by the hour; refresh on a timer rather than by hand.",
        style="lj.muted",
    )


ENDPOINT_MAP = (
    (
        "pulse hunt triage pivot report match snapshot diff inspect (unfiltered)",
        "/feed.json",
    ),
    ("pulse hunt triage pivot report (with server filters)", "/api/v1/domains"),
    ("search", "/api/v1/search.json"),
    ("analyze", "/api/v1/analyze"),
    ("deep", "/api/v1/analyze/deep"),
    ("campaigns", "/api/v1/campaigns"),
    ("campaign", "/api/v1/campaigns/KEY and /api/v1/campaigns/KEY/export"),
    ("related", "/api/v1/domains/UUID/related"),
    ("enrich", "/api/v1/enrich/UUID/"),
    ("brand", "/api/v1/brands/SLUG.json"),
    ("cert", "/api/v1/certs/NAME.json"),
    ("feed", "/feed.json /feed.csv /feed.txt /stix/bundle.json"),
    (
        "blocklist",
        "/blocklist/ domains.txt hosts.txt adblock.txt dnsmasq.conf unbound.conf rpz.zone",
    ),
    ("watch", "/api/v1/domains"),
)


def render_about():
    SCREEN.print(
        panel(
            lines_text(
                (
                    "phishunt.io publishes phishing detections as open data (CC0); the open endpoints need no API key.",
                    "pipeline: hourly detections from Certificate Transparency, 6-hour rechecks, a daily new-registration scan.",
                    "sources: Google Safe Browsing, OpenPhish, PhishTank, TweetFeed and urlscan.io; geolocation from ipinfo.io.",
                    "phishunt allows 10 requests per second; this client paces itself to about 8.",
                    "the feed is what phishunt has seen, not a census; scores are heuristics and false positives happen.",
                    "campaign labels describe shared infrastructure, not attribution.",
                    "deep is the one authenticated, active call: it needs a token and makes phishunt fetch the URL.",
                    f"documentation: {DOCS}",
                )
            ),
            f"about {NAME} {VERSION}",
        )
    )
    table = table_of(["command", "GET path"], title="endpoint map")
    for command, path in ENDPOINT_MAP:
        table.add_row(lit(command), lit(path))
    SCREEN.print(table)


# --------------------------------------------------------------------------------------------
# Files: exports, saved text, indicator input
# --------------------------------------------------------------------------------------------


def ensure_newline(text):
    return text if text.endswith("\n") else text + "\n"


def write_file(path, text):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def save_text(path, text):
    write_file(path, text)
    note(f"wrote {path} ({Path(path).stat().st_size:,} bytes)")


def write_csv(target, rows):
    target.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        *CSV_COLUMNS,
        *[
            name
            for name in ("matched_indicator", "match_reason")
            if any(name in row for row in rows)
        ],
    ]
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=columns, extrasaction="ignore", restval=""
        )
        writer.writeheader()
        writer.writerows(rows)


def export_sites(destination, rows):
    """Write rows to a file chosen by extension: .json, .txt (raw url else domain) or CSV (the default)."""
    path = Path(destination)
    kind = path.suffix.lower()
    written = path
    if kind == ".json":
        write_file(path, json.dumps(rows, indent=2, ensure_ascii=False) + "\n")
    elif kind == ".txt":
        write_file(
            path,
            "".join(f"{row.get('url') or row.get('domain') or ''}\n" for row in rows),
        )
    else:
        written = path if kind == ".csv" else path.with_name(path.name + ".csv")
        write_csv(written, rows)
    note(f"wrote {written} ({len(rows)} rows, live indicators)")


def load_indicators(source):
    """Indicators from a file or stdin: one per line, '#' comments, CSV-ish lines keep their first column."""
    try:
        text = (
            sys.stdin.read()
            if source == "-"
            else Path(source).read_text(encoding="utf-8", errors="replace")
        )
    except OSError as problem:
        raise PhishuntError(f"could not read {source}: {problem}") from problem
    found = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "," in line and "://" not in line:
            line = line.split(",", 1)[0].strip().strip("\"'")
        if line:
            found.append(line)
    return found


def read_snapshot(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as problem:
        raise PhishuntError(f"could not read snapshot {path}: {problem}") from problem
    rows = data.get("sites") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise PhishuntError(f"{path} has no sites array")
    return rows


# --------------------------------------------------------------------------------------------
# Matching an indicator list against the feed (entirely local)
# --------------------------------------------------------------------------------------------


class FeedIndex:
    """Feed rows indexed by domain, address and URL, remembering feed order."""

    def __init__(self, rows):
        self.by_domain, self.by_ip, self.by_url = {}, {}, {}
        for position, row in enumerate(rows):
            entry = (position, row)
            for table, key in (
                (self.by_domain, str(row.get("domain") or "").lower().rstrip(".")),
                (self.by_ip, str(row.get("ip") or "").strip()),
                (self.by_url, str(row.get("url") or "").lower()),
            ):
                if key:
                    table.setdefault(key, []).append(entry)

    @staticmethod
    def _rows(entries, unique=False):
        seen, rows = set(), []
        for _position, row in sorted(entries, key=lambda entry: entry[0]):
            key = row.get("uuid")
            if unique and key and key in seen:
                continue
            seen.add(key)
            rows.append(row)
        return rows

    def exact(self, table, key):
        return self._rows(getattr(self, table).get(key, []))

    def children_of(self, host):
        suffix = "." + host
        return self._rows(
            [
                entry
                for domain, entries in self.by_domain.items()
                if domain.endswith(suffix)
                for entry in entries
            ],
            True,
        )

    def parents_of(self, host):
        labels = host.split(".")
        return self._rows(
            [
                entry
                for start in range(1, len(labels))
                for entry in self.by_domain.get(".".join(labels[start:]), [])
            ],
            True,
        )


def match_indicator(index, indicator):
    """(reason, rows) for the first rule that finds feed rows, else None."""
    text = refang(indicator).lower()
    host = host_of(text)
    rules = (
        ("ip", lambda: index.exact("by_ip", host) if looks_like_ipv4(host) else []),
        ("exact-url", lambda: index.exact("by_url", text) if "://" in text else []),
        ("exact-domain", lambda: index.exact("by_domain", host)),
        (
            "subdomain-of-indicator",
            lambda: index.children_of(host) if "." in host else [],
        ),
        ("under-known-phish-host", lambda: index.parents_of(host)),
    )
    for reason, find in rules:
        rows = find()
        if rows:
            return reason, rows
    return None


# --------------------------------------------------------------------------------------------
# The URL-sharing gate (analyze and deep hand a URL to phishunt)
# --------------------------------------------------------------------------------------------


def normalize_url(raw):
    text = refang(raw)
    if not text:
        raise PhishuntError("url is empty", status=400)
    if "://" not in text:
        text = "https://" + text
        note("assuming https://")
    try:
        parts = urlsplit(text)
        scheme, host = parts.scheme, parts.hostname or ""
    except ValueError:
        scheme, host = "", ""
    if scheme not in ("http", "https") or "." not in host:
        raise PhishuntError("url must be http(s) with a dotted hostname", status=400)
    if len(text) > MAX_URL_LENGTH:
        raise PhishuntError(
            f"url is longer than {MAX_URL_LENGTH} characters", status=400
        )
    return text


def share_gate(url, action, assume_yes):
    """Scope, then policy, then confirmation. Raises (status 400) before anything is sent."""
    if not workspace.allowed(url):
        raise PhishuntError(
            workspace.explain_block(urlsplit(url).hostname or url), status=400
        )
    try:
        egress.authorize(url, "active_scan")
    except egress.PolicyBlocked as denial:
        raise PhishuntError(str(denial), status=400) from denial
    if not confirm(
        f"phishunt.io will {action} {url}. Continue?",
        assume_yes=assume_yes,
        stream=sys.stderr if DISPLAY.json else None,
    ):
        raise PhishuntError(
            "not sent. Answer y, or pass --yes when not interactive.", status=400
        )


def checked_uuid(value):
    if not valid_uuid(value):
        raise PhishuntError(
            f"{value!r} is not a valid uuid (expected 8-4-4-4-12 hex)", status=400
        )
    return value


def checked_identifier(value):
    if (
        not isinstance(value, str)
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise PhishuntError(f"{value!r} is not a valid API path identifier", status=400)
    value = value.strip()
    if not value or value in {".", ".."}:
        raise PhishuntError(f"{value!r} is not a valid API path identifier", status=400)
    return value


def new_client(args):
    from bughunt.core import pipeline_context

    client = Client(timeout=args.timeout, verbose=args.verbose)
    client.cache_enabled = not (
        getattr(args, "structured", False) and pipeline_context.current() is not None
    )
    return client


def show_result(payload, render, *, structured=False):
    """Print a server object as JSON in machine mode, otherwise hand it to its view."""
    if structured:
        return payload
    if DISPLAY.json:
        emit_json(payload)
    else:
        render(payload)
    return 0


# --------------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------------


def cmd_about(args):
    if getattr(args, "structured", False):
        return {"name": NAME, "version": VERSION, "docs": DOCS}
    render_about()
    return 0


def cmd_pulse(args):
    rows, label = gather(new_client(args), args)
    summary = summarize(rows)
    if getattr(args, "structured", False):
        return pulse_payload(summary)
    if DISPLAY.json:
        emit_json(pulse_payload(summary))
    elif not rows:
        note("empty slice.")
    else:
        render_pulse(summary, label)
    return 0


def cmd_hunt(args):
    rows, label = gather(new_client(args), args)
    page = rows if (args.all or args.offset) else clip(rows, args.limit, 25)
    if args.export:
        export_sites(args.export, page)
    if getattr(args, "structured", False):
        return page
    if DISPLAY.json:
        emit_json(page)
        return 0
    if args.values:
        for row in page:
            print(shown(row.get("url") or row.get("domain"), True))
    elif page:
        SCREEN.print(
            panel(lines_text((f"{label}", f"{len(page)} shown of {len(rows)}")), "hunt")
        )
        print_sites(page)
        if len(rows) > len(page):
            SCREEN.print(
                f"{len(rows) - len(page)} more not shown - raise --limit or pass --all",
                style="lj.muted",
            )
    else:
        note("nothing matched.")
    return 0


def cmd_search(args):
    if len(args.query.strip()) < 3:
        raise PhishuntError("search needs a query of at least 3 characters", status=400)
    payload = new_client(args).get_json(
        "/api/v1/search.json", {"q": args.query, "limit": args.limit or 50}
    )
    rows = sort_rows(
        apply_client_filters(payload.get("results") or [], args), args.sort
    )
    if args.export:
        export_sites(args.export, rows)
    if getattr(args, "structured", False):
        return rows if (args.verdict or args.min_score or args.min_sources) else payload
    if DISPLAY.json:
        emit_json(
            rows if (args.verdict or args.min_score or args.min_sources) else payload
        )
        return 0
    summary = Text.assemble(
        "query ",
        (args.query, "bold"),
        f" - {shown(payload.get('count'))} reported, {len(rows)} shown",
    )
    SCREEN.print(panel(summary, "search"))
    if rows:
        print_sites(rows)
    else:
        note("nothing matched.")
    return 0


def cmd_analyze(args):
    url = normalize_url(args.url)
    share_gate(url, "receive and log", args.yes)
    return show_result(
        new_client(args).get_json("/api/v1/analyze", {"url": url}),
        render_analyze,
        structured=getattr(args, "structured", False),
    )


def cmd_deep(args):
    token = args.token or os.environ.get("PHISHUNT_DEEP_TOKEN")
    if not token:
        raise PhishuntError(
            "deep needs a token: pass --token or set PHISHUNT_DEEP_TOKEN", status=400
        )
    ledger.remember_secret(token, redact_at_rest=True)
    if not args.yes:
        raise PhishuntError(
            "deep makes phishunt fetch the URL, log it and spend the shared daily budget of 50; pass --yes to go ahead",
            status=400,
        )
    url = normalize_url(args.url)
    share_gate(url, "actively fetch", True)
    caution("deep analysis can take 5-15 seconds")
    data = new_client(args).get_json(
        "/api/v1/analyze/deep",
        {"url": url},
        headers={"X-Phishunt-Deep-Token": token},
        timeout=max(args.timeout, BULK_TIMEOUT),
    )
    return show_result(data, render_deep, structured=getattr(args, "structured", False))


def page_campaigns(client, filters):
    rows, offset, last = [], 0, {}
    while True:
        last = client.get_json(
            "/api/v1/campaigns", {"limit": 200, "offset": offset, **filters}
        )
        batch = last.get("results") or []
        rows += batch
        offset += len(batch)
        total = last.get("total")
        if (
            not batch
            or (isinstance(total, int) and offset >= total)
            or offset > OFFSET_CEILING
        ):
            return {**last, "results": rows, "count": len(rows)}


def cmd_campaigns(args):
    client = new_client(args)
    filters = {
        "brand": (args.brand or "").strip().lower(),
        "status": args.status,
        "min_size": args.min_size,
    }
    if args.all and not args.offset:
        payload = page_campaigns(client, filters)
    else:
        payload = client.get_json(
            "/api/v1/campaigns",
            {"limit": args.limit or 20, "offset": args.offset or 0, **filters},
        )
    return show_result(
        payload, render_campaign_list, structured=getattr(args, "structured", False)
    )


def cmd_campaign(args):
    client = new_client(args)
    path = "/api/v1/campaigns/" + quote(checked_identifier(args.key), safe="")
    if not args.export:
        return show_result(
            client.get_json(path),
            render_campaign,
            structured=getattr(args, "structured", False),
        )
    text, _response = client.get_text(path + "/export", {"format": args.export})
    if getattr(args, "structured", False):
        if args.out:
            save_text(args.out, ensure_newline(text))
        return (
            json.loads(text)
            if args.export == "json"
            else {"text": text, "format": args.export}
        )
    if DISPLAY.json or args.export == "json":
        try:
            data = json.loads(text)
        except ValueError as bad:
            raise PhishuntError("export was not JSON") from bad
        if args.out:
            save_text(args.out, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        show_result(data, render_campaign)
    elif args.out:
        save_text(args.out, ensure_newline(text))
    else:
        emit_raw(text)
    return 0


def cmd_related(args):
    uuid = checked_uuid(args.uuid)
    data = new_client(args).get_json(
        f"/api/v1/domains/{uuid}/related",
        {"limit": args.limit or 10, "min_score": args.min_score or 0},
    )
    return show_result(
        data, render_related, structured=getattr(args, "structured", False)
    )


def cmd_enrich(args):
    uuid = checked_uuid(args.uuid)
    return show_result(
        new_client(args).get_json(f"/api/v1/enrich/{uuid}/"),
        render_enrich,
        structured=getattr(args, "structured", False),
    )


def cmd_brand(args):
    slug = checked_identifier(args.slug).lower()
    return show_result(
        new_client(args).get_json(f"/api/v1/brands/{quote(slug, safe='')}.json"),
        render_brand,
        structured=getattr(args, "structured", False),
    )


def cmd_cert(args):
    name = checked_identifier(args.name)
    return show_result(
        new_client(args).get_json(f"/api/v1/certs/{quote(name, safe='')}.json"),
        render_cert,
        structured=getattr(args, "structured", False),
    )


def cmd_feed(args):
    client = new_client(args)
    path = "/stix/bundle.json" if args.kind == "stix" else f"/feed.{args.kind}"
    if args.kind in ("json", "stix"):
        data = client.get_json(path, timeout=BULK_TIMEOUT)
        if args.out:
            save_text(args.out, json.dumps(data, indent=2, ensure_ascii=False) + "\n")
        if getattr(args, "structured", False):
            return data
        if DISPLAY.json:
            emit_json(data)
        elif args.kind == "json":
            render_pulse(summarize(object_rows(data)), "feed.json")
        else:
            render_stix(data)
        return 0
    text, _response = client.get_text(path, timeout=BULK_TIMEOUT)
    if args.out:
        save_text(args.out, ensure_newline(text))
    if getattr(args, "structured", False):
        return {"text": text, "format": args.kind}
    if DISPLAY.json:
        emit_raw(text)
    else:
        render_feed_text(text, args.limit or 15)
    return 0


def cmd_blocklist(args):
    text, _response = new_client(args).get_text(
        "/blocklist/" + BLOCKLIST_FILES[args.kind], timeout=BULK_TIMEOUT
    )
    if getattr(args, "structured", False):
        if args.out:
            save_text(args.out, ensure_newline(text))
        return {"kind": args.kind, "text": text}
    if args.out:
        save_text(args.out, ensure_newline(text))
    elif args.values or DISPLAY.json:
        emit_raw(text)
    else:
        render_blocklist(args.kind, text, args.limit or 20)
    return 0


def pivot_groups(rows, field, minimum):
    """(value, member rows) buckets of at least `minimum` rows, largest first, plus how many rows lack the field."""
    groups, missing = {}, 0
    for row in rows:
        value = str(row.get(field) or "").strip()
        if value in ("", "-"):
            missing += 1
            continue
        groups.setdefault(
            "AS" + value if field == "asn" and value.isdigit() else value, []
        ).append(row)
    kept = [
        (value, members)
        for value, members in groups.items()
        if len(members) >= (minimum or 2)
    ]
    return sorted(kept, key=lambda pair: len(pair[1]), reverse=True), missing


def tally_field(members, field, limit):
    return [
        list(pair)
        for pair in Counter(
            str(member.get(field) or ABSENT) for member in members
        ).most_common(limit)
    ]


def bucket_payload(value, members):
    return {
        "value": value,
        "count": len(members),
        "brands": tally_field(members, "company", 5),
        "countries": tally_field(members, "country", 3),
        "median_score": median([site_score(member) for member in members]),
        "sample": next(
            (member.get("domain") for member in members if member.get("domain")), ""
        ),
    }


def render_pivot(field, buckets, missing, total, limit):
    SCREEN.print(
        panel(
            lines_text(
                (
                    f"grouped by {field}",
                    f"{len(buckets)} buckets",
                    f"{missing} rows missing the field",
                )
            ),
            "pivot",
        )
    )
    if field == "registrar" and total and missing == total:
        caution(
            "the active feed does not currently ship registrar; `hunt --registrar VALUE` still filters server-side"
        )
    table = table_of(
        ["value", "n", "median", "top brands", "sample"], right=("n", "median")
    )
    for value, members in buckets[:limit]:
        entry = bucket_payload(value, members)
        brands = ", ".join(f"{name} {count}" for name, count in entry["brands"][:3])
        table.add_row(
            lit(shown(value, field == "ip")),
            lit(entry["count"]),
            lit(f"{entry['median_score']:g}"),
            lit(brands),
            lit(shown(entry["sample"], True)),
        )
    SCREEN.print(table)


def cmd_pivot(args):
    rows, _label = gather(new_client(args), args)
    buckets, missing = pivot_groups(rows, args.field, args.min_count)
    if getattr(args, "structured", False):
        return [
            bucket_payload(value, members)
            for value, members in buckets[: args.limit or 30]
        ]
    if DISPLAY.json:
        emit_json(
            [
                bucket_payload(value, members)
                for value, members in buckets[: args.limit or 30]
            ]
        )
    else:
        render_pivot(args.field, buckets, missing, len(rows), args.limit or 25)
    return 0


def cmd_triage(args):
    rows, _label = gather(new_client(args), args)
    page = rows if args.all else clip(rows, args.limit, 20)
    if args.export:
        export_sites(args.export, page)
    if getattr(args, "structured", False):
        return page
    if DISPLAY.json:
        emit_json(page)
        return 0
    if page:
        SCREEN.print(
            panel(
                lines_text(
                    (
                        f"{len(page)} shown of {len(rows)}",
                        f"hottest first, {len(rows)} total",
                    )
                ),
                "triage",
            )
        )
        print_sites(page)
        render_site_card(page[0], "lead row")
    else:
        note("nothing matched.")
    return 0


def capture(call):
    """(result, None) or ({"error": message}, message) when the call raises a PhishuntError."""
    try:
        return call(), None
    except PhishuntError as problem:
        return {"error": str(problem)}, str(problem)


def render_inspection(uuid, active, related, enrich):
    if active:
        render_site_card(active, "detection")
    else:
        domain = related[0].get("domain") if related[0] and not related[1] else None
        named = (
            f" (the related endpoint names it {escape(defang(domain))})"
            if domain
            else ""
        )
        caution(f"{escape(uuid)} is not in the current active feed{named}")
    for label, (payload, problem), view in (
        ("related", related, render_related),
        ("enrich", enrich, render_enrich),
    ):
        if problem:
            caution(f"{label}: {escape(problem)}")
        elif payload is not None:
            view(payload)


def cmd_inspect(args):
    uuid = checked_uuid(args.uuid)
    client = new_client(args)
    rows = object_rows(load_feed(client, args.fresh))
    active = next(
        (row for row in rows if str(row.get("uuid") or "").lower() == uuid.lower()),
        None,
    )
    related, enrich = (None, None), (None, None)
    if not args.skip_related:
        related = capture(
            lambda: client.get_json(
                f"/api/v1/domains/{uuid}/related",
                {"limit": args.limit or 10, "min_score": 0},
            )
        )
    if not args.skip_enrich:
        enrich = capture(lambda: client.get_json(f"/api/v1/enrich/{uuid}/"))
    if getattr(args, "structured", False):
        return {"active": active, "related": related[0], "enrich": enrich[0]}
    if DISPLAY.json:
        emit_json({"active": active, "related": related[0], "enrich": enrich[0]})
    else:
        render_inspection(uuid, active, related, enrich)
    return 0


def match_payload(indicators, hits, misses, show_misses):
    return {
        "indicators": len(indicators),
        "hit_indicators": len(hits),
        "miss_indicators": len(misses),
        "hits": [
            {
                "indicator": item,
                "reason": reason,
                "uuids": [row.get("uuid") for row in rows],
                "domains": [row.get("domain") for row in rows],
            }
            for item, (reason, rows) in hits
        ],
        "misses": misses if show_misses else [],
    }


def matched_rows(hits):
    """One export row per matched detection, tagged with the indicator and rule that found it first."""
    seen, tagged = set(), []
    for item, (reason, rows) in hits:
        for row in rows:
            key = row.get("uuid") or id(row)
            if key not in seen:
                seen.add(key)
                tagged.append(
                    {**row, "matched_indicator": item, "match_reason": reason}
                )
    return tagged


def render_matches(indicators, total, hits, misses, show_misses):
    SCREEN.print(
        panel(
            lines_text(
                (
                    f"{len(indicators)} indicators checked against {total} active detections",
                    f"{len(hits)} hit, {len(misses)} miss",
                )
            ),
            "match",
        )
    )
    if hits:
        table = table_of(
            ["indicator", "reason", "brand", "domain", "score"], right=("score",)
        )
        for item, (reason, rows) in hits:
            lead = rows[0]
            more = f" +{len(rows) - 1}" if len(rows) > 1 else ""
            table.add_row(
                lit(shown(item, True)),
                lit(reason),
                lit(shown(lead.get("company"))),
                lit(shown(lead.get("domain"), True) + more),
                score_cell(site_score(lead)),
            )
        SCREEN.print(table)
    if show_misses and misses:
        SCREEN.print(
            lines_text(["no match:", *[f"  {shown(item, True)}" for item in misses]])
        )


def cmd_match(args):
    indicators = load_indicators(args.file)
    feed = object_rows(load_feed(new_client(args), args.fresh))
    index = FeedIndex(feed)
    verdicts = [(item, match_indicator(index, item)) for item in indicators]
    hits = [(item, found) for item, found in verdicts if found]
    misses = [item for item, found in verdicts if not found]
    status = 1 if (args.fail_on_hit and hits) else 0
    if args.export:
        export_sites(args.export, matched_rows(hits))
    if getattr(args, "structured", False):
        return match_payload(indicators, hits, misses, args.show_misses)
    if DISPLAY.json:
        emit_json(match_payload(indicators, hits, misses, args.show_misses))
        return status
    render_matches(indicators, len(feed), hits, misses, args.show_misses)
    return status


def poll_new(client, args, cursor, seen):
    """One watch poll: (new rows newest first, newest stamp seen)."""
    page = client.get_json(
        "/api/v1/domains",
        {
            "since": cursor,
            "limit": PAGE_ROWS,
            "company": (args.company or "").strip().lower(),
            "country": args.country,
            "tier": args.tier,
        },
    )
    stamps, fresh = [], []
    for row in page.get("results") or []:
        stamps.append(str(row.get("date") or row.get("first_seen") or ""))
        key = row.get("uuid")
        if key and key in seen:
            continue
        if row.get("first_seen") and stamp_key(row["first_seen"]) < stamp_key(cursor):
            continue
        if key:
            seen.add(key)
        fresh.append(row)
    return sort_rows(apply_client_filters(fresh, args), "first_seen"), max(
        stamps, default=""
    )


def report_poll(args, cursor, fresh):
    if getattr(args, "structured", False):
        pass
    elif DISPLAY.json:
        if fresh:
            emit_json({"since": cursor, "count": len(fresh), "results": fresh})
    elif fresh:
        SCREEN.print(f"{len(fresh)} new  {tiny_time(now_iso())}", style="lj.head")
        print_sites(clip(fresh, args.limit, 50))
    else:
        note(f"quiet: nothing new since {cursor}")
    if args.log and fresh:
        Path(args.log).parent.mkdir(parents=True, exist_ok=True)
        with open(args.log, "a", encoding="utf-8", newline="\n") as handle:
            handle.writelines(
                json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n"
                for row in fresh
            )


def cmd_watch(args):
    from bughunt.core.addon_adapters import wait_for_poll

    remaining = getattr(args, "polls", None)
    if remaining is not None and remaining < 1:
        raise PhishuntError("--polls must be positive", status=400)
    client = new_client(args)
    cursor = args.since or now_iso()
    pause = max(30, args.interval or 300)
    if getattr(args, "structured", False):
        polls, seen = [], set()
        for index in range(args.polls):
            fresh, newest = poll_new(client, args, cursor, seen)
            report_poll(args, cursor, fresh)
            polls.append({"since": cursor, "results": fresh})
            cursor = max(cursor, newest)
            if index + 1 < args.polls:
                wait_for_poll(pause)
        return polls
    SCREEN.print(
        panel(
            lines_text(
                (
                    f"polling new detections since {cursor} every {pause} s",
                    "Ctrl-C stops",
                )
            ),
            "watch",
        )
    )
    seen = set()
    while True:
        fresh, newest = poll_new(client, args, cursor, seen)
        report_poll(args, cursor, fresh)
        if remaining is not None:
            remaining -= 1
        if args.once or remaining == 0:
            return 0
        if newest > cursor:
            cursor = newest
        time.sleep(pause)


def cmd_snapshot(args):
    rows = load_feed(new_client(args), args.fresh)
    saved = now_iso()
    path = (
        args.out
        or f"lanternjaw-snapshot-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.json"
    )
    envelope = {
        "tool": NAME,
        "version": VERSION,
        "saved_at": saved,
        "count": len(rows),
        "sites": rows,
    }
    save_text(
        path, json.dumps(envelope, ensure_ascii=False, separators=(",", ":")) + "\n"
    )
    if getattr(args, "structured", False):
        return {"saved": True, "count": len(rows), "saved_at": saved}
    if DISPLAY.json:
        emit_json({"path": path, "count": len(rows), "saved_at": saved})
    return 0


def keyed_by_uuid(rows):
    return {row["uuid"]: row for row in rows if row.get("uuid")}


def cmd_diff(args):
    server_params(args)
    earlier = object_rows(read_snapshot(args.snapshot))
    current = object_rows(load_feed(new_client(args), True))
    before = keyed_by_uuid(
        sort_rows(narrow_rows(earlier, args, "snapshot"), "first_seen")
    )
    now = keyed_by_uuid(
        sort_rows(narrow_rows(current, args, "live feed"), "first_seen")
    )
    added = [row for key, row in now.items() if key not in before]
    gone = [row for key, row in before.items() if key not in now]
    if args.export:
        export_sites(args.export, added)
    if getattr(args, "structured", False):
        return {
            "before": len(before),
            "now": len(now),
            "added": len(added),
            "gone": len(gone),
            "added_rows": added,
            "gone_rows": gone,
        }
    if DISPLAY.json:
        emit_json(
            {
                "before": len(before),
                "now": len(now),
                "added": len(added),
                "gone": len(gone),
                "added_rows": added,
                "gone_rows": gone,
            }
        )
        return 0
    SCREEN.print(
        panel(
            lines_text(
                (
                    f"snapshot {len(before)} -> now {len(now)}",
                    f"+{len(added)} new uuids",
                    f"-{len(gone)} no longer in this slice",
                )
            ),
            "diff",
        )
    )
    for title, rows in (("added", added), ("gone", gone)):
        if rows:
            print_sites(clip(rows, args.limit, 20), title)
    return 0


def md_cell(value):
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def md_table(headers, body):
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines += [
        "| " + " | ".join(md_cell(cell) for cell in cells) + " |" for cells in body
    ]
    return lines


def md_ranked(counter, limit):
    return (
        ", ".join(f"{name} ({count})" for name, count in counter.most_common(limit))
        or ABSENT
    )


def brief_tables(top, newest):
    sources = lambda row: "".join(
        g if hit else "-" for g, hit in zip(SOURCE_GLYPHS, source_flags(row))
    )  # noqa: E731
    hottest = [
        [
            site_score(row),
            verdict_of(row),
            shown(row.get("company")),
            shown(row.get("domain"), True),
            shown(row.get("ip"), True),
            sources(row),
        ]
        for row in top
    ]
    recent = [
        [
            short_time(row.get("first_seen")),
            shown(row.get("company")),
            shown(row.get("domain"), True),
            site_score(row),
        ]
        for row in newest
    ]
    return [
        "",
        "## Hottest",
        "",
        *md_table(["score", "verdict", "brand", "domain", "ip", "sources"], hottest),
        "",
        "## Newest",
        "",
        *md_table(["first seen", "brand", "domain", "score"], recent),
    ]


def brief_lines(rows, label, limit):
    summary = summarize(rows)
    top = clip(sort_rows(rows, "score"), limit, 15)
    newest = clip(sort_rows(rows, "first_seen"), limit, 15)
    lines = [
        f"# {NAME} brief",
        "",
        f"Generated {now_iso()} by {NAME} {VERSION}.",
        f"Source slice: {label}.",
        "",
        "Data is best-effort and published by phishunt.io under CC0. False positives happen and scores are heuristics, "
        "not verdicts. A source flag that reads false means that source had not flagged the URL when last checked; it "
        "does not mean the URL is clean. Campaign language describes shared infrastructure, not attribution.",
        "",
        "## Snapshot",
        "",
        f"- Rows: {summary['count']}",
        f"- Median score: {summary['median_score']}",
        f"- First seen: {summary['first'] or ABSENT}",
        f"- Newest first-seen: {summary['last'] or ABSENT}",
        f"- Latest recheck: {summary['checked'] or ABSENT}",
        f"- Noise-tier but feed-flagged: {summary['noise_flagged']}",
        f"- Punycode hosts: {summary['punycode']}",
        f"- Shared-platform suffixes: {summary['paas_suffix']}",
        f"- Credential-ish paths: {summary['credential_path']}",
        "",
        "## Verdicts",
        "",
        *[f"- {name}: {count}" for name, count in summary["verdicts"].most_common()],
        "",
        "## Targeted brands",
        "",
        *[f"- {name}: {count}" for name, count in summary["brands"].most_common(15)],
        "",
        "## Hosting",
        "",
        f"Countries: {md_ranked(summary['countries'], 8)}",
        f"Networks: {md_ranked(summary['networks'], 8)}",
        f"Issuers: {md_ranked(summary['certs'], 6)}",
        *brief_tables(top, newest),
        "",
        "## Defanged indicators (hottest)",
        "",
        "```",
        *[defang(str(r.get("url") or r.get("domain") or ABSENT)) for r in top],
        "```",
        "",
        f"Upstream docs: {DOCS}",
    ]
    return lines


def cmd_report(args):
    rows, label = gather(new_client(args), args)
    markdown = "\n".join(brief_lines(rows, label, args.limit)) + "\n"
    if getattr(args, "structured", False):
        if args.out:
            save_text(args.out, markdown)
        return {"media_type": "text/markdown", "text": markdown}
    if args.out:
        save_text(args.out, markdown)
    else:
        print(markdown, end="")
    return 0


# --------------------------------------------------------------------------------------------
# self-test: a few offline checks of the rules everything else leans on
# --------------------------------------------------------------------------------------------


def expect(condition, message):
    if not condition:
        raise AssertionError(f"self-test failed: {message}")


def selftest_text_rules():
    expect(
        defang("https://evil.example/a") == "hxxps://evil[.]example/a", "defang a url"
    )
    expect(
        defang(defang("http://a.b")) == "hxxp://a[.]b",
        "defang twice is the same as once",
    )
    expect(refang("hxxps://evil[.]example/a") == "https://evil.example/a", "refang")
    expect(host_of("hxxps://Login.Example.com/path") == "login.example.com", "host_of")
    expect(
        stamp_key("2026-10-12T00:00:00Z") == stamp_key("2026-10-12T00:00:00+00:00"),
        "Z and +00:00 compare equal",
    )


def selftest_score_rules():
    expect(all(flag(item) for item in ("1", True, 1)), "truthy flags")
    expect(not any(flag(item) for item in ("0", False, 0, None)), "falsy flags")
    sample = {
        "malicious_google": False,
        "malicious_openphish": "1",
        "malicious_phishtank": 0,
        "malicious_tweetfeed": False,
        "malicious_urlscan": True,
        "score": "40",
    }
    expect(
        source_count(sample) == 2 and site_score(sample) == 40,
        "source_count and site_score",
    )
    expect(median([1, 9, 3]) == 3, "median of three")


def selftest_match_rules():
    rows = [
        {"uuid": "a", "domain": "paypal-login1.example.net", "ip": "203.0.113.2"},
        {
            "uuid": "b",
            "domain": "x.pages.dev",
            "url": "https://x.pages.dev/verify/login",
        },
        {"uuid": "c", "domain": "other.example.net"},
        {"uuid": "d", "domain": "third.example.net"},
        {"uuid": "e", "domain": "sub.a.com"},
    ]
    index = FeedIndex(rows)
    vectors = (
        ("paypal-login1[.]example[.]net", "exact-domain"),
        ("203.0.113.2", "ip"),
        ("https://x.pages.dev/verify/login", "exact-url"),
        ("sub.paypal-login1.example.net", "under-known-phish-host"),
        ("example.net", "subdomain-of-indicator"),
        ("a.com", "subdomain-of-indicator"),
        ("com", None),
        ("www.safe.example", None),
    )
    for indicator, reason in vectors:
        found = match_indicator(index, indicator)
        expect((found[0] if found else None) == reason, f"match rule for {indicator}")
    expect(
        len(match_indicator(index, "example.net")[1]) == 3,
        "example.net matches three rows",
    )


def selftest_narrowing():
    args = SimpleNamespace(
        company="PayPal",
        since="2026-09-01",
        contains=None,
        tier=None,
        asn=None,
        org=None,
        registrar=None,
        cert=None,
        country=None,
        ip=None,
        verdict=None,
        min_score=None,
        min_sources=None,
    )
    rows = [
        {"company": "paypal", "first_seen": "2026-09-02T00:00:00Z"},
        {"company": "ebay", "first_seen": "2026-09-02T00:00:00Z"},
        {"company": "paypal", "first_seen": "2026-08-01T00:00:00Z"},
    ]
    kept = narrow_rows(rows, args, "self-test")
    expect(
        len(kept) == 1 and kept[0]["company"] == "paypal", "company and since narrowing"
    )


def cmd_self_test(args):
    for check in (
        selftest_text_rules,
        selftest_score_rules,
        selftest_match_rules,
        selftest_narrowing,
    ):
        check()
    if getattr(args, "structured", False):
        return {"checks": ["text", "score", "match", "narrowing"], "passed": True}
    print("lanternjaw self-test ok")
    return 0


# --------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------


def flag_opt(*names, about):
    return names, {"action": "store_true", "help": about}


def text_opt(*names, about, **extra):
    return names, {"help": about, **extra}


def int_opt(*names, about, default=None):
    return names, {"type": int, "default": default, "help": about}


def positional(name, about, **extra):
    return (name,), {"help": about, **extra}


JSON_OUT = flag_opt("--json", about="print the machine payload as JSON on stdout")
SERVER_OPTS = (
    text_opt("--company", about="brand slug, e.g. paypal"),
    text_opt("--since", about="only detections newer than this ISO time"),
    text_opt("--contains", about="substring of the URL or domain (3-80 characters)"),
    text_opt("--tier", about="confidence tier", choices=("all", "verified")),
    text_opt("--asn", about="autonomous system number (AS prefix optional)"),
    text_opt("--org", about="hosting organization"),
    text_opt("--registrar", about="domain registrar"),
    text_opt("--cert", about="TLS certificate issuer"),
    text_opt("--country", about="hosting country"),
    text_opt("--ip", about="hosting address"),
)
CLIENT_OPTS = (
    text_opt("--verdict", about="keep one verdict tier", choices=VERDICT_CHOICES),
    int_opt("--min-score", about="drop detections scoring below N"),
    int_opt("--min-sources", about="drop detections flagged by fewer than N sources"),
)
SORT_OPT = text_opt(
    "--sort", about="row order", choices=SORT_CHOICES, default="first_seen"
)
EXPORT_OPT = text_opt(
    "--export", about="write the rows to FILE (.json, .txt, otherwise CSV)"
)
UUID_ARG = "detection uuid (8-4-4-4-12 hex)"

#: (name, help, options, hidden defaults). The order here is the order the subcommands are registered.
COMMAND_TABLE = (
    ("about", "what phishunt.io is and which endpoints this tool uses", (), {}),
    (
        "pulse",
        "dashboard for the current slice of the feed",
        (JSON_OUT, *SERVER_OPTS, *CLIENT_OPTS),
        {"sort": "first_seen", "all": True, "offset": None},
    ),
    (
        "hunt",
        "list detections",
        (
            JSON_OUT,
            *SERVER_OPTS,
            *CLIENT_OPTS,
            int_opt("--limit", about="rows to show", default=25),
            int_opt(
                "--offset",
                about="fetch one raw API page at this offset (needs a server filter)",
            ),
            flag_opt("--all", about="show every row"),
            SORT_OPT,
            flag_opt("--values", about="print one url or domain per row on stdout"),
            EXPORT_OPT,
        ),
        {},
    ),
    (
        "search",
        "full-text search of detections",
        (
            JSON_OUT,
            positional("query", "text to search for (3+ characters)"),
            int_opt("--limit", about="rows to request", default=50),
            *CLIENT_OPTS,
            SORT_OPT,
            EXPORT_OPT,
        ),
        {},
    ),
    (
        "analyze",
        "have phishunt score a URL without fetching it (scope-gated)",
        (
            JSON_OUT,
            positional("url", "URL to submit"),
            flag_opt("--yes", about="skip the confirmation prompt"),
        ),
        {},
    ),
    (
        "deep",
        "have phishunt fetch and analyze a URL (active, needs a token)",
        (
            JSON_OUT,
            positional("url", "URL to submit"),
            text_opt(
                "--token", about="deep-analysis token (or set PHISHUNT_DEEP_TOKEN)"
            ),
            flag_opt("--yes", about="confirm that phishunt will contact the URL"),
        ),
        {},
    ),
    (
        "campaigns",
        "list clusters of detections that share infrastructure",
        (
            JSON_OUT,
            text_opt("--brand", about="only clusters that target this brand"),
            text_opt(
                "--status",
                about="cluster status",
                choices=("active", "all"),
                default="all",
            ),
            int_opt("--min-size", about="smallest cluster size", default=0),
            int_opt("--limit", about="clusters per page", default=20),
            int_opt("--offset", about="page offset", default=0),
            flag_opt("--all", about="page through every cluster"),
        ),
        {},
    ),
    (
        "campaign",
        "show one cluster",
        (
            JSON_OUT,
            positional("key", "cluster key"),
            text_opt(
                "--export",
                about="download the cluster as json, csv or txt",
                choices=("json", "csv", "txt"),
            ),
            text_opt("--out", about="save the export to FILE"),
        ),
        {},
    ),
    (
        "related",
        "detections that share infrastructure with one detection",
        (
            JSON_OUT,
            positional("uuid", UUID_ARG),
            int_opt("--limit", about="results to request", default=10),
            int_opt("--min-score", about="minimum relationship score", default=0),
        ),
        {},
    ),
    (
        "enrich",
        "registration and geolocation lookups for one detection",
        (JSON_OUT, positional("uuid", UUID_ARG)),
        {},
    ),
    (
        "brand",
        "show what phishunt knows about a brand",
        (JSON_OUT, positional("slug", "brand slug")),
        {},
    ),
    (
        "cert",
        "show what phishunt knows about a certificate issuer",
        (JSON_OUT, positional("name", "issuer name")),
        {},
    ),
    (
        "feed",
        "download a feed file",
        (
            JSON_OUT,
            positional("kind", "feed format", choices=FEED_KINDS),
            text_opt("--out", about="save the download to FILE"),
            int_opt("--limit", about="preview lines for csv and txt", default=15),
        ),
        {},
    ),
    (
        "blocklist",
        "download a ready-made blocklist",
        (
            JSON_OUT,
            positional("kind", "list format", choices=tuple(BLOCKLIST_FILES)),
            text_opt("--out", about="save the list to FILE"),
            flag_opt("--values", about="print the raw list on stdout"),
            int_opt("--limit", about="preview lines", default=20),
        ),
        {},
    ),
    (
        "pivot",
        "group the slice by one infrastructure field",
        (
            JSON_OUT,
            positional("field", "field to group by", choices=PIVOT_FIELDS),
            *SERVER_OPTS,
            *CLIENT_OPTS,
            int_opt("--min-count", about="smallest group to keep", default=2),
            int_opt("--limit", about="groups to show", default=25),
        ),
        {"sort": "first_seen", "all": True, "offset": None},
    ),
    (
        "triage",
        "highest-scoring detections with a detail card for the top one",
        (
            JSON_OUT,
            *SERVER_OPTS,
            *CLIENT_OPTS,
            int_opt("--limit", about="rows to show", default=20),
            flag_opt("--all", about="show every row"),
            EXPORT_OPT,
        ),
        {"sort": "score"},
    ),
    (
        "inspect",
        "everything known about one detection",
        (
            JSON_OUT,
            positional("uuid", UUID_ARG),
            int_opt("--limit", about="related results", default=10),
            flag_opt("--skip-related", about="do not ask for related detections"),
            flag_opt("--skip-enrich", about="do not ask for registration data"),
        ),
        {},
    ),
    (
        "match",
        "check a local indicator list against the feed (nothing is uploaded)",
        (
            JSON_OUT,
            positional("file", "indicator file, or - for stdin"),
            flag_opt("--show-misses", about="list indicators with no match"),
            flag_opt("--fail-on-hit", about="exit 1 when any indicator matches"),
            EXPORT_OPT,
        ),
        {},
    ),
    (
        "watch",
        "poll for new detections",
        (
            JSON_OUT,
            text_opt("--since", about="start from this ISO time (default: now)"),
            int_opt(
                "--polls",
                about="finite number of polls (required for embedding unless --once)",
            ),
            int_opt(
                "--interval", about="seconds between polls (minimum 30)", default=300
            ),
            text_opt("--company", about="brand slug"),
            text_opt("--country", about="hosting country"),
            text_opt("--tier", about="confidence tier", choices=("all", "verified")),
            *CLIENT_OPTS,
            int_opt("--limit", about="rows to show per poll", default=50),
            flag_opt("--once", about="poll once and exit"),
            text_opt("--log", about="append new rows to FILE as JSON lines"),
        ),
        {},
    ),
    (
        "snapshot",
        "save the active feed to a file",
        (JSON_OUT, text_opt("--out", about="snapshot file name")),
        {},
    ),
    (
        "diff",
        "compare a snapshot with the live feed",
        (
            JSON_OUT,
            positional("snapshot", "snapshot file"),
            *SERVER_OPTS,
            *CLIENT_OPTS,
            int_opt("--limit", about="rows to show per side", default=20),
            EXPORT_OPT,
        ),
        {"sort": "first_seen", "all": True, "offset": None},
    ),
    (
        "report",
        "write a Markdown brief",
        (
            JSON_OUT,
            *SERVER_OPTS,
            *CLIENT_OPTS,
            int_opt("--limit", about="table rows", default=15),
            text_opt("--out", about="write the brief to FILE"),
        ),
        {"sort": "first_seen", "all": True, "offset": None},
    ),
    ("self-test", "run offline sanity checks", (), {}),
)

EPILOG = """\
examples (global flags such as --fresh and --live go before or after the subcommand):
  lanternjaw.py pulse
  lanternjaw.py --fresh hunt --company paypal --limit 10
  lanternjaw.py pivot asn --min-count 3
  lanternjaw.py match indicators.txt --fail-on-hit
  lanternjaw.py analyze https://suspect.example/login --yes

notes:
  screen output goes to stderr and is defanged unless --live is given.
  --json prints the machine payload on stdout; tables stay on stderr.
"""


def show_banner():
    SCREEN.print(BANNER.format(version=VERSION), style="lj.head", markup=False)


class QuietAwareParser(argparse.ArgumentParser):
    """Prints the banner before help text unless quiet was requested."""

    def parse_known_args(self, args=None, namespace=None):
        arguments = list(sys.argv[1:] if args is None else args)
        self.quiet_help = getattr(self, "parent_quiet_help", False) or bool(
            {"-q", "--quiet"} & set(arguments)
        )
        for action in self._actions:
            if isinstance(action, argparse._SubParsersAction):
                for child in action.choices.values():
                    child.parent_quiet_help = self.quiet_help
        return super().parse_known_args(arguments, namespace)

    def print_help(self, file=None):
        if not getattr(self, "quiet_help", False):
            show_banner()
        super().print_help(file)


def add_globals(parser, suppress_defaults=False):
    defaults = {"default": argparse.SUPPRESS} if suppress_defaults else {}
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="do not print the banner", **defaults
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print each HTTP response status and URL on stderr",
        **defaults,
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="show raw indicators on screen instead of defanged text",
        **defaults,
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="ignore the 10-minute active-feed cache (it is still rewritten)",
        **defaults,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=argparse.SUPPRESS if suppress_defaults else 45.0,
        help="HTTP timeout in seconds",
    )


def build_parser():
    parser = QuietAwareParser(
        prog="lanternjaw.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=EPILOG,
        description="Passive threat intel from the public phishunt.io feed: browse, pivot, match and monitor phishing detections.",
    )
    add_globals(parser)
    commands = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")
    for name, about, options, defaults in COMMAND_TABLE:
        sub = commands.add_parser(name, help=about, description=about)
        add_globals(sub, suppress_defaults=True)
        for names, spec in options:
            sub.add_argument(*names, **spec)
        sub.set_defaults(**defaults)
    return parser


HANDLERS = {
    "about": cmd_about,
    "pulse": cmd_pulse,
    "hunt": cmd_hunt,
    "search": cmd_search,
    "analyze": cmd_analyze,
    "deep": cmd_deep,
    "campaigns": cmd_campaigns,
    "campaign": cmd_campaign,
    "related": cmd_related,
    "enrich": cmd_enrich,
    "brand": cmd_brand,
    "cert": cmd_cert,
    "feed": cmd_feed,
    "blocklist": cmd_blocklist,
    "pivot": cmd_pivot,
    "triage": cmd_triage,
    "inspect": cmd_inspect,
    "match": cmd_match,
    "watch": cmd_watch,
    "snapshot": cmd_snapshot,
    "diff": cmd_diff,
    "report": cmd_report,
    "self-test": cmd_self_test,
}


def validate_structured(args):
    import math
    from bughunt.core.addon_adapters import validate_watch

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError("Timeout must be finite and positive")
    parameters = server_params(args)
    if getattr(args, "offset", None) and not parameters and args.command != "campaigns":
        raise ValueError("Offset requires a server filter")
    if getattr(args, "limit", 0) is not None and getattr(args, "limit", 0) < 0:
        raise ValueError("Limit cannot be negative")
    if hasattr(args, "uuid"):
        checked_uuid(args.uuid)
    for name in ("key", "slug", "name"):
        if hasattr(args, name):
            checked_identifier(getattr(args, name))
    if args.command in {"analyze", "deep"}:
        normalize_url(args.url)
        if not args.yes:
            raise ValueError("Embedding disclosure requires --yes")
        share_gate(normalize_url(args.url), "receive and log", True)
    if args.command == "search" and len(args.query.strip()) < 3:
        raise ValueError("Search requires at least three characters")
    if args.command == "match":
        if args.file == "-":
            raise ValueError("Embedding requires an indicator file")
        load_indicators(args.file)
    if args.command == "diff":
        read_snapshot(args.snapshot)
    if args.command == "watch":
        args.polls = 1 if args.once else args.polls
        validate_watch(args.polls, max(30, args.interval or 300))


def run_structured(args, *, dry_run=False):
    from bughunt.core.addon_adapters import document, effect, external, planned

    validate_structured(args)
    if dry_run:
        return planned("phish", args.command)
    args.structured, args.verbose = True, False
    data = HANDLERS[args.command](args)
    status = "success"
    if args.command == "inspect" and any(
        isinstance(data.get(key), dict) and "error" in data[key]
        for key in ("related", "enrich")
    ):
        status = "partial"
    output = external("phish", args.command, data, status=status)
    if (
        isinstance(data, dict)
        and "text" in data
        and args.command in {"report", "feed", "blocklist", "campaign"}
    ):
        document(output, data["text"], data.get("media_type", "text/plain"))
    if (
        args.command == "snapshot"
        or getattr(args, "out", None)
        or getattr(args, "export", None)
        and args.command != "campaign"
    ):
        effect(output, "phish-export", "write")
    return output


def report_failure(problem):
    SCREEN.print(Text(f"error: {problem}", style="lj.bad"), soft_wrap=True)
    if DISPLAY.json:
        print(
            json.dumps(
                {"error": str(problem), "status": problem.status}, ensure_ascii=False
            ),
            file=sys.stderr,
        )


@contextmanager
def legacy_output():
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


@legacy_output()
def main(argv=None):
    args = build_parser().parse_args(argv)
    DISPLAY.json = bool(getattr(args, "json", False))
    DISPLAY.live = bool(args.live)
    if not (args.quiet or DISPLAY.json or args.command == "self-test"):
        show_banner()
    try:
        return HANDLERS[args.command](args)
    except PhishuntError as problem:
        report_failure(problem)
        return 2 if problem.status in (400, 404) else 1
    except KeyboardInterrupt:
        SCREEN.print("stopped (Ctrl-C)", style="lj.warn")
        return 130


if __name__ == "__main__":
    sys.exit(main())
