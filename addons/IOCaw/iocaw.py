#!/usr/bin/env python3
"""IOCaw - a terminal reader for the public TweetFeed.live indicator feed.

TweetFeed republishes indicators of compromise (URLs, domains, IP addresses, MD5 and
SHA-256 hashes) that researchers post on X/Twitter, as CC0 data with no API key.
IOCaw only READS that feed. It does not extract indicators from text and it never
visits, resolves or verifies anything it lists.

Network posture: every request is a GET made through the shared guarded client from
``bughunt.core.http`` - policy-gated under the ``passive`` operation, host
allow-listed, no environment proxies, no automatic redirects. The only hosts involved
are ``api.tweetfeed.live`` and (for the ``feed year`` CSV redirect)
``raw.githubusercontent.com``. The command is not scope-gated: the "target" is the
public feed, not an engagement host.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import time
import zlib
from collections import Counter
from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

try:
    from bughunt.core import egress
    from bughunt.core.http import api_client, get_following
except ModuleNotFoundError:  # launched as a loose script from outside the repository
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from bughunt.core import egress
    from bughunt.core.http import api_client, get_following

NAME = "IOCaw"
VERSION = "1.0.0"
BASE = "https://api.tweetfeed.live"
DOCS = "https://tweetfeed.live/api/"
USER_AGENT = f"{NAME}/{VERSION} (+https://tweetfeed.live; research CLI)"
ACCEPT_HEADER = "application/json, text/csv, text/plain;q=0.8, */*;q=0.5"
TIMEOUT = 30
API_HOSTS = frozenset({"api.tweetfeed.live", "raw.githubusercontent.com"})

WINDOWS = ("today", "week", "month", "year")
IOC_TYPES = ("url", "domain", "ip", "sha256", "md5")
BLOCKLIST_KINDS = (
    "domains",
    "ips",
    "urls",
    "sha256",
    "md5",
    "hosts",
    "adguard",
    "rpz",
    "dnsmasq",
    "nrd-domains",
)
EXPORT_COLUMNS = ("date", "user", "type", "value", "tags", "tweet")
ARTIFACT_ORDER = tuple(f"{window}.csv" for window in WINDOWS) + tuple(
    f"{stem}.json" for stem in ("campaigns", "counts", "trends")
)
ARTIFACT_ROW_CAP = 20

DASH = "—"
SPARK_BLOCKS = "".join(chr(code) for code in range(0x2581, 0x2589))
TYPE_COLORS = {
    "url": "bright_blue",
    "domain": "magenta",
    "ip": "yellow",
    "sha256": "green",
    "md5": "cyan",
}
TAG_PALETTE = (
    "cyan",
    "magenta",
    "green",
    "yellow",
    "blue",
    "red",
    "bright_cyan",
    "bright_magenta",
)
CONFIDENCE_COLORS = {"high": "green", "medium": "yellow", "low": "dim"}

BANNER_LINES = (
    r"      .   *   .",
    r"    ( (   o   ) )      I O C a w",
    r"      '   *   '        indicator feed, read-only",
)
YEAR_NOTICE = (
    "[dim]year window: the feed serves one unfiltered CSV, so --type, --tag and --user "
    "are applied client-side after the download[/dim]"
)

console = Console()


class TweetFeedError(RuntimeError):
    """Anything that stops a TweetFeed read: policy, transport, HTTP status or payload shape."""


# --------------------------------------------------------------------------------------
# HTTP seam
# --------------------------------------------------------------------------------------


def _session() -> httpx.Client:
    """Guarded client: passive egress, listed hosts only, no env proxies, manual redirects."""
    return api_client(
        API_HOSTS,
        timeout=TIMEOUT,
        headers={"Accept": ACCEPT_HEADER, "User-Agent": USER_AGENT},
    )


SESSION = None


def _check_status(response: httpx.Response) -> None:
    code = response.status_code
    if code < 400:
        return
    where = str(response.url)
    if code == 410:
        raise TweetFeedError(
            "gone: TweetFeed only keeps 365 days of history and that record is older"
        )
    if code == 404:
        raise TweetFeedError(f"not found: {where}")
    if code == 403:
        raise TweetFeedError(
            "403 from TweetFeed: Cloudflare refused the request (a custom User-Agent is already sent), retry shortly"
        )
    snippet = " ".join(response.text[:240].splitlines())
    raise TweetFeedError(f"HTTP {code} from {where}: {snippet}")


def _read_payload(response: httpx.Response):
    body = response.text
    declared_json = "json" in response.headers.get("content-type", "").lower()
    if not (declared_json or body[:1] in ("[", "{", "")):
        return body
    try:
        return json.loads(body)
    except ValueError as reason:
        raise TweetFeedError(f"invalid JSON from {response.url}: {reason}") from reason


def api_get(path, params=None, *, allow_redirects=True, expect_json=True):
    """GET `path` (must start with '/') from the TweetFeed API. Returns (payload, response)."""
    if not path.startswith("/"):
        raise TweetFeedError(f"API paths must begin with a slash, got {path!r}")
    url = BASE + path
    try:
        with _session() if SESSION is None else nullcontext(SESSION) as session:
            if allow_redirects:
                response = get_following(session, url, params=params)
            else:
                response = session.get(url, params=params)
    except httpx.HTTPError as failure:
        raise TweetFeedError(
            f"network error talking to TweetFeed: {failure}"
        ) from failure
    _check_status(response)
    if not expect_json:
        return response.text, response
    return _read_payload(response), response


def _object_response(path, params=None):
    payload, response = api_get(path, params)
    if not isinstance(payload, dict):
        raise TweetFeedError(
            f"expected a JSON object from {path}, got {type(payload).__name__}"
        )
    return payload, response


# --------------------------------------------------------------------------------------
# Small data helpers
# --------------------------------------------------------------------------------------


def _field(row: dict, key: str) -> str:
    value = row.get(key)
    return "" if value is None else str(value)


def _row_tags(row: dict) -> list[str]:
    raw = row.get("tags") or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(tag) for tag in raw if tag]


def _hashtag(tag: str) -> str:
    return tag if tag.startswith("#") else f"#{tag}"


def _or_dash(value) -> str:
    return DASH if value is None or value == "" else escape(str(value))


def _clip(items: list, limit: int) -> list:
    return items[:limit] if limit else items


def _print_json(payload) -> None:
    print(json.dumps(payload, indent=2))


_DEFANG_TOKENS = re.compile(r"https?:|\.")


def defang(text: str) -> str:
    """Neutralise scheme prefixes and dots so an indicator cannot be clicked by accident."""

    def swap(hit: re.Match) -> str:
        token = hit.group(0)
        return "[.]" if token == "." else token.replace("tt", "xx")

    return _DEFANG_TOKENS.sub(swap, text)


def _masked(value: str, active: bool) -> str:
    return defang(value) if active else value


def _feed_filters(args) -> list[str]:
    """Filter segments in the order the API expects: tag, user, type (blank ones dropped)."""
    chosen = []
    if args.tag:
        chosen.append(args.tag.lstrip("/"))
    if args.user:
        chosen.append(args.user if args.user.startswith("@") else f"@{args.user}")
    if args.type:
        chosen.append(args.type)
    return [segment for segment in chosen if segment]


def _path_segment(value: str, *, safe: str = "") -> str:
    if value in {".", ".."}:
        raise TweetFeedError("API path identifiers cannot be dot segments")
    return quote(value, safe=safe)


def _path_suffix(filters: list[str]) -> str:
    return "".join("/" + _path_segment(segment, safe="@#") for segment in filters)


# --------------------------------------------------------------------------------------
# Year CSV, local filters, export
# --------------------------------------------------------------------------------------

_COLUMN_WORDS = frozenset({"date", "user", "type", "value"})
_TAG_SEPARATORS = re.compile(r"[,|\s]+")


def parse_year_csv(text: str) -> list[dict]:
    """Turn the unfiltered year CSV into feed-shaped rows (header optional, short rows padded)."""
    records = [cells for cells in csv.reader(io.StringIO(text)) if cells]
    if records and any(cell.strip().lower() in _COLUMN_WORDS for cell in records[0]):
        records = records[1:]
    rows = []
    for cells in records:
        date, user, kind, value, tag_cell, tweet = (
            [cell.strip() for cell in cells] + [""] * 6
        )[:6]
        tags = [piece for piece in _TAG_SEPARATORS.split(tag_cell) if piece]
        rows.append(
            {
                "date": date,
                "user": user,
                "type": kind,
                "value": value,
                "tags": tags,
                "tweet": tweet,
            }
        )
    return rows


def _passes_year_filters(row: dict, args) -> bool:
    if args.type and _field(row, "type").lower() != args.type.lower():
        return False
    if args.tag:
        wanted = args.tag.removeprefix("#").lower()
        if wanted not in {tag.removeprefix("#").lower() for tag in _row_tags(row)}:
            return False
    if args.user:
        if (
            _field(row, "user").removeprefix("@").lower()
            != args.user.removeprefix("@").lower()
        ):
            return False
    return True


def _row_mentions(row: dict, needle: str) -> bool:
    parts = [
        _field(row, key) for key in ("value", "user", "type", "tweet")
    ] + _row_tags(row)
    return needle.lower() in " ".join(parts).lower()


def export_rows(rows: list[dict], target: str) -> str:
    """Write rows by file extension (.json, .txt, anything else -> CSV). Returns the path written."""
    lowered = target.lower()
    if lowered.endswith(".json"):
        Path(target).write_text(
            json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return target
    if lowered.endswith(".txt"):
        Path(target).write_text(
            "".join(f"{_field(row, 'value')}\n" for row in rows), encoding="utf-8"
        )
        return target
    if not lowered.endswith(".csv"):
        target += ".csv"
    with open(target, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(EXPORT_COLUMNS)
        for row in rows:
            writer.writerow(
                [
                    _field(row, "date"),
                    _field(row, "user"),
                    _field(row, "type"),
                    _field(row, "value"),
                    " ".join(_row_tags(row)),
                    _field(row, "tweet"),
                ]
            )
    return target


def _save_if_asked(rows: list[dict], target) -> None:
    if target:
        written = export_rows(rows, target)
        print(f"saved {len(rows)} rows to {written}", file=sys.stderr)


# --------------------------------------------------------------------------------------
# Rendering helpers
# --------------------------------------------------------------------------------------


def _tag_cell(tags: list[str]) -> str:
    if not tags:
        return f"[dim]{DASH}[/dim]"
    pieces = []
    for tag in tags:
        label = _hashtag(tag)
        color = TAG_PALETTE[
            zlib.crc32(label.lower().encode("utf-8")) % len(TAG_PALETTE)
        ]
        pieces.append(f"[{color}]{escape(label)}[/{color}]")
    return " ".join(pieces)


def _response_hints(response: httpx.Response) -> str:
    headers = response.headers
    found = []
    for label, header in (
        ("count", "x-result-count"),
        ("from", "x-result-window-start"),
        ("to", "x-result-window-end"),
    ):
        if headers.get(header):
            found.append(f"{label}={headers[header]}")
    if headers.get("x-result-truncated", "").lower() == "true":
        found.append("TRUNCATED@10k")
    if headers.get("x-resp-state"):
        found.append(f"cache={headers['x-resp-state']}")
    return "  ".join(found) or "ok"


def _ioc_table(rows: list[dict], mask: bool) -> Table:
    grid = Table(box=box.SIMPLE_HEAD, header_style="bold", pad_edge=False)
    grid.add_column("when", style="dim", no_wrap=True)
    grid.add_column("type", no_wrap=True)
    grid.add_column("value", overflow="fold")
    grid.add_column("tags")
    grid.add_column("by", no_wrap=True)
    for row in rows:
        kind = _field(row, "type")
        reporter = _field(row, "user").removeprefix("@") or "?"
        grid.add_row(
            Text(_field(row, "date") or DASH),
            Text(kind, style=TYPE_COLORS.get(kind, "white")),
            Text(_masked(_field(row, "value"), mask)),
            _tag_cell(_row_tags(row)),
            Text(f"@{reporter}"),
        )
    return grid


def _print_summary(rows: list[dict]) -> None:
    kinds = Counter(kind for kind in (_field(row, "type") for row in rows) if kind)
    tags = Counter(
        tag.removeprefix("#").lower()
        for row in rows
        for tag in _row_tags(row)
        if tag.removeprefix("#")
    )
    people = Counter(
        name for name in (_field(row, "user").removeprefix("@") for row in rows) if name
    )
    console.print(
        f"[bold]{len(rows)} IOCs[/bold]  "
        + "  ".join(f"{escape(kind)} {n}" for kind, n in kinds.most_common())
    )
    if tags:
        console.print(
            "[bold]top tags[/bold]  "
            + "  ".join(f"#{escape(tag)}" for tag, _ in tags.most_common(8))
        )
    if people:
        console.print(
            "[bold]top reporters[/bold]  "
            + "  ".join(f"@{escape(name)}" for name, _ in people.most_common(5))
        )


def _print_tweet_sources(rows: list[dict], mask: bool) -> None:
    linked = [row for row in rows if _field(row, "tweet")]
    if not linked:
        return
    console.print("[bold]source tweets[/bold]")
    for row in linked:
        console.print(
            f"  {escape(_masked(_field(row, 'value'), mask))}  [blue]{escape(_field(row, 'tweet'))}[/blue]"
        )


def _show_banner() -> None:
    for line in BANNER_LINES:
        console.print(Text(line, style="bold cyan"))
    console.print(
        f"[dim]{NAME} {VERSION}  {DOCS}  no key needed, please go easy on the API[/dim]"
    )


# --------------------------------------------------------------------------------------
# feed
# --------------------------------------------------------------------------------------


def _fetch_window_rows(args, filters: list[str]):
    path = f"/v1/{args.window}{_path_suffix(filters)}"
    payload, response = api_get(path)
    if not isinstance(payload, list):
        raise TweetFeedError(
            f"expected a JSON array from {path}, got {type(payload).__name__}"
        )
    return response, payload


def _fetch_year_rows(args):
    text, response = api_get("/v1/year", expect_json=False)
    return response, [
        row for row in parse_year_csv(text) if _passes_year_filters(row, args)
    ]


def _feed_panel(window: str, filters: list[str], response: httpx.Response) -> Panel:
    scope = " / ".join(filters) or "none"
    return Panel(
        f"[bold]{window}[/bold]  filters: {escape(scope)}",
        subtitle=Text(_response_hints(response)),
    )


def cmd_feed(args, *, structured=False):
    filters = _feed_filters(args)
    if args.window == "year":
        print(YEAR_NOTICE, file=sys.stderr)
        response, rows = _fetch_year_rows(args)
    else:
        response, rows = _fetch_window_rows(args, filters)
    if args.contains:
        rows = [row for row in rows if _row_mentions(row, args.contains)]
    shown = _clip(rows, args.limit)
    if structured:
        if args.export:
            export_rows(shown, args.export)
        return shown
    if args.json:
        _save_if_asked(shown, args.export)
        _print_json(shown)
        return 0
    if args.values_only:
        for row in shown:
            print(_masked(_field(row, "value"), args.defang))
        _save_if_asked(shown, args.export)
        return 0
    console.print(_feed_panel(args.window, filters, response))
    if not rows:
        console.print("[yellow]no IOCs matched[/yellow]")
        return 0
    console.print(_ioc_table(shown, args.defang))
    _print_summary(rows)
    if args.limit and len(rows) > args.limit:
        console.print(f"[dim]showing {args.limit} of {len(rows)}[/dim]")
    if args.tweets:
        _print_tweet_sources(shown, args.defang)
    _save_if_asked(shown, args.export)
    return 0


# --------------------------------------------------------------------------------------
# lookup
# --------------------------------------------------------------------------------------


def _show_ai_context(ai) -> None:
    if not ai or not ai.get("summary"):
        return
    detail = (
        f"{escape(str(ai['summary']))}\n"
        f"[dim]family[/dim] {_or_dash(ai.get('family'))}  "
        f"[dim]threat[/dim] {_or_dash(ai.get('threat_type'))}  "
        f"[dim]confidence[/dim] {_or_dash(ai.get('confidence'))}"
    )
    console.print(
        Panel(detail, title="AI context", border_style="magenta", expand=False)
    )


def _show_lookup_records(records, args) -> None:
    records = [record for record in (records or []) if isinstance(record, dict)]
    if not records:
        return
    grid = Table(box=box.SIMPLE_HEAD, header_style="bold")
    for heading in (
        "type",
        "value",
        "first seen",
        "last seen",
        "count",
        "tags",
        "reporters",
    ):
        grid.add_column(heading)
    for record in records:
        reporters = record.get("users") or record.get("reporters") or []
        grid.add_row(
            _or_dash(record.get("type")),
            Text(_masked(_field(record, "value"), args.defang)),
            _or_dash(record.get("first_seen")),
            _or_dash(record.get("last_seen")),
            _or_dash(record.get("count")),
            _tag_cell([str(tag) for tag in record.get("tags") or []]),
            Text(
                " ".join(f"@{str(name).removeprefix('@')}" for name in reporters)
                or DASH
            ),
        )
    console.print(grid)
    if args.tweets:
        for record in records:
            for link in record.get("tweets") or []:
                console.print(f"  [blue]{escape(str(link))}[/blue]")


def _show_registration(reg) -> None:
    if not reg:
        return
    labels = (
        ("apex", "apex"),
        ("registrar", "registrar"),
        ("created", "created"),
        ("asn", "asn"),
        ("org", "org"),
        ("newly_registered", "newly registered"),
    )
    lines = [
        f"[dim]{label}[/dim] {escape(str(reg[key]))}"
        for key, label in labels
        if reg.get(key) not in (None, "")
    ]
    addresses = reg.get("ips") or []
    if addresses:
        lines.append(
            "[dim]ips[/dim] "
            + "  ".join(escape(str(address)) for address in addresses[:6])
        )
    console.print(Panel("\n".join(lines), title="registration / network", expand=False))


def _confidence_cell(level) -> str:
    if level in (None, ""):
        return DASH
    color = CONFIDENCE_COLORS.get(str(level).lower(), "white")
    return f"[{color}]{escape(str(level))}[/{color}]"


def _show_related_campaigns(entries) -> None:
    entries = [entry for entry in (entries or []) if isinstance(entry, dict)]
    if not entries:
        return
    console.print("[bold]related campaigns[/bold]")
    for entry in entries:
        console.print(
            f"  {_or_dash(entry.get('id'))}  {_or_dash(entry.get('name'))}  "
            f"{_confidence_cell(entry.get('confidence'))}  {_or_dash(entry.get('ioc_count'))}"
        )


def cmd_lookup(args, *, structured=False):
    payload, _response = _object_response("/v1/ioc", {"value": args.value})
    if structured:
        return payload
    if args.json:
        _print_json(payload)
        return 0
    console.print(f"[bold]{escape(str(payload.get('query') or args.value))}[/bold]")
    if payload.get("found"):
        console.print(
            f"[green]found[/green] within {escape(str(payload.get('window') or '365d'))}"
        )
    else:
        console.print("[yellow]not found in the live 365-day window[/yellow]")
    _show_ai_context(payload.get("ai"))
    _show_lookup_records(payload.get("records"), args)
    _show_registration(payload.get("reg"))
    _show_related_campaigns(payload.get("campaigns"))
    older = (payload.get("archive") or {}).get("total")
    if older:
        console.print(
            f"[dim]{escape(str(older))} further records predate the 365-day window[/dim]"
        )
    return 0


# --------------------------------------------------------------------------------------
# campaigns
# --------------------------------------------------------------------------------------


def _campaign_table(campaigns: list[dict]) -> Table:
    grid = Table(box=box.SIMPLE_HEAD, header_style="bold")
    for heading in (
        "id",
        "name",
        "confidence",
        "iocs",
        "iocs 7d",
        "last seen",
        "target",
    ):
        grid.add_column(heading)
    for entry in campaigns:
        grid.add_row(
            _or_dash(entry.get("id")),
            _or_dash(entry.get("name")),
            _confidence_cell(entry.get("confidence")),
            _or_dash(entry.get("ioc_count")),
            _or_dash(entry.get("ioc_count_7d")),
            _or_dash(entry.get("last_seen")),
            _or_dash(entry.get("targeted_brand") or entry.get("targeted_sector")),
        )
    return grid


def _campaign_list(args, *, structured=False):
    payload, _response = _object_response("/v1/campaigns")
    if structured:
        return payload
    if args.json:
        _print_json(payload)
        return 0
    campaigns = [
        entry for entry in (payload.get("campaigns") or []) if isinstance(entry, dict)
    ]
    count = payload.get("campaign_count")
    console.print(
        f"[bold]{len(campaigns) if count is None else escape(str(count))} campaigns[/bold]  "
        f"window {_or_dash(payload.get('window'))}  generated {_or_dash(payload.get('generated_at'))}"
    )
    console.print(_campaign_table(_clip(campaigns, args.limit)))
    console.print("[dim]drill into one with: iocaw campaigns --id <ID>[/dim]")
    return 0


def _campaign_summary_line(record: dict) -> str:
    pairs = [
        ("confidence", record.get("confidence")),
        ("iocs", record.get("ioc_count")),
        ("first seen", record.get("first_seen")),
        ("last seen", record.get("last_seen")),
        ("brand", record.get("targeted_brand")),
        ("sector", record.get("targeted_sector")),
    ]
    line = "  ".join(f"[dim]{label}[/dim] {_or_dash(value)}" for label, value in pairs)
    if record.get("ttps"):
        line += "  [dim]ttps[/dim] " + ", ".join(
            escape(str(item)) for item in record["ttps"]
        )
    return line


def _campaign_detail(args, *, structured=False):
    payload, _response = _object_response("/v1/campaigns/" + _path_segment(args.id))
    if structured:
        return payload
    if args.json:
        _print_json(payload)
        return 0
    record = payload.get("campaign") or payload
    headline = record.get("name") or record.get("id") or args.id
    body = f"[dim]{_or_dash(record.get('id'))}[/dim]"
    if record.get("context"):
        body += f"\n{escape(str(record['context']))}"
    console.print(Panel(body, title=Text(str(headline)), expand=False))
    console.print(_campaign_summary_line(record))
    indicators = (
        payload.get("iocs")
        or payload.get("records")
        or record.get("iocs")
        or record.get("records")
    )
    if (
        isinstance(indicators, list)
        and indicators
        and isinstance(indicators[0], dict)
        and "value" in indicators[0]
    ):
        console.print(_ioc_table(_clip(indicators, args.limit), args.defang))
        _print_summary(indicators)
    return 0


def cmd_campaigns(args, *, structured=False):
    if args.export:
        raise TweetFeedError(
            "--export is not supported for campaigns; use --json to save the response"
        )
    if args.id:
        return _campaign_detail(args, structured=structured)
    return _campaign_list(args, structured=structured)


# --------------------------------------------------------------------------------------
# trends
# --------------------------------------------------------------------------------------

_MAPPING_NOISE = frozenset({"generated_at", "window", "version"})


def _mover_rows(raw) -> list[dict]:
    if isinstance(raw, list):
        return [entry for entry in raw if isinstance(entry, dict)]
    if not isinstance(raw, dict):
        return []
    for key in ("items", "tags", "top", "up"):
        if isinstance(raw.get(key), list):
            listed = list(raw[key])
            if key == "up" and isinstance(raw.get("down"), list):
                listed += raw["down"]
            return [entry for entry in listed if isinstance(entry, dict)]
    rows = []
    for tag, value in raw.items():
        if tag in _MAPPING_NOISE:
            continue
        if isinstance(value, dict):
            rows.append({"tag": tag, **value})
        elif isinstance(value, (int, float)):
            rows.append({"tag": tag, "current": value})
    return sorted(
        rows,
        key=lambda entry: abs(entry.get("delta") or entry.get("current") or 0),
        reverse=True,
    )


def _first_present(row: dict, *keys: str):
    for key in keys:
        if row.get(key) is not None:
            return row[key]
    return None


def _sign_style(number) -> str:
    if not number:
        return "dim"
    return "green" if number > 0 else "red"


def _movers_table(rows: list[dict], cap: int) -> Table:
    grid = Table(
        title="week-over-week tag movers", box=box.SIMPLE_HEAD, header_style="bold"
    )
    for heading in ("tag", "now", "prev", "delta", "change"):
        grid.add_column(heading)
    for row in rows[:cap]:
        delta = row.get("delta")
        pct = _first_present(row, "pct", "percent")
        grid.add_row(
            Text(_hashtag(str(row.get("tag") or "?")), style="bold"),
            _or_dash(_first_present(row, "count", "current", "now")),
            _or_dash(_first_present(row, "previous", "prev")),
            Text("" if delta is None else f"{delta:+}", style=_sign_style(delta)),
            Text("" if pct is None else f"{pct:.0f}%", style=_sign_style(pct)),
        )
    return grid


def _tld_rows(raw) -> list[tuple[str, object]]:
    if isinstance(raw, dict):
        for key in ("items", "top", "tlds"):
            if isinstance(raw.get(key), (list, dict)):
                return _tld_rows(raw[key])
        pairs = [
            (str(name), count)
            for name, count in raw.items()
            if isinstance(count, (int, float))
        ]
        return sorted(pairs, key=lambda pair: pair[1], reverse=True)
    if isinstance(raw, list):
        return [
            (
                str(entry.get("tld") or entry.get("name") or entry.get("tag") or "?"),
                _first_present(entry, "count", "total"),
            )
            for entry in raw
            if isinstance(entry, dict)
        ]
    return []


def _tld_table(pairs: list[tuple[str, object]], cap: int) -> Table:
    grid = Table(title="hot TLDs (30d)", box=box.SIMPLE_HEAD, header_style="bold")
    grid.add_column("tld")
    grid.add_column("count")
    for name, count in pairs[:cap]:
        grid.add_row(Text(name), _or_dash(count))
    return grid


def _sparkline(values: list[float]) -> str:
    low, high = min(values), max(values)
    span = (high - low) or 1
    top = len(SPARK_BLOCKS) - 1
    return "".join(
        SPARK_BLOCKS[int((value - low) / span * top + 0.5)] for value in values
    )


def _novelty_pairs(raw) -> str:
    if not isinstance(raw, dict):
        return ""
    skipped = _MAPPING_NOISE
    return "  ".join(
        f"{key}={value}"
        for key, value in raw.items()
        if key not in skipped and isinstance(value, (str, int, float, bool))
    )


def cmd_trends(args, *, structured=False):
    payload, _response = _object_response("/v1/trends")
    if structured:
        return payload
    if args.json:
        _print_json(payload)
        return 0
    console.print(
        f"[bold]trends[/bold]  generated {_or_dash(payload.get('generated_at'))}"
    )
    movers = _mover_rows(payload.get("movers"))
    if movers:
        console.print(_movers_table(movers, args.limit or 15))
    domains = _tld_rows(payload.get("tlds"))
    if domains:
        console.print(_tld_table(domains, args.limit or 12))
    novelty = _novelty_pairs(payload.get("novelty"))
    if novelty:
        console.print(f"[bold]novelty[/bold]  {escape(novelty)}")
    daily = payload.get("daily")
    totals = daily.get("total") if isinstance(daily, dict) else None
    recent = [value for value in (totals or [])[-7:] if isinstance(value, (int, float))]
    if recent:
        console.print(f"[bold]daily[/bold]  {_sparkline(recent)}  {recent}")
    return 0


# --------------------------------------------------------------------------------------
# counts and status
# --------------------------------------------------------------------------------------


def _show_count_window(name: str, block: dict, cap: int) -> None:
    span = f"{escape(str(block.get('first_date')))} → {escape(str(block.get('last_date')))}"
    console.print(
        f"[bold cyan]{escape(name)}[/bold cyan]  total {escape(str(block.get('total')))}  {span}"
    )
    kinds = block.get("types") or {}
    if kinds:
        console.print(
            "[dim]types[/dim]  "
            + "  ".join(
                f"{escape(str(kind))}={escape(str(n))}" for kind, n in kinds.items()
            )
        )
    tags = block.get("tags") or {}
    if not tags:
        return
    grid = Table(box=box.SIMPLE_HEAD, header_style="bold")
    grid.add_column("tag")
    grid.add_column("count")
    for tag, amount in sorted(tags.items(), key=lambda pair: pair[1], reverse=True)[
        :cap
    ]:
        grid.add_row(Text(_hashtag(str(tag)), style="bold"), Text(str(amount)))
    console.print(grid)


def cmd_counts(args, *, structured=False):
    payload, _response = _object_response("/v1/counts")
    if structured:
        return payload
    if args.json:
        _print_json(payload)
        return 0
    console.print(
        f"[bold]counts[/bold]  generated {_or_dash(payload.get('generated_at'))}"
    )
    windows = payload.get("windows") or {}
    for name in [args.window] if args.window else WINDOWS:
        if windows.get(name):
            _show_count_window(name, windows[name], args.limit or 12)
    return 0


def _artifact_grid(artifacts: dict) -> Table:
    ordered = [name for name in ARTIFACT_ORDER if name in artifacts]
    ordered += [name for name in artifacts if name not in ARTIFACT_ORDER]
    grid = Table(box=box.SIMPLE_HEAD, header_style="bold")
    for heading in ("artifact", "window", "rows", "updated", "age", "stale"):
        grid.add_column(heading)
    listed = [
        (name, artifacts[name]) for name in ordered if isinstance(artifacts[name], dict)
    ]
    for name, info in listed[:ARTIFACT_ROW_CAP]:
        grid.add_row(
            Text(name),
            _or_dash(info.get("window")),
            _or_dash(info.get("rows")),
            _or_dash(info.get("updated_at")),
            _or_dash(info.get("age_seconds")),
            "yes" if info.get("stale") else "no",
        )
    return grid


def cmd_status(args, *, structured=False):
    payload, response = _object_response("/v1/status")
    if structured:
        return payload
    if args.json:
        _print_json(payload)
        return 0
    stale = payload.get("stale", payload.get("any_stale"))
    age = payload.get("age_seconds")
    summary = (
        f"stale {escape(str(stale))}   age {DASH if age is None else escape(str(age)) + 's'}   "
        f"checked {_or_dash(payload.get('checked_at'))}"
    )
    console.print(
        Panel(
            summary,
            title="TweetFeed pipeline",
            border_style="yellow" if stale else "green",
            expand=False,
        )
    )
    contract = payload.get("contract")
    if contract:
        console.print(
            f"[dim]license {_or_dash(contract.get('license'))}  tlp {_or_dash(contract.get('tlp'))}  "
            f"docs {_or_dash(contract.get('docs'))}[/dim]"
        )
    console.print(_artifact_grid(payload.get("artifacts") or {}))
    console.print(f"[dim]{escape(_response_hints(response))}[/dim]")
    return 0


# --------------------------------------------------------------------------------------
# watch and blocklist
# --------------------------------------------------------------------------------------


def _poll_once(since: str, suffix: str, seen: set, args, *, structured=False):
    """One poll of /v1/since. Returns the cursor to use next time."""
    try:
        payload, response = api_get(f"/v1/since/{quote(since, safe=':-')}{suffix}")
    except TweetFeedError as problem:
        if structured or isinstance(problem.__cause__, egress.PolicyBlocked):
            raise
        console.print(f"[red]{escape(str(problem))}[/red]")
        return since
    rows = payload if isinstance(payload, list) else []
    fresh = []
    for row in rows:
        identity = (_field(row, "date"), _field(row, "type"), _field(row, "value"))
        if identity not in seen:
            seen.add(identity)
            fresh.append(row)
    clock = datetime.now().strftime("%H:%M:%S")
    if structured:
        newest = max((_field(row, "date") for row in fresh), default="")
        cursor = newest.replace(" ", "T") + "Z" if newest else since
        return cursor, fresh
    if not fresh:
        console.print(f"[dim]{clock}  silence ({len(rows)} already seen)[/dim]")
        return since
    console.print(
        f"[bold green]+{len(fresh)}[/bold green]  {clock}  [dim]{escape(_response_hints(response))}[/dim]"
    )
    console.print(_ioc_table(fresh, args.defang))
    newest = max(_field(row, "date") for row in fresh)
    return newest.replace(" ", "T") + "Z" if newest else since


def cmd_watch(args, *, structured=False):
    from bughunt.core.addon_adapters import wait_for_poll

    if args.interval <= 0:
        raise TweetFeedError("--interval must be greater than zero")
    remaining = getattr(args, "polls", None)
    if remaining is not None and remaining < 1:
        raise TweetFeedError("--polls must be positive")
    since = args.since or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    suffix = _path_suffix(_feed_filters(args))
    if structured:
        since, seen, polls = since, set(), []
        for index in range(args.polls):
            since, rows = _poll_once(since, suffix, seen, args, structured=True)
            polls.append({"cursor": since, "records": rows})
            if index + 1 < args.polls:
                wait_for_poll(args.interval)
        return polls
    console.print(
        f"[bold]watching[/bold] since {escape(since)} every {args.interval}s, Ctrl-C to stop"
    )
    seen: set = set()
    try:
        while True:
            since = _poll_once(since, suffix, seen, args)
            if remaining is not None:
                remaining -= 1
                if remaining == 0:
                    break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        console.print("[dim]watch stopped[/dim]")
    return 0


def cmd_blocklist(args, *, structured=False):
    text, _response = api_get(f"/v1/blocklist/{args.kind}.txt", expect_json=False)
    entries = [line for line in text.splitlines() if line and not line.startswith("#")]
    if structured:
        if args.export:
            Path(args.export).write_text(text, encoding="utf-8")
        return {"kind": args.kind, "entries": _clip(entries, args.limit)}
    console.print(f"[bold]{args.kind}[/bold] blocklist, {len(entries)} entries")
    for entry in _clip(entries, args.limit):
        print(_masked(entry, args.defang))
    if args.limit and len(entries) > args.limit:
        console.print(f"[dim]showing {args.limit} of {len(entries)}[/dim]")
    if args.export:
        Path(args.export).write_text(text, encoding="utf-8")
        console.print(f"[green]saved[/green] the full list to {escape(args.export)}")
    return 0


# --------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------


def _add_filter_options(sub: argparse.ArgumentParser) -> None:
    sub.add_argument("--type", choices=IOC_TYPES, help="only this indicator type")
    sub.add_argument("--tag", help="only indicators carrying this tag")
    sub.add_argument(
        "--user", help="only indicators from this reporter (leading @ optional)"
    )


def _add_output_options(sub: argparse.ArgumentParser, default_limit: int) -> None:
    sub.add_argument(
        "--json", action="store_true", help="print the raw JSON instead of tables"
    )
    sub.add_argument(
        "--defang", action="store_true", help="print indicators defanged (hxxp, [.])"
    )
    sub.add_argument(
        "--limit",
        type=int,
        default=default_limit,
        help=f"rows to show, 0 for all (default {default_limit})",
    )
    sub.add_argument(
        "--export",
        metavar="FILE",
        help="save the shown rows (.json, .txt, otherwise CSV)",
    )


def _register_feed(commands) -> None:
    sub = commands.add_parser("feed", help="pull indicators for a time window")
    sub.add_argument(
        "window",
        nargs="?",
        choices=WINDOWS,
        default="today",
        help="time window (default today)",
    )
    _add_filter_options(sub)
    _add_output_options(sub, 40)
    sub.add_argument(
        "--contains",
        help="keep rows whose value, user, type, tweet or tags contain this text",
    )
    sub.add_argument(
        "--values-only", action="store_true", help="print just the indicator values"
    )
    sub.add_argument(
        "--tweets",
        action="store_true",
        help="also list the source tweet of each shown row",
    )


def _register_lookup(commands) -> None:
    sub = commands.add_parser(
        "lookup", help="check one indicator against the last 365 days"
    )
    sub.add_argument("value", help="URL, domain, IP address or file hash to look up")
    sub.add_argument(
        "--json", action="store_true", help="print the raw JSON instead of panels"
    )
    sub.add_argument(
        "--defang", action="store_true", help="print record values defanged"
    )
    sub.add_argument(
        "--tweets", action="store_true", help="list the source tweets of each record"
    )


def _register_reports(commands) -> None:
    sub = commands.add_parser(
        "campaigns", help="AI-clustered campaigns, or one campaign in detail"
    )
    sub.add_argument("--id", help="campaign id (tfc-...) to show in detail")
    _add_output_options(sub, 40)
    sub = commands.add_parser("trends", help="tag movers, hot TLDs and novelty")
    sub.add_argument("--json", action="store_true", help="print the raw JSON")
    sub.add_argument(
        "--limit", type=int, default=15, help="rows per table (default 15)"
    )
    sub = commands.add_parser("counts", help="totals by window, type and tag")
    sub.add_argument(
        "window", nargs="?", choices=WINDOWS, help="a single window (default all four)"
    )
    sub.add_argument("--json", action="store_true", help="print the raw JSON")
    sub.add_argument(
        "--limit", type=int, default=12, help="tags per window (default 12)"
    )
    sub = commands.add_parser("status", help="how fresh the feed pipeline is")
    sub.add_argument("--json", action="store_true", help="print the raw JSON")


def _register_streams(commands) -> None:
    sub = commands.add_parser("watch", help="poll for new indicators until interrupted")
    sub.add_argument("--since", help="start cursor, ISO-8601 UTC (default: now)")
    sub.add_argument(
        "--interval", type=int, default=60, help="seconds between polls (default 60)"
    )
    sub.add_argument(
        "--polls", type=int, help="finite number of polls (required for embedding)"
    )
    _add_filter_options(sub)
    sub.add_argument("--defang", action="store_true", help="print indicators defanged")
    sub = commands.add_parser("blocklist", help="ready-made 30-day blocklists")
    sub.add_argument("kind", choices=BLOCKLIST_KINDS, help="which list to fetch")
    sub.add_argument(
        "--limit", type=int, default=30, help="entries to show, 0 for all (default 30)"
    )
    sub.add_argument("--defang", action="store_true", help="print entries defanged")
    sub.add_argument(
        "--export", metavar="FILE", help="save the complete list, comments included"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iocaw",
        description="Read the TweetFeed.live indicator-of-compromise feed (CC0 data, no API key).",
        epilog=(
            "TweetFeed data is community-sourced and unverified. Treat every indicator as hostile:\n"
            "never open a live malicious URL, and prefer --defang when pasting into tickets or chat.\n"
            "--quiet may appear before or after the command: iocaw feed week --quiet"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{NAME} {VERSION}")
    parser.add_argument("--quiet", action="store_true", help="skip the banner")
    commands = parser.add_subparsers(dest="cmd", required=True, metavar="COMMAND")
    _register_feed(commands)
    _register_lookup(commands)
    _register_reports(commands)
    _register_streams(commands)
    for command in commands.choices.values():
        command.add_argument(
            "--quiet",
            action="store_true",
            default=argparse.SUPPRESS,
            help="skip the banner",
        )
    return parser


COMMANDS = {
    "feed": cmd_feed,
    "lookup": cmd_lookup,
    "campaigns": cmd_campaigns,
    "trends": cmd_trends,
    "counts": cmd_counts,
    "status": cmd_status,
    "watch": cmd_watch,
    "blocklist": cmd_blocklist,
}


def run_structured(args, *, dry_run=False):
    from bughunt.core.addon_adapters import effect, external, planned, validate_watch

    if getattr(args, "limit", 0) < 0:
        raise ValueError("Limit cannot be negative")
    if args.cmd == "watch":
        validate_watch(args.polls, args.interval)
        _path_suffix(_feed_filters(args))
    if args.cmd == "campaigns":
        if args.export:
            raise ValueError("Campaign exports use the returned structured response")
        if args.id:
            _path_segment(args.id)
    if dry_run:
        return planned("ioc", args.cmd)
    output = external("ioc", args.cmd, COMMANDS[args.cmd](args, structured=True))
    if getattr(args, "export", None):
        effect(output, "ioc-export", "write")
    return output


@contextmanager
def _output_encoding():
    originals = []
    try:
        for stream in (sys.stdout, sys.stderr):
            if any(stream is previous for previous, _, _ in originals):
                continue
            reconfigure = getattr(stream, "reconfigure", None)
            if reconfigure is not None:
                originals.append((stream, stream.encoding, stream.errors))
                reconfigure(encoding="utf-8", errors="strict")
        yield
    finally:
        for stream, encoding, errors in reversed(originals):
            stream.reconfigure(encoding=encoding, errors=errors)


def _run(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not (
        args.quiet
        or getattr(args, "json", False)
        or getattr(args, "values_only", False)
    ):
        _show_banner()
    try:
        return COMMANDS[args.cmd](args) or 0
    except TweetFeedError as problem:
        print(str(problem), file=sys.stderr)
        return 2
    except OSError as problem:
        print(f"could not write export: {problem}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        console.print("[yellow]interrupted[/yellow]")
        return 130


def main(argv=None) -> int:
    with _output_encoding():
        return _run(argv)


if __name__ == "__main__":
    sys.exit(main())
