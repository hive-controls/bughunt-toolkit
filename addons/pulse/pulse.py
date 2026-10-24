"""pulse: scope-gated URL liveness check, grouped by status family.

Every URL is checked with one GET through Bughunt's policy-guarded egress client (operation
"crawl"). A URL outside the active scope is never contacted. With --follow-redirects each 3xx hop
is walked one request at a time, and every hop must also be in scope and permitted by policy.

Run it as `bughunt pulse urls.txt` or from the console (`use pulse`, `set FILE urls.txt`, `run`).
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import sys
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bughunt.core import egress
from bughunt.core.http import redirect_target
from bughunt.core.workspace import allowed

MAX_HOPS = 10
BACKOFF_STEP_SECONDS = 0.4
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; BughuntPulse/1.0)"

# (family, table title, colour). The tuple order is the fixed display order.
FAMILY_DISPLAY = (
    ("2xx", "LIVE", "green"),
    ("3xx", "REDIRECT", "cyan"),
    ("4xx", "CLIENT ERROR", "yellow"),
    ("5xx", "SERVER ERROR", "red"),
    ("error", "UNREACHABLE", "magenta"),
    ("excluded", "EXCLUDED", "yellow"),
)
SUMMARY_LABELS = {"error": "err"}
HARD_FAILURE_FAMILIES = ("5xx", "error")

NO_STATUS_CELL = "----"
NO_TIMING_CELL = "-"
CHAIN_ARROW = " → "
EXPORT_CHAIN_JOINER = " -> "

console = Console(highlight=False)


@dataclass
class CheckResult:
    url: str
    ok: bool
    status: int | None = None
    reason: str = ""
    family: str = "error"
    elapsed_ms: int = 0
    final_url: str = ""
    content_type: str = ""
    error: str = ""
    redirects: list[str] = field(default_factory=list)
    excluded: bool = False


EXPORT_COLUMNS = tuple(column.name for column in fields(CheckResult))


def export_row(result: CheckResult) -> dict:
    row = asdict(result)
    row["redirects"] = EXPORT_CHAIN_JOINER.join(result.redirects)
    return row


# ---------------------------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------------------------


def status_family(code: int | None) -> str:
    if code is None:
        return "error"
    hundreds = code // 100
    return f"{hundreds}xx" if 2 <= hundreds <= 5 else "error"


def normalize_url(raw: str) -> str:
    cleaned = raw.strip()
    if not cleaned:
        return cleaned
    try:
        has_scheme = bool(urlparse(cleaned).scheme)
        authority = cleaned.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if authority.rpartition(":")[2].isdigit():
            has_scheme = False
    except ValueError:
        has_scheme = True
    return cleaned if has_scheme else "https://" + cleaned


def load_urls(source: str) -> list[str]:
    """Read URLs from a file path or "-" (stdin). Raises FileNotFoundError for a missing file."""
    if source == "-":
        text = sys.stdin.read()
    else:
        with open(source, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    first_seen: dict[str, None] = {}
    for line in text.split("\n"):
        entry = line.strip()
        for index, character in enumerate(entry):
            if character == "#" and (index == 0 or entry[index - 1].isspace()):
                entry = entry[:index].rstrip()
                break
        if entry and not entry.startswith("#"):
            first_seen.setdefault(normalize_url(entry), None)
    return list(first_seen)


# ---------------------------------------------------------------------------------------------
# Checking
# ---------------------------------------------------------------------------------------------


def _describe_connect_error(exc: Exception, text: str) -> str:
    upper = text.upper()
    if "CERTIFICATE" in upper or "SSL" in upper:
        return f"tls error: {text}"
    return f"connection failed: {text or type(exc).__name__}"


# Checked top to bottom; the first matching exception class decides the message.
FAILURE_MESSAGES = (
    (httpx.TimeoutException, lambda exc, text: "timeout"),
    (httpx.ConnectError, _describe_connect_error),
    (httpx.TooManyRedirects, lambda exc, text: "too many redirects"),
    (httpx.UnsupportedProtocol, lambda exc, text: "unsupported protocol"),
    (httpx.HTTPError, lambda exc, text: text or type(exc).__name__),
)


def describe_failure(exc: Exception) -> str:
    text = str(exc)
    for exception_class, render in FAILURE_MESSAGES:
        if isinstance(exc, exception_class):
            return render(exc, text)
    return f"{type(exc).__name__}: {text}"


async def follow_in_scope(client, url: str, follow: bool):
    """GET `url`; with `follow`, keep walking 3xx hops that stay in scope.

    Returns (last response, URLs requested in order, stop note). The policy is consulted
    explicitly before every request so an unguarded client cannot skip it.
    """
    requested = [url]
    response = None
    while True:
        current = requested[-1]
        try:
            egress.authorize(current, "crawl")
            response = await client.get(current)
        except egress.PolicyBlocked as exc:
            if response is None:
                raise
            return response, requested[:-1], exc
        if not follow:
            return response, requested, ""
        target = redirect_target(current, response)
        if not target:
            return response, requested, ""
        if not allowed(target):
            host = urlparse(target).hostname or target
            return (
                response,
                requested,
                f"redirect to {host} is outside scope, not followed",
            )
        if len(requested) > MAX_HOPS:
            return response, requested, f"stopped after {MAX_HOPS} redirects"
        requested.append(target)


def _result_from_response(
    url: str,
    response,
    requested: list[str],
    note: str | egress.PolicyBlocked,
    follow: bool,
    elapsed_ms: int,
) -> CheckResult:
    family = status_family(response.status_code)
    excluded = isinstance(note, egress.PolicyBlocked)
    return CheckResult(
        url=url,
        ok=not excluded and (family == "2xx" or (family == "3xx" and not follow)),
        status=response.status_code,
        reason=response.reason_phrase or "",
        family=family,
        elapsed_ms=elapsed_ms,
        final_url=requested[-1],
        content_type=response.headers.get("content-type", "").split(";")[0].strip(),
        error=describe_failure(note) if excluded else note,
        redirects=list(requested) if len(requested) > 1 else [],
        excluded=excluded,
    )


def _in_scope(url: str) -> bool:
    try:
        return allowed(url)
    except ValueError:
        return False


async def check_one(client, url: str, follow: bool, retries: int) -> CheckResult:
    if not _in_scope(url):
        return CheckResult(url=url, ok=False, error="outside scope, not contacted")
    attempts = max(1, retries + 1)
    last_failure = ""
    for attempt in range(1, attempts + 1):
        started = time.perf_counter()
        try:
            response, requested, note = await follow_in_scope(client, url, follow)
        except egress.PolicyBlocked as exc:
            return CheckResult(
                url=url,
                ok=False,
                family="excluded",
                excluded=True,
                error=describe_failure(exc),
            )
        except Exception as exc:
            last_failure = describe_failure(exc)
            if attempt < attempts:
                await asyncio.sleep(BACKOFF_STEP_SECONDS * attempt)
            continue
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return _result_from_response(url, response, requested, note, follow, elapsed_ms)
    return CheckResult(url=url, ok=False, error=last_failure)


def http2_available() -> bool:
    try:
        import h2  # noqa: F401
    except ImportError:
        return False
    return True


async def run_checks(
    urls,
    *,
    follow,
    timeout,
    concurrency,
    retries,
    user_agent,
    insecure,
    method_note,
    display=True,
) -> list[CheckResult]:
    """Check every URL concurrently and return the results in input order.

    `method_note` is accepted for call compatibility; the method is always GET.
    """
    async with egress.async_client(
        operation="crawl",
        timeout=httpx.Timeout(timeout, connect=min(10, timeout)),
        headers={"User-Agent": user_agent, "Accept": "*/*"},
        limits=httpx.Limits(
            max_connections=concurrency, max_keepalive_connections=concurrency
        ),
        verify=not insecure,
        http2=http2_available(),
        trust_env=False,
        follow_redirects=False,
    ) as client:
        gate = asyncio.Semaphore(concurrency)
        progress = Progress(
            TextColumn("Checking"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=console,
            disable=not display,
        )
        ticket = progress.add_task("checks", total=len(urls))

        async def bounded(url: str) -> CheckResult:
            async with gate:
                result = await check_one(client, url, follow=follow, retries=retries)
            progress.advance(ticket)
            return result

        with progress:
            return list(await asyncio.gather(*(bounded(url) for url in urls)))


# ---------------------------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------------------------


def render_header(args: argparse.Namespace, url_count: int) -> None:
    redirects = "followed" if args.follow_redirects else "not followed"
    body = (
        f"{url_count} URLs | concurrency {args.concurrency} | timeout {args.timeout}s | "
        f"retries {args.retries} | redirects {redirects}"
    )
    console.print(Panel(Text(body), title="pulse", expand=False))


def families_to_show(results: list[CheckResult], only: str | None):
    """Yield (title, colour, rows) for each non-empty table, honouring the --only filter.

    Family tokens pick which tables appear; numeric tokens then keep only rows whose status code
    matches one of them. Numbers alone select their corresponding status families.
    """
    tokens = (
        [token.strip() for token in only.split(",") if token.strip()] if only else None
    )
    codes = {
        int(token) for token in tokens or () if token.isascii() and token.isdigit()
    }
    if codes and not any(
        family in tokens for family, _title, _colour in FAMILY_DISPLAY
    ):
        tokens.extend(status_family(code) for code in codes)
    for family, title, colour in FAMILY_DISPLAY:
        if tokens is not None and family not in tokens:
            continue
        rows = [
            item
            for item in results
            if ("excluded" if item.excluded else item.family) == family
        ]
        if codes:
            rows = [item for item in rows if item.status in codes]
        if rows:
            yield title, colour, rows


def _info_cell(item: CheckResult, show_redirects: bool) -> str:
    if item.excluded:
        info = f"excluded: {item.error}"
    elif item.final_url and item.final_url != item.url:
        info = item.final_url
    else:
        info = item.error or item.reason
    lines = [info] if info else []
    if show_redirects and item.redirects:
        lines.append(CHAIN_ARROW.join(item.redirects))
    return "\n".join(lines)


def _family_table(
    title: str, colour: str, rows: list[CheckResult], show_redirects: bool
) -> Table:
    table = Table(
        title=Text(f"{title} ({len(rows)})", style=f"bold {colour}"),
        box=box.SIMPLE_HEAD,
        header_style="bold",
    )
    table.add_column("Status", justify="right")
    table.add_column("ms", justify="right")
    table.add_column("URL", overflow="fold")
    table.add_column("Final / Info", overflow="fold")
    table.add_column("Content-Type", overflow="fold")
    for item in rows:
        status_cell = NO_STATUS_CELL if item.status is None else str(item.status)
        timing_cell = str(item.elapsed_ms) if item.elapsed_ms else NO_TIMING_CELL
        table.add_row(
            Text(status_cell, style=colour),
            Text(timing_cell),
            Text(item.url),
            Text(_info_cell(item, show_redirects), style="dim"),
            Text(item.content_type),
        )
    return table


def render_results(
    results: list[CheckResult], only: str | None, show_redirects: bool
) -> None:
    shown = False
    for title, colour, rows in families_to_show(results, only):
        console.print(_family_table(title, colour, rows, show_redirects))
        shown = True
    if not shown:
        console.print("No results matched the current filter.")


def render_summary(results: list[CheckResult], wall_seconds: float) -> None:
    live = sum(1 for item in results if item.ok and not item.excluded)
    excluded = sum(1 for item in results if item.excluded)
    per_family = {
        family: sum(
            1
            for item in results
            if ("excluded" if item.excluded else item.family) == family
        )
        for family, _title, _colour in FAMILY_DISPLAY
    }
    timings = [item.elapsed_ms for item in results if item.elapsed_ms]
    average_ms = round(sum(timings) / len(timings)) if timings else 0
    lines = [
        f"{live} live | {len(results) - live - excluded} down | "
        + (f"{excluded} excluded | " if excluded else "")
        + f"{len(results)} total",
        " | ".join(
            f"{SUMMARY_LABELS.get(family, family)} {count}"
            for family, count in per_family.items()
            if family != "excluded" or count
        ),
        f"avg {average_ms} ms | wall {wall_seconds:.2f} s",
    ]
    console.print(Panel(Text("\n".join(lines)), title="Summary", expand=False))


# ---------------------------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------------------------


def export_json(path: str, results: list[CheckResult], *, notify: bool = True) -> None:
    document = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(results),
        "results": [export_row(item) for item in results],
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
    if notify:
        console.print(Text(f"Wrote JSON export: {path}"))


def export_csv(path: str, results: list[CheckResult], *, notify: bool = True) -> None:
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=EXPORT_COLUMNS)
        writer.writeheader()
        writer.writerows(export_row(item) for item in results)
    if notify:
        console.print(Text(f"Wrote CSV export: {path}"))


# ---------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check which URLs in a list are live. Only in-scope URLs are contacted; "
        "results are grouped by status family.",
        epilog="examples:\n"
        "  bughunt pulse urls.txt\n"
        "  bughunt pulse urls.txt --follow-redirects --show-redirects\n"
        "  bughunt pulse urls.txt --only 4xx,5xx,error --json results.json\n"
        "  cat urls.txt | bughunt pulse -",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file", nargs="?", help="text file with one URL per line, or - to read stdin"
    )
    parser.add_argument("--urls", nargs="+", help="explicit URLs instead of a file")
    parser.add_argument(
        "-f",
        "--follow-redirects",
        action="store_true",
        help="follow in-scope 3xx hops (at most 10) and report the final answer",
    )
    parser.add_argument(
        "--show-redirects",
        action="store_true",
        help="print the redirect chain next to rows that followed one",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=20,
        metavar="N",
        help="most URLs checked at the same time (default 20)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        metavar="SEC",
        help="per-request timeout in seconds (default 10)",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=1,
        metavar="N",
        help="extra attempts after a network failure (default 1)",
    )
    parser.add_argument(
        "-A",
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        help="User-Agent to request; an active policy profile replaces it on the wire",
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="skip TLS certificate verification, including on redirect hops",
    )
    parser.add_argument(
        "--only",
        metavar="FAMILIES",
        help="show only these tables: 2xx,3xx,4xx,5xx,error,excluded (comma separated); "
        "a status code listed with them keeps just that code's rows",
    )
    parser.add_argument(
        "--json",
        dest="json_out",
        metavar="PATH",
        help="write every result to a JSON file",
    )
    parser.add_argument(
        "--csv", dest="csv_out", metavar="PATH", help="write every result to a CSV file"
    )
    return parser


def validation_problem(args: argparse.Namespace) -> str:
    if args.concurrency < 1:
        return "--concurrency must be at least 1."
    if args.timeout <= 0:
        return "--timeout must be greater than 0."
    if args.retries < 0:
        return "--retries cannot be negative."
    return ""


def _load_or_exit(source: str) -> list[str]:
    try:
        urls = load_urls(source)
    except FileNotFoundError:
        console.print(Text(f"File not found: {source}"))
        raise SystemExit(1)
    except OSError as problem:
        console.print(Text(f"Could not read {source}: {problem}"))
        raise SystemExit(1) from problem
    if not urls:
        console.print(Text(f"No URLs found in {'stdin' if source == '-' else source}"))
        raise SystemExit(1)
    return urls


def _run_or_exit(urls: list[str], args: argparse.Namespace):
    started = time.perf_counter()
    try:
        results = asyncio.run(
            run_checks(
                urls,
                follow=args.follow_redirects,
                timeout=args.timeout,
                concurrency=args.concurrency,
                retries=args.retries,
                user_agent=args.user_agent,
                insecure=args.insecure,
                method_note="GET",
            )
        )
    except KeyboardInterrupt:
        console.print("Interrupted.")
        raise SystemExit(130)
    return results, time.perf_counter() - started


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
def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    problem = validation_problem(args)
    if problem:
        console.print(problem)
        raise SystemExit(2)
    if bool(args.file) == bool(args.urls):
        parser.error("Supply exactly one input file or --urls")
    urls = (
        list(dict.fromkeys(normalize_url(url) for url in args.urls))
        if args.urls
        else _load_or_exit(args.file)
    )
    render_header(args, len(urls))
    results, wall_seconds = _run_or_exit(urls, args)
    render_results(results, args.only, args.show_redirects)
    render_summary(results, wall_seconds)
    for target, export in ((args.json_out, export_json), (args.csv_out, export_csv)):
        if target:
            try:
                export(target, results)
            except OSError as problem:
                console.print(Text(f"Could not write {target}: {problem}"))
                raise SystemExit(1) from problem
    if any(item.excluded for item in results):
        raise SystemExit(2)
    failed = any(item.family in HARD_FAILURE_FAMILIES for item in results)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
