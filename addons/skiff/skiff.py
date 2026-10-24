"""skiff: scope- and policy-gated HTTP request-position fuzzer.

Substitutes the placeholder ``FUZZ`` (in the URL, a raw request file, headers, cookies or the
body) with entries drawn from a user-supplied wordlist file, sends each resulting request, and
reports hits by response filter (status/size/words/lines/regex/header).

Every request -- including each redirect hop when --follow-redirects is given -- goes through
``bughunt.core.egress.async_client(operation="fuzz")``, so it also needs a matching grant in the
mission policy. The policy's own requests_per_second/concurrency is a mandatory, workspace-wide
cap enforced inside the egress transport; -t/--rps/--delay are advisory and may only tighten that
cap, never loosen it (effective pacing is the minimum of the two).

Run it through the toolkit as ``bughunt skiff`` or directly as ``python skiff.py``.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import csv
import hashlib
import itertools
import json
import random
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import httpx
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from bughunt import VERSION as BUGHUNT_VERSION
from bughunt.core import egress, identity
from bughunt.core.workspace import allowed, explain_block, hostname_of

SCHEMA_VERSION = 1
TOOL_NAME = "skiff"
OPERATION = "fuzz"
FUZZ_TOKEN = "FUZZ"
DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; BughuntSkiff/1.0)"
CALIBRATION_PROBES = 3

console = Console(highlight=False)

EXAMPLES = """\
examples:
  %(prog)s -u https://allowed.example/item?id=FUZZ -w ids.txt
  %(prog)s -u https://allowed.example/FUZZ -w paths.txt -mc 200,301-302
  %(prog)s --request-file req.txt -w ids.txt --follow-redirects -o hits.json -of json
"""


class TargetError(ValueError):
    """The -u/--request-file/-H/-c/-d/filter input could not be turned into a request plan."""


# ---------------------------------------------------------------------------------------------
# Target: method/url/headers/cookies/body, from -u/-H/-c/-d or --request-file
# ---------------------------------------------------------------------------------------------


@dataclass
class Target:
    method: str
    url: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    cookies: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""


def parse_header_argument(raw: str) -> tuple[str, str]:
    name, sep, value = raw.partition(":")
    if not sep:
        raise TargetError(f"Malformed header (expected NAME: VALUE): {raw!r}")
    return name.strip(), value.strip()


def parse_cookie_argument(raw: str) -> tuple[str, str]:
    name, sep, value = raw.partition("=")
    if not sep:
        raise TargetError(f"Malformed cookie (expected NAME=VALUE): {raw!r}")
    return name.strip(), value.strip()


def parse_raw_request(text: str, *, scheme: str) -> Target:
    """A minimal start-line + headers + blank line + body parser (RFC 7230 shape only)."""
    normalized = text.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise TargetError("Request file is empty.")
    start_line = lines[0].split()
    if len(start_line) < 2:
        raise TargetError("Request file's first line must be 'METHOD PATH [VERSION]'.")
    method, path = start_line[0].upper(), start_line[1]
    headers = [parse_header_argument(line) for line in lines[1:]]
    host = next((value for name, value in headers if name.lower() == "host"), "")
    if not host:
        raise TargetError("Request file needs a Host header.")
    url = (
        path if path.startswith(("http://", "https://")) else f"{scheme}://{host}{path}"
    )
    cookies: list[tuple[str, str]] = []
    kept_headers: list[tuple[str, str]] = []
    for name, value in headers:
        if name.lower() == "cookie":
            for segment in value.split(";"):
                segment = segment.strip()
                if segment:
                    cookie_name, _, cookie_value = segment.partition("=")
                    cookies.append((cookie_name.strip(), cookie_value.strip()))
        elif name.lower() != "host":
            kept_headers.append((name, value))
    return Target(method, url, kept_headers, cookies, body)


def build_target_from_args(args: argparse.Namespace) -> Target:
    if bool(args.url) == bool(args.request_file):
        raise TargetError("Provide exactly one of --url or --request-file.")
    headers = [parse_header_argument(item) for item in args.header]
    cookies = [parse_cookie_argument(item) for item in args.cookie]
    if args.url:
        return Target(args.method.upper(), args.url, headers, cookies, args.data or "")
    try:
        text = Path(args.request_file).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise TargetError(
            f"Could not read request file {args.request_file}: {exc}"
        ) from exc
    parsed = parse_raw_request(text, scheme=args.scheme)
    body = args.data if args.data is not None else parsed.body
    return Target(
        parsed.method,
        parsed.url,
        parsed.headers + headers,
        parsed.cookies + cookies,
        body,
    )


# ---------------------------------------------------------------------------------------------
# FUZZ positions and substitution
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Position:
    kind: str
    name: str = ""


def locate_positions(target: Target) -> list[Position]:
    positions = []
    if FUZZ_TOKEN in target.url:
        positions.append(Position("url"))
    positions.extend(
        Position("header", name)
        for name, value in target.headers
        if FUZZ_TOKEN in value
    )
    positions.extend(
        Position("cookie", name)
        for name, value in target.cookies
        if FUZZ_TOKEN in value
    )
    if FUZZ_TOKEN in target.body:
        positions.append(Position("body"))
    return positions


def substitute(target: Target, assignment: dict[Position, str]) -> Target:
    def sub(text: str, position: Position) -> str:
        payload = assignment.get(position)
        return text.replace(FUZZ_TOKEN, payload) if payload is not None else text

    url = sub(target.url, Position("url"))
    headers = [
        (name, sub(value, Position("header", name))) for name, value in target.headers
    ]
    cookies = [
        (name, sub(value, Position("cookie", name))) for name, value in target.cookies
    ]
    body = sub(target.body, Position("body"))
    return Target(target.method, url, headers, cookies, body)


def plan_index_tuples(position_count: int, payload_count: int, multi_fuzz: str):
    """Yield one tuple of payload indices per request, length == position_count."""
    if position_count == 0 or payload_count == 0:
        return
    if multi_fuzz == "combo" and position_count > 1:
        yield from itertools.product(range(payload_count), repeat=position_count)
    else:
        for index in range(payload_count):
            yield (index,) * position_count


# ---------------------------------------------------------------------------------------------
# Wordlist and payload construction (spec 1: case/affix/encoding variants)
# ---------------------------------------------------------------------------------------------


def load_wordlist(source: str, *, dedup: bool, keep_comments: bool) -> list[str]:
    if source == "-":
        raw = sys.stdin.read()
    else:
        try:
            raw = Path(source).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise TargetError(f"Could not read wordlist {source}: {exc}") from exc
    words: list[str] = []
    seen: set[str] = set()
    for line in raw.split("\n"):
        word = line.rstrip("\r")
        if not word.strip():
            continue
        if not keep_comments and word.lstrip().startswith("#"):
            continue
        if dedup:
            if word in seen:
                continue
            seen.add(word)
        words.append(word)
    return words


def apply_extensions(words: list[str], extensions: list[str]) -> list[str]:
    if not extensions:
        return list(words)
    expanded = list(words)
    for word in words:
        for extension in extensions:
            suffix = extension if extension.startswith(".") else f".{extension}"
            expanded.append(word + suffix)
    return expanded


def build_payload(
    word: str, *, transform: str, prefix: str, suffix: str, encoding: str
) -> str:
    text = word
    if transform == "upper":
        text = text.upper()
    elif transform == "lower":
        text = text.lower()
    text = f"{prefix}{text}{suffix}"
    if encoding == "url":
        text = quote(text, safe="")
    elif encoding == "base64":
        text = base64.b64encode(text.encode("utf-8")).decode("ascii")
    return text


def build_payloads(words: list[str], args: argparse.Namespace) -> list[str]:
    expanded = apply_extensions(words, args.extensions)
    return [
        build_payload(
            word,
            transform=args.transform,
            prefix=args.prefix,
            suffix=args.suffix,
            encoding=args.encoding,
        )
        for word in expanded
    ]


def order_payloads(
    payloads: list[str], *, randomize: bool, seed: int | None
) -> list[str]:
    if not randomize:
        return payloads
    shuffled = list(payloads)
    random.Random(seed).shuffle(shuffled)
    return shuffled


def payload_ref_for(index: int, ref_text: str) -> str:
    digest = hashlib.sha256(ref_text.encode("utf-8", "replace")).hexdigest()[:12]
    return f"{index}:{digest}"


def assignment_ref_text(assignment: dict[Position, str]) -> str:
    ordered = sorted(assignment.items(), key=lambda pair: (pair[0].kind, pair[0].name))
    return "|".join(
        f"{position.kind}:{position.name}={value}" for position, value in ordered
    )


# ---------------------------------------------------------------------------------------------
# Response filters (spec 1: status/size/words/lines/regex/header) and auto-calibration
# ---------------------------------------------------------------------------------------------


def parse_ranges(spec: str | None) -> frozenset[int] | None:
    if not spec:
        return None
    values: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, high = part.split("-", 1)
            values.update(range(int(low), int(high) + 1))
        else:
            values.add(int(part))
    return frozenset(values)


@dataclass
class Filters:
    match_code: frozenset[int] | None = None
    match_size: frozenset[int] | None = None
    match_words: frozenset[int] | None = None
    match_lines: frozenset[int] | None = None
    match_regex: re.Pattern | None = None
    match_header: tuple[str, re.Pattern] | None = None
    filter_code: frozenset[int] | None = None
    filter_size: frozenset[int] | None = None
    filter_words: frozenset[int] | None = None
    filter_lines: frozenset[int] | None = None
    filter_regex: re.Pattern | None = None


def _header_filter(spec: str | None) -> tuple[str, re.Pattern] | None:
    if not spec:
        return None
    name, sep, pattern = spec.partition(":")
    if not sep:
        raise TargetError("--match-header expects NAME:REGEX")
    return name.strip(), re.compile(pattern)


def build_filters(args: argparse.Namespace) -> Filters:
    return Filters(
        match_code=parse_ranges(args.match_code),
        match_size=parse_ranges(args.match_size),
        match_words=parse_ranges(args.match_words),
        match_lines=parse_ranges(args.match_lines),
        match_regex=re.compile(args.match_regex) if args.match_regex else None,
        match_header=_header_filter(args.match_header),
        filter_code=parse_ranges(args.filter_code),
        filter_size=parse_ranges(args.filter_size),
        filter_words=parse_ranges(args.filter_words),
        filter_lines=parse_ranges(args.filter_lines),
        filter_regex=re.compile(args.filter_regex) if args.filter_regex else None,
    )


def classify(
    *,
    status,
    size,
    words,
    lines,
    body_text,
    headers,
    filters: Filters,
    noise_signature: tuple | None,
    signature: tuple,
) -> str:
    if noise_signature is not None and signature == noise_signature:
        return "filtered"
    match_checks = []
    if filters.match_code is not None:
        match_checks.append(status in filters.match_code)
    if filters.match_size is not None:
        match_checks.append(size in filters.match_size)
    if filters.match_words is not None:
        match_checks.append(words in filters.match_words)
    if filters.match_lines is not None:
        match_checks.append(lines in filters.match_lines)
    if filters.match_regex is not None:
        match_checks.append(bool(filters.match_regex.search(body_text)))
    if filters.match_header is not None:
        name, pattern = filters.match_header
        match_checks.append(bool(pattern.search(headers.get(name, ""))))
    if match_checks and not all(match_checks):
        return "filtered"
    filter_checks = [
        filters.filter_code is not None and status in filters.filter_code,
        filters.filter_size is not None and size in filters.filter_size,
        filters.filter_words is not None and words in filters.filter_words,
        filters.filter_lines is not None and lines in filters.filter_lines,
        filters.filter_regex is not None
        and bool(filters.filter_regex.search(body_text)),
    ]
    if any(filter_checks):
        return "filtered"
    return "hit"


# ---------------------------------------------------------------------------------------------
# Pacing: policy is a ceiling skiff's own flags may only tighten, never loosen
# ---------------------------------------------------------------------------------------------


def effective_limits(profile, args: argparse.Namespace) -> tuple[int, float]:
    concurrency = max(1, min(args.threads, profile.concurrency))
    rps_cap = (
        min(args.rps, profile.requests_per_second)
        if args.rps
        else profile.requests_per_second
    )
    min_interval = max(1.0 / rps_cap if rps_cap > 0 else 0.0, args.delay or 0.0)
    return concurrency, min_interval


class Throttle:
    """A local, advisory minimum spacing between dispatches; not a safety boundary by itself."""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = min_interval
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if self.min_interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            target = max(now, self._next)
            if target > now:
                await asyncio.sleep(target - now)
            self._next = target + self.min_interval


# ---------------------------------------------------------------------------------------------
# Sending requests (spec 2: every request through egress, operation "fuzz")
# ---------------------------------------------------------------------------------------------


def describe_failure(exc: Exception) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(exc, egress.PolicyBlocked):
        return str(exc)
    if isinstance(exc, httpx.ConnectError):
        text = str(exc)
        return f"connection failed: {text}" if text else "connection failed"
    text = str(exc)
    return text or type(exc).__name__


def build_client(args: argparse.Namespace, verify: bool):
    timeout = httpx.Timeout(args.timeout, connect=min(10, args.timeout))
    kwargs = dict(
        operation=OPERATION,
        timeout=timeout,
        headers={"User-Agent": args.user_agent},
        verify=verify,
        follow_redirects=args.follow_redirects,
        trust_env=False,
    )
    if args.proxy:
        kwargs["proxy"] = args.proxy
    return egress.async_client(**kwargs)


@dataclass
class Measurement:
    index: int
    ref_text: str
    run_id: str
    status: int | None
    size: int
    words: int
    lines: int
    time_ms: int
    redirects: int
    final_url: str
    body_text: str
    headers: dict
    error: str = ""

    def signature(self) -> tuple:
        return (self.status, self.size)

    def to_outcome(self, classification: str) -> dict:
        row = {
            "run_id": self.run_id,
            "payload_ref": payload_ref_for(self.index, self.ref_text),
            "status": self.status,
            "size": self.size,
            "words": self.words,
            "lines": self.lines,
            "time_ms": self.time_ms,
            "redirects": self.redirects,
            "final_url": self.final_url,
            "classification": classification,
        }
        if self.error:
            row["error"] = self.error
        return row


async def measure(
    client,
    throttle: Throttle,
    gate: asyncio.Semaphore,
    request_target: Target,
    index: int,
    ref_text: str,
) -> Measurement:
    headers = list(request_target.headers)
    if request_target.cookies:
        headers.append(
            (
                "Cookie",
                "; ".join(f"{name}={value}" for name, value in request_target.cookies),
            )
        )
    body = (
        request_target.body.encode("utf-8", "replace") if request_target.body else None
    )
    request = httpx.Request(
        request_target.method, request_target.url, headers=headers, content=body
    )
    async with gate:
        await throttle.wait()
        started = time.perf_counter()
        try:
            response = await client.send(request)
        except (httpx.HTTPError, egress.PolicyBlocked) as exc:
            return Measurement(
                index,
                ref_text,
                "",
                None,
                0,
                0,
                0,
                0,
                0,
                "",
                "",
                {},
                describe_failure(exc),
            )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    body_text = response.text
    return Measurement(
        index=index,
        ref_text=ref_text,
        run_id=response.extensions.get("bughunt_run_id", ""),
        status=response.status_code,
        size=len(response.content),
        words=len(body_text.split()),
        lines=len(body_text.splitlines()),
        time_ms=elapsed_ms,
        redirects=len(response.history),
        final_url=str(response.url),
        body_text=body_text,
        headers=dict(response.headers),
    )


async def calibrate(
    client,
    throttle: Throttle,
    gate: asyncio.Semaphore,
    target: Target,
    positions: list[Position],
    seed: int | None,
) -> tuple | None:
    """Probe throwaway payloads before the run; a shared (status, size) signature is noise."""
    rng = random.Random(seed)
    signatures = []
    for _ in range(CALIBRATION_PROBES):
        token = "zzcalibrate" + format(rng.getrandbits(64), "x")
        assignment = {position: token for position in positions}
        measured = await measure(
            client, throttle, gate, substitute(target, assignment), -1, "calibration"
        )
        if measured.error:
            return None
        signatures.append(measured.signature())
    return signatures[0] if len(set(signatures)) == 1 else None


async def run_fuzz(
    target: Target,
    positions: list[Position],
    payload_words: list[str],
    args: argparse.Namespace,
    profile,
    filters: Filters,
) -> tuple[list[dict], int, bool]:
    concurrency, min_interval = effective_limits(profile, args)
    gate = asyncio.Semaphore(concurrency)
    throttle = Throttle(min_interval)
    combos = list(
        plan_index_tuples(len(positions), len(payload_words), args.multi_fuzz)
    )
    async with build_client(args, args.verify_ssl) as client:
        noise_signature = None
        if args.auto_calibrate and positions:
            noise_signature = await calibrate(
                client, throttle, gate, target, positions, args.seed
            )

        async def one(index: int, combo: tuple[int, ...]) -> Measurement:
            assignment = {
                position: payload_words[payload_index]
                for position, payload_index in zip(positions, combo)
            }
            ref_text = assignment_ref_text(assignment)
            return await measure(
                client, throttle, gate, substitute(target, assignment), index, ref_text
            )

        measurements = list(
            await asyncio.gather(*(one(i, combo) for i, combo in enumerate(combos)))
        )
    outcomes = []
    for measurement in measurements:
        classification = (
            "error"
            if measurement.error
            else classify(
                status=measurement.status,
                size=measurement.size,
                words=measurement.words,
                lines=measurement.lines,
                body_text=measurement.body_text,
                headers=measurement.headers,
                filters=filters,
                noise_signature=noise_signature,
                signature=measurement.signature(),
            )
        )
        outcomes.append(measurement.to_outcome(classification))
    return outcomes, len(combos), noise_signature is not None


# ---------------------------------------------------------------------------------------------
# The typed result envelope (spec 4)
# ---------------------------------------------------------------------------------------------


def build_envelope(
    *,
    run_id: str,
    target: Target,
    profile,
    actor: str,
    started_at: str,
    finished_at: str,
    outcomes: list[dict],
    requests_planned: int,
    requests_sent: int,
    requests_per_second_effective: float,
    auto_calibrated: bool,
) -> dict:
    hit_count = sum(1 for row in outcomes if row["classification"] == "hit")
    by_status: dict[str, int] = {}
    for row in outcomes:
        if row["status"] is not None:
            key = str(row["status"])
            by_status[key] = by_status.get(key, 0) + 1
    exit_code = 0 if hit_count else 1
    return {
        "schema_version": SCHEMA_VERSION,
        "run": {
            "run_id": run_id,
            "tool": TOOL_NAME,
            "operation": OPERATION,
            "actor": actor,
            "policy_version": profile.policy_version,
            "target": target.url,
            "method": target.method,
            "started_at": started_at,
            "finished_at": finished_at,
            "requests_planned": requests_planned,
            "requests_sent": requests_sent,
            "requests_per_second_effective": requests_per_second_effective,
        },
        "outcomes": outcomes,
        "findings_summary": {
            "hit_count": hit_count,
            "by_status": by_status,
            "auto_calibrated": auto_calibrated,
        },
        "exit_code": exit_code,
    }


# ---------------------------------------------------------------------------------------------
# Display and exports
# ---------------------------------------------------------------------------------------------


def render_dry_run(
    target: Target,
    positions: list[Position],
    payload_words: list[str],
    requests_planned: int,
    args: argparse.Namespace,
) -> None:
    display = Console(highlight=False, no_color=not args.color)
    where = ", ".join(
        position.kind + (f":{position.name}" if position.name else "")
        for position in positions
    )
    body = (
        f"target: {target.method} {target.url}\npositions: {where}\n"
        f"wordlist entries: {len(payload_words)} | multi-fuzz: {args.multi_fuzz} | "
        f"planned requests: {requests_planned}"
    )
    display.print(Panel(Text(body), title="skiff dry-run", expand=False))


def render_results(envelope: dict, args: argparse.Namespace) -> None:
    display = Console(highlight=False, no_color=not args.color)
    run, summary = envelope["run"], envelope["findings_summary"]
    header = (
        f"{run['requests_sent']} sent | {summary['hit_count']} hits | "
        f"{run['requests_per_second_effective']} req/s effective | {run['method']} {run['target']}"
    )
    display.print(Panel(Text(header), title="skiff", expand=False))
    rows = (
        envelope["outcomes"]
        if args.verbose
        else [row for row in envelope["outcomes"] if row["classification"] == "hit"]
    )
    table = Table(box=box.SIMPLE_HEAD, header_style="bold")
    for column in (
        "Status",
        "Size",
        "Words",
        "Lines",
        "ms",
        "Payload ref",
        "Final URL",
        "Classification",
    ):
        table.add_column(column)
    for row in rows:
        table.add_row(
            str(row["status"]) if row["status"] is not None else "----",
            str(row["size"]),
            str(row["words"]),
            str(row["lines"]),
            str(row["time_ms"]),
            row["payload_ref"],
            row["final_url"],
            row["classification"],
        )
    display.print(table)
    if not rows:
        display.print("No results matched the current filter.")


_CSV_COLUMNS = (
    "run_id",
    "payload_ref",
    "status",
    "size",
    "words",
    "lines",
    "time_ms",
    "redirects",
    "final_url",
    "classification",
    "error",
)


def export_results(
    path: str, output_format: str, envelope: dict, *, notify: bool = True
) -> None:
    if output_format == "json":
        Path(path).write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    elif output_format == "jsonl":
        lines = [json.dumps(row) for row in envelope["outcomes"]]
        Path(path).write_text(
            "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
        )
    elif output_format == "csv":
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=_CSV_COLUMNS)
            writer.writeheader()
            for row in envelope["outcomes"]:
                writer.writerow(
                    {column: row.get(column, "") for column in _CSV_COLUMNS}
                )
    else:
        hits = [row for row in envelope["outcomes"] if row["classification"] == "hit"]
        lines = [
            f"[{row['status']}] {row['payload_ref']} size={row['size']} words={row['words']} "
            f"final_url={row['final_url']}"
            for row in hits
        ]
        Path(path).write_text(
            "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
        )
    if notify:
        console.print(f"Wrote {output_format} export: {path}")


# ---------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------


def _add_target_options(parser: argparse.ArgumentParser) -> None:
    target = parser.add_argument_group("target")
    target.add_argument(
        "-u", "--url", help="target URL; include FUZZ where a payload belongs"
    )
    target.add_argument(
        "--request-file",
        metavar="FILE",
        help="raw HTTP request file with FUZZ placeholder(s), instead of --url",
    )
    target.add_argument(
        "--scheme",
        choices=("http", "https"),
        default="https",
        help="scheme for a --request-file whose first line is a relative path "
        "(default: %(default)s)",
    )
    target.add_argument(
        "-w",
        "--wordlist",
        required=True,
        metavar="FILE",
        help="path to a wordlist file, or - to read entries from stdin",
    )


def _add_shape_options(parser: argparse.ArgumentParser) -> None:
    shape = parser.add_argument_group("request shape")
    shape.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        metavar="N",
        help="advisory concurrency cap; tightens the policy's own cap, never "
        "loosens it (default: %(default)s)",
    )
    shape.add_argument(
        "-m",
        "--method",
        default="GET",
        metavar="METHOD",
        help="HTTP method for --url (--request-file keeps its own); default: %(default)s",
    )
    shape.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="extra header; repeatable; may contain FUZZ",
    )
    shape.add_argument(
        "-c",
        "--cookie",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="extra cookie; repeatable; may contain FUZZ",
    )
    shape.add_argument(
        "-d",
        "--data",
        default=None,
        metavar="BODY",
        help="request body; may contain FUZZ",
    )
    shape.add_argument(
        "-p",
        "--proxy",
        default=None,
        metavar="URL",
        help="forward through this HTTP(S) proxy (also policy-checked)",
    )
    shape.add_argument(
        "--follow-redirects",
        action="store_true",
        default=False,
        help="follow redirects; each hop is authorized like the first request",
    )
    shape.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="per-request timeout in seconds (default: %(default)s)",
    )
    shape.add_argument(
        "--rps",
        type=float,
        default=None,
        metavar="N",
        help="advisory requests/second cap; tightens the policy's rate, never loosens it",
    )
    shape.add_argument(
        "--delay",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="advisory minimum spacing between dispatches (default: %(default)s)",
    )
    shape.add_argument(
        "--user-agent",
        default=DEFAULT_USER_AGENT,
        metavar="UA",
        help="User-Agent to request; an active policy profile may override it",
    )
    shape.add_argument(
        "-x",
        "--extensions",
        action="append",
        default=[],
        metavar="EXT",
        help="also send each payload with this suffix appended; repeatable",
    )
    shape.add_argument(
        "--transform",
        choices=("none", "upper", "lower"),
        default="none",
        help="case transform applied to every payload (default: %(default)s)",
    )
    shape.add_argument(
        "--prefix", default="", metavar="TEXT", help="text prepended to every payload"
    )
    shape.add_argument(
        "--suffix", default="", metavar="TEXT", help="text appended to every payload"
    )
    shape.add_argument(
        "--multi-fuzz",
        choices=("same", "combo"),
        default="same",
        help="with more than one FUZZ position: same wordlist index everywhere "
        "(same) or the full cartesian product (combo); default: %(default)s",
    )
    shape.add_argument(
        "--encoding",
        dest="encoding",
        choices=("url", "none", "base64"),
        default="url",
        help="payload encoding before substitution; --base64 and "
        "--no-encode are shorthands for base64 and none (default: %(default)s)",
    )
    shape.add_argument(
        "--base64",
        dest="encoding",
        action="store_const",
        const="base64",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    shape.add_argument(
        "--no-encode",
        dest="encoding",
        action="store_const",
        const="none",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )
    shape.add_argument(
        "--randomize",
        action="store_true",
        default=False,
        help="shuffle the wordlist order before sending",
    )
    shape.add_argument(
        "--seed",
        type=int,
        default=None,
        metavar="N",
        help="seed for --randomize and --auto-calibrate (default: unseeded)",
    )
    shape.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="print the plan and exit without sending any request",
    )
    shape.add_argument(
        "--no-dedup",
        action="store_true",
        default=False,
        help="keep duplicate wordlist entries instead of deduplicating them",
    )
    shape.add_argument(
        "--keep-comments",
        action="store_true",
        default=False,
        help="keep wordlist lines starting with # instead of skipping them",
    )
    shape.add_argument(
        "--authorized",
        action="store_true",
        default=False,
        help="no-op confirmation echo; the policy gate is the only real check",
    )
    shape.add_argument(
        "--ignore-ssl",
        dest="verify_ssl",
        action="store_false",
        default=True,
        help="disable TLS certificate verification; --no-ignore-ssl explicitly keeps "
        "it on (default: verification is ON)",
    )
    shape.add_argument(
        "--no-ignore-ssl",
        dest="verify_ssl",
        action="store_true",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )


def _add_output_options(parser: argparse.ArgumentParser) -> None:
    output = parser.add_argument_group("output")
    output.add_argument(
        "-o", "--output", metavar="FILE", help="write the typed result to FILE"
    )
    output.add_argument(
        "-of",
        "--output-format",
        choices=("txt", "json", "jsonl", "csv"),
        default="txt",
        help="format for --output (default: %(default)s)",
    )
    output.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="show filtered outcomes too, not only hits",
    )
    output.add_argument(
        "--silent",
        action="store_true",
        default=False,
        help="print nothing but errors to stdout",
    )
    output.add_argument(
        "--color",
        dest="color",
        action="store_true",
        default=True,
        help=argparse.SUPPRESS,
    )
    output.add_argument(
        "--no-color",
        dest="color",
        action="store_false",
        default=argparse.SUPPRESS,
        help="disable color in table output",
    )


def _add_filter_options(parser: argparse.ArgumentParser) -> None:
    filters = parser.add_argument_group("filters")
    filters.add_argument(
        "-mc", "--match-code", metavar="CODES", help="keep only these status codes"
    )
    filters.add_argument(
        "-fc", "--filter-code", metavar="CODES", help="drop these status codes"
    )
    filters.add_argument(
        "-ms", "--match-size", metavar="SIZES", help="keep only these response sizes"
    )
    filters.add_argument(
        "-fs", "--filter-size", metavar="SIZES", help="drop these response sizes"
    )
    filters.add_argument(
        "-mw", "--match-words", metavar="COUNTS", help="keep only these word counts"
    )
    filters.add_argument(
        "-fw", "--filter-words", metavar="COUNTS", help="drop these word counts"
    )
    filters.add_argument(
        "-ml", "--match-lines", metavar="COUNTS", help="keep only these line counts"
    )
    filters.add_argument(
        "-fl", "--filter-lines", metavar="COUNTS", help="drop these line counts"
    )
    filters.add_argument(
        "--match-regex", metavar="REGEX", help="keep only responses whose body matches"
    )
    filters.add_argument(
        "--filter-regex", metavar="REGEX", help="drop responses whose body matches"
    )
    filters.add_argument(
        "--match-header",
        metavar="NAME:REGEX",
        help="keep only responses whose NAME header matches REGEX",
    )
    filters.add_argument(
        "--auto-calibrate",
        action="store_true",
        default=False,
        help="probe baseline noise with throwaway payloads and filter matching responses",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skiff",
        description="Substitute FUZZ in a URL, raw request file, headers, cookies or body with "
        "entries from a wordlist file, send each request through the policy-gated "
        "egress client, and report hits by response filter.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    _add_target_options(parser)
    _add_shape_options(parser)
    _add_output_options(parser)
    _add_filter_options(parser)
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        dest=argparse.SUPPRESS,
        version=f"skiff (bughunt {BUGHUNT_VERSION})",
    )
    return parser


@dataclass
class RunPlan:
    target: Target
    positions: list[Position]
    payload_words: list[str]
    filters: Filters
    profile: object
    requests_planned: int


def prepare_run(args: argparse.Namespace) -> RunPlan | int:
    """Everything that can fail before a request is sent; returns the exit code on failure."""
    try:
        target = build_target_from_args(args)
    except TargetError as exc:
        console.print(str(exc))
        return 2
    host = hostname_of(target.url)
    if not host or not allowed(target.url):
        if not args.silent:
            console.print(explain_block(host or target.url))
        return 2
    positions = locate_positions(target)
    if not positions:
        if not args.silent:
            console.print(
                "No FUZZ placeholder found in the URL, headers, cookies or body."
            )
        return 2
    try:
        filters = build_filters(args)
    except (TargetError, re.error, ValueError) as exc:
        console.print(str(exc))
        return 2
    try:
        words = load_wordlist(
            args.wordlist, dedup=not args.no_dedup, keep_comments=args.keep_comments
        )
    except TargetError as exc:
        console.print(str(exc))
        return 1
    if not words:
        console.print(f"No wordlist entries found in {args.wordlist}")
        return 1
    payload_words = order_payloads(
        build_payloads(words, args), randomize=args.randomize, seed=args.seed
    )
    try:
        profile = egress.authorize(target.url, OPERATION, target.method)
    except egress.PolicyBlocked as exc:
        console.print(str(exc))
        return 2
    planned = len(
        list(plan_index_tuples(len(positions), len(payload_words), args.multi_fuzz))
    )
    return RunPlan(target, positions, payload_words, filters, profile, planned)


def produce_run(plan: RunPlan, args: argparse.Namespace) -> dict:
    run_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()
    actor = identity.selection_signature()[1]
    outcomes, requests_sent, auto_calibrated = asyncio.run(
        run_fuzz(
            plan.target,
            plan.positions,
            plan.payload_words,
            args,
            plan.profile,
            plan.filters,
        )
    )
    finished_at = datetime.now(timezone.utc).isoformat()
    _, min_interval = effective_limits(plan.profile, args)
    effective_rps = (
        round(1.0 / min_interval, 4)
        if min_interval > 0
        else plan.profile.requests_per_second
    )
    envelope = build_envelope(
        run_id=run_id,
        target=plan.target,
        profile=plan.profile,
        actor=actor,
        started_at=started_at,
        finished_at=finished_at,
        outcomes=outcomes,
        requests_planned=plan.requests_planned,
        requests_sent=requests_sent,
        requests_per_second_effective=effective_rps,
        auto_calibrated=auto_calibrated,
    )
    return envelope


def execute_run(plan: RunPlan, args: argparse.Namespace) -> int:
    try:
        envelope = produce_run(plan, args)
    except KeyboardInterrupt:
        console.print("Interrupted.")
        return 130
    if not args.silent:
        render_results(envelope, args)
    if args.output:
        export_results(args.output, args.output_format, envelope)
    return envelope["exit_code"]


def run_structured(args, *, dry_run=False):
    from bughunt.core.addon_adapters import external, planned

    if args.wordlist == "-":
        raise ValueError("Embedding requires a wordlist file")
    target = build_target_from_args(args)
    if not allowed(target.url):
        raise ValueError("Target is outside scope")
    positions = locate_positions(target)
    if not positions:
        raise ValueError("No FUZZ placeholder found")
    filters = build_filters(args)
    words = load_wordlist(
        args.wordlist, dedup=not args.no_dedup, keep_comments=args.keep_comments
    )
    if not words:
        raise ValueError("Empty wordlist")
    payloads = order_payloads(
        build_payloads(words, args), randomize=args.randomize, seed=args.seed
    )
    count = sum(
        1 for _ in plan_index_tuples(len(positions), len(payloads), args.multi_fuzz)
    )
    if dry_run or args.dry_run:
        return planned("skiff", "default", requests=count, target=target.url)
    profile = egress.authorize(target.url, OPERATION, target.method)
    plan = RunPlan(target, positions, payloads, filters, profile, count)
    envelope = produce_run(plan, args)
    if args.output:
        export_results(args.output, args.output_format, envelope, notify=False)
    status = (
        "partial"
        if any(row.get("error") for row in envelope["outcomes"])
        else "success"
    )
    return external("skiff", "default", envelope, status=status)


def run_main(args: argparse.Namespace) -> int:
    if args.authorized and not args.silent:
        console.print(
            "--authorized is a no-op; the policy gate is the sole authorization check."
        )
    plan = prepare_run(args)
    if isinstance(plan, int):
        return plan
    if args.dry_run:
        render_dry_run(
            plan.target, plan.positions, plan.payload_words, plan.requests_planned, args
        )
        return 0
    return execute_run(plan, args)


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(run_main(args))


if __name__ == "__main__":
    main()
