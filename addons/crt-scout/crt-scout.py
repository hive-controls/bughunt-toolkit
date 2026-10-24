"""Subdomain discovery for one apex domain, backed by the crt.name certificate-transparency index.

Run it through the toolkit as ``bughunt ct <domain>`` (alias ``crt-scout``). The domain must be
in scope, and every outbound request (the crt.name lookup and any liveness probe) goes through
``bughunt.core.egress``, so it also needs a matching grant in the mission policy.
"""

import argparse
import asyncio
import string
import sys
from datetime import date
from pathlib import Path
from typing import NamedTuple

import httpx

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from bughunt.core import egress, workspace
from bughunt.core.http import api_client, get_following, redirect_target

API_HOSTS = frozenset({"crt.name"})
SEARCH_ENDPOINT = "https://crt.name/v1/search"
API_REDIRECT_LIMIT = 5
PROBE_REDIRECT_LIMIT = 10
SUMMARY_ROWS = 20
DEAD = "dead"
BLOCKED = "blocked"
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
COMMON_LABELS = frozenset("www mail ftp blog shop".split())
ARROW = "→"

EXAMPLES = """\
examples:
  %(prog)s example.com
  %(prog)s example.com -c --show-dead
  %(prog)s example.com -c --https-only -o live.txt
  %(prog)s example.com -w prefixes.txt -q
"""

_ROLE_SGR = {
    "info": 94,
    "success": 92,
    "warning": 93,
    "error": 91,
    "heading": 96,
    "live": 92,
    "dead": 91,
}
_SGR_RESET = "\x1b[0m"

_ALNUM = frozenset(string.ascii_letters + string.digits)
_LABEL_CHARS = _ALNUM | {"-"}


class ProbeResult(NamedTuple):
    host: str
    scheme: str
    status: int | None


def paint(role: str, text: str) -> str:
    return f"\x1b[{_ROLE_SGR[role]}m{text}{_SGR_RESET}"


def say(role: str, message: str) -> None:
    print(paint(role, message), file=sys.stderr)


def counted(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def is_valid_domain_argument(text: str) -> bool:
    labels = text.split(".")
    return len(labels) >= 2 and all(
        label != "" and label[0] in _ALNUM and set(label) <= _LABEL_CHARS
        for label in labels
    )


def _is_plain_label(label: str) -> bool:
    return (
        0 < len(label) <= 63
        and label[0] in _ALNUM
        and label[-1] in _ALNUM
        and set(label) <= _LABEL_CHARS
    )


def is_certificate_hostname(name: str) -> bool:
    if not 0 < len(name) <= 253:
        return False
    *leading, top = name.split(".")
    if not leading or not all(_is_plain_label(label) for label in leading):
        return False
    return (
        2 <= len(top) <= 63 and top[0] in string.ascii_letters and _is_plain_label(top)
    )


def parse_listing(body: str) -> set[str]:
    """First token of each non-blank line, lower-cased and stripped of trailing dots."""
    names = set()
    for line in body.splitlines():
        tokens = line.split()
        if tokens:
            names.add(tokens[0].lower().rstrip("."))
    return names


def prefix_labels(name: str, domain: str) -> list[str]:
    prefix = name.removesuffix(domain).removesuffix(".")
    return [label for label in prefix.split(".") if label]


def format_live_line(record: ProbeResult) -> str:
    return f"[LIVE] {record.scheme}://{record.host}  {ARROW}  HTTP {record.status}"


class ProgressTicker:
    """Rewrites a ``done/total`` counter on stderr; silent when disabled."""

    def __init__(self, total: int, enabled: bool) -> None:
        self.total = total
        self.enabled = enabled
        self.done = 0

    def tick(self) -> None:
        self.done += 1
        if self.enabled:
            sys.stderr.write(f"\r{self.done}/{self.total}")
            sys.stderr.flush()

    def close(self) -> None:
        if self.enabled:
            sys.stderr.write("\n")
            sys.stderr.flush()


class CrtScout:
    def __init__(self, domain: str, args: argparse.Namespace) -> None:
        self.domain = domain
        self.args = args
        self.subdomains: set[str] = set()
        self.listing_dates: dict[str, set[str]] = {}
        self.results: list[ProbeResult] = []
        self.lookup_failed = False

    def _api(self):
        return api_client(API_HOSTS, timeout=30, headers={"User-Agent": self.args.ua})

    def _probe_client(self):
        return egress.async_client(
            operation="crawl",
            headers={"User-Agent": self.args.ua},
            timeout=httpx.Timeout(self.args.timeout + 3, connect=self.args.timeout),
            limits=httpx.Limits(max_connections=100),
            verify=not self.args.insecure,
            trust_env=False,
            follow_redirects=False,
        )

    def keep_name(self, name: str) -> bool:
        return (
            is_certificate_hostname(name)
            and (name == self.domain or name.endswith("." + self.domain))
            and workspace.allowed(name)
        )

    def _download_listing(self, query: dict[str, str]) -> str | None:
        try:
            with self._api() as client:
                response = get_following(
                    client, SEARCH_ENDPOINT, params=query, limit=API_REDIRECT_LIMIT
                )
        except httpx.TimeoutException:
            say("error", "crt.name did not answer before the timeout")
            return None
        except httpx.HTTPError as exc:
            say("error", f"crt.name lookup failed: {exc}")
            return None
        if response.status_code != 200:
            say("error", f"crt.name replied with HTTP {response.status_code}")
            return None
        return response.text

    async def fetch_subdomains(self) -> set[str]:
        query = {"apex": self.domain}
        if self.args.dates:
            query["dates"] = "1"
        say("info", f"asking crt.name about {self.domain}")
        body = self._download_listing(query)
        if body is None:
            self.lookup_failed = True
            return self.subdomains
        candidates = parse_listing(body)
        kept = {name for name in candidates if self.keep_name(name)}
        dropped = len(candidates) - len(kept)
        if dropped:
            say(
                "warning",
                f"skipped {counted(dropped, 'name')} "
                f"(not a hostname under {self.domain}, or out of scope)",
            )
        if not kept:
            say("error", f"no subdomains returned for {self.domain}")
            return self.subdomains
        self.subdomains = kept
        if self.args.dates:
            self._record_listing_dates(body)
        say("success", f"found {counted(len(kept), 'unique subdomain')}")
        return self.subdomains

    def _record_listing_dates(self, body: str) -> None:
        for line in body.splitlines():
            fields = line.split()
            if not fields:
                continue
            name = fields[0].lower().rstrip(".")
            if name not in self.subdomains:
                continue
            for token in fields[1:]:
                try:
                    supplied_date = date.fromisoformat(token).isoformat()
                except ValueError:
                    continue
                self.listing_dates.setdefault(name, set()).add(supplied_date)

    def _with_listing_dates(self, line: str, name: str) -> str:
        dates = self.listing_dates.get(name)
        return f"{line} [dates: {', '.join(sorted(dates))}]" if dates else line

    def _save_wordlist(self) -> None:
        target = self.args.wordlist
        labels = sorted(
            {
                label
                for name in self.subdomains
                for label in prefix_labels(name, self.domain)
            }
            - COMMON_LABELS
        )
        try:
            # Always UTF-8 (a cp1252 locale cannot encode the arrow); the platform newline is kept (tracked defect D4).
            with open(target, "w", encoding="utf-8") as handle:
                handle.writelines(f"{label}\n" for label in labels)
        except OSError as exc:
            say("error", f"could not write wordlist {target}: {exc}")
            raise SystemExit(1) from exc
        say(
            "success",
            f"wordlist with {counted(len(labels), 'entry')} saved to {target}",
        )

    def _schemes_to_try(self) -> tuple[str, ...]:
        return ("https",) if self.args.https_only else ("https", "http")

    async def status_in_scope(self, session, url: str) -> int:
        """GET ``url`` and follow redirects only while each hop is in scope and permitted."""
        current = url
        for _ in range(PROBE_REDIRECT_LIMIT + 1):
            egress.authorize(current, "crawl")
            response = await session.get(current)
            following = redirect_target(current, response)
            if not following or not workspace.allowed(following):
                return response.status_code
            current = following
        return response.status_code

    async def check_host(self, session, host: str) -> ProbeResult:
        if not workspace.allowed(host):
            return ProbeResult(host, BLOCKED, None)
        for scheme in self._schemes_to_try():
            try:
                status = await self.status_in_scope(session, f"{scheme}://{host}")
            except egress.PolicyBlocked:
                return ProbeResult(host, BLOCKED, None)
            except httpx.HTTPError:
                continue
            return ProbeResult(host, scheme, status)
        return ProbeResult(host, DEAD, None)

    async def _probe_one(
        self, gate, session, host: str, ticker: ProgressTicker
    ) -> None:
        async with gate:
            outcome = await self.check_host(session, host)
        self.results.append(outcome)
        ticker.tick()

    async def check_all_hosts(self) -> None:
        hosts = sorted(self.subdomains)
        say(
            "info",
            f"probing {counted(len(hosts), 'host')} (connect timeout {self.args.timeout}s, "
            f"up to {self.args.workers} at a time)",
        )
        print(file=sys.stderr)
        gate = asyncio.Semaphore(self.args.workers)
        ticker = ProgressTicker(len(hosts), enabled=not self.args.quiet)
        async with self._probe_client() as session:
            await asyncio.gather(
                *(self._probe_one(gate, session, host, ticker) for host in hosts)
            )
        ticker.close()

    def _save_report(self, lines: list[str], live: list[ProbeResult]) -> None:
        target = self.args.output
        try:
            # Always UTF-8 (a cp1252 locale cannot encode the arrow); the platform newline is kept (tracked defect D4).
            with open(target, "w", encoding="utf-8") as handle:
                handle.writelines(f"{line}\n" for line in lines)
        except OSError as exc:
            say("error", f"could not write {target}: {exc}")
            raise SystemExit(1) from exc
        say("success", f"results saved to {target}")
        say("success", f"live hosts: {len(live)}")
        if not live:
            return
        say("heading", "responding URLs:")
        for record in live[:SUMMARY_ROWS]:
            print(
                f"  {record.scheme}://{record.host} ({record.status})", file=sys.stderr
            )
        if len(live) > SUMMARY_ROWS:
            print(f"  ... and {len(live) - SUMMARY_ROWS} more", file=sys.stderr)

    def _present_results(self) -> None:
        live = sorted(
            (record for record in self.results if record.status is not None),
            key=lambda record: (record.scheme, record.status),
        )
        live_lines = [
            self._with_listing_dates(format_live_line(record), record.host)
            for record in live
        ]
        dead_lines = []
        blocked_lines = []
        if self.args.show_dead:
            dead_hosts = sorted(r.host for r in self.results if r.scheme == DEAD)
            dead_lines = [
                self._with_listing_dates(f"[DEAD] {host}", host) for host in dead_hosts
            ]
            blocked_lines = [
                self._with_listing_dates(f"[BLOCKED] {host}", host)
                for host in sorted(r.host for r in self.results if r.scheme == BLOCKED)
            ]
        if self.args.output:
            self._save_report(live_lines + dead_lines + blocked_lines, live)
            return
        for line in live_lines:
            print(paint("live", line))
        for line in dead_lines:
            print(paint("dead", line))
        for line in blocked_lines:
            print(paint("warning", line))

    async def run(self) -> None:
        await self.fetch_subdomains()
        if not self.subdomains:
            return
        if self.args.wordlist:
            self._save_wordlist()
        if not self.args.check:
            names = [
                self._with_listing_dates(name, name) for name in sorted(self.subdomains)
            ]
            if self.args.output:
                try:
                    with open(self.args.output, "w", encoding="utf-8") as handle:
                        handle.writelines(f"{name}\n" for name in names)
                except OSError as exc:
                    say("error", f"could not write {self.args.output}: {exc}")
                    raise SystemExit(1) from exc
                say("success", f"results saved to {self.args.output}")
            else:
                for name in names:
                    print(name)
            return
        await self.check_all_hosts()
        self._present_results()


def run_structured(args, *, dry_run=False):
    from bughunt.core.addon_adapters import external, planned
    from bughunt.core.results import Artifact

    if (
        args.workers < 1
        or args.timeout <= 0
        or not is_valid_domain_argument(args.domain)
    ):
        raise ValueError("A valid domain and positive workers/timeout are required")
    domain = args.domain.lower()
    if not workspace.allowed(domain):
        raise ValueError("Domain is outside scope")
    if dry_run:
        return planned("ct", "default", domain=domain, probe=args.check)
    egress.authorize(egress.host_target(domain, "passive"), "passive")
    scout = CrtScout(domain, args)
    asyncio.run(scout.fetch_subdomains())
    if args.check and scout.subdomains:
        asyncio.run(scout.check_all_hosts())
    if args.wordlist:
        scout._save_wordlist()
    if args.output:
        lines = [
            scout._with_listing_dates(name, name) for name in sorted(scout.subdomains)
        ]
        if args.check:
            lines = [
                format_live_line(row) for row in scout.results if row.status is not None
            ]
        Path(args.output).write_text(
            "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
        )
    status = "failed" if scout.lookup_failed else "success"
    if any(row.scheme == BLOCKED for row in scout.results):
        status = "blocked"
    output = external(
        "ct",
        "default",
        {
            "hosts": sorted(scout.subdomains),
            "dates": {
                name: sorted(dates) for name, dates in scout.listing_dates.items()
            },
            "probes": [row._asdict() for row in scout.results],
        },
        status=status,
    )
    output.artifacts.append(
        Artifact.create("hosts", {"hosts": sorted(scout.subdomains)})
    )
    urls = [
        f"{row.scheme}://{row.host}" for row in scout.results if row.status is not None
    ]
    if urls:
        output.artifacts.append(Artifact.create("urls", {"urls": urls}))
    return output


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Find subdomains of one in-scope apex domain from certificate-transparency "
        "data, optionally check which ones answer, and optionally export their name prefixes.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domain", help="apex domain to enumerate, such as example.com")
    parser.add_argument(
        "-c",
        "--check",
        action="store_true",
        help="probe every name over HTTPS, then HTTP, and report the ones that answer",
    )
    parser.add_argument(
        "--https-only", action="store_true", help="with --check, probe over HTTPS only"
    )
    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="do not verify TLS certificates on probes (the crt.name lookup is "
        "always verified)",
    )
    parser.add_argument(
        "--ua",
        default=DEFAULT_USER_AGENT,
        help="User-Agent to request; an active policy profile may override it",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the result lines to FILE instead of stdout",
    )
    parser.add_argument(
        "-w",
        "--wordlist",
        metavar="FILE",
        help="write the unique subdomain prefixes to FILE, one per line",
    )
    parser.add_argument(
        "-d",
        "--dates",
        action="store_true",
        help="ask crt.name to include dates in its listing",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        metavar="SECONDS",
        help="probe connect timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        metavar="N",
        help="maximum hosts probed at once (default: %(default)s)",
    )
    parser.add_argument(
        "--show-dead",
        action="store_true",
        help="with --check, also list the hosts that did not answer",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="hide the probe progress counter"
    )
    return parser


async def main() -> None:
    parser = create_parser()
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if not is_valid_domain_argument(args.domain):
        say("error", f"not a valid domain name: {args.domain}")
        sys.exit(1)
    domain = args.domain.lower()
    if not workspace.allowed(domain):
        print(workspace.explain_block(domain), file=sys.stderr)
        sys.exit(2)
    scout = CrtScout(domain, args)
    egress.authorize(egress.host_target(domain, "passive"), "passive")
    await scout.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        say("warning", "interrupted")
        sys.exit(130)
