"""Read robots.txt and sitemap files and list the URLs they name, ready for pulse.

Local files stay local. --fetch requests one in-scope http(s) URL, and nested sitemaps stop at ten.
The URL list goes to stdout; the summary goes to stderr.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from urllib.parse import urljoin

import httpx

from bughunt.core import crawlhints, pagefetch
from bughunt.core.crawlhints import is_sitemap_index, sitemap_locs
from bughunt.core.pagefetch import (
    FetchError,
    Halt,
    ScopeError,
    is_web_url,
    report_error,
    report_note,
)
from bughunt.core.workspace import (
    allowed,
    authority,
    explain_target,
    remember_urls,
    scope_is_active,
    urls_path,
)

_SITEMAP_BUDGET = 10
_SITEMAP_SNIFF = 800
_SITEMAP_MARKERS = ("<urlset", "<sitemapindex", "<loc")
_FETCH_TIMEOUT = 10.0
_DIRECTIVE_KINDS = {"allow": "path", "disallow": "path", "sitemap": "sitemap"}

_OPTIONS = (
    (("inputs",), {"nargs": "*", "help": "Local robots.txt or sitemap files."}),
    (("--base",), {"help": "Origin for relative paths, such as https://app.internal."}),
    (("--fetch",), {"help": "Fetch this in-scope robots.txt or sitemap."}),
    (("--save",), {"help": "Also write the URL list to this file."}),
    (
        ("--no-workspace",),
        {
            "action": "store_true",
            "help": "Print every URL and leave the scope URL list unchanged.",
        },
    ),
)


def build_parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        prog="bughunt robots",
        description="Read robots.txt and sitemaps and print URLs pulse can check.",
    )
    for flags, settings in _OPTIONS:
        cli.add_argument(*flags, **settings)
    return cli


# --- reading the text formats -----------------------------------------------------------------------------


def looks_like_sitemap(text: str) -> bool:
    sample = text.lstrip()[:_SITEMAP_SNIFF].lower()
    return sample.startswith("<?xml") or any(
        marker in sample for marker in _SITEMAP_MARKERS
    )


def origin_of(url: str) -> str | None:
    parts = pagefetch.web_parts(url)
    if parts is None:
        return None
    return f"{parts.scheme}://{authority(parts.hostname or '', parts.port)}"


def resolve(value: str, base: str | None) -> str | None:
    token = value.strip()
    if is_web_url(token):
        absolute = token
    elif token and base:
        absolute = urljoin(base if base.endswith("/") else base + "/", token)
    else:
        return None
    return absolute if is_web_url(absolute) else None


def _split_robots(text: str, base: str | None) -> tuple[list[str], list[str], int]:
    """Path URLs, sitemap URLs, and how many entries could not be made absolute."""
    buckets: dict[str, list[str]] = {"path": [], "sitemap": []}
    unresolved = 0
    for key, value in crawlhints.directives(text):
        kind = _DIRECTIVE_KINDS.get(key)
        if kind == "path":
            value = crawlhints.rule_path(value)
        if kind is None or (kind == "path" and not value):
            continue
        absolute = resolve(value, base)
        if absolute is None:
            unresolved += 1
        else:
            buckets[kind].append(absolute)
    return buckets["path"], buckets["sitemap"], unresolved


# --- following sitemaps -----------------------------------------------------------------------------------


def fetch_document(client: httpx.Client, url: str) -> tuple[str, str]:
    # Unlike the other commands, a failed fetch here shows the exception's own text.
    return pagefetch.fetch_document(client, url, describe=str)


class _SitemapCrawler:
    """Expands sitemap URLs for one run; the fetch budget and the seen set are shared with callers."""

    def __init__(
        self, client: httpx.Client, base: str | None, budget: list[int], seen: set[str]
    ) -> None:
        self.client, self.base, self.budget, self.seen = client, base, budget, seen

    def expand(self, locs: list[str]) -> list[str]:
        return [
            page for loc in locs if loc not in self.seen for page in self._visit(loc)
        ]

    def _visit(self, loc: str) -> list[str]:
        in_scope = allowed(loc)
        if not in_scope or self.budget[0] <= 0:
            return [loc] if in_scope or not scope_is_active() else []
        self.seen.add(loc)
        self.budget[0] -= 1
        try:
            body, final = fetch_document(self.client, loc)
        except pagefetch.RedirectLimitError:
            raise
        except (ScopeError, FetchError) as problem:
            return [] if isinstance(problem, ScopeError) else [loc]
        children, _ = urls_from_text(
            body,
            self.base or origin_of(final),
            client=self.client,
            budget=self.budget,
            seen=self.seen,
        )
        return children


def robots_urls(
    text: str,
    base: str | None,
    *,
    client: httpx.Client | None,
    budget: list[int],
    seen: set[str],
) -> tuple[list[str], int]:
    paths, sitemaps, unresolved = _split_robots(text, base)
    if client is not None:
        sitemaps = _SitemapCrawler(client, base, budget, seen).expand(sitemaps)
    return paths + sitemaps, unresolved


def _sitemap_urls(
    text: str,
    base: str | None,
    *,
    client: httpx.Client | None,
    budget: list[int],
    seen: set[str],
) -> tuple[list[str], int]:
    locs = [
        absolute
        for absolute in (resolve(loc, base) for loc in sitemap_locs(text))
        if absolute
    ]
    descend = client is not None and is_sitemap_index(text)
    return (
        _SitemapCrawler(client, base, budget, seen).expand(locs) if descend else locs
    ), 0


def urls_from_text(
    text: str,
    base: str | None,
    *,
    client: httpx.Client | None,
    budget: list[int],
    seen: set[str],
) -> tuple[list[str], int]:
    reader = _sitemap_urls if looks_like_sitemap(text) else robots_urls
    return reader(text, base, client=client, budget=budget, seen=seen)


# --- command ----------------------------------------------------------------------------------------------


def _screen_arguments(options: argparse.Namespace) -> tuple[str, bool]:
    base = (options.base or "").strip()
    if not (options.inputs or options.fetch):
        raise Halt(
            2, report_error, "Give a local robots.txt or sitemap, or pass --fetch URL."
        )
    if base and not is_web_url(base):
        raise Halt(
            2,
            report_error,
            "Base needs an http or https URL, such as https://app.internal.",
        )
    scoped = scope_is_active() and not options.no_workspace
    for target, enforced in ((base, scoped), (options.fetch, True)):
        if target and enforced and not allowed(target):
            raise Halt(2, report_note, explain_target(target))
    return base, scoped


def _read_input(name: str) -> str:
    source = Path(name)
    if source.is_file():
        return source.read_text(encoding="utf-8", errors="replace")
    raise Halt(2, report_error, f"No file named {name}.")


def _from_files(names: list[str], base: str) -> tuple[list[str], int]:
    runs = [
        urls_from_text(
            _read_input(name),
            base or None,
            client=None,
            budget=[_SITEMAP_BUDGET],
            seen=set(),
        )
        for name in names
    ]
    return [url for urls, _ in runs for url in urls], sum(missed for _, missed in runs)


def _from_remote(target: str, base: str, run_ids=None) -> tuple[list[str], int]:
    try:
        with pagefetch.crawl_client(
            "manual", _FETCH_TIMEOUT, with_session=False
        ) as http:
            if run_ids is not None:
                http.event_hooks["response"].append(
                    lambda response: run_ids.append(
                        response.extensions["bughunt_run_id"]
                    )
                )
            text, final = fetch_document(http, target)
            return urls_from_text(
                text,
                base or origin_of(final),
                client=http,
                budget=[_SITEMAP_BUDGET],
                seen=set(),
            )
    except (ScopeError, FetchError) as problem:
        raise pagefetch.halt_for(problem) from problem


def _summary_line(kept: int, unresolved: int, dropped: int, fresh: int | None) -> str:
    counted = ((unresolved, "relative path(s) need --base"), (dropped, "outside scope"))
    pieces = [
        f"{kept} URL(s)",
        *(f"{count} {label}" for count, label in counted if count),
    ]
    if fresh is not None:
        pieces.append(f"{fresh} new in {urls_path().name}")
    return "  ".join(pieces)


def _gather(
    options: argparse.Namespace, base: str, run_ids=None
) -> tuple[list[str], int]:
    urls, unresolved = _from_files(options.inputs or [], base)
    if options.fetch:
        remote, missed = _from_remote(options.fetch, base, run_ids)
        urls, unresolved = urls + remote, unresolved + missed
    return urls, unresolved


def collect(options: argparse.Namespace, *, capture_runs=False) -> dict:
    base, scoped = _screen_arguments(options)
    run_ids = [] if capture_runs else None
    urls, unresolved = _gather(options, base, run_ids)
    unique = list(dict.fromkeys(filter(is_web_url, urls)))
    kept = [url for url in unique if allowed(url)] if scoped else unique
    fresh = remember_urls(kept) if scoped else None
    return {
        "urls": kept,
        "unresolved": unresolved,
        "dropped": len(unique) - len(kept),
        "fresh": fresh,
        "run_ids": run_ids or [],
    }


def _run(options: argparse.Namespace) -> int:
    result = collect(options)
    kept = result["urls"]
    listing = "".join(f"{url}\n" for url in kept)
    sys.stdout.write(listing)
    if options.save:
        _save_listing(options.save, listing)
    report_note(
        _summary_line(
            len(kept), result["unresolved"], result["dropped"], result["fresh"]
        )
    )
    return 0


def _save_listing(destination: str, listing: str) -> None:
    try:
        Path(destination).write_text(listing, encoding="utf-8")
    except OSError as problem:
        raise Halt(
            1, report_error, f"Could not write {destination}: {problem}"
        ) from problem


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    return pagefetch.run_halting(_run, options)
