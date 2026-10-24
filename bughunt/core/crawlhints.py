"""Reading robots.txt rules and sitemap entries, shared by robots and silk. Standard library only."""

from __future__ import annotations

import html
import re
from collections.abc import Iterator

LOC_ELEMENT = re.compile(
    r"""
    <loc>
    \s*
    (?P<url>[^<]+?)
    \s*
    </loc>
    """,
    re.IGNORECASE | re.VERBOSE,
)
INDEX_SNIFF = 8_000
# robots.txt lets a rule end in one "$" anchor and one "*" wildcard; neither names a different path.
PATH_SUFFIXES = (re.compile(r"\s*\$\Z"), re.compile(r"\s*\*\Z"))


def sitemap_locs(text: str) -> list[str]:
    """Every non-empty <loc> in the text, XML entities unescaped, in order."""
    unescaped = (html.unescape(found.group("url")).strip() for found in LOC_ELEMENT.finditer(text))
    return [loc for loc in unescaped if loc]


def is_sitemap_index(text: str) -> bool:
    """True when a <sitemapindex> opens within the first INDEX_SNIFF characters."""
    return "<sitemapindex" in text[:INDEX_SNIFF].lower()


def rule_path(value: str) -> str:
    """A robots.txt rule's path without its trailing anchor or wildcard; empty when it names no path."""
    path = value.strip()
    for suffix in PATH_SUFFIXES:
        path = suffix.sub("", path, count=1)
    return "" if path in ("", "*") else path


def directives(text: str) -> Iterator[tuple[str, str]]:
    """(lower-cased key, value) for every ``key: value`` line, comments removed."""
    for line in text.splitlines():
        content = line.split("#", 1)[0].strip()
        key, colon, value = content.partition(":")
        if colon:
            yield key.strip().lower(), value.strip()
