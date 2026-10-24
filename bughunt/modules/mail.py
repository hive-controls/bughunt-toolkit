"""Explain MX, SPF, DKIM, and DMARC for one in-scope name.

Reads the records the name publishes through one resolver and says what they mean.
DKIM selectors are only checked when given. Nothing is guessed.
"""

from __future__ import annotations

import argparse
import re
from collections.abc import Iterator
from contextlib import suppress
from functools import partial
from typing import NamedTuple

from bughunt.core import banner, cli, termio
from bughunt.core.workspace import allowed, explain_block
from bughunt.modules import MODULES
# resolver_address and system_resolver are not called here; they stay importable from mail because
# the characterization oracle pins them to dns's own objects.
from bughunt.modules.dns import (
    RESOLVER_OPTIONS,
    lookup,
    normalize_name,
    pick_resolver,
    resolver_address,
    system_resolver,
)

_SIGIL = "mail"
_SUBTITLE = "MX, SPF, DKIM, and DMARC for one name"
_PAD = " " * 4


def _slanted(depth: int, middle: str) -> str:
    gap = " " * depth
    return f"{_PAD}|{gap}\\{middle.ljust(15 - 2 * depth)}/{gap}|"


_ART = (
    f"{_PAD}.{'-' * 17}.",
    _slanted(0, ""),
    _slanted(1, f"    {_SIGIL}"),
    _slanted(2, "   (  )"),
    f"{_PAD}|   '{'-' * 9}'   |",
    f"{_PAD}'{'-' * 17}'",
)
_SELECTOR_SHAPE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ALL_TERM = re.compile(r"([+\-~?]?)all;*")
_CLIP = 300
_KEPT_NOTE_PREFIXES = ("The answer was truncated",)
_RECORD_PREFIXES = {"spf": "v=spf1", "dmarc": "v=dmarc1", "dkim": "v=dkim1"}


class _Request(NamedTuple):
    """A vetted command line: the name, its DKIM selectors, and how to reach the resolver."""

    name: str
    selectors: list[str]
    resolver: str
    port: int
    timeout: float


class _Probe(NamedTuple):
    """One follow-up TXT lookup: the record it was after, the notes worth keeping, and whether it failed."""

    record: str
    notes: list[str]
    failed: bool


class _Posture(NamedTuple):
    """The published records, as the review rules read them."""

    mx: list[str]
    spf: str
    dmarc: str
    selectors: list[str]
    dkim: list[tuple[str, str]]


_ARGUMENTS = (
    (("name",), {"help": "Hostname to explain. A URL uses that URL's hostname."}),
    *RESOLVER_OPTIONS,
    (("--selector",), {"action": "append", "default": None,
                       "help": "DKIM selector, such as s1. Repeat for another. None are guessed."}),
    cli.PLAIN,
)


def build_parser() -> argparse.ArgumentParser:
    return cli.build_parser("bughunt mail", MODULES["mail"], _ARGUMENTS)


def format_banner(color: bool) -> str:
    return banner.render_banner(_ART, _SIGIL, _SUBTITLE, color)


def format_field(key: str, value: str, color: bool) -> str:
    return banner.format_pair(key, value, color)


def _emit(color: bool, key: str, value: str) -> None:
    print(format_field(key, value, color))


def _squeeze(value: str) -> str:
    flat = termio.neutralize(" ".join(value.split()))
    return flat if len(flat) <= _CLIP else flat[:_CLIP - 1] + "…"


def _published(records: list[str], kind: str) -> str:
    prefix = _RECORD_PREFIXES[kind]
    return next((text for text in records if text.lower().startswith(prefix)), "")


def _setting(record: str, key: str) -> str:
    entries = (part.partition("=") for part in record.split(";"))
    return next((value.strip().lower() for name, equals, value in entries
                 if equals and name.strip().lower() == key), "")


def _truncation_notes(notes: list[str]) -> list[str]:
    return [note for note in notes if note.startswith(_KEPT_NOTE_PREFIXES)]


def _spf_review(record: str) -> list[str]:
    hits = (_ALL_TERM.fullmatch(term.lower()) for term in record.split())
    qualifiers = {hit[1] or "+" for hit in hits if hit}
    if "+" in qualifiers:
        verdict = "review: SPF allows any sender (+all)"
    elif not qualifiers & {"-", "~"}:
        verdict = "review: SPF does not use -all or ~all"
    else:
        return []
    return [verdict]


def _review_mx(posture: _Posture) -> Iterator[str]:
    if not posture.mx:
        yield "review: no MX"


def _review_spf(posture: _Posture) -> Iterator[str]:
    if posture.spf:
        yield from _spf_review(posture.spf)
    else:
        yield "review: no SPF"


def _review_dmarc(posture: _Posture) -> Iterator[str]:
    if not posture.dmarc:
        yield "review: no DMARC"
    elif (_setting(posture.dmarc, "p") or "none") == "none":
        yield "review: DMARC policy is none"


def _review_dkim(posture: _Posture) -> Iterator[str]:
    if not posture.selectors:
        yield "review: no DKIM selector was given"
    yield from (f"review: no DKIM record for {selector}"
                for selector, summary in posture.dkim if not summary)


_REVIEW_RULES = (_review_mx, _review_spf, _review_dmarc, _review_dkim)


def review_notes(mx: list[str], spf: str, dmarc: str, selectors: list[str],
                 dkim: list[tuple[str, str]]) -> list[str]:
    posture = _Posture(mx, spf, dmarc, selectors, dkim)
    return [note for rule in _REVIEW_RULES for note in rule(posture)]


def _probe(request: _Request, owner: str, kind: str) -> _Probe:
    """Look up TXT at `owner` and pick out the `kind` record. A failed lookup is reported, never raised."""
    with suppress(OSError, ValueError):
        found, notes, failed = lookup(owner, request.resolver, request.port, request.timeout)
        return _Probe(_published(found["TXT"], kind), _truncation_notes(notes), failed)
    return _Probe("", [], True)


def _dkim_summary(record: str) -> str:
    if not record:
        return ""
    return "key present" if _setting(record, "p") else _squeeze(record)


def _vet(parsed: argparse.Namespace) -> _Request:
    cli.check(parsed, [cli.ENDPOINT_RULE])
    name = normalize_name(parsed.name)
    if not name:
        raise cli.CommandExit(2, "Give a hostname, such as app.internal.")
    selectors = [raw.strip().lower() for raw in parsed.selector or ()]
    if not all(map(_SELECTOR_SHAPE.match, selectors)):
        raise cli.CommandExit(2, "A selector is one label, such as s1.")
    owners = (name, f"_dmarc.{name}", *(f"{selector}._domainkey.{name}" for selector in selectors))
    refused = next((owner for owner in owners if not allowed(owner)), None)
    if refused is not None:
        raise cli.CommandExit(2, explain_block(refused))
    return _Request(name, selectors, pick_resolver(parsed.resolver), parsed.port, parsed.timeout)


def _primary(request: _Request) -> tuple[dict[str, list[str]], list[str], bool]:
    try:
        return lookup(request.name, request.resolver, request.port, request.timeout)
    except (OSError, ValueError) as failure:
        raise cli.CommandExit(
            1, f"Could not look up {request.name}: {type(failure).__name__}") from failure


def _follow_up(request: _Request, emit) -> tuple[_Probe, list[tuple[str, _Probe]], list[tuple[str, str]]]:
    """DMARC, then DKIM per selector: show their rows and return what the review and complaints need."""
    dmarc = _probe(request, f"_dmarc.{request.name}", "dmarc")
    if dmarc.record:
        emit("DMARC", _squeeze(dmarc.record))
    dkim = [(selector, _probe(request, f"{selector}._domainkey.{request.name}", "dkim"))
            for selector in request.selectors]
    summaries = [(selector, _dkim_summary(probe.record)) for selector, probe in dkim
                 if probe.record or not probe.failed]
    for selector, summary in summaries:
        if summary:
            emit("DKIM", f"{selector}\t{summary}")
    return dmarc, dkim, summaries


def _complaints(dmarc: _Probe, dkim: list[tuple[str, _Probe]]) -> list[str]:
    complaints = ["DMARC lookup failed."] if dmarc.failed and not dmarc.record else []
    complaints += [f"DKIM lookup failed for {selector}."
                   for selector, probe in dkim if probe.failed and not probe.record]
    return complaints


def _run(parsed: argparse.Namespace) -> int:
    request = _vet(parsed)
    if not parsed.plain:
        termio.show_banner(format_banner)
    found, notes, failed = _primary(request)
    spf = _published(found["TXT"], "spf")
    if failed and not (found["MX"] or spf):
        raise cli.CommandExit(1, f"{request.name} lookup failed.")
    emit = partial(_emit, termio.stdout_color(parsed.plain))
    for exchange in found["MX"]:
        emit("MX", _squeeze(exchange))
    if spf:
        emit("SPF", _squeeze(spf))
    dmarc, dkim, summaries = _follow_up(request, emit)
    review = review_notes(found["MX"], spf, dmarc.record, request.selectors, summaries)
    kept = [remark for _selector, probe in dkim for remark in probe.notes]
    for remark in (*_truncation_notes(notes), *dmarc.notes, *kept, *review):
        banner.note(remark)
    for complaint in _complaints(dmarc, dkim):
        termio.say(complaint)
    return 0


def main(argv: list[str] | None = None) -> int:
    return cli.run(_run, build_parser().parse_args(argv))
