"""Look up registrar, dates, and nameservers for one in-scope domain.

Asks whois.iana.org which registry holds the domain, then asks that registry once.
A server passed with --server skips the referral. Replies are read up to 64 KiB.
"""

from __future__ import annotations

import argparse
import re
import socket
from collections.abc import Iterable, Iterator
from contextlib import suppress
from datetime import datetime, timedelta, timezone

from bughunt.core import banner, cli, egress, termio
from bughunt.core.workspace import allowed, explain_block
from bughunt.modules import MODULES
from bughunt.modules.dns import normalize_name, resolver_address

_ROOT_SERVER = "whois.iana.org"
_REPLY_CAP = 1 << 16
_CHUNK_BYTES = 4096
_TEXT_CAP = 300
_EXPIRY_WINDOW = timedelta(days=30)

_REGISTRAR_KEYS = ("registrar", "sponsoring registrar")
_SERVER_KEYS = ("name server", "nserver")
_DATE_KEYS = {
    "created": ("creation date", "created"),
    "expires": ("registry expiry date", "expiry date", "expiration date", "expires"),
}
_DATE_LAYOUTS = (
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S %z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%Y%m%d",
)
_STAMP_REWRITES = (
    (re.compile(r"\s*(?:UTC|GMT)$", re.IGNORECASE), ""),
    (re.compile(r"(\d{2}:\d{2}:\d{2})\.\d+"), r"\1"),
    (re.compile(r"(?<=\d)T(?=\d)"), " "),
    (re.compile(r"Z\Z"), ""),
)
_FIELD_LINE = re.compile(r"(?![%#])([^:]+):(.+)")
_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"(?=.{{1,253}}$)(?:{_DNS_LABEL}\.)+[a-z]{{2,63}}")

_BADGE = "whois"
_TAGLINE = "registrar, dates, and nameservers for one domain"
_ART = (
    " " * 5 + "_" * 16,
    "   .'_(" + " " * 12 + ")_'.",
    "   |" + "registrar".center(17) + "|",
    "   |" + f"({_BADGE})".center(17) + "|",
    "   '" + "-" * 17 + "'",
)


class RegistryError(Exception):
    """Registry discovery or a query to the identified registry failed."""


_ARGUMENTS = (
    (("name",), {"help": "Domain to look up. A URL uses that URL's hostname."}),
    (
        ("--server",),
        {"default": None, "help": "Whois server address. Skips the IANA referral."},
    ),
    (("--port",), {"type": int, "default": 43, "help": "Whois port. Default 43."}),
    (
        ("--timeout",),
        {"type": float, "default": 10.0, "help": "Seconds to wait. Default 10."},
    ),
    cli.PLAIN,
)


def build_parser() -> argparse.ArgumentParser:
    return cli.build_parser("bughunt whois", MODULES["whois"], _ARGUMENTS)


def _choose_server(requested: str | None) -> str | None:
    if not requested:
        return None
    address = resolver_address(requested)
    if not address:
        raise cli.CommandExit(2, "Pass a server address, such as 127.0.0.1.")
    return address


def _vet(parsed: argparse.Namespace) -> tuple[str, str | None]:
    cli.check(parsed, [cli.ENDPOINT_RULE])
    name = normalize_name(parsed.name)
    if not name:
        raise cli.CommandExit(2, "Give a hostname, such as app.internal.")
    if allowed(name):
        return name, _choose_server(parsed.server)
    raise cli.CommandExit(2, explain_block(name))


def _retrieve(
    name: str, server: str | None, parsed: argparse.Namespace
) -> tuple[str, list[str]]:
    try:
        return fetch_record(name, server, parsed.port, parsed.timeout)
    except RegistryError as failure:
        raise cli.CommandExit(1, str(failure)) from failure
    except OSError as failure:
        raise cli.CommandExit(
            1, f"Could not query {server or _ROOT_SERVER}: {type(failure).__name__}"
        ) from failure


def _present(
    name: str, record: dict[str, object], notes: Iterable[str], plain: bool
) -> int:
    table = record_rows(name, record)
    shaded = termio.stdout_color(plain)
    print(
        "\n".join(
            format_field(key, termio.neutralize(value), shaded) for key, value in table
        )
    )
    for remark in (*notes, *review_notes(record)):
        banner.note(remark)
    if len(table) < 2:
        termio.say("no registrar record")
    return 0


def _run(parsed: argparse.Namespace) -> int:
    name, server = _vet(parsed)
    if not parsed.plain:
        termio.show_banner(format_banner)
    text, notes = _retrieve(name, server, parsed)
    return _present(name, parse_record(text), notes, parsed.plain)


def main(argv: list[str] | None = None) -> int:
    return cli.run(_run, build_parser().parse_args(argv))


def _registry_for(name: str, port: int, timeout: float) -> str:
    directory, _cut = _fetch(_ROOT_SERVER, port, name, timeout)
    registry = referral_host(directory)
    if not registry:
        raise RegistryError("The registry was not named.")
    return registry


def fetch_record(
    name: str, server: str | None, port: int, timeout: float
) -> tuple[str, list[str]]:
    """The registry's text for `name`, with a note if it was cut short. A given `server` skips the referral."""
    host = server or _registry_for(name, port, timeout)
    try:
        text, cut = _fetch(host, port, name, timeout)
    except OSError as failure:
        raise RegistryError(
            f"Could not query {host}: {type(failure).__name__}"
        ) from failure
    return text, (["The reply was truncated."] if cut else [])


def _fetch_targets(bound: dict) -> list[str]:
    return [
        egress.host_target(bound["name"], "passive"),
        egress.endpoint(bound["host"], bound["port"], "http"),
    ]


def _read_capped(link: socket.socket, limit: int) -> Iterator[bytes]:
    taken = 0
    while (room := limit - taken) > 0 and (piece := link.recv(min(_CHUNK_BYTES, room))):
        taken += len(piece)
        yield piece


@egress.guarded("passive", _fetch_targets)
def _fetch(host: str, port: int, name: str, timeout: float) -> tuple[str, bool]:
    request = name.encode("idna") + b"\r\n"
    targets = tuple(_fetch_targets({"name": name, "host": host, "port": port}))
    profile, signature = egress.current_profile(), egress._actor_signature()
    with socket.create_connection((host, port), timeout) as link:
        link.settimeout(timeout)
        egress.dispatch(
            targets[0],
            "passive",
            "GET",
            lambda: link.sendall(request),
            check=lambda: egress._raw_ready(
                profile, signature, targets, "passive", "GET"
            ),
        )
        reply = b"".join(_read_capped(link, _REPLY_CAP))
    return reply.decode("utf-8", "replace"), len(reply) >= _REPLY_CAP


def pairs(text: str) -> list[tuple[str, str]]:
    matches = (_FIELD_LINE.fullmatch(line.strip()) for line in text.splitlines())
    return [
        (" ".join(match[1].lower().split()), " ".join(match[2].split()))
        for match in matches
        if match
    ]


def _hostname_token(value: str) -> str:
    tokens = value.split()
    return tokens[0].lower().rstrip(".") if tokens else ""


def referral_host(text: str) -> str | None:
    """The host named by the first `refer` field. An address, or any later refer, is ignored."""
    announced = next((value for key, value in pairs(text) if key == "refer"), "")
    host = _hostname_token(announced)
    return host if _HOST.fullmatch(host) else None


def _index(fields: Iterable[tuple[str, str]]) -> dict[str, list[str]]:
    grouped: dict[str, list[str]] = {}
    for label, content in fields:
        grouped.setdefault(label, []).append(content)
    return grouped


def _first_value(index: dict[str, list[str]], keys: tuple[str, ...]) -> str:
    return next((index[key][0] for key in keys if index.get(key)), "")


def _nameservers(index: dict[str, list[str]]) -> list[str]:
    hosts = (
        _hostname_token(value) for key in _SERVER_KEYS for value in index.get(key, ())
    )
    return list(dict.fromkeys(filter(None, hosts)))


def parse_record(text: str) -> dict[str, object]:
    index = _index(pairs(text))
    record: dict[str, object] = {"registrar": _first_value(index, _REGISTRAR_KEYS)}
    for label, keys in _DATE_KEYS.items():
        raw = _first_value(index, keys)
        record[label] = parse_when(raw)
        record[f"{label}_text"] = raw
    record["nameservers"] = _nameservers(index)
    return record


def _normalized_stamp(value: str) -> str:
    trimmed = value.strip()
    for pattern, replacement in _STAMP_REWRITES:
        trimmed = pattern.sub(replacement, trimmed)
    return trimmed


def _strptime_utc(text: str, layout: str) -> datetime | None:
    with suppress(ValueError):
        parsed = datetime.strptime(text, layout)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    return None


def parse_when(value: str) -> datetime | None:
    text = _normalized_stamp(value)
    return next(
        filter(None, (_strptime_utc(text, layout) for layout in _DATE_LAYOUTS)), None
    )


def _when_text(parsed: object, raw: object) -> str:
    if not isinstance(parsed, datetime):
        return raw[:_TEXT_CAP] if isinstance(raw, str) else ""
    return parsed.strftime(termio.UTC_STAMP)


def record_rows(name: str, record: dict[str, object]) -> list[tuple[str, str]]:
    sponsor = record.get("registrar")
    candidates = [("registrar", sponsor if isinstance(sponsor, str) else "")]
    candidates += [
        (label, _when_text(record.get(label), record.get(f"{label}_text")))
        for label in _DATE_KEYS
    ]
    hosts = record.get("nameservers")
    servers = [("nserver", host) for host in hosts] if isinstance(hosts, list) else []
    return [("domain", name), *(pair for pair in candidates if pair[1]), *servers]


def review_notes(record: dict[str, object]) -> list[str]:
    due = record.get("expires")
    if not isinstance(due, datetime):
        return []
    remaining = due - datetime.now(timezone.utc)
    when = due.strftime(termio.UTC_STAMP)
    if remaining < timedelta(0):
        return [f"review: expired on {when}"]
    if remaining <= _EXPIRY_WINDOW:
        return [f"review: expires within 30 days ({when})"]
    return []


def format_banner(color: bool) -> str:
    return banner.render_banner(_ART, _BADGE, _TAGLINE, color)


def format_field(key: str, value: str, color: bool) -> str:
    return banner.format_pair(key, value, color)
