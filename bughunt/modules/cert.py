"""Read the TLS certificate on one in-scope host.

Opens one connection, takes the certificate the server presents, and prints its
subject, issuer, validity dates, and alternative names. Nothing is verified.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import ssl
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import NamedTuple
from urllib.parse import urlsplit

from bughunt.core import cli, egress, termio
from bughunt.core.workspace import allowed, explain_target, parse_ip

_SAN_OID = "2.5.29.17"
_ATTR = {
    f"2.5.4.{arc}": label
    for arc, label in ((3, "CN"), (6, "C"), (7, "L"), (8, "ST"), (10, "O"), (11, "OU"))
}

_TAG_OCTETS = 0x04
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_VERSION = 0xA0
_TAG_EXTENSIONS = 0xA3
_TAG_DNS_NAME = 0x82
_TAG_IP_ADDRESS = 0x87
_STRING_CODECS = {0x1E: "utf-16-be", 0x1C: "utf-32-be"}

_TRUNCATED = "certificate was truncated"
_TLS_PORT = 443
_URL_SCHEMES = ("http", "https")
_UNUSABLE = ("", None)
_FAILURES = (
    (TimeoutError, "Could not connect to {where}: timed out."),
    (OSError, "Could not connect to {where}: {kind}"),
    (ValueError, "Could not read the certificate: {detail}"),
)


@dataclass
class Certificate:
    """The parts of an X.509 certificate this command reports."""

    subject: str
    issuer: str
    not_before: str
    not_after: str
    names: list[str] = field(default_factory=list)

    def summary_lines(self) -> list[str]:
        labelled = (
            ("subject", self.subject),
            ("issuer", self.issuer),
            ("not before", self.not_before),
            ("not after", self.not_after),
        )
        return [f"{label}: {text}" for label, text in labelled] + [
            f"san: {name}" for name in self.names
        ]


class _Item(NamedTuple):
    tag: int
    value: bytes


class _Der:
    """A cursor over DER bytes. Iterating yields each remaining (tag, value) item in turn."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._at = 0

    def _take(self, count: int) -> bytes:
        stop = self._at + count
        if stop > len(self._data):
            raise ValueError(_TRUNCATED)
        chunk, self._at = self._data[self._at : stop], stop
        return chunk

    def _length(self) -> int:
        first = self._take(1)[0]
        if first < 0x80:
            return first
        width = first - 0x80
        if width not in (1, 2, 3):
            raise ValueError(_TRUNCATED)
        return int.from_bytes(self._take(width), "big")

    def item(self) -> _Item:
        tag = self._take(1)[0]
        return _Item(tag, self._take(self._length()))

    def __iter__(self) -> Iterator[_Item]:
        while self._at < len(self._data):
            yield self.item()


def _children(data: bytes) -> list[_Item]:
    return list(_Der(data))


def _items(data: bytes) -> list[_Item]:
    """The siblings in `data`, or what they hold when one SEQUENCE wraps the whole buffer."""
    siblings = _children(data)
    if len(siblings) == 1 and siblings[0].tag == _TAG_SEQUENCE:
        return _children(siblings[0].value)
    return siblings


def _first_tagged(items: Iterable[_Item], tag: int) -> _Item | None:
    return next((item for item in items if item.tag == tag), None)


def _oid_arcs(chunk: bytes) -> Iterator[int]:
    arc = 0
    for byte in chunk:
        arc = arc << 7 | byte & 0x7F
        if byte < 0x80:
            yield arc
            arc = 0


def _dotted_oid(data: bytes) -> str:
    arcs = [*divmod(data[0], 40), *_oid_arcs(data[1:])] if data else []
    return ".".join(map(str, arcs))


def _string(item: _Item) -> str:
    return item.value.decode(_STRING_CODECS.get(item.tag, "utf-8"), errors="replace")


def _name_attributes(data: bytes) -> Iterator[tuple[str, str]]:
    groups = (
        entry for rdn in _Der(data) if rdn.tag == _TAG_SET for entry in _Der(rdn.value)
    )
    for entry in groups:
        if entry.tag != _TAG_SEQUENCE:
            continue
        pair = _children(entry.value)
        if len(pair) >= 2 and pair[0].tag == _TAG_OID:
            yield _dotted_oid(pair[0].value), _string(pair[1])


def _render_name(data: bytes) -> str:
    return ", ".join(
        f"{_ATTR.get(oid, oid)}={text}" for oid, text in _name_attributes(data)
    )


def _split_year(text: str) -> tuple[str, str] | None:
    if len(text) > 13 and text[:4].isdigit():
        return text[:4], text[4:]
    if len(text) > 11:
        short_year = int(text[:2])
        return str(short_year + (1900 if short_year >= 50 else 2000)), text[2:]
    return None


def _utc_text(data: bytes) -> str:
    decoded = data.decode("ascii", "replace")
    parts = _split_year(decoded.strip("Z"))
    if parts is None:
        return decoded
    year, tail = parts
    fields = [tail[start : start + 2] for start in range(0, 10, 2)]
    return "{}-{}-{} {}:{}:{}Z".format(year, *fields)


def _window(data: bytes) -> tuple[str, str]:
    moments = _items(data)
    if len(moments) < 2:
        raise ValueError("certificate has no dates")
    not_before, not_after = (_utc_text(moment.value) for moment in moments[:2])
    return not_before, not_after


def _dns_name(value: bytes) -> str:
    return "DNS:" + value.decode("ascii", "replace")


def _ip_name(value: bytes) -> str | None:
    return "IP:" + str(ipaddress.ip_address(value)) if len(value) in (4, 16) else None


_NAME_RENDERERS: dict[int, Callable[[bytes], str | None]] = {
    _TAG_DNS_NAME: _dns_name,
    _TAG_IP_ADDRESS: _ip_name,
}


def _general_names(payload: bytes) -> Iterator[str]:
    if payload[0] == _TAG_SEQUENCE:
        entries = _items(payload)
    else:
        entries = [_Item(payload[0], payload[1:])]
    if len(entries) == 1 and entries[0].tag == _TAG_SEQUENCE:
        entries = _children(entries[0].value)
    for entry in entries:
        render = _NAME_RENDERERS.get(entry.tag)
        text = render(entry.value) if render else None
        if text:
            yield text


def _extension_payloads(items: Iterable[_Item], wanted_oid: str) -> Iterator[bytes]:
    """The non-empty octet-string payload of each extension that carries `wanted_oid`."""
    for wrapper in items:
        if wrapper.tag != _TAG_EXTENSIONS:
            continue
        for extension in _items(wrapper.value):
            parts = (
                _children(extension.value)
                if extension.tag == _TAG_SEQUENCE
                else _items(extension.value)
            )
            identifier = _first_tagged(parts, _TAG_OID)
            payload = _first_tagged(parts, _TAG_OCTETS)
            if (
                identifier is not None
                and _dotted_oid(identifier.value) == wanted_oid
                and payload
                and payload.value
            ):
                yield payload.value


def _alt_names(items: Iterable[_Item]) -> list[str]:
    return [
        name
        for payload in _extension_payloads(items, _SAN_OID)
        for name in _general_names(payload)
    ]


def parse_certificate(der: bytes) -> Certificate:
    """Turn a DER certificate into its subject, issuer, validity dates, and alternative names."""
    outer = _items(_Der(der).item().value)
    if not outer or outer[0].tag != _TAG_SEQUENCE:
        raise ValueError("not a certificate")
    tbs = _items(outer[0].value)
    leading_version = bool(tbs) and tbs[0].tag == _TAG_VERSION
    core = tbs[int(leading_version) :]
    if len(core) < 6:
        raise ValueError("certificate is missing the subject")
    _serial, _algorithm, issuer, validity, subject, _key, *trailing = core
    issuer_text = _render_name(issuer.value)
    not_before, not_after = _window(validity.value)
    subject_text = _render_name(subject.value)
    return Certificate(
        subject_text, issuer_text, not_before, not_after, _alt_names(trailing)
    )


def _unverified_context() -> ssl.SSLContext:
    permissive = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    permissive.check_hostname = False
    permissive.verify_mode = ssl.CERT_NONE
    return permissive


@egress.guarded("manual", lambda args: [egress.endpoint(args["host"], args["port"])])
def fetch_certificate(host: str, port: int, timeout: float) -> bytes:
    permissive = _unverified_context()
    sni = None if parse_ip(host) is not None else host
    target = egress.endpoint(host, port)
    profile, signature = egress.current_profile(), egress._actor_signature()

    def read_peer():
        with socket.create_connection((host, port), timeout=timeout) as raw:
            egress._raw_ready(profile, signature, (target,), "manual", "GET")
            with permissive.wrap_socket(raw, server_hostname=sni) as tls:
                return tls.getpeercert(binary_form=True)

    presented = egress.dispatch(
        target,
        "manual",
        "GET",
        read_peer,
        check=lambda: egress._raw_ready(profile, signature, (target,), "manual", "GET"),
    )
    if not presented:
        raise ValueError("the server presented no certificate")
    return presented


def _from_url(text: str, port_arg: int) -> tuple[str, int | None] | None:
    if "://" not in text:
        return None
    url = urlsplit(text)
    if url.scheme not in _URL_SCHEMES or not url.hostname:
        return _UNUSABLE
    authority = url.netloc.rsplit("@", 1)[-1]
    if (
        "]" in authority
        and authority.partition("]")[2]
        and not authority.partition("]")[2].startswith(":")
    ):
        raise ValueError("invalid bracketed host suffix")
    if not port_arg and authority.endswith(":"):
        raise ValueError("empty port")
    port = port_arg or url.port
    if port is None:
        port = _TLS_PORT if url.scheme == "https" else None
    if port is None:
        return _UNUSABLE
    return url.hostname.lower().rstrip("."), port


def _from_bracketed(text: str, port_arg: int) -> tuple[str, int | None] | None:
    if not (text.startswith("[") and "]" in text):
        return None
    inside, _, rest = text[1:].partition("]")
    ipaddress.IPv6Address(inside)
    if rest and not rest.startswith(":"):
        raise ValueError("invalid bracketed host suffix")
    if rest and not port_arg and not rest[1:].isdigit():
        raise ValueError("invalid port")
    announced = int(rest[1:]) if rest and not port_arg else _TLS_PORT
    return inside.lower(), port_arg or announced


def _from_host_port(text: str, port_arg: int) -> tuple[str, int | None] | None:
    head, _, tail = text.rpartition(":")
    if text.count(":") != 1:
        return None
    if not port_arg and not tail.isdigit():
        raise ValueError("invalid port")
    return head.lower().rstrip("."), port_arg or int(tail)


def _endpoint(value: str, port_arg: int) -> tuple[str, int | None]:
    trimmed = value.strip()
    if "://" not in trimmed and ("[" in trimmed or "]" in trimmed):
        if (
            not trimmed.startswith("[")
            or trimmed.count("[") != 1
            or trimmed.count("]") != 1
        ):
            raise ValueError("invalid bracketed host")
    readings = (
        shape(trimmed, port_arg)
        for shape in (_from_url, _from_bracketed, _from_host_port)
    )
    return next(
        (found for found in readings if found is not None),
        (trimmed.lower().rstrip("."), port_arg or _TLS_PORT),
    )


_ARGUMENTS = (
    (("host",), {"help": "Hostname, address, or https URL."}),
    (
        ("--port",),
        {
            "type": int,
            "default": 0,
            "help": "TLS port. Default 443, or the port in the URL.",
        },
    ),
    (
        ("--timeout",),
        {
            "type": float,
            "default": 10.0,
            "help": "Seconds to wait for the handshake. Default 10.",
        },
    ),
)


def build_parser() -> argparse.ArgumentParser:
    return cli.build_parser(
        "bughunt cert", "Read the TLS certificate on one in-scope host.", _ARGUMENTS
    )


def _vet(parsed: argparse.Namespace) -> tuple[str, int]:
    if parsed.timeout <= 0 or parsed.port not in range(65536):
        raise cli.CommandExit(
            2, "Timeout must be greater than 0, and the port must be 0 through 65535."
        )
    try:
        endpoint = _endpoint(parsed.host, parsed.port)
    except ValueError as problem:
        raise cli.CommandExit(2, f"Invalid target: {problem}") from problem
    host, port = endpoint
    if port is not None and port not in range(1, 65536):
        raise cli.CommandExit(2, "The destination port must be 1 through 65535.")
    if port is None or not host:
        raise cli.CommandExit(
            2,
            "Give a hostname or an https URL, such as 127.0.0.1 or https://127.0.0.1:8443.",
        )
    if allowed(host):
        return endpoint
    raise cli.CommandExit(2, explain_target(host))


def _failure_text(failure: Exception, host: str, port: int) -> str:
    template = next(text for kind, text in _FAILURES if isinstance(failure, kind))
    return template.format(
        where=f"{host}:{port}", kind=type(failure).__name__, detail=failure
    )


def _read(host: str, port: int, timeout: float) -> Certificate:
    try:
        return parse_certificate(fetch_certificate(host, port, timeout))
    except (OSError, ValueError) as failure:
        raise cli.CommandExit(1, _failure_text(failure, host, port)) from failure


def _run(parsed: argparse.Namespace) -> int:
    host, port = _vet(parsed)
    certificate = _read(host, port, parsed.timeout)
    print("\n".join(termio.neutralize(line) for line in certificate.summary_lines()))
    return 0


def main(argv: list[str] | None = None) -> int:
    return cli.run(_run, build_parser().parse_args(argv))
