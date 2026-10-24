"""Look up A, AAAA, CNAME, MX, TXT, and NS for one in-scope name.

Each type is one UDP query to a single resolver: the one passed in, or the first
system nameserver. No zone transfer, and a CNAME is reported but not chased.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
import re
import socket
import struct
from collections.abc import Callable, Iterator
from contextlib import closing, suppress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from bughunt.core import cli, egress, termio
from bughunt.core.workspace import allowed, explain_block, parse_ip
from bughunt.modules import MODULES


_TYPE_CODES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "TXT": 16, "NS": 2}
RECORD_TYPES = tuple(_TYPE_CODES.items())
_LABEL_OF_CODE = {code: label for label, code in _TYPE_CODES.items()}

_HEADER = struct.Struct("!HHHHHH")
_QUESTION_TAIL = struct.Struct("!HH")
_RR_FIXED = struct.Struct("!HHIH")

_REPLY_BUFFER = 4096
_POINTER_FOLLOWS = 17
_MAX_QUESTIONS = 8
_MAX_RECORDS = 128
_FLAG_RECURSION = 0x0100
_FLAG_TRUNCATED = 0x0200
_FLAGS_REPLY = 0x8180
_RCODE_MASK = 0x000F
_CLEAN_RCODES = frozenset((0, 3))
_CLASS_IN = 1
_REPLY_TTL = 60
_QUESTION_POINTER = b"\xc0\x0c"
_RESOLV_CONF = Path("/etc/resolv.conf")
_UNFIT_HOST = re.compile(r"[\s*/\\:]")


def _section() -> list:
    return field(default_factory=list)


@dataclass
class Question:
    """One entry of a message's question section."""

    name: str
    qtype: int
    qclass: int


@dataclass
class Record:
    """One resource record, its data already rendered as text."""

    name: str
    rtype: int
    rclass: int
    ttl: int
    text: str


@dataclass
class Message:
    """A parsed DNS message: two header words and four sections."""

    ident: int
    flags: int
    questions: list[Question] = _section()
    answers: list[Record] = _section()
    authorities: list[Record] = _section()
    additionals: list[Record] = _section()


class _Reader:
    """A cursor over one packet. A short read names what it was in the middle of."""

    def __init__(self, packet: bytes, position: int = 0) -> None:
        self.packet = packet
        self.position = position

    def take(self, count: int, what: str) -> bytes:
        stop = self.position + count
        if stop > len(self.packet):
            raise ValueError(f"dns {what} was truncated")
        chunk = self.packet[self.position : stop]
        self.position = stop
        return chunk

    def unpack(self, layout: struct.Struct, what: str) -> tuple[int, ...]:
        return layout.unpack(self.take(layout.size, what))

    def _name_byte(self) -> int:
        return self.take(1, "name")[0]

    def _labels(self) -> tuple[list[str], int | None]:
        """Labels up to the root or a compression pointer, plus that pointer's target."""
        found: list[str] = []
        while lead := self._name_byte():
            kind = lead & 0xC0
            if kind == 0xC0:
                return found, (lead & 0x3F) << 8 | self._name_byte()
            if kind:
                raise ValueError("dns name is not a hostname")
            found.append(self.take(lead, "name").decode("ascii", errors="replace"))
        return found, None

    def name(self) -> str:
        """Read a possibly compressed name; the cursor stays after the first run of labels."""
        labels, pointer = self._labels()
        for _ in range(_POINTER_FOLLOWS):
            if pointer is None:
                break
            more, pointer = _Reader(self.packet, pointer)._labels()
            labels += more
        if pointer is not None:
            raise ValueError("dns name pointer loop")
        return ".".join(labels)

    def question(self) -> Question:
        name = self.name()
        return Question(name, *self.unpack(_QUESTION_TAIL, "question"))

    def record(self) -> Record:
        name = self.name()
        rtype, rclass, ttl, length = self.unpack(_RR_FIXED, "record")
        start = self.position
        self.take(length, "record")
        return Record(
            name, rtype, rclass, ttl, _render_rdata(rtype, self.packet, start, length)
        )


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    reader = _Reader(data, offset)
    text = reader.name()
    return text, reader.position


def parse_message(data: bytes) -> Message:
    reader = _Reader(data)
    ident, flags, question_count, *section_counts = reader.unpack(_HEADER, "message")
    if question_count > _MAX_QUESTIONS or sum(section_counts) > _MAX_RECORDS:
        raise ValueError("dns message is too large")
    questions = [reader.question() for _ in range(question_count)]
    sections = [[reader.record() for _ in range(count)] for count in section_counts]
    return Message(ident, flags, questions, *sections)


def _rdata_ipv4(packet: bytes, start: int, length: int) -> str:
    return socket.inet_ntoa(packet[start : start + length]) if length == 4 else ""


def _rdata_ipv6(packet: bytes, start: int, length: int) -> str:
    return (
        str(ipaddress.IPv6Address(packet[start : start + length]))
        if length == 16
        else ""
    )


def _rdata_domain(packet: bytes, start: int, length: int) -> str:
    return read_name(packet, start)[0]


def _rdata_exchange(packet: bytes, start: int, length: int) -> str:
    if length < 3:
        return ""
    preference = int.from_bytes(packet[start : start + 2], "big")
    return f"{preference} {read_name(packet, start + 2)[0]}"


def _text_chunks(blob: bytes) -> Iterator[bytes]:
    cursor = 0
    while cursor < len(blob):
        end = cursor + 1 + blob[cursor]
        yield blob[cursor + 1 : end]
        cursor = end


def _rdata_text(packet: bytes, start: int, length: int) -> str:
    blob = packet[start : start + length]
    return "".join(
        chunk.decode("utf-8", errors="replace") for chunk in _text_chunks(blob)
    )


_RDATA_RENDERERS: dict[str, Callable[[bytes, int, int], str]] = {
    "A": _rdata_ipv4,
    "AAAA": _rdata_ipv6,
    "NS": _rdata_domain,
    "CNAME": _rdata_domain,
    "MX": _rdata_exchange,
    "TXT": _rdata_text,
}


def _render_rdata(rtype: int, packet: bytes, start: int, length: int) -> str:
    render = _RDATA_RENDERERS.get(_LABEL_OF_CODE.get(rtype, ""))
    return render(packet, start, length) if render else ""


def _encode_label(label: str) -> bytes:
    wire = label.encode("ascii" if label.isascii() else "idna")
    if len(wire) not in range(1, 64):
        raise ValueError("bad name")
    return len(wire).to_bytes(1, "big") + wire


def encode_name(name: str) -> bytes:
    labels = name.strip().strip(".").split(".")
    if labels == [""]:
        raise ValueError("empty name")
    wire = b"".join(map(_encode_label, labels)) + b"\x00"
    if len(wire) > 255:
        raise ValueError("name is too long")
    return wire


def build_query(name: str, qtype: int, ident: int) -> bytes:
    if ident not in range(1 << 16):
        raise ValueError("query id is out of range")
    return b"".join(
        (
            _HEADER.pack(ident, _FLAG_RECURSION, 1, 0, 0, 0),
            encode_name(name),
            _QUESTION_TAIL.pack(qtype, _CLASS_IN),
        )
    )


def answer_packet(
    query: bytes,
    records: list[tuple[int, bytes]],
    *,
    rcode: int = 0,
    tc: bool = False,
    ident: int | None = None,
) -> bytes:
    """A reply to `query` that carries just the records matching its first question's type."""
    parsed = parse_message(query)
    if not parsed.questions:
        raise ValueError("query has no question")
    asked = parsed.questions[0]
    payloads = [rdata for rtype, rdata in records if rtype == asked.qtype]
    flags = _FLAGS_REPLY | (_FLAG_TRUNCATED if tc else 0) | (rcode & _RCODE_MASK)
    header = _HEADER.pack(
        parsed.ident if ident is None else ident, flags, 1, len(payloads), 0, 0
    )
    question = encode_name(asked.name) + _QUESTION_TAIL.pack(asked.qtype, asked.qclass)
    answers = (
        _QUESTION_POINTER
        + _RR_FIXED.pack(asked.qtype, _CLASS_IN, _REPLY_TTL, len(rdata))
        + rdata
        for rdata in payloads
    )
    return header + question + b"".join(answers)


def _nameserver_fields(text: str) -> Iterator[str]:
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and fields[0].lower() == "nameserver":
            yield fields[1]


def system_resolver() -> str | None:
    with suppress(OSError):
        text = _RESOLV_CONF.read_text(encoding="utf-8", errors="replace")
        return next(filter(None, map(resolver_address, _nameserver_fields(text))), None)
    return None


def resolver_address(value: str) -> str | None:
    trimmed = value.strip()
    inner = trimmed[1:-1] if trimmed[:1] + trimmed[-1:] == "[]" else trimmed
    parsed = parse_ip(inner)
    return None if parsed is None else str(parsed)


def _host_part(text: str) -> str:
    """The host an argument points at: a URL's hostname, otherwise the text itself."""
    return (urlsplit(text).hostname or "") if "://" in text else text


def normalize_name(value: str) -> str | None:
    host = _host_part(value.strip()).lower().rstrip(".")
    unfit = not host or _UNFIT_HOST.search(host) or parse_ip(host) is not None
    return None if unfit else host


@dataclass
class _Tally:
    """What the replies so far add up to: values per label and the two flags."""

    found: dict[str, list[str]]
    truncated: bool = False
    failed: bool = False

    def absorb(self, message: Message) -> None:
        self.truncated |= bool(message.flags & _FLAG_TRUNCATED)
        if message.flags & _RCODE_MASK not in _CLEAN_RCODES:
            self.failed = True
            return
        for record in (*message.answers, *message.authorities, *message.additionals):
            label = _LABEL_OF_CODE.get(record.rtype)
            if label and record.text and record.text not in self.found[label]:
                self.found[label].append(record.text)

    def notes(self) -> list[str]:
        notes = ["The answer was truncated."] if self.truncated else []
        aliases = self.found["CNAME"]
        if aliases and not self.found["A"] and not self.found["AAAA"]:
            notes.append(f"review: CNAME {aliases[0]} has no address in this answer")
        return notes


class _Dialogue:
    """One datagram socket aimed at one resolver; every datagram takes its own egress slot."""

    def __init__(
        self, datagram: socket.socket, name: str, resolver: str, port: int
    ) -> None:
        self._socket = datagram
        self._name = name
        self._peer = (resolver, port)
        self._target = egress.host_target(name, "dns")
        self._endpoints = (self._target, egress.endpoint(resolver, port, "http"))
        self._profile = egress.current_profile()
        self._signature = egress._actor_signature()

    def _recheck(self) -> None:
        egress._raw_ready(self._profile, self._signature, self._endpoints, "dns", "GET")

    def _round_trip(self, query: bytes) -> bytes:
        def send_query():
            self._socket.connect(self._peer)
            return self._socket.send(query)

        egress.dispatch(self._target, "dns", "GET", send_query, check=self._recheck)
        return self._socket.recv(_REPLY_BUFFER)

    def _exchange(self, query: bytes) -> bytes:
        try:
            return self._round_trip(query)
        except TimeoutError:
            return self._round_trip(query)

    def ask(self, qtype: int) -> Message:
        ident = random.randrange(1 << 16)
        message = parse_message(self._exchange(build_query(self._name, qtype, ident)))
        if ident != message.ident:
            raise ValueError("response id did not match")
        return message


def _lookup_targets(bound: dict) -> list[str]:
    return [
        egress.host_target(bound["name"], "dns"),
        egress.endpoint(bound["resolver"], bound["port"], "http"),
    ]


def _lookup_records(name: str, resolver: str, port: int, timeout: float):
    tally = _Tally({label: [] for label, _code in RECORD_TYPES})
    records = []
    wire_family = socket.AF_INET6 if ":" in resolver else socket.AF_INET
    with closing(socket.socket(wire_family, socket.SOCK_DGRAM)) as datagram:
        datagram.settimeout(timeout)
        dialogue = _Dialogue(datagram, name, resolver, port)
        for message in map(dialogue.ask, [code for _label, code in RECORD_TYPES]):
            tally.absorb(message)
            if message.flags & _RCODE_MASK in _CLEAN_RCODES:
                records.extend(
                    record
                    for record in (
                        *message.answers,
                        *message.authorities,
                        *message.additionals,
                    )
                    if record.rtype in _LABEL_OF_CODE and record.text
                )
    return tally, records


@egress.guarded("dns", _lookup_targets)
def lookup(
    name: str, resolver: str, port: int, timeout: float
) -> tuple[dict[str, list[str]], list[str], bool]:
    tally, _ = _lookup_records(name, resolver, port, timeout)
    return tally.found, tally.notes(), tally.failed


@egress.guarded("dns", _lookup_targets)
def lookup_records(name: str, resolver: str, port: int, timeout: float):
    tally, records = _lookup_records(name, resolver, port, timeout)
    return records, tally.notes(), tally.failed


RESOLVER_OPTIONS = (
    (
        ("--resolver",),
        {
            "default": None,
            "help": "Resolver address. Default: the first system nameserver.",
        },
    ),
    (("--port",), {"type": int, "default": 53, "help": "Resolver port. Default 53."}),
    (
        ("--timeout",),
        {
            "type": float,
            "default": 5.0,
            "help": "Seconds to wait for each reply. Default 5.",
        },
    ),
)
_ARGUMENTS = (
    (("name",), {"help": "Hostname to look up. A URL uses that URL's hostname."}),
    *RESOLVER_OPTIONS,
)


def build_parser() -> argparse.ArgumentParser:
    return cli.build_parser("bughunt dns", MODULES["dns"], _ARGUMENTS)


def pick_resolver(requested: str | None) -> str:
    if requested:
        address, refusal = (
            resolver_address(requested),
            (2, "Pass a resolver address, such as 127.0.0.1."),
        )
    else:
        address, refusal = (
            system_resolver(),
            (1, "No resolver is set. Pass --resolver with an address."),
        )
    if not address:
        raise cli.CommandExit(*refusal)
    return address


def _vet(parsed: argparse.Namespace) -> tuple[str, str]:
    cli.check(parsed, [cli.ENDPOINT_RULE])
    name = normalize_name(parsed.name)
    if not name:
        raise cli.CommandExit(2, "Give a hostname, such as app.internal.")
    if allowed(name):
        return name, pick_resolver(parsed.resolver)
    raise cli.CommandExit(2, explain_block(name))


def _query(name: str, resolver: str, parsed: argparse.Namespace):
    try:
        return lookup(name, resolver, parsed.port, parsed.timeout)
    except ValueError as failure:
        raise cli.CommandExit(1, str(failure)) from failure
    except OSError as failure:
        raise cli.CommandExit(
            1, f"Could not look up {name}: {type(failure).__name__}"
        ) from failure


def _report(
    name: str, found: dict[str, list[str]], notes: list[str], failed: bool
) -> int:
    rows = [
        f"{label}\t{termio.neutralize(value)}"
        for label, _code in RECORD_TYPES
        for value in found[label]
    ]
    for row in rows:
        print(row)
    for remark in notes:
        termio.say(remark)
    if rows:
        return 0
    termio.say(f"{name} lookup failed." if failed else "no records")
    return int(failed)


def _run(parsed: argparse.Namespace) -> int:
    name, resolver = _vet(parsed)
    found, notes, failed = _query(name, resolver, parsed)
    return _report(name, found, notes, failed)


def main(argv: list[str] | None = None) -> int:
    return cli.run(_run, build_parser().parse_args(argv))
