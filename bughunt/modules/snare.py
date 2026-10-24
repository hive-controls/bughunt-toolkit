"""snare: a loopback-only capture proxy for in-scope HTTP and intercepted HTTPS.

Layers, top to bottom of this file: constants and look, console formatters, the HTTP message
model (pure parsing and rebuilding), blocking wire reads, the capture store, the local CA, the
per-connection pipeline, the listener, the console job, and the command line.
"""

from __future__ import annotations

import argparse
import contextlib
from contextvars import ContextVar, copy_context
import functools
import ipaddress
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit

from bughunt.core import banner, egress, identity, ledger, termio
from bughunt.core.workspace import (
    allowed,
    authority,
    requests_dir,
    responses_dir,
    split_host,
    urls_path,
    workspace_dir,
)

_NAME = "snare"
_STRAPLINE = "the web the browser flies into"
_LOOPBACK = "127.0.0.1"

_DEFAULT_PORT = 8080
_DEFAULT_TIMEOUT = 10.0
_DEFAULT_KEEP = 1_000_000
_FORWARD_FLOOR = 8_000_000
_HEAD_LIMIT = 64 * 1024
_RECV_SIZE = 65_536
_NAME_CAP = 200
_SERIAL_CEILING = 100_000
_BACKLOG = 64
_ACCEPT_POLL = 0.2
_READY_WAIT = 30
_JOIN_WAIT = 3
_OPENSSL_WAIT = 30
_CA_DAYS = 825
_LEAF_DAYS = 30
_OWNER_ONLY = 0o600
_capture_deadline: ContextVar[float | None] = ContextVar(
    "snare_capture_deadline", default=None
)

_CRLF = b"\r\n"
_STRICT_LINE_END = re.compile(r"\r\n|\n")
_STRAY_BREAKS = re.compile("[\r\x0b\x0c\x1c\x1d\x1e\x85]")
_HEAD_ENDS = (_CRLF * 2, b"\n\n")
_TUNNEL_READY = b"HTTP/1.1 200 Connection Established" + _CRLF * 2
_HOP_BY_HOP = frozenset(
    "connection proxy-connection keep-alive te trailer upgrade transfer-encoding "
    "proxy-authorization".split()
)

_PROMPT_FREE = "The prompt is free. Other modules keep working."
_STOP_HINT = "snare stop closes the listener."
_TRUST_HINT = "Trust that certificate in the test browser."
_IDLE_NOTE = "snare is not listening."
_UNBOUND_NOTE = "snare did not bind."
_DROPPED_NOTE = "snare dropped one connection."
_BAD_HOST_NOTE = "That host cannot have a certificate."
_OPENSSL_FAILED = "openssl failed."

_Fields = list[tuple[str, str]]


class CaError(Exception):
    """The CA or a leaf certificate could not be produced."""


class _WireError(Exception):
    """Base of the failures raised while reading a message off a socket."""


class _Malformed(_WireError):
    """Input that is malformed, or that the peer closed early."""


class _Oversize(_WireError):
    """A size limit was exceeded."""


_REPLIES = {
    "malformed": (400, "Bad request"),
    "scope": (403, "Outside scope"),
    "policy": (403, "Mission policy blocked"),
    "actor": (403, "Actor blocked"),
    "oversize": (413, "Body is too large"),
    "upstream": (502, "Upstream failed"),
    "no_tls": (502, "HTTPS is unavailable"),
}


class _Refuse(Exception):
    """A request that gets a short error reply instead of being relayed."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.code, self.reason = _REPLIES[kind]


@dataclass
class Settings:
    port: int = _DEFAULT_PORT
    timeout: float = _DEFAULT_TIMEOUT
    insecure: bool = False
    max_body: int = _DEFAULT_KEEP
    plain: bool = False
    bound_port: int = 0
    ready: threading.Event | None = None
    forward_limit: int = field(init=False)

    def __post_init__(self) -> None:
        self.forward_limit = max(self.max_body, _FORWARD_FLOOR)


_STATUS_HUE = {"2": "green", "3": "cyan", "4": "yellow", "5": "red"}
_SIGIL = (
    (14, "\\   |   /"),
    (15, "\\  |  /"),
    (12, ".---\\ | /---."),
    (11, "/     \\|/     \\"),
    (10, "|     snare     |"),
    (11, "\\     /|\\     /"),
    (12, "'---/ | \\---'"),
    (15, "/  |  \\"),
    (14, "/   |   \\"),
    (16, "[web]"),
)
_CLUTCH = "clutch"
_GUIDE_VERB = re.compile("|".join(map(re.escape, (f"{_CLUTCH} show", _CLUTCH, "diff"))))


def format_banner(color: bool) -> str:
    return banner.render_banner(banner.art_rows(_SIGIL), _NAME, _STRAPLINE, color)


def _inked_row(
    method: str, status: str, size: int, location: str, name: str, note: str
) -> str:
    ink = banner.ANSI
    leading = [
        ink.wrap("cyan", f"{method:<7}"),
        ink.wrap(_STATUS_HUE.get(status[:1], "white"), f"{status:<3}"),
        ink.wrap("dim", f"{size:>8}"),
    ]
    trailing = [(2, "white", location), (2, "magenta", name), (1, "yellow", note)]
    return " ".join(leading) + "".join(
        " " * gap + ink.wrap(hue, text) for gap, hue, text in trailing if text
    )


def format_row(
    method: str,
    status: str,
    size: int,
    host: str,
    path: str,
    color: bool,
    *,
    name: str = "",
    note: str = "",
) -> str:
    if color:
        return _inked_row(method, status, size, f"{host} {path}", name, note)
    return "\t".join(
        [method, status, str(size), host, path, *filter(None, (name, note))]
    )


def _notice(verb: str, subject: str, color: bool) -> str:
    if color:
        return (
            banner.ANSI.wrap("yellow", verb)
            + " " * (9 - len(verb))
            + banner.ANSI.wrap("dim", subject)
        )
    return f"{verb}\t{subject}"


def format_skip(host: str, color: bool) -> str:
    return _notice("skipped", host, color)


def format_tunnel(host: str, port: int, color: bool) -> str:
    return _notice("tunnel", f"{host}:{port}", color)


def _display(folder: Path) -> str:
    resolved, here = folder.resolve(), Path.cwd().resolve()
    return (
        resolved.relative_to(here) if resolved.is_relative_to(here) else folder
    ).as_posix()


def _guide_rows() -> list[tuple[str, str]]:
    first, second = (f"example.com-{_NAME}-{serial:04d}.http" for serial in (1, 2))
    return [
        ("requests", f"{_display(requests_dir())}/{first}"),
        ("responses", f"{_display(responses_dir())}/{first}"),
        ("view", _CLUTCH),
        ("", f"{_CLUTCH} show {first}"),
        ("compare", f"diff {first} {second}"),
    ]


def _guide_line(label: str, value: str, color: bool) -> str:
    ink = banner.ink(color)
    lead = ink.wrap("cyan", f"{label:<10}") if label else " " * 10
    verb = _GUIDE_VERB.match(value)
    if verb:
        value = f"{ink.magenta}{verb[0]}{ink.reset}{ink.white}{value[verb.end() :]}"
    return f"{lead}{ink.white}{value}{ink.reset}"


def format_guide(color: bool) -> str:
    return "\n".join(_guide_line(label, value, color) for label, value in _guide_rows())


@dataclass
class _Job:
    settings: Settings
    stop: threading.Event
    thread: threading.Thread


class _Board:
    """The one background listener the console may hold, plus its prompt-redraw hook."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.job: _Job | None = None
        self.redraw: Callable[[str], None] | None = None

    def live(self) -> _Job | None:
        with self.lock:
            job = self.job
        return job if job is not None and job.thread.is_alive() else None


_board = _Board()
_row_lock = threading.Lock()
_to_stdout = functools.partial(print, flush=True)


def _rows_in_color(settings: Settings) -> bool:
    return termio.stdout_color(settings.plain)


def _publish(line: str) -> None:
    if _capture_deadline.get() is not None:
        return
    with _row_lock:
        hook = _board.redraw
        (_to_stdout if hook is None else hook)(line)


def _say_guide(plain: bool) -> None:
    termio.say(format_guide(not plain and termio.color_enabled(sys.stderr)))


def _report_idle() -> int:
    termio.say(_IDLE_NOTE)
    _say_guide(False)
    return 0


@dataclass
class _Message:
    line: str
    headers: _Fields


@dataclass(frozen=True)
class _Site:
    """Where a proxied request is going."""

    scheme: str
    host: str
    port: int
    path: str

    @property
    def url(self) -> str:
        return _url_for(self.scheme, self.host, self.port, self.path)


def _split_head(data: bytes | bytearray) -> tuple[bytes, bytes] | None:
    """Cut at the first blank line, preferring the CRLF form over the bare-LF form."""
    for marker in _HEAD_ENDS:
        at = data.find(marker)
        if at >= 0:
            return bytes(data[:at]), bytes(data[at + len(marker) :])
    return None


def _decode_message(head: bytes) -> _Message | None:
    text = head.decode("latin-1", errors="replace").strip()
    lines = (
        [_STRAY_BREAKS.sub(" ", line) for line in _STRICT_LINE_END.split(text)]
        if text
        else []
    )
    if not lines:
        return None
    first, *rest = lines
    cells = (row.partition(":") for row in rest)
    return _Message(
        first.strip(),
        [(key.strip(), value.strip()) for key, colon, value in cells if colon],
    )


def _dissect_request_line(line: str) -> tuple[str, str, str] | None:
    tokens = line.split()
    if len(tokens) < 2 or tokens[0].upper().startswith("HTTP/"):
        return None
    method, target, *tail = tokens
    return method, target, tail[0] if tail else "HTTP/1.1"


def _first_value(headers: Iterable[tuple[str, str]], name: str) -> str:
    wanted = name.lower()
    return next((value for key, value in headers if key.lower() == wanted), "")


def _hop_names(headers: _Fields) -> frozenset[str]:
    named = {
        token.strip().lower()
        for key, value in headers
        if key.lower() == "connection"
        for token in value.split(",")
    }
    return _HOP_BY_HOP | (named - {""})


class _Framing(NamedTuple):
    kind: str  # "none", "length" or "chunked"
    size: int = 0


def _framing_of(headers: _Fields) -> _Framing:
    if "chunked" in _first_value(headers, "transfer-encoding").lower():
        return _Framing("chunked")
    declared = _first_value(headers, "content-length").partition(",")[0].strip()
    if not declared:
        return _Framing("none")
    if not re.fullmatch(r"[0-9]+", declared):
        raise _Malformed
    return _Framing("length", int(declared))


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _url_for(scheme: str, host: str, port: int, path: str) -> str:
    netloc = authority(host, port, omit=(_default_port(scheme),))
    return f"{scheme}://{netloc}{path if path.startswith('/') else '/' + path}"


def _host_value(host: str, port: int) -> str:
    return authority(host, port, omit=(80, 443))


def _port_digits(text: str) -> int | None:
    return int(text) if text.isascii() and text.isdigit() else None


def _authority_parts(value: str) -> tuple[str, int | None]:
    bare = value.strip()
    if bare[:1] == "[" and "]" not in bare:
        return "", None
    host, declared = split_host(bare)
    return host, _port_digits(declared or "")


def _canonical_host(host: str | None) -> str:
    return (host or "").lower().rstrip(".")


def _site_from_url(target: str) -> _Site | None:
    url = urlsplit(target)
    if url.scheme not in ("http", "https") or not url.hostname:
        return None
    query = f"?{url.query}" if url.query else ""
    return _Site(
        url.scheme,
        _canonical_host(url.hostname),
        url.port or _default_port(url.scheme),
        (url.path or "/") + query,
    )


def _locate(
    target: str, scheme: str | None, default_host: str, default_port: int | None
) -> _Site | None:
    if "://" in target:
        return _site_from_url(target)
    host = _canonical_host(default_host)
    if host == "":
        return None
    chosen = scheme or "http"
    return _Site(chosen, host, default_port or _default_port(chosen), target or "/")


def _serialize(
    start_line: str, fields: Iterable[tuple[str, str]], body: bytes
) -> bytes:
    head = (
        "\r\n".join([start_line, *(f"{name}: {value}" for name, value in fields)])
        + "\r\n\r\n"
    )
    return head.encode("latin-1", errors="replace") + body


def _rebuild_request(
    method: str,
    path: str,
    version: str,
    headers: _Fields,
    body: bytes,
    host: str,
    port: int,
) -> bytes:
    dropped = _hop_names(headers) | {"content-length"}
    fields = [
        (name, "identity" if name.lower() == "accept-encoding" else value)
        for name, value in headers
        if name.lower() not in dropped
    ]
    present = {name.lower() for name, _ in fields}
    if "host" not in present:
        fields.append(("Host", _host_value(host, port)))
    if "accept-encoding" not in present:
        fields.append(("Accept-Encoding", "identity"))
    fields += [("Content-Length", str(len(body))), ("Connection", "close")]
    return _serialize(f"{method} {path} {version}", fields, body)


def _rebuild_response(message: _Message, body: bytes, *, method: str = "GET") -> bytes:
    dropped = _hop_names(message.headers) | {"transfer-encoding"}
    if method != "HEAD":
        dropped |= {"content-length"}
    fields = [
        (name, value) for name, value in message.headers if name.lower() not in dropped
    ]
    if method != "HEAD":
        fields.append(("Content-Length", str(len(body))))
    fields.append(("Connection", "close"))
    return _serialize(message.line, fields, b"" if method == "HEAD" else body)


def _require_message(head: bytes) -> _Message:
    if (message := _decode_message(head)) is not None:
        return message
    raise _Malformed


def _unpack_reply(data: bytes) -> tuple[_Message, bytes]:
    head, body = _split_head(data) or (b"", b"")
    return _require_message(head), body


def _status_code(status_line: str) -> str:
    pieces = status_line.split()
    return (
        pieces[1] if len(pieces) > 1 and pieces[0].startswith("HTTP/") else status_line
    )


def _bodyless_status(status_line: str) -> bool:
    code = _status_code(status_line)
    return status_line.startswith("HTTP/") and (
        code in ("204", "304") or code.startswith("1")
    )


def _clip_body(payload: bytes, cap: int) -> bytes:
    head, marker, body = payload.partition(_CRLF * 2)
    return head + marker + body[:cap]


class _Inbox:
    """Buffers one socket and hands out the head, lines, counted slices and the unframed rest.

    `read_exact` is also the body-reader seam `_handle_exchange` is exercised through.
    """

    def __init__(self, sock, deadline: float) -> None:
        sock.settimeout(_bounded_timeout(deadline))
        self._timeout = deadline
        self._sock = sock
        self._held = bytearray()

    def _more(self) -> bool:
        self._sock.settimeout(_bounded_timeout(self._timeout))
        chunk = self._sock.recv(_RECV_SIZE)
        self._held += chunk
        return bool(chunk)

    def _release(self, count: int) -> bytes:
        taken = bytes(self._held[:count])
        del self._held[:count]
        return taken

    def head(self) -> bytes:
        cut = _split_head(self._held)
        while cut is None and self._more():
            if len(self._held) > _HEAD_LIMIT:
                raise _Oversize
            cut = _split_head(self._held)
        if cut is None:
            raise _Malformed
        self._held[:] = cut[1]
        return cut[0]

    def line(self) -> bytes:
        while (end := self._held.find(b"\n")) < 0:
            if len(self._held) > _HEAD_LIMIT:
                raise _Oversize
            if not self._more():
                raise _Malformed
        return self._release(end + 1).rstrip(b"\r\n")

    def read_exact(self, count: int) -> bytes:
        if count < 0:
            raise _Malformed
        while len(self._held) < count and self._more():
            pass
        if len(self._held) < count:
            raise _Malformed
        return self._release(count)

    def until_close(self, limit: int) -> bytes:
        with contextlib.suppress(TimeoutError):
            while len(self._held) < limit and self._more():
                pass
        return self._release(limit)


def _chunk_size(line: bytes) -> int:
    token = line.split(b";", 1)[0].strip() or b"0"
    with contextlib.suppress(ValueError):
        size = int(token, 16)
        if size >= 0:
            return size
    raise _Malformed


def _chunks(inbox: _Inbox, limit: int) -> Iterator[bytes]:
    seen = 0
    while (size := _chunk_size(inbox.line())) > 0:
        seen += size
        if seen > limit:
            raise _Oversize
        yield inbox.read_exact(size)
        inbox.read_exact(len(_CRLF))
    while inbox.line():
        pass


def _empty_body(inbox: _Inbox, limit: int) -> bytes:
    return b""


def _read_until_close(inbox: _Inbox, limit: int) -> bytes:
    body = inbox.until_close(limit)
    if len(body) >= limit:
        raise _Oversize
    return body


def _read_body(
    inbox: _Inbox,
    headers: _Fields,
    limit: int,
    *,
    when_unframed: Callable[[_Inbox, int], bytes],
) -> bytes:
    match _framing_of(headers):
        case _Framing("chunked", _):
            return b"".join(_chunks(inbox, limit))
        case _Framing("length", size) if size > limit:
            raise _Oversize
        case _Framing("length", size):
            return inbox.read_exact(size)
        case _:
            return when_unframed(inbox, limit)


def _read_upstream(inbox: _Inbox, limit: int, *, method: str = "GET") -> bytes:
    reply = _require_message(inbox.head())
    if method == "HEAD":
        return _rebuild_response(reply, b"", method=method)
    body = (
        b""
        if _bodyless_status(reply.line)
        else _read_body(inbox, reply.headers, limit, when_unframed=_read_until_close)
    )
    return _rebuild_response(reply, body)


def _client_tls(raw: socket.socket, host: str, verify: bool) -> ssl.SSLSocket:
    tls = ssl.create_default_context()
    if not verify:
        tls.check_hostname = False
        tls.verify_mode = ssl.CERT_NONE
    return tls.wrap_socket(raw, server_hostname=host or None)


@contextlib.contextmanager
def _upstream(
    host: str, port: int, scheme: str, settings: Settings
) -> Iterator[socket.socket]:
    with socket.create_connection(
        (host, port), _bounded_timeout(settings.timeout)
    ) as raw:
        raw.settimeout(_bounded_timeout(settings.timeout))
        if scheme != "https":
            yield raw
            return
        with _client_tls(raw, host, not settings.insecure) as secured:
            yield secured


def _fetch_wire(
    host: str, port: int, scheme: str, payload: bytes, settings: Settings
) -> bytes:
    with _upstream(host, port, scheme, settings) as link:
        link.sendall(payload)
        method = payload.split(b" ", 1)[0].decode("ascii")
        return _read_upstream(
            _Inbox(link, settings.timeout), settings.forward_limit, method=method
        )


def _stamp_policy_headers(payload: bytes, profile) -> bytes:
    head, marker, body = payload.partition(_CRLF * 2)
    lines = head.split(_CRLF)
    for name, value in (*profile.required_headers, ("User-Agent", profile.user_agent)):
        prefix = f"{name.lower()}:".encode()
        lines = [row for row in lines if not row.lower().startswith(prefix)] + [
            f"{name}: {value}".encode()
        ]
    return _CRLF.join(lines) + marker + body


def _fetch(
    host: str,
    port: int,
    scheme: str,
    payload: bytes,
    settings: Settings,
    *,
    return_sent: bool = False,
):
    method, path, _version = payload.split(_CRLF, 1)[0].decode("ascii").split(" ", 2)
    url = _url_for(scheme, host, port, path)
    selection = identity.selection_signature()
    with egress.action(url, "manual", method) as profile:
        payload = _stamp_policy_headers(payload, profile)
        payload, actor = identity.apply_raw_headers(payload, url, prior=selection)
        signature = egress._actor_signature()
        response = egress.dispatch(
            url,
            "manual",
            method,
            lambda: _fetch_wire(host, port, scheme, payload, settings),
            check=lambda: egress._raw_ready(
                profile, signature, (url,), "manual", method
            ),
        )
    return (response, payload, actor) if return_sent else response


_store_lock = threading.Lock()


def _file_stem(host: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", host.lower()).strip("._")
    return (cleaned or "host")[:_NAME_CAP]


def _next_serial(stem: str) -> int:
    taken = re.compile(rf"{re.escape(stem)}-{_NAME}-([0-9]+)\.http")
    serials = [
        int(hit.group(1))
        for folder in (requests_dir(), responses_dir())
        if folder.is_dir()
        for entry in folder.iterdir()
        if (hit := taken.fullmatch(entry.name))
    ]
    serial = max(serials, default=0) + 1
    if serial > _SERIAL_CEILING:
        raise _Malformed
    return serial


def _note_url(url: str) -> None:
    listing = urls_path()
    with contextlib.suppress(FileNotFoundError):
        known = listing.read_text(encoding="utf-8", errors="replace").splitlines()
        if url in {row.strip() for row in known}:
            return
    os.makedirs(listing.parent, exist_ok=True)
    with listing.open("a", encoding="utf-8") as out:
        out.write(f"{url}\n")


def _write_pair(host: str, request: bytes, response: bytes) -> str:
    stem = _file_stem(host)
    name = f"{stem}-{_NAME}-{_next_serial(stem):04d}.http"
    for folder, payload in ((requests_dir(), request), (responses_dir(), response)):
        os.makedirs(folder, exist_ok=True)
        (folder / name).write_bytes(payload)
    return name


def _store(
    request: bytes,
    response: bytes,
    url: str,
    host: str,
    *,
    actor: str | None = None,
    truncated: bool = False,
) -> str:
    method = request.split(None, 1)[0].decode("latin-1") if request.strip() else ""
    profile = egress.authorize(url, "manual", method)
    capture = ledger.begin(
        profile,
        tool="snare",
        operation="manual",
        target=url,
        request=request,
        actor=identity.selected_name() if actor is None else actor,
        truncated=truncated,
    )
    capture.manifest["representation"] = "raw-http capture"
    head, _, body = response.partition(_CRLF * 2)
    capture.response_prefix = head + _CRLF * 2
    capture.feed(body)
    capture.truncated = truncated
    with _store_lock:
        name = _write_pair(host, request, response)
        capture.manifest["source_files"] = {
            "request": f"requests/{name}",
            "response": f"responses/{name}",
        }
        capture.finish()
        _note_url(url)
    return name


_leaf_lock = threading.Lock()


def _ini(**sections: tuple[str, ...]) -> str:
    return "".join(
        f"[{title}]\n" + "".join(f"{line}\n" for line in lines)
        for title, lines in sections.items()
    )


def _options(*items: str | tuple[str, str | int]) -> list[str]:
    argv: list[str] = []
    for item in items:
        flag, *value = (item,) if isinstance(item, str) else item
        argv += [f"-{flag}", *map(str, value)]
    return argv


_HOSTLIKE = re.compile(r"[A-Za-z0-9._:-]+")
_CA_CONFIG = _ini(
    req=("distinguished_name=dn", "x509_extensions=v3_ca", "prompt=no"),
    dn=("CN=Bughunt snare CA",),
    v3_ca=(
        "basicConstraints=critical,CA:TRUE",
        "keyUsage=critical,keyCertSign,cRLSign",
        "subjectKeyIdentifier=hash",
    ),
)


def _subject_alt_name(host: str) -> str:
    with contextlib.suppress(ValueError):
        return f"IP:{ipaddress.ip_address(host)}"
    return f"DNS:{host}"


def _leaf_config(host: str) -> str:
    return _ini(
        req=("distinguished_name=dn", "prompt=no"),
        dn=(f"CN={host}",),
        v3=(
            "basicConstraints=CA:FALSE",
            f"subjectAltName={_subject_alt_name(host)}",
            "keyUsage=digitalSignature,keyEncipherment",
            "extendedKeyUsage=serverAuth",
        ),
    )


def _home() -> Path:
    return workspace_dir() / _NAME


def _pair_in(folder: Path, stem: str) -> tuple[Path, Path]:
    return folder / f"{stem}.crt", folder / f"{stem}.key"


def _last_line(raw: bytes) -> str:
    lines = raw.decode("utf-8", errors="replace").strip().splitlines()
    return lines[-1] if lines else _OPENSSL_FAILED


@egress.guarded("process", lambda bound: ["http://localhost/"])
def _openssl(args: list[str], cwd: Path) -> None:
    try:
        done = subprocess.run(
            ["openssl", *args],
            cwd=cwd,
            check=False,
            capture_output=True,
            timeout=_bounded_timeout(_OPENSSL_WAIT),
        )
    except FileNotFoundError:
        raise CaError("openssl is not on PATH.") from None
    except subprocess.TimeoutExpired:
        raise CaError("openssl took too long.") from None
    if done.returncode != 0:
        raise CaError(_last_line(done.stderr))


def ensure_ca() -> tuple[Path, Path]:
    home = _home()
    pair = cert, key = _pair_in(home, "ca")
    if all(member.exists() for member in pair):
        return pair
    os.makedirs(home, exist_ok=True)
    (home / "ca.cnf").write_text(_CA_CONFIG, encoding="utf-8")
    _openssl(
        [
            "req",
            "-x509",
            *_options(
                ("newkey", "rsa:2048"),
                ("keyout", key.name),
                ("out", cert.name),
                ("days", _CA_DAYS),
                "nodes",
                ("config", "ca.cnf"),
            ),
        ],
        home,
    )
    os.chmod(key, _OWNER_ONLY)
    return pair


def issue_leaf(host: str) -> tuple[Path, Path]:
    if _HOSTLIKE.fullmatch(host) is None:
        raise CaError(_BAD_HOST_NOTE)
    stem = host.replace(":", "_")
    leafs = _home() / "leafs"
    pair = cert, key = _pair_in(leafs, stem)
    with _leaf_lock:
        if all(member.exists() for member in pair):
            return pair
        issuer_cert, issuer_key = ensure_ca()
        os.makedirs(leafs, exist_ok=True)
        config, csr = leafs / f"{stem}.cnf", f"{stem}.csr"
        config.write_text(_leaf_config(host), encoding="utf-8")
        _openssl(
            [
                "req",
                "-new",
                *_options(
                    ("newkey", "rsa:2048"),
                    ("keyout", key.name),
                    ("out", csr),
                    "nodes",
                    ("config", config.name),
                ),
            ],
            leafs,
        )
        _openssl(
            [
                "x509",
                "-req",
                *_options(
                    ("in", csr),
                    ("CA", str(issuer_cert)),
                    ("CAkey", str(issuer_key)),
                    ("CAserial", str(_home() / "ca.srl")),
                    "CAcreateserial",
                    ("out", cert.name),
                    ("days", _LEAF_DAYS),
                    ("extfile", config.name),
                    ("extensions", "v3"),
                ),
            ],
            leafs,
        )
        os.chmod(key, _OWNER_ONLY)
    return pair


def _announce_ca() -> None:
    try:
        cert, _ = ensure_ca()
    except CaError as problem:
        termio.say(str(problem))
        termio.say("HTTP still logs. HTTPS inside scope needs openssl.")
        return
    termio.say(f"CA {cert}")
    termio.say(_TRUST_HINT)


def _send_status(sock, code: int, reason: str) -> None:
    plain = reason.encode("ascii", errors="replace")
    fields = [("Content-Length", str(len(plain))), ("Connection", "close")]
    with contextlib.suppress(OSError):
        sock.sendall(_serialize(f"HTTP/1.1 {code} {plain.decode()}", fields, plain))


@contextlib.contextmanager
def _answering(sock) -> Iterator[None]:
    """Turn a `_Refuse` raised inside the block into its short error reply on `sock`."""
    try:
        yield
    except _Refuse as refusal:
        _send_status(sock, refusal.code, refusal.reason)


def _clear(host: str, target: str, method: str) -> None:
    """Scope first, then mission policy; either one refuses with its own reply."""
    if allowed(host):
        try:
            egress.authorize(target, "manual", method)
        except egress.PolicyBlocked:
            raise _Refuse("policy") from None
    else:
        raise _Refuse("scope")


def _forward(site: _Site, wire: bytes, settings: Settings) -> tuple[bytes, bytes, str]:
    try:
        return _fetch(
            site.host, site.port, site.scheme, wire, settings, return_sent=True
        )
    except identity.IdentityError:
        raise _Refuse("actor") from None
    except (OSError, _WireError, egress.PolicyBlocked):
        raise _Refuse("upstream") from None


def _keep(
    site: _Site,
    method: str,
    request_body: bytes,
    sent: bytes,
    reply: bytes,
    actor: str,
    settings: Settings,
) -> None:
    answer, full_body = _unpack_reply(reply)
    cap = settings.max_body
    clipped = max(len(request_body), len(full_body)) > cap
    name = _store(
        _clip_body(sent, cap),
        _rebuild_response(answer, full_body[:cap], method=method),
        site.url,
        site.host,
        actor=actor,
        truncated=clipped,
    )
    _publish(
        format_row(
            method.upper(),
            _status_code(answer.line),
            len(full_body),
            site.host,
            site.path,
            _rows_in_color(settings),
            name=name,
            note="truncated" if clipped else "",
        )
    )


def _capture(
    inbox,
    message: _Message,
    method: str,
    target: str,
    version: str,
    settings: Settings,
    scheme: str | None,
    default_port: int | None,
    default_host: str,
) -> bytes:
    site = _locate(target, scheme, default_host, default_port)
    if site is None:
        raise _Refuse("malformed")
    _clear(site.host, site.url, method)
    body = _read_body(
        inbox, message.headers, settings.forward_limit, when_unframed=_empty_body
    )
    wire = _rebuild_request(
        method, site.path, version, message.headers, body, site.host, site.port
    )
    reply, sent, actor = _forward(site, wire, settings)
    _keep(site, method, body, sent, reply, actor, settings)
    return reply


def _handle_exchange(
    sock,
    reader,
    message: _Message,
    method: str,
    target: str,
    version: str,
    settings: Settings,
    *,
    scheme: str | None,
    default_port: int | None,
    default_host: str = "",
) -> None:
    with _answering(sock):
        reply = _capture(
            reader,
            message,
            method,
            target,
            version,
            settings,
            scheme,
            default_port,
            default_host,
        )
        sock.sendall(reply)


def _admit_tunnel(target: str) -> tuple[str, int]:
    host, declared = _authority_parts(target)
    if host:
        port = 443 if declared is None else declared
        _clear(host, egress.endpoint(host, port), "CONNECT")
        return host, port
    raise _Refuse("malformed")


def _leaf_or_refuse(host: str) -> tuple[Path, Path]:
    try:
        return issue_leaf(host)
    except CaError as problem:
        termio.say(str(problem))
        raise _Refuse("no_tls") from None


def _read_request(inbox: _Inbox) -> tuple[_Message, tuple[str, str, str]] | None:
    message = _decode_message(inbox.head())
    parts = _dissect_request_line(message.line) if message else None
    return (message, parts) if parts else None


def _server_tls(cert: Path, key: Path) -> ssl.SSLContext:
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    return tls


def _serve_tunnelled(
    tls: ssl.SSLSocket, host: str, port: int, settings: Settings
) -> None:
    inbox = _Inbox(tls, settings.timeout)
    request = _read_request(inbox)
    if request is not None:
        message, (method, target, version) = request
        _handle_exchange(
            tls,
            inbox,
            message,
            method,
            target,
            version,
            settings,
            scheme="https",
            default_port=port,
            default_host=host,
        )


def _handle_connect(conn, target: str, settings: Settings) -> None:
    with _answering(conn):
        host, port = _admit_tunnel(target)
        cert, key = _leaf_or_refuse(host)
        conn.sendall(_TUNNEL_READY)
        with _server_tls(cert, key).wrap_socket(conn, server_side=True) as tls:
            _serve_tunnelled(tls, host, port, settings)


@egress.guarded("manual", lambda args: [egress.endpoint(args["host"], args["port"])])
def _tunnel(conn, host: str, port: int, settings: Settings) -> None:
    remote = None
    with contextlib.suppress(OSError):
        remote = socket.create_connection((host, port), settings.timeout)
    if remote is None:
        _send_status(conn, *_REPLIES["upstream"])
        return
    with remote:
        _publish(format_tunnel(host, port, _rows_in_color(settings)))
        conn.sendall(_TUNNEL_READY)
        remote.settimeout(settings.timeout)
        _splice(conn, remote, timeout=settings.timeout)


def _pump(source, sink) -> None:
    with contextlib.suppress(OSError):
        try:
            while chunk := source.recv(_RECV_SIZE):
                sink.sendall(chunk)
        finally:
            with contextlib.suppress(OSError):
                sink.shutdown(socket.SHUT_WR)


def _splice(left, right, timeout: float) -> None:
    workers = [
        threading.Thread(target=copy_context().run, args=(_pump, *ends), daemon=True)
        for ends in ((left, right), (right, left))
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout)


def _route(conn, inbox: _Inbox, settings: Settings) -> None:
    request = _read_request(inbox)
    if request is None:
        _send_status(conn, *_REPLIES["malformed"])
        return
    message, (method, target, version) = request
    match method.upper():
        case "CONNECT":
            _handle_connect(conn, target, settings)
        case _:
            _handle_exchange(
                conn,
                inbox,
                message,
                method,
                target,
                version,
                settings,
                scheme=None,
                default_port=None,
            )


def _hang_up(sock) -> None:
    with contextlib.suppress(OSError):
        sock.close()


def _handle_client(conn: socket.socket, settings: Settings) -> None:
    try:
        _route(conn, _Inbox(conn, settings.timeout), settings)
    except _Oversize:
        _send_status(conn, *_REPLIES["oversize"])
    except (_WireError, TimeoutError, ConnectionError, ssl.SSLError):
        pass
    except Exception:
        if _capture_deadline.get() is None:
            termio.say(_DROPPED_NOTE)
    finally:
        _hang_up(conn)


def _signal_ready(settings: Settings) -> None:
    gate = settings.ready
    if gate is not None:
        gate.set()


def _is_loopback(address: str) -> bool:
    with contextlib.suppress(ValueError):
        return ipaddress.ip_address(address).is_loopback
    return False


def _open_socket(settings: Settings) -> socket.socket | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((_LOOPBACK, settings.port))
        sock.listen(_BACKLOG)
        sock.settimeout(_ACCEPT_POLL)
        _, settings.bound_port = sock.getsockname()
    except OSError:
        _hang_up(sock)
        return None
    return sock


def _accepted(
    sock: socket.socket, stop: threading.Event
) -> Iterator[tuple[socket.socket, str]]:
    while not stop.is_set():
        try:
            conn, address = sock.accept()
        except TimeoutError:
            continue
        except OSError:
            return
        yield conn, address[0]


def _hand_off(conn: socket.socket, settings: Settings) -> None:
    """One daemon thread per client, so a stalled peer never delays another."""
    handler = threading.Thread(
        target=copy_context().run, args=(_handle_client, conn, settings), daemon=True
    )
    handler.start()


def _serve(sock: socket.socket, settings: Settings, stop: threading.Event) -> None:
    for conn, peer in _accepted(sock, stop):
        if _is_loopback(peer):
            _hand_off(conn, settings)
        else:
            _hang_up(conn)


def _announce_listening(settings: Settings) -> None:
    termio.say(f"listening on {_LOOPBACK}:{settings.bound_port}")
    _announce_ca()
    _say_guide(settings.plain)
    _signal_ready(settings)


def listen(settings: Settings, stop: threading.Event) -> int:
    egress.authorize(egress.endpoint(_LOOPBACK, settings.port, "http"), "manual")
    egress.authorize("http://localhost/", "process")
    sock = _open_socket(settings)
    if sock is None:
        termio.say(f"Could not listen on {_LOOPBACK}:{settings.port}.")
        _signal_ready(settings)
        return 1
    try:
        _announce_listening(settings)
        _serve(sock, settings, stop)
    finally:
        _hang_up(sock)
        _signal_ready(settings)
    return 0


def _bounded_timeout(timeout: float) -> float:
    deadline = _capture_deadline.get()
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Capture duration elapsed")
    return min(timeout, remaining)


def prepare_capture(settings: Settings, *, seconds: float, max_exchanges: int) -> dict:
    if (
        not 0 < seconds <= 60
        or type(max_exchanges) is not int
        or not 1 <= max_exchanges <= 100
    ):
        raise ValueError("Capture requires 0 < seconds <= 60 and 1..100 exchanges")
    if (
        not 0 <= settings.port <= 65535
        or settings.timeout <= 0
        or not 1 <= settings.max_body <= ledger.CAPTURE_LIMIT
    ):
        raise ValueError("Invalid capture port, timeout, or body bound")
    egress.authorize(egress.endpoint(_LOOPBACK, settings.port, "http"), "manual")
    egress.authorize("http://localhost/", "process")
    return {
        "bind_host": _LOOPBACK,
        "port": settings.port,
        "seconds": seconds,
        "max_exchanges": max_exchanges,
        "max_connections": max_exchanges,
        "body_limit": settings.max_body,
        "outbound_actions": 0,
    }


def capture_bounded(settings: Settings, *, seconds: float, max_exchanges: int) -> dict:
    plan = prepare_capture(settings, seconds=seconds, max_exchanges=max_exchanges)
    plan.pop("outbound_actions")
    deadline = time.monotonic() + seconds
    token = _capture_deadline.set(deadline)
    sock = None
    connections = 0
    try:
        sock = _open_socket(settings)
        if sock is None:
            raise OSError("Capture listener could not bind")
        _signal_ready(settings)
        with ledger.collect_runs() as runs:
            while connections < max_exchanges and time.monotonic() < deadline:
                try:
                    sock.settimeout(_bounded_timeout(_ACCEPT_POLL))
                    conn, address = sock.accept()
                except TimeoutError:
                    continue
                connections += 1
                if _is_loopback(address[0]):
                    _handle_client(conn, settings)
                else:
                    _hang_up(conn)
        return {
            **plan,
            "port": settings.bound_port,
            "connections": connections,
            "run_ids": list(runs),
            "stopped": "connection-limit"
            if connections == max_exchanges
            else "duration",
        }
    finally:
        if sock is not None:
            _hang_up(sock)
        _capture_deadline.reset(token)
        _signal_ready(settings)


def attach_console(redraw: Callable[[str], None] | None) -> None:
    with _board.lock:
        _board.redraw = redraw


def console_attached() -> bool:
    with _board.lock:
        return _board.redraw is not None


def job_tag() -> str:
    job = _board.live()
    return f"snare:{job.settings.bound_port}" if job and job.settings.bound_port else ""


def _run_background(settings: Settings, stop: threading.Event) -> None:
    try:
        listen(settings, stop)
    except egress.PolicyBlocked as problem:
        termio.say(str(problem))
    finally:
        _signal_ready(settings)


def _spawn(settings: Settings) -> _Job:
    settings.ready = threading.Event()
    halt = threading.Event()
    worker = threading.Thread(
        target=copy_context().run,
        args=(_run_background, settings, halt),
        name=_NAME,
        daemon=True,
    )
    worker.start()
    return _Job(settings, halt, worker)


def _claim(settings: Settings) -> tuple[_Job, bool]:
    with _board.lock:
        incumbent = _board.job
        if incumbent is not None and incumbent.thread.is_alive():
            return incumbent, False
        _board.job = _spawn(settings)
        return _board.job, True


def _await_binding(job: _Job) -> int:
    if not job.settings.ready.wait(_READY_WAIT):
        job.stop.set()
        termio.say(_UNBOUND_NOTE)
        return 1
    if job.settings.bound_port == 0 or not job.thread.is_alive():
        return 1
    termio.say(_PROMPT_FREE)
    termio.say(_STOP_HINT)
    return 0


def begin(settings: Settings) -> int:
    job, started = _claim(settings)
    if started:
        return _await_binding(job)
    termio.say(f"snare is already listening on {_LOOPBACK}:{job.settings.bound_port}.")
    _say_guide(bool(job.settings.plain))
    termio.say(_STOP_HINT)
    return 0


def stop_listener(*, quiet: bool = False) -> int:
    job = _board.live()
    if job is None:
        return 0 if quiet else _report_idle()
    job.stop.set()
    job.thread.join(_JOIN_WAIT)
    termio.say(f"snare stopped. It was on {_LOOPBACK}:{job.settings.bound_port}.")
    termio.say("The saved files stay where they are.")
    _say_guide(bool(job.settings.plain))
    return 0


def print_status() -> int:
    job = _board.live()
    if job is None:
        return _report_idle()
    termio.say(f"listening on {_LOOPBACK}:{job.settings.bound_port}")
    termio.say(_PROMPT_FREE)
    termio.say(_STOP_HINT)
    _say_guide(job.settings.plain)
    return 0


_SWITCHES = (
    (
        ("--plain",),
        {"action": "store_true", "help": "Skip the banner and the row colors."},
    ),
    (
        ("--port",),
        {
            "type": int,
            "default": _DEFAULT_PORT,
            "help": "Port on 127.0.0.1. 0 picks a free port.",
        },
    ),
    (
        ("--timeout",),
        {
            "type": float,
            "default": _DEFAULT_TIMEOUT,
            "help": "Seconds for a socket. Default 10.",
        },
    ),
    (
        ("--insecure",),
        {"action": "store_true", "help": "Do not verify upstream TLS certificates."},
    ),
    (
        ("--max-body",),
        {
            "type": int,
            "default": _DEFAULT_KEEP,
            "help": "Bytes kept from each body. Default 1000000.",
        },
    ),
)
_SUBCOMMANDS = (
    ("ca", "Write the CA, if needed, and print its certificate path."),
    ("status", "Show the port and where saved requests go."),
    ("stop", "Close the listener and leave the saved files in place."),
)
_OPTION_RULES: tuple[tuple[Callable[[argparse.Namespace], bool], str], ...] = (
    (lambda opts: not 0 <= opts.port <= 65535, "The port has to be from 0 to 65535."),
    (lambda opts: opts.timeout <= 0, "Timeout must be greater than 0."),
    (lambda opts: opts.max_body < 1, "The body cap has to be at least 1 byte."),
)


def build_parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        prog="bughunt snare",
        description="Capture scoped HTTP exchanges through a loopback proxy. "
        "Browse the saved traffic with clutch while the console remains available.",
    )
    for names, options in _SWITCHES:
        cli.add_argument(*names, **options)
    commands = cli.add_subparsers(dest="command")
    for name, summary in _SUBCOMMANDS:
        commands.add_parser(name, help=summary)
    capture = commands.add_parser(
        "capture", help="Capture a finite number of exchanges within a duration."
    )
    capture.add_argument("--seconds", type=float, required=True)
    capture.add_argument("--max-exchanges", type=int, required=True)
    return cli


def _show_ca() -> int:
    try:
        cert, _ = ensure_ca()
    except CaError as problem:
        termio.say(str(problem))
        return 1
    print(cert)
    termio.say(f"{_TRUST_HINT} The key stays beside it.")
    return 0


def _run_foreground(settings: Settings) -> int:
    termio.say(
        "Ctrl-C stops this listener. From the Bughunt prompt, snare stays up beside the other modules."
    )
    halt = threading.Event()
    try:
        return listen(settings, halt)
    except KeyboardInterrupt:
        halt.set()
        return 0


def _run_listener(settings: Settings) -> int:
    return begin(settings) if console_attached() else _run_foreground(settings)


def _first_complaint(options: argparse.Namespace) -> str | None:
    return next((text for broken, text in _OPTION_RULES if broken(options)), None)


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    match options.command:
        case "stop":
            return stop_listener()
        case "status":
            return print_status()
    if (complaint := _first_complaint(options)) is not None:
        termio.say(complaint)
        return 2
    if not options.plain:
        termio.show_banner(format_banner)
    if options.command == "ca":
        return _show_ca()
    if options.command == "capture":
        import json

        try:
            result = capture_bounded(
                Settings(
                    options.port,
                    options.timeout,
                    options.insecure,
                    options.max_body,
                    options.plain,
                ),
                seconds=options.seconds,
                max_exchanges=options.max_exchanges,
            )
        except (ValueError, OSError, egress.PolicyBlocked):
            return 2
        print(json.dumps(ledger.redact(result), sort_keys=True))
        return 0
    return _run_listener(
        Settings(
            options.port,
            options.timeout,
            options.insecure,
            options.max_body,
            options.plain,
        )
    )
