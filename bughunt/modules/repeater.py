"""repeater: edit one saved HTTP request, preview it, store it, or send it once more.

The module is split in three layers: a pure request toolkit (parse, edit, render, URL math),
the editor hand-off, and the send path (one `_Leg` per hop, walked by `_walk`).
"""

from __future__ import annotations

import argparse
import contextlib
import itertools
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit, urlunsplit

import httpx
from rich.markup import escape
from rich.text import Text

from bughunt.console import ui
from bughunt.core import egress, ledger
from bughunt.core.http import (
    is_credential_header,
    read_body,
    redirect_target,
    same_origin,
)
from bughunt.core.workspace import (
    allowed,
    authority,
    explain_block,
    explain_target,
    hostname_of,
    save_request,
    split_host,
)

_CEILING = 8 << 20
_SCREEN_BYTES = 512 << 10
_DRAIN_BYTES = 64 << 10
_HOP_BUDGET = 5
_DEMOTE_TO_GET = frozenset({301, 302, 303})
_WEB_SCHEMES = ("http", "https")
_BLANK_LINE = re.compile(rb"\r\n\r\n|\n\n")
_STRICT_LINE_END = re.compile(r"\r\n|\n")
_STRAY_BREAKS = re.compile("[\r\x0b\x0c\x1c\x1d\x1e\x85]")
_FRAMING_NAMES = frozenset({"content-length", "transfer-encoding"})
_NO_HOST_HINT = (
    "[err]The request has no host.[/err] Add a Host header, --host, or --connect."
)

_PROBLEMS = {
    "empty-file": "The request file is empty.",
    "no-request-line": "The request has no request line.",
    "short-request-line": "The request line needs a method and a target.",
    "nameless-line": "Header has no name: {line}",
    "nameless": "Header has no name.",
    "port-text": "Port {port} is not a number.",
    "port-range": "Port {port} is out of range.",
    "host-empty": "Host is empty.",
    "method-empty": "Method is empty.",
    "header-shape": "Header needs a name and a value: {item}",
    "no-such-file": "No file named {name}.",
    "body-too-big": "The request body is larger than 8 MB.",
    "web-only": "Only http and https requests can be sent.",
    "no-editor": "Set EDITOR or VISUAL to edit the request.",
    "editor-launch": "Could not run the editor: {why}",
    "editor-readback": "Could not read the edited request: {why}",
    "editor-empty": "The editor saved an empty request.",
    "edit-too-big": "The edited request is larger than 8 MB.",
}


def _problem(code: str, **detail: object) -> ValueError:
    return ValueError(_PROBLEMS[code].format(**detail))


@dataclass
class RawRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    scheme: str | None = None
    declare_length: bool = False


class _Stop(Exception):
    """Ends a run early: `message` goes to the console (rich markup unless told otherwise)."""

    def __init__(self, message: str, status: int = 2, **print_options) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.print_options = print_options


def _fail(text: str, status: int = 2) -> _Stop:
    return _Stop(f"[err]{escape(text)}[/err]", status)


@contextlib.contextmanager
def _as_usage_error() -> Iterator[None]:
    """Report a `ValueError` raised inside the block as a console error and exit status 2."""
    try:
        yield
    except ValueError as problem:
        raise _fail(str(problem)) from None


@contextlib.contextmanager
def _os_errors_as(code: str) -> Iterator[None]:
    try:
        yield
    except OSError as failure:
        raise _problem(code, why=failure) from failure


def _cut_message(data: bytes) -> tuple[bytes, bytes]:
    """Split at the first blank line, whichever line-ending style it uses."""
    blank = _BLANK_LINE.search(data)
    return (data[: blank.start()], data[blank.end() :]) if blank else (data, b"")


def _request_line(line: str) -> tuple[str, str, str]:
    pieces = line.split()
    if len(pieces) < 2:
        raise _problem("short-request-line")
    method, target, *tail = pieces
    return method, target, tail[0] if tail else "HTTP/1.1"


def _header_pair(line: str) -> tuple[str, str]:
    name, colon, value = line.partition(":")
    if not colon:
        raise _problem("nameless-line", line=line.strip())
    if not name.strip():
        raise _problem("nameless")
    return name.strip(), value.strip()


def _read_headers(lines: list[str]) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = []
    for line in filter(str.strip, lines):
        if fields and line[0] in " \t":
            held_name, held_value = fields.pop()
            fields.append((held_name, f"{held_value} {line.strip()}".strip()))
        else:
            fields.append(_header_pair(line))
    return fields


def _strict_lines(text: str) -> list[str]:
    """Split on CRLF/LF only; any other line-break character inside a line becomes a space."""
    return [_STRAY_BREAKS.sub(" ", line) for line in _STRICT_LINE_END.split(text)]


def parse_raw(data: bytes) -> RawRequest:
    if not data.lstrip():
        raise _problem("empty-file")
    head, body = _cut_message(data)
    first, *rest = _strict_lines(head.decode("latin-1"))
    if not first.strip():
        raise _problem("no-request-line")
    method, target, version = _request_line(first)
    headers = _read_headers(rest)
    sizes_body = bool(body) or any(
        name.lower() == "content-length" for name, _ in headers
    )
    return RawRequest(method.upper(), target, version, headers, body, None, sizes_body)


def render(req: RawRequest) -> bytes:
    declared = [("Content-Length", str(len(req.body)))] if req.declare_length else []
    sent = [
        (name, value)
        for name, value in req.headers
        if name.lower() not in _FRAMING_NAMES
    ] + declared
    lines = [
        f"{req.method} {req.target} {req.version or 'HTTP/1.1'}",
        *(f"{name}: {value}" for name, value in sent),
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode(
        "latin-1", errors="replace"
    ) + req.body


def first_header(req: RawRequest, name: str) -> str | None:
    wanted = name.lower()
    return next((value for key, value in req.headers if key.lower() == wanted), None)


def remove_header(req: RawRequest, name: str) -> None:
    wanted = name.lower()
    req.headers[:] = [
        (key, value) for key, value in req.headers if key.lower() != wanted
    ]


def replace_header(req: RawRequest, name: str, value: str) -> None:
    remove_header(req, name)
    req.headers.append((name, value))


def _is_absolute(target: str) -> bool:
    return "://" in target


def _bare_host(text: str) -> str:
    return text.strip().strip("[]")


def _port_number(raw: str | int | None) -> int | None:
    if raw in (None, ""):
        return None
    number = raw
    if isinstance(raw, str):
        if not (raw.isascii() and raw.isdigit()):
            raise _problem("port-text", port=raw)
        number = int(raw)
    if not 1 <= number <= 65535:
        raise _problem("port-range", port=number)
    return number


def _join_netloc(host: str, port: int | None) -> str:
    return authority(host, port or None)


def _host_and_port(text: str) -> tuple[str, int | None]:
    host_text, port_text = split_host(text)
    return _bare_host(host_text), _port_number(port_text)


def _retarget_host(target: str, value: str) -> str:
    host_text, port_text = split_host(value)
    url = urlsplit(target)
    port = _port_number(port_text) or url.port
    return urlunsplit(url._replace(netloc=_join_netloc(_bare_host(host_text), port)))


def set_host(req: RawRequest, value: str) -> None:
    if value == "":
        raise _problem("host-empty")
    replace_header(req, name="Host", value=value)
    if _is_absolute(req.target):
        req.target = _retarget_host(req.target, value)


def replace_path(target: str, path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    wanted = path if path.startswith(("/", "?")) else f"/{path}"
    if not _is_absolute(target):
        return wanted
    new_path, _, query = wanted.partition("?")
    return urlunsplit(
        urlsplit(target)._replace(path=new_path or "/", query=query, fragment="")
    )


def replace_scheme(target: str, scheme: str) -> str:
    return urlunsplit(urlsplit(target)._replace(scheme=scheme))


def _set_method(req: RawRequest, text: str) -> None:
    if not (method := text.strip().upper()):
        raise _problem("method-empty")
    req.method = method


def _set_path(req: RawRequest, text: str) -> None:
    req.target = replace_path(req.target, text.strip())


def _set_host_option(req: RawRequest, text: str) -> None:
    set_host(req, text.strip())


def _set_scheme(req: RawRequest, scheme: str) -> None:
    req.scheme = scheme
    if _is_absolute(req.target):
        req.target = replace_scheme(req.target, scheme)


def _apply_header_option(req: RawRequest, item: str) -> None:
    label, colon, text = item.partition(":")
    if not colon:
        raise _problem("header-shape", item=item)
    label = label.strip()
    if not label:
        raise _problem("nameless")
    if label.lower() == "host":
        set_host(req, text.strip())
    else:
        replace_header(req, label, text.strip())


def _read_body_file(name: str) -> bytes:
    source = Path(name)
    if not source.is_file():
        raise _problem("no-such-file", name=name)
    if source.stat().st_size > _CEILING:
        raise _problem("body-too-big")
    return source.read_bytes()


def _drop_header_option(req: RawRequest, item: str) -> None:
    remove_header(req, item.strip())


def _body_replacement(args) -> bytes | None:
    if (text := args.body) is not None:
        return text.encode("utf-8")
    return _read_body_file(args.body_file) if args.body_file else None


def _apply_body(req: RawRequest, args) -> None:
    replacement = _body_replacement(args)
    if replacement is not None:
        req.body, req.declare_length = replacement, True
        remove_header(req, "transfer-encoding")


_SCALAR_EDITS = (
    ("method", _set_method),
    ("path", _set_path),
    ("host", _set_host_option),
    ("scheme", _set_scheme),
)
_REPEATED_EDITS = (
    ("header", _apply_header_option),
    ("remove_header", _drop_header_option),
)


def apply_edits(req: RawRequest, args) -> RawRequest:
    for attribute, edit in _SCALAR_EDITS:
        supplied = getattr(args, attribute)
        if supplied is not None:
            edit(req, supplied)
    for attribute, edit in _REPEATED_EDITS:
        for item in getattr(args, attribute):
            edit(req, item)
    _apply_body(req, args)
    return req


def endpoint(req: RawRequest, connect: str | None) -> tuple[str, int | None]:
    if connect:
        return _host_and_port(connect.strip())
    if _is_absolute(req.target):
        url = urlsplit(req.target)
        return url.hostname or "", url.port
    declared = first_header(req, "Host")
    return ("", None) if declared is None else _host_and_port(declared)


def effective_scheme(req: RawRequest, port: int | None) -> str:
    if req.scheme in _WEB_SCHEMES:
        return req.scheme
    if not _is_absolute(req.target):
        return "https" if port == 443 else "http"
    scheme = urlsplit(req.target).scheme
    if scheme not in _WEB_SCHEMES:
        raise _problem("web-only")
    return scheme


def path_and_query(req: RawRequest) -> str:
    text = req.target.strip()
    if _is_absolute(text):
        url = urlsplit(text)
        return (url.path or "/") + (f"?{url.query}" if url.query else "")
    return text if text.startswith("/") else f"/{text}"


def request_url(req: RawRequest, connect: str | None) -> str:
    hostname, port = endpoint(req, connect)
    scheme = effective_scheme(req, port)
    return f"{scheme}://{_join_netloc(hostname, port)}{path_and_query(req)}"


@contextlib.contextmanager
def _scratch_copy(payload: bytes) -> Iterator[Path]:
    handle, name = tempfile.mkstemp(prefix="bughunt-request-", suffix=".http")
    scratch = Path(name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(payload)
        yield scratch
    finally:
        with contextlib.suppress(OSError):
            scratch.unlink()


def _chosen_editor() -> str:
    for variable in ("VISUAL", "EDITOR"):
        command = os.environ.get(variable, "").strip()
        if command:
            return command
    raise _problem("no-editor")


def _edited_bytes(editor: str, scratch: Path) -> bytes:
    with _os_errors_as("editor-launch"):
        subprocess.run([*shlex.split(editor), str(scratch)], check=False)
    with _os_errors_as("editor-readback"):
        return scratch.read_bytes()


@egress.guarded("process", lambda args: ["http://localhost/"])
def edit_request(req: RawRequest) -> RawRequest:
    editor = _chosen_editor()
    with _scratch_copy(render(req)) as scratch:
        saved = _edited_bytes(editor, scratch)
    if not saved:
        raise _problem("editor-empty")
    if len(saved) > _CEILING:
        raise _problem("edit-too-big")
    return parse_raw(saved)


def _print_bytes(data: bytes) -> None:
    clean = ledger.redact_bytes(data)
    if not clean.endswith(b"\n"):
        clean += b"\n"
    binary = getattr(sys.stdout, "buffer", None)
    sink, payload = (
        (sys.stdout, clean.decode("latin-1", errors="replace"))
        if binary is None
        else (binary, clean)
    )
    sink.write(payload)
    sink.flush()


def _raw_reply(response: httpx.Response, body: bytes) -> bytes:
    status = f"{response.http_version} {response.status_code} {response.reason_phrase}".rstrip()
    fields = (f"{name}: {value}" for name, value in response.headers.multi_items())
    head = "\r\n".join([status, *fields]) + "\r\n\r\n"
    return (head.encode("latin-1", errors="replace") + body)[:_CEILING]


def _display(response: httpx.Response, raw: bytes) -> int:
    print(f"sent {response.request.method} {response.url}", flush=True)
    shown = ledger.redact_text(raw[:_SCREEN_BYTES].decode("utf-8", errors="replace"))
    _print_bytes(shown.encode())
    if len(raw) > _SCREEN_BYTES:
        ui.console.print(f"[muted]Response truncated at {_SCREEN_BYTES} bytes.[/muted]")
    return 0


def _receipt(
    response: httpx.Response,
    written: int,
    destination: str | None = None,
    note: str = "",
) -> int:
    print(f"sent {response.request.method} {response.url}", flush=True)
    saved = f" saved to {destination}" if destination else ""
    detail = f" ({note})" if note else ""
    print(f"status {response.status_code}, {written} bytes{saved}{detail}", flush=True)
    return 0


def _save_output(destination: str | None, raw: bytes) -> int:
    if not destination:
        return 0
    saved = ledger.redact_bytes(raw)
    try:
        Path(destination).write_bytes(saved)
    except OSError as failure:
        raise _Stop(
            f"[err]Could not write the response:[/err] {escape(str(failure))}", 1
        ) from None
    return len(saved)


def _emit_response(response: httpx.Response, raw: bytes, args, note: str = "") -> int:
    written = _save_output(args.output, raw)
    if args.output:
        return _receipt(response, written, args.output, note)
    if args.quiet:
        return _receipt(response, len(raw), note=note)
    return _display(response, raw)


@dataclass
class _Leg:
    method: str
    url: str
    headers: list[tuple[str, str]]
    content: bytes | None

    def after_redirect(self, status: int, destination: str) -> _Leg:
        demoted = status in _DEMOTE_TO_GET
        crossing = not same_origin(self.url, destination)
        carried = [
            (name, value)
            for name, value in self.headers
            if name.lower() != "host" and not (crossing and is_credential_header(name))
        ]
        return _Leg(
            "GET" if demoted else self.method,
            destination,
            carried,
            None if demoted else self.content,
        )


def _first_leg(req: RawRequest, url: str, keep_host: bool) -> _Leg:
    dropped = _FRAMING_NAMES if keep_host else _FRAMING_NAMES | {"host"}
    headers = [
        (name, value) for name, value in req.headers if name.lower() not in dropped
    ]
    sends_body = req.declare_length or bool(req.body)
    return _Leg(req.method, url, headers, req.body if sends_body else None)


def _vet_redirect(
    response: httpx.Response, destination: str, args, *, report: bool = True
) -> None:
    host = hostname_of(destination)
    if host and allowed(destination) and urlsplit(destination).scheme in _WEB_SCHEMES:
        return
    raw = _raw_reply(response, read_body(response, _CEILING))
    if report:
        _emit_response(response, raw, args, note="stopped at out-of-scope redirect")
    raise _Stop(explain_target(destination), markup=False, highlight=False)


def _walk(
    client: httpx.Client, leg: _Leg, args, *, report: bool = True
) -> tuple[httpx.Response, bytes]:
    for hop in itertools.count():
        with client.stream(
            leg.method, leg.url, headers=leg.headers, content=leg.content
        ) as response:
            destination = (
                redirect_target(str(response.url), response)
                if args.follow and hop < _HOP_BUDGET
                else ""
            )
            if not destination:
                return response, read_body(response, _CEILING)
            _vet_redirect(response, destination, args, report=report)
            read_body(response, _DRAIN_BYTES)
        leg = leg.after_redirect(response.status_code, destination)


def send_request(
    req: RawRequest, url: str, args: argparse.Namespace, *, report: bool = False
) -> tuple[httpx.Response, bytes]:
    leg = _first_leg(req, url, bool(args.connect))
    try:
        with egress.client(
            timeout=args.timeout,
            verify=not args.insecure,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response, body = _walk(client, leg, args, report=report)
    except httpx.HTTPError as failure:
        raise _Stop(f"[err]Request failed:[/err] {escape(str(failure))}", 1) from None
    return response, body


def _deliver(req: RawRequest, url: str, args) -> int:
    response, body = send_request(req, url, args, report=True)
    return _emit_response(response, _raw_reply(response, body), args)


class _Flag(NamedTuple):
    names: tuple[str, ...]
    help: str
    options: dict


_FLAGS = (
    _Flag(("request",), "Raw HTTP request file.", {}),
    _Flag(("--method",), "Replace the method.", {}),
    _Flag(("--path",), "Replace the path and query.", {}),
    _Flag(("--host",), "Set the Host header. An absolute URL is rewritten too.", {}),
    _Flag(("--scheme",), "Use http or https.", {"choices": _WEB_SCHEMES}),
    _Flag(
        ("--header",),
        "Set one header, as 'Name: value'. Replaces that name.",
        {"action": "append", "default": []},
    ),
    _Flag(
        ("--remove-header",),
        "Remove every header with this name.",
        {"action": "append", "default": []},
    ),
    _Flag(("--body",), "Replace the body with this text.", {}),
    _Flag(("--body-file",), "Replace the body with this file.", {}),
    _Flag(
        ("--edit",),
        "Open $VISUAL or $EDITOR after the other edits.",
        {"action": "store_true"},
    ),
    _Flag(
        ("--print",),
        "Write the edited request and do not connect.",
        {"action": "store_true", "dest": "preview"},
    ),
    _Flag(
        ("--follow",), "Follow redirects that stay in scope.", {"action": "store_true"}
    ),
    _Flag(("--insecure",), "Do not verify TLS certificates.", {"action": "store_true"}),
    _Flag(
        ("--timeout",),
        "Seconds to wait for the response.",
        {"type": float, "default": 15},
    ),
    _Flag(("--output",), "Write the response to this file.", {}),
    _Flag(
        ("--quiet",),
        "Print only a receipt, not the response body.",
        {"action": "store_true"},
    ),
    _Flag(("--save-request",), "Store the edited request in the scope workspace.", {}),
    _Flag(("--connect",), "Send to HOST or HOST:PORT and keep the Host header.", {}),
)
_EXCLUSIVE_BODY = frozenset({"--body", "--body-file"})


def build_parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(
        prog="bughunt repeater",
        description="Edit a captured HTTP request, then send that edited copy.",
    )
    either_body = cli.add_mutually_exclusive_group()
    for flag in _FLAGS:
        home = either_body if flag.names[0] in _EXCLUSIVE_BODY else cli
        home.add_argument(*flag.names, help=flag.help, **flag.options)
    return cli


def _prepare(args) -> RawRequest:
    source = Path(args.request)
    if not source.is_file():
        raise _Stop(f"[err]No file named[/err] {escape(args.request)}")
    if source.stat().st_size > _CEILING:
        raise _Stop("[err]That request is larger than 8 MB.[/err]")
    with _as_usage_error():
        req = apply_edits(parse_raw(source.read_bytes()), args)
        edited = edit_request(req) if args.edit else req
    if len(edited.body) > _CEILING:
        raise _fail(_PROBLEMS["body-too-big"])
    return edited


def _store_copy(req: RawRequest, name: str | None) -> None:
    if name:
        with _as_usage_error():
            saved = save_request(name, render(req))
        ui.console.print(
            Text.assemble(("saved", "ok"), " ", str(saved)),
            markup=False,
            soft_wrap=True,
        )


def _require_reachable(host: str) -> None:
    if host and allowed(host):
        return
    raise (
        _Stop(explain_block(host), markup=False, highlight=False)
        if host
        else _Stop(_NO_HOST_HINT)
    )


def _destination(req: RawRequest, connect: str | None) -> str:
    with _as_usage_error():
        hostname, port = endpoint(req, connect)
        effective_scheme(req, port)
        _require_reachable(hostname)
        return request_url(req, connect)


def _run(args) -> int:
    req = _prepare(args)
    _store_copy(req, args.save_request)
    if not args.preview:
        return _deliver(req, _destination(req, args.connect), args)
    _print_bytes(render(req))
    return 0


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    try:
        return _run(options)
    except _Stop as halt:
        ui.console.print(halt.message, **halt.print_options)
        return halt.status
