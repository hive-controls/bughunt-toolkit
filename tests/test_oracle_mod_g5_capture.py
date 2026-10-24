"""Characterization oracle for G5 capture: `bughunt/modules/snare.py` and `bughunt/modules/repeater.py`.

Written BEFORE the clean-room rebuild. It pins what the current modules do so a from-scratch rewrite can
be held to it. The tiers:

  1. Registry and public surface (MODULES strings, signatures, dataclass field contracts).
  2. repeater: the pure request toolkit (parse / render / edit / endpoint / url), the CLI messages and
     exit codes, and the real send path against a loopback origin.
  3. snare: the listener lifecycle, the wire behavior of the proxy against a loopback origin, the
     on-disk capture contract (requests/, responses/, urls.txt, runs/<id>/manifest.json), the CA and
     leaf-certificate files, and the console formatters.
  4. KNOWN DEFECTS: tests named `test_defect_*` assert the CORRECT behavior and are xfail(strict=True)
     because the rebuild must reproduce the current (buggy) behavior; they are fixed later (M6).

Network posture: only loopback. The "origins" are throwaway threaded TCP servers on 127.0.0.1 with
ephemeral ports; the snare listener binds an ephemeral loopback port. Every listener and origin is torn
down by a fixture finalizer, and an autouse guard asserts no thread outlives its test and that every
port a fixture opened is released afterwards (a bind probe finds it free). The only subprocess edge that
is mocked is `openssl` (the editor is a real stub script); everything else is real.

Files the oracle relies on staying as they are (cross-importers and existing tests): see the spec.
"""

from __future__ import annotations

import dataclasses
import gc
import hashlib
import inspect
import io
import json
import os
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import threading
import time
import warnings
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from rich.console import Console

from bughunt import modules
from bughunt.console import ui
from bughunt.core import egress, identity, ledger
from bughunt.core.workspace import requests_dir, responses_dir, urls_path, workspace_dir
from bughunt.modules import repeater, snare
from bughunt.modules.policy import example_document

HAVE_OPENSSL = shutil.which("openssl") is not None
needs_openssl = pytest.mark.skipif(not HAVE_OPENSSL, reason="openssl is not on PATH")

_ALL_METHODS = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT"]
_ESC = "\x1b"
CYAN, YELLOW, MAGENTA = f"{_ESC}[1;96m", f"{_ESC}[1;93m", f"{_ESC}[1;95m"
WHITE, GREEN, RED = f"{_ESC}[1;97m", f"{_ESC}[1;92m", f"{_ESC}[1;91m"
DIM, RESET = f"{_ESC}[2;96m", f"{_ESC}[0m"


# --------------------------------------------------------------------------------------------------
# harness: workspace + policy, loopback origin, snare listener, output capture, leak guard
# --------------------------------------------------------------------------------------------------


class Lab:
    """One scratch engagement: scope file, verified policy, and helpers to re-grant origins."""

    def __init__(self, root: Path):
        self.root = root

    def grant(self, *origins: str, methods=None, **document_overrides) -> dict:
        document = example_document()
        document.update(
            state="verified", verified_at=datetime.now(timezone.utc).isoformat()
        )
        document["permissions"] = {name: True for name in document["permissions"]}
        document["limits"] = {"requests_per_second": 1000000, "concurrency": 100}
        wanted = [
            *origins,
            "http://localhost",
            "http://127.0.0.1:0",
            "https://allowed.example",
            "http://allowed.example",
        ]
        document["assets"] = [
            {
                "id": f"asset-{index}",
                "origin": origin,
                "paths": ["/"],
                "operations": list(document["permissions"]),
                "methods": list(methods or _ALL_METHODS),
            }
            for index, origin in enumerate(dict.fromkeys(wanted))
        ]
        document["exclusions"] = []
        document.update(document_overrides)
        (self.root / "policy.json").write_text(json.dumps(document), encoding="utf-8")
        return document

    def seed_placeholder_ca(self) -> None:
        folder = self.root / "snare"
        folder.mkdir(parents=True, exist_ok=True)
        for name in ("ca.crt", "ca.key"):
            target = folder / name
            if not target.exists():
                target.write_bytes(b"placeholder")


@pytest.fixture
def lab(monkeypatch, tmp_path):
    root = tmp_path / "ws"
    root.mkdir()
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    (root / "scope.txt").write_text("allowed.example\n", encoding="utf-8")
    instance = Lab(root)
    instance.grant()
    return instance


def _read_head_and_body(connection: socket.socket) -> bytes:
    connection.settimeout(5)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(65536)
        if not chunk:
            return data
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value.strip())
    while len(body) < length:
        chunk = connection.recv(65536)
        if not chunk:
            break
        body += chunk
    return head + b"\r\n\r\n" + body


class RawOrigin:
    """Loopback TCP origin: records each raw request and answers with whatever `responder` returns."""

    def __init__(self, responder, *, tls_files=None):
        self.requests: list[bytes] = []
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    raw = _read_head_and_body(self.request)
                except OSError:
                    return
                outer.requests.append(raw)
                try:
                    self.request.sendall(responder(raw))
                except OSError:
                    pass

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", 0), Handler)
        if tls_files is not None:
            import ssl

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*tls_files)
            self.server.socket = context.wrap_socket(
                self.server.socket, server_side=True
            )
        self.port = self.server.server_address[1]
        self.origin = (
            f"{'https' if tls_files is not None else 'http'}://127.0.0.1:{self.port}"
        )
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
            name="oracle-origin",
        )
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)


CANNED = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Backend: one\r\nKeep-Alive: timeout=5\r\n"
    b"Connection: keep-alive, X-Backend\r\nSet-Cookie: sid=abc\r\n\r\nhello"
)


def port_is_free(port: int) -> bool:
    """True when nothing is listening on 127.0.0.1:port (a bind probe; a refused connect is slow on Windows)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


@pytest.fixture
def opened_ports():
    ports: list[int] = []
    yield ports
    deadline = time.monotonic() + 5
    for port in ports:
        while not port_is_free(port):
            if time.monotonic() > deadline:
                pytest.fail(f"port {port} is still bound after teardown")
            time.sleep(0.05)


@pytest.fixture
def make_origin(lab, opened_ports):
    created: list[RawOrigin] = []

    def make(responder=lambda raw: CANNED, *, grant=True):
        origin = RawOrigin(responder)
        created.append(origin)
        opened_ports.append(origin.port)
        if grant:
            lab.grant(*[item.origin for item in created])
        return origin

    yield make
    for origin in created:
        origin.close()


class Proxy:
    def __init__(
        self, settings: snare.Settings, thread: threading.Thread, stop: threading.Event
    ):
        self.settings, self.thread, self.stop_event = settings, thread, stop

    @property
    def port(self) -> int:
        return self.settings.bound_port

    def talk(
        self, raw: bytes, *, half_close: bool = False, timeout: float = 10.0
    ) -> bytes:
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        try:
            connection.sendall(raw)
            if half_close:
                connection.shutdown(socket.SHUT_WR)
            data = b""
            while True:
                try:
                    chunk = connection.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                data += chunk
            return data
        finally:
            connection.close()


@pytest.fixture
def start_proxy(lab, opened_ports):
    started: list[Proxy] = []

    def start(*, seed_ca: bool = True, **settings_arguments) -> Proxy:
        if seed_ca:
            lab.seed_placeholder_ca()
        settings_arguments.setdefault("port", 0)
        settings_arguments.setdefault("plain", True)
        settings_arguments.setdefault("timeout", 5.0)
        settings = snare.Settings(**settings_arguments)
        settings.ready = threading.Event()
        stop = threading.Event()
        thread = threading.Thread(
            target=snare.listen, args=(settings, stop), daemon=True, name="oracle-snare"
        )
        thread.start()
        assert settings.ready.wait(30), "snare.listen never signalled ready"
        assert settings.bound_port, "snare.listen did not bind"
        proxy = Proxy(settings, thread, stop)
        started.append(proxy)
        opened_ports.append(proxy.port)
        return proxy

    yield start
    for proxy in started:
        proxy.stop_event.set()
        proxy.thread.join(10)
        assert not proxy.thread.is_alive(), "snare.listen did not stop when asked"


@pytest.fixture
def repeater_io(monkeypatch, capsysbinary):
    """Bytes written to stdout (accumulated) and the rich console text (the console is swapped to a buffer)."""
    sink = io.StringIO()
    monkeypatch.setattr(
        ui, "console", Console(file=sink, theme=ui.THEME, highlight=False, width=10000)
    )

    class Capture:
        def __init__(self):
            self._collected = b""

        @property
        def out(self) -> bytes:
            self._collected += capsysbinary.readouterr().out
            return self._collected

        @property
        def console(self) -> str:
            return sink.getvalue()

    return Capture()


@pytest.fixture(autouse=True)
def isolate_snare_module_state():
    snare.attach_console(None)
    yield
    snare.stop_listener(quiet=True)
    snare.attach_console(None)


@pytest.fixture(autouse=True)
def no_thread_leaks():
    before = set(threading.enumerate())
    yield
    deadline = time.monotonic() + 8
    while True:
        leaked = [t for t in threading.enumerate() if t not in before and t.is_alive()]
        if not leaked or time.monotonic() > deadline:
            break
        time.sleep(0.05)
    assert not leaked, f"threads outlived the test: {[t.name for t in leaked]}"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request_to(
    proxy_origin: RawOrigin,
    method: str = "GET",
    path: str = "/",
    extra: str = "",
    body: bytes = b"",
    host: bool = True,
) -> bytes:
    lines = [f"{method} {proxy_origin.origin}{path} HTTP/1.1"]
    if host:
        lines.append(f"Host: 127.0.0.1:{proxy_origin.port}")
    if extra:
        lines.append(extra)
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def saved_pairs() -> list[tuple[str, bytes, bytes]]:
    names = (
        sorted(path.name for path in requests_dir().glob("*.http"))
        if requests_dir().is_dir()
        else []
    )
    return [
        (
            name,
            (requests_dir() / name).read_bytes(),
            (responses_dir() / name).read_bytes(),
        )
        for name in names
    ]


def snare_manifests() -> list[dict]:
    runs = ledger.runs_dir()
    found = (
        [
            json.loads(path.read_text(encoding="utf-8"))
            for path in sorted(runs.glob("*/manifest.json"))
        ]
        if runs.is_dir()
        else []
    )
    return [item for item in found if item["tool"] == "snare"]


def error_reply(code: int, reason: str) -> bytes:
    return f"HTTP/1.1 {code} {reason}\r\nContent-Length: {len(reason)}\r\nConnection: close\r\n\r\n{reason}".encode()


def signature_of(function) -> list[tuple[str, str, object]]:
    return [
        (
            p.name,
            p.kind.name,
            p.default if p.default is not inspect.Parameter.empty else "<required>",
        )
        for p in inspect.signature(function).parameters.values()
    ]


# ==================================================================================================
# 1. registry and public surface
# ==================================================================================================


def test_modules_registry_descriptions_are_byte_identical():
    assert modules.MODULES["snare"] == (
        "Record scoped browser exchanges through a local proxy while using the console."
    )
    assert (
        modules.MODULES["repeater"]
        == "Revise a saved request and dispatch the revised HTTP exchange."
    )


def test_load_builtin_returns_the_importable_modules():
    assert modules.load_builtin("snare") is snare
    assert modules.load_builtin("repeater") is repeater
    for module in (snare, repeater):
        assert callable(module.main) and callable(module.build_parser)


def test_snare_public_signatures_cross_importers_depend_on():
    required, positional = "<required>", "POSITIONAL_OR_KEYWORD"
    assert signature_of(snare.main) == [("argv", positional, None)]
    assert signature_of(snare.build_parser) == []
    assert signature_of(snare.listen) == [
        ("settings", positional, required),
        ("stop", positional, required),
    ]
    assert signature_of(snare.attach_console) == [("redraw", positional, required)]
    assert signature_of(snare.console_attached) == []
    assert signature_of(snare.job_tag) == []
    assert signature_of(snare.begin) == [("settings", positional, required)]
    assert signature_of(snare.stop_listener) == [("quiet", "KEYWORD_ONLY", False)]
    assert signature_of(snare.print_status) == []
    assert signature_of(snare.ensure_ca) == []
    assert signature_of(snare.issue_leaf) == [("host", positional, required)]
    assert signature_of(snare.format_banner) == [("color", positional, required)]
    assert signature_of(snare.format_guide) == [("color", positional, required)]
    assert signature_of(snare.format_skip) == [
        ("host", positional, required),
        ("color", positional, required),
    ]
    assert signature_of(snare.format_tunnel) == [
        ("host", positional, required),
        ("port", positional, required),
        ("color", positional, required),
    ]
    assert signature_of(snare.format_row) == [
        ("method", positional, required),
        ("status", positional, required),
        ("size", positional, required),
        ("host", positional, required),
        ("path", positional, required),
        ("color", positional, required),
        ("name", "KEYWORD_ONLY", ""),
        ("note", "KEYWORD_ONLY", ""),
    ]
    assert issubclass(snare.CaError, Exception)


def test_existing_suites_still_reach_these_snare_seams():
    # tests/test_gate.py, test_safety.py, test_ledger.py and test_snare_identity.py monkeypatch or call these.
    for name in (
        "_fetch",
        "_fetch_wire",
        "_handle_exchange",
        "_handle_connect",
        "_tunnel",
        "_send_status",
        "_store",
        "_openssl",
        "_Message",
        "_splice",
    ):
        assert hasattr(snare, name), name
    assert snare.egress is egress
    assert signature_of(snare._fetch) == [
        ("host", "POSITIONAL_OR_KEYWORD", "<required>"),
        ("port", "POSITIONAL_OR_KEYWORD", "<required>"),
        ("scheme", "POSITIONAL_OR_KEYWORD", "<required>"),
        ("payload", "POSITIONAL_OR_KEYWORD", "<required>"),
        ("settings", "POSITIONAL_OR_KEYWORD", "<required>"),
        ("return_sent", "KEYWORD_ONLY", False),
    ]
    assert signature_of(snare._store) == [
        ("request", "POSITIONAL_OR_KEYWORD", "<required>"),
        ("response", "POSITIONAL_OR_KEYWORD", "<required>"),
        ("url", "POSITIONAL_OR_KEYWORD", "<required>"),
        ("host", "POSITIONAL_OR_KEYWORD", "<required>"),
        ("actor", "KEYWORD_ONLY", None),
        ("truncated", "KEYWORD_ONLY", False),
    ]
    message = snare._Message("GET / HTTP/1.1", [("A", "b")])
    assert (message.line, message.headers) == ("GET / HTTP/1.1", [("A", "b")])


def test_repeater_public_signatures_cross_importers_depend_on():
    required, positional = "<required>", "POSITIONAL_OR_KEYWORD"
    assert signature_of(repeater.parse_raw) == [("data", positional, required)]
    assert signature_of(repeater.apply_edits) == [
        ("req", positional, required),
        ("args", positional, required),
    ]
    assert signature_of(repeater.render) == [("req", positional, required)]
    assert signature_of(repeater.endpoint) == [
        ("req", positional, required),
        ("connect", positional, required),
    ]
    assert signature_of(repeater.request_url) == [
        ("req", positional, required),
        ("connect", positional, required),
    ]
    assert signature_of(repeater.path_and_query) == [("req", positional, required)]
    assert signature_of(repeater.remove_header) == [
        ("req", positional, required),
        ("name", positional, required),
    ]
    assert signature_of(repeater.replace_header) == [
        ("req", positional, required),
        ("name", positional, required),
        ("value", positional, required),
    ]
    assert signature_of(repeater.first_header) == [
        ("req", positional, required),
        ("name", positional, required),
    ]
    assert signature_of(repeater.effective_scheme) == [
        ("req", positional, required),
        ("port", positional, required),
    ]
    assert signature_of(repeater.replace_path) == [
        ("target", positional, required),
        ("path", positional, required),
    ]
    assert signature_of(repeater.replace_scheme) == [
        ("target", positional, required),
        ("scheme", positional, required),
    ]
    assert signature_of(repeater.set_host) == [
        ("req", positional, required),
        ("value", positional, required),
    ]
    assert signature_of(repeater.edit_request) == [("req", positional, required)]
    assert signature_of(repeater.main) == [("argv", positional, None)]
    assert signature_of(repeater.build_parser) == []


def test_snare_settings_dataclass_contract():
    names = [field.name for field in dataclasses.fields(snare.Settings)]
    assert names == [
        "port",
        "timeout",
        "insecure",
        "max_body",
        "plain",
        "bound_port",
        "ready",
        "forward_limit",
    ]
    settings = snare.Settings()
    assert (settings.port, settings.timeout, settings.insecure, settings.max_body) == (
        8080,
        10.0,
        False,
        1_000_000,
    )
    assert (settings.plain, settings.bound_port, settings.ready) == (False, 0, None)
    assert settings.forward_limit == 8_000_000
    assert snare.Settings(max_body=9_000_000).forward_limit == 9_000_000
    assert snare.Settings(max_body=7_999_999).forward_limit == 8_000_000
    with pytest.raises(TypeError):
        snare.Settings(forward_limit=1)  # derived, not an init argument
    assert (
        snare.Settings(1, 2.5, True, 3, True).plain is True
    )  # positional order: port, timeout, insecure, max_body, plain


def test_repeater_rawrequest_dataclass_contract():
    names = [field.name for field in dataclasses.fields(repeater.RawRequest)]
    assert names == [
        "method",
        "target",
        "version",
        "headers",
        "body",
        "scheme",
        "declare_length",
    ]
    first, second = (
        repeater.RawRequest("GET", "/", "HTTP/1.1"),
        repeater.RawRequest("GET", "/", "HTTP/1.1"),
    )
    assert (first.headers, first.body, first.scheme, first.declare_length) == (
        [],
        b"",
        None,
        False,
    )
    first.headers.append(("A", "b"))
    assert second.headers == []  # each instance owns its header list
    built = repeater.RawRequest(
        "POST", "/x", "HTTP/1.0", [("A", "b")], b"zz", "https", True
    )
    assert (
        built.method,
        built.target,
        built.version,
        built.headers,
        built.body,
        built.scheme,
        built.declare_length,
    ) == ("POST", "/x", "HTTP/1.0", [("A", "b")], b"zz", "https", True)


# ==================================================================================================
# 2. repeater: pure request toolkit
# ==================================================================================================


def parsed(raw: bytes) -> repeater.RawRequest:
    return repeater.parse_raw(raw)


def as_tuple(req: repeater.RawRequest):
    return (
        req.method,
        req.target,
        req.version,
        req.headers,
        req.body,
        req.scheme,
        req.declare_length,
    )


@pytest.mark.parametrize(
    "raw, expected",
    [
        (
            b"get /a HTTP/1.0\r\nHost: x\r\nA:  b  \r\n\r\nBODY",
            ("GET", "/a", "HTTP/1.0", [("Host", "x"), ("A", "b")], b"BODY", None, True),
        ),
        (
            b"GET /a\r\nHost: x\r\n\r\n",
            ("GET", "/a", "HTTP/1.1", [("Host", "x")], b"", None, False),
        ),
        (
            b"GET /a HTTP/1.1\nHost: x\n\nB",
            ("GET", "/a", "HTTP/1.1", [("Host", "x")], b"B", None, True),
        ),
        (
            b"GET /a HTTP/1.1\nHost: x\r\n\r\nB\n\nC",
            ("GET", "/a", "HTTP/1.1", [("Host", "x")], b"B\n\nC", None, True),
        ),
        (
            b"GET /a HTTP/1.1\r\nHost: x",
            ("GET", "/a", "HTTP/1.1", [("Host", "x")], b"", None, False),
        ),
        (
            b"GET /a HTTP/1.1\r\nX-A: one\r\n  two\r\n\tthree\r\n\r\n",
            ("GET", "/a", "HTTP/1.1", [("X-A", "one two three")], b"", None, False),
        ),
        (
            b"GET /a HTTP/1.1\r\n  stray: x\r\n\r\n",
            ("GET", "/a", "HTTP/1.1", [("stray", "x")], b"", None, False),
        ),
        (
            b"GET / HTTP/1.1 junk\r\n\r\n",
            ("GET", "/", "HTTP/1.1", [], b"", None, False),
        ),
        (
            b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            ("POST", "/", "HTTP/1.1", [("Content-Length", "0")], b"", None, True),
        ),
        (
            b"POST / HTTP/1.1\r\n\r\nxyz",
            ("POST", "/", "HTTP/1.1", [], b"xyz", None, True),
        ),
        (
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
            (
                "POST",
                "/",
                "HTTP/1.1",
                [("Transfer-Encoding", "chunked")],
                b"3\r\nabc\r\n0\r\n\r\n",
                None,
                True,
            ),
        ),
        (
            b"GET /\xe9 HTTP/1.1\r\nX-A: \xe9\r\n\r\n\xff\xfe",
            ("GET", "/\xe9", "HTTP/1.1", [("X-A", "\xe9")], b"\xff\xfe", None, True),
        ),
        (
            b"GET http://h.example:8080/p?q=1 HTTP/1.1\r\n\r\n",
            ("GET", "http://h.example:8080/p?q=1", "HTTP/1.1", [], b"", None, False),
        ),
        (
            b"GET / HTTP/1.1\r\nA: 1\r\nA: 2\r\nB:\r\n\r\n",
            (
                "GET",
                "/",
                "HTTP/1.1",
                [("A", "1"), ("A", "2"), ("B", "")],
                b"",
                None,
                False,
            ),
        ),
    ],
)
def test_parse_raw_cases(raw, expected):
    assert as_tuple(parsed(raw)) == expected


@pytest.mark.parametrize(
    "raw, message",
    [
        (b"", "The request file is empty."),
        (b"  \r\n ", "The request file is empty."),
        (b"\r\nGET / HTTP/1.1\r\n\r\n", "The request has no request line."),
        (b"GET\r\n\r\n", "The request line needs a method and a target."),
        (b"GET / HTTP/1.1\r\n: v\r\n\r\n", "Header has no name."),
        (b"GET / HTTP/1.1\r\nbadheader\r\n\r\n", "Header has no name: badheader"),
    ],
)
def test_parse_raw_errors_are_valueerrors_with_exact_messages(raw, message):
    with pytest.raises(ValueError) as caught:
        parsed(raw)
    assert str(caught.value) == message


@pytest.mark.parametrize(
    "request_fields, expected",
    [
        (
            dict(
                method="POST",
                target="/p?q=1",
                version="HTTP/1.1",
                headers=[
                    ("Host", "h.example"),
                    ("Content-Length", "3"),
                    ("Transfer-Encoding", "chunked"),
                    ("X-A", "1"),
                ],
                body=b"abc",
                declare_length=True,
            ),
            b"POST /p?q=1 HTTP/1.1\r\nHost: h.example\r\nX-A: 1\r\nContent-Length: 3\r\n\r\nabc",
        ),
        (
            dict(method="GET", target="/", version="", headers=[("A", "b")]),
            b"GET / HTTP/1.1\r\nA: b\r\n\r\n",
        ),
        (
            dict(
                method="GET",
                target="/\u4e2d",
                version="HTTP/1.1",
                headers=[("A", "\u4e2d")],
                body=b"\xff",
                declare_length=True,
            ),
            b"GET /? HTTP/1.1\r\nA: ?\r\nContent-Length: 1\r\n\r\n\xff",
        ),
        (
            dict(
                method="PUT",
                target="/",
                version="HTTP/1.1",
                headers=[("content-length", "9")],
                body=b"",
                declare_length=True,
            ),
            b"PUT / HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            dict(
                method="GET",
                target="/",
                version="HTTP/1.1",
                headers=[],
                body=b"raw",
                declare_length=False,
            ),
            b"GET / HTTP/1.1\r\n\r\nraw",
        ),
    ],
)
def test_render_produces_crlf_wire_bytes(request_fields, expected):
    assert repeater.render(repeater.RawRequest(**request_fields)) == expected


def test_parse_then_render_round_trips_a_clean_request():
    raw = b"POST /submit?x=1 HTTP/1.1\r\nHost: a.example\r\nX-A: 1\r\nContent-Length: 4\r\n\r\nbody"
    assert repeater.render(parsed(raw)) == raw


def edit(raw: bytes, **overrides) -> tuple:
    defaults = dict(
        method=None,
        path=None,
        host=None,
        scheme=None,
        header=[],
        remove_header=[],
        body=None,
        body_file=None,
    )
    return as_tuple(
        repeater.apply_edits(parsed(raw), Namespace(**{**defaults, **overrides}))
    )


BASE = b"GET /old?x=1 HTTP/1.1\r\nHost: a.example\r\nCookie: c\r\n\r\n"
ABSOLUTE = b"GET http://a.example:81/old?x=1 HTTP/1.1\r\n\r\n"


@pytest.mark.parametrize(
    "raw, overrides, expected",
    [
        (
            BASE,
            dict(method=" post "),
            (
                "POST",
                "/old?x=1",
                "HTTP/1.1",
                [("Host", "a.example"), ("Cookie", "c")],
                b"",
                None,
                False,
            ),
        ),
        (
            BASE,
            dict(path="new"),
            (
                "GET",
                "/new",
                "HTTP/1.1",
                [("Host", "a.example"), ("Cookie", "c")],
                b"",
                None,
                False,
            ),
        ),
        (
            BASE,
            dict(path="?y=2"),
            (
                "GET",
                "?y=2",
                "HTTP/1.1",
                [("Host", "a.example"), ("Cookie", "c")],
                b"",
                None,
                False,
            ),
        ),
        (
            BASE,
            dict(path="https://z.example/q"),
            (
                "GET",
                "https://z.example/q",
                "HTTP/1.1",
                [("Host", "a.example"), ("Cookie", "c")],
                b"",
                None,
                False,
            ),
        ),
        (
            b"GET http://a.example:81/old?x=1#f HTTP/1.1\r\n\r\n",
            dict(path="/n?k=v"),
            ("GET", "http://a.example:81/n?k=v", "HTTP/1.1", [], b"", None, False),
        ),
        (
            ABSOLUTE,
            dict(path="?k=v"),
            ("GET", "http://a.example:81/?k=v", "HTTP/1.1", [], b"", None, False),
        ),
        (
            ABSOLUTE,
            dict(path="n"),
            ("GET", "http://a.example:81/n", "HTTP/1.1", [], b"", None, False),
        ),
        (
            BASE,
            dict(host="b.example:8080"),
            (
                "GET",
                "/old?x=1",
                "HTTP/1.1",
                [("Cookie", "c"), ("Host", "b.example:8080")],
                b"",
                None,
                False,
            ),
        ),
        (
            b"GET http://a.example:81/old HTTP/1.1\r\nHost: a.example:81\r\n\r\n",
            dict(host="b.example"),
            (
                "GET",
                "http://b.example:81/old",
                "HTTP/1.1",
                [("Host", "b.example")],
                b"",
                None,
                False,
            ),
        ),
        (
            b"GET http://a.example:81/old HTTP/1.1\r\nHost: a.example:81\r\n\r\n",
            dict(host="b.example:9"),
            (
                "GET",
                "http://b.example:9/old",
                "HTTP/1.1",
                [("Host", "b.example:9")],
                b"",
                None,
                False,
            ),
        ),
        (
            b"GET http://a.example:81/old HTTP/1.1\r\n\r\n",
            dict(host="[::1]:9"),
            (
                "GET",
                "http://[::1]:9/old",
                "HTTP/1.1",
                [("Host", "[::1]:9")],
                b"",
                None,
                False,
            ),
        ),
        (
            b"GET http://a.example/p HTTP/1.1\r\n\r\n",
            dict(scheme="https"),
            ("GET", "https://a.example/p", "HTTP/1.1", [], b"", "https", False),
        ),
        (
            BASE,
            dict(scheme="https"),
            (
                "GET",
                "/old?x=1",
                "HTTP/1.1",
                [("Host", "a.example"), ("Cookie", "c")],
                b"",
                "https",
                False,
            ),
        ),
        (
            BASE,
            dict(header=["cookie:  new ", "X-N: 1"]),
            (
                "GET",
                "/old?x=1",
                "HTTP/1.1",
                [("Host", "a.example"), ("cookie", "new"), ("X-N", "1")],
                b"",
                None,
                False,
            ),
        ),
        (
            BASE,
            dict(header=["host: z.example"]),
            (
                "GET",
                "/old?x=1",
                "HTTP/1.1",
                [("Cookie", "c"), ("Host", "z.example")],
                b"",
                None,
                False,
            ),
        ),
        (
            b"GET http://a.example:81/old HTTP/1.1\r\nHost: a.example:81\r\n\r\n",
            dict(header=["Host: z.example:9"]),
            (
                "GET",
                "http://z.example:9/old",
                "HTTP/1.1",
                [("Host", "z.example:9")],
                b"",
                None,
                False,
            ),
        ),
        (
            BASE,
            dict(remove_header=[" COOKIE "]),
            ("GET", "/old?x=1", "HTTP/1.1", [("Host", "a.example")], b"", None, False),
        ),
        (
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 9\r\n\r\nx",
            dict(body="\u00e9"),
            (
                "POST",
                "/",
                "HTTP/1.1",
                [("Content-Length", "9")],
                b"\xc3\xa9",
                None,
                True,
            ),
        ),
        (
            BASE,
            dict(body=""),
            (
                "GET",
                "/old?x=1",
                "HTTP/1.1",
                [("Host", "a.example"), ("Cookie", "c")],
                b"",
                None,
                True,
            ),
        ),
    ],
)
def test_apply_edits_cases(raw, overrides, expected):
    assert edit(raw, **overrides) == expected


def test_apply_edits_sets_headers_before_removing_them_when_several_flags_combine():
    result = edit(
        BASE,
        header=["X-One: 1", "X-Two: 2"],
        remove_header=["x-one", "Host"],
        method="put",
        body="zz",
    )
    assert result == (
        "PUT",
        "/old?x=1",
        "HTTP/1.1",
        [("Cookie", "c"), ("X-Two", "2")],
        b"zz",
        None,
        True,
    )


def test_apply_edits_body_file_replaces_body_and_drops_transfer_encoding(tmp_path):
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"\x00\x01body")
    raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\nold"
    assert edit(raw, body_file=str(payload)) == (
        "POST",
        "/",
        "HTTP/1.1",
        [("X-A", "1")],
        b"\x00\x01body",
        None,
        True,
    )


@pytest.mark.parametrize(
    "overrides, message",
    [
        (dict(method="   "), "Method is empty."),
        (dict(host="  "), "Host is empty."),
        (dict(header=["nocolon"]), "Header needs a name and a value: nocolon"),
        (dict(header=[" : v"]), "Header has no name."),
        (
            dict(body_file="Z:/definitely/not/here.bin"),
            "No file named Z:/definitely/not/here.bin.",
        ),
    ],
)
def test_apply_edits_errors(overrides, message):
    with pytest.raises(ValueError) as caught:
        edit(BASE, **overrides)
    assert str(caught.value) == message


def test_apply_edits_rejects_a_host_with_a_non_numeric_port():
    with pytest.raises(ValueError) as caught:
        edit(b"GET http://a.example/ HTTP/1.1\r\n\r\n", host="b:xx")
    assert str(caught.value) == "Port xx is not a number."


def test_apply_edits_body_file_over_eight_megabytes_is_refused(tmp_path):
    big = tmp_path / "big.bin"
    with big.open("wb") as handle:
        handle.truncate(8 * 1024 * 1024 + 1)
    with pytest.raises(ValueError) as caught:
        edit(BASE, body_file=str(big))
    assert str(caught.value) == "The request body is larger than 8 MB."


def test_header_helpers_are_case_insensitive_and_mutate_in_place():
    req = repeater.RawRequest(
        "GET", "/", "HTTP/1.1", [("A", "1"), ("a", "2"), ("B", "3")]
    )
    assert repeater.first_header(req, "A") == "1"
    assert repeater.first_header(req, "missing") is None
    repeater.replace_header(req, "a", "9")
    assert req.headers == [("B", "3"), ("a", "9")]
    repeater.remove_header(req, "b")
    assert req.headers == [("a", "9")]


@pytest.mark.parametrize(
    "raw, connect, expected",
    [
        (b"GET / HTTP/1.1\r\nHost: A.Example:8443\r\n\r\n", None, ("A.Example", 8443)),
        (b"GET / HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n", None, ("::1", 8443)),
        (b"GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n", None, ("::1", None)),
        (
            b"GET http://X.example:81/p HTTP/1.1\r\nHost: other\r\n\r\n",
            None,
            ("x.example", 81),
        ),
        (b"GET http://X.example/p HTTP/1.1\r\n\r\n", None, ("x.example", None)),
        (b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", " c.example:99 ", ("c.example", 99)),
        (b"GET / HTTP/1.1\r\n\r\n", "[::1]:81", ("::1", 81)),
        (b"GET / HTTP/1.1\r\n\r\n", "::1", ("::1", None)),
        (b"GET / HTTP/1.1\r\nHost: [::1\r\n\r\n", None, ("::1", None)),
        (b"GET / HTTP/1.1\r\n\r\n", None, ("", None)),
    ],
)
def test_endpoint_picks_the_host_and_port_that_will_be_contacted(
    raw, connect, expected
):
    assert repeater.endpoint(parsed(raw), connect) == expected


@pytest.mark.parametrize(
    "connect, message",
    [
        ("c.example:x", "Port x is not a number."),
        ("c.example:0", "Port 0 is out of range."),
        ("c.example:70000", "Port 70000 is out of range."),
    ],
)
def test_endpoint_rejects_bad_connect_ports(connect, message):
    with pytest.raises(ValueError) as caught:
        repeater.endpoint(parsed(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), connect)
    assert str(caught.value) == message


@pytest.mark.parametrize(
    "raw, connect, scheme_override, expected",
    [
        (
            b"GET /p?q=1 HTTP/1.1\r\nHost: a.example\r\n\r\n",
            None,
            None,
            "http://a.example/p?q=1",
        ),
        (
            b"GET /p HTTP/1.1\r\nHost: a.example:443\r\n\r\n",
            None,
            None,
            "https://a.example:443/p",
        ),
        (
            b"GET /p HTTP/1.1\r\nHost: a.example:8443\r\n\r\n",
            None,
            None,
            "http://a.example:8443/p",
        ),
        (
            b"GET https://a.example/p?z=1#frag HTTP/1.1\r\n\r\n",
            None,
            None,
            "https://a.example/p?z=1",
        ),
        (
            b"GET /p HTTP/1.1\r\nHost: a.example\r\n\r\n",
            None,
            "https",
            "https://a.example/p",
        ),
        (b"GET /p HTTP/1.1\r\nHost: [::1]:81\r\n\r\n", None, None, "http://[::1]:81/p"),
        (
            b"GET /p HTTP/1.1\r\nHost: a.example\r\n\r\n",
            "10.0.0.1:81",
            None,
            "http://10.0.0.1:81/p",
        ),
        (
            b"GET p HTTP/1.1\r\nHost: a.example\r\n\r\n",
            None,
            None,
            "http://a.example/p",
        ),
        (
            b"OPTIONS * HTTP/1.1\r\nHost: a.example\r\n\r\n",
            None,
            None,
            "http://a.example/*",
        ),
        (b"GET http://a.example HTTP/1.1\r\n\r\n", None, None, "http://a.example/"),
    ],
)
def test_request_url(raw, connect, scheme_override, expected):
    req = parsed(raw)
    if scheme_override:
        req.scheme = scheme_override
    assert repeater.request_url(req, connect) == expected


def test_request_url_rejects_non_http_schemes():
    with pytest.raises(ValueError) as caught:
        repeater.request_url(parsed(b"GET ftp://a.example/p HTTP/1.1\r\n\r\n"), None)
    assert str(caught.value) == "Only http and https requests can be sent."


def test_path_and_query_and_effective_scheme_and_replacers():
    cases = ["/a?b", "a", "", "  /x ", "http://h/p?q", "http://h", "http://h?q=1"]
    assert [
        repeater.path_and_query(repeater.RawRequest("GET", t, "HTTP/1.1"))
        for t in cases
    ] == ["/a?b", "/a", "/", "/x", "/p?q", "/", "/?q=1"]
    scheme_cases = [
        ("/", None, None),
        ("/", None, 443),
        ("/", "http", 443),
        ("http://h/", None, 443),
        ("https://h/", None, 80),
        ("/", "https", 80),
    ]
    assert [
        repeater.effective_scheme(
            repeater.RawRequest("GET", t, "HTTP/1.1", scheme=s), p
        )
        for t, s, p in scheme_cases
    ] == ["http", "https", "http", "http", "https", "https"]
    assert [
        repeater.replace_path(t, p)
        for t, p in [
            ("/a", "/b"),
            ("/a", "b"),
            ("/a", "?q"),
            ("/a", "http://x/y"),
            ("http://h/a?z", "/b?c=d"),
            ("http://h/a?z", "?q=1"),
            ("http://h/a", "b"),
            ("http://h/a", ""),
        ]
    ] == [
        "/b",
        "/b",
        "?q",
        "http://x/y",
        "http://h/b?c=d",
        "http://h/?q=1",
        "http://h/b",
        "http://h/",
    ]
    assert repeater.replace_scheme("http://h:1/p?q#f", "https") == "https://h:1/p?q#f"
    with pytest.raises(ValueError):
        repeater.effective_scheme(
            repeater.RawRequest("GET", "ws://h/", "HTTP/1.1"), None
        )


def test_set_host_updates_the_header_and_an_absolute_target_together():
    req = parsed(
        b"GET http://a.example:81/p?q=1 HTTP/1.1\r\nHost: a.example:81\r\nX: 1\r\n\r\n"
    )
    repeater.set_host(req, "b.example")
    assert req.target == "http://b.example:81/p?q=1"
    assert req.headers == [("X", "1"), ("Host", "b.example")]
    with pytest.raises(ValueError) as caught:
        repeater.set_host(req, "")
    assert str(caught.value) == "Host is empty."


def option_rows(parser) -> list[tuple]:
    from bughunt.console import options

    spec = options.spec_from_parser(parser)
    return (
        [
            (
                o.name,
                o.flags,
                o.kind,
                o.required,
                o.help,
                o.choices,
                o.subcommand,
                o.repeatable,
                o.default,
            )
            for o in spec.options
        ],
        list(spec.subcommands),
        spec.command_name,
    )


def test_repeater_catalog_form_is_pinned():
    rows, subcommands, command_name = option_rows(repeater.build_parser())
    assert (subcommands, command_name) == ([], "")
    assert rows == [
        (
            "REQUEST",
            (),
            "positional",
            True,
            "Raw HTTP request file.",
            (),
            "",
            False,
            "",
        ),
        (
            "METHOD",
            ("--method",),
            "value",
            False,
            "Replace the method.",
            (),
            "",
            False,
            "",
        ),
        (
            "PATH",
            ("--path",),
            "value",
            False,
            "Replace the path and query.",
            (),
            "",
            False,
            "",
        ),
        (
            "HOST",
            ("--host",),
            "value",
            False,
            "Set the Host header. An absolute URL is rewritten too.",
            (),
            "",
            False,
            "",
        ),
        (
            "SCHEME",
            ("--scheme",),
            "value",
            False,
            "Use http or https.",
            ("http", "https"),
            "",
            False,
            "",
        ),
        (
            "HEADER",
            ("--header",),
            "value",
            False,
            "Set one header, as 'Name: value'. Replaces that name.",
            (),
            "",
            True,
            "",
        ),
        (
            "REMOVE_HEADER",
            ("--remove-header",),
            "value",
            False,
            "Remove every header with this name.",
            (),
            "",
            True,
            "",
        ),
        (
            "BODY",
            ("--body",),
            "value",
            False,
            "Replace the body with this text.",
            (),
            "",
            False,
            "",
        ),
        (
            "BODY_FILE",
            ("--body-file",),
            "value",
            False,
            "Replace the body with this file.",
            (),
            "",
            False,
            "",
        ),
        (
            "EDIT",
            ("--edit",),
            "bool",
            False,
            "Open $VISUAL or $EDITOR after the other edits.",
            (),
            "",
            False,
            "",
        ),
        (
            "PREVIEW",
            ("--print",),
            "bool",
            False,
            "Write the edited request and do not connect.",
            (),
            "",
            False,
            "",
        ),
        (
            "FOLLOW",
            ("--follow",),
            "bool",
            False,
            "Follow redirects that stay in scope.",
            (),
            "",
            False,
            "",
        ),
        (
            "INSECURE",
            ("--insecure",),
            "bool",
            False,
            "Do not verify TLS certificates.",
            (),
            "",
            False,
            "",
        ),
        (
            "TIMEOUT",
            ("--timeout",),
            "value",
            False,
            "Seconds to wait for the response.",
            (),
            "",
            False,
            "15",
        ),
        (
            "OUTPUT",
            ("--output",),
            "value",
            False,
            "Write the response to this file.",
            (),
            "",
            False,
            "",
        ),
        (
            "QUIET",
            ("--quiet",),
            "bool",
            False,
            "Print only a receipt, not the response body.",
            (),
            "",
            False,
            "",
        ),
        (
            "SAVE_REQUEST",
            ("--save-request",),
            "value",
            False,
            "Store the edited request in the scope workspace.",
            (),
            "",
            False,
            "",
        ),
        (
            "CONNECT",
            ("--connect",),
            "value",
            False,
            "Send to HOST or HOST:PORT and keep the Host header.",
            (),
            "",
            False,
            "",
        ),
    ]


def test_snare_catalog_form_is_pinned():
    rows, subcommands, command_name = option_rows(snare.build_parser())
    assert command_name == "COMMAND"
    assert subcommands == [
        ("ca", "Write the CA, if needed, and print its certificate path."),
        ("status", "Show the port and where saved requests go."),
        ("stop", "Close the listener and leave the saved files in place."),
        ("capture", "Capture a finite number of exchanges within a duration."),
    ]
    assert rows == [
        (
            "PLAIN",
            ("--plain",),
            "bool",
            False,
            "Skip the banner and the row colors.",
            (),
            "",
            False,
            "",
        ),
        (
            "PORT",
            ("--port",),
            "value",
            False,
            "Port on 127.0.0.1. 0 picks a free port.",
            (),
            "",
            False,
            "8080",
        ),
        (
            "TIMEOUT",
            ("--timeout",),
            "value",
            False,
            "Seconds for a socket. Default 10.",
            (),
            "",
            False,
            "10.0",
        ),
        (
            "INSECURE",
            ("--insecure",),
            "bool",
            False,
            "Do not verify upstream TLS certificates.",
            (),
            "",
            False,
            "",
        ),
        (
            "MAX_BODY",
            ("--max-body",),
            "value",
            False,
            "Bytes kept from each body. Default 1000000.",
            (),
            "",
            False,
            "1000000",
        ),
        ("SECONDS", ("--seconds",), "value", True, "", (), "capture", False, ""),
        (
            "MAX_EXCHANGES",
            ("--max-exchanges",),
            "value",
            True,
            "",
            (),
            "capture",
            False,
            "",
        ),
        (
            "COMMAND",
            (),
            "positional",
            False,
            "Subcommand.",
            ("ca", "status", "stop", "capture"),
            "",
            False,
            "",
        ),
    ]
    assert snare.build_parser().description == (
        "Capture scoped HTTP exchanges through a loopback proxy. "
        "Browse the saved traffic with clutch while the console remains available."
    )
    assert (
        repeater.build_parser().description
        == "Edit a captured HTTP request, then send that edited copy."
    )


def test_repeater_parser_contract():
    parser = repeater.build_parser()
    assert parser.prog == "bughunt repeater"
    defaults = parser.parse_args(["req.http"])
    assert vars(defaults) == dict(
        request="req.http",
        method=None,
        path=None,
        host=None,
        scheme=None,
        header=[],
        remove_header=[],
        body=None,
        body_file=None,
        edit=False,
        preview=False,
        follow=False,
        insecure=False,
        timeout=15,
        output=None,
        quiet=False,
        save_request=None,
        connect=None,
    )
    options = {
        action.option_strings[0]: action
        for action in parser._actions
        if action.option_strings
    }
    assert sorted(options) == sorted(
        [
            "-h",
            "--method",
            "--path",
            "--host",
            "--scheme",
            "--header",
            "--remove-header",
            "--body",
            "--body-file",
            "--edit",
            "--print",
            "--follow",
            "--insecure",
            "--timeout",
            "--output",
            "--quiet",
            "--save-request",
            "--connect",
        ]
    )
    assert options["--print"].dest == "preview"
    assert options["--scheme"].choices == ("http", "https")
    assert options["--timeout"].type is float
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["req.http", "--body", "a", "--body-file", "b"]
        )  # mutually exclusive
    with pytest.raises(SystemExit):
        parser.parse_args(["req.http", "--scheme", "ftp"])
    both = parser.parse_args(
        [
            "r",
            "--header",
            "A: 1",
            "--header",
            "B: 2",
            "--remove-header",
            "C",
            "--remove-header",
            "D",
            "--timeout",
            "2.5",
        ]
    )
    assert (both.header, both.remove_header, both.timeout) == (
        ["A: 1", "B: 2"],
        ["C", "D"],
        2.5,
    )


# ==================================================================================================
# 2b. repeater: CLI behavior (messages, exit codes, files) and the real send path
# ==================================================================================================


def write_request(tmp_path: Path, raw: bytes, name: str = "req.http") -> str:
    path = tmp_path / name
    path.write_bytes(raw)
    return str(path)


def test_main_missing_file_exits_2_and_names_it(repeater_io, tmp_path):
    missing = str(tmp_path / "absent.http")
    assert repeater.main([missing]) == 2
    assert repeater_io.console.strip() == f"No file named {missing}"
    assert repeater_io.out == b""


def test_main_oversized_request_file_exits_2(repeater_io, tmp_path):
    big = tmp_path / "big.http"
    with big.open("wb") as handle:
        handle.write(b"GET / HTTP/1.1\r\n\r\n")
        handle.truncate(8 * 1024 * 1024 + 1)
    assert repeater.main([str(big), "--print"]) == 2
    assert repeater_io.console.strip() == "That request is larger than 8 MB."


@pytest.mark.parametrize(
    "raw, message",
    [
        (b"", "The request file is empty."),
        (b"GET\r\n\r\n", "The request line needs a method and a target."),
        (b"GET / HTTP/1.1\r\nbadheader\r\n\r\n", "Header has no name: badheader"),
    ],
)
def test_main_parse_errors_exit_2_with_the_message(repeater_io, tmp_path, raw, message):
    assert repeater.main([write_request(tmp_path, raw), "--print"]) == 2
    assert repeater_io.console.strip() == message
    assert repeater_io.out == b""


def test_main_edit_flag_errors_exit_2(repeater_io, tmp_path):
    path = write_request(tmp_path, b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
    assert repeater.main([path, "--print", "--method", "  "]) == 2
    assert repeater_io.console.strip() == "Method is empty."


def test_main_print_writes_the_redacted_edited_request_and_never_connects(
    repeater_io, tmp_path, monkeypatch
):
    def forbidden(*args, **kwargs):
        raise AssertionError("repeater --print must not open a connection")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    path = write_request(
        tmp_path,
        b"GET /a?q=1 HTTP/1.1\r\nHost: 127.0.0.1:9\r\nX-CSRF-Token: tok\r\n"
        b"Cookie: sid=cookiev\r\nX-Keep: yes\r\n\r\n",
    )
    assert repeater.main([path, "--print"]) == 0
    assert repeater_io.out == (
        b"GET /a?q=1 HTTP/1.1\r\nHost: 127.0.0.1:9\r\nX-CSRF-Token: [REDACTED]\r\n"
        b"Cookie: [REDACTED]\r\nX-Keep: yes\r\n\r\n"
    )


def test_main_print_applies_every_edit_flag_and_ends_with_a_newline(
    repeater_io, tmp_path
):
    path = write_request(
        tmp_path, b"GET /a?q=1 HTTP/1.1\r\nHost: h.example\r\nCookie: c\r\n\r\n"
    )
    code = repeater.main(
        [
            path,
            "--print",
            "--method",
            "post",
            "--path",
            "/z",
            "--header",
            "X-A: b",
            "--remove-header",
            "cookie",
            "--body",
            "hi",
        ]
    )
    assert code == 0
    assert (
        repeater_io.out
        == b"POST /z HTTP/1.1\r\nHost: h.example\r\nX-A: b\r\nContent-Length: 2\r\n\r\nhi\n"
    )


def test_main_save_request_needs_an_active_scope_file(repeater_io, tmp_path, lab):
    (lab.root / "scope.txt").unlink()
    path = write_request(tmp_path, b"GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
    assert repeater.main([path, "--save-request", "x.http", "--print"]) == 2
    assert (
        repeater_io.console.strip()
        == "this workspace has no scope file yet; run `bughunt scope init` first"
    )
    assert not (requests_dir() / "x.http").exists()


def test_main_save_request_stores_the_raw_unredacted_bytes_under_requests(
    repeater_io, tmp_path, lab
):
    raw = b"GET /a HTTP/1.1\r\nHost: allowed.example\r\nCookie: sid=raw\r\n\r\n"
    assert (
        repeater.main(
            [write_request(tmp_path, raw), "--save-request", "kept.http", "--print"]
        )
        == 0
    )
    assert (requests_dir() / "kept.http").read_bytes() == raw
    assert str(requests_dir() / "kept.http") in repeater_io.console
    assert (
        b"Cookie: [REDACTED]" in repeater_io.out
    )  # the preview is redacted, the saved copy is not


def test_main_save_request_cannot_escape_the_requests_directory(
    repeater_io, tmp_path, lab
):
    path = write_request(tmp_path, b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
    assert repeater.main([path, "--save-request", "../../evil.http", "--print"]) == 0
    assert [p.name for p in requests_dir().iterdir()] == ["evil.http"]
    assert (
        not (lab.root.parent / "evil.http").exists()
        and not (lab.root / "evil.http").exists()
    )


def test_main_unsendable_requests_exit_2_before_any_connection(
    repeater_io, tmp_path, lab
):
    assert repeater.main([write_request(tmp_path, b"GET / HTTP/1.1\r\n\r\n")]) == 2
    assert (
        repeater_io.console.strip()
        == "The request has no host. Add a Host header, --host, or --connect."
    )
    path = write_request(
        tmp_path, b"GET / HTTP/1.1\r\nHost: outside.example\r\n\r\n", "out.http"
    )
    assert repeater.main([path]) == 2
    assert repeater_io.console.strip().splitlines()[-2:] == [
        "outside.example is outside this engagement's scope, so it was left alone.",
        "    bughunt scope add outside.example",
    ]
    ftp = write_request(
        tmp_path, b"GET ftp://allowed.example/x HTTP/1.1\r\n\r\n", "ftp.http"
    )
    assert repeater.main([ftp]) == 2
    assert "Only http and https requests can be sent." in repeater_io.console
    bad_port = write_request(
        tmp_path, b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n", "port.http"
    )
    assert repeater.main([bad_port, "--connect", "allowed.example:99999"]) == 2
    assert "Port 99999 is out of range." in repeater_io.console


def test_main_oversized_replacement_body_exits_2(repeater_io, tmp_path, lab):
    path = write_request(tmp_path, b"POST / HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
    big = tmp_path / "body.bin"
    with big.open("wb") as handle:
        handle.truncate(8 * 1024 * 1024)
    assert (
        repeater.main([path, "--body-file", str(big), "--print"]) == 0
    )  # exactly 8 MiB is allowed
    # 8 MiB + 1 is refused up front by apply_edits
    with big.open("ab") as handle:
        handle.write(b"x")
    assert repeater.main([path, "--body-file", str(big), "--print"]) == 2


def _stub_editor(tmp_path: Path, replace_from: str, replace_to: str) -> str:
    script = (
        tmp_path
        / f"stub_editor_{hashlib.sha256((replace_from + '|' + replace_to).encode()).hexdigest()[:8]}.py"
    )
    script.write_text(
        "import sys\n"
        "target = sys.argv[1]\n"
        f"open({str(tmp_path / 'editor-target.txt')!r}, 'w').write(target)\n"
        "data = open(target, 'rb').read()\n"
        f"open(target, 'wb').write(data.replace({replace_from.encode()!r}, {replace_to.encode()!r}))\n",
        encoding="utf-8",
    )
    return f'"{Path(sys.executable).as_posix()}" "{script.as_posix()}"'


def test_edit_flag_runs_the_editor_on_the_rendered_request(
    repeater_io, tmp_path, lab, monkeypatch
):
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setenv("EDITOR", _stub_editor(tmp_path, "GET /a", "GET /edited"))
    path = write_request(tmp_path, b"GET /a HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
    assert repeater.main([path, "--edit", "--print"]) == 0
    assert repeater_io.out == b"GET /edited HTTP/1.1\r\nHost: allowed.example\r\n\r\n"
    handed_over = Path((tmp_path / "editor-target.txt").read_text(encoding="utf-8"))
    assert (
        handed_over.name.startswith("bughunt-request-")
        and handed_over.suffix == ".http"
    )
    assert (
        not handed_over.exists()
    )  # the temporary file is removed once the edit is read back


def test_visual_takes_precedence_over_editor(repeater_io, tmp_path, lab, monkeypatch):
    monkeypatch.setenv("EDITOR", _stub_editor(tmp_path, "GET /a", "GET /from-editor"))
    monkeypatch.setenv("VISUAL", _stub_editor(tmp_path, "GET /a", "GET /from-visual"))
    path = write_request(tmp_path, b"GET /a HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
    assert repeater.main([path, "--edit", "--print"]) == 0
    assert b"GET /from-visual HTTP/1.1" in repeater_io.out


def test_edit_flag_without_an_editor_exits_2(repeater_io, tmp_path, lab, monkeypatch):
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.delenv("EDITOR", raising=False)
    path = write_request(tmp_path, b"GET /a HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
    assert repeater.main([path, "--edit", "--print"]) == 2
    assert repeater_io.console.strip() == "Set EDITOR or VISUAL to edit the request."


def test_edit_flag_with_an_editor_that_empties_the_file_exits_2(
    repeater_io, tmp_path, lab, monkeypatch
):
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setenv(
        "EDITOR",
        _stub_editor(tmp_path, "GET /a HTTP/1.1\r\nHost: allowed.example\r\n\r\n", ""),
    )
    path = write_request(tmp_path, b"GET /a HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
    assert repeater.main([path, "--edit", "--print"]) == 2
    assert repeater_io.console.strip() == "The editor saved an empty request."


def test_edit_flag_is_a_guarded_process_boundary(
    repeater_io, tmp_path, lab, monkeypatch
):
    monkeypatch.setenv("EDITOR", _stub_editor(tmp_path, "a", "b"))
    document = lab.grant()
    document["permissions"]["process"] = False
    (lab.root / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    req = repeater.RawRequest("GET", "/", "HTTP/1.1", [("Host", "allowed.example")])
    with pytest.raises(egress.PolicyBlocked):
        repeater.edit_request(req)


def header_block(raw: bytes) -> list[bytes]:
    return raw.partition(b"\r\n\r\n")[0].split(b"\r\n")


def header_value(raw: bytes, name: str) -> bytes | None:
    for line in header_block(raw)[1:]:
        key, _, value = line.partition(b":")
        if key.strip().lower() == name.lower().encode():
            return value.strip()
    return None


def test_send_relays_the_request_and_prints_a_redacted_response(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin()
    raw = (
        f"GET /a?q=1 HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nX-Custom: keep\r\n"
        f"Content-Length: 99\r\n\r\n"
    ).encode()
    assert repeater.main([write_request(tmp_path, raw)]) == 0
    (seen,) = origin.requests
    assert seen.startswith(b"GET /a?q=1 HTTP/1.1\r\n")
    assert header_value(seen, "Host") == f"127.0.0.1:{origin.port}".encode()
    assert header_value(seen, "X-Custom") == b"keep"
    assert header_value(seen, "User-Agent") == b"Bughunt-owned-lab"
    assert header_value(seen, "X-Researcher") == b"owned-lab"
    assert (
        header_value(seen, "Content-Length") is None
    )  # framing headers are dropped; no body was declared
    out = repeater_io.out.decode("latin-1")
    assert out.startswith(
        f"sent GET http://127.0.0.1:{origin.port}/a?q=1\nHTTP/1.1 200 OK\r\n"
    )
    assert "content-length: 5\r\n" in out and "x-backend: one\r\n" in out
    assert "set-cookie: [REDACTED]\r\n" in out and "sid=abc" not in out
    assert out.endswith("\r\n\r\nhello\n")


def test_send_framing_headers_come_from_the_client_library_not_the_file(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin()
    get_path = write_request(
        tmp_path, f"GET /p HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    )
    assert repeater.main([get_path]) == 0
    assert header_value(origin.requests[0], "Content-Length") is None
    post_path = write_request(
        tmp_path,
        f"POST /p HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nContent-Length: 77\r\n\r\n".encode(),
        "p.http",
    )
    assert repeater.main([post_path]) == 0
    assert (
        header_value(origin.requests[1], "Content-Length") == b"0"
    )  # the stale value is dropped; httpx frames POST


def test_send_with_a_body_sets_the_content_length_and_sends_the_bytes(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin()
    raw = f"POST /p HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    assert repeater.main([write_request(tmp_path, raw), "--body", "payload"]) == 0
    (seen,) = origin.requests
    assert seen.startswith(b"POST /p HTTP/1.1\r\n") and seen.endswith(
        b"\r\n\r\npayload"
    )
    assert header_value(seen, "Content-Length") == b"7"


def test_send_keeps_the_host_header_only_when_connect_chose_another_target(
    repeater_io, tmp_path, make_origin, lab
):
    origin = make_origin()
    lab.grant(origin.origin, "http://vhost.example")
    raw = f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    path = write_request(tmp_path, raw)
    assert (
        repeater.main(
            [path, "--host", "vhost.example", "--connect", f"127.0.0.1:{origin.port}"]
        )
        == 0
    )
    assert header_value(origin.requests[-1], "Host") == b"vhost.example"
    assert (
        repeater.main([path, "--host", "vhost.example"]) == 2
    )  # without --connect the Host decides: out of scope


def test_send_output_file_gets_the_redacted_raw_response(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin()
    target = tmp_path / "response.bin"
    raw = f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    assert repeater.main([write_request(tmp_path, raw), "--output", str(target)]) == 0
    saved = target.read_bytes()
    assert saved.startswith(b"HTTP/1.1 200 OK\r\n") and saved.endswith(b"\r\n\r\nhello")
    assert b"set-cookie: [REDACTED]" in saved and b"sid=abc" not in saved


def test_send_with_output_prints_only_a_receipt_not_the_response(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin()
    target = tmp_path / "response.bin"
    raw = f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    assert repeater.main([write_request(tmp_path, raw), "--output", str(target)]) == 0
    shown = repeater_io.out
    assert (
        b"hello" not in shown
        and b"set-cookie" not in shown.lower()
        and b"HTTP/1.1 200" not in shown
    )
    assert (
        f"status 200, {len(target.read_bytes())} bytes saved to {target}".encode()
        in shown
    )
    assert target.read_bytes().endswith(b"hello")


def test_quiet_suppresses_the_response_body_and_prints_only_a_receipt(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin()
    raw = f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    assert repeater.main([write_request(tmp_path, raw), "--quiet"]) == 0
    shown = repeater_io.out
    assert (
        b"hello" not in shown
        and b"set-cookie" not in shown.lower()
        and b"HTTP/1.1 200" not in shown
    )
    assert b"status 200," in shown and f"sent GET {origin.origin}/".encode() in shown


def test_send_response_with_an_empty_reason_phrase_has_no_trailing_space(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin(
        lambda raw: b"HTTP/1.1 200 \r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    )
    target = tmp_path / "out.bin"
    path = write_request(
        tmp_path, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    )
    assert repeater.main([path, "--output", str(target)]) == 0
    assert target.read_bytes().startswith(b"HTTP/1.1 200\r\ncontent-length: 2\r\n")


def test_send_connection_failure_exits_1(repeater_io, tmp_path, lab):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
    lab.grant(f"http://127.0.0.1:{dead_port}")
    raw = f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{dead_port}\r\n\r\n".encode()
    assert repeater.main([write_request(tmp_path, raw)]) == 1
    assert repeater_io.console.startswith("Request failed:")


def test_send_policy_denial_exits_1_with_the_policy_reason(repeater_io, tmp_path, lab):
    lab.grant()  # loopback is in scope, but the mission policy has no asset row for this port
    raw = b"GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"
    assert repeater.main([write_request(tmp_path, raw)]) == 1
    assert (
        repeater_io.console.strip()
        == "Request failed: asset-unknown; no outbound action ran"
    )


def test_oversized_response_display_is_truncated_with_a_notice(
    repeater_io, tmp_path, make_origin
):
    body = b"A" * (600 * 1024)
    reply = (
        b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
        % len(body)
        + body
    )
    origin = make_origin(lambda raw: reply)
    path = write_request(
        tmp_path, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    )
    assert repeater.main([path]) == 0
    assert "Response truncated at 524288 bytes." in repeater_io.console
    assert 524288 <= len(repeater_io.out) < 524288 + 400


def redirecting(codes_to_location):
    """A responder that replies 3xx with a Location to `codes_to_location(path)` for /r..., else 200."""

    def respond(raw: bytes) -> bytes:
        path = raw.split(b" ", 2)[1].decode()
        if path.startswith("/r"):
            code, location = codes_to_location(path)
            return (
                f"HTTP/1.1 {code} Moved\r\nLocation: {location}\r\nContent-Length: 0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
        return CANNED.replace(
            b"Connection: keep-alive, X-Backend", b"Connection: close"
        )

    return respond


@pytest.mark.parametrize(
    "code, method_after, body_after",
    [
        (301, "GET", b""),
        (302, "GET", b""),
        (303, "GET", b""),
        (307, "POST", b"keep"),
        (308, "POST", b"keep"),
    ],
)
def test_follow_redirect_rewrites_method_and_body_per_status(
    repeater_io, tmp_path, make_origin, code, method_after, body_after
):
    origin = make_origin(redirecting(lambda path: (code, "/landing")))
    path = write_request(
        tmp_path, f"POST /r HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    )
    assert repeater.main([path, "--body", "keep", "--follow"]) == 0
    first, second = origin.requests
    assert first.startswith(b"POST /r ") and second.startswith(
        f"{method_after} /landing ".encode()
    )
    assert second.endswith(b"\r\n\r\n" + body_after)
    assert f"sent {method_after} {origin.origin}/landing".encode() in repeater_io.out


def test_without_follow_the_redirect_response_is_shown_as_is(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin(redirecting(lambda path: (302, "/landing")))
    path = write_request(
        tmp_path, f"GET /r HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    )
    assert repeater.main([path]) == 0
    assert len(origin.requests) == 1
    assert (
        b"HTTP/1.1 302 Moved" in repeater_io.out
        and b"location: /landing" in repeater_io.out
    )


def test_follow_drops_the_host_override_after_the_first_hop(
    repeater_io, tmp_path, make_origin, lab
):
    landing = make_origin()
    hop = make_origin(redirecting(lambda path: (302, f"{landing.origin}/landing")))
    lab.grant(hop.origin, landing.origin, "http://vhost.example")
    path = write_request(tmp_path, b"GET /r HTTP/1.1\r\nHost: placeholder\r\n\r\n")
    assert (
        repeater.main(
            [
                path,
                "--host",
                "vhost.example",
                "--connect",
                f"127.0.0.1:{hop.port}",
                "--follow",
            ]
        )
        == 0
    )
    assert header_value(hop.requests[0], "Host") == b"vhost.example"
    assert (
        header_value(landing.requests[0], "Host")
        == f"127.0.0.1:{landing.port}".encode()
    )


def test_follow_stops_after_five_redirects(repeater_io, tmp_path, make_origin):
    origin = make_origin(redirecting(lambda path: (302, "/r2")))
    path = write_request(
        tmp_path, f"GET /r HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    )
    assert repeater.main([path, "--follow"]) == 0
    assert len(origin.requests) == 6  # the original request plus five followed hops
    assert b"HTTP/1.1 302 Moved" in repeater_io.out


def test_follow_into_an_out_of_scope_host_stops_and_exits_2(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin(redirecting(lambda path: (302, "http://outside.example/x")))
    path = write_request(
        tmp_path, f"GET /r HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    )
    assert repeater.main([path, "--follow"]) == 2
    assert len(origin.requests) == 1
    assert b"HTTP/1.1 302 Moved" in repeater_io.out
    assert (
        "outside.example is outside this engagement's scope, so it was left alone."
        in repeater_io.console
    )


def test_follow_out_of_scope_redirect_with_output_writes_file_and_withholds_body(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin(redirecting(lambda path: (302, "http://outside.example/x")))
    target = tmp_path / "halted.bin"
    path = write_request(
        tmp_path, f"GET /r HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    )
    assert repeater.main([path, "--output", str(target), "--follow"]) == 2
    assert len(origin.requests) == 1
    shown = repeater_io.out
    assert b"HTTP/1.1 302 Moved" not in shown and b"location:" not in shown.lower()
    assert target.exists(), (
        "the out-of-scope redirect response was not written to --output"
    )
    saved = target.read_bytes()
    assert saved.startswith(b"HTTP/1.1 302 Moved")
    assert f"status 302, {len(saved)} bytes saved to {target}".encode() in shown
    assert b"stopped at out-of-scope redirect" in shown
    assert "outside.example is outside this engagement's scope" in repeater_io.console


def test_follow_without_a_location_header_shows_the_response(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin(
        lambda raw: (
            b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    )
    path = write_request(
        tmp_path, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    )
    assert repeater.main([path, "--follow"]) == 0
    assert len(origin.requests) == 1 and b"HTTP/1.1 302 Found" in repeater_io.out


def test_credentials_are_redacted_from_everything_repeater_prints(
    repeater_io, tmp_path, make_origin
):
    echoed = b"Authorization: Bearer topsecret\nX-API-Key: keyvalue\nplain line\n"
    reply = (
        b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
        % len(echoed)
        + echoed
    )
    origin = make_origin(lambda raw: reply)
    raw = (
        f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nAuthorization: Bearer topsecret\r\n"
        f"X-API-Key: keyvalue\r\n\r\n"
    ).encode()
    assert repeater.main([write_request(tmp_path, raw)]) == 0
    assert b"topsecret" not in repeater_io.out and b"keyvalue" not in repeater_io.out
    assert (
        b"Authorization: [REDACTED]\nX-API-Key: [REDACTED]\nplain line\n"
        in repeater_io.out
    )
    assert (
        header_value(origin.requests[0], "Authorization") == b"Bearer topsecret"
    )  # but it IS sent


def test_default_actor_forwards_a_csrf_companion_header(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin()
    raw = (
        f"GET /a HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nX-CSRF-Token: tok\r\n"
        f"Cookie: browser=1\r\n\r\n"
    ).encode()
    assert repeater.main([write_request(tmp_path, raw)]) == 0
    assert header_value(origin.requests[0], "X-CSRF-Token") == b"tok"
    assert header_value(origin.requests[0], "Cookie") == b"browser=1"


def test_named_actor_replaces_browser_credentials_with_its_own(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin()
    identity.create_profile("owner", "owner", [origin.origin], owned=True)
    identity.set_credential("owner", "cookie", "sid=owner-secret")
    identity.use_profile("owner")
    raw = (
        f"GET /a HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nCookie: browser=1\r\n"
        f"X-Custom: keep\r\n\r\n"
    ).encode()
    assert repeater.main([write_request(tmp_path, raw)]) == 0
    seen = origin.requests[0]
    assert header_value(seen, "Cookie") == b"sid=owner-secret"
    assert header_value(seen, "X-Custom") == b"keep"
    assert b"browser=1" not in seen


def test_save_request_happens_before_the_scope_check_and_before_sending(
    repeater_io, tmp_path, lab
):
    raw = b"GET / HTTP/1.1\r\nHost: outside.example\r\n\r\n"
    assert (
        repeater.main([write_request(tmp_path, raw), "--save-request", "early.http"])
        == 2
    )
    assert (requests_dir() / "early.http").read_bytes() == raw
    assert "outside.example is outside this engagement's scope" in repeater_io.console


def test_send_timeout_flag_bounds_the_wait_for_a_response(
    repeater_io, tmp_path, make_origin
):
    def slow(raw: bytes) -> bytes:
        time.sleep(3)
        return CANNED

    origin = make_origin(slow)
    path = write_request(
        tmp_path, f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
    )
    started = time.monotonic()
    assert repeater.main([path, "--timeout", "0.4"]) == 1
    assert time.monotonic() - started < 2.8
    assert repeater_io.console.startswith("Request failed:")


# ==================================================================================================
# 3. snare: formatters (pure)
# ==================================================================================================


def test_format_banner_plain_is_the_ascii_art_plus_the_tagline():
    expected = (
        "              \\   |   /\n"
        "               \\  |  /\n"
        "            .---\\ | /---.\n"
        "           /     \\|/     \\\n"
        "          |     snare     |\n"
        "           \\     /|\\     /\n"
        "            '---/ | \\---'\n"
        "               /  |  \\\n"
        "              /   |   \\\n"
        "                [web]\n"
        "the web the browser flies into"
    )
    assert snare.format_banner(False) == expected


def test_format_banner_color_wraps_the_same_text_in_ansi():
    colored = snare.format_banner(True)
    assert re.sub(r"\x1b\[[0-9;]*m", "", colored) == snare.format_banner(False)
    assert f"{CYAN}          |     {MAGENTA}snare{CYAN}     |{RESET}" in colored
    assert f"{CYAN}                {YELLOW}[{CYAN}web{YELLOW}]{CYAN}{RESET}" in colored
    assert colored.endswith(f"{DIM}the web the browser flies into{RESET}")


@pytest.mark.parametrize(
    "args, kwargs, expected",
    [
        (
            ("GET", "200", 1234, "example.com", "/a"),
            {},
            "GET\t200\t1234\texample.com\t/a",
        ),
        (
            ("POST", "404", 0, "h", "/p?q=1"),
            dict(name="h-snare-0001.http"),
            "POST\t404\t0\th\t/p?q=1\th-snare-0001.http",
        ),
        (
            ("GET", "200", 5, "h", "/"),
            dict(name="n.http", note="truncated"),
            "GET\t200\t5\th\t/\tn.http\ttruncated",
        ),
        (
            ("GET", "200", 5, "h", "/"),
            dict(note="truncated"),
            "GET\t200\t5\th\t/\ttruncated",
        ),
    ],
)
def test_format_row_plain_is_tab_separated(args, kwargs, expected):
    assert snare.format_row(*args, False, **kwargs) == expected


def test_format_row_color_layout_and_status_colors():
    row = snare.format_row(
        "GET", "200", 12, "example.com", "/a", True, name="n.http", note="truncated"
    )
    assert row == (
        f"{CYAN}GET    {RESET} {GREEN}200{RESET} {DIM}      12{RESET}  {WHITE}example.com /a{RESET}"
        f"  {MAGENTA}n.http{RESET} {YELLOW}truncated{RESET}"
    )
    bare = snare.format_row("DELETE", "302", 123456789, "h", "/", True)
    assert (
        bare
        == f"{CYAN}DELETE {RESET} {CYAN}302{RESET} {DIM}123456789{RESET}  {WHITE}h /{RESET}"
    )
    for status, color in (
        ("204", GREEN),
        ("301", CYAN),
        ("403", YELLOW),
        ("503", RED),
        ("100", WHITE),
        ("-", WHITE),
    ):
        assert f" {color}{status:<3}{RESET} " in snare.format_row(
            "GET", status, 1, "h", "/", True
        )


def test_format_skip_and_tunnel():
    assert snare.format_skip("h.example", False) == "skipped\th.example"
    assert (
        snare.format_skip("h.example", True)
        == f"{YELLOW}skipped{RESET}  {DIM}h.example{RESET}"
    )
    assert snare.format_tunnel("h.example", 443, False) == "tunnel\th.example:443"
    assert (
        snare.format_tunnel("h.example", 443, True)
        == f"{YELLOW}tunnel{RESET}   {DIM}h.example:443{RESET}"
    )


def test_format_guide_names_the_capture_folders_relative_to_the_working_directory(
    lab, monkeypatch, tmp_path
):
    monkeypatch.chdir(tmp_path)
    plain = snare.format_guide(False)
    assert plain.splitlines() == [
        "requests  ws/requests/example.com-snare-0001.http",
        "responses ws/responses/example.com-snare-0001.http",
        "view      clutch",
        "          clutch show example.com-snare-0001.http",
        "compare   diff example.com-snare-0001.http example.com-snare-0002.http",
    ]
    colored = snare.format_guide(True)
    assert re.sub(r"\x1b\[[0-9;]*m", "", colored) == plain
    assert (
        f"{CYAN}requests  {RESET}{WHITE}ws/requests/example.com-snare-0001.http{RESET}"
        in colored
    )
    assert (
        f"{CYAN}view      {RESET}{WHITE}{MAGENTA}clutch{RESET}{WHITE}{RESET}" in colored
    )
    assert (
        f"{' ' * 10}{WHITE}{MAGENTA}clutch show{RESET}{WHITE} example.com-snare-0001.http{RESET}"
        in colored
    )
    assert (
        f"{CYAN}compare   {RESET}{WHITE}{MAGENTA}diff{RESET}{WHITE} "
        f"example.com-snare-0001.http example.com-snare-0002.http{RESET}"
    ) in colored


def test_format_guide_uses_the_absolute_posix_path_outside_the_working_directory(
    lab, monkeypatch, tmp_path
):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    first = snare.format_guide(False).splitlines()[0]
    assert first == f"requests  {requests_dir().as_posix()}/example.com-snare-0001.http"
    assert "\\" not in first


# ==================================================================================================
# 3b. snare: offline capture store (names, urls.txt, manifest)
# ==================================================================================================

REQUEST_BYTES = b"GET /x HTTP/1.1\r\nHost: allowed.example\r\n\r\n"
RESPONSE_BYTES = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


def test_store_writes_the_pair_with_the_same_name_and_returns_it(lab):
    name = snare._store(
        REQUEST_BYTES, RESPONSE_BYTES, "https://allowed.example/x", "allowed.example"
    )
    assert name == "allowed.example-snare-0001.http"
    assert (requests_dir() / name).read_bytes() == REQUEST_BYTES
    assert (responses_dir() / name).read_bytes() == RESPONSE_BYTES
    assert urls_path().read_text(encoding="utf-8") == "https://allowed.example/x\n"


def test_store_numbers_per_host_and_counts_both_folders(lab):
    first = snare._store(
        REQUEST_BYTES, RESPONSE_BYTES, "https://allowed.example/a", "allowed.example"
    )
    second = snare._store(
        REQUEST_BYTES, RESPONSE_BYTES, "https://allowed.example/b", "allowed.example"
    )
    assert (first, second) == (
        "allowed.example-snare-0001.http",
        "allowed.example-snare-0002.http",
    )
    (responses_dir() / "allowed.example-snare-0041.http").write_bytes(
        b"orphan response only"
    )
    third = snare._store(
        REQUEST_BYTES, RESPONSE_BYTES, "https://allowed.example/c", "allowed.example"
    )
    assert third == "allowed.example-snare-0042.http"
    other = snare._store(
        REQUEST_BYTES,
        RESPONSE_BYTES,
        "https://allowed.example/d",
        "www.allowed.example",
    )
    assert other == "www.allowed.example-snare-0001.http"
    (requests_dir() / "allowed.example-snare-9999.http").write_bytes(b"x")
    assert (
        snare._store(
            REQUEST_BYTES,
            RESPONSE_BYTES,
            "https://allowed.example/e",
            "allowed.example",
        )
        == "allowed.example-snare-10000.http"
    )


@pytest.mark.parametrize(
    "host, expected_prefix",
    [
        ("Example.COM.", "example.com"),
        ("a:8080", "a_8080"),
        ("::1", "1"),
        ("../../evil", "evil"),
        ("x/y\\z", "x_y_z"),
        ("", "host"),
        ("...", "host"),
        ("m\u00fcnchen.de", "m_nchen.de"),
        ("a" * 300, "a" * 200),
    ],
)
def test_store_sanitizes_the_host_into_a_safe_file_name(lab, host, expected_prefix):
    name = snare._store(
        REQUEST_BYTES, RESPONSE_BYTES, "https://allowed.example/x", host
    )
    assert name == f"{expected_prefix}-snare-0001.http"
    assert (requests_dir() / name).is_file() and (responses_dir() / name).is_file()
    assert {p.name for p in requests_dir().iterdir()} == {name}


def test_store_is_safe_under_concurrent_callers(lab):
    count = 24
    barrier = threading.Barrier(count)
    names: list[str] = []
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            barrier.wait(10)
            names.append(
                snare._store(
                    REQUEST_BYTES,
                    RESPONSE_BYTES,
                    f"https://allowed.example/{index}",
                    "allowed.example",
                )
            )
        except BaseException as exc:  # noqa: BLE001 - collected for the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert errors == []
    assert sorted(names) == [
        f"allowed.example-snare-{number:04d}.http" for number in range(1, count + 1)
    ]
    assert (
        len(list(requests_dir().iterdir())) == count
        and len(list(responses_dir().iterdir())) == count
    )
    assert sorted(urls_path().read_text(encoding="utf-8").splitlines()) == sorted(
        f"https://allowed.example/{index}" for index in range(count)
    )


def test_store_keeps_each_url_in_urls_txt_once(lab):
    for _ in range(3):
        snare._store(
            REQUEST_BYTES,
            RESPONSE_BYTES,
            "https://allowed.example/x",
            "allowed.example",
        )
    snare._store(
        REQUEST_BYTES, RESPONSE_BYTES, "https://allowed.example/y", "allowed.example"
    )
    assert urls_path().read_text(encoding="utf-8").splitlines() == [
        "https://allowed.example/x",
        "https://allowed.example/y",
    ]
    assert (
        len(list(requests_dir().iterdir())) == 4
    )  # every exchange still gets its own file pair


def test_store_leaves_existing_urls_txt_lines_and_appends_without_a_scope_file(lab):
    (lab.root / "scope.txt").unlink()
    urls_path().write_text("https://pre.example/\n", encoding="utf-8")
    snare._store(
        REQUEST_BYTES, RESPONSE_BYTES, "https://allowed.example/x", "allowed.example"
    )
    assert (
        urls_path().read_text(encoding="utf-8")
        == "https://pre.example/\nhttps://allowed.example/x\n"
    )


def test_store_records_a_ledger_run_that_points_at_the_files(lab):
    name = snare._store(
        REQUEST_BYTES, RESPONSE_BYTES, "https://allowed.example/x", "allowed.example"
    )
    (manifest,) = snare_manifests()
    assert (manifest["tool"], manifest["operation"], manifest["target"]) == (
        "snare",
        "manual",
        "https://allowed.example/x",
    )
    assert manifest["representation"] == "raw-http capture"
    assert manifest["source_files"] == {
        "request": f"requests/{name}",
        "response": f"responses/{name}",
    }
    assert manifest["actor"] == "default" and manifest["decision"] == "permitted"
    assert manifest["classification"] == "observation" and manifest["error"] == ""
    assert manifest["request"] == {
        "path": "request.http",
        "sha256": sha(REQUEST_BYTES),
        "size": len(REQUEST_BYTES),
        "truncated": False,
    }
    assert manifest["response"] == {
        "path": "response.http",
        "sha256": sha(RESPONSE_BYTES),
        "size": len(RESPONSE_BYTES),
        "truncated": False,
    }
    run = ledger.runs_dir() / manifest["run_id"]
    assert (run / "request.http").read_bytes() == REQUEST_BYTES
    assert (run / "response.http").read_bytes() == RESPONSE_BYTES


def test_store_marks_truncation_in_both_evidence_entries_and_names_the_actor(lab):
    snare._store(
        REQUEST_BYTES,
        RESPONSE_BYTES,
        "https://allowed.example/x",
        "allowed.example",
        actor="analyst",
        truncated=True,
    )
    (manifest,) = snare_manifests()
    assert manifest["actor"] == "analyst"
    assert (
        manifest["request"]["truncated"] is True
        and manifest["response"]["truncated"] is True
    )


def test_store_refuses_a_target_the_policy_does_not_grant(lab):
    with pytest.raises(egress.PolicyBlocked):
        snare._store(
            REQUEST_BYTES,
            RESPONSE_BYTES,
            "https://not-granted.example/",
            "not-granted.example",
        )
    assert not requests_dir().exists() or list(requests_dir().iterdir()) == []


# ==================================================================================================
# 3c. snare: CA and leaf certificates
# ==================================================================================================

CA_CONFIG = (
    "[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\nprompt=no\n[dn]\nCN=Bughunt snare CA\n"
    "[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
    "subjectKeyIdentifier=hash\n"
)


@pytest.mark.parametrize(
    "host",
    ["bad host", "a/b", "a\\b", "", "x;y", "h\u00e9llo", "a b.example", "../x/y"],
)
def test_issue_leaf_rejects_hostnames_that_cannot_be_certificate_names(lab, host):
    with pytest.raises(snare.CaError) as caught:
        snare.issue_leaf(host)
    assert str(caught.value) == "That host cannot have a certificate."
    assert not (workspace_dir() / "snare").exists()


def validity_days(certificate: Path) -> int:
    text = subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(certificate),
            "-noout",
            "-startdate",
            "-enddate",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    fields = dict(line.split("=", 1) for line in text.strip().splitlines())
    parse = lambda value: datetime.strptime(
        " ".join(value.split()), "%b %d %H:%M:%S %Y GMT"
    )  # noqa: E731
    return (parse(fields["notAfter"]) - parse(fields["notBefore"])).days


@pytest.fixture
def chmod_calls(monkeypatch):
    calls: list[tuple[str, int]] = []
    real = os.chmod

    def record(path, mode, *args, **kwargs):
        calls.append((Path(path).name, mode))
        return real(path, mode, *args, **kwargs)

    monkeypatch.setattr(os, "chmod", record)
    return calls


@needs_openssl
def test_ensure_ca_writes_the_ca_once_and_reuses_it(lab, chmod_calls):
    cert, key = snare.ensure_ca()
    assert ("ca.key", 0o600) in chmod_calls
    assert validity_days(cert) == 825
    assert (cert, key) == (
        workspace_dir() / "snare" / "ca.crt",
        workspace_dir() / "snare" / "ca.key",
    )
    assert (workspace_dir() / "snare" / "ca.cnf").read_text(
        encoding="utf-8"
    ) == CA_CONFIG
    first = (cert.read_bytes(), key.read_bytes())
    assert snare.ensure_ca() == (cert, key)
    assert (
        cert.read_bytes(),
        key.read_bytes(),
    ) == first  # never regenerated while both files exist
    subject = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-subject"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "Bughunt snare CA" in subject
    text = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-text"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "CA:TRUE" in text and "Certificate Sign" in text


@needs_openssl
@pytest.mark.parametrize(
    "host, san",
    [("127.0.0.1", "IP Address:127.0.0.1"), ("lab.example", "DNS:lab.example")],
)
def test_issue_leaf_signs_a_leaf_for_the_host_with_the_right_san(
    lab, chmod_calls, host, san
):
    cert, key = snare.issue_leaf(host)
    assert (f"{host}.key", 0o600) in chmod_calls
    assert validity_days(cert) == 30
    leafs = workspace_dir() / "snare" / "leafs"
    assert (cert, key) == (leafs / f"{host}.crt", leafs / f"{host}.key")
    text = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-text"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert (
        san in text and "CA:FALSE" in text and "TLS Web Server Authentication" in text
    )
    assert f"CN={host}" in text.replace("CN = ", "CN=")
    verify = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(workspace_dir() / "snare" / "ca.crt"),
            str(cert),
        ],
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr
    mtime = cert.stat().st_mtime_ns
    assert (
        snare.issue_leaf(host) == (cert, key) and cert.stat().st_mtime_ns == mtime
    )  # cached


@needs_openssl
def test_issue_leaf_replaces_colons_in_the_file_name(lab):
    cert, _key = snare.issue_leaf("::1")
    assert cert.name == "__1.crt"


def fake_openssl(monkeypatch, behavior):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return behavior(command, kwargs)

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_ensure_ca_reports_a_missing_openssl(lab, monkeypatch):
    def missing(command, kwargs):
        raise FileNotFoundError(command[0])

    fake_openssl(monkeypatch, missing)
    with pytest.raises(snare.CaError) as caught:
        snare.ensure_ca()
    assert str(caught.value) == "openssl is not on PATH."


def test_ensure_ca_reports_a_hung_openssl(lab, monkeypatch):
    def hung(command, kwargs):
        raise subprocess.TimeoutExpired(command, kwargs.get("timeout", 30))

    calls = fake_openssl(monkeypatch, hung)
    with pytest.raises(snare.CaError) as caught:
        snare.ensure_ca()
    assert str(caught.value) == "openssl took too long."
    assert calls[0][1]["timeout"] == 30 and calls[0][0][0] == "openssl"


@pytest.mark.parametrize(
    "stderr, message",
    [(b"warn\nboom: bad config\n", "boom: bad config"), (b"", "openssl failed.")],
)
def test_ensure_ca_reports_the_last_stderr_line_of_a_failed_openssl(
    lab, monkeypatch, stderr, message
):
    fake_openssl(
        monkeypatch,
        lambda command, kwargs: subprocess.CompletedProcess(command, 1, b"", stderr),
    )
    with pytest.raises(snare.CaError) as caught:
        snare.ensure_ca()
    assert str(caught.value) == message


def test_ensure_ca_command_line_and_working_directory(lab, monkeypatch):
    calls = fake_openssl(
        monkeypatch,
        lambda command, kwargs: subprocess.CompletedProcess(command, 1, b"", b"stop"),
    )
    with pytest.raises(snare.CaError):
        snare.ensure_ca()
    command, kwargs = calls[0]
    assert command == [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-keyout",
        "ca.key",
        "-out",
        "ca.crt",
        "-days",
        "825",
        "-nodes",
        "-config",
        "ca.cnf",
    ]
    assert Path(kwargs["cwd"]) == workspace_dir() / "snare"


def test_openssl_is_a_policy_guarded_process_boundary(lab):
    document = lab.grant()
    document["permissions"]["process"] = False
    (lab.root / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(egress.PolicyBlocked):
        snare.ensure_ca()


# ==================================================================================================
# 3d. snare: listener lifecycle
# ==================================================================================================


def test_listen_binds_loopback_reports_readiness_and_stops_on_request(
    lab, start_proxy, capsys
):
    proxy = start_proxy()
    assert isinstance(proxy.port, int) and 0 < proxy.port < 65536
    assert proxy.settings.ready.is_set()
    err = capsys.readouterr().err.splitlines()
    assert err[0] == f"listening on 127.0.0.1:{proxy.port}"
    assert err[1] == f"CA {workspace_dir() / 'snare' / 'ca.crt'}"
    assert err[2] == "Trust that certificate in the test browser."
    assert err[3].startswith("requests  ") and err[3].endswith(
        "/requests/example.com-snare-0001.http"
    )
    socket.create_connection(("127.0.0.1", proxy.port), timeout=2).close()
    proxy.stop_event.set()
    proxy.thread.join(10)
    assert not proxy.thread.is_alive()


def test_listen_returns_zero_when_stopped(lab):
    lab.seed_placeholder_ca()
    settings = snare.Settings(port=0, plain=True)
    settings.ready = threading.Event()
    stop = threading.Event()
    result = []
    gc.collect()  # flush garbage left by earlier tests so only this listener can warn
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        thread = threading.Thread(
            target=lambda: result.append(snare.listen(settings, stop)), daemon=True
        )
        thread.start()
        assert settings.ready.wait(20)
        port = settings.bound_port
        stop.set()
        thread.join(10)
        gc.collect()
    assert result == [0]
    assert [
        str(item.message)
        for item in caught
        if issubclass(item.category, ResourceWarning)
    ] == []
    assert port_is_free(port)


def test_listen_accepts_port_zero_only_when_the_requested_endpoint_is_granted(lab):
    # Pinned quirk: authorization is checked against the REQUESTED port (":0"), not the bound one.
    lab.seed_placeholder_ca()
    lab.grant()  # grant() always includes http://127.0.0.1:0
    document = json.loads((lab.root / "policy.json").read_text(encoding="utf-8"))
    document["assets"] = [
        row for row in document["assets"] if row["origin"] != "http://127.0.0.1:0"
    ]
    (lab.root / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    already_stopped = threading.Event()
    already_stopped.set()  # a listener that wrongly gets past the policy check returns instead of blocking
    with pytest.raises(egress.PolicyBlocked):
        snare.listen(snare.Settings(port=0), already_stopped)


@pytest.mark.parametrize("denied_operation", ["manual", "process"])
def test_listen_policy_denial_happens_before_any_socket_is_opened(
    lab, opened_ports, denied_operation
):
    lab.seed_placeholder_ca()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
    document = lab.grant(f"http://127.0.0.1:{free_port}")
    document["permissions"][denied_operation] = False
    (lab.root / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    already_stopped = threading.Event()
    already_stopped.set()  # a listener that wrongly gets past the policy check returns instead of blocking
    with pytest.raises(egress.PolicyBlocked):
        snare.listen(snare.Settings(port=free_port), already_stopped)
    with socket.socket() as again:
        again.bind(("127.0.0.1", free_port))  # nothing was left bound


def _exclusive_listener() -> socket.socket:
    squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        squatter.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    squatter.bind(("127.0.0.1", 0))
    squatter.listen(1)
    return squatter


def test_listen_reports_a_busy_port_and_still_signals_ready(lab, capsys):
    lab.seed_placeholder_ca()
    squatter = _exclusive_listener()
    try:
        port = squatter.getsockname()[1]
        lab.grant(f"http://127.0.0.1:{port}")
        settings = snare.Settings(port=port, plain=True)
        settings.ready = threading.Event()
        stopped = threading.Event()
        stopped.set()  # a listener that wrongly binds anyway returns instead of blocking
        gc.collect()  # flush garbage left by earlier tests so only this listener can warn
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            result = snare.listen(settings, stopped)
            gc.collect()
        assert result == 1
        assert [
            str(item.message)
            for item in caught
            if issubclass(item.category, ResourceWarning)
        ] == []
        assert settings.ready.is_set() and settings.bound_port == 0
        assert f"Could not listen on 127.0.0.1:{port}." in capsys.readouterr().err
    finally:
        squatter.close()


def test_listen_without_openssl_still_serves_plain_http(
    lab, make_origin, start_proxy, monkeypatch, capsys
):
    def missing(command, kwargs):
        raise FileNotFoundError(command[0])

    fake_openssl(monkeypatch, missing)
    origin = make_origin()
    proxy = start_proxy(seed_ca=False)
    err = capsys.readouterr().err
    assert "openssl is not on PATH." in err
    assert "HTTP still logs. HTTPS inside scope needs openssl." in err
    assert "Trust that certificate in the test browser." not in err
    assert proxy.talk(request_to(origin)).startswith(b"HTTP/1.1 200 OK")


def test_begin_runs_the_listener_in_the_background_and_stop_closes_it(
    lab, capsys, opened_ports
):
    lab.seed_placeholder_ca()
    settings = snare.Settings(port=0, plain=True)
    assert snare.job_tag() == "" and not snare.console_attached()
    assert snare.begin(settings) == 0
    port = settings.bound_port
    opened_ports.append(port)
    assert port > 0
    assert snare.job_tag() == f"snare:{port}"
    err = capsys.readouterr().err
    assert f"listening on 127.0.0.1:{port}" in err
    assert err.rstrip().endswith(
        "The prompt is free. Other modules keep working.\nsnare stop closes the listener."
    )
    socket.create_connection(("127.0.0.1", port), timeout=2).close()
    # a second begin does not start another listener
    other = snare.Settings(port=0, plain=True)
    assert snare.begin(other) == 0
    again = capsys.readouterr().err
    assert f"snare is already listening on 127.0.0.1:{port}." in again
    assert "snare stop closes the listener." in again and other.bound_port == 0
    # status reports it
    assert snare.print_status() == 0
    status = capsys.readouterr().err
    assert status.startswith(
        f"listening on 127.0.0.1:{port}\nThe prompt is free. Other modules keep working.\n"
    )
    # stop closes it and leaves the files
    assert snare.stop_listener() == 0
    stopped = capsys.readouterr().err
    assert stopped.startswith(
        f"snare stopped. It was on 127.0.0.1:{port}.\nThe saved files stay where they are.\n"
    )
    assert snare.job_tag() == ""
    assert port_is_free(port)


def test_stop_and_status_when_nothing_is_listening(lab, capsys):
    assert snare.stop_listener(quiet=True) == 0
    assert capsys.readouterr().err == ""
    assert snare.stop_listener() == 0
    err = capsys.readouterr().err
    assert (
        err.startswith("snare is not listening.\n")
        and "clutch show example.com-snare-0001.http" in err
    )
    assert snare.print_status() == 0
    assert capsys.readouterr().err.startswith("snare is not listening.\n")
    assert snare.job_tag() == ""


def test_begin_returns_1_when_the_port_cannot_be_bound(lab, capsys):
    lab.seed_placeholder_ca()
    squatter = _exclusive_listener()
    try:
        port = squatter.getsockname()[1]
        lab.grant(f"http://127.0.0.1:{port}")
        assert snare.begin(snare.Settings(port=port, plain=True)) == 1
        assert f"Could not listen on 127.0.0.1:{port}." in capsys.readouterr().err
        assert snare.job_tag() == ""
    finally:
        squatter.close()


def test_attach_console_routes_live_rows_to_the_hook_instead_of_stdout(
    lab, make_origin, start_proxy, capsys
):
    origin = make_origin()
    proxy = start_proxy()
    rows: list[str] = []
    snare.attach_console(rows.append)
    assert snare.console_attached()
    capsys.readouterr()
    assert proxy.talk(request_to(origin, path="/live")).startswith(b"HTTP/1.1 200 OK")
    assert rows == [f"GET\t200\t5\t127.0.0.1\t/live\t127.0.0.1-snare-0001.http"]
    assert capsys.readouterr().out == ""
    snare.attach_console(None)
    assert not snare.console_attached()
    proxy.talk(request_to(origin, path="/again"))
    assert (
        capsys.readouterr().out
        == "GET\t200\t5\t127.0.0.1\t/again\t127.0.0.1-snare-0002.http\n"
    )


def test_main_validates_its_options_before_listening(lab, capsys, monkeypatch):
    def never_listen(settings, stop):
        raise KeyboardInterrupt  # a broken validator must end here instead of binding a real port

    monkeypatch.setattr(snare, "listen", never_listen)
    assert snare.main(["--plain", "--port", "70000"]) == 2
    assert snare.main(["--plain", "--port", "65536"]) == 2
    assert snare.main(["--plain", "--port", "-1"]) == 2
    assert snare.main(["--plain", "--port", "0", "--timeout", "0"]) == 2
    assert snare.main(["--plain", "--port", "0", "--timeout", "-1"]) == 2
    assert snare.main(["--plain", "--port", "0", "--max-body", "0"]) == 2
    assert snare.main(["--plain", "--port", "70000", "ca"]) == 2
    assert capsys.readouterr().err.splitlines() == [
        "The port has to be from 0 to 65535.",
        "The port has to be from 0 to 65535.",
        "The port has to be from 0 to 65535.",
        "Timeout must be greater than 0.",
        "Timeout must be greater than 0.",
        "The body cap has to be at least 1 byte.",
        "The port has to be from 0 to 65535.",
    ]
    assert (
        snare.main(
            ["--plain", "--port", "65535", "--timeout", "0.001", "--max-body", "1"]
        )
        == 0
    )  # accepted


def test_main_stop_and_status_skip_option_validation(lab, capsys):
    assert snare.main(["--port", "70000", "stop"]) == 0
    assert snare.main(["--port", "70000", "status"]) == 0
    assert capsys.readouterr().err.count("snare is not listening.") == 2


def test_main_in_the_console_starts_the_background_listener_and_stop_ends_it(
    lab, capsys, opened_ports, monkeypatch
):
    lab.seed_placeholder_ca()
    real_listen = snare.listen

    def watchdog_listen(settings, stop):
        # If main() wrongly runs the listener in the foreground, this ends it instead of hanging the suite.
        timer = threading.Timer(20, stop.set)
        timer.daemon = True
        timer.start()
        try:
            return real_listen(settings, stop)
        finally:
            timer.cancel()

    monkeypatch.setattr(snare, "listen", watchdog_listen)
    snare.attach_console(lambda line: None)
    assert snare.main(["--plain", "--port", "0", "--timeout", "3"]) == 0
    tag = snare.job_tag()
    assert re.fullmatch(r"snare:\d+", tag)
    opened_ports.append(int(tag.split(":")[1]))
    assert snare.main(["status"]) == 0
    assert f"listening on 127.0.0.1:{tag.split(':')[1]}" in capsys.readouterr().err
    assert snare.main(["stop"]) == 0
    assert snare.job_tag() == ""


def test_main_outside_the_console_runs_the_listener_in_the_foreground_until_interrupted(
    lab, capsys, monkeypatch
):
    seen = {}

    def fake_listen(settings, stop):
        seen["settings"], seen["stop"] = settings, stop
        raise KeyboardInterrupt

    monkeypatch.setattr(snare, "listen", fake_listen)
    assert (
        snare.main(
            [
                "--plain",
                "--port",
                "0",
                "--timeout",
                "2.5",
                "--insecure",
                "--max-body",
                "77",
            ]
        )
        == 0
    )
    settings = seen["settings"]
    assert (
        settings.port,
        settings.timeout,
        settings.insecure,
        settings.max_body,
        settings.plain,
    ) == (0, 2.5, True, 77, True)
    assert seen["stop"].is_set()
    assert capsys.readouterr().err.splitlines() == [
        "Ctrl-C stops this listener. From the Bughunt prompt, snare stays up beside the other modules."
    ]


@needs_openssl
def test_main_ca_prints_the_certificate_path_on_stdout(lab, capsys):
    assert snare.main(["--plain", "ca"]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == str(workspace_dir() / "snare" / "ca.crt")
    assert (
        captured.err.strip()
        == "Trust that certificate in the test browser. The key stays beside it."
    )
    assert (workspace_dir() / "snare" / "ca.key").is_file()


def test_main_ca_reports_a_missing_openssl(lab, capsys, monkeypatch):
    def missing(command, kwargs):
        raise FileNotFoundError(command[0])

    fake_openssl(monkeypatch, missing)
    assert snare.main(["--plain", "ca"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err.strip() == "openssl is not on PATH."


def test_snare_parser_contract():
    parser = snare.build_parser()
    assert parser.prog == "bughunt snare"
    defaults = parser.parse_args([])
    assert vars(defaults) == dict(
        plain=False,
        port=8080,
        timeout=10.0,
        insecure=False,
        max_body=1_000_000,
        command=None,
    )
    assert (
        parser.parse_args(
            [
                "--port",
                "0",
                "--timeout",
                "2",
                "--max-body",
                "9",
                "--plain",
                "--insecure",
            ]
        ).port
        == 0
    )
    assert parser.parse_args(["ca"]).command == "ca"
    assert parser.parse_args(["status"]).command == "status"
    assert parser.parse_args(["stop"]).command == "stop"
    flags = {a.option_strings[0] for a in parser._actions if a.option_strings}
    assert flags == {"-h", "--plain", "--port", "--timeout", "--insecure", "--max-body"}
    with pytest.raises(SystemExit):
        parser.parse_args(["bogus"])


# ==================================================================================================
# 3e. snare: wire behavior and capture, end to end against a loopback origin
# ==================================================================================================


def test_proxied_get_is_rebuilt_forwarded_and_captured(
    lab, make_origin, start_proxy, capsys
):
    origin = make_origin()
    proxy = start_proxy()
    raw = (
        f"GET {origin.origin}/a/b?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nProxy-Connection: keep-alive\r\n"
        f"Connection: keep-alive, X-Hop\r\nX-Hop: dropped\r\nProxy-Authorization: Basic eHl6\r\n"
        f"TE: trailers\r\nUpgrade: h2c\r\nTrailer: x\r\nAccept-Encoding: gzip, br\r\nX-Dup: 1\r\n"
        f"this line has no colon\r\nCookie: sid=browser\r\nX-Dup: 2\r\nUser-Agent: Mozilla/5.0\r\n"
        f"Keep-Alive: 5\r\n\r\n"
    ).encode()
    capsys.readouterr()
    reply = proxy.talk(raw)
    expected_reply = b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
    assert reply == expected_reply
    (seen,) = origin.requests
    expected_wire = (
        f"GET /a/b?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nAccept-Encoding: identity\r\n"
        f"X-Dup: 1\r\nCookie: sid=browser\r\nX-Dup: 2\r\nContent-Length: 0\r\nConnection: close\r\n"
        f"X-Researcher: owned-lab\r\nUser-Agent: Bughunt-owned-lab\r\n\r\n"
    ).encode()
    assert seen == expected_wire
    assert saved_pairs() == [
        ("127.0.0.1-snare-0001.http", expected_wire, expected_reply)
    ]
    assert urls_path().read_text(encoding="utf-8") == f"{origin.origin}/a/b?x=1\n"
    assert (
        capsys.readouterr().out
        == "GET\t200\t5\t127.0.0.1\t/a/b?x=1\t127.0.0.1-snare-0001.http\n"
    )
    (manifest,) = snare_manifests()
    assert manifest["target"] == f"{origin.origin}/a/b?x=1"
    assert manifest["source_files"] == {
        "request": "requests/127.0.0.1-snare-0001.http",
        "response": "responses/127.0.0.1-snare-0001.http",
    }
    assert manifest["request"]["sha256"] == sha(expected_wire) and manifest["response"][
        "sha256"
    ] == sha(expected_reply)


HOP_BY_HOP = [
    "Connection",
    "Proxy-Connection",
    "Keep-Alive",
    "TE",
    "Trailer",
    "Upgrade",
    "Transfer-Encoding",
    "Proxy-Authorization",
]


@pytest.mark.parametrize("name", HOP_BY_HOP)
def test_every_hop_by_hop_request_header_is_removed(
    lab, make_origin, start_proxy, name
):
    origin = make_origin()
    proxy = start_proxy()
    proxy.talk(request_to(origin, "GET", "/h", f"{name}: x"))
    names = [
        line.partition(b":")[0].lower() for line in header_block(origin.requests[0])[1:]
    ]
    assert names.count(name.lower().encode()) == (1 if name == "Connection" else 0)
    assert header_value(origin.requests[0], "Connection") == b"close"


@pytest.mark.parametrize("name", HOP_BY_HOP)
def test_every_hop_by_hop_response_header_is_removed(
    lab, make_origin, start_proxy, name
):
    origin = make_origin(
        lambda raw: (
            f"HTTP/1.1 200 OK\r\n{name}: x\r\nContent-Length: 5\r\n\r\nhello".encode()
        )
    )
    proxy = start_proxy()
    got = proxy.talk(request_to(origin))
    assert (
        got == b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
    )
    assert saved_pairs()[0][2] == got


def test_proxied_post_body_is_forwarded_and_saved(lab, make_origin, start_proxy):
    origin = make_origin()
    proxy = start_proxy()
    raw = request_to(
        origin,
        "POST",
        "/submit",
        "Content-Length: 11\r\nContent-Type: text/plain",
        b"hello world",
    )
    assert proxy.talk(raw).startswith(b"HTTP/1.1 200 OK")
    (seen,) = origin.requests
    assert seen.startswith(b"POST /submit HTTP/1.1\r\n") and seen.endswith(
        b"\r\n\r\nhello world"
    )
    assert [
        line
        for line in header_block(seen)
        if line.lower().startswith(b"content-length")
    ] == [b"Content-Length: 11"]
    ((name, saved_request, _),) = saved_pairs()
    assert saved_request == seen and name.endswith("-0001.http")


def test_request_without_a_host_header_gets_one_from_the_url(
    lab, make_origin, start_proxy
):
    origin = make_origin()
    proxy = start_proxy()
    proxy.talk(request_to(origin, host=False))
    assert (
        header_value(origin.requests[0], "Host") == f"127.0.0.1:{origin.port}".encode()
    )


def test_bare_lf_request_heads_are_accepted(lab, make_origin, start_proxy):
    origin = make_origin()
    proxy = start_proxy()
    reply = proxy.talk(
        f"GET {origin.origin}/lf HTTP/1.1\nHost: lf.example\n\n".encode()
    )
    assert reply.startswith(b"HTTP/1.1 200 OK")
    assert header_value(origin.requests[0], "Host") == b"lf.example"


def test_chunked_request_body_is_reassembled_with_a_content_length(
    lab, make_origin, start_proxy
):
    origin = make_origin()
    proxy = start_proxy()
    raw = request_to(
        origin,
        "POST",
        "/c",
        "Transfer-Encoding: chunked",
        b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: x\r\n\r\n",
    )
    assert proxy.talk(raw).startswith(b"HTTP/1.1 200 OK")
    (seen,) = origin.requests
    assert seen.endswith(b"\r\n\r\nWikipedia")
    assert (
        header_value(seen, "Content-Length") == b"9"
        and header_value(seen, "Transfer-Encoding") is None
    )


def test_chunked_response_is_reassembled_for_the_client_and_the_saved_copy(
    lab, make_origin, start_proxy
):
    reply = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Up: 1\r\n\r\n"
        b"4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\nTrailer: x\r\n\r\n"
    )
    origin = make_origin(lambda raw: reply)
    proxy = start_proxy()
    got = proxy.talk(request_to(origin, path="/chunked"))
    assert (
        got
        == b"HTTP/1.1 200 OK\r\nX-Up: 1\r\nContent-Length: 9\r\nConnection: close\r\n\r\nWikipedia"
    )
    ((_, _, saved_response),) = saved_pairs()
    assert saved_response == got


def test_response_without_framing_is_read_until_the_origin_closes(
    lab, make_origin, start_proxy
):
    origin = make_origin(
        lambda raw: b"HTTP/1.0 200 OK\r\nX-A: 1\r\n\r\nuntil-close-body"
    )
    proxy = start_proxy()
    got = proxy.talk(request_to(origin))
    assert (
        got
        == b"HTTP/1.0 200 OK\r\nX-A: 1\r\nContent-Length: 16\r\nConnection: close\r\n\r\nuntil-close-body"
    )


@pytest.mark.parametrize(
    "status_line",
    [
        b"HTTP/1.1 204 No Content",
        b"HTTP/1.1 304 Not Modified",
        b"HTTP/1.1 100 Continue",
        b"HTTP/1.1 101 Switching Protocols",
    ],
)
def test_bodyless_statuses_are_relayed_without_waiting_for_a_body(
    lab, make_origin, start_proxy, status_line
):
    origin = make_origin(
        lambda raw: status_line + b"\r\nContent-Length: 7\r\nConnection: close\r\n\r\n"
    )
    proxy = start_proxy()
    got = proxy.talk(request_to(origin))
    assert got == status_line + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    assert saved_pairs()[0][2] == got
    assert snare_manifests()[0]["response"]["size"] == len(got)


def test_truncation_applies_to_the_saved_copy_only(
    lab, make_origin, start_proxy, capsys
):
    body = b"B" * 300
    reply = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 300\r\nConnection: close\r\n\r\n" + body
    )
    origin = make_origin(lambda raw: reply)
    proxy = start_proxy(max_body=100)
    capsys.readouterr()
    got = proxy.talk(
        request_to(origin, "POST", "/t", "Content-Length: 250", b"Q" * 250)
    )
    assert (
        got.endswith(b"B" * 300) and b"Content-Length: 300" in got
    )  # the client gets everything
    ((name, saved_request, saved_response),) = saved_pairs()
    assert saved_request.endswith(b"\r\n\r\n" + b"Q" * 100)
    assert (
        saved_response
        == b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n"
        + b"B" * 100
    )
    assert (
        len(origin.requests[0].partition(b"\r\n\r\n")[2]) == 250
    )  # the origin received the whole body
    assert (
        capsys.readouterr().out == f"POST\t200\t300\t127.0.0.1\t/t\t{name}\ttruncated\n"
    )
    (manifest,) = snare_manifests()
    assert (
        manifest["request"]["truncated"] is True
        and manifest["response"]["truncated"] is True
    )


def test_small_exchanges_are_not_flagged_truncated(lab, make_origin, start_proxy):
    origin = make_origin()
    proxy = start_proxy(max_body=5)  # the 5-byte body is exactly at the cap
    proxy.talk(request_to(origin))
    (manifest,) = snare_manifests()
    assert (
        manifest["request"]["truncated"] is False
        and manifest["response"]["truncated"] is False
    )


@pytest.mark.parametrize(
    "raw, reason",
    [
        (b"\r\n\r\n", b"400 Bad request"),
        (b"garbage\r\n\r\n", b"400 Bad request"),
        (b"HTTP/1.1 200 OK\r\n\r\n", b"400 Bad request"),
        (b"GET /abc HTTP/1.1\r\n\r\n", b"400 Bad request"),
        (b"GET ftp://127.0.0.1/ HTTP/1.1\r\n\r\n", b"400 Bad request"),
        (b"CONNECT :443 HTTP/1.1\r\n\r\n", b"400 Bad request"),
        (
            b"GET http://outside.example/ HTTP/1.1\r\nHost: outside.example\r\n\r\n",
            b"403 Outside scope",
        ),
        (b"CONNECT outside.example:443 HTTP/1.1\r\n\r\n", b"403 Outside scope"),
        (
            b"POST http://127.0.0.1:1/x HTTP/1.1\r\nContent-Length: 9000000\r\n\r\n",
            b"413 Body is too large",
        ),
    ],
)
def test_error_replies_use_a_fixed_shape_and_save_nothing(
    lab, make_origin, start_proxy, raw, reason
):
    origin = make_origin()
    lab.grant(origin.origin, "http://127.0.0.1:1")
    proxy = start_proxy()
    expected_body = reason.split(b" ", 1)[1]
    assert proxy.talk(raw) == (
        b"HTTP/1.1 "
        + reason
        + b"\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(expected_body)
        + expected_body
    )
    assert origin.requests == [] and saved_pairs() == [] and snare_manifests() == []


def test_a_head_larger_than_64k_is_rejected_with_413(lab, start_proxy):
    proxy = start_proxy()
    got = proxy.talk(b"GET /" + b"a" * 70000)
    assert (
        got
        == b"HTTP/1.1 413 Body is too large\r\nContent-Length: 17\r\nConnection: close\r\n\r\nBody is too large"
    )


def test_connections_that_cannot_be_parsed_are_dropped_without_a_reply(
    lab, make_origin, start_proxy, capsys
):
    origin = make_origin()
    proxy = start_proxy()
    capsys.readouterr()
    assert proxy.talk(request_to(origin, "POST", "/x", "Content-Length: abc")) == b""
    assert (
        proxy.talk(f"GET {origin.origin}/t HTTP/1.1\r\nX: y".encode(), half_close=True)
        == b""
    )
    assert origin.requests == [] and saved_pairs() == []
    assert (
        "snare dropped one connection." not in capsys.readouterr().err
    )  # parse failures are silent drops


def test_a_stalled_client_does_not_block_other_clients(lab, make_origin, start_proxy):
    origin = make_origin()
    proxy = start_proxy(timeout=4.0)
    staller = socket.create_connection(("127.0.0.1", proxy.port), timeout=10)
    try:
        staller.sendall(
            b"GET http://127.0.0.1:1/"
        )  # an unfinished request line holds its handler open
        started = time.monotonic()
        assert proxy.talk(request_to(origin, path="/fast")).startswith(
            b"HTTP/1.1 200 OK"
        )
        assert time.monotonic() - started < 2.5
    finally:
        staller.close()


def test_a_silent_client_is_closed_after_the_timeout(lab, start_proxy):
    proxy = start_proxy(timeout=0.3)
    started = time.monotonic()
    assert proxy.talk(b"", timeout=10) == b""
    assert time.monotonic() - started < 5


def test_unreachable_upstream_gives_502_and_saves_nothing(lab, start_proxy):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
    lab.grant(f"http://127.0.0.1:{dead}")
    proxy = start_proxy()
    got = proxy.talk(f"GET http://127.0.0.1:{dead}/ HTTP/1.1\r\n\r\n".encode())
    assert (
        got
        == b"HTTP/1.1 502 Upstream failed\r\nContent-Length: 15\r\nConnection: close\r\n\r\nUpstream failed"
    )
    assert saved_pairs() == [] and snare_manifests() == []


def test_a_malformed_upstream_reply_gives_502(lab, make_origin, start_proxy):
    origin = make_origin(lambda raw: b"not http at all")
    proxy = start_proxy()
    assert proxy.talk(request_to(origin)).startswith(b"HTTP/1.1 502 Upstream failed")
    assert saved_pairs() == []


def test_upstream_response_over_the_forward_limit_gives_502(
    lab, make_origin, start_proxy
):
    origin = make_origin(
        lambda raw: (
            b"HTTP/1.1 200 OK\r\nContent-Length: 9000000\r\nConnection: close\r\n\r\nx"
        )
    )
    proxy = start_proxy()
    assert proxy.talk(request_to(origin)).startswith(b"HTTP/1.1 502 Upstream failed")


def test_policy_denial_for_an_in_scope_host_gives_403_before_contacting_it(
    lab, make_origin, start_proxy
):
    origin = make_origin()
    proxy = start_proxy()
    lab.grant()  # revoke the origin's asset row; loopback stays "in scope" but is no longer permitted
    got = proxy.talk(request_to(origin))
    assert got == error_reply(403, "Mission policy blocked")
    assert origin.requests == [] and saved_pairs() == []


def test_a_denied_method_is_blocked_per_request(lab, make_origin, start_proxy):
    origin = make_origin()
    lab.grant(origin.origin, methods=["GET"])
    proxy = start_proxy()
    assert proxy.talk(
        request_to(origin, "POST", "/x", "Content-Length: 1", b"z")
    ).startswith(b"HTTP/1.1 403 Mission policy blocked")
    assert proxy.talk(request_to(origin)).startswith(b"HTTP/1.1 200 OK")


def test_out_of_scope_https_connect_is_refused_before_any_certificate_work(
    lab, start_proxy, monkeypatch
):
    calls = fake_openssl(
        monkeypatch, lambda command, kwargs: pytest.fail("openssl must not run")
    )
    proxy = start_proxy()
    assert proxy.talk(b"CONNECT outside.example:443 HTTP/1.1\r\n\r\n").startswith(
        b"HTTP/1.1 403 Outside scope"
    )
    assert calls == []


def test_connect_to_a_granted_host_without_openssl_gives_502(
    lab, start_proxy, monkeypatch
):
    lab.grant("https://127.0.0.1:4443")
    proxy = start_proxy()

    def missing(command, kwargs):
        raise FileNotFoundError(command[0])

    fake_openssl(monkeypatch, missing)
    got = proxy.talk(b"CONNECT 127.0.0.1:4443 HTTP/1.1\r\n\r\n")
    assert got == (
        b"HTTP/1.1 502 HTTPS is unavailable\r\nContent-Length: 20\r\nConnection: close\r\n\r\n"
        b"HTTPS is unavailable"
    )


def test_connect_without_a_port_defaults_to_443(lab, start_proxy, monkeypatch):
    proxy = (
        start_proxy()
    )  # lab grants https://allowed.example (port 443) and the scope file lists the host

    def missing(command, kwargs):
        raise FileNotFoundError(command[0])

    fake_openssl(monkeypatch, missing)
    assert proxy.talk(b"CONNECT allowed.example HTTP/1.1\r\n\r\n") == error_reply(
        502, "HTTPS is unavailable"
    )


def test_connect_without_a_policy_grant_gives_403(lab, start_proxy):
    proxy = start_proxy()
    got = proxy.talk(b"CONNECT 127.0.0.1:4443 HTTP/1.1\r\n\r\n")
    assert got.startswith(b"HTTP/1.1 403 Mission policy blocked")


def test_concurrent_clients_get_unique_names_and_complete_files(
    lab, make_origin, start_proxy
):
    origin = make_origin()
    proxy = start_proxy()
    replies: list[bytes] = []
    errors: list[BaseException] = []

    def one(index: int):
        try:
            replies.append(proxy.talk(request_to(origin, path=f"/p{index}")))
        except BaseException as exc:  # noqa: BLE001 - collected for the assertion below
            errors.append(exc)

    threads = [threading.Thread(target=one, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert errors == [] and len(replies) == 8
    assert all(reply.startswith(b"HTTP/1.1 200 OK") for reply in replies)
    names = sorted(name for name, _, _ in saved_pairs())
    assert names == [f"127.0.0.1-snare-{number:04d}.http" for number in range(1, 9)]
    assert sorted(urls_path().read_text(encoding="utf-8").splitlines()) == sorted(
        f"{origin.origin}/p{index}" for index in range(8)
    )
    assert len(snare_manifests()) == 8


def test_each_proxied_exchange_adds_exactly_one_snare_manifest(
    lab, make_origin, start_proxy
):
    origin = make_origin()
    proxy = start_proxy()
    proxy.talk(request_to(origin, path="/one"))
    proxy.talk(request_to(origin, path="/two"))
    assert sorted(m["target"] for m in snare_manifests()) == [
        f"{origin.origin}/one",
        f"{origin.origin}/two",
    ]


def test_the_named_actor_credentials_replace_the_browsers_in_the_forwarded_request(
    lab, make_origin, start_proxy
):
    origin = make_origin()
    identity.create_profile("owner", "owner", [origin.origin], owned=True)
    identity.set_credential("owner", "cookie", "sid=owner-secret")
    identity.use_profile("owner")
    proxy = start_proxy()
    proxy.talk(request_to(origin, extra="Cookie: sid=browser-secret"))
    assert header_value(origin.requests[0], "Cookie") == b"sid=owner-secret"
    (manifest,) = snare_manifests()
    assert manifest["actor"] == "owner"


@needs_openssl
@pytest.mark.parametrize(
    "target, public_path", [("/secure?x=1", "/secure?x=1"), ("noslash", "/noslash")]
)
def test_https_connect_is_intercepted_and_captured(
    lab, start_proxy, opened_ports, target, public_path
):
    import ssl

    cert, key = snare.issue_leaf("127.0.0.1")
    reply = b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\nsecure hello"
    origin = RawOrigin(lambda raw: reply, tls_files=(cert, key))
    opened_ports.append(origin.port)
    try:
        lab.grant(origin.origin)
        proxy = start_proxy(insecure=True)
        client = socket.create_connection(("127.0.0.1", proxy.port), timeout=20)
        client.sendall(
            f"CONNECT 127.0.0.1:{origin.port} HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
        )
        assert client.recv(4096) == b"HTTP/1.1 200 Connection Established\r\n\r\n"
        trust = ssl.create_default_context(
            cafile=str(workspace_dir() / "snare" / "ca.crt")
        )
        tls = trust.wrap_socket(client, server_hostname="127.0.0.1")
        tls.sendall(
            f"GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nCookie: k=v\r\n\r\n".encode()
        )
        got = b""
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            got += chunk
        tls.close()
        assert got == reply
        ((name, saved_request, saved_response),) = saved_pairs()
        assert name == "127.0.0.1-snare-0001.http" and saved_response == got
        assert (
            saved_request.startswith(f"GET {target} HTTP/1.1\r\n".encode())
            and saved_request == origin.requests[0]
        )
        assert (
            urls_path().read_text(encoding="utf-8")
            == f"https://127.0.0.1:{origin.port}{public_path}\n"
        )
        (manifest,) = snare_manifests()
        assert manifest["target"] == f"https://127.0.0.1:{origin.port}{public_path}"
        assert (workspace_dir() / "snare" / "leafs" / "127.0.0.1.crt").is_file()
    finally:
        origin.close()


@needs_openssl
def test_insecure_flag_controls_tls_verification(
    repeater_io, tmp_path, lab, opened_ports
):
    cert, key = snare.issue_leaf(
        "127.0.0.1"
    )  # signed by a CA that no trust store knows
    origin = RawOrigin(
        lambda raw: CANNED.replace(
            b"Connection: keep-alive, X-Backend", b"Connection: close"
        ),
        tls_files=(cert, key),
    )
    opened_ports.append(origin.port)
    try:
        lab.grant(origin.origin)
        path = write_request(
            tmp_path,
            f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode(),
        )
        assert repeater.main([path, "--scheme", "https"]) == 1
        assert repeater_io.console.startswith("Request failed:")
        assert origin.requests == []
        assert repeater.main([path, "--scheme", "https", "--insecure"]) == 0
        assert b"hello" in repeater_io.out and len(origin.requests) == 1
    finally:
        origin.close()


def test_a_request_with_no_headers_gets_exactly_the_minimum_rebuilt_head(
    lab, make_origin, start_proxy
):
    origin = make_origin()
    proxy = start_proxy()
    proxy.talk(request_to(origin, path="/min", host=False))
    assert (
        origin.requests[0]
        == (
            f"GET /min HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nAccept-Encoding: identity\r\nContent-Length: 0\r\n"
            f"Connection: close\r\nX-Researcher: owned-lab\r\nUser-Agent: Bughunt-owned-lab\r\n\r\n"
        ).encode()
    )


def test_host_names_in_absolute_urls_are_folded_to_canonical_form(
    lab, make_origin, start_proxy
):
    origin = make_origin()
    proxy = start_proxy()
    got = proxy.talk(
        f"GET http://127.0.0.1.:{origin.port}/dot HTTP/1.1\r\nHost: x\r\n\r\n".encode()
    )
    assert got.startswith(b"HTTP/1.1 200 OK")
    assert urls_path().read_text(encoding="utf-8") == f"{origin.origin}/dot\n"
    assert saved_pairs()[0][0] == "127.0.0.1-snare-0001.http"


class _FakeClient:
    def __init__(self):
        self.sent = []

    def sendall(self, payload):
        self.sent.append(payload)


@pytest.mark.parametrize(
    "target, url, host_header",
    [
        (
            "http://allowed.example/a",
            "http://allowed.example/a",
            b"Host: allowed.example\r\n",
        ),
        (
            "https://allowed.example/b",
            "https://allowed.example/b",
            b"Host: allowed.example\r\n",
        ),
        (
            "http://allowed.example:8080/c?q=1",
            "http://allowed.example:8080/c?q=1",
            b"Host: allowed.example:8080\r\n",
        ),
        (
            "http://allowed.example:443/d",
            "http://allowed.example:443/d",
            b"Host: allowed.example\r\n",
        ),
        (
            "https://allowed.example:80/e",
            "https://allowed.example:80/e",
            b"Host: allowed.example\r\n",
        ),
        ("http://[::1]:8081/f", "http://[::1]:8081/f", b"Host: [::1]:8081\r\n"),
        (
            "http://ALLOWED.example./g",
            "http://allowed.example/g",
            b"Host: allowed.example\r\n",
        ),
    ],
)
def test_public_urls_and_host_headers_omit_only_the_default_ports(
    lab, monkeypatch, target, url, host_header
):
    lab.grant(
        "http://allowed.example:8080",
        "http://allowed.example:443",
        "https://allowed.example:80",
        "http://[::1]:8081",
    )
    canned = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
    wires: list[bytes] = []
    monkeypatch.setattr(
        snare, "_fetch_wire", lambda *args: wires.append(args[3]) or canned
    )
    client = _FakeClient()
    snare._handle_exchange(
        client,
        None,
        snare._Message(f"GET {target} HTTP/1.1", []),
        "GET",
        target,
        "HTTP/1.1",
        snare.Settings(plain=True),
        scheme=None,
        default_port=None,
    )
    assert client.sent == [canned]
    assert host_header in wires[0]
    assert urls_path().read_text(encoding="utf-8") == url + "\n"
    (manifest,) = snare_manifests()
    assert manifest["target"] == url


def test_the_request_line_version_is_preserved(lab, make_origin, start_proxy):
    origin = make_origin()
    proxy = start_proxy()
    proxy.talk(f"GET {origin.origin}/old HTTP/1.0\r\n\r\n".encode())
    assert origin.requests[0].startswith(b"GET /old HTTP/1.0\r\n")


def test_oversized_chunk_sizes_are_413_and_garbled_ones_are_dropped(
    lab, make_origin, start_proxy
):
    origin = make_origin()
    proxy = start_proxy()
    too_big = request_to(
        origin, "POST", "/c", "Transfer-Encoding: chunked", b"7A1201\r\nxx"
    )  # 8,000,001 bytes
    assert proxy.talk(too_big) == error_reply(413, "Body is too large")
    garbled = request_to(
        origin, "POST", "/c", "Transfer-Encoding: chunked", b"zz\r\nxx\r\n0\r\n\r\n"
    )
    assert proxy.talk(garbled) == b""
    assert origin.requests == [] and saved_pairs() == []


@pytest.mark.parametrize(
    "tty, term, no_color, plain, colored",
    [
        (True, "xterm", None, False, True),
        (True, "xterm", None, True, False),
        (True, "xterm", "1", False, False),
        (True, "dumb", None, False, False),
        (True, "", None, False, False),
        (False, "xterm", None, False, False),
    ],
)
def test_live_rows_are_colored_only_on_a_color_terminal(
    lab,
    make_origin,
    start_proxy,
    capsys,
    monkeypatch,
    tty,
    term,
    no_color,
    plain,
    colored,
):
    origin = make_origin()
    monkeypatch.setattr(sys.stdout, "isatty", lambda: tty, raising=False)
    monkeypatch.setenv("TERM", term)
    if no_color is None:
        monkeypatch.delenv("NO_COLOR", raising=False)
    else:
        monkeypatch.setenv("NO_COLOR", no_color)
    proxy = start_proxy(plain=plain)
    capsys.readouterr()
    proxy.talk(request_to(origin, path="/c"))
    row = capsys.readouterr().out.strip()
    if colored:
        assert row == snare.format_row(
            "GET", "200", 5, "127.0.0.1", "/c", True, name="127.0.0.1-snare-0001.http"
        )
        assert row.startswith(CYAN)
    else:
        assert row == "GET\t200\t5\t127.0.0.1\t/c\t127.0.0.1-snare-0001.http"


def test_main_prints_the_banner_on_a_terminal_unless_plain(lab, capsys, monkeypatch):
    lab.seed_placeholder_ca()
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True, raising=False)
    monkeypatch.setenv("TERM", "xterm")
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert snare.main(["ca"]) == 0
    captured = capsys.readouterr()
    assert captured.err == (
        snare.format_banner(True) + "\n\n"
        "Trust that certificate in the test browser. The key stays beside it.\n"
    )
    assert captured.out.strip() == str(workspace_dir() / "snare" / "ca.crt")
    assert snare.main(["--plain", "ca"]) == 0
    assert (
        capsys.readouterr().err
        == "Trust that certificate in the test browser. The key stays beside it.\n"
    )
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False, raising=False)
    assert snare.main(["ca"]) == 0
    assert (
        capsys.readouterr().err
        == "Trust that certificate in the test browser. The key stays beside it.\n"
    )


def test_the_listener_is_not_reachable_on_a_non_loopback_address(lab, start_proxy):
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(
            ("192.0.2.1", 9)
        )  # no packet is sent; this only asks the OS which interface it would use
        local_address = probe.getsockname()[0]
    except OSError:
        pytest.skip("no routable local address to probe")
    finally:
        probe.close()
    if local_address.startswith("127.") or local_address == "0.0.0.0":
        pytest.skip("no non-loopback local address to probe")
    proxy = start_proxy()
    with pytest.raises(OSError):
        socket.create_connection((local_address, proxy.port), timeout=3)


def test_peers_that_are_not_loopback_are_dropped_without_a_reply(
    lab, make_origin, start_proxy, monkeypatch
):
    origin = make_origin()
    proxy = start_proxy()
    real_accept = socket.socket.accept
    entered = threading.Event()

    def spoofed_accept(self):
        listening_here = self.getsockname()[1] == proxy.port
        if listening_here:
            entered.set()
        connection, address = real_accept(self)
        if listening_here:
            return connection, ("203.0.113.9", address[1])
        return connection, address

    monkeypatch.setattr(socket.socket, "accept", spoofed_accept)
    assert entered.wait(5), "the accept loop never called the patched accept"
    assert proxy.talk(request_to(origin)) == b""
    assert origin.requests == [] and saved_pairs() == []


def test_tunnel_helper_splices_bytes_both_ways_after_announcing_the_connection(
    lab, opened_ports, capsys
):
    # snare._tunnel is not reached by the current listener (CONNECT is always intercepted) but is kept and
    # monkeypatched by tests/test_safety.py, so it stays part of the contract.
    echo = RawOrigin(lambda raw: raw)
    opened_ports.append(echo.port)
    lab.grant(f"https://127.0.0.1:{echo.port}")
    near, far = socket.socketpair()
    settings = snare.Settings(timeout=3, plain=True)
    worker = threading.Thread(
        target=snare._tunnel, args=(far, "127.0.0.1", echo.port, settings), daemon=True
    )
    try:
        worker.start()
        near.settimeout(5)
        assert near.recv(4096) == b"HTTP/1.1 200 Connection Established\r\n\r\n"
        near.sendall(b"GET /echo HTTP/1.1\r\nHost: x\r\n\r\n")
        got = b""
        while b"\r\n\r\n" not in got:
            got += near.recv(4096)
        assert got == b"GET /echo HTTP/1.1\r\nHost: x\r\n\r\n"
        near.shutdown(socket.SHUT_WR)
        worker.join(10)
        assert not worker.is_alive()
    finally:
        near.close()
        far.close()
        echo.close()
    assert capsys.readouterr().out == f"tunnel\t127.0.0.1:{echo.port}\n"


def test_tunnel_helper_reports_an_unreachable_target(lab):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
    lab.grant(f"https://127.0.0.1:{dead}")
    near, far = socket.socketpair()
    try:
        snare._tunnel(far, "127.0.0.1", dead, snare.Settings(timeout=2))
        near.settimeout(5)
        assert near.recv(4096) == error_reply(502, "Upstream failed")
    finally:
        near.close()
        far.close()


# ==================================================================================================
# 4. KNOWN DEFECTS (xfail strict): the assertions state the CORRECT behavior; the current code fails them.
# ==================================================================================================


def test_defect_49122e63_named_actor_forwards_the_csrf_companion_header(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin()
    identity.create_profile("owner", "owner", [origin.origin], owned=True)
    identity.set_credential("owner", "cookie", "sid=owner-secret")
    identity.set_companion_headers("owner", ["X-CSRF-Token"])
    identity.use_profile("owner")
    raw = (
        f"GET /a HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nX-CSRF-Token: tok\r\n\r\n"
    ).encode()
    assert repeater.main([write_request(tmp_path, raw)]) == 0
    assert header_value(origin.requests[0], "X-CSRF-Token") == b"tok"


def test_repeater_follow_strips_credentials_across_origins(
    repeater_io, tmp_path, make_origin
):
    target = make_origin()
    hop = make_origin(redirecting(lambda path: (302, f"{target.origin}/landing")))
    raw = (
        f"GET /r HTTP/1.1\r\nHost: 127.0.0.1:{hop.port}\r\nAuthorization: Bearer secrettok\r\n\r\n"
    ).encode()
    assert repeater.main([write_request(tmp_path, raw), "--follow"]) == 0
    assert header_value(target.requests[0], "Authorization") is None


def test_repeater_follow_keeps_credentials_on_a_same_origin_redirect(
    repeater_io, tmp_path, make_origin
):
    origin = make_origin(redirecting(lambda path: (302, "/landing")))
    raw = (
        f"GET /r HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\nAuthorization: Bearer secrettok\r\n"
        "Cookie: s=1\r\n\r\n"
    ).encode()
    assert repeater.main([write_request(tmp_path, raw), "--follow"]) == 0
    assert header_value(origin.requests[-1], "Authorization") == b"Bearer secrettok"
    assert header_value(origin.requests[-1], "Cookie") == b"s=1"


def test_defect_repeater_save_request_prints_literal_markup(repeater_io, tmp_path, lab):
    path = write_request(tmp_path, b"GET / HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
    assert repeater.main([path, "--save-request", "kept.http", "--print"]) == 0
    assert "[ok]" not in repeater_io.console and "[/ok]" not in repeater_io.console


@pytest.mark.parametrize(
    "separator", [b"\r", b"\x0b", b"\x0c", b"\x1c", b"\x1d", b"\x1e", b"\x85"]
)
def test_repeater_parse_raw_splits_only_on_crlf_or_lf(separator):
    req = repeater.parse_raw(
        b"GET / HTTP/1.1\r\nX-A: a" + separator + b"X-Injected: b\r\n\r\n"
    )
    assert [name for name, _ in req.headers] == ["X-A"]


def test_snare_lone_cr_in_a_header_value_does_not_inject_a_header(
    lab, make_origin, start_proxy
):
    origin = make_origin()
    proxy = start_proxy()
    proxy.talk(
        f"GET {origin.origin}/cr HTTP/1.1\r\nX-A: a\rX-Injected: b\r\n\r\n".encode()
    )
    assert header_value(origin.requests[0], "X-Injected") is None


def test_defect_snare_head_requests_fail_with_502(lab, make_origin, start_proxy):
    origin = make_origin(
        lambda raw: (
            b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\n"
        )
    )
    proxy = start_proxy()
    reply = proxy.talk(request_to(origin, "HEAD", "/h"))
    assert reply.startswith(b"HTTP/1.1 200 OK")
    assert b"Content-Length: 17\r\n" in reply
    assert reply.partition(b"\r\n\r\n")[2] == b""
    captures = saved_pairs()
    assert len(captures) == 1
    assert captures[0][2] == reply


def test_defect_snare_begin_hangs_when_the_policy_denies_the_listener(lab, capsys):
    lab.seed_placeholder_ca()
    document = lab.grant()
    document["permissions"]["manual"] = False
    (lab.root / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    settings = snare.Settings(port=0, plain=True)
    outcome = []
    starter = threading.Thread(
        target=lambda: outcome.append(snare.begin(settings)), daemon=True
    )
    starter.start()
    starter.join(3)
    released = not starter.is_alive()
    if settings.ready is not None:
        settings.ready.set()  # unblock begin() so the test leaves no thread behind
    starter.join(10)
    snare.stop_listener(quiet=True)
    assert released, "begin() was still blocked after 3 s"
    assert outcome == [1]
    assert settings.bound_port == 0
    assert snare.job_tag() == ""
    assert "listening on" not in capsys.readouterr().err.lower()
