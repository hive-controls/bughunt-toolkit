"""Shared fixtures for the scanner characterization oracle (milestone M2).

Not a test module (no ``test_`` prefix). The scanner oracle files import the fixtures and helpers
below so every test drives the real scan pipeline against loopback services.

* ``LabServer``  : a scripted HTTP(S) server on 127.0.0.1 that records every request it receives.
* ``RawServer``  : a plain TCP server (banners, silence) for the non-HTTP paths.
* ``grant``      : writes a verified policy that permits scanning the loopback ports under test.
* ``lab``        : pytest fixture = a LabServer + a closed port + a granted policy + a scratch dir.

Only the sockets and the HTTP library are real; nothing is mocked in these helpers.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from bughunt.core import scanner
from bughunt.modules.policy import example_document

# --------------------------------------------------------------------------------------
# Scripted responses
# --------------------------------------------------------------------------------------

HOME_BODY = (
    b"<html><head><title>Lab  Home | Page</title></head>"
    b"<body><script src='/app.js'></script>nginx demo</body></html>"
)
APP_JS_BODY = b"fetch('/api/items'); var api_key='ABCDEFGH12345';"
SECURITY_TXT_BODY = b"Contact: mailto:sec@x.example\nExpires: 2999-01-01T00:00:00Z\nPolicy: https://x.example/policy\n"
FAVICON_BODY = bytes(range(200))
FAVICON_HASH = "-1874651529"  # Spec 11.7: the 200 bytes 0x00..0xC7
BIG_BODY = b"x" * 5000
SLOW_SECONDS = 1.5

# path -> (status, [(header, value), ...], body). Server and Date are set explicitly so the
# output does not depend on the Python version string.
ROUTES: dict[str, tuple[int, list[tuple[str, str]], bytes]] = {
    "/": (200, [
        ("Content-Type", "text/html; charset=utf-8"), ("Server", "nginx/1.25"), ("X-Custom", "yes"),
        ("Set-Cookie", "sid=abc123; Path=/"),
        ("Set-Cookie", "prefs=1; Secure; HttpOnly; SameSite=Lax"),
    ], HOME_BODY),
    "/app.js": (200, [("Content-Type", "application/javascript"), ("Server", "nginx/1.25")], APP_JS_BODY),
    "/.env": (200, [("Content-Type", "text/plain"), ("Server", "nginx/1.25")], b"SECRET=1\n"),
    "/.well-known/security.txt": (200, [("Content-Type", "text/plain")], SECURITY_TXT_BODY),
    "/admin": (403, [("Content-Type", "text/html")], b"<html><head><title>Forbidden</title></head></html>"),
    "/login": (401, [("Content-Type", "text/plain"), ("Server", "nginx/1.25"),
                     ("WWW-Authenticate", 'Basic realm="lab"')], b"auth needed"),
    "/old": (302, [("Location", "/new"), ("Server", "Apache"), ("Content-Type", "text/plain")], b""),
    "/boom": (500, [("Content-Type", "text/html")], b"<h1>Jenkins</h1>"),
    "/listing": (200, [("Content-Type", "text/html")], b"<html><head><title>Index of /</title></head></html>"),
    "/welcome": (200, [("Content-Type", "text/html")], b"<html><head><title>Welcome to nginx!</title></head></html>"),
    "/info.php": (200, [("Content-Type", "text/html"), ("X-Powered-By", "PHP/8.2.1")], b"<html>phpinfo()</html>"),
    "/favicon.ico": (200, [("Content-Type", "image/x-icon")], FAVICON_BODY),
    "/data.json": (200, [("Content-Type", "application/json")], b'{"a": 1}'),
    "/reflect": (200, [("Content-Type", "text/html"), ("Access-Control-Allow-Origin", "https://evil.bughunt.example")],
                 b"<html>reflect</html>"),
    "/star": (200, [("Content-Type", "text/html"), ("Access-Control-Allow-Origin", "*")], b"<html>star</html>"),
    "/unicode": (200, [("Content-Type", "text/html; charset=utf-8")],
                 "<html><head><title>Café — menu</title></head></html>".encode("utf-8")),
    "/cookies": (200, [("Content-Type", "text/html"), ("Set-Cookie", "secure_httponly_samesite=1; Path=/")],
                 b"<html>cookies</html>"),
    "/big": (200, [("Content-Type", "text/plain")], BIG_BODY),
    "/empty": (204, [], b""),
    "/slow": (200, [("Content-Type", "text/plain")], b"slow"),
}
NOT_FOUND = (404, [("Content-Type", "text/plain"), ("Server", "nginx/1.25")], b"nope")


@dataclass
class Recorded:
    method: str
    path: str
    headers: dict[str, str]


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:  # silence
        pass

    def _serve(self, send_body: bool) -> None:
        lab: LabServer = self.server.lab  # type: ignore[attr-defined]
        lab.requests.append(Recorded(self.command, self.path,
                                     {name.lower(): value for name, value in self.headers.items()}))
        with lab.lock:
            lab.inflight += 1
            lab.max_inflight = max(lab.max_inflight, lab.inflight)
        try:
            self._respond(lab, send_body)
        finally:
            with lab.lock:
                lab.inflight -= 1

    def _respond(self, lab: "LabServer", send_body: bool) -> None:
        route = self.path.split("?")[0]
        if route == "/slow":
            time.sleep(lab.slow_seconds)
        status, headers, body = ROUTES.get(route, NOT_FOUND)
        extra: list[tuple[str, str]] = []
        if self.command == "OPTIONS":
            status, headers, body = 200, [("Allow", "GET, HEAD, OPTIONS")], b""
            origin = self.headers.get("Origin")
            if origin and lab.cors == "echo":
                extra.append(("Access-Control-Allow-Origin", origin))
            elif origin and lab.cors == "star":
                extra.append(("Access-Control-Allow-Origin", "*"))
        self.send_response_only(status)
        for name, value in headers + extra:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if send_body and body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        self._serve(True)

    def do_HEAD(self) -> None:
        self._serve(False)

    def do_OPTIONS(self) -> None:
        self._serve(False)

    def do_POST(self) -> None:
        self._serve(True)


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address) -> None:  # TLS probes reset connections by design
        pass


class LabServer:
    """Scripted loopback HTTP (or HTTPS) server. ``cors`` is none | echo | star for OPTIONS requests."""

    def __init__(self, cors: str = "none", tls: tuple[Path, Path] | None = None,
                 extra_routes: dict | None = None) -> None:
        self.cors = cors
        self.requests: list[Recorded] = []
        self.tls = bool(tls)
        self.slow_seconds = SLOW_SECONDS
        self.lock = threading.Lock()
        self.inflight = 0
        self.max_inflight = 0
        self._server = _QuietServer(("127.0.0.1", 0), _Handler)
        self._server.lab = self  # type: ignore[attr-defined]
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(tls[0]), str(tls[1]))
            self._server.socket = context.wrap_socket(self._server.socket, server_side=True)
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def paths(self, method: str | None = None) -> list[str]:
        return [item.path for item in self.requests if method is None or item.method == method]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


class RawServer:
    """Plain TCP server. Sends ``banner`` on accept, records what the client sends, then closes."""

    def __init__(self, banner: bytes = b"", port: int = 0, read_wait: float = 0.4,
                 hold: float = 0.0) -> None:
        self.banner = banner
        self.received: list[bytes] = []
        self.accepted = 0
        self.eof_seen = threading.Event()
        self._read_wait = read_wait
        self._hold = hold
        self._sock = socket.socket()
        if os.name != "nt":  # on Windows SO_REUSEADDR would let a second listener share a busy port
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(16)
        self.port: int = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop:
            try:
                connection, _ = self._sock.accept()
            except OSError:
                return
            self.accepted += 1
            threading.Thread(target=self._one, args=(connection,), daemon=True).start()

    def _one(self, connection: socket.socket) -> None:
        with connection:
            try:
                if self.banner:
                    connection.sendall(self.banner)
                connection.settimeout(self._read_wait)
                try:
                    data = connection.recv(256)
                except (socket.timeout, TimeoutError):
                    data = None
                if data == b"":
                    self.eof_seen.set()
                elif data:
                    self.received.append(data)
                if self._hold:
                    time.sleep(self._hold)
            except OSError:
                pass

    def close(self) -> None:
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


def closed_port() -> int:
    """A loopback port that nothing is listening on (bound then released)."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# --------------------------------------------------------------------------------------
# Policy + workspace
# --------------------------------------------------------------------------------------

def grant(workspace: Path, *, http=(), https=(), hosts=("127.0.0.1",), exclusions=(), extra_origins=()) -> dict:
    """Write a verified policy that lets every operation run against the given loopback ports."""
    document = example_document()
    document.update(state="verified", verified_at=datetime.now(timezone.utc).isoformat())
    document["permissions"] = {operation: True for operation in document["permissions"]}
    document["limits"] = {"requests_per_second": 1000000, "concurrency": 100}
    assets = []
    for host in hosts:
        for scheme, ports in (("http", http), ("https", https)):
            for port in ports:
                assets.append({"id": f"{scheme}-{host}-{port}", "origin": f"{scheme}://{host}:{port}",
                               "paths": ["/"], "operations": list(document["permissions"]),
                               "methods": ["GET", "HEAD", "POST", "OPTIONS", "CONNECT"]})
    for origin in extra_origins:  # any other origin the scenario needs (a DoH resolver, a CT log, ...)
        assets.append({"id": f"extra-{origin}", "origin": origin, "paths": ["/"],
                       "operations": list(document["permissions"]),
                       "methods": ["GET", "HEAD", "POST", "OPTIONS", "CONNECT"]})
    document["assets"] = assets
    document["exclusions"] = [{"id": f"exclude-{index}", "origin": origin, "paths": paths}
                              for index, (origin, paths) in enumerate(exclusions)]
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    return document


@dataclass
class Lab:
    server: LabServer
    closed: int
    workspace: Path
    out: Path
    extra: list = field(default_factory=list)

    @property
    def port(self) -> int:
        return self.server.port

    @property
    def requests(self) -> list[Recorded]:
        return self.server.requests

    def base(self, path: str = "/") -> str:
        return f"http://127.0.0.1:{self.port}{path}"


@pytest.fixture
def workspace(monkeypatch, tmp_path):
    """An empty engagement workspace (no policy, no scope file); loopback is always in scope."""
    directory = tmp_path / "workspace"
    directory.mkdir()
    monkeypatch.setenv("BUGHUNT_SCOPE", str(directory))
    monkeypatch.delenv("BUGHUNT_ROUTE_CONFIG", raising=False)
    return directory


@pytest.fixture
def lab(workspace, tmp_path):
    """Scripted loopback server + a closed port, both granted by a verified policy."""
    server = LabServer()
    closed = closed_port()
    grant(workspace, http=[server.port, closed], hosts=("127.0.0.1", "localhost"))
    yield Lab(server, closed, workspace, tmp_path / "out")
    server.close()


def make_self_signed_certificate(directory: Path) -> tuple[Path, Path] | None:
    """A throwaway self-signed certificate via the openssl CLI, or None when openssl is absent."""
    openssl = shutil.which("openssl")
    if not openssl:
        return None
    certificate, key = directory / "lab.pem", directory / "lab.key"
    command = [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
               "-out", str(certificate), "-days", "2", "-subj", "/CN=127.0.0.1"]
    try:
        completed = subprocess.run(command, check=False, capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0 or not certificate.exists():
        return None
    return certificate, key


# --------------------------------------------------------------------------------------
# Running the scanner and building synthetic records
# --------------------------------------------------------------------------------------

def run_cli(argv: list[str]) -> tuple[int, str]:
    """Run ``scan_main`` with stdout captured. argparse's SystemExit propagates untouched."""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = scanner.scan_main(list(argv))
    return code, buffer.getvalue()


def squash(text: str) -> str:
    """Collapse whitespace so a wrapped console message can be searched as one sentence."""
    return " ".join(text.split())


def make_hit(scheme: str, url: str, *, status: int | None = None, reason: str = "", server: str = "",
             powered_by: str = "", content_type: str = "", location: str = "", title: str = "",
             snippet: str = "", bytes_read: int = 0, sha256: str = "", elapsed_ms: float = 0.0,
             tags=(), headers=None, error: str = "", body: bytes = b"", final_url: str | None = None):
    """A hit built through the pinned ``error_hit`` constructor, then filled in field by field."""
    hit = scanner.error_hit(scheme, url, 0, error)
    hit.final_url = final_url if final_url is not None else url
    hit.status, hit.reason, hit.server, hit.powered_by = status, reason, server, powered_by
    hit.content_type, hit.location, hit.title, hit.snippet = content_type, location, title, snippet
    hit.bytes_read, hit.sha256, hit.elapsed_ms = bytes_read, sha256, elapsed_ms
    hit.tags, hit.headers, hit.body = list(tags), dict(headers or {}), body
    return hit


def csv_rows_for(tmp_path, *hits, port: int = 80):
    """Rows the CSV writer emits for these hits: a name-independent way to ask 'is this hit live?'."""
    report = scanner.HostReport("h.example", [], [scanner.PortResult(port, True, hits=list(hits))], 0.0)
    target = tmp_path / "probe.csv"
    scanner.write_csv(target, [report])
    return list(csv.reader(target.read_text(encoding="utf-8").splitlines()))[1:]
