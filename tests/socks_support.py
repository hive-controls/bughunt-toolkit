"""A loopback SOCKS5 server that stands in for Tor, and a network booby trap.

No real Tor and no internet: FakeSocks accepts SOCKS5 CONNECT requests, records exactly what the client
asked for (credentials, address type, host name, port) and answers the HTTP request that follows with a
canned response. NetworkTrap makes any local name resolution, or any TCP connect to a place other than a
declared SOCKS listener, a recorded failure, so a leak (a DNS lookup or a direct connection) is visible.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from test_gate import seed_policy

CHECK_HOST = "check.torproject.org"
TOR_ANSWER = b'{"IsTor": true, "IP": "203.0.113.7"}'
ONION_V3 = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
SOCKS_REPLY_REFUSED = 5

REASONS = {200: "OK", 301: "Moved Permanently", 302: "Found", 303: "See Other", 307: "Temporary Redirect",
           308: "Permanent Redirect", 403: "Forbidden", 404: "Not Found", 500: "Internal Server Error"}


@dataclass
class Seen:
    """One SOCKS connection and the HTTP request that rode on it."""

    user: str | None = None
    password: str | None = None
    atyp: int | None = None
    host: str = ""
    port: int = 0
    method: str = ""
    target: str = ""
    headers: dict = field(default_factory=dict)
    body: bytes = b""

    @property
    def first_line(self) -> str:
        return f"{self.method} {self.target}" if self.method else ""


def default_responder(seen: Seen):
    if seen.host == CHECK_HOST and seen.target == "/api/ip":
        return 200, {"Content-Type": "application/json"}, TOR_ANSWER
    return 200, {"Content-Type": "text/plain; charset=utf-8"}, b"hello via fake tor"


class FakeSocks:
    def __init__(self, responder=None, *, reply_code=None, stall_seconds: float = 0.0, require_auth=True):
        self.responder = responder or default_responder
        self.reply_code = reply_code or (lambda host, port: 0)
        self.stall_seconds = stall_seconds
        self.require_auth = require_auth
        self.connections: list[Seen] = []
        self.errors: list[str] = []
        self._lock = threading.Lock()
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def endpoint(self) -> str:
        return f"127.0.0.1:{self.port}"

    def close(self) -> None:
        try:
            self._listener.close()
        except OSError:
            pass

    def hosts(self) -> list[str]:
        return [seen.host for seen in self.connections]

    def _serve(self) -> None:
        while True:
            try:
                connection, _address = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    @staticmethod
    def _exact(connection, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = connection.recv(count - len(data))
            if not chunk:
                raise EOFError("client closed during the SOCKS handshake")
            data += chunk
        return data

    def _negotiate(self, connection, seen: Seen) -> None:
        _version, method_count = self._exact(connection, 2)
        methods = self._exact(connection, method_count)
        if 2 in methods:
            connection.sendall(b"\x05\x02")
            _version, user_length = self._exact(connection, 2)
            seen.user = self._exact(connection, user_length).decode()
            password_length = self._exact(connection, 1)[0]
            seen.password = self._exact(connection, password_length).decode()
            connection.sendall(b"\x01\x00")
        else:
            connection.sendall(b"\x05\x00")

    def _read_address(self, connection, seen: Seen) -> None:
        _version, _command, _reserved, seen.atyp = self._exact(connection, 4)
        if seen.atyp == 3:
            seen.host = self._exact(connection, self._exact(connection, 1)[0]).decode()
        elif seen.atyp == 1:
            seen.host = socket.inet_ntoa(self._exact(connection, 4))
        else:
            seen.host = ipaddress.ip_address(self._exact(connection, 16)).compressed
        seen.port = int.from_bytes(self._exact(connection, 2), "big")

    def _read_http(self, connection, seen: Seen) -> None:
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = connection.recv(65536)
            if not chunk:
                raise EOFError("client closed before sending a request")
            raw += chunk
        head, _separator, rest = raw.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        seen.method, seen.target, _version = lines[0].split(" ", 2)
        seen.headers = {name.lower(): value.strip() for name, _colon, value in (line.partition(":") for line in lines[1:])}
        wanted = int(seen.headers.get("content-length", "0"))
        while len(rest) < wanted:
            rest += connection.recv(65536)
        seen.body = rest[:wanted]

    def _respond(self, connection, seen: Seen) -> None:
        status, headers, body = self.responder(seen)
        head = f"HTTP/1.1 {status} {REASONS.get(status, 'Status')}\r\n"
        for name, value in {**headers, "Content-Length": str(len(body)), "Connection": "close"}.items():
            head += f"{name}: {value}\r\n"
        connection.sendall(head.encode("latin-1") + b"\r\n" + body)

    def _handle(self, connection) -> None:
        seen = Seen()
        try:
            self._negotiate(connection, seen)
            self._read_address(connection, seen)
            with self._lock:
                self.connections.append(seen)
            code = self.reply_code(seen.host, seen.port)
            connection.sendall(bytes([5, code, 0, 1]) + b"\x00\x00\x00\x00\x00\x00")
            if code != 0:
                return
            self._read_http(connection, seen)
            if self.stall_seconds:
                time.sleep(self.stall_seconds)
            self._respond(connection, seen)
        except (EOFError, OSError, ValueError) as failure:
            self.errors.append(repr(failure))
        finally:
            connection.close()


def closed_port() -> int:
    """A loopback port nothing is listening on."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class NetworkTrap:
    """Records every local name lookup and every TCP connect to somewhere other than an allowed SOCKS port."""

    def __init__(self) -> None:
        self.attempts: list[tuple[str, object]] = []
        self.allowed_ports: set[int] = set()

    def allow(self, port: int) -> None:
        self.allowed_ports.add(port)

    def install(self, monkeypatch) -> "NetworkTrap":
        real_getaddrinfo, real_connect = socket.getaddrinfo, socket.socket.connect

        def getaddrinfo(host, *args, **kwargs):
            name = host.decode() if isinstance(host, bytes) else host
            try:
                ipaddress.ip_address(name)
            except (ValueError, TypeError):
                self.attempts.append(("resolve", name))
                raise socket.gaierror(socket.EAI_NONAME, "network trap: local name resolution")
            return real_getaddrinfo(host, *args, **kwargs)

        def connect(sock, address):
            if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1"} and address[1] in self.allowed_ports:
                return real_connect(sock, address)
            self.attempts.append(("connect", address))
            raise OSError("network trap: unexpected TCP connect")

        def gethostbyname(name):
            self.attempts.append(("resolve", name))
            raise socket.gaierror(socket.EAI_NONAME, "network trap: local name resolution")

        monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
        monkeypatch.setattr(socket, "gethostbyname", gethostbyname)
        monkeypatch.setattr(socket.socket, "connect", connect)
        return self


def asset(identifier: str, origin: str, paths, operations, methods) -> dict:
    return {"id": identifier, "origin": origin, "paths": list(paths),
            "operations": list(operations), "methods": list(methods)}


def build_policy(path: Path, *, socks_port: int, target=True, onion=True, hop=True, check=True,
                 hop_operations=("manual", "passive"), hop_methods=("GET",), extra=()) -> None:
    """A verified policy for tcurl-style tests: target rows, the SOCKS hop and the exit-check row, each switchable."""
    document = seed_policy(path)
    rows = []
    if target:
        rows += [asset("target", "http://target.example", ["/"], ["manual"], ["GET", "HEAD", "POST", "OPTIONS"]),
                 asset("other", "http://other.example", ["/"], ["manual"], ["GET", "HEAD"]),
                 asset("outside", "http://outside.example", ["/"], ["manual"], ["GET"])]
    if onion:
        rows.append(asset("onion", f"http://{ONION_V3}", ["/"], ["manual"], ["GET", "HEAD"]))
    if hop:
        rows.append(asset("hop", f"http://127.0.0.1:{socks_port}", ["/"], hop_operations, hop_methods))
    if check:
        rows.append(asset("check", f"http://{CHECK_HOST}", ["/api/ip"], ["passive"], ["GET"]))
    document["assets"] = rows + list(extra)
    document["permissions"] = {name: name in {"manual", "passive"} for name in document["permissions"]}
    document["limits"] = {"requests_per_second": 1000, "concurrency": 8}
    document["required_headers"] = {"X-Probe-Handle": "tcurl-probe"}
    document["user_agent"] = "BughuntTcurlProbe/1"
    document["exclusions"] = []
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
