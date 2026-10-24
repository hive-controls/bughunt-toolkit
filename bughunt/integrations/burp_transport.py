"""Fixed read-only stdio/SSE bridge; standalone child with no target-send tools."""

from __future__ import annotations

import http.client
import json
import math
import re
import socket
import sys
import threading
import time
from urllib.parse import urlsplit

LIMIT = 16 * 1024 * 1024
PROTOCOL = "2024-11-05"
HISTORY = "get_proxy_http_history"


def unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate RPC key")
        result[name] = value
    return result


def decode(raw: bytes):
    if len(raw) > LIMIT:
        raise ValueError("RPC byte cap")
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    json.dumps(value, allow_nan=False)
    return value


def endpoint(value: str) -> tuple[str, int]:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.netloc != f"127.0.0.1:{parsed.port}"
    ):
        raise ValueError("Only inspected literal-loopback SSE root is supported")
    if parsed.port is None or not 1 <= parsed.port <= 65535:
        raise ValueError("Explicit local port required")
    return parsed.hostname, parsed.port


def message_endpoint(value: str) -> str:
    if not re.fullmatch(
        r"/?\?sessionId=[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value
    ):
        raise ValueError("Unexpected SSE message endpoint or redirect")
    return value if value.startswith("/") else "/" + value


def request_allowed(value: dict, stage: int) -> int:
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise ValueError("Unsupported RPC request")
    method, params = value.get("method"), value.get("params")
    if stage == 0 and method == "initialize" and value.get("id") == 1:
        if params != {
            "protocolVersion": PROTOCOL,
            "capabilities": {},
            "clientInfo": {"name": "bughunt-read-only", "version": "1"},
        }:
            raise ValueError("Unexpected initialization")
    elif (
        stage == 1
        and method == "notifications/initialized"
        and "id" not in value
        and params == {}
    ):
        pass
    elif (
        stage == 2 and method == "tools/list" and value.get("id") == 2 and params == {}
    ):
        pass
    elif stage == 3 and method == "tools/call" and value.get("id") == 3:
        if (
            not isinstance(params, dict)
            or set(params) != {"name", "arguments"}
            or params["name"] != HISTORY
        ):
            raise ValueError("Tool not on the read-only allowlist")
        arguments = params["arguments"]
        if (
            not isinstance(arguments, dict)
            or set(arguments) != {"count", "offset"}
            or type(arguments["count"]) is not int
            or not 1 <= arguments["count"] <= 10
            or type(arguments["offset"]) is not int
            or not 0 <= arguments["offset"] <= 500
        ):
            raise ValueError("Explicit bounded history selection required")
    else:
        raise ValueError("RPC sequence or tool forbidden")
    expected = {"jsonrpc", "method", "params"} | ({"id"} if stage != 1 else set())
    if set(value) != expected or (stage != 1 and type(value["id"]) is not int):
        raise ValueError("Unknown RPC request fields")
    return stage + 1


def events(response):
    name, data, used = None, [], 0
    while True:
        raw = response.readline(LIMIT + 1)
        if not raw:
            raise ValueError("SSE stream ended")
        used += len(raw)
        if used > LIMIT or len(raw) > LIMIT:
            raise ValueError("SSE connection byte cap")
        line = raw.decode("utf-8").rstrip("\r\n")
        if not line:
            if name is not None:
                yield name, "\n".join(data)
            name, data = None, []
        elif line.startswith(":"):
            continue
        elif line.startswith("event:") and name is None:
            name = line[6:].lstrip(" ")
        elif line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        else:
            raise ValueError("Unsupported SSE field")


class Bridge:
    def __init__(self, url: str, seconds: float):
        if not math.isfinite(seconds) or not 0 < seconds <= 120:
            raise ValueError("Bridge deadline must be at most 120 seconds")
        self.host, self.port = endpoint(url)
        self.deadline = time.monotonic() + seconds
        self.budget = seconds
        self.connection = http.client.HTTPConnection(
            self.host, self.port, timeout=seconds
        )
        self.path = None
        self.closed = threading.Event()
        self.pending = set()
        self.lock = threading.Lock()
        self.used = 0
        self.stage = 0
        self.admissions = 0

    def admit(self, method: str) -> None:
        self.admissions += 1
        if self.admissions > 5:
            raise ValueError("Bridge admission cap")
        self.emit({"transport_admission": self.admissions, "method": method})

    def emit(self, value: dict) -> None:
        raw = json.dumps(value, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        with self.lock:
            self.used += len(raw)
            if self.used > LIMIT:
                raise ValueError("Bridge stdout byte cap")
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()

    def receive(self, iterator) -> None:
        try:
            for name, data in iterator:
                if name != "message" or time.monotonic() >= self.deadline:
                    raise ValueError("Unexpected SSE event or expired bridge")
                value = decode(data.encode())
                if (
                    not isinstance(value, dict)
                    or value.get("jsonrpc") != "2.0"
                    or set(value)
                    not in ({"jsonrpc", "id", "result"}, {"jsonrpc", "id", "error"})
                    or type(value.get("id")) is not int
                    or value["id"] not in self.pending
                ):
                    raise ValueError("Unsolicited, duplicate or malformed RPC response")
                self.pending.remove(value["id"])
                self.emit(value)
        except (OSError, ValueError, http.client.HTTPException):
            if not self.closed.is_set():
                self.emit({"transport_error": "SSE stream blocked or ended"})

    def open(self):
        self.admit("GET")
        self.connection.request("GET", "/", headers={"Accept": "text/event-stream"})
        response = self.connection.getresponse()
        if (
            response.status != 200
            or response.getheader("Content-Type", "").split(";", 1)[0]
            != "text/event-stream"
        ):
            raise ValueError("SSE status/type or redirect rejected")
        iterator = events(response)
        name, data = next(iterator)
        if name != "endpoint":
            raise ValueError("SSE endpoint must be first")
        self.path = message_endpoint(data)
        threading.Thread(target=self.receive, args=(iterator,), daemon=True).start()

    def post(self, raw: bytes):
        value = decode(raw)
        stage = request_allowed(value, self.stage)
        remaining = min(self.deadline - time.monotonic(), self.budget)
        if remaining <= 0:
            raise ValueError("Bridge expired")
        if "id" in value:
            self.pending.add(value["id"])
        connection = http.client.HTTPConnection(self.host, self.port, timeout=remaining)
        try:
            self.admit("POST")
            connection.request(
                "POST",
                self.path,
                body=raw,
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            if response.status != 202 or len(response.read(1025)) > 1024:
                raise ValueError("RPC POST status/size or redirect rejected")
            self.stage = stage
        finally:
            connection.close()

    def close(self):
        self.closed.set()
        if self.connection.sock is not None:
            try:
                self.connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.connection.close()


def main() -> int:
    bridge = None
    try:
        if len(sys.argv) != 3:
            raise ValueError("Expected local endpoint and deadline")
        bridge = Bridge(sys.argv[1], float(sys.argv[2]))
        bridge.open()
        while raw := sys.stdin.buffer.readline(65537):
            if len(raw) > 65536:
                raise ValueError("RPC request byte cap")
            bridge.post(raw)
        return 0
    except (OSError, ValueError, TypeError, KeyError, http.client.HTTPException):
        print('{"transport_error":"Read-only bridge blocked"}', flush=True)
        return 2
    finally:
        if bridge is not None:
            bridge.close()


if __name__ == "__main__":
    raise SystemExit(main())
