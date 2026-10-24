"""Bounded client for the fixed read-only child; no arbitrary tool forwarding."""

from __future__ import annotations

from contextvars import copy_context
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

from bughunt.core import exchange, execution_receipts
from bughunt.integrations import burp_profile, burp_transport


def _reader(
    stream, replies: queue.Queue, failed: threading.Event, admission=None
) -> None:
    used = 0
    try:
        while raw := stream.readline(burp_transport.LIMIT + 1):
            used += len(raw)
            if used > burp_transport.LIMIT:
                raise ValueError("MCP output cap")
            value = exchange.load_json(raw)
            if isinstance(value, dict) and "transport_admission" in value:
                if admission is None:
                    raise ValueError("Unexpected admission channel")
                admission(value)
                continue
            replies.put_nowait((raw, value))
    except (OSError, ValueError, queue.Full):
        if admission is not None:
            admission(incomplete=True)
        failed.set()


class Client:
    def __init__(self, url: str, *, deadline: float, check=lambda: None):
        burp_transport.endpoint(url)
        check()
        seconds = deadline - time.monotonic()
        if not 0 < seconds <= 120:
            raise ValueError("Invalid MCP client deadline")
        self.deadline, self.check = deadline, check
        self.replies = queue.Queue(maxsize=2)
        self.failed = threading.Event()
        self.receipts = {}
        self.url, self.process, self.reader = url, None, None
        self.admissions = 0
        self.observer = None

    def _admission(self, value=None, *, incomplete=False):
        if incomplete:
            if self.observer is not None:
                self.observer(incomplete=True)
            return
        if (
            not isinstance(value, dict)
            or set(value) != {"transport_admission", "method"}
            or type(value["transport_admission"]) is not int
            or value["transport_admission"] != self.admissions + 1
            or self.admissions >= 5
            or value["method"] != ("GET" if self.admissions == 0 else "POST")
        ):
            self._admission(incomplete=True)
            raise ValueError("Malformed child admission sequence")
        self.admissions += 1
        if self.observer is not None:
            self.observer()

    def start(self):
        self.check()
        if self.process is not None:
            raise ValueError("MCP client already started")
        seconds = self.deadline - time.monotonic()
        if not 0 < seconds <= 120:
            raise ValueError("MCP client expired before launch")
        self.observer = execution_receipts.child_admission_observer()
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-I",
                str(Path(burp_transport.__file__).resolve()),
                self.url,
                str(seconds),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self.reader = threading.Thread(
            target=copy_context().run,
            args=(
                _reader,
                self.process.stdout,
                self.replies,
                self.failed,
                self._admission,
            ),
            daemon=True,
        )
        try:
            self.reader.start()
        except RuntimeError:
            self._admission(incomplete=True)
            raise

    def send(self, method: str, params: dict, identifier=None):
        self.check()
        if self.process is None:
            raise ValueError("Initialize the read-only client before requests")
        value = {"jsonrpc": "2.0", "method": method, "params": params}
        if identifier is not None:
            value["id"] = identifier
        raw = exchange.canonical(value) + b"\n"
        if (
            len(raw) > 65536
            or self.failed.is_set()
            or time.monotonic() >= self.deadline
        ):
            raise ValueError("MCP request blocked or expired")
        self.process.stdin.write(raw)
        self.process.stdin.flush()
        if identifier is not None:
            return self.receive(identifier)

    def receive(self, identifier: int):
        while True:
            self.check()
            if self.failed.is_set() or time.monotonic() >= self.deadline:
                raise ValueError("MCP response cap, revocation or deadline")
            try:
                raw, value = self.replies.get(
                    timeout=min(0.05, max(0.001, self.deadline - time.monotonic()))
                )
            except queue.Empty:
                if self.process.poll() is not None:
                    self._admission(incomplete=True)
                    raise ValueError("MCP bridge exited without response")
                continue
            if isinstance(value, dict) and "jsonrpc" in value:
                if self.admissions != {1: 2, 2: 4, 3: 5}.get(identifier):
                    self._admission(incomplete=True)
                    raise ValueError("Missing child admission receipts")
            if (
                not isinstance(value, dict)
                or value.get("jsonrpc") != "2.0"
                or value.get("id") != identifier
                or set(value) != {"jsonrpc", "id", "result"}
                or not isinstance(value["result"], dict)
            ):
                raise ValueError("MCP error, unsolicited or malformed response")
            self.receipts[str(identifier)] = raw
            return value["result"]

    def handshake(self, expected_hash=None) -> dict:
        self.start()
        initialized = self.send(
            "initialize",
            {
                "protocolVersion": burp_transport.PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "bughunt-read-only", "version": "1"},
            },
            1,
        )
        if (
            initialized.get("protocolVersion") != burp_transport.PROTOCOL
            or initialized.get("serverInfo")
            != {"name": "burp-suite", "version": burp_profile.VERSIONS["server"]}
            or not isinstance(initialized.get("capabilities", {}).get("tools"), dict)
        ):
            raise ValueError("Unsupported Burp protocol/server")
        self.send("notifications/initialized", {})
        inventory = self.send("tools/list", {}, 2)
        if (
            set(inventory) not in ({"tools"}, {"tools", "_meta"})
            or inventory.get("_meta", {}) != {}
            or not isinstance(inventory["tools"], list)
            or len(inventory["tools"]) != 24
        ):
            raise ValueError("Unexpected Community tool inventory or pagination")
        names = [value.get("name") for value in inventory["tools"]]
        if len(set(names)) != len(names) or burp_transport.HISTORY not in names:
            raise ValueError("Missing or duplicate read-only tool")
        selected = inventory["tools"][names.index(burp_transport.HISTORY)][
            "inputSchema"
        ]
        if (
            selected.get("type") != "object"
            or set(selected.get("properties", {})) != {"count", "offset"}
            or set(selected.get("required", [])) != {"count", "offset"}
            or any(
                value != {"type": "integer"}
                for value in selected["properties"].values()
            )
        ):
            raise ValueError("Unsupported HTTP history input schema")
        digest = exchange.digest(exchange.canonical(inventory))
        if expected_hash is not None and digest != expected_hash:
            raise ValueError("Community tool fingerprint changed")
        return {
            "connected": True,
            "protocol": burp_transport.PROTOCOL,
            "server": initialized["serverInfo"],
            "tools_sha256": digest,
            "tool_names": names,
            "tool_allowlist": [burp_transport.HISTORY],
        }

    def history(self, count: int, offset: int) -> dict:
        return self.send(
            "tools/call",
            {
                "name": burp_transport.HISTORY,
                "arguments": {"count": count, "offset": offset},
            },
            3,
        )

    def close(self) -> bool:
        if self.process is None:
            return True
        try:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        except (OSError, subprocess.SubprocessError):
            self._admission(incomplete=True)
            return False
        if self.reader is not None and self.reader.is_alive():
            self.reader.join(timeout=1)
            if self.reader.is_alive():
                self._admission(incomplete=True)
        for stream in (self.process.stdin, self.process.stdout):
            stream.close()
        if self.reader is not None and self.reader.is_alive():
            self.reader.join(timeout=1)
        return self.process.poll() is not None and (
            self.reader is None or not self.reader.is_alive()
        )
