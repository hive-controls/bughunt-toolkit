"""Named owned-loopback text capture/replay with a final protocol-write gate."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import logging
import socket
import threading
import time
from urllib.parse import urlsplit

import httpx

from bughunt.core import egress, exchange, identity, job, ledger
from bughunt.core.workspace import matches, read_entries


@dataclass(frozen=True)
class Plan:
    url: str
    http_url: str
    messages: tuple[str, ...]
    budget: job.Budget
    source_run_id: str | None = None
    source_sha256: str | None = None


def prepare(url: str, messages: list, *, mission: str, owned_lab=False, seconds=5,
            source_run_id=None, source_sha256=None) -> Plan:
    exchange.text(url, maximum=8192)
    parsed = urlsplit(url)
    if (owned_lab is not True or parsed.scheme != "ws" or not ipaddress.ip_address(parsed.hostname).is_loopback
            or not parsed.path.startswith("/__bughunt_lab__/")):
        raise ValueError("Only explicitly owned literal-loopback plaintext WS lab paths are supported")
    http_url = str(httpx.URL("http" + url[2:]))
    exchange.target_parts(http_url)
    if not isinstance(messages, list) or not 1 <= len(messages) <= 4:
        raise ValueError("Supply 1..4 application text messages")
    if any(not isinstance(value, str) or len(value.encode()) > 4096 for value in messages):
        raise ValueError("Each text message is bounded to 4096 UTF-8 bytes")
    if type(seconds) not in (int, float) or not 0 < seconds <= 10:
        raise ValueError("Job deadline must be finite and at most 10 seconds")
    profile = egress.authorize(http_url, "active_scan", "GET")
    egress.authorize(http_url, "active_scan", "CONNECT")
    if any(name.lower() in {"connection", "upgrade", "content-length", "transfer-encoding", "expect"}
           or name.lower().startswith("sec-websocket-") for name, _ in profile.required_headers):
        raise ValueError("Required identity headers cannot override WS protocol/framing fields")
    if profile.mission != mission or mission != "whk015-owned-ws" or not matches(parsed.hostname, read_entries()):
        raise ValueError("Named WS mission and explicit workspace scope required")
    ledger.redact_text("")
    budget = job.Budget(frozenset({("CONNECT", http_url)}), 16, seconds, strict_scope=True)
    return Plan("ws" + http_url[4:], http_url, tuple(messages), budget, source_run_id, source_sha256)


def preview(plan: Plan) -> dict:
    return {"job_id": plan.budget.job_id, "target": plan.url, "message_count": len(plan.messages),
            "wire_write_cap": 16, "wire_byte_cap": 65536, "duration_cap": plan.budget.seconds,
            "source_run_id": plan.source_run_id, "actor": plan.budget.state[0][1], "dry_run": True,
            "claim": "Owned text-message lab only; no binary/compression/TLS/wire-frame or impact proof"}


class _Wire:
    def __init__(self, inner, plan: Plan):
        self.inner, self.plan = inner, plan
        self.lock = threading.Lock()
        self.bytes_sent = 0
        self.first_write = None

    def __getattr__(self, name):
        if name in {"sendto", "sendmsg", "sendfile", "makefile", "dup"}:
            raise ValueError("Unsupported socket escape path")
        return getattr(self.inner, name)

    def settimeout(self, value):
        remaining = max(0.001, self.plan.budget.deadline - time.monotonic())
        self.inner.settimeout(remaining if value is None else min(value, remaining))

    def sendall(self, data, *args):
        with self.lock:
            request = httpx.Request("CONNECT", self.plan.http_url)
            check = lambda: self.plan.budget.check(request)
            check()
            if not isinstance(data, bytes) or self.bytes_sent + len(data) > 65536:
                raise egress.PolicyBlocked("WS protocol byte cap")
            profile = egress.authorize(self.plan.http_url, "active_scan", "CONNECT")
            capture = ledger.begin(profile, tool="websocket-wire", operation="active_scan", target=self.plan.http_url,
                                   request=exchange.canonical({"size": len(data), "sha256": exchange.digest(data)}),
                                   actor=self.plan.budget.state[0][1])
            capture.manifest["representation"] = "protocol-write metadata; no HTTP or frame bytes"
            request.extensions["bughunt_run_id"] = capture.manifest["run_id"]
            try:
                def prepare_write():
                    self.plan.budget.admit(request)
                    self.settimeout(None)
                    check()
                egress.dispatch(self.plan.http_url, "active_scan", "CONNECT",
                    lambda: self.inner.sendall(data, *args), check=check,
                    commit=prepare_write, capture=capture)
                self.bytes_sent += len(data)
                if self.first_write is None:
                    self.first_write = data
                capture.finish()
            except BaseException as exc:
                capture.finish(classification="invalid", complete=False, error=type(exc).__name__)
                raise

    def send(self, data, *args):
        self.sendall(data, *args)
        return len(data)


def _handshake(connection, wire: _Wire, profile) -> tuple[str, str]:
    raw = wire.first_write
    response = connection.response.serialize()
    if raw is None or len(raw) > 65536 or len(response) > 65536:
        raise ValueError("Incomplete or oversized WS handshake")
    capture = ledger.begin(profile, tool="websocket-handshake", operation="active_scan", target=wire.plan.http_url,
                           request=raw, actor=wire.plan.budget.state[0][1])
    capture.response_prefix = response
    capture.finish()
    run_id = capture.manifest["run_id"]
    record = exchange.from_run(run_id)
    ids = exchange.save([record], source_id="websocket-handshake:" + run_id, source_bytes=raw + response, kind="ledger")
    return run_id, ids[0]


def _frame(direction: str, value: str) -> dict:
    if not isinstance(value, str) or len(value.encode()) > 4096:
        raise ValueError("Only complete bounded decoded text messages are supported")
    return {"direction": direction, "text": value, "size": len(value.encode()),
            "sha256": exchange.digest(value.encode()), "captured_at": datetime.now(timezone.utc).isoformat()}


def _capture(plan: Plan, profile) -> dict:
    from websockets.exceptions import WebSocketException
    from websockets.sync.client import connect
    frames, handshake, error, wire = [], None, None, None
    logger = logging.getLogger("bughunt.websocket.private")
    logger.disabled = True
    request = httpx.Request("CONNECT", plan.http_url)
    check = lambda: plan.budget.check(request)
    try:
        with egress.action(plan.http_url, "active_scan", "CONNECT", check=check):
            check()
            name, _, credentials = identity.snapshot(plan.http_url, plan.budget.state[0])
            for value in credentials.values():
                ledger.remember_secret(value)
            headers = {**credentials, **dict(profile.required_headers)}
            parsed = urlsplit(plan.http_url)
            check()
            inner = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=plan.budget.deadline - time.monotonic())
            wire = _Wire(inner, plan)
            try:
                with connect(plan.url, sock=wire, proxy=None, compression=None, ping_interval=None,
                             additional_headers=headers, user_agent_header=profile.user_agent,
                             open_timeout=max(0.001, plan.budget.deadline - time.monotonic()),
                             close_timeout=0.1, max_size=4096, max_queue=2, logger=logger) as connection:
                    handshake = _handshake(connection, wire, profile)
                    for value in plan.messages:
                        check()
                        connection.send(value)
                        frames.append(_frame("client", value))
                        incoming = connection.recv(timeout=max(0.001, plan.budget.deadline - time.monotonic()))
                        check()
                        frames.append(_frame("server", incoming))
            finally:
                wire.close()
    except (ValueError, OSError, httpx.HTTPError, WebSocketException) as exc:
        error = type(exc).__name__
    return {"frames": frames, "handshake": handshake, "error": error,
            "bytes_sent": wire.bytes_sent if wire is not None else 0}


def execute(plan: Plan) -> dict:
    profile = egress.authorize(plan.http_url, "active_scan", "GET")
    exchange._write(plan.budget.stop_path().parent / "job.json", {**preview(plan), "job_id": plan.budget.job_id})
    captured = _capture(plan, profile)
    complete = captured["error"] is None and len(captured["frames"]) == 2 * len(plan.messages)
    transcript = {"schema_version": 1, "url": plan.url, "frames": captured["frames"], "complete": complete,
                  "handshake": captured["handshake"], "source_run_id": plan.source_run_id,
                  "source_sha256": plan.source_sha256, "representation": "logical decoded text messages; not wire frames"}
    snapshot = {"mission": profile.mission, "policy_version": profile.policy_version,
                "policy_verified_at": profile.verified_at.isoformat()}
    metadata = {"observation_count": len(captured["frames"]), "policy_snapshot": snapshot,
                "complete": complete, "writes": list(plan.budget.sent), "error": captured["error"],
                "claim": "Owned lab logical messages; no impact or server-side identity attestation"}
    run_id = ledger.record_import(tool="websocket", metadata=metadata,
                                  artifacts={"transcript.json": exchange.canonical(transcript)},
                                  classification="observation" if complete else "invalid")
    return ledger.redact({**preview(plan), "dry_run": False, "run_id": run_id,
                         "classification": "observation" if complete else "invalid", "complete": complete,
                         "handshake": captured["handshake"], "write_count": len(plan.budget.sent),
                         "bytes_sent": captured["bytes_sent"], "error": captured["error"]})


def replay_plan(run_id: str, *, mission: str, owned_lab=False, seconds=5) -> Plan:
    exported = ledger.export_run(run_id)
    manifest = ledger.manifest_for(run_id)
    if manifest["tool"] != "websocket" or not manifest["import_metadata"]["complete"] or "transcript.json" not in exported["artifacts"]:
        raise ValueError("Require a complete hash-checked WS transcript")
    data = (ledger.runs_dir() / run_id / "transcript.json").read_bytes()
    value = exchange.load_json(data)
    fields = {"schema_version", "url", "frames", "complete", "handshake", "source_run_id", "source_sha256", "representation"}
    if (not isinstance(value, dict) or set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["complete"] is not True or not isinstance(value["frames"], list)
            or not 2 <= len(value["frames"]) <= 8 or len(value["frames"]) % 2):
        raise ValueError("Invalid WS transcript")
    for index, frame in enumerate(value["frames"]):
        checked = _frame("client" if index % 2 == 0 else "server", frame["text"])
        if any(frame[key] != checked[key] for key in ("direction", "text", "size", "sha256")) or exchange.timestamp(frame["captured_at"]) is None:
            raise ValueError("WS message integrity mismatch")
    handshake = exchange.from_run(value["handshake"][0])
    http_url = str(httpx.URL("http" + value["url"][2:]))
    if (handshake["exchange_id"] != value["handshake"][1] or exchange.read(value["handshake"][1])["exchange_id"] != handshake["exchange_id"]
            or handshake["request"]["url"] != http_url or handshake["request"]["method"] != "GET"
            or handshake["response"] is None or handshake["response"]["status"] != 101):
        raise ValueError("WS handshake source mismatch")
    messages = [frame["text"] for frame in value["frames"] if frame["direction"] == "client"]
    return prepare(value["url"], messages, mission=mission, owned_lab=owned_lab, seconds=seconds,
                   source_run_id=run_id, source_sha256=exchange.digest(data))
