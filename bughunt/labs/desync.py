"""Fixed, owned HTTP/1.1 parser and response-queue laboratory."""

from __future__ import annotations

from contextvars import copy_context
from dataclasses import dataclass, field
import hashlib
import math
import secrets
import socket
import threading
import time
from urllib.parse import urlsplit
import uuid

import httpx

from bughunt.core import egress, exchange, identity, job, ledger, policy, session
from bughunt.core.workspace import read_entries, workspace_dir


MISSION = "whk016-owned-desync"
HOST = "127.0.0.1"
PATH = "/__bughunt_lab__/desync"
MARKER_PATH = "/__bughunt_lab__/marker"
CONNECTION_CAP = 6
WRITE_CAP = 12
WRITE_BYTE_CAP = 8192
OUTBOUND_BYTE_CAP = 65536
RESPONSE_BYTE_CAP = 65536
EMBEDDED_MESSAGE_CAP = 5


@dataclass(frozen=True)
class Plan:
    front_url: str
    backend_url: str
    front_port: int
    backend_port: int
    budget: job.Budget
    profile: object


@dataclass(frozen=True)
class Case:
    name: str
    raw: bytes
    front_mode: str
    backend_mode: str
    embedded_messages: int
    marker_sha256: str


def _owned_url(value: str) -> int:
    exchange.text(value, maximum=256)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid owned laboratory URL") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname != HOST
        or port is None
        or not 1 <= port <= 65535
        or value != f"http://{HOST}:{port}{PATH}"
    ):
        raise ValueError("Require exact literal-loopback HTTP laboratory URL and port")
    return port


def _literal_grants(profile, front_url: str, backend_url: str) -> bool:
    for url in (front_url, backend_url):
        for target, method in (
            (url, "GET"),
            (url, "POST"),
            (url.replace(PATH, MARKER_PATH), "GET"),
        ):
            origin, path = policy.target_parts(target)
            if not any(
                asset.origin == origin
                and path in asset.paths
                and "active_scan" in asset.operations
                and method in asset.methods
                for asset in profile.assets
            ):
                return False
    return True


def prepare(
    front_url: str, backend_url: str, *, mission: str, owned_lab=False, seconds=10
) -> Plan:
    front_port, backend_port = _owned_url(front_url), _owned_url(backend_url)
    if (
        owned_lab is not True
        or mission != MISSION
        or front_port == backend_port
        or type(seconds) not in (int, float)
        or not math.isfinite(seconds)
        or not 0 < seconds <= 60
    ):
        raise ValueError(
            "Named owned lab, distinct ports and bounded duration required"
        )
    profiles = [
        egress.authorize(url, "active_scan", method)
        for url in (front_url, backend_url)
        for method in ("GET", "POST")
    ]
    profiles.extend(
        egress.authorize(url.replace(PATH, MARKER_PATH), "active_scan", "GET")
        for url in (front_url, backend_url)
    )
    profile = profiles[0]
    if (
        any(row.mission != MISSION for row in profiles)
        or not _literal_grants(profile, front_url, backend_url)
        or profile.concurrency < 2
        or profile.required_headers
        or HOST not in read_entries()
        or identity.selection_signature()[1] != "default"
        or session.load_legacy_session()
    ):
        raise ValueError(
            "Explicit scope, credential-free default actor and two-slot lab grant required"
        )
    ledger.redact_text("")
    budget = job.Budget(
        frozenset({("GET", front_url), ("GET", backend_url)}),
        WRITE_CAP,
        seconds,
        strict_scope=True,
    )
    return Plan(front_url, backend_url, front_port, backend_port, budget, profile)


def preview(plan: Plan) -> dict:
    return {
        "job_id": plan.budget.job_id,
        "front": plan.front_url,
        "backend": plan.backend_url,
        "mission": MISSION,
        "actor": "default",
        "cases": ["baseline", "matched-cl-cl", "divergent-cl-te"],
        "connection_cap": CONNECTION_CAP,
        "write_cap": WRITE_CAP,
        "per_write_byte_cap": WRITE_BYTE_CAP,
        "outbound_byte_cap": OUTBOUND_BYTE_CAP,
        "response_byte_cap_per_connection": RESPONSE_BYTE_CAP,
        "generated_embedded_message_cap": EMBEDDED_MESSAGE_CAP,
        "duration_cap": plan.budget.seconds,
        "dry_run": True,
        "claim": "Owned parser/queue observation only; not impact, victim traffic or packet-engine parity",
    }


def _cases(plan: Plan) -> tuple[Case, ...]:
    host = f"{HOST}:{plan.front_port}".encode("ascii")
    baseline = b"GET " + PATH.encode() + b" HTTP/1.1\r\nHost: " + host + b"\r\n\r\n"
    cases = [Case("baseline", baseline, "cl", "cl", 1, "")]
    for name, backend_mode in (("matched-cl-cl", "cl"), ("divergent-cl-te", "te")):
        marker = secrets.token_hex(8).encode("ascii")
        second = (
            b"GET "
            + MARKER_PATH.encode()
            + b"?nonce="
            + marker
            + b" HTTP/1.1\r\nHost: "
            + host
            + b"\r\n\r\n"
        )
        body = b"0\r\n\r\n" + second
        first = (
            b"POST "
            + PATH.encode()
            + b" HTTP/1.1\r\nHost: "
            + host
            + b"\r\nContent-Length: "
            + str(len(body)).encode("ascii")
            + b"\r\nTransfer-Encoding: chunked\r\n\r\n"
            + body
        )
        cases.append(Case(name, first, "cl", backend_mode, 2, exchange.digest(marker)))
    if sum(case.embedded_messages for case in cases) > EMBEDDED_MESSAGE_CAP:
        raise ValueError("Generated embedded HTTP message cap")
    return tuple(cases)


def _parse_requests(raw: bytes, mode: str) -> list[dict]:
    rows, offset = [], 0
    while offset < len(raw):
        end = raw.find(b"\r\n\r\n", offset)
        if end < 0 or end - offset > WRITE_BYTE_CAP:
            raise ValueError("Incomplete or oversized laboratory request headers")
        lines = raw[offset:end].split(b"\r\n")
        parts = lines[0].split(b" ")
        if (
            len(parts) != 3
            or parts[0] not in {b"GET", b"POST"}
            or parts[2] != b"HTTP/1.1"
        ):
            raise ValueError("Unsupported laboratory request line")
        path = parts[1].decode("ascii")
        if path != PATH and not path.startswith(MARKER_PATH + "?nonce="):
            raise ValueError("Unexpected laboratory path")
        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b":")
            key = name.lower()
            if not separator or key in headers:
                raise ValueError("Ambiguous laboratory header")
            headers[key] = value.strip()
        if b"host" not in headers:
            raise ValueError("Missing laboratory Host")
        body_start = end + 4
        if mode == "te" and headers.get(b"transfer-encoding") == b"chunked":
            if raw[body_start : body_start + 5] != b"0\r\n\r\n":
                raise ValueError("Only fixed zero-chunk fixture is supported")
            next_offset = body_start + 5
        else:
            length = int(headers.get(b"content-length", b"0"))
            next_offset = body_start + length
        if next_offset > len(raw) or next_offset <= offset:
            raise ValueError("Truncated laboratory request")
        rows.append(
            {
                "method": parts[0].decode(),
                "path": path,
                "start": offset,
                "end": next_offset,
            }
        )
        offset = next_offset
        if len(rows) > 2:
            raise ValueError("Embedded HTTP message cap")
    return rows


def _response(rows: list[dict], case_name: str) -> bytes:
    result = bytearray()
    for index, row in enumerate(rows):
        body = f"owned:{case_name}:{index}:{row['path']}".encode("ascii")
        result.extend(
            b"HTTP/1.1 200 OK\r\nContent-Length: "
            + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n"
            + body
        )
    if len(result) > WRITE_BYTE_CAP:
        raise ValueError("Laboratory response exceeds one write")
    return bytes(result)


def _parse_responses(raw: bytes) -> list[dict]:
    rows, offset = [], 0
    while offset < len(raw):
        end = raw.find(b"\r\n\r\n", offset)
        if end < 0 or raw[offset:end].split(b"\r\n", 1)[0] != b"HTTP/1.1 200 OK":
            raise ValueError("Incomplete laboratory response")
        headers = raw[offset:end].lower().split(b"\r\n")
        lengths = [
            line[16:] for line in headers if line.startswith(b"content-length: ")
        ]
        if len(lengths) != 1:
            raise ValueError("Invalid laboratory response length")
        next_offset = end + 4 + int(lengths[0])
        if next_offset > len(raw):
            raise ValueError("Truncated laboratory response")
        rows.append(
            {
                "start": offset,
                "end": next_offset,
                "body_sha256": exchange.digest(raw[end + 4 : next_offset]),
            }
        )
        offset = next_offset
        if len(rows) > 2:
            raise ValueError("Response queue cap")
    return rows


@dataclass
class _Meter:
    plan: Plan
    lock: threading.Lock = field(default_factory=threading.Lock)
    connections: list[dict] = field(default_factory=list)
    writes: list[dict] = field(default_factory=list)
    reads: list[dict] = field(default_factory=list)
    outbound_bytes: int = 0

    def check(self, aborted: threading.Event | None = None) -> None:
        if aborted is not None and aborted.is_set():
            raise egress.PolicyBlocked("Laboratory case aborted")
        if HOST not in read_entries() or session.load_legacy_session():
            raise egress.PolicyBlocked("Laboratory scope or actor session changed")
        if not _literal_grants(
            egress.current_profile(), self.plan.front_url, self.plan.backend_url
        ):
            raise egress.PolicyBlocked("Literal laboratory path grants changed")
        for url in (self.plan.front_url, self.plan.backend_url):
            self.plan.budget.check(httpx.Request("GET", url))
            egress.authorize(url, "active_scan", "POST")
            egress.authorize(url.replace(PATH, MARKER_PATH), "active_scan", "GET")

    def connect(self, url: str, role: str, aborted: threading.Event) -> socket.socket:
        self.check(aborted)
        with self.lock:
            if len(self.connections) >= CONNECTION_CAP:
                raise egress.PolicyBlocked("Laboratory connection cap")
            row = {"role": role, "target": url, "connected": False}
            self.connections.append(row)
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.settimeout(
                min(0.2, max(0.001, self.plan.budget.deadline - time.monotonic()))
            )
            connection.connect((HOST, urlsplit(url).port))
            row["connected"] = True
            return connection
        except BaseException:
            connection.close()
            raise

    def send(
        self,
        connection: socket.socket,
        data: bytes,
        url: str,
        role: str,
        aborted: threading.Event,
    ) -> None:
        self.check(aborted)
        if not isinstance(data, bytes) or not 0 < len(data) <= WRITE_BYTE_CAP:
            raise egress.PolicyBlocked("Laboratory per-write byte cap")
        with self.lock:
            if (
                len(self.writes) >= WRITE_CAP
                or self.outbound_bytes + len(data) > OUTBOUND_BYTE_CAP
            ):
                raise egress.PolicyBlocked("Laboratory write or aggregate byte cap")
            row = {
                "role": role,
                "target": url,
                "size": len(data),
                "sha256": exchange.digest(data),
                "complete": False,
            }
            self.writes.append(row)
            self.outbound_bytes += len(data)
        capture = ledger.begin(
            self.plan.profile,
            tool="desync-wire",
            operation="active_scan",
            target=url,
            request=exchange.canonical(
                {
                    "role": role,
                    "target": url,
                    "size": len(data),
                    "sha256": row["sha256"],
                }
            ),
            actor="default",
        )
        capture.manifest["representation"] = (
            "raw-desync-write-metadata; no HTTP exchange"
        )
        row["run_id"] = capture.manifest["run_id"]
        try:

            def prepare_write():
                connection.settimeout(
                    min(0.2, max(0.001, self.plan.budget.deadline - time.monotonic()))
                )
                self.check(aborted)

            egress.dispatch(
                url,
                "active_scan",
                "GET",
                lambda: connection.sendall(data),
                check=lambda: self.check(aborted),
                commit=prepare_write,
                capture=capture,
            )
            row["complete"] = True
            capture.finish()
        except BaseException as exc:
            capture.finish(
                classification="invalid", complete=False, error=type(exc).__name__
            )
            raise


def _listener(port: int, meter: _Meter) -> socket.socket:
    meter.check()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind((HOST, port))
        listener.listen(1)
        listener.settimeout(0.1)
        return listener
    except BaseException:
        listener.close()
        raise


def _accept(
    listener: socket.socket, meter: _Meter, aborted: threading.Event
) -> socket.socket:
    while True:
        meter.check(aborted)
        try:
            connection, address = listener.accept()
            if address[0] != HOST:
                connection.close()
                raise ValueError("Non-loopback laboratory peer")
            connection.settimeout(0.1)
            return connection
        except socket.timeout:
            continue


def _receive(
    connection: socket.socket, meter: _Meter, aborted: threading.Event, role: str
) -> bytes:
    body = bytearray()
    while True:
        meter.check(aborted)
        try:
            chunk = connection.recv(min(4096, RESPONSE_BYTE_CAP + 1 - len(body)))
        except socket.timeout:
            continue
        if not chunk:
            meter.check(aborted)
            with meter.lock:
                meter.reads.append(
                    {
                        "role": role,
                        "size": len(body),
                        "sha256": exchange.digest(bytes(body)),
                        "complete": True,
                    }
                )
            return bytes(body)
        body.extend(chunk)
        if len(body) > RESPONSE_BYTE_CAP:
            with meter.lock:
                meter.reads.append(
                    {
                        "role": role,
                        "size": len(body),
                        "sha256": exchange.digest(bytes(body)),
                        "complete": False,
                    }
                )
            raise egress.PolicyBlocked("Laboratory per-connection receive cap")


def _backend(
    listener: socket.socket,
    case: Case,
    meter: _Meter,
    state: dict,
    aborted: threading.Event,
) -> None:
    try:
        with _accept(listener, meter, aborted) as peer:
            raw = _receive(peer, meter, aborted, "backend-request")
            if raw != case.raw:
                raise ValueError("Unrelated laboratory backend stream")
            rows = _parse_requests(raw, case.backend_mode)
            state["backend"] = rows
            response = _response(rows, case.name)
            meter.send(
                peer, response, meter.plan.backend_url, "backend-to-front", aborted
            )
            peer.shutdown(socket.SHUT_WR)
    except (OSError, ValueError) as exc:
        state["backend_error"] = type(exc).__name__
        aborted.set()


def _frontend(
    listener: socket.socket,
    case: Case,
    meter: _Meter,
    state: dict,
    aborted: threading.Event,
) -> None:
    try:
        with _accept(listener, meter, aborted) as peer:
            raw = _receive(peer, meter, aborted, "front-request")
            if raw != case.raw:
                raise ValueError("Unrelated laboratory front stream")
            state["front"] = _parse_requests(raw, case.front_mode)
            with meter.connect(
                meter.plan.backend_url, "front-to-back", aborted
            ) as backend:
                meter.send(
                    backend, raw, meter.plan.backend_url, "front-to-back", aborted
                )
                backend.shutdown(socket.SHUT_WR)
                response = _receive(backend, meter, aborted, "front-response")
            state["front_responses"] = _parse_responses(response)
            meter.send(peer, response, meter.plan.front_url, "front-to-client", aborted)
            peer.shutdown(socket.SHUT_WR)
    except (OSError, ValueError) as exc:
        state["front_error"] = type(exc).__name__
        aborted.set()


def _run_case(
    front_listener: socket.socket,
    backend_listener: socket.socket,
    case: Case,
    meter: _Meter,
) -> dict:
    state = {
        "name": case.name,
        "marker_sha256": case.marker_sha256,
        "embedded_messages": case.embedded_messages,
        "raw_request": case.raw,
        "raw_response": b"",
    }
    aborted = threading.Event()
    threads = [
        threading.Thread(
            target=copy_context().run,
            args=(_backend, backend_listener, case, meter, state, aborted),
            daemon=True,
        ),
        threading.Thread(
            target=copy_context().run,
            args=(_frontend, front_listener, case, meter, state, aborted),
            daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    try:
        with meter.connect(meter.plan.front_url, "client-to-front", aborted) as client:
            meter.send(
                client, case.raw, meter.plan.front_url, "client-to-front", aborted
            )
            client.shutdown(socket.SHUT_WR)
            response = _receive(client, meter, aborted, "client-response")
        state["raw_response"] = response
        state["client_responses"] = _parse_responses(response)
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        state["client_error"] = type(exc).__name__
        aborted.set()
    for thread in threads:
        thread.join(timeout=0.5)
    if any(thread.is_alive() for thread in threads):
        aborted.set()
        for thread in threads:
            thread.join(timeout=0.5)
    state["threads_joined"] = all(not thread.is_alive() for thread in threads)
    if not state["threads_joined"]:
        state["client_error"] = "WorkerShutdownTimeout"
    return state


def _retain(capture, case: dict) -> dict:
    root = capture.root
    refs = {}
    for kind, key in (("request", "raw_request"), ("response", "raw_response")):
        raw = case.pop(key)
        name = f"{case['name']}-{kind}.bin"
        ledger._write_private(root / name, raw)
        refs[kind] = {
            "path": name,
            "size": len(raw),
            "sha256": exchange.digest(raw),
            "truncated": bool(
                case.get("client_error")
                or case.get("front_error")
                or case.get("backend_error")
            ),
        }
    capture.manifest.setdefault("raw_streams", {})[case["name"]] = refs
    return case


def _valid(samples: list[dict], meter: _Meter) -> bool:
    if len(samples) != 3 or any(
        any(key.endswith("_error") for key in row) or not row["threads_joined"]
        for row in samples
    ):
        return False
    fronts = [len(row["front"]) for row in samples]
    backs = [len(row["backend"]) for row in samples]
    clients = [len(row["client_responses"]) for row in samples]
    forwarded = [len(row["front_responses"]) for row in samples]
    if (
        fronts != [1, 1, 1]
        or backs != [1, 1, 2]
        or clients != [1, 1, 2]
        or forwarded != [1, 1, 2]
    ):
        return False
    for sample in samples:
        expected = _parse_responses(_response(sample["backend"], sample["name"]))
        if (
            sample["front_responses"] != expected
            or sample["client_responses"] != expected
        ):
            return False
    marker = samples[2]["backend"][1]["path"]
    return (
        marker.startswith(MARKER_PATH + "?nonce=")
        and exchange.digest(marker.rsplit("=", 1)[1].encode())
        == samples[2]["marker_sha256"]
        and len(meter.connections) == CONNECTION_CAP
        and len(meter.writes) == WRITE_CAP
        and len(meter.reads) == 12
        and all(row["complete"] for row in meter.reads)
        and all(row["connected"] for row in meter.connections)
        and all(row["complete"] for row in meter.writes)
    )


def _public_samples(samples: list[dict]) -> list[dict]:
    for sample in samples:
        for layer in ("front", "backend"):
            for observed in sample.get(layer, []):
                raw_path = observed["path"]
                observed["path_sha256"] = exchange.digest(raw_path.encode())
                observed["path"] = raw_path.split("?", 1)[0]
    return samples


def execute(plan: Plan, *, on_start=None) -> dict:
    exchange._write(plan.budget.stop_path().parent / "job.json", preview(plan))
    capture = ledger.begin(
        plan.profile,
        tool="desync",
        operation="active_scan",
        target=plan.front_url,
        request=exchange.canonical(preview(plan)),
        actor="default",
    )
    capture.manifest["representation"] = (
        "private raw desync streams; not normal HTTP exchange"
    )
    meter = _Meter(plan)
    listeners, samples, error = [], [], ""
    try:
        if on_start is not None:
            on_start(plan.budget.job_id)
        meter.check()
        listeners.append(_listener(plan.backend_port, meter))
        listeners.append(_listener(plan.front_port, meter))
        with egress.action(plan.front_url, "active_scan", "GET", check=meter.check):
            for case in _cases(plan):
                meter.check()
                sample = _retain(
                    capture, _run_case(listeners[1], listeners[0], case, meter)
                )
                samples.append(sample)
                if (
                    any(key.endswith("_error") for key in sample)
                    or not sample["threads_joined"]
                ):
                    error = "IncompleteOwnedCase"
                    break
    except (OSError, ValueError, KeyboardInterrupt) as exc:
        plan.budget.cancelled.set()
        error = type(exc).__name__
    finally:
        for listener in listeners:
            listener.close()
    complete = not error and _valid(samples, meter)
    samples = _public_samples(samples)
    result = {
        **preview(plan),
        "dry_run": False,
        "run_id": capture.manifest["run_id"],
        "classification": "observation" if complete else "invalid",
        "complete": complete,
        "samples": samples,
        "connections": meter.connections,
        "writes": meter.writes,
        "reads": meter.reads,
        "connection_count": len(meter.connections),
        "write_count": len(meter.writes),
        "outbound_bytes_reserved": meter.outbound_bytes,
        "generated_embedded_messages": sum(row["embedded_messages"] for row in samples),
        "cleanup": "listeners-closed; case-workers-joined"
        if all(row["threads_joined"] for row in samples)
        else "worker-shutdown-unconfirmed",
        "error": error,
    }
    saved_result = ledger.redact(result)
    capture.manifest["analysis"] = saved_result
    capture.manifest["result_sha256"] = exchange.digest(
        exchange.canonical(saved_result)
    )
    capture.manifest["cleanup"] = result["cleanup"]
    capture.finish(
        classification=result["classification"], complete=complete, error=error
    )
    exchange._write(plan.budget.stop_path().parent / "result.json", saved_result)
    return saved_result


def _verify_raw(run_id: str, manifest: dict, complete: bool) -> None:
    expected = {"baseline", "matched-cl-cl", "divergent-cl-te"}
    streams = manifest.get("raw_streams", {})
    if (
        not isinstance(streams, dict)
        or set(streams) - expected
        or (complete and set(streams) != expected)
    ):
        raise ValueError("Desync raw stream inventory changed")
    root = ledger.runs_dir() / run_id
    for case_name, refs in streams.items():
        if not isinstance(refs, dict) or set(refs) != {"request", "response"}:
            raise ValueError("Desync raw stream pair changed")
        for kind, evidence in refs.items():
            expected_name = f"{case_name}-{kind}.bin"
            maximum = WRITE_BYTE_CAP if kind == "request" else RESPONSE_BYTE_CAP
            if (
                not isinstance(evidence, dict)
                or evidence.get("path") != expected_name
                or type(evidence.get("size")) is not int
                or not 0 <= evidence["size"] <= maximum
            ):
                raise ValueError("Desync raw stream path or cap changed")
            path = root / expected_name
            if path.is_symlink() or path.resolve().parent != root.resolve():
                raise ValueError("Desync raw stream path escaped run")
            if path.stat().st_size != evidence["size"]:
                raise ValueError("Desync raw stream size changed")
            if hashlib.sha256(path.read_bytes()).hexdigest() != evidence.get("sha256"):
                raise ValueError("Desync raw stream hash mismatch")


def status(job_id: str) -> dict:
    if str(uuid.UUID(job_id)) != job_id:
        raise ValueError("Expected canonical job ID")
    root = workspace_dir() / "jobs" / job_id
    job_file = root / "job.json"
    if job_file.is_symlink() or not job_file.is_file():
        raise ValueError("Unknown desync job")
    result_file = root / "result.json"
    if not result_file.exists():
        return {
            "job_id": job_id,
            "status": "cancel_requested" if (root / "STOP").exists() else "running",
            "complete": False,
        }
    if result_file.is_symlink() or result_file.stat().st_size > ledger.CAPTURE_LIMIT:
        raise ValueError("Desync result path changed")
    result = exchange.load_json(result_file.read_bytes())
    if result.get("job_id") != job_id:
        raise ValueError("Desync job/result mismatch")
    manifest = ledger.manifest_for(result["run_id"])
    if (
        manifest.get("representation")
        != "private raw desync streams; not normal HTTP exchange"
    ):
        raise ValueError("Desync evidence representation changed")
    if (
        manifest.get("run_id") != result["run_id"]
        or manifest.get("analysis") != result
        or manifest.get("classification") != result.get("classification")
        or manifest.get("result_sha256") != exchange.digest(exchange.canonical(result))
    ):
        raise ValueError("Desync result/evidence mismatch")
    _verify_raw(result["run_id"], manifest, result.get("complete") is True)
    return ledger.redact(result)
