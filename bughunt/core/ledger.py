"""Private run evidence and sanitized console/export views."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
import hashlib
import json
from pathlib import Path
import platform
import re
import sys
import threading
import uuid
from urllib.parse import quote, quote_plus, urlsplit, urlunsplit

from bughunt.core.workspace import workspace_dir

CAPTURE_LIMIT = 1_000_000
CURRENT_TOOL = ContextVar("bughunt_tool", default="httpx")
_RECEIPTS = ContextVar("bughunt_receipts", default=())
_secrets: dict[str, set[str]] = {}
_nonpersistent_secrets: dict[str, set[str]] = {}
_lock = threading.RLock()
_CREDENTIAL_NAME = (
    r"cookie|set-cookie|authorization|proxy-authorization|auth-key|"
    r"x-api-key|api[_-]?key|access_token|refresh_token|token|password|"
    r"secret|client_secret|credentials?|auth|session(?:[_-]?(?:id|token))?|"
    r"csrf(?:[_-]?token)?|xsrf(?:[_-]?token)?|x-csrf-token|x-xsrf-token"
)
_HEADER = re.compile(rf"(?im)^((?:{_CREDENTIAL_NAME})\s*(?::|=>))\s*[^\r\n]*")
_KEY = re.compile(
    rf'(?i)((?:["\x27]?(?:{_CREDENTIAL_NAME})["\x27]?)\s*[:=]\s*)'
    r'(["\x27][^"\x27\r\n]*["\x27]|[^\s&;,}\r\n]+)'
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?P<key_type>[^\r\n-]*PRIVATE KEY)-----.*?(?:-----END (?P=key_type)-----|\Z)",
    re.S,
)
_PROXY = re.compile(r"(https?://)[^/@\s]+@", re.I)


def remember_secret(value: str, *, redact_at_rest: bool = False) -> None:
    if value:
        with _lock:
            mission = str(workspace_dir().resolve())
            _secrets.setdefault(mission, set()).add(value)
            if redact_at_rest:
                _nonpersistent_secrets.setdefault(mission, set()).add(value)


def _persistent_bytes(data: bytes) -> bytes:
    with _lock:
        values = tuple(
            _nonpersistent_secrets.get(str(workspace_dir().resolve()), set())
        )
    for value in sorted(values, key=len, reverse=True):
        renderings = {
            value,
            quote(value, safe=""),
            quote_plus(value),
            json.dumps(value, ensure_ascii=True)[1:-1],
            json.dumps(value, ensure_ascii=False)[1:-1],
        }
        for rendered in sorted(renderings, key=len, reverse=True):
            data = data.replace(rendered.encode("utf-8"), b"[REDACTED]")
    return data


def _persistent_url(value: str) -> str:
    parts = urlsplit(value)
    authority = parts.netloc
    if "@" in authority:
        userinfo, host = authority.rsplit("@", 1)
        authority = _persistent_bytes(userinfo.encode()).decode() + "@" + host
    query = []
    for parameter in parts.query.split("&"):
        name, separator, content = parameter.partition("=")
        query.append(
            name + separator + _persistent_bytes(content.encode()).decode()
            if separator
            else _persistent_bytes(name.encode()).decode()
        )
    updated = parts._replace(
        netloc=authority,
        path=_persistent_bytes(parts.path.encode()).decode(),
        query="&".join(query),
        fragment=_persistent_bytes(parts.fragment.encode()).decode(),
    )
    return value if updated == parts else urlunsplit(updated)


def _persistent_http(data: bytes) -> bytes:
    if _persistent_bytes(data) == data:
        return data
    newline = b"\r\n" if b"\r\n" in data else b"\n"
    head, separator, body = data.partition(newline * 2)
    lines = head.split(newline)
    start = lines[0].split(b" ", 2)
    if len(start) != 3:
        return _persistent_bytes(data)
    if start[2].startswith(b"HTTP/"):
        start[1] = _persistent_url(start[1].decode("latin-1")).encode("latin-1")
    elif start[0].startswith(b"HTTP/"):
        start[2] = _persistent_bytes(start[2])
    else:
        return _persistent_bytes(data)
    headers = []
    for line in lines[1:]:
        name, colon, value = line.partition(b":")
        if colon and name.lower() not in {
            b"host",
            b"content-length",
            b"transfer-encoding",
        }:
            line = name + colon + _persistent_bytes(value)
        headers.append(line)
    return (
        newline.join([b" ".join(start), *headers]) + separator + _persistent_bytes(body)
    )


def _persistent_metadata(value):
    """Sanitize URLs and diagnostics without rewriting evidence references or schema values."""
    if isinstance(value, dict):
        return {
            key: _persistent_url(item)
            if key in {"target", "url"} and isinstance(item, str)
            else _persistent_bytes(item.encode("utf-8")).decode("utf-8")
            if key in {"error", "reason"} and isinstance(item, str)
            else _persistent_metadata(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_persistent_metadata(item) for item in value]
    return value


def _patterns() -> set[str]:
    from bughunt.core import identity, verification
    from bughunt.core.session import load_legacy_session, load_session

    values = set(load_session().values())
    values.update(load_legacy_session().values())
    values.update(identity.all_secret_values())
    values.update(verification.all_private_values())
    with _lock:
        values.update(_secrets.get(str(workspace_dir().resolve()), set()))
    path = workspace_dir() / "redaction.json"
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(data, dict)
            or set(data) != {"patterns"}
            or not isinstance(data["patterns"], list)
            or any(
                not isinstance(value, str) or not value for value in data["patterns"]
            )
        ):
            raise ValueError("Invalid redaction patterns; sanitized output blocked")
        values.update(data["patterns"])
    return values


def redact_text(text: str) -> str:
    result = _PRIVATE_KEY.sub("[REDACTED PRIVATE KEY]", text)
    result = _PROXY.sub(r"\1[REDACTED]@", result)
    result = _HEADER.sub(r"\1 [REDACTED]", result)

    def replacement(match):
        value = match.group(2)
        quote = value[0] if value[0] in "\"'" else ""
        return match.group(1) + quote + "[REDACTED]" + quote

    result = _KEY.sub(replacement, result)
    for value in sorted(_patterns(), key=len, reverse=True):
        result = result.replace(value, "[REDACTED]")
    return result


def redact(value):
    if isinstance(value, dict):
        return {
            key: (
                "[REDACTED]"
                if re.fullmatch(_CREDENTIAL_NAME, str(key), re.I)
                else redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [redact(item) for item in value]
    return redact_text(value) if isinstance(value, str) else value


def redact_bytes(data: bytes) -> bytes:
    text = redact_text(data.decode("latin-1"))
    for secret in _patterns():
        text = text.replace(secret.encode("utf-8").decode("latin-1"), "[REDACTED]")
    return text.encode("latin-1", errors="replace")


def runs_dir() -> Path:
    return workspace_dir() / "runs"


def _write_private(path: Path, data: bytes) -> None:
    from bughunt.core import execution_receipts

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    execution_receipts.retain(path, len(data))
    path.chmod(0o600)


def _write_manifest(path: Path, data: bytes) -> None:
    original = json.loads(data)
    sanitized = _persistent_metadata(original)
    if sanitized != original:
        data = json.dumps(sanitized, indent=2).encode()
    _write_private(path, data)
    for receipts in _RECEIPTS.get():
        identifier = original.get("run_id")
        if identifier is not None and identifier not in receipts:
            receipts.append(identifier)


@contextmanager
def collect_runs():
    receipts = []
    token = _RECEIPTS.set((*_RECEIPTS.get(), receipts))
    try:
        yield receipts
    finally:
        _RECEIPTS.reset(token)


def record_route_optout(point: str) -> str:
    """Persist a local route bypass decision without requiring policy or HTTP evidence."""
    if point not in {"console", "proxy_scan", "tooling_launcher"}:
        raise ValueError("Invalid route protection point")
    run_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "tool": "bughunt",
        "operation": "route_gate",
        "decision": "operator-optout",
        "classification": "observation",
        "representation": "local-route-optout; no HTTP capture",
        "started_at": timestamp,
        "finished_at": timestamp,
        "route_gate": {"point": point, "disabled_by": "BUGHUNT_ALLOW_NO_ROUTE=1"},
        "request": None,
        "response": None,
    }
    _write_manifest(
        runs_dir() / run_id / "manifest.json", json.dumps(manifest, indent=2).encode()
    )
    return run_id


def _evidence(path: Path, data: bytes, truncated: bool, *, charged: int = 0) -> dict:
    persisted = _persistent_http(data)
    _retain_pipeline_bytes(max(0, len(persisted) - charged))
    _write_private(path, persisted)
    evidence = {
        "path": path.name,
        "sha256": hashlib.sha256(persisted).hexdigest(),
        "size": len(persisted),
        "truncated": truncated,
    }
    if persisted != data:
        evidence["sanitized_at_rest"] = True
    return evidence


def _retain_pipeline_bytes(amount):
    from bughunt.core.pipeline_context import current

    governor = current()
    if governor is not None:
        governor.retain(amount)


@dataclass
class Capture:
    root: Path
    manifest: dict
    response_prefix: bytes = b""
    body: bytearray = field(default_factory=bytearray)
    truncated: bool = False
    finished: bool = False

    def feed(self, chunk: bytes) -> None:
        if self.manifest.get("representation") == "identity-verification-metadata":
            return
        remaining = max(0, CAPTURE_LIMIT - len(self.body))
        _retain_pipeline_bytes(min(len(chunk), remaining))
        self.body.extend(chunk[:remaining])
        self.truncated |= len(chunk) > remaining

    def finish(
        self,
        *,
        classification: str = "observation",
        complete: bool = True,
        error: str = "",
    ) -> None:
        if self.finished:
            return
        self.finished = True
        if self.response_prefix:
            data = self.response_prefix + bytes(self.body)
            self.manifest["response"] = _evidence(
                self.root / "response.http",
                data,
                self.truncated or not complete,
                charged=len(self.body),
            )
        self.manifest.update(
            classification=classification,
            error=redact_text(error) if error else "",
            finished_at=datetime.now(timezone.utc).isoformat(),
        )
        _write_manifest(
            self.root / "manifest.json", json.dumps(self.manifest, indent=2).encode()
        )


def begin(
    profile,
    *,
    tool: str,
    operation: str,
    target: str,
    request: bytes,
    actor: str = "default",
    truncated: bool = False,
) -> Capture:
    _retain_pipeline_bytes(min(len(request), CAPTURE_LIMIT))
    run_id = str(uuid.uuid4())
    root = runs_dir() / run_id
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "mission": profile.mission,
        "policy_version": profile.policy_version,
        "policy_source": profile.source,
        "policy_verified_at": profile.verified_at.isoformat(),
        "actor": actor,
        "environment": {
            "platform": platform.system(),
            "python": platform.python_version(),
        },
        "tool": tool,
        "operation": operation,
        "target": target,
        "decision": "permitted",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "classification": "in_progress",
        "cleanup": "pending",
        "representation": "logical-http; not a wire-byte claim",
        "request": _evidence(
            root / "request.http",
            request[:CAPTURE_LIMIT],
            truncated or len(request) > CAPTURE_LIMIT,
            charged=min(len(request), CAPTURE_LIMIT),
        ),
        "response": None,
    }
    _write_manifest(root / "manifest.json", json.dumps(manifest, indent=2).encode())
    return Capture(root, manifest)


def begin_http(profile, request, operation: str) -> Capture:
    import httpx

    for name, value in request.headers.items():
        if re.search(r"(?i)cookie|authorization|auth-key|api-key", name):
            remember_secret(value)
    try:
        body = request.content
        truncated = False
    except httpx.RequestNotRead:
        body, truncated = b"", True
    head = f"{request.method} {request.url} HTTP/1.1\r\n"
    head += "".join(
        f"{name}: {value}\r\n" for name, value in request.headers.multi_items()
    )
    capture = begin(
        profile,
        tool=CURRENT_TOOL.get(),
        operation=operation,
        target=str(request.url),
        request=head.encode() + b"\r\n" + body,
        actor=request.extensions.get("bughunt_actor_snapshot", ("", "default", ""))[1],
        truncated=truncated,
    )
    verification_run_id = request.extensions.get("bughunt_verification_run_id")
    if verification_run_id:
        capture.manifest["verification_run_id"] = verification_run_id
        _write_manifest(
            capture.root / "manifest.json",
            json.dumps(capture.manifest, indent=2).encode(),
        )
    return capture


def begin_verification_probe(profile, request, operation: str) -> Capture:
    actor = request.extensions.get("bughunt_actor_snapshot", ("", "default", ""))[1]
    metadata = {
        "method": request.method,
        "url": str(request.url),
        "header_names": sorted(request.headers.keys()),
    }
    capture = begin(
        profile,
        tool=CURRENT_TOOL.get(),
        operation=operation,
        target=str(request.url),
        request=json.dumps(metadata).encode(),
        actor=actor,
    )
    capture.manifest["representation"] = "identity-verification-metadata"
    capture.manifest["verification_result"] = {"passed": None}
    _write_manifest(
        capture.root / "manifest.json", json.dumps(capture.manifest, indent=2).encode()
    )
    return capture


def finish_verification_probe(
    run_id: str, *, passed: bool, status: int, size: int, sha256: str, reason: str
) -> None:
    manifest = manifest_for(run_id)
    if manifest.get("representation") != "identity-verification-metadata":
        raise ValueError("Run is not an identity verification probe")
    manifest["verification_result"] = {
        "passed": passed,
        "status": status,
        "size": size,
        "sha256": sha256,
        "reason": reason if not passed else "verified",
    }
    manifest["classification"] = "observation" if passed else "invalid"
    _write_manifest(
        runs_dir() / run_id / "manifest.json", json.dumps(manifest, indent=2).encode()
    )


def invalid_verification_attempt(profile, request, actor: str, reason: str) -> str:
    url = str(request.url)
    parsed = urlsplit(url)
    safe_target = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    metadata = {
        "method": request.method,
        "target_sha256": hashlib.sha256(url.encode()).hexdigest(),
    }
    capture = begin(
        profile,
        tool=CURRENT_TOOL.get(),
        operation="manual",
        target=safe_target,
        request=json.dumps(metadata).encode(),
        actor=actor,
    )
    capture.manifest["representation"] = "identity-verification-decision"
    capture.manifest["verification_result"] = {"passed": False, "reason": reason}
    capture.finish(classification="invalid")
    return capture.manifest["run_id"]


def response_head(response) -> bytes:
    head = f"HTTP/1.1 {response.status_code} {response.reason_phrase}\r\n"
    head += "".join(
        f"{name}: {value}\r\n" for name, value in response.headers.multi_items()
    )
    return head.encode() + b"\r\n"


def manifest_for(run_id: str) -> dict:
    canonical = str(uuid.UUID(run_id))
    if run_id != canonical:
        raise ValueError("Expected a canonical run ID")
    return json.loads(
        (runs_dir() / run_id / "manifest.json").read_text(encoding="utf-8")
    )


def _artifact_name(name: object) -> str:
    if (
        not isinstance(name, str)
        or name == "manifest.json"
        or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}\.json", name)
    ):
        raise ValueError("Invalid imported artifact name")
    return name


def record_import(
    *, tool: str, metadata: dict, artifacts: dict[str, bytes], classification=None
) -> str:
    """Retain inert JSON source evidence; never reuse an outbound permission claim."""
    from bughunt.core import exchange

    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", tool) or not isinstance(
        metadata, dict
    ):
        raise ValueError("Invalid import metadata")
    count = metadata.get("observation_count")
    if type(count) is not int or not 0 <= count <= 5000:
        raise ValueError("Invalid imported observation count")
    classification = (
        classification
        if classification is not None
        else ("hypothesis" if count else "observation")
    )
    if classification not in {"hypothesis", "observation", "invalid"}:
        raise ValueError("Imported evidence cannot claim confirmed impact")
    snapshot = metadata.get("policy_snapshot", {})
    if not isinstance(snapshot, dict):
        raise ValueError("Invalid imported policy snapshot")
    encoded = exchange.canonical(metadata)
    if (
        len(encoded) > CAPTURE_LIMIT
        or not isinstance(artifacts, dict)
        or not 1 <= len(artifacts) <= 4
    ):
        raise ValueError("Oversized import metadata or artifact batch")
    if any(
        not isinstance(data, bytes) or len(data) > exchange.INPUT_LIMIT
        for data in artifacts.values()
    ):
        raise ValueError("Oversized or invalid imported evidence")
    if sum(len(data) for data in artifacts.values()) > 2 * exchange.INPUT_LIMIT:
        raise ValueError("Imported evidence exceeds batch bound")
    for name, data in artifacts.items():
        _artifact_name(name)
        exchange.load_json(data)
    redact(metadata)
    run_id = str(uuid.uuid4())
    root = runs_dir() / run_id
    now = datetime.now(timezone.utc).isoformat()
    evidence = {
        name: _evidence(root / name, data, False) for name, data in artifacts.items()
    }
    manifest = {
        "schema_version": 1,
        "run_id": run_id,
        "tool": tool,
        "operation": "import",
        "target": "external:" + tool,
        "actor": "unverified-source",
        "decision": "inert-import",
        "mission": snapshot.get("mission"),
        "policy_version": snapshot.get("policy_version"),
        "policy_verified_at": snapshot.get("policy_verified_at"),
        "policy_sha256": snapshot.get("policy_sha256"),
        "policy_source": None,
        "environment": {
            "platform": platform.system(),
            "python": platform.python_version(),
        },
        "started_at": now,
        "finished_at": now,
        "cleanup": "pending",
        "error": "",
        "classification": classification,
        "representation": "external-json-observations; not HTTP capture",
        "request": None,
        "response": None,
        "artifacts": evidence,
        "import_metadata": metadata,
        "claim": "Imported data is not execution authority or validated impact",
    }
    _write_manifest(root / "manifest.json", exchange.canonical(manifest) + b"\n")
    return run_id


def record_analysis(
    profile,
    *,
    tool: str,
    operation: str,
    target: str,
    actor: str,
    value: dict,
    classification: str,
) -> str:
    """A bounded local summary links real request runs; it is not an HTTP exchange."""
    from bughunt.core import exchange

    encoded = exchange.canonical(value)
    if len(encoded) > CAPTURE_LIMIT or classification not in {
        "lead",
        "negative",
        "invalid",
        "inconclusive",
        "observation",
    }:
        raise ValueError("Invalid analysis summary")
    redact(value)
    capture = begin(
        profile,
        tool=tool,
        operation=operation,
        target=target,
        request=encoded,
        actor=actor,
    )
    capture.manifest.update(
        representation="local-analysis; linked request runs, not HTTP capture",
        analysis=value,
    )
    capture.finish(classification=classification)
    return capture.manifest["run_id"]


def _export_artifacts(root: Path, artifacts: object) -> dict:
    from bughunt.core import exchange

    if not isinstance(artifacts, dict) or len(artifacts) > 4:
        raise ValueError("Invalid imported artifact manifest")
    results = {}
    for name, evidence in artifacts.items():
        name = _artifact_name(name)
        if not isinstance(evidence, dict) or evidence.get("path") != name:
            raise ValueError("Invalid imported artifact path")
        path = root / name
        if path.is_symlink() or path.resolve().parent != root.resolve():
            raise ValueError("Imported artifact path differs from run")
        with path.open("rb") as handle:
            raw = handle.read(exchange.INPUT_LIMIT + 1)
        if (
            len(raw) > exchange.INPUT_LIMIT
            or len(raw) != evidence.get("size")
            or hashlib.sha256(raw).hexdigest() != evidence.get("sha256")
        ):
            raise ValueError("Imported evidence hash or size mismatch; export blocked")
        value = redact(exchange.load_json(raw))
        results[name] = {
            "value": value,
            "original_sha256": evidence["sha256"],
            "sanitized_sha256": hashlib.sha256(exchange.canonical(value)).hexdigest(),
            "claim": "Sanitized source artifact; source assertions are not validation",
        }
    return results


def export_run(run_id: str) -> dict:
    manifest = manifest_for(run_id)
    if manifest.get("representation") == "managed-engine-job; linked request runs":
        from bughunt.core import job

        job.verify_engine_evidence(manifest)
    root = runs_dir() / run_id
    result = {"manifest": redact(manifest), "captures": {}}
    for kind in ("request", "response"):
        evidence = manifest.get(kind)
        if evidence:
            path = root / f"{kind}.http"
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != evidence["sha256"]:
                raise ValueError("Evidence hash mismatch; export blocked")
            text = redact_text(raw.decode("utf-8", errors="replace"))
            result["captures"][kind] = {
                "text": text,
                "sanitized_sha256": hashlib.sha256(text.encode()).hexdigest(),
                "original_sha256": evidence["sha256"],
                "truncated": evidence["truncated"],
            }
    if "artifacts" in manifest:
        result["artifacts"] = _export_artifacts(root, manifest["artifacts"])
    return result


class _Output:
    def __init__(self, stream):
        self.stream, self.pending = stream, ""
        self.private_key = False

    def write(self, text: str) -> int:
        self.pending += text
        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            if re.search(r"-----BEGIN [^-]*PRIVATE KEY-----", line):
                self.private_key = True
                self.stream.write("[REDACTED PRIVATE KEY]\n")
            if self.private_key:
                if re.search(r"-----END [^-]*PRIVATE KEY-----", line):
                    self.private_key = False
                continue
            self.stream.write(redact_text(line) + "\n")
        return len(text)

    def flush(self) -> None:
        if self.pending:
            if re.search(r"-----BEGIN [^-]*PRIVATE KEY-----", self.pending):
                self.private_key = True
                self.stream.write("[REDACTED PRIVATE KEY]")
            if not self.private_key:
                self.stream.write(redact_text(self.pending))
            self.pending = ""
        self.stream.flush()

    def __getattr__(self, name):
        if name == "buffer":
            return _ByteOutput(self)
        return getattr(self.stream, name)


class _ByteOutput:
    def __init__(self, output):
        self.output = output

    def write(self, data: bytes) -> int:
        self.output.write(redact_bytes(data).decode("latin-1"))
        return len(data)

    def flush(self) -> None:
        self.output.flush()


@contextmanager
def sanitized_output():
    from bughunt.console import ui

    old_out, old_err, old_console = sys.stdout, sys.stderr, ui.console._file
    output, errors = _Output(old_out), _Output(old_err)
    console_output = (
        output
        if old_console is None or old_console is old_out
        else _Output(old_console)
    )
    sys.stdout, sys.stderr, ui.console._file = output, errors, console_output
    try:
        yield
    finally:
        try:
            output.flush()
            errors.flush()
            if console_output is not output:
                console_output.flush()
        finally:
            sys.stdout, sys.stderr, ui.console._file = old_out, old_err, old_console


def sanitized(function):
    @wraps(function)
    def run(*args, **kwargs):
        token = CURRENT_TOOL.set("bughunt")
        try:
            with sanitized_output():
                return function(*args, **kwargs)
        finally:
            CURRENT_TOOL.reset(token)

    return run
