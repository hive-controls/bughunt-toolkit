"""Private, inert exchange records with stable content IDs and provenance."""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import tempfile
import uuid
from urllib.parse import urlsplit

from bughunt.core import ledger
from bughunt.core.policy import PolicyError, read_document, target_parts
from bughunt.core.workspace import allowed, workspace_dir

MESSAGE_LIMIT = 2 * 1024 * 1024
BODY_LIMIT = 1_000_000
INPUT_LIMIT = 16 * 1024 * 1024
ENTRY_LIMIT = 500
LEDGER_REPRESENTATION = "ledger-logical; transfer framing decoded; not wire bytes"
_REPRESENTATIONS = {
    "raw-http-capture",
    "har-logical; not wire bytes",
    "sanitized derivative",
    LEDGER_REPRESENTATION,
    "burp-exported-http; not wire bytes",
    "burp-sdk-text; incomplete; not wire bytes",
}
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_HASH = re.compile(r"[0-9a-f]{64}")
_CREDENTIAL = re.compile(r"cookie|auth|token|api[-_]?key|secret|session|csrf", re.I)
_VERSIONS = {"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0", "HTTP/3"}


class ExchangeError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_pairs(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExchangeError("Duplicate JSON field")
        result[key] = value
    return result


def load_json(data: bytes) -> object:
    if len(data) > INPUT_LIMIT:
        raise ExchangeError("Import exceeds 16 MiB")
    try:
        value = json.loads(data.decode("utf-8-sig"), object_pairs_hook=unique_pairs)
        canonical(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ExchangeError("Invalid or ambiguous JSON") from exc


def text(value: object, *, maximum: int = 4096, empty: bool = False) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or (not value and not empty)
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ExchangeError("Invalid metadata text")
    return value


def timestamp(value: object) -> str | None:
    if value is None:
        return None
    value = text(value, maximum=64)
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timezone missing")
    except ValueError as exc:
        raise ExchangeError("Timestamp needs an ISO timezone") from exc
    return value


def decode(value: object, maximum: int = MESSAGE_LIMIT) -> bytes:
    if not isinstance(value, str) or len(value) > 4 * ((maximum + 2) // 3):
        raise ExchangeError("Encoded capture exceeds its limit")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ExchangeError("Invalid base64 capture") from exc
    if len(raw) > maximum or base64.b64encode(raw).decode() != value:
        raise ExchangeError("Noncanonical base64 capture")
    return raw


def headers(value: object) -> list[list[str]]:
    if not isinstance(value, (list, tuple)) or len(value) > 1000:
        raise ExchangeError("Invalid header list")
    result = []
    for pair in value:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ExchangeError("Invalid header pair")
        name, current = pair
        if not isinstance(name, str) or not _TOKEN.fullmatch(name):
            raise ExchangeError("Invalid header name")
        current = text(current, maximum=65536, empty=True)
        if any(ord(char) > 255 for char in current):
            raise ExchangeError("Header cannot be encoded as HTTP text")
        result.append([name, current])
    if sum(len(name) + len(current) for name, current in result) > 65536:
        raise ExchangeError("Headers exceed 64 KiB")
    return result


def header_values(message: dict, name: str) -> list[str]:
    return [
        value
        for current, value in message["headers"]
        if current.lower() == name.lower()
    ]


def _split(raw: bytes) -> tuple[str, list[list[str]], bytes]:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MESSAGE_LIMIT:
        raise ExchangeError("Missing or oversized HTTP message")
    separators = [(raw.find(marker), marker) for marker in (b"\r\n\r\n", b"\n\n")]
    separators = [(index, marker) for index, marker in separators if index >= 0]
    if not separators:
        raise ExchangeError("HTTP message needs a header/body separator")
    index, marker = min(separators, key=lambda item: item[0])
    lines = raw[:index].decode("latin-1").splitlines()
    if not lines or not lines[0]:
        raise ExchangeError("HTTP message needs a first line")
    pairs = []
    for line in lines[1:]:
        if line[:1] in {" ", "\t"} or ":" not in line:
            raise ExchangeError("Ambiguous or folded HTTP header")
        name, value = line.split(":", 1)
        pairs.append([name, value.strip(" ")])
    return lines[0], headers(pairs), raw[index + len(marker) :]


def _framing(pairs: list, body: bytes, *, truncated: bool, no_body: bool) -> None:
    lengths = [value for name, value in pairs if name.lower() == "content-length"]
    if any(name.lower() == "transfer-encoding" for name, _value in pairs):
        raise ExchangeError("Decode transfer framing before importing raw HTTP")
    if len(lengths) > 1:
        raise ExchangeError("Duplicate HTTP length")
    if lengths:
        value = lengths[0]
        if not value.isascii() or not value.isdigit() or len(value) > 16:
            raise ExchangeError("Invalid HTTP length")
        size = int(value)
        if (no_body and body) or (
            not no_body and (size < len(body) or (size != len(body) and not truncated))
        ):
            raise ExchangeError("HTTP body length mismatch")


def _request_url(target: str, pairs: list, url: str | None) -> str:
    host_values = [value for name, value in pairs if name.lower() == "host"]
    if len(host_values) > 1:
        raise ExchangeError("Duplicate Host header")
    if target.startswith(("http://", "https://")):
        resolved = target
    elif target.startswith("/") and not target.startswith("//") and url is not None:
        parsed = urlsplit(url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        if path != target:
            raise ExchangeError("Explicit URL differs from captured target")
        resolved = url
    else:
        raise ExchangeError("Relative captures require an explicit full URL")
    parsed = urlsplit(resolved)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or any(char.isspace() for char in resolved)
    ):
        raise ExchangeError("Invalid HTTP capture URL")
    try:
        parsed.port
    except ValueError as exc:
        raise ExchangeError("Invalid capture port") from exc
    if url is not None and resolved != url:
        raise ExchangeError("Explicit URL differs from captured URL")
    return resolved


def message(
    raw: bytes,
    *,
    request: bool,
    url: str | None = None,
    truncated=False,
    representation="raw-http-capture",
    head_response=False,
) -> dict:
    if not isinstance(representation, str) or representation not in _REPRESENTATIONS:
        raise ExchangeError("Unknown capture representation")
    if type(truncated) is not bool:
        raise ExchangeError("Truncation must be explicit boolean")
    line, pairs, body = _split(raw)
    if len(body) > BODY_LIMIT:
        raise ExchangeError("Captured body exceeds 1000000 bytes")
    pieces = line.split(" ", 2)
    if len(pieces) != 3:
        raise ExchangeError("Invalid HTTP first line")
    result = {
        "first_line": line,
        "headers": pairs,
        "body_b64": base64.b64encode(body).decode(),
        "body_sha256": digest(body),
        "body_size": len(body),
        "truncated": truncated,
        "raw_b64": base64.b64encode(raw).decode(),
        "raw_sha256": digest(raw),
        "representation": representation,
    }
    if request:
        method, target, version = pieces
        if not re.fullmatch(r"[A-Z]+", method) or version not in _VERSIONS:
            raise ExchangeError("Unsupported HTTP request line")
        if (
            representation == "raw-http-capture"
            and version == "HTTP/1.1"
            and not any(name.lower() == "host" for name, _value in pairs)
        ):
            raise ExchangeError("Raw HTTP/1.1 request lacks Host")
        result.update(
            method=method, url=_request_url(target, pairs, url), http_version=version
        )
        no_body = False
    else:
        version, status, reason = pieces
        if (
            version not in _VERSIONS
            or not status.isascii()
            or not status.isdigit()
            or not 100 <= int(status) <= 599
        ):
            raise ExchangeError("Unsupported HTTP response line")
        result.update(
            http_version=version, status=int(status), reason=text(reason, empty=True)
        )
        no_body = head_response or int(status) in {204, 304} or int(status) < 200
    if no_body and body:
        raise ExchangeError("HTTP response forbids a body")
    if representation not in {"har-logical; not wire bytes", LEDGER_REPRESENTATION}:
        _framing(pairs, body, truncated=truncated, no_body=no_body)
    return result


def source(
    kind: str,
    source_id: str,
    source_hash: str,
    *,
    captured_at=None,
    actor: str | None = None,
    run_id: str | None = None,
) -> dict:
    if (
        not isinstance(kind, str)
        or kind not in {"raw", "har", "ledger", "burp"}
        or not isinstance(source_hash, str)
        or not _HASH.fullmatch(source_hash)
    ):
        raise ExchangeError("Invalid source identity/hash")
    if run_id is not None:
        try:
            if str(uuid.UUID(run_id)) != run_id:
                raise ValueError("noncanonical run ID")
        except (ValueError, TypeError) as exc:
            raise ExchangeError("Invalid source run ID") from exc
    return {
        "kind": kind,
        "source_id": text(source_id, maximum=512),
        "sha256": source_hash,
        "captured_at": timestamp(captured_at),
        "actor": text(actor, maximum=128) if actor is not None else None,
        "run_id": run_id,
        "claim": "source metadata; actor verification is not asserted",
    }


def scope_decision(request: dict) -> dict:
    result = {
        "permitted": False,
        "reason": "policy-missing-or-invalid",
        "mission": None,
        "policy_version": None,
        "policy_sha256": None,
        "policy_verified_at": None,
    }
    try:
        policy_path = workspace_dir() / "policy.json"
        _document, profile = read_document(policy_path)
        decision = profile.decide(request["url"], "passive", method=request["method"])
        result.update(
            permitted=decision.permitted,
            reason=decision.reason,
            mission=profile.mission,
            policy_version=profile.policy_version,
            policy_sha256=digest(policy_path.read_bytes()),
            policy_verified_at=profile.verified_at.isoformat(),
        )
        if not allowed(request["url"]):
            result.update(permitted=False, reason="workspace-scope-blocked")
        hosts = header_values(request, "host")
        if (
            hosts
            and target_parts(f"{urlsplit(request['url']).scheme}://{hosts[0]}/")[0]
            != target_parts(request["url"])[0]
        ):
            result.update(permitted=False, reason="captured-host-route-mismatch")
    except (PolicyError, OSError, ValueError):
        result.update(permitted=False, reason="policy-or-target-invalid")
    return result


def _content(value: dict | None) -> object:
    if value is None:
        return None
    fields = {
        name: value[name]
        for name in ("http_version", "body_sha256", "body_size", "truncated")
    }
    fields["headers"] = [[name.lower(), current] for name, current in value["headers"]]
    for name in ("method", "url", "status", "reason"):
        if name in value:
            fields[name] = value[name]
    return fields


def content_id(request: dict, response: dict | None) -> str:
    return digest(canonical([_content(request), _content(response)]))


def record(request: dict, response: dict | None, sources: list) -> dict:
    return {
        "schema_version": 1,
        "exchange_id": content_id(request, response),
        "inert": True,
        "request": request,
        "response": response,
        "sources": sources,
        "scope_history": [scope_decision(request)],
        "derivative_of": None,
    }


def raw_record(
    request_bytes: bytes,
    response_bytes: bytes | None,
    *,
    source_id: str,
    url=None,
    captured_at=None,
    actor=None,
    run_id=None,
    request_truncated=False,
    response_truncated=False,
    kind="raw",
    representation="raw-http-capture",
) -> dict:
    request = message(
        request_bytes,
        request=True,
        url=url,
        truncated=request_truncated,
        representation=representation,
    )
    response = (
        message(
            response_bytes,
            request=False,
            truncated=response_truncated,
            head_response=request["method"] == "HEAD",
            representation=representation,
        )
        if response_bytes is not None
        else None
    )
    source_hash = digest(
        canonical(
            [
                base64.b64encode(request_bytes).decode(),
                base64.b64encode(response_bytes).decode()
                if response_bytes is not None
                else None,
            ]
        )
    )
    provenance = source(
        kind,
        source_id,
        source_hash,
        captured_at=captured_at,
        actor=actor,
        run_id=run_id,
    )
    return record(request, response, [provenance])


def _validate_message(value: object, *, request: bool, head_response=False) -> dict:
    if not isinstance(value, dict):
        raise ExchangeError("Invalid exchange message")
    try:
        raw = decode(value["raw_b64"])
        if value["representation"] not in _REPRESENTATIONS:
            raise ExchangeError("Unknown capture representation")
        parsed = message(
            raw,
            request=request,
            url=value.get("url") if request else None,
            truncated=value["truncated"],
            representation=value["representation"],
            head_response=head_response,
        )
        if canonical(parsed) != canonical(value):
            raise ExchangeError("Capture fields or hashes differ from retained bytes")
        return parsed
    except (KeyError, TypeError) as exc:
        raise ExchangeError("Invalid capture schema") from exc


def validate(value: object) -> dict:
    fields = {
        "schema_version",
        "exchange_id",
        "inert",
        "request",
        "response",
        "sources",
        "scope_history",
        "derivative_of",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["inert"] is not True
    ):
        raise ExchangeError("Invalid exchange schema")
    request = _validate_message(value["request"], request=True)
    if value["response"] is not None:
        _validate_message(
            value["response"], request=False, head_response=request["method"] == "HEAD"
        )
    if value["exchange_id"] != content_id(request, value["response"]):
        raise ExchangeError("Exchange content ID mismatch")
    if (
        not isinstance(value["sources"], list)
        or not 0 < len(value["sources"]) <= ENTRY_LIMIT
    ):
        raise ExchangeError("Invalid exchange provenance")
    for item in value["sources"]:
        if not isinstance(item, dict) or set(item) != {
            "kind",
            "source_id",
            "sha256",
            "captured_at",
            "actor",
            "run_id",
            "claim",
        }:
            raise ExchangeError("Invalid source schema")
        if (
            source(
                item["kind"],
                item["source_id"],
                item["sha256"],
                captured_at=item["captured_at"],
                actor=item["actor"],
                run_id=item["run_id"],
            )
            != item
        ):
            raise ExchangeError("Invalid source claim")
    if (
        not isinstance(value["scope_history"], list)
        or not 0 < len(value["scope_history"]) <= ENTRY_LIMIT
    ):
        raise ExchangeError("Invalid scope history")
    for decision in value["scope_history"]:
        if (
            not isinstance(decision, dict)
            or set(decision) != set(scope_decision(request))
            or type(decision["permitted"]) is not bool
        ):
            raise ExchangeError("Invalid scope decision")
        for name in (
            "reason",
            "mission",
            "policy_version",
            "policy_sha256",
            "policy_verified_at",
        ):
            if decision[name] is not None:
                text(decision[name])
    if value["derivative_of"] is not None and (
        not isinstance(value["derivative_of"], str)
        or not _HASH.fullmatch(value["derivative_of"])
    ):
        raise ExchangeError("Invalid derivative source ID")
    return value


def directory() -> Path:
    return workspace_dir() / "exchanges"


def _path(exchange_id: str) -> Path:
    if not isinstance(exchange_id, str) or not _HASH.fullmatch(exchange_id):
        raise ExchangeError("Expected a canonical exchange ID")
    return directory() / f"{exchange_id}.json"


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(canonical(value) + b"\n")
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read(exchange_id: str) -> dict:
    return validate(load_json(_path(exchange_id).read_bytes()))


def _union(*groups: list) -> list:
    indexed = {canonical(item): item for group in groups for item in group}
    return [indexed[key] for key in sorted(indexed)]


def _retain_capture(path: Path, value: object) -> None:
    from bughunt.core import execution_receipts, pipeline_context

    size = len(canonical(value)) + 1
    governor = pipeline_context.current()
    if governor is not None:
        governor.retain(size)
    _write(path, value)
    execution_receipts.retain(path, size)


def save(
    records: list[dict], *, source_id: str, source_bytes: bytes, kind: str
) -> list[str]:
    if not records or len(records) > ENTRY_LIMIT or len(source_bytes) > INPUT_LIMIT:
        raise ExchangeError("Invalid import batch size")
    receipt = {
        "source_id": text(source_id, maximum=512),
        "source_sha256": digest(source_bytes),
        "format": text(kind),
        "inert": True,
        "exchange_ids": [],
    }
    pending = {}
    for value in records:
        validate(value)
        exchange_id = value["exchange_id"]
        existing = pending.get(exchange_id)
        if existing is None and _path(exchange_id).exists():
            existing = read(exchange_id)
        merged = json.loads(canonical(existing or value))
        merged["sources"] = _union(merged["sources"], value["sources"])
        merged["scope_history"] = _union(
            merged["scope_history"],
            value["scope_history"],
            [scope_decision(value["request"])],
        )
        validate(merged)
        pending[exchange_id] = merged
    receipt["exchange_ids"] = sorted(pending)
    for exchange_id, value in pending.items():
        _retain_capture(_path(exchange_id), value)
    _retain_capture(
        directory() / "receipts" / f"{digest(canonical(receipt))}.json", receipt
    )
    return sorted(pending)


def summary(value: dict) -> dict:
    validate(value)
    request, response = value["request"], value["response"]
    return ledger.redact(
        {
            "exchange_id": value["exchange_id"],
            "inert": True,
            "method": request["method"],
            "url": request["url"],
            "status": response["status"] if response else None,
            "request_sha256": request["raw_sha256"],
            "response_sha256": response["raw_sha256"] if response else None,
            "truncated": request["truncated"]
            or bool(response and response["truncated"]),
            "sources": value["sources"],
            "scope_history": value["scope_history"],
            "current_scope": scope_decision(request),
        }
    )


def _render(first_line: str, pairs: list, body: bytes) -> bytes:
    pairs = [
        pair
        for pair in pairs
        if pair[0].lower() not in {"content-length", "transfer-encoding"}
    ]
    pairs.append(["Content-Length", str(len(body))])
    head = (
        first_line
        + "\r\n"
        + "".join(f"{name}: {value}\r\n" for name, value in pairs)
        + "\r\n"
    )
    return head.encode("latin-1") + body


def _safe_message(original: dict) -> tuple[str, list, bytes]:
    line, pairs, body = _split(decode(original["raw_b64"]))
    line = ledger.redact_text(line)
    pairs = [
        [name, "[REDACTED]" if _CREDENTIAL.search(name) else ledger.redact_text(value)]
        for name, value in pairs
    ]
    encoding = header_values(original, "content-encoding")
    try:
        decoded = body.decode("utf-8")
        readable = not any(ord(char) < 32 and char not in "\r\n\t" for char in decoded)
    except UnicodeError:
        readable = False
    if body and (
        not readable or any(value.lower() != "identity" for value in encoding)
    ):
        body = b"[REDACTED binary or encoded body]"
        pairs = [pair for pair in pairs if pair[0].lower() != "content-encoding"]
    else:
        body = ledger.redact_bytes(body)
    return line, pairs, body


def project(value: dict, *, private: bool = False) -> dict:
    validate(value)
    if type(private) is not bool:
        raise ExchangeError("Private export must be an explicit boolean")
    if private:
        return json.loads(canonical(value))
    messages = []
    for original in (value["request"], value["response"]):
        if original is None:
            messages.append(None)
            continue
        line, pairs, body = _safe_message(original)
        url = ledger.redact_text(original["url"]) if "url" in original else None
        rendered = _render(line, pairs, body)
        messages.append(
            message(
                rendered,
                request=url is not None,
                url=url,
                truncated=original["truncated"],
                representation="sanitized derivative",
                head_response=value["request"]["method"] == "HEAD",
            )
        )
    result = record(messages[0], messages[1], ledger.redact(value["sources"]))
    result["scope_history"] = ledger.redact(value["scope_history"])
    result["derivative_of"] = value["derivative_of"] or value["exchange_id"]
    return validate(result)


def from_run(run_id: str) -> dict:
    manifest = ledger.manifest_for(run_id)
    representation = manifest.get("representation")
    snare_capture = (
        representation == "raw-http capture" and manifest.get("tool") == "snare"
    )
    if representation != "logical-http; not a wire-byte claim" and not snare_capture:
        raise ExchangeError("Run has no complete HTTP exchange representation")
    root = ledger.runs_dir() / run_id
    retained = []
    for name in ("request", "response"):
        evidence = manifest.get(name)
        if not evidence:
            raise ExchangeError("Run lacks an HTTP request or response")
        raw = (root / f"{name}.http").read_bytes()
        if digest(raw) != evidence["sha256"]:
            raise ExchangeError("Ledger evidence hash mismatch")
        retained.append(raw)
    return raw_record(
        *retained,
        source_id=run_id,
        url=manifest["target"],
        captured_at=manifest["started_at"],
        actor=manifest["actor"],
        run_id=run_id,
        request_truncated=manifest["request"]["truncated"],
        response_truncated=manifest["response"]["truncated"],
        kind="ledger",
        representation=LEDGER_REPRESENTATION,
    )
