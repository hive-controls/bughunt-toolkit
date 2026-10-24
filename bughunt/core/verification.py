"""Bounded, private server-side actor checks before discriminating requests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tempfile
import threading
import time
import uuid

import httpx

from bughunt.core import identity, ledger
from bughunt.core.policy import PolicyError, target_parts
from bughunt.core.workspace import allowed, workspace_dir

_FIELDS = {"schema_version", "name", "url", "principal_path", "expected_principal",
           "role_path", "expected_role", "expected_status", "max_bytes",
           "timeout_seconds", "ttl_seconds"}
_OPTIONAL_FIELDS = {"role_contains"}
_FIELD_PATH = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_-]{0,63}){0,7}")
_proofs: dict[str, tuple] = {}
_probe_proofs: dict[str, tuple] = {}
_proof_lock = threading.Lock()


class VerificationError(ValueError):
    """A failed identity assertion that prevents the next request."""


def require_workspace_scope(target: str) -> None:
    if not allowed(target):
        raise VerificationError("workspace-scope-blocked")


def require_verification_origin(target: str, configuration: dict) -> None:
    try:
        if target_parts(target)[0] != target_parts(configuration["url"])[0]:
            raise VerificationError("verification-origin-mismatch")
    except PolicyError as exc:
        raise VerificationError("verification-origin-mismatch") from exc


def _path(name: str) -> Path:
    try:
        identity.read_profile(name)
    except identity.IdentityError as exc:
        raise VerificationError("actor-invalid") from exc
    return workspace_dir() / "identities" / "verification" / f"{name}.json"


def _canonical_url(url: str, origins: list[str]) -> str:
    try:
        origin, path = target_parts(url)
    except (PolicyError, TypeError) as exc:
        raise VerificationError("verification-url-invalid") from exc
    if url != origin + path or origin not in origins:
        raise VerificationError("verification-url-invalid")
    return url


def _bounded_text(value: object, limit: int) -> bool:
    return (isinstance(value, str) and 0 < len(value) <= limit and value == value.strip()
            and all(ord(character) >= 32 and ord(character) != 127 for character in value))


def _bounded_role(value: object) -> bool:
    return _bounded_text(value, 128) or (type(value) is int and 0 <= value < 2 ** 53)


def _validated(value: object, name: str) -> dict:
    if not isinstance(value, dict) or not _FIELDS <= set(value) <= _FIELDS | _OPTIONAL_FIELDS:
        raise VerificationError("configuration-invalid")
    if "role_contains" in value and type(value["role_contains"]) is not bool:
        raise VerificationError("configuration-invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["name"] != name:
        raise VerificationError("configuration-invalid")
    actor = identity.read_profile(name)
    _canonical_url(value["url"], actor["origins"])
    numbers = (("max_bytes", 0, 65536), ("timeout_seconds", 0, 30), ("ttl_seconds", 0, 30))
    for field, minimum, maximum in numbers:
        number = value[field]
        if type(number) not in {int, float} or not minimum < number <= maximum:
            raise VerificationError("configuration-invalid")
    if type(value["max_bytes"]) is not int or type(value["expected_status"]) is not int:
        raise VerificationError("configuration-invalid")
    if actor["kind"] == "anonymous":
        if (value["expected_status"] != 401 or value.get("role_contains")
                or any(value[field] is not None for field in
                       ("principal_path", "expected_principal", "role_path", "expected_role"))):
            raise VerificationError("configuration-invalid")
    elif (value["expected_status"] != 200
          or not _bounded_text(value["expected_principal"], 256)
          or not _bounded_role(value["expected_role"]) or not all(
            isinstance(value[field], str) and _FIELD_PATH.fullmatch(value[field])
            for field in ("principal_path", "role_path"))):
        raise VerificationError("configuration-invalid")
    return value


def _write_private(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix="verification-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(document, handle, indent=2)
            handle.write("\n")
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def configure(name, url, principal_path, expected_principal, role_path, expected_role,
              *, expected_status=200, max_bytes=65536, timeout_seconds=5, ttl_seconds=5,
              role_contains=False) -> None:
    document = {"schema_version": 1, "name": name, "url": url,
                "principal_path": principal_path, "expected_principal": expected_principal,
                "role_path": role_path, "expected_role": expected_role,
                "expected_status": expected_status, "max_bytes": max_bytes,
                "timeout_seconds": timeout_seconds, "ttl_seconds": ttl_seconds}
    if role_contains is not False:
        document["role_contains"] = role_contains
    _validated(document, name)
    _write_private(_path(name), document)


def read_configuration(name: str) -> dict:
    path = _path(name)
    try:
        document = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError("configuration-missing-or-invalid") from exc
    return _validated(document, name)


def all_private_values() -> set[str]:
    directory = workspace_dir() / "identities" / "verification"
    values = set()
    for path in directory.glob("*.json"):
        document = read_configuration(path.stem)
        if document["expected_principal"] is not None:
            values.add(document["expected_principal"])
    return values


def _digest(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise VerificationError("verification-state-unavailable") from exc


def _state(name: str) -> tuple:
    try:
        signature = identity.selection_signature()
    except identity.IdentityError as exc:
        raise VerificationError("actor-invalid") from exc
    if signature[1] != name:
        raise VerificationError("actor-changed")
    return (signature, _digest(workspace_dir() / "policy.json"), _digest(_path(name)))


def _selected() -> tuple[dict, tuple]:
    try:
        name = identity.selected_name()
        if name == "default":
            raise VerificationError("named-actor-required")
        configuration = read_configuration(name)
        return configuration, _state(name)
    except identity.IdentityError as exc:
        raise VerificationError("actor-invalid") from exc


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("ambiguous-json")
        result[key] = value
    return result


def _walk(document: dict, path: str, label: str):
    value = document
    for segment in path.split("."):
        if not isinstance(value, dict) or segment not in value:
            raise VerificationError(f"{label}-missing")
        value = value[segment]
    return value


def _role_is_member(document: dict, path: str, expected_role) -> bool:
    members = _walk(document, path, "role")
    if type(members) is not list:
        raise VerificationError("role-ambiguous")
    return any(type(member) is type(expected_role) and member == expected_role
               for member in members)


def _field(document: dict, path: str, label: str, expected_type=str) -> str | int:
    value = _walk(document, path, label)
    if type(value) is not expected_type:
        raise VerificationError(f"{label}-ambiguous")
    return value


def _assert_response(configuration: dict, status: int, body: bytes) -> None:
    if status != configuration["expected_status"] or 300 <= status < 400:
        raise VerificationError("status-mismatch")
    if configuration["expected_status"] == 401:
        return
    try:
        document = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError("response-json-invalid") from exc
    if not isinstance(document, dict):
        raise VerificationError("response-json-invalid")
    if _field(document, configuration["principal_path"], "principal") != configuration["expected_principal"]:
        raise VerificationError("principal-mismatch")
    expected_role = configuration["expected_role"]
    if configuration.get("role_contains"):
        if not _role_is_member(document, configuration["role_path"], expected_role):
            raise VerificationError("role-mismatch")
        return
    if _field(document, configuration["role_path"], "role", type(expected_role)) != expected_role:
        raise VerificationError("role-mismatch")


def _probe_request(client, configuration: dict, state: tuple) -> httpx.Request:
    request = client.build_request("GET", configuration["url"],
                                   headers={"Accept": "application/json", "Accept-Encoding": "identity",
                                            "Cache-Control": "no-cache"},
                                   timeout=configuration["timeout_seconds"])
    for header, value in identity.companion_supplements(
            configuration["name"], configuration["url"]).items():
        request.headers[header] = value
        ledger.remember_secret(value)
    nonce = str(uuid.uuid4())
    now = time.monotonic()
    with _proof_lock:
        for expired in [key for key, value in _probe_proofs.items() if value[3] <= now]:
            _probe_proofs.pop(expired, None)
        _probe_proofs[nonce] = (state, request, configuration["url"],
                                now + configuration["timeout_seconds"] + 5)
    request.extensions["bughunt_verification_probe"] = nonce
    return request


def validate_probe(request: httpx.Request, profile) -> bool:
    if "bughunt_verification_probe" not in request.extensions:
        return False
    require_workspace_scope(str(request.url))
    nonce = request.extensions["bughunt_verification_probe"]
    if not isinstance(nonce, str):
        raise VerificationError("probe-authorization-invalid")
    with _proof_lock:
        record = _probe_proofs.get(nonce)
    if record is None:
        raise VerificationError("probe-authorization-invalid")
    state, original, target, expiry = record
    if original is not request or time.monotonic() >= expiry:
        raise VerificationError("probe-authorization-invalid")
    if request.method != "GET" or str(request.url) != target:
        raise VerificationError("probe-target-changed")
    try:
        if request.content != b"":
            raise VerificationError("probe-body-invalid")
    except httpx.RequestNotRead as exc:
        raise VerificationError("probe-body-invalid") from exc
    if "bughunt_require_verified" in request.extensions:
        raise VerificationError("probe-mixed-marker")
    if request.extensions.get("bughunt_actor_snapshot") != state[0]:
        raise VerificationError("probe-actor-changed")
    if _state(state[0][1]) != state:
        raise VerificationError("probe-state-changed")
    return True


def claim_probe(request: httpx.Request, profile) -> bool:
    if not validate_probe(request, profile):
        return False
    nonce = request.extensions["bughunt_verification_probe"]
    with _proof_lock:
        record = _probe_proofs.get(nonce)
        if record is None or time.monotonic() >= record[3]:
            raise VerificationError("probe-authorization-invalid")
        _probe_proofs.pop(nonce)
    return True


def _read_sync(response: httpx.Response, maximum: int, deadline: float,
               body: bytearray) -> None:
    chunks = ([response.content] if response.is_closed else response.iter_raw(chunk_size=8192))
    for chunk in chunks:
        if time.monotonic() > deadline:
            raise VerificationError("verification-timeout")
        body.extend(chunk[:maximum + 1 - len(body)])
        if len(body) > maximum:
            raise VerificationError("response-too-large")
    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
        raise VerificationError("response-encoding-unsupported")


async def _read_async(response: httpx.Response, maximum: int, deadline: float,
                      body: bytearray) -> None:
    if response.is_closed:
        body.extend(response.content[:maximum + 1])
        if len(body) > maximum:
            raise VerificationError("response-too-large")
    else:
        async for chunk in response.aiter_raw(chunk_size=8192):
            if time.monotonic() > deadline:
                raise VerificationError("verification-timeout")
            body.extend(chunk[:maximum + 1 - len(body)])
            if len(body) > maximum:
                raise VerificationError("response-too-large")
    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
        raise VerificationError("response-encoding-unsupported")


def _finish_probe(run_id: str | None, request: httpx.Request, actor: str,
                  status: int, body: bytearray, passed: bool, reason: str) -> None:
    if run_id is not None:
        ledger.finish_verification_probe(run_id, passed=passed, status=status, size=len(body),
                                         sha256=hashlib.sha256(body).hexdigest(), reason=reason)
    elif not passed:
        from bughunt.core import egress
        try:
            ledger.invalid_verification_attempt(egress.current_profile(), request, actor, reason)
        except egress.PolicyBlocked:
            pass


def _verify_sync(client) -> tuple[str, tuple, dict]:
    if getattr(client, "_bughunt_guarded", False) is not True:
        raise VerificationError("guarded-client-required")
    configuration, state = _selected()
    request = _probe_request(client, configuration, state)
    deadline = time.monotonic() + configuration["timeout_seconds"]
    run_id, status, body, reason = None, 0, bytearray(), "verification-transport-error"
    try:
        response = client.send(request, stream=True, follow_redirects=False)
        run_id = response.extensions.get("bughunt_verification_run_id")
        status = response.status_code
        try:
            if not isinstance(run_id, str):
                raise VerificationError("probe-ledger-missing")
            _read_sync(response, configuration["max_bytes"], deadline, body)
        finally:
            response.close()
        if time.monotonic() > deadline:
            raise VerificationError("verification-timeout")
        _assert_response(configuration, status, bytes(body))
        if _state(configuration["name"]) != state:
            raise VerificationError("verification-state-changed")
        reason = "verified"
        _finish_probe(run_id, request, state[0][1], status, body, True, reason)
        return run_id, state, configuration
    except VerificationError as exc:
        reason = str(exc)
        _finish_probe(run_id, request, state[0][1], status, body, False, reason)
        raise
    except httpx.TimeoutException as exc:
        _finish_probe(run_id, request, state[0][1], status, body, False, "verification-timeout")
        raise VerificationError("verification-timeout") from exc
    except httpx.HTTPError as exc:
        _finish_probe(run_id, request, state[0][1], status, body, False, reason)
        raise VerificationError(reason) from exc
    finally:
        with _proof_lock:
            _probe_proofs.pop(request.extensions["bughunt_verification_probe"], None)


async def _verify_async(client) -> tuple[str, tuple, dict]:
    if getattr(client, "_bughunt_guarded", False) is not True:
        raise VerificationError("guarded-client-required")
    configuration, state = _selected()
    request = _probe_request(client, configuration, state)
    deadline = time.monotonic() + configuration["timeout_seconds"]
    run_id, status, body, reason = None, 0, bytearray(), "verification-transport-error"
    try:
        response = await client.send(request, stream=True, follow_redirects=False)
        run_id = response.extensions.get("bughunt_verification_run_id")
        status = response.status_code
        try:
            if not isinstance(run_id, str):
                raise VerificationError("probe-ledger-missing")
            await _read_async(response, configuration["max_bytes"], deadline, body)
        finally:
            await response.aclose()
        if time.monotonic() > deadline:
            raise VerificationError("verification-timeout")
        _assert_response(configuration, status, bytes(body))
        if _state(configuration["name"]) != state:
            raise VerificationError("verification-state-changed")
        reason = "verified"
        _finish_probe(run_id, request, state[0][1], status, body, True, reason)
        return run_id, state, configuration
    except VerificationError as exc:
        reason = str(exc)
        _finish_probe(run_id, request, state[0][1], status, body, False, reason)
        raise
    except httpx.TimeoutException as exc:
        _finish_probe(run_id, request, state[0][1], status, body, False, "verification-timeout")
        raise VerificationError("verification-timeout") from exc
    except httpx.HTTPError as exc:
        _finish_probe(run_id, request, state[0][1], status, body, False, reason)
        raise VerificationError(reason) from exc
    finally:
        with _proof_lock:
            _probe_proofs.pop(request.extensions["bughunt_verification_probe"], None)


def verify_selected(client) -> str:
    return _verify_sync(client)[0]


async def verify_selected_async(client) -> str:
    return (await _verify_async(client))[0]


def _issue_proof(request: httpx.Request, run_id: str, state: tuple, configuration: dict) -> None:
    try:
        require_verification_origin(str(request.url), configuration)
        current = _state(configuration["name"])
    except VerificationError as exc:
        _record_invalid_request(request, str(exc))
        raise
    if current != state:
        _record_invalid_request(request, "verification-state-changed")
        raise VerificationError("verification-state-changed")
    nonce = str(uuid.uuid4())
    now = time.monotonic()
    record = (state, str(request.url), request.method, now +
              configuration["ttl_seconds"], run_id, request)
    with _proof_lock:
        for expired in [key for key, value in _proofs.items() if value[3] <= now]:
            _proofs.pop(expired, None)
        _proofs[nonce] = record
    request.extensions["bughunt_require_verified"] = True
    request.extensions["bughunt_verification_proof"] = nonce


def _record_invalid_request(request: httpx.Request, reason: str) -> None:
    from bughunt.core import egress
    try:
        profile = egress.current_profile()
        actor = identity.selection_signature()[1]
        ledger.invalid_verification_attempt(profile, request, actor, reason)
    except (egress.PolicyBlocked, identity.IdentityError):
        pass


def validate_request(request: httpx.Request, profile) -> str | None:
    if "bughunt_require_verified" not in request.extensions:
        return None
    require_workspace_scope(str(request.url))
    if request.extensions["bughunt_require_verified"] is not True:
        raise VerificationError("proof-marker-invalid")
    nonce = request.extensions.get("bughunt_verification_proof")
    if not isinstance(nonce, str):
        raise VerificationError("proof-missing")
    with _proof_lock:
        record = _proofs.get(nonce)
    if record is None:
        raise VerificationError("proof-missing-or-used")
    state, target, method, expiry, run_id, original = record
    if original is not request:
        raise VerificationError("proof-request-changed")
    if time.monotonic() >= expiry:
        raise VerificationError("proof-expired")
    if str(request.url) != target or request.method != method:
        raise VerificationError("proof-target-changed")
    if request.extensions.get("bughunt_actor_snapshot") != state[0]:
        raise VerificationError("proof-actor-changed")
    if _state(state[0][1]) != state:
        raise VerificationError("proof-state-changed")
    return run_id


def claim_request(request: httpx.Request, profile) -> str | None:
    run_id = validate_request(request, profile)
    if run_id is None:
        return None
    nonce = request.extensions["bughunt_verification_proof"]
    with _proof_lock:
        record = _proofs.get(nonce)
        if record is None:
            raise VerificationError("proof-missing-or-used")
        if time.monotonic() >= record[3]:
            _proofs.pop(nonce, None)
            raise VerificationError("proof-expired")
        _proofs.pop(nonce)
    return run_id


def verify_and_send(client, request: httpx.Request, *, stream: bool = False) -> httpx.Response:
    try:
        require_workspace_scope(str(request.url))
        require_verification_origin(str(request.url), _selected()[0])
        run_id, state, configuration = _verify_sync(client)
    except VerificationError:
        _record_invalid_request(request, "configuration-or-assertion-invalid")
        raise
    _issue_proof(request, run_id, state, configuration)
    return client.send(request, follow_redirects=False, stream=stream)


async def verify_and_send_async(client, request: httpx.Request, *, stream: bool = False) -> httpx.Response:
    try:
        require_workspace_scope(str(request.url))
        require_verification_origin(str(request.url), _selected()[0])
        run_id, state, configuration = await _verify_async(client)
    except VerificationError:
        _record_invalid_request(request, "configuration-or-assertion-invalid")
        raise
    _issue_proof(request, run_id, state, configuration)
    return await client.send(request, follow_redirects=False, stream=stream)
