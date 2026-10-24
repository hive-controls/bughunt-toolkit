"""Workspace-private, origin-bound actor profiles for owned work."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import json
from pathlib import Path
import re
import tempfile
import uuid
from urllib.parse import urlsplit

from bughunt.core.policy import PolicyError, target_parts
from bughunt.core.workspace import workspace_dir

KINDS = ("owner", "lower_privilege", "anonymous", "browser", "api")
CREDENTIAL_HEADERS = {
    "cookie": "Cookie",
    "authorization": "Authorization",
    "x-api-key": "X-API-Key",
    "auth-key": "Auth-Key",
}
_CREDENTIAL_NAME = re.compile(r"(?i)cookie|auth|token|api[-_]?key|secret|session|csrf")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_COMPANION_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
_MAX_COMPANIONS = 8
_actor_context = ContextVar("bughunt_actor_context", default=None)


class IdentityError(ValueError):
    """Invalid or changed actor state; no outbound request may use it."""


def _directory() -> Path:
    return workspace_dir() / "identities"


def _name(value: str) -> str:
    if (
        not isinstance(value, str)
        or not _NAME.fullmatch(value)
        or value in {"default", "selected"}
    ):
        raise IdentityError("Invalid actor name")
    return value


def _profile_path(name: str) -> Path:
    return _directory() / f"{_name(name)}.json"


def _write_private(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix="identity-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump(value, handle, indent=2)
            handle.write("\n")
        temporary.chmod(0o600)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _origin(value: str) -> str:
    try:
        canonical, path = target_parts(value)
    except (PolicyError, TypeError) as exc:
        raise IdentityError("Actor origin must be an exact HTTP(S) origin") from exc
    if value != canonical or path != "/" or "?" in value:
        raise IdentityError("Actor origin must be canonical with no path or query")
    return canonical


def _validated_companions(headers: object) -> list[str]:
    """Companion allowlist: distinct lowercase exact header names, never a credential header."""
    if (
        not isinstance(headers, list)
        or len(headers) > _MAX_COMPANIONS
        or any(
            not isinstance(item, str) or not _COMPANION_NAME.fullmatch(item)
            for item in headers
        )
        or len(headers) != len(set(headers))
        or set(headers) & set(CREDENTIAL_HEADERS)
    ):
        raise IdentityError("Invalid actor companion headers")
    return headers


def _validated(value: object, name: str) -> dict:
    fields = {
        "schema_version",
        "name",
        "kind",
        "origins",
        "owned",
        "revision",
        "credentials",
    }
    if (
        not isinstance(value, dict)
        or not fields <= set(value)
        or set(value) - fields - {"companion_headers"}
    ):
        raise IdentityError("Invalid actor profile")
    _validated_companions(value.get("companion_headers", []))
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["name"] != name
        or value["kind"] not in KINDS
        or value["owned"] is not True
    ):
        raise IdentityError("Invalid actor profile")
    origins = value["origins"]
    if (
        not isinstance(origins, list)
        or not origins
        or any(not isinstance(origin, str) for origin in origins)
        or len(origins) != len(set(origins))
    ):
        raise IdentityError("Invalid actor origins")
    for origin in origins:
        _origin(origin)
    try:
        if str(uuid.UUID(value["revision"])) != value["revision"]:
            raise ValueError("noncanonical revision")
    except (TypeError, ValueError) as exc:
        raise IdentityError("Invalid actor revision") from exc
    credentials = value["credentials"]
    if (
        not isinstance(credentials, dict)
        or any(not isinstance(key, str) for key in credentials)
        or set(credentials) - set(CREDENTIAL_HEADERS.values())
    ):
        raise IdentityError("Invalid actor credentials")
    if (value["kind"] == "anonymous" and credentials) or any(
        not isinstance(item, str)
        or not item.strip()
        or any(ord(character) < 32 or ord(character) > 255 for character in item)
        for item in credentials.values()
    ):
        raise IdentityError("Invalid actor credentials")
    return value


def read_profile(name: str) -> dict:
    path = _profile_path(name)
    try:
        return _validated(json.loads(path.read_text(encoding="utf-8")), name)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IdentityError("Actor profile missing or unreadable") from exc


def create_profile(name: str, kind: str, origins, *, owned: bool = False) -> None:
    name = _name(name)
    if kind not in KINDS or owned is not True:
        raise IdentityError("Named actors require a known kind and owned assertion")
    canonical = [_origin(origin) for origin in origins]
    if not canonical or len(canonical) != len(set(canonical)):
        raise IdentityError("Actor needs distinct exact origins")
    path = _profile_path(name)
    if path.exists():
        raise IdentityError("Actor already exists")
    value = {
        "schema_version": 1,
        "name": name,
        "kind": kind,
        "origins": canonical,
        "owned": True,
        "revision": str(uuid.uuid4()),
        "credentials": {},
    }
    _write_private(path, value)


def _summary(value: dict) -> dict:
    return {
        "name": value["name"],
        "kind": value["kind"],
        "origins": value["origins"],
        "owned": value["owned"],
        "credential_headers": sorted(value["credentials"]),
        "companion_headers": list(value.get("companion_headers", [])),
        "selected": selected_name() == value["name"],
    }


def list_profiles() -> list[dict]:
    return [
        _summary(read_profile(path.stem))
        for path in sorted(_directory().glob("*.json"))
        if path.name != "selected.json"
    ]


def show_profile(name: str) -> dict:
    return _summary(read_profile(name))


def selected_name() -> str:
    scoped = _actor_context.get()
    if scoped is not None:
        workspace, name = scoped
        if str(workspace_dir().resolve()) != workspace:
            raise IdentityError("Actor context workspace changed")
        read_profile(name)
        return name
    path = _directory() / "selected.json"
    if not path.exists():
        return "default"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or set(value) != {"name"}:
            raise IdentityError("Invalid actor selection")
        name = _name(value["name"])
        read_profile(name)
        return name
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IdentityError("Actor selection missing or unreadable") from exc


def use_profile(name: str) -> None:
    if name == "default":
        (_directory() / "selected.json").unlink(missing_ok=True)
        return
    read_profile(name)
    _write_private(_directory() / "selected.json", {"name": name})


@contextmanager
def actor_context(name: str):
    """Select a named actor for this execution context without changing saved state."""
    read_profile(name)
    token = _actor_context.set((str(workspace_dir().resolve()), name))
    try:
        yield
    finally:
        _actor_context.reset(token)


def set_credential(name: str, header: str, value: str) -> None:
    profile = read_profile(name)
    if profile["kind"] == "anonymous":
        raise IdentityError("Anonymous actor cannot hold credentials")
    canonical = CREDENTIAL_HEADERS.get(header.lower())
    if (
        canonical is None
        or not isinstance(value, str)
        or not value.strip()
        or any(ord(character) < 32 or ord(character) > 255 for character in value)
    ):
        raise IdentityError("Invalid credential header or value")
    profile["credentials"][canonical] = value.strip()
    profile["revision"] = str(uuid.uuid4())
    _write_private(_profile_path(name), profile)


def set_companion_headers(name: str, headers) -> None:
    """Declare the exact request headers this actor forwards verbatim (e.g. a CSRF token)."""
    profile = read_profile(name)
    if not isinstance(headers, (list, tuple)) or any(
        not isinstance(item, str) for item in headers
    ):
        raise IdentityError("Invalid actor companion headers")
    canonical = []
    for item in headers:
        lowered = item.lower()
        if lowered not in canonical:
            canonical.append(lowered)
    profile["companion_headers"] = _validated_companions(canonical)
    profile["revision"] = str(uuid.uuid4())
    _write_private(_profile_path(name), profile)


def _parse_cookie(cookie: str) -> dict[str, str]:
    """Split a Cookie header value into a name->value map keyed by lowercase cookie name."""
    pairs: dict[str, str] = {}
    for part in cookie.split(";"):
        cookie_name, separator, value = part.strip().partition("=")
        if separator and cookie_name:
            pairs.setdefault(cookie_name.lower(), value.strip())
    return pairs


def companion_supplements(name: str, target: str) -> dict[str, str]:
    """Private double-submit values for a named actor's allowlisted companion headers.

    Each allowlisted companion header is matched, case-insensitively, against a cookie in
    the actor's stored session (the conventional leading ``x-`` request-header prefix is
    optional); the header is supplied that cookie's current value. Only when the target
    origin is one of the actor's own origins. The default actor supplies nothing.
    """
    if name == "default":
        return {}
    profile = read_profile(name)
    companions = profile.get("companion_headers", [])
    if not companions:
        return {}
    try:
        origin, _path = target_parts(target)
    except (PolicyError, TypeError):
        return {}
    if origin not in profile["origins"]:
        return {}
    cookies = _parse_cookie(profile["credentials"].get("Cookie", ""))
    supplements: dict[str, str] = {}
    for header in companions:
        candidates = [header] + ([header[2:]] if header.startswith("x-") else [])
        value = next(
            (cookies[candidate] for candidate in candidates if candidate in cookies),
            None,
        )
        if value:
            supplements[header] = value
    return supplements


def clear_profile(name: str) -> None:
    profile = read_profile(name)
    profile["credentials"] = {}
    profile["revision"] = str(uuid.uuid4())
    _write_private(_profile_path(name), profile)


def replace_session(name: str, values: dict[str, str]) -> None:
    profile = read_profile(name)
    if profile["kind"] == "anonymous" and any(values.values()):
        raise IdentityError("Anonymous actor cannot hold credentials")
    for key, header in (("cookie", "Cookie"), ("authorization", "Authorization")):
        value = values.get(key, "")
        if not isinstance(value, str):
            raise IdentityError("Invalid session header")
        value = value.strip()
        if "\r" in value or "\n" in value:
            raise IdentityError("Invalid session header")
        if value:
            profile["credentials"][header] = value
        else:
            profile["credentials"].pop(header, None)
    profile["revision"] = str(uuid.uuid4())
    _validated(profile, name)
    _write_private(_profile_path(name), profile)


def all_secret_values() -> set[str]:
    return {
        secret
        for path in _directory().glob("*.json")
        if path.name != "selected.json"
        for secret in read_profile(path.stem)["credentials"].values()
    }


def selection_signature() -> tuple[str, str, str]:
    name = selected_name()
    revision = "legacy" if name == "default" else read_profile(name)["revision"]
    return str(workspace_dir().resolve()), name, revision


def snapshot(
    target: str, prior: tuple | None = None
) -> tuple[str, str, dict[str, str]]:
    name, revision, credentials, _companions = _snapshot_profile(target, prior)
    return name, revision, credentials


def _snapshot_profile(
    target: str, prior: tuple | None = None
) -> tuple[str, str, dict[str, str], frozenset[str]]:
    name = selected_name()
    workspace = str(workspace_dir().resolve())
    if name == "default":
        revision, credentials, companions = "legacy", {}, frozenset()
    else:
        profile = read_profile(name)
        origin, _path = target_parts(target)
        if origin not in profile["origins"]:
            raise IdentityError("Actor origin mismatch; no outbound action ran")
        revision, credentials = profile["revision"], profile["credentials"]
        companions = frozenset(profile.get("companion_headers", []))
    if prior is not None and prior != (workspace, name, revision):
        raise IdentityError(
            "Actor changed while request was queued; no outbound action ran"
        )
    return name, revision, credentials, companions


def apply_raw_headers(
    payload: bytes, target: str, prior: tuple | None = None
) -> tuple[bytes, str]:
    name, _revision, credentials, companions = _snapshot_profile(target, prior)
    if name == "default":
        return payload, name
    head, separator, body = payload.partition(b"\r\n\r\n")
    if not separator:
        raise IdentityError("Malformed raw request")
    lines = head.split(b"\r\n")
    kept = [lines[0]]
    hosts = []
    for line in lines[1:]:
        header, colon, _value = line.partition(b":")
        if not colon:
            raise IdentityError("Malformed raw header")
        try:
            credential = _CREDENTIAL_NAME.search(header.decode("ascii"))
        except UnicodeError as exc:
            raise IdentityError("Malformed raw header") from exc
        if header.lower() == b"host":
            hosts.append(_value.strip().decode("latin-1"))
        if not credential or header.decode("ascii").lower() in companions:
            kept.append(line)
    if len(hosts) != 1 or _host_origin(target, hosts[0]) != target_parts(target)[0]:
        raise IdentityError("Actor Host override mismatch")
    try:
        kept.extend(
            f"{header}: {value}".encode("latin-1")
            for header, value in credentials.items()
        )
    except UnicodeError as exc:
        raise IdentityError("Actor credential cannot be encoded as a header") from exc
    return b"\r\n".join(kept) + separator + body, name


def _host_origin(target: str, host: str) -> str:
    try:
        return target_parts(f"{urlsplit(target).scheme}://{host}/")[0]
    except PolicyError as exc:
        raise IdentityError("Invalid Host override") from exc


def apply_request(request, *, strip_default: bool = False) -> str:
    prior = request.extensions.get("bughunt_actor_snapshot")
    name, revision, credentials, companions = _snapshot_profile(str(request.url), prior)
    if (
        name != "default"
        and _host_origin(str(request.url), request.headers.get("Host", ""))
        != target_parts(str(request.url))[0]
    ):
        raise IdentityError("Actor Host override mismatch")
    if name != "default" or strip_default:
        for header in list(request.headers):
            if _CREDENTIAL_NAME.search(header) and header.lower() not in companions:
                request.headers.pop(header, None)
        for header, value in credentials.items():
            request.headers[header] = value
    request.extensions["bughunt_actor_snapshot"] = (
        str(workspace_dir().resolve()),
        name,
        revision,
    )
    return name
