"""Offline mission policy. Outbound enforcement is a separate integration layer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import threading
from urllib.parse import urlsplit

OPERATIONS = ("passive", "manual", "crawl", "fuzz", "active_scan", "dns", "process", "callback")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Asset:
    asset_id: str
    origin: str
    paths: tuple[str, ...]
    operations: tuple[str, ...]
    methods: tuple[str, ...]

    def matches(self, origin: str, path: str) -> bool:
        return self.origin == origin and any(
            path == entry or (entry.endswith("/") and path.startswith(entry))
            for entry in self.paths
        )


@dataclass(frozen=True)
class Decision:
    permitted: bool
    reason: str
    mission: str
    policy_version: str
    asset_id: str = ""


@dataclass(frozen=True)
class Profile:
    mission: str
    policy_version: str
    state: str
    source: str
    verified_at: datetime
    stale_after_seconds: int
    assets: tuple[Asset, ...]
    exclusions: tuple[Asset, ...]
    permissions: tuple[tuple[str, bool], ...]
    requests_per_second: float
    concurrency: int
    required_headers: tuple[tuple[str, str], ...]
    user_agent: str
    callback_domains: tuple[str, ...]
    ai_notes: str
    confidentiality_notes: str

    def freshness(self, now: datetime | None = None) -> str:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            raise PolicyError("Decision time must include a timezone.")
        if self.state != "verified":
            return self.state
        if current < self.verified_at:
            return "unverified"
        if current >= self.verified_at + timedelta(seconds=self.stale_after_seconds):
            return "stale"
        return "verified"

    def decide(self, target: str, operation: str, *, method: str = "GET",
               callback_domain: str | None = None, now: datetime | None = None) -> Decision:
        def result(permitted: bool, reason: str, asset_id: str = "") -> Decision:
            return Decision(permitted, reason, self.mission, self.policy_version, asset_id)

        state = self.freshness(now)
        if state != "verified":
            return result(False, f"policy-{state}")
        if operation not in OPERATIONS or not dict(self.permissions).get(operation, False):
            return result(False, "operation-disallowed")
        try:
            origin, path = target_parts(target)
        except PolicyError:
            return result(False, "invalid-target")
        if any(row.matches(origin, path) for row in self.exclusions):
            return result(False, "asset-excluded")
        rows = [row for row in self.assets if row.matches(origin, path)]
        if not rows:
            return result(False, "asset-unknown")
        # Overlapping grants must all allow the operation; a broad row cannot widen a narrow one.
        if any(operation not in row.operations or method not in row.methods for row in rows):
            return result(False, "asset-method-disallowed")
        if operation == "callback" and callback_domain is None:
            return result(False, "callback-required")
        if callback_domain is not None:
            try:
                domain = _hostname(callback_domain)
            except PolicyError:
                return result(False, "callback-disallowed")
            if domain not in self.callback_domains or not dict(self.permissions)["callback"]:
                return result(False, "callback-disallowed")
        return result(True, "permitted", rows[0].asset_id)


def _keys(value: object, required: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != required:
        raise PolicyError(f"{label} has missing or unknown fields.")
    return value


def _text(value: object, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value.strip()):
        raise PolicyError(f"{label} must be text.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise PolicyError(f"{label} contains control characters.")
    return value


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyError(f"{label} must be a list.")
    items = tuple(_text(item, label) for item in value)
    if len(items) != len(set(items)):
        raise PolicyError(f"{label} contains duplicates.")
    return items


def _hostname(value: str) -> str:
    if not value or value != value.strip() or any(c in value for c in "/\\@%?#*"):
        raise PolicyError("Expected an exact hostname or IP address.")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", value):
        raise PolicyError("Ambiguous numeric host.")
    try:
        name = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise PolicyError("Invalid hostname.") from exc
    if len(name) > 253 or not all(
        re.fullmatch(r"(?:_[a-z0-9-]{1,62}|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)", label)
        for label in name.split(".")
    ):
        raise PolicyError("Invalid hostname.")
    return name


def _path(value: str) -> str:
    # Conservative rejection avoids disagreements between URL parsers and servers.
    if (not value.startswith("/") or "\\" in value or "%" in value or "//" in value
            or any(c in value for c in "?#*") or any(c.isspace() for c in value)
            or any(part in {".", ".."} for part in value.split("/"))):
        raise PolicyError("Paths must be literal absolute paths without ambiguous encoding.")
    _text(value, "path")
    return value


def target_parts(target: str) -> tuple[str, str]:
    _text(target, "target")
    if target != target.strip() or "\\" in target or any(c.isspace() for c in target):
        raise PolicyError("Invalid target URL.")
    try:
        parsed = urlsplit(target)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None or parsed.fragment):
            raise PolicyError("Expected an HTTP(S) URL without credentials or fragment.")
        host = _hostname(parsed.hostname)
        port = parsed.port
    except ValueError as exc:
        raise PolicyError("Invalid target URL.") from exc
    host = f"[{host}]" if ":" in host else host
    default_port = 443 if parsed.scheme == "https" else 80
    suffix = f":{port}" if port is not None and port != default_port else ""
    return f"{parsed.scheme}://{host}{suffix}", _path(parsed.path or "/")


def _asset(value: object, *, exclusion: bool) -> Asset:
    fields = {"id", "origin", "paths"}
    if not exclusion:
        fields |= {"operations", "methods"}
    row = _keys(value, fields, "asset")
    origin = _text(row["origin"], "origin")
    canonical, path = target_parts(origin)
    if path != "/" or "?" in origin or origin.rstrip("/") != canonical:
        raise PolicyError("Asset origin must be canonical and contain no path or query.")
    paths = tuple(_path(item) for item in _strings(row["paths"], "paths"))
    if not paths:
        raise PolicyError("Asset needs at least one path.")
    operations = () if exclusion else _strings(row["operations"], "operations")
    methods = () if exclusion else _strings(row["methods"], "methods")
    if not exclusion and (not operations or not methods or set(operations) - set(OPERATIONS)):
        raise PolicyError("Asset needs known operations and HTTP methods.")
    if any(not re.fullmatch(r"[A-Z]+", method) for method in methods):
        raise PolicyError("HTTP methods must be uppercase tokens.")
    if "_" in (urlsplit(canonical).hostname or "") and not exclusion and set(operations) != {"dns"}:
        raise PolicyError("DNS service labels can only grant DNS operations.")
    return Asset(_text(row["id"], "asset id"), canonical, paths, operations, methods)


def _timestamp(value: object) -> datetime:
    try:
        timestamp = datetime.fromisoformat(_text(value, "verified_at"))
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("timezone missing")
        return timestamp.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise PolicyError("verified_at must be an ISO timestamp with timezone.") from exc


def _positive(value: object, label: str, *, integer: bool = False) -> float | int:
    try:
        valid = (type(value) in {int, float} and math.isfinite(value) and value > 0
                 and (not integer or type(value) is int))
    except OverflowError:
        valid = False
    if not valid:
        raise PolicyError(f"{label} must be a positive {'integer' if integer else 'number'}.")
    return value


def _headers(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, dict):
        raise PolicyError("required_headers must be an object.")
    result = []
    for name, raw in value.items():
        if (not re.fullmatch(r"[!#$&'*+.^_`|~0-9A-Za-z-]+", name)
                or name.lower() == "host"
                or re.search(r"(?i)cookie|auth|token|api[-_]?key|secret|session|csrf", name)):
            raise PolicyError("Required headers must be non-credential identity headers.")
        result.append((name, _text(raw, "header value").strip()))
    if len({name.lower() for name, _ in result}) != len(result):
        raise PolicyError("Duplicate header names.")
    return tuple(result)


def parse_profile(value: object) -> Profile:
    fields = {"schema_version", "mission", "policy_version", "state", "source", "verified_at",
              "stale_after_seconds", "assets", "exclusions", "permissions", "limits",
              "required_headers", "user_agent", "callback_domains", "ai_notes", "confidentiality_notes"}
    data = _keys(value, fields, "profile")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise PolicyError("Unsupported policy schema version.")
    if data["state"] not in ("draft", "verified", "stale", "unknown"):
        raise PolicyError("Invalid policy state.")
    permissions = _keys(data["permissions"], set(OPERATIONS), "permissions")
    if any(type(value) is not bool for value in permissions.values()):
        raise PolicyError("Permissions must be explicit booleans.")
    limits = _keys(data["limits"], {"requests_per_second", "concurrency"}, "limits")
    assets = _rows(data["assets"], exclusion=False)
    exclusions = _rows(data["exclusions"], exclusion=True)
    if len({row.asset_id for row in (*assets, *exclusions)}) != len(assets) + len(exclusions):
        raise PolicyError("Asset IDs must be unique.")
    stale_after = _positive(data["stale_after_seconds"], "stale_after_seconds", integer=True)
    if stale_after > 31536000:
        raise PolicyError("Policy verification lifetime cannot exceed one year.")
    verified_at = _timestamp(data["verified_at"])
    try:
        verified_at + timedelta(seconds=stale_after)
    except OverflowError as exc:
        raise PolicyError("Policy expiry is outside the supported timestamp range.") from exc
    callbacks = tuple(_hostname(item) for item in _strings(data["callback_domains"], "callbacks"))
    return Profile(
        _text(data["mission"], "mission"), _text(data["policy_version"], "policy version"),
        data["state"], _text(data["source"], "source"), verified_at, stale_after,
        assets, exclusions, tuple(permissions.items()),
        _positive(limits["requests_per_second"], "rate"),
        _positive(limits["concurrency"], "concurrency", integer=True),
        _headers(data["required_headers"]), _text(data["user_agent"], "user_agent").strip(), callbacks,
        _text(data["ai_notes"], "ai_notes", empty=True),
        _text(data["confidentiality_notes"], "confidentiality_notes", empty=True),
    )


def _rows(value: object, *, exclusion: bool) -> tuple[Asset, ...]:
    if not isinstance(value, list):
        raise PolicyError("Asset rows must be a list.")
    return tuple(_asset(row, exclusion=exclusion) for row in value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("Duplicate JSON field.")
        result[key] = value
    return result


_parse_lock = threading.Lock()
_parsed_entry: tuple[bytes, Profile] | None = None  # one entry: (sha256 digest of raw bytes, Profile)


def read_document(path: Path) -> tuple[dict, Profile]:
    global _parsed_entry
    try:
        raw = path.read_bytes()  # re-read on every call; only the parse is reused
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        digest = hashlib.sha256(raw).digest()
        with _parse_lock:
            entry = _parsed_entry
            if entry is not None and entry[0] == digest:
                return data, entry[1]
        profile = parse_profile(data)  # a failure raises here and is never cached
        with _parse_lock:
            _parsed_entry = (digest, profile)
        return data, profile
    except (OSError, UnicodeError, ValueError, TypeError, OverflowError) as exc:
        raise PolicyError("Cannot load a valid mission policy; check file and schema.") from exc
