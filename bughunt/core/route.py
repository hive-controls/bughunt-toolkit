"""Route gate: would traffic to a destination leave through the named tunnel?

Pure policy logic over an injected ``RouteProbe`` and resolver (stdlib only).
It reads the OS routing table and sends no packets. The gate is opt-in: no
config means inactive; a config that exists but is invalid blocks (fail closed).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

from bughunt.core import route_probe
from bughunt.core.route_probe import Interface, ProbeError, RouteProbe
from bughunt.core.workspace import workspace_dir

LOGGER = logging.getLogger(__name__)

ENV_CONFIG = "BUGHUNT_ROUTE_CONFIG"
CONFIG_FILENAME = "route.json"
MAX_CONFIG_BYTES = 64 * 1024
SCHEMA_VERSION = 1
PROTECT_POINTS = ("console", "proxy_scan")
DEFAULT_PROBE_ADDRESS = "1.1.1.1"
_ALLOWED_KEYS = {
    "schema_version",
    "interfaces",
    "probe_address",
    "protect",
    "allow_loopback_proxy",
}

Resolver = Callable[..., list]

ENV_ALLOW_NO_ROUTE = "BUGHUNT_ALLOW_NO_ROUTE"
OPTOUT_WARNING = (
    "WARNING: route/VPN protection is DISABLED by operator opt-out "
    f"({ENV_ALLOW_NO_ROUTE}=1); scan and console traffic is NOT confined to the configured tunnel."
)


def optout_requested(env: Mapping[str, str] | None = None) -> bool:
    """True when the per-run, ephemeral route-gate opt-out flag is set to '1'."""
    environment = os.environ if env is None else env
    return (environment.get(ENV_ALLOW_NO_ROUTE) or "").strip() == "1"


def warn_optout(point: str) -> None:
    """Persist the bypass before warning; persistence failure must block the caller."""
    from bughunt.core import ledger

    ledger.record_route_optout(point)
    try:
        from rich.console import Console
        from rich.text import Text

        Console(stderr=True, highlight=False).print(
            Text(OPTOUT_WARNING, style="red bold"), soft_wrap=True
        )
    except Exception:
        try:
            print(OPTOUT_WARNING, file=sys.stderr)
        except Exception:
            pass


class ConfigError(Exception):
    """The route config is unreadable or invalid."""


@dataclass(frozen=True)
class RoutePolicy:
    interfaces: tuple[str, ...]
    probe_address: str = DEFAULT_PROBE_ADDRESS
    protect: tuple[str, ...] = PROTECT_POINTS
    allow_loopback_proxy: bool = False
    source: str = ""


@dataclass(frozen=True)
class Verdict:
    ok: bool
    summary: str
    details: tuple[str, ...] = ()


def _blocked(summary: str, *details: str) -> Verdict:
    return Verdict(False, summary, details)


# ---------------------------------------------------------------- config


def _validate_interfaces(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError("interfaces must be a non-empty list")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise ConfigError("interfaces must contain only non-empty strings")
    return tuple(item.strip() for item in value)


def _validate_probe_address(value: object) -> str:
    if not isinstance(value, str):
        raise ConfigError("probe_address must be an IP literal string")
    try:
        ipaddress.ip_address(value)
    except ValueError as error:
        raise ConfigError(f"probe_address is not an IP literal: {value}") from error
    return value


def _validate_protect(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError("protect must be a list of strings")
    unknown = sorted(set(value) - set(PROTECT_POINTS))
    if unknown:
        raise ConfigError(f"protect has unknown points: {', '.join(unknown)}")
    return tuple(dict.fromkeys(value))


def parse_config(text: str, source: str = "") -> RoutePolicy:
    """Strictly parse route.json text; any deviation raises ConfigError."""
    if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise ConfigError("route config exceeds 64 KiB")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        raise ConfigError(f"route config is not valid JSON: {error}") from error
    if not isinstance(data, dict):
        raise ConfigError("route config must be a JSON object")
    unknown = sorted(set(data) - _ALLOWED_KEYS)
    if unknown:
        raise ConfigError(f"route config has unknown keys: {', '.join(unknown)}")
    if data.get("schema_version") != SCHEMA_VERSION or isinstance(
        data.get("schema_version"), bool
    ):
        raise ConfigError(f"schema_version must be {SCHEMA_VERSION}")
    if "interfaces" not in data:
        raise ConfigError("interfaces is required")
    loopback = data.get("allow_loopback_proxy", False)
    if not isinstance(loopback, bool):
        raise ConfigError("allow_loopback_proxy must be true or false")
    return RoutePolicy(
        interfaces=_validate_interfaces(data["interfaces"]),
        probe_address=_validate_probe_address(
            data.get("probe_address", DEFAULT_PROBE_ADDRESS)
        ),
        protect=_validate_protect(data["protect"])
        if "protect" in data
        else PROTECT_POINTS,
        allow_loopback_proxy=loopback,
        source=source,
    )


def load_config(path: Path) -> RoutePolicy:
    try:
        size = path.stat().st_size
        if size > MAX_CONFIG_BYTES:
            raise ConfigError("route config exceeds 64 KiB")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise ConfigError(f"cannot read route config {path}: {error}") from error
    return parse_config(text, source=str(path))


def locate_config(env: Mapping[str, str] | None = None) -> Path | None:
    """Env path wins (even if missing); else the workspace route.json; else None."""
    environment = os.environ if env is None else env
    explicit = (environment.get(ENV_CONFIG) or "").strip()
    if explicit:
        return Path(explicit).expanduser()
    candidate = workspace_dir() / CONFIG_FILENAME
    return candidate if candidate.exists() else None


# ------------------------------------------------------------------ gate


def _matching_tunnels(
    policy: RoutePolicy, interfaces: list[Interface]
) -> list[Interface]:
    fragments = [fragment.lower() for fragment in policy.interfaces]
    return [
        item
        for item in interfaces
        if item.up
        and any(
            fragment in f"{item.name} {item.description}".lower()
            for fragment in fragments
        )
    ]


def _resolve_addresses(destination: str, resolver: Resolver) -> list[str]:
    try:
        ipaddress.ip_address(destination)
        return [destination]
    except ValueError:
        pass
    try:
        infos = resolver(destination, None)
    except (OSError, UnicodeError) as error:
        raise ProbeError(f"cannot resolve {destination}: {error}") from error
    addresses = sorted({str(info[4][0]).split("%", 1)[0] for info in infos})
    if not addresses:
        raise ProbeError(f"{destination} resolved to no addresses")
    return addresses


def _check_probe_address(
    policy: RoutePolicy, probe: RouteProbe, tunnel_indexes: set[int]
) -> Verdict | None:
    egress = probe.egress_indexes(policy.probe_address)
    if egress and egress <= tunnel_indexes:
        return None
    return _blocked(
        "Tunnel is up but the probe address does not use it.",
        f"{policy.probe_address} egresses via interface index {sorted(egress)}, "
        f"not the tunnel {sorted(tunnel_indexes)}.",
    )


def _check_destination(
    policy: RoutePolicy,
    probe: RouteProbe,
    tunnel_indexes: set[int],
    destination: str,
    kind: str,
    resolver: Resolver,
) -> tuple[Verdict | None, list[str]]:
    addresses = _resolve_addresses(destination, resolver)
    lines: list[str] = []
    all_loopback = all(
        ipaddress.ip_address(address).is_loopback for address in addresses
    )
    if kind == "proxy" and policy.allow_loopback_proxy and all_loopback:
        return None, [f"{destination} is loopback; allowed by allow_loopback_proxy."]
    for address in addresses:
        egress = probe.egress_indexes(address)
        if not egress or not egress <= tunnel_indexes:
            return _blocked(
                f"Destination {destination} ({address}) does not route through the tunnel.",
                *lines,
            ), lines
        lines.append(f"{address} routes through the tunnel.")
    return None, lines


def verify(
    policy: RoutePolicy,
    *,
    destination: str | None = None,
    kind: str = "probe",
    probe: RouteProbe | None = None,
    resolver: Resolver = socket.getaddrinfo,
) -> Verdict:
    """Gate steps 1-6; every backend failure becomes a blocking Verdict."""
    if not policy.interfaces:
        return _blocked("No tunnel interface names are configured.")
    try:
        backend = probe if probe is not None else route_probe.default_probe()
        tunnels = _matching_tunnels(policy, backend.interfaces())
        if not tunnels:
            return _blocked(
                "No matching tunnel interface is up.",
                f"Looked for: {', '.join(policy.interfaces)}",
            )
        tunnel_indexes = {item.index for item in tunnels}
        names = ", ".join(item.name for item in tunnels)
        failure = _check_probe_address(policy, backend, tunnel_indexes)
        if failure is not None:
            return failure
        details = [
            f"Tunnel up: {names}.",
            f"Probe address {policy.probe_address} uses the tunnel.",
        ]
        if destination:
            failure, lines = _check_destination(
                policy, backend, tunnel_indexes, destination, kind, resolver
            )
            if failure is not None:
                return failure
            details.extend(lines)
    except (ProbeError, OSError, ValueError) as error:
        LOGGER.warning("route verification failed: %s", error)
        return _blocked(f"Route could not be verified: {error}")
    return Verdict(True, "Route check passed.", tuple(details))


def gate(
    point: str,
    destination: str | None = None,
    *,
    kind: str = "probe",
    env: Mapping[str, str] | None = None,
    probe: RouteProbe | None = None,
    resolver: Resolver = socket.getaddrinfo,
) -> Verdict | None:
    """None: gate not active for this point. Verdict(ok=False): caller must block."""
    path = locate_config(env)
    if path is None:
        return None
    try:
        policy = load_config(path)
    except ConfigError as error:
        return _blocked(f"Route config invalid; blocked: {error}")
    if point not in policy.protect:
        return None
    return verify(
        policy, destination=destination, kind=kind, probe=probe, resolver=resolver
    )
