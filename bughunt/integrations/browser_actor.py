"""Exact, owned browser-actor plans; dry-run is not containment acceptance."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import urlsplit

import httpx

from bughunt.core import egress, exchange, identity, job, verification
from bughunt.core.policy import Profile
from bughunt.core.workspace import workspace_dir

MISSION = "whk027-owned-browser"
PROFILE_ID = "browser-owned"
DRIVER_VERSION = "1.62.1"
IMAGE = "mcr.microsoft.com/playwright@sha256:dcc5531e97840b9b5e794f2814476b21571c5124a3fca2267d73041f56e7580e"
DRIVER_SHA256 = "954be1e183d0ddb9748fe0d2d08b0b66a9210c74dd75c397aeb70303b9f08a00"
UPSTREAM_SECCOMP_SHA256 = "cc3e61cabda6bbc1e53e54d27ba4d55a9d3be829b6dd1a596f4a7b31b1cc7849"


def _owned_url(value: str) -> str:
    exchange.text(value, maximum=8192)
    parsed = urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.fragment
            or not parsed.path.startswith("/__bughunt_lab__/") or parsed.username or parsed.password
            or str(httpx.URL(value)) != value):
        raise ValueError("Initial browser profile requires canonical owned literal-loopback HTTP lab URLs")
    return exchange.target_parts(value)[0]


def fingerprint(path: Path, maximum: int = 8000000) -> str:
    if path.is_symlink() or path.stat().st_size > maximum:
        raise ValueError("Browser input path or size invalid")
    with path.open("rb") as handle:
        raw = handle.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("Browser input grew beyond its bound")
    return exchange.digest(raw)


def seccomp_profile(source: Path) -> dict:
    if fingerprint(source, 100000) != UPSTREAM_SECCOMP_SHA256:
        raise ValueError("Pinned browser seccomp source fingerprint differs")
    document = exchange.load_json(source.read_bytes())
    if document["defaultAction"] != "SCMP_ACT_ERRNO":
        raise ValueError("Browser seccomp must retain default deny")
    document["syscalls"].insert(0, {"names": ["chroot"], "action": "SCMP_ACT_ALLOW",
                                   "args": [], "includes": {}, "excludes": {}})
    return document


class ActorBudget(job.Budget):
    def __init__(self, urls: tuple[str, ...], actor: str, probe: str, maximum: int, seconds: float):
        self.actor, self.probe = actor, probe
        root = workspace_dir() / "identities"
        self.artifacts = {}
        self.bind_artifacts([root / f"{actor}.json", root / "verification" / f"{actor}.json"])
        super().__init__(frozenset(("GET", url) for url in (*urls, probe)), maximum, seconds, strict_scope=True)

    def bind_artifacts(self, paths: list[Path]) -> None:
        self.artifacts.update({path: fingerprint(path) for path in paths})

    def check(self, request: httpx.Request) -> None:
        if request.method != "GET" or request.content:
            raise egress.PolicyBlocked("browser-only-selected-bodyless-gets")
        super().check(request)
        if any(fingerprint(path) != digest for path, digest in self.artifacts.items()):
            raise egress.PolicyBlocked("browser-authority-or-input-changed")


@dataclass(frozen=True)
class Plan:
    urls: tuple[str, ...]
    actor: str
    origin: str
    budget: ActorBudget
    max_bytes: int
    profile: Profile


def prepare(urls: list[str], *, actor: str, mission: str, owned_lab: bool = False,
            requests: int = 20, seconds: float = 120, max_bytes: int = 65536) -> Plan:
    if (owned_lab is not True or not isinstance(urls, list) or not 1 <= len(urls) <= 32
            or len(urls) != len(set(urls)) or type(max_bytes) is not int or not 1 <= max_bytes <= 65536):
        raise ValueError("Browser jobs require explicit owned URLs and bounded response bytes")
    origins = {_owned_url(url) for url in urls}
    if len(origins) != 1 or mission != MISSION:
        raise ValueError("One exact owned origin and browser mission required")
    with identity.actor_context(actor):
        configuration = verification.read_configuration(actor)
        if _owned_url(configuration["url"]) not in origins:
            raise ValueError("Verification probe must use the same owned origin")
        for url in (*urls, configuration["url"]):
            profile = egress.authorize(url, "active_scan", "GET")
            identity.snapshot(url)
        egress.authorize(urls[0], "process", "GET")
        if profile.mission != mission or any(re.search(r"cookie|auth|token|key|secret|session|csrf", name, re.I)
                                             for name, _value in profile.required_headers):
            raise ValueError("Browser mission or credential authority invalid")
        budget = ActorBudget(tuple(urls), actor, configuration["url"], requests, seconds)
        for url in (*urls, configuration["url"]):
            budget.check(httpx.Request("GET", url))
    return Plan(tuple(urls), actor, origins.pop(), budget, max_bytes, profile)


def descriptor(plan: Plan) -> dict:
    with identity.actor_context(plan.actor):
        plan.budget.check(httpx.Request("GET", plan.urls[0]))
    return {"profile_id": PROFILE_ID, "engine": "browser-actors", "operation": "active_scan",
        "target": plan.urls[0].split("?", 1)[0], "permitted_targets": [
            {"method": "GET", "route": url.split("?", 1)[0], "url_sha256": exchange.digest(url.encode())}
            for url in plan.urls], "origin": plan.origin,
        "actor": plan.actor, "actor_revision": plan.budget.state[0][2],
        "policy_sha256": plan.budget.state[1], "mission": plan.profile.mission,
        "driver_version": DRIVER_VERSION, "image": IMAGE,
        "budgets": {"physical_requests": plan.budget.maximum, "seconds": plan.budget.seconds,
                    "response_bytes": plan.max_bytes, "concurrency": 1},
        "verification": "identity probe immediately before each selected request; both count",
        "credential_authority": "Bughunt named actor; browser headers never select identity",
        "browser_network": "none; host-mediated selected GETs only",
        "profile_lifetime": "one job; private container tmpfs; never personal browser data",
        "limits": ["owned literal-loopback HTTP only", "no automatic login or authenticated crawler",
                   "WebSocket and service-worker traffic unavailable", "no cross-process rate guarantee",
                   "strict native-header spacing requires the separately reviewed dispatch-spacing delivery"]}


def preview(plan: Plan) -> dict:
    return dict(descriptor(plan), job_id=plan.budget.job_id, dry_run=True,
                consumer_status="not-probed; dry-run is not containment evidence")
