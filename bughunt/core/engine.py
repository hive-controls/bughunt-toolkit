"""Curated supporting-engine capabilities; execution reuses the existing job path."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import importlib.util
from pathlib import Path
import shutil
from typing import Callable

import httpx

from bughunt import VERSION
from bughunt.core import exchange
from bughunt.integrations import browser_actor, zap, zap_active
from bughunt.modules import MODULES


@dataclass(frozen=True)
class ManagedProfile:
    profile_id: str
    engine: str
    version: str
    image: str
    edition: str
    network: str
    credentials: str
    mutations: str
    background_fetch: str


ZAP_ACTIVE = ManagedProfile("zap-owned-active", "zap-active", zap.SUPPORTED_VERSION,
    zap.SUPPORTED_IMAGE, "free/open-source", "network-none; file proxy; Bughunt final sends",
    "credential-free default actor; engine credential headers discarded",
    "one explicit GET query parameter on the owned literal-loopback route",
    "updates/telemetry disabled; no engine route to external networks")
ZAP_PASSIVE = ManagedProfile("zap-passive", "zap-passive", zap.SUPPORTED_VERSION,
    zap.SUPPORTED_IMAGE, "free/open-source", "network-none; recorded HAR only; no published ports",
    "sanitized captures; unverified named labels; no login or engine credentials",
    "passive annotations only; no generated target requests",
    "updates/telemetry disabled; read-only root; isolated bounded temporary filesystem")

# Exact inventory measured by the pinned ZAP consumer.
ZAP_ADDONS = {
    "alertFilters": "29.0.0", "ascanrules": "84.0.0", "authhelper": "0.43.0",
    "automation": "0.61.0", "bruteforce": "21.0.0", "callhome": "0.23.0",
    "client": "0.33.0", "commonlib": "1.44.0", "database": "0.9.0", "diff": "18.0.0",
    "directorylistv1": "9.0.0", "domxss": "24.0.0", "encoder": "1.9.0", "exim": "0.22.0",
    "formhandler": "6.9.0", "fuzz": "13.17.0", "gettingStarted": "20.0.0",
    "graaljs": "0.14.0", "graphql": "0.35.0", "help": "22.0.0", "hud": "0.19.0",
    "insights": "0.6.0", "invoke": "17.0.0", "network": "0.30.0", "oast": "0.26.0",
    "onlineMenu": "15.0.0", "openapi": "58.0.0", "params": "0.1.0", "postman": "0.10.0",
    "pscan": "0.6.0", "pscanrules": "76.0.0", "quickstart": "60.0.0", "replacer": "22.0.0",
    "reports": "0.46.0", "requester": "7.10.0", "retest": "0.11.0", "retire": "0.66.0",
    "reveal": "10.0.0", "scanpolicies": "0.8.0", "scripts": "45.20.0", "selenium": "15.58.0",
    "sequence": "10.0.0", "soap": "32.0.0", "spider": "0.20.0", "spiderAjax": "23.33.0",
    "tips": "16.0.0", "webdriverlinux": "227.0.0", "websocket": "38.0.0", "zest": "48.14.0",
}


def inventory() -> dict:
    return {"version": zap.SUPPORTED_VERSION, "addons": dict(ZAP_ADDONS)}


def _capability(profile: ManagedProfile, launcher: str) -> dict:
    passive = profile == ZAP_PASSIVE
    return {"profile": asdict(profile), "available": launcher == "present",
        "installed": {"launcher": launcher, "consumer": "not-probed; checked on authorized start"},
        "loaded": "not-observed", "protocol_connected": "not-observed",
        "permitted": ("requires current passive/process grants and immutable recorded inputs" if passive
                      else "requires explicit owned active/process grants and immutable plan") if launcher == "present" else False,
        "owned_fixture": {"version": zap.SUPPORTED_VERSION,
            "source": "bundled owned fixtures; see tests/",
            "limits": "recorded sanitized HTTP/HTML; owned lifecycle/failure controls verified 2026-10-14; broader coverage unverified" if passive
                      else "owned HTTP/default-actor/Python rule 40012 only"},
        "addon_inventory_sha256": exchange.digest(exchange.canonical(inventory())),
        "unavailable_reason": None if launcher == "present" else "Docker launcher missing; no automatic install"}


def capabilities() -> dict:
    native = []
    for name in ("policy", "ledger", "identity", "verify", "replay", "exchange", "discover",
                 "oast", "race", "ws", "desync"):
        missing = name == "ws" and importlib.util.find_spec("websockets") is None
        native.append({"workflow": name, "engine": "native", "version": VERSION,
            "installed": "bundled", "permitted": "requires current mission and inputs",
            "available": not missing, "unavailable_reason": "Missing websockets dependency" if missing else None,
            "description": MODULES[name]})
    launcher = "present" if shutil.which("docker") else "absent"
    supporting = [_capability(profile, launcher) for profile in (ZAP_ACTIVE, ZAP_PASSIVE)]
    supporting.append({"profile": {"profile_id": browser_actor.PROFILE_ID, "engine": "browser-actors",
        "version": browser_actor.DRIVER_VERSION, "image": browser_actor.IMAGE, "edition": "free/open-source"},
        "available": launcher == "present", "installed": {"launcher": launcher, "consumer": "not-probed"},
        "permitted": "requires one owned actor, current browser mission and exact selected URLs" if launcher == "present" else False,
        "owned_fixture": {"source": "bundled owned fixtures; see tests/",
                          "limits": "owned literal-loopback HTTP; sandboxed network-none Chromium; no general login/crawl"},
        "unavailable_reason": None if launcher == "present" else "Docker launcher missing; no automatic install"})
    from bughunt.integrations import burp_intake
    supporting.append(burp_intake.doctor())
    for name, engine_name, reason in (
            ("burp-specialist", "Burp Community", "No accepted hook/transport profile; managed sends unavailable"),):
        supporting.append({"profile_id": name, "engine": engine_name, "available": False,
            "installed": "unprobed", "loaded": "unprobed", "protocol_connected": "unprobed",
            "permitted": False, "owned_fixture": "not accepted for this workflow",
            "edition": "free only; paid Burp features unavailable", "unavailable_reason": reason})
    return {"native": native, "supporting": supporting, "installation_probe": "filesystem only; no process or network"}


def prepare(profile_id: str, exchange_id: str | list[str], **options: object):
    identifiers = [exchange_id] if isinstance(exchange_id, str) else exchange_id
    actors = options.pop("actors", None)
    alerts = options.pop("alerts", 10)
    requests = options.pop("requests", None)
    if profile_id == browser_actor.PROFILE_ID:
        if (not isinstance(actors, list) or len(actors) != 1 or alerts != 10 or options.get("technology") is not None
                or set(options) - {"mission", "owned_lab", "technology", "seconds", "max_bytes"}):
            raise ValueError("Browser profile requires one named actor, not ZAP scan options")
        return browser_actor.prepare(identifiers, actor=actors[0], mission=options.get("mission"),
            owned_lab=options.get("owned_lab", False), requests=20 if requests is None else requests,
            seconds=options.get("seconds", 120), max_bytes=options.get("max_bytes", 65536))
    if profile_id == "burp-mcp-intake":
        from bughunt.integrations import burp_intake
        if (not isinstance(identifiers, list) or len(identifiers) != 1 or actors or alerts != 10
                or options.get("owned_lab") or options.get("technology") is not None or requests is not None
                or options.get("max_bytes", 65536) != 65536):
            raise ValueError("Burp intake takes one exact source URL and no active/passive-scan options")
        return burp_intake.prepare(url=identifiers[0], mission=options.get("mission"),
            source_id=options.get("source_id"), method=options.get("method", "GET"), config=options.get("config"),
            offset=options.get("offset", 0), count=options.get("count", 1), seconds=options.get("seconds", 30))
    if profile_id == ZAP_PASSIVE.profile_id:
        from bughunt.integrations import zap_passive
        if not actors or options.get("owned_lab") or options.get("technology") is not None or requests is not None:
            raise ValueError("Passive profile requires named actors, not active target-send options")
        seconds = options.get("seconds", 120)
        if type(seconds) is float and seconds.is_integer():
            seconds = int(seconds)
        return zap_passive.prepare(identifiers, actors=actors, mission=options.get("mission"),
                                  seconds=seconds, alerts=alerts, max_bytes=options.get("max_bytes", 65536))
    if profile_id != ZAP_ACTIVE.profile_id:
        raise ValueError("Unsupported or unavailable managed engine profile")
    if not isinstance(identifiers, list) or len(identifiers) != 1 or actors or alerts != 10:
        raise ValueError("Owned active profile requires one exchange and no passive options")
    return zap_active.prepare(identifiers[0], requests=40 if requests is None else requests, **options)


def descriptor(plan: zap_active.Plan) -> dict:
    if isinstance(plan, browser_actor.Plan):
        return browser_actor.descriptor(plan)
    from bughunt.integrations import burp_intake
    if isinstance(plan, burp_intake.Plan):
        return burp_intake.descriptor(plan)
    if not isinstance(plan, zap_active.Plan):
        from bughunt.integrations import zap_passive
        return zap_passive.descriptor(plan)
    plan.budget.check(httpx.Request("GET", plan.url))
    helper = Path(zap_active.__file__).with_name("zap_consumer.py")
    return {**asdict(ZAP_ACTIVE), "operation": "active_scan", "target": plan.url.split("?", 1)[0],
        "permitted_targets": [{"method": "GET", "route": plan.url.split("?", 1)[0],
                               "query_parameter": plan.parameter, "query_values": "mutable within URL cap"}],
        "actor": plan.budget.state[0][1], "actor_revision": plan.budget.state[0][2],
        "source_exchange_id": plan.source_id, "source_sha256": plan.budget.source_hash,
        "policy_sha256": plan.budget.state[1],
        "plan_sha256": exchange.digest(exchange.canonical(zap_active.automation_plan(plan))),
        "consumer_sha256": zap_active.ActiveBudget._hash(helper, 1000000),
        "addon_inventory_sha256": exchange.digest(exchange.canonical(inventory())),
        "hash_representation": "canonical JSON plan/inventory; exact source/helper bytes",
        "budgets": {"physical_requests": plan.budget.maximum, "seconds": plan.budget.seconds,
                    "concurrency": 1, "response_bytes": plan.max_bytes, "engine_request_bytes": 65536,
                    "url_bytes": 8192},
        "expected_artifacts": ["provenance.json", "attempts.json", "consumer.log", "input/plan.json",
                               "input/bounds.json", "engine/rpc/READY", "engine/reports/active.json"],
        "attribution": "final logical HTTP request captures and hashes; not wire-byte parity"}


def preview(plan: zap_active.Plan) -> dict:
    if isinstance(plan, browser_actor.Plan):
        return browser_actor.preview(plan)
    from bughunt.integrations import burp_intake
    if isinstance(plan, burp_intake.Plan):
        return burp_intake.preview(plan)
    if not isinstance(plan, zap_active.Plan):
        from bughunt.integrations import zap_passive
        return zap_passive.preview(plan)
    return {**zap_active.preview(plan), "engine_plan": descriptor(plan)}


def run(plan: zap_active.Plan, on_start: Callable[[str], None] | None = None) -> dict:
    if isinstance(plan, browser_actor.Plan):
        from bughunt.integrations import browser_runtime
        return browser_runtime.run(plan, on_start=on_start)
    from bughunt.integrations import burp_intake
    if isinstance(plan, burp_intake.Plan):
        return burp_intake.run(plan, on_start=on_start)
    if not isinstance(plan, zap_active.Plan):
        from bughunt.integrations import zap_passive
        return zap_passive.run(plan, on_start=on_start)
    from bughunt.integrations import zap_runtime
    return zap_runtime.run(plan, on_start=on_start)
