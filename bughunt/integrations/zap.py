"""Offline, secret-free ZAP 2.17.0 passive recorded-traffic bundles."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from bughunt.core import exchange, har, identity, ledger
from bughunt.core.policy import parse_profile, target_parts
from bughunt.core.workspace import workspace_dir

SUPPORTED_VERSION = "2.17.0"
SUPPORTED_IMAGE = "ghcr.io/zaproxy/zaproxy@sha256:7aaa659b0d43078febd82e29bad112285c370727e86ab8340444220e17d9f0d2"
CONTEXT_NAME = "Bughunt passive"
LOGGED_IN = "BUGHUNT_UNCONFIGURED_LOGGED_IN"
LOGGED_OUT = "BUGHUNT_UNCONFIGURED_LOGGED_OUT"


class ZapError(ValueError):
    pass


def _bounded(value, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ZapError("Passive limit is missing, unlimited or excessive")
    return value


def _regex(origin: str, path: str) -> str:
    # Java-compatible: ambiguous path forms cannot become a ZAP scope grant.
    guard = r"(?!(?:[^?]*//|[^?]*/[.]{1,2}(?:/|[?]|$)))"
    tail = r"[^%?*#\\\s]*" if path.endswith("/") else ""
    query = r"(?:[?][^#\\\s]*)?"
    return "^" + re.escape(origin) + guard + re.escape(path) + tail + query + "$"


def context_rules(profile) -> tuple[list[str], list[str]]:
    includes, excludes = [], []
    for row in profile.assets:
        target = includes if "passive" in row.operations and row.methods else excludes
        target.extend(_regex(row.origin, path) for path in row.paths)
    excludes.extend(_regex(row.origin, path) for row in profile.exclusions for path in row.paths)
    if not includes:
        raise ZapError("No explicit passive assets")
    includes = sorted(set(includes))
    # AF adds unescaped seed-url + .* includes. This exclusion neutralizes them.
    allowed_union = "|".join(pattern[1:-1] for pattern in includes)
    excludes.append("^(?!(?:" + allowed_union + ")$).*$")
    return includes, sorted(set(excludes))


def _actors(names: list[str], origins: set[str]) -> list[dict]:
    if not names or len(names) > 20 or len(names) != len(set(names)):
        raise ZapError("Select distinct named owned actors (maximum 20)")
    results = []
    for name in names:
        actor = identity.read_profile(name)
        if not origins.issubset(set(actor["origins"])):
            raise ZapError("Every selected actor must own every selected origin")
        results.append({"name": name, "kind": actor["kind"], "owned": True,
                        "authentication_ready": False})
    return results


def _eligible(records: list[dict], profile) -> list[dict]:
    if not records or len(records) > exchange.ENTRY_LIMIT:
        raise ZapError("Select 1 to 500 complete exchanges")
    seen, selected = set(), []
    for value in records:
        exchange.validate(value)
        if value["exchange_id"] in seen:
            raise ZapError("Duplicate selected exchange")
        seen.add(value["exchange_id"])
        request, response = value["request"], value["response"]
        if "${" in request["url"]:
            raise ZapError("Captured URL cannot contain Automation Framework variable syntax")
        if response is None or request["truncated"] or response["truncated"]:
            raise ZapError("Passive export needs complete request and response")
        if not exchange.scope_decision(request)["permitted"] or not profile.decide(
                request["url"], "passive", method=request["method"]).permitted:
            raise ZapError("Selected exchange lacks current passive permission")
        safe = exchange.project(value)
        if not exchange.scope_decision(safe["request"])["permitted"]:
            raise ZapError("Sanitized target is no longer eligible")
        origin, path = target_parts(safe["request"]["url"])
        query = urlsplit(safe["request"]["url"]).query
        if safe["request"]["url"] != origin + path + ("?" + query if query else ""):
            raise ZapError("Context export requires canonical URLs")
        selected.append(safe)
    return selected


def _context_xml(includes, excludes, actors) -> bytes:
    root = ET.Element("configuration")
    context = ET.SubElement(root, "context")
    for name, value in (("name", CONTEXT_NAME), ("desc", "Recorded passive traffic only; authentication unconfigured"),
                        ("inscope", "true")):
        ET.SubElement(context, name).text = value
    for tag, patterns in (("incregexes", includes), ("excregexes", excludes)):
        for pattern in patterns:
            ET.SubElement(context, tag).text = pattern
    auth = ET.SubElement(context, "authentication")
    for tag, value in (("type", "0"), ("strategy", "EACH_RESP"),
                       ("loggedin", LOGGED_IN), ("loggedout", LOGGED_OUT)):
        ET.SubElement(auth, tag).text = value
    users = ET.SubElement(context, "users")
    for number, actor in enumerate(actors):
        encoded = base64.b64encode(actor["name"].encode()).decode()
        ET.SubElement(users, "user").text = f"{number};false;{encoded};0;"
    ET.SubElement(context, "forceduser").text = "-1"
    ET.SubElement(ET.SubElement(context, "session"), "type").text = "0"
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _plan(selected, includes, excludes, actors, bundle: Path, seconds, alerts, body_limit) -> dict:
    context = {"name": CONTEXT_NAME,
               "urls": sorted({value["request"]["url"] for value in selected}),
               "includePaths": includes, "excludePaths": excludes,
               "authentication": {"method": "manual", "verification": {
                   "method": "response", "loggedInRegex": LOGGED_IN, "loggedOutRegex": LOGGED_OUT}},
               "sessionManagement": {"method": "cookie"},
               "users": [{"name": actor["name"]} for actor in actors]}
    return {"env": {"contexts": [context], "vars": {"BUGHUNT_BUNDLE_DIR": str(bundle.resolve())},
                    "parameters": {"failOnError": True, "failOnWarning": True,
                                   "continueOnFailure": False, "progressToStdout": True,
                                   "maxDuration": seconds}},
            "jobs": [
                {"type": "passiveScan-config", "parameters": {"scanOnlyInScope": True,
                    "maxAlertsPerRule": alerts, "maxBodySizeInBytesToScan": body_limit, "enableTags": False}},
                {"type": "import", "parameters": {"type": "har", "sendRequests": False,
                    "maxMessages": len(selected), "fileName": "${BUGHUNT_BUNDLE_DIR}/traffic.har"}},
                {"type": "passiveScan-wait", "parameters": {"maxDuration": max(1, seconds // 60)}},
                {"type": "report", "parameters": {"template": "traditional-json",
                    "reportDir": "${BUGHUNT_BUNDLE_DIR}/reports", "reportFile": "passive-report.json",
                    "reportTitle": "Bughunt passive hypotheses",
                    "reportDescription": "Sanitized recorded traffic; candidates only; authentication unconfigured",
                    "displayReport": False}}]}


def _guidance() -> bytes:
    return ("# Bughunt passive bundle\n\n"
            "Supported consumer: ZAP 2.17.0. Inspect manifest.json, context.context and plan.yaml.\n"
            "Use a fresh, isolated ZAP session. Set Protected mode (API value: protect) before use.\n"
            "Protected mode limits active tools; it does NOT make proxy browsing passive-only.\n"
            "Disable update checks and keep the fixture offline. No browsing, spider, requestor,\n"
            "active scan, login or callback job is included. HAR import sendRequests is false.\n"
            "Override BUGHUNT_BUNDLE_DIR for the consumer's absolute bundle path. Run ZAP's\n"
            "-autocheck before manually using -autorun; Bughunt never launches ZAP.\n\n"
            "Named users are labels only, with no credentials. Manual auth and sentinel regexes\n"
            "are placeholders, NOT verified login. Desktop imported users are disabled. Before\n"
            "any future authenticated live use, configure credentials privately and verify\n"
            "server-side principal/role plus logged-in/logged-out indicators independently.\n"
            "Do not reuse this passive plan as live execution authorization.\n\n"
            "Context regexes enforce canonical origin/path boundaries and exclusions, not HTTP\n"
            "methods. Bughunt checks selected methods at generation. Recheck policy freshness,\n"
            "hash and permissions before any later manual use; artifacts are snapshots only.\n"
            "Inspect the exported content for additional application-specific secrets. HAR is\n"
            "sanitized, binary/encoded bodies suppressed; this reduces passive coverage. Reports\n"
            "are hypotheses, not confirmed findings. Duration/alert/body caps are plan settings,\n"
            "not OS resource guarantees; enforce an external timeout/resource limit as well.\n").encode()


def build(records: list[dict], actors: list[str], output: Path, *, seconds=300,
          alerts=10, body_limit=65536) -> dict[str, bytes]:
    seconds, alerts = _bounded(seconds, 3600), _bounded(alerts, 100)
    body_limit = _bounded(body_limit, exchange.BODY_LIMIT)
    policy_path = workspace_dir() / "policy.json"
    policy_bytes = policy_path.read_bytes()
    profile = parse_profile(exchange.load_json(policy_bytes))
    if profile.freshness() != "verified" or not dict(profile.permissions)["passive"]:
        raise ZapError("Current explicit passive permission required")
    selected = _eligible(records, profile)
    named = _actors(actors, {target_parts(value["request"]["url"])[0] for value in selected})
    includes, excludes = context_rules(profile)
    plan = _plan(selected, includes, excludes, named, output, seconds, alerts, body_limit)
    files = {"plan.yaml": json.dumps(plan, indent=2, ensure_ascii=True).encode() + b"\n",
             "context.context": _context_xml(includes, excludes, named),
             "traffic.har": har.export(selected), "GUIDANCE.md": _guidance()}
    manifest = {"schema_version": 1, "supported_zap": SUPPORTED_VERSION,
                "supported_image": SUPPORTED_IMAGE, "generated_at": datetime.now(timezone.utc).isoformat(),
                "policy_sha256": exchange.digest(policy_bytes), "policy_version": profile.policy_version,
                "policy_verified_at": profile.verified_at.isoformat(),
                "policy_expires_at": (profile.verified_at.timestamp() + profile.stale_after_seconds),
                "mission": ledger.redact_text(profile.mission), "actors": named,
                "authentication_ready": False, "send_requests": False, "sanitized": True,
                "source_exchange_ids": [value["exchange_id"] for value in records],
                "derivative_exchange_ids": [value["exchange_id"] for value in selected],
                "limits": {"seconds": seconds, "alerts_per_rule": alerts,
                           "body_bytes": body_limit, "messages": len(selected)},
                "files": {name: exchange.digest(data) for name, data in files.items()}}
    files["manifest.json"] = exchange.canonical(manifest) + b"\n"
    if policy_path.read_bytes() != policy_bytes or profile.freshness() != "verified":
        raise ZapError("Policy changed or expired during generation")
    return files


def export(exchange_ids: list[str], actors: list[str], output: Path, **limits) -> dict:
    if output.exists():
        raise ZapError("Bundle destination already exists")
    files = build([exchange.read(key) for key in exchange_ids], actors, output, **limits)
    output.mkdir(parents=False)
    (output / "reports").mkdir()
    for name, data in files.items():
        with (output / name).open("xb") as handle:
            handle.write(data)
        (output / name).chmod(0o600)
    return {"output": str(output), "exchanges": len(exchange_ids), "supported_zap": SUPPORTED_VERSION,
            "send_requests": False, "authentication_ready": False}
