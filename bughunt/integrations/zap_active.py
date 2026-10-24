"""Guarded ZAP active profile; initial support is an explicitly owned HTTP lab."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from urllib.parse import parse_qsl, urlsplit

import httpx

from bughunt.core import egress, exchange, identity, job, ledger
from bughunt.integrations import zap
from bughunt.core.session import load_legacy_session
from bughunt.core.policy import Profile
from bughunt.core.workspace import matches, read_entries, workspace_dir

MISSION = "whk012-owned-active"
RULE_IDS = [40012]
_CREDENTIAL = re.compile(r"cookie|auth|token|api[-_]?key|secret|session|csrf", re.I)


class ActiveBudget(job.Budget):
    def __init__(self, seed_url: str, parameter: str, source_path: Path, maximum: int, seconds: float):
        self.seed_url, self.parameter, self.source_path = seed_url, parameter, source_path
        self.route = exchange.target_parts(seed_url)
        self.source_hash = self._hash(source_path, exchange.INPUT_LIMIT)
        self.session_hash = self._session_hash()
        self.artifacts = {}
        super().__init__(frozenset({("GET", seed_url)}), maximum, seconds, strict_scope=True)

    def bind_artifacts(self, paths: list[Path]) -> None:
        self.artifacts.update({path: self._hash(path, 1000000) for path in paths})

    @staticmethod
    def _hash(path: Path, maximum: int) -> str:
        if path.is_symlink() or path.stat().st_size > maximum:
            raise ValueError("Active input size or path changed")
        with path.open("rb") as handle:
            raw = handle.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("Active input grew")
        return exchange.digest(raw)

    def _session_hash(self):
        path = workspace_dir() / "session.txt"
        return self._hash(path, 1000000) if path.exists() else None

    def check(self, request: httpx.Request) -> None:
        target = str(request.url)
        parameters = parse_qsl(urlsplit(target).query, keep_blank_values=True, max_num_fields=1, strict_parsing=True)
        if (request.method != "GET" or request.content or len(target) > 8192
                or exchange.target_parts(target) != self.route
                or len(parameters) != 1 or parameters[0][0] != self.parameter):
            raise egress.PolicyBlocked("zap-generated-target-not-approved")
        if (self._hash(self.source_path, exchange.INPUT_LIMIT) != self.source_hash
                or self._session_hash() != self.session_hash
                or any(self._hash(path, 1000000) != digest for path, digest in self.artifacts.items())):
            raise egress.PolicyBlocked("zap-source-or-default-session-changed")
        super().check(httpx.Request("GET", self.seed_url))


@dataclass(frozen=True)
class Plan:
    source_id: str
    url: str
    parameter: str
    technology: str
    budget: ActiveBudget
    max_bytes: int
    profile: Profile


def _source(exchange_id: str, owned_lab: bool) -> tuple[str, str]:
    record = exchange.read(exchange_id)
    request, response = record["request"], record["response"]
    parsed = urlsplit(request["url"])
    if str(httpx.URL(request["url"])) != request["url"]:
        raise ValueError("Canonical HTTPX target required for exact request accounting")
    if (owned_lab is not True or parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or not ipaddress.ip_address(parsed.hostname).is_loopback
            or not parsed.path.startswith("/__bughunt_lab__/")):
        raise ValueError("Initial active profile requires explicit owned literal-loopback HTTP laboratory paths")
    if (request["method"] != "GET" or request["body_size"] or request["truncated"] or response is None
            or response["truncated"] or response["status"] != 200
            or not any(value.lower().startswith("text/html") for value in exchange.header_values(response, "content-type"))):
        raise ValueError("Require a complete bodyless GET with an owned HTML baseline")
    parameters = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=1, strict_parsing=True)
    if (len(parameters) != 1 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", parameters[0][0])
            or _CREDENTIAL.search(parameters[0][0])):
        raise ValueError("Initial active profile requires exactly one non-credential query input")
    return request["url"], parameters[0][0]


def prepare(exchange_id: str, *, mission: str, owned_lab=False, technology: str,
            requests=40, seconds=120, max_bytes=65536) -> Plan:
    url, parameter = _source(exchange_id, owned_lab)
    profile = egress.authorize(url, "active_scan", "GET")
    egress.authorize(url, "process", "GET")
    if (mission != MISSION or profile.mission != mission or technology != "Python"
            or identity.selected_name() != "default" or load_legacy_session()
            or any(_CREDENTIAL.search(name) for name, _value in profile.required_headers)
            or not matches(urlsplit(url).hostname, read_entries())):
        raise ValueError("Named active mission, explicit technology/scope and credential-free default actor required")
    if type(max_bytes) is not int or not 1 <= max_bytes <= 65536:
        raise ValueError("Response cap must be 1..65536")
    source_path = exchange.directory() / f"{exchange_id}.json"
    budget = ActiveBudget(url, parameter, source_path, requests, seconds)
    return Plan(exchange_id, url, parameter, technology, budget, max_bytes, profile)


def preview(plan: Plan) -> dict:
    return {"job_id": plan.budget.job_id, "source_exchange_id": plan.source_id,
            "target": plan.url.split("?", 1)[0], "method": "GET", "operation": "active_scan",
            "technology": plan.technology, "rule_ids": list(RULE_IDS), "request_cap": plan.budget.maximum,
            "duration_cap": plan.budget.seconds, "body_limit": plan.max_bytes, "actor": "default", "dry_run": True,
            "warning": "Owned HTTP-only query profile; not HTTPS/authentication or full scanner coverage"}


def automation_plan(plan: Plan) -> dict:
    origin, path = exchange.target_parts(plan.url)
    include = zap._regex(origin, path)
    return {"env": {"contexts": [{"name": MISSION, "urls": [plan.url], "includePaths": [include],
                "excludePaths": ["^(?!(?:" + include[1:-1] + ")$).*$"],
                "technology": {"include": [plan.technology]}}],
                "parameters": {"failOnError": True, "failOnWarning": True, "continueOnFailure": False,
                               "progressToStdout": True}},
            "jobs": [{"type": "requestor", "requests": [{"url": plan.url, "method": "GET", "responseCode": 200}]},
                     {"type": "activeScan", "parameters": {"context": MISSION, "url": plan.url,
                       "maxRuleDurationInMins": 1, "maxScanDurationInMins": 1, "threadPerHost": 1,
                       "handleAntiCSRFTokens": False, "maxAlertsPerRule": 1},
                      "policyDefinition": {"defaultThreshold": "Off", "defaultStrength": "Low",
                       "rules": [{"id": 40012, "strength": "Low", "threshold": "Low"}]}},
                     {"type": "report", "alwaysRun": True, "parameters": {"template": "traditional-json",
                       "reportDir": "/proof/reports", "reportFile": "active", "displayReport": False}}]}
