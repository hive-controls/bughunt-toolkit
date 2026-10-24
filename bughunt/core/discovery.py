"""Small explicit input probes with repeated baselines and negative controls."""

from __future__ import annotations

from dataclasses import dataclass
import re
import uuid
from urllib.parse import parse_qsl, urlsplit

import httpx

from bughunt.core import egress, exchange, identity, job, ledger
from bughunt.core.workspace import allowed

_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
_SECRET = re.compile(r"cookie|auth|token|api[-_]?key|secret|session|csrf", re.I)
_RESERVED = {"host", "connection", "content-length", "transfer-encoding", "expect", "upgrade",
             "user-agent", "cache-control", "pragma", "te", "trailer", "accept-encoding"}


@dataclass(frozen=True)
class Plan:
    source_id: str
    method: str
    url: str
    probes: tuple[dict, ...]
    budget: job.Budget
    max_bytes: int


def _candidates(values: list, request: dict, profile) -> list[tuple[str, str]]:
    if not isinstance(values, list) or not 1 <= len(values) <= 40:
        raise ValueError("Supply 1..40 explicit candidates")
    existing = {"header": {name.lower() for name, _ in request["headers"]},
                "query": {name.lower() for name, _ in parse_qsl(urlsplit(request["url"]).query)},
                "cookie": {item.split("=", 1)[0].strip().lower()
                           for value in exchange.header_values(request, "cookie") for item in value.split(";")}}
    reserved = _RESERVED | {name.lower() for name, _ in profile.required_headers}
    result, seen = [], set()
    for value in values:
        if not isinstance(value, (list, tuple)) or len(value) != 2:
            raise ValueError("Candidate needs kind and name")
        kind, name = value
        if kind not in existing or not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("Invalid candidate")
        if _SECRET.search(name) or name.lower() in existing[kind] or (kind == "header" and name.lower() in reserved):
            raise ValueError("Candidate edits an existing, routing, framing or credential field")
        dedup_key = kind, name.lower()
        if dedup_key in seen:
            raise ValueError("Duplicate candidate")
        if kind == "cookie" and identity.selected_name() != "default":
            raise ValueError("Cookie probes require the credential-free default actor")
        seen.add(dedup_key)
        result.append((kind, name))
    return result


def _probe(method: str, url: str, headers: tuple, role: str, kind=None, name=None, marker=None) -> dict:
    pairs = list(headers)
    if kind == "query":
        url = str(httpx.URL(url).copy_add_param(name, marker))
    elif kind == "header":
        pairs.append((name, marker))
    elif kind == "cookie":
        pairs.append(("Cookie", name + "=" + marker))
    return {"role": role, "kind": kind, "name": name, "method": method, "url": url, "headers": pairs}


def prepare(record: dict, candidates: list, *, maximum=30, seconds=60, max_bytes=65536) -> Plan:
    exchange.validate(record)
    request = record["request"]
    if request["truncated"] or request["body_size"] or request["method"] not in {"GET", "HEAD"}:
        raise ValueError("Discovery requires a complete bodyless GET/HEAD capture")
    if type(max_bytes) is not int or not 1 <= max_bytes <= 1_000_000:
        raise ValueError("Invalid response cap")
    method, url = request["method"], request["url"]
    profile = egress.authorize(url, "fuzz", method)
    values = _candidates(candidates, request, profile)
    headers = tuple((name, value) for name, value in request["headers"]
                    if not _SECRET.search(name) and name.lower() not in _RESERVED | {"host"})
    headers += (("Cache-Control", "no-store, no-cache"), ("Pragma", "no-cache"), ("Accept-Encoding", "identity"))
    marker = "whk" + uuid.uuid4().hex
    probes = [_probe(method, url, headers, "baseline") for _ in range(2)]
    for kind in sorted({kind for kind, _ in values}):
        name = "whk_control_" + uuid.uuid4().hex
        probes.extend(_probe(method, url, headers, "control", kind, name, marker) for _ in range(2))
    for kind, name in values:
        probes.extend(_probe(method, url, headers, "candidate", kind, name, marker) for _ in range(2))
    probes.append(_probe(method, url, headers, "baseline"))
    if type(maximum) is not int or len(probes) > maximum:
        raise ValueError("Budget cannot cover repeated baseline, controls and candidates")
    for probe in probes:
        if not allowed(probe["url"]):
            raise ValueError("Workspace scope blocks discovery")
        egress.authorize(probe["url"], "fuzz", method)
    ledger.redact_text("")
    budget = job.Budget(frozenset((method, probe["url"]) for probe in probes), maximum, seconds)
    return Plan(record["exchange_id"], method, url, tuple(probes), budget, max_bytes)


def preview(plan: Plan) -> dict:
    return {"source_exchange_id": plan.source_id, "operation": "fuzz", "actor": plan.budget.state[0][1],
            "planned_requests": len(plan.probes), "request_cap": plan.budget.maximum,
            "duration_cap": plan.budget.seconds, "target": plan.url, "dry_run": True,
            "warning": "Read-only probes can still change server/cache state; no cache-safety guarantee"}


def _sample(response, probe, plan) -> dict:
    body = bytearray()
    valid = True
    for chunk in response.iter_raw():
        plan.budget.check(response.request)
        if len(body) + len(chunk) > plan.max_bytes:
            valid = False
            break
        body.extend(chunk)
    cache = response.headers.get("cache-control", "").lower()
    warning = ("public" in cache or "s-maxage" in cache or "age" in response.headers
               or "hit" in response.headers.get("x-cache", "").lower()
               or response.headers.get("cf-cache-status", "").lower() == "hit")
    valid &= not response.is_redirect and response.headers.get("content-encoding", "identity") == "identity"
    return {"role": probe["role"], "kind": probe["kind"], "name": probe["name"],
            "run_id": response.extensions["bughunt_run_id"], "valid": valid, "cache_warning": warning,
            "fingerprint": [response.status_code, response.headers.get("content-type", ""), exchange.digest(bytes(body))]}


def _result(samples: list) -> dict:
    baseline = [value["fingerprint"] for value in samples if value["role"] == "baseline"]
    usable = (len(baseline) == 3 and all(value == baseline[0] for value in baseline)
              and all(value["valid"] and not value["cache_warning"] for value in samples)
              and all(value["fingerprint"] == baseline[0] for value in samples if value["role"] == "control"))
    candidates = {}
    for sample in samples:
        if sample["role"] == "candidate":
            candidates.setdefault((sample["kind"], sample["name"]), []).append(sample["fingerprint"])
    observations = []
    for (kind, name), prints in candidates.items():
        outcome = ("lead" if prints[0] != baseline[0] else "negative") if usable and len(prints) == 2 and prints[0] == prints[1] else "inconclusive"
        observations.append({"kind": kind, "name": name, "classification": outcome,
                             "confirmed": False, "manual_controls_required": True})
    outcome = "inconclusive" if not usable or any(row["classification"] == "inconclusive" for row in observations) else (
        "lead" if any(row["classification"] == "lead" for row in observations) else "negative")
    return {"classification": outcome, "observations": observations, "samples": samples,
            "claim": "Differential input leads only; no exploitation, severity or identity attestation"}


def execute(plan: Plan, *, transport=None) -> dict:
    profile = egress.authorize(plan.url, "fuzz", plan.method)
    samples, error = [], None
    token = ledger.CURRENT_TOOL.set("discovery")
    try:
        with egress.client(operation="fuzz", transport=job.Transport(plan.budget, transport), follow_redirects=False) as client:
            for probe in plan.probes:
                request = httpx.Request(plan.method, probe["url"], headers=probe["headers"])
                request.extensions["bughunt_job_guard"] = plan.budget.check
                try:
                    response = client.send(request, stream=True)
                    try:
                        samples.append(_sample(response, probe, plan))
                    finally:
                        response.close()
                except (ValueError, OSError, httpx.HTTPError) as exc:
                    error = type(exc).__name__
                    break
    finally:
        ledger.CURRENT_TOOL.reset(token)
    result = _result(samples) if error is None else {"classification": "invalid", "observations": [], "samples": samples, "error": error}
    result.update(source_exchange_id=plan.source_id, requests=list(plan.budget.sent),
                  request_cap=plan.budget.maximum, duration_cap=plan.budget.seconds,
                  cache_warning="Read-only probes may change state; no exploitation or follow-ups")
    result["run_id"] = ledger.record_analysis(profile, tool="discovery", operation="fuzz", target=plan.url,
                                              actor=plan.budget.state[0][1], value=result,
                                              classification=result["classification"])
    return ledger.redact(result)
