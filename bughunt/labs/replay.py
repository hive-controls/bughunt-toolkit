"""Bounded, verified comparison of one owned request across three actors."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import re
import time

import httpx

from bughunt.core import egress, identity, ledger, verification
from bughunt.modules.repeater import RawRequest, render, request_url
from bughunt.core.policy import target_parts
from bughunt.core.workspace import workspace_dir

_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
_CREDENTIAL = re.compile(r"cookie|auth|token|api[-_]?key|secret|session|csrf", re.I)
_READ_METHODS = {"GET", "HEAD", "OPTIONS"}
_DENIALS = {401, 403, 404}


class ReplayError(ValueError):
    def __init__(self, reason: str, exchange: dict | None = None):
        super().__init__(reason)
        self.exchange = exchange or {}


@dataclass(frozen=True)
class Plan:
    method: str
    url: str
    headers: tuple
    body: bytes
    source: bytes
    baseline: bytes
    actors: tuple[str, str, str]
    selected_headers: tuple[str, ...]
    observe_url: str | None
    max_bytes: int
    timeout: float
    state: tuple


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def _state(actors: tuple) -> tuple:
    workspace = workspace_dir().resolve()
    profiles = tuple((name, identity.read_profile(name)["revision"],
                      _hash(_canonical(verification.read_configuration(name)))) for name in actors)
    return str(workspace), _hash((workspace / "policy.json").read_bytes()), profiles


def _ensure_state(plan: Plan) -> None:
    try:
        if _state(plan.actors) != plan.state:
            raise ReplayError("replay-state-changed")
        for target in (plan.url, plan.observe_url, *(verification.read_configuration(name)["url"]
                                                   for name in plan.actors)):
            if target is not None:
                verification.require_workspace_scope(target)
    except (OSError, identity.IdentityError, verification.VerificationError) as exc:
        raise ReplayError("replay-state-changed") from exc


def _validate_request(request: RawRequest) -> str:
    if not _TOKEN.fullmatch(request.method) or request.version not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ReplayError("baseline-request-invalid")
    if not request.target.startswith(("/", "http://", "https://")):
        raise ReplayError("baseline-target-invalid")
    if "#" in request.target or request.target.startswith("//"):
        raise ReplayError("baseline-target-invalid")
    framing, hosts = [], []
    for name, value in request.headers:
        if not _TOKEN.fullmatch(name) or any(ord(char) < 32 or ord(char) > 255 for char in value):
            raise ReplayError("baseline-header-invalid")
        if name.lower() == "transfer-encoding":
            raise ReplayError("baseline-transfer-encoding-unsupported")
        if name.lower() == "content-length":
            framing.append(value)
        if name.lower() == "host":
            hosts.append(value)
    if len(hosts) != 1 or len(framing) > 1:
        raise ReplayError("baseline-framing-invalid")
    if framing and (not framing[0].isascii() or not framing[0].isdigit()
                    or int(framing[0]) != len(request.body)):
        raise ReplayError("baseline-framing-invalid")
    url = request_url(request, None)
    origin, _path = target_parts(url)
    if target_parts(f"{url.split(':', 1)[0]}://{hosts[0]}/")[0] != origin:
        raise ReplayError("baseline-host-mismatch")
    return url


def _validate_source(source: bytes) -> None:
    lines = source.splitlines()
    parts = lines[0].decode("latin-1").split() if lines else []
    if len(parts) != 3 or parts[2] not in {"HTTP/1.0", "HTTP/1.1"}:
        raise ReplayError("source-request-line-invalid")
    if parts[1].startswith(("http://", "https://")):
        try:
            target_parts(parts[1])
        except ValueError as exc:
            raise ReplayError("source-target-invalid") from exc


def prepare(request: RawRequest, source: bytes, actors: tuple[str, str, str], *,
            selected_headers=("content-type", "location"), observe_url=None,
            max_bytes=65536, timeout=15) -> Plan:
    if not isinstance(source, bytes) or not isinstance(request.body, bytes):
        raise ReplayError("baseline-request-invalid")
    actors = tuple(actors)
    _validate_source(source)
    if (len(actors) != 3 or len(set(actors)) != 3
            or type(max_bytes) is not int or not 0 < max_bytes <= ledger.CAPTURE_LIMIT
            or type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= 30):
        raise ReplayError("replay-options-invalid")
    if len(source) > 8 * 1024 * 1024 or len(render(request)) > ledger.CAPTURE_LIMIT:
        raise ReplayError("baseline-too-large")
    url = _validate_request(request)
    verification.require_workspace_scope(url)
    if observe_url is not None:
        verification.require_workspace_scope(observe_url)
    chosen = tuple(name.lower() for name in selected_headers)
    if (len(chosen) > 16 or len(set(chosen)) != len(chosen)
            or any(not _TOKEN.fullmatch(name) for name in chosen)):
        raise ReplayError("comparison-headers-invalid")
    configurations = []
    for name, kind in zip(actors, ("owner", "lower_privilege", "anonymous")):
        if identity.read_profile(name)["kind"] != kind:
            raise ReplayError("actor-kind-mismatch")
        configurations.append(verification.read_configuration(name))
        verification.require_workspace_scope(configurations[-1]["url"])
        verification.require_verification_origin(url, configurations[-1])
        with identity.actor_context(name):
            identity.snapshot(url)
            egress.authorize(url, "manual", request.method)
            egress.authorize(configurations[-1]["url"], "manual", "GET")
    if configurations[0]["expected_principal"] == configurations[1]["expected_principal"]:
        raise ReplayError("distinct-owned-principals-required")
    if observe_url is not None:
        verification.require_verification_origin(observe_url, configurations[0])
        with identity.actor_context(actors[0]):
            identity.snapshot(observe_url)
            egress.authorize(observe_url, "manual", "GET")
    headers = tuple((name, value) for name, value in request.headers
                    if name.lower() != "content-length")
    return Plan(request.method, url, headers, request.body, source, render(request), actors,
                chosen, observe_url, max_bytes, timeout, _state(actors))


def preview(plan: Plan) -> dict:
    _ensure_state(plan)
    origin, path = target_parts(plan.url)
    return {"method": plan.method, "target": origin + path, "actors": list(plan.actors),
            "baseline_sha256": _hash(plan.baseline), "observer": bool(plan.observe_url),
            "max_bytes": plan.max_bytes, "network_requests": 0}


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ReplayError("ambiguous-json")
        result[key] = value
    return result


def _json(body: bytes):
    def reject_constant(value):
        raise ReplayError("invalid-json")
    document = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_pairs,
                          parse_constant=reject_constant)
    _canonical(document)
    return document


def _normalized(body: bytes, content_type: str) -> tuple[bytes | None, str]:
    if "json" in content_type.lower():
        try:
            return _canonical(_json(body)), "canonical-json"
        except (ValueError, UnicodeError, RecursionError):
            return None, "ambiguous-or-invalid-json"
    try:
        return body.decode("utf-8").replace("\r\n", "\n").encode(), "utf8-newlines"
    except UnicodeError:
        return body, "binary"


def _request_fingerprint(request: httpx.Request) -> str:
    headers = sorted((name.lower(), value) for name, value in request.headers.multi_items()
                     if not _CREDENTIAL.search(name))
    return _hash(_canonical([request.method, str(request.url), headers, _hash(request.content)]))


def _read(response: httpx.Response, plan: Plan) -> tuple[bytes, bool]:
    body = bytearray()
    deadline = time.monotonic() + plan.timeout
    chunks = [response.content] if response.is_closed else response.iter_raw(chunk_size=8192)
    for chunk in chunks:
        if time.monotonic() > deadline:
            raise ReplayError("response-deadline-exceeded")
        body.extend(chunk[:plan.max_bytes + 1 - len(body)])
        if len(body) > plan.max_bytes:
            return bytes(body[:plan.max_bytes]), True
    return bytes(body), False


def _summary(response: httpx.Response, body: bytes, truncated: bool, plan: Plan) -> dict:
    normalized, representation = _normalized(body, response.headers.get("content-type", ""))
    run_id = response.extensions.get("bughunt_run_id")
    if not isinstance(run_id, str):
        raise ReplayError("exchange-ledger-missing")
    manifest = ledger.manifest_for(run_id)
    return {"run_id": run_id, "verification_run_id": manifest.get("verification_run_id"),
            "status": response.status_code, "size": len(body), "body_sha256": _hash(body),
            "normalized_body_sha256": _hash(normalized) if normalized is not None else None,
            "normalization": representation, "truncated": truncated,
            "encoding_supported": response.headers.get("content-encoding", "identity").lower() == "identity",
            "cached": (response.headers.get("age", "0") != "0"
                       or "hit" in response.headers.get("x-cache", "").lower()),
            "headers": {name: _hash(_canonical(response.headers.get_list(name)))
                        for name in plan.selected_headers},
            "request_sha256": _request_fingerprint(response.request)}


def _send(plan: Plan, name: str, *, observer: bool, transport=None) -> tuple[dict, bytes]:
    _ensure_state(plan)
    token = ledger.CURRENT_TOOL.set("replay-observer" if observer else "replay")
    try:
        with identity.actor_context(name):
            with egress.client(timeout=plan.timeout, transport=transport, follow_redirects=False) as client:
                request = (httpx.Request("GET", plan.observe_url, headers={"Accept": "application/json"})
                           if observer else httpx.Request(plan.method, plan.url,
                                                         headers=plan.headers, content=plan.body))
                response = verification.verify_and_send(client, request, stream=True)
                try:
                    body, truncated = _read(response, plan)
                except (httpx.HTTPError, ReplayError) as exc:
                    run_id = response.extensions.get("bughunt_run_id")
                    manifest = ledger.manifest_for(run_id) if run_id else {}
                    exc.exchange = {"run_id": run_id, "status": response.status_code,
                                    "verification_run_id": manifest.get("verification_run_id")}
                    raise
                finally:
                    response.close()
                summary = _summary(response, body, truncated, plan)
                try:
                    _ensure_state(plan)
                except ReplayError as exc:
                    exc.exchange = summary
                    raise
                if not summary["verification_run_id"]:
                    raise ReplayError("verification-ledger-missing", summary)
                return summary, body
    finally:
        ledger.CURRENT_TOOL.reset(token)


def _observe(plan: Plan, transport) -> tuple[dict, object]:
    summary, body = _send(plan, plan.actors[0], observer=True, transport=transport)
    if (not 200 <= summary["status"] < 300 or summary["truncated"]
            or not summary["encoding_supported"] or summary["cached"]):
        raise ReplayError("observer-unreliable", summary)
    try:
        return summary, _json(body)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ReplayError("observer-json-invalid", summary) from exc


def _effects(before: tuple, after: tuple) -> dict:
    previous, current = before[1], after[1]
    if isinstance(previous, dict) and isinstance(current, dict):
        changed = sorted(key for key in previous.keys() | current.keys()
                         if key not in previous or key not in current
                         or _canonical(previous[key]) != _canonical(current[key]))
    else:
        changed = ["$"] if _canonical(previous) != _canonical(current) else []
    return {"before_run_id": before[0]["run_id"], "after_run_id": after[0]["run_id"],
            "before_sha256": _hash(_canonical(previous)), "after_sha256": _hash(_canonical(current)),
            "changed_count": len(changed), "changed_fields_sha256": _hash(_canonical(changed))}


def _unreliable(exchange: dict) -> bool:
    return (exchange["truncated"] or exchange["cached"] or not exchange["encoding_supported"]
            or exchange["normalized_body_sha256"] is None or 300 <= exchange["status"] < 400)


def _compare(baseline: dict, candidate: dict, method: str) -> dict:
    result = {"actor": candidate["actor"], "run_id": candidate.get("run_id"),
              "classification": "inconclusive", "reason": "different-success-or-unresolved-response"}
    if candidate.get("error"):
        return dict(result, classification="invalid", reason=candidate["error"])
    facts = {"status_equal": baseline["status"] == candidate["status"],
             "headers_equal": baseline["headers"] == candidate["headers"],
             "body_equal": baseline["normalized_body_sha256"] == candidate["normalized_body_sha256"]}
    result.update(facts)
    if candidate["request_sha256"] != baseline["request_sha256"]:
        return dict(result, classification="invalid", reason="non-identity-request-fields-changed")
    if _unreliable(baseline) or _unreliable(candidate):
        return dict(result, reason="partial-cached-encoded-or-redirected-response")
    effects = candidate.get("side_effects")
    baseline_effects = baseline.get("side_effects")
    if effects is not None and baseline_effects is not None:
        result["changed_fields_equal"] = effects["changed_fields_sha256"] == baseline_effects["changed_fields_sha256"]
        if effects["changed_count"] and baseline_effects["changed_count"] and result["changed_fields_equal"]:
            return dict(result, classification="lead", reason="matching-observed-state-change")
        if effects["changed_count"]:
            return dict(result, reason="different-observed-state-change")
    if method not in _READ_METHODS and effects is None:
        return dict(result, reason="state-observation-missing")
    if facts["body_equal"] and baseline["size"] > 0:
        if facts["headers_equal"]:
            return dict(result, classification="lead", reason="matching-positive-body-review-required")
        return dict(result, reason="matching-positive-body-with-different-headers")
    if candidate["status"] in _DENIALS:
        reason = ("denied-with-different-body" if method in _READ_METHODS else
                  "denied-with-different-body-and-no-observed-state-change")
        return dict(result, classification="negative", reason=reason)
    return result


def _attempt(plan: Plan, name: str, transport, attempts: list) -> dict:
    item = {"actor": name}
    attempts.append(item)
    stage = "before-observation"
    try:
        before = _observe(plan, transport) if plan.observe_url else None
        if before is not None:
            item["observation_before_run_id"] = before[0]["run_id"]
        stage = "target"
        summary, _body = _send(plan, name, observer=False, transport=transport)
        item.update(summary)
        stage = "after-observation"
        if before is not None:
            item["side_effects"] = _effects(before, _observe(plan, transport))
    except (ReplayError, verification.VerificationError, identity.IdentityError,
            httpx.HTTPError, OSError, RecursionError) as exc:
        exchange = getattr(exc, "exchange", {})
        if stage == "target":
            item.update(exchange)
        elif exchange:
            item["observation_error_exchange"] = exchange
        item["error"] = str(exc) if isinstance(exc, ReplayError) else type(exc).__name__
    return item


def _baseline_outcome(baseline: dict, plan: Plan) -> tuple[str, str] | None:
    if baseline.get("error") or not 200 <= baseline.get("status", 0) < 300:
        return "invalid", "positive-owner-baseline-missing"
    if _unreliable(baseline):
        return "inconclusive", "owner-baseline-unreliable"
    if plan.method not in _READ_METHODS and plan.observe_url:
        if not baseline["side_effects"]["changed_count"]:
            return "invalid", "positive-owner-state-change-missing"
    return None


def execute(plan: Plan, *, transport=None) -> dict:
    capture = ledger.begin(egress.current_profile(), tool="replay", operation="manual",
                           target=plan.url, request=plan.baseline, actor=plan.actors[0])
    capture.manifest.update(representation="authorization-differential", automatic_finding=False,
                            source=ledger._evidence(capture.root / "source.http", plan.source, False),
                            comparisons=[], attempts=[])
    try:
        _ensure_state(plan)
        attempts = capture.manifest["attempts"]
        baseline = _attempt(plan, plan.actors[0], transport, attempts)
        capture.manifest["positive_baseline_run_id"] = baseline.get("run_id")
        failure = _baseline_outcome(baseline, plan)
        if failure is not None:
            classification, reason = failure
        else:
            comparisons = capture.manifest["comparisons"]
            for name in plan.actors[1:]:
                comparisons.append(_compare(baseline, _attempt(plan, name, transport, attempts), plan.method))
                if comparisons[-1]["classification"] == "invalid":
                    break
            outcomes = {item["classification"] for item in comparisons}
            classification = next(value for value in ("invalid", "lead", "inconclusive", "negative")
                                  if value in outcomes)
            reason = "actor-comparisons-recorded"
        capture.manifest["reason"] = reason
    except (ReplayError, identity.IdentityError, verification.VerificationError, OSError) as exc:
        classification = "invalid"
        capture.manifest["reason"] = str(exc) if isinstance(exc, ReplayError) else type(exc).__name__
    capture.finish(classification=classification)
    return ledger.redact(capture.manifest)
