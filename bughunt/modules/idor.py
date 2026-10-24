"""Bounded, dry-run-first one-field body-reference ID-differential for owned-object IDOR (BH-7).

The command changes exactly one JSON field of a captured request from the owner's own id to a
single second-account owned id, then compares what the origin-bound ``--actor`` sees for each.
Both ids belong to accounts the operator owns, so the probe never touches an arbitrary object.

It reuses ``bughunt.labs.replay`` for every outbound step: the verified send under an origin-bound
identity (credentials and allowlisted companion headers ride only in-origin), the sanitized ledger
receipt per request, the response summary, and the reliability/denial taxonomy. The owner-positive
request is a positive control; each negative request (the second-account id, and optionally an
anonymous actor) is classified against it. The comparison itself is owned here rather than reused
from ``replay._compare``: that comparator rejects any request whose body differs from the baseline
(``non-identity-request-fields-changed``), and this differential changes the body by design.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
import json
from pathlib import Path
import re

import httpx

from bughunt.core import egress, identity, ledger, verification
from bughunt.core.policy import target_parts
from bughunt.labs import replay
from bughunt.modules.repeater import (
    RawRequest,
    apply_edits,
    parse_raw,
    remove_header,
    render,
)

_FIELD_PATH = re.compile(
    r"[A-Za-z_][A-Za-z0-9_-]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_-]{0,63}){0,7}"
)
_OWNED_ID = re.compile(r"[A-Za-z0-9._~@:+-]{1,256}")
_NUMERIC_RANGE = re.compile(r"^-?\d+-\d+$")
_INTEGER = re.compile(r"-?[0-9]+")
_OWNED_KINDS = {"owner", "lower_privilege"}
_READ_SAFE = {"GET", "HEAD"}


class IdorError(ValueError):
    """A refused IDOR plan; no outbound request may run."""


@dataclass(frozen=True)
class IdorPlan:
    actor: str
    anonymous: str | None
    field_path: str
    owner_value: object
    compare_actor: str
    compare_value: object
    method: str
    url: str
    positive: replay.Plan
    negative: replay.Plan


def _owned_id(compare: str) -> tuple[str, str]:
    """Split ``--compare`` as ``actor/id``; the id must be a single bounded, non-range token."""
    actor_name, slash, raw_id = compare.partition("/")
    if not slash or not actor_name or not raw_id:
        raise IdorError("non-owned-id")
    if ".." in raw_id or _NUMERIC_RANGE.fullmatch(raw_id):
        raise IdorError("unbounded-id")
    if not _OWNED_ID.fullmatch(raw_id):
        raise IdorError("unbounded-id")
    return actor_name, raw_id


def _owned_actor(
    name: str, origin: str, *, missing: str, not_owned: str, wrong_origin: str
) -> dict:
    try:
        profile = identity.read_profile(name)
    except identity.IdentityError as exc:
        raise IdorError(missing) from exc
    if profile["kind"] not in _OWNED_KINDS or profile["owned"] is not True:
        raise IdorError(not_owned)
    if origin not in profile["origins"]:
        raise IdorError(wrong_origin)
    return profile


def _json_object(body: bytes) -> dict:
    if not body:
        raise IdorError("body-not-json")
    try:
        document = replay._json(body)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise IdorError("body-not-json") from exc
    if not isinstance(document, dict):
        raise IdorError("body-not-json")
    return document


def _scalar_at(document: dict, path: str) -> object:
    value: object = document
    for segment in path.split("."):
        if not isinstance(value, dict) or segment not in value:
            raise IdorError("field-not-found")
        value = value[segment]
    if type(value) not in (str, int):
        raise IdorError("field-not-scalar-id")
    return value


def _coerce_like(owner_value: object, raw_id: str) -> object:
    if type(owner_value) is int:
        if not (raw_id.isascii() and _INTEGER.fullmatch(raw_id)):
            raise IdorError("field-not-scalar-id")
        return int(raw_id)
    return raw_id


def _substitute(document: dict, path: str, new_value: object) -> bytes:
    changed = copy.deepcopy(document)
    cursor = changed
    segments = path.split(".")
    for segment in segments[:-1]:
        cursor = cursor[segment]
    cursor[segments[-1]] = new_value
    return json.dumps(changed, separators=(",", ":"), ensure_ascii=True).encode()


def _rendered(request: RawRequest, body: bytes) -> bytes:
    headers = [
        (name, value)
        for name, value in request.headers
        if name.lower() != "content-length"
    ]
    return render(
        RawRequest(
            request.method,
            request.target,
            request.version,
            headers,
            body,
            request.scheme,
            True,
        )
    )


def _leg(
    request: RawRequest,
    source: bytes,
    url: str,
    headers: tuple,
    body: bytes,
    actors: tuple[str, ...],
    max_bytes: int,
    timeout: float,
) -> replay.Plan:
    return replay.Plan(
        request.method,
        url,
        headers,
        body,
        source,
        _rendered(request, body),
        actors,
        ("content-type", "location"),
        None,
        max_bytes,
        timeout,
        replay._state(actors),
    )


def prepare(
    request: RawRequest,
    source: bytes,
    *,
    actor: str,
    compare: str,
    field_paths: list[str],
    anonymous: str | None = None,
    max_bytes: int = 65536,
    timeout: float = 15,
) -> IdorPlan:
    if len(field_paths) != 1 or not _FIELD_PATH.fullmatch(field_paths[0]):
        raise IdorError(
            "exactly-one-field-required"
            if len(field_paths) != 1
            else "field-path-invalid"
        )
    field_path = field_paths[0]
    compare_actor, raw_id = _owned_id(compare)
    if not isinstance(source, bytes) or not isinstance(request.body, bytes):
        raise IdorError("baseline-request-invalid")
    replay._validate_source(source)
    url = replay._validate_request(request)
    if (
        type(max_bytes) is not int
        or not 0 < max_bytes <= ledger.CAPTURE_LIMIT
        or type(timeout) not in {int, float}
        or not 0 < timeout <= 30
    ):
        raise IdorError("idor-options-invalid")
    verification.require_workspace_scope(url)
    origin, _path = target_parts(url)
    _owned_actor(
        actor,
        origin,
        missing="actor-invalid",
        not_owned="actor-not-owned",
        wrong_origin="actor-origin-mismatch",
    )
    verification.require_verification_origin(
        url, verification.read_configuration(actor)
    )
    _owned_actor(
        compare_actor,
        origin,
        missing="non-owned-id",
        not_owned="non-owned-id",
        wrong_origin="non-owned-id",
    )
    actors = [actor]
    if anonymous is not None:
        if identity.read_profile(anonymous)["kind"] != "anonymous":
            raise IdorError("anonymous-actor-required")
        verification.require_verification_origin(
            url, verification.read_configuration(anonymous)
        )
        actors.append(anonymous)
    document = _json_object(request.body)
    owner_value = _scalar_at(document, field_path)
    compare_value = _coerce_like(owner_value, raw_id)
    if compare_value == owner_value:
        raise IdorError("ids-not-distinct")
    headers = tuple(
        (name, value)
        for name, value in request.headers
        if name.lower() != "content-length"
    )
    positive = _leg(
        request, source, url, headers, request.body, (actor,), max_bytes, timeout
    )
    negative = _leg(
        request,
        source,
        url,
        headers,
        _substitute(document, field_path, compare_value),
        tuple(actors),
        max_bytes,
        timeout,
    )
    return IdorPlan(
        actor,
        anonymous,
        field_path,
        owner_value,
        compare_actor,
        compare_value,
        request.method,
        url,
        positive,
        negative,
    )


def _safe_target(url: str) -> str:
    origin, path = target_parts(url)
    return origin + path


def _cleanup_note(plan: IdorPlan) -> str:
    return (
        f"idor changed only field {plan.field_path} to one second-account owned id; "
        f"if {plan.method} wrote to {_safe_target(plan.url)}, review and restore the two "
        "owned objects it referenced. No arbitrary object was touched."
    )


def _remember_ids(plan: IdorPlan) -> None:
    ledger.remember_secret(str(plan.owner_value))
    ledger.remember_secret(str(plan.compare_value))


def _negative_actors(plan: IdorPlan) -> list[str]:
    return [plan.actor] + ([plan.anonymous] if plan.anonymous is not None else [])


def _planned(plan: IdorPlan, role: str, actor: str, value: object) -> dict:
    return {
        "role": role,
        "actor": actor,
        "field": plan.field_path,
        "value_sha256": replay._hash(replay._canonical(value)),
    }


def preview(plan: IdorPlan) -> dict:
    replay._ensure_state(plan.positive)
    _remember_ids(plan)
    requests = [
        _planned(plan, "owner-positive", plan.actor, plan.owner_value),
        _planned(plan, "compare-negative", plan.actor, plan.compare_value),
    ]
    if plan.anonymous is not None:
        requests.append(
            _planned(plan, "anonymous-negative", plan.anonymous, plan.compare_value)
        )
    return {
        "method": plan.method,
        "target": _safe_target(plan.url),
        "field_path": plan.field_path,
        "actor": plan.actor,
        "compare_actor": plan.compare_actor,
        "planned_requests": requests,
        "network_requests": 0,
        "requires_allow_write": plan.method not in _READ_SAFE,
        "cleanup_note": _cleanup_note(plan),
    }


def _attempt(leg: replay.Plan, name: str, transport, attempts: list) -> dict:
    item = {"actor": name}
    attempts.append(item)
    try:
        summary, _body = replay._send(leg, name, observer=False, transport=transport)
        item.update(summary)
    except (
        replay.ReplayError,
        verification.VerificationError,
        identity.IdentityError,
        httpx.HTTPError,
        OSError,
        RecursionError,
    ) as exc:
        item.update(getattr(exc, "exchange", {}))
        item["error"] = (
            str(exc) if isinstance(exc, replay.ReplayError) else type(exc).__name__
        )
    return item


def _classify(baseline: dict, candidate: dict, name: str) -> dict:
    result = {
        "actor": name,
        "run_id": candidate.get("run_id"),
        "classification": "inconclusive",
        "reason": "different-or-unresolved-response",
    }
    if candidate.get("error"):
        return dict(result, classification="invalid", reason=candidate["error"])
    if replay._unreliable(baseline) or replay._unreliable(candidate):
        return dict(result, reason="partial-cached-encoded-or-redirected-response")
    if candidate["status"] in replay._DENIALS:
        return dict(
            result, classification="negative", reason="owned-object-reference-denied"
        )
    if 200 <= candidate["status"] < 300 and candidate["size"] > 0:
        return dict(
            result,
            classification="lead",
            reason="cross-account-owned-object-reachable-review-required",
        )
    return result


def execute(plan: IdorPlan, *, allow_write: bool = False, transport=None) -> dict:
    if plan.method not in _READ_SAFE and not allow_write:
        raise IdorError(
            f"method {plan.method} may mutate state; pass --allow-write to authorize"
        )
    capture = ledger.begin(
        egress.current_profile(),
        tool="idor",
        operation="manual",
        target=plan.url,
        request=plan.positive.baseline,
        actor=plan.actor,
    )
    capture.manifest.update(
        representation="owned-object-id-differential",
        automatic_finding=False,
        field_path=plan.field_path,
        cleanup_note=_cleanup_note(plan),
        comparisons=[],
        attempts=[],
    )
    _remember_ids(plan)
    try:
        replay._ensure_state(plan.positive)
        attempts = capture.manifest["attempts"]
        baseline = _attempt(plan.positive, plan.actor, transport, attempts)
        capture.manifest["positive_control_run_id"] = baseline.get("run_id")
        failure = replay._baseline_outcome(baseline, plan.positive)
        if failure is not None:
            classification, reason = failure
        else:
            comparisons = capture.manifest["comparisons"]
            for name in _negative_actors(plan):
                comparisons.append(
                    _classify(
                        baseline,
                        _attempt(plan.negative, name, transport, attempts),
                        name,
                    )
                )
                if comparisons[-1]["classification"] == "invalid":
                    break
            outcomes = {item["classification"] for item in comparisons}
            classification = next(
                value
                for value in ("invalid", "lead", "inconclusive", "negative")
                if value in outcomes
            )
            reason = "owner-vs-second-account-comparisons-recorded"
        capture.manifest["reason"] = reason
    except (
        IdorError,
        replay.ReplayError,
        identity.IdentityError,
        verification.VerificationError,
        egress.PolicyBlocked,
        OSError,
    ) as exc:
        classification = "invalid"
        capture.manifest["reason"] = (
            str(exc)
            if isinstance(exc, (IdorError, replay.ReplayError))
            else type(exc).__name__
        )
    capture.finish(classification=classification)
    return ledger.redact(capture.manifest)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bughunt idor", description=__doc__)
    parser.add_argument(
        "request", help="Captured raw HTTP request carrying a JSON body."
    )
    parser.add_argument(
        "--actor",
        required=True,
        help="Owned, origin-bound actor that sends every request.",
    )
    parser.add_argument(
        "--field",
        action="append",
        default=[],
        required=True,
        help="The one JSON field path to change, e.g. data.ownerId. Exactly one.",
    )
    parser.add_argument(
        "--compare",
        required=True,
        help="A second owned account and its object id, as actor/id. One bounded id.",
    )
    parser.add_argument(
        "--anonymous",
        help="Optional anonymous actor for an unauthenticated comparison.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=65536,
        help="Response body cap, at most 1000000.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15,
        help="Per-request timeout, at most 30 seconds.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Send the bounded set. Without it, idor only previews and sends nothing.",
    )
    parser.add_argument(
        "--allow-write",
        action="store_true",
        help="Authorize a potentially-mutating method (anything but GET/HEAD) under --execute.",
    )
    parser.add_argument("--method", help="Explicitly replace the baseline method.")
    parser.add_argument("--path", help="Explicitly replace the baseline path/query.")
    parser.add_argument("--host", help="Explicitly replace the baseline host.")
    parser.add_argument(
        "--scheme",
        choices=("http", "https"),
        help="Required for TLS when the capture is relative.",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Explicitly replace one header as Name: value.",
    )
    parser.add_argument("--remove-header", action="append", default=[])
    bodies = parser.add_mutually_exclusive_group()
    bodies.add_argument(
        "--body", help="Explicitly replace the body; may enter shell history."
    )
    bodies.add_argument("--body-file", help="Explicitly replace the body from a file.")
    return parser


def prepare_args(args: argparse.Namespace) -> IdorPlan:
    try:
        path = Path(args.request)
        if path.stat().st_size > 8 * 1024 * 1024:
            raise IdorError("baseline-too-large")
        source = path.read_bytes()
    except FileNotFoundError as error:
        raise IdorError("baseline-missing") from error
    request = apply_edits(parse_raw(source), args)
    if args.body is not None or args.body_file:
        remove_header(request, "Content-Length")
    return prepare(
        request,
        source,
        actor=args.actor,
        compare=args.compare,
        field_paths=args.field,
        anonymous=args.anonymous,
        max_bytes=args.max_bytes,
        timeout=args.timeout,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        plan = prepare_args(args)
        result = (
            execute(plan, allow_write=args.allow_write)
            if args.execute
            else preview(plan)
        )
        print(json.dumps(ledger.redact(result), indent=2, sort_keys=True))
        return 2 if result.get("classification") == "invalid" else 0
    except (
        ValueError,
        OSError,
        httpx.HTTPError,
        identity.IdentityError,
        verification.VerificationError,
    ):
        print(
            "IDOR blocked: invalid baseline, actor, field, owned id, or mission policy."
        )
        return 2
