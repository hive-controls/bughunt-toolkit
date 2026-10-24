"""Inert, exact-domain callback receipts correlated to retained initiating runs."""

from __future__ import annotations

from datetime import datetime
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit

from bughunt.core import egress, exchange, ledger
from bughunt.core.workspace import allowed, workspace_dir

_PROVIDERS = {"collaborator", "interactsh-selfhosted"}
_ID = re.compile(r"[a-z0-9]{1,128}")


def _domain(value: str) -> str:
    exchange.text(value, maximum=253)
    origin, _ = exchange.target_parts("https://" + value + "/")
    if (
        value != urlsplit(origin).hostname
        or "." not in value
        or not _ID.fullmatch(value.split(".")[0])
    ):
        raise ValueError(
            "Name an exact canonical payload hostname, including its issued ID"
        )
    return value


def _origin(run_id: str, domain: str) -> tuple[dict, object, dict]:
    record = exchange.from_run(run_id)
    manifest = ledger.manifest_for(run_id)
    if (
        manifest["classification"] in {"invalid", "in_progress"}
        or manifest["decision"] != "permitted"
    ):
        raise ValueError("Initiating run must be a completed permitted HTTP exchange")
    request = record["request"]
    raw = exchange.decode(request["raw_b64"])
    if not re.search(
        rb"(?<![a-z0-9_.-])" + re.escape(domain.encode()) + rb"(?![a-z0-9_.-])",
        raw.lower(),
    ):
        raise ValueError("Initiating request does not retain the exact payload domain")
    profile = egress.current_profile()
    decision = profile.decide(
        request["url"], "callback", method=request["method"], callback_domain=domain
    )
    scope = {
        "permitted": decision.permitted and allowed(request["url"]),
        "reason": decision.reason,
        "mission": profile.mission,
        "policy_version": profile.policy_version,
        "policy_verified_at": profile.verified_at.isoformat(),
        "policy_sha256": exchange.digest(
            (workspace_dir() / "policy.json").read_bytes()
        ),
    }
    return record, profile, scope


def _path(provider: str, domain: str):
    if provider not in _PROVIDERS:
        raise ValueError(
            "Only Collaborator or explicitly self-hosted Interactsh is supported"
        )
    key = exchange.digest(exchange.canonical([provider, _domain(domain)]))
    return workspace_dir() / "oast" / (key + ".json")


def _bind_registration(path: Path, value: dict, receipt: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(
                exchange.canonical({"receipt_run_id": receipt, "registration": value})
                + b"\n"
            )
        temporary.chmod(0o600)
        try:
            os.link(temporary, path)
        except Exception as exc:
            manifest = ledger.manifest_for(receipt)
            manifest.update(
                classification="invalid",
                error="Callback domain registration was not bound",
            )
            ledger._write_private(
                ledger.runs_dir() / receipt / "manifest.json",
                exchange.canonical(manifest) + b"\n",
            )
            if isinstance(exc, FileExistsError):
                raise ValueError(
                    "Payload domain was concurrently bound to another initiating run"
                ) from exc
            raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def prepare_registration(run_id: str, *, provider: str, domain: str) -> dict:
    path = _path(provider, domain)
    record, profile, scope = _origin(run_id, domain)
    if not scope["permitted"]:
        raise ValueError(
            "Current mission/scope does not approve this exact callback domain"
        )
    value = {
        "schema_version": 1,
        "provider": provider,
        "domain": domain,
        "payload_id": domain.split(".")[0],
        "origin_run_id": run_id,
        "origin_exchange_id": record["exchange_id"],
        "request_sha256": record["request"]["raw_sha256"],
        "policy_snapshot": scope,
        "claim": "Locally correlated issued payload; provider ownership and receipt authenticity are not attested",
    }
    ledger.redact(value)
    if path.exists():
        existing = _registration(provider, domain)
        if existing["origin_run_id"] != run_id:
            raise ValueError(
                "Payload domain is already bound to another initiating run"
            )
        return ledger.redact(existing)
    return value


def register(run_id: str, *, provider: str, domain: str) -> dict:
    value = prepare_registration(run_id, provider=provider, domain=domain)
    if "receipt_run_id" in value:
        return value
    receipt = ledger.record_import(
        tool="oast",
        metadata={
            "observation_count": 0,
            "policy_snapshot": value["policy_snapshot"],
            "registration": value,
        },
        artifacts={"registration.json": exchange.canonical(value)},
    )
    _bind_registration(_path(provider, domain), value, receipt)
    return ledger.redact({"receipt_run_id": receipt, **value})


def _registration(provider: str, domain: str) -> dict:
    stored = exchange.load_json(_path(provider, domain).read_bytes())
    exported = ledger.export_run(stored["receipt_run_id"])
    receipt = ledger.manifest_for(stored["receipt_run_id"])
    artifact = ledger.runs_dir() / stored["receipt_run_id"] / "registration.json"
    value = exchange.load_json(artifact.read_bytes())
    if (
        receipt["tool"] != "oast"
        or "registration.json" not in exported["artifacts"]
        or stored["registration"] != value
        or value["provider"] != provider
        or value["domain"] != domain
    ):
        raise ValueError("Registration evidence mismatch")
    record, _, _ = _origin(value["origin_run_id"], domain)
    if (
        record["exchange_id"] != value["origin_exchange_id"]
        or record["request"]["raw_sha256"] != value["request_sha256"]
    ):
        raise ValueError("Initiating evidence changed")
    return {"receipt_run_id": stored["receipt_run_id"], **value}


def _event(value: dict, pointer: str) -> dict:
    fields = {
        "provider",
        "domain",
        "payload_id",
        "event_id",
        "protocol",
        "received_at",
        "raw",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("Expected normalized callback bundle v1 event")
    registration = _registration(value["provider"], value["domain"])
    if value["payload_id"] != registration["payload_id"] or value["protocol"] not in {
        "dns",
        "http",
        "smtp",
    }:
        raise ValueError("Callback payload/protocol mismatch")
    exchange.text(value["event_id"], maximum=256)
    if exchange.timestamp(value["received_at"]) is None:
        raise ValueError("Callback timestamp is required")
    if (
        not isinstance(value["raw"], str)
        or len(value["raw"].encode()) > 65536
        or "\x00" in value["raw"]
    ):
        raise ValueError("Retain decoded textual callback evidence, at most 64 KiB")
    _, _, scope = _origin(registration["origin_run_id"], value["domain"])
    started = ledger.manifest_for(registration["origin_run_id"])["started_at"]
    temporal = datetime.fromisoformat(value["received_at"]) >= datetime.fromisoformat(
        started
    )
    return {
        "observation_id": exchange.digest(exchange.canonical(value)),
        "event": value,
        "origin_run_id": registration["origin_run_id"],
        "origin_exchange_id": registration["origin_exchange_id"],
        "registration_run_id": registration["receipt_run_id"],
        "classification": "observation",
        "confirmed": False,
        "impact_proven": False,
        "manual_controls_required": True,
        "current_policy": scope,
        "temporal_match": temporal,
        "quarantined": not scope["permitted"] or not temporal,
        "sources": [pointer],
        "claim": "Declared-provider callback matched to retained payload; not proof of requester or impact",
    }


def prepare_callbacks(data: bytes, *, source_id: str) -> dict:
    exchange.text(source_id, maximum=512)
    document = exchange.load_json(data)
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "events"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
    ):
        raise ValueError("Expected normalized callback bundle v1")
    events = document["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= 500:
        raise ValueError("Supply 1..500 callback events")
    distinct = {}
    for index, value in enumerate(events):
        observation = _event(value, "/events/" + str(index))
        key = observation["observation_id"]
        if key in distinct:
            distinct[key]["sources"].extend(observation["sources"])
        else:
            distinct[key] = observation
    return {
        "source_id": source_id,
        "source_sha256": exchange.digest(data),
        "observations": list(distinct.values()),
    }


def import_callbacks(data: bytes, *, source_id: str) -> dict:
    prepared = prepare_callbacks(data, source_id=source_id)
    distinct = prepared["observations"]
    normalized = exchange.canonical(prepared)
    metadata = {
        "observation_count": len(distinct),
        "policy_snapshot": distinct[0]["current_policy"],
        "claim": "Callback observations only; neither authenticated provider nor impact proof",
    }
    receipt = ledger.record_import(
        tool="oast",
        metadata=metadata,
        artifacts={"source.json": data, "observations.json": normalized},
        classification="observation",
    )
    return {
        "run_id": receipt,
        "classification": "observation",
        "observation_count": len(distinct),
        "quarantined_count": sum(row["quarantined"] for row in distinct),
        "impact_proven": False,
    }
