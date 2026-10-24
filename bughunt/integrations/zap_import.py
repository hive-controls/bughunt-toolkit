"""Inert ZAP report receipts in the existing private run ledger."""

from __future__ import annotations

from bughunt.core import exchange, ledger
from bughunt.integrations import zap_report

NORMALIZED_LIMIT = exchange.INPUT_LIMIT


def _selected(records: list[dict]) -> dict[tuple[str, str], list[str]]:
    if not isinstance(records, list) or len(records) > exchange.ENTRY_LIMIT:
        raise ValueError("Select at most 500 source exchanges")
    indexed, seen = {}, set()
    for value in records:
        exchange.validate(value)
        if value["exchange_id"] in seen:
            raise ValueError("Duplicate selected source exchange")
        seen.add(value["exchange_id"])
        for request in (value["request"], exchange.project(value)["request"]):
            key = request["url"], request["method"]
            candidates = indexed.setdefault(key, [])
            if value["exchange_id"] not in candidates:
                candidates.append(value["exchange_id"])
    return indexed


def _normalize(parsed: dict, selected: dict) -> list[dict]:
    distinct = {}
    for original in parsed["observations"]:
        identifier = original["observation_id"]
        if identifier in distinct:
            distinct[identifier]["sources"].extend(original["sources"])
            continue
        value = dict(original, sources=list(original["sources"]))
        instance = value["instance"]
        value["current_scope"] = exchange.scope_decision(
            {"url": instance["uri"], "method": instance["method"], "headers": []}
        )
        value["quarantined"] = not value["current_scope"]["permitted"]
        value["source_exchange_candidates"] = sorted(
            selected.get((instance["uri"], instance["method"]), [])
        )
        value["association"] = "url-method-only; not verified capture correspondence"
        distinct[identifier] = value
    return list(distinct.values())


def prepare_report(
    data: bytes, *, source_id: str, records: list[dict] | None = None
) -> tuple[dict, bytes]:
    parsed = zap_report.parse(data, source_id=source_id)
    selected = _selected([] if records is None else records)
    observations = _normalize(parsed, selected)
    normalized = (
        exchange.canonical(
            {
                "schema_version": 1,
                "source": parsed["source"],
                "observations": observations,
            }
        )
        + b"\n"
    )
    if len(normalized) > NORMALIZED_LIMIT:
        raise ValueError("Normalized report exceeds retained artifact bound")
    metadata = {
        "source": parsed["source"],
        "instance_count": len(parsed["observations"]),
        "observation_count": len(observations),
        "quarantined_count": sum(value["quarantined"] for value in observations),
        "policy_snapshot": observations[0]["current_scope"] if observations else {},
        "association": "URL/method candidates only; no principal or capture attestation",
    }
    return metadata, normalized


def import_report(
    data: bytes, *, source_id: str, records: list[dict] | None = None
) -> str:
    """Each import is a receipt; stable hypothesis IDs are not repeated confirmation."""
    metadata, normalized = prepare_report(data, source_id=source_id, records=records)
    return ledger.record_import(
        tool="zap",
        metadata=metadata,
        artifacts={"source.json": data, "observations.json": normalized},
    )


def summary(run_id: str) -> dict:
    manifest = ledger.manifest_for(run_id)
    if manifest.get("tool") != "zap" or manifest.get("decision") != "inert-import":
        raise ValueError("Expected an imported ZAP report run")
    metadata = manifest["import_metadata"]
    return ledger.redact(
        {
            "run_id": run_id,
            "classification": manifest["classification"],
            "observation_count": metadata["observation_count"],
            "instance_count": metadata["instance_count"],
            "quarantined_count": metadata["quarantined_count"],
            "source": metadata["source"],
            "manual_controls_required": True,
        }
    )
