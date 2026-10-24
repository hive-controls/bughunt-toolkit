"""Bounded, inert ZAP traditional JSON observations; no execution or finding claims."""

from __future__ import annotations

import re

from bughunt.core import exchange
from bughunt.core.policy import target_parts
from bughunt.integrations.zap import SUPPORTED_VERSION

OBSERVATION_LIMIT = 5000
FIELD_LIMIT = 16384


class ReportError(ValueError):
    """Unsupported or ambiguous report data; no partial import is permitted."""


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        raise ReportError("ZAP report object required")
    return value


def _array(value: object, *, maximum: int, nonempty: bool = False) -> list:
    if not isinstance(value, list) or len(value) > maximum or (nonempty and not value):
        raise ReportError("Invalid or oversized ZAP report array")
    return value


def _text(value: object, *, required: bool = False, maximum: int = FIELD_LIMIT) -> str:
    if (not isinstance(value, str) or len(value) > maximum or "\x00" in value
            or (required and not value.strip())):
        raise ReportError("Invalid or oversized ZAP report text")
    return value


def _number(value: object, *, maximum: int = 2 ** 31 - 1, optional: bool = False) -> int | None:
    if optional and (value is None or value == "-1" or type(value) is int and value == -1):
        return None
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 10:
        value = int(value)
    if type(value) is not int or not 0 <= value <= maximum:
        raise ReportError("Invalid ZAP scanner code")
    return value


def _scanner(alert: dict) -> dict:
    name = _text(alert.get("alert"), required=True)
    result = {"plugin_id": _number(alert.get("pluginid")),
              "alert_ref": _text(alert.get("alertRef"), required=True, maximum=128),
              "alert": name, "name": _text(alert.get("name", name), required=True),
              "risk": _number(alert.get("riskcode"), maximum=3),
              "confidence": _number(alert.get("confidence"), maximum=4),
              "cwe": _number(alert.get("cweid"), optional=True),
              "wasc": _number(alert.get("wascid"), optional=True)}
    for source, target in (("desc", "description"), ("solution", "solution"),
                           ("reference", "references"), ("otherinfo", "other_info")):
        result[target] = _text(alert.get(source, ""))
    return result


def _instance(value: dict, origin: str) -> dict:
    uri = _text(value.get("uri"), required=True, maximum=8192)
    if target_parts(uri)[0] != origin:
        raise ReportError("ZAP instance differs from its reported site origin")
    method = _text(value.get("method"), required=True, maximum=32)
    if not re.fullmatch(r"[A-Z]+", method):
        raise ReportError("Invalid or ambiguous ZAP instance method")
    result = {"uri": uri, "method": method}
    for source, target in (("param", "parameter"), ("attack", "attack"), ("evidence", "evidence"),
                           ("otherinfo", "other_info"), ("nodeName", "node_name")):
        result[target] = _text(value.get(source, ""))
    return result


def _observations(alert: dict, origin: str, source: dict, pointer: str) -> list[dict]:
    scanner = _scanner(alert)
    source_id = _text(alert.get("sourceid", ""), maximum=128)
    instances = _array(alert.get("instances"), maximum=OBSERVATION_LIMIT, nonempty=True)
    result = []
    for index, value in enumerate(instances):
        instance = _instance(_object(value), origin)
        observation_id = exchange.digest(exchange.canonical({"scanner": scanner, "instance": instance}))
        provenance = dict(source, json_pointer=f"{pointer}/instances/{index}", site_origin=origin,
                          scanner_source_id=source_id)
        result.append({"schema_version": 1, "observation_id": observation_id,
                       "classification": "hypothesis", "hypothesis_level": 1,
                       "manual_controls_required": True, "confirmed": False,
                       "scanner": scanner, "instance": instance, "sources": [provenance]})
    return result


def _parse(data: bytes, source_id: str) -> dict:
    document = _object(exchange.load_json(data))
    if document.get("@version") != SUPPORTED_VERSION:
        raise ReportError("Unsupported declared ZAP version")
    identifier = _text(source_id, required=True, maximum=512)
    if any(ord(character) < 32 for character in identifier):
        raise ReportError("Invalid report source identifier")
    reported_at = exchange.timestamp(_text(document.get("created"), required=True, maximum=64))
    source = {"source_id": identifier, "report_sha256": exchange.digest(data),
              "producer_version": SUPPORTED_VERSION, "reported_at": reported_at,
              "claim": "source-reported metadata; producer and capture are not attested"}
    observations, alert_count = [], 0
    sites = _array(document.get("site"), maximum=500)
    for site_index, value in enumerate(sites):
        site = _object(value)
        origin = target_parts(_text(site.get("@name"), required=True, maximum=8192))[0]
        for alert_index, alert in enumerate(_array(site.get("alerts"), maximum=OBSERVATION_LIMIT)):
            alert_count += 1
            if alert_count > OBSERVATION_LIMIT:
                raise ReportError("ZAP report exceeds alert bound")
            pointer = f"/site/{site_index}/alerts/{alert_index}"
            observations.extend(_observations(_object(alert), origin, source, pointer))
            if len(observations) > OBSERVATION_LIMIT:
                raise ReportError("ZAP report exceeds observation bound")
    return {"schema_version": 1, "format": "zap-traditional-json",
            "source": source, "observations": observations}


def parse(data: bytes, *, source_id: str) -> dict:
    """Validate the entire report without files, traffic, authority or severity promotion."""
    if not isinstance(data, bytes) or not data:
        raise ReportError("ZAP report bytes required")
    try:
        return _parse(data, source_id)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ReportError("Malformed or unsupported ZAP report") from exc
