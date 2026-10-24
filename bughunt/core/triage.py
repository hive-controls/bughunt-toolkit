"""Inert, hash-linked grouping of explicitly selected retained responses."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlsplit

from bughunt.core import exchange, ledger

MAX_SELECTED = 32
MAX_CANDIDATES = 256
_NORMALIZATIONS = {"exact", "ascii-whitespace"}
_MEDIA_TYPE = re.compile(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\Z")


def _selected_ids(exchange_ids: list[str]) -> list[str]:
    if (type(exchange_ids) is not list or not 1 <= len(exchange_ids) <= MAX_SELECTED
            or any(type(value) is not str for value in exchange_ids)
            or len(set(exchange_ids)) != len(exchange_ids)):
        raise exchange.ExchangeError("Select 1-32 distinct exchange IDs")
    return sorted(exchange_ids)


def _media_type(response: dict) -> str | None:
    values = exchange.header_values(response, "content-type")
    if len(values) != 1:
        return None
    media_type = values[0].split(";", 1)[0].strip().lower()
    return media_type if _MEDIA_TYPE.fullmatch(media_type) else None


def _body_fingerprint(response: dict, normalization: str) -> str:
    body = exchange.decode(response["body_b64"], maximum=exchange.BODY_LIMIT)
    if normalization == "ascii-whitespace":
        body = re.sub(rb"[ \t\r\n\f\v]+", b" ", body)
    return exchange.digest(body)


def _input(exchange_id: str, retained: dict, normalization: str) -> tuple[dict, tuple, str | None]:
    response = retained["response"]
    actors = sorted({source["actor"] for source in retained["sources"] if source["actor"] is not None})
    actor_partition = exchange.digest(exchange.canonical(actors))
    incomplete = retained["request"]["truncated"] or response is None or response["truncated"]
    status = response["status"] if response is not None else None
    media_type = _media_type(response) if response is not None else None
    fingerprint = _body_fingerprint(response, normalization) if response is not None else None
    item = {"exchange_id": exchange_id,
            "request_sha256": retained["request"]["raw_sha256"],
            "response_sha256": response["raw_sha256"] if response is not None else None,
            "source_sha256": sorted({source["sha256"] for source in retained["sources"]}),
            "actor_partition_sha256": actor_partition,
            "status": status, "media_type": media_type,
            "body_fingerprint": fingerprint, "incomplete": incomplete}
    key = (status, media_type, actor_partition, fingerprint, exchange_id if incomplete else "")
    warning = f"{exchange_id}: missing response or truncated exchange kept as a singleton" if incomplete else None
    return item, key, warning


def response_groups(exchange_ids: list[str], *, normalization: str = "exact") -> dict:
    selected = _selected_ids(exchange_ids)
    if normalization not in _NORMALIZATIONS:
        raise exchange.ExchangeError("Unsupported response normalization")
    inputs = []
    grouped: dict[tuple, list[str]] = {}
    warnings = ["Body equality is not proof of authorization, state or impact equivalence."]
    for exchange_id in selected:
        retained = exchange.read(exchange_id)
        item, key, warning = _input(exchange_id, retained, normalization)
        inputs.append(item)
        grouped.setdefault(key, []).append(exchange_id)
        if warning:
            warnings.append(warning)
    groups = []
    for key, members in grouped.items():
        representative = members[0]
        groups.append({"status": key[0], "media_type": key[1],
                       "actor_partition_sha256": key[2], "body_fingerprint": key[3],
                       "representative_exchange_id": representative,
                       "exchange_ids": members, "count": len(members),
                       "singleton": len(members) == 1})
    groups.sort(key=lambda group: group["representative_exchange_id"])
    return {"schema_version": 1, "inert": True,
            "settings": {"normalization": normalization, "similarity": "digest-equality"},
            "selected_exchange_ids": selected, "inputs": inputs,
            "groups": groups, "warnings": warnings}


def _reference_kind(value: str | None) -> str:
    if value is None:
        return "implicit-current"
    if not value or value.lstrip().startswith(("//", "\\")):
        return "unsupported"
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return "unsupported"
    if parsed.scheme:
        return "http-url" if parsed.scheme.lower() in {"http", "https"} else "unsupported"
    return "relative-url" if not parsed.netloc else "unsupported"


class _CandidateParser(HTMLParser):
    def __init__(self, exchange_id: str, candidates: list[dict], warnings: list[str]):
        super().__init__(convert_charrefs=True)
        self.exchange_id = exchange_id
        self.candidates = candidates
        self.warnings = warnings
        self.form_ordinal: int | None = None
        self.ordinal = 0
        self.limit_reported = False
        self.duplicate_reported = False

    def handle_starttag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        if tag not in {"form", "input", "a"}:
            return
        if len(self.candidates) >= MAX_CANDIDATES:
            if not self.limit_reported:
                self.warnings.append("Candidate limit reached; additional tags omitted")
                self.limit_reported = True
            return
        names = [name.lower() for name, _value in attributes]
        if len(names) != len(set(names)):
            if not self.duplicate_reported:
                self.warnings.append(f"{self.exchange_id}: duplicate attributes skipped; further occurrences omitted")
                self.duplicate_reported = True
            return
        values = dict(attributes)
        if tag == "a" and "href" not in values:
            return
        self.ordinal += 1
        line, column = self.getpos()
        item = {"exchange_id": self.exchange_id, "ordinal": self.ordinal,
                "tag": tag, "line": line, "column": column + 1}
        if tag == "form":
            self.form_ordinal = self.ordinal
            method = (values.get("method") or "GET").upper()
            item["method"] = method if method in {"GET", "POST"} else "other"
            reference = values.get("action")
        elif tag == "input":
            name = values.get("name") or ""
            item["display_name"] = escape(ledger.redact_text(name[:128]), quote=True)
            item["form_ordinal"] = self.form_ordinal
            input_type = (values.get("type") or "text").lower()
            item["input_type"] = input_type if input_type in {
                "text", "password", "hidden", "email", "search", "checkbox", "radio", "submit"} else "other"
            reference = None
        else:
            reference = values.get("href")
        item["reference_kind"] = _reference_kind(reference)
        item["reference_sha256"] = exchange.digest(reference.encode()) if reference is not None else None
        self.candidates.append(item)

    def handle_startendtag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attributes)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.form_ordinal = None


def html_candidates(exchange_ids: list[str]) -> dict:
    selected = _selected_ids(exchange_ids)
    candidates: list[dict] = []
    inputs = []
    warnings = ["Original retained HTML is parsed in memory; output is sanitized inert hints, not fetch targets."]
    for exchange_id in selected:
        retained = exchange.read(exchange_id)
        response = retained["response"]
        reason = None
        if response is None or response["truncated"]:
            reason = "missing or truncated response"
        elif _media_type(response) != "text/html":
            reason = "non-HTML or ambiguous content type"
        elif exchange.header_values(response, "content-encoding") not in ([], ["identity"]):
            reason = "encoded response"
        if reason:
            warnings.append(f"{exchange_id}: {reason} skipped")
            continue
        body = exchange.decode(response["body_b64"], maximum=exchange.BODY_LIMIT)
        inputs.append({"exchange_id": exchange_id, "response_sha256": response["raw_sha256"],
                       "body_sha256": exchange.digest(body),
                       "source_sha256": sorted({source["sha256"] for source in retained["sources"]})})
        parser = _CandidateParser(exchange_id, candidates, warnings)
        parser.feed(body.decode("utf-8", errors="replace"))
        parser.close()
    return {"schema_version": 1, "inert": True,
            "position_basis": "captured response text, line/column; output sanitized",
            "selected_exchange_ids": selected, "inputs": inputs,
            "candidates": candidates, "warnings": warnings}


def _flow_hint(url: str) -> str | None:
    path = urlsplit(url).path.lower()
    if "saml" in path:
        return "possible-saml; path-only inference"
    if "oauth" in path or path.endswith("/authorize"):
        return "possible-oauth; path-only inference"
    return None


def _flow_event(exchange_id: str, retained: dict, source: dict) -> dict:
    request, response = retained["request"], retained["response"]
    target = urlsplit(request["url"])
    actor = source["actor"]
    return {"exchange_id": exchange_id, "source_sha256": source["sha256"],
            "source_kind": source["kind"], "source_run_id": source["run_id"],
            "captured_at": source["captured_at"],
            "actor": escape(ledger.redact_text(actor), quote=True) if actor else None,
            "actor_claim": source["claim"], "method": request["method"],
            "target_host": escape(target.hostname or "", quote=True),
            "target_url_sha256": exchange.digest(request["url"].encode()),
            "status": response["status"] if response else None,
            "request_sha256": request["raw_sha256"],
            "request_truncated": request["truncated"],
            "response_sha256": response["raw_sha256"] if response else None,
            "response_truncated": response["truncated"] if response else None,
            "auth_flow_hint": _flow_hint(request["url"])}


def flow_summary(exchange_ids: list[str]) -> dict:
    selected = _selected_ids(exchange_ids)
    events = []
    for exchange_id in selected:
        retained = exchange.read(exchange_id)
        events.extend(_flow_event(exchange_id, retained, source) for source in retained["sources"])
    events.sort(key=lambda event: (event["captured_at"] is None,
                                   datetime.fromisoformat(event["captured_at"]).astimezone(timezone.utc)
                                   if event["captured_at"] else datetime.max.replace(tzinfo=timezone.utc),
                                   event["exchange_id"], event["source_sha256"]))
    known = [datetime.fromisoformat(event["captured_at"]).astimezone(timezone.utc)
             for event in events if event["captured_at"] is not None]
    unknown_count = len(events) - len(known)
    tied_count = len(known) - len(set(known))
    return {"schema_version": 1, "inert": True, "selected_exchange_ids": selected,
            "events": events,
            "ordering": {"basis": "source capture timestamps; unknown last",
                         "unknown_timestamp_count": unknown_count,
                         "tied_timestamp_count": tied_count,
                         "partial": bool(unknown_count or tied_count)},
            "warnings": ["Actor names and inferred auth-flow hints are source claims, not verified identities.",
                         "Unknown or tied timestamps do not establish a complete event order."]}
