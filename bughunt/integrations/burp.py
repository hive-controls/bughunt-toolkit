"""Bounded, inert Community Save-items XML; never parse proprietary projects."""

from __future__ import annotations

from datetime import datetime, timezone as utc_timezone
import re
from urllib.parse import urlsplit
import xml.etree.ElementTree as xml
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from bughunt.core import exchange

REPRESENTATION = "burp-exported-http; not wire bytes"
_FIELDS = ("time", "url", "host", "port", "protocol", "method", "path", "extension",
           "request", "status", "responselength", "mimetype", "response", "comment")
_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
_WEEKDAYS = "Mon Tue Wed Thu Fri Sat Sun".split()
_TIME = re.compile(r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun) ([A-Z][a-z]{2}) ([0-9]{2}) "
                   r"([0-9]{2}):([0-9]{2}):([0-9]{2}) ([A-Za-z0-9+:-]+) ([0-9]{4})")
_DTD = """<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT port (#PCDATA)>
<!ELEMENT protocol (#PCDATA)>
<!ELEMENT method (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT extension (#PCDATA)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT status (#PCDATA)>
<!ELEMENT responselength (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT comment (#PCDATA)>
]>"""


def _timestamp(value: str, zone: ZoneInfo) -> str:
    match = _TIME.fullmatch(exchange.text(value, maximum=64))
    if match is None:
        raise exchange.ExchangeError("Unsupported Burp capture time")
    weekday, month, day, hour, minute, second, abbreviation, year = match.groups()
    try:
        naive = datetime(int(year), _MONTHS.index(month) + 1, int(day), int(hour), int(minute), int(second))
        if _WEEKDAYS[naive.weekday()] != weekday:
            raise ValueError("weekday mismatch")
    except ValueError as exc:
        raise exchange.ExchangeError("Invalid Burp calendar time") from exc
    candidates = {}
    for fold in (0, 1):
        candidate = naive.replace(tzinfo=zone, fold=fold)
        restored = candidate.astimezone(utc_timezone.utc).astimezone(zone)
        if (candidate.tzname() == abbreviation and restored.replace(tzinfo=None) == naive
                and restored.utcoffset() == candidate.utcoffset()):
            candidates[candidate.isoformat()] = candidate
    if len(candidates) != 1:
        raise exchange.ExchangeError("Burp time is ambiguous, nonexistent or conflicts with the explicit timezone")
    return next(iter(candidates))


def _root(raw: bytes) -> xml.Element:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= exchange.INPUT_LIMIT:
        raise exchange.ExchangeError("Burp XML exceeds 16 MiB or is empty")
    try:
        text = raw.decode("utf-8-sig")
        if "\x00" in text:
            raise ValueError("unsupported XML encoding")
        declaration = re.match(r"<\?xml[^?]*\?>", text)
        if declaration and declaration.group() not in {
                '<?xml version="1.0"?>', '<?xml version="1.0" encoding="UTF-8"?>'}:
            raise ValueError("unsupported XML declaration")
        doctypes = list(re.finditer(r"<!DOCTYPE\s+items\s+(?:\[[\s\S]*?\]\s*>|[^>]*>)", text))
        if doctypes:
            if len(doctypes) != 1 or " ".join(doctypes[0].group().split()) != " ".join(_DTD.split()):
                raise ValueError("untrusted DTD")
            text = text[:doctypes[0].start()] + text[doctypes[0].end():]
        if re.search(r"<!(?!\[CDATA\[)", text):
            raise ValueError("XML declarations/entities are unsupported")
        root = xml.fromstring(text)
    except (ValueError, xml.ParseError, RecursionError) as exc:
        raise exchange.ExchangeError("Malformed or unsafe Burp XML") from exc
    if (root.tag != "items" or set(root.attrib) != {"burpVersion", "exportTime"}
            or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", root.attrib["burpVersion"])
            or not 0 < len(root) <= exchange.ENTRY_LIMIT):
        raise exchange.ExchangeError("Unsupported Burp items schema or count")
    exchange.text(root.attrib["burpVersion"], maximum=64)
    exchange.text(root.attrib["exportTime"], maximum=64)
    return root


def _fields(item: xml.Element) -> dict[str, str]:
    if item.tag != "item" or item.attrib or tuple(child.tag for child in item) != _FIELDS:
        raise exchange.ExchangeError("Ambiguous Burp item fields")
    values = {}
    for child in item:
        permitted = {"ip"} if child.tag == "host" else {"base64"} if child.tag in {"request", "response"} else set()
        if len(child) or set(child.attrib) - permitted:
            raise exchange.ExchangeError("Nested or unknown Burp field")
        if child.tag in {"request", "response"} and child.attrib != {"base64": "true"}:
            raise exchange.ExchangeError("Select Base64 encoding in Burp Save items")
        values[child.tag] = child.text or ""
    return values


def _record(item: xml.Element, *, zone: ZoneInfo, version: str, source_id: str, source_hash: str) -> dict:
    fields = _fields(item)
    url = exchange.text(fields["url"], maximum=8192)
    request = exchange.message(exchange.decode(fields["request"]), request=True, url=url,
                               representation=REPRESENTATION)
    response = exchange.message(exchange.decode(fields["response"]), request=False,
                                head_response=request["method"] == "HEAD", representation=REPRESENTATION)
    if any(message["http_version"] not in {"HTTP/1.0", "HTTP/1.1"} for message in (request, response)):
        raise exchange.ExchangeError("This Burp bridge supports exported HTTP/1.x messages only")
    parsed = urlsplit(url)
    target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
    hosts = exchange.header_values(request, "host")
    if (fields["method"] != request["method"] or fields["protocol"] != parsed.scheme
            or fields["host"] != parsed.hostname or fields["port"] != str(parsed.port or (443 if parsed.scheme == "https" else 80))
            or fields["path"] != target or fields["status"] != str(response["status"])
            or fields["responselength"] != str(len(exchange.decode(response["raw_b64"])))):
        raise exchange.ExchangeError("Burp metadata conflicts with the exported messages")
    if hosts:
        routed = urlsplit(f"{parsed.scheme}://{hosts[0]}/")
        if (routed.hostname, routed.port or (443 if parsed.scheme == "https" else 80)) != (
                parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)):
            raise exchange.ExchangeError("Burp request Host conflicts with its target")
    elif request["http_version"] == "HTTP/1.1":
        raise exchange.ExchangeError("Burp HTTP/1.1 export lacks Host")
    provenance = exchange.source("burp", f"{source_id}:burp-{version}", source_hash,
                                 captured_at=_timestamp(fields["time"], zone))
    return exchange.record(request, response, [provenance])


def parse(raw: bytes, *, source_id: str, timezone: str) -> list[dict]:
    exchange.text(source_id, maximum=512)
    root = _root(raw)
    try:
        zone = ZoneInfo(exchange.text(timezone, maximum=128))
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise exchange.ExchangeError("An installed IANA timezone matching the Burp export is required") from exc
    _timestamp(root.attrib["exportTime"], zone)
    version, source_hash = root.attrib["burpVersion"], exchange.digest(raw)
    records = []
    for index, item in enumerate(root, 1):
        record = _record(item, zone=zone, version=version, source_id=source_id, source_hash=source_hash)
        record["sources"][0]["source_id"] = exchange.text(f"{source_id}:burp-{version}:item-{index}", maximum=512)
        records.append(exchange.validate(record))
    return records


def save(raw: bytes, *, source_id: str, timezone: str) -> list[str]:
    records = parse(raw, source_id=source_id, timezone=timezone)
    destination = exchange.directory() / "sources" / f"{exchange.digest(raw)}.burp.xml"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise exchange.ExchangeError("Changed Burp source destination")
    try:
        with destination.open("xb") as handle:
            handle.write(raw)
        destination.chmod(0o600)
    except FileExistsError:
        if destination.read_bytes() != raw:
            raise exchange.ExchangeError("Retained Burp original has changed")
    return exchange.save(records, source_id=source_id, source_bytes=raw, kind="burp")
