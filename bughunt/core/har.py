"""Bounded HAR 1.2 interchange; imports never send archived requests."""

from __future__ import annotations

import base64
from urllib.parse import parse_qsl

from bughunt.core import exchange


def _object(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise exchange.ExchangeError(f"Invalid HAR {label}")
    return value


def _headers(value: object) -> list[list[str]]:
    if not isinstance(value, list):
        raise exchange.ExchangeError("HAR headers must be an array")
    pairs = []
    for item in value:
        item = _object(item, "header")
        pairs.append([item.get("name"), item.get("value")])
    return exchange.headers(pairs)


def _number(value: object, *, unknown: bool = False) -> int:
    if type(value) is not int or not (-1 if unknown else 0) <= value <= 2 ** 53:
        raise exchange.ExchangeError("Invalid HAR size/status")
    return value


def _body_sizes(container: dict, content: dict, *, request: bool) -> list[int]:
    size = _number(container.get("bodySize", -1) if request else content.get("size", -1), unknown=True)
    wire_size = _number(container.get("bodySize", -1), unknown=True)
    pairs = _headers(container.get("headers", []))
    lengths = [value for name, value in pairs if name.lower() == "content-length"]
    if len(lengths) > 1 or (lengths and (not lengths[0].isascii() or not lengths[0].isdigit() or len(lengths[0]) > 16)):
        raise exchange.ExchangeError("Invalid or ambiguous HAR body length")
    length = _number(int(lengths[0])) if lengths else -1
    encoded = any(value.lower() != "identity" and (name.lower() == "transfer-encoding" or
                  (not request and name.lower() == "content-encoding")) for name, value in pairs)
    sizes = [size]
    if not encoded or (size < 0 and content.get("text") is None):
        sizes.extend([wire_size, length])
    return [value for value in sizes if value >= 0]


def _body(container: dict, *, request: bool, encoding: object = None, no_body=False) -> tuple[bytes, bool]:
    content = container.get("postData", {}) if request else container.get("content", {})
    content = _object(content, "body")
    value = content.get("text")
    if request and value is None and content.get("params"):
        raise exchange.ExchangeError("HAR form bodies need retained postData.text")
    sizes = _body_sizes(container, content, request=request)
    if value is None:
        return b"", not no_body and (not sizes or any(size > 0 for size in sizes))
    if not isinstance(value, str) or len(value) > exchange.MESSAGE_LIMIT:
        raise exchange.ExchangeError("Oversized or invalid HAR body text")
    encoding = encoding if request else content.get("encoding")
    if encoding is None:
        body = value.encode("utf-8")
    elif encoding == "base64":
        body = exchange.decode(value, exchange.BODY_LIMIT)
    else:
        raise exchange.ExchangeError("Unsupported HAR body encoding")
    if len(body) > exchange.BODY_LIMIT:
        raise exchange.ExchangeError("HAR body exceeds 1000000 bytes")
    return body, not no_body and any(size > len(body) for size in sizes)


def _message(container: dict, *, request: bool, entry: dict, head_response=False) -> dict:
    pairs = _headers(container.get("headers"))
    version = exchange.text(container.get("httpVersion"), maximum=32)
    if request:
        method = exchange.text(container.get("method"), maximum=32)
        url = exchange.text(container.get("url"), maximum=8192)
        first_line = f"{method} {url} {version}"
        body, truncated = _body(container, request=True, encoding=entry.get("_bughuntRequestEncoding"))
        marker = entry.get("_bughuntRequestTruncated", False)
    else:
        status = _number(container.get("status"))
        reason = exchange.text(container.get("statusText", ""), maximum=512, empty=True)
        first_line = f"{version} {status} {reason}"
        body, truncated = _body(container, request=False,
                                no_body=head_response or status < 200 or status in {204, 304})
        marker = entry.get("_bughuntResponseTruncated", False)
        url = None
    if type(marker) is not bool:
        raise exchange.ExchangeError("HAR truncation marker must be boolean")
    head = first_line + "\r\n" + "".join(f"{name}: {value}\r\n" for name, value in pairs) + "\r\n"
    return exchange.message(head.encode("latin-1") + body, request=request, url=url,
                            truncated=truncated or marker, representation="har-logical; not wire bytes",
                            head_response=head_response)


def _entry(entry: dict, source_id: str, source_hash: str, index: int) -> dict:
    request = _message(_object(entry.get("request"), "request"), request=True, entry=entry)
    response_data = _object(entry.get("response"), "response")
    status = _number(response_data.get("status"))
    response = (_message(response_data, request=False, entry=entry,
                         head_response=request["method"] == "HEAD") if status else None)
    captured_at = exchange.timestamp(entry.get("startedDateTime"))
    if captured_at is None:
        raise exchange.ExchangeError("HAR entry lacks capture timestamp")
    if "_bughunt" in entry:
        retained = exchange.validate(entry["_bughunt"])
        if exchange.content_id(request, response) != retained["exchange_id"]:
            raise exchange.ExchangeError("HAR fields differ from retained exchange metadata")
        return retained
    entry_id = entry.get("_id", f"{source_id}#entry-{index}")
    provenance = exchange.source("har", entry_id, source_hash, captured_at=captured_at)
    return exchange.record(request, response, [provenance])


def parse(data: bytes, *, source_id: str) -> list[dict]:
    document = _object(exchange.load_json(data), "document")
    log = _object(document.get("log"), "log")
    if log.get("version") != "1.2":
        raise exchange.ExchangeError("Supported HAR version is 1.2")
    entries = log.get("entries")
    if not isinstance(entries, list) or not 0 < len(entries) <= exchange.ENTRY_LIMIT:
        raise exchange.ExchangeError("HAR must contain 1–500 entries")
    source_hash = exchange.digest(data)
    return [_entry(_object(entry, "entry"), source_id, source_hash, index)
            for index, entry in enumerate(entries)]


def _headers_out(message: dict) -> list[dict]:
    return [{"name": name, "value": value} for name, value in message["headers"]]


def _request_out(message: dict) -> tuple[dict, str | None]:
    body = exchange.decode(message["body_b64"], exchange.BODY_LIMIT)
    result = {"method": message["method"], "url": message["url"], "httpVersion": message["http_version"],
              "headers": _headers_out(message), "cookies": [],
              "queryString": [{"name": name, "value": value}
                              for name, value in parse_qsl(message["url"].partition("?")[2], keep_blank_values=True)],
              "headersSize": -1, "bodySize": len(body)}
    encoding = None
    if body:
        try:
            value = body.decode("utf-8")
        except UnicodeError:
            value, encoding = base64.b64encode(body).decode(), "base64"
        types = exchange.header_values(message, "content-type")
        result["postData"] = {"mimeType": types[0] if types else "application/octet-stream", "text": value}
    return result, encoding


def _response_out(message: dict | None) -> dict:
    if message is None:
        return {"status": 0, "statusText": "", "httpVersion": "", "headers": [], "cookies": [],
                "content": {"size": 0, "mimeType": "", "text": ""}, "redirectURL": "",
                "headersSize": -1, "bodySize": 0}
    body = exchange.decode(message["body_b64"], exchange.BODY_LIMIT)
    types = exchange.header_values(message, "content-type")
    locations = exchange.header_values(message, "location")
    return {"status": message["status"], "statusText": message["reason"],
            "httpVersion": message["http_version"], "headers": _headers_out(message), "cookies": [],
            "content": {"size": len(body), "mimeType": types[0] if types else "application/octet-stream",
                        "text": base64.b64encode(body).decode(), "encoding": "base64"},
            "redirectURL": locations[0] if locations else "", "headersSize": -1, "bodySize": len(body)}


def export(records: list[dict], *, private: bool = False) -> bytes:
    if not records or len(records) > exchange.ENTRY_LIMIT:
        raise exchange.ExchangeError("Invalid HAR export batch")
    entries = []
    for original in records:
        value = exchange.project(original, private=private)
        request, encoding = _request_out(value["request"])
        times = [source["captured_at"] for source in value["sources"] if source["captured_at"]]
        entry = {"startedDateTime": min(times) if times else "1970-01-01T00:00:00+00:00",
                 "time": 0, "request": request, "response": _response_out(value["response"]),
                 "cache": {}, "timings": {"send": 0, "wait": 0, "receive": 0},
                 "_bughunt": value, "_bughuntRequestTruncated": value["request"]["truncated"],
                 "_bughuntResponseTruncated": bool(value["response"] and value["response"]["truncated"]),
                 "comment": "Inert retained exchange; elapsed timings are unknown export placeholders"}
        if encoding:
            entry["_bughuntRequestEncoding"] = encoding
        entries.append(entry)
    result = exchange.canonical({"log": {"version": "1.2", "creator": {"name": "Bughunt", "version": "1"},
                                        "entries": entries}}) + b"\n"
    if len(result) > exchange.INPUT_LIMIT:
        raise exchange.ExchangeError("HAR export exceeds 16 MiB")
    return result
