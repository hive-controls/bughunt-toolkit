"""Inert Burp Save-items XML: owned bytes, provenance and fail-closed input."""

import base64
import json
from pathlib import Path
import xml.etree.ElementTree as xml

import pytest

from bughunt.core import exchange, har
from bughunt.integrations import burp
from bughunt.modules import exchange as exchange_command
from test_gate import boundaries, policy

CAPTURE_TIME = "Tue Oct 13 14:02:36 PDT 2026"
TIMEZONE = "America/Los_Angeles"
REQUEST = (
    b"GET /item?token=query-secret HTTP/1.1\r\nHost: allowed.example\r\n"
    b"Authorization: Bearer header-secret\r\nCookie: id=cookie-secret\r\n\r\n"
)
RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
    b"Set-Cookie: id=response-secret\r\n\r\nowned"
)


def _document(
    *,
    request=REQUEST,
    response=RESPONSE,
    url="https://allowed.example/item?token=query-secret",
):
    root = xml.Element("items", burpVersion="2026.9.2", exportTime=CAPTURE_TIME)
    item = xml.SubElement(root, "item")
    values = {
        "time": CAPTURE_TIME,
        "url": url,
        "host": "allowed.example",
        "port": "443",
        "protocol": "https",
        "method": "GET",
        "path": "/item?token=query-secret",
        "extension": "null",
        "request": base64.b64encode(request).decode(),
        "status": "200",
        "responselength": str(len(response)),
        "mimetype": "text",
        "response": base64.b64encode(response).decode(),
        "comment": "",
    }
    for name, value in values.items():
        field = xml.SubElement(item, name)
        field.text = value
        if name in {"request", "response"}:
            field.set("base64", "true")
        if name == "host":
            field.set("ip", "127.0.0.1")
    return xml.tostring(root, encoding="utf-8")


def _change(raw, field, *, text=None, attribute=None):
    root = xml.fromstring(raw)
    element = root.find(f"item/{field}")
    if text is not None:
        element.text = text
    if attribute:
        element.set(*attribute)
    return xml.tostring(root)


def test_owned_burp_preserves_bytes_timestamp_source_and_policy(policy, boundaries):
    raw = _document()
    value = burp.parse(raw, source_id="owned", timezone=TIMEZONE)[0]
    assert exchange.validate(value) == value
    assert exchange.decode(value["request"]["raw_b64"]) == REQUEST
    assert exchange.decode(value["response"]["raw_b64"]) == RESPONSE
    assert value["request"]["representation"] == burp.REPRESENTATION
    source = value["sources"][0]
    assert source["kind"] == "burp" and source["sha256"] == exchange.digest(raw)
    assert source["captured_at"] == "2026-10-13T14:02:36-07:00"
    assert source["source_id"] == "owned:burp-2026.9.2:item-1"
    assert source["actor"] is None and source["run_id"] is None
    assert value["inert"] is True and value["scope_history"][0]["permitted"] is True


def test_private_source_retention_idempotence_and_tamper_refusal(policy, boundaries):
    raw = _document()
    ids = burp.save(raw, source_id="owned", timezone=TIMEZONE)
    original = exchange.directory() / "sources" / f"{exchange.digest(raw)}.burp.xml"
    assert original.read_bytes() == raw
    assert burp.save(raw, source_id="owned", timezone=TIMEZONE) == ids
    original.write_bytes(b"changed")
    with pytest.raises(exchange.ExchangeError):
        burp.save(raw, source_id="owned", timezone=TIMEZONE)
    assert original.read_bytes() == b"changed"


def test_default_burp_export_redacts_and_retains_derivative_link(policy, boundaries):
    value = burp.parse(_document(), source_id="owned", timezone=TIMEZONE)[0]
    projected = exchange.project(value)
    request = exchange.decode(projected["request"]["raw_b64"])
    response = exchange.decode(projected["response"]["raw_b64"])
    for secret in (
        b"header-secret",
        b"cookie-secret",
        b"query-secret",
        b"response-secret",
    ):
        assert secret not in request + response + har.export([value])
    assert projected["derivative_of"] == value["exchange_id"]
    assert projected["sources"] == value["sources"]
    assert har.parse(har.export([value], private=True), source_id="back") == [value]


def test_offscope_burp_import_is_quarantined_without_io(policy, boundaries):
    raw = _document(url="https://outside.example/item?token=query-secret")
    raw = _change(raw, "host", text="outside.example")
    raw = _change(
        raw,
        "request",
        text=base64.b64encode(
            REQUEST.replace(b"allowed.example", b"outside.example")
        ).decode(),
    )
    ids = burp.save(raw, source_id="outside", timezone=TIMEZONE)
    assert (
        exchange.summary(exchange.read(ids[0]))["current_scope"]["permitted"] is False
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("method", "POST"),
        ("host", "outside.example"),
        ("port", "80"),
        ("protocol", "http"),
        ("path", "/different"),
        ("status", "201"),
        ("responselength", "1"),
        ("time", "Tue Oct 13 14:02:36 PST 2026"),
        ("time", "Mon Oct 13 14:02:36 PDT 2026"),
        ("request", "!!!!"),
        ("response", ""),
    ],
)
def test_conflicting_or_incomplete_metadata_is_rejected(
    policy, boundaries, field, value
):
    raw = _change(_document(), field, text=value)
    with pytest.raises(exchange.ExchangeError):
        burp.save(raw, source_id="bad", timezone=TIMEZONE)
    assert not exchange.directory().exists()


@pytest.mark.parametrize(
    "timezone", ["UTC", "Missing/Zone", "../America/Los_Angeles", ""]
)
def test_wrong_missing_or_unsafe_timezone_is_rejected(policy, boundaries, timezone):
    with pytest.raises(exchange.ExchangeError):
        burp.parse(_document(), source_id="bad", timezone=timezone)


@pytest.mark.parametrize(
    "raw",
    [
        b'<!DOCTYPE items SYSTEM "file:///owned">' + _document(),
        b'<!DOCTYPE items [<!ENTITY owned "expanded">]>' + _document(),
        _document().replace(b"<item>", b"<item><method>GET</method>", 1),
        _document().replace(b"<item>", b"<item extra='unknown'>", 1),
        _document().replace(b"<time>", b"<time><nested/>", 1),
        _document().replace(b'base64="true"', b'base64="false"', 1),
        _document().replace(b"<items", b"<unknown", 1),
        _document().decode().encode("utf-16"),
        b"<items/>",
        b"not xml",
    ],
)
def test_hostile_or_ambiguous_xml_never_creates_evidence(policy, boundaries, raw):
    with pytest.raises(exchange.ExchangeError):
        burp.save(raw, source_id="bad", timezone=TIMEZONE)
    assert not exchange.directory().exists()


def test_entire_batch_is_validated_before_writing(policy, boundaries):
    root = xml.fromstring(_document())
    invalid = xml.fromstring(_document()).find("item")
    invalid.find("status").text = "500"
    root.append(invalid)
    with pytest.raises(exchange.ExchangeError):
        burp.save(xml.tostring(root), source_id="batch", timezone=TIMEZONE)
    assert not exchange.directory().exists()


def test_native_internal_dtd_is_accepted_but_cannot_define_entities(policy, boundaries):
    raw = burp._DTD.encode() + _document()
    assert len(burp.parse(raw, source_id="native-dtd", timezone=TIMEZONE)) == 1
    altered = raw.replace(
        b"<!ELEMENT items", b'<!ENTITY injected "owned">\n<!ELEMENT items', 1
    )
    with pytest.raises(exchange.ExchangeError):
        burp.parse(altered, source_id="entity", timezone=TIMEZONE)


def test_entry_and_source_limits(policy, boundaries):
    root = xml.fromstring(_document())
    for _ in range(exchange.ENTRY_LIMIT):
        root.append(xml.fromstring(_document()).find("item"))
    with pytest.raises(exchange.ExchangeError):
        burp.parse(xml.tostring(root), source_id="big", timezone=TIMEZONE)
    with pytest.raises(exchange.ExchangeError):
        burp.parse(
            b" " * (exchange.INPUT_LIMIT + 1), source_id="big", timezone=TIMEZONE
        )


@pytest.mark.parametrize("source_id", ["", None, [], "x" * 513])
def test_invalid_caller_source_identity_is_rejected_before_retention(
    policy, boundaries, source_id
):
    with pytest.raises(exchange.ExchangeError):
        burp.save(_document(), source_id=source_id, timezone=TIMEZONE)
    assert not exchange.directory().exists()


def test_cli_import_and_sanitized_raw_export(policy, boundaries, capsys):
    source = policy[1] / "owned.xml"
    source.write_bytes(_document())
    assert (
        exchange_command.main(
            ["import-burp", str(source), "--source-id", "owned", "--timezone", TIMEZONE]
        )
        == 0
    )
    ids = json.loads(capsys.readouterr().out)["exchange_ids"]
    destination = policy[1] / "sanitized"
    assert (
        exchange_command.main(
            ["export", ids[0], "--format", "raw", "--output", str(destination)]
        )
        == 0
    )
    assert b"header-secret" not in (destination / "request.http").read_bytes()
    assert b"response-secret" not in (destination / "response.http").read_bytes()


def test_actual_community_2026_9_2_export(policy, boundaries):
    raw = (Path(__file__).parent / "fixtures" / "burp_2026_9_2_owned.xml").read_bytes()
    assert (
        exchange.digest(raw)
        == "46d56e9a31ed8b6d051458e505bb00b6f06503cc898433b92c28ca7481c47ca0"
    )
    value = burp.parse(raw, source_id="whk010-owned", timezone=TIMEZONE)[0]
    assert value["sources"][0]["captured_at"] == "2026-10-22T05:08:27-07:00"
    assert b"whk010-owned" in exchange.decode(value["response"]["body_b64"])
    assert (
        value["request"]["url"]
        == "http://127.0.0.1:59988/whk010/fixture?token=whk010-query-secret"
    )
    assert value["scope_history"][0]["permitted"] is False
    ids = burp.save(raw, source_id="whk010-owned", timezone=TIMEZONE)
    sanitized = exchange.project(exchange.read(ids[0]))
    retained = exchange.decode(sanitized["request"]["raw_b64"]) + exchange.decode(
        sanitized["response"]["raw_b64"]
    )
    for secret in (
        b"whk010-request-secret",
        b"whk010-cookie-secret",
        b"whk010-query-secret",
        b"whk010-response-secret",
    ):
        assert secret not in retained
