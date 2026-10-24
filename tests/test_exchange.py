"""Owned inert raw HTTP/HAR interchange, integrity and provenance fixtures."""

import base64
import gzip
import json
import uuid
from urllib.parse import urlsplit

import pytest

from bughunt.core import exchange, har, ledger
from bughunt.modules import exchange as exchange_command, load_builtin
from test_gate import boundaries, policy

CAPTURE_TIME = "2026-10-13T00:00:00+00:00"


def _capture(
    *,
    url="https://allowed.example/item?token=query-secret",
    body=b"hello",
    response_body=b"world",
    source_id="capture-one",
    status=200,
):
    request = (
        f"POST {url} HTTP/1.1\r\nHost: {urlsplit(url).netloc}\r\n"
        "Authorization: Bearer header-secret\r\nCookie: id=cookie-secret\r\n"
        "X-Session-Id: custom-secret\r\nContent-Type: text/plain\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    response = (
        f"HTTP/1.1 {status} OK\r\nContent-Type: text/plain\r\n"
        f"Content-Length: {len(response_body)}\r\n\r\n"
    ).encode() + response_body
    return (
        exchange.raw_record(
            request,
            response,
            source_id=source_id,
            captured_at=CAPTURE_TIME,
            actor="owner",
        ),
        request,
        response,
    )


def _plain_har(*, url="https://allowed.example/item", binary=False):
    body = b"\xff\x00owned binary" if binary else b"owned response"
    entry = {
        "startedDateTime": CAPTURE_TIME,
        "time": 5,
        "request": {
            "method": "GET",
            "url": url,
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Host", "value": urlsplit(url).netloc}],
            "cookies": [],
            "queryString": [],
            "headersSize": -1,
            "bodySize": 0,
        },
        "response": {
            "status": 200,
            "statusText": "OK",
            "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": "application/octet-stream"}],
            "cookies": [],
            "content": {
                "size": len(body),
                "mimeType": "application/octet-stream",
                "encoding": "base64",
                "text": base64.b64encode(body).decode(),
            },
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": len(body),
        },
        "cache": {},
        "timings": {"send": 1, "wait": 3, "receive": 1},
    }
    return exchange.canonical(
        {
            "log": {
                "version": "1.2",
                "creator": {"name": "owned fixture", "version": "1"},
                "entries": [entry],
            }
        }
    )


def test_raw_private_roundtrip_preserves_bytes_hashes_and_timestamp(policy, boundaries):
    value, request, response = _capture(
        body=b"\x00\xff", response_body=b"\x80\x00owned"
    )
    assert exchange.validate(value) == value
    private = exchange.project(value, private=True)
    assert exchange.decode(private["request"]["raw_b64"]) == request
    assert exchange.decode(private["response"]["raw_b64"]) == response
    assert private["request"]["raw_sha256"] == exchange.digest(request)
    assert private["sources"][0]["captured_at"] == CAPTURE_TIME
    assert private["inert"] is True


@pytest.mark.parametrize("slot", ["request", "response"])
def test_partial_private_key_is_removed_from_default_exports(policy, slot):
    partial = b"-----BEGIN " + b"PRIVATE KEY-----\nMIIE-OWNED-SYNTHETIC-KEY-MATERIAL\n"
    _value, request, response = _capture(
        body=partial if slot == "request" else b"owned",
        response_body=partial if slot == "response" else b"owned",
    )
    value = exchange.raw_record(
        request,
        response,
        source_id="partial-key",
        request_truncated=slot == "request",
        response_truncated=slot == "response",
    )
    sanitized = exchange.project(value)
    assert b"SYNTHETIC-KEY-MATERIAL" not in exchange.decode(sanitized[slot]["raw_b64"])
    assert b"SYNTHETIC-KEY-MATERIAL" not in har.export([value])
    assert b"SYNTHETIC-KEY-MATERIAL" in exchange.decode(
        exchange.project(value, private=True)[slot]["raw_b64"]
    )
    assert sanitized[slot]["truncated"] is True


def test_duplicate_imports_converge_and_preserve_provenance(policy, boundaries):
    first, request, response = _capture()
    second = exchange.raw_record(
        request,
        response,
        source_id="capture-two",
        captured_at=CAPTURE_TIME,
        actor="viewer",
        run_id=str(uuid.uuid4()),
    )
    first_ids = exchange.save(
        [first], source_id="raw-one", source_bytes=request, kind="raw"
    )
    second_ids = exchange.save(
        [second, first], source_id="raw-two", source_bytes=response, kind="raw"
    )
    assert first_ids == second_ids
    retained = exchange.read(first_ids[0])
    assert {item["source_id"] for item in retained["sources"]} == {
        "capture-one",
        "capture-two",
    }
    assert {item["actor"] for item in retained["sources"]} == {"owner", "viewer"}
    assert any(item["run_id"] for item in retained["sources"])
    exchange.save([first], source_id="raw-one", source_bytes=request, kind="raw")
    assert exchange.read(first_ids[0]) == retained
    assert len(list((exchange.directory() / "receipts").glob("*.json"))) == 2


def test_offscope_import_is_quarantined_without_execution(policy, boundaries):
    value, raw, _response = _capture(url="https://outside.example/item")
    assert value["scope_history"][0]["permitted"] is False
    ids = exchange.save([value], source_id="outside", source_bytes=raw, kind="raw")
    assert exchange.read(ids[0])["inert"] is True
    assert (
        exchange.summary(exchange.read(ids[0]))["current_scope"]["permitted"] is False
    )


def test_partial_and_head_responses_keep_explicit_truncation(policy):
    request = (
        b"GET https://allowed.example/item HTTP/1.1\r\nHost: allowed.example\r\n\r\n"
    )
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\npartial"
    with pytest.raises(exchange.ExchangeError):
        exchange.raw_record(request, response, source_id="complete")
    value = exchange.raw_record(
        request, response, source_id="partial", response_truncated=True
    )
    assert value["response"]["truncated"] is True
    head = exchange.raw_record(
        request.replace(b"GET ", b"HEAD "),
        response.replace(b"partial", b""),
        source_id="head",
    )
    assert head["response"]["body_size"] == 0 and head["response"]["truncated"] is False


@pytest.mark.parametrize(
    "raw",
    [
        b"GET /item HTTP/1.1\r\nHost: allowed.example\r\n\r\n",
        b"GET https://allowed.example/item HTTP/1.1\r\nHost: allowed.example\r\nContent-Length: 1\r\n\r\n",
        b"GET https://allowed.example/item HTTP/1.1\r\nHost: allowed.example\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
        b"GET https://allowed.example/item HTTP/1.1\r\nHost: allowed.example\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"GET https://allowed.example/item HTTP/1.1 ignored\r\nHost: allowed.example\r\n\r\n",
    ],
)
def test_malformed_or_ambiguous_raw_input_is_inert(policy, boundaries, raw):
    with pytest.raises(exchange.ExchangeError):
        exchange.raw_record(raw, None, source_id="bad")
    assert not exchange.directory().exists()


def test_native_roundtrip_and_tampering_block_export(policy):
    value, request, _response = _capture()
    assert exchange.validate(exchange.load_json(exchange.canonical(value))) == value
    ids = exchange.save([value], source_id="capture", source_bytes=request, kind="raw")
    path = exchange.directory() / f"{ids[0]}.json"
    altered = json.loads(path.read_bytes())
    altered["request"]["body_sha256"] = "0" * 64
    path.write_bytes(exchange.canonical(altered))
    with pytest.raises(exchange.ExchangeError):
        exchange.read(ids[0])
    with pytest.raises(exchange.ExchangeError):
        exchange.project(altered, private=True)


def test_default_export_redacts_standard_and_custom_credentials(policy):
    value, _request, _response = _capture(body=b"password=body-secret")
    projected = exchange.project(value)
    raw = exchange.decode(projected["request"]["raw_b64"])
    for secret in (
        b"header-secret",
        b"cookie-secret",
        b"custom-secret",
        b"query-secret",
        b"body-secret",
    ):
        assert secret not in raw
    assert projected["derivative_of"] == value["exchange_id"]
    assert projected["sources"] == value["sources"]


def test_default_binary_and_encoded_body_export_is_suppressed(policy):
    value, _request, _response = _capture(response_body=b"\xff\x00owned private binary")
    assert exchange.decode(exchange.project(value)["response"]["body_b64"]).startswith(
        b"[REDACTED"
    )
    encoded = gzip.compress(b"private encoded entity")
    raw = (
        b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: "
        + str(len(encoded)).encode()
        + b"\r\n\r\n"
        + encoded
    )
    request = exchange.decode(value["request"]["raw_b64"])
    compressed = exchange.raw_record(request, raw, source_id="compressed")
    assert exchange.decode(
        exchange.project(compressed)["response"]["body_b64"]
    ).startswith(b"[REDACTED")
    assert (
        exchange.decode(
            exchange.project(compressed, private=True)["response"]["raw_b64"]
        )
        == raw
    )


@pytest.mark.parametrize("binary", [False, True])
def test_har_binary_body_and_deterministic_roundtrip(policy, boundaries, binary):
    imported = har.parse(_plain_har(binary=binary), source_id="owned-har")
    encoded = har.export(imported, private=True)
    again = har.parse(encoded, source_id="roundtrip-har")
    assert again == imported
    assert har.export(again, private=True) == encoded
    assert imported[0]["request"]["representation"] == "har-logical; not wire bytes"


@pytest.mark.parametrize(
    "content_size,body_size,length",
    [(-1, 100, 100), (0, 100, 100), (-1, -1, None), (-1, 100, None)],
)
def test_missing_har_body_is_incomplete(policy, content_size, body_size, length):
    document = json.loads(_plain_har())
    response = document["log"]["entries"][0]["response"]
    response["content"] = {"size": content_size, "mimeType": "text/plain"}
    response["bodySize"] = body_size
    response["headers"] = (
        [] if length is None else [{"name": "Content-Length", "value": str(length)}]
    )
    value = har.parse(exchange.canonical(document), source_id="missing-body")[0]
    assert value["response"]["truncated"] is True
    assert value["response"]["body_size"] == 0
    assert (
        har.parse(har.export([value], private=True), source_id="retained-incomplete")[0]
        == value
    )


def test_har_unknown_decoded_size_checks_other_body_evidence(policy):
    document = json.loads(_plain_har())
    response = document["log"]["entries"][0]["response"]
    response["content"] = {"size": -1, "mimeType": "text/plain", "text": "part"}
    response["bodySize"] = 100
    response["headers"] = [{"name": "Content-Length", "value": "100"}]
    value = har.parse(exchange.canonical(document), source_id="short-body")[0]
    assert value["response"]["truncated"] is True


@pytest.mark.parametrize("method,status", [("HEAD", 200), ("GET", 204), ("GET", 304)])
def test_har_bodyless_responses_and_encoded_sizes_remain_valid(policy, method, status):
    document = json.loads(_plain_har())
    entry = document["log"]["entries"][0]
    entry["request"]["method"] = method
    entry["response"].update(
        status=status,
        bodySize=0,
        content={"size": 0, "mimeType": "text/plain"},
        headers=[{"name": "Content-Length", "value": "100"}],
    )
    assert (
        har.parse(exchange.canonical(document), source_id="bodyless")[0]["response"][
            "truncated"
        ]
        is False
    )
    entry["request"]["method"] = "GET"
    entry["response"].update(
        status=200,
        bodySize=100,
        content={"size": 5, "mimeType": "text/plain", "text": "owned"},
        headers=[
            {"name": "Content-Encoding", "value": "gzip"},
            {"name": "Content-Length", "value": "100"},
        ],
    )
    assert (
        har.parse(exchange.canonical(document), source_id="decoded-body")[0][
            "response"
        ]["truncated"]
        is False
    )


@pytest.mark.parametrize(
    "method,status", [("HEAD", 200), ("GET", 103), ("GET", 204), ("GET", 304)]
)
def test_bodyless_private_har_roundtrip_and_empty_text_remain_complete(
    policy, method, status
):
    request = f"{method} https://allowed.example/item HTTP/1.1\r\nHost: allowed.example\r\n\r\n".encode()
    length = b"Content-Length: 100\r\n" if method == "HEAD" or status == 304 else b""
    response = f"HTTP/1.1 {status} Owned\r\n".encode() + length + b"\r\n"
    value = exchange.raw_record(
        request, response, source_id="bodyless-raw", captured_at=CAPTURE_TIME
    )
    document = json.loads(har.export([value], private=True))
    assert (
        har.parse(exchange.canonical(document), source_id="bodyless-roundtrip")[0]
        == value
    )
    entry = document["log"]["entries"][0]
    del entry["_bughunt"]
    entry["response"]["content"].pop("encoding")
    assert entry["response"]["content"]["text"] == ""
    ordinary = har.parse(exchange.canonical(document), source_id="bodyless-empty-text")[
        0
    ]
    assert ordinary["response"]["truncated"] is False
    assert ordinary["response"]["body_size"] == 0


@pytest.mark.parametrize(
    "method,status", [("HEAD", 200), ("GET", 103), ("GET", 204), ("GET", 304)]
)
def test_har_bodyless_responses_reject_nonempty_text(policy, method, status):
    document = json.loads(_plain_har())
    entry = document["log"]["entries"][0]
    entry["request"]["method"] = method
    entry["response"]["status"] = status
    with pytest.raises(exchange.ExchangeError, match="forbids a body"):
        har.parse(exchange.canonical(document), source_id="forbidden-body")


def test_raw_to_har_retains_original_bytes_and_links(policy):
    value, request, response = _capture()
    exported = har.export([value], private=True)
    result = har.parse(exported, source_id="cross-tool")[0]
    assert result["exchange_id"] == value["exchange_id"]
    assert exchange.decode(result["request"]["raw_b64"]) == request
    assert exchange.decode(result["response"]["raw_b64"]) == response
    assert result["sources"] == value["sources"]


def test_malformed_har_batch_has_no_partial_storage(policy, boundaries):
    document = json.loads(_plain_har())
    document["log"]["entries"].append({"startedDateTime": CAPTURE_TIME, "request": {}})
    with pytest.raises(exchange.ExchangeError):
        values = har.parse(exchange.canonical(document), source_id="bad batch")
        exchange.save(values, source_id="bad batch", source_bytes=b"bad", kind="har")
    assert not exchange.directory().exists()


def test_har_retained_metadata_cannot_override_standard_fields(policy):
    value, _request, _response = _capture()
    document = json.loads(har.export([value], private=True))
    document["log"]["entries"][0]["request"]["url"] = "https://outside.example/changed"
    with pytest.raises(exchange.ExchangeError):
        har.parse(exchange.canonical(document), source_id="tampered")


def test_sanitized_har_roundtrip_is_stable(policy):
    value, _request, _response = _capture()
    first = har.export([value])
    roundtrip = har.parse(first, source_id="sanitized")
    assert har.export(roundtrip) == first


def test_body_forbidden_response_is_rejected_even_without_length(policy):
    request = (
        b"GET https://allowed.example/item HTTP/1.1\r\nHost: allowed.example\r\n\r\n"
    )
    with pytest.raises(exchange.ExchangeError):
        exchange.raw_record(
            request, b"HTTP/1.1 204 No Content\r\n\r\ninvalid body", source_id="bad204"
        )


def test_cli_import_export_is_inert_and_does_not_overwrite(policy, boundaries, capsys):
    value, request, response = _capture()
    root = policy[1]
    request_path, response_path = root / "request.http", root / "response.http"
    request_path.write_bytes(request)
    response_path.write_bytes(response)
    assert load_builtin("exchange") is exchange_command
    assert (
        exchange_command.main(
            [
                "import-raw",
                str(request_path),
                "--response",
                str(response_path),
                "--source-id",
                "owned-cli",
                "--timestamp",
                CAPTURE_TIME,
            ]
        )
        == 0
    )
    imported = json.loads(capsys.readouterr().out)
    exchange_id = imported["exchange_ids"][0]
    output = root / "sanitized.har"
    assert (
        exchange_command.main(
            ["export", exchange_id, "--format", "har", "--output", str(output)]
        )
        == 0
    )
    capsys.readouterr()
    archived = har.parse(output.read_bytes(), source_id="cli-export")
    assert archived[0]["derivative_of"] == exchange_id
    sentinel = output.read_bytes()
    assert exchange_command.main(["export", exchange_id, "--output", str(output)]) == 2
    capsys.readouterr()
    assert output.read_bytes() == sentinel


def test_ledger_bridge_checks_hashes_and_retains_run_actor_links(policy):
    from bughunt.core import egress
    import httpx

    with egress.client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"owned")
        )
    ) as client:
        response = client.get("https://allowed.example/item")
    run_id = response.extensions["bughunt_run_id"]
    value = exchange.from_run(run_id)
    assert value["sources"][0]["run_id"] == run_id
    assert value["sources"][0]["actor"] == "default"
    path = ledger.runs_dir() / run_id / "response.http"
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(exchange.ExchangeError):
        exchange.from_run(run_id)


def test_chunked_logical_ledger_bridge_preserves_bytes_and_hashes(policy):
    from bughunt.core import egress
    import httpx

    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            200,
            headers={"Transfer-Encoding": "chunked", "Content-Type": "text/plain"},
            stream=httpx.ByteStream(b"owned"),
        )
    )
    with egress.client(transport=transport) as client:
        response = client.get("https://allowed.example/item")
    run_id = response.extensions["bughunt_run_id"]
    manifest = ledger.manifest_for(run_id)
    value = exchange.from_run(run_id)
    assert exchange.validate(value) == value
    for name in ("request", "response"):
        original = (ledger.runs_dir() / run_id / f"{name}.http").read_bytes()
        assert exchange.decode(value[name]["raw_b64"]) == original
        assert value[name]["raw_sha256"] == manifest[name]["sha256"]
        assert value[name]["representation"] == exchange.LEDGER_REPRESENTATION
    assert value["response"]["truncated"] is False
    assert exchange.decode(value["response"]["body_b64"]) == b"owned"
    assert (
        har.parse(har.export([value], private=True), source_id="logical-har")[0]
        == value
    )
    with pytest.raises(exchange.ExchangeError, match="transfer framing"):
        exchange.raw_record(
            exchange.decode(value["request"]["raw_b64"]),
            exchange.decode(value["response"]["raw_b64"]),
            source_id="raw-wire-claim",
        )


@pytest.mark.parametrize(
    "field,bad", [("sha256", None), ("kind", []), ("source_id", 1)]
)
def test_bad_native_source_types_are_controlled_and_inert(policy, field, bad):
    value, _request, _response = _capture()
    value["sources"][0][field] = bad
    with pytest.raises(exchange.ExchangeError):
        exchange.validate(value)
    assert not exchange.directory().exists()


def test_raw_http11_missing_host_is_rejected(policy):
    with pytest.raises(exchange.ExchangeError):
        exchange.raw_record(
            b"GET https://allowed.example/item HTTP/1.1\r\n\r\n",
            None,
            source_id="missing-host",
        )
