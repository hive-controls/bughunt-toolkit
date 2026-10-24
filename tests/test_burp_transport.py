"""Offline transport guards; these do not attest the Community consumer."""

import io
import json

import pytest

from bughunt.integrations import burp_transport as transport


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:9876",
        "http://0.0.0.0:9876",
        "https://127.0.0.1:9876",
        "http://127.0.0.1",
        "http://user@127.0.0.1:9876",
        "http://127.0.0.1:9876/sse",
        "http://127.0.0.1:9876?target=remote",
        "http://[::1]:9876",
        "http://127.0.0.1:9876#fragment",
    ],
)
def test_remote_or_ambiguous_endpoint_rejected(url):
    with pytest.raises(ValueError):
        transport.endpoint(url)


@pytest.mark.parametrize(
    "value",
    [
        "http://remote/message",
        "/message?sessionId=abc",
        "//remote/?sessionId=abc",
        "?sessionId=00000000-0000-0000-0000-000000000000&target=remote",
        "../?sessionId=abc",
    ],
)
def test_unexpected_sse_post_endpoint_rejected(value):
    with pytest.raises(ValueError):
        transport.message_endpoint(value)


def test_exact_local_endpoint_and_uuid_post_path():
    assert transport.endpoint("http://127.0.0.1:9876") == ("127.0.0.1", 9876)
    path = "?sessionId=00000000-0000-0000-0000-000000000000"
    assert transport.message_endpoint(path) == "/" + path


def test_only_fixed_handshake_and_one_bounded_history_call_allowed():
    values = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": transport.PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "bughunt-read-only", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": transport.HISTORY,
                "arguments": {"count": 1, "offset": 0},
            },
        },
    ]
    for stage, value in enumerate(values):
        assert transport.request_allowed(value, stage) == stage + 1
    for tool in (
        "send_http1_request",
        "get_proxy_http_history_regex",
        "set_user_options",
        "get_proxy_websocket_history",
    ):
        value = dict(
            values[-1], params={"name": tool, "arguments": {"count": 1, "offset": 0}}
        )
        with pytest.raises(ValueError):
            transport.request_allowed(value, 3)
    for arguments in (
        {"count": 0, "offset": 0},
        {"count": True, "offset": 0},
        {"count": 1, "offset": 501},
    ):
        with pytest.raises(ValueError):
            transport.request_allowed(
                dict(
                    values[-1],
                    params={"name": transport.HISTORY, "arguments": arguments},
                ),
                3,
            )


def test_sse_parser_and_duplicate_json_fail_closed(monkeypatch):
    iterator = transport.events(
        io.BytesIO(
            b"event: endpoint\ndata: ?sessionId=nonce\n\nevent: message\ndata: {}\n\n"
        )
    )
    assert next(iterator) == ("endpoint", "?sessionId=nonce")
    assert next(iterator) == ("message", "{}")
    with pytest.raises(ValueError):
        transport.decode(b'{"id":1,"id":2}')
    with pytest.raises(ValueError):
        next(transport.events(io.BytesIO(b"retry: 1000\n\n")))
    monkeypatch.setattr(transport, "LIMIT", 8)
    with pytest.raises(ValueError):
        next(transport.events(io.BytesIO(b"event: endpoint\n\n")))


def test_approval_post_wait_uses_remaining_job_deadline(monkeypatch):
    timeouts = []

    class Response:
        status = 202

        def read(self, maximum):
            return b""

    class Connection:
        def __init__(self, host, port, *, timeout):
            assert host == "127.0.0.1" and port == 9876
            timeouts.append(timeout)

        def request(self, method, path, **options):
            assert method == "POST"

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(transport.http.client, "HTTPConnection", Connection)
    bridge = transport.Bridge("http://127.0.0.1:9876", 60)
    bridge.stage, bridge.path = 3, "/?sessionId=00000000-0000-0000-0000-000000000000"
    bridge.post(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": transport.HISTORY,
                    "arguments": {"count": 1, "offset": 0},
                },
            }
        ).encode()
    )
    assert 30 < timeouts[-1] <= 60


def test_post_timeout_never_exceeds_budget(monkeypatch):
    timeouts = []

    class Response:
        status = 202

        def read(self, maximum):
            return b""

    class Connection:
        def __init__(self, host, port, *, timeout):
            timeouts.append(timeout)

        def request(self, method, path, **options):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(transport.http.client, "HTTPConnection", Connection)
    readings = iter(
        [1000.0, 999.999]
    )  # deterministic PROXY for Windows FP/coarse-clock overshoot (raw remaining 60.001 > 60)
    monkeypatch.setattr(transport.time, "monotonic", lambda: next(readings))
    bridge = transport.Bridge("http://127.0.0.1:9876", 60)
    bridge.stage, bridge.path = 3, "/?sessionId=00000000-0000-0000-0000-000000000000"
    bridge.post(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": transport.HISTORY,
                    "arguments": {"count": 1, "offset": 0},
                },
            }
        ).encode()
    )
    assert 0 < timeouts[-1] <= 60
