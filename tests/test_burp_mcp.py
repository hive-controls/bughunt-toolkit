"""Client lifecycle/schema controls; fake replies do not attest Burp behavior."""

import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import queue
import threading
import time

import pytest

from bughunt.integrations import burp_mcp, burp_profile, burp_transport
from test_gate import policy


def client_with_inventory(inventory):
    client = burp_mcp.Client.__new__(burp_mcp.Client)
    client.start = lambda: None
    initialized = {
        "protocolVersion": burp_transport.PROTOCOL,
        "serverInfo": {
            "name": "burp-suite",
            "version": burp_profile.VERSIONS["server"],
        },
        "capabilities": {"tools": {}},
    }
    client.send = lambda method, params, identifier=None: (
        inventory if method == "tools/list" else initialized
    )
    return client


def inventory():
    schema = {
        "type": "object",
        "properties": {"count": {"type": "integer"}, "offset": {"type": "integer"}},
        "required": ["count", "offset"],
    }
    return {
        "tools": [{"name": burp_transport.HISTORY, "inputSchema": schema}]
        + [
            {"name": "unexposed-" + str(index), "inputSchema": {}}
            for index in range(23)
        ],
        "_meta": {},
    }


def test_observed_empty_sdk_metadata_is_supported_without_broadening_tools():
    result = client_with_inventory(inventory()).handshake()
    assert result["connected"] and result["tool_allowlist"] == [burp_transport.HISTORY]


@pytest.mark.parametrize(
    "change", ["pagination", "metadata", "count", "schema", "duplicate"]
)
def test_unexpected_inventory_or_schema_remains_blocked(change):
    value = inventory()
    if change == "pagination":
        value["nextCursor"] = "another-page"
    elif change == "metadata":
        value["_meta"] = {"uninspected": True}
    elif change == "count":
        value["tools"].pop()
    elif change == "schema":
        value["tools"][0]["inputSchema"]["properties"]["count"] = {"type": "number"}
    else:
        value["tools"][1]["name"] = burp_transport.HISTORY
    with pytest.raises(ValueError):
        client_with_inventory(value).handshake()


def test_reader_start_failure_leaves_cleanup_handle_with_caller(monkeypatch):
    class Process:
        stdin, stdout = io.BytesIO(), io.BytesIO()
        status = None

        def poll(self):
            return self.status

        def terminate(self):
            self.status = -1

        def wait(self, timeout):
            return self.status

    class Reader:
        def __init__(self, **options):
            pass

        def start(self):
            raise RuntimeError("reader unavailable")

        def is_alive(self):
            return False

    process = Process()
    monkeypatch.setattr(burp_mcp.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(burp_mcp.threading, "Thread", Reader)
    client = None
    try:
        with pytest.raises(RuntimeError):
            client = burp_mcp.Client(
                "http://127.0.0.1:9876", deadline=time.monotonic() + 5
            )
            client.handshake()
    finally:
        if client is not None:
            client.close()
    assert process.poll() is not None


class OwnedSseHandler(BaseHTTPRequestHandler):
    """PROXY peer; exercise the real isolated bridge without Burp or target traffic."""

    def log_message(self, *_arguments):
        pass

    def event(self, name, payload):
        self.wfile.write(b"event: " + name.encode() + b"\ndata: " + payload + b"\n\n")
        self.wfile.flush()

    def do_GET(self):
        self.server.gets += 1
        if self.server.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "http://remote.invalid/")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        path = b"?sessionId=00000000-0000-0000-0000-000000000000"
        if self.server.mode == "endpoint-redirect":
            path = b"http://remote.invalid/message"
        try:
            self.event("endpoint", path)
            while not self.server.stopped.is_set():
                try:
                    payload = self.server.responses.get(timeout=0.05)
                except queue.Empty:
                    continue
                self.event("message", payload)
        except (OSError, ValueError):
            pass

    def reply(self, value):
        identifier = value["id"]
        if identifier == 1:
            result = {
                "protocolVersion": burp_transport.PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "burp-suite",
                    "version": burp_profile.VERSIONS["server"],
                },
            }
        elif identifier == 2:
            result = inventory()
            if self.server.mode == "schema":
                result["tools"][0]["inputSchema"]["properties"]["count"] = {
                    "type": "number"
                }
        else:
            self.server.called.set()
            if self.server.mode in {"timeout", "cancel"}:
                return
            result = {
                "content": [
                    {"type": "text", "text": "HTTP history access denied by Burp Suite"}
                ],
                "isError": False,
            }
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": identifier, "result": result}
        ).encode()
        if identifier == 1:
            if self.server.mode == "malformed":
                payload = b'{"jsonrpc":"2.0","id":1,"result":[]}'
            elif self.server.mode == "duplicate":
                payload = b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}'
            elif self.server.mode == "unsolicited":
                payload = b'{"jsonrpc":"2.0","id":99,"result":{}}'
            elif self.server.mode == "oversized":
                payload = b"x" * (burp_transport.LIMIT + 1)
            elif self.server.mode == "admission-spoof":
                payload = b'{"transport_admission":3,"method":"POST"}'
        self.server.responses.put(payload)

    def do_POST(self):
        value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append(value)
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()
        if "id" in value:
            self.reply(value)


@pytest.fixture
def sse_peer(request):
    server = ThreadingHTTPServer(("127.0.0.1", 0), OwnedSseHandler)
    server.daemon_threads = True
    server.mode = request.param
    server.responses, server.requests = queue.Queue(), []
    server.gets = 0
    server.stopped, server.called = threading.Event(), threading.Event()
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server
    finally:
        server.stopped.set()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        assert not worker.is_alive()


@pytest.mark.parametrize(
    "sse_peer",
    [
        "redirect",
        "endpoint-redirect",
        "malformed",
        "duplicate",
        "unsolicited",
        "oversized",
        "schema",
        "inventory-drift",
    ],
    indirect=True,
)
def test_real_bridge_rejects_untrusted_peer_and_is_reaped(sse_peer):
    client = burp_mcp.Client(
        "http://127.0.0.1:" + str(sse_peer.server_port), deadline=time.monotonic() + 5
    )
    try:
        with pytest.raises(ValueError):
            client.handshake(
                burp_profile.TOOLS_SHA256
                if sse_peer.mode == "inventory-drift"
                else None
            )
    finally:
        assert client.close()
    assert client.process.poll() is not None and not client.reader.is_alive()
    assert not any(value["method"] == "tools/call" for value in sse_peer.requests)


@pytest.mark.parametrize("sse_peer", ["timeout", "cancel"], indirect=True)
def test_real_bridge_inflight_history_is_bounded_and_reaped(sse_peer):
    def check():
        if sse_peer.mode == "cancel" and sse_peer.called.is_set():
            raise ValueError("Owned injected cancellation")

    setup_started = time.monotonic()
    client = burp_mcp.Client(
        "http://127.0.0.1:" + str(sse_peer.server_port),
        deadline=setup_started + 10,
        check=check,
    )
    try:
        client.handshake()
        assert time.monotonic() - setup_started < 10
        started = time.monotonic()
        client.deadline = min(client.deadline, started + 2)
        with pytest.raises(ValueError):
            client.history(1, 0)
    finally:
        assert client.close()
    assert sse_peer.called.is_set() and time.monotonic() - started < 5
    assert client.process.poll() is not None and not client.reader.is_alive()
    assert [
        value.get("params", {}).get("name")
        for value in sse_peer.requests
        if value["method"] == "tools/call"
    ] == [burp_transport.HISTORY]


@pytest.mark.parametrize("sse_peer", ["denied"], indirect=True)
def test_real_bridge_preserves_denial_reply_and_forbids_second_page(sse_peer):
    client = burp_mcp.Client(
        "http://127.0.0.1:" + str(sse_peer.server_port), deadline=time.monotonic() + 5
    )
    try:
        client.handshake()
        result = client.history(1, 0)
        assert "denied" in result["content"][0]["text"] and set(client.receipts) == {
            "1",
            "2",
            "3",
        }
        with pytest.raises(ValueError):
            client.history(1, 1)
    finally:
        assert client.close()
    assert client.process.poll() is not None and not client.reader.is_alive()
    assert (
        len([value for value in sse_peer.requests if value["method"] == "tools/call"])
        == 1
    )


@pytest.mark.parametrize(
    "sse_peer,expected",
    [("denied", 5), ("redirect", 1), ("malformed", 2), ("admission-spoof", 2)],
    indirect=["sse_peer"],
)
def test_real_child_admission_receipts_count_bridge_http_even_on_failure(
    policy, sse_peer, expected
):
    from bughunt.core import execution_receipts

    with execution_receipts.collect() as measured:
        client = burp_mcp.Client(
            "http://127.0.0.1:" + str(sse_peer.server_port),
            deadline=time.monotonic() + 5,
        )
        try:
            if sse_peer.mode == "denied":
                client.handshake()
                client.history(1, 0)
            else:
                with pytest.raises(ValueError):
                    client.handshake()
        finally:
            assert client.close()
    assert measured.metrics(0)["requests_admitted"] == expected
    assert sse_peer.gets + len(sse_peer.requests) == expected


@pytest.mark.parametrize(
    "rows",
    [
        [{"transport_admission": 2, "method": "GET"}],
        [
            {"transport_admission": 1, "method": "GET"},
            {"transport_admission": 1, "method": "GET"},
        ],
        [{"transport_admission": 1, "method": "POST"}],
    ],
)
def test_child_admission_sequence_refuses_missing_duplicate_or_wrong_method(rows):
    client = burp_mcp.Client("http://127.0.0.1:9876", deadline=time.monotonic() + 5)
    stream = io.BytesIO(b"".join(json.dumps(row).encode() + b"\n" for row in rows))
    burp_mcp._reader(stream, client.replies, client.failed, client._admission)
    assert client.failed.is_set()
    assert client.replies.empty()


def test_missing_child_events_never_claim_zero_requests(policy):
    from bughunt.core import execution_receipts

    with execution_receipts.collect() as measured:
        client = burp_mcp.Client("http://127.0.0.1:9876", deadline=time.monotonic() + 5)
        client.observer = execution_receipts.child_admission_observer()
        reply = {"jsonrpc": "2.0", "id": 1, "result": {}}
        client.replies.put((json.dumps(reply).encode(), reply))
        with pytest.raises(ValueError, match="Missing child admission"):
            client.receive(1)
    assert measured.metrics(0)["requests_admitted"] is None
    assert measured.authority() is None


@pytest.mark.parametrize("sse_peer", ["denied"], indirect=True)
def test_child_admissions_keep_original_authority_after_policy_changes(
    policy, sse_peer
):
    from bughunt.core import execution_receipts

    document, root = policy
    with execution_receipts.collect() as measured:
        client = burp_mcp.Client(
            "http://127.0.0.1:" + str(sse_peer.server_port),
            deadline=time.monotonic() + 5,
        )
        try:
            client.handshake()
            document["mission"] = "changed-after-handshake"
            (root / "policy.json").write_text(json.dumps(document))
            client.history(1, 0)
        finally:
            assert client.close()
    assert measured.metrics(0)["requests_admitted"] == 5
    assert sse_peer.gets + len(sse_peer.requests) == 5
    assert measured.authority() is None


def test_reader_launch_failure_marks_child_measurements_incomplete(policy, monkeypatch):
    from bughunt.core import execution_receipts

    class Process:
        stdin, stdout = io.BytesIO(), io.BytesIO()

    class Reader:
        def __init__(self, **options):
            pass

        def start(self):
            raise RuntimeError("reader unavailable")

    monkeypatch.setattr(
        burp_mcp.subprocess, "Popen", lambda *_args, **_kwargs: Process()
    )
    monkeypatch.setattr(burp_mcp.threading, "Thread", Reader)
    with execution_receipts.collect() as measured:
        client = burp_mcp.Client("http://127.0.0.1:9876", deadline=time.monotonic() + 5)
        with pytest.raises(RuntimeError):
            client.start()
    assert measured.metrics(0)["requests_admitted"] is None
