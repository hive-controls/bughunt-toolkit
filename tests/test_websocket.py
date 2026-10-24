"""whk015-owned-ws: protocol write gate plus opt-in owned echo capture/replay."""

import json
import os
import threading

import httpx
import pytest

from bughunt.core import egress, exchange, identity, job, ledger
from bughunt.labs import websocket
from bughunt.modules import ws as command
from test_gate import boundaries, policy

URL = "ws://127.0.0.1:8080/__bughunt_lab__/ws"


def approve(policy, url=URL):
    document, path = policy
    document["mission"] = "whk015-owned-ws"
    document["assets"] = [row for row in document["assets"] if row["id"] != "ws-lab"]
    origin = "http" + url.rsplit("/__bughunt_lab__/", 1)[0][2:]
    document["assets"].append({"id": "ws-lab", "origin": origin, "paths": ["/__bughunt_lab__/"],
                               "operations": ["active_scan"], "methods": ["GET", "CONNECT"]})
    (path / "scope.txt").write_text("127.0.0.1\n")
    (path / "policy.json").write_text(json.dumps(document))


def prepare(policy, messages=None, **kwargs):
    approve(policy)
    return websocket.prepare(URL, ["owned"] if messages is None else messages,
                             mission="whk015-owned-ws", owned_lab=True, **kwargs)


class Socket:
    def __init__(self):
        self.writes = []
        self.timeout = None
    def settimeout(self, value):
        self.timeout = value
    def sendall(self, value, *args):
        self.writes.append(value)


def test_every_protocol_write_is_gated_bounded_and_linked(policy, boundaries):
    plan = prepare(policy)
    inner = Socket()
    wire = websocket._Wire(inner, plan)
    for _ in range(16):
        wire.sendall(b"owned-protocol-write")
    with pytest.raises(egress.PolicyBlocked):
        wire.sendall(b"overflow")
    assert len(inner.writes) == len(plan.budget.sent) == 16
    for row in plan.budget.sent:
        assert ledger.manifest_for(row["run_id"])["representation"] == "protocol-write metadata; no HTTP or frame bytes"
    assert inner.timeout <= plan.budget.seconds


@pytest.mark.parametrize("change", ["policy", "scope", "actor", "cancel", "expiry"])
def test_automatic_pong_close_or_send_cannot_bypass_revocation(policy, boundaries, change):
    plan = prepare(policy)
    plan.budget.activate()
    inner = Socket()
    wire = websocket._Wire(inner, plan)
    wire.sendall(b"owned-handshake")
    document, path = policy
    if change == "policy":
        document["permissions"]["active_scan"] = False
        (path / "policy.json").write_text(json.dumps(document))
    elif change == "scope":
        (path / "scope.txt").write_text("outside.example\n")
    elif change == "actor":
        identity.create_profile("guest", "anonymous", ["http://127.0.0.1:8080"], owned=True)
        identity.use_profile("guest")
    elif change == "cancel":
        job.cancel(plan.budget.job_id)
    else:
        plan.budget.deadline = 0
    with pytest.raises(egress.PolicyBlocked):
        wire.sendall(b"automatic-pong-or-close")
    assert inner.writes == [b"owned-handshake"] and len(plan.budget.sent) == 1


def test_protocol_total_bytes_and_escape_paths_reject(policy, boundaries):
    plan = prepare(policy)
    inner = Socket()
    wire = websocket._Wire(inner, plan)
    wire.sendall(b"x" * 65536)
    with pytest.raises(egress.PolicyBlocked):
        wire.sendall(b"x")
    with pytest.raises(ValueError):
        wire.sendto(b"unsupported")
    assert len(inner.writes) == 1


@pytest.mark.parametrize("url", ["ws://outside.example/__bughunt_lab__/ws", URL.replace("127.0.0.1", "localhost"),
                                 URL.replace("ws:", "wss:"), URL.replace("/__bughunt_lab__/", "/"),
                                 URL + "#fragment", URL.replace("127.0.0.1", "user:secret@127.0.0.1")])
def test_unsupported_targets_reject_before_connect(policy, boundaries, url):
    approve(policy)
    with pytest.raises(ValueError):
        websocket.prepare(url, ["owned"], mission="whk015-owned-ws", owned_lab=True)
    assert not ledger.runs_dir().exists()


@pytest.mark.parametrize("messages,seconds", [([], 5), (["x"] * 5, 5), ([b"binary"], 5),
                                             (["x" * 4097], 5), (["owned"], 0), (["owned"], 11), (["owned"], float("nan"))])
def test_protocol_load_bounds_before_connect(policy, boundaries, messages, seconds):
    with pytest.raises(ValueError):
        prepare(policy, messages=messages, seconds=seconds)


@pytest.mark.parametrize("change", ["stale", "permission", "method", "scope", "mission"])
def test_current_policy_denials_before_connect(policy, boundaries, change):
    approve(policy)
    document, path = policy
    if change == "scope":
        (path / "scope.txt").write_text("outside.example\n")
    else:
        if change == "stale":
            document["state"] = "stale"
        elif change == "permission":
            document["permissions"]["active_scan"] = False
        elif change == "method":
            document["assets"][-1]["methods"] = ["GET"]
        else:
            document["mission"] = "wrong"
        (path / "policy.json").write_text(json.dumps(document))
    with pytest.raises(ValueError):
        websocket.prepare(URL, ["owned"], mission="whk015-owned-ws", owned_lab=True)
    assert not ledger.runs_dir().exists()


@pytest.mark.parametrize("header", ["Connection", "Upgrade", "Content-Length", "Transfer-Encoding", "Sec-WebSocket-Extensions"])
def test_required_headers_cannot_override_protocol_framing(policy, boundaries, header):
    approve(policy)
    document, path = policy
    document["required_headers"][header] = "untrusted"
    (path / "policy.json").write_text(json.dumps(document))
    with pytest.raises(ValueError):
        websocket.prepare(URL, ["owned"], mission="whk015-owned-ws", owned_lab=True)


def test_failed_connect_retains_invalid_partial_receipt(policy, boundaries, monkeypatch):
    plan = prepare(policy)
    def failed(*args, **kwargs):
        raise OSError("owned connect failure")
    monkeypatch.setattr(websocket.socket, "create_connection", failed)
    result = websocket.execute(plan)
    assert result["complete"] is False and result["classification"] == "invalid"
    assert result["write_count"] == 0
    assert ledger.manifest_for(result["run_id"])["classification"] == "invalid"
    with pytest.raises(ValueError):
        websocket.replay_plan(result["run_id"], mission="whk015-owned-ws", owned_lab=True)


def test_capture_cli_dry_run_is_secret_free(policy, boundaries, capsys):
    approve(policy)
    path = policy[1] / "messages.json"
    path.write_text('["owned-private-message"]')
    assert command.main(["capture", URL, "--messages", str(path), "--mission", "whk015-owned-ws", "--owned-lab", "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "owned-private-message" not in output and '"wire_write_cap": 16' in output
    assert not ledger.runs_dir().exists()


@pytest.mark.skipif(os.environ.get("BUGHUNT_WS_INTEGRATION") != "1", reason="opt-in owned WS wire contract")
def test_owned_echo_capture_replay_has_handshake_exchange_and_private_text(policy):
    from websockets.sync.server import serve
    seen = []
    def echo(connection):
        for message in connection:
            seen.append(message)
            connection.send(message)
    with serve(echo, "127.0.0.1", 0, compression=None, ping_interval=None) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"ws://127.0.0.1:{server.socket.getsockname()[1]}/__bughunt_lab__/ws"
        approve(policy, url)
        (policy[1] / "redaction.json").write_text('{"patterns": ["ws-private-value"]}')
        plan = websocket.prepare(url, ["owned", "ws-private-value"], mission="whk015-owned-ws", owned_lab=True)
        first = websocket.execute(plan)
        assert first["classification"] == "observation" and first["complete"]
        exported = ledger.export_run(first["run_id"])
        assert "ws-private-value" not in json.dumps(exported)
        handshake = exchange.read(first["handshake"][1])
        assert handshake["response"]["status"] == 101
        replay = websocket.replay_plan(first["run_id"], mission="whk015-owned-ws", owned_lab=True)
        second = websocket.execute(replay)
        assert second["complete"] and second["source_run_id"] == first["run_id"]
        assert seen == ["owned", "ws-private-value"] * 2
        assert first["write_count"] <= 16 and first["bytes_sent"] <= 65536
        assert second["write_count"] <= 16 and second["bytes_sent"] <= 65536
        (ledger.runs_dir() / first["run_id"] / "transcript.json").write_bytes(b"{}")
        with pytest.raises(ValueError):
            websocket.replay_plan(first["run_id"], mission="whk015-owned-ws", owned_lab=True)
        server.shutdown()
        thread.join(timeout=2)


@pytest.mark.skipif(os.environ.get("BUGHUNT_WS_INTEGRATION") != "1", reason="opt-in unsupported binary contract")
def test_binary_server_message_remains_incomplete_and_not_exported(policy):
    from websockets.sync.server import serve
    def binary(connection):
        connection.recv(timeout=2)
        connection.send(b"Authorization: Bearer binary-private-value")
    with serve(binary, "127.0.0.1", 0, compression=None, ping_interval=None) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"ws://127.0.0.1:{server.socket.getsockname()[1]}/__bughunt_lab__/ws"
        approve(policy, url)
        plan = websocket.prepare(url, ["owned"], mission="whk015-owned-ws", owned_lab=True)
        result = websocket.execute(plan)
        assert result["classification"] == "invalid" and not result["complete"]
        assert "binary-private-value" not in json.dumps(ledger.export_run(result["run_id"]))
        with pytest.raises(ValueError):
            websocket.replay_plan(result["run_id"], mission="whk015-owned-ws", owned_lab=True)
        server.shutdown()
        thread.join(timeout=2)


@pytest.mark.skipif(os.environ.get("BUGHUNT_WS_INTEGRATION") != "1", reason="opt-in automatic pong revocation contract")
def test_native_automatic_pong_is_blocked_after_policy_revocation(policy):
    from websockets.exceptions import ConnectionClosed
    from websockets.sync.server import serve
    completed = threading.Event()
    state = {"pong_received": None}
    def revoke(connection):
        try:
            connection.recv(timeout=2)
            document, path = policy
            document["permissions"]["active_scan"] = False
            (path / "policy.json").write_text(json.dumps(document))
            pong = connection.ping(b"owned-control")
            state["pong_received"] = pong.wait(timeout=0.3)
        except ConnectionClosed:
            state["pong_received"] = False
        finally:
            completed.set()
    with serve(revoke, "127.0.0.1", 0, compression=None, ping_interval=None) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = f"ws://127.0.0.1:{server.socket.getsockname()[1]}/__bughunt_lab__/ws"
        approve(policy, url)
        plan = websocket.prepare(url, ["owned"], mission="whk015-owned-ws", owned_lab=True)
        result = websocket.execute(plan)
        assert completed.wait(timeout=1)
        assert not result["complete"] and result["write_count"] == 2
        assert state["pong_received"] is False
        server.shutdown()
        thread.join(timeout=2)
