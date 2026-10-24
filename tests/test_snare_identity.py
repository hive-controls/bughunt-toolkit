"""Offline checks for the actor used by Snare's raw outbound request."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json

import pytest

from bughunt.core import egress, identity, ledger
from bughunt.modules import snare
from bughunt.core.workspace import requests_dir
from test_gate import policy


class _ClientSocket:
    def __init__(self):
        self.sent = []

    def sendall(self, payload):
        self.sent.append(payload)


class _BodyReader:
    def read_exact(self, count):
        assert count == 3
        return b"abc"


def _actors():
    identity.create_profile("owner", "owner", ["http://allowed.example"], owned=True)
    identity.set_credential("owner", "cookie", "sid=owner-secret")
    identity.create_profile("lower", "lower_privilege", ["http://allowed.example"], owned=True)
    identity.set_credential("lower", "cookie", "sid=lower-secret")
    identity.create_profile("guest", "anonymous", ["http://allowed.example"], owned=True)


def test_proxy_actor_isolation_reaches_background_thread(policy, monkeypatch):
    _actors()
    outgoing = []
    monkeypatch.setattr(snare, "_fetch_wire", lambda *args: outgoing.append(args[3]) or b"response")
    browser_request = (b"GET / HTTP/1.1\r\nHost: allowed.example\r\nCookie: sid=browser-secret\r\n"
                       b"Authorization: Bearer stale-secret\r\nX-CSRF-Token: stale-csrf\r\n\r\n")
    with ThreadPoolExecutor(max_workers=1) as pool:
        for actor, cookie in (("owner", b"sid=owner-secret"),
                              ("lower", b"sid=lower-secret"), ("guest", b"")):
            identity.use_profile(actor)
            assert pool.submit(snare._fetch, "allowed.example", 80, "http",
                               browser_request, snare.Settings()).result() == b"response"
            head = outgoing[-1].split(b"\r\n\r\n", 1)[0]
            assert b"browser-secret" not in head and b"stale-secret" not in head
            assert b"stale-csrf" not in head
            assert (b"Cookie: " + cookie in head) if cookie else b"Cookie:" not in head
            assert b"X-Researcher: owned-lab" in head


def test_capture_records_actual_sent_request_and_actor(policy, monkeypatch):
    _actors()
    identity.use_profile("owner")
    outgoing = []
    reply = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    def upstream(*args):
        outgoing.append(args[3])
        identity.use_profile("lower")
        return reply
    monkeypatch.setattr(snare, "_fetch_wire", upstream)
    client = _ClientSocket()
    snare._handle_exchange(
        client, _BodyReader(),
        snare._Message("POST /example HTTP/1.1", [("Cookie", "sid=browser-secret"),
                                                  ("Content-Length", "3")]),
        "POST", "http://allowed.example/example", "HTTP/1.1", snare.Settings(max_body=2),
        scheme=None, default_port=None,
    )
    assert client.sent == [reply]
    request_head, separator, request_body = outgoing[0].partition(b"\r\n\r\n")
    assert separator and request_body == b"abc"
    assert b"Cookie: sid=owner-secret" in request_head
    assert b"browser-secret" not in request_head
    assert b"User-Agent: Bughunt-owned-lab" in request_head
    saved_request = next(requests_dir().iterdir()).read_bytes()
    assert saved_request == request_head + separator + b"ab"
    manifests = [json.loads(path.read_text()) for path in ledger.runs_dir().glob("*/manifest.json")]
    manifest = next(record for record in manifests if record["tool"] == "snare")
    assert manifest["actor"] == "owner" and manifest["request"]["truncated"]
    assert (ledger.runs_dir() / manifest["run_id"] / "request.http").read_bytes() == saved_request
    assert "owner-secret" not in json.dumps(ledger.export_run(manifest["run_id"]))


def test_actor_origin_mismatch_blocks_before_raw_socket(policy, monkeypatch):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.use_profile("owner")
    monkeypatch.setattr(snare, "_fetch_wire", lambda *args: pytest.fail("raw socket reached"))
    client = _ClientSocket()
    snare._handle_exchange(
        client, None, snare._Message("GET / HTTP/1.1", []),
        "GET", "http://allowed.example/", "HTTP/1.1", snare.Settings(),
        scheme=None, default_port=None,
    )
    assert client.sent and client.sent[0].startswith(b"HTTP/1.1 403 Actor blocked")
    assert list(requests_dir().glob("*.http")) == []


def test_actor_host_override_blocks_before_raw_socket(policy, monkeypatch):
    _actors()
    identity.use_profile("owner")
    monkeypatch.setattr(snare, "_fetch_wire", lambda *args: pytest.fail("raw socket reached"))
    client = _ClientSocket()
    snare._handle_exchange(
        client, None, snare._Message("GET / HTTP/1.1", [("Host", "other.example")]),
        "GET", "http://allowed.example/", "HTTP/1.1", snare.Settings(),
        scheme=None, default_port=None,
    )
    assert client.sent and client.sent[0].startswith(b"HTTP/1.1 403 Actor blocked")


def test_actor_switch_while_queued_blocks_before_raw_socket(policy, monkeypatch):
    _actors()
    identity.use_profile("owner")
    original_profile = egress.current_profile()

    @contextmanager
    def switched_action(*args):
        identity.use_profile("lower")
        yield original_profile

    monkeypatch.setattr(snare.egress, "action", switched_action)
    monkeypatch.setattr(snare, "_fetch_wire", lambda *args: pytest.fail("raw socket reached"))
    with pytest.raises(identity.IdentityError, match="changed"):
        snare._fetch("allowed.example", 80, "http", b"GET / HTTP/1.1\r\n\r\n", snare.Settings())
