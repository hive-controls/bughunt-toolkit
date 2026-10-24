"""Isolated consumer control-plane compatibility must fail before traffic."""

from email.message import Message
import json
import socket
import threading
from http.server import ThreadingHTTPServer

import pytest

from bughunt.integrations import zap_consumer


def test_public_proxy_configuration_is_verified_not_assert_side_effects(monkeypatch, tmp_path):
    calls = []
    def api(endpoint, **parameters):
        calls.append((endpoint, parameters))
        if endpoint.endswith("getHttpProxyExclusions"):
            return {"getHttpProxyExclusions": []}
        if endpoint.endswith("getHttpProxy"):
            return {"getHttpProxy": {"host": "127.0.0.1", "port": 12345}}
        if endpoint.endswith("isHttpProxyEnabled"):
            return {"isHttpProxyEnabled": True}
        if endpoint.endswith(("isSocksProxyEnabled", "isHttpProxyAuthEnabled", "isUseGlobalHttpState")):
            return {endpoint.rsplit("/", 1)[-1]: False}
        return {"Result": "OK"}
    monkeypatch.setattr(zap_consumer, "api", api)
    state = zap_consumer.configure(12345)
    assert state["enabled"] is True and state["excluded"] == []
    assert state["proxy"]["host"] == "127.0.0.1"
    assert any(endpoint.endswith("setUseGlobalHttpState") and parameters["use"] == "false"
               for endpoint, parameters in calls)


@pytest.mark.parametrize("option", ["isSocksProxyEnabled", "isHttpProxyAuthEnabled", "isUseGlobalHttpState"])
def test_disabled_bypass_controls_require_readback(monkeypatch, option):
    def api(endpoint, **parameters):
        name = endpoint.rsplit("/", 1)[-1]
        if name == "getHttpProxyExclusions":
            return {name: []}
        if name == "getHttpProxy":
            return {name: {"host": "127.0.0.1", "port": 12345}}
        if name == "isHttpProxyEnabled":
            return {name: True}
        if name.startswith("is"):
            return {name: name == option}
        return {"Result": "OK"}
    monkeypatch.setattr(zap_consumer, "api", api)
    with pytest.raises(ValueError):
        zap_consumer.configure(12345)


def test_consumer_proxy_configuration_failure_is_closed(monkeypatch):
    monkeypatch.setattr(zap_consumer, "api", lambda *_arguments, **_parameters: {"Result": "FAIL"})
    with pytest.raises(ValueError):
        zap_consumer.configure(12345)


@pytest.mark.parametrize("version,addons", [
    ("2.18.0", [{"id": "network", "version": "0.30.0"}, {"id": "ascanrules", "version": "84"}]),
    ("2.17.0", [{"id": "network", "version": "0.25.0"}, {"id": "ascanrules", "version": "84"}]),
    ("2.17.0", [{"id": "network", "version": "0.30.0"}, {"id": "ascanrules", "version": "85"}]),
    ("2.17.0", []),
])
def test_consumer_version_or_required_addon_drift_is_rejected(monkeypatch, version, addons):
    def api(endpoint, **parameters):
        return {"version": version} if endpoint.endswith("version") else {"installedAddons": addons}
    monkeypatch.setattr(zap_consumer, "api", api)
    with pytest.raises(ValueError):
        zap_consumer.inventory()


def test_exact_pinned_consumer_inventory_is_accepted(monkeypatch):
    def api(endpoint, **parameters):
        return {"version": "2.17.0"} if endpoint.endswith("version") else {"installedAddons": [
            {"id": "network", "version": "0.30.0"}, {"id": "ascanrules", "version": "84.0.0"}]}
    monkeypatch.setattr(zap_consumer, "api", api)
    assert zap_consumer.inventory()["version"] == "2.17.0"


def test_proxy_request_cap_preserves_evidence_without_unbounded_sidecars(monkeypatch, tmp_path):
    monkeypatch.setattr(zap_consumer, "RPC", tmp_path)
    monkeypatch.setattr(zap_consumer, "SEQUENCE", 499)
    for sequence in range(1, 500):
        (tmp_path / f"{sequence:06d}.denied").write_text("{}", encoding="utf-8")
    errors = []

    class Request:
        command = "GET"
        path = "/owned-lab"
        request_version = "HTTP/1.1"
        headers = Message()
        connection = type("Connection", (), {"settimeout": lambda _self, _seconds: None})()

        def send_error(self, code):
            errors.append(code)

    Request.headers["Transfer-Encoding"] = "chunked"
    request = Request()
    zap_consumer.FileProxy.do_GET(request)
    zap_consumer.FileProxy.do_GET(request)
    overflow = tmp_path / "000500.denied"
    recorded = overflow.read_bytes()
    zap_consumer.FileProxy.do_GET(request)

    assert errors == [503, 503, 503]
    assert len(list(tmp_path.glob("*.denied"))) == 500
    assert overflow.read_bytes() == recorded
    assert (tmp_path / "STOP").exists()
    evidence = json.loads(recorded)
    assert evidence["sequence"] == 501 and evidence["reason"] == "proxy-request-cap"
    assert evidence["prior_denial"]["sequence"] == 500


@pytest.mark.parametrize("raw,status,reason", [
    (b"BREW /owned HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", b"501", "proxy-http-rejected"),
    (b"GET /owned HTTP/1.1 extra\r\nHost: 127.0.0.1\r\n\r\n", b"400", "proxy-http-rejected"),
    (b"GET /owned HTTP/1.1\r\nX-Long: " + b"a" * 65537 + b"\r\n\r\n", b"431", "proxy-http-rejected"),
    (b"POST /owned HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n", b"503", "proxy-method-denied"),
    (b"HEAD /owned HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", b"503", "proxy-method-denied"),
    (b"CONNECT owned:443 HTTP/1.1\r\nHost: owned:443\r\n\r\n", b"503", "proxy-method-denied"),
], ids=["unknown-verb", "bad-first-line", "long-header", "post", "head", "connect"])
def test_unsafe_http_request_is_accounted_and_stops_consumer(monkeypatch, tmp_path, raw, status, reason):
    monkeypatch.setattr(zap_consumer, "RPC", tmp_path)
    monkeypatch.setattr(zap_consumer, "SEQUENCE", 0)
    server = ThreadingHTTPServer(("127.0.0.1", 0), zap_consumer.FileProxy)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with socket.create_connection(server.server_address, timeout=3) as connection:
            connection.sendall(raw)
            connection.shutdown(socket.SHUT_WR)
            response = bytearray()
            while chunk := connection.recv(4096):
                response.extend(chunk)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)

    assert status in bytes(response).split(b"\r\n", 1)[0]
    assert not list(tmp_path.glob("*.req"))
    assert (tmp_path / "STOP").exists()
    evidence = [json.loads(path.read_text(encoding="utf-8")) for path in tmp_path.glob("*.denied")]
    assert len(evidence) == 1 and evidence[0]["sequence"] == 1
    assert evidence[0]["reason"] == reason
