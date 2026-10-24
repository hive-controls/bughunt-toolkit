import socket
import threading
import time

import bughunt
from bughunt.core import exchange, ledger
from bughunt.modules import snare
from test_oracle_mod_g5_capture import RawOrigin, lab
from test_native_lab_adapters import assert_artifact_contract


def test_snare_capture_is_finite_and_returns_retained_exchange(
    lab, monkeypatch, capsys
):
    origin = RawOrigin(
        lambda request: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nowned"
    )
    lab.grant(origin.origin)
    ready = threading.Event()
    ports = []
    original = snare._open_socket

    def opened(settings):
        listener = original(settings)
        ports.append(settings.bound_port)
        ready.set()
        return listener

    monkeypatch.setattr(snare, "_open_socket", opened)
    received = []

    def request():
        assert ready.wait(5)
        with socket.create_connection(("127.0.0.1", ports[0]), timeout=2) as client:
            client.sendall(
                f"GET {origin.origin}/owned HTTP/1.1\r\nHost: 127.0.0.1:{origin.port}\r\n\r\n".encode()
            )
            received.append(client.recv(65536))

    sender = threading.Thread(target=request)
    sender.start()
    try:
        result = bughunt.run_module(
            "snare",
            operation="capture",
            options={"port": 0, "seconds": 2, "max_exchanges": 1},
        )
        sender.join(5)
        assert result.status == "success", result.to_dict()
        assert len(origin.requests) == 1 and b"owned" in received[0]
        identifiers = next(
            item for item in result.artifacts if item.kind == "exchanges"
        ).payload["exchange_ids"]
        assert len(identifiers) == 1
        assert (
            exchange.read(identifiers[0])["request"]["url"] == origin.origin + "/owned"
        )
        assert result.evidence
        assert result.metrics["requests_admitted"] == 1
        assert capsys.readouterr().out == ""
    finally:
        origin.close()


def test_snare_preview_and_idle_capture_are_bounded(lab):
    options = {"port": 0, "seconds": 0.1, "max_exchanges": 1}
    preview = bughunt.run_module(
        "snare", operation="capture", options=options, dry_run=True
    )
    assert preview.status == "planned", preview.to_dict()
    assert not ledger.runs_dir().exists()
    started = time.monotonic()
    result = bughunt.run_module("snare", operation="capture", options=options)
    assert time.monotonic() - started < 1
    assert result.status == "success", result.to_dict()
    assert (
        next(item for item in result.artifacts if item.kind == "exchanges").payload[
            "exchange_ids"
        ]
        == []
    )
