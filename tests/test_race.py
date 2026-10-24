"""Dedicated whk014-owned-race safety/load laboratory; no external targets."""

import json
import os
import socketserver
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from bughunt.core import egress, exchange, job, ledger
from bughunt.labs import race
from bughunt.modules import MODULES, race as command
from test_gate import boundaries, policy

URL = "http://127.0.0.1:8080/__bughunt_lab__/race"


def approve(policy, url=URL):
    document, path = policy
    document["mission"] = "whk014-owned-race"
    origin = url.rsplit("/__bughunt_lab__/", 1)[0]
    document["assets"] = [row for row in document["assets"] if row["id"] != "race-lab"]
    document["assets"].append(
        {
            "id": "race-lab",
            "origin": origin,
            "paths": ["/__bughunt_lab__/"],
            "operations": ["active_scan"],
            "methods": ["GET", "POST", "HEAD"],
        }
    )
    (path / "scope.txt").write_text("127.0.0.1\n")
    (path / "policy.json").write_text(json.dumps(document))


def source(url=URL, method="GET"):
    host = httpx.URL(url).netloc
    raw = (
        method.encode()
        + b" "
        + url.encode()
        + b" HTTP/1.1\r\nHost: "
        + host
        + b"\r\nAuthorization: Bearer captured-secret\r\n\r\n"
    )
    return exchange.raw_record(raw, None, source_id="owned-race-source")


def prepare(policy, **kwargs):
    approve(policy)
    return race.prepare(source(), mission="whk014-owned-race", owned_lab=True, **kwargs)


def test_four_attempts_two_workers_linked_evidence_observation_only(policy, boundaries):
    plan = prepare(policy)
    lock = threading.Lock()
    state = {"active": 0, "peak": 0, "count": 0}
    rendezvous = threading.Barrier(2)

    def respond(request):
        assert "captured-secret" not in str(request.headers)
        with lock:
            state["count"] += 1
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
            is_probe_call = state["count"] in (2, 3)
        if is_probe_call:
            # Calls 1 and 4 are the serial controls; calls 2-3 are the two concurrent probes. A barrier
            # (not a wall-clock sleep) makes them meet; a broken barrier leaves peak == 1 and fails below.
            # The 5s cap is a hang guard, not a success margin: on a correct run both probes meet in
            # microseconds; it only elapses on an actual serialization regression (which then fails on
            # peak != 2), with headroom for a slow 2-vCPU CI runner not to false-RED.
            try:
                rendezvous.wait(timeout=5)
            except threading.BrokenBarrierError:
                pass
        with lock:
            state["active"] -= 1
        return httpx.Response(200, stream=httpx.ByteStream(b"owned"))

    result = race.execute(plan, transport_factory=lambda: httpx.MockTransport(respond))
    assert result["classification"] == "observation"
    assert state["count"] == len(result["requests"]) == 4 and state["peak"] == 2
    assert [row["role"] for row in result["samples"]] == [
        "control-before",
        "probe",
        "probe",
        "control-after",
    ]
    assert result["cleanup"] == "pending"
    for row in result["requests"]:
        assert ledger.manifest_for(row["run_id"])["tool"] == "race"
        assert row["admitted_monotonic"] > 0
    assert "captured-secret" not in json.dumps(ledger.export_run(result["run_id"]))


@pytest.mark.parametrize(
    "url,owned,mission",
    [
        ("https://allowed.example/__bughunt_lab__/race", True, "whk014-owned-race"),
        (URL.replace("127.0.0.1", "localhost"), True, "whk014-owned-race"),
        (URL.replace("/__bughunt_lab__/", "/"), True, "whk014-owned-race"),
        (URL, False, "whk014-owned-race"),
        (URL, True, "wrong"),
    ],
)
def test_unowned_external_or_ambiguous_targets_block(
    policy, boundaries, url, owned, mission
):
    approve(policy)
    with pytest.raises(ValueError):
        race.prepare(source(url), mission=mission, owned_lab=owned)
    assert not ledger.runs_dir().exists()


@pytest.mark.parametrize(
    "change", ["stale", "permission", "scope", "concurrency", "excluded"]
)
def test_lab_policy_denials_make_zero_physical_sends(policy, boundaries, change):
    approve(policy)
    document, path = policy
    if change == "scope":
        (path / "scope.txt").write_text("outside.example\n")
    else:
        if change == "stale":
            document["state"] = "stale"
        elif change == "permission":
            document["permissions"]["active_scan"] = False
        elif change == "concurrency":
            document["limits"]["concurrency"] = 1
        else:
            document["exclusions"] = [
                {"id": "no-race", "origin": "http://127.0.0.1:8080", "paths": ["/"]}
            ]
        (path / "policy.json").write_text(json.dumps(document))
    with pytest.raises(ValueError):
        race.prepare(source(), mission="whk014-owned-race", owned_lab=True)
    assert not ledger.runs_dir().exists()


@pytest.mark.parametrize("seconds", [0, True, 11, float("nan")])
def test_load_bound_rejection(policy, boundaries, seconds):
    with pytest.raises(ValueError):
        prepare(policy, seconds=seconds)


def test_stop_marker_stops_after_control_no_burst(policy, boundaries):
    plan = prepare(policy)

    def respond(request):
        job.cancel(plan.budget.job_id)
        return httpx.Response(200, stream=httpx.ByteStream(b"owned"))

    result = race.execute(plan, transport_factory=lambda: httpx.MockTransport(respond))
    assert result["classification"] == "invalid"
    assert len(result["requests"]) == 1
    assert plan.budget.stop_path().read_bytes() == b"stop\n"


def test_failed_control_and_oversized_read_stop_later_attempts(policy, boundaries):
    for mode in ["failure", "large"]:
        plan = prepare(policy, max_bytes=1)

        def respond(request):
            if mode == "failure":
                raise httpx.ConnectError("owned failure", request=request)
            return httpx.Response(200, stream=httpx.ByteStream(b"large"))

        result = race.execute(
            plan, transport_factory=lambda: httpx.MockTransport(respond)
        )
        assert result["classification"] == "invalid" and len(result["requests"]) == 1


def test_registered_cli_dry_run_no_side_effects(policy, boundaries, capsys):
    approve(policy)
    value = source()
    exchange.save([value], source_id="owned-cli", source_bytes=b"owned", kind="raw")
    assert "race" in MODULES
    assert (
        command.main(
            [
                "run",
                value["exchange_id"],
                "--mission",
                "whk014-owned-race",
                "--owned-lab",
                "--dry-run",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert "captured-secret" not in output and '"request_cap": 4' in output
    assert not ledger.runs_dir().exists() and not (policy[1] / "jobs").exists()


def test_scope_removed_after_prepare_blocks_all_sends(policy, boundaries):
    plan = prepare(policy)
    (policy[1] / "scope.txt").write_text("outside.example\n")
    seen = []
    result = race.execute(
        plan,
        transport_factory=lambda: httpx.MockTransport(
            lambda request: seen.append(request)
        ),
    )
    assert result["classification"] == "invalid" and result["requests"] == seen == []


@contextmanager
def _owned_wire_receiver(policy, *, rendezvous_timeout=5):
    lock = threading.Lock()
    state = {"count": 0, "probes_met": 0}
    probe_entered = threading.Event()
    rendezvous = threading.Barrier(2)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                state["count"] += 1
                is_probe = state["count"] in (2, 3)
            if is_probe:
                probe_entered.set()
                try:
                    rendezvous.wait(timeout=rendezvous_timeout)
                except threading.BrokenBarrierError:
                    pass
                else:
                    with lock:
                        state["probes_met"] += 1
            self.send_response(200)
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"owned")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/__bughunt_lab__/race"
        approve(policy, url)
        yield url, state, probe_entered
    finally:
        rendezvous.abort()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def _assert_wire_overlap(state):
    assert state["count"] == 4
    assert state["probes_met"] == 2, "Probe requests did not overlap at the receiver"


@pytest.mark.skipif(
    os.environ.get("BUGHUNT_RACE_INTEGRATION") != "1",
    reason="opt-in owned loopback wire contract",
)
@pytest.mark.parametrize("delayed_probe", [False, True])
@pytest.mark.parametrize("delayed_epilogue", [False, True])
def test_owned_loopback_wire_contract(
    policy, monkeypatch, delayed_probe, delayed_epilogue
):
    release_epilogue = threading.Event()
    original_write = socketserver._SocketWriter.write

    def hold_after_body(writer, data):
        written = original_write(writer, data)
        if data == b"owned":
            release_epilogue.wait(timeout=10)
        return written

    if delayed_epilogue:
        monkeypatch.setattr(socketserver._SocketWriter, "write", hold_after_body)
    with _owned_wire_receiver(policy) as (url, state, probe_entered):
        lock = threading.Lock()
        factory_calls = 0

        def transport_factory():
            nonlocal factory_calls
            with lock:
                factory_calls += 1
                call = factory_calls
            if delayed_probe and call == 3:
                assert probe_entered.wait(timeout=2)
                time.sleep(0.2)
            return None

        plan = race.prepare(source(url), mission="whk014-owned-race", owned_lab=True)
        try:
            result = race.execute(plan, transport_factory=transport_factory)
            assert result["classification"] == "observation"
            assert len(result["requests"]) == 4
            _assert_wire_overlap(state)
            for row in result["requests"]:
                assert exchange.from_run(row["run_id"])["response"]["body_size"] == 5
        finally:
            release_epilogue.set()


@pytest.mark.skipif(
    os.environ.get("BUGHUNT_RACE_INTEGRATION") != "1",
    reason="opt-in owned loopback wire contract",
)
def test_owned_loopback_overlap_oracle_rejects_serial_requests(policy):
    with _owned_wire_receiver(policy, rendezvous_timeout=0.2) as (url, state, _entered):
        with egress.client(operation="active_scan") as client:
            for _ in range(4):
                assert client.get(url).content == b"owned"
        assert state["count"] == 4
        with pytest.raises(AssertionError, match="did not overlap"):
            _assert_wire_overlap(state)
