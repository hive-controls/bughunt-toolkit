"""Fixed owned HTTP/1.1 parser and queue laboratory contracts."""

import json
import os
import re
import socket
import threading
import time

import pytest

from bughunt.core import egress, exchange, identity, job, ledger
from bughunt.labs import desync
from bughunt.modules import desync as command
from test_gate import boundaries, policy


FRONT = "http://127.0.0.1:53001/__bughunt_lab__/desync"
BACK = "http://127.0.0.1:53002/__bughunt_lab__/desync"


def approve(policy, front=FRONT, back=BACK):
    document, path = policy
    document["mission"] = desync.MISSION
    document["assets"] = [
        {
            "id": name,
            "origin": url.rsplit("/__bughunt_lab__/", 1)[0],
            "paths": [desync.PATH, "/__bughunt_lab__/marker"],
            "operations": ["active_scan"],
            "methods": ["GET", "POST"],
        }
        for name, url in (("desync-front", front), ("desync-back", back))
    ]
    document["exclusions"] = []
    document["required_headers"] = {}
    (path / "scope.txt").write_text("127.0.0.1\n", encoding="utf-8")
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")


def prepare(policy, front=FRONT, back=BACK, **kwargs):
    approve(policy, front, back)
    return desync.prepare(front, back, mission=desync.MISSION, owned_lab=True, **kwargs)


@pytest.mark.parametrize(
    "front,back,owned,mission,seconds",
    [
        (FRONT.replace("127.0.0.1", "localhost"), BACK, True, desync.MISSION, 10),
        (FRONT.replace("http:", "https:"), BACK, True, desync.MISSION, 10),
        (FRONT + "?x=1", BACK, True, desync.MISSION, 10),
        (FRONT.replace(desync.PATH, "/"), BACK, True, desync.MISSION, 10),
        (FRONT, FRONT, True, desync.MISSION, 10),
        (FRONT, BACK, False, desync.MISSION, 10),
        (FRONT, BACK, True, "another-mission", 10),
        (FRONT, BACK, True, desync.MISSION, 0),
        (FRONT, BACK, True, desync.MISSION, 61),
        (FRONT, BACK, True, desync.MISSION, float("nan")),
    ],
)
def test_unowned_or_unbounded_denies_before_socket(
    policy, monkeypatch, front, back, owned, mission, seconds
):
    approve(policy)
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("socket opened"))
    with pytest.raises(ValueError):
        desync.prepare(front, back, mission=mission, owned_lab=owned, seconds=seconds)
    assert not ledger.runs_dir().exists()


@pytest.mark.parametrize(
    "change",
    [
        "stale",
        "permission",
        "method",
        "excluded",
        "scope",
        "headers",
        "capacity",
        "session",
        "actor",
    ],
)
def test_policy_and_actor_denials_before_socket(
    policy, boundaries, monkeypatch, change
):
    approve(policy)
    document, path = policy
    if change == "stale":
        document["state"] = "stale"
    elif change == "permission":
        document["permissions"]["active_scan"] = False
    elif change == "method":
        document["assets"][1]["methods"] = ["GET"]
    elif change == "excluded":
        document["exclusions"] = [
            {
                "id": "excluded",
                "origin": BACK.rsplit(desync.PATH, 1)[0],
                "paths": [desync.PATH],
            }
        ]
    elif change == "scope":
        (path / "scope.txt").write_text("outside.example\n", encoding="utf-8")
    elif change == "headers":
        document["required_headers"]["X-Lab"] = "value"
    elif change == "capacity":
        document["limits"]["concurrency"] = 1
    elif change == "session":
        (path / "session.txt").write_text("authorization: bearer private\n")
    else:
        identity.create_profile(
            "guest", "anonymous", [FRONT.rsplit(desync.PATH, 1)[0]], owned=True
        )
        identity.use_profile("guest")
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("socket opened"))
    with pytest.raises(ValueError):
        desync.prepare(FRONT, BACK, mission=desync.MISSION, owned_lab=True)
    assert not ledger.runs_dir().exists()


def test_marker_path_requires_explicit_front_and_backend_grants(policy, boundaries):
    document, path = policy
    for denied_side in (0, 1):
        approve(policy)
        document["assets"][denied_side]["paths"] = [desync.PATH]
        (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(ValueError):
            desync.prepare(FRONT, BACK, mission=desync.MISSION, owned_lab=True)


def test_broad_root_only_grants_do_not_authorize_lab(policy, boundaries):
    document, path = policy
    for denied_side in (0, 1):
        approve(policy)
        document["assets"][denied_side]["paths"] = ["/"]
        (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
        with pytest.raises(ValueError):
            desync.prepare(FRONT, BACK, mission=desync.MISSION, owned_lab=True)


def test_generated_fixture_and_independent_parser_views(policy, boundaries):
    plan = prepare(policy)
    cases = desync._cases(plan)
    assert [case.name for case in cases] == [
        "baseline",
        "matched-cl-cl",
        "divergent-cl-te",
    ]
    assert sum(case.embedded_messages for case in cases) == 5
    assert all(len(case.raw) <= desync.WRITE_BYTE_CAP for case in cases)
    front_counts = [
        len(desync._parse_requests(case.raw, case.front_mode)) for case in cases
    ]
    back_counts = [
        len(desync._parse_requests(case.raw, case.backend_mode)) for case in cases
    ]
    assert front_counts == [1, 1, 1] and back_counts == [1, 1, 2]
    assert cases[1].marker_sha256 != cases[2].marker_sha256
    assert cases[2].raw.count(b"GET /__bughunt_lab__/marker?nonce=") == 1


def test_response_observations_must_match_generated_marker(policy, boundaries):
    plan = prepare(policy)
    samples = []
    for case in desync._cases(plan):
        front = desync._parse_requests(case.raw, case.front_mode)
        backend = desync._parse_requests(case.raw, case.backend_mode)
        responses = desync._parse_responses(desync._response(backend, case.name))
        samples.append(
            {
                "name": case.name,
                "front": front,
                "backend": backend,
                "front_responses": [dict(row) for row in responses],
                "client_responses": [dict(row) for row in responses],
                "marker_sha256": case.marker_sha256,
                "threads_joined": True,
            }
        )
    meter = desync._Meter(plan)
    meter.connections = [{"connected": True}] * desync.CONNECTION_CAP
    meter.writes = [{"complete": True}] * desync.WRITE_CAP
    meter.reads = [{"complete": True}] * 12
    assert desync._valid(samples, meter)
    samples[2]["client_responses"][1]["body_sha256"] = "0" * 64
    assert not desync._valid(samples, meter)
    samples[2]["front_responses"][1]["body_sha256"] = "0" * 64
    assert not desync._valid(samples, meter)


class Socket:
    def __init__(self):
        self.writes = []
        self.timeout = None

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.writes.append(data)


def test_physical_send_and_aggregate_caps_account_attempts(policy, boundaries):
    plan = prepare(policy)
    meter = desync._Meter(plan)
    fake = Socket()
    aborted = threading.Event()
    for _ in range(desync.WRITE_CAP):
        meter.send(fake, b"owned", plan.front_url, "test-write", aborted)
    with pytest.raises(egress.PolicyBlocked):
        meter.send(fake, b"extra", plan.front_url, "test-write", aborted)
    assert len(fake.writes) == len(meter.writes) == desync.WRITE_CAP
    assert all(row["complete"] for row in meter.writes)
    assert all(
        ledger.manifest_for(row["run_id"])["representation"]
        == "raw-desync-write-metadata; no HTTP exchange"
        for row in meter.writes
    )
    with pytest.raises(egress.PolicyBlocked):
        desync._Meter(plan).send(
            fake,
            b"x" * (desync.WRITE_BYTE_CAP + 1),
            plan.front_url,
            "test-write",
            aborted,
        )
    large = desync._Meter(plan)
    for _ in range(desync.OUTBOUND_BYTE_CAP // desync.WRITE_BYTE_CAP):
        large.send(
            fake, b"x" * desync.WRITE_BYTE_CAP, plan.front_url, "test-write", aborted
        )
    with pytest.raises(egress.PolicyBlocked):
        large.send(fake, b"x", plan.front_url, "test-write", aborted)
    assert large.outbound_bytes == desync.OUTBOUND_BYTE_CAP


@pytest.mark.parametrize(
    "change", ["stop", "policy", "broad-root", "scope", "actor", "deadline", "session"]
)
def test_revocation_prevents_subsequent_raw_write(policy, boundaries, change):
    plan = prepare(policy)
    plan.budget.activate()
    meter = desync._Meter(plan)
    fake = Socket()
    aborted = threading.Event()
    meter.send(fake, b"first", plan.front_url, "test-write", aborted)
    document, path = policy
    if change == "stop":
        job.cancel(plan.budget.job_id)
    elif change == "policy":
        document["permissions"]["active_scan"] = False
        (path / "policy.json").write_text(json.dumps(document))
    elif change == "broad-root":
        document["assets"][0]["paths"] = ["/"]
        (path / "policy.json").write_text(json.dumps(document))
    elif change == "scope":
        (path / "scope.txt").write_text("outside.example\n")
    elif change == "actor":
        identity.create_profile(
            "guest", "anonymous", [FRONT.rsplit(desync.PATH, 1)[0]], owned=True
        )
        identity.use_profile("guest")
    elif change == "deadline":
        plan.budget.deadline = 0
    else:
        (path / "session.txt").write_text("cookie: private\n")
    with pytest.raises(egress.PolicyBlocked):
        meter.send(fake, b"second", plan.front_url, "test-write", aborted)
    assert fake.writes == [b"first"] and len(meter.writes) == 1


def test_cli_dry_run_has_no_socket_or_private_payload(policy, boundaries, capsys):
    approve(policy)
    assert (
        command.main(
            ["dry-run", FRONT, BACK, "--mission", desync.MISSION, "--owned-lab"]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert (
        '"connection_cap": 6' in output
        and '"generated_embedded_message_cap": 5' in output
    )
    assert "nonce=" not in output and not ledger.runs_dir().exists()


def test_incomplete_probe_parser_view_is_invalid_not_an_exception(policy, boundaries):
    plan = prepare(policy)
    sample = {
        "front": [{}],
        "backend": [{}],
        "client_responses": [{}],
        "front_responses": [{}],
        "threads_joined": True,
    }
    assert desync._valid([dict(sample) for _ in range(3)], desync._Meter(plan)) is False


def test_second_listener_failure_closes_first(policy, boundaries, monkeypatch):
    plan = prepare(policy)

    class Listener:
        closed = False

        def close(self):
            self.closed = True

    first = Listener()
    calls = []

    def listen(port, meter):
        calls.append(port)
        if len(calls) == 2:
            raise OSError("second owned port unavailable")
        return first

    monkeypatch.setattr(desync, "_listener", listen)
    result = desync.execute(plan)
    assert result["classification"] == "invalid" and first.closed


def test_durable_announcement_can_cancel_before_any_socket(policy, monkeypatch):
    plan = prepare(policy)
    seen = []

    def announced(job_id):
        assert (plan.budget.stop_path().parent / "job.json").is_file()
        seen.append(job_id)
        job.cancel(job_id)

    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("socket opened"))
    result = desync.execute(plan, on_start=announced)
    assert seen == [plan.budget.job_id]
    assert result["classification"] == "invalid" and result["connection_count"] == 0


def test_revocation_after_prepare_denies_before_listener(policy, monkeypatch):
    plan = prepare(policy)
    document, path = policy
    document["permissions"]["active_scan"] = False
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("socket opened"))
    result = desync.execute(plan)
    assert result["classification"] == "invalid" and result["connection_count"] == 0
    assert desync.status(plan.budget.job_id)["run_id"] == result["run_id"]


def test_unrelated_local_stream_cannot_be_forwarded(policy, monkeypatch):
    plan = prepare(policy)
    case = desync._cases(plan)[0]
    meter = desync._Meter(plan)

    class Peer:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    injected = case.raw.replace(b"\r\n\r\n", b"\r\nAuthorization: private\r\n\r\n")
    monkeypatch.setattr(desync, "_accept", lambda *args: Peer())
    monkeypatch.setattr(desync, "_receive", lambda *args: injected)
    monkeypatch.setattr(
        meter, "connect", lambda *args: pytest.fail("unowned stream forwarded")
    )
    state = {}
    desync._frontend(object(), case, meter, state, threading.Event())
    assert state["front_error"] == "ValueError" and meter.connections == []


def test_response_read_cap_rejects_excess_bytes(policy, boundaries):
    plan = prepare(policy)
    meter = desync._Meter(plan)

    class Oversized:
        remaining = desync.RESPONSE_BYTE_CAP + 1

        def recv(self, maximum):
            count = min(maximum, self.remaining)
            self.remaining -= count
            return b"x" * count

    with pytest.raises(egress.PolicyBlocked):
        desync._receive(Oversized(), meter, threading.Event(), "client-response")
    assert meter.reads[-1]["size"] == desync.RESPONSE_BYTE_CAP + 1
    assert meter.reads[-1]["complete"] is False


def owned_urls():
    ports = []
    for _ in range(2):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            ports.append(listener.getsockname()[1])
    return [f"http://127.0.0.1:{port}{desync.PATH}" for port in ports]


@pytest.mark.skipif(
    os.environ.get("BUGHUNT_DESYNC_INTEGRATION") != "1",
    reason="opt-in owned front/back wire contract",
)
def test_owned_wire_counts_offsets_private_raw_and_tamper_rejection(policy):
    front, back = owned_urls()
    plan = prepare(policy, front, back)
    started = time.monotonic()
    result = desync.execute(plan)
    assert result["classification"] == "observation" and result["complete"]
    assert time.monotonic() - started < plan.budget.seconds
    assert result["connection_count"] == 6 and result["write_count"] == 12
    assert result["generated_embedded_messages"] == 5
    assert len(result["reads"]) == 12
    assert all(
        row["complete"] and row["size"] <= desync.RESPONSE_BYTE_CAP
        for row in result["reads"]
    )
    assert [len(row["front"]) for row in result["samples"]] == [1, 1, 1]
    assert [len(row["backend"]) for row in result["samples"]] == [1, 1, 2]
    assert [len(row["client_responses"]) for row in result["samples"]] == [1, 1, 2]
    assert result["outbound_bytes_reserved"] <= desync.OUTBOUND_BYTE_CAP
    assert all(row["complete"] for row in result["writes"])
    manifest = ledger.manifest_for(result["run_id"])
    assert (
        manifest["representation"]
        == "private raw desync streams; not normal HTTP exchange"
    )
    assert len(manifest["raw_streams"]) == 3
    with pytest.raises(ValueError):
        exchange.from_run(result["run_id"])
    assert desync.status(plan.budget.job_id)["run_id"] == result["run_id"]
    result_file = policy[1] / "jobs" / plan.budget.job_id / "result.json"
    saved_result = exchange.load_json(result_file.read_bytes())
    exchange._write(result_file, {**saved_result, "write_count": 1})
    with pytest.raises(ValueError):
        desync.status(plan.budget.job_id)
    exchange._write(result_file, saved_result)
    raw = manifest["raw_streams"]["divergent-cl-te"]["request"]
    path = ledger.runs_dir() / result["run_id"] / raw["path"]
    nonce = (
        re.search(rb"marker\?nonce=([0-9a-f]+)", path.read_bytes()).group(1).decode()
    )
    assert nonce not in json.dumps(result)
    assert nonce not in json.dumps(desync.status(plan.budget.job_id))
    assert nonce not in json.dumps(ledger.export_run(result["run_id"]))
    original = dict(raw)
    outside = ledger.runs_dir() / "outside.bin"
    outside.write_bytes(b"unrelated-private-file")
    raw.update(
        path="../outside.bin",
        size=outside.stat().st_size,
        sha256=exchange.digest(outside.read_bytes()),
    )
    exchange._write(ledger.runs_dir() / result["run_id"] / "manifest.json", manifest)
    with pytest.raises(ValueError):
        desync.status(plan.budget.job_id)
    raw.update(original)
    exchange._write(ledger.runs_dir() / result["run_id"] / "manifest.json", manifest)
    path.write_bytes(path.read_bytes() + b"tamper")
    with pytest.raises(ValueError):
        desync.status(plan.budget.job_id)


@pytest.mark.skipif(
    os.environ.get("BUGHUNT_DESYNC_INTEGRATION") != "1",
    reason="opt-in owned cancellation wire contract",
)
def test_owned_cancel_after_first_send_stops_later_writes_and_cleans(
    policy, monkeypatch
):
    front, back = owned_urls()
    plan = prepare(policy, front, back)
    original = desync._Meter.send

    def stop_after_first(self, connection, data, url, role, aborted):
        original(self, connection, data, url, role, aborted)
        if len(self.writes) == 1:
            job.cancel(plan.budget.job_id)

    monkeypatch.setattr(desync._Meter, "send", stop_after_first)
    started = time.monotonic()
    result = desync.execute(plan)
    assert result["classification"] == "invalid" and not result["complete"]
    assert result["write_count"] == 1
    assert all(row["threads_joined"] for row in result["samples"])
    assert plan.budget.stop_path().is_file()
    assert time.monotonic() - started < 2


@pytest.mark.skipif(
    os.environ.get("BUGHUNT_DESYNC_INTEGRATION") != "1",
    reason="opt-in owned CLI wire contract",
)
def test_cli_run_status_and_cancel_use_durable_job(policy, capsys):
    front, back = owned_urls()
    approve(policy, front, back)
    assert (
        command.main(["run", front, back, "--mission", desync.MISSION, "--owned-lab"])
        == 0
    )
    output = capsys.readouterr().out
    job_id = json.loads(output.splitlines()[0])["starting_job_id"]
    assert '"classification": "observation"' in output
    assert (policy[1] / "jobs" / job_id / "job.json").is_file()
    assert command.main(["status", job_id]) == 0
    assert '"complete": true' in capsys.readouterr().out
    assert command.main(["cancel", job_id]) == 0
    assert (policy[1] / "jobs" / job_id / "STOP").is_file()
