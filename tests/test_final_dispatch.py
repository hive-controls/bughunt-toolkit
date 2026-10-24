"""Deterministic dispatch controls; callback times are a PROXY for wire arrival."""

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from bughunt.core import egress, job, ledger
from bughunt.integrations import zap_runtime
from bughunt.labs import desync, websocket
from bughunt.modules import dns
from test_gate import boundaries, policy


URL = "https://allowed.example/"


class Clock:
    def __init__(self):
        self.value = 0.0

    def monotonic(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds

    async def asleep(self, seconds):
        self.sleep(seconds)
        await asyncio.sleep(0)


def _clock(policy, monkeypatch):
    document, workspace = policy
    document["limits"]["requests_per_second"] = 2
    (workspace / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    clock = Clock()
    monkeypatch.setattr(egress.clock, "now", clock.monotonic)
    monkeypatch.setattr(egress.clock, "sleep", clock.sleep)
    monkeypatch.setattr(egress.clock, "async_sleep", clock.asleep)
    return clock


def _two_requests(clock, asynchronous):
    starts = []

    def respond(_request):
        starts.append(clock.monotonic())
        return httpx.Response(200, content=b"owned")

    async def run():
        async with (
            egress.async_client(transport=httpx.MockTransport(respond)) as first,
            egress.async_client(transport=httpx.MockTransport(respond)) as second,
        ):
            await first.get(URL)
            await second.get(URL)

    if asynchronous:
        asyncio.run(run())
    else:
        with (
            egress.client(transport=httpx.MockTransport(respond)) as first,
            egress.client(transport=httpx.MockTransport(respond)) as second,
        ):
            first.get(URL)
            second.get(URL)
    return starts


@pytest.mark.parametrize("asynchronous", [False, True])
def test_ledger_preparation_delay_cannot_compress_dispatch_spacing(
    policy, boundaries, monkeypatch, asynchronous
):
    clock = _clock(policy, monkeypatch)
    original = ledger.begin_http
    prepared = []

    def delayed(*args):
        capture = original(*args)
        if not prepared:
            clock.sleep(2.0)
        prepared.append(capture)
        return capture

    monkeypatch.setattr(ledger, "begin_http", delayed)
    starts = _two_requests(clock, asynchronous)
    assert starts[1] - starts[0] >= 0.5
    assert len(prepared) == 2
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0


@pytest.mark.parametrize("asynchronous", [False, True])
def test_verification_preparation_delay_cannot_compress_dispatch_spacing(
    policy, boundaries, monkeypatch, asynchronous
):
    clock = _clock(policy, monkeypatch)
    original = egress._verification_decision
    claims = []

    def delayed(request, profile, *, claim=False):
        result = original(request, profile, claim=claim)
        if claim and not claims:
            clock.sleep(2.0)
        if claim:
            claims.append(True)
        return result

    monkeypatch.setattr(egress, "_verification_decision", delayed)
    starts = _two_requests(clock, asynchronous)
    assert starts[1] - starts[0] >= 0.5
    assert len(claims) == 2


def test_job_admission_delay_precedes_one_shared_dispatch_slot(
    policy, boundaries, monkeypatch
):
    clock = _clock(policy, monkeypatch)
    budget = job.Budget(frozenset({("GET", URL)}), 2, 10)
    admit = budget.admit

    def delayed(request):
        admit(request)
        if len(budget.sent) == 1:
            clock.sleep(2.0)

    monkeypatch.setattr(budget, "admit", delayed)
    starts = []
    inner = httpx.MockTransport(
        lambda _request: starts.append(clock.monotonic()) or httpx.Response(200)
    )
    with egress.client(transport=job.Transport(budget, inner)) as client:
        for _index in range(2):
            request = httpx.Request(
                "GET", URL, extensions={"bughunt_job_guard": budget.check}
            )
            client.send(request)
    assert starts[1] - starts[0] >= 0.5
    assert [row["index"] for row in budget.sent] == [1, 2]
    assert all(row["run_id"] for row in budget.sent)
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0


def test_capped_wrapper_preparation_precedes_dispatch_slot(
    policy, boundaries, monkeypatch
):
    clock = _clock(policy, monkeypatch)
    original = zap_runtime._CappedTransport.prepare_request
    prepared = []

    def delayed(self, request):
        original(self, request)
        if not prepared:
            clock.sleep(2.0)
        prepared.append(True)

    monkeypatch.setattr(zap_runtime._CappedTransport, "prepare_request", delayed)
    starts = []
    inner = httpx.MockTransport(
        lambda _request: starts.append(clock.monotonic()) or httpx.Response(200)
    )
    with egress.client(transport=zap_runtime._CappedTransport(inner, 1024)) as client:
        client.get(URL)
        client.get(URL)
    assert starts[1] - starts[0] >= 0.5


def test_final_dispatch_slot_is_shared_between_sync_and_async_clients(
    policy, boundaries, monkeypatch
):
    clock = _clock(policy, monkeypatch)
    starts = []

    def respond(request):
        starts.append(
            (clock.monotonic(), request.extensions["bughunt_dispatch_monotonic"])
        )
        return httpx.Response(200)

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        client.get(URL)

    async def run():
        async with egress.async_client(
            transport=httpx.MockTransport(respond)
        ) as client:
            await client.get(URL)

    asyncio.run(run())
    assert starts[1][0] - starts[0][0] >= 0.5
    assert all(callback == dispatched for callback, dispatched in starts)


def test_each_redirect_hop_uses_a_new_dispatch_slot(policy, boundaries, monkeypatch):
    clock = _clock(policy, monkeypatch)
    _delay_raw_capture(monkeypatch, clock)
    starts = []

    def respond(request):
        starts.append(clock.monotonic())
        return (
            httpx.Response(302, headers={"Location": "/next"})
            if request.url.path == "/"
            else httpx.Response(200)
        )

    with egress.client(
        transport=httpx.MockTransport(respond), follow_redirects=True
    ) as client:
        assert client.get(URL).status_code == 200
    assert len(starts) == 2 and starts[1] - starts[0] >= 0.5


def test_cancelled_job_while_waiting_for_dispatch_is_not_admitted(
    policy, boundaries, monkeypatch
):
    clock = _clock(policy, monkeypatch)
    starts = []
    inner = httpx.MockTransport(
        lambda _request: starts.append(True) or httpx.Response(200)
    )
    with egress.client(transport=inner) as client:
        client.get(URL)
    budget = job.Budget(frozenset({("GET", URL)}), 1, 10)

    def cancel(seconds):
        clock.sleep(seconds)
        budget.cancelled.set()

    monkeypatch.setattr(egress.clock, "sleep", cancel)
    with egress.client(transport=job.Transport(budget, inner)) as client:
        with pytest.raises(egress.PolicyBlocked, match="cancelled"):
            client.get(URL)
    assert starts == [True] and budget.sent == []
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0


def test_async_task_cancelled_in_final_queue_releases_capacity(
    policy, boundaries, monkeypatch
):
    clock = _clock(policy, monkeypatch)
    starts = []
    inner = httpx.MockTransport(
        lambda _request: starts.append(True) or httpx.Response(200)
    )
    with egress.client(transport=inner) as client:
        client.get(URL)

    async def run():
        waiting = asyncio.Event()

        async def pause(_seconds):
            waiting.set()
            await asyncio.sleep(10)

        monkeypatch.setattr(egress.clock, "async_sleep", pause)
        async with egress.async_client(transport=inner) as client:
            task = asyncio.create_task(client.get(URL))
            await asyncio.wait_for(waiting.wait(), timeout=1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(run())
    assert starts == [True]
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0


def test_actor_change_in_final_queue_blocks_dispatch(policy, boundaries, monkeypatch):
    clock = _clock(policy, monkeypatch)
    starts = []
    inner = httpx.MockTransport(
        lambda _request: starts.append(True) or httpx.Response(200)
    )
    with egress.client(transport=inner) as client:
        client.get(URL)
    signature = egress._actor_signature()
    monkeypatch.setattr(
        egress,
        "_actor_signature",
        lambda: (signature[0], "changed", "changed") if clock.value else signature,
    )
    with egress.client(transport=inner) as client:
        with pytest.raises(egress.PolicyBlocked, match="actor-changed"):
            client.get(URL)
    assert starts == [True]
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0


def test_opaque_async_transport_keeps_inflight_concurrency(policy, boundaries):
    async def run():
        entered, both_entered = [], asyncio.Event()

        async def respond(request):
            entered.append(str(request.url))
            if len(entered) == 2:
                both_entered.set()
            await asyncio.wait_for(both_entered.wait(), timeout=1)
            return httpx.Response(200)

        async with egress.async_client(
            transport=httpx.MockTransport(respond)
        ) as client:
            responses = await asyncio.gather(client.get(URL), client.get(URL))
        assert len(entered) == 2 and all(
            response.status_code == 200 for response in responses
        )

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
def test_policy_revocation_during_capture_preparation_blocks_dispatch(
    policy, boundaries, monkeypatch, asynchronous
):
    document, workspace = policy
    _clock(policy, monkeypatch)
    original = ledger.begin_http

    def revoke(*args):
        capture = original(*args)
        document["state"] = "stale"
        (workspace / "policy.json").write_text(json.dumps(document), encoding="utf-8")
        return capture

    monkeypatch.setattr(ledger, "begin_http", revoke)
    starts = []

    def respond(_request):
        starts.append(True)
        return httpx.Response(200)

    async def run():
        async with egress.async_client(
            transport=httpx.MockTransport(respond)
        ) as client:
            await client.get(URL)

    with pytest.raises(egress.PolicyBlocked):
        if asynchronous:
            asyncio.run(run())
        else:
            with egress.client(transport=httpx.MockTransport(respond)) as client:
                client.get(URL)
    assert starts == []
    assert egress._budgets[str(workspace.resolve())][0] == 0
    manifests = [
        json.loads(path.read_text())
        for path in ledger.runs_dir().glob("*/manifest.json")
    ]
    assert any(item["classification"] == "invalid" for item in manifests)


def _delay_raw_capture(monkeypatch, clock):
    original = ledger.begin
    captures = []

    def delayed(*args, **kwargs):
        capture = original(*args, **kwargs)
        if not captures:
            clock.sleep(2.0)
        captures.append(capture)
        return capture

    monkeypatch.setattr(ledger, "begin", delayed)


class Wire:
    def __init__(self, clock):
        self.clock, self.starts = clock, []

    def settimeout(self, _seconds):
        pass

    def sendall(self, _data, *_args):
        self.starts.append(self.clock.monotonic())


def test_websocket_capture_preparation_precedes_physical_write_slot(
    policy, boundaries, monkeypatch
):
    clock = _clock(policy, monkeypatch)
    _delay_raw_capture(monkeypatch, clock)
    budget = job.Budget(frozenset({("CONNECT", URL)}), 2, 10)
    wire = Wire(clock)
    controlled = websocket._Wire(wire, SimpleNamespace(http_url=URL, budget=budget))
    controlled.sendall(b"owned")
    controlled.sendall(b"owned")
    assert wire.starts[1] - wire.starts[0] >= 0.5
    assert [row["index"] for row in budget.sent] == [1, 2]


def test_desync_capture_preparation_precedes_physical_write_slot(
    policy, boundaries, monkeypatch
):
    clock = _clock(policy, monkeypatch)
    _delay_raw_capture(monkeypatch, clock)
    budget = job.Budget(frozenset({("GET", URL)}), 2, 10)
    meter = desync._Meter(
        SimpleNamespace(profile=egress.current_profile(), budget=budget)
    )
    monkeypatch.setattr(
        meter, "check", lambda _aborted=None: budget.check(httpx.Request("GET", URL))
    )
    wire = Wire(clock)
    for _index in range(2):
        meter.send(wire, b"owned", URL, "owned-proxy", None)
    assert wire.starts[1] - wire.starts[0] >= 0.5
    assert len(meter.writes) == 2
    assert all(row["run_id"] and row["complete"] for row in meter.writes)


def test_dns_secondary_authorization_precedes_each_datagram_slot(
    policy, boundaries, monkeypatch
):
    document, workspace = policy
    resolver = "http://127.0.0.1:5353/"
    document["assets"].append(
        {
            "id": "resolver",
            "origin": resolver.rstrip("/"),
            "paths": ["/"],
            "operations": ["dns"],
            "methods": ["GET"],
        }
    )
    clock = _clock(policy, monkeypatch)
    wire = Wire(clock)
    state = {
        "opened": False,
        "delayed": False,
        "ident": 0,
        "resolver_checks": 0,
        "sent_checks": 0,
    }
    authorize = egress.authorize

    def delayed(target, operation, method="GET"):
        if target == resolver:
            state["resolver_checks"] += 1
        if target == resolver and state["opened"] and not state["delayed"]:
            state["delayed"] = True
            clock.sleep(2.0)
        return authorize(target, operation, method)

    class Datagram:
        def __init__(self, *_args):
            state["opened"] = True

        def settimeout(self, _seconds):
            pass

        def connect(self, address):
            assert address == ("127.0.0.1", 5353)
            assert state["resolver_checks"] > state["sent_checks"]
            self.peer = address

        def send(self, query):
            assert self.peer == ("127.0.0.1", 5353)
            assert state["resolver_checks"] > state["sent_checks"]
            state["sent_checks"] = state["resolver_checks"]
            state["ident"] = int.from_bytes(query[:2], "big")
            wire.starts.append(clock.monotonic())
            return len(query)

        def recv(self, _maximum):
            return b"owned"

        def close(self):
            pass

    monkeypatch.setattr(egress, "authorize", delayed)
    monkeypatch.setattr(dns.socket, "socket", Datagram)
    monkeypatch.setattr(dns, "RECORD_TYPES", [("A", 1), ("AAAA", 28), ("CNAME", 5)])
    monkeypatch.setattr(
        dns,
        "parse_message",
        lambda _data: SimpleNamespace(
            ident=state["ident"], flags=0, answers=[], authorities=[], additionals=[]
        ),
    )
    dns.lookup("allowed.example", "127.0.0.1", 5353, 1)
    assert len(wire.starts) == 3
    assert wire.starts[1] - wire.starts[0] >= 0.5
