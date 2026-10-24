"""PROXY fault controls for the pinned native header-write trace contract."""

import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest

from bughunt.core import egress, job, ledger
from test_final_dispatch import URL, _clock
from test_gate import boundaries, policy


START = "http11.send_request_headers.started"
COMPLETE = "http11.send_request_headers.complete"


def _native(monkeypatch, callback, *, asynchronous=False, proxy=None):
    transport = (httpx.AsyncHTTPTransport(proxy=proxy, trust_env=False) if asynchronous else
                 httpx.HTTPTransport(proxy=proxy, trust_env=False))
    monkeypatch.setattr(transport, "handle_async_request" if asynchronous else "handle_request", callback)
    return transport


def _core(request, method=None):
    return SimpleNamespace(method=method or request.method.encode("ascii"), extensions=request.extensions)


def _headers(request, callback=lambda: None, *, method=None):
    trace = request.extensions["trace"]
    trace(START, {"request": _core(request, method)})
    callback()
    trace(COMPLETE, {"return_value": None})


@pytest.mark.parametrize("asynchronous", [False, True])
def test_native_connection_preparation_is_before_write_pacing(policy, boundaries, monkeypatch, asynchronous):
    clock = _clock(policy, monkeypatch)
    starts, arrivals = [], []
    def respond(request):
        if not arrivals:
            clock.sleep(2)
        arrivals.append(True)
        _headers(request, lambda: starts.append(clock.monotonic()))
        return httpx.Response(200)
    async def arespond(request):
        if not arrivals:
            clock.sleep(2)
        arrivals.append(True)
        await request.extensions["trace"](START, {"request": _core(request)})
        starts.append(clock.monotonic())
        await request.extensions["trace"](COMPLETE, {"return_value": None})
        return httpx.Response(200)
    transport = _native(monkeypatch, arespond if asynchronous else respond, asynchronous=asynchronous)
    async def run():
        async with egress.async_client(transport=transport) as client:
            await client.get(URL)
            await client.get(URL)
    if asynchronous:
        asyncio.run(run())
    else:
        with egress.client(transport=transport) as client:
            client.get(URL)
            client.get(URL)
    assert starts[1] - starts[0] >= 0.5


@pytest.mark.parametrize("asynchronous", [False, True])
def test_tightened_rate_applies_to_gap_after_previous_write(policy, boundaries, monkeypatch, asynchronous):
    document, workspace = policy
    clock = _clock(policy, monkeypatch)
    starts = []
    def respond(request):
        _headers(request, lambda: starts.append(clock.monotonic()))
        return httpx.Response(200)
    async def arespond(request):
        await request.extensions["trace"](START, {"request": _core(request)})
        starts.append(clock.monotonic())
        await request.extensions["trace"](COMPLETE, {"return_value": None})
        return httpx.Response(200)
    def tighten():
        document["limits"]["requests_per_second"] = 1
        (workspace / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    transport = _native(monkeypatch, arespond if asynchronous else respond, asynchronous=asynchronous)
    async def run():
        async with egress.async_client(transport=transport) as client:
            await client.get(URL)
            tighten()
            await client.get(URL)
    if asynchronous:
        asyncio.run(run())
    else:
        with egress.client(transport=transport) as client:
            client.get(URL)
            tighten()
            client.get(URL)
    assert starts[1] - starts[0] >= 1.0


def test_user_trace_delay_precedes_slot_and_is_restored(policy, boundaries, monkeypatch):
    clock = _clock(policy, monkeypatch)
    starts, prior_calls = [], []
    def prior(event, _info):
        if event == START and not prior_calls:
            clock.sleep(2)
        prior_calls.append(event)
    def respond(request):
        _headers(request, lambda: starts.append(clock.monotonic()))
        return httpx.Response(200)
    transport = _native(monkeypatch, respond)
    with egress.client(transport=transport) as client:
        requests = [client.build_request("GET", URL, extensions={"trace": prior}) for _index in range(2)]
        for request in requests:
            client.send(request)
    assert starts[1] - starts[0] >= 0.5 and len(prior_calls) == 4
    assert all(request.extensions["trace"] is prior for request in requests)


def test_native_header_failure_releases_lease_and_capacity(policy, boundaries, monkeypatch):
    _clock(policy, monkeypatch)
    def fail(request):
        request.extensions["trace"](START, {"request": _core(request)})
        raise httpx.ConnectError("owned write failure")
    with egress.client(transport=_native(monkeypatch, fail)) as client:
        with pytest.raises(httpx.ConnectError):
            client.get(URL)
    key = str(egress.workspace_dir().resolve())
    assert not egress._dispatch_locks[key].locked() and egress._budgets[key][0] == 0
    manifests = [json.loads(path.read_text()) for path in ledger.runs_dir().glob("*/manifest.json")]
    assert len(manifests) == 1 and manifests[0]["classification"] == "invalid"


def test_failed_connection_is_charged_once_before_native_send(policy, boundaries, monkeypatch):
    _clock(policy, monkeypatch)
    budget = job.Budget(frozenset({("GET", URL)}), 1, 10)
    attempts = []
    def fail(_request):
        attempts.append(True)
        raise httpx.ConnectError("owned connect failure before header trace")
    with egress.client(transport=job.Transport(budget, _native(monkeypatch, fail))) as client:
        with pytest.raises(httpx.ConnectError):
            client.get(URL)
        with pytest.raises(egress.PolicyBlocked, match="request-cap"):
            client.get(URL)
    assert attempts == [True] and len(budget.sent) == 1
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0


@pytest.mark.parametrize("fault", ["version", "retries", "uds", "proxy"])
def test_native_layout_drift_blocks_before_connection(policy, boundaries, monkeypatch, fault):
    _clock(policy, monkeypatch)
    attempts = []
    transport = _native(monkeypatch, lambda _request: attempts.append(True),
                        proxy="http://outside.example:8080" if fault == "proxy" else None)
    if fault == "version":
        monkeypatch.setattr(egress.httpcore, "__version__", "unsupported")
    elif fault == "retries":
        transport._pool._retries = 1
    elif fault == "uds":
        transport._pool._uds = "owned.socket"
    with egress.client(transport=transport) as client:
        with pytest.raises(egress.PolicyBlocked):
            client.get(URL)
    assert attempts == []
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0


@pytest.mark.parametrize("proxy", ["http://proxy.example:8080", "http://proxy.example"])
def test_manual_proxy_connect_and_origin_headers_share_write_clock(policy, boundaries, monkeypatch, proxy):
    if proxy == "http://proxy.example":
        document, _workspace = policy
        document["assets"].append({"id": "default-proxy", "origin": proxy, "paths": ["/"],
                                    "operations": ["manual"], "methods": ["GET"]})
    clock = _clock(policy, monkeypatch)
    starts = []
    def respond(request):
        _headers(request, lambda: starts.append(clock.monotonic()), method=b"CONNECT")
        _headers(request, lambda: starts.append(clock.monotonic()))
        return httpx.Response(200)
    transport = _native(monkeypatch, respond, proxy=proxy)
    with egress.client(transport=transport) as client:
        response = client.get(URL)
    assert starts[1] - starts[0] >= 0.5
    manifest = json.loads((ledger.runs_dir() / response.extensions["bughunt_run_id"] / "manifest.json").read_text())
    assert len(manifest["protocol_dispatches"]) == 1 and "dispatch" in manifest


def test_managed_https_proxy_is_unavailable_before_connection(policy, boundaries, monkeypatch):
    _clock(policy, monkeypatch)
    budget = job.Budget(frozenset({("GET", URL)}), 1, 10)
    attempts = []
    native = _native(monkeypatch, lambda _request: attempts.append(True), proxy="http://proxy.example:8080")
    with egress.client(transport=job.Transport(budget, native)) as client:
        with pytest.raises(egress.PolicyBlocked, match="managed-proxy-connect"):
            client.get(URL)
    assert attempts == [] and budget.sent == []


def test_managed_proxy_mounts_cannot_bypass_budget_transport(policy, boundaries):
    budget = job.Budget(frozenset({("GET", URL)}), 1, 10)
    with pytest.raises(egress.PolicyBlocked, match="managed-transport-proxy"):
        egress.client(transport=job.Transport(budget), proxy="http://proxy.example:8080")


def test_native_response_without_header_trace_is_not_accepted(policy, boundaries, monkeypatch):
    _clock(policy, monkeypatch)
    transport = _native(monkeypatch, lambda _request: httpx.Response(200))
    with egress.client(transport=transport) as client:
        with pytest.raises(egress.PolicyBlocked, match="not-observed"):
            client.get(URL)
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0


def test_native_trace_cannot_rebind_to_another_run(policy, boundaries, monkeypatch):
    _clock(policy, monkeypatch)
    writes = []
    def respond(request):
        request.extensions["trace"](START, {"request": SimpleNamespace(method=b"GET", extensions={})})
        writes.append(True)
        return httpx.Response(200)
    with egress.client(transport=_native(monkeypatch, respond)) as client:
        with pytest.raises(egress.PolicyBlocked, match="request-mismatch"):
            client.get(URL)
    assert writes == []


def test_native_redirect_does_not_reuse_prior_gate_trace(policy, boundaries, monkeypatch):
    _clock(policy, monkeypatch)
    requests = []
    def respond(request):
        requests.append(request)
        _headers(request)
        return httpx.Response(302, headers={"Location": "/next"}) if len(requests) == 1 else httpx.Response(200)
    with egress.client(transport=_native(monkeypatch, respond), follow_redirects=True) as client:
        assert client.get(URL).status_code == 200
    assert len(requests) == 2 and all("trace" not in request.extensions for request in requests)


def test_http2_header_trace_contract_uses_same_lease_without_claiming_wire_acceptance(policy, boundaries, monkeypatch):
    clock = _clock(policy, monkeypatch)
    starts = []
    def respond(request):
        trace = request.extensions["trace"]
        trace("http2.send_request_headers.started", {"request": _core(request)})
        starts.append(clock.monotonic())
        trace("http2.send_request_headers.complete", {"return_value": None})
        return httpx.Response(200)
    with egress.client(transport=_native(monkeypatch, respond)) as client:
        client.get(URL)
        client.get(URL)
    assert starts[1] - starts[0] >= 0.5


def test_async_native_header_cancellation_releases_write_lease(policy, boundaries, monkeypatch):
    _clock(policy, monkeypatch)
    async def run():
        writing = asyncio.Event()
        async def respond(request):
            await request.extensions["trace"](START, {"request": _core(request)})
            writing.set()
            await asyncio.sleep(10)
        transport = _native(monkeypatch, respond, asynchronous=True)
        async with egress.async_client(transport=transport) as client:
            task = asyncio.create_task(client.get(URL))
            await asyncio.wait_for(writing.wait(), timeout=1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    asyncio.run(run())
    key = str(egress.workspace_dir().resolve())
    assert not egress._dispatch_locks[key].locked() and egress._budgets[key][0] == 0
