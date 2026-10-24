"""Ledger writes on the async egress path run off the event loop, awaited, in order (PR-B)."""

import asyncio
import json
import threading
import time

from bughunt.core import ledger, scanner
from scanner_oracle_support import grant, lab, workspace  # noqa: F401  (fixtures)


def _scan_coroutine(lab, paths, concurrency=4, connect_timeout=0.5):
    return scanner.scan_host(
        target="127.0.0.1", ports=[lab.port], connect_timeout=connect_timeout, http_timeout=5.0,
        concurrency=concurrency, paths=paths, follow_redirects=False, try_http=True, try_https=False,
        verify_tls=True, user_agents=[], rotate_agent=False, host_header=None, custom_headers={},
        collect_certs=False, keep_body=False, max_body=1024, delay_lo=0, delay_hi=0, proxy=None, sink=None,
        status_allow=None, grep=None, skip_tcp=True, method="GET", retries=0, auth=None)


def _scan(lab, paths, **kwargs):
    return asyncio.run(_scan_coroutine(lab, paths, **kwargs))


def _paths(count=24):
    return [f"/p{index}" for index in range(count)]


def test_slow_ledger_write_cannot_lose_a_request(lab, monkeypatch):
    real, calls, lock = ledger._write_private, [0], threading.Lock()

    def slow(path, data):
        with lock:
            calls[0] += 1
            stall = 9 <= calls[0] <= 20
        if stall:
            time.sleep(0.7)
        real(path, data)

    monkeypatch.setattr(ledger, "_write_private", slow)
    paths = _paths()
    _scan(lab, paths)
    assert calls[0] > 20
    assert sorted(set(lab.server.paths())) == sorted(paths)


def test_ledger_writes_run_on_a_non_loop_thread(lab, monkeypatch):
    real, loop_thread, seen = ledger._write_private, [], []

    def record(path, data):
        seen.append(threading.get_ident())
        real(path, data)

    async def run():
        loop_thread.append(threading.get_ident())
        return await _scan_coroutine(lab, _paths(6), connect_timeout=1.0)

    monkeypatch.setattr(ledger, "_write_private", record)
    asyncio.run(run())
    assert seen and loop_thread[0] not in seen


def test_worker_thread_sees_current_tool_and_workspace(lab, monkeypatch):
    observed = []
    real_begin = ledger.begin

    def spy(*args, **kwargs):
        observed.append((kwargs["tool"], ledger.runs_dir()))
        return real_begin(*args, **kwargs)

    monkeypatch.setattr(ledger, "begin", spy)

    async def run():
        token = ledger.CURRENT_TOOL.set("offload-probe")
        try:
            return await _scan_coroutine(lab, _paths(4), connect_timeout=1.0)
        finally:
            ledger.CURRENT_TOOL.reset(token)

    asyncio.run(run())
    assert observed and all(tool == "offload-probe" for tool, _ in observed)
    assert all(root == lab.workspace / "runs" for _, root in observed)


def test_every_request_has_a_finished_ordered_ledger_run(lab):
    _scan(lab, _paths(), connect_timeout=1.0)
    runs = [path for path in (lab.workspace / "runs").iterdir() if path.is_dir()]
    assert len(runs) == len(lab.server.requests) > 0
    for run in runs:
        manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["classification"] != "in_progress"
        assert manifest["finished_at"] and manifest["started_at"] <= manifest["finished_at"]


def test_finish_is_durable_before_the_response_returns(lab, monkeypatch):
    from bughunt.core import egress
    real = ledger._write_private

    def slow_final(path, data):
        if path.name == "response.http":
            time.sleep(0.3)
        real(path, data)

    monkeypatch.setattr(ledger, "_write_private", slow_final)

    # finish must be complete when the awaited request returns, not merely scheduled
    async def one():
        async with egress.async_client() as client:
            response = await client.get(lab.base("/"))
            run_dir = lab.workspace / "runs" / response.extensions["bughunt_run_id"]
            return json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))

    manifest = asyncio.run(one())
    assert manifest["classification"] != "in_progress" and manifest["finished_at"]


def _cancel_begin(lab, monkeypatch, cancels):
    from bughunt.core import egress
    real = ledger._write_private

    def slow(path, data):
        time.sleep(0.4)
        real(path, data)

    monkeypatch.setattr(ledger, "_write_private", slow)

    async def one():
        async def request():
            async with egress.async_client() as client:
                await client.get(lab.base("/cancelled"))
        task = asyncio.ensure_future(request())
        await asyncio.sleep(0.15)  # begin's worker is in flight (first write sleeping)
        for _ in range(cancels):
            task.cancel()
            await asyncio.sleep(0.05)
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(one())  # shutdown joins the worker, so the disk state below is final
    manifests = [json.loads(path.read_text(encoding="utf-8"))
                 for path in (lab.workspace / "runs").glob("*/manifest.json")]
    assert manifests, "begin never ran; the test would be vacuous"
    assert all(item["classification"] != "in_progress" for item in manifests)
    assert lab.server.requests == []


def test_single_cancel_mid_begin_leaves_no_in_progress_run(lab, monkeypatch):
    _cancel_begin(lab, monkeypatch, 1)


def test_double_cancel_mid_begin_leaves_no_in_progress_run(lab, monkeypatch):
    _cancel_begin(lab, monkeypatch, 2)
