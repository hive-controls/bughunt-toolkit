"""Opt-in owned loopback arrival observations, distinct from local dispatch times."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time

import pytest

from bughunt.core import egress, ledger
from test_gate import policy


pytestmark = pytest.mark.skipif(os.environ.get("BUGHUNT_RUN_DISPATCH_CONSUMER") != "1",
                              reason="Explicit owned dispatch-wire consumer opt-in required")
INTERVAL = 0.2


@pytest.fixture
def owned(policy):
    document, workspace = policy
    arrivals, lock, second_seen = [], threading.Lock(), threading.Event()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                arrivals.append({"path": self.path, "arrival_monotonic": time.monotonic()})
            if self.path == "/second":
                second_seen.set()
            self.send_response(200)
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"owned")
        def log_message(self, *_args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    origin = f"http://127.0.0.1:{server.server_port}"
    document["limits"] = {"requests_per_second": 1 / INTERVAL, "concurrency": 2}
    document["assets"] = [{"id": "owned-wire", "origin": origin, "paths": ["/"],
                            "operations": ["manual"], "methods": ["GET"]}]
    (workspace / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    (workspace / "scope.txt").write_text("127.0.0.1\n", encoding="utf-8")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"origin": origin, "arrivals": arrivals, "second_seen": second_seen}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


def _sync_request(url):
    with egress.client(timeout=3, follow_redirects=False) as client:
        request = client.build_request("GET", url)
        assert client.send(request).content == b"owned"
    return request.extensions["bughunt_run_id"]


async def _async_request(url):
    async with egress.async_client(timeout=3, follow_redirects=False) as client:
        request = client.build_request("GET", url)
        response = await client.send(request)
        assert response.content == b"owned"
    return response.extensions["bughunt_run_id"]


def _delayed_capture(monkeypatch, mode, prepared, release, observations):
    begin = ledger.begin_http
    def delayed(profile, request, operation):
        capture = begin(profile, request, operation)
        if request.url.path == "/first":
            started = time.monotonic()
            prepared.set()
            if mode == "async-tasks":
                time.sleep(INTERVAL * 2)
            else:
                assert release.wait(timeout=5), "Owned preparation release timed out"
            observations["preparation_delay_seconds"] = time.monotonic() - started
        return capture
    monkeypatch.setattr(ledger, "begin_http", delayed)


def _run_workers(owned, mode, prepared, release, observations):
    with ThreadPoolExecutor(max_workers=2) as workers:
        first = workers.submit(_sync_request, owned["origin"] + "/first")
        try:
            assert prepared.wait(timeout=3)
            if mode == "mixed-clients":
                second = asyncio.run(_async_request(owned["origin"] + "/second"))
            else:
                second = workers.submit(_sync_request, owned["origin"] + "/second")
            assert owned["second_seen"].wait(timeout=3)
            time.sleep(0.02)
            observations["preparation_released_monotonic"] = time.monotonic()
        finally:
            release.set()
        return [first.result(timeout=5), second if isinstance(second, str) else second.result(timeout=5)]


@pytest.mark.parametrize("mode", ["sync-workers", "async-tasks", "mixed-clients"])
def test_owned_delayed_preparation_preserves_shared_wire_spacing(owned, monkeypatch, tmp_path, mode):
    expected_root = os.environ.get("BUGHUNT_EXPECT_DISPATCH_ROOT")
    if expected_root:
        assert Path(egress.__file__).resolve().parent.parent == Path(expected_root).resolve()
    prepared, release, observations = threading.Event(), threading.Event(), {}
    _delayed_capture(monkeypatch, mode, prepared, release, observations)
    if mode == "async-tasks":
        async def run():
            return await asyncio.gather(_async_request(owned["origin"] + "/first"),
                                        _async_request(owned["origin"] + "/second"))
        run_ids = asyncio.run(run())
    else:
        run_ids = _run_workers(owned, mode, prepared, release, observations)
    manifests = []
    for run_id in run_ids:
        ledger.export_run(run_id)
        manifests.append(json.loads((ledger.runs_dir() / run_id / "manifest.json").read_text()))
    arrivals = sorted(owned["arrivals"], key=lambda row: row["arrival_monotonic"])
    wire_gap = arrivals[1]["arrival_monotonic"] - arrivals[0]["arrival_monotonic"]
    dispatches = [item.get("dispatch", {}).get("monotonic") for item in manifests]
    completions = [item.get("dispatch", {}).get("completed_monotonic") for item in manifests]
    proof = {"mode": mode, "source": str(Path(egress.__file__).resolve()),
             "configured_interval_seconds": INTERVAL, "wire_request_count": len(arrivals),
             "arrivals": arrivals, "wire_arrival_gap_seconds": wire_gap,
             "local_dispatch_monotonic": dispatches, "local_write_completed_monotonic": completions,
             "run_ids": run_ids,
             "observations": observations,
             "claim": "Owned local transport dispatch and server arrival observations; not remote processing timing"}
    (tmp_path / "dispatch-proof.json").write_text(json.dumps(proof, indent=2), encoding="utf-8")
    print(json.dumps(proof, sort_keys=True))
    assert len(arrivals) == 2 and {row["path"] for row in arrivals} == {"/first", "/second"}
    assert wire_gap >= INTERVAL - 0.02
    assert all(value is not None for value in dispatches)
    assert abs(dispatches[1] - dispatches[0]) >= INTERVAL
    ordered = sorted(zip(dispatches, completions))
    assert ordered[1][0] >= ordered[0][1] + INTERVAL
    assert all(item["classification"] != "invalid" for item in manifests)
    assert egress._budgets[str(egress.workspace_dir().resolve())][0] == 0
