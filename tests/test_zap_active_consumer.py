"""Opt-in actual pinned ZAP consumer with independent owned-server wire accounting."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import time
from urllib.parse import parse_qsl, urlsplit

import pytest

from bughunt.core import engine, exchange, job, ledger
from bughunt.integrations import zap_active
from test_gate import seed_policy

pytestmark = pytest.mark.skipif(
    os.environ.get("BUGHUNT_ZAP_ACTIVE_INTEGRATION") != "1",
    reason="opt-in actual network-disabled ZAP active consumer",
)


class Reflection(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.wire.append(self.path)
        value = dict(parse_qsl(urlsplit(self.path).query)).get("q", "owned")
        body = (
            "<!doctype html><html><body><p>" + value + "</p></body></html>"
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def prepare(root, port, monkeypatch, mode):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(root))
    document = seed_policy(root)
    origin = f"http://127.0.0.1:{port}"
    document.update(
        mission=zap_active.MISSION, limits={"requests_per_second": 5, "concurrency": 1}
    )
    document["assets"] = [
        {
            "id": "owned-active",
            "origin": origin,
            "paths": ["/__bughunt_lab__/reflect"],
            "methods": ["GET"],
            "operations": ["passive", "process", "active_scan"],
        }
    ]
    (root / "policy.json").write_text(json.dumps(document))
    (root / "scope.txt").write_text("127.0.0.1\n")
    url = origin + "/__bughunt_lab__/reflect?q=owned"
    request = (
        f"GET /__bughunt_lab__/reflect?q=owned HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
    ).encode()
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nowned"
    )
    record = exchange.raw_record(
        request, response, source_id="owned-consumer-baseline", url=url
    )
    ids = exchange.save(
        [record], source_id="owned-consumer-baseline", source_bytes=request, kind="raw"
    )
    return engine.prepare(
        "zap-owned-active",
        ids[0],
        mission=zap_active.MISSION,
        owned_lab=True,
        technology="Python",
        requests=1 if mode == "cap" else 40,
        seconds=120,
    )


def control(plan, server, root, mode, stopped):
    while not stopped.wait(0.005):
        if not server.wire:
            continue
        if mode == "cancel":
            job.cancel(plan.budget.job_id)
        elif mode == "revocation":
            (root / "policy.json").unlink()
        elif mode == "drift":
            path = plan.budget.stop_path().parent / "input" / "plan.json"
            path.write_bytes(b"changed after first actual request")
        elif mode == "deadline":
            plan.budget.deadline = time.monotonic()
        return


@pytest.mark.parametrize(
    "mode", ["complete", "cap", "cancel", "revocation", "drift", "deadline"]
)
def test_actual_active_consumer_contract(tmp_path, monkeypatch, mode):
    server = ThreadingHTTPServer(("127.0.0.1", 0), Reflection)
    server.wire = []
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    plan = prepare(tmp_path, server.server_port, monkeypatch, mode)
    stopped = threading.Event()
    controller = threading.Thread(
        target=control, args=(plan, server, tmp_path, mode, stopped), daemon=True
    )
    controller.start()
    started = time.monotonic()
    announced = []
    try:
        result = engine.run(
            plan, on_start=lambda job_id: announced.append(job.status(job_id))
        )
    finally:
        stopped.set()
        controller.join(timeout=2)
        server.shutdown()
        server.server_close()
        serving.join(timeout=2)
    assert result["cleanup_confirmed"], result
    assert (
        announced[0]["state"] == "starting"
        and announced[0]["run_id"] == result["run_id"]
    )
    assert job.status(plan.budget.job_id) == result
    assert result["state"] == (
        "success"
        if mode == "complete"
        else "cancelled"
        if mode == "cancel"
        else "partial"
    )
    assert result["admitted_count"] == len(server.wire) <= plan.budget.maximum
    assert len(server.wire) >= 1, (
        result,
        plan.budget.stop_path().parent / "consumer.log",
    )
    if mode == "complete":
        assert result["classification"] == "observation", result
        assert result["attempt_count"] == len(server.wire)
        report = ledger.export_run(result["report_run_id"])
        assert report["manifest"]["classification"] == "hypothesis"
        observations = report["artifacts"]["observations.json"]["value"]["observations"]
        plugin_ids = [item["scanner"]["plugin_id"] for item in observations]
        assert plugin_ids.count(40012) == 1
        # The owned server omits security headers and exposes its Python version banner.
        passive_plugin_ids = {10020, 10021, 10036, 10038}
        assert set(plugin_ids) - {40012} <= passive_plugin_ids
        assert (
            len(observations)
            == report["manifest"]["import_metadata"]["observation_count"]
        )
        assert all(
            item["classification"] == "hypothesis"
            and item["hypothesis_level"] == 1
            and item["confirmed"] is False
            for item in observations
        )
    else:
        assert result["classification"] == "inconclusive", result
        assert len(server.wire) == 1, server.wire
        assert time.monotonic() - started < 120
    for admission in plan.budget.sent:
        assert ledger.manifest_for(admission["run_id"])["finished_at"]
