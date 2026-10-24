import pytest

from bughunt.core.pipeline_budget import Governor, bind, current
from test_gate import policy
from test_dispatch_wire import owned


def limits(**changes):
    return {
        "requests": 2,
        "seconds": 60,
        "requests_per_second": 100,
        "bytes": 1000,
        "concurrency": 1,
        **changes,
    }


def test_shared_governor_never_resets_request_count_between_steps(monkeypatch):
    governor = Governor(
        {
            "requests": 2,
            "seconds": 60,
            "requests_per_second": 10,
            "bytes": 1000,
            "concurrency": 1,
        }
    )
    monkeypatch.setattr(governor, "check", lambda: None)
    with bind(governor):
        current().admit("http://localhost/", "manual", "GET")
        current().admit("http://localhost/", "manual", "GET")
        with pytest.raises(ValueError):
            current().admit("http://localhost/", "manual", "GET")
    assert governor.requests_admitted == 2


def test_context_reaches_worker_threads_in_same_workspace(monkeypatch, tmp_path):
    import concurrent.futures

    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    governor = Governor(
        {
            "requests": 2,
            "seconds": 60,
            "requests_per_second": 10,
            "bytes": 1000,
            "concurrency": 1,
        }
    )
    with bind(governor):
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            assert executor.submit(current).result() is governor


def test_http_final_dispatch_consumes_one_shared_cap(policy):
    import httpx
    from bughunt.core import egress

    seen = []
    transport = httpx.MockTransport(
        lambda request: (
            seen.append(str(request.url)) or httpx.Response(200, content=b"owned")
        )
    )
    governor = Governor(limits(), mission="owned-lab")
    with bind(governor), egress.client(transport=transport) as client:
        for _ in range(2):
            assert client.get("https://allowed.example/").status_code == 200
        with pytest.raises(egress.PolicyBlocked, match="pipeline-request-cap"):
            client.get("https://allowed.example/")
    assert len(seen) == governor.requests_admitted == 2


def test_raw_dispatch_counts_but_setup_pacing_does_not(policy):
    from bughunt.core import egress

    governor = Governor(limits(requests=1), mission="owned-lab")
    seen = []
    with bind(governor):
        egress.pace("https://allowed.example/", "manual")
        assert governor.requests_admitted == 0
        egress.dispatch(
            "https://allowed.example/", "manual", "GET", lambda: seen.append("owned")
        )
        with pytest.raises(egress.PolicyBlocked, match="pipeline-request-cap"):
            egress.dispatch(
                "https://allowed.example/",
                "manual",
                "GET",
                lambda: seen.append("extra"),
            )
    assert seen == ["owned"] and governor.requests_admitted == 1


def test_native_job_poll_observes_chain_cancellation_before_transport(policy):
    import httpx
    from bughunt.core import egress, job

    governor = Governor(limits(), mission="owned-lab")
    with bind(governor):
        budget = job.Budget(frozenset({("GET", "https://allowed.example/")}), 2, 60)
        governor.cancelled.set()
        with pytest.raises(egress.PolicyBlocked, match="pipeline-cancelled"):
            budget.check(httpx.Request("GET", "https://allowed.example/"))


def test_native_job_deadline_does_not_restart_chain_clock(policy):
    import time
    from bughunt.core import job

    governor = Governor(limits(), mission="owned-lab", deadline=time.time() + 2)
    with bind(governor):
        budget = job.Budget(frozenset({("GET", "https://allowed.example/")}), 2, 60)
        assert budget.deadline - time.monotonic() <= 2


@pytest.mark.parametrize("name", ["scope.txt", "policy.json"])
def test_authority_change_blocks_even_if_new_contents_are_more_permissive(policy, name):
    from bughunt.core import egress

    governor = Governor(limits(), mission="owned-lab")
    path = policy[1] / name
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(egress.PolicyBlocked, match="authority-changed"):
        governor.admit("https://allowed.example/", "manual", "GET")
    assert governor.requests_admitted == 0


def test_persistence_failure_stops_further_admission(policy):
    from bughunt.core import egress

    def failed(_):
        raise OSError("owned audit failure")

    governor = Governor(limits(), mission="owned-lab", persist=failed)
    with pytest.raises(OSError):
        governor.admit("https://allowed.example/", "manual", "GET")
    with pytest.raises(egress.PolicyBlocked, match="cancelled"):
        governor.admit("https://allowed.example/", "manual", "GET")


def test_retained_bytes_are_cumulative_and_bounded(policy):
    from bughunt.core import egress

    governor = Governor(limits(bytes=5), mission="owned-lab")
    governor.retain(3)
    governor.retain(2)
    with pytest.raises(egress.PolicyBlocked, match="byte-cap"):
        governor.retain(1)
    assert governor.bytes_retained == 5


def test_pipeline_cap_stops_actual_loopback_receiver(owned):
    from bughunt.core import egress

    governor = Governor(limits(), mission="owned-lab")
    with bind(governor), egress.client(timeout=3) as client:
        for _ in range(2):
            assert client.get(owned["origin"] + "/owned").content == b"owned"
        with pytest.raises(egress.PolicyBlocked, match="pipeline-request-cap"):
            client.get(owned["origin"] + "/extra")
    assert [row["path"] for row in owned["arrivals"]] == ["/owned", "/owned"]
    assert governor.requests_admitted == 2


def test_chain_concurrency_applies_to_module_worker_threads(policy):
    from concurrent.futures import ThreadPoolExecutor
    import json
    import threading
    import httpx
    from bughunt.core import egress

    document, root = policy
    document["limits"] = {"requests_per_second": 1000, "concurrency": 2}
    (root / "policy.json").write_text(json.dumps(document))
    first, second, release = threading.Event(), threading.Event(), threading.Event()

    def response(request):
        if request.url.path == "/first":
            first.set()
            assert release.wait(3)
        else:
            second.set()
        return httpx.Response(200, content=b"owned")

    def send(path):
        with egress.client(transport=httpx.MockTransport(response)) as client:
            return client.get("https://allowed.example/" + path).status_code

    governor = Governor(limits(), mission="owned-lab")
    with bind(governor), ThreadPoolExecutor(max_workers=2) as workers:
        pending = workers.submit(send, "first")
        assert first.wait(2)
        other = workers.submit(send, "second")
        try:
            assert not second.wait(0.2)
        finally:
            release.set()
        assert pending.result(3) == other.result(3) == 200


def test_capture_body_retention_obeys_chain_byte_cap(policy):
    from bughunt.core import egress, ledger

    governor = Governor(limits(bytes=5), mission="owned-lab")
    with bind(governor):
        capture = ledger.begin(
            egress.current_profile(),
            tool="owned",
            operation="manual",
            target="https://allowed.example/",
            request=b"",
        )
        capture.feed(b"one")
        with pytest.raises(egress.PolicyBlocked, match="byte-cap"):
            capture.feed(b"two")
    assert bytes(capture.body) == b"one"
    assert governor.bytes_retained == 3


def test_request_capture_is_charged_before_persistence(policy):
    from bughunt.core import egress, ledger

    governor = Governor(limits(bytes=5), mission="owned-lab")
    with bind(governor), pytest.raises(egress.PolicyBlocked, match="byte-cap"):
        ledger.begin(
            egress.current_profile(),
            tool="owned",
            operation="manual",
            target="https://allowed.example/",
            request=b"too-large",
        )
    assert not ledger.runs_dir().exists()


def test_worker_cannot_escape_governor_by_switching_workspace(
    policy, monkeypatch, tmp_path
):
    from concurrent.futures import ThreadPoolExecutor
    from bughunt.core import egress

    governor = Governor(limits(), mission="owned-lab")

    def changed_workspace():
        monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "other"))
        active = current()
        assert active is governor
        with pytest.raises(egress.PolicyBlocked, match="authority-changed"):
            active.admit("https://allowed.example/", "manual", "GET")

    with bind(governor), ThreadPoolExecutor(max_workers=1) as workers:
        workers.submit(changed_workspace).result()
    assert governor.requests_admitted == 0


def test_resumed_governor_preserves_rate_floor(policy, monkeypatch):
    from bughunt.core import clock

    instant = [100.0]
    monkeypatch.setattr(clock, "now", lambda: instant[0])
    governor = Governor(
        limits(requests_per_second=0.1),
        mission="owned-lab",
        counters={"requests_admitted": 1, "bytes_retained": 0},
    )
    assert governor.ready() is False
    instant[0] += 10
    assert governor.ready() is True


def test_response_headers_cannot_bypass_retained_byte_cap(policy):
    from bughunt.core import egress, ledger

    governor = Governor(limits(bytes=5), mission="owned-lab")
    with bind(governor):
        capture = ledger.begin(
            egress.current_profile(),
            tool="owned",
            operation="manual",
            target="https://allowed.example/",
            request=b"",
        )
        capture.response_prefix = b"HTTP/1.1 200 OK\r\nX-Owned: oversized\r\n\r\n"
        with pytest.raises(egress.PolicyBlocked, match="byte-cap"):
            capture.finish()
    assert not (capture.root / "response.http").exists()


@pytest.mark.parametrize("stop", ["cancel", "deadline", "revoke"])
def test_receipt_retention_after_stop_is_bounded_and_never_reopens_activity(
    policy, stop
):
    from bughunt.core import egress

    snapshots = []
    governor = Governor(limits(bytes=5), mission="owned-lab", persist=snapshots.append)
    governor.retain(2)
    if stop == "cancel":
        governor.cancelled.set()
    elif stop == "deadline":
        governor.deadline = 0
    else:
        path = policy[1] / "policy.json"
        path.write_bytes(path.read_bytes() + b"\n")
    governor.retain_receipt(3)
    assert snapshots[-1] == {"requests_admitted": 0, "bytes_retained": 5}
    with pytest.raises(egress.PolicyBlocked, match="pipeline-byte-cap"):
        governor.retain_receipt(1)
    with pytest.raises(egress.PolicyBlocked):
        governor.retain(0)
    with pytest.raises(egress.PolicyBlocked):
        governor.admit("https://allowed.example/", "manual", "GET")
    assert governor.requests_admitted == 0 and governor.bytes_retained == 5


@pytest.mark.parametrize("amount", [True, -1, 1.5])
def test_receipt_retention_rejects_invalid_counts(policy, amount):
    governor = Governor(limits(), mission="owned-lab")
    with pytest.raises(ValueError, match="Invalid retained-byte count"):
        governor.retain_receipt(amount)
    assert governor.bytes_retained == 0


def test_receipt_counter_persistence_failure_stops_admission(policy):
    from bughunt.core import egress

    def failed(_):
        raise OSError("owned receipt-counter failure")

    governor = Governor(limits(), mission="owned-lab", persist=failed)
    with pytest.raises(OSError, match="receipt-counter"):
        governor.retain_receipt(1)
    assert governor.cancelled.is_set()
    with pytest.raises(egress.PolicyBlocked, match="cancelled"):
        governor.admit("https://allowed.example/", "manual", "GET")
