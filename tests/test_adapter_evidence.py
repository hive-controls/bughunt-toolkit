import pytest

import bughunt
from bughunt.core import adapters, egress, ledger
from bughunt.core.results import ModuleOutput
from test_gate import policy


@pytest.mark.parametrize("fails", [False, True])
def test_api_collects_real_ledger_receipts_even_when_producer_fails(
    policy, monkeypatch, fails
):
    def producer(*_):
        capture = ledger.begin(
            egress.current_profile(),
            tool="owned",
            operation="manual",
            target="https://allowed.example/",
            request=b"owned",
        )
        capture.finish()
        if fails:
            raise OSError("private source path must not escape")
        return ModuleOutput()

    monkeypatch.setattr(adapters, "execute", producer)
    result = bughunt.run_module("scope", operation="urls")
    assert result.status == ("failed" if fails else "success")
    assert len(result.evidence) == 1
    assert (
        ledger.export_run(result.evidence[0]["run_id"])["captures"]["request"]["text"]
        == "owned"
    )


def test_receipt_collection_does_not_mix_concurrent_api_calls(policy, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading

    barrier = threading.Barrier(2)

    def producer(*_):
        capture = ledger.begin(
            egress.current_profile(),
            tool="owned",
            operation="manual",
            target="https://allowed.example/",
            request=b"owned",
        )
        barrier.wait(timeout=3)
        capture.finish()
        return ModuleOutput()

    monkeypatch.setattr(adapters, "execute", producer)
    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [
            workers.submit(bughunt.run_module, "scope", operation="urls")
            for _ in range(2)
        ]
        results = [future.result(timeout=5) for future in futures]
    assert all(
        result.status == "success" and len(result.evidence) == 1 for result in results
    )
    assert results[0].evidence[0]["run_id"] != results[1].evidence[0]["run_id"]
