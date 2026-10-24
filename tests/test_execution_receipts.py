import json

import bughunt
from bughunt.core import adapters, egress, exchange
from test_pipeline_acceptance import owned_chain
from test_gate import policy


def test_local_and_preview_results_measure_zero_admissions(owned_chain):
    origin, _, hits, _ = owned_chain
    local = bughunt.run_module("scope", operation="list")
    preview = bughunt.run_module(
        "robots", options={"fetch": origin + "/robots.txt"}, dry_run=True
    )
    assert local.status == "success"
    assert preview.status == "planned"
    for result in (local, preview):
        assert result.metrics["requests_admitted"] == 0
        assert result.metrics["bytes_retained"] == 0
        assert result.policy is None
    assert hits == []


def test_owned_http_receipt_measures_admission_files_and_authority(owned_chain):
    origin, _, hits, root = owned_chain
    result = bughunt.run_module(
        "robots", options={"fetch": origin + "/robots.txt", "no_workspace": True}
    )
    assert result.status == "success"
    assert result.metrics["requests_admitted"] == len(hits) == 1
    retained = sum(
        path.stat().st_size for path in (root / "runs").rglob("*") if path.is_file()
    )
    assert result.metrics["bytes_retained"] == retained > 0
    document = json.loads((root / "policy.json").read_text())
    assert result.policy["policy_sha256"] == exchange.digest(
        (root / "policy.json").read_bytes()
    )
    assert result.policy["policy_version"] == document["policy_version"]
    assert result.policy["scope_sha256"] == exchange.digest(
        (root / "scope.txt").read_bytes()
    )
    assert result.policy["actor_revision"] == "legacy"
    assert (
        result.metrics["limits"]["requests_per_second"]
        == document["limits"]["requests_per_second"]
    )


def test_failed_producer_keeps_actual_metrics_and_receipts(owned_chain, monkeypatch):
    origin, _, hits, _ = owned_chain

    def producer(*args):
        with egress.client() as client:
            client.get(origin + "/robots.txt")
        raise RuntimeError("producer failed after receipt")

    monkeypatch.setattr(adapters, "execute", producer)
    result = bughunt.run_module("robots", options={"fetch": origin + "/robots.txt"})
    assert result.status == "failed"
    assert result.metrics["requests_admitted"] == len(hits) == 1
    assert result.metrics["bytes_retained"] > 0
    assert len(result.evidence) == 1
    assert result.policy is not None


def test_worker_context_keeps_receipts_and_counts_isolated(owned_chain, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context
    from bughunt.core.results import ModuleOutput

    origin, _, hits, _ = owned_chain

    def request():
        with egress.client() as client:
            client.get(origin + "/robots.txt")

    def producer(*args):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(copy_context().run, request) for _ in range(2)]
            for future in futures:
                future.result()
        return ModuleOutput()

    monkeypatch.setattr(adapters, "execute", producer)
    result = bughunt.run_module("robots", options={"fetch": origin + "/robots.txt"})
    assert result.status == "success"
    assert result.metrics["requests_admitted"] == len(hits) == 2
    assert len(result.evidence) == 2
    monkeypatch.undo()
    local = bughunt.run_module("scope", operation="list")
    assert local.metrics["requests_admitted"] == 0
    assert local.evidence == []


def test_multiple_policies_do_not_produce_a_false_single_receipt(
    owned_chain, monkeypatch
):
    from bughunt.core.results import ModuleOutput

    origin, _, hits, root = owned_chain

    def producer(*args):
        with egress.client() as client:
            client.get(origin + "/robots.txt")
        path = root / "policy.json"
        document = json.loads(path.read_text())
        document["policy_version"] += "-updated"
        path.write_text(json.dumps(document))
        with egress.client() as client:
            client.get(origin + "/robots.txt")
        return ModuleOutput()

    monkeypatch.setattr(adapters, "execute", producer)
    result = bughunt.run_module("robots", options={"fetch": origin + "/robots.txt"})
    assert result.status == "success"
    assert result.metrics["requests_admitted"] == len(hits) == 2
    assert result.policy is None
    assert any("Multiple authorities" in warning for warning in result.warnings)


def test_inert_import_measures_retained_exchange_files(owned_chain):
    origin, raw, hits, root = owned_chain
    result = bughunt.run_module(
        "exchange",
        operation="import-raw",
        options={
            "request": str(raw),
            "url": origin + "/app/item",
            "source_id": "receipt-import",
        },
    )
    assert result.status == "success"
    retained = sum(
        path.stat().st_size
        for path in (root / "exchanges").rglob("*")
        if path.is_file()
    )
    assert result.metrics["bytes_retained"] == retained > 0
    assert result.metrics["requests_admitted"] == 0
    assert hits == []


def test_exchange_storage_respects_pipeline_byte_cap_before_write(owned_chain):
    from bughunt.core.pipeline_budget import Governor, bind

    origin, raw, hits, root = owned_chain
    governor = Governor(
        {
            "requests": 3,
            "seconds": 30,
            "concurrency": 1,
            "requests_per_second": 100,
            "bytes": 100,
        }
    )
    with bind(governor):
        result = bughunt.run_module(
            "exchange",
            operation="import-raw",
            options={
                "request": str(raw),
                "url": origin + "/app/item",
                "source_id": "capped-import",
            },
        )
    assert result.status == "blocked"
    assert result.metrics["limits"] == dict(governor.limits)
    assert list((root / "exchanges").rglob("*.json")) == []
    assert hits == []
