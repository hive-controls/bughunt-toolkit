from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

import pytest

import bughunt
from bughunt.core import api, exchange
from bughunt.core.pipeline import load_pipeline, run_pipeline, resume_pipeline
from bughunt.core.pipeline_budget import current
from test_gate import policy
from test_oracle_mod_g1_recon import NAME, dns_lab, lab, resolver


@pytest.fixture
def owned_chain(policy):
    document, root = policy
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            if self.path == "/robots.txt":
                body = b"User-agent: *\nDisallow: /app/item\n"
            else:
                body = (
                    b"candidate"
                    if self.headers.get("X-Owned-Candidate")
                    else b"baseline"
                )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    origin = f"http://127.0.0.1:{server.server_port}"
    document["assets"] = [
        {
            "id": "owned-chain",
            "origin": origin,
            "paths": ["/"],
            "operations": ["manual", "fuzz"],
            "methods": ["GET"],
        }
    ]
    (root / "policy.json").write_text(json.dumps(document))
    (root / "scope.txt").write_text("127.0.0.1\n")
    raw = root / "owned.http"
    raw.write_bytes(
        f"GET /app/item HTTP/1.1\r\nHost: 127.0.0.1:{server.server_port}\r\n\r\n".encode()
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield origin, raw, hits, root
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()


def chain(origin, raw):
    return load_pipeline(
        {
            "schema_version": 1,
            "mission": "owned-lab",
            "limits": {
                "requests": 20,
                "seconds": 60,
                "concurrency": 1,
                "requests_per_second": 100,
                "bytes": 1000000,
            },
            "steps": [
                {
                    "id": "recon",
                    "module": "robots",
                    "options": {"fetch": origin + "/robots.txt", "no_workspace": True},
                },
                {
                    "id": "capture",
                    "module": "exchange",
                    "operation": "import-raw",
                    "options": {"request": str(raw), "source_id": "owned-chain"},
                    "inputs": {
                        "url": {"step": "recon", "artifact": "urls", "index": 0}
                    },
                },
                {
                    "id": "test",
                    "module": "discover",
                    "options": {"header": ["X-Owned-Candidate"], "requests": 10},
                    "inputs": {
                        "exchange_id": {
                            "step": "capture",
                            "artifact": "exchanges",
                            "index": 0,
                        }
                    },
                },
            ],
        }
    )


@pytest.mark.parametrize(
    "module,selectors", [("dns", []), ("mail", []), ("mail", ["s1", "s2"])]
)
def test_insufficient_dns_budget_blocks_before_first_actual_datagram(
    dns_lab, module, selectors
):
    from bughunt.core import egress
    from bughunt.modules import dns

    value = {
        "schema_version": 1,
        "mission": egress.current_profile().mission,
        "limits": {
            "requests": len(dns.RECORD_TYPES)
            * (1 if module == "dns" else 2 + len(selectors))
            - 1,
            "seconds": 30,
            "concurrency": 1,
            "requests_per_second": 100,
            "bytes": 100000,
        },
        "steps": [
            {
                "id": "dns",
                "module": module,
                "options": {
                    "name": NAME,
                    "resolver": "127.0.0.1",
                    "port": dns_lab.resolver.port,
                    **({"selector": selectors} if selectors else {}),
                },
            }
        ],
    }
    result = run_pipeline(value, execute=True)
    assert result.status == "blocked", result.to_dict()
    assert result.metrics["requests_admitted"] == 0
    assert dns_lab.resolver.seen == []


def test_pipeline_preview_runs_inert_producer_validation_without_datagrams(dns_lab):
    from bughunt.core import egress

    value = {
        "schema_version": 1,
        "mission": egress.current_profile().mission,
        "limits": {
            "requests": 20,
            "seconds": 30,
            "concurrency": 1,
            "requests_per_second": 100,
            "bytes": 100000,
        },
        "steps": [
            {
                "id": "dns",
                "module": "dns",
                "options": {"name": NAME, "resolver": "127.0.0.1", "port": -1},
            }
        ],
    }
    result = run_pipeline(value)
    assert result.status == "invalid", result.to_dict()
    assert dns_lab.resolver.seen == []


def test_explicit_exchange_set_handoff_uses_retained_records_without_sends(policy):
    root = policy[1]
    request = root / "owned.http"
    request.write_bytes(b"GET /owned HTTP/1.1\r\nHost: allowed.example\r\n\r\n")
    value = {
        "schema_version": 1,
        "mission": "owned-lab",
        "limits": {
            "requests": 1,
            "seconds": 30,
            "concurrency": 1,
            "requests_per_second": 100,
            "bytes": 100000,
        },
        "steps": [
            {
                "id": "capture",
                "module": "exchange",
                "operation": "import-raw",
                "options": {
                    "request": str(request),
                    "source_id": "owned-set",
                    "url": "https://allowed.example/owned",
                },
            },
            {
                "id": "flow",
                "module": "exchange",
                "operation": "flow",
                "inputs": {
                    "exchange_ids": {
                        "step": "capture",
                        "artifact": "exchanges",
                        "indices": [0],
                    }
                },
            },
        ],
    }
    result = run_pipeline(value, execute=True)
    assert result.status == "success", result.to_dict()
    assert result.metrics["requests_admitted"] == 0
    assert result.artifacts[0].payload["items"][-1]["id"] == "flow"


def test_real_chain_passes_typed_urls_and_capture_ids_and_reuses_receipts(
    owned_chain, capsys
):
    origin, raw, hits, root = owned_chain
    result = run_pipeline(chain(origin, raw), execute=True)
    assert result.status == "success", result.to_dict()
    assert hits == ["/robots.txt"] + ["/app/item"] * 7
    assert result.metrics["requests_admitted"] == 8
    identifier = result.execution_id
    capture = json.loads(
        (root / "jobs" / identifier / "steps" / "capture" / "result.json").read_text()
    )
    record = exchange.read(capture["artifacts"][0]["payload"]["exchange_ids"][0])
    assert record["request"]["url"] == origin + "/app/item"
    resumed = resume_pipeline(identifier, execute=True)
    assert resumed.status == "success", resumed.to_dict()
    assert len(hits) == 8
    assert capsys.readouterr() == ("", "")


def test_pipeline_preview_is_inert_and_does_not_create_jobs(owned_chain):
    origin, raw, hits, root = owned_chain
    selected = chain(origin, raw)
    before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    result = run_pipeline(selected)
    assert result.status == "planned", result.to_dict()
    assert hits == [] and not (root / "jobs").exists()
    assert before == {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
    assert str(raw) not in json.dumps(result.to_dict())


def test_policy_revocation_after_import_blocks_discovery(owned_chain, monkeypatch):
    origin, raw, hits, root = owned_chain
    original = api.run_module

    def revoke(name, **options):
        result = original(name, **options)
        if name == "exchange" and not options.get("dry_run"):
            document = json.loads((root / "policy.json").read_text())
            document["state"] = "unknown"
            (root / "policy.json").write_text(json.dumps(document))
        return result

    monkeypatch.setattr(api, "run_module", revoke)
    result = run_pipeline(chain(origin, raw), execute=True)
    assert result.status == "blocked", result.to_dict()
    assert hits == ["/robots.txt"]


@pytest.mark.parametrize("stop", ["cancel", "deadline", "revoke"])
@pytest.mark.parametrize("last_step", [False, True])
def test_completed_producer_receipt_survives_stop_before_finalization(
    owned_chain, monkeypatch, stop, last_step
):
    origin, raw, hits, root = owned_chain
    document = chain(origin, raw).document
    document["steps"] = document["steps"][:1]
    if not last_step:
        document["steps"].append({**document["steps"][0], "id": "later"})
    original = api.run_module
    produced = []

    def stop_after_producer(name, **options):
        result = original(name, **options)
        produced.append(result.to_dict())
        assert name == "robots" and result.status == "success"
        governor = current()
        if stop == "cancel":
            governor.stop_path.write_text("cancelled")
        elif stop == "deadline":
            governor.deadline = 0
        else:
            policy_path = root / "policy.json"
            policy_path.write_bytes(policy_path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(api, "run_module", stop_after_producer)
    result = run_pipeline(document, execute=True)
    assert result.status == ("cancelled" if stop == "cancel" else "blocked")
    assert hits == ["/robots.txt"] and len(produced) == 1
    journal = root / "jobs" / result.execution_id
    receipt = journal / "steps" / "recon" / "result.json"
    assert receipt.is_file(), "Completed producer receipt was lost during stop"
    assert json.loads(receipt.read_bytes()) == produced[0]
    snapshot = json.loads((journal / "pipeline.json").read_bytes())
    assert snapshot["state"] == result.status
    assert snapshot["steps"]["recon"]["state"] == "completed"
    assert result.artifacts[-1].to_dict() == produced[0]["artifacts"][-1]
    assert result.evidence == produced[0]["evidence"]
    assert not (journal / "steps" / "later").exists()


def test_stop_cannot_retain_completed_receipt_beyond_byte_cap(owned_chain, monkeypatch):
    from bughunt.core.pipeline_store import Journal

    origin, raw, hits, root = owned_chain
    original = api.run_module

    def exhaust_after_producer(name, **options):
        result = original(name, **options)
        assert name == "robots" and result.status == "success"
        governor = current()
        governor.retain(governor.limits["bytes"] - governor.bytes_retained)
        governor.stop_path.write_text("cancelled")
        return result

    monkeypatch.setattr(api, "run_module", exhaust_after_producer)
    result = run_pipeline(chain(origin, raw), execute=True)
    assert result.status == "cancelled"
    assert result.metrics["bytes_retained"] == result.metrics["limits"]["bytes"]
    journal = Journal(result.execution_id)
    assert journal.status()["steps"][0] == {"id": "recon", "state": "running"}
    assert not (journal.root / "steps" / "recon" / "result.json").exists()
    assert resume_pipeline(result.execution_id, execute=True).status == "blocked"
    assert hits == ["/robots.txt"]


def test_local_diff_needs_no_network_budget(owned_chain):
    origin, raw, hits, root = owned_chain
    left, right = root / "left.http", root / "right.http"
    left.write_text("HTTP/1.1 200 OK\nContent-Type: text/plain\n\nleft")
    right.write_text("HTTP/1.1 200 OK\nContent-Type: text/plain\n\nright")
    document = chain(origin, raw).document
    document["limits"]["requests"] = 1
    document["steps"] = [
        {
            "id": "compare",
            "module": "diff",
            "options": {"left": str(left), "right": str(right)},
        }
    ]
    result = run_pipeline(document, execute=True)
    assert result.status == "success"
    assert result.metrics["requests_admitted"] == 0
    assert hits == []


def test_pipeline_rejects_passive_engine_before_unmetered_job_files(policy):
    from test_zap_passive import passive_fixture

    identifiers, policy_document, root = passive_fixture(policy)
    document = {
        "schema_version": 1,
        "mission": policy_document["mission"],
        "limits": {
            "requests": 10,
            "seconds": 30,
            "concurrency": 1,
            "requests_per_second": 100,
            "bytes": 1,
        },
        "steps": [
            {
                "id": "passive",
                "module": "engine",
                "operation": "start",
                "options": {
                    "profile_id": "zap-passive",
                    "exchange_id": identifiers,
                    "mission": policy_document["mission"],
                    "actor": ["owner", "guest"],
                },
            }
        ],
    }
    with pytest.raises(ValueError, match="eligible"):
        load_pipeline(document)
    assert not (root / "jobs").exists()


def test_pipeline_export_cannot_write_before_shared_byte_cap_rejects(owned_chain):
    origin, raw, hits, root = owned_chain
    record = exchange.raw_record(
        raw.read_bytes(), None, source_id="owned-export", url=origin + "/app/item"
    )
    identifier = exchange.save(
        [record], source_id="owned-export", source_bytes=raw.read_bytes(), kind="raw"
    )[0]
    destination = root / "unmetered-export.json"
    document = chain(origin, raw).document
    document["limits"]["bytes"] = 1
    document["steps"] = [
        {
            "id": "export",
            "module": "exchange",
            "operation": "export",
            "options": {"exchange_id": identifier, "output": str(destination)},
        }
    ]
    result = run_pipeline(document, execute=True)
    assert not destination.exists()
    assert result.status == "invalid"
    assert hits == []


@pytest.mark.parametrize("failure", ["counters", "receipt", "terminal"])
def test_finalization_persistence_failure_never_reports_success_or_replays(
    owned_chain, monkeypatch, failure
):
    from bughunt.core import pipeline_store

    origin, raw, hits, root = owned_chain
    document = chain(origin, raw).document
    document["steps"] = document["steps"][:1]
    if failure != "terminal":
        document["steps"].append({**document["steps"][0], "id": "later"})
    original_run, original_write = api.run_module, pipeline_store._write
    produced = []

    def after_producer(name, **options):
        result = original_run(name, **options)
        produced.append(result.to_dict())
        assert name == "robots" and result.status == "success"
        return result

    def fail_write(path, value):
        if produced and (
            failure == "counters"
            and path.name == "pipeline.json"
            or failure == "receipt"
            and path.name == "result.json"
            or failure == "terminal"
            and value.get("state") == "success"
        ):
            raise OSError("owned finalization persistence failure")
        return original_write(path, value)

    with monkeypatch.context() as patch:
        patch.setattr(api, "run_module", after_producer)
        patch.setattr(pipeline_store, "_write", fail_write)
        result = run_pipeline(document, execute=True)
    assert result.status == "failed" and len(produced) == 1
    journal = root / "jobs" / result.execution_id
    snapshot = json.loads((journal / "pipeline.json").read_bytes())
    assert snapshot["state"] != "success"
    receipt = journal / "steps" / "recon" / "result.json"
    if failure == "terminal":
        assert json.loads(receipt.read_bytes()) == produced[0]
        assert result.artifacts[-1].to_dict() == produced[0]["artifacts"][-1]
        assert result.errors[0]["code"] == "pipeline_journal_not_committed"
    else:
        assert not receipt.exists()
        assert snapshot["steps"]["recon"]["state"] == "running"
    assert resume_pipeline(result.execution_id, execute=True).status == "blocked"
    assert hits == ["/robots.txt"]
