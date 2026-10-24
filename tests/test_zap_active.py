"""Owned guarded active profile: no process/send before explicit acceptance."""

from datetime import datetime, timezone
import json

import httpx
import pytest

from bughunt.core import egress, exchange, identity, job, ledger
from bughunt.integrations import zap, zap_active, zap_runtime
from test_gate import boundaries, policy

SEED = "http://127.0.0.1:45678/__bughunt_lab__/reflect?q=owned"


@pytest.fixture
def owned(policy):
    document, root = policy
    document["mission"] = "whk012-owned-active"
    document["assets"] = [{"id": "owned-reflection", "origin": "http://127.0.0.1:45678",
                            "paths": ["/__bughunt_lab__/reflect"], "operations": ["passive", "active_scan", "process"],
                            "methods": ["GET"]}]
    document["exclusions"] = []
    (root / "scope.txt").write_text("127.0.0.1\n")
    (root / "policy.json").write_text(json.dumps(document))
    request = b"GET /__bughunt_lab__/reflect?q=owned HTTP/1.1\r\nHost: 127.0.0.1:45678\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nowned"
    record = exchange.raw_record(request, response, source_id="owned-active", url=SEED)
    ids = exchange.save([record], source_id="owned-active", source_bytes=request, kind="raw")
    return ids[0], document, root


def _prepare(owned, **changes):
    options = {"mission": "whk012-owned-active", "owned_lab": True, "technology": "Python",
               "requests": 4, "seconds": 30, "max_bytes": 4096}
    options.update(changes)
    return zap_active.prepare(owned[0], **options)


def test_exact_owned_dry_run_is_inert(owned, boundaries):
    plan = _prepare(owned)
    value = zap_active.preview(plan)
    assert value["request_cap"] == 4 and value["duration_cap"] == 30
    assert value["technology"] == "Python" and value["rule_ids"] == [40012]
    assert value["actor"] == "default" and value["dry_run"] is True
    assert value["target"] == SEED.split("?")[0]
    assert not (owned[2] / "jobs").exists()


@pytest.mark.parametrize("options", [
    {"owned_lab": False}, {"mission": "different"}, {"technology": "Unknown"},
    {"requests": 0}, {"requests": 101}, {"requests": True},
    {"seconds": 0}, {"seconds": 301}, {"seconds": float("nan")},
    {"max_bytes": 0}, {"max_bytes": 65537},
])
def test_missing_grants_and_invalid_bounds_do_not_launch(owned, boundaries, options):
    with pytest.raises(ValueError):
        _prepare(owned, **options)
    assert not (owned[2] / "jobs").exists()


@pytest.mark.parametrize("failure", ["active", "process", "scope", "stale", "excluded", "actor"])
def test_live_profile_denials_stop_before_boundaries(owned, boundaries, failure):
    document, root = owned[1:]
    if failure in {"active", "process"}:
        document["permissions"]["active_scan" if failure == "active" else "process"] = False
    if failure == "scope":
        (root / "scope.txt").write_text("")
    if failure == "stale":
        document["state"] = "stale"
    if failure == "excluded":
        document["exclusions"] = list(document["assets"])
    if failure == "actor":
        identity.create_profile("owner", "owner", ["http://127.0.0.1:45678"], owned=True)
        identity.use_profile("owner")
    (root / "policy.json").write_text(json.dumps(document))
    with pytest.raises(ValueError):
        _prepare(owned)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:45678/__bughunt_lab__/other?q=x",
    "http://127.0.0.1:45679/__bughunt_lab__/reflect?q=x",
    "https://127.0.0.1:45678/__bughunt_lab__/reflect?q=x",
    "http://outside.example/__bughunt_lab__/reflect?q=x",
    SEED + "&extra=x", SEED + "&q=duplicate",
])
def test_generated_mutations_cannot_widen_the_approved_target(owned, boundaries, url):
    plan = _prepare(owned)
    with pytest.raises(ValueError):
        plan.budget.check(httpx.Request("GET", url))
    assert plan.budget.sent == []


def test_approved_query_mutation_retains_hard_physical_cap_and_capture(owned):
    plan = _prepare(owned, requests=1)
    seen = []
    def respond(request):
        seen.append(str(request.url))
        return httpx.Response(200, stream=httpx.ByteStream(b"owned"))
    with egress.client(operation="active_scan", transport=job.Transport(plan.budget, httpx.MockTransport(respond))) as client:
        request = client.build_request("GET", SEED.replace("q=owned", "q=mutation"))
        request.extensions["bughunt_job_guard"] = plan.budget.check
        response = client.send(request, stream=True)
        try:
            assert b"".join(response.iter_raw()) == b"owned"
        finally:
            response.close()
        with pytest.raises(ValueError):
            plan.budget.admit(request)
    assert len(seen) == len(plan.budget.sent) == 1
    assert ledger.manifest_for(plan.budget.sent[0]["run_id"])["response"] is not None


def test_public_plan_is_active_only_by_explicit_profile_and_rule(owned, boundaries):
    plan = _prepare(owned)
    value = zap_active.automation_plan(plan)
    jobs = value["jobs"]
    assert [item["type"] for item in jobs] == ["requestor", "activeScan", "report"]
    context = value["env"]["contexts"][0]
    assert context["technology"] == {"include": ["Python"]}
    assert len(context["includePaths"]) == 1 and len(context["excludePaths"]) == 1
    assert jobs[1]["policyDefinition"]["defaultThreshold"] == "Off"
    assert jobs[1]["policyDefinition"]["rules"] == [{"id": 40012, "strength": "Low", "threshold": "Low"}]
    assert "script" not in json.dumps(value)


def test_rpc_preserves_final_capture_but_never_engine_credentials(owned, monkeypatch):
    import base64
    plan = _prepare(owned)
    calls = []
    request_bytes = (f"GET {SEED} HTTP/1.1\r\nHost: 127.0.0.1:45678\r\n"
                     "Cookie: engine-secret\r\nAuthorization: Bearer engine-secret\r\n\r\n").encode()
    rpc = owned[2] / "000001.req"
    rpc.write_bytes(base64.b64encode(SEED.encode()) + b"\n" + base64.b64encode(request_bytes) + b"\n")
    def respond(request):
        calls.append(request)
        assert "Cookie" not in request.headers and "Authorization" not in request.headers
        return httpx.Response(200, headers={"Set-Cookie": "id=upstream-secret"}, stream=httpx.ByteStream(b"owned"))
    with egress.client(operation="active_scan", transport=job.Transport(plan.budget, httpx.MockTransport(respond))) as client:
        result = zap_runtime.mediate(rpc, client, plan)
    assert result["sent"] is True and result["run_id"] is not None
    assert len(calls) == len(plan.budget.sent) == 1
    assert ledger.manifest_for(result["run_id"])["response"] is not None
    assert b"engine-secret" not in (owned[2] / "runs" / result["run_id"] / "request.http").read_bytes()


def test_runtime_command_has_no_consumer_network_or_published_ports(owned, boundaries):
    plan = _prepare(owned)
    command = zap_runtime.command(plan, owned[2], "whk012-test")
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--pull") + 1] == "never"
    assert "-p" not in command and "--publish" not in command and "--privileged" not in command
    assert zap.SUPPORTED_IMAGE in command
    assert "readonly" in " ".join(command) and "--cap-drop" in command


def test_source_and_plan_drift_deny_before_send(owned, boundaries):
    plan = _prepare(owned)
    artifact = owned[2] / "plan.json"
    artifact.write_bytes(b"owned plan")
    plan.budget.bind_artifacts([artifact])
    artifact.write_bytes(b"changed")
    with pytest.raises(ValueError):
        plan.budget.check(httpx.Request("GET", SEED))
    assert plan.budget.sent == []


def test_cancelled_job_blocks_subsequent_send(owned, boundaries):
    plan = _prepare(owned)
    plan.budget.activate()
    job.cancel(plan.budget.job_id)
    with pytest.raises(ValueError):
        plan.budget.check(httpx.Request("GET", SEED))
    assert plan.budget.sent == []
