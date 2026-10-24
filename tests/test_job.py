"""Final physical-boundary controls, including revocation during policy waits."""

import json
import time

import httpx
import pytest

from bughunt.core import egress, identity, job, ledger
from test_gate import boundaries, policy

URL = "https://allowed.example/app/item"


def test_budget_exact_requests_no_redirects_and_accounting(policy, boundaries):
    seen = []
    budget = job.Budget(frozenset({("GET", URL)}), 2, 10)
    inner = httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(302, content=b"owned"))
    with egress.client(operation="fuzz", transport=job.Transport(budget, inner), follow_redirects=False) as client:
        assert client.get(URL).status_code == 302
        assert client.get(URL).status_code == 302
        with pytest.raises(egress.PolicyBlocked):
            client.get(URL)
        with pytest.raises(egress.PolicyBlocked):
            client.get(URL + "?unplanned=1")
    assert len(seen) == len(budget.sent) == 2
    for row in budget.sent:
        manifest = ledger.manifest_for(row["run_id"])
        assert manifest["request"] and manifest["response"]


@pytest.mark.parametrize("change", ["cancel", "expiry", "scope", "policy"])
def test_queued_revocation_blocks_physical_send(policy, boundaries, monkeypatch, change):
    document, path = policy
    seen = []
    budget = job.Budget(frozenset({("GET", URL)}), 1, 10)
    reserve = egress._reserve
    def waiting(*args):
        reserve(*args)
        if change == "cancel":
            budget.cancelled.set()
        elif change == "expiry":
            budget.deadline = time.monotonic() - 1
        elif change == "scope":
            (path / "scope.txt").write_text("outside.example\n")
        else:
            document["policy_version"] = "revision-2"
            (path / "policy.json").write_text(json.dumps(document))
    monkeypatch.setattr(egress, "_reserve", waiting)
    inner = httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(200))
    with egress.client(operation="fuzz", transport=job.Transport(budget, inner)) as client:
        with pytest.raises(egress.PolicyBlocked):
            client.get(URL)
    assert seen == budget.sent == []


def test_failed_physical_attempt_still_links_private_run(policy, boundaries):
    budget = job.Budget(frozenset({("GET", URL)}), 1, 10)
    def failed(request):
        raise httpx.ConnectError("owned failure", request=request)
    with egress.client(operation="fuzz", transport=job.Transport(budget, httpx.MockTransport(failed))) as client:
        with pytest.raises(httpx.ConnectError):
            client.get(URL)
    assert len(budget.sent) == 1
    assert ledger.manifest_for(budget.sent[0]["run_id"])["classification"] == "invalid"


@pytest.mark.parametrize("maximum,seconds", [(0, 1), (101, 1), (True, 1), (1, 0), (1, 301), (1, float("nan"))])
def test_invalid_bounds_reject(policy, maximum, seconds):
    with pytest.raises(ValueError):
        job.Budget(frozenset({("GET", URL)}), maximum, seconds)


def test_changed_actor_blocks_send_even_if_changed_before_preparation(policy, boundaries):
    budget = job.Budget(frozenset({("GET", URL)}), 1, 10)
    identity.create_profile("guest", "anonymous", ["https://allowed.example"], owned=True)
    identity.use_profile("guest")
    seen = []
    inner = httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(200))
    with egress.client(operation="fuzz", transport=job.Transport(budget, inner)) as client:
        with pytest.raises(egress.PolicyBlocked):
            client.get(URL)
    assert seen == budget.sent == []


def test_invalid_redaction_after_budget_preparation_blocks_physical_send(policy, boundaries):
    budget = job.Budget(frozenset({("GET", URL)}), 1, 10)
    (policy[1] / "redaction.json").write_text('{"patterns": "invalid"}')
    seen = []
    inner = httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(200))
    with egress.client(operation="fuzz", transport=job.Transport(budget, inner)) as client:
        with pytest.raises(ValueError):
            client.get(URL)
    assert seen == budget.sent == []


def test_job_deadline_interrupts_policy_queue_wait(policy, boundaries, monkeypatch):
    budget = job.Budget(frozenset({("GET", URL)}), 1, 0.03)
    budget.activate()
    attempted = []
    original = egress._try_reserve
    def queue(profile):
        attempted.append(True)
        if time.monotonic() >= budget.deadline + 0.15:
            return original(profile)
        return False
    monkeypatch.setattr(egress, "_try_reserve", queue)
    seen = []
    inner = httpx.MockTransport(lambda request: seen.append(request) or httpx.Response(200))
    with egress.client(operation="fuzz", transport=job.Transport(budget, inner)) as client:
        request = httpx.Request("GET", URL, extensions={"bughunt_job_guard": budget.check})
        started = time.monotonic()
        with pytest.raises(egress.PolicyBlocked):
            client.send(request)
    assert attempted and time.monotonic() - started < 0.12
    assert seen == budget.sent == []


def test_expiry_without_policy_file_change_blocks_live_job_check(policy, boundaries, monkeypatch):
    from bughunt.core.policy import Profile
    budget = job.Budget(frozenset({("GET", URL)}), 1, 10)
    monkeypatch.setattr(Profile, "freshness", lambda self, now=None: "stale")
    with pytest.raises(egress.PolicyBlocked):
        budget.check(httpx.Request("GET", URL))
