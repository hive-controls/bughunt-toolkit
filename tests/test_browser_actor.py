"""Offline policy/identity controls, not browser containment acceptance."""

import json

import httpx
import pytest

from bughunt.core import egress, identity, verification
from bughunt.integrations import browser_actor
from test_gate import boundaries, seed_policy


ORIGIN = "http://127.0.0.1:8765"
URL = ORIGIN + "/__bughunt_lab__/page"
PROBE = ORIGIN + "/__bughunt_lab__/whoami"


@pytest.fixture
def actor_lab(tmp_path, monkeypatch):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    document = seed_policy(tmp_path)
    document["mission"] = browser_actor.MISSION
    document["assets"] = [{"id": "browser-lab", "origin": ORIGIN,
        "paths": ["/__bughunt_lab__/"], "operations": ["active_scan", "process"],
        "methods": ["GET"]}]
    (tmp_path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    (tmp_path / "scope.txt").write_text("127.0.0.1\n", encoding="utf-8")
    for name, kind in (("owner", "owner"), ("lower", "lower_privilege"), ("anonymous", "anonymous")):
        identity.create_profile(name, kind, [ORIGIN], owned=True)
        if kind != "anonymous":
            identity.set_credential(name, "cookie", "session=owned-private-" + name)
            verification.configure(name, PROBE, "user.id", "private-principal-" + name,
                                   "user.role", kind)
        else:
            verification.configure(name, PROBE, None, None, None, None, expected_status=401)
    return tmp_path, document


def prepare(actor="owner", urls=None, **options):
    return browser_actor.prepare(urls or [URL], actor=actor,
        mission=options.pop("mission", browser_actor.MISSION), owned_lab=options.pop("owned_lab", True), **options)


def test_dry_run_is_private_and_has_no_outbound_side_effect(actor_lab, boundaries):
    root, _document = actor_lab
    value = browser_actor.preview(prepare())
    assert value["dry_run"] is True and value["actor"] == "owner"
    assert value["budgets"]["physical_requests"] == 20
    assert value["credential_authority"] == "Bughunt named actor; browser headers never select identity"
    assert value["browser_network"] == "none; host-mediated selected GETs only"
    assert not (root / "jobs").exists()
    raw = json.dumps(value)
    assert "owned-private" not in raw and "private-principal" not in raw


def test_named_actor_plans_do_not_change_saved_selection(actor_lab, boundaries):
    identity.use_profile("lower")
    plans = [prepare(actor) for actor in ("owner", "lower", "anonymous")]
    assert [plan.budget.state[0][1] for plan in plans] == ["owner", "lower", "anonymous"]
    assert len({plan.budget.job_id for plan in plans}) == 3
    assert identity.selected_name() == "lower"
    assert all(plan.budget.targets == frozenset({("GET", URL), ("GET", PROBE)}) for plan in plans)


@pytest.mark.parametrize("options", [
    {"mission": "another-mission"}, {"owned_lab": False}, {"requests": 0},
    {"requests": 101}, {"seconds": 0}, {"seconds": 301}, {"max_bytes": 0},
    {"max_bytes": 65537}, {"actor": "default"}, {"actor": "missing"},
    {"urls": ["https://127.0.0.1:8765/__bughunt_lab__/page"]},
    {"urls": ["http://localhost:8765/__bughunt_lab__/page"]},
    {"urls": [ORIGIN + "/outside"]}, {"urls": [URL, URL]},
])
def test_invalid_or_unbounded_browser_plan_has_no_downstream_activity(actor_lab, boundaries, options):
    with pytest.raises(ValueError):
        prepare(**options)


def test_exact_selection_does_not_implicitly_authorize_subresources_or_post(actor_lab, boundaries):
    plan = prepare()
    with identity.actor_context(plan.actor):
        for request in (httpx.Request("GET", ORIGIN + "/__bughunt_lab__/unselected"),
                        httpx.Request("POST", URL), httpx.Request("GET", URL, content=b"not-empty")):
            with pytest.raises(ValueError):
                plan.budget.check(request)


@pytest.mark.parametrize("mutate", ["credentials", "verification", "policy"])
def test_changed_authority_blocks_prepared_browser_work(actor_lab, boundaries, mutate):
    root, document = actor_lab
    plan = prepare()
    if mutate == "credentials":
        path = root / "identities" / "owner.json"
        value = json.loads(path.read_text())
        value["credentials"]["Cookie"] = "session=other-owned-actor"
    elif mutate == "verification":
        path = root / "identities" / "verification" / "owner.json"
        value = json.loads(path.read_text())
        value["expected_principal"] = "another-private-principal"
    else:
        path, value = root / "policy.json", dict(document, state="stale")
    path.write_text(json.dumps(value), encoding="utf-8")
    with identity.actor_context(plan.actor), pytest.raises(ValueError):
        plan.budget.check(httpx.Request("GET", URL))


def test_physical_budget_covers_probe_and_discriminating_request(actor_lab, boundaries):
    plan = prepare(requests=2)
    with identity.actor_context(plan.actor):
        for index, url in enumerate((PROBE, URL)):
            request = httpx.Request("GET", url, extensions={"bughunt_run_id": f"owned-run-{index}"})
            plan.budget.admit(request)
        assert [item["index"] for item in plan.budget.sent] == [1, 2]
        with pytest.raises(egress.PolicyBlocked, match="request-cap"):
            plan.budget.admit(request)
        plan.budget.cancelled.set()
        with pytest.raises(egress.PolicyBlocked, match="cancelled"):
            plan.budget.check(request)


def test_seccomp_translation_keeps_default_deny_and_only_adds_chroot(tmp_path, monkeypatch):
    original = {"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [
        {"names": ["chroot"], "action": "SCMP_ACT_ALLOW", "includes": {"caps": ["CAP_SYS_CHROOT"]}}]}
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setattr(browser_actor, "UPSTREAM_SECCOMP_SHA256", browser_actor.fingerprint(path))
    rendered = browser_actor.seccomp_profile(path)
    assert rendered["defaultAction"] == "SCMP_ACT_ERRNO"
    assert rendered["syscalls"][1:] == original["syscalls"]
    assert rendered["syscalls"][0] == {"names": ["chroot"], "action": "SCMP_ACT_ALLOW",
                                       "args": [], "includes": {}, "excludes": {}}


def test_seccomp_source_drift_is_not_accepted(tmp_path):
    path = tmp_path / "changed.json"
    path.write_text('{"defaultAction": "SCMP_ACT_ALLOW"}', encoding="utf-8")
    with pytest.raises(ValueError, match="fingerprint"):
        browser_actor.seccomp_profile(path)


def test_primary_engine_cli_previews_browser_without_a_process(actor_lab, boundaries, capsys):
    from bughunt.modules import engine as command
    assert command.main(["dry-run", "browser-owned", URL, "--actor", "owner", "--mission",
                         browser_actor.MISSION, "--owned-lab", "--requests", "4"]) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["actor"] == "owner" and value["budgets"]["physical_requests"] == 4
    assert value["dry_run"] is True


def test_primary_engine_dispatcher_keeps_the_typed_browser_plan(actor_lab, boundaries):
    from bughunt.core import engine
    plan = engine.prepare("browser-owned", URL, actors=["owner"], mission=browser_actor.MISSION, owned_lab=True)
    assert isinstance(plan, browser_actor.Plan)
    assert engine.preview(plan) == browser_actor.preview(plan)
    assert engine.descriptor(plan) == browser_actor.descriptor(plan)


def test_public_browser_plan_keeps_query_values_private(actor_lab, boundaries):
    url = URL + "?q=private-browser-query-marker"
    value = browser_actor.preview(prepare(urls=[url]))
    assert "private-browser-query-marker" not in json.dumps(value)
    assert value["permitted_targets"][0]["route"] == URL
    assert len(value["permitted_targets"][0]["url_sha256"]) == 64


@pytest.mark.parametrize("options", [{"proxy": "http://unused.example:8080"}, {"method": "POST"},
                                     {"config": "uninspected.json"}, {"offset": 0}])
def test_browser_dispatcher_does_not_silently_ignore_authority_options(actor_lab, boundaries, options):
    from bughunt.core import engine
    with pytest.raises(ValueError):
        engine.prepare("browser-owned", URL, actors=["owner"], mission=browser_actor.MISSION,
                       owned_lab=True, **options)
