"""PROXY bridge/receipt controls using HTTPX at the network edge."""

import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from bughunt.core import egress, exchange, identity, job, ledger
from bughunt.integrations import browser_actor, browser_runtime, zap_runtime
from test_browser_actor import ORIGIN, PROBE, URL, actor_lab, prepare
from test_gate import boundaries


@pytest.fixture
def started(actor_lab, tmp_path, monkeypatch):
    archive = tmp_path / "driver.tgz"
    archive.write_bytes(b"offline proxy dependency")
    source = tmp_path / "upstream.json"
    source.write_text(json.dumps({"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}))
    monkeypatch.setattr(browser_actor, "UPSTREAM_SECCOMP_SHA256", browser_actor.fingerprint(source))
    def start(**options):
        plan = prepare(**options)
        with identity.actor_context(plan.actor):
            root = browser_runtime._files(plan, archive, source)
        return plan, root
    return start


def rpc(root, url=URL, method="GET", headers=None):
    path = root / "engine" / "rpc" / "000001.req"
    exchange._write(path, {"sequence": "000001", "method": method, "url": url, "headers": headers or {}})
    return path


def client(plan, handler):
    bounded = zap_runtime._CappedTransport(job.Transport(plan.budget, httpx.MockTransport(handler)), plan.max_bytes)
    return egress.client(operation="active_scan", transport=bounded, follow_redirects=False)


def responder(sent, *, invalid=False, redirect=None):
    def respond(request):
        sent.append(request)
        actor = request.headers.get("cookie", "").removeprefix("session=owned-private-")
        if str(request.url) == PROBE:
            if not actor:
                return httpx.Response(401)
            role = "owner" if actor == "owner" else "lower_privilege"
            return httpx.Response(200, json={"user": {"id": "wrong" if invalid else "private-principal-" + actor,
                                                     "role": role}})
        if redirect is not None and str(request.url) == URL:
            return httpx.Response(302, headers={"Location": redirect})
        return httpx.Response(200, content=b"owned rendered page", headers={"Content-Type": "text/html"})
    return respond


@pytest.mark.parametrize("actor", ["owner", "lower", "anonymous"])
def test_bridge_verifies_exact_actor_and_charges_both_sends(started, boundaries, actor):
    plan, root = started(actor=actor)
    sent = []
    path = rpc(root)
    with identity.actor_context(actor), client(plan, responder(sent)) as controlled:
        result = browser_runtime.mediate(path, controlled, plan)
    reply = job._load(path.with_suffix(".resp"))
    assert not result["fatal"] and not result["denied"]
    assert [str(request.url) for request in sent] == [PROBE, URL]
    assert len(plan.budget.sent) == 2 and len(result["run_ids"]) == 1
    assert all(request.headers.get("cookie", "") == ("" if actor == "anonymous" else "session=owned-private-" + actor)
               for request in sent)
    assert base64.b64decode(reply["body"]) == b"owned rendered page"


@pytest.mark.parametrize("options", [
    {"url": ORIGIN + "/__bughunt_lab__/unselected"}, {"method": "POST"},
    {"headers": {"Authorization": "Bearer stale-other-actor"}},
])
def test_unselected_or_credential_carrying_browser_rpc_never_sends(started, boundaries, options):
    plan, root = started()
    sent = []
    with identity.actor_context(plan.actor), client(plan, responder(sent)) as controlled:
        result = browser_runtime.mediate(rpc(root, **options), controlled, plan)
    assert result["fatal"] or result["denied"]
    assert sent == [] and plan.budget.sent == []


@pytest.mark.parametrize("mode", ["invalid-actor", "cap"])
def test_failed_assertion_or_single_request_cap_stops_before_page(started, boundaries, mode):
    plan, root = started(requests=1 if mode == "cap" else 20)
    sent = []
    with identity.actor_context(plan.actor), client(plan, responder(sent, invalid=mode == "invalid-actor")) as controlled:
        result = browser_runtime.mediate(rpc(root), controlled, plan)
    assert result["fatal"] and [str(request.url) for request in sent] == [PROBE]
    assert len(plan.budget.sent) == 1


@pytest.mark.parametrize("selected", [False, True])
def test_redirects_are_walked_per_verified_selected_hop(started, boundaries, selected):
    destination = ORIGIN + "/__bughunt_lab__/next"
    plan, root = started(urls=[URL, destination] if selected else [URL])
    sent = []
    with identity.actor_context(plan.actor), client(plan, responder(sent, redirect=destination)) as controlled:
        result = browser_runtime.mediate(rpc(root), controlled, plan)
    assert not result["fatal"] and result["denied"] is not selected
    assert [str(request.url) for request in sent] == ([PROBE, URL, PROBE, destination] if selected else [PROBE, URL])
    assert len(plan.budget.sent) == len(sent)


def complete_proxy(plan, root):
    observed = {"body_sha256": "a" * 64, "storage_sha256": "b" * 64,
        "final_url": URL, "renderers": [{"no_sandbox_flag": False, "seccomp": 2, "no_new_privileges": 1}],
        "job_id": plan.budget.job_id, "actor": plan.actor, "initial_storage_empty": True,
        "generated_requests": 1, "blocked_websockets": 0, "complete": True}
    exchange._write(root / "engine" / "browser-result.json", observed)
    return observed


def test_cancel_at_completion_cannot_be_an_observation(started, boundaries):
    plan, root = started()
    sent = []
    with identity.actor_context(plan.actor), client(plan, responder(sent)) as controlled:
        attempt = browser_runtime.mediate(rpc(root), controlled, plan)
        complete_proxy(plan, root)
        plan.budget.cancelled.set()
        result = browser_runtime._finish(plan, root, [attempt], "consumer-completed", 0, True)
    assert result["classification"] == "inconclusive" and result["state"] == "cancelled"


@pytest.mark.parametrize("mutate", ["hash", "sandbox", "extra-field", "missing-url", "invalid-url-type", "oversized-final"])
def test_unbound_or_unsandboxed_consumer_observation_cannot_succeed(started, boundaries, mutate):
    plan, root = started()
    sent = []
    with identity.actor_context(plan.actor), client(plan, responder(sent)) as controlled:
        attempt = browser_runtime.mediate(rpc(root), controlled, plan)
        observed = complete_proxy(plan, root)
        if mutate == "hash":
            observed["body_sha256"] = "not-a-hash"
        elif mutate == "sandbox":
            observed["renderers"][0]["no_sandbox_flag"] = True
        elif mutate == "missing-url":
            observed.pop("final_url")
        elif mutate == "invalid-url-type":
            observed["final_url"] = []
        elif mutate == "oversized-final":
            pass
        else:
            observed["unexpected"] = "not-bound-by-schema"
        exchange._write(root / "engine" / "browser-result.json", observed)
        if mutate == "oversized-final":
            path = root / "engine" / "browser-result.json"
            path.write_bytes(path.read_bytes() + b" " * 200001)
        result = browser_runtime._finish(plan, root, [attempt], "consumer-completed", 0, True)
    assert result["classification"] == "inconclusive" and result["state"] != "success"
    assert result["reason"] == "browser-evidence-incomplete"
    assert ledger.manifest_for(result["run_id"])["analysis"]["observation"] is None


@pytest.mark.parametrize("relative", ["rpc/READY.tmp", "rpc/000001.req.tmp", "browser-result.json.tmp"])
def test_output_scan_tolerates_only_known_atomic_publication(started, monkeypatch, relative):
    _plan, root = started()
    pending = root / "engine" / relative
    pending.write_bytes(b"{}")
    original_stat, original_lstat, renamed = os.stat, os.lstat, []
    def publish(path, original, *args, **kwargs):
        if isinstance(path, (str, os.PathLike)) and os.fspath(path) == str(pending) and not renamed:
            renamed.append(True)
            Path(path).replace(pending.with_suffix(""))
        return original(path, *args, **kwargs)
    monkeypatch.setattr(os, "stat", lambda path, *args, **kwargs: publish(path, original_stat, *args, **kwargs))
    monkeypatch.setattr(os, "lstat", lambda path, *args, **kwargs: publish(path, original_lstat, *args, **kwargs))
    browser_runtime._outputs(root)
    assert renamed and pending.with_suffix("").exists()


@pytest.mark.parametrize("relative", ["rpc/READY", "rpc/000001.req", "rpc/000129.req.tmp", "unknown.tmp"])
def test_output_scan_rejects_other_disappearing_paths(started, monkeypatch, relative):
    _plan, root = started()
    pending = root / "engine" / relative
    pending.write_bytes(b"{}")
    original_stat, original_lstat, removed = os.stat, os.lstat, []
    def disappear(path, original, *args, **kwargs):
        if isinstance(path, (str, os.PathLike)) and os.fspath(path) == str(pending) and not removed:
            removed.append(True)
            Path(path).unlink()
        return original(path, *args, **kwargs)
    monkeypatch.setattr(os, "stat", lambda path, *args, **kwargs: disappear(path, original_stat, *args, **kwargs))
    monkeypatch.setattr(os, "lstat", lambda path, *args, **kwargs: disappear(path, original_lstat, *args, **kwargs))
    with pytest.raises(FileNotFoundError):
        browser_runtime._outputs(root)
    assert removed


@pytest.mark.parametrize("mode", ["oversized", "symlink-guard"])
def test_unsealable_artifact_retains_private_bytes_and_terminal_receipt(started, boundaries, monkeypatch, mode):
    plan, root = started()
    sent = []
    with identity.actor_context(plan.actor), client(plan, responder(sent)) as controlled:
        attempt = browser_runtime.mediate(rpc(root), controlled, plan)
        complete_proxy(plan, root)
        rejected = root / "engine" / "browser-result.json"
        if mode == "oversized":
            rejected.write_bytes(b"x" * (exchange.INPUT_LIMIT + 1))
        else:
            original = Path.is_symlink
            monkeypatch.setattr(Path, "is_symlink", lambda path: path == rejected or original(path))
        result = browser_runtime._finish(plan, root, [attempt], "consumer-completed", 0, True)
    assert result["classification"] == "inconclusive" and result["state"] == "partial"
    assert result["reason"] == "browser-evidence-incomplete" and rejected.exists()
    assert result["rejected_artifacts"] == [{"path": "engine/browser-result.json", "reason": "unsealable-artifact"}]
    assert "engine/browser-result.json" not in {row["path"] for row in result["artifacts"]}
    assert job.status(result["job_id"]) == result
    assert ledger.manifest_for(result["run_id"])["analysis"]["observation"] is None
    assert ledger.export_run(result["run_id"])


def test_command_has_no_personal_mounts_or_unconfined_execution(started):
    plan, root = started()
    args = browser_runtime.command(plan, root, "whk027-" + plan.budget.job_id, root / "input" / "driver.tgz")
    assert args[args.index("--network") + 1] == "none"
    assert args[args.index("--user") + 1] == "1000:1000"
    assert args[args.index("--cap-drop") + 1] == "ALL"
    assert "--read-only" in args and "--init" in args
    assert not any(value in args for value in ("--privileged", "--cap-add", "--publish", "--ipc", "--no-sandbox"))


def container_metadata(plan, root):
    identifier = "a" * 64
    (root / "consumer.cid").write_text(identifier)
    return {"Id": identifier, "Image": browser_actor.IMAGE.split("@", 1)[1],
        "Config": {"User": "1000:1000", "Labels": {"bughunt.job": plan.budget.job_id}},
        "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
            "CapAdd": [], "CapDrop": ["ALL"], "PidMode": "", "IpcMode": "private", "PortBindings": {},
            "Memory": 2147483648, "NanoCpus": 1000000000, "PidsLimit": 256, "ShmSize": 134217728,
            "SecurityOpt": ["no-new-privileges", "seccomp=" + json.dumps(job._load(root / "input" / "seccomp.json"))]},
        "Mounts": [{"Type": "bind", "Destination": name, "RW": name == "/proof"} for name in
                   ("/bughunt/consumer.cjs", "/bughunt/driver.tgz", "/bughunt/input", "/proof")]}


@pytest.mark.parametrize("change", ["nnp", "memory", "cpu", "pids", "identity"])
def test_actual_container_contract_rejects_disabled_guards(started, monkeypatch, change):
    plan, root = started()
    value = container_metadata(plan, root)
    if change == "nnp":
        value["HostConfig"]["SecurityOpt"][0] = "no-new-privileges:false"
    elif change == "identity":
        value["Config"]["Labels"]["bughunt.job"] = "another-job"
    else:
        value["HostConfig"][{"memory": "Memory", "cpu": "NanoCpus", "pids": "PidsLimit"}[change]] = 0
    monkeypatch.setattr(browser_runtime.subprocess, "run", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=0, stdout=exchange.canonical(value)))
    with pytest.raises(ValueError):
        browser_runtime._container("whk027-" + plan.budget.job_id, root)


@pytest.mark.parametrize("foreign", [False, True])
@pytest.mark.parametrize("fault", ["none", "stop-write", "late-cid"])
def test_cleanup_uses_owned_immutable_container_identity_only(started, monkeypatch, foreign, fault):
    plan, root = started()
    value = container_metadata(plan, root)
    if foreign:
        value["Config"]["Labels"]["bughunt.job"] = "foreign-container"
    calls = []
    def invoke(args, **_options):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout=exchange.canonical(value) if args[1] == "inspect" else b"")
    monkeypatch.setattr(browser_runtime.subprocess, "run", invoke)
    process = SimpleNamespace(poll=lambda: 0, wait=lambda **_options: 0)
    if fault == "stop-write":
        def blocked_stop(*_args, **_kwargs):
            raise OSError("Injected STOP publication failure")
        monkeypatch.setattr(ledger, "_write_private", blocked_stop)
    elif fault == "late-cid":
        (root / "consumer.cid").unlink()
        exited = []
        process = SimpleNamespace(poll=lambda: 0 if exited else None,
                                  wait=lambda **_options: exited.append(True) or 0)
        monkeypatch.setattr(browser_runtime.time, "sleep", lambda _seconds:
                            (root / "consumer.cid").write_text(value["Id"]))
    cleaned = browser_runtime._cleanup(process, root, plan)
    destructive = [args for args in calls if args[1] in {"stop", "rm"}]
    assert cleaned is not foreign
    if foreign:
        assert destructive == []
    else:
        assert destructive and all(args[-1] == "a" * 64 for args in destructive)
