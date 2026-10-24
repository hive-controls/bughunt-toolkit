"""Owned offline two-account and anonymous replay laboratory."""

import asyncio
import hashlib
import json

import httpx
import pytest

import bughunt
from bughunt.core import egress, identity, ledger, verification
from bughunt.labs import replay
from bughunt.modules.repeater import parse_raw
from bughunt.modules import load_builtin, replay as replay_command
from bughunt.console.catalog import group_for
from test_gate import boundaries, policy
from test_verification import _configure


def test_actor_context_is_private_and_preserves_saved_selection(policy):
    _configure("owner")
    _configure(
        "guest",
        "anonymous",
        expected_status=401,
        expected_principal=None,
        expected_role=None,
    )
    assert identity.selected_name() == "guest"
    with identity.actor_context("owner"):
        assert identity.selected_name() == "owner"
        with identity.actor_context("guest"):
            assert identity.selected_name() == "guest"
        assert identity.selected_name() == "owner"
    assert identity.selected_name() == "guest"


def test_verified_send_can_stream_and_exposes_exchange_id(policy):
    _configure()
    consumed = []

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            consumed.append(True)
            yield b"private record"

    def respond(request):
        if request.url.path == "/whoami":
            return httpx.Response(
                200, json={"user": {"id": "person-1", "role": "owner"}}
            )
        return httpx.Response(200, stream=Stream())

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        response = verification.verify_and_send(
            client,
            client.build_request("GET", "https://allowed.example/records/owned"),
            stream=True,
        )
        assert consumed == []
        assert response.extensions["bughunt_run_id"]
        response.close()


def _lab(outcome="negative"):
    for name, kind, role in (
        ("owner", "owner", "owner"),
        ("viewer", "lower_privilege", "viewer"),
        ("guest", "anonymous", None),
    ):
        _configure(
            name,
            kind,
            expected_status=401 if kind == "anonymous" else 200,
            expected_principal=None if kind == "anonymous" else "person-" + name,
            expected_role=role,
        )
    seen, state = [], {"count": 0}

    def respond(request):
        authorization = request.headers.get("authorization")
        actor = (
            "owner"
            if authorization == "Bearer private-token-owner"
            else (
                "viewer" if authorization == "Bearer private-token-viewer" else "guest"
            )
        )
        seen.append(
            (
                actor,
                request.url.path,
                request.method,
                request.content,
                list(request.headers.multi_items()),
            )
        )
        if request.url.path == "/whoami":
            if actor == "guest":
                return httpx.Response(401)
            principal = (
                "wrong-person"
                if outcome == "invalid" and actor == "viewer"
                else "person-" + actor
            )
            return httpx.Response(
                200,
                json={
                    "user": {
                        "id": principal,
                        "role": "viewer" if actor == "viewer" else "owner",
                    }
                },
            )
        if request.url.path == "/state":
            assert actor == "owner"
            return httpx.Response(200, json=state)
        permitted = actor == "owner" or outcome in {"lead", "mutating-lead"}
        if request.method == "POST" and permitted and outcome != "no-owner-effect":
            state["count"] += 1
        if not permitted:
            if outcome == "different":
                return httpx.Response(200, json={"public": True})
            return httpx.Response(403, json={"error": "denied"})
        headers = {"Content-Type": "application/json"}
        if outcome == "cache":
            headers["Age"] = "10"
        if outcome == "redirect":
            return httpx.Response(302, headers={"Location": "/other"})
        if outcome == "partial":
            return httpx.Response(200, content=b"x" * 1025)
        if outcome == "ambiguous":
            return httpx.Response(200, headers=headers, content=b'{"id":1,"id":2}')
        body = (
            b'{"id":7,"private":"owned record"}'
            if actor == "owner"
            else b'{"private":"owned record","id":7}'
        )
        return httpx.Response(200, headers=headers, content=body)

    return httpx.MockTransport(respond), seen, state


def _plan(method="GET", *, observe=False, body=b"", max_bytes=65536, source=None):
    raw = (
        f"{method} https://allowed.example/records/owned?version=7 HTTP/1.1\r\nHost: allowed.example\r\n"
        "Cookie: captured-secret\r\nAuthorization: captured-token\r\n"
        "X-Trace: preserve-me\r\n"
        + (f"Content-Length: {len(body)}\r\n" if body else "")
        + "\r\n"
    ).encode() + body
    return replay.prepare(
        parse_raw(raw),
        source or raw,
        ("owner", "viewer", "guest"),
        observe_url="https://allowed.example/state" if observe else None,
        max_bytes=max_bytes,
    )


def _api_options(path, **options):
    return {
        "request": str(path),
        "owner": "owner",
        "lower": "viewer",
        "anonymous": "guest",
        **options,
    }


@pytest.mark.parametrize("explicit", [False, True])
def test_api_replay_preview_validates_real_plan_without_effects(
    policy, boundaries, monkeypatch, capsys, explicit
):
    from bughunt.core import route

    monkeypatch.setattr(route, "gate", boundaries)
    _lab()
    path = policy[1] / "request.http"
    source = _plan().source
    path.write_bytes(source)
    before = {
        item: item.read_bytes() for item in policy[1].rglob("*") if item.is_file()
    }
    result = bughunt.run_module(
        "replay", options=_api_options(path, dry_run=not explicit), dry_run=explicit
    )
    assert result.status == "planned", result.to_dict()
    preview = result.artifacts[0].payload["items"][0]["attributes"]
    assert preview["baseline_sha256"] == hashlib.sha256(source).hexdigest()
    assert preview["actors"] == ["owner", "viewer", "guest"]
    assert preview["network_requests"] == 0
    assert result.dry_run is True and result.evidence == []
    assert "captured-secret" not in json.dumps(result.to_dict())
    assert capsys.readouterr().out == ""
    after = {item: item.read_bytes() for item in policy[1].rglob("*") if item.is_file()}
    assert after == before


@pytest.mark.parametrize("explicit", [False, True])
@pytest.mark.parametrize("baseline", [None, b"malformed request"])
def test_api_replay_preview_rejects_missing_or_malformed_baseline(
    policy, boundaries, explicit, baseline
):
    _lab()
    path = policy[1] / "request.http"
    if baseline is not None:
        path.write_bytes(baseline)
    result = bughunt.run_module(
        "replay", options=_api_options(path, dry_run=not explicit), dry_run=explicit
    )
    assert result.status == "invalid", result.to_dict()
    assert result.evidence == []
    assert not ledger.runs_dir().exists()


@pytest.mark.parametrize(
    "outcome,classification,status",
    [
        ("negative", "negative", "success"),
        ("different", "inconclusive", "partial"),
        ("invalid", "invalid", "partial"),
    ],
)
def test_api_replay_returns_domain_values_and_actual_ledger_evidence(
    policy, monkeypatch, capsys, outcome, classification, status
):
    transport, seen, _state = _lab(outcome)
    original = replay.execute
    monkeypatch.setattr(
        replay, "execute", lambda plan: original(plan, transport=transport)
    )
    path = policy[1] / "request.http"
    source = _plan().source
    path.write_bytes(source)
    result = bughunt.run_module("replay", options=_api_options(path))
    assert result.status == status, result.to_dict()
    artifact = result.artifacts[0].payload
    manifest = artifact["items"][0]["attributes"]
    assert artifact["classification"] == classification
    assert manifest["automatic_finding"] is False
    assert manifest["attempts"] and seen
    assert manifest["run_id"] in artifact["source_run_ids"]
    evidence_ids = {item["run_id"] for item in result.evidence}
    assert manifest["run_id"] in evidence_ids
    assert manifest["positive_baseline_run_id"] in evidence_ids
    assert (
        ledger.runs_dir() / manifest["run_id"] / "source.http"
    ).read_bytes() == source
    for receipt in result.evidence:
        exported = ledger.export_run(receipt["run_id"])
        from bughunt.core import exchange

        assert receipt["sha256"] == exchange.digest(exchange.canonical(exported))
    serialized = json.dumps(result.to_dict())
    assert all(
        secret not in serialized
        for secret in (
            "captured-secret",
            "captured-token",
            "private-token",
            "owned record",
        )
    )
    assert identity.selected_name() == "guest"
    assert capsys.readouterr().out == ""


def test_api_replay_body_edit_retains_original_capture(policy, monkeypatch):
    transport, seen, _state = _lab()
    original = replay.execute
    monkeypatch.setattr(
        replay, "execute", lambda plan: original(plan, transport=transport)
    )
    path = policy[1] / "request.http"
    source = _plan("POST", body=b"old").source
    path.write_bytes(source)
    body_path = policy[1] / "new-body.json"
    body_path.write_bytes(b'{"new":true}')
    result = bughunt.run_module(
        "replay",
        options=_api_options(
            path, body_file=str(body_path), observe="https://allowed.example/state"
        ),
    )
    assert result.status == "success", result.to_dict()
    manifest = result.artifacts[0].payload["items"][0]["attributes"]
    assert manifest["classification"] == "negative"
    assert (
        ledger.runs_dir() / manifest["run_id"] / "source.http"
    ).read_bytes() == source
    requests = [item for item in seen if item[1] == "/records/owned"]
    assert len(requests) == 3
    assert all(item[3] == b'{"new":true}' for item in requests)


def test_replay_preparation_rejects_workspace_scope_before_traffic(policy, boundaries):
    _document, workspace = policy
    _transport, seen, _state = _lab()
    (workspace / "scope.txt").write_text("unrelated.example\n")
    with pytest.raises(ValueError, match="workspace-scope"):
        _plan(observe=True)
    assert seen == []


def test_replay_execution_rechecks_revoked_workspace_scope(policy, boundaries):
    _document, workspace = policy
    transport, seen, _state = _lab()
    plan = _plan(observe=True)
    (workspace / "scope.txt").write_text("unrelated.example\n")
    result = replay.execute(plan, transport=transport)
    assert result["classification"] == "invalid"
    assert seen == []


@pytest.mark.parametrize("foreign", ["target", "observer", "probe"])
def test_replay_preflight_requires_same_origin_verification(
    policy, boundaries, foreign
):
    _document, workspace = policy
    _transport, seen, _state = _lab()
    for name in ("owner", "viewer", "guest"):
        profile = identity.read_profile(name)
        profile["origins"].append("https://api.example")
        identity._write_private(identity._profile_path(name), profile)
    (workspace / "scope.txt").write_text("allowed.example\napi.example\n")
    if foreign == "probe":
        verification.configure(
            "viewer",
            "https://api.example/whoami",
            "user.id",
            "person-viewer",
            "user.role",
            "viewer",
        )
    host = "api.example" if foreign == "target" else "allowed.example"
    raw = f"GET https://{host}/private HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    observer = "https://api.example/state" if foreign == "observer" else None
    with pytest.raises(
        verification.VerificationError, match="verification-origin-mismatch"
    ):
        replay.prepare(
            parse_raw(raw), raw, ("owner", "viewer", "guest"), observe_url=observer
        )
    assert seen == []


@pytest.mark.parametrize(
    "outcome,expected",
    [
        ("negative", "negative"),
        ("lead", "lead"),
        ("invalid", "invalid"),
        ("different", "inconclusive"),
        ("cache", "inconclusive"),
        ("partial", "inconclusive"),
        ("ambiguous", "inconclusive"),
        ("redirect", "invalid"),
    ],
)
def test_four_outcomes_preserve_baseline_and_never_promote(policy, outcome, expected):
    transport, seen, _state = _lab(outcome)
    plan = _plan(max_bytes=1024)
    result = replay.execute(plan, transport=transport)
    assert result["classification"] == expected
    assert result["automatic_finding"] is False
    assert "severity" not in result and "finding" not in result
    assert result["positive_baseline_run_id"]
    assert identity.selected_name() == "guest"
    assert "captured-secret" not in json.dumps(result)
    assert "owned record" not in json.dumps(result)
    assert len([item for item in seen if item[1] == "/other"]) == 0
    assert ledger.manifest_for(result["run_id"])["classification"] == expected


def test_same_request_fields_fresh_assertions_and_evidence(policy):
    transport, seen, _state = _lab()
    plan = _plan()
    result = replay.execute(plan, transport=transport)
    assert [item[1] for item in seen] == ["/whoami", "/records/owned"] * 3
    requests = [item for item in seen if item[1] == "/records/owned"]
    fingerprints = []
    for actor, _path, method, body, headers in requests:
        assert method == "GET" and body == b""
        pairs = dict(headers)
        assert pairs["x-trace"] == "preserve-me"
        assert "cookie" not in pairs
        assert pairs.get("authorization") == (
            None if actor == "guest" else "Bearer private-token-" + actor
        )
        fingerprints.append(
            [(key, value) for key, value in headers if key != "authorization"]
        )
    assert fingerprints[0] == fingerprints[1] == fingerprints[2]
    root = ledger.runs_dir() / result["run_id"]
    assert (root / "source.http").read_bytes() == plan.source
    assert result["source"]["sha256"] == hashlib.sha256(plan.source).hexdigest()
    for attempt in result["attempts"]:
        manifest = ledger.manifest_for(attempt["run_id"])
        assert manifest["actor"] == attempt["actor"]
        assert manifest["response"] and manifest["verification_run_id"]


@pytest.mark.parametrize(
    "outcome,observe,expected",
    [
        ("negative", False, "inconclusive"),
        ("negative", True, "negative"),
        ("mutating-lead", True, "lead"),
        ("no-owner-effect", True, "invalid"),
    ],
)
def test_state_changes_require_explicit_before_after_observations(
    policy, outcome, observe, expected
):
    transport, seen, state = _lab(outcome)
    result = replay.execute(
        _plan("POST", observe=observe, body=b'{"change":true}'), transport=transport
    )
    assert result["classification"] == expected
    target_requests = [item for item in seen if item[1] == "/records/owned"]
    assert all(item[2:4] == ("POST", b'{"change":true}') for item in target_requests)
    if observe:
        assert result["attempts"][0]["side_effects"]["before_run_id"]
        assert result["attempts"][0]["side_effects"]["after_run_id"]
        assert state["count"] == (
            3
            if outcome == "mutating-lead"
            else 0
            if outcome == "no-owner-effect"
            else 1
        )


def test_failed_verification_stops_replay_and_records_invalid(policy):
    transport, seen, _state = _lab("invalid")
    result = replay.execute(_plan(), transport=transport)
    assert result["classification"] == "invalid"
    assert [item[0] for item in seen if item[1] == "/records/owned"] == ["owner"]
    assert result["attempts"][-1]["error"] == "VerificationError"
    assert any(
        ledger.manifest_for(path.name)["classification"] == "invalid"
        for path in ledger.runs_dir().iterdir()
    )


def test_changed_actor_or_policy_is_invalid_before_any_transport(policy):
    transport, seen, _state = _lab()
    plan = _plan()
    identity.set_credential("viewer", "authorization", "Bearer changed-token")
    result = replay.execute(plan, transport=transport)
    assert result["classification"] == "invalid" and seen == []


@pytest.mark.parametrize(
    "raw",
    [
        b"GET / HTTP/1.1\r\nHost: allowed.example\r\nHost: allowed.example\r\n\r\n",
        b"POST / HTTP/1.1\r\nHost: allowed.example\r\nContent-Length: 10\r\n\r\nx",
        b"POST / HTTP/1.1\r\nHost: allowed.example\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"GET https://allowed.example/ HTTP/1.1\r\nHost: api.example\r\n\r\n",
    ],
)
def test_malformed_baselines_stay_inert(policy, raw):
    _lab()
    with pytest.raises(replay.ReplayError):
        replay.prepare(parse_raw(raw), raw, ("owner", "viewer", "guest"))


def test_preflight_and_preview_do_not_contact_any_boundary(policy, monkeypatch):
    _lab()

    def forbidden(*args, **kwargs):
        raise AssertionError("Network reached during dry-run")

    monkeypatch.setattr(egress, "client", forbidden)
    plan = _plan()
    assert replay.preview(plan)["network_requests"] == 0
    assert not ledger.runs_dir().exists()


def test_matching_private_body_with_changed_headers_is_not_negative(policy):
    transport, _seen, _state = _lab()

    def respond(request):
        response = transport.handle_request(request)
        if (
            request.url.path == "/records/owned"
            and identity.selected_name() == "viewer"
        ):
            return httpx.Response(
                403,
                headers={"Content-Type": "text/plain"},
                content=b'{"id":7,"private":"owned record"}',
            )
        return response

    result = replay.execute(_plan(), transport=httpx.MockTransport(respond))
    # Different content types need manual interpretation; this is not a proven denial.
    assert result["comparisons"][0]["classification"] == "inconclusive"


def test_json_state_observation_distinguishes_boolean_from_number():
    before = ({"run_id": "before"}, {"enabled": True})
    after = ({"run_id": "after"}, {"enabled": 1})
    assert replay._effects(before, after)["changed_count"] == 1


def test_state_change_after_send_preserves_actual_exchange_link(policy):
    transport, seen, _state = _lab()
    plan = _plan()

    def respond(request):
        response = transport.handle_request(request)
        if request.url.path == "/records/owned":
            identity.set_credential("viewer", "authorization", "Bearer changed-token")
        return response

    result = replay.execute(plan, transport=httpx.MockTransport(respond))
    assert result["classification"] == "invalid"
    assert result["attempts"][0]["run_id"]
    assert result["positive_baseline_run_id"]
    assert [item[0] for item in seen if item[1] == "/records/owned"] == ["owner"]


def test_baseline_larger_than_capture_limit_is_rejected(policy):
    _lab()
    raw = (
        b"GET https://allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\nX-Note: "
        + b"x" * ledger.CAPTURE_LIMIT
        + b"\r\n\r\n"
    )
    with pytest.raises(replay.ReplayError, match="baseline-too-large"):
        replay.prepare(parse_raw(raw), raw, ("owner", "viewer", "guest"))


def test_cli_dry_run_is_registered_and_secret_safe(policy, monkeypatch, capsys):
    _lab()
    path = policy[1] / "request.http"
    path.write_bytes(_plan().source)

    def forbidden(*args, **kwargs):
        raise AssertionError("Dry-run sent a request")

    monkeypatch.setattr(egress, "client", forbidden)
    assert load_builtin("replay") is replay_command and group_for("replay") == "Test"
    assert (
        replay_command.main(
            [
                str(path),
                "--owner",
                "owner",
                "--lower",
                "viewer",
                "--anonymous",
                "guest",
                "--dry-run",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    assert json.loads(output)["network_requests"] == 0
    assert "captured-secret" not in output and "private-token" not in output
    assert not ledger.runs_dir().exists()


def test_cli_explicit_body_edit_preserves_source_and_replays_edited_copy(
    policy, monkeypatch, capsys
):
    transport, seen, _state = _lab()
    original = egress.client

    def client(**kwargs):
        return original(**dict(kwargs, transport=transport))

    monkeypatch.setattr(egress, "client", client)
    path = policy[1] / "request.http"
    source = _plan("POST", body=b"old").source
    path.write_bytes(source)
    body_path = policy[1] / "new-body.json"
    body_path.write_bytes(b'{"new":true}')
    status = replay_command.main(
        [
            str(path),
            "--owner",
            "owner",
            "--lower",
            "viewer",
            "--anonymous",
            "guest",
            "--body-file",
            str(body_path),
            "--observe",
            "https://allowed.example/state",
        ]
    )
    assert status == 0
    result = json.loads(capsys.readouterr().out)
    assert result["classification"] == "negative"
    assert (ledger.runs_dir() / result["run_id"] / "source.http").read_bytes() == source
    assert all(
        item[3] == b'{"new":true}' for item in seen if item[1] == "/records/owned"
    )


def test_cli_invalid_profile_does_not_leak_error_values(policy, capsys):
    _lab()
    path = policy[1] / "request.http"
    path.write_bytes(_plan().source)
    assert (
        replay_command.main(
            [str(path), "--owner", "guest", "--lower", "viewer", "--anonymous", "owner"]
        )
        == 2
    )
    assert "Replay blocked" in capsys.readouterr().out
    assert not ledger.runs_dir().exists()


def test_stream_error_keeps_sent_exchange_link(policy):
    transport, _seen, _state = _lab()

    class Broken(httpx.SyncByteStream):
        def __iter__(self):
            yield b"partial"
            raise httpx.ReadError("synthetic stream failure")

    def respond(request):
        if request.url.path == "/records/owned":
            return httpx.Response(200, stream=Broken())
        return transport.handle_request(request)

    result = replay.execute(_plan(), transport=httpx.MockTransport(respond))
    assert result["classification"] == "invalid"
    exchange = ledger.manifest_for(result["attempts"][0]["run_id"])
    assert exchange["response"]["truncated"] is True


def test_observer_error_does_not_replace_target_exchange_link(policy):
    transport, _seen, _state = _lab()
    observations = []

    class Broken(httpx.SyncByteStream):
        def __iter__(self):
            raise httpx.ReadError("synthetic observation failure")
            yield b""

    def respond(request):
        if request.url.path == "/state":
            observations.append(True)
            if len(observations) == 2:
                return httpx.Response(200, stream=Broken())
        return transport.handle_request(request)

    result = replay.execute(
        _plan("POST", observe=True), transport=httpx.MockTransport(respond)
    )
    attempt = result["attempts"][0]
    assert result["classification"] == "invalid"
    assert "/records/owned" in ledger.manifest_for(attempt["run_id"])["target"]
    assert attempt["observation_error_exchange"]["run_id"]


def test_actor_contexts_do_not_bleed_between_async_tasks(policy):
    _lab()

    async def selected(name):
        with identity.actor_context(name):
            await asyncio.sleep(0)
            return identity.selected_name()

    async def run():
        return await asyncio.gather(
            selected("owner"), selected("viewer"), selected("guest")
        )

    assert asyncio.run(run()) == ["owner", "viewer", "guest"]
    assert identity.selected_name() == "guest"


def test_distinct_principals_and_actor_kinds_are_required(policy):
    _lab()
    plan = _plan()
    verification.configure(
        "viewer",
        "https://allowed.example/whoami",
        "user.id",
        "person-owner",
        "user.role",
        "viewer",
    )
    with pytest.raises(replay.ReplayError, match="distinct-owned-principals-required"):
        replay.prepare(parse_raw(plan.source), plan.source, plan.actors)
    with pytest.raises(replay.ReplayError, match="actor-kind-mismatch"):
        replay.prepare(
            parse_raw(plan.source), plan.source, ("guest", "viewer", "owner")
        )


@pytest.mark.parametrize("state", ["missing", "stale", "excluded", "disallowed"])
def test_replay_preflight_denials_stop_before_dns_socket_or_transport(
    policy, boundaries, state
):
    _lab()
    document, root = policy
    raw = _plan().source
    if state == "missing":
        (root / "policy.json").unlink()
    else:
        if state == "stale":
            document["state"] = "stale"
        elif state == "excluded":
            document["exclusions"] = [
                {"id": "denied", "origin": "https://allowed.example", "paths": ["/"]}
            ]
        else:
            document["permissions"]["manual"] = False
        (root / "policy.json").write_text(json.dumps(document))
    with pytest.raises(egress.PolicyBlocked):
        replay.prepare(parse_raw(raw), raw, ("owner", "viewer", "guest"))
    assert not ledger.runs_dir().exists()


def test_policy_change_between_prepare_and_execute_records_invalid_without_send(policy):
    transport, seen, _state = _lab()
    plan = _plan()
    document, root = policy
    document["user_agent"] = "changed-policy-agent"
    (root / "policy.json").write_text(json.dumps(document))
    result = replay.execute(plan, transport=transport)
    assert result["classification"] == "invalid" and seen == []


def test_denied_write_with_owner_body_is_not_a_negative(policy):
    transport, _seen, _state = _lab()

    def respond(request):
        response = transport.handle_request(request)
        if (
            request.url.path == "/records/owned"
            and identity.selected_name() == "viewer"
        ):
            return httpx.Response(
                403,
                headers={"Content-Type": "application/json"},
                content=b'{"id":7,"private":"owned record"}',
            )
        return response

    result = replay.execute(
        _plan("POST", observe=True), transport=httpx.MockTransport(respond)
    )
    assert result["comparisons"][0]["classification"] == "lead"


def test_nonfinite_observer_json_is_invalid_and_stops_target(policy):
    transport, seen, _state = _lab()

    def respond(request):
        if request.url.path == "/state":
            return httpx.Response(200, content=b'{"counter":1e9999}')
        return transport.handle_request(request)

    result = replay.execute(
        _plan("POST", observe=True), transport=httpx.MockTransport(respond)
    )
    assert result["classification"] == "invalid"
    assert not [item for item in seen if item[1] == "/records/owned"]
    assert ledger.manifest_for(result["run_id"])["finished_at"]


@pytest.mark.parametrize(
    "raw",
    [
        b"GET https://user:pass@allowed.example/ HTTP/1.1\r\nHost: allowed.example\r\n\r\n",
        b"GET https://allowed.example/ HTTP/1.1 ignored\r\nHost: allowed.example\r\n\r\n",
    ],
)
def test_ambiguous_source_request_line_is_not_silently_normalized(policy, raw):
    _lab()
    with pytest.raises(replay.ReplayError):
        replay.prepare(parse_raw(raw), raw, ("owner", "viewer", "guest"))
