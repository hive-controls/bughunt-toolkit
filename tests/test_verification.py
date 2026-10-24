"""Offline identity assertions and one-use request proofs."""

import asyncio
import json
import threading
import time

import httpx
import pytest

from bughunt.core import egress, identity, ledger, verification
from bughunt.modules import verify as verify_command
from test_gate import policy


def _configure(
    name="owner",
    kind="owner",
    *,
    expected_status=200,
    expected_principal="person-1",
    expected_role="owner",
    **overrides,
):
    identity.create_profile(name, kind, ["https://allowed.example"], owned=True)
    if kind != "anonymous":
        identity.set_credential(name, "authorization", "Bearer private-token-" + name)
    identity.use_profile(name)
    options = {
        "expected_status": expected_status,
        "max_bytes": 65536,
        "timeout_seconds": 5,
        "ttl_seconds": 5,
    }
    options.update(overrides)
    verification.configure(
        name,
        "https://allowed.example/whoami",
        None if kind == "anonymous" else "user.id",
        expected_principal,
        None if kind == "anonymous" else "user.role",
        expected_role,
        **options,
    )


def _runs():
    return [
        json.loads(path.read_text())
        for path in ledger.runs_dir().glob("*/manifest.json")
    ]


def _allow_second_owned_origin(policy, name="owner"):
    _document, workspace = policy
    profile = identity.read_profile(name)
    profile["origins"].append("https://api.example")
    identity._write_private(identity._profile_path(name), profile)
    (workspace / "scope.txt").write_text("allowed.example\napi.example\n")


@pytest.mark.parametrize("asynchronous", [False, True])
def test_cross_origin_verified_send_blocks_before_probe(policy, asynchronous):
    _configure()
    _allow_second_owned_origin(policy)
    seen = []

    def respond(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={"user": {"id": "person-1", "role": "owner"}})

    async def run():
        async with egress.async_client(
            transport=httpx.MockTransport(respond)
        ) as client:
            with pytest.raises(
                verification.VerificationError, match="verification-origin-mismatch"
            ):
                await verification.verify_and_send_async(
                    client, client.build_request("GET", "https://api.example/private")
                )

    if asynchronous:
        asyncio.run(run())
    else:
        with egress.client(transport=httpx.MockTransport(respond)) as client:
            with pytest.raises(
                verification.VerificationError, match="verification-origin-mismatch"
            ):
                verification.verify_and_send(
                    client, client.build_request("GET", "https://api.example/private")
                )
    assert seen == []
    assert any(run["classification"] == "invalid" for run in _runs())


def test_cross_origin_proof_cannot_be_issued(policy):
    _configure()
    _allow_second_owned_origin(policy)
    with egress.client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"user": {"id": "person-1", "role": "owner"}}
            )
        )
    ) as client:
        run_id, state, configuration = verification._verify_sync(client)
        request = client.build_request("GET", "https://api.example/private")
        with pytest.raises(
            verification.VerificationError, match="verification-origin-mismatch"
        ):
            verification._issue_proof(request, run_id, state, configuration)
    assert "bughunt_verification_proof" not in request.extensions


@pytest.mark.parametrize("asynchronous", [False, True])
def test_probe_rechecks_workspace_scope_after_queue(policy, monkeypatch, asynchronous):
    _document, workspace = policy
    _configure()
    seen = []
    reserve = egress._try_reserve

    def revoke(profile):
        result = reserve(profile)
        if result:
            (workspace / "scope.txt").write_text("unrelated.example\n")
        return result

    monkeypatch.setattr(egress, "_try_reserve", revoke)

    def respond(request):
        seen.append(request)
        return httpx.Response(200, json={"user": {"id": "person-1", "role": "owner"}})

    async def run():
        async with egress.async_client(
            transport=httpx.MockTransport(respond)
        ) as client:
            with pytest.raises(
                verification.VerificationError, match="verification-transport-error"
            ):
                await verification.verify_selected_async(client)

    if asynchronous:
        asyncio.run(run())
    else:
        with egress.client(transport=httpx.MockTransport(respond)) as client:
            with pytest.raises(
                verification.VerificationError, match="verification-transport-error"
            ):
                verification.verify_selected(client)
    assert seen == []
    assert egress._budgets[str(workspace.resolve())][0] == 0


@pytest.mark.parametrize("asynchronous", [False, True])
def test_marked_send_rechecks_workspace_scope_after_queue(
    policy, monkeypatch, asynchronous
):
    _document, workspace = policy
    _configure()
    seen = []
    reserve = egress._try_reserve
    reservations = []

    def revoke(profile):
        result = reserve(profile)
        if result:
            reservations.append(True)
            if len(reservations) == 2:
                (workspace / "scope.txt").write_text("unrelated.example\n")
        return result

    monkeypatch.setattr(egress, "_try_reserve", revoke)

    def respond(request):
        seen.append(request.url.path)
        return httpx.Response(200, json={"user": {"id": "person-1", "role": "owner"}})

    async def run():
        async with egress.async_client(
            transport=httpx.MockTransport(respond)
        ) as client:
            with pytest.raises(egress.PolicyBlocked):
                await verification.verify_and_send_async(
                    client,
                    client.build_request("GET", "https://allowed.example/private"),
                )

    if asynchronous:
        asyncio.run(run())
    else:
        with egress.client(transport=httpx.MockTransport(respond)) as client:
            with pytest.raises(egress.PolicyBlocked):
                verification.verify_and_send(
                    client,
                    client.build_request("GET", "https://allowed.example/private"),
                )
    assert seen == ["/whoami"]
    assert egress._budgets[str(workspace.resolve())][0] == 0


def test_verified_send_checks_workspace_target_before_probe(policy):
    _document, workspace = policy
    _configure()
    (workspace / "scope.txt").write_text("unrelated.example\n")
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(200, json={"user": {"id": "person-1", "role": "owner"}})

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(verification.VerificationError, match="workspace-scope"):
            verification.verify_and_send(
                client, client.build_request("GET", "https://allowed.example/private")
            )
    assert seen == []


def test_three_named_actors_validate_server_identity_and_link_evidence(policy):
    seen = []
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

    def respond(request):
        actor = identity.selected_name()
        seen.append((actor, request.url.path, request.headers.get("Authorization")))
        if request.url.path == "/whoami":
            if actor == "guest":
                return httpx.Response(401)
            return httpx.Response(
                200,
                json={
                    "user": {
                        "id": "person-" + actor,
                        "role": "viewer" if actor == "viewer" else "owner",
                    }
                },
            )
        return httpx.Response(200, content=b"downstream")

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        for name in ("owner", "viewer", "guest"):
            identity.use_profile(name)
            response = verification.verify_and_send(
                client, client.build_request("GET", "https://allowed.example/private")
            )
            assert response.status_code == 200
    assert [path for _, path, _ in seen] == ["/whoami", "/private"] * 3
    assert seen[-2][2] is None and seen[-1][2] is None
    runs = _runs()
    probes = [
        run for run in runs if run["representation"] == "identity-verification-metadata"
    ]
    exchanges = [
        run
        for run in runs
        if run["representation"] == "logical-http; not a wire-byte claim"
    ]
    assert len(probes) == len(exchanges) == 3
    assert {run["actor"] for run in probes} == {"owner", "viewer", "guest"}
    assert all(
        run["verification_result"]["passed"] is True and run["response"] is None
        for run in probes
    )
    assert {run["verification_run_id"] for run in exchanges} == {
        run["run_id"] for run in probes
    }
    for run in probes:
        raw = (ledger.runs_dir() / run["run_id"] / "request.http").read_text()
        assert "private-token" not in raw and "person-" not in raw


@pytest.mark.parametrize(
    "body,reason",
    [
        ({"user": {"id": "other", "role": "owner"}}, "principal-mismatch"),
        ({"user": {"id": "person-1", "role": "viewer"}}, "role-mismatch"),
        ({"user": {"role": "owner"}}, "principal-missing"),
        (
            b'{"user":{"id":"person-1","id":"person-1","role":"owner"}}',
            "ambiguous-json",
        ),
        (b"x" * 1025, "response-too-large"),
    ],
)
def test_bad_or_ambiguous_probe_blocks_downstream(policy, body, reason):
    _configure(max_bytes=1024)
    seen = []

    def respond(request):
        seen.append(request.url.path)
        return httpx.Response(
            200, content=body if isinstance(body, bytes) else json.dumps(body).encode()
        )

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(verification.VerificationError, match=reason):
            verification.verify_and_send(
                client, client.build_request("POST", "https://allowed.example/private")
            )
    assert seen == ["/whoami"]
    probe = next(
        run
        for run in _runs()
        if run["representation"] == "identity-verification-metadata"
    )
    assert probe["classification"] == "invalid"
    assert probe["verification_result"]["reason"] == reason
    assert probe["response"] is None


def test_redirect_probe_does_not_follow_or_send_discriminating_request(policy):
    _configure()
    seen = []

    def respond(request):
        seen.append(request.url.path)
        return httpx.Response(
            302, headers={"Location": "https://allowed.example/other"}
        )

    with egress.client(
        transport=httpx.MockTransport(respond), follow_redirects=True
    ) as client:
        with pytest.raises(verification.VerificationError, match="status-mismatch"):
            verification.verify_and_send(
                client, client.build_request("GET", "https://allowed.example/private")
            )
    assert seen == ["/whoami"]


def test_timeout_probe_blocks_downstream(policy):
    _configure(timeout_seconds=0.001)
    seen = []

    def respond(request):
        seen.append(request.url.path)
        time.sleep(0.01)
        return httpx.Response(200, json={"user": {"id": "person-1", "role": "owner"}})

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(
            verification.VerificationError, match="verification-timeout"
        ):
            verification.verify_and_send(
                client, client.build_request("GET", "https://allowed.example/private")
            )
    assert seen == ["/whoami"]


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("expiry", "proof-expired"),
        ("token", "proof-state-changed"),
        ("configuration", "proof-state-changed"),
        ("policy", "proof-state-changed"),
    ],
)
def test_stale_proof_is_rejected_at_send(policy, mutation, reason):
    _configure(ttl_seconds=0.001 if mutation == "expiry" else 5)
    seen = []

    def respond(request):
        seen.append(request.url.path)
        if request.url.path == "/whoami":
            return httpx.Response(
                200, json={"user": {"id": "person-1", "role": "owner"}}
            )
        return httpx.Response(200)

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        run_id, state, configuration = verification._verify_sync(client)
        request = client.build_request("GET", "https://allowed.example/private")
        verification._issue_proof(request, run_id, state, configuration)
        if mutation == "expiry":
            time.sleep(0.01)
        elif mutation == "token":
            identity.set_credential("owner", "authorization", "Bearer replacement")
        elif mutation == "configuration":
            verification.configure(
                "owner",
                "https://allowed.example/whoami",
                "user.id",
                "another-expected-person",
                "user.role",
                "owner",
            )
        else:
            document, root = policy
            document["user_agent"] = "changed-agent"
            (root / "policy.json").write_text(json.dumps(document))
        with pytest.raises(egress.PolicyBlocked):
            client.send(request)
    assert seen == ["/whoami"]
    assert any(run["classification"] == "invalid" for run in _runs())


def test_proof_cannot_be_reused(policy):
    _configure()
    seen = []

    def respond(request):
        seen.append(request.url.path)
        if request.url.path == "/whoami":
            return httpx.Response(
                200, json={"user": {"id": "person-1", "role": "owner"}}
            )
        return httpx.Response(200)

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        run_id, state, configuration = verification._verify_sync(client)
        request = client.build_request("GET", "https://allowed.example/private")
        verification._issue_proof(request, run_id, state, configuration)
        assert client.send(request).status_code == 200
        with pytest.raises(egress.PolicyBlocked):
            client.send(request)
    assert seen == ["/whoami", "/private"]


@pytest.mark.parametrize("body", [b"original", b"changed"])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_marked_proof_cannot_be_copied_to_another_request(policy, body, asynchronous):
    _configure()
    seen = []

    def respond(request):
        seen.append(request.url.path)
        if request.url.path == "/whoami":
            return httpx.Response(
                200, json={"user": {"id": "person-1", "role": "owner"}}
            )
        return httpx.Response(200, content=b"owned response")

    async def run():
        async with egress.async_client(
            transport=httpx.MockTransport(respond)
        ) as client:
            run_id, state, configuration = await verification._verify_async(client)
            original = client.build_request(
                "POST", "https://allowed.example/private", content=b"original"
            )
            verification._issue_proof(original, run_id, state, configuration)
            copied = client.build_request(
                "POST", "https://allowed.example/private", content=body
            )
            copied.extensions.update(original.extensions)
            with pytest.raises(egress.PolicyBlocked):
                await client.send(copied)
            assert (await client.send(original)).status_code == 200
            with pytest.raises(egress.PolicyBlocked):
                await client.send(original)

    if asynchronous:
        asyncio.run(run())
    else:
        with egress.client(transport=httpx.MockTransport(respond)) as client:
            run_id, state, configuration = verification._verify_sync(client)
            original = client.build_request(
                "POST", "https://allowed.example/private", content=b"original"
            )
            verification._issue_proof(original, run_id, state, configuration)
            copied = client.build_request(
                "POST", "https://allowed.example/private", content=body
            )
            copied.extensions.update(original.extensions)
            with pytest.raises(egress.PolicyBlocked):
                client.send(copied)
            assert client.send(original).status_code == 200
            with pytest.raises(egress.PolicyBlocked):
                client.send(original)
    assert seen == ["/whoami", "/private"]


def test_async_probe_and_discriminating_request(policy):
    _configure()
    seen = []

    async def respond(request):
        seen.append(request.url.path)
        if request.url.path == "/whoami":
            return httpx.Response(
                200, json={"user": {"id": "person-1", "role": "owner"}}
            )
        return httpx.Response(200)

    async def run():
        async with egress.async_client(
            transport=httpx.MockTransport(respond)
        ) as client:
            request = client.build_request("GET", "https://allowed.example/private")
            return await verification.verify_and_send_async(client, request)

    assert asyncio.run(run()).status_code == 200
    assert seen == ["/whoami", "/private"]


def test_configuration_requires_canonical_owned_url_and_private_values(policy):
    _configure()
    assert (
        verification.read_configuration("owner")["url"]
        == "https://allowed.example/whoami"
    )
    assert "person-1" in verification.all_private_values()
    for url in (
        "https://allowed.example/whoami?user=person-1",
        "https://person-1@allowed.example/whoami",
        "https://allowed.example/whoami#fragment",
        "https://api.example/whoami",
    ):
        with pytest.raises(verification.VerificationError):
            verification.configure(
                "owner", url, "user.id", "person-1", "user.role", "owner"
            )


def test_missing_configuration_blocks_and_records_invalid_request(policy):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.use_profile("owner")
    seen = []
    with egress.client(
        transport=httpx.MockTransport(lambda request: seen.append(request))
    ) as client:
        with pytest.raises(
            verification.VerificationError, match="configuration-missing-or-invalid"
        ):
            verification.verify_and_send(
                client, client.build_request("GET", "https://allowed.example/private")
            )
    assert seen == []
    assert any(
        run["representation"] == "identity-verification-decision"
        and run["classification"] == "invalid"
        for run in _runs()
    )


def test_marked_direct_send_without_proof_is_blocked_and_recorded(policy):
    _configure()
    seen = []
    with egress.client(
        transport=httpx.MockTransport(lambda request: seen.append(request))
    ) as client:
        request = client.build_request("GET", "https://allowed.example/private")
        request.extensions["bughunt_require_verified"] = True
        with pytest.raises(egress.PolicyBlocked):
            client.send(request)
    assert seen == []
    assert any(
        run["representation"] == "identity-verification-decision"
        and run["verification_result"]["reason"] == "proof-missing"
        for run in _runs()
    )


@pytest.mark.parametrize("marker", [True, "forged-probe-token"])
def test_forged_probe_marker_cannot_suppress_full_capture(policy, marker):
    _configure()
    seen = []
    with egress.client(
        transport=httpx.MockTransport(
            lambda request: (
                seen.append(request),
                httpx.Response(200, content=b"sensitive fixture"),
            )[1]
        )
    ) as client:
        request = client.build_request("GET", "https://allowed.example/whoami")
        request.extensions["bughunt_verification_probe"] = marker
        with pytest.raises(egress.PolicyBlocked):
            client.send(request)
    assert seen == []
    assert any(
        run["representation"] == "identity-verification-decision"
        and run["classification"] == "invalid"
        for run in _runs()
    )


def test_probe_token_is_bound_to_original_request_and_one_use(policy):
    _configure()
    seen = []

    def respond(request):
        seen.append(request)
        return httpx.Response(200, json={"user": {"id": "person-1", "role": "owner"}})

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        configuration, state = verification._selected()
        probe = verification._probe_request(client, configuration, state)
        copy = client.build_request("GET", "https://allowed.example/whoami")
        copy.extensions["bughunt_verification_probe"] = probe.extensions[
            "bughunt_verification_probe"
        ]
        with pytest.raises(egress.PolicyBlocked):
            client.send(copy)
        response = client.send(probe, stream=True, follow_redirects=False)
        response.close()
        with pytest.raises(egress.PolicyBlocked):
            client.send(probe)
    assert seen == [probe]


@pytest.mark.parametrize("marker", [False, None, 1, "true"])
def test_malformed_verification_marker_fails_closed(policy, marker):
    _configure()
    seen = []
    with egress.client(
        transport=httpx.MockTransport(lambda request: seen.append(request))
    ) as client:
        request = client.build_request("GET", "https://allowed.example/private")
        request.extensions["bughunt_require_verified"] = marker
        with pytest.raises(egress.PolicyBlocked):
            client.send(request)
    assert seen == []
    assert any(
        run["representation"] == "identity-verification-decision"
        and run["verification_result"]["reason"] == "proof-marker-invalid"
        for run in _runs()
    )


def test_cli_show_and_check_keep_expected_values_private(policy, capsys):
    _configure(expected_principal="private-person-42", expected_role="internal-role")
    assert verify_command.main(["show", "owner"]) == 0
    output = capsys.readouterr().out
    assert "private-person-42" not in output and "internal-role" not in output
    assert "user.id" in output and "user.role" in output
    identity.use_profile("default")
    assert verify_command.main(["check", "owner"]) == 2
    assert "private-person-42" not in capsys.readouterr().out


def test_cli_status_reports_readiness_without_leaking_expected_values(policy, capsys):
    _configure(expected_principal="private-person-42", expected_role="internal-role")
    assert verify_command.main(["status"]) == 0
    output = capsys.readouterr().out
    summary = json.loads(output)
    assert summary["selected_actor"] == "owner"
    assert summary["configured"] is True
    assert summary["probe"]["url"] == "https://allowed.example/whoami"
    assert "user.id" in output and "user.role" in output
    assert "private-person-42" not in output and "internal-role" not in output
    assert "private-token-owner" not in output
    identity.use_profile("default")
    capsys.readouterr()
    assert verify_command.main(["status"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "selected_actor": "default",
        "configured": False,
        "probe": None,
    }


def test_anonymous_configuration_rejects_principal_fields(policy):
    identity.create_profile(
        "guest", "anonymous", ["https://allowed.example"], owned=True
    )
    with pytest.raises(verification.VerificationError, match="configuration-invalid"):
        verification.configure(
            "guest",
            "https://allowed.example/whoami",
            "user.id",
            "person",
            None,
            None,
            expected_status=401,
        )


def test_plain_http_client_is_rejected_before_probe(policy):
    _configure()
    seen = []
    with httpx.Client(
        transport=httpx.MockTransport(lambda request: seen.append(request))
    ) as client:
        with pytest.raises(
            verification.VerificationError, match="guarded-client-required"
        ):
            verification.verify_selected(client)
    assert seen == []


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "actual_role,reason",
    [
        (1, None),
        ("1", "role-ambiguous"),
        (True, "role-ambiguous"),
        (1.0, "role-ambiguous"),
        (2, "role-mismatch"),
        (None, "role-ambiguous"),
        ([], "role-ambiguous"),
        ({}, "role-ambiguous"),
    ],
)
def test_integer_role_is_exact_and_gates_downstream(
    policy, asynchronous, actual_role, reason
):
    _configure(expected_role=1)
    seen = []

    def respond(request):
        seen.append(request.url.path)
        return httpx.Response(
            200, json={"user": {"id": "person-1", "role": actual_role}}
        )

    async def run():
        async with egress.async_client(
            transport=httpx.MockTransport(respond)
        ) as client:
            await verification.verify_and_send_async(
                client, client.build_request("GET", "https://allowed.example/private")
            )

    def invoke():
        if asynchronous:
            asyncio.run(run())
        else:
            with egress.client(transport=httpx.MockTransport(respond)) as client:
                verification.verify_and_send(
                    client,
                    client.build_request("GET", "https://allowed.example/private"),
                )

    if reason is None:
        invoke()
        assert seen == ["/whoami", "/private"]
    else:
        with pytest.raises(verification.VerificationError, match=reason):
            invoke()
        assert seen == ["/whoami"]


@pytest.mark.parametrize("expected_role", [True, 1.0, -1, 2**53, [], {}])
def test_invalid_typed_role_configuration_fails_closed(policy, expected_role):
    with pytest.raises(verification.VerificationError, match="configuration-invalid"):
        _configure(expected_role=expected_role)


def test_string_role_does_not_accept_numeric_response(policy):
    _configure(expected_role="1")
    with egress.client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"user": {"id": "person-1", "role": 1}}
            )
        )
    ) as client:
        with pytest.raises(verification.VerificationError, match="role-ambiguous"):
            verification.verify_selected(client)


def test_cli_integer_role_hidden_input_and_public_metadata(policy, monkeypatch, capsys):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    values = iter(["private-person-42", "1"])
    monkeypatch.setattr(verify_command.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(verify_command.getpass, "getpass", lambda prompt: next(values))
    assert (
        verify_command.main(
            [
                "configure",
                "owner",
                "--url",
                "https://allowed.example/whoami",
                "--principal-path",
                "user.id",
                "--prompt-principal",
                "--role-path",
                "user.role",
                "--prompt-role",
                "--role-type",
                "integer",
            ]
        )
        == 0
    )
    assert type(verification.read_configuration("owner")["expected_role"]) is int
    assert verify_command.main(["show", "owner"]) == 0
    output = capsys.readouterr().out
    assert '"role_type": "integer"' in output
    assert "private-person-42" not in output and '"expected_role"' not in output


@pytest.mark.parametrize("role", ["true", "1.0", '"1"', "null", "-1", str(2**53)])
def test_cli_integer_role_rejects_non_integer_or_unbounded_input(policy, role):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    assert (
        verify_command.main(
            [
                "configure",
                "owner",
                "--url",
                "https://allowed.example/whoami",
                "--principal-path",
                "user.id",
                "--expect-principal",
                "person-1",
                "--role-path",
                "user.role",
                "--expect-role",
                role,
                "--role-type",
                "integer",
            ]
        )
        == 2
    )


def test_policy_stales_while_verified_request_waits_for_capacity(policy):
    _configure()
    document, root = policy
    document["limits"]["concurrency"] = 1
    (root / "policy.json").write_text(json.dumps(document))
    seen = []

    def respond(request):
        seen.append(request.url.path)
        return httpx.Response(200, json={"user": {"id": "person-1", "role": "owner"}})

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        run_id, state, configuration = verification._verify_sync(client)
        request = client.build_request("GET", "https://allowed.example/private")
        verification._issue_proof(request, run_id, state, configuration)
        assert egress._try_reserve(egress.current_profile())

        def stale():
            document["state"] = "stale"
            (root / "policy.json").write_text(json.dumps(document))

        timer = threading.Timer(0.03, stale)
        timer.start()
        try:
            with pytest.raises(egress.PolicyBlocked):
                client.send(request)
        finally:
            timer.join()
            egress._release()
    assert seen == ["/whoami"]
    assert any(
        run["representation"] == "identity-verification-decision"
        and run["classification"] == "invalid"
        for run in _runs()
    )


def _verify_role_payload(role):
    with egress.client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"user": {"id": "person-1", "role": role}}
            )
        )
    ) as client:
        verification.verify_selected(client)


def _configure_contains(expected_role="admin"):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.set_credential("owner", "authorization", "Bearer private-token-owner")
    identity.use_profile("owner")
    verification.configure(
        "owner",
        "https://allowed.example/whoami",
        "user.id",
        "person-1",
        "user.role",
        expected_role,
        role_contains=True,
    )


@pytest.mark.parametrize(
    "expected_role,payload",
    [
        ("admin", ["viewer", "admin"]),
        ("admin", ["admin"]),
        (7, [3, 7]),
    ],
)
def test_role_contains_passes_when_expected_role_is_a_member(
    policy, expected_role, payload
):
    _configure_contains(expected_role)
    _verify_role_payload(payload)


@pytest.mark.parametrize(
    "payload,reason",
    [
        (["viewer", "editor"], "role-mismatch"),
        ([], "role-mismatch"),
        ("admin", "role-ambiguous"),
        ({"a": "admin"}, "role-ambiguous"),
        ([["admin"]], "role-mismatch"),
        ([1], "role-mismatch"),
    ],
)
def test_role_contains_fails_when_absent_or_not_an_array(policy, payload, reason):
    _configure_contains("admin")
    with pytest.raises(verification.VerificationError, match=reason):
        _verify_role_payload(payload)


def test_role_contains_does_not_match_across_types(policy):
    _configure_contains(1)
    with pytest.raises(verification.VerificationError, match="role-mismatch"):
        _verify_role_payload(["1", True])


def test_scalar_role_config_still_validates_and_passes_without_contains(policy):
    _configure(expected_role="owner")
    assert "role_contains" not in verification.read_configuration("owner")
    _verify_role_payload("owner")
    with pytest.raises(verification.VerificationError, match="role-ambiguous"):
        _verify_role_payload(["owner"])


def test_role_contains_must_be_boolean_and_not_on_anonymous(policy):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    with pytest.raises(verification.VerificationError, match="configuration-invalid"):
        verification.configure(
            "owner",
            "https://allowed.example/whoami",
            "user.id",
            "p",
            "user.role",
            "r",
            role_contains="yes",
        )
    identity.create_profile(
        "anon", "anonymous", ["https://allowed.example"], owned=True
    )
    with pytest.raises(verification.VerificationError, match="configuration-invalid"):
        verification.configure(
            "anon",
            "https://allowed.example/whoami",
            None,
            None,
            None,
            None,
            expected_status=401,
            role_contains=True,
        )


def _companion_configure(
    cookie="session=owner-secret; x-sample-token=sample-xsrf-value",
    companions=("x-sample-token",),
):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.set_credential("owner", "cookie", cookie)
    if companions is not None:
        identity.set_companion_headers("owner", list(companions))
    identity.use_profile("owner")
    verification.configure(
        "owner",
        "https://allowed.example/whoami",
        "user.id",
        "person-1",
        "user.role",
        "owner",
    )


def test_probe_supplies_allowlisted_companion_and_authenticates(policy):
    _companion_configure()
    seen = []

    def respond(request):
        seen.append(request.headers.get("x-sample-token"))
        if request.headers.get("x-sample-token") == "sample-xsrf-value":
            return httpx.Response(
                200, json={"user": {"id": "person-1", "role": "owner"}}
            )
        return httpx.Response(401)

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        run_id = verification.verify_selected(client)
    assert isinstance(run_id, str)
    assert seen == ["sample-xsrf-value"]


def test_probe_without_allowlist_stays_unauthenticated(policy):
    _companion_configure(
        companions=None
    )  # cookie carries the token, but it is NOT allowlisted
    seen = []

    def respond(request):
        seen.append(request.headers.get("x-sample-token"))
        if request.headers.get("x-sample-token"):
            return httpx.Response(
                200, json={"user": {"id": "person-1", "role": "owner"}}
            )
        return httpx.Response(401)

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(verification.VerificationError, match="status-mismatch"):
            verification.verify_selected(client)
    assert seen == [None]


def test_probe_supplies_rotated_companion_value(policy):
    _companion_configure(cookie="session=owner-secret; x-sample-token=v1")
    seen = []

    def respond(request):
        seen.append(request.headers.get("x-sample-token"))
        return httpx.Response(200, json={"user": {"id": "person-1", "role": "owner"}})

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        verification.verify_selected(client)
        identity.set_credential(
            "owner", "cookie", "session=owner-secret; x-sample-token=v2"
        )
        verification.verify_selected(client)
    assert seen == ["v1", "v2"]  # the current value, never a stale cached one


def test_anonymous_probe_needs_no_companion(policy):
    identity.create_profile(
        "guest", "anonymous", ["https://allowed.example"], owned=True
    )
    identity.use_profile("guest")
    verification.configure(
        "guest",
        "https://allowed.example/whoami",
        None,
        None,
        None,
        None,
        expected_status=401,
    )
    seen = []

    def respond(request):
        seen.append(request.headers.get("x-sample-token"))
        return httpx.Response(401)

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        assert isinstance(verification.verify_selected(client), str)
    assert seen == [None]


def test_probe_companion_value_is_redacted(policy):
    _companion_configure()

    def respond(request):
        if request.headers.get("x-sample-token") == "sample-xsrf-value":
            return httpx.Response(
                200, json={"user": {"id": "person-1", "role": "owner"}}
            )
        return httpx.Response(401)

    with egress.client(transport=httpx.MockTransport(respond)) as client:
        verification.verify_selected(client)
    # The supplied double-submit value is credential-class: redacted as a bare value anywhere.
    rendered = ledger.redact_text("companion carried sample-xsrf-value onward")
    assert "sample-xsrf-value" not in rendered and "[REDACTED]" in rendered
    # The probe's own evidence records header names only, never the value.
    probe = next(
        run
        for run in _runs()
        if run["representation"] == "identity-verification-metadata"
    )
    raw = (ledger.runs_dir() / probe["run_id"] / "request.http").read_text()
    assert "sample-xsrf-value" not in raw


def test_cli_role_contains_flag_configures_and_shows_metadata(policy, capsys):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    assert (
        verify_command.main(
            [
                "configure",
                "owner",
                "--url",
                "https://allowed.example/whoami",
                "--principal-path",
                "user.id",
                "--expect-principal",
                "person-1",
                "--role-path",
                "user.roles",
                "--expect-role",
                "admin",
                "--role-contains",
            ]
        )
        == 0
    )
    assert verification.read_configuration("owner")["role_contains"] is True
    assert verify_command.main(["show", "owner"]) == 0
    assert '"role_contains": true' in capsys.readouterr().out
    assert (
        verify_command.main(
            [
                "configure",
                "owner",
                "--url",
                "https://allowed.example/whoami",
                "--status",
                "401",
                "--role-contains",
            ]
        )
        == 2
    )
