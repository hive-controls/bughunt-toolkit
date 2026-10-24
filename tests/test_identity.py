"""Offline actor isolation and attribution controls."""

import json

import httpx
import pytest

from bughunt.core import egress, identity, ledger
from bughunt.modules import identity as identity_command
from bughunt.core.session import load_session, write_session
from test_gate import policy


def _actors():
    for name, kind in (
        ("owner", "owner"),
        ("viewer", "lower_privilege"),
        ("guest", "anonymous"),
    ):
        identity.create_profile(name, kind, ["https://allowed.example"], owned=True)
    identity.set_credential("owner", "cookie", "session=owner-secret")
    identity.set_credential("owner", "authorization", "Bearer owner-token")
    identity.set_credential("viewer", "cookie", "session=viewer-secret")


def test_named_actors_same_client_and_anonymous_never_bleed(policy):
    _actors()
    seen = []

    def respond(request):
        seen.append(
            (
                request.headers.get("Cookie"),
                request.headers.get("Authorization"),
                request.headers.get("X-API-Key"),
            )
        )
        return httpx.Response(200, headers={"Set-Cookie": "server=should-not-bleed"})

    with egress.client(
        transport=httpx.MockTransport(respond),
        headers={
            "Cookie": "session=stale-client",
            "Authorization": "Bearer stale-client",
            "X-API-Key": "stale-api-key",
        },
    ) as client:
        for name in ("owner", "viewer", "guest"):
            identity.use_profile(name)
            client.get("https://allowed.example/")
    assert seen == [
        ("session=owner-secret", "Bearer owner-token", None),
        ("session=viewer-secret", None, None),
        (None, None, None),
    ]
    manifests = [
        json.loads(path.read_text())
        for path in ledger.runs_dir().glob("*/manifest.json")
    ]
    assert {row["actor"] for row in manifests} == {"owner", "viewer", "guest"}
    for row in manifests:
        raw = (ledger.runs_dir() / row["run_id"] / "request.http").read_text()
        assert "stale-client" not in raw and "stale-api-key" not in raw


def test_logout_token_replacement_and_queued_snapshot(policy):
    _actors()
    seen = []
    with egress.client(
        transport=httpx.MockTransport(
            lambda request: (
                seen.append(request.headers.get("Authorization")),
                httpx.Response(200),
            )[1]
        )
    ) as client:
        identity.use_profile("owner")
        client.get("https://allowed.example/")
        queued = client.build_request("GET", "https://allowed.example/")
        egress._prepare(queued, "manual", None)
        identity.set_credential("owner", "authorization", "Bearer replacement")
        with pytest.raises(egress.PolicyBlocked):
            client.send(queued)
        client.get("https://allowed.example/")
        identity.clear_profile("owner")
        client.get("https://allowed.example/")
    assert seen == ["Bearer owner-token", "Bearer replacement", None]


def test_session_changes_only_selected_actor_and_anonymous_rejects_secret(policy):
    _actors()
    identity.use_profile("viewer")
    assert load_session() == {"cookie": "session=viewer-secret"}
    write_session({"authorization": "Bearer viewer-new"})
    assert load_session() == {"authorization": "Bearer viewer-new"}
    identity.use_profile("owner")
    assert load_session()["authorization"] == "Bearer owner-token"
    identity.use_profile("guest")
    with pytest.raises(identity.IdentityError):
        write_session({"cookie": "session=forbidden"})
    assert load_session() == {}


def test_origin_binding_selection_and_secret_safe_listing(policy):
    _actors()
    identity.use_profile("owner")
    assert identity.show_profile("owner")["credential_headers"] == [
        "Authorization",
        "Cookie",
    ]
    assert "owner-secret" not in json.dumps(identity.list_profiles())
    seen = []
    with egress.client(
        transport=httpx.MockTransport(
            lambda request: (seen.append(request), httpx.Response(200))[1]
        )
    ) as client:
        with pytest.raises(egress.PolicyBlocked):
            client.get("https://api.example/")
        with pytest.raises(egress.PolicyBlocked):
            client.get("https://allowed.example/", headers={"Host": "api.example"})
    assert not seen
    identity.use_profile("default")
    assert identity.selected_name() == "default"


def test_anonymous_cannot_hold_credentials_and_invalid_name_is_inert(policy):
    identity.create_profile(
        "guest", "anonymous", ["https://allowed.example"], owned=True
    )
    with pytest.raises(identity.IdentityError):
        identity.set_credential("guest", "cookie", "session=secret")
    with pytest.raises(identity.IdentityError):
        identity.create_profile(
            "../escape", "owner", ["https://allowed.example"], owned=True
        )
    with pytest.raises(identity.IdentityError):
        identity.create_profile(
            "owner", "owner", ["https://allowed.example"], owned=False
        )
    assert identity.list_profiles()[0]["name"] == "guest"


def test_browser_and_api_profiles_keep_header_secrets_private(policy):
    identity.create_profile(
        "browser-one", "browser", ["https://allowed.example"], owned=True
    )
    identity.create_profile("service-one", "api", ["https://api.example"], owned=True)
    identity.set_credential("browser-one", "cookie", "browser=private-value")
    identity.set_credential("service-one", "x-api-key", "private-api-value")
    identity.use_profile("service-one")
    seen = []
    with egress.client(
        transport=httpx.MockTransport(
            lambda request: (
                seen.append(request.headers.get("X-API-Key")),
                httpx.Response(200),
            )[1]
        )
    ) as client:
        client.get("https://api.example/")
    assert seen == ["private-api-value"]
    assert "private-api-value" not in json.dumps(identity.list_profiles())
    assert "browser=private-value" not in ledger.redact_text("browser=private-value")
    assert "private-api-value" not in ledger.redact_text("private-api-value")


def test_return_to_default_on_same_client_clears_named_state(policy):
    _actors()
    identity.use_profile("owner")
    seen = []

    def respond(request):
        seen.append(request.headers.get("Cookie"))
        return httpx.Response(200, headers={"Set-Cookie": "server=owner-state"})

    with egress.client(
        transport=httpx.MockTransport(respond),
        headers={"Cookie": "session=owner-captured"},
    ) as client:
        client.get("https://allowed.example/")
        identity.use_profile("default")
        client.get("https://allowed.example/")
    assert seen == ["session=owner-secret", None]


def test_default_client_cannot_carry_credentials_into_another_workspace(
    policy, monkeypatch, tmp_path
):
    document, original = policy
    other = tmp_path / "other-workspace"
    other.mkdir()
    (other / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    seen = []

    def respond(request):
        seen.append(
            (request.headers.get("Authorization"), request.headers.get("Cookie"))
        )
        return httpx.Response(200, headers={"Set-Cookie": "workspace=first"})

    with egress.client(
        transport=httpx.MockTransport(respond),
        headers={
            "Authorization": "Bearer first-workspace",
            "Cookie": "session=first-workspace",
        },
    ) as client:
        client.get("https://allowed.example/")
        monkeypatch.setenv("BUGHUNT_SCOPE", str(other))
        with pytest.raises(egress.PolicyBlocked, match="client-workspace-changed"):
            client.get("https://allowed.example/")
    assert seen == [("Bearer first-workspace", "session=first-workspace")]
    assert not (other / "runs").exists()


def test_identity_commands_report_metadata_only(policy, capsys):
    assert (
        identity_command.main(
            [
                "create",
                "owned-api",
                "--kind",
                "api",
                "--origin",
                "https://api.example",
                "--owned",
            ]
        )
        == 0
    )
    assert (
        identity_command.main(["set", "owned-api", "x-api-key", "api-private-value"])
        == 0
    )
    assert identity_command.main(["use", "owned-api"]) == 0
    assert identity_command.main(["show", "owned-api"]) == 0
    assert identity_command.main(["list"]) == 0
    assert identity_command.main(["clear", "owned-api"]) == 0
    output = capsys.readouterr().out
    assert "api-private-value" not in output
    assert "X-API-Key" in output
    assert identity.read_profile("owned-api")["credentials"] == {}


CSRF = {"X-CSRF-Token": "tok", "X-Session-Id": "sid"}


def _csrf_request(url="https://allowed.example/"):
    return httpx.Request("GET", url, headers=CSRF)


def _companion_actor(name="owner", companions=("X-CSRF-TOKEN",)):
    identity.create_profile(name, "owner", ["https://allowed.example"], owned=True)
    identity.set_credential(name, "cookie", "session=owner-secret")
    if companions is not None:
        identity.set_companion_headers(name, list(companions))


def test_companion_header_forwards_only_declared_name_to_own_origin(policy):
    _companion_actor()
    identity.use_profile("owner")
    request = _csrf_request()
    identity.apply_request(request)
    assert request.headers.get("X-CSRF-Token") == "tok"
    assert (
        request.headers.get("X-Session-Id") is None
    )  # credential-named, not in allowlist
    assert request.headers.get("Cookie") == "session=owner-secret"
    payload, _name = identity.apply_raw_headers(
        b"GET / HTTP/1.1\r\nHost: allowed.example\r\nX-CSRF-Token: tok\r\nX-Session-Id: sid\r\n\r\n",
        "https://allowed.example/",
    )
    assert b"X-CSRF-Token: tok" in payload and b"X-Session-Id" not in payload


def test_companion_header_still_dropped_for_default_actor(policy):
    _companion_actor()
    request = _csrf_request()
    identity.apply_request(request, strip_default=True)
    assert request.headers.get("X-CSRF-Token") is None


def test_companion_header_dropped_for_named_actor_without_allowlist(policy):
    _companion_actor(companions=None)
    identity.use_profile("owner")
    request = _csrf_request()
    identity.apply_request(request)
    assert request.headers.get("X-CSRF-Token") is None
    payload, _name = identity.apply_raw_headers(
        b"GET / HTTP/1.1\r\nHost: allowed.example\r\nX-CSRF-Token: tok\r\n\r\n",
        "https://allowed.example/",
    )
    assert b"X-CSRF-Token" not in payload


def test_companion_header_never_crosses_origin(policy):
    _companion_actor()
    identity.use_profile("owner")
    request = _csrf_request("https://other.example/")
    with pytest.raises(identity.IdentityError):
        identity.apply_request(request)
    with pytest.raises(identity.IdentityError):
        identity.apply_raw_headers(
            b"GET / HTTP/1.1\r\nHost: other.example\r\nX-CSRF-Token: tok\r\n\r\n",
            "https://other.example/",
        )


def test_companion_allowlist_cannot_name_credential_headers_or_bad_names(policy):
    _companion_actor(companions=None)
    for bad in (
        ["Cookie"],
        ["Authorization"],
        ["x-api-key"],
        ["a\r\nb"],
        [""],
        ["a b"],
        [f"h{i}" for i in range(9)],
        "x-csrf-token",
        [1],
    ):
        with pytest.raises(identity.IdentityError):
            identity.set_companion_headers("owner", bad)
    assert "companion_headers" not in identity.read_profile("owner")


def test_companion_cli_sets_and_shows_only_names(policy, capsys):
    assert (
        identity_command.main(
            [
                "create",
                "owner",
                "--kind",
                "owner",
                "--origin",
                "https://allowed.example",
                "--owned",
            ]
        )
        == 0
    )
    assert (
        identity_command.main(
            [
                "set",
                "owner",
                "cookie",
                "session=owner-secret; x-sample-token=sample-xsrf-value",
            ]
        )
        == 0
    )
    capsys.readouterr()
    # Set the allowlist from the CLI (names only, lowercased, validated).
    assert (
        identity_command.main(["companion", "owner", "X-Sample-Token", "X-Request-Id"])
        == 0
    )
    assert identity.read_profile("owner")["companion_headers"] == [
        "x-sample-token",
        "x-request-id",
    ]
    # Show prints the names and nothing resembling the stored XSRF value.
    capsys.readouterr()
    assert identity_command.main(["companion", "owner"]) == 0
    shown = capsys.readouterr().out
    assert "x-sample-token" in shown and "x-request-id" in shown
    assert "sample-xsrf-value" not in shown
    # The general show surfaces the names too, still never a value.
    assert identity_command.main(["show", "owner"]) == 0
    overview = capsys.readouterr().out
    assert "companion_headers" in overview and "x-sample-token" in overview
    assert "sample-xsrf-value" not in overview


def test_companion_cli_rejects_values_and_credential_names(policy, capsys):
    assert (
        identity_command.main(
            [
                "create",
                "owner",
                "--kind",
                "owner",
                "--origin",
                "https://allowed.example",
                "--owned",
            ]
        )
        == 0
    )
    capsys.readouterr()
    # A value masquerading as a name (contains "=") is refused by the allowlist validator.
    assert (
        identity_command.main(
            ["companion", "owner", "x-sample-token=sample-xsrf-value"]
        )
        == 2
    )
    # A real credential header name is refused by design.
    assert identity_command.main(["companion", "owner", "cookie"]) == 2
    assert "companion_headers" not in identity.read_profile("owner")


def test_companion_cli_clear_empties_the_allowlist(policy, capsys):
    _companion_actor(companions=("x-sample-token",))
    capsys.readouterr()
    assert identity_command.main(["companion", "owner", "--clear"]) == 0
    assert identity.read_profile("owner")["companion_headers"] == []


def test_companion_supplements_derive_from_session_cookie(policy):
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.set_credential(
        "owner",
        "cookie",
        "session=owner-secret; x-sample-token=same-name; sample-csrf=stripped",
    )
    identity.set_companion_headers(
        "owner", ["x-sample-token", "x-sample-csrf", "x-absent-token"]
    )
    supplements = identity.companion_supplements(
        "owner", "https://allowed.example/whoami"
    )
    # Same-name match, plus the optional leading x- stripped to match a bare cookie name.
    assert supplements == {"x-sample-token": "same-name", "x-sample-csrf": "stripped"}
    assert "x-absent-token" not in supplements  # no cookie of either name exists
    # Never crosses to an origin outside the actor's own origins.
    assert identity.companion_supplements("owner", "https://other.example/") == {}
    # The default actor supplies nothing at all.
    identity.use_profile("default")
    assert identity.companion_supplements("default", "https://allowed.example/") == {}


def test_cross_origin_redirect_drops_companion_class_header():
    from bughunt.core import http

    with httpx.Client() as conn:
        same = http.hop_request(
            conn,
            "GET",
            "https://allowed.example/next",
            came_from="https://allowed.example/",
            headers={"x-sample-token": "v"},
        )
        assert same.headers.get("x-sample-token") == "v"  # same-origin hop retains it
        crossed = http.hop_request(
            conn,
            "GET",
            "https://other.example/next",
            came_from="https://allowed.example/",
            headers={"x-sample-token": "v"},
        )
        assert (
            crossed.headers.get("x-sample-token") is None
        )  # cross-origin hop strips it (#93 class)
