import json

import pytest

import bughunt
from bughunt.core import identity, session
from test_gate import policy


@pytest.fixture
def local_workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    return tmp_path


def test_identity_lifecycle_uses_private_store_without_printing(
    local_workspace, capsys
):
    def run(operation, **options):
        result = bughunt.run_module("identity", operation=operation, options=options)
        assert result.status == "success", result.to_dict()
        assert "owned-secret" not in json.dumps(result.to_dict())
        return result

    run(
        "create",
        name="owner",
        kind="owner",
        origin=["https://owned.example"],
        owned=True,
    )
    run("use", name="owner")
    run("set", name="owner", header="authorization", value=["Bearer owned-secret"])
    assert (
        identity.read_profile("owner")["credentials"]["Authorization"]
        == "Bearer owned-secret"
    )
    run("companion", name="owner", header=["x-owned-label"])
    assert identity.show_profile("owner")["companion_headers"] == ["x-owned-label"]
    run("companion", name="owner", clear_companions=True)
    assert identity.show_profile("owner")["companion_headers"] == []
    run("clear", name="owner")
    assert not identity.read_profile("owner")["credentials"]
    run("list")
    run("show", name="owner")
    assert capsys.readouterr() == ("", "")


def test_session_adapter_reports_effects_without_exposing_values(
    local_workspace, capsys
):
    saved = bughunt.run_module(
        "session",
        operation="set",
        options={"kind": "cookie", "value": ["owned=secret"]},
    )
    assert saved.status == "success"
    assert session.load_session() == {"cookie": "owned=secret"}
    shown = bughunt.run_module("session", operation="show")
    assert shown.status == "success"
    assert "owned=secret" not in json.dumps(shown.to_dict())
    assert shown.artifacts[0].payload["items"] == [{"saved_headers": ["cookie"]}]
    cleared = bughunt.run_module("session", operation="clear")
    assert cleared.status == "success" and session.load_session() == {}
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "options",
    [
        {"name": "owner", "header": "authorization"},
        {"name": "owner", "header": "authorization", "prompt": True},
    ],
)
def test_identity_api_requires_explicit_values_without_prompting(
    local_workspace, monkeypatch, options
):
    import getpass

    monkeypatch.setattr(getpass, "getpass", lambda *_: pytest.fail("API prompted"))
    result = bughunt.run_module("identity", operation="set", options=options)
    assert result.status == "invalid"
    assert list(local_workspace.iterdir()) == []


def test_session_invalid_value_keeps_existing_credentials(local_workspace):
    session.write_session({"cookie": "owned=before"})
    result = bughunt.run_module(
        "session",
        operation="set",
        options={"kind": "cookie", "value": ["new\r\nheader"]},
    )
    assert result.status == "invalid"
    assert session.load_session() == {"cookie": "owned=before"}


def test_verification_configuration_is_local_and_value_free(
    local_workspace, monkeypatch, capsys
):
    from bughunt.core import route, verification

    monkeypatch.setattr(
        route, "gate", lambda *_: pytest.fail("Local configuration probed route")
    )
    identity.create_profile("owner", "owner", ["https://owned.example"], owned=True)
    identity.use_profile("owner")
    options = {
        "name": "owner",
        "url": "https://owned.example/whoami",
        "principal_path": "user.id",
        "expect_principal": "private-person",
        "role_path": "user.role",
        "expect_role": "private-role",
    }
    configured = bughunt.run_module("verify", operation="configure", options=options)
    assert configured.status == "success"
    assert (
        verification.read_configuration("owner")["expected_principal"]
        == "private-person"
    )
    for operation, values in [("show", {"name": "owner"}), ("status", {})]:
        result = bughunt.run_module("verify", operation=operation, options=values)
        assert result.status == "success"
        assert "private-person" not in json.dumps(result.to_dict())
        assert "private-role" not in json.dumps(result.to_dict())
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "principal,expected", [("owned-person", "success"), ("wrong-person", "blocked")]
)
def test_verification_adapter_uses_guarded_transport_and_real_ledger(
    policy, monkeypatch, principal, expected
):
    import httpx
    from bughunt.core import egress, ledger, verification

    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.use_profile("owner")
    verification.configure(
        "owner",
        "https://allowed.example/whoami",
        "user.id",
        "owned-person",
        "user.role",
        "owner",
    )
    client = egress.client
    seen = []

    def response(request):
        seen.append(str(request.url))
        return httpx.Response(200, json={"user": {"id": principal, "role": "owner"}})

    monkeypatch.setattr(
        egress,
        "client",
        lambda **kwargs: client(transport=httpx.MockTransport(response), **kwargs),
    )
    result = bughunt.run_module("verify", operation="check", options={"name": "owner"})
    assert result.status == expected, result.to_dict()
    assert seen == ["https://allowed.example/whoami"]
    assert len(list(ledger.runs_dir().glob("*/manifest.json"))) == 1
    if expected == "success":
        assert len(result.evidence) == 1
        assert result.artifacts[0].payload["run_ids"] == [result.evidence[0]["run_id"]]


def test_local_robots_producer_returns_urls_without_route_probe(
    local_workspace, monkeypatch, capsys
):
    from bughunt.core import route

    source = local_workspace / "robots.txt"
    source.write_text("User-agent: *\nDisallow: /owned\n")
    monkeypatch.setattr(
        route, "gate", lambda *_: pytest.fail("Local input probed route")
    )
    result = bughunt.run_module(
        "robots",
        options={
            "inputs": [str(source)],
            "base": "https://owned.example",
            "no_workspace": True,
        },
    )
    assert result.status == "success", result.to_dict()
    assert result.artifacts[0].payload == {"urls": ["https://owned.example/owned"]}
    assert result.evidence == []
    assert capsys.readouterr() == ("", "")


def test_marks_use_shared_mutators_and_report_actual_changes(local_workspace, capsys):
    from bughunt.core import workspace
    from bughunt.modules import blaze

    target = "https://owned.example/login"
    workspace.init_workspace()
    workspace.remember_urls([target])
    options = {"label": "Login", "url": target}
    added = bughunt.run_module("blaze", operation="add", options=options)
    assert added.status == "success", added.to_dict()
    assert blaze.read_marks() == [("login", target)]
    assert added.artifacts[0].payload["changed"] is True
    repeated = bughunt.run_module("blaze", operation="add", options=options)
    assert repeated.artifacts[0].payload["changed"] is False
    listing = bughunt.run_module("blaze")
    assert listing.operation == "list"
    assert listing.artifacts[0].payload["items"] == [{"label": "login", "url": target}]
    removed = bughunt.run_module("blaze", operation="remove", options=options)
    assert removed.status == "success" and blaze.read_marks() == []
    assert (
        bughunt.run_module("blaze", operation="remove", options=options).status
        == "invalid"
    )
    assert capsys.readouterr() == ("", "")


def test_notes_preserve_comments_and_report_clear_idempotence(local_workspace, capsys):
    from bughunt.modules import quill

    quill.notes_path().write_text("# owned comment\n")
    result = bughunt.run_module(
        "quill", operation="add", options={"text": ["Owned", "note"]}
    )
    assert result.status == "success", result.to_dict()
    assert quill.notes_path().read_text().startswith("# owned comment\n")
    listing = bughunt.run_module("quill")
    assert listing.status == "success" and listing.operation == "list"
    assert listing.artifacts[0].payload["items"][0]["text"] == "Owned note"
    for expected in (True, False):
        cleared = bughunt.run_module("quill", operation="clear")
        assert cleared.status == "success"
        assert cleared.artifacts[0].payload["changed"] is expected
    assert capsys.readouterr() == ("", "")


def test_saved_request_show_redacts_credentials_and_rejects_traversal(
    local_workspace, capsys
):
    from bughunt.core import workspace

    root = workspace.requests_dir()
    root.mkdir()
    (root / "owned.http").write_bytes(
        b"GET /owned HTTP/1.1\r\nHost: owned.example\r\nAuthorization: Bearer private-value\r\n\r\n"
    )
    result = bughunt.run_module(
        "clutch", operation="show", options={"name": "owned.http"}
    )
    assert result.status == "success", result.to_dict()
    assert "private-value" not in json.dumps(result.to_dict())
    assert "GET /owned" in result.artifacts[0].payload["text"]
    assert (
        bughunt.run_module(
            "clutch", operation="show", options={"name": "../owned.http"}
        ).status
        == "invalid"
    )
    assert bughunt.run_module("clutch").operation == "list"
    assert capsys.readouterr() == ("", "")
