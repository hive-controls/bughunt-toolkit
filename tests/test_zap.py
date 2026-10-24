"""Owned offline ZAP generation and fail-closed fixtures."""

import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

import pytest

from bughunt.core import exchange, identity
from bughunt.integrations import zap
from bughunt.modules import load_builtin
from bughunt.modules import zap as command
from test_gate import boundaries, policy


def fixture_records(workspace: Path):
    document = json.loads((workspace / "policy.json").read_text())
    document["assets"] = [
        {
            "id": "app",
            "origin": "https://allowed.example",
            "paths": ["/app/", "/exact"],
            "operations": ["passive"],
            "methods": ["GET"],
        },
        {
            "id": "denied-overlap",
            "origin": "https://allowed.example",
            "paths": ["/app/admin/"],
            "operations": ["manual"],
            "methods": ["GET"],
        },
    ]
    document["exclusions"] = [
        {"id": "logout", "origin": "https://allowed.example", "paths": ["/app/logout"]}
    ]
    (workspace / "policy.json").write_text(json.dumps(document))
    identity.create_profile("owner", "owner", ["https://allowed.example"], owned=True)
    identity.set_credential("owner", "authorization", "Bearer fixture-private-secret")
    identity.create_profile(
        "guest", "anonymous", ["https://allowed.example"], owned=True
    )
    request = (
        b"GET https://allowed.example/app/data HTTP/1.1\r\nHost: allowed.example\r\n"
        b"Authorization: Bearer fixture-private-secret\r\n\r\n"
    )
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nowned"
    )
    return [exchange.raw_record(request, response, source_id="whk008-owned-passive")]


def test_plan_is_bounded_import_only_and_secret_free(policy, boundaries):
    _document, workspace = policy
    records = fixture_records(workspace)
    files = zap.build(records, ["owner", "guest"], workspace / "bundle")
    assert not any(b"fixture-private-secret" in data for data in files.values())
    plan = json.loads(files["plan.yaml"])
    assert [job["type"] for job in plan["jobs"]] == [
        "passiveScan-config",
        "import",
        "passiveScan-wait",
        "report",
    ]
    assert plan["jobs"][1]["parameters"]["sendRequests"] is False
    assert plan["jobs"][1]["parameters"]["maxMessages"] == 1
    assert plan["jobs"][0]["parameters"]["maxAlertsPerRule"] == 10
    assert plan["env"]["parameters"]["maxDuration"] == 300
    context = plan["env"]["contexts"][0]
    assert context["users"] == [{"name": "owner"}, {"name": "guest"}]
    assert context["authentication"]["verification"]["loggedInRegex"] == zap.LOGGED_IN
    manifest = json.loads(files["manifest.json"])
    assert manifest["authentication_ready"] is False
    assert manifest["source_exchange_ids"] == [records[0]["exchange_id"]]
    for name, digest in manifest["files"].items():
        assert exchange.digest(files[name]) == digest
    xml = ET.fromstring(files["context.context"])
    assert xml.findtext("context/name") == zap.CONTEXT_NAME
    assert all(";false;" in user.text for user in xml.findall("context/users/user"))


@pytest.mark.parametrize(
    "path,allowed",
    [
        ("/app/data", True),
        ("/app/", True),
        ("/exact", True),
        ("/exact?q=x", True),
        ("/exact/more", False),
        ("/app/logout", False),
        ("/app/logout?q=x", False),
        ("/app/admin/secret", False),
        ("/other", False),
        ("/app//data", False),
        ("/app/../secret", False),
        ("/app/%2e%2e/secret", False),
        ("/app/data#x", False),
    ],
)
def test_context_scope_neutralizes_af_seed_widening(policy, path, allowed):
    _document, workspace = policy
    files = zap.build(fixture_records(workspace), ["owner"], workspace / "bundle")
    context = json.loads(files["plan.yaml"])["env"]["contexts"][0]
    # Include AF's unsafe automatic seed rule too, not only our own includes.
    includes = context["includePaths"] + [url + ".*" for url in context["urls"]]
    target = "https://allowed.example" + path
    permitted = any(re.fullmatch(pattern, target) for pattern in includes) and not any(
        re.fullmatch(pattern, target) for pattern in context["excludePaths"]
    )
    assert permitted is allowed
    assert not any(
        re.fullmatch(pattern, "https://allowedXexample/app/data")
        for pattern in context["includePaths"]
    )


@pytest.mark.parametrize(
    "state", ["unknown", "stale", "draft", "missing", "disallowed"]
)
def test_unknown_stale_policy_prevents_artifacts(policy, boundaries, state):
    _document, workspace = policy
    records = fixture_records(workspace)
    path = workspace / "policy.json"
    document = json.loads(path.read_text())
    if state == "missing":
        path.unlink()
    else:
        if state == "disallowed":
            document["permissions"]["passive"] = False
        else:
            document["state"] = state
        path.write_text(json.dumps(document))
    with pytest.raises((OSError, ValueError)):
        zap.build(records, ["owner"], workspace / "bundle")
    assert not (workspace / "bundle").exists()


@pytest.mark.parametrize(
    "change",
    ["excluded", "method", "partial", "no-response", "actor-origin", "duplicate"],
)
def test_unusable_evidence_cannot_generate(policy, boundaries, change):
    _document, workspace = policy
    records = fixture_records(workspace)
    value = records[0]
    if change in {"excluded", "method", "partial", "no-response"}:
        request = exchange.decode(value["request"]["raw_b64"])
        if change == "excluded":
            request = request.replace(b"/app/data", b"/app/logout")
        if change == "method":
            request = request.replace(b"GET ", b"POST ")
        response = (
            exchange.decode(value["response"]["raw_b64"])
            if change != "no-response"
            else None
        )
        records = [
            exchange.raw_record(
                request,
                response,
                source_id="changed",
                response_truncated=change == "partial",
            )
        ]
    if change == "actor-origin":
        identity.create_profile(
            "outside", "owner", ["https://outside.example"], owned=True
        )
    if change == "duplicate":
        records *= 2
    with pytest.raises(zap.ZapError):
        zap.build(
            records,
            ["outside" if change == "actor-origin" else "owner"],
            workspace / "bundle",
        )


@pytest.mark.parametrize(
    "limits",
    [
        {"seconds": 0},
        {"seconds": 3601},
        {"alerts": 0},
        {"alerts": True},
        {"body_limit": 0},
        {"body_limit": 1000001},
    ],
)
def test_unlimited_or_excessive_values_block(policy, limits):
    _document, workspace = policy
    with pytest.raises(zap.ZapError):
        zap.build(fixture_records(workspace), ["owner"], workspace / "bundle", **limits)


def test_cli_new_bundle_no_overwrite(policy, boundaries):
    _document, workspace = policy
    records = fixture_records(workspace)
    ids = exchange.save(
        records, source_id="fixture", source_bytes=b"fixture", kind="raw"
    )
    output = workspace / "bundle"
    assert load_builtin("zap") is command
    assert (
        command.main(["export", *ids, "--actor", "owner", "--output", str(output)]) == 0
    )
    assert (output / "reports").is_dir()
    original = (output / "plan.yaml").read_bytes()
    assert (
        command.main(["export", *ids, "--actor", "owner", "--output", str(output)]) == 2
    )
    assert (output / "plan.yaml").read_bytes() == original


def test_changed_policy_during_generation_blocks(policy, monkeypatch):
    _document, workspace = policy
    records = fixture_records(workspace)
    original = zap._plan

    def change(*args):
        value = original(*args)
        (workspace / "policy.json").write_text("{}")
        return value

    monkeypatch.setattr(zap, "_plan", change)
    with pytest.raises(zap.ZapError):
        zap.build(records, ["owner"], workspace / "bundle")


def test_missing_har_body_cannot_enter_complete_only_zap_export(policy, boundaries):
    from bughunt.core import har

    _document, workspace = policy
    record = fixture_records(workspace)[0]
    document = json.loads(har.export([record], private=True))
    entry = document["log"]["entries"][0]
    entry.pop("_bughunt")
    entry["response"].update(
        bodySize=100,
        content={"size": -1, "mimeType": "text/plain"},
        headers=[{"name": "Content-Length", "value": "100"}],
    )
    records = har.parse(exchange.canonical(document), source_id="omitted-response")
    with pytest.raises(zap.ZapError, match="complete request and response"):
        zap.build(records, ["owner"], workspace / "bundle")
    assert not (workspace / "bundle").exists()


def test_captured_af_variable_is_not_expanded(policy):
    _document, workspace = policy
    value = fixture_records(workspace)[0]
    request = exchange.decode(value["request"]["raw_b64"]).replace(
        b"/app/data", b"/app/${TARGET}"
    )
    record = exchange.raw_record(
        request, exchange.decode(value["response"]["raw_b64"]), source_id="variable"
    )
    with pytest.raises(zap.ZapError):
        zap.build([record], ["owner"], workspace / "bundle")
