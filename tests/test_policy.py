"""Exact-asset policy fixtures; no DNS, sockets or subprocesses."""

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import json
import io
from pathlib import Path
import socket
import subprocess

import pytest
from rich.console import Console

from bughunt.console import cli, loader, options
from bughunt.modules import policy as command
from bughunt.core.policy import PolicyError, parse_profile, read_document

NOW = datetime(2026, 10, 12, 12, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def no_outbound(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Outbound boundary reached")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.fixture
def document():
    profile = command.example_document()
    profile["state"] = "verified"
    profile["verified_at"] = NOW.isoformat()
    profile["assets"][0]["origin"] = "https://lab.example"
    profile["exclusions"][0]["origin"] = "https://lab.example"
    profile["assets"][0]["paths"].append("/health")
    return profile


def test_permitted_fixture_preserves_contract(document):
    profile = parse_profile(document)
    decision = profile.decide("https://lab.example/api/objects?id=1", "manual", now=NOW)
    assert decision.permitted and decision.asset_id == "lab-api"
    assert decision.policy_version == "1" and decision.mission == "owned-lab"
    assert profile.requests_per_second == 1 and profile.concurrency == 1
    assert profile.required_headers == (("X-Researcher", "owned-lab"),)
    assert profile.source == document["source"]
    assert profile.ai_notes == document["ai_notes"]
    assert profile.confidentiality_notes == document["confidentiality_notes"]
    assert profile.user_agent == "Bughunt-owned-lab"
    assert profile.decide("https://lab.example:443/health", "manual", now=NOW).permitted
    with pytest.raises(FrozenInstanceError):
        profile.state = "draft"


@pytest.mark.parametrize(
    "target,reason",
    [
        ("https://lab.example/api/admin/users", "asset-excluded"),
        ("https://other.example/api/", "asset-unknown"),
        ("https://child.lab.example/api/", "asset-unknown"),
        ("http://lab.example/api/", "asset-unknown"),
        ("https://lab.example:8443/api/", "asset-unknown"),
        ("https://lab.example/health/more", "asset-unknown"),
        ("https://lab.example/api", "asset-unknown"),
        ("http://127.0.0.1/api/", "asset-unknown"),
        ("https://lab.example/api/../outside", "invalid-target"),
        ("https://lab.example/api/%2e%2e/admin", "invalid-target"),
        ("https://lab.example/api/%2fadmin", "invalid-target"),
        ("https://lab.example/api//admin", "invalid-target"),
        ("https://lab.example/api/\\admin", "invalid-target"),
        ("https://user:secret@lab.example/api/", "invalid-target"),
        ("https://lab.example/api/#fragment", "invalid-target"),
        ("https://lab.example:bad/api/", "invalid-target"),
        ("ftp://lab.example/api/", "invalid-target"),
        ("lab.example", "invalid-target"),
        ("https://127.1/api/", "invalid-target"),
    ],
)
def test_rejects_target_boundaries(document, target, reason):
    decision = parse_profile(document).decide(target, "manual", now=NOW)
    assert not decision.permitted and decision.reason == reason


@pytest.mark.parametrize("state", ["draft", "unknown", "stale"])
def test_unverified_states_block(document, state):
    document["state"] = state
    decision = parse_profile(document).decide(
        "https://lab.example/api/", "manual", now=NOW
    )
    assert not decision.permitted and decision.reason == f"policy-{state}"


def test_freshness_boundary_and_future_verification(document):
    profile = parse_profile(document)
    assert profile.freshness(NOW + timedelta(seconds=86399)) == "verified"
    assert profile.freshness(NOW + timedelta(seconds=86400)) == "stale"
    assert profile.freshness(NOW - timedelta(seconds=1)) == "unverified"
    with pytest.raises(PolicyError):
        profile.freshness(NOW.replace(tzinfo=None))


@pytest.mark.parametrize(
    "operation,method",
    [
        ("crawl", "GET"),
        ("fuzz", "GET"),
        ("active_scan", "GET"),
        ("unexpected", "GET"),
        ("manual", "POST"),
        ("manual", "get"),
    ],
)
def test_operation_and_http_method_are_explicit(document, operation, method):
    assert (
        not parse_profile(document)
        .decide("https://lab.example/api/", operation, method=method, now=NOW)
        .permitted
    )


def test_global_grant_cannot_widen_row_or_overlapping_grant(document):
    document["permissions"]["crawl"] = True
    profile = parse_profile(document)
    assert not profile.decide("https://lab.example/api/", "crawl", now=NOW).permitted
    document["assets"].append(
        {
            "id": "restricted",
            "origin": "https://lab.example",
            "paths": ["/api/private/"],
            "operations": ["manual"],
            "methods": ["HEAD"],
        }
    )
    profile = parse_profile(document)
    assert not profile.decide(
        "https://lab.example/api/private/x", "manual", now=NOW
    ).permitted


def test_global_permission_blocks_even_when_asset_allows(document):
    document["permissions"]["manual"] = False
    decision = parse_profile(document).decide(
        "https://lab.example/api/", "manual", now=NOW
    )
    assert not decision.permitted and decision.reason == "operation-disallowed"


def test_callback_requires_exact_domain_and_permission(document):
    document["permissions"]["callback"] = True
    document["assets"][0]["operations"].append("callback")
    document["callback_domains"] = ["callback.lab.example"]
    profile = parse_profile(document)
    assert profile.decide(
        "https://lab.example/api/",
        "callback",
        callback_domain="callback.lab.example",
        now=NOW,
    ).permitted
    for domain in (
        None,
        "child.callback.lab.example",
        "outside.example",
        "*.lab.example",
    ):
        assert not profile.decide(
            "https://lab.example/api/", "callback", callback_domain=domain, now=NOW
        ).permitted
    document["permissions"]["callback"] = False
    assert (
        not parse_profile(document)
        .decide(
            "https://lab.example/api/",
            "manual",
            callback_domain="callback.lab.example",
            now=NOW,
        )
        .permitted
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("state", "allow"),
        ("verified_at", "2026-10-12"),
        ("stale_after_seconds", 0),
        ("stale_after_seconds", True),
        ("stale_after_seconds", 31536001),
        ("assets", {}),
        ("source", ""),
        ("user_agent", "bad\r\nheader"),
        ("required_headers", {"Authorization": "secret"}),
        ("required_headers", {"X-API-Key": "secret"}),
        ("required_headers", {"X-Researcher": "one", "x-researcher": "two"}),
        ("required_headers", {"X-Researcher": "bad\r\nvalue"}),
        ("permissions", {"manual": True}),
        ("callback_domains", ["*.example"]),
    ],
)
def test_invalid_profiles_fail_closed(document, field, value):
    document[field] = value
    with pytest.raises(PolicyError):
        parse_profile(document)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Bughunt-owned-lab ", "Bughunt-owned-lab"),
        (" Bughunt-owned-lab", "Bughunt-owned-lab"),
        ("  Bughunt-owned-lab  ", "Bughunt-owned-lab"),
        ("Bughunt-owned-lab", "Bughunt-owned-lab"),
    ],
)
def test_user_agent_surrounding_whitespace_stripped(document, raw, expected):
    document["user_agent"] = raw
    assert parse_profile(document).user_agent == expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("owned-lab ", "owned-lab"),
        (" owned-lab", "owned-lab"),
        ("  owned-lab  ", "owned-lab"),
        ("owned-lab", "owned-lab"),
    ],
)
def test_required_header_value_surrounding_whitespace_stripped(document, raw, expected):
    document["required_headers"] = {"X-Researcher": raw}
    assert parse_profile(document).required_headers == (("X-Researcher", expected),)


@pytest.mark.parametrize(
    "limits",
    [
        {"requests_per_second": 0, "concurrency": 1},
        {"requests_per_second": float("nan"), "concurrency": 1},
        {"requests_per_second": 1, "concurrency": True},
        {"requests_per_second": 1, "concurrency": 1.5},
    ],
)
def test_invalid_limits(document, limits):
    document["limits"] = limits
    with pytest.raises(PolicyError):
        parse_profile(document)


def test_unknown_fields_and_duplicate_row_ids(document):
    document["typo"] = True
    with pytest.raises(PolicyError):
        parse_profile(document)
    document.pop("typo")
    document["exclusions"][0]["id"] = document["assets"][0]["id"]
    with pytest.raises(PolicyError):
        parse_profile(document)


def test_document_rejects_missing_malformed_and_duplicate_json(tmp_path):
    path = tmp_path / "policy.json"
    for content in (None, "{", '{"state":"stale","state":"verified"}', "[]"):
        if content is not None:
            path.write_text(content, encoding="utf-8")
        with pytest.raises(PolicyError):
            read_document(path)


def test_import_and_check_through_real_dispatch(document, tmp_path, monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(command.ui, "console", Console(file=output, width=200))
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "workspace"))
    document["verified_at"] = datetime.now(timezone.utc).isoformat()
    source = tmp_path / "source.json"
    source.write_text(json.dumps(document), encoding="utf-8")

    def forbidden_scan(*args, **kwargs):
        raise AssertionError("Policy command fell through to scanner")

    def dispatch(args):
        return cli.dispatch(
            args,
            scan_main=forbidden_scan,
            build_parser=lambda _: None,
            tool_file=Path(__file__),
            interactive=False,
        )

    assert dispatch(["policy", "import", "--file", str(source)]) == 0
    assert json.loads(command.policy_path().read_text()) == document
    assert (
        dispatch(
            ["policy", "check", "https://lab.example/api/", "--operation", "manual"]
        )
        == 0
    )
    assert (
        dispatch(
            ["policy", "check", "https://outside.example/api/", "--operation", "manual"]
        )
        == 2
    )
    assert "outbound gate" in output.getvalue()
    spec = options.load_spec("policy", tool_file=Path(__file__), build_parser=None)
    assert ("check", "") in spec.subcommands
    assert (
        loader.run_named(
            "policy", ["status"], tool_file=Path(__file__), scan_main=forbidden_scan
        )
        == 0
    )


def test_failed_import_preserves_existing_policy(tmp_path, monkeypatch):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    command.policy_path().write_text("original", encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("{}", encoding="utf-8")
    assert command.main(["import", "--file", str(bad)]) == 2
    assert command.policy_path().read_text() == "original"


def test_example_is_draft_and_missing_workspace_blocks(tmp_path, monkeypatch):
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    assert parse_profile(command.example_document()).freshness() == "draft"
    assert command.main(["status"]) == 2


@pytest.mark.parametrize(
    "origin",
    [
        "https://*.lab.example",
        "https://lab.example/api/",
        "https://lab.example?query=1",
        "https://lab.example:443",
        "https://lab.example.",
    ],
)
def test_noncanonical_origins_reject(document, origin):
    document["assets"][0]["origin"] = origin
    with pytest.raises(PolicyError):
        parse_profile(document)


@pytest.mark.parametrize(
    "field,value",
    [
        ("paths", []),
        ("paths", ["/api/../admin"]),
        ("operations", ["unknown"]),
        ("methods", ["get"]),
        ("methods", []),
    ],
)
def test_invalid_asset_rows(document, field, value):
    document["assets"][0][field] = value
    with pytest.raises(PolicyError):
        parse_profile(document)


def test_malformed_permission_boolean_and_copy_isolation(document):
    document["permissions"]["manual"] = "true"
    with pytest.raises(PolicyError):
        parse_profile(document)
    document["permissions"]["manual"] = True
    profile = parse_profile(document)
    document["assets"][0]["paths"].append("/outside")
    document["permissions"]["manual"] = False
    assert profile.decide("https://lab.example/api/", "manual", now=NOW).permitted
    assert not profile.decide(
        "https://lab.example/outside", "manual", now=NOW
    ).permitted


@pytest.mark.parametrize("change", ["overflow-rate", "overflow-expiry"])
def test_numeric_and_datetime_extremes_are_policy_errors(document, change):
    if change == "overflow-rate":
        document["limits"]["requests_per_second"] = 10**1000
    else:
        document["verified_at"] = "9999-12-31T23:59:59+00:00"
    with pytest.raises(PolicyError):
        parse_profile(document)


def test_cli_hides_invalid_profile_and_target_secrets(tmp_path, monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(command.ui, "console", Console(file=output, width=200))
    source = tmp_path / "bad.json"
    source.write_text('{"Authorization": "super-secret"}', encoding="utf-8")
    assert command.main(["validate", "--file", str(source)]) == 2
    assert "super-secret" not in output.getvalue()


def test_expired_cli_profile_has_visible_block(document, tmp_path, monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(command.ui, "console", Console(file=output, width=200))
    document["verified_at"] = "2020-01-01T00:00:00+00:00"
    source = tmp_path / "stale.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    assert (
        command.main(
            [
                "check",
                "https://lab.example/api/",
                "--operation",
                "manual",
                "--file",
                str(source),
            ]
        )
        == 2
    )
    assert "policy-stale" in output.getvalue()


def test_example_json_remains_parseable_at_narrow_terminal_width(monkeypatch):
    output = io.StringIO()
    monkeypatch.setattr(command.ui, "console", Console(file=output, width=30))
    assert command.main(["example"]) == 0
    document = json.loads(output.getvalue())
    assert parse_profile(document).state == "draft"


def test_explicit_dns_service_labels_can_be_granted(document):
    document["permissions"]["dns"] = True
    document["assets"].append(
        {
            "id": "dmarc",
            "origin": "https://_dmarc.lab.example",
            "paths": ["/"],
            "operations": ["dns"],
            "methods": ["GET"],
        }
    )
    profile = parse_profile(document)
    assert profile.decide("https://_dmarc.lab.example/", "dns", now=NOW).permitted
