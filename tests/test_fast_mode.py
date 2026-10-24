"""BH-23 fast mode: a scan flag that auto-generates a scoped, verified mission policy so the
scan's ``egress.authorize`` preflight passes without a manual ``bughunt policy import``.

The safety gate STILL runs -- "fast" removes the manual policy-authoring step, not the gate.
These tests pin the four safety invariants and the boundary behaviour; they never send real
traffic (every scan runs with ``--dry-run``, which exercises the policy decision offline).
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from bughunt.core import egress, scanner as bughunt_scanner
from bughunt.core.policy import read_document
from bughunt.modules.policy import example_document


@pytest.fixture
def workspace(monkeypatch, tmp_path):
    """Point the whole toolchain at an isolated, empty workspace (no scope, no policy)."""
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path))
    return tmp_path


def _dry_run(*argv: str) -> int:
    # 127.0.0.1 is always in scope (loopback), so the POLICY gate -- not the scope gate --
    # is what a bare scan trips; --dry-run exercises the decision without any network call.
    return bughunt_scanner.scan_main([*argv, "--dry-run", "--quiet"])


BASE = ("127.0.0.1", "--ports", "8080", "--http-only")


@pytest.mark.parametrize("flag", ["--dns", "--ct", "--intel"])
def test_fast_enrichment_warns_without_expanding_grants(workspace, capsys, flag):
    assert _dry_run(*BASE, "--fast", "--authorized", flag) == 0
    assert "enrichment" in capsys.readouterr().err
    document, profile = read_document(workspace / "policy.json")
    assert dict(profile.permissions)["dns"] is False
    assert all("127.0.0.1:8080" in asset["origin"] for asset in document["assets"])


def test_unsetup_scan_fails_with_policy_missing_without_fast(workspace, capsys):
    code = _dry_run(*BASE)
    out = capsys.readouterr().out
    assert code == 2
    assert "policy-missing-or-invalid" in out
    assert not (workspace / "policy.json").exists()


def test_fast_mode_authorizes_the_target_and_proceeds_past_the_gate(workspace, capsys):
    code = _dry_run(*BASE, "--fast", "--authorized")
    out = capsys.readouterr().out
    assert code == 0, out
    assert (workspace / "policy.json").exists()
    rows = json.loads(out)
    assert rows and all(row["permitted"] for row in rows)
    assert all(row["operation"] == "active_scan" for row in rows)


def test_fast_policy_is_verified(workspace):
    assert _dry_run(*BASE, "--fast", "--authorized") == 0
    _document, profile = read_document(workspace / "policy.json")
    assert profile.freshness() == "verified"
    assert dict(profile.permissions)["active_scan"] is True


def test_fast_policy_is_scoped_a_different_origin_is_still_blocked(workspace):
    assert _dry_run(*BASE, "--fast", "--authorized") == 0
    # the exact scanned origin is authorised ...
    egress.authorize("http://127.0.0.1:8080/", "active_scan")
    # ... but any OTHER origin under the same loopback host is still blocked (never a wildcard).
    with pytest.raises(egress.PolicyBlocked):
        egress.authorize("http://127.0.0.1:9090/", "active_scan")
    with pytest.raises(egress.PolicyBlocked):
        egress.authorize("http://other.invalid:8080/", "active_scan")


def test_fast_mode_requires_the_authorization_affirmation(workspace, capsys):
    code = _dry_run(*BASE, "--fast")  # no --authorized
    out = capsys.readouterr().out
    assert code == 2
    assert "authorized" in out.lower()
    assert not (workspace / "policy.json").exists()


def test_fast_mode_does_not_silently_clobber_a_hand_authored_policy(workspace, capsys):
    hand_authored = json.dumps(example_document())  # source is not the fast-mode marker
    (workspace / "policy.json").write_text(hand_authored, encoding="utf-8")
    code = _dry_run(*BASE, "--fast", "--authorized")
    out = capsys.readouterr().out
    assert code == 2
    assert (workspace / "policy.json").read_text(encoding="utf-8") == hand_authored
    assert "overwrite" in out.lower() or "already exists" in out.lower()


def test_fast_scope_persists_but_stale_policy_denies_selected_method(workspace):
    assert _dry_run(*BASE, "--fast", "--authorized", "--method", "HEAD") == 0
    document, profile = read_document(workspace / "policy.json")
    assert document["assets"][0]["methods"] == ["GET", "HEAD"]
    assert "127.0.0.1" in (workspace / "scope.txt").read_text()
    decision = profile.decide(
        "http://127.0.0.1:8080/",
        "active_scan",
        method="HEAD",
        now=profile.verified_at + timedelta(hours=24),
    )
    assert not decision.permitted and decision.reason == "policy-stale"
