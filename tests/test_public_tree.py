"""Guards that also run in the exported source repository."""

import subprocess
from pathlib import Path

import pytest

from public_tree_support import (
    KEY_RULES,
    REPO_ROOT,
    broken_markdown_links,
    findings_for_text,
    public_tree_paths,
    repository_paths,
    scan_paths,
    stale_allowances,
)


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        ".env.production",
        "tests/.private-terms",
        "session.key",
        ".bughunt/requests/raw.txt",
        ".venv/x",
        ".pytest_cache/x",
        "__pycache__/x.pyc",
        "dist/x.whl",
        "build/x",
        "credentials.json",
    ],
)
def test_sensitive_local_paths_are_ignored(path):
    checked = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", path], cwd=REPO_ROOT
    )
    assert checked.returncode == 0, path


@pytest.mark.parametrize(
    "path",
    [
        "examples/targets.example.txt",
        "bughunt/core/route.py",
        ".github/workflows/ci.yml",
        "tests/fixtures/burp_2026_9_2_owned.xml",
    ],
)
def test_public_source_paths_remain_trackable(path):
    checked = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", path], cwd=REPO_ROOT
    )
    assert checked.returncode == 1, path


def test_candidate_has_no_tracked_databases_or_binary_build_artifacts():
    rejected = (".sqlite", ".sqlite3", ".db", ".whl", ".tar", ".tar.gz", ".pem", ".key")
    assert not [path for path in repository_paths() if path.endswith(rejected)]


def test_public_candidate_has_no_credential_shapes():
    assert scan_paths(REPO_ROOT, public_tree_paths(), KEY_RULES) == []


def test_public_markdown_links_resolve_inside_candidate():
    assert broken_markdown_links(REPO_ROOT, public_tree_paths()) == []


def test_link_checker_handles_html_and_reports_missing_paths(tmp_path):
    (tmp_path / "one.md").write_text(
        '[present](two.md) <img src="missing.png">\n```text\n[x](ignored)\n```\n',
        encoding="utf-8",
    )
    (tmp_path / "two.md").write_text("present", encoding="utf-8")
    assert broken_markdown_links(tmp_path, ["one.md", "two.md"]) == [
        "one.md:1 [broken-local-link]"
    ]


def test_secret_controls_scan_fixture_content_and_report_only_rules():
    token = "ghp_" + "a" * 30
    assert findings_for_text("tests/fixtures/example.xml", token, KEY_RULES) == [
        "tests/fixtures/example.xml:1 [github-token]"
    ]


def test_scrub_rejects_undecodable_content(tmp_path):
    (tmp_path / "one.txt").write_bytes(b"invalid\xfftext")
    assert scan_paths(tmp_path, ["one.txt"], KEY_RULES) == ["one.txt:0 [invalid-utf8]"]


def test_link_cannot_escape_candidate_and_reenter_by_name(tmp_path):
    (tmp_path / "one.md").write_text("[outside](../two.md)", encoding="utf-8")
    (tmp_path / "two.md").write_text("inside", encoding="utf-8")
    assert broken_markdown_links(tmp_path, ["one.md", "two.md"]) == [
        "one.md:1 [broken-local-link]"
    ]


def test_allowance_validation_rejects_stale_and_unknown_entries(tmp_path):
    (tmp_path / "one.md").write_text("allowed", encoding="utf-8")
    rules = {"word": "allowed"}
    for allowances in (
        {"word": {"gone.md": {"allowed"}}},
        {"word": {"one.md": {"absent"}}},
        {"unknown": {"one.md": {"allowed"}}},
    ):
        assert stale_allowances(tmp_path, ["one.md"], rules, allowances)
