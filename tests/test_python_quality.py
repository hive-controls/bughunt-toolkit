"""Exercise the Python quality gate against Git index and working tree snapshots."""

import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

GATE = Path(__file__).resolve().parents[1] / "scripts" / "check_python_quality.py"


@pytest.fixture
def quality_project(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "config", "core.autocrlf", "false"], cwd=tmp_path, check=True
    )
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / GATE.name).write_bytes(GATE.read_bytes())
    (tmp_path / "pyproject.toml").write_text(
        '[tool.ruff]\nrequired-version = "==0.17.1"\ntarget-version = "py312"\n'
        '[tool.ruff.lint]\nselect = ["E9", "F63", "F7", "F82"]\n',
        encoding="utf-8",
    )
    write_baseline(tmp_path, {})
    return tmp_path


def write_baseline(project, files):
    entries = {
        path: hashlib.sha256(content.replace(b"\r\n", b"\n")).hexdigest()
        for path, content in files.items()
    }
    (project / "scripts" / "python-quality-baseline.json").write_text(
        json.dumps({"schema_version": 1, "format_sha256": entries}),
        encoding="utf-8",
    )


def run_quality(project, *arguments):
    return subprocess.run(
        [sys.executable, str(project / "scripts" / GATE.name), *arguments],
        cwd=project,
        capture_output=True,
        text=True,
    )


def stage(project):
    subprocess.run(["git", "add", "."], cwd=project, check=True)


def test_clean_files_and_unchanged_legacy_format_pass(quality_project):
    legacy = b"answer=42\n"
    (quality_project / "legacy.py").write_bytes(legacy)
    (quality_project / "clean.py").write_text("answer = 42\n", encoding="utf-8")
    write_baseline(quality_project, {"legacy.py": legacy})
    result = run_quality(quality_project)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("content", ["answer = missing_name\n", "if True\n"])
def test_lint_errors_fail_even_when_format_is_grandfathered(quality_project, content):
    encoded = content.encode()
    (quality_project / "broken.py").write_bytes(encoded)
    write_baseline(quality_project, {"broken.py": encoded})
    result = run_quality(quality_project)
    assert result.returncode != 0
    assert (
        "F821" in result.stdout + result.stderr
        or "invalid-syntax" in result.stdout + result.stderr
    )


def test_new_unformatted_python_fails(quality_project):
    (quality_project / "new.py").write_text("answer=42\n", encoding="utf-8")
    result = run_quality(quality_project)
    assert result.returncode != 0
    assert "new.py" in result.stdout + result.stderr


def test_edited_legacy_file_must_format_and_retire_its_baseline(quality_project):
    write_baseline(quality_project, {"legacy.py": b"answer=42\n"})
    (quality_project / "legacy.py").write_text("answer = 43\n", encoding="utf-8")
    result = run_quality(quality_project)
    assert result.returncode != 0
    assert "retire" in (result.stdout + result.stderr).lower()
    write_baseline(quality_project, {})
    assert run_quality(quality_project).returncode == 0


def test_staged_gate_rejects_bad_index_despite_clean_working_copy(quality_project):
    path = quality_project / "partial.py"
    path.write_text("answer=42\n", encoding="utf-8")
    stage(quality_project)
    path.write_text("answer = 42\n", encoding="utf-8")
    result = run_quality(quality_project, "--staged")
    assert result.returncode != 0
    assert "partial.py" in result.stdout + result.stderr


def test_staged_gate_uses_staged_baseline_and_ignores_unstaged_changes(quality_project):
    path = quality_project / "partial.py"
    path.write_text("answer = 42\n", encoding="utf-8")
    stage(quality_project)
    path.write_text("answer=42\n", encoding="utf-8")
    write_baseline(quality_project, {"partial.py": path.read_bytes()})
    result = run_quality(quality_project, "--staged")
    assert result.returncode == 0, result.stdout + result.stderr


def test_staged_gate_does_not_trust_unstaged_baseline_expansion(quality_project):
    path = quality_project / "partial.py"
    path.write_text("answer=42\n", encoding="utf-8")
    stage(quality_project)
    write_baseline(quality_project, {"partial.py": path.read_bytes()})
    assert run_quality(quality_project, "--staged").returncode != 0


def test_legacy_hashes_are_portable_across_checkout_line_endings(quality_project):
    write_baseline(quality_project, {"legacy.py": b"answer=42\n"})
    (quality_project / "legacy.py").write_bytes(b"answer=42\r\n")
    assert run_quality(quality_project).returncode == 0


def test_vendor_and_scratch_python_are_outside_first_party_gate(quality_project):
    for folder in ("addons", "scratchpad"):
        (quality_project / folder).mkdir()
        (quality_project / folder / "foreign.py").write_text(
            "answer = missing_name\n", encoding="utf-8"
        )
    assert run_quality(quality_project).returncode == 0


def test_managed_python_is_checked_even_in_ruff_default_excluded_folders(
    quality_project,
):
    folder = quality_project / "tests" / "build"
    folder.mkdir(parents=True)
    (folder / "broken.py").write_text("answer = missing_name\n", encoding="utf-8")
    result = run_quality(quality_project)
    assert result.returncode != 0
    assert "F821" in result.stdout + result.stderr


def test_quality_entrypoints_share_pinned_gate_and_staged_commit_scope():
    root = GATE.parents[1]
    command = "python scripts/check_python_quality.py"
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for job_name in ("test", "smoke"):
        job = re.search(rf"(?ms)^  {job_name}:\n(.*?)(?=^  [\w-]+:\n|\Z)", workflow)
        assert job is not None, f"Missing CI job: {job_name}"
        job_block = job.group(1)
        assert re.search(rf"(?m)^ +run: {re.escape(command)}$", job_block)
        assert re.search(
            r"(?m)^ +(?:python -m )?pip install -r requirements-dev\.txt(?:\s|$)",
            job_block,
        )
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version = config["tool"]["ruff"]["required-version"].removeprefix("==")
    assert f"ruff=={version}" in (root / "requirements-dev.txt").read_text(
        encoding="utf-8"
    )
