"""Check first-party Python with Ruff, preserving only exact legacy format hashes.

The format baseline is adoption debt, never a list of permanent file exclusions.
After editing a listed file, format it and retire its entry. There is intentionally
no command for regenerating this baseline. Staged checks read the Git index,
including the staged Ruff configuration and baseline, to handle partial staging.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

BASELINE = "scripts/python-quality-baseline.json"
CONFIG = "pyproject.toml"


def managed_python(filename: str) -> bool:
    parts = PurePosixPath(filename).parts
    return filename.endswith(".py") and (
        len(parts) == 1 or parts[0] in {"bughunt", "tests", "bin", "scripts"}
    )


def git_output(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", *arguments], cwd=root, capture_output=True, check=True
    ).stdout


def read_snapshot(root: Path, filename: str, staged: bool) -> bytes:
    if staged:
        return git_output(root, "show", f":{filename}")
    return (root / filename).read_bytes()


def collect_sources(root: Path, staged: bool) -> tuple[dict[str, bytes], set[str]]:
    if staged:
        names = git_output(
            root,
            "diff",
            "--cached",
            "--name-only",
            "--no-renames",
            "--diff-filter=ACMRD",
            "-z",
            "--",
            "*.py",
        )
        present = set(git_output(root, "ls-files", "-z").split(b"\0"))
    else:
        names = git_output(
            root, "ls-files", "--cached", "--others", "--exclude-standard", "-z"
        )
        present = None
    selected = {
        name.decode("utf-8")
        for name in names.split(b"\0")
        if name and managed_python(name.decode("utf-8"))
    }
    sources = {}
    for filename in sorted(selected):
        exists = (
            filename.encode("utf-8") in present
            if staged
            else (root / filename).is_file()
        )
        if exists:
            sources[filename] = read_snapshot(root, filename, staged)
    return sources, selected


def load_baseline(contents: bytes) -> dict[str, str]:
    baseline = json.loads(contents)
    if baseline.get("schema_version") != 1:
        raise ValueError("Unsupported Python quality baseline schema.")
    entries = baseline.get("format_sha256")
    if not isinstance(entries, dict) or any(
        not managed_python(path)
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        for path, digest in entries.items()
    ):
        raise ValueError("Invalid format_sha256 baseline entries.")
    return entries


def content_hash(contents: bytes) -> str:
    return hashlib.sha256(contents.replace(b"\r\n", b"\n")).hexdigest()


def run_ruff(snapshot: Path, command: str, *arguments: str) -> int:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            command,
            "--config",
            str(snapshot / CONFIG),
            "--no-cache",
            "--output-format",
            "concise",
            *arguments,
        ],
        cwd=snapshot,
        check=False,
    ).returncode


def check_quality(root: Path, *, staged: bool, lint: bool, formatting: bool) -> int:
    sources, selected = collect_sources(root, staged)
    if not selected and staged:
        print("No staged first-party Python changes.")
        return 0
    baseline = load_baseline(read_snapshot(root, BASELINE, staged))
    retired = sorted(
        path
        for path, digest in baseline.items()
        if (path in selected or not staged)
        and (path not in sources or content_hash(sources[path]) != digest)
    )
    result = 0
    with tempfile.TemporaryDirectory(prefix="bughunt-quality-") as directory:
        snapshot = Path(directory)
        (snapshot / CONFIG).write_bytes(read_snapshot(root, CONFIG, staged))
        for filename, contents in sources.items():
            destination = snapshot / filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(contents)
        if lint and sources:
            result |= run_ruff(snapshot, "check", ".")
        if formatting:
            for path in retired:
                print(
                    f"{path}: format the edited file and retire its entry in {BASELINE}."
                )
            result |= bool(retired)
            candidates = [
                path
                for path, contents in sources.items()
                if content_hash(contents) != baseline.get(path)
            ]
            print(
                f"Format: {len(candidates)} checked; "
                f"{len(sources) - len(candidates)} unchanged legacy files."
            )
            if candidates:
                result |= run_ruff(snapshot, "format", "--check", *candidates)
    return int(bool(result))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--staged", action="store_true", help="check index content only"
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--lint-only", action="store_true")
    mode.add_argument("--format-only", action="store_true")
    arguments = parser.parse_args()
    try:
        return check_quality(
            Path(__file__).resolve().parents[1],
            staged=arguments.staged,
            lint=not arguments.format_only,
            formatting=not arguments.lint_only,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Python quality gate failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
