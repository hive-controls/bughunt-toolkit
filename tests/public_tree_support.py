"""Shared public-source inventory and sanitized content checks."""

from __future__ import annotations

import html
import re
import subprocess
import unicodedata
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
KEY_RULES = {
    "cloud-key": r"[A]KIA[0-9A-Z]{16}",
    "github-token": r"[g]hp_[A-Za-z0-9]{20,}|[g]ithub_pat_[A-Za-z0-9_]{20,}",
    "api-token": r"[s]k-[A-Za-z0-9]{20,}",
    "slack-token": r"[x]ox[baprs]-[A-Za-z0-9-]{10,}",
    "google-key": r"[A]Iza[0-9A-Za-z_-]{35}",
    "private-key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "jwt": r"[e]yJ[A-Za-z0-9_-]{20,}\.[e]yJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+",
}
IDENTIFIER_RULES = {
    "email": r"(?<![\w.+-])[A-Za-z0-9_.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])",
    "private-ipv4": r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?![\d.])",
}


def repository_paths(root=REPO_ROOT):
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        capture_output=True,
        check=True,
    )
    return sorted(set(result.stdout.decode("utf-8").strip("\0").split("\0")) - {""})


def public_tree_paths(root=REPO_ROOT):
    paths = repository_paths(root)
    try:
        from private_paths import public_paths
    except ModuleNotFoundError as failure:
        if failure.name != "private_paths":
            raise
        return paths
    return public_paths(paths)


def normalize_term(value):
    return unicodedata.normalize("NFKC", value).casefold()


def read_private_terms(path):
    try:
        terms = {
            normalize_term(line.strip())
            for line in Path(path).read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except (OSError, UnicodeError):
        raise ValueError(
            "Required private-term input is missing or unreadable"
        ) from None
    if not terms:
        raise ValueError("Required private-term input has no active terms")
    return terms


def private_term_rules(terms):
    return {
        f"private-term-{index}": re.escape(term)
        for index, term in enumerate(sorted(terms))
    }


def findings_for_text(path, text, rules, allowances=None):
    compiled = {
        name: re.compile(pattern, re.IGNORECASE) for name, pattern in rules.items()
    }
    findings = []
    for number, line in enumerate(normalize_term(text).splitlines(), 1):
        for name, pattern in compiled.items():
            permitted = (allowances or {}).get(name, {}).get(path, set())
            if any(match.group() not in permitted for match in pattern.finditer(line)):
                findings.append(f"{path}:{number} [{name}]")
    return findings


def scan_paths(root, paths, rules, allowances=None):
    findings = []
    for path in paths:
        full_path = root / path
        if full_path.is_symlink() or not full_path.is_file():
            findings.append(f"{path}:0 [not-regular-file]")
            continue
        data = full_path.read_bytes()
        if b"\0" in data:
            findings.append(f"{path}:0 [unreviewed-binary]")
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            findings.append(f"{path}:0 [invalid-utf8]")
            continue
        findings.extend(findings_for_text(path, text, rules, allowances))
    return findings


def stale_allowances(root, paths, rules, allowances):
    findings = []
    for name, files in allowances.items():
        for path, values in files.items():
            if name not in rules or path not in paths:
                findings.append(f"{path}:0 [invalid-allowance]")
                continue
            text = normalize_term((root / path).read_text(encoding="utf-8"))
            matched = {
                match.group() for match in re.finditer(rules[name], text, re.IGNORECASE)
            }
            if not values or not values.issubset(matched):
                findings.append(f"{path}:0 [stale-allowance]")
    return findings


def broken_markdown_links(root, paths):
    known = set(paths)
    findings = []
    links = re.compile(r"""!?\[[^\]]*\]\(([^)\s]+)\)|(?:href|src)=["']([^"']+)["']""")
    for path in paths:
        if not path.endswith(".md"):
            continue
        in_fence = False
        for number, line in enumerate(
            (root / path).read_text(encoding="utf-8").splitlines(), 1
        ):
            if line.lstrip().startswith(("```", "~~~")):
                in_fence = not in_fence
            if in_fence:
                continue
            for match in links.finditer(line):
                target = html.unescape(next(value for value in match.groups() if value))
                if urlsplit(target).scheme or target.startswith("#"):
                    continue
                parts = list(PurePosixPath(path).parent.parts)
                escaped = False
                for part in unquote(target.split("#")[0]).split("/"):
                    if part == "..":
                        if parts:
                            parts.pop()
                        else:
                            escaped = True
                    elif part not in {"", "."}:
                        parts.append(part)
                resolved = "/".join(parts)
                if escaped or (
                    resolved not in known
                    and not any(item.startswith(resolved + "/") for item in known)
                ):
                    findings.append(f"{path}:{number} [broken-local-link]")
    return findings
