"""Inspect and import mission policy without making outbound calls."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile

from bughunt.console import ui
from bughunt.core.policy import OPERATIONS, PolicyError, Profile, parse_profile, read_document
from bughunt.core.workspace import workspace_dir


def policy_path() -> Path:
    return workspace_dir() / "policy.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bughunt policy", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("example", help="Print a synthetic draft profile to author offline.")
    for command in ("import", "validate", "status", "check"):
        child = commands.add_parser(command)
        child.add_argument("--file", type=Path, default=None, required=command == "import",
                           help="Profile file; defaults to the workspace policy.json.")
        if command == "check":
            child.add_argument("target", help="Exact HTTP(S) URL. Evaluated offline only.")
            child.add_argument("--operation", required=True, choices=OPERATIONS)
            child.add_argument("--method", default="GET")
            child.add_argument("--callback-domain")
    return parser


def _summary(profile: Profile) -> dict:
    return {
        "mission": profile.mission, "policy_version": profile.policy_version,
        "state": profile.freshness(), "verified_at": profile.verified_at.isoformat(),
        "stale_after_seconds": profile.stale_after_seconds,
        "assets": len(profile.assets), "exclusions": len(profile.exclusions),
        "permissions": dict(profile.permissions),
        "limits": {"requests_per_second": profile.requests_per_second,
                   "concurrency": profile.concurrency},
        "outbound_enforcement": "outbound gate at transport/socket/process boundaries; check is offline",
    }


def _install(document: dict) -> None:
    destination = policy_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent,
                                         prefix="policy-", suffix=".tmp", delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(document, handle, indent=2, allow_nan=False)
            handle.write("\n")
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def install_document(document: dict) -> None:
    """Validate a policy document, then atomically write it to the workspace policy.json."""
    parse_profile(document)
    _install(document)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "example":
            output = example_document()
            permitted = True
        else:
            document, profile = read_document(args.file or policy_path())
            if args.command == "check":
                decision = profile.decide(args.target, args.operation, method=args.method,
                                          callback_domain=args.callback_domain)
                output = asdict(decision)
                permitted = decision.permitted
            else:
                if args.command == "import":
                    _install(document)
                output = _summary(profile)
                permitted = args.command == "import" or profile.freshness() == "verified"
        ui.console.print(json.dumps(output, indent=2), markup=False, highlight=False, soft_wrap=True)
        return 0 if permitted else 2
    except (PolicyError, OSError):
        ui.console.print("Policy blocked: missing, unreadable or invalid profile. No outbound action ran.",
                         markup=False)
        return 2


def example_document() -> dict:
    return {
        "schema_version": 1, "mission": "owned-lab", "policy_version": "1",
        "state": "draft", "source": "Owned laboratory rules; replace with verified provenance",
        "verified_at": datetime.now(timezone.utc).isoformat(), "stale_after_seconds": 86400,
        "assets": [{"id": "lab-api", "origin": "http://127.0.0.1:8080", "paths": ["/api/"],
                    "operations": ["manual"], "methods": ["GET", "HEAD"]}],
        "exclusions": [{"id": "lab-admin", "origin": "http://127.0.0.1:8080",
                        "paths": ["/api/admin/"]}],
        "permissions": {operation: operation == "manual" for operation in OPERATIONS},
        "limits": {"requests_per_second": 1, "concurrency": 1},
        "required_headers": {"X-Researcher": "owned-lab"}, "user_agent": "Bughunt-owned-lab",
        "callback_domains": [], "ai_notes": "Confirm AI policy before marking verified.",
        "confidentiality_notes": "Keep private evidence in the ignored workspace.",
    }
