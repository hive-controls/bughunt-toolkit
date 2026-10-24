"""Replay one owned baseline as verified owner, lower privilege, and anonymous."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx

from bughunt.core import identity, ledger, verification
from bughunt.labs import replay
from bughunt.modules.repeater import apply_edits, parse_raw, remove_header


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bughunt replay", description=__doc__)
    parser.add_argument("request", help="Captured raw HTTP request file.")
    parser.add_argument("--owner", required=True, help="Owned actor with kind owner.")
    parser.add_argument(
        "--lower", required=True, help="Owned actor with kind lower_privilege."
    )
    parser.add_argument(
        "--anonymous", required=True, help="Credential-free anonymous actor."
    )
    parser.add_argument(
        "--observe",
        help="Owned JSON state URL; verified owner reads it before/after each replay.",
    )
    parser.add_argument(
        "--compare-header",
        action="append",
        help="Response header to compare; defaults to Content-Type and Location.",
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=65536,
        help="Response body cap, at most 1000000.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15,
        help="Per-request timeout, at most 30 seconds.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate actors, policy and baseline without sending.",
    )
    parser.add_argument("--method", help="Explicitly replace the baseline method.")
    parser.add_argument("--path", help="Explicitly replace the baseline path/query.")
    parser.add_argument("--host", help="Explicitly replace the baseline host.")
    parser.add_argument(
        "--scheme",
        choices=("http", "https"),
        help="Required for TLS when the capture has a relative target.",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        help="Explicitly replace one header as Name: value.",
    )
    parser.add_argument("--remove-header", action="append", default=[])
    bodies = parser.add_mutually_exclusive_group()
    bodies.add_argument(
        "--body", help="Explicitly replace the body; may enter shell history."
    )
    bodies.add_argument("--body-file", help="Explicitly replace the body from a file.")
    return parser


def prepare_args(args: argparse.Namespace) -> replay.Plan:
    try:
        path = Path(args.request)
        if path.stat().st_size > 8 * 1024 * 1024:
            raise replay.ReplayError("baseline-too-large")
        source = path.read_bytes()
    except FileNotFoundError as error:
        raise replay.ReplayError("baseline-missing") from error
    request = apply_edits(parse_raw(source), args)
    if args.body is not None or args.body_file:
        remove_header(request, "Content-Length")
    return replay.prepare(
        request,
        source,
        (args.owner, args.lower, args.anonymous),
        selected_headers=args.compare_header or ("content-type", "location"),
        observe_url=args.observe,
        max_bytes=args.max_bytes,
        timeout=args.timeout,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        plan = prepare_args(args)
        result = replay.preview(plan) if args.dry_run else replay.execute(plan)
        print(json.dumps(ledger.redact(result), indent=2, sort_keys=True))
        return 2 if result.get("classification") == "invalid" else 0
    except (
        ValueError,
        OSError,
        httpx.HTTPError,
        identity.IdentityError,
        verification.VerificationError,
    ):
        print(
            "Replay blocked: invalid baseline, actors, verification, or mission policy."
        )
        return 2
