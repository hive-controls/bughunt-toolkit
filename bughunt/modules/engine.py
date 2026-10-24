"""List curated capabilities and start, inspect or cancel a managed engine job."""

import argparse
import json
import subprocess

from bughunt.core import engine, job, ledger
from bughunt.console import capability_map
from bughunt.integrations import burp_intake


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="Filesystem-only capability inventory; performs no engine probe.")
    commands.add_parser("map", help="Versioned fixture coverage and linked gaps; never grants execution authority.")
    for name in ("dry-run", "start"):
        command = commands.add_parser(name)
        command.add_argument("profile_id", help="Curated profile ID from engine list.")
        command.add_argument("exchange_id", nargs="+", help="ZAP capture IDs; selected browser URLs; one exact Burp source URL.")
        command.add_argument("--mission", required=True)
        command.add_argument("--owned-lab", action="store_true")
        command.add_argument("--technology", help="Required for owned active; forbidden for passive.")
        command.add_argument("--requests", type=int, help="Physical send cap for owned active/browser jobs; includes browser probes.")
        command.add_argument("--actor", action="append", help="One owned browser actor, or passive recorded labels (not login claims).")
        command.add_argument("--alerts", type=int, default=10, help="Passive maximum alerts per rule.")
        command.add_argument("--seconds", type=float, default=120)
        command.add_argument("--body-limit", type=int, default=65536)
        command.add_argument("--source-id", help="Explicit Burp source receipt label.")
        command.add_argument("--config", help="Inspected local Burp profile; never arbitrary commands.")
        command.add_argument("--offset", type=int, help="Explicit Burp history offset, 0..500.")
        command.add_argument("--count", type=int, help="One selected Burp page, 1..10 items.")
        command.add_argument("--method", help="Exact selected Burp request method.")
    doctor = commands.add_parser("doctor", help="Inspect configured Community fingerprints; optional owned handshake only.")
    doctor.add_argument("profile_id", choices=("burp-mcp-intake",))
    doctor.add_argument("--config")
    doctor.add_argument("--probe", action="store_true", help="Create a bounded handshake job; does not read history.")
    doctor.add_argument("--mission")
    doctor.add_argument("--target", help="Exact authorized source target for the probe's policy contract.")
    doctor.add_argument("--method", default="GET")
    doctor.add_argument("--seconds", type=float, default=10)
    for name in ("status", "cancel"):
        commands.add_parser(name).add_argument("job_id")
    return parser


def _announce(job_id: str) -> None:
    value = job.status(job_id)
    print(json.dumps({"starting_job_id": job_id, "run_id": value["run_id"],
                      "cancel_command": "bughunt engine cancel " + job_id}), flush=True)


def _prepare(args):
    selected = {name: getattr(args, name) for name in ("source_id", "config", "offset", "count", "method")
                if getattr(args, name) is not None}
    if selected and args.profile_id != "burp-mcp-intake":
        raise ValueError("Burp intake selection options cannot alter other profiles")
    return engine.prepare(args.profile_id, args.exchange_id, mission=args.mission,
        owned_lab=args.owned_lab, technology=args.technology, requests=args.requests,
        actors=args.actor, alerts=args.alerts, seconds=args.seconds, max_bytes=args.body_limit, **selected)


def _doctor(args):
    if not args.probe:
        return burp_intake.doctor(config=args.config)
    if not args.mission or not args.target:
        raise ValueError("Doctor probe requires an exact owned target and current mission")
    plan = burp_intake.prepare(mission=args.mission, url=args.target, method=args.method,
        source_id="doctor-probe", seconds=args.seconds, config=args.config)
    return burp_intake.run(plan, probe=True, on_start=_announce)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list":
            result = engine.capabilities()
        elif args.command == "map":
            result = capability_map.describe()
        elif args.command == "doctor":
            result = _doctor(args)
        elif args.command in {"dry-run", "start"}:
            plan = _prepare(args)
            result = engine.preview(plan) if args.command == "dry-run" else engine.run(plan, on_start=_announce)
        else:
            if args.command == "cancel":
                job.cancel(args.job_id)
            result = job.status(args.job_id)
        print(json.dumps(ledger.redact(result), indent=2))
        return 2 if result.get("classification") == "inconclusive" else 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print("Engine operation blocked: check current policy, curated profile, evidence fingerprints and bounds.")
        return 2
