"""Controlled named-loopback lab scheduler; not a general race/exploit engine."""

import argparse
import json

import httpx

from bughunt.core import exchange, job, ledger
from bughunt.labs import race


def build_parser():
    parser = argparse.ArgumentParser(prog="bughunt race", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("exchange_id")
    run.add_argument("--mission", required=True)
    run.add_argument("--owned-lab", action="store_true", help="Assert ownership of the named laboratory.")
    run.add_argument("--seconds", type=float, default=5)
    run.add_argument("--max-bytes", type=int, default=65536)
    run.add_argument("--dry-run", action="store_true")
    cancel = commands.add_parser("cancel")
    cancel.add_argument("job_id")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "cancel":
            job.cancel(args.job_id)
            result = {"job_id": args.job_id, "cancel_requested": True, "claim": "Stops new attempts, not in-flight I/O"}
        else:
            plan = race.prepare(exchange.read(args.exchange_id), mission=args.mission, owned_lab=args.owned_lab,
                                seconds=args.seconds, max_bytes=args.max_bytes)
            if not args.dry_run:
                print(json.dumps({"starting_job_id": plan.budget.job_id, "cancel_command": "bughunt race cancel " + plan.budget.job_id}))
            result = race.preview(plan) if args.dry_run else race.execute(plan)
        print(json.dumps(ledger.redact(result), indent=2, sort_keys=True))
        return 2 if result.get("classification") == "invalid" else 0
    except (ValueError, OSError, httpx.HTTPError):
        print("Race job blocked: invalid owned lab, source, mission, load limits or policy.")
        return 2
