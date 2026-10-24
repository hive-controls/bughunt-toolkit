"""Run the fixed owned HTTP/1.1 front/back parser laboratory."""

import argparse
import json

from bughunt.core import job, ledger
from bughunt.labs import desync


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bughunt desync", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "dry-run"):
        command = commands.add_parser(name)
        command.add_argument("front_url", help="Exact owned front-end laboratory URL and port.")
        command.add_argument("backend_url", help="Exact owned back-end laboratory URL and port.")
        command.add_argument("--mission", required=True)
        command.add_argument("--owned-lab", action="store_true")
        command.add_argument("--seconds", type=float, default=10)
    for name in ("status", "cancel"):
        command = commands.add_parser(name)
        command.add_argument("job_id")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command in {"run", "dry-run"}:
            plan = desync.prepare(args.front_url, args.backend_url,
                                  mission=args.mission, owned_lab=args.owned_lab,
                                  seconds=args.seconds)
            def announce(job_id):
                print(json.dumps({"starting_job_id": job_id,
                                  "cancel_command": "bughunt desync cancel " + job_id}),
                      flush=True)
            result = (desync.preview(plan) if args.command == "dry-run"
                      else desync.execute(plan, on_start=announce))
        else:
            if args.command == "cancel":
                job.cancel(args.job_id)
            result = desync.status(args.job_id)
        print(json.dumps(ledger.redact(result), indent=2, sort_keys=True))
        return 2 if result.get("classification") == "invalid" else 0
    except (OSError, ValueError, TypeError, KeyError):
        print("Desync lab blocked: check exact owned ports, mission, policy, actor and limits.")
        return 2
