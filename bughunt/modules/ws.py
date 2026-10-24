"""Owned literal-loopback WebSocket text capture/replay and sanitized receipts."""

import argparse
import json
from pathlib import Path

import httpx

from bughunt.core import exchange, job, ledger
from bughunt.labs import websocket


def build_parser():
    parser = argparse.ArgumentParser(prog="bughunt ws", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("capture", "replay"):
        child = commands.add_parser(name)
        child.add_argument("target", help="WS URL for capture, receipt run ID for replay.")
        if name == "capture":
            child.add_argument("--messages", required=True, help="Private JSON file containing a list of text messages.")
        child.add_argument("--mission", required=True)
        child.add_argument("--owned-lab", action="store_true")
        child.add_argument("--seconds", type=float, default=5)
        child.add_argument("--dry-run", action="store_true")
    cancel = commands.add_parser("cancel")
    cancel.add_argument("job_id")
    show = commands.add_parser("show")
    show.add_argument("run_id")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "cancel":
            job.cancel(args.job_id)
            result = {"job_id": args.job_id, "cancel_requested": True}
        elif args.command == "show":
            result = ledger.export_run(args.run_id)
        else:
            kwargs = {"mission": args.mission, "owned_lab": args.owned_lab, "seconds": args.seconds}
            if args.command == "capture":
                with Path(args.messages).open("rb") as handle:
                    messages = exchange.load_json(handle.read(exchange.INPUT_LIMIT + 1))
                plan = websocket.prepare(args.target, messages, **kwargs)
            else:
                plan = websocket.replay_plan(args.target, **kwargs)
            if not args.dry_run:
                print(json.dumps({"starting_job_id": plan.budget.job_id, "cancel_command": "bughunt ws cancel " + plan.budget.job_id}))
            result = websocket.preview(plan) if args.dry_run else websocket.execute(plan)
        print(json.dumps(ledger.redact(result), indent=2, sort_keys=True))
        return 2 if result.get("classification") == "invalid" else 0
    except (ValueError, OSError, httpx.HTTPError, ImportError, KeyError, TypeError):
        print("WebSocket job blocked: invalid owned lab, source, mission, protocol or limits.")
        return 2
