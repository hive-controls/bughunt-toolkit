"""Export passive evidence, import hypotheses, or explicitly run the owned active lab."""

import argparse
import json
from pathlib import Path
import subprocess

from bughunt.core import exchange, job, ledger
from bughunt.integrations import zap, zap_active, zap_import, zap_runtime


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    exporter = commands.add_parser("export")
    exporter.add_argument("exchange_ids", nargs="+")
    exporter.add_argument("--actor", action="append", required=True)
    exporter.add_argument("--output", required=True, help="New bundle directory; refuses overwrite.")
    exporter.add_argument("--seconds", type=int, default=300)
    exporter.add_argument("--alerts", type=int, default=10, help="Maximum alerts per passive rule.")
    exporter.add_argument("--body-limit", type=int, default=65536)
    importer = commands.add_parser("import")
    importer.add_argument("report")
    importer.add_argument("--source-id", required=True)
    importer.add_argument("--exchange-id", action="append", default=[], help="Optional URL/method source candidates.")
    show = commands.add_parser("show")
    show.add_argument("run_id")
    active = commands.add_parser("active", help="Explicit owned HTTP-only active profile; never the default.")
    active.add_argument("exchange_id")
    active.add_argument("--mission", required=True)
    active.add_argument("--owned-lab", action="store_true")
    active.add_argument("--technology", required=True)
    active.add_argument("--requests", type=int, default=40)
    active.add_argument("--seconds", type=float, default=120)
    active.add_argument("--body-limit", type=int, default=65536)
    active.add_argument("--dry-run", action="store_true")
    for name in ("status", "cancel"):
        command = commands.add_parser(name)
        command.add_argument("job_id")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "export":
            result = zap.export(args.exchange_ids, args.actor, Path(args.output), seconds=args.seconds,
                                alerts=args.alerts, body_limit=args.body_limit)
        elif args.command == "import":
            with Path(args.report).open("rb") as handle:
                raw = handle.read(exchange.INPUT_LIMIT + 1)
            run_id = zap_import.import_report(raw, source_id=args.source_id,
                                              records=[exchange.read(key) for key in args.exchange_id])
            result = zap_import.summary(run_id)
        elif args.command == "active":
            plan = zap_active.prepare(args.exchange_id, mission=args.mission, owned_lab=args.owned_lab,
                technology=args.technology, requests=args.requests, seconds=args.seconds, max_bytes=args.body_limit)
            def announce(job_id: str) -> None:
                print(json.dumps({"starting_job_id": job_id,
                                  "cancel_command": "bughunt zap cancel " + job_id}), flush=True)
            result = zap_active.preview(plan) if args.dry_run else zap_runtime.run(plan, on_start=announce)
        elif args.command in {"status", "cancel"}:
            if args.command == "cancel":
                job.cancel(args.job_id)
            result = zap_runtime.status(args.job_id)
        else:
            result = ledger.export_run(args.run_id)
        print(json.dumps(ledger.redact(result), indent=2))
        return 2 if result.get("classification") == "inconclusive" else 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print("ZAP operation blocked: check explicit policy, owned profile, pinned consumer, evidence and limits.")
        return 2
