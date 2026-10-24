"""Inspect sanitized run manifests and exports."""

import argparse
import json

from bughunt.core import ledger


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bughunt ledger", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    for name in ("show", "export"):
        child = commands.add_parser(name)
        child.add_argument("run_id")
    cleanup = commands.add_parser("cleanup")
    cleanup.add_argument("run_id")
    cleanup.add_argument("state", choices=("pending", "complete", "retained"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list":
            result = [ledger.redact(ledger.manifest_for(path.parent.name))
                      for path in sorted(ledger.runs_dir().glob("*/manifest.json"))]
        elif args.command == "show":
            result = ledger.redact(ledger.manifest_for(args.run_id))
        elif args.command == "cleanup":
            manifest = ledger.manifest_for(args.run_id)
            manifest["cleanup"] = args.state
            ledger._write_private(ledger.runs_dir() / args.run_id / "manifest.json",
                                  json.dumps(manifest, indent=2).encode())
            result = ledger.redact(manifest)
        else:
            result = ledger.export_run(args.run_id)
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError):
        print("Ledger read/export blocked: missing, invalid or changed evidence.")
        return 2
