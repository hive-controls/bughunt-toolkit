"""Register issued approved payloads and import inert normalized callbacks."""

import argparse
import json
from pathlib import Path

import httpx

from bughunt.core import exchange, ledger, oast


def build_parser():
    parser = argparse.ArgumentParser(prog="bughunt oast", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    registration = commands.add_parser("register")
    registration.add_argument("run_id")
    registration.add_argument("--provider", required=True, choices=("collaborator", "interactsh-selfhosted"))
    registration.add_argument("--domain", required=True, help="Exact already-issued payload hostname approved in mission policy.")
    incoming = commands.add_parser("import")
    incoming.add_argument("file")
    incoming.add_argument("--source-id", required=True)
    show = commands.add_parser("show")
    show.add_argument("run_id")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.command == "register":
            result = oast.register(args.run_id, provider=args.provider, domain=args.domain)
        elif args.command == "show":
            result = ledger.export_run(args.run_id)
        else:
            with Path(args.file).open("rb") as handle:
                result = oast.import_callbacks(handle.read(exchange.INPUT_LIMIT + 1), source_id=args.source_id)
        print(json.dumps(ledger.redact(result), indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError, httpx.HTTPError, KeyError, TypeError):
        print("OAST blocked: invalid provider, payload, callback evidence or mission policy.")
        return 2
