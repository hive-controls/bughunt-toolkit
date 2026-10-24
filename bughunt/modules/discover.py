"""Bounded header/cookie/query candidate discovery; no automatic exploitation."""

import argparse
import json

import httpx

from bughunt.core import discovery, exchange, ledger


def build_parser():
    parser = argparse.ArgumentParser(prog="bughunt discover", description=__doc__)
    parser.add_argument("exchange_id")
    for kind in ("header", "cookie", "query"):
        parser.add_argument("--" + kind, action="append", default=[], help="Explicit candidate name (repeatable).")
    parser.add_argument("--requests", type=int, default=30, help="Hard cap, including controls; at most 100.")
    parser.add_argument("--seconds", type=float, default=60, help="Job deadline, at most 300 seconds.")
    parser.add_argument("--max-bytes", type=int, default=65536)
    parser.add_argument("--dry-run", action="store_true")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        candidates = [(kind, name) for kind in ("header", "cookie", "query") for name in getattr(args, kind)]
        plan = discovery.prepare(exchange.read(args.exchange_id), candidates, maximum=args.requests,
                                 seconds=args.seconds, max_bytes=args.max_bytes)
        result = discovery.preview(plan) if args.dry_run else discovery.execute(plan)
        print(json.dumps(ledger.redact(result), indent=2, sort_keys=True))
        return 2 if result.get("classification") == "invalid" else 0
    except (ValueError, OSError, httpx.HTTPError):
        print("Discovery blocked: invalid source, candidate, budget, actor or mission policy.")
        return 2
