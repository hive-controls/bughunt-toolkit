"""Import, export and group inert raw HTTP, HAR, Burp XML and native records."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from bughunt.core import exchange, har, ledger, triage
from bughunt.integrations import burp


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bughunt exchange", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    raw = commands.add_parser("import-raw", help="Retain one request and optional response; never replay.")
    raw.add_argument("request")
    raw.add_argument("--response")
    raw.add_argument("--url", help="Full URL required for a relative captured target.")
    raw.add_argument("--source-id", required=True)
    raw.add_argument("--timestamp", help="ISO capture time with timezone; absent means unknown.")
    raw.add_argument("--actor", help="Source actor label, not a verified identity assertion.")
    raw.add_argument("--run-id", help="Optional source run UUID; linkage is metadata only.")
    raw.add_argument("--request-truncated", action="store_true")
    raw.add_argument("--response-truncated", action="store_true")
    for name in ("import-har", "import-json", "import-burp"):
        importer = commands.add_parser(name)
        importer.add_argument("file")
        importer.add_argument("--source-id", required=True)
        if name == "import-burp":
            importer.add_argument("--timezone", required=True, help="IANA timezone matching the Burp capture/export clock.")
    run = commands.add_parser("import-run", help="Import hash-checked captures from the local ledger.")
    run.add_argument("run_id")
    commands.add_parser("list")
    show = commands.add_parser("show")
    show.add_argument("exchange_id")
    group = commands.add_parser("group", help="Group 1-32 selected retained response bodies offline.")
    group.add_argument("exchange_ids", nargs="+")
    group.add_argument("--normalization", choices=("exact", "ascii-whitespace"), default="exact")
    candidates = commands.add_parser("candidates", help="Extract inert hints from selected retained HTML offline.")
    candidates.add_argument("exchange_ids", nargs="+")
    flow = commands.add_parser("flow", help="Summarize selected captured exchanges by source time offline.")
    flow.add_argument("exchange_ids", nargs="+")
    exporter = commands.add_parser("export")
    exporter.add_argument("exchange_id")
    exporter.add_argument("--format", choices=("json", "har", "raw"), default="json")
    exporter.add_argument("--output", required=True, help="New file, or new directory for raw bundles.")
    exporter.add_argument("--private", action="store_true", help="Explicitly retain original credentials and bytes.")
    return parser


def _read(path: str) -> bytes:
    file_path = Path(path)
    if file_path.stat().st_size > exchange.INPUT_LIMIT:
        raise exchange.ExchangeError("Import exceeds 16 MiB")
    value = file_path.read_bytes()
    if len(value) > exchange.INPUT_LIMIT:
        raise exchange.ExchangeError("Import exceeds 16 MiB")
    return value


def _import(args: argparse.Namespace) -> list[str]:
    if args.command == "import-raw":
        request = _read(args.request)
        response = _read(args.response) if args.response else None
        value = exchange.raw_record(request, response, source_id=args.source_id, url=args.url,
                                    captured_at=args.timestamp, actor=args.actor, run_id=args.run_id,
                                    request_truncated=args.request_truncated,
                                    response_truncated=args.response_truncated)
        records, raw, source_id, kind = [value], exchange.canonical(value), args.source_id, "raw"
    elif args.command == "import-run":
        value = exchange.from_run(args.run_id)
        records, raw, source_id, kind = [value], exchange.canonical(value), args.run_id, "ledger"
    elif args.command == "import-burp":
        return burp.save(_read(args.file), source_id=args.source_id, timezone=args.timezone)
    else:
        raw, source_id = _read(args.file), args.source_id
        if args.command == "import-har":
            records, kind = har.parse(raw, source_id=source_id), "har"
        else:
            records, kind = [exchange.validate(exchange.load_json(raw))], "json"
    return exchange.save(records, source_id=source_id, source_bytes=raw, kind=kind)


def _write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(data)
    path.chmod(0o600)


def _export(args: argparse.Namespace) -> dict:
    retained = exchange.read(args.exchange_id)
    value = exchange.project(retained, private=args.private)
    output = Path(args.output)
    if args.format == "raw":
        if output.exists():
            raise exchange.ExchangeError("Raw export directory already exists")
        output.mkdir(parents=False)
        for name in ("request", "response"):
            if value[name] is not None:
                _write_new(output / f"{name}.http", exchange.decode(value[name]["raw_b64"]))
        _write_new(output / "metadata.json", exchange.canonical(value) + b"\n")
    else:
        data = har.export([retained], private=args.private) if args.format == "har" else exchange.canonical(value) + b"\n"
        _write_new(output, data)
    return {"exchange_id": retained["exchange_id"], "output": str(output),
            "private": args.private, "inert": True, "derivative_of": value["derivative_of"]}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command.startswith("import-"):
            result = {"exchange_ids": _import(args), "inert": True}
        elif args.command == "list":
            result = [exchange.summary(exchange.read(path.stem))
                      for path in sorted(exchange.directory().glob("*.json"))]
        elif args.command == "show":
            result = exchange.summary(exchange.read(args.exchange_id))
        elif args.command == "group":
            result = triage.response_groups(args.exchange_ids, normalization=args.normalization)
        elif args.command == "candidates":
            result = triage.html_candidates(args.exchange_ids)
        elif args.command == "flow":
            result = triage.flow_summary(args.exchange_ids)
        else:
            result = _export(args)
        print(json.dumps(ledger.redact(result), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print("Exchange import/export blocked: malformed, oversized, ambiguous or changed evidence.")
        return 2
