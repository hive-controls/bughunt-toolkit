"""Structured access to the same bounded producers used by addon commands."""

import asyncio
import copy
import math
from pathlib import Path

from bughunt.console import catalog, loader
from bughunt.core import egress, ledger, scanner
from bughunt.core.results import Artifact, ExecutionContext, ModuleOutput, safe_url


def load_addon(name: str):
    path = catalog.locate_script(catalog.tool_by_command(name), Path(scanner.__file__))
    if path is None:
        raise FileNotFoundError("Addon is not installed")
    return loader.import_script(path)


def external(
    name: str, operation: str, value, *, status: str = "success"
) -> ModuleOutput:
    records = value if isinstance(value, list) else [value]
    return ModuleOutput(
        [
            Artifact.create(
                "external",
                {
                    "provider": name,
                    "operation": operation,
                    "records": records,
                    "source_run_ids": [],
                },
            )
        ],
        status=status,
    )


def planned(name: str, operation: str, **details) -> ModuleOutput:
    return ModuleOutput(
        [
            Artifact.create(
                "inventory",
                {
                    "resource": "addon-plan",
                    "items": [
                        {
                            "module_id": name,
                            "operation": operation,
                            "outbound_actions": 0,
                            **details,
                        }
                    ],
                },
            )
        ],
        status="planned",
    )


def validate_watch(polls: int | None, interval: float) -> None:
    if not isinstance(polls, int) or not 1 <= polls <= 100:
        raise ValueError("Embedding requires --polls between 1 and 100")
    if not math.isfinite(interval) or interval <= 0 or (polls - 1) * interval > 300:
        raise ValueError(
            "Watch interval must be positive with at most 300 seconds of waits"
        )


def document(output: ModuleOutput, text: str, media_type: str = "text/plain") -> None:
    output.artifacts.append(
        Artifact.create(
            "document",
            {
                "media_type": media_type,
                "text": text,
                "truncated": False,
            },
        )
    )


def effect(output: ModuleOutput, resource: str, action: str) -> None:
    output.artifacts.append(
        Artifact.create(
            "effect",
            {
                "resource": resource,
                "action": action,
                "changed": True,
                "identifiers": [],
            },
        )
    )


def wait_for_poll(seconds: float) -> None:
    from bughunt.core import clock, pipeline_context

    governor = pipeline_context.current()
    if governor is None:
        clock.sleep(seconds)
        return
    deadline = clock.now() + seconds
    while True:
        governor.check()
        remaining = deadline - clock.now()
        if remaining <= 0:
            return
        clock.sleep(min(0.05, remaining))


def _pulse(module, args, dry_run: bool) -> ModuleOutput:
    problem = module.validation_problem(args)
    if problem or args.file == "-" or not math.isfinite(args.timeout):
        raise ValueError(problem or "Embedding requires an input file")
    if bool(args.file) == bool(args.urls):
        raise ValueError("Supply exactly one input file or URLs")
    urls = (
        list(dict.fromkeys(module.normalize_url(url) for url in args.urls))
        if args.urls
        else module.load_urls(args.file)
    )
    if not urls:
        raise ValueError("No input URLs")
    if dry_run:
        return planned("pulse", "default", input_count=len(urls), method="GET")
    rows = asyncio.run(
        module.run_checks(
            urls,
            follow=args.follow_redirects,
            timeout=args.timeout,
            concurrency=args.concurrency,
            retries=args.retries,
            user_agent=args.user_agent,
            insecure=args.insecure,
            method_note="GET",
            display=False,
        )
    )
    for path, writer in (
        (args.json_out, module.export_json),
        (args.csv_out, module.export_csv),
    ):
        if path:
            writer(path, rows, notify=False)
    status = (
        "blocked"
        if any(row.excluded for row in rows)
        else (
            "partial"
            if any(row.family in module.HARD_FAILURE_FAMILIES for row in rows)
            else "success"
        )
    )
    output = external(
        "pulse", "default", [module.export_row(row) for row in rows], status=status
    )
    live = [row.final_url or row.url for row in rows if row.ok and not row.excluded]
    output.artifacts.append(
        Artifact.create(
            "urls", {"urls": list(dict.fromkeys(url for url in live if safe_url(url)))}
        )
    )
    return output


def _carve(module, args, dry_run: bool) -> ModuleOutput:
    if "-" in args.inputs:
        raise ValueError("Embedding requires input files")
    records = []
    for path in args.inputs:
        records.extend(module.load_input(path))
    rows = module.apply_filters(module.flatten(records, args.include_requests), args)
    if dry_run:
        return planned(
            "carve", "default", input_count=len(args.inputs), extracted_count=len(rows)
        )
    if args.save:
        module.save_rows(
            rows, args.save, module.infer_format(args.save, args.format), args.resolve
        )
    clean = [
        {key: value for key, value in row.items() if key != "source"} for row in rows
    ]
    for row in clean:
        if not safe_url(row["flow_url"]):
            row["flow_url"] = ""
    output = external("carve", "default", clean)
    urls = list(
        dict.fromkeys(row["resolved"] for row in rows if safe_url(row["resolved"]))
    )
    output.artifacts.append(Artifact.create("urls", {"urls": urls}))
    return output


def _tcurl(module, args, dry_run: bool) -> ModuleOutput:
    selected = copy.copy(args)
    selected.dry_run = dry_run or args.dry_run
    result = module.run(selected)
    status = {
        0: "planned" if selected.dry_run else "success",
        2: "blocked",
        130: "cancelled",
    }.get(result.exit_code, "failed")
    if result.outcome == "invalid-input":
        status = "invalid"
    document = result.to_document()
    if document["error"]:
        document["error"]["message"] = document["error"]["kind"].replace("-", " ")
    if document["response"]:
        document["response"]["body"]["saved_to"] = bool(
            document["response"]["body"]["saved_to"]
        )
    output = external("tcurl", "default", document, status=status)
    output.run_ids = [
        value for value in (result.run_id, result.exit_info.check_run_id) if value
    ]
    if output.run_ids:
        output.artifacts.append(Artifact.create("runs", {"run_ids": output.run_ids}))
    if document["response"] and document["response"]["body"].get("text") is not None:
        body = document["response"]["body"]
        output.artifacts.append(
            Artifact.create(
                "document",
                {
                    "media_type": "text/plain",
                    "text": body["text"],
                    "truncated": bool(body.get("truncated", False)),
                },
            )
        )
    return output


def execute(name: str, operation: str, args, context: ExecutionContext) -> ModuleOutput:
    module = load_addon(name)
    handlers = {"pulse": _pulse, "carve": _carve, "tcurl": _tcurl}
    try:
        with ledger.collect_runs() as receipts:
            output = (
                handlers[name](module, args, context.dry_run)
                if name in handlers
                else module.run_structured(args, dry_run=context.dry_run)
            )
    except Exception as failure:
        cause = failure
        while cause is not None:
            if isinstance(cause, egress.PolicyBlocked):
                raise cause
            cause = cause.__cause__
        raise
    output.run_ids = list(dict.fromkeys([*output.run_ids, *receipts]))
    if receipts:
        output.artifacts = [
            Artifact.create(item.kind, {**item.payload, "source_run_ids": receipts})
            if item.kind == "external"
            else item
            for item in output.artifacts
        ]
        if not any(item.kind == "runs" for item in output.artifacts):
            output.artifacts.append(Artifact.create("runs", {"run_ids": receipts}))
    return output
