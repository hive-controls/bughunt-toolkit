"""Embedding entry points which return domain data without terminal output."""

from dataclasses import replace
import re
import time

import httpx

from bughunt.core import adapters, cli, egress, execution_receipts, ledger, route
from bughunt.core.results import ExecutionContext, ModuleOutput, Result, now

_LOCAL_MODULES = {
    "scope",
    "policy",
    "ledger",
    "identity",
    "session",
    "roost",
    "clutch",
    "blaze",
    "quill",
    "jwt",
    "exchange",
    "route",
    "oast",
}


def _error(status: str, code: str) -> ModuleOutput:
    return ModuleOutput(
        status=status,
        errors=[{"code": code, "message": code.replace("_", " "), "retryable": False}],
    )


def _local_operation(name, operation, args):
    local_engine = name == "engine" and (
        operation in {"list", "map", "status", "cancel"}
        or operation == "doctor"
        and not args.probe
    )
    local_verification = name == "verify" and operation in {
        "configure",
        "show",
        "status",
    }
    local_robots = name == "robots" and not args.fetch
    local_lab = (
        name in {"race", "desync", "ws"}
        and operation in {"status", "cancel", "show"}
        or name == "zap"
        and operation != "active"
        or name == "snare"
        and operation in {"ca", "status", "stop"}
    )
    if name == "decode":
        from pathlib import Path

        return Path(args.target).is_file()
    if name == "diff":
        from bughunt.modules.diff import _remote_sources

        return not _remote_sources(args)
    return (
        name in _LOCAL_MODULES
        or local_engine
        or local_verification
        or local_robots
        or local_lab
    )


def _route_check(name, operation, args, context):
    if context.dry_run or _local_operation(name, operation, args):
        return []
    try:
        if route.optout_requested():
            ledger.record_route_optout("console")
            return [route.OPTOUT_WARNING]
        verdict = route.gate("console")
        if verdict is not None and verdict.ok is not True:
            raise egress.PolicyBlocked("route-blocked")
    except Exception as error:
        raise egress.PolicyBlocked("route-not-verified") from error
    return []


def _produce(name, operation, options, context):
    args = adapters.parse_options(name, operation, options)
    preview = bool(
        getattr(args, "dry_run", False)
        or getattr(args, "preview", False)
        or operation == "dry-run"
        or name == "idor"
        and not args.execute
    )
    context = replace(context, dry_run=context.dry_run or preview)
    if context.pipeline and adapters.pipeline_restriction(name, operation, vars(args)):
        return _error("unsupported", "operation_not_pipeline_eligible"), context
    warnings = _route_check(name, operation, args, context)
    output = adapters.execute(name, operation, args, context)
    output.warnings.extend(warnings)
    return output, context


def _finish(name, operation, output, context, started, clock_started, measurements):
    metrics = measurements.metrics(time.monotonic() - clock_started)
    if measurements.incomplete_admissions:
        output.warnings.append(
            "Admission measurements are incomplete; request count is unknown"
        )
    if measurements.mixed_authority:
        output.warnings.append(
            "Multiple authorities were used; no single policy receipt applies"
        )
    try:
        result = Result.create(
            name,
            operation,
            output,
            context=context,
            started_at=started,
            metrics=metrics,
            policy=measurements.authority(),
        )
        result.to_dict()
        return result
    except Exception:
        errors = [
            {
                "code": "invalid_producer_result",
                "message": "Producer result could not be validated",
                "retryable": False,
            }
        ]
        return Result(
            name,
            operation,
            context.execution_id,
            "failed",
            1,
            started,
            now(),
            context.dry_run,
            [],
            [],
            None,
            errors,
            [],
            metrics,
        )


def run_module(
    module_id: str,
    *,
    operation: str | None = None,
    options: dict | None = None,
    dry_run: bool = False,
    context: ExecutionContext | None = None,
) -> Result:
    started, clock_started = now(), time.monotonic()
    context = (
        replace(context, dry_run=context.dry_run or dry_run)
        if context
        else ExecutionContext(dry_run=dry_run)
    )
    operation = operation or "default"
    canonical = "unknown"
    captured = []
    measurements = execution_receipts.Measurements()
    try:
        canonical = adapters.canonical_module(module_id)
        operation = adapters.canonical_operation(canonical, operation)
        with (
            ledger.collect_runs() as captured,
            execution_receipts.collect() as measurements,
        ):
            output, context = _produce(canonical, operation, options, context)
    except egress.PolicyBlocked:
        output = _error("blocked", "policy_blocked")
    except cli.CommandExit as error:
        output = _error(
            "invalid" if error.code == 2 else "failed", "module_input_rejected"
        )
    except (ValueError, TypeError, KeyError):
        output = _error("invalid", "invalid_module_options_or_evidence")
    except (ImportError, FileNotFoundError):
        output = _error("unsupported", "adapter_or_dependency_unavailable")
    except (OSError, httpx.HTTPError):
        output = _error("failed", "operation_failed")
    except KeyboardInterrupt:
        output = _error("cancelled", "cancelled")
    except SystemExit:
        output = _error("failed", "producer_terminated")
    except Exception:
        output = _error("failed", "internal_error")
    output.run_ids = list(dict.fromkeys([*output.run_ids, *captured]))
    safe_operation = (
        operation
        if isinstance(operation, str) and re.fullmatch(r"[a-z0-9_/-]{1,100}", operation)
        else "default"
    )
    return _finish(
        canonical, safe_operation, output, context, started, clock_started, measurements
    )


def catalog() -> dict:
    from pathlib import Path
    from bughunt.console.catalog_export import export_catalog
    from bughunt.core import scanner

    return export_catalog(
        tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
