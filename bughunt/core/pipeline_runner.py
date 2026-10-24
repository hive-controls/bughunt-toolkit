"""Sequential typed handoffs with persistent intents and cumulative dispatch bounds."""

import time

from bughunt.core import adapters, api, egress, exchange
from bughunt.core.pipeline import PipelinePlan, _selection, load_pipeline
from bughunt.core.pipeline_budget import Governor, bind
from bughunt.core.pipeline_store import Journal, _restore_plan
from bughunt.core.results import Artifact, ExecutionContext, ModuleOutput, Result


def _result(
    state, *, identifier=None, governor=None, values=None, error=None, started=None
):
    values = values or {}
    summaries = [
        {"id": key, "module": value["module_id"], "status": value["status"]}
        for key, value in values.items()
    ]
    artifacts = [
        Artifact.create("inventory", {"resource": "pipeline", "items": summaries})
    ]
    if values:
        artifacts.extend(
            Artifact(**value) for value in next(reversed(values.values()))["artifacts"]
        )
    runs = list(
        dict.fromkeys(
            evidence["run_id"]
            for value in values.values()
            for evidence in value["evidence"]
        )
    )
    errors = (
        []
        if error is None
        else [{"code": error, "message": error.replace("_", " "), "retryable": False}]
    )
    context = (
        ExecutionContext(execution_id=identifier) if identifier else ExecutionContext()
    )
    metrics = {
        "requests_admitted": governor.requests_admitted if governor else 0,
        "bytes_retained": governor.bytes_retained if governor else 0,
        "elapsed_seconds": time.monotonic() - started if started else 0,
        "limits": dict(governor.limits) if governor else {},
    }
    return Result.create(
        "pipeline",
        "run",
        ModuleOutput(artifacts, runs, status=state, errors=errors),
        context=context,
        metrics=metrics,
    )


def _preview(plan):
    steps = [
        {
            "id": step["id"],
            "module": step["module"],
            "operation": step["operation"],
            "input_keys": sorted(step["options"]),
            "deferred_inputs": step.get("inputs", {}),
            "preview": _preview_step(step, plan),
        }
        for step in plan.document["steps"]
    ]
    states = [step["preview"]["status"] for step in steps]
    state = next(
        (status for status in states if status not in {"planned", "deferred"}),
        "planned",
    )
    artifact = Artifact.create(
        "inventory",
        {
            "resource": "pipeline-plan",
            "items": [
                {
                    "plan_sha256": plan.sha256,
                    "limits": plan.limits,
                    "steps": steps,
                    "outbound_actions": 0,
                    "authority": "rechecked at execution; preview grants no authority",
                }
            ],
        },
    )
    return Result.create(
        "pipeline",
        "dry-run",
        ModuleOutput([artifact], status=state),
        context=ExecutionContext(dry_run=True),
    )


def _preview_step(step, plan):
    if step.get("inputs"):
        return {
            "status": "deferred",
            "policy": None,
            "reason": "typed inputs require prior step results",
        }
    paths = {name: metadata["path"] for name, metadata in plan.trusted_inputs.items()}
    result = api.run_module(
        step["module"],
        operation=step["operation"],
        options=_options(step, {}, paths),
        dry_run=True,
        context=ExecutionContext(pipeline=True),
    )
    return {
        "status": result.status,
        "policy": result.policy,
        "artifacts": [artifact.to_dict() for artifact in result.artifacts],
        "errors": result.errors,
    }


def _options(step, completed, paths):
    options = {
        key: _materialize(value, paths) for key, value in step["options"].items()
    }
    for destination, reference in step.get("inputs", {}).items():
        source = completed[reference["step"]]
        matches = [
            Artifact(**value)
            for value in source["artifacts"]
            if value["kind"] == reference["artifact"]
        ]
        if source["status"] != "success" or len(matches) != 1:
            raise ValueError("Typed handoff requires one successful source artifact")
        selected = [matches[0].select(index) for index in _selection(reference)]
        options[destination] = selected if "indices" in reference else selected[0]
        if reference["artifact"] == "exchanges":
            for identifier in selected:
                exchange.read(identifier)
    return options


def _materialize(value, paths):
    if isinstance(value, list):
        return [_materialize(item, paths) for item in value]
    return paths[value["trusted_input"]] if isinstance(value, dict) else value


def _preflight(step, options, governor):
    planned = _minimum_requests(step, options)
    if step["module"] == "discover":
        preview = api.run_module(
            step["module"],
            operation=step["operation"],
            options=options,
            dry_run=True,
            context=ExecutionContext(pipeline=True),
        )
        if preview.status != "planned":
            raise egress.PolicyBlocked("pipeline-step-preview-blocked")
        planned = preview.artifacts[0].payload["items"][0]["attributes"][
            "planned_requests"
        ]
    if planned > governor.limits["requests"] - governor.requests_admitted:
        raise egress.PolicyBlocked("pipeline-insufficient-remaining-budget")


def _minimum_requests(step, options):
    name, operation = step["module"], step["operation"]
    if name in {"dns", "mail"}:
        from bughunt.modules.dns import RECORD_TYPES

        if name == "mail":
            args = adapters.parse_options(name, operation, options)
            return len(RECORD_TYPES) * (2 + len(args.selector or []))
        return len(RECORD_TYPES)
    if name == "desync" and operation == "run":
        from bughunt.labs.desync import WRITE_CAP

        return WRITE_CAP
    if name in {"cert", "whois", "redirect"}:
        return 1
    if name == "robots":
        return int(bool(options.get("fetch")))
    if name == "diff":
        from bughunt.modules.diff import _remote_sources

        return len(_remote_sources(adapters.parse_options(name, operation, options)))
    if name == "engine" and operation == "start":
        from bughunt.integrations.browser_actor import PROFILE_ID

        args = adapters.parse_options(name, operation, options)
        if args.profile_id == PROFILE_ID:
            return 2 * len(args.exchange_id)
    return 0


def _step(journal, plan, step, completed, governor):
    governor.check()
    plan.verify_inputs()
    options = _options(step, completed, journal.input_paths(plan, governor))
    _preflight(step, options, governor)
    attempt = journal.start_step(step["id"])
    result = api.run_module(
        step["module"],
        operation=step["operation"],
        options=options,
        context=ExecutionContext(execution_id=attempt, pipeline=True),
    )
    governor.retain_receipt(len(exchange.canonical(result.to_dict())))
    journal.finish_step(step["id"], result)
    completed[step["id"]] = result.to_dict()
    return result.status


def _execute(journal, plan, completed):
    started = time.monotonic()
    governor = Governor(
        plan.limits,
        mission=plan.document["mission"],
        deadline=journal.data["deadline"],
        counters=journal.data["counters"],
        authority=journal.data["authority"],
        stop_path=journal.root / "STOP",
        persist=journal.counters,
    )
    state, error = "success", None
    try:
        with bind(governor):
            for step in plan.document["steps"]:
                if step["id"] in completed:
                    continue
                outcome = _step(journal, plan, step, completed, governor)
                if outcome != "success":
                    state = (
                        outcome
                        if outcome in {"partial", "blocked", "failed", "cancelled"}
                        else "blocked"
                    )
                    error = "pipeline_step_not_successful"
                    break
            if state == "success":
                governor.check()
    except egress.PolicyBlocked:
        state = (
            "cancelled"
            if governor.cancelled.is_set() or (journal.root / "STOP").exists()
            else "blocked"
        )
        error = "pipeline_authority_or_budget_blocked"
    except KeyboardInterrupt:
        state, error = "cancelled", "pipeline_interrupted"
    except Exception:
        state, error = "failed", "pipeline_execution_or_persistence_failed"
    try:
        journal.finish(state)
    except Exception:
        state, error = "failed", "pipeline_journal_not_committed"
    return _result(
        state,
        identifier=journal.identifier,
        governor=governor,
        values=completed,
        error=error,
        started=started,
    )


def run_pipeline(source, *, execute=False):
    try:
        if type(execute) is not bool:
            raise ValueError("Execution requires an explicit boolean")
        supplied = source if isinstance(source, PipelinePlan) else load_pipeline(source)
        plan = _restore_plan(supplied.document, supplied.trusted_inputs)
        if not execute:
            return _preview(plan)
        governor = Governor(plan.limits, mission=plan.document["mission"])
        journal = Journal.create(plan, governor)
        with journal.locked():
            restored, completed = journal.restore()
            return _execute(journal, restored, completed)
    except egress.PolicyBlocked:
        return _result("blocked", error="pipeline_authority_blocked")
    except (ValueError, TypeError, KeyError, OSError):
        return _result("invalid", error="invalid_pipeline_or_inputs")


def resume_pipeline(identifier, *, execute=False):
    try:
        if execute is not True:
            return _result("invalid", error="resume_requires_explicit_execution")
        journal = Journal(identifier)
        with journal.locked():
            plan, completed = journal.restore()
            return _execute(journal, plan, completed)
    except (ValueError, TypeError, KeyError, OSError):
        return _result("blocked", error="pipeline_resume_not_safe")
