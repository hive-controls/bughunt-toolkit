"""Machine-readable CLI dispatch, using structured producers rather than rendered text."""

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from bughunt import VERSION
from bughunt.console import catalog as vocabulary
from bughunt.core import adapters, api
from bughunt.core.results import (
    Artifact,
    ModuleOutput,
    Result,
    artifact_schema,
    result_schema,
)


def _inventory(resource, value, *, status="success"):
    artifact = Artifact.create(
        "inventory",
        {"resource": resource, "items": value if isinstance(value, list) else [value]},
    )
    return Result.create(resource, "default", ModuleOutput([artifact], status=status))


def _plain_value(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [_plain_value(item) for item in value]
    return value


def _module_result(name, words):
    parser = adapters.parser_for(name)
    if any(word in {"-h", "--help"} for word in words):
        return _inventory("help", {"module": name, "form": adapters.describe(name)})
    selectors = [
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    for current in (parser, *adapters._branches(parser).values()):
        current.error = adapters._invalid_parser
    parser.exit = lambda *args, **kwargs: adapters._invalid_parser("Parser exited")
    parser._print_message = lambda *args, **kwargs: None
    args = parser.parse_args(words)
    selected = selectors[0].dest if selectors else None
    operation = getattr(args, selected) if selected else "default"
    actions = [
        action
        for current in adapters._selected_parsers(parser, operation or "default")
        for action in current._actions
        if not isinstance(action, argparse._SubParsersAction)
    ]
    known = {action.dest for action in actions}
    values = {
        key: _plain_value(value)
        for key, value in vars(args).items()
        if key in known and key != selected and value is not None
    }
    return api.run_module(
        name,
        operation=operation or "default",
        options=values,
        dry_run=bool(values.get("dry_run") or operation == "dry-run"),
    )


def _builtin(route):
    if route.command == "version":
        return _inventory("version", {"version": VERSION})
    if route.command in {"catalog", "modules", "phase"}:
        return _inventory(route.command, api.catalog())
    if route.command == "guide":
        from bughunt.console import guide

        return _inventory(
            "guide",
            [
                {
                    **asdict(step),
                    "operations": adapters.describe(step.module)["operations"],
                }
                for step in guide.plan()
            ],
        )
    if route.command == "doctor":
        from bughunt.console import doctor
        from bughunt.core import scanner

        checks = doctor.collect_checks(Path(scanner.__file__))
        return _inventory(
            "doctor",
            [
                {"name": check.name, "ok": check.ok, "required": check.required}
                for check in checks
            ],
            status="failed"
            if any(check.required and not check.ok for check in checks)
            else "success",
        )
    if route.command in {"help", "help-usage", "examples", "completion"}:
        return _inventory(
            "help",
            {
                "commands": list(vocabulary.BUILTIN_SUMMARIES),
                "modules": list(vocabulary.MODULE_WHEN),
                "global_json": "prefix --json",
            },
        )
    return _inventory(
        route.command,
        {"noninteractive": "Use catalog forms and run_module with explicit options"},
        status="unsupported" if route.command in {"console", "setup"} else "invalid",
    )


def schema_document(words):
    if words == ["result"]:
        return result_schema()
    if len(words) == 2 and words[0] == "artifact":
        return artifact_schema(words[1])
    if words == ["pipeline"]:
        from bughunt.core.pipeline import pipeline_schema

        return pipeline_schema()
    raise ValueError("Schema requires result, pipeline or artifact KIND")


def dispatch(words, *, emit=True):
    from bughunt.console.cli import route_argv

    try:
        route = route_argv(words)
        if route.command in {"pipeline", "chain"}:
            from bughunt.core.pipeline import cli_result

            result = cli_result(route.args)
        elif route.command == "schema":
            result = _inventory("schema", schema_document(route.args))
        elif route.command in {"module", "scan"}:
            result = _module_result(
                route.token if route.command == "module" else "scan", route.args
            )
        else:
            result = _builtin(route)
    except (ValueError, TypeError, KeyError, FileNotFoundError):
        result = Result.create(
            "cli", "default", api._error("invalid", "invalid_command_or_options")
        )
    if emit:
        sys.stdout.write(
            json.dumps(result.to_dict(), ensure_ascii=True, allow_nan=False) + "\n"
        )
    return result.exit_code
