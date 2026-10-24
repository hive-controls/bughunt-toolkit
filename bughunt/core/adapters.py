"""Closed module registry and typed option conversion using existing parser contracts."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path

from bughunt.console import catalog as vocabulary, loader, options as forms
from bughunt.core.results import ExecutionContext, ModuleOutput
from bughunt.core.adapter_contracts import (
    input_kinds as input_kinds,
    output_kinds as output_kinds,
)
from bughunt.modules import MODULES, load_builtin

CONTRACT_VERSION = 1
_MUTATIONS = {
    "scope",
    "policy",
    "identity",
    "session",
    "blaze",
    "quill",
    "route",
    "verify",
}
_READS = {
    "list",
    "show",
    "status",
    "path",
    "urls",
    "allow",
    "check",
    "example",
    "validate",
}
_FILE_KEYS = {
    "file",
    "files",
    "request",
    "response",
    "inputs",
    "messages",
    "report",
    "wordlist",
    "paths_file",
    "targets_file",
    "body_file",
    "names",
    "config",
}


def canonical_module(name: str) -> str:
    if name == "scan":
        return name
    canonical = vocabulary.reference_canonical(name)
    if canonical is None:
        raise ValueError("Unknown module ID")
    return canonical


def canonical_operation(name: str, operation: str) -> str:
    if operation != "default":
        return operation
    attributes = {
        "clutch": "_DEFAULT_SUB",
        "blaze": "_DEFAULT_ACTION",
        "quill": "_DEFAULT_VERB",
    }
    attribute = attributes.get(name)
    return getattr(load_builtin(name), attribute) if attribute else operation


def parser_for(name: str) -> argparse.ArgumentParser:
    from bughunt.core import scanner

    name = canonical_module(name)
    if name == "scan":
        return scanner.build_parser()
    if name in MODULES:
        module = load_builtin(name)
    else:
        reference = vocabulary.tool_by_command(name)
        path = vocabulary.locate_script(reference, Path(scanner.__file__))
        if path is None:
            raise FileNotFoundError("Addon is not installed")
        module = loader.import_script(path)
    return forms._parser_of(module, name)


def _branches(parser: argparse.ArgumentParser) -> dict:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    return {}


def operation_names(name: str) -> tuple[str, ...]:
    branches = _branches(parser_for(name))
    names = tuple(branches) or ("default",)
    return ("default", *names) if name == "snare" else names


def _selected_actions(parser: argparse.ArgumentParser, operation: str) -> list:
    branches = _branches(parser)
    if branches and operation not in branches and operation != "default":
        raise ValueError("Unknown module operation")
    if not branches and operation != "default":
        raise ValueError("Module has no such operation")
    actions = [
        action
        for action in parser._actions
        if not isinstance(action, argparse._SubParsersAction)
    ]
    if operation in branches:
        actions.extend(branches[operation]._actions)
    return [
        action for action in actions if action.dest not in {"help", argparse.SUPPRESS}
    ]


def _scalar(value, action):
    if not isinstance(value, (str, int, float)) or isinstance(value, bool):
        raise ValueError("Option requires a string or number")
    if action.type is int and type(value) is float:
        raise ValueError("Integer option cannot receive a float")
    text = str(value)
    if "\x00" in text:
        raise ValueError("Option contains a null byte")
    try:
        converted = action.type(text) if action.type is not None else text
    except (ValueError, TypeError, argparse.ArgumentTypeError) as error:
        raise ValueError("Invalid option value") from error
    if action.choices is not None and converted not in action.choices:
        raise ValueError("Option value outside choices")
    return converted


def _nargs_value(action, value):
    multiple = action.nargs in ("*", "+") or isinstance(action.nargs, int)
    if not multiple:
        return _scalar(value, action)
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError("Option requires a bounded list")
    if (
        action.nargs == "+"
        and not value
        or type(action.nargs) is int
        and len(value) != action.nargs
    ):
        raise ValueError("Option value count differs from nargs")
    return [_scalar(item, action) for item in value]


def _action_value(action, value):
    if isinstance(
        action,
        (
            argparse._StoreTrueAction,
            argparse._StoreFalseAction,
            argparse.BooleanOptionalAction,
        ),
    ):
        if type(value) is not bool:
            raise ValueError("Boolean option requires a boolean")
        return value
    if isinstance(action, argparse._CountAction):
        if type(value) is not int or not 0 <= value <= 100:
            raise ValueError("Invalid count option")
        return value
    if isinstance(action, argparse._AppendConstAction):
        if not isinstance(value, list) or any(item != action.const for item in value):
            raise ValueError("Append-constant option requires its declared constants")
        return list(value)
    if isinstance(action, argparse._StoreConstAction):
        if value not in (action.const, action.default):
            raise ValueError("Constant option requires its declared value")
        return value
    if isinstance(action, argparse._ExtendAction):
        return _nargs_value(action, value)
    if isinstance(action, argparse._AppendAction):
        if not isinstance(value, list) or len(value) > 1000:
            raise ValueError("Repeated option requires a list")
        return [_nargs_value(action, item) for item in value]
    if not isinstance(action, argparse._StoreAction):
        raise ValueError("Unsupported parser action")
    return _nargs_value(action, value)


def _invalid_parser(message):
    raise ValueError("Invalid module options")


def _selected_parsers(parser, operation):
    selected = [parser]
    words = [] if operation == "default" else operation.split("/")
    while True:
        selectors = [
            action
            for action in selected[-1]._actions
            if isinstance(action, argparse._SubParsersAction)
        ]
        if not selectors:
            if words:
                raise ValueError("Unknown module operation")
            return selected
        selector = selectors[0]
        if not words:
            if selector.required:
                raise ValueError("Module requires an operation")
            return selected
        word = words.pop(0)
        if word not in selector.choices:
            raise ValueError("Unknown module operation")
        selected.append(selector.choices[word])


def _check_groups(parsers, values, namespace):
    for parser in parsers:
        for group in parser._mutually_exclusive_groups:
            supplied = {
                action.dest
                for action in group._group_actions
                if action.dest in values
                and not (
                    isinstance(values[action.dest], bool)
                    and values[action.dest] == action.default
                )
            }
            if len(supplied) > 1 or group.required and not supplied:
                raise ValueError(
                    "Mutually exclusive options differ from parser contract"
                )


def _typed_actions(actions, values):
    selected = {}
    for action in actions:
        previous = selected.get(action.dest)
        if previous is None or isinstance(action, argparse._StoreAction):
            selected[action.dest] = action
        elif (
            not isinstance(previous, argparse._StoreAction)
            and isinstance(action, argparse._StoreConstAction)
            and values.get(action.dest) == action.const
        ):
            selected[action.dest] = action
    return list(selected.values())


def _namespace(parsers, operation, actions, values):
    namespace = argparse.Namespace()
    for parser in parsers:
        for action in parser._actions:
            if (
                action.dest not in {"help", argparse.SUPPRESS}
                and action.default != argparse.SUPPRESS
            ):
                default = copy.deepcopy(action.default)
                if (
                    default is None
                    and action.nargs == "*"
                    and not action.option_strings
                ):
                    default = []
                if isinstance(default, str) and action.type is not None:
                    default = _scalar(default, action)
                setattr(namespace, action.dest, default)
        for name, value in parser._defaults.items():
            setattr(namespace, name, copy.deepcopy(value))
    operation_words = [] if operation == "default" else operation.split("/")
    for parser, word in zip(parsers, operation_words):
        selector = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        if selector.dest != argparse.SUPPRESS:
            setattr(namespace, selector.dest, word)
    required = {action.dest for action in actions if action.required}
    if required - set(values):
        raise ValueError("Required module option is missing")
    for action in _typed_actions(actions, values):
        if action.dest in values:
            setattr(namespace, action.dest, _action_value(action, values[action.dest]))
    _check_groups(parsers, values, namespace)
    return namespace


def parse_options(name: str, operation: str, values: dict | None = None):
    values = {} if values is None else values
    if not isinstance(values, dict) or any(not isinstance(key, str) for key in values):
        raise ValueError("Options must be an object")
    parser = parser_for(name)
    parsers = _selected_parsers(parser, operation)
    actions = [
        action
        for current in parsers
        for action in current._actions
        if not isinstance(action, argparse._SubParsersAction)
        and action.dest not in {"help", argparse.SUPPRESS}
    ]
    known = {action.dest for action in actions}
    if set(values) - known:
        raise ValueError("Unknown option key")
    return _namespace(parsers, operation, actions, values)


def pipeline_restriction(name: str, operation: str, values: dict) -> str:
    output_restriction = _output_restriction(name, values, operation)
    if output_restriction:
        return output_restriction
    if name == "scan":
        return "raw-dispatch-unmetered"
    if name == "snare" and operation in {"default", "capture"}:
        return "capture-deadline-unproven"
    if name == "snare" and operation == "ca":
        return "configuration-mutation"
    if name in _MUTATIONS and operation not in _READS:
        return "configuration-mutation"
    if name == "ledger" and operation == "cleanup":
        return "evidence-annotation"
    if values.get("fast") or values.get("edit") or values.get("private"):
        return "interactive-or-authority-mutating-option"
    if name == "race" and operation == "run":
        return "requires-concurrency-two"
    if (name, operation) in {
        ("zap", "active"),
        ("desync", "run"),
        ("ws", "capture"),
        ("ws", "replay"),
    } and not values.get("dry_run"):
        return "managed-retention-unmetered"
    if name in {"replay", "idor"}:
        return "changes-pinned-actor"
    if name == "engine":
        return _engine_restriction(operation, values)
    if operation == "watch":
        polls = values.get("polls")
        return (
            "" if type(polls) is int and 1 <= polls <= 100 else "finite-polls-required"
        )
    if operation in {"repl", "download", "screenshot"}:
        return "unbounded-or-binary-operation"
    return ""


def _output_restriction(name, values, operation="default"):
    if name == "phish" and operation == "snapshot":
        return "unmetered-output-destination"
    destinations = {
        "pulse": ("json_out", "csv_out"),
        "ct": ("output", "wordlist"),
        "carve": ("save",),
        "tcurl": ("output",),
        "skiff": ("output",),
        "urlscan": ("save", "output"),
        "ioc": ("export",),
        "phish": ("export", "out", "log"),
        "chroma": ("out",),
        "robots": ("save",),
        "silk": ("save",),
        "forms": ("save_requests",),
        "repeater": ("save_request", "output"),
        "exchange": ("output",),
        "zap": ("output",),
    }
    for key in destinations.get(name, ()):
        if name == "phish" and operation == "campaign" and key == "export":
            continue
        value = values.get(key)
        if value and not (name == "tcurl" and key == "output" and value == "-"):
            return "unmetered-output-destination"
    if name in {"robots", "silk"} and values.get("no_workspace") is not True:
        return "workspace-url-write-unmetered"
    return ""


def _engine_restriction(operation, values):
    if operation == "doctor":
        return "child-transport-unmetered" if values.get("probe") else ""
    if operation not in {"start", "dry-run"}:
        return ""
    profile = values.get("profile_id")
    if profile == "burp-mcp-intake":
        return "child-transport-unmetered"
    if profile not in {"zap-owned-active", "zap-passive", "browser-owned"}:
        return "managed-profile-selection-required"
    if operation == "start":
        return "managed-retention-unmetered"
    if profile == "browser-owned":
        from bughunt.core import identity

        actors = values.get("actor")
        if (
            not isinstance(actors, list)
            or len(actors) != 1
            or actors[0] != identity.selected_name()
        ):
            return "changes-pinned-actor"
    return ""


def file_options(name: str, operation: str) -> set[str]:
    return {
        action.dest
        for action in _selected_actions(parser_for(name), operation)
        if action.dest in _FILE_KEYS
    }


def execute(name: str, operation: str, args, context: ExecutionContext) -> ModuleOutput:
    if name in MODULES or name == "scan":
        from bughunt.core import native_adapters

        return native_adapters.execute(name, operation, args, context)
    from bughunt.core import addon_adapters

    return addon_adapters.execute(name, operation, args, context)


def describe(name: str) -> dict:
    from bughunt.core import adapter_contracts

    name = canonical_module(name)
    return {
        "id": name,
        "contract_version": CONTRACT_VERSION,
        "operations": [
            {
                "id": operation,
                "pipeline_restriction": pipeline_restriction(name, operation, {}),
                "result_schema": "urn:bughunt:result:1",
                "input_artifacts": input_kinds(name, operation),
                "output_artifacts": sorted(output_kinds(name, operation)),
                "preview_output_artifacts": ["inventory", "observations"],
                "side_effect": adapter_contracts.side_effect(name, operation),
                "supports_dry_run": operation != "repl"
                and (name, operation) != ("snare", "default"),
                "pipeline_eligible": not pipeline_restriction(name, operation, {}),
                "noninteractive_equivalent": adapter_contracts.equivalent(
                    name, operation
                ),
            }
            for operation in operation_names(name)
        ],
    }
