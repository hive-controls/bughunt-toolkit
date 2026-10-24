import argparse
import copy

import pytest

from bughunt.console.catalog import MODULE_GROUPS
from bughunt.core import adapters


def _sample_scalar(action):
    if action.choices:
        return next(iter(action.choices))
    candidates = [
        "sample",
        "1",
        "a" * 64,
        "00000000-0000-0000-0000-000000000000",
        "https://127.0.0.1/",
        "127.0.0.1",
        "owner",
    ]
    for value in candidates:
        try:
            if action.type:
                action.type(value)
            return value
        except (ValueError, TypeError, argparse.ArgumentTypeError):
            continue
    raise AssertionError(f"No safe test sample for {action.dest}")


def _sample(action):
    if isinstance(
        action,
        (
            argparse._StoreTrueAction,
            argparse._StoreFalseAction,
            argparse._StoreConstAction,
        ),
    ):
        return action.const
    value = _sample_scalar(action)
    if action.nargs in ("*", "+") or type(action.nargs) is int:
        value = [value] * (action.nargs if type(action.nargs) is int else 1)
    return [value] if isinstance(action, argparse._AppendAction) else value


def _words(action, value):
    prefix = [action.option_strings[0]] if action.option_strings else []
    if isinstance(
        action,
        (
            argparse._StoreTrueAction,
            argparse._StoreFalseAction,
            argparse._StoreConstAction,
        ),
    ):
        return prefix if value == action.const else []
    if isinstance(action, argparse._AppendAction):
        return [
            word
            for item in value
            for word in prefix
            + ([str(part) for part in item] if isinstance(item, list) else [str(item)])
        ]
    return prefix + (
        [str(item) for item in value] if isinstance(value, list) else [str(value)]
    )


def _oracle_words(parsers, operation, values):
    words = []
    operations = [] if operation == "default" else operation.split("/")
    for index, parser in enumerate(parsers):
        optional, positional = [], []
        chosen = {}
        for action in parser._actions:
            previous = chosen.get(action.dest)
            matches_constant = (
                isinstance(action, argparse._StoreConstAction)
                and values.get(action.dest) == action.const
            )
            if (
                previous is None
                or isinstance(action, argparse._StoreAction)
                or not isinstance(previous, argparse._StoreAction)
                and matches_constant
            ):
                chosen[action.dest] = action
        for action in chosen.values():
            if action.dest in values and not isinstance(
                action, argparse._SubParsersAction
            ):
                (optional if action.option_strings else positional).extend(
                    _words(action, values[action.dest])
                )
        words.extend(optional + positional)
        if index < len(operations):
            words.append(operations[index])
    return words


def _required(parsers):
    result = {}
    for parser in parsers:
        for action in parser._actions:
            if action.required and not isinstance(action, argparse._SubParsersAction):
                result[action.dest] = _sample(action)
        for group in parser._mutually_exclusive_groups:
            if group.required:
                action = group._group_actions[0]
                result[action.dest] = _sample(action)
    return result


def _remove_conflicts(parsers, values, selected):
    for parser in parsers:
        for group in parser._mutually_exclusive_groups:
            if selected in group._group_actions:
                for action in group._group_actions:
                    if action is not selected:
                        values.pop(action.dest, None)


def test_all_162_operations_match_argparse_for_defaults_and_every_runtime_action():
    operations, checked = 0, 0
    failures = []
    for _phase, names in MODULE_GROUPS:
        for name in names:
            parser = adapters.parser_for(name)
            for operation in adapters.operation_names(name):
                operations += 1
                parsers = adapters._selected_parsers(parser, operation)
                baseline = _required(parsers)
                actions = [
                    action
                    for current in parsers
                    for action in current._actions
                    if not isinstance(
                        action,
                        (
                            argparse._SubParsersAction,
                            argparse._HelpAction,
                            argparse._VersionAction,
                        ),
                    )
                ]
                cases = [baseline]
                for action in actions:
                    values = copy.deepcopy(baseline)
                    _remove_conflicts(parsers, values, action)
                    values[action.dest] = _sample(action)
                    cases.append(values)
                for values in cases:
                    checked += 1
                    try:
                        actual = adapters.parse_options(name, operation, values)
                        expected = parser.parse_args(
                            _oracle_words(parsers, operation, values)
                        )
                        if vars(actual) != vars(expected):
                            failures.append(
                                (name, operation, sorted(values), "namespace mismatch")
                            )
                    except (ValueError, TypeError, SystemExit) as error:
                        failures.append(
                            (name, operation, sorted(values), type(error).__name__)
                        )
    assert operations == 162
    assert checked > 1000
    assert not failures, f"{len(failures)} parser mismatches; first 10: {failures[:10]}"


def test_append_nargs_boolean_optional_constants_and_groups(monkeypatch):
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs", action="append", nargs=2)
    parser.add_argument(
        "--feature", action=argparse.BooleanOptionalAction, default=True
    )
    parser.add_argument(
        "--mode", action="store_const", const="strict", default="normal"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--left", action="store_true")
    group.add_argument("--right", action="store_true")
    monkeypatch.setattr(adapters, "parser_for", lambda _: parser)
    values = {
        "pairs": [["--help", "value"]],
        "feature": False,
        "mode": "strict",
        "left": True,
    }
    result = adapters.parse_options("test", "default", values)
    assert result.pairs == [["--help", "value"]]
    assert result.feature is False and result.mode == "strict"
    with pytest.raises(ValueError):
        adapters.parse_options("test", "default", {"left": True, "right": True})
