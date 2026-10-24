"""Option forms for the console.

An argparse parser is read once into a :class:`Spec`: a flat, ordered list of :class:`Option` rows
plus the subcommand names. The typed console edits saved settings against that spec, the picker
draws it as a form, and :func:`render_argv` turns the saved settings back into command-line words.
"""

from __future__ import annotations

import argparse
import itertools
import re
import shlex
import sys
from collections import namedtuple
from pathlib import Path
from typing import Callable

from rich.markup import escape
from rich.table import Table
from rich.text import Text

from bughunt.console import ui
from bughunt.core import termio
from bughunt.console.catalog import (
    DISABLED_REFERENCES,
    locate_script,
    reference_canonical,
    tool_by_command,
)

Settings = dict[str, str]
ParserBuilder = Callable[[str], argparse.ArgumentParser] | None


def split_words(value: str) -> list[str]:
    """Keep native absolute Windows paths while retaining shell quoting elsewhere."""
    if sys.platform != "win32":
        return shlex.split(value)
    protected: list[str] = []
    quote = ""
    path = False
    boundary = True
    index = 0
    while index < len(value):
        character = value[index]
        if not quote and character.isspace():
            path = False
            boundary = True
        elif character in ("'", '"') and (not quote or quote == character):
            if quote:
                quote = ""
            else:
                quote = character
                if boundary:
                    path = bool(
                        re.match(
                            r"(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/])", value[index + 1 :]
                        )
                    )
            boundary = False
        elif boundary:
            path = bool(
                re.match(r"(?:[A-Za-z]:[\\/]|\\\\[^\\/\s]+[\\/])", value[index:])
            )
            boundary = False
        if character == "\\" and quote != "'":
            if path:
                protected.append("\\\\")
            elif index + 1 < len(value):
                protected.append(value[index : index + 2])
                index += 2
                continue
            else:
                protected.append(character)
        else:
            protected.append(character)
        if character == "=" and not quote and not path:
            boundary = True
        index += 1
    return shlex.split("".join(protected))


_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})
_NOTE_LIMIT = 36
_NOTE_CLIP = 33
_NOTE_MIN_CUT = 16
_PARSER_FACTORIES = ("build_parser", "create_parser")
_QUIET_ACTIONS = (
    argparse._StoreTrueAction,
    argparse._StoreFalseAction,
    argparse._AppendAction,
    argparse._CountAction,
)

_OPTION_FIELDS = (
    "name",
    "dest",
    "flags",
    "kind",
    "required",
    "help",
    "choices",
    "subcommand",
    "repeatable",
    "store_false",
    "default",
)


class Option(namedtuple("Option", _OPTION_FIELDS, defaults=("",))):
    """One editable row of a form, as a tuple of the fields below (only ``default`` may be left out).

    name         the key saved settings use: the argparse dest, upper-cased
    dest         the argparse dest itself, used to tell whether typed words already cover the row
    flags        option strings in declaration order; empty for a positional
    kind         "positional", "bool", "value" or "tail"
    required     whether argparse insists on the row being given
    help         the one-line description shown in tables
    choices      the allowed values, or an empty tuple when anything goes
    subcommand   the subcommand that owns the row, or "" for a top-level row
    repeatable   whether the row takes a list of values
    store_false  a bool row whose flag turns the setting off instead of on
    default      a short single-line rendering of the parser default, or "" when it says nothing
    """

    __slots__ = ()


class Spec(namedtuple("Spec", ("options", "subcommands", "command_name"))):
    """One module's whole form.

    options        every Option, subcommand rows included, in declaration order
    subcommands    (name, help) pairs for the subcommands the parser offers
    command_name   the label of the row that selects a subcommand, or "" when there are none
    """

    __slots__ = ()


class SpecError(Exception):
    """The form for a module cannot be built; ``message`` is fit to show a person."""

    @property
    def message(self) -> str:
        return str(self.args[0]) if self.args else ""


# --------------------------------------------------------------------------------------
# argparse -> Spec
# --------------------------------------------------------------------------------------


def _clip_note(text: str) -> str:
    """Cut a long default to fit a table cell, at a word boundary when one is far enough in."""
    if len(text) <= _NOTE_LIMIT:
        return text
    clipped = text[:_NOTE_CLIP]
    boundary = clipped.rfind(" ")
    if boundary >= _NOTE_MIN_CUT:
        clipped = clipped[:boundary]
    return clipped + "..."


def _default_note(parser_action: argparse.Action) -> str:
    """A short, single-line rendering of an action's default for tables, or "" when it says nothing."""
    default = parser_action.default
    if default is None or isinstance(default, bool) or default == argparse.SUPPRESS:
        return ""
    if isinstance(parser_action, _QUIET_ACTIONS):
        return ""
    return _clip_note(" ".join(str(default).split()))


def _kind_of(parser_action: argparse.Action) -> str:
    if not parser_action.option_strings:
        return "positional"
    is_switch = parser_action.nargs == 0 and isinstance(parser_action.const, bool)
    return "bool" if is_switch else "value"


def _is_required(parser_action: argparse.Action) -> bool:
    if parser_action.option_strings:
        return bool(parser_action.required)
    return parser_action.nargs not in ("?", "*")


def _option_from_action(parser_action: argparse.Action, owner: str) -> Option:
    choices = parser_action.choices
    return Option(
        name=parser_action.dest.upper(),
        dest=parser_action.dest,
        flags=tuple(parser_action.option_strings),
        kind=_kind_of(parser_action),
        required=_is_required(parser_action),
        help=parser_action.help or "",
        choices=tuple(str(choice) for choice in choices) if choices else (),
        subcommand=owner,
        repeatable=isinstance(parser_action, argparse._AppendAction)
        or parser_action.nargs in ("+", "*"),
        store_false=isinstance(parser_action, argparse._StoreFalseAction),
        default=_default_note(parser_action),
    )


def _hidden(parser_action: argparse.Action) -> bool:
    if isinstance(parser_action, (argparse._HelpAction, argparse._VersionAction)):
        return True
    suppressed_dest = parser_action.dest in (None, "", "help", argparse.SUPPRESS)
    return suppressed_dest or parser_action.help == argparse.SUPPRESS


def _command_label(selector: argparse._SubParsersAction) -> str:
    dest = selector.dest
    generic = dest in (None, "", argparse.SUPPRESS, "command", "cmd")
    return "COMMAND" if generic else dest.upper()


def _subparser_rows(
    selector: argparse._SubParsersAction,
    inherited_actions: tuple[argparse.Action, ...] = (),
) -> tuple[list[tuple[str, str]], list[Option]]:
    """Subcommand (name, help) pairs plus every child option, flattened in declaration order."""
    helps = {sub.dest: sub.help or "" for sub in selector._get_subactions()}
    names: list[tuple[str, str]] = []
    children: list[Option] = []
    for choice, child_parser in selector.choices.items():
        names.append((choice, helps.get(choice, "")))
        children.extend(
            spec_from_parser(
                child_parser, owner=choice, inherited_actions=inherited_actions
            ).options
        )
    return names, children


def _command_option(selector: argparse._SubParsersAction, label: str) -> Option:
    named = selector.dest not in (None, "", argparse.SUPPRESS)
    return Option(
        name=label,
        dest=selector.dest if named else label.lower(),
        flags=(),
        kind="positional",
        required=bool(selector.required),
        help="Subcommand.",
        choices=tuple(selector.choices),
        subcommand="",
        repeatable=False,
        store_false=False,
    )


def _repeats_inherited_action(
    action: argparse.Action, inherited_actions: tuple[argparse.Action, ...]
) -> bool:
    if not action.option_strings or action.default != argparse.SUPPRESS:
        return False
    fields = ("dest", "option_strings", "nargs", "const", "type", "choices", "required")
    return any(
        type(action) is type(inherited)
        and all(getattr(action, field) == getattr(inherited, field) for field in fields)
        for inherited in inherited_actions
    )


def spec_from_parser(
    parser: argparse.ArgumentParser,
    *,
    owner: str = "",
    inherited_actions: tuple[argparse.Action, ...] = (),
) -> Spec:
    rows: list[Option] = []
    subcommands: list[tuple[str, str]] = []
    command_name = ""
    global_actions = inherited_actions + tuple(
        action
        for action in parser._actions
        if action.option_strings and not _hidden(action)
    )
    for parser_action in parser._actions:
        if isinstance(parser_action, argparse._SubParsersAction):
            command_name = _command_label(parser_action)
            names, children = _subparser_rows(parser_action, global_actions)
            subcommands.extend(names)
            rows.extend(children)
            rows.append(_command_option(parser_action, command_name))
        elif not _hidden(parser_action) and not _repeats_inherited_action(
            parser_action, inherited_actions
        ):
            rows.append(_option_from_action(parser_action, owner))
    return Spec(
        options=tuple(rows), subcommands=tuple(subcommands), command_name=command_name
    )


# --------------------------------------------------------------------------------------
# load_spec: resolve a module name to its form
# --------------------------------------------------------------------------------------


def _call_factory(factory: Callable):
    try:
        return factory()
    except TypeError:
        return factory("bughunt")


def _parser_of(module, label: str) -> argparse.ArgumentParser:
    for attribute in _PARSER_FACTORIES:
        factory = getattr(module, attribute, None)
        if not callable(factory):
            continue
        built = _call_factory(factory)
        if isinstance(built, argparse.ArgumentParser):
            return built
    raise SpecError(f"{label} has no argument parser to read.")


def _builtin_spec(canonical: str, label: str) -> Spec:
    from bughunt import modules

    try:
        module = modules.load_builtin(canonical)
    except Exception as exc:
        raise SpecError(f"Could not load {label}: {exc}") from exc
    return spec_from_parser(_parser_of(module, label))


def _reference_spec(canonical: str, label: str, tool_file: Path) -> Spec:
    from bughunt.console import loader

    tool = tool_by_command(canonical)
    if tool is None:
        raise SpecError(f"Unknown module {label}.")
    located = locate_script(tool, tool_file)
    if located is None:
        raise SpecError(f"{tool.folder}/{tool.script} is not on disk.")
    if not loader.looks_like_python(located):
        raise SpecError(f"{label} has no option list.")
    try:
        module = loader.import_script(located)
    except ModuleNotFoundError as exc:
        missing = exc.name or str(exc)
        raise SpecError(
            f"{label} needs the Python package {missing}. Install the requirements for {tool.folder} and retry."
        ) from exc
    except Exception as exc:
        raise SpecError(f"Could not load {label}: {exc}") from exc
    return spec_from_parser(_parser_of(module, label))


def load_spec(
    module_name: str, *, tool_file: Path, build_parser: ParserBuilder
) -> Spec:
    if module_name == "scan":
        if build_parser is None:
            raise SpecError("Scanner options are unavailable here.")
        return spec_from_parser(build_parser("bughunt scan"))
    canonical = reference_canonical(module_name) or module_name
    if canonical in DISABLED_REFERENCES:
        raise SpecError(
            f"{module_name} is disabled until its network path is scope audited."
        )
    from bughunt.modules import MODULES

    if canonical in MODULES:
        return _builtin_spec(canonical, module_name)
    return _reference_spec(canonical, module_name, tool_file)


# --------------------------------------------------------------------------------------
# which rows apply, and finding one by the name a person typed
# --------------------------------------------------------------------------------------


def _active_command(spec: Spec, saved: Settings) -> str | None:
    if not spec.command_name:
        return None
    return saved.get(spec.command_name) or None


def _visible(spec: Spec, active_command: str | None) -> list[Option]:
    return [row for row in spec.options if row.subcommand in ("", active_command)]


def normalize_key(typed: str) -> str:
    return typed.strip().upper().replace("-", "_")


def find_option(spec: Spec, key: str, active_command: str | None) -> Option | None:
    """The option a typed key means: unique among the visible rows, else unique in the whole spec."""
    wanted = normalize_key(key)
    in_view = [row for row in _visible(spec, active_command) if row.name == wanted]
    if len(in_view) == 1:
        return in_view[0]
    anywhere = [row for row in spec.options if row.name == wanted]
    return anywhere[0] if len(anywhere) == 1 else None


# --------------------------------------------------------------------------------------
# console commands: show / set / unset
# --------------------------------------------------------------------------------------


def _plain(message: str, style: str | None = None) -> None:
    """Print one line with no markup, emoji or highlighting applied to it."""
    ui.console.print(Text(message, style=style or ""))


def redacted_value(
    module_name: str, option_name: str, value: str, *, option_kind: str = ""
) -> str:
    if option_kind == "bool" and value.lower() in {"true", "false"}:
        return value
    credential_value = (
        module_name in {"session", "identity"} and normalize_key(option_name) == "VALUE"
    )
    if termio.is_credential_name(option_name) or credential_value:
        return termio.REDACTED
    return termio.redact_text(value)


def redacted_argv(module_name: str, argv: list[str]) -> list[str]:
    masked = termio.redact_argv(argv)
    private_from = {"session": 2, "identity": 3}.get(module_name)
    if private_from is not None and argv[:1] == ["set"] and len(argv) > private_from:
        masked[private_from:] = [termio.REDACTED]
    return masked


def _assignment(
    option_name: str, value: str, *, module_name: str = "", option_kind: str = ""
) -> None:
    """The `NAME => value` echo. The name keeps its own style, as it always has (spec 11.7)."""
    safe_value = redacted_value(
        module_name, option_name, value, option_kind=option_kind
    )
    ui.console.print(Text.assemble((option_name, "info"), f" => {safe_value}"))


def _report_spec_error(failure: SpecError) -> None:
    ui.console.print(f"[err]{escape(failure.message)}[/err]")


def _spec_or_report(
    module_name: str, *, tool_file: Path, build_parser: ParserBuilder
) -> Spec | None:
    """The module's form, or None after telling the person why there is none."""
    try:
        return load_spec(module_name, tool_file=tool_file, build_parser=build_parser)
    except SpecError as failure:
        _report_spec_error(failure)
        return None


def _description_cell(option: Option) -> Text:
    cell = Text(option.help)
    if option.choices:
        cell.append(f" ({', '.join(option.choices)})")
    if option.flags:
        cell.append(
            ("  " if cell.plain else "") + ", ".join(option.flags), style="muted"
        )
    return cell


def _value_cell(option: Option, saved: Settings, module_name: str = "") -> Text:
    chosen = saved.get(option.name)
    if chosen:
        return Text(
            redacted_value(module_name, option.name, chosen, option_kind=option.kind)
        )
    if option.default:
        return Text(
            redacted_value(
                module_name, option.name, option.default, option_kind=option.kind
            ),
            style="muted",
        )
    return Text("·", style="muted")


def _options_table(module_name: str, rows: list[Option], saved: Settings) -> Table:
    table = Table(
        title=f"{module_name} options",
        title_justify="left",
        box=None,
        pad_edge=False,
        header_style="bold",
    )
    for heading, column_settings in (
        ("Name", {"no_wrap": True}),
        ("Value", {"overflow": "fold"}),
        ("Required", {"no_wrap": True}),
        ("Description", {}),
    ):
        table.add_column(heading, **column_settings)
    for option in rows:
        table.add_row(
            option.name,
            _value_cell(option, saved, module_name),
            "yes" if option.required else "no",
            _description_cell(option),
        )
    return table


def show_options(
    module_name: str, saved: Settings, *, tool_file: Path, build_parser: ParserBuilder
) -> None:
    spec = _spec_or_report(module_name, tool_file=tool_file, build_parser=build_parser)
    if spec is None:
        return
    active_command = _active_command(spec, saved)
    rows = _visible(spec, active_command)
    ui.console.print(_options_table(module_name, rows, saved))
    if spec.subcommands and active_command is None:
        listed = ", ".join(name for name, _help in spec.subcommands)
        _plain(f"Subcommands: {listed}")
        _plain(f"Pick one first with: set {spec.command_name} <subcommand>", "muted")
    if any(option.default and not saved.get(option.name) for option in rows):
        _plain("Dim values are defaults; they apply until you set your own.", "muted")
    _plain(
        "Use set NAME VALUE to save an option, then run to start the module.", "muted"
    )


def _explain_unknown_key(spec: Spec, key: str, active_command: str | None) -> None:
    wanted = normalize_key(key)
    clashes = [option for option in spec.options if option.name == wanted]
    if len(clashes) > 1 and active_command is None and spec.command_name:
        _plain(
            f"{key} belongs to more than one subcommand. Set {spec.command_name} first.",
            "warn",
        )
    else:
        _plain(f"Unknown option {key}. show options lists the names.", "warn")


def _coerce_bool(option: Option, value: str) -> str | None:
    word = value.strip().lower()
    if word in _TRUE:
        return "true"
    if word in _FALSE:
        return "false"
    _plain(f"{option.name} takes true or false.", "warn")
    return None


def _coerce_choice(option: Option, value: str) -> str | None:
    wanted = value.strip().lower()
    matches = [choice for choice in option.choices if choice.lower() == wanted]
    if len(matches) == 1:
        return matches[0]
    allowed = escape(", ".join(option.choices))
    ui.console.print(f"[info]{escape(option.name)}[/info] must be one of: {allowed}")
    return None


def _coerce_many(value: str, tokens: list[str] | None) -> str | None:
    try:
        parts = split_words(value) if tokens is None else list(tokens)
    except ValueError as exc:
        _plain(f"Could not read that value: {exc}", "warn")
        return None
    return shlex.join(parts)


def _coerce_value(option: Option, value: str, tokens: list[str] | None) -> str | None:
    """The string to save for a typed value, or None after explaining why it was refused."""
    if option.kind == "bool":
        return _coerce_bool(option, value)
    if option.choices:
        return _coerce_choice(option, value)
    if option.repeatable or option.kind == "tail":
        return _coerce_many(value, tokens)
    return value


def set_option(
    module_name: str,
    saved: Settings,
    key: str,
    value: str,
    *,
    tool_file: Path,
    build_parser: ParserBuilder,
    tokens: list[str] | None = None,
) -> bool:
    spec = _spec_or_report(module_name, tool_file=tool_file, build_parser=build_parser)
    if spec is None:
        return False
    active_command = _active_command(spec, saved)
    option = find_option(spec, key, active_command)
    if option is None:
        _explain_unknown_key(spec, key, active_command)
        return False
    stored = _coerce_value(option, value, tokens)
    if stored is None:
        return False
    saved[option.name] = stored
    _assignment(option.name, stored, module_name=module_name, option_kind=option.kind)
    return True


def unset_option(saved: Settings, key: str) -> None:
    if key.strip().lower() in ("all", "*"):
        saved.clear()
        _plain("Cleared every saved option.", "muted")
        return
    wanted = normalize_key(key)
    stored_name = next((name for name in saved if name.upper() == wanted), None)
    if stored_name is None:
        _plain(f"{key} is not set.", "muted")
        return
    del saved[stored_name]
    _plain(f"Unset {stored_name}.", "muted")


def print_settings(
    module_name: str, saved: Settings, *, spec: Spec | None = None
) -> None:
    if not saved:
        _plain(f"No options saved for {module_name}.", "muted")
        return
    for option_name in sorted(saved):
        row = (
            find_option(spec, option_name, _active_command(spec, saved))
            if spec
            else None
        )
        _assignment(
            option_name,
            saved[option_name],
            module_name=module_name,
            option_kind=row.kind if row else "",
        )


def prepare_argv(
    module_name: str,
    argv: list[str],
    saved: Settings,
    *,
    tool_file: Path,
    build_parser: ParserBuilder,
) -> list[str]:
    if not saved:
        return list(argv)
    try:
        spec = load_spec(module_name, tool_file=tool_file, build_parser=build_parser)
    except SpecError as failure:
        ui.console.print(
            f"[warn]Saved options were not applied:[/warn] {escape(failure.message)}"
        )
        return list(argv)
    return render_argv(spec, saved, argv)


# --------------------------------------------------------------------------------------
# render_argv: saved settings + typed words -> one argv
# --------------------------------------------------------------------------------------


def subcommand_in(spec: Spec, words: list[str]) -> str | None:
    known = {name for name, _help in spec.subcommands}
    before_separator = itertools.takewhile(lambda word: word != "--", words)
    return next(
        (
            word
            for word in before_separator
            if not word.startswith("-") and word in known
        ),
        None,
    )


def _supplied_dests(
    rows: list[Option], argv: list[str], command_name: str = ""
) -> set[str]:
    """Dests the typed words already cover, matching flags exactly (no abbreviations, no clustering)."""
    row_by_flag = {flag: row for row in rows for flag in row.flags}
    positional_rows = sorted(
        (row for row in rows if row.kind == "positional"),
        key=lambda row: row.name != command_name,
    )
    covered: set[str] = set()
    next_positional = 0
    expect_value = False
    past_separator = False
    for word in argv:
        if expect_value:
            expect_value = False
            continue
        if not past_separator and word == "--":
            past_separator = True
            continue
        if not past_separator and word.startswith("-") and word != "-":
            flag, has_inline, _value = word.partition("=")
            matched = row_by_flag.get(flag)
            if matched is not None:
                covered.add(matched.dest)
                expect_value = matched.kind == "value" and not has_inline
            continue
        if next_positional < len(positional_rows):
            slot = positional_rows[next_positional]
            if slot.choices and word.lower() not in slot.choices:
                continue
            covered.add(slot.dest)
            next_positional += 1
    return covered


def _preferred_flag(option: Option) -> str:
    long_flags = [flag for flag in option.flags if flag.startswith("--")]
    return (long_flags or list(option.flags) or [""])[0]


def _pair(flag: str, value: str) -> list[str]:
    if value.startswith("-"):
        return [f"{flag}={value}"]
    return [flag, value]


def _words_for(option: Option, stored: str) -> list[str]:
    """Command-line words for one saved option."""
    flag = _preferred_flag(option)
    if option.kind == "bool":
        switched_on = stored.strip().lower() in _TRUE
        return [flag] if flag and switched_on != option.store_false else []
    if option.kind == "tail" or (option.kind == "positional" and option.repeatable):
        return shlex.split(stored)
    if not flag:
        return shlex.split(stored) if option.repeatable else [stored]
    if option.repeatable:
        return [word for part in shlex.split(stored) for word in _pair(flag, part)]
    return _pair(flag, stored)


def _placement(option: Option, command_name: str) -> str:
    """Which part of the final argv a saved option's words belong to."""
    if option.kind == "tail":
        return "tail"
    if option.kind == "positional":
        return (
            "leading" if command_name and option.name == command_name else "positionals"
        )
    return "flags"


def render_argv(spec: Spec, saved: Settings, argv: list[str]) -> list[str]:
    typed_command = subcommand_in(spec, argv)
    active_command = typed_command or _active_command(spec, saved)
    rows = _visible(spec, active_command)
    supplied_rows = (
        rows
        if typed_command
        else [row for row in rows if row.name != spec.command_name]
    )
    supplied = _supplied_dests(supplied_rows, argv, spec.command_name)
    placed: dict[str, list[str]] = {
        "leading": [],
        "flags": [],
        "positionals": [],
        "tail": [],
    }
    for option in rows:
        if option.name not in saved or option.dest in supplied:
            continue
        placed[_placement(option, spec.command_name)].extend(
            _words_for(option, saved[option.name])
        )
    return (
        placed["leading"]
        + placed["flags"]
        + list(argv)
        + placed["positionals"]
        + placed["tail"]
    )
