"""Tab completion and command history for the typed console.

``complete_line`` is a pure function of the text before the cursor, so it is easy to drive without a
terminal. ``install_reader`` is the only part that touches ``readline``.
"""

from __future__ import annotations

import difflib
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from bughunt.console.catalog import REFERENCES, group_names, reference_canonical
from bughunt.console.options import (
    Option,
    Spec,
    SpecError,
    _active_command,
    _visible,
    find_option,
    load_spec,
    normalize_key,
    split_words,
    subcommand_in,
)
from bughunt.core import workspace
from bughunt.modules import MODULES

CONSOLE_COMMANDS = (
    "help",
    "show",
    "use",
    "set",
    "unset",
    "run",
    "back",
    "banner",
    "doctor",
    "version",
    "examples",
    "modules",
    "search",
    "history",
    "exit",
    "quit",
)

HISTORY_LIMIT = 1000

_FILE_OPTION_NAMES = frozenset(
    {"FILE", "INPUTS", "SAVE", "OUTPUT", "WORDLIST", "REQUEST"}
)

# Lines mentioning any of these never reach the history file.
_SENSITIVE_FRAGMENTS = (
    "token",
    "password",
    "secret",
    r"api[_-]?key",
    r"auth[_-]?key",
    "authorization",
    "cookie",
    "eyJ",
)
_SENSITIVE = re.compile("|".join(_SENSITIVE_FRAGMENTS), re.IGNORECASE)


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def sensitive_line(text: str) -> bool:
    return bool(_SENSITIVE.search(text))


def suggest_console(token: str) -> str | None:
    closest = difflib.get_close_matches(token, CONSOLE_COMMANDS, n=1, cutoff=0.8)
    return closest[0] if closest else None


def presented_match(candidate: str, sole_match: bool) -> str:
    """readline appends nothing itself, so a lone finished word gets its trailing space here."""
    finished = bool(candidate) and not candidate.endswith("/")
    return candidate + " " if sole_match and finished else candidate


def module_names() -> list[str]:
    """``scan``, every built-in module, then each reference tool followed by its aliases."""
    reference_spellings = [
        spelling for tool in REFERENCES for spelling in (tool.command, *tool.aliases)
    ]
    return ["scan", *MODULES, *reference_spellings]


def _matching(items: Iterable[str], word: str) -> list[str]:
    """Items that begin with ``word``, ignoring case."""
    prefix = word.lower()
    return [item for item in items if item.lower().startswith(prefix)]


# --------------------------------------------------------------------------------------
# history
# --------------------------------------------------------------------------------------

_DEFAULT_HISTORY_PARTS = (".local", "share", "bughunt", "history")


def history_path() -> Path:
    configured = os.environ.get("BUGHUNT_HISTORY", "").strip()
    if configured:
        return Path(configured).expanduser()
    return Path.home().joinpath(*_DEFAULT_HISTORY_PARTS)


def _retained(lines: Iterable[str]) -> list[str]:
    """Drop blank and credential-bearing lines, then keep only the most recent HISTORY_LIMIT."""
    kept = [line for line in lines if line.strip() and not sensitive_line(line)]
    return kept[-HISTORY_LIMIT:]


def save_history(target: Path, lines: Iterable[str]) -> None:
    kept = _retained(lines)
    body = "\n".join(kept) + "\n" if kept else ""
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8", newline="\n")
    except OSError:
        pass


def load_history(target: Path) -> list[str]:
    import readline

    try:
        stored = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    kept = _retained(stored.splitlines())
    for entry in kept:
        readline.add_history(entry)
    return kept


# --------------------------------------------------------------------------------------
# per-session state and the readline hookup
# --------------------------------------------------------------------------------------


@dataclass(eq=False)
class CompleteState:
    """What completion needs to know about the running console."""

    tool_file: Path
    build_parser: Callable | None
    settings: dict
    active: str | None = None
    _forms: dict[str, Spec | None] = field(default_factory=dict, init=False, repr=False)

    def spec(self, name: str | None) -> Spec | None:
        if not name:
            return None
        if name not in self._forms:
            try:
                self._forms[name] = load_spec(
                    name, tool_file=self.tool_file, build_parser=self.build_parser
                )
            except SpecError:
                self._forms[name] = None
        return self._forms[name]


def _is_terminal(handle) -> bool:
    try:
        return bool(handle.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _make_completer(
    readline_module, state: CompleteState
) -> Callable[[str, int], str | None]:
    """The function readline calls on each tab press; it never raises, so a failure cannot disturb the prompt."""
    offered: list[str] = []

    def completer(text: str, index: int):
        try:
            if index == 0:
                before_word = readline_module.get_line_buffer()[
                    : readline_module.get_begidx()
                ]
                found = complete_line(before_word, text, state)
                sole = len(found) == 1
                offered[:] = [presented_match(item, sole) for item in found]
            return offered[index] if index < len(offered) else None
        except Exception:
            return None

    return completer


def _bind_completer(
    readline_module, completer: Callable[[str, int], str | None]
) -> None:
    readline_module.set_completer_delims(" \t\n")
    readline_module.set_completer(completer)
    readline_module.parse_and_bind("tab: complete")
    set_auto_history = getattr(readline_module, "set_auto_history", None)
    if callable(set_auto_history):
        set_auto_history(False)


def install_reader(state: CompleteState):
    """Wire tab completion into readline; returns the line reader to use, or None without a terminal."""
    if not (_is_terminal(sys.stdin) and _is_terminal(sys.stdout)):
        return None
    try:
        import readline
    except ImportError:
        return None
    _bind_completer(readline, _make_completer(readline, state))
    return input


# --------------------------------------------------------------------------------------
# paths
# --------------------------------------------------------------------------------------


def _explicit_path(typed: str) -> bool:
    return (
        typed.startswith(("/", "~", "./", "../"))
        or "/" in typed
        or (os.sep == "\\" and "\\" in typed)
    )


def _split_folder(typed_path: str) -> tuple[str, str]:
    """Split typed text into the folder part (with its trailing separator) and the partial name."""
    cut = max(typed_path.rfind(sep) for sep in {"/", os.sep})
    return typed_path[: cut + 1], typed_path[cut + 1 :]


def _path_matches(typed_path: str) -> list[str]:
    if typed_path == "~":
        return ["~/"]
    folder_text, partial = _split_folder(typed_path)
    location = Path(folder_text).expanduser() if folder_text else Path(".")
    show_hidden = partial.startswith(".")
    found: list[str] = []
    try:
        with os.scandir(location) as entries:
            for entry in entries:
                if not entry.name.startswith(partial) or (
                    entry.name.startswith(".") and not show_hidden
                ):
                    continue
                found.append(folder_text + entry.name + ("/" if entry.is_dir() else ""))
    except OSError:
        return []
    return found


def _saved_names(module_name: str, subcommand: str | None) -> list[str]:
    """Names of files the workspace saved for modules that read them (diff, clutch show)."""
    if module_name == "diff":
        saved_folder = workspace.responses_dir()
    elif module_name == "clutch" and subcommand == "show":
        saved_folder = workspace.requests_dir()
    else:
        return []
    try:
        return [
            item.name
            for item in saved_folder.iterdir()
            if item.is_file() and not item.name.startswith(".")
        ]
    except OSError:
        return []


# --------------------------------------------------------------------------------------
# option values and module arguments
# --------------------------------------------------------------------------------------


def _file_valued(row: Option) -> bool:
    return row.name in _FILE_OPTION_NAMES or row.name.endswith("_FILE")


def _values_for(row: Option, typed: str) -> list[str]:
    if row.kind == "bool":
        return _matching(("true", "false"), typed)
    if row.choices:
        return _matching(row.choices, typed)
    if _file_valued(row) or _explicit_path(typed):
        return _path_matches(typed)
    return []


def _row_for_flag(rows: list[Option], wanted_flag: str) -> Option | None:
    return next((row for row in rows if wanted_flag in row.flags), None)


def _argument_candidates(
    spec: Spec, module: str, preceding: list[str], word: str, state: CompleteState
) -> list[str]:
    saved = state.settings.get(module, {})
    command = subcommand_in(spec, preceding) or _active_command(spec, saved)
    rows = _visible(spec, command)
    dashed = word.startswith("-")
    if dashed and "=" in word:
        flag, _, partial = word.partition("=")
        row = _row_for_flag(rows, flag)
        return [f"{flag}={value}" for value in _values_for(row, partial)] if row else []
    if preceding and not dashed:
        row = _row_for_flag(rows, preceding[-1])
        if row is not None and row.kind == "value":
            return _values_for(row, word)
    if spec.subcommands and command is None and not dashed:
        names = _matching([sub for sub, _help in spec.subcommands], word)
        if names:
            return names
    if dashed:
        return [flag for row in rows for flag in row.flags if flag.startswith(word)]
    if not _explicit_path(word):
        names = _matching(_saved_names(module, command), word)
        if names:
            return names
    if not word:
        return [flag for row in rows for flag in row.flags if flag.startswith("--")]
    return _path_matches(word)


def _complete_arguments(
    module: str | None, preceding: list[str], word: str, state: CompleteState
) -> list[str]:
    spec = state.spec(module)
    if spec is None:
        return [] if word.startswith("-") or not word else _path_matches(word)
    return _argument_candidates(spec, module, preceding, word, state)


# --------------------------------------------------------------------------------------
# console commands
# --------------------------------------------------------------------------------------


def _option_names(spec: Spec, word: str, active_command: str | None) -> list[str]:
    stem = normalize_key(word.lstrip("-"))

    def spelled_like_stem(row: Option) -> bool:
        spellings = [row.name, *(normalize_key(flag.lstrip("-")) for flag in row.flags)]
        return any(spelling.startswith(stem) for spelling in spellings)

    return [
        row.name for row in _visible(spec, active_command) if spelled_like_stem(row)
    ]


def _complete_set(preceding: list[str], word: str, state: CompleteState) -> list[str]:
    spec = state.spec(state.active)
    if spec is None:
        return []
    command = _active_command(spec, state.settings.get(state.active, {}))
    if not preceding:
        if "=" not in word:
            return _option_names(spec, word, command)
        typed_name, _, partial = word.partition("=")
        row = find_option(spec, typed_name, command)
        return (
            [f"{typed_name}={value}" for value in _values_for(row, partial)]
            if row
            else []
        )
    if len(preceding) == 1:
        row = find_option(spec, preceding[0], command)
        return _values_for(row, word) if row else []
    return []


def _complete_show(preceding: list[str], word: str) -> list[str]:
    if not preceding:
        return _matching(("modules", "options"), word)
    if len(preceding) == 1 and preceding[0].lower() in ("modules", "module"):
        return _matching(group_names(), word)
    return []


def _complete_unset(preceding: list[str], word: str, state: CompleteState) -> list[str]:
    if preceding:
        return []
    saved = state.settings.get(state.active, {}) if state.active else {}
    return _matching([*saved, "all"], word)


def _candidates(preceding: list[str], word: str, state: CompleteState) -> list[str]:
    if not preceding:
        return _matching([*CONSOLE_COMMANDS, *module_names()], word)
    head, rest = preceding[0], preceding[1:]
    if head in ("use", "search"):
        return [] if rest else _matching(module_names(), word)
    if head == "show":
        return _complete_show(rest, word)
    if head in ("modules", "commands"):
        return [] if rest else _matching(group_names(), word)
    if head == "set":
        return _complete_set(rest, word, state)
    if head == "unset":
        return _complete_unset(rest, word, state)
    if head == "run":
        return _complete_arguments(state.active, rest, word, state)
    module = "scan" if head == "scan" else reference_canonical(head)
    if module is None:
        return []
    return _complete_arguments(module, rest, word, state)


def complete_line(line_before: str, word: str, state: CompleteState) -> list[str]:
    """Completions for ``word`` given the console text before it: unique, sorted case-insensitively."""
    try:
        preceding = split_words(line_before)
    except ValueError:
        return []
    return sorted(
        set(_candidates(preceding, word, state)), key=lambda item: (item.lower(), item)
    )
