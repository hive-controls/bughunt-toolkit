"""A timestamped note pad that lives in the workspace as notes.txt.

Nothing here touches the network or the scope list.
"""

from __future__ import annotations

import re
from argparse import ArgumentParser, Namespace
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from bughunt.core import banner, cli, termio
from bughunt.core.workspace import (
    live_lines,
    read_workspace_text,
    store_workspace_text,
    workspace_dir,
)
from bughunt.modules import MODULES

_PAD_HEAD = "# Bughunt notes. One timestamped line each.\n\n"
_PAD_FILE = "notes.txt"
_EMPTY_PAD = "no notes"
_CLEARED = "notes cleared"
_SINGLE_LINE = "Give a single line."
# 20 stamp characters, one space, then the note itself.
_NOTE_LINE = re.compile(r"(.{20}) (.+)")

Note = tuple[str, str]


# ---- terminal layer -------------------------------------------------------------------------

_NAMEPLATE = "quill"
_TAGLINE = "field notes beside the scope"
# Each row carries a leading "|" so editors cannot eat the indentation.
_ART_BLOCK = r"""
|               /
|              /
|             /
|            / \
|           | quill |
|            \   /
|             [_]
"""
_ART = [row[1:] for row in _ART_BLOCK.strip("\n").splitlines()]


def format_banner(color: bool) -> str:
    return banner.render_banner(_ART, _NAMEPLATE, _TAGLINE, color)


# ---- the pad: pure parse and render, then the file around them ---------------------------------


def _parse_pad(text: str) -> list[Note]:
    return [
        (hit[1], hit[2]) for hit in map(_NOTE_LINE.fullmatch, live_lines(text)) if hit
    ]


def _render_pad(notes: list[Note]) -> str:
    return _PAD_HEAD + "".join(f"{stamp} {text}\n" for stamp, text in notes)


def notes_path() -> Path:
    return workspace_dir() / _PAD_FILE


def read_notes() -> list[Note]:
    return _parse_pad(read_workspace_text(_PAD_FILE))


def _write(notes: list[Note]) -> None:
    store_workspace_text(_PAD_FILE, _render_pad(notes) if notes else None)


def format_note(stamp: str, text: str, color: bool) -> str:
    stamp, text = termio.neutralize(stamp), termio.neutralize(text)
    if color:
        return f"  {banner.ANSI.wrap('dim', stamp)}  {banner.ANSI.wrap('white', text)}"
    return "  ".join((stamp, text))


# ---- verbs ------------------------------------------------------------------------------------


def _single_line(words: list[str]) -> str:
    joined = " ".join(words)
    note = " ".join(joined.split())
    if not note or "\r" in joined or "\n" in joined:
        raise cli.CommandExit(2, _SINGLE_LINE)
    return note


def append_note(words: list[str]) -> Note:
    note = _single_line(words)
    stamp = datetime.now(timezone.utc).strftime(termio.UTC_STAMP)
    location = notes_path()
    existing = (
        location.read_bytes() if location.is_file() else _PAD_HEAD.encode("utf-8")
    )
    separator = b"\n" if existing and not existing.endswith((b"\r", b"\n")) else b""
    location.parent.mkdir(parents=True, exist_ok=True)
    location.write_bytes(existing + separator + f"{stamp} {note}\n".encode("utf-8"))
    return stamp, note


def _add(args: Namespace, color: bool) -> None:
    stamp, note = append_note(args.text)
    print(format_note(stamp, note, color))


def _list(args: Namespace, color: bool) -> None:
    notes = read_notes()
    if not notes:
        termio.say(_EMPTY_PAD)
        return
    print("\n".join(format_note(stamp, text, color) for stamp, text in notes))


def clear_notes() -> bool:
    location = notes_path()
    existed = location.is_file()
    location.unlink(missing_ok=True)
    return existed


def _clear(args: Namespace, color: bool) -> None:
    clear_notes()
    print(_CLEARED)


# Declaration order is the order the console and the catalog show.
_VERBS = {
    "list": cli.Verb("Print the pad.", _list),
    "add": cli.Verb(
        "Append one note.",
        _add,
        ((("text",), {"nargs": "+", "help": "The note. One line."}),),
    ),
    "clear": cli.Verb("Remove the pad.", _clear),
}
_DEFAULT_VERB = "list"


def build_parser() -> ArgumentParser:
    root = cli.build_parser("bughunt quill", MODULES["quill"], [cli.PLAIN])
    cli.add_verbs(root, _VERBS)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    colour = termio.open_output(options.plain, format_banner)
    return cli.run(_VERBS[options.command or _DEFAULT_VERB].run, options, colour)
