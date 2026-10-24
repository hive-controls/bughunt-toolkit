"""Put short labels on URLs that are already in the shared list (marks.txt).

Nothing here touches the network or the scope list.
"""

from __future__ import annotations

import itertools
import re
from argparse import ArgumentParser, Namespace
from collections.abc import Sequence
from pathlib import Path

from bughunt.core import banner, cli, termio
from bughunt.core.workspace import (
    live_lines,
    read_urls,
    read_workspace_text,
    workspace_dir,
)
from bughunt.modules import MODULES

Mark = tuple[str, str]

_MARKS_FILE = "marks.txt"
_FILE_HEAD = "# Bughunt marks. One label and one URL per line.\n\n"
_LABEL_SHAPE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
_LABEL_HINT = "A label is a short word, such as login."
_SINGLE_URL = "Give a single URL."
_NOT_LISTED = "That URL is not in the shared list."
_NEED_PAIR = "Give a label and a URL."
_NOT_SAVED = "That mark is not saved."


# ---- terminal layer -------------------------------------------------------------------------

_NAMEPLATE = "blaze"
_TAGLINE = "trail marks on the url list"
_ART = banner.art_rows(
    (
        (14, ")"),
        (13, ") \\"),
        (12, ")   )"),
        (11, "( blaze )"),
        (12, ")   )"),
        (13, ") /"),
        (13, "[_]"),
    )
)


def format_banner(color: bool) -> str:
    return banner.render_banner(_ART, _NAMEPLATE, _TAGLINE, color)


# ---- marks: parsing, rendering, and the file around them ----------------------------------------


def _normal_label(value: str) -> str | None:
    found = _LABEL_SHAPE.fullmatch(value.strip().lower())
    return found[0] if found else None


def _parse_marks(text: str) -> list[Mark]:
    marks = []
    for line in live_lines(text):
        label, space, url = line.partition(" ")
        if space:
            marks.append((label.strip().lower(), url.strip()))
    return marks


def _render_marks(marks: Sequence[Mark]) -> str:
    return _FILE_HEAD + "".join(f"{label} {url}\n" for label, url in marks)


def marks_path() -> Path:
    return workspace_dir() / _MARKS_FILE


def read_marks() -> list[Mark]:
    return _parse_marks(read_workspace_text(_MARKS_FILE))


def _save(marks: Sequence[Mark]) -> None:
    location = marks_path()
    existing = (
        location.read_bytes() if location.is_file() else _FILE_HEAD.encode("utf-8")
    )
    retained = []
    original_marks = set()
    for line in existing.splitlines(keepends=True):
        parsed = _parse_marks(line.decode("utf-8", errors="replace"))
        original_marks.update(parsed)
        if not parsed or parsed[0] in marks:
            retained.append(line)
    payload = b"".join(retained)
    for label, url in marks:
        if (label, url) not in original_marks:
            if payload and not payload.endswith((b"\r", b"\n")):
                payload += b"\n"
            payload += f"{label} {url}\n".encode("utf-8")
    if not marks and payload == _FILE_HEAD.encode("utf-8"):
        location.unlink(missing_ok=True)
    else:
        location.parent.mkdir(parents=True, exist_ok=True)
        location.write_bytes(payload)


def _grouped_lines(marks: Sequence[Mark], color: bool) -> list[str]:
    hues = banner.ink(color)
    lines = []
    for label, run in itertools.groupby(marks, key=lambda mark: mark[0]):
        lines.append(hues.wrap("magenta", label))
        lines.extend("  " + hues.wrap("white", url) for _, url in run)
    return lines


# ---- verbs ------------------------------------------------------------------------------------


def _require_label(value: str) -> str:
    label = _normal_label(value)
    if label is None:
        raise cli.CommandExit(2, _LABEL_HINT)
    return label


def _require_listed_url(value: str) -> str:
    target = value.strip()
    if not target or "\r" in target or "\n" in target:
        raise cli.CommandExit(2, _SINGLE_URL)
    listed = read_urls()
    if target not in listed:
        raise cli.CommandExit(2, _NOT_LISTED)
    return target


def add_mark(label: str, url: str) -> tuple[str, str, bool]:
    label = _require_label(label)
    target = _require_listed_url(url)
    marks = read_marks()
    if (label, target) in marks:
        return label, target, False
    _save([*marks, (label, target)])
    return label, target, True


def remove_mark(label: str, url: str) -> tuple[str, str]:
    label, target = _normal_label(label), url.strip()
    if label is None or not target:
        raise cli.CommandExit(2, _NEED_PAIR)
    marks = read_marks()
    kept = [mark for mark in marks if mark != (label, target)]
    if len(kept) == len(marks):
        raise cli.CommandExit(2, _NOT_SAVED)
    _save(kept)
    return label, target


def _add(args: Namespace, color: bool) -> None:
    label, target, changed = add_mark(args.label, args.url)
    print(f"{label} {'marks' if changed else 'already marks'} {target}")


def _remove(args: Namespace, color: bool) -> None:
    label, target = remove_mark(args.label, args.url)
    print(f"{label} cleared {target}")


def _list(args: Namespace, color: bool) -> None:
    marks = read_marks()
    wanted = getattr(args, "label", None)
    if wanted:
        label = _require_label(wanted)
        lines = [url for owner, url in marks if owner == label]
        nothing = f"no {label} marks"
    else:
        lines = _grouped_lines(marks, color)
        nothing = "no marks"
    if lines:
        print("\n".join(lines))
    else:
        termio.say(nothing)


# Declaration order is the order the console and the catalog show.
_ACTIONS = {
    "list": cli.Verb(
        "Print marks, or the URLs for one label.",
        _list,
        ((("label",), {"nargs": "?", "help": "Only this label."}),),
    ),
    "add": cli.Verb(
        "Mark one listed URL.",
        _add,
        (
            (("label",), {"help": "Short label, such as login or review."}),
            (("url",), {"help": "URL that is already in the shared list."}),
        ),
    ),
    "remove": cli.Verb("Remove one mark.", _remove, ((("label",), {}), (("url",), {}))),
}
_DEFAULT_ACTION = "list"


def build_parser() -> ArgumentParser:
    root = cli.build_parser("bughunt blaze", MODULES["blaze"], [cli.PLAIN])
    cli.add_verbs(root, _ACTIONS)
    return root


def main(argv: Sequence[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    colour = termio.open_output(options.plain, format_banner)
    return cli.run(_ACTIONS[options.command or _DEFAULT_ACTION].run, options, colour)
