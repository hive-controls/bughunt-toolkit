"""Persist request authentication for the current scoped workspace."""

from __future__ import annotations

import argparse

from bughunt.core import cli
from bughunt.core.identity import IdentityError
from bughunt.core.session import (
    has_line_separator,
    load_session,
    session_path,
    write_session,
)

_DESCRIPTION = "Save a Cookie or Authorization header for in-scope requests."
_KINDS = ("cookie", "authorization")
_SAMPLES = {"cookie": "session=abc", "authorization": "Bearer token"}
_VALUE_HELP = "The header value you already have."

_MSG_NOTHING_SAVED = "No session headers saved."
_MSG_BAD_VALUE = "Give a single header value."
_MSG_BAD_ACTOR = "Selected actor is invalid or cannot hold session credentials."
_MSG_UNKNOWN = "Unknown session command."
_MSG_CLEARED_ALL = "session cleared"


def _refuse(message: str) -> int:
    print(message, flush=True)
    return 2


def _inventory(saved: dict[str, str]) -> list[str]:
    if saved:
        return [f"{kind}: [REDACTED]" for kind in _KINDS if kind in saved]
    hints = [f"  bughunt session set {kind} '{_SAMPLES[kind]}'" for kind in _KINDS]
    return [_MSG_NOTHING_SAVED, *hints]


def _show(args: argparse.Namespace) -> int:
    for line in _inventory(load_session()):
        print(line)
    return 0


def _acceptable(value: str) -> bool:
    return bool(value) and not has_line_separator(value)


def _save(args: argparse.Namespace) -> int:
    value = " ".join(args.value).strip()
    if not _acceptable(value):
        return _refuse(_MSG_BAD_VALUE)
    write_session({**load_session(), args.kind: value})
    print(f"{args.kind} saved in {session_path()}")
    return 0


def _drop(args: argparse.Namespace) -> int:
    saved = load_session()
    survivors = (
        {} if args.kind is None else {k: v for k, v in saved.items() if k != args.kind}
    )
    write_session(survivors)
    print(_MSG_CLEARED_ALL if args.kind is None else f"{args.kind} cleared")
    return 0


_COMMANDS = {
    "show": cli.Verb("Print the saved headers.", _show),
    "set": cli.Verb(
        "Save one header.",
        _save,
        (
            (("kind",), {"choices": _KINDS}),
            (("value",), {"nargs": "+", "help": _VALUE_HELP}),
        ),
    ),
    "clear": cli.Verb(
        "Remove one saved header, or both.",
        _drop,
        ((("kind",), {"nargs": "?", "choices": _KINDS}),),
    ),
}


def build_parser() -> argparse.ArgumentParser:
    parser = cli.build_parser("bughunt session", _DESCRIPTION)
    cli.add_verbs(parser, _COMMANDS, required=True)
    return parser


def _dispatch(args: argparse.Namespace) -> int:
    verb = _COMMANDS.get(args.command)
    if verb is None:
        return _refuse(_MSG_UNKNOWN)
    return verb.run(args)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _dispatch(args)
    except IdentityError:
        return _refuse(_MSG_BAD_ACTOR)
