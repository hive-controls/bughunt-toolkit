"""Command-line plumbing shared by the command modules: early exits, parsers, common options.

A module keeps its options and verbs as plain data and hands them to the builders here, so the
order they are registered in, their help text, and the exit codes stay exactly as the module
declares them. Imports only ``argparse`` and ``termio``.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable, Mapping
from typing import Any, NamedTuple

from bughunt.core import termio

# What ``add_argument(*flags, **settings)`` takes: a flag or positional name, and the rest.
Option = tuple[tuple[str, ...], dict[str, Any]]
# A refusal condition on parsed options, and the message shown when it holds.
Rule = tuple[Callable[[argparse.Namespace], bool], str]


class CommandExit(Exception):
    """Ends a command early: ``message`` is said on stderr, then the command returns ``code``."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def run(entry: Callable[..., int | None], *arguments: Any) -> int:
    """Call ``entry(*arguments)`` and return its exit code; returning nothing means 0.

    A CommandExit raised on the way is said on stderr and becomes the code it carries.
    """
    try:
        return entry(*arguments) or 0
    except CommandExit as stop:
        termio.say(stop.message)
        return stop.code


PLAIN: Option = (("--plain",), {"action": "store_true", "help": "Skip the banner."})
INSECURE: Option = (("--insecure",), {"action": "store_true", "help": "Do not verify TLS certificates."})
COOKIE: Option = (
    ("--cookie",),
    {"default": None, "help": "Cookie for this run. Replaces the saved session cookie."},
)
AUTHORIZATION: Option = (
    ("--authorization",),
    {"default": None, "help": "Authorization for this run. Replaces the saved session value."},
)
SESSION_OPTIONS = (COOKIE, AUTHORIZATION)


def _bad_endpoint(options: argparse.Namespace) -> bool:
    return options.timeout <= 0 or options.port not in range(1, 65536)


ENDPOINT_RULE: Rule = (
    _bad_endpoint,
    "Timeout must be greater than 0, and the port must be 1 through 65535.",
)


def check(options: argparse.Namespace, rules: Iterable[Rule], *, code: int = 2) -> None:
    """Exit with ``code`` and the message of the first rule the parsed options trip."""
    for refused, message in rules:
        if refused(options):
            raise CommandExit(code, message)


def build_parser(prog: str, description: str, options: Iterable[Option] = ()) -> argparse.ArgumentParser:
    """A parser whose options are registered in the order given, after ``-h``."""
    parser = argparse.ArgumentParser(prog=prog, description=description)
    for flags, settings in options:
        parser.add_argument(*flags, **settings)
    return parser


class Verb(NamedTuple):
    """One subcommand: the summary the help lists, what it runs, and the arguments it takes."""

    summary: str
    run: Callable[..., Any]
    arguments: tuple[Option, ...] = ()


def add_verbs(
    parser: argparse.ArgumentParser,
    verbs: Mapping[str, Verb],
    *,
    dest: str = "command",
    required: bool = False,
) -> None:
    """Register each verb as a subcommand, in the order the mapping lists them."""
    branches = parser.add_subparsers(dest=dest, required=required)
    for name, verb in verbs.items():
        branch = branches.add_parser(name, help=verb.summary)
        for flags, settings in verb.arguments:
            branch.add_argument(*flags, **settings)
