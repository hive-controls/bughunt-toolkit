"""Scope workspace commands."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator
from pathlib import Path

from rich.markup import escape
from rich.text import Text

from bughunt.console import ui
from bughunt.core import cli, workspace

# How a line reaches the console: with Rich markup and highlight as configured, with markup
# switched off, or with both off.
_STYLED: dict[str, bool] = {}
_LITERAL: dict[str, bool] = {"markup": False}
_VERBATIM: dict[str, bool] = {"markup": False, "highlight": False}

_NO_SCOPE_LINES = ("No scope file yet.", "  bughunt scope init")
_ADD_GROUPS = (("ok", "added"), ("muted", "already in scope"))
_REMOVE_GROUPS = (("ok", "removed"), ("warn", "not in scope"))


def _show(text: str | Text, mode: dict[str, bool] = _STYLED) -> None:
    ui.console.print(text, soft_wrap=True, **mode)


def _apply_edit(
    editor: Callable[[list[str]], tuple[list[str], list[str]]],
    hosts: list[str],
    groups: tuple[tuple[str, str], ...],
) -> list[str] | None:
    """Run an add or remove and print both result groups; None means the entries were refused."""
    try:
        changed, untouched = editor(hosts)
    except ValueError as refusal:
        _show(f"[err]{escape(str(refusal))}[/err]")
        return None
    for (style, label), bucket in zip(groups, (changed, untouched)):
        for host in bucket:
            _show(Text.assemble((label, style), " ", host), _LITERAL)
    return changed


def _screen_urls(text: str, admit: Callable[[str], bool]) -> tuple[list[str], int]:
    """The unique admitted URLs in first-seen order, and how many candidate lines were turned away."""
    candidates = workspace.live_lines(text)
    accepted = [line for line in candidates if "://" in line and admit(line)]
    return list(dict.fromkeys(accepted)), len(candidates) - len(accepted)


def _scope_listing() -> Iterator[tuple[str, dict[str, bool]]]:
    yield str(workspace.workspace_dir()), _VERBATIM
    listed = workspace.read_entries()
    if listed:
        yield from ((entry, _VERBATIM) for entry in listed)
    else:
        yield "Scope is empty. Loopback is still allowed.", _STYLED
    yield (
        f"{len(workspace.read_urls())} URL(s) in {workspace.urls_path().name}",
        _STYLED,
    )


def _do_init(args: argparse.Namespace) -> int:
    _show(
        Text.assemble(("scope", "ok"), " ", str(workspace.init_workspace())), _VERBATIM
    )
    return 0


def _do_path(args: argparse.Namespace) -> int:
    _show(str(workspace.workspace_dir()), _VERBATIM)
    return 0


def _do_list(args: argparse.Namespace) -> int:
    if not workspace.scope_is_active():
        for line in _NO_SCOPE_LINES:
            _show(line)
        return 2
    for text, mode in _scope_listing():
        _show(text, mode)
    return 0


def _do_add(args: argparse.Namespace) -> int:
    return (
        2 if _apply_edit(workspace.add_entries, args.hosts, _ADD_GROUPS) is None else 0
    )


def _do_remove(args: argparse.Namespace) -> int:
    return 0 if _apply_edit(workspace.remove_entries, args.hosts, _REMOVE_GROUPS) else 2


def _do_allow(args: argparse.Namespace) -> int:
    host = workspace.hostname_of(args.target) or args.target.strip()
    if workspace.allowed(host):
        _show(Text.assemble(("in scope", "ok"), " ", host), _LITERAL)
        return 0
    _show(workspace.explain_block(host), _VERBATIM)
    return 2


def _do_import_urls(args: argparse.Namespace) -> int:
    source = Path(args.file)
    if not source.is_file():
        _show(Text.assemble(("No file named", "err"), " ", args.file), _LITERAL)
        return 2
    if not workspace.scope_is_active():
        _show(workspace.explain_block("(no host)"), _VERBATIM)
        return 2
    text = source.read_text(encoding="utf-8", errors="replace")
    unique, skipped = _screen_urls(text, workspace.allowed)
    fresh = workspace.remember_urls(unique)
    for address in unique:
        print(address)
    _show(f"[ok]{fresh} new[/ok]  {len(unique)} in scope  {skipped} skipped")
    return 0


def _do_urls(args: argparse.Namespace) -> int:
    for url in workspace.read_urls():
        print(url)
    return 0


_COMMANDS = {
    "init": cli.Verb("Create .bughunt with an empty scope.", _do_init),
    "path": cli.Verb("Print the workspace directory.", _do_path),
    "list": cli.Verb("Print scope entries.", _do_list),
    "add": cli.Verb(
        "Add hosts, domains, *.domains, or CIDRs.",
        _do_add,
        (
            (
                ("hosts",),
                {"nargs": "+", "help": "Host, domain, *.domain, CIDR, or URL."},
            ),
        ),
    ),
    "remove": cli.Verb(
        "Remove scope entries.", _do_remove, ((("hosts",), {"nargs": "+"}),)
    ),
    "allow": cli.Verb(
        "Exit 0 when the host is in scope.",
        _do_allow,
        ((("target",), {"help": "Host or URL."}),),
    ),
    "import-urls": cli.Verb(
        "Keep in-scope URLs from a file.",
        _do_import_urls,
        ((("file",), {"help": "One URL per line."}),),
    ),
    "urls": cli.Verb("Print the shared URL list.", _do_urls),
}


def build_parser() -> argparse.ArgumentParser:
    parser = cli.build_parser(
        "bughunt scope",
        "Keep the hosts this engagement may touch, and the URL list other modules share.",
    )
    cli.add_verbs(parser, _COMMANDS, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parsed = build_parser().parse_args(argv)
    command = _COMMANDS.get(parsed.command)
    if command is None:
        _show("[err]Unknown scope command.[/err]")
        return 2
    return command.run(parsed)
