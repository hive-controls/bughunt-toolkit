"""Terminal presentation shared by every Bughunt command: one theme, one console, one yes/no prompt."""

from __future__ import annotations

import sys

from rich.console import Console
from rich.theme import Theme

# Callers write these names in markup; only the colours behind them are free to change.
_STYLE_TABLE: tuple[tuple[str, str], ...] = (
    ("ok", "green"),
    ("warn", "yellow"),
    ("err", "red bold"),
    ("info", "cyan"),
    ("muted", "grey50"),
    ("brand", "magenta bold"),
)

THEME = Theme(dict(_STYLE_TABLE))


def _stdout_console() -> Console:
    """Framework reports go to stdout so `bughunt modules` and friends can be piped.

    Highlighting stays off: numbers and URLs inside module output must reach the screen as written.
    """
    return Console(
        file=sys.stdout,
        highlight=False,
        theme=THEME,
    )


console = _stdout_console()

_YES_ANSWERS = frozenset({"y", "yes"})


def confirm(question: str, *, assume_yes: bool = False, stream=None) -> bool:
    """Ask a y/N question. Without a terminal the answer is always no, so a script cannot opt in by accident."""
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        return False
    try:
        prompt = f"{question} [y/N] "
        if stream is None:
            reply = input(prompt)
        else:
            print(prompt, end="", file=stream, flush=True)
            reply = input()
    except EOFError:
        return False
    return reply.strip().lower() in _YES_ANSWERS
