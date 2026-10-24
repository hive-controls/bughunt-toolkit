"""Banner painting shared by the command modules: the colour palette, the picture painter, key/value rows.

A module keeps its own picture, nameplate, tagline text, and the hue its tagline takes; this file only
turns them into bytes. ``Ink`` holds the escape sequences and ``BARE`` is the same shape with every
sequence empty, so one code path draws both the coloured and the plain form. Imports only ``termio``.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable
from typing import NamedTuple

from bughunt.core import termio

_ACCENTED = "()[]"
_KEY_COLUMN = 12


def sgr(code: str) -> str:
    """The escape sequence that selects the graphic rendition ``code``, such as ``1;96``."""
    return f"\x1b[{code}m"


class Ink(NamedTuple):
    """The eight escape sequences banners and their rows are drawn with."""

    cyan: str
    yellow: str
    magenta: str
    white: str
    green: str
    red: str
    dim: str
    reset: str

    def wrap(self, hue: str, text: str) -> str:
        """``text`` in the named hue, closed with a reset."""
        return f"{getattr(self, hue)}{text}{self.reset}"


ANSI = Ink(*map(sgr, ("1;96", "1;93", "1;95", "1;97", "1;92", "1;91", "2;96", "0")))
BARE = Ink(*[""] * len(Ink._fields))


def ink(color: bool) -> Ink:
    """The palette to draw with: real escape sequences, or the empty one for plain text."""
    return ANSI if color else BARE


def art_rows(margins_and_glyphs: Iterable[tuple[int, str]]) -> list[str]:
    """Picture rows from ``(left margin, glyphs)`` pairs."""
    return [" " * margin + glyphs for margin, glyphs in margins_and_glyphs]


def paint_row(row: str, nameplate: str, hues: Ink) -> str:
    """One picture row in cyan, the nameplate in magenta.

    A row without the nameplate gets each bracket in yellow instead; a row that holds the
    nameplate keeps its brackets cyan.
    """
    if nameplate in row:
        before, _, after = row.partition(nameplate)
        return f"{hues.cyan}{before}{hues.magenta}{nameplate}{hues.cyan}{after}{hues.reset}"
    accents = str.maketrans({mark: f"{hues.yellow}{mark}{hues.cyan}" for mark in _ACCENTED})
    return f"{hues.cyan}{row.translate(accents)}{hues.reset}"


def render_banner(
    rows: Iterable[str], nameplate: str, tagline: str, color: bool, *, tagline_hue: str = "dim"
) -> str:
    """The picture rows then the tagline, one per line; ``color`` False gives the bare text.

    ``tagline_hue`` names the ``Ink`` field the tagline is drawn in.
    """
    hues = ink(color)
    painted = [paint_row(row, nameplate, hues) for row in rows]
    return "\n".join([*painted, hues.wrap(tagline_hue, tagline)])


def format_pair(key: str, value: str, color: bool, *, dim: bool = False) -> str:
    """A key and its value: a cyan key column and white (or dim) value, or ``key<TAB>value`` plain."""
    if not color:
        return f"{key}\t{value}"
    return f"  {ANSI.wrap('cyan', key.ljust(_KEY_COLUMN))} {ANSI.wrap('dim' if dim else 'white', value)}"


def note(message: str) -> None:
    """Say ``message`` on stderr, in yellow when stderr takes colour."""
    termio.say(ink(termio.color_enabled(sys.stderr)).wrap("yellow", message))
