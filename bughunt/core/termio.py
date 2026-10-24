"""Shared terminal plumbing for the command modules: tty and colour rules, stderr notes, banners.

Streams and the environment are read at call time, so swapping ``sys.stderr`` or setting
``NO_COLOR``/``TERM`` after import is honoured. Banner art and palettes stay in each module;
only the generic decisions live here.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Callable
from typing import TextIO


def stream_is_tty(stream: TextIO) -> bool:
    """True when ``stream`` reports a terminal; a missing or failing ``isatty`` counts as no."""
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def color_enabled(stream: TextIO) -> bool:
    """Colour only on a terminal, never with a non-empty ``NO_COLOR`` or an empty/``dumb`` ``TERM``."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") in ("", "dumb"):
        return False
    return stream_is_tty(stream)


UTC_STAMP = "%Y-%m-%d %H:%M:%SZ"


def stdout_color(plain: bool) -> bool:
    """Colour on stdout: never when ``plain`` was asked for, otherwise the usual colour rule."""
    return not plain and color_enabled(sys.stdout)


_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_CONTROL_CHARS_KEEP_LINES = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def neutralize(text: str, *, keep_lines: bool = False) -> str:
    """Make untrusted text safe to print: every control character becomes a visible ``\\xNN`` escape.

    Covers ESC (so no ANSI/OSC sequence survives), CR, NUL, DEL and the C1 range. Use it on
    server- or target-supplied data only; the app's own colour sequences must not pass through it.
    ``keep_lines`` leaves tab and newline (only) untouched for multi-line values.
    """
    pattern = _CONTROL_CHARS_KEEP_LINES if keep_lines else _CONTROL_CHARS
    return pattern.sub(lambda hit: f"\\x{ord(hit.group()):02x}", str(text))


REDACTED = "***"
_SECRET_WORDS = re.compile(
    r"cookie|auth|token|passw|secret|api[-_]?key|credential|bearer|session|csrf|xsrf",
    re.I,
)
_HEADER_PREFIX = re.compile(r"(?i)(?<![-a-z0-9_])([-a-z0-9_]+)([ \t]*:[ \t]*)")
_HEADER_LINE_END = re.compile(r"[\r\n]")
_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]*@")


def is_credential_name(name: str) -> bool:
    """True when an option or flag name says its value is a secret (cookie, token, password, ...)."""
    return bool(_SECRET_WORDS.search(name))


def redact_text(text: str) -> str:
    """Mask credential values in free text: secret header lines and ``user:pw@`` URL userinfo."""
    text = _USERINFO.sub(lambda hit: f"{hit.group(1)}{REDACTED}@", text)
    pieces: list[str] = []
    copied_to = 0
    for hit in _HEADER_PREFIX.finditer(text):
        if hit.start() < copied_to or not is_credential_name(hit.group(1)):
            continue
        line_end = _HEADER_LINE_END.search(text, hit.end())
        pieces.extend((text[copied_to : hit.end()], REDACTED))
        copied_to = line_end.start() if line_end else len(text)
    pieces.append(text[copied_to:])
    return "".join(pieces)


def redact_argv(argv: list[str]) -> list[str]:
    """Copy of a command line safe to echo: values of secret-named flags and secret-looking text are masked."""
    masked: list[str] = []
    hide_next = False
    for word in argv:
        if hide_next:
            masked.append(REDACTED)
            hide_next = False
        elif (
            word.startswith("-")
            and "=" in word
            and is_credential_name(word.split("=", 1)[0])
        ):
            masked.append(word.split("=", 1)[0] + "=" + REDACTED)
        elif word.startswith("-") and is_credential_name(word):
            safe_word = redact_text(word)
            masked.append(safe_word)
            hide_next = safe_word == word
        else:
            masked.append(redact_text(word))
    return masked


def say(message: str) -> None:
    """Print one diagnostic line to stderr and flush it."""
    print(message, file=sys.stderr, flush=True)


def show_banner(render: Callable[[bool], str]) -> None:
    """Print ``render(color)`` and a blank line to stderr, but only when stderr is a terminal."""
    if not stream_is_tty(sys.stderr):
        return
    print(render(color_enabled(sys.stderr)), file=sys.stderr)
    print(file=sys.stderr)


def open_output(plain: bool, render: Callable[[bool], str]) -> bool:
    """Show the banner unless ``plain``; say whether stdout may carry colour."""
    if not plain:
        show_banner(render)
    return stdout_color(plain)
