"""Inspect supplied JWT claims without authenticating the token's signature."""

from __future__ import annotations

import argparse
import base64
import json
from datetime import datetime, timezone

from bughunt.core import banner, cli, identity, termio
from bughunt.core.session import load_session
from bughunt.modules import MODULES

_TOKEN_HELP = "Token with a header, payload, and signature."
_SESSION_HELP = "Decode the saved Authorization value. A positional token wins."

_ERR_SHAPE = "A token has three parts."
_ERR_DECODE = "The token could not be decoded."
_ERR_OBJECTS = "The token header and payload must be objects."
_ERR_NO_SAVED = "No Authorization value is saved."
_ERR_NO_TOKEN = "Give a token, or pass --session."

_NOTE_ALG_NONE = "review: algorithm is none"
_NOTE_NO_EXP = "review: no exp"
_NOTE_EXPIRED = "review: exp is in the past"
_NOTE_NOT_YET = "review: nbf is in the future"

_HEADER_LEADERS = ("alg", "typ")
_CLAIM_LEADERS = ("exp", "nbf", "iat", "iss", "sub", "aud")
_STAMP_KEYS = frozenset(("exp", "nbf", "iat"))
_SEAL_VERDICT = {True: "present, not checked", False: "absent"}


_MARK = "jwt"
_TAGLINE = "header and claims, with the signature left unchecked"
_ART_GLYPHS = (
    ".----.",
    "/  ()  \\",
    f"|  {_MARK}  |",
    "\\  ||  /",
    "'----'",
    "||",
    "[key]",
)
_SPINE_COLUMN = 13
_ART = tuple(
    " " * (_SPINE_COLUMN - (len(glyphs) + 1) // 2) + glyphs for glyphs in _ART_GLYPHS
)


def _fail(message: str) -> int:
    termio.say(message)
    return 2


def format_banner(color: bool) -> str:
    return banner.render_banner(_ART, _MARK, _TAGLINE, color)


def format_field(key: str, value: str, color: bool, *, dim: bool = False) -> str:
    return banner.format_pair(key, value, color, dim=dim)


def _moment(value: object) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(int(value), timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def _stamp(value: object) -> str | None:
    moment = _moment(value)
    return None if moment is None else moment.strftime(termio.UTC_STAMP)


_KIND_RENDERERS = (
    (list, lambda items: ", ".join(show_value("", item) for item in items)),
    (dict, lambda mapping: json.dumps(mapping, separators=(",", ":"))),
    (bool, lambda flag: "true" if flag else "false"),
)


def show_value(key: str, value: object) -> str:
    stamped = _stamp(value) if key in _STAMP_KEYS else None
    if stamped is not None:
        return stamped
    for kind, render in _KIND_RENDERERS:
        if isinstance(value, kind):
            return render(value)
    return str(value)


def _rows(fields: dict, leaders: tuple[str, ...]) -> list[tuple[str, str]]:
    slot = {name: position for position, name in enumerate(leaders)}
    ordered = sorted(fields, key=lambda name: slot.get(name, len(slot)))
    return [(str(name), show_value(name, fields[name])) for name in ordered]


def header_rows(header: dict) -> list[tuple[str, str]]:
    return _rows(header, _HEADER_LEADERS)


def claim_rows(payload: dict) -> list[tuple[str, str]]:
    return _rows(payload, _CLAIM_LEADERS)


def _report_lines(header: dict, payload: dict, signed: bool, tinted: bool) -> list[str]:
    fields = header_rows(header) + claim_rows(payload)
    lines = [
        format_field(termio.neutralize(key), termio.neutralize(shown), tinted)
        for key, shown in fields
    ]
    lines.append(format_field("signature", _SEAL_VERDICT[signed], tinted, dim=True))
    return lines


def _restore_padding(segment: str) -> str:
    quads = -(-len(segment) // 4)
    return segment.ljust(quads * 4, "=")


_SEGMENT_STAGES = (_restore_padding, base64.urlsafe_b64decode, json.loads)


def _decode_segment(segment: str) -> object:
    carried: object = segment
    for stage in _SEGMENT_STAGES:
        carried = stage(carried)
    return carried


def _split_token(token: str) -> tuple[str, str, str]:
    text = token.strip()
    head, _, rest = text.partition(".")
    body, second_dot, seal = rest.partition(".")
    if not (head and body and second_dot) or "." in seal or any(map(str.isspace, text)):
        raise ValueError(_ERR_SHAPE)
    return head, body, seal


def decode_token(token: str) -> tuple[dict, dict, bool]:
    head, body, seal = _split_token(token)
    try:
        header, payload = _decode_segment(head), _decode_segment(body)
    except (ValueError, RecursionError) as cause:
        raise ValueError(_ERR_DECODE) from cause
    if not (isinstance(header, dict) and isinstance(payload, dict)):
        raise ValueError(_ERR_OBJECTS)
    return header, payload, bool(seal)


def _claim_time(claims: dict, name: str) -> datetime | None:
    return _moment(claims.get(name))


def _alg_is_none(header: dict, payload: dict, now: datetime) -> bool:
    return str(header.get("alg", "")).strip().lower() == "none"


def _exp_absent(header: dict, payload: dict, now: datetime) -> bool:
    return "exp" not in payload


def _exp_elapsed(header: dict, payload: dict, now: datetime) -> bool:
    expiry = _claim_time(payload, "exp")
    return expiry is not None and expiry < now


def _nbf_ahead(header: dict, payload: dict, now: datetime) -> bool:
    start = _claim_time(payload, "nbf")
    return start is not None and start > now


_REVIEW_RULES = (
    (_alg_is_none, _NOTE_ALG_NONE),
    (_exp_absent, _NOTE_NO_EXP),
    (_exp_elapsed, _NOTE_EXPIRED),
    (_nbf_ahead, _NOTE_NOT_YET),
)


def review_notes(header: dict, payload: dict) -> list[str]:
    now = datetime.now(timezone.utc)
    return [note for applies, note in _REVIEW_RULES if applies(header, payload, now)]


def _saved_token() -> str:
    saved = load_session().get("authorization", "").strip()
    scheme, space, credentials = saved.partition(" ")
    return credentials.strip() if space and scheme.lower() == "bearer" else saved


def _pick_token(args: argparse.Namespace) -> str:
    return (args.token or "").strip() or (_saved_token() if args.session else "")


_OPTIONS = (
    (("token",), {"nargs": "?", "default": None, "help": _TOKEN_HELP}),
    (("--session",), {"action": "store_true", "help": _SESSION_HELP}),
    cli.PLAIN,
)


def build_parser() -> argparse.ArgumentParser:
    return cli.build_parser("bughunt jwt", MODULES["jwt"], _OPTIONS)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        token = _pick_token(args)
    except identity.IdentityError as problem:
        return _fail(str(problem))
    if not token:
        return _fail(_ERR_NO_SAVED if args.session else _ERR_NO_TOKEN)
    if not args.plain:
        termio.show_banner(format_banner)
    try:
        header, payload, signed = decode_token(token)
    except ValueError as problem:
        return _fail(str(problem))
    tinted = termio.stdout_color(args.plain)
    print(*_report_lines(header, payload, signed, tinted), sep="\n")
    for note in review_notes(header, payload):
        banner.note(note)
    return 0
