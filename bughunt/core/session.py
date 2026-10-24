"""Request credentials for the actor in use.

The default actor keeps a Cookie and an Authorization value in session.txt inside the
workspace; any named actor keeps its own in its identity profile. Callers use this
module so they never have to care which of the two is active.
"""

from __future__ import annotations

import pathlib
import re

from bughunt.core import identity, workspace

# (key used in the dicts and in session.txt, HTTP header it travels as)
_CREDENTIAL_FIELDS = (("cookie", "Cookie"), ("authorization", "Authorization"))

_SAVED_FILENAME = "session.txt"
_SAVED_BANNER = "# Saved request credentials (cookie and authorization only)."
_SAVED_LINE = re.compile(r"(cookie|authorization)\s*:(.*)", re.IGNORECASE)


def _named_actor() -> str | None:
    """The selected actor's name, or None while the default actor is in use."""
    selected = identity.selected_name()
    return None if selected == "default" else selected


def _saved_file() -> pathlib.Path:
    return workspace.workspace_dir() / _SAVED_FILENAME


def session_path() -> pathlib.Path:
    actor = _named_actor()
    return _saved_file() if actor is None else identity._profile_path(actor)


def load_legacy_session() -> dict[str, str]:
    location = _saved_file()
    if not location.is_file():
        return {}
    text = location.read_text(encoding="utf-8", errors="replace")
    found: dict[str, str] = {}
    for line in text.splitlines():
        hit = _SAVED_LINE.match(line.strip())
        if hit and hit.group(2).strip():
            found[hit.group(1).lower()] = hit.group(2).strip()
    return found


def load_session() -> dict[str, str]:
    actor = _named_actor()
    if actor is None:
        return load_legacy_session()
    stored = identity.read_profile(actor).get("credentials") or {}
    return {
        key: stored[header] for key, header in _CREDENTIAL_FIELDS if header in stored
    }


def has_line_separator(value: str) -> bool:
    return any(mark in value for mark in "\r\n\v\f\x1c\x1d\x1e\x85\u2028\u2029")


def write_session(values: dict[str, str]) -> None:
    actor = _named_actor()
    lines = []
    for key, _header in _CREDENTIAL_FIELDS:
        value = values.get(key) or ""
        if not isinstance(value, str):
            raise identity.IdentityError("Invalid session header")
        value = value.strip()
        if has_line_separator(value):
            raise identity.IdentityError("Invalid session header")
        if value:
            lines.append(f"{key}: {value}")
    if actor is not None:
        identity.replace_session(actor, values)
        return
    location = _saved_file()
    if not lines:
        location.unlink(missing_ok=True)
        return
    location.parent.mkdir(parents=True, exist_ok=True)
    document = "\n".join([_SAVED_BANNER, "", *lines]) + "\n"
    location.write_text(document, encoding="utf-8")


def apply_headers(
    base_headers: dict[str, str], *, cookie: str | None, authorization: str | None
) -> dict[str, str]:
    saved = load_session() if cookie is None or authorization is None else {}
    explicit = {"cookie": cookie, "authorization": authorization}
    merged = dict(base_headers)
    for key, header in _CREDENTIAL_FIELDS:
        chosen = saved.get(key, "") if explicit[key] is None else explicit[key].strip()
        if chosen:
            merged[header] = chosen
        else:
            merged.pop(header, None)
    return merged
