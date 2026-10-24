"""Where an engagement keeps its files, and which hosts it may talk to.

The workspace root is recomputed from the environment and the working directory on
every call, so the launcher and the tests may repoint it after import. Most of the
package imports this module, so it must never import another bughunt module.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import pathlib
import re
from collections.abc import Iterable
from urllib.parse import urlsplit

Entries = list[str]
_IPAddr = ipaddress.IPv4Address | ipaddress.IPv6Address

_ENV_OVERRIDE = "BUGHUNT_SCOPE"
_DEFAULT_DIRNAME = ".bughunt"
_SCOPE_FILE = "scope.txt"
_URLS_FILE = "urls.txt"

_BANNER = "".join(
    f"{line}\n"
    for line in (
        "# Scope for this engagement: bughunt only contacts the hosts named below.",
        "# Write one item per line -- a hostname, a domain, *.domain, an address or a CIDR range.",
        "# A bare domain covers itself and all of its subdomains; *.domain covers subdomains only.",
        "# Loopback addresses (localhost, 127.0.0.1, ::1) are always permitted and need no entry.",
        "#   shop.example.org",
        "#   *.cdn.example.org",
        "#   203.0.113.0/24",
    )
)

_BRACKETED_HOST = re.compile(r"\[([^\]]*)\](?::(.*))?", re.DOTALL)
_LOOPBACK_NAMES = frozenset({"localhost"})


def fold_host(raw: str) -> str:
    return raw.lower().rstrip(".")


def workspace_dir() -> pathlib.Path:
    chosen = (os.environ.get(_ENV_OVERRIDE) or "").strip()
    return (
        pathlib.Path(chosen).expanduser()
        if chosen
        else pathlib.Path.cwd() / _DEFAULT_DIRNAME
    )


def _inside(name: str) -> pathlib.Path:
    return workspace_dir() / name


def scope_path() -> pathlib.Path:
    return _inside(_SCOPE_FILE)


def urls_path() -> pathlib.Path:
    return _inside(_URLS_FILE)


def requests_dir() -> pathlib.Path:
    return _inside("requests")


def responses_dir() -> pathlib.Path:
    return _inside("responses")


def samples_dir() -> pathlib.Path:
    return _inside("samples")


def scope_is_active() -> bool:
    return scope_path().is_file()


def init_workspace() -> pathlib.Path:
    requests_dir().mkdir(parents=True, exist_ok=True)
    for location, starting_text in ((urls_path(), ""), (scope_path(), _BANNER)):
        if not location.exists():
            location.write_text(starting_text, encoding="utf-8")
    return workspace_dir()


def live_lines(text: str) -> Entries:
    """The lines of ``text`` that say something: stripped, without blank lines or ``#`` comments."""
    trimmed = (piece.strip() for piece in text.splitlines())
    return [piece for piece in trimmed if piece and not piece.startswith("#")]


def _read_text(location: pathlib.Path) -> str:
    return (
        location.read_text(encoding="utf-8", errors="replace")
        if location.is_file()
        else ""
    )


def read_workspace_text(name: str) -> str:
    """The text of the workspace file ``name``, or an empty string while it does not exist."""
    return _read_text(_inside(name))


def store_workspace_text(name: str, text: str | None) -> None:
    """Write ``text`` to the workspace file ``name``, creating the folder; ``None`` removes the file."""
    location = _inside(name)
    if text is None:
        location.unlink(missing_ok=True)
        return
    location.parent.mkdir(parents=True, exist_ok=True)
    location.write_text(text, encoding="utf-8")


def read_entries() -> Entries:
    return live_lines(_read_text(scope_path()))


def read_urls() -> Entries:
    return live_lines(_read_text(urls_path()))


def _store_entries(entries: Entries) -> None:
    listing = "".join(f"{entry}\n" for entry in entries)
    scope_path().write_text(_BANNER + listing, encoding="utf-8")


def normalize_entry(token: str) -> str:
    text = token.strip()
    if not text or re.search(r"\s", text):
        raise ValueError(f"{token!r} is not a host, domain or CIDR range")
    if "://" in text:
        url_host = urlsplit(text).hostname
        if not url_host:
            raise ValueError(f"{token!r} has no host part")
        return fold_host(url_host)
    if "/" in text:
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            raise ValueError(f"{token!r} is not a valid CIDR range") from None
    if text.startswith("[") and text.endswith("]"):
        parsed = ipaddress.IPv6Address(text[1:-1])
        return str(parsed)
    return fold_host(text)


def add_entries(tokens: Entries) -> tuple[Entries, Entries]:
    init_workspace()
    normalized = [normalize_entry(token) for token in tokens]
    stored = read_entries()
    seen = {entry.lower() for entry in stored}
    fresh: Entries = []
    repeats: Entries = []
    for value in normalized:
        (repeats if value.lower() in seen else fresh).append(value)
        seen.add(value.lower())
    _store_entries(stored + fresh)
    return fresh, repeats


def remove_entries(tokens: Entries) -> tuple[Entries, Entries]:
    if not scope_is_active():
        return [], [token.strip() for token in tokens if token.strip()]
    requested = [(token.strip(), normalize_entry(token).lower()) for token in tokens]
    targets = {canonical for _, canonical in requested}
    stored = read_entries()
    removed = [entry for entry in stored if entry.lower() in targets]
    survivors = [entry for entry in stored if entry.lower() not in targets]
    gone = {entry.lower() for entry in removed}
    missing = [original for original, canonical in requested if canonical not in gone]
    _store_entries(survivors)
    return removed, missing


def remember_urls(urls: Entries) -> int:
    if not scope_is_active():
        return 0
    init_workspace()
    already_saved = set(read_urls())
    additions = [url for url in dict.fromkeys(urls) if url not in already_saved]
    if additions:
        existing = urls_path().read_bytes()
        with urls_path().open("a", encoding="utf-8") as handle:
            if existing and not existing.endswith((b"\r", b"\n")):
                handle.write("\n")
            handle.writelines(f"{url}\n" for url in additions)
    return len(additions)


def save_request(name: str, data: bytes) -> pathlib.Path:
    if not scope_is_active():
        raise ValueError(
            "this workspace has no scope file yet; run `bughunt scope init` first"
        )
    leaf = pathlib.PurePath(name).name
    if not leaf or leaf in {".", ".."}:
        raise ValueError(f"{name!r} does not name a file")
    init_workspace()
    destination = requests_dir() / leaf
    destination.write_bytes(data)
    return destination


def split_host(value: str) -> tuple[str, str | None]:
    text = value.strip()
    if text.startswith("["):
        found = _BRACKETED_HOST.match(text)
        if found is None:
            return text, None
        return found.group(1), found.group(2) or None
    head, colon, tail = text.partition(":")
    if colon and ":" not in tail:
        return head, tail or None
    return text, None


def hostname_of(target: str) -> str:
    text = target.strip()
    extracted = (
        (urlsplit(text).hostname or "")
        if "://" in text
        else split_host(text.split("/", 1)[0])[0]
    )
    return fold_host(extracted)


def authority(host: str, port: int | None = None, *, omit: Iterable[int] = ()) -> str:
    """``host`` as a URL or Host header shows it: IPv6 literals bracketed, ``:port`` unless absent or in ``omit``."""
    shown = f"[{host}]" if ":" in host else host
    return shown if port is None or port in omit else f"{shown}:{port}"


def parse_ip(text: str) -> _IPAddr | None:
    with contextlib.suppress(ValueError):
        return ipaddress.ip_address(text)
    return None


def _parse_network(text: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if "/" in text:
        with contextlib.suppress(ValueError):
            return ipaddress.ip_network(text, strict=False)
    return None


def is_loopback(host: str) -> bool:
    candidate = fold_host(host)
    parsed = parse_ip(candidate)
    if parsed is None:
        return candidate in _LOOPBACK_NAMES
    return parsed.is_loopback


def _entry_covers(name: str, name_ip: _IPAddr | None, raw_entry: str) -> bool:
    entry = fold_host(raw_entry.strip())
    if not entry or entry[0] == "#":
        return False
    network = _parse_network(entry)
    if network is not None:
        return name_ip is not None and name_ip in network
    if name_ip is not None or parse_ip(entry) is not None:
        return name == entry
    if entry.startswith("*."):
        return name.endswith(entry[1:])
    return name == entry or name.endswith("." + entry)


def matches(host: str, entries: Entries) -> bool:
    name = fold_host(host)
    name_ip = parse_ip(name)
    return any(_entry_covers(name, name_ip, candidate) for candidate in entries)


def allowed(target: str) -> bool:
    name = hostname_of(target)
    if not name:
        return False
    if is_loopback(name):
        return True
    return scope_is_active() and matches(name, read_entries())


def explain_block(host: str) -> str:
    add_command = f"    bughunt scope add {host}"
    if scope_is_active():
        return f"{host} is outside this engagement's scope, so it was left alone.\n{add_command}"
    return (
        f"{host} was not contacted: there is no scope file for this workspace yet.\n"
        f"    bughunt scope init\n{add_command}"
    )


def explain_target(target: str) -> str:
    """The scope refusal for a URL or host argument, naming its hostname (the text itself when it has none)."""
    return explain_block(hostname_of(target) or target)
