"""chromahaus - ask the abuse.ch community threat feeds about an indicator, from a terminal.

Subcommands (or the interactive prompt) query URLhaus, MalwareBazaar and ThreatFox for a URL,
host or IP, hash, tag or malware family, list the latest entries of each service, print the
Feodo Tracker and SSL blacklist feeds, poll URLhaus for new URLs, and (behind an explicit flag)
save a malware sample ZIP inside the workspace. Samples are never unpacked or run.

Every request goes through bughunt's policy-gated egress client (operation "passive") and is
limited to abuse.ch hosts, so the Auth-Key never leaves abuse.ch. This tool does NOT check the
engagement scope: the indicators you type are sent to abuse.ch as typed.

Global options may come before or after the subcommand. Exit codes: 0 ok, 1 runtime failure, 2 usage error
or no Auth-Key.
"""

from __future__ import annotations

import argparse
import colorsys
import csv
import json
import os
import re
import string
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

import httpx

try:
    from bughunt.core import ledger
    from bughunt.core.http import api_client, get_following
    from bughunt.core.workspace import samples_dir
except ImportError:  # started as a bare script from outside the repository
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from bughunt.core import ledger
    from bughunt.core.http import api_client, get_following
    from bughunt.core.workspace import samples_dir

# --------------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------------

VERSION_LINE = "CHROMAHAUS 1.1.0"
USER_AGENT = "chromahaus/1.1.0"
KEY_PORTAL = "https://auth.abuse.ch/"
API_HOSTS = frozenset({"abuse.ch"})
REQUEST_TIMEOUT_SECONDS = 45

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
FEODO_BLOCKLIST = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
SSLBL_BLOCKLIST = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
# Two more published abuse.ch lists, noted for reference only: no command requests them.

FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"
JSON_CONTENT_TYPE = "application/json"
ZIP_PASSWORD = "infected"
KEY_ENV_NAMES = ("ABUSECH_AUTH_KEY", "ABUSE_CH_KEY")

DEFAULT_COUNT = 25
URL_PAYLOAD_CAP = 25
HOST_URL_CAP = 40
PAYLOAD_URL_CAP = 20
TAG_URL_CAP = 30
BAZAAR_ROW_CAP = 40
THREATFOX_ROW_CAP = 50
YARA_RULE_CAP = 8
REPL_THREATFOX_LIMIT = 50
REPL_WATCH_POLL_SIZE = 50
REPL_WATCH_INTERVAL = 30
REPL_FEODO_CAP = 40
REPL_SSLBL_CAP = 30
WATCH_FLOOR_SECONDS = 15
MIN_SAMPLE_BYTES = 32
ERROR_SNIPPET_CHARS = 300

DASH = "-"
FIELD_LABEL_WIDTH = 12
RULE = "  " + "-" * 78

HTTP = None  # the cached egress client; built on first use by _http()
NO_COLOR = False  # set from --no-color at the start of every main() run


# --------------------------------------------------------------------------------------------
# Color and decoration
# --------------------------------------------------------------------------------------------

_RESET = "\x1b[0m"
_ROLE_CODES = {
    "title": "1;38;5;177",
    "accent": "1;38;5;219",
    "label": "38;5;245",
    "dim": "2;38;5;250",
    "good": "1;38;5;41",
    "caution": "1;38;5;214",
    "danger": "1;38;5;203",
    "chip": "38;5;81",
}

_BANNER_GLYPHS = {
    "C": (" ####", "#    ", "#    ", "#    ", " ####"),
    "H": ("#   #", "#   #", "#####", "#   #", "#   #"),
    "R": ("#### ", "#   #", "#### ", "#  # ", "#   #"),
    "O": (" ### ", "#   #", "#   #", "#   #", " ### "),
    "M": ("#   #", "## ##", "# # #", "#   #", "#   #"),
    "A": (" ### ", "#   #", "#####", "#   #", "#   #"),
    "U": ("#   #", "#   #", "#   #", "#   #", " ### "),
    "S": (" ####", "#    ", " ### ", "    #", "#### "),
}
_BANNER_WORD = "CHROMAHAUS"

_HOUSE_ART = (
    "        /\\",
    "       /  \\",
    "      /____\\",
    "      | [] |",
    "      |_||_|",
)


def colors_enabled() -> bool:
    """Color only for a terminal, and never when --no-color or the NO_COLOR variable asks otherwise."""
    if NO_COLOR or os.environ.get("NO_COLOR"):
        return False
    probe = getattr(sys.stdout, "isatty", None)
    return bool(probe and probe())


def paint(text: str, role: str) -> str:
    code = _ROLE_CODES.get(role)
    if code is None or not colors_enabled():
        return text
    return f"\x1b[{code}m{text}{_RESET}"


def rainbow(text: str, shift: int = 0) -> str:
    """Spread the spectrum over the characters of one line; plain text when color is off."""
    if not colors_enabled():
        return text
    pieces = []
    for position, character in enumerate(text):
        if character.isspace():
            pieces.append(character)
            continue
        red, green, blue = colorsys.hsv_to_rgb(
            ((position + shift * 3) % 30) / 30, 0.85, 1.0
        )
        cube_index = 16 + 36 * round(red * 5) + 6 * round(green * 5) + round(blue * 5)
        pieces.append(f"\x1b[38;5;{cube_index}m{character}")
    return "".join(pieces) + _RESET


def banner_rows() -> list[str]:
    return [
        " ".join(_BANNER_GLYPHS[letter][row] for letter in _BANNER_WORD)
        for row in range(5)
    ]


def print_banner() -> None:
    print()
    for shift, row in enumerate(banner_rows()):
        print("  " + rainbow(row, shift))
    print("  " + paint(f"{VERSION_LINE}  |  abuse.ch threat feeds, in color", "dim"))
    print()


def print_house() -> None:
    for shift, row in enumerate(_HOUSE_ART):
        print(rainbow(row, shift))


# --------------------------------------------------------------------------------------------
# Small value formatters
# --------------------------------------------------------------------------------------------


def present(value) -> bool:
    return value is not None and value != "" and value != [] and value != {}


def text_or_dash(value) -> str:
    return str(value) if present(value) else DASH


def shorten(value, width: int) -> str:
    text = text_or_dash(value)
    return text if len(text) <= width else text[: width - 3] + "..."


def head(value, count: int) -> str:
    text = text_or_dash(value)
    return text if len(text) <= count else text[:count] + "..."


def stamp(value) -> str:
    """Show a timestamp as 'YYYY-MM-DD HH:MM:SS UTC'."""
    if not present(value):
        return DASH
    text = str(value).strip()
    already_labelled = text.endswith("UTC")
    text = re.sub(r"(?<=\d)T(?=\d)", " ", text)
    return text if already_labelled else f"{text} UTC"


def tag_chips(value) -> str:
    if isinstance(value, str):
        names = [piece.strip() for piece in value.split(",")]
    elif isinstance(value, (list, tuple)):
        names = [str(piece).strip() for piece in value]
    else:
        names = []
    names = [name for name in names if name]
    return " ".join(paint(f"#{name}", "chip") for name in names) if names else DASH


def status_role(label: str) -> str:
    return {"ONLINE": "good", "OFFLINE": "danger"}.get(label, "caution")


def render_status(value) -> str:
    label = str(value).upper() if present(value) else "?"
    return paint(label, status_role(label))


def dict_rows(value) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    return []


def data_rows(payload):
    """The `data` rows of a Bazaar/ThreatFox answer, as exported (a lone object is wrapped)."""
    data = payload.get("data") if isinstance(payload, dict) else None
    return dict_rows(data)


# --------------------------------------------------------------------------------------------
# Indicator classification
# --------------------------------------------------------------------------------------------

_HEX_DIGITS = frozenset(string.hexdigits)
_ASCII_DIGITS = frozenset(string.digits)
_LABEL_CHARACTERS = frozenset(string.ascii_letters + string.digits + "-")
_DIGEST_LENGTHS = (32, 40, 64)


def _made_of(text: str, alphabet) -> bool:
    return bool(text) and all(character in alphabet for character in text)


def _is_ipv4_endpoint(text: str) -> bool:
    """Dotted quad of 1-3 digit groups with an optional :port of up to five digits (no range check)."""
    address, colon, port = text.partition(":")
    groups = address.split(".")
    if len(groups) != 4 or not all(
        1 <= len(group) <= 3 and _made_of(group, _ASCII_DIGITS) for group in groups
    ):
        return False
    return not colon or (1 <= len(port) <= 5 and _made_of(port, _ASCII_DIGITS))


def _is_hostname_label(label: str) -> bool:
    return (
        1 <= len(label) <= 63
        and _made_of(label, _LABEL_CHARACTERS)
        and label[0] != "-"
        and label[-1] != "-"
    )


def _is_hostname(text: str) -> bool:
    name = text[:-1] if text.endswith(".") else text
    labels = name.split(".")
    return (
        1 <= len(name) <= 253
        and len(labels) >= 2
        and all(_is_hostname_label(label) for label in labels)
    )


def classify(indicator: str) -> str:
    """Name what an indicator looks like: url, hash, ip, host, or (anything else) term."""
    text = indicator.strip()
    if text.lower().startswith(("http://", "https://")):
        return "url"
    if len(text) in _DIGEST_LENGTHS and _made_of(text, _HEX_DIGITS):
        return "hash"
    if _is_ipv4_endpoint(text):
        return "ip"
    if _is_hostname(text):
        return "host"
    return "term"


# --------------------------------------------------------------------------------------------
# Auth-Key
# --------------------------------------------------------------------------------------------


def _key_file_candidates() -> list[Path]:
    try:
        home = Path.home()
    except RuntimeError:
        return [Path(".chromahaus.key")]
    return [
        home / ".config" / "chromahaus" / "auth.key",
        home / ".chromahaus.key",
        Path(".chromahaus.key"),
    ]


def resolve_key(explicit):
    """--key, then the two environment variables, then the first non-blank key file."""
    for candidate in (explicit, *(os.environ.get(name) for name in KEY_ENV_NAMES)):
        if candidate and candidate.strip():
            return candidate.strip()
    for path in _key_file_candidates():
        try:
            text = path.read_text(encoding="utf-8").strip()
        except (OSError, ValueError):
            continue
        if text:
            return text
    return None


KEY_HELP = f"""\
  chromahaus needs a free abuse.ch Auth-Key.  Get one at {KEY_PORTAL}
  then hand it over in any one of these ways:
    --key KEY                         (a global option: put it before the subcommand)
    ABUSECH_AUTH_KEY=KEY              (or ABUSE_CH_KEY=KEY) in the environment
    a file holding only the key:      ~/.config/chromahaus/auth.key,
                                      ~/.chromahaus.key or ./.chromahaus.key"""


# --------------------------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------------------------


def _http():
    """The egress client for abuse.ch, built once and reused."""
    global HTTP
    if HTTP is None:
        HTTP = api_client(API_HOSTS, timeout=REQUEST_TIMEOUT_SECONDS)
    return HTTP


def _exchange(
    method: str,
    url: str,
    key: str,
    *,
    content: bytes | None = None,
    content_type: str | None = None,
):
    """Send one request; transport, policy and host-guard failures become RuntimeError."""
    ledger.remember_secret(key, redact_at_rest=True)
    headers = {"Accept": "*/*", "User-Agent": USER_AGENT, "Auth-Key": key}
    if content_type:
        headers["Content-Type"] = content_type
    client = _http()
    try:
        if method == "GET":
            return get_following(client, url, headers=headers)
        return client.post(url, content=content, headers=headers)
    except httpx.HTTPError as failure:
        raise RuntimeError(f"network error talking to {url}: {failure}") from failure


def _complain_about_status(response, url: str) -> None:
    status = response.status_code
    if status == 401:
        raise RuntimeError(
            f"401 unauthorized from {url} - check your Auth-Key (get one at {KEY_PORTAL})"
        )
    if status == 429:
        raise RuntimeError("429 rate limited by abuse.ch - wait a bit and try again")
    if status >= 400:
        snippet = " ".join(response.text[:ERROR_SNIPPET_CHARS].splitlines())
        raise RuntimeError(f"HTTP {status} from {url} - {snippet}")


def _decode_answer(response):
    text = response.text
    looks_like_json = "application/json" in response.headers.get("content-type", "")
    if looks_like_json or not text.strip() or text.lstrip().startswith(("{", "[")):
        try:
            return json.loads(text)
        except ValueError:
            return {"_raw": text, "query_status": "parse_error"}
    return {"_raw": text, "query_status": "ok"}


def api_json(url: str, key: str, *, form: dict | None = None, body: dict | None = None):
    """GET (no payload), POST a form, or POST a JSON body; return the decoded answer."""
    if form is not None:
        encoded = urlencode(
            {name: value for name, value in form.items() if value is not None}
        ).encode("utf-8")
        response = _exchange(
            "POST", url, key, content=encoded, content_type=FORM_CONTENT_TYPE
        )
    elif body is not None:
        response = _exchange(
            "POST",
            url,
            key,
            content=json.dumps(body).encode("utf-8"),
            content_type=JSON_CONTENT_TYPE,
        )
    else:
        response = _exchange("GET", url, key)
    _complain_about_status(response, url)
    return _decode_answer(response)


def fetch_text_list(url: str, key: str) -> str:
    """Download a plain-text feed (with the Auth-Key header) and return its text."""
    response = _exchange("GET", url, key)
    if response.status_code == 401:
        raise RuntimeError(f"401 unauthorized fetching {url}")
    if response.status_code >= 400:
        raise RuntimeError(f"HTTP {response.status_code} fetching {url}")
    return response.text


# --------------------------------------------------------------------------------------------
# Views: turning an answer into text
# --------------------------------------------------------------------------------------------

BAZAAR_OK = ("ok", "success")

_RENDERERS = {
    "text": text_or_dash,
    "asis": str,  # shown exactly as received, even when missing
    "stamp": stamp,
    "tags": tag_chips,
    "status": render_status,
    "label": lambda value: str(value) if present(value) else "unlabeled",
    "ssdeep": lambda value: shorten(value, 60),
}

URL_DETAIL_FIELDS = (
    ("id", "id", "text"),
    ("url", "url", "text"),
    ("status", "url_status", "status"),
    ("host", "host", "text"),
    ("threat", "threat", "text"),
    ("added", "date_added", "stamp"),
    ("last online", "last_online", "stamp"),
    ("reporter", "reporter", "text"),
    ("larted", "larted", "text"),
    ("tags", "tags", "tags"),
    ("reference", "urlhaus_reference", "text"),
)
HOST_FIELDS = (
    ("host", "host", "text"),
    ("first seen", "firstseen", "stamp"),
    ("urls", "url_count", "text"),
    ("reference", "urlhaus_reference", "text"),
)
PAYLOAD_FIELDS = (
    ("md5", "md5_hash", "text"),
    ("sha256", "sha256_hash", "text"),
    ("type", "file_type", "text"),
    ("size", "file_size", "text"),
    ("signature", "signature", "label"),
    ("first seen", "firstseen", "stamp"),
    ("imphash", "imphash", "text"),
    ("ssdeep", "ssdeep", "ssdeep"),
    ("tlsh", "tlsh", "text"),
    ("magika", "magika", "text"),
)
BAZAAR_INFO_FIELDS = (
    ("sha256", "sha256_hash", "text"),
    ("sha1", "sha1_hash", "text"),
    ("md5", "md5_hash", "text"),
    ("signature", "signature", "label"),
    ("type", "file_type", "text"),
    ("mime", "file_type_mime", "text"),
    ("size", "file_size", "text"),
    ("first seen", "first_seen", "stamp"),
    ("last seen", "last_seen", "stamp"),
    ("delivery", "delivery_method", "text"),
    ("origin", "origin_country", "text"),
    ("reporter", "reporter", "text"),
    ("tags", "tags", "tags"),
)


def print_field(label: str, rendered: str) -> None:
    print(f"  {paint(label.ljust(FIELD_LABEL_WIDTH), 'label')} {rendered}")


def print_fields(record: dict, specs) -> None:
    for label, key, kind in specs:
        print_field(label, _RENDERERS[kind](record.get(key)))


def status_gate(payload, accepted=("ok",)) -> bool:
    """True when the answer carries data; otherwise print why not (no hit, or the odd status)."""
    status = payload.get("query_status") if isinstance(payload, dict) else None
    if status in accepted:
        return True
    if status == "no_results":
        print("  " + paint("no hit", "dim"))
    else:
        print(f"  status: {text_or_dash(status)}")
    return False


def print_url_rows(rows, cap=None, tail=False) -> None:
    rows = dict_rows(rows)
    shown = rows[:cap] if cap and cap > 0 else rows
    for number, row in enumerate(shown, start=1):
        label = str(row.get("url_status") or row.get("status") or "?").upper()
        badge = paint(f"{label:<8}", status_role(label))
        print(f"  {number:>3}  {badge} {shorten(row.get('url'), 70)}")
        when = stamp(row.get("date_added") or row.get("firstseen"))
        print(
            f"       {when}  {shorten(row.get('threat'), 24)}  {shorten(row.get('host'), 40)}  "
            f"{tag_chips(row.get('tags'))}"
        )
    if tail and len(rows) > len(shown):
        print(f"  ... {len(rows) - len(shown)} more")


def print_blacklists(record: dict) -> None:
    listings = record.get("blacklists")
    if isinstance(listings, dict) and listings:
        print_field("spamhaus dbl", text_or_dash(listings.get("spamhaus_dbl")))
        print_field("surbl", text_or_dash(listings.get("surbl")))


def view_url_list(payload, cap) -> None:
    if status_gate(payload):
        print_url_rows(payload.get("urls"), cap)


def view_url_detail(payload) -> None:
    if not status_gate(payload):
        return
    print_fields(payload, URL_DETAIL_FIELDS)
    print_blacklists(payload)
    entries = dict_rows(payload.get("payloads"))
    if entries:
        print("  " + paint("payloads", "label"))
    for entry in entries[:URL_PAYLOAD_CAP]:
        digest = entry.get("response_sha256") or entry.get("sha256_hash")
        print(
            f"    {shorten(entry.get('signature') or 'unlabeled', 24):<24} {shorten(entry.get('file_type'), 8):<8} "
            f"{head(digest, 16)}  {stamp(entry.get('firstseen'))}"
        )


def view_host_detail(payload) -> None:
    if not status_gate(payload):
        return
    print_fields(payload, HOST_FIELDS)
    print_blacklists(payload)
    print_url_rows(payload.get("urls"), HOST_URL_CAP, tail=True)


def view_url_collection(payload, name_key: str) -> None:
    """URLhaus tag and signature answers: the name, first-seen, count, then the URLs."""
    if not status_gate(payload):
        return
    print_field(name_key, text_or_dash(payload.get(name_key)))
    print_field("first seen", stamp(payload.get("firstseen")))
    print_field("urls", text_or_dash(payload.get("url_count")))
    print_url_rows(payload.get("urls"), TAG_URL_CAP)


def view_payload_detail(payload) -> None:
    if not status_gate(payload):
        return
    print_fields(payload, PAYLOAD_FIELDS)
    scan = payload.get("virustotal")
    if isinstance(scan, dict):
        print_field(
            "virustotal",
            f"{text_or_dash(scan.get('result'))} ({text_or_dash(scan.get('percent'))}%)",
        )
    print_url_rows(payload.get("urls"), PAYLOAD_URL_CAP)


def view_payload_list(payload, cap) -> None:
    if not status_gate(payload):
        return
    rows = dict_rows(payload.get("payloads"))
    for number, row in enumerate(rows[:cap] if cap > 0 else rows, start=1):
        print(
            f"  {number:>3}  {shorten(row.get('signature') or 'unlabeled', 20):<20} "
            f"{shorten(row.get('file_type'), 8):<8} {head(row.get('sha256_hash'), 18)}  {stamp(row.get('firstseen'))}"
        )


def view_bazaar_list(payload) -> None:
    if not status_gate(payload, BAZAAR_OK):
        return
    for number, row in enumerate(
        dict_rows(payload.get("data"))[:BAZAAR_ROW_CAP], start=1
    ):
        signature = row.get("signature") or row.get("malware") or "unlabeled"
        kind = row.get("file_type") or row.get("file_type_mime")
        first_seen = row.get("first_seen") or row.get("firstseen")
        print(
            f"  {number:>3}  {shorten(signature, 22):<22} {shorten(kind, 10):<10} "
            f"{head(row.get('sha256_hash'), 16)}  {stamp(first_seen)}  {tag_chips(row.get('tags'))}"
        )


def _yara_names(row: dict) -> list[str]:
    rules = row.get("yara_rules") or row.get("yara") or []
    names = []
    for rule in rules if isinstance(rules, list) else []:
        name = (
            (rule.get("rule_name") or rule.get("rule"))
            if isinstance(rule, dict)
            else rule
        )
        if present(name):
            names.append(str(name))
    return names[:YARA_RULE_CAP]


def view_bazaar_info(payload) -> None:
    rows = dict_rows(payload.get("data")) if isinstance(payload, dict) else []
    if not status_gate(payload, BAZAAR_OK) or not rows:
        return
    sample = rows[0]
    print_fields(sample, BAZAAR_INFO_FIELDS)
    intelligence = sample.get("intelligence")
    if isinstance(intelligence, dict):
        for name in ("downloads", "uploads", "clamav"):
            print_field(name, text_or_dash(intelligence.get(name)))
    yara = _yara_names(sample)
    if yara:
        print_field("yara", ", ".join(yara))
    if present(sample.get("sha256_hash")):
        print_field(
            "sample page", f"https://bazaar.abuse.ch/sample/{sample['sha256_hash']}/"
        )


def confidence_percent(row: dict) -> int:
    try:
        return int(row.get("confidence_level"))
    except (TypeError, ValueError):
        return 0


def view_threatfox_list(payload) -> None:
    if not status_gate(payload):
        return
    for row in dict_rows(payload.get("data"))[:THREATFOX_ROW_CAP]:
        percent = confidence_percent(row)
        role = "good" if percent >= 90 else "caution" if percent >= 50 else "danger"
        family = row.get("malware") or row.get("malware_printable") or "?"
        kind = row.get("ioc_type") or row.get("threat_type")
        print(
            f"  {paint(f'{percent:>3}%', role)}  {shorten(family, 18):<18}  {shorten(kind, 14):<14}  "
            f"{shorten(row.get('ioc'), 48)}"
        )


def show_feodo(text: str, cap: int) -> None:
    entries = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    print()
    print(
        "  "
        + paint(f"Feodo Tracker - {len(entries)} C2 addresses", "title")
        + "  (the list can be empty after botnet takedowns)"
    )
    shown = entries[:cap] if cap > 0 else entries
    for entry in shown:
        print(f"  {entry}")
    if len(entries) > len(shown):
        print(f"  ... {len(entries) - len(shown)} more")


def show_sslbl(text: str, cap: int) -> None:
    rows = [
        row
        for row in csv.reader(text.splitlines())
        if row and not row[0].lstrip().startswith("#")
    ]
    print()
    print("  " + paint(f"SSL blacklist - {len(rows)} entries", "title"))
    shown = rows[:cap] if cap > 0 else rows
    for row in shown:
        print("  " + "  ".join(row[:4]))
    if len(rows) > len(shown):
        print(f"  ... {len(rows) - len(shown)} more")


# --------------------------------------------------------------------------------------------
# Feeds: one request plus its display
# --------------------------------------------------------------------------------------------


class Settings:
    """Per-run options shared by every command."""

    def __init__(
        self,
        key: str,
        raw: bool = False,
        limit: int = DEFAULT_COUNT,
        *,
        structured: bool = False,
    ):
        self.key = key
        self.raw = raw
        self.limit = limit
        self.structured = structured
        self.responses = []


def run_feed(settings: Settings, title: str, fetch, view):
    """Fetch one answer, then print it raw (--json) or through `view` under a heading."""
    payload = fetch()
    if settings.structured:
        settings.responses.append({"source": title, "payload": payload})
        return payload
    if settings.raw:
        print(json.dumps(payload, default=str))
    else:
        print()
        print("  " + paint(title, "title"))
        view(payload)
    return payload


def _recent_path(kind: str, count: int) -> str:
    suffix = f"limit/{count}/" if count != 0 else ""
    return f"{URLHAUS_API}/{kind}/recent/{suffix}"


def _urlhaus(settings: Settings, endpoint: str, **fields):
    return api_json(f"{URLHAUS_API}/{endpoint}/", settings.key, form=fields)


def _bazaar(settings: Settings, query: str, **fields):
    return api_json(BAZAAR_API, settings.key, form={"query": query, **fields})


def _threatfox(settings: Settings, query: str, **fields):
    return api_json(THREATFOX_API, settings.key, body={"query": query, **fields})


def _digest_field(value: str) -> dict:
    digest = value.strip().lower()
    return {"md5_hash" if len(digest) == 32 else "sha256_hash": digest}


def feed_recent_urls(s: Settings, count: int):
    return run_feed(
        s,
        "URLhaus - recent URLs",
        lambda: api_json(_recent_path("urls", count), s.key),
        lambda payload: view_url_list(payload, count),
    )


def feed_recent_payloads(s: Settings, count: int):
    return run_feed(
        s,
        "URLhaus - recent payloads",
        lambda: api_json(_recent_path("payloads", count), s.key),
        lambda payload: view_payload_list(payload, count),
    )


def feed_url(s: Settings, value: str):
    return run_feed(
        s, "URLhaus - URL", lambda: _urlhaus(s, "url", url=value), view_url_detail
    )


def feed_host(s: Settings, value: str):
    return run_feed(
        s, "URLhaus - host", lambda: _urlhaus(s, "host", host=value), view_host_detail
    )


def feed_payload(s: Settings, value: str):
    return run_feed(
        s,
        "URLhaus - payload",
        lambda: _urlhaus(s, "payload", **_digest_field(value)),
        view_payload_detail,
    )


def feed_urlhaus_tag(s: Settings, value: str):
    return run_feed(
        s,
        "URLhaus - tag",
        lambda: _urlhaus(s, "tag", tag=value),
        lambda payload: view_url_collection(payload, "tag"),
    )


def feed_urlhaus_signature(s: Settings, value: str):
    return run_feed(
        s,
        "URLhaus - signature",
        lambda: _urlhaus(s, "signature", signature=value),
        lambda payload: view_url_collection(payload, "signature"),
    )


def feed_bazaar_info(s: Settings, value: str):
    return run_feed(
        s,
        "MalwareBazaar - sample",
        lambda: _bazaar(s, "get_info", hash=value),
        view_bazaar_info,
    )


def feed_bazaar_tag(s: Settings, value: str, limit: int):
    return run_feed(
        s,
        "MalwareBazaar - tag",
        lambda: _bazaar(s, "get_taginfo", tag=value, limit=limit),
        view_bazaar_list,
    )


def feed_bazaar_signature(s: Settings, value: str, limit: int):
    return run_feed(
        s,
        "MalwareBazaar - signature",
        lambda: _bazaar(s, "get_siginfo", signature=value, limit=limit),
        view_bazaar_list,
    )


def feed_bazaar_recent(s: Settings, count: int):
    return run_feed(
        s,
        "MalwareBazaar - recent samples",
        lambda: _bazaar(s, "get_recent", selector=count),
        view_bazaar_list,
    )


def feed_threatfox_hash(s: Settings, value: str):
    return run_feed(
        s,
        "ThreatFox - hash",
        lambda: _threatfox(s, "search_hash", hash=value),
        view_threatfox_list,
    )


def feed_threatfox_malware(s: Settings, value: str, limit: int):
    return run_feed(
        s,
        "ThreatFox - malware family",
        lambda: _threatfox(s, "malwareinfo", malware=value, limit=limit),
        view_threatfox_list,
    )


def feed_threatfox_ioc(s: Settings, term: str):
    return run_feed(
        s,
        "ThreatFox - indicator",
        lambda: _threatfox(s, "search_ioc", search_term=term),
        view_threatfox_list,
    )


def feed_threatfox_recent(s: Settings, days: int):
    return run_feed(
        s,
        "ThreatFox - recent indicators",
        lambda: _threatfox(s, "get_iocs", days=days),
        view_threatfox_list,
    )


# --------------------------------------------------------------------------------------------
# Commands: compositions of feeds. Each returns the rows `--out` / `export` may save (or None).
# --------------------------------------------------------------------------------------------


def command_recent(s: Settings, count: int):
    payload = feed_recent_urls(s, count)
    return (payload.get("urls") or []) if isinstance(payload, dict) else []


def command_payloads(s: Settings, count: int):
    payload = feed_recent_payloads(s, count)
    return (payload.get("payloads") or []) if isinstance(payload, dict) else []


def command_url(s: Settings, value: str):
    return [feed_url(s, value)]


def command_host(s: Settings, value: str):
    payload = feed_host(s, value)
    return (payload.get("urls") if isinstance(payload, dict) else None) or [payload]


def command_hash(s: Settings, value: str):
    feed_payload(s, value)
    feed_bazaar_info(s, value)
    feed_threatfox_hash(s, value)


def command_tag(s: Settings, value: str, bazaar_limit: int):
    urlhaus = feed_urlhaus_tag(s, value)
    urls = dict_rows(urlhaus.get("urls")) if isinstance(urlhaus, dict) else []
    return urls + data_rows(feed_bazaar_tag(s, value, bazaar_limit))


def command_family(s: Settings, value: str, threatfox_limit: int, bazaar_limit: int):
    feed_urlhaus_signature(s, value)
    feed_threatfox_malware(s, value, threatfox_limit)
    feed_bazaar_signature(s, value, bazaar_limit)


def command_iocs(s: Settings, days: int):
    return data_rows(feed_threatfox_recent(s, max(1, min(7, days))))


def command_fox(s: Settings, term: str):
    return data_rows(feed_threatfox_ioc(s, term))


def command_bazaar(s: Settings, count: int):
    return data_rows(feed_bazaar_recent(s, count))


def command_feodo(s: Settings, cap: int):
    text = fetch_text_list(FEODO_BLOCKLIST, s.key)
    if s.structured:
        return {"source": "Feodo", "text": text}
    show_feodo(text, cap)


def command_sslbl(s: Settings, cap: int):
    text = fetch_text_list(SSLBL_BLOCKLIST, s.key)
    if s.structured:
        return {"source": "SSLBL", "text": text}
    show_sslbl(text, cap)


def _hunt_url(s: Settings, value: str) -> None:
    feed_url(s, value)
    feed_threatfox_ioc(s, value)


def _hunt_address(s: Settings, value: str) -> None:
    feed_host(s, value.partition(":")[0])
    feed_threatfox_ioc(s, value)


def _hunt_term(s: Settings, value: str) -> None:
    feed_urlhaus_tag(s, value)
    feed_threatfox_ioc(s, value)
    feed_bazaar_tag(s, value, DEFAULT_COUNT)


_HUNT_PLANS = {
    "url": _hunt_url,
    "hash": command_hash,
    "ip": _hunt_address,
    "host": _hunt_address,
    "term": _hunt_term,
}


def run_hunt(s: Settings, indicator: str) -> None:
    """Work out what the indicator is and ask every feed that can know about that kind of thing."""
    kind = classify(indicator)
    if not s.raw and not s.structured:
        print()
        print(f"  {paint('hunt', 'title')} {paint(indicator, 'accent')}  ({kind})")
        print(RULE)
    _HUNT_PLANS[kind](s, indicator)


# --------------------------------------------------------------------------------------------
# watch
# --------------------------------------------------------------------------------------------


def _item_identity(item: dict):
    return item.get("id") if present(item.get("id")) else item.get("url")


def _watch_poll(s: Settings, poll_size: int, seen: set, primed: bool):
    payload = api_json(_recent_path("urls", poll_size), s.key)
    items = dict_rows(payload.get("urls")) if isinstance(payload, dict) else []
    fresh = [item for item in items if _item_identity(item) not in seen]
    seen.update(_item_identity(item) for item in items)
    if s.structured:
        return {
            "primed": not primed,
            "records": fresh if primed else [],
            "observed": len(items),
        }
    clock = paint(f"[{datetime.now(timezone.utc).strftime('%H:%M:%S')}]", "dim")
    if not primed:
        print(f"  {clock} primed with {len(items)} URLs")
    elif fresh:
        print(f"  {clock} +{len(fresh)} new")
        print_url_rows(fresh)
    else:
        print(f"  {clock} quiet")


def run_watch(s: Settings, interval: int, poll_size: int, polls: int | None = None):
    """Poll URLhaus for recent URLs forever, listing only the ones not seen before. Ctrl-C stops it."""
    from bughunt.core.addon_adapters import wait_for_poll

    pause = max(WATCH_FLOOR_SECONDS, interval)
    if polls is not None and polls < 1:
        raise ValueError("--polls must be positive")
    if s.structured:
        observations, seen = [], set()
        for index in range(polls):
            observations.append(_watch_poll(s, poll_size, seen, index > 0))
            if index + 1 < polls:
                wait_for_poll(pause)
        return observations
    print()
    print(
        f"  {paint('watch', 'title')} URLhaus recent URLs every {interval}s, poll size {poll_size} "
        "(Ctrl-C to stop)"
    )
    seen: set = set()
    primed = False
    try:
        while True:
            _watch_poll(s, poll_size, seen, primed)
            primed = True
            if polls is not None:
                polls -= 1
                if polls == 0:
                    break
            sys.stdout.flush()
            time.sleep(pause)
    except KeyboardInterrupt:
        print()
        print("  watch stopped")


# --------------------------------------------------------------------------------------------
# download
# --------------------------------------------------------------------------------------------

DOWNLOAD_WARNING = f"""
  *** LIVE MALWARE ***
  The sample you are asking for is real malware.  It is saved as a ZIP archive
  (archive password: {ZIP_PASSWORD}) and is never unpacked or executed by this tool.
  Handle it only inside an isolated analysis environment."""

DOWNLOAD_REFUSAL = "download refused: add --i-understand to confirm you want to save a live malware sample"


def normalize_digest(value: str) -> str:
    digest = value.strip().lower()
    if len(digest) != 64 or not _made_of(digest, string.hexdigits):
        raise SystemExit("need a SHA256 digest (64 hex characters)")
    return digest


def resolve_destination(dest: str) -> Path:
    """`dest` names a sub-folder of <workspace>/samples; anything that leaves that folder is refused."""
    root = samples_dir().resolve()
    requested = Path(dest or ".")
    if requested.is_absolute():
        raise SystemExit(
            "--dest must be a sub-folder of the workspace samples directory, not an absolute path"
        )
    folder = (root / requested).resolve()
    if folder != root and root not in folder.parents:
        raise SystemExit("--dest must stay inside the workspace samples directory")
    return folder


def _fetch_sample(key: str, digest: str, *, notify: bool = True) -> bytes:
    response = _exchange("GET", f"{URLHAUS_API}/download/{digest}/", key)
    if response.status_code >= 400 or len(response.content) < MIN_SAMPLE_BYTES:
        if notify:
            print("  URLhaus had no usable copy; trying MalwareBazaar instead")
        form = urlencode({"query": "get_file", "sha256_hash": digest}).encode("utf-8")
        response = _exchange(
            "POST", BAZAAR_API, key, content=form, content_type=FORM_CONTENT_TYPE
        )
    if response.status_code >= 400:
        raise SystemExit(f"download failed HTTP {response.status_code}")
    blob = response.content
    if blob[:1] == b"{":
        try:
            reply = json.loads(blob)
        except ValueError:
            return blob
        raise SystemExit(f"API said: {reply!r}")
    return blob


def cmd_download(
    key: str, sha256: str, dest: str, i_understand: bool, *, structured: bool = False
):
    """Save a sample ZIP under <workspace>/samples/<dest>/. Every refusal is a SystemExit."""
    digest = normalize_digest(sha256)
    if not structured:
        print(DOWNLOAD_WARNING)
    if not i_understand:
        raise SystemExit(DOWNLOAD_REFUSAL)
    folder = resolve_destination(dest)
    folder.mkdir(parents=True, exist_ok=True)
    blob = (
        _fetch_sample(key, digest, notify=not structured)
        if structured
        else _fetch_sample(key, digest)
    )
    archive = folder / f"{digest}.zip"
    archive.write_bytes(blob)
    if structured:
        return {
            "sha256": digest,
            "bytes": len(blob),
            "saved": True,
            "media_type": "application/zip",
        }
    print(f"  saved {len(blob)} bytes -> {archive}  (zip password: {ZIP_PASSWORD})")


# --------------------------------------------------------------------------------------------
# Export
# --------------------------------------------------------------------------------------------


def _csv_cell(value):
    return (
        json.dumps(value, ensure_ascii=False, default=str)
        if isinstance(value, (list, dict))
        else value
    )


def _write_json_rows(rows, target: Path) -> None:
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(rows, indent=2, default=str, ensure_ascii=False) + "\n")


def _write_csv_rows(rows, target: Path) -> None:
    with target.open("w", encoding="utf-8", newline="") as handle:
        columns: list = []
        for row in rows:
            columns.extend(column for column in row if column not in columns)
        writer = csv.writer(handle)
        writer.writerow(columns)
        for row in rows:
            writer.writerow([_csv_cell(row.get(column)) for column in columns])


def export_rows(rows, destination: str) -> None:
    """Save rows as a JSON array (name ends in .json, any case) or as CSV (anything else)."""
    target = Path(destination)
    if target.suffix.lower() == ".json":
        _write_json_rows(rows, target)
    else:
        _write_csv_rows(rows, target)
    print(f"  wrote {len(rows)} rows -> {destination}", file=sys.stderr)


# --------------------------------------------------------------------------------------------
# Interactive prompt
# --------------------------------------------------------------------------------------------

REPL_HELP = """\
  hunt <indicator>      detect what it is and ask every relevant feed
  url <url>             URLhaus URL lookup            host <host|ip>   URLhaus host lookup
  hash <digest>         md5 or sha256 across URLhaus, MalwareBazaar and ThreatFox (same as hunt)
  tag <tag>             URLhaus and MalwareBazaar     family <name>    signature across all three
  recent [n]            latest URLhaus URLs           payloads [n]     latest URLhaus payloads
  bazaar [n]            latest MalwareBazaar samples  iocs [days]      ThreatFox IOCs, 1-7 days
  fox <term>            ThreatFox IOC search          feodo / sslbl    the two blocklists
  watch [seconds]       follow new URLhaus URLs (Ctrl-C returns here)
  download <sha256>     explains the safety flag; use the one-shot subcommand to fetch
  export <file>         save the last url/host/recent/payloads/iocs/fox/bazaar rows (.json or CSV)
  raw                   switch raw JSON output on or off
  help | ?              this list          quit | q | exit   leave
  A bare URL, IP, host or hash is treated as 'hunt'."""

STOP = object()


class ReplContext:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.last_rows: list = []

    def remember(self, rows) -> None:
        if rows is not None:
            self.last_rows = rows


class ReplCommand:
    def __init__(self, run, needs_argument: bool):
        self.run = run
        self.needs_argument = needs_argument


def _count_argument(argument: str) -> int:
    return int(argument) if argument else DEFAULT_COUNT


def _repl_quit(context, argument):
    return STOP


def _repl_help(context, argument):
    print(REPL_HELP)


def _repl_raw(context, argument):
    context.settings.raw = not context.settings.raw
    print(f"  raw JSON output: {'on' if context.settings.raw else 'off'}")


def _repl_hunt(context, argument):
    run_hunt(context.settings, argument)


def _repl_url(context, argument):
    context.remember(command_url(context.settings, argument))


def _repl_host(context, argument):
    context.remember(command_host(context.settings, argument))


def _repl_recent(context, argument):
    context.remember(command_recent(context.settings, _count_argument(argument)))


def _repl_payloads(context, argument):
    context.remember(command_payloads(context.settings, _count_argument(argument)))


def _repl_bazaar(context, argument):
    context.remember(command_bazaar(context.settings, _count_argument(argument)))


def _repl_tag(context, argument):
    command_tag(context.settings, argument, DEFAULT_COUNT)


def _repl_family(context, argument):
    command_family(context.settings, argument, REPL_THREATFOX_LIMIT, DEFAULT_COUNT)


def _repl_iocs(context, argument):
    context.remember(command_iocs(context.settings, int(argument) if argument else 1))


def _repl_fox(context, argument):
    context.remember(command_fox(context.settings, argument))


def _repl_feodo(context, argument):
    command_feodo(context.settings, REPL_FEODO_CAP)


def _repl_sslbl(context, argument):
    command_sslbl(context.settings, REPL_SSLBL_CAP)


def _repl_watch(context, argument):
    run_watch(
        context.settings,
        int(argument) if argument else REPL_WATCH_INTERVAL,
        REPL_WATCH_POLL_SIZE,
    )


def _repl_download(context, argument):
    try:
        cmd_download(context.settings.key, argument, ".", False)
    except SystemExit as refusal:
        print(f"  ! {refusal}")


def _repl_export(context, argument):
    if not context.last_rows:
        print(
            "  nothing to export yet - run url, host, recent, payloads, iocs, fox or bazaar first"
        )
        return
    export_rows(context.last_rows, argument)


REPL_COMMANDS = {
    "quit": ReplCommand(_repl_quit, False),
    "q": ReplCommand(_repl_quit, False),
    "exit": ReplCommand(_repl_quit, False),
    "help": ReplCommand(_repl_help, False),
    "?": ReplCommand(_repl_help, False),
    "raw": ReplCommand(_repl_raw, False),
    "hunt": ReplCommand(_repl_hunt, True),
    "hash": ReplCommand(_repl_hunt, True),
    "url": ReplCommand(_repl_url, True),
    "host": ReplCommand(_repl_host, True),
    "recent": ReplCommand(_repl_recent, False),
    "payloads": ReplCommand(_repl_payloads, False),
    "bazaar": ReplCommand(_repl_bazaar, False),
    "tag": ReplCommand(_repl_tag, True),
    "family": ReplCommand(_repl_family, True),
    "sig": ReplCommand(_repl_family, True),
    "signature": ReplCommand(_repl_family, True),
    "iocs": ReplCommand(_repl_iocs, False),
    "fox": ReplCommand(_repl_fox, True),
    "feodo": ReplCommand(_repl_feodo, False),
    "sslbl": ReplCommand(_repl_sslbl, False),
    "watch": ReplCommand(_repl_watch, False),
    "download": ReplCommand(_repl_download, True),
    "export": ReplCommand(_repl_export, True),
}


def _dispatch_repl_line(context: ReplContext, text: str):
    parts = text.split(None, 1)
    word = parts[0].lower()
    argument = parts[1].strip() if len(parts) > 1 else ""
    entry = REPL_COMMANDS.get(word)
    if entry is not None and (argument or not entry.needs_argument):
        return entry.run(context, argument)
    candidate = text
    if classify(candidate) != "term":
        run_hunt(context.settings, candidate)
    else:
        print(f"  unknown command: {text}   (type 'help')")
    return None


def _run_repl_line(context: ReplContext, line: str):
    text = line.strip()
    if not text:
        return None
    try:
        return _dispatch_repl_line(context, text)
    except Exception as failure:  # one bad line must not end the session
        print(f"  ! {failure}")
        return None


def run_repl(settings: Settings) -> None:
    print_banner()
    print_house()
    print("  " + paint("type 'help' for the commands, 'quit' to leave", "dim"))
    context = ReplContext(settings)
    prompt = paint("chroma", "title") + paint("^", "accent") + " "
    while True:
        try:
            line = input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if _run_repl_line(context, line) is STOP:
            break
    print("  " + paint("bye", "dim"))


# --------------------------------------------------------------------------------------------
# Command line
# --------------------------------------------------------------------------------------------

EPILOG = """\
Global options (--key, --no-color, --json, --out, -n/--limit) go BEFORE or AFTER the subcommand:

  chromahaus hunt 8.8.8.8
  chromahaus -n 50 recent
  chromahaus --out hits.csv bazaar
  chromahaus --json url http://example.test/x.exe
  chromahaus download <sha256> --i-understand

Without a subcommand an interactive prompt starts.  The Auth-Key comes from --key,
ABUSECH_AUTH_KEY, ABUSE_CH_KEY or a key file (see the README)."""

_SUBCOMMANDS = (
    ("repl", "interactive prompt (same as no subcommand)", ()),
    (
        "hunt",
        "detect the indicator kind and query every relevant feed",
        ((("indicator",), {"help": "URL, host, IP, hash or term"}),),
    ),
    ("url", "URLhaus: look up a URL", ((("value",), {"help": "the URL"}),)),
    (
        "host",
        "URLhaus: look up a host or IP",
        ((("value",), {"help": "the host name or IP"}),),
    ),
    (
        "hash",
        "md5 or sha256 across URLhaus, MalwareBazaar and ThreatFox",
        ((("value",), {"help": "the digest"}),),
    ),
    ("recent", "latest URLhaus URLs", ()),
    ("payloads", "latest URLhaus payloads", ()),
    (
        "tag",
        "URLhaus and MalwareBazaar: entries carrying a tag",
        ((("value",), {"help": "the tag"}),),
    ),
    (
        "family",
        "malware family across URLhaus, ThreatFox and MalwareBazaar",
        ((("value",), {"help": "the family / signature name"}),),
    ),
    (
        "iocs",
        "recent ThreatFox IOCs",
        (
            (
                ("--days",),
                {
                    "type": int,
                    "default": 1,
                    "help": "how many days back, clamped to 1-7 (default 1)",
                },
            ),
        ),
    ),
    (
        "fox",
        "ThreatFox: search for an IOC",
        ((("value",), {"help": "the IOC to search for"}),),
    ),
    ("bazaar", "latest MalwareBazaar samples", ()),
    ("feodo", "Feodo Tracker recommended C2 IP blocklist", ()),
    ("sslbl", "SSL blacklist of malicious certificates", ()),
    (
        "watch",
        "poll URLhaus and print newly listed URLs",
        (
            (
                ("--interval",),
                {
                    "type": int,
                    "default": 30,
                    "help": "seconds between polls, at least 15 (default 30)",
                },
            ),
            (
                ("--polls",),
                {"type": int, "help": "finite polls (required for embedding)"},
            ),
        ),
    ),
    (
        "download",
        "save a malware sample ZIP into <workspace>/samples",
        (
            (("sha256",), {"help": "SHA256 of the sample"}),
            (
                ("--dest",),
                {
                    "default": ".",
                    "help": "sub-folder of <workspace>/samples (default: the folder itself)",
                },
            ),
            (
                ("--i-understand",),
                {
                    "action": "store_true",
                    "dest": "i_understand",
                    "help": "confirm that you are fetching live malware",
                },
            ),
        ),
    ),
)


def _add_global_options(parser, *, suppress_defaults=False):
    defaults = {"default": argparse.SUPPRESS} if suppress_defaults else {}
    parser.add_argument("--key", help="abuse.ch Auth-Key for this run", **defaults)
    parser.add_argument(
        "--no-color", action="store_true", help="never print ANSI colors", **defaults
    )
    parser.add_argument(
        "--json",
        dest="raw",
        action="store_true",
        help="print the raw API JSON",
        **defaults,
    )
    parser.add_argument(
        "--out",
        help="save the last listing to FILE (.json = JSON array, otherwise CSV)",
        **defaults,
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=argparse.SUPPRESS if suppress_defaults else DEFAULT_COUNT,
        help="row cap / API limit (default 25)",
    )
    parser.add_argument("-V", "--version", action="version", version=VERSION_LINE)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name,
        description="Query the abuse.ch threat feeds (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker, SSLBL).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_global_options(parser)
    commands = parser.add_subparsers(dest="cmd", required=False, title="commands")
    for name, summary, arguments in _SUBCOMMANDS:
        sub = commands.add_parser(name, help=summary, description=summary)
        _add_global_options(sub, suppress_defaults=True)
        for flags, options in arguments:
            sub.add_argument(*flags, **options)
    return parser


COMMANDS = {
    "hunt": lambda s, a: run_hunt(s, a.indicator),
    "url": lambda s, a: command_url(s, a.value),
    "host": lambda s, a: command_host(s, a.value),
    "hash": lambda s, a: command_hash(s, a.value),
    "recent": lambda s, a: command_recent(s, s.limit),
    "payloads": lambda s, a: command_payloads(s, s.limit),
    "tag": lambda s, a: command_tag(s, a.value, s.limit),
    "family": lambda s, a: command_family(s, a.value, s.limit, s.limit),
    "iocs": lambda s, a: command_iocs(s, a.days),
    "fox": lambda s, a: command_fox(s, a.value),
    "bazaar": lambda s, a: command_bazaar(s, s.limit),
    "feodo": lambda s, a: command_feodo(s, s.limit),
    "sslbl": lambda s, a: command_sslbl(s, s.limit),
    "watch": lambda s, a: run_watch(s, a.interval, s.limit, getattr(a, "polls", None)),
    "download": lambda s, a: cmd_download(
        s.key, a.sha256, a.dest, a.i_understand, structured=s.structured
    ),
}


def run_structured(args, *, dry_run=False):
    from bughunt.core.addon_adapters import planned, validate_watch
    from bughunt.core.results import ModuleOutput

    if args.cmd in (None, "repl"):
        equivalents = ", ".join(COMMANDS)
        return ModuleOutput(
            status="unsupported",
            errors=[
                {
                    "code": "interactive_operation",
                    "message": "Use one-shot operations: " + equivalents,
                    "retryable": False,
                }
            ],
        )
    if args.limit < 0:
        raise ValueError("Limit cannot be negative")
    if args.cmd == "watch":
        validate_watch(args.polls, max(WATCH_FLOOR_SECONDS, args.interval))
    if args.cmd == "download":
        normalize_digest(args.sha256)
        resolve_destination(args.dest)
        if not args.i_understand:
            raise ValueError("Sample download requires --i-understand")
    if args.cmd == "hash":
        digest = args.value.strip().lower()
        if len(digest) not in (32, 64) or not _made_of(digest, string.hexdigits):
            raise ValueError("Hash must be MD5 or SHA256")
    if dry_run:
        return planned("chroma", args.cmd)
    key = resolve_key(args.key)
    if not key:
        raise ValueError("An abuse.ch authentication key is required")
    settings = Settings(key, limit=args.limit, structured=True)
    rows = COMMANDS[args.cmd](settings, args)
    return structured_result(settings, args, rows)


def structured_result(settings: Settings, args, rows):
    from bughunt.core.addon_adapters import document, effect, external

    records = settings.responses or rows
    if args.out and records:
        export_rows(records if isinstance(records, list) else [records], args.out)
    failures = [
        record
        for record in settings.responses
        if isinstance(record["payload"], dict)
        and record["payload"].get("query_status", "ok") not in {"ok", "no_results"}
    ]
    status = (
        "partial"
        if failures and len(failures) < len(settings.responses)
        else "failed"
        if failures
        else "success"
    )
    output = external("chroma", args.cmd, settings.responses or rows, status=status)
    if args.cmd in {"feodo", "sslbl"}:
        document(output, rows["text"])
    if args.cmd == "download" or args.out and records:
        effect(output, "chroma-export", "write")
    return output


def _run_one_shot(settings: Settings, args: argparse.Namespace) -> None:
    if args.cmd == "download":
        normalize_digest(
            args.sha256
        )  # a malformed digest is refused before anything is printed
    if args.cmd != "watch" and not settings.raw:
        print_banner()
    rows = COMMANDS[args.cmd](settings, args)
    if args.out:
        if rows:
            export_rows(rows, args.out)
        else:
            print(f"  no export data; {args.out} was not written", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    global NO_COLOR
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.raw and args.cmd in (None, "repl", "feodo", "sslbl", "watch", "download"):
        parser.error(f"--json is not supported for {args.cmd or 'repl'}")
    NO_COLOR = bool(args.no_color)
    key = resolve_key(args.key)
    if not key:
        print(KEY_HELP)
        raise SystemExit(2)
    settings = Settings(key, raw=args.raw, limit=args.limit)
    try:
        if args.cmd in (None, "repl"):
            run_repl(settings)
        else:
            _run_one_shot(settings, args)
    except Exception as failure:
        print(f"  ! {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
