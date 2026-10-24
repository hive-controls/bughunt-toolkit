#!/usr/bin/env python3
"""flowcarve: pull links and endpoints out of captures and saved pages, entirely offline.

Reads HAR captures, raw HTTP messages, native mitmproxy flow dumps and plain HTML / JavaScript /
CSS / JSON text (from files or standard input), finds every URL or path-like reference in them,
labels each hit with a kind and an origin, filters the list, then prints it and/or saves it as
txt, json or csv.

The tool never opens a socket. The only optional third-party package is mitmproxy, imported lazily
and used purely as a file reader for native flow dumps.
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import sys
from collections import Counter
from contextlib import contextmanager
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin, urlsplit

STDIN_NAME = "-"
SNIFF_BYTES = 4096
MAX_LINK_LENGTH = 2048
MAX_QUOTED_LENGTH = 4096

MITM_INSTALL_HINT = "mitmproxy is not available; reading native flow dumps needs it (pip install mitmproxy)"
MITM_STDIN_REFUSAL = "Reading mitmproxy dumps from stdin is not supported; pass a file path."

ROW_FIELDS = ("link", "resolved", "kind", "origin", "flow_url", "status", "content_type", "source")

# ---------------------------------------------------------------------------------------------
# Vocabulary tables
# ---------------------------------------------------------------------------------------------

# File suffixes (lower case, final dot-part) that mark a reference as a real resource.
RECOGNIZED_EXTENSIONS = frozenset(
    """
    html htm xhtml shtml js mjs cjs jsx ts tsx json jsonp xml rss atom css scss less map txt csv
    pdf php php3 php4 php5 phtml asp aspx ashx asmx jsp jspx do action pl cgi cfm png jpg jpeg gif
    svg webp ico bmp avif woff woff2 ttf otf eot mp3 mp4 webm swf wasm zip gz tgz yaml yml
    """.split()
)
# Extensions that are also common top-level domains or plain words: they only count with a slash.
SLASH_REQUIRED_EXTENSIONS = frozenset({"do", "action", "pl"})

# Hosts under these domains name XML / schema vocabularies, not places worth visiting.
VOCABULARY_DOMAINS = (
    "w3.org",
    "json-schema.org",
    "purl.org",
    "schemas.microsoft.com",
    "xmlsoap.org",
    "schema.org",
    "xmlns.com",
    "ogp.me",
    "openxmlformats.org",
)
# One-label host names that are placeholders or grammar words rather than machines.
PLACEHOLDER_HOSTS = frozenset(
    "com net org edu www http https ftp url uri host hostname domain example".split()
)
UNIX_SYSTEM_ROOTS = frozenset("etc usr var bin sbin proc tmp home dev opt sys mnt".split())
ENDPOINT_PREFIXES = (
    "api/", "rest/", "static/", "assets/", "graphql/", ".well-known/",
    "ajax/", "rpc/", "auth/", "oauth/", "admin/",
)
# Words that look like path segments but are markup or language vocabulary (and regex flag runs).
SEGMENT_STOPWORDS = frozenset(
    """
    g i m s u y gi gm gu gy ig im mi gim gis
    div span img nav ul li ol tr td th tbody thead table form input button label select option
    textarea body html head meta link script style svg canvas iframe
    null true false void this var let const else case try catch throw new super yield await
    function return typeof while
    """.split()
)
REGEX_FLAG_LETTERS = frozenset("gimsuy")

BLOCKED_SCHEMES = (
    "javascript:", "data:", "blob:", "about:", "file:", "chrome:", "chrome-extension:", "view-source:",
)
ABSOLUTE_SCHEMES = ("http://", "https://", "ws://", "wss://")

BINARY_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".avif", ".tif", ".tiff",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".m4a", ".wav", ".ogg", ".webm",
    ".mov", ".avi", ".flac", ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".wasm",
)
HAR_SUFFIXES = (".har", ".zhar")
FLOW_DUMP_SUFFIXES = (".mitm", ".flow", ".flows", ".dump")
# First bytes that are allowed in a file that is NOT treated as a binary flow dump.

# Link attributes read at the loosest trust, and the attribute families with their own handling.
LOOSE_LINK_ATTRIBUTES = frozenset(
    "href src action formaction poster cite icon manifest longdesc data".split()
)
SRCSET_ATTRIBUTES = frozenset({"srcset", "imagesrcset", "data-srcset"})

TEXTUAL_MIME_MARKERS = ("svg", "json", "javascript", "ecmascript", "xml", "html", "css", "yaml")
BINARY_MIME_FAMILIES = ("image/", "audio/", "video/", "font/")
BINARY_MIME_TYPES = frozenset(
    {
        "application/octet-stream", "application/pdf", "application/zip",
        "application/gzip", "application/wasm", "application/x-protobuf",
    }
)

# Trust ladder for candidate strings: the more structured the source, the more it is believed.
TRUST_URL = "url"
TRUST_QUOTED = "quoted"
TRUST_ATTRIBUTE = "attribute"
TRUST_LAX = "lax"
LOOSE_TRUSTS = (TRUST_ATTRIBUTE, TRUST_LAX)

# SGR codes: roles first, then one entry per link kind.
CODE_TITLE = "1;96"
CODE_DIM = "2"
CODE_DONE = "92"
CODE_WARNING = "93"
CODE_ERROR = "31"
CODE_FALLBACK_KIND = "37"
KIND_CODES = {
    "https": "1;92",
    "http": "1;33",
    "protocol-relative": "96",
    "absolute-path": "94",
    "relative-path": "34",
    "js-endpoint": "95",
    "ws": "1;35",
    "wss": "1;35",
    "mailto": "36",
}

# ---------------------------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------------------------

_JS_ESCAPE = re.compile(r"\\(?:u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2})|(/))")
_UNESCAPED_CHARACTERS = frozenset("#%&+/:=?@")
_ENTITY_VALUES = {
    "&#x2f;": "/", "&#47;": "/", "&sol;": "/",
    "&quot;": '"', "&#34;": '"', "&#x22;": '"',
    "&apos;": "'", "&#39;": "'", "&#x27;": "'",
    "&lt;": "<", "&gt;": ">", "&amp;": "&",
}
_ENTITY = re.compile("|".join(re.escape(name) for name in _ENTITY_VALUES), re.IGNORECASE)
_CUT_POINT = re.compile(r"[\"'<>\r\n\t]")
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x1f\x7f-\x9f\s]")
_TRAILING_JUNK = frozenset(".,;:!?\"'`<>]}|$")

_IPV4 = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_IPV6_CHARS = re.compile(r"[0-9a-f:.]+")
_BARE_WWW = re.compile(r"www\.((?:[a-z0-9-]+\.)+[a-z0-9-]+)(?::\d{1,5})?(?:[/?#].*)?", re.IGNORECASE | re.DOTALL)

_DRIVE_PATH = re.compile(r"[A-Za-z]:[\\/]")
_PATH_CHARACTERS = re.compile(r"[A-Za-z0-9._~!$&'()*+,;=:@%/?#-]+")
_NUMERIC_SHAPE = re.compile(r"\d+(?:/\d+)+/?")
_MIME_SHAPE = re.compile(
    r"(?:application|audio|font|image|message|model|multipart|text|video)/"
    r"(?:(?:vnd|prs|x)[.-][\w.+-]+|[a-z0-9][a-z0-9+-]*)",
    re.IGNORECASE,
)
_VERSION_PREFIX = re.compile(r"v\d+/")
_BARE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]{1,63}")
_FLAG_RUN = re.compile(r"[gimsuy]{1,4}")

_HOST_NAME = r"[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)*"
_URL_TAIL = r"[^\s\"'<>`\\{}|,]*"
_ABSOLUTE_URL = re.compile(
    r"(?<![A-Za-z0-9+.\-])(?:https?|wss?)://"
    r"(?:[^\s/?#@\"'<>`\\{}|,]+@)?"
    r"(?:\[[0-9A-Fa-f:.]+\]|" + _HOST_NAME + r")"
    r"(?::\d{1,5})?" + _URL_TAIL,
    re.IGNORECASE,
)
_PROTOCOL_RELATIVE = re.compile(
    r"(?<!:)//(?:[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]+)+|localhost)(?::\d{1,5})?" + _URL_TAIL,
    re.IGNORECASE,
)
_CSS_URL = re.compile(r"\burl\(\s*(?:\"([^\"]*)\"|'([^']*)'|([^)\s]*))\s*\)", re.IGNORECASE)
_CSS_IMPORT = re.compile(r"@import\s+(['\"])(.+?)\1", re.IGNORECASE)
_SOURCE_REFERENCE = re.compile(r"source(?:Mapping)?URL=(\S+)", re.IGNORECASE)
_QUOTED_STRING_STYLES = (
    re.compile(r"'((?:[^'\\\r\n]|\\.){1,%d})'" % MAX_QUOTED_LENGTH),
    re.compile(r'"((?:[^"\\\r\n]|\\.){1,%d})"' % MAX_QUOTED_LENGTH),
    re.compile(r"`((?:[^`\\]|\\[\s\S]){1,%d})`" % MAX_QUOTED_LENGTH),
)
_LINK_HEADER_TARGET = re.compile(r"<([^>]*)>")
_VERSIONED_ENDPOINT = re.compile(r"v\d+/")

_REDIRECT_HEADERS = ("location", "content-location", "x-redirect")
_ENDPOINT_MARKERS = ("api/", "graphql/", "ajax/", "endpoint/")
_ENDPOINT_SUFFIXES = (".js", ".mjs", ".cjs", ".json", ".php", ".aspx", ".jsp", ".cgi")
_SCHEME_KINDS = (
    ("https://", "https"), ("http://", "http"), ("wss://", "wss"), ("ws://", "ws"), ("//", "protocol-relative"),
)
_UNTOUCHED_PREFIXES = ABSOLUTE_SCHEMES + ("mailto:", "data:")


# ---------------------------------------------------------------------------------------------
# Candidate normalisation and acceptance
# ---------------------------------------------------------------------------------------------


def _unescape_js(text):
    def swap(match):
        digits = match.group(1) or match.group(2)
        character = chr(int(digits, 16)) if digits else "/"
        return character if character in _UNESCAPED_CHARACTERS else match.group(0)

    return _JS_ESCAPE.sub(swap, text)


def _trim_trailing(text):
    cut = text.find("${")
    if cut >= 0:
        text = text[:cut]
    while text:
        last = text[-1]
        if text.endswith("*/"):
            text = text[:-2]
        elif last in _TRAILING_JUNK:
            text = text[:-1]
        elif last == ")" and text.count(")") > text.count("("):
            text = text[:-1]
        elif last == "*" and not text.endswith("/*"):
            text = text[:-1]
        else:
            break
    return text


def _normalize_candidate(raw):
    text = _unescape_js(raw.strip())
    if len(text) > 1 and text[0] in "\"'`" and text[-1] == text[0]:
        text = text[1:-1].strip()
    text = _ENTITY.sub(lambda match: _ENTITY_VALUES[match.group(0).lower()], text)
    cut = _CUT_POINT.search(text)
    if cut:
        text = text[: cut.start()]
    text = text.strip()
    while text[:4].lower() == "url=":
        text = text[4:].lstrip()
    return _trim_trailing(text)


def _plausible_top_label(label):
    return len(label) >= 2 and label.isascii() and label.isalpha()


def _inside_vocabulary_domain(host):
    return any(host == domain or host.endswith("." + domain) for domain in VOCABULARY_DOMAINS)


def _lone_label_acceptable(host, parts):
    if host in PLACEHOLDER_HOSTS or len(host) < 3:
        return False
    return bool(parts.path) or parts.port is not None


def _authority_acceptable(text, *, allow_lone_label):
    try:
        parts = urlsplit(text)
        host = (parts.hostname or "").rstrip(".")
        _ = parts.port
    except ValueError:
        return False
    if not host or _inside_vocabulary_domain(host):
        return False
    if host == "localhost":
        return True
    if _IPV4.fullmatch(host):
        return all(int(octet) <= 255 for octet in host.split("."))
    if ":" in host:
        return bool(_IPV6_CHARS.fullmatch(host))
    if "." in host:
        return _plausible_top_label(host.rsplit(".", 1)[1])
    return allow_lone_label and _lone_label_acceptable(host, parts)


def _is_bare_www(text):
    match = _BARE_WWW.fullmatch(text)
    if not match:
        return False
    host = match.group(1).lower()
    return _plausible_top_label(host.rsplit(".", 1)[1]) and not _inside_vocabulary_domain("www." + host)


def _file_extension(path_part):
    last_segment = path_part.rsplit("/", 1)[-1]
    return last_segment.rsplit(".", 1)[1].lower() if "." in last_segment else ""


def _is_bare_token(text):
    return bool(_BARE_TOKEN.fullmatch(text)) and not text.isdigit() and text.lower() not in SEGMENT_STOPWORDS


def _rooted_path_acceptable(text, path_part, recognized, trust):
    segments = [piece for piece in path_part.split("/") if piece not in ("", ".", "..")]
    if text.startswith("/") and segments and segments[0].lower() in UNIX_SYSTEM_ROOTS and not recognized:
        return False
    if recognized or len(path_part) < len(text):
        return True
    if not segments:
        return False
    if len(segments) == 1:
        return len(segments[0]) >= 3 and segments[0].lower() not in SEGMENT_STOPWORDS
    tail = segments[-1].lower()
    if tail in SEGMENT_STOPWORDS and _FLAG_RUN.fullmatch(tail):
        return trust in LOOSE_TRUSTS
    return True


def _relative_path_acceptable(text, path_part, recognized, trust):
    if "://" in path_part:
        return False
    if recognized:
        return True
    lowered = text.lower()
    if lowered.startswith(ENDPOINT_PREFIXES) or _VERSION_PREFIX.match(lowered):
        return True
    if text.count("/") >= 2:
        return True
    return trust == TRUST_LAX and _is_bare_token(text)


def _path_acceptable(text, trust):
    if _DRIVE_PATH.match(text) or not _PATH_CHARACTERS.fullmatch(text) or text.startswith("#"):
        return False
    if text.startswith("?"):
        return trust in LOOSE_TRUSTS
    rooted = text.startswith(("/", "./", "../"))
    if not rooted and (_NUMERIC_SHAPE.fullmatch(text) or _MIME_SHAPE.fullmatch(text)):
        return False
    path_part = re.split(r"[?#]", text, maxsplit=1)[0]
    extension = _file_extension(path_part)
    if extension in SLASH_REQUIRED_EXTENSIONS and "/" not in text:
        return False
    recognized = extension in RECOGNIZED_EXTENSIONS
    judge = _rooted_path_acceptable if rooted else _relative_path_acceptable
    return judge(text, path_part, recognized, trust)


def keep_link(raw, *, trust=TRUST_QUOTED):
    """Normalise a raw candidate string; return the cleaned link, or None when it is not a link.

    Malformed bracketed hosts and ports are rejected as invalid candidates.
    """
    text = _normalize_candidate(raw)
    if not 2 <= len(text) <= MAX_LINK_LENGTH or _CONTROL_OR_SPACE.search(text):
        return None
    lowered = text.lower()
    if lowered.startswith(BLOCKED_SCHEMES):
        return None
    if lowered.startswith(ABSOLUTE_SCHEMES):
        return text if _authority_acceptable(text, allow_lone_label=True) else None
    if text.startswith("//"):
        return text if _authority_acceptable(text, allow_lone_label=False) else None
    if lowered.startswith("mailto:"):
        return text if "@" in text[len("mailto:"):] else None
    if trust == TRUST_URL:
        return None
    return text if _is_bare_www(text) or _path_acceptable(text, trust) else None


# ---------------------------------------------------------------------------------------------
# Classification and content-type helpers
# ---------------------------------------------------------------------------------------------


def _is_www_host(lowered):
    return lowered.startswith("www.") and "." in lowered[4:]


def classify_link(link):
    """Name the kind of a link: one of nine fixed labels."""
    lowered = link.lower()
    for prefix, kind in _SCHEME_KINDS:
        if lowered.startswith(prefix):
            return kind
    if _is_www_host(lowered):
        return "https"
    if lowered.startswith("data:"):
        return "data"
    if lowered.startswith("mailto:"):
        return "mailto"
    if lowered.startswith("/"):
        return "absolute-path"
    if any(marker in lowered for marker in _ENDPOINT_MARKERS):
        return "js-endpoint"
    if _VERSIONED_ENDPOINT.search(lowered) or lowered.endswith(_ENDPOINT_SUFFIXES):
        return "js-endpoint"
    return "relative-path"


def scannable_mime(content_type):
    """Whether a body with this content type is worth scanning for links."""
    if not content_type:
        return True
    mime = content_type.split(";", 1)[0].strip().lower()
    if not mime or mime.startswith("text/"):
        return True
    if any(marker in mime for marker in TEXTUAL_MIME_MARKERS):
        return True
    return not (mime.startswith(BINARY_MIME_FAMILIES) or mime in BINARY_MIME_TYPES)


def _typed_dictionary_frame(path, head):
    prefix = re.match(rb"([0-9]{1,12}):", head)
    if prefix is None:
        return False
    payload_start = prefix.end()
    payload_end = payload_start + int(prefix[1])
    first_key = re.match(rb"([0-9]{1,12}):", head[payload_start:])
    if first_key is None:
        return False
    key_end = payload_start + first_key.end() + int(first_key[1])
    if key_end >= payload_end or head[key_end:key_end + 1] not in (b",", b";"):
        return False
    if payload_end < len(head):
        return head[payload_end:payload_end + 1] == b"}"
    if str(path) == STDIN_NAME:
        return False
    try:
        with open(path, "rb") as handle:
            handle.seek(payload_end)
            return handle.read(1) == b"}"
    except OSError:
        return False


def sniff_kind(path, head):
    """Guess what an input is from its name and first bytes: har, mitm, raw-http or text."""
    name = str(path).lower()
    if name.endswith(HAR_SUFFIXES):
        return "har"
    if name.endswith(FLOW_DUMP_SUFFIXES):
        return "mitm"
    stripped = head.lstrip()
    if stripped.startswith(b"{") and b'"log"' in stripped[:4000]:
        return "har"
    if stripped[:5] in (b"HTTP/", b"http/"):
        return "raw-http"
    if not head:
        return "text"
    binary = any(byte < 32 and byte not in b"\t\r\n\f" for byte in head[:64])
    if binary or _typed_dictionary_frame(path, head):
        return "mitm"
    return "text"


# ---------------------------------------------------------------------------------------------
# Extraction passes
# ---------------------------------------------------------------------------------------------


class _LinkCollector:
    """Ordered, de-duplicated accumulator of (link, kind, origin) hits."""

    def __init__(self, *, with_twins=True):
        self.items = []
        self._seen = set()
        self._with_twins = with_twins

    def _append(self, link, origin):
        if link not in self._seen:
            self._seen.add(link)
            self.items.append((link, classify_link(link), origin))

    def _offer(self, raw, trust, origin):
        kept = keep_link(raw, trust=trust)
        if kept is not None:
            self._append(kept, origin)
        if not self._with_twins:
            return
        source = raw if kept is None else kept
        decoded = unquote(source)
        if decoded != source:
            twin = keep_link(decoded, trust=trust)
            if twin is not None:
                self._append(twin, origin + "+decoded")

    def offer(self, raw, trust, origin, *, tolerant=False):
        try:
            self._offer(raw, trust, origin)
        except ValueError:
            if not tolerant:
                raise


def _attribute_candidates(name, value):
    local = name.rsplit(":", 1)[-1]
    if local in SRCSET_ATTRIBUTES:
        for entry in value.split(","):
            pieces = entry.split()
            if pieces:
                yield pieces[0], TRUST_ATTRIBUTE
    elif local == "content":
        position = value.lower().find("url=")
        if position < 0:
            yield value, TRUST_QUOTED
        else:
            pieces = value[position + 4:].split()
            yield (pieces[0] if pieces else ""), TRUST_ATTRIBUTE
    elif local == "ping":
        for token in value.split():
            yield token, TRUST_ATTRIBUTE
    elif local in LOOSE_LINK_ATTRIBUTES:
        yield value, TRUST_LAX
    elif local.startswith("data-"):
        yield value, TRUST_ATTRIBUTE


class _AttributeHarvester(HTMLParser):
    """Collects (candidate, trust) pairs from the attributes of every start tag."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.candidates = []

    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if value:
                self.candidates.extend(_attribute_candidates(name, value))


def _html_candidates(text):
    if "<" not in text or ">" not in text:
        return []
    harvester = _AttributeHarvester()
    try:
        harvester.feed(text)
        harvester.close()
    except Exception:  # a markup parser failure only ends this pass
        pass
    return harvester.candidates


def _css_candidates(text):
    for match in _CSS_URL.finditer(text):
        yield next(group for group in match.groups() if group is not None), TRUST_ATTRIBUTE
    for match in _CSS_IMPORT.finditer(text):
        yield match.group(2), TRUST_ATTRIBUTE


def _source_reference_candidates(text):
    for match in _SOURCE_REFERENCE.finditer(text):
        yield match.group(1), TRUST_QUOTED


def _json_strings(document):
    pending = [document]
    while pending:
        node = pending.pop()
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for key, value in reversed(list(node.items())):
                pending.append(value)
                pending.append(key)
        elif isinstance(node, list):
            pending.extend(reversed(node))


def _json_candidates(text):
    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")):
        return
    try:
        document = json.loads(stripped)
    except (ValueError, RecursionError):
        return
    for string in _json_strings(document):
        yield string, TRUST_QUOTED


def _absolute_url_candidates(text):
    for match in _ABSOLUTE_URL.finditer(text):
        yield match.group(0), TRUST_URL


def _protocol_relative_candidates(text):
    for match in _PROTOCOL_RELATIVE.finditer(text):
        yield match.group(0), TRUST_URL


def _quoted_candidates(text):
    for style in _QUOTED_STRING_STYLES:
        for match in style.finditer(text):
            yield match.group(1), TRUST_QUOTED


# (gatherer, origin tag, tolerate URL-parser errors); the order is the observable pass order.
_BODY_PASSES = (
    (_html_candidates, "html", False),
    (_css_candidates, "css", False),
    (_source_reference_candidates, "regex", False),
    (_json_candidates, "json", False),
    (_absolute_url_candidates, "regex", True),
    (_protocol_relative_candidates, "regex", True),
    (_quoted_candidates, "regex", False),
)


def extract_from_text(text):
    """Find every link in a text body: ordered, de-duplicated (link, kind, origin) triples."""
    collector = _LinkCollector()
    for gather, origin, tolerant in _BODY_PASSES:
        for raw, trust in gather(text):
            collector.offer(raw, trust, origin, tolerant=tolerant)
    return collector.items


def extract_from_headers(headers):
    """Find links in response headers (names must already be lower-cased)."""
    collector = _LinkCollector(with_twins=False)
    for name in _REDIRECT_HEADERS:
        value = headers.get(name)
        if value:
            collector.offer(value, TRUST_ATTRIBUTE, "header")
    for target in _LINK_HEADER_TARGET.findall(headers.get("link") or ""):
        collector.offer(target, TRUST_ATTRIBUTE, "header")
    after_semicolon = (headers.get("refresh") or "").partition(";")[2]
    if after_semicolon.strip():
        collector.offer(after_semicolon, TRUST_ATTRIBUTE, "header")
    return collector.items


# ---------------------------------------------------------------------------------------------
# Input loading
# ---------------------------------------------------------------------------------------------


def _make_record(source, url, status, content_type, links):
    return {"source": source, "url": url, "status": status, "content_type": content_type, "links": links}


def _request_links(url):
    kept = keep_link(url, trust=TRUST_URL)
    return [] if kept is None else [(kept, classify_link(kept), "request")]


def _decode_text(data, *, from_stdin):
    if from_stdin:
        return data.decode("utf-8", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", "replace")


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _har_header_map(listing):
    mapping = {}
    for item in listing if isinstance(listing, list) else []:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            mapping[item["name"].lower()] = str(item.get("value") or "")
    return mapping


def _har_body(content):
    text = content.get("text")
    if not isinstance(text, str) or not text:
        return ""
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text).decode("utf-8", "replace")
        except ValueError:
            return ""
    return text


def _har_entry_record(entry, source):
    request = _as_dict(entry.get("request"))
    response = _as_dict(entry.get("response"))
    content = _as_dict(response.get("content"))
    url = request.get("url") if isinstance(request.get("url"), str) else ""
    headers = _har_header_map(response.get("headers"))
    mime = content.get("mimeType") or headers.get("content-type") or ""
    links = _request_links(url) + extract_from_headers(headers)
    body = _har_body(content)
    if body and scannable_mime(mime):
        links += extract_from_text(body)
    return _make_record(source, url, response.get("status"), mime, links)


def _har_records(data, source):
    """Records for a HAR document, or None when the bytes are not a HAR log."""
    try:
        document = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    log = _as_dict(document).get("log")
    entries = _as_dict(log).get("entries")
    if not isinstance(entries, list):
        return None
    usable = [entry for entry in entries if isinstance(entry, dict)]
    if entries and not usable:
        return None
    return [_har_entry_record(entry, source) for entry in usable]


def _split_head_and_body(text):
    head, _separator, body = text.partition("\r\n\r\n")
    if not body:
        lf_head, lf_separator, lf_body = text.partition("\n\n")
        if lf_separator:
            return lf_head, lf_body
    return head, body


def _raw_header_map(head):
    mapping = {}
    for line in head.splitlines()[1:]:
        name, colon, value = line.partition(":")
        if colon:
            mapping[name.strip().lower()] = value.strip()
    return mapping


def _raw_http_record(data, source, *, from_stdin):
    text = _decode_text(data, from_stdin=from_stdin)
    head, body = _split_head_and_body(text)
    headers = _raw_header_map(head)
    content_type = headers.get("content-type", "")
    links = extract_from_headers(headers)
    if scannable_mime(headers.get("content-type")):
        links += extract_from_text(body)
    if from_stdin:
        return _make_record(source, source, None, content_type, links)
    status_line = head.splitlines()[0].split() if head else []
    status = (int(status_line[1]) if len(status_line) > 1
              and status_line[0].startswith("HTTP/") and status_line[1].isdigit() else None)
    return _make_record(source, headers.get("x-request-url") or source, status, content_type, links)


def _flow_header_map(response):
    try:
        return {str(name).lower(): str(value) for name, value in response.headers.items()}
    except Exception:
        return {}


def _flow_body(response):
    try:
        return response.get_text(strict=False) or ""
    except Exception:
        return (response.content or b"").decode("utf-8", "replace")


def _flow_record(flow, source):
    request = flow.request
    url = getattr(request, "pretty_url", None) or request.url
    links = _request_links(url)
    status, content_type = None, ""
    response = flow.response
    if response is not None:
        status = response.status_code
        headers = _flow_header_map(response)
        content_type = headers.get("content-type", "")
        links += extract_from_headers(headers)
        body = _flow_body(response)
        if body and scannable_mime(content_type):
            links += extract_from_text(body)
    return _make_record(source, url, status, content_type, links)


def _read_flow_dump(path):
    """Read a native mitmproxy flow file; mitmproxy is imported here and nowhere else."""
    try:
        from mitmproxy import exceptions as flow_exceptions
        from mitmproxy import http as flow_http
        from mitmproxy import io as flow_io
    except ImportError as exc:
        raise RuntimeError(MITM_INSTALL_HINT) from exc
    records = []
    try:
        with open(path, "rb") as handle:
            for flow in flow_io.FlowReader(handle).stream():
                if isinstance(flow, flow_http.HTTPFlow):
                    records.append(_flow_record(flow, path))
    except flow_exceptions.FlowReadException as exc:
        raise RuntimeError(f"Flow file could not be read: {exc}") from exc
    return records


def _read_stdin_bytes():
    stream = getattr(sys.stdin, "buffer", None)
    if stream is not None:
        return stream.read()
    return sys.stdin.read().encode("utf-8", "replace")


def _records_from_bytes(data, kind, source, *, from_stdin):
    if kind == "har":
        records = _har_records(data, source)
        if records is not None:
            return records
    elif kind == "raw-http":
        return [_raw_http_record(data, source, from_stdin=from_stdin)]
    text = _decode_text(data, from_stdin=from_stdin)
    return [_make_record(source, source, None, "", extract_from_text(text))]


def load_input(path):
    """Turn one input (a file path, or '-' for stdin) into a list of records."""
    path = str(path)
    if path == STDIN_NAME:
        data = _read_stdin_bytes()
        kind = sniff_kind(path, data)
        if kind == "mitm":
            raise RuntimeError(MITM_STDIN_REFUSAL)
        return _records_from_bytes(data, kind, path, from_stdin=True)
    if path.lower().endswith(BINARY_SUFFIXES):
        return [_make_record(path, path, None, "", [])]
    with open(path, "rb") as handle:
        head = handle.read(SNIFF_BYTES)
        kind = sniff_kind(path, head)
        if kind != "mitm":
            head += handle.read()
    if kind == "mitm":
        return _read_flow_dump(path)
    return _records_from_bytes(head, kind, path, from_stdin=False)


# ---------------------------------------------------------------------------------------------
# Resolving, flattening, filtering
# ---------------------------------------------------------------------------------------------


def try_resolve(link, base):
    """Best-effort absolute form of a link against the URL of the flow that produced it."""
    lowered = link.lower()
    if _is_www_host(lowered):
        return "https://" + link
    if not base or not base.lower().startswith(("http://", "https://")):
        return link
    if lowered.startswith(_UNTOUCHED_PREFIXES):
        return link
    try:
        if link.startswith("//"):
            return base.split(":", 1)[0] + ":" + link
        return urljoin(base, link)
    except ValueError:
        return link


def flatten(records, include_requests):
    """One row per link of every record, with the fixed eight-field shape."""
    rows = []
    for record in records:
        flow_url = record.get("url") or ""
        for link, kind, origin in record.get("links", ()):
            if origin == "request" and not include_requests:
                continue
            rows.append(
                {
                    "link": link,
                    "resolved": try_resolve(link, flow_url),
                    "kind": kind,
                    "origin": origin,
                    "flow_url": flow_url,
                    "status": record.get("status"),
                    "content_type": record.get("content_type") or "",
                    "source": record.get("source") or "",
                }
            )
    return rows


def _word_set(value):
    return {piece.strip().lower() for piece in value.split(",") if piece.strip()}


def _row_host(row):
    target = row["resolved"] if "://" in row["resolved"] else row["link"]
    try:
        return urlsplit(target).hostname
    except ValueError:
        return None


def _in_domains(host, domains):
    return bool(host) and any(host == domain or host.endswith("." + domain) for domain in domains)


def _row_key(row, resolve):
    return row["resolved"] if resolve else row["link"]


def _drop_repeats(rows, resolve):
    seen = set()
    kept = []
    for row in rows:
        key = _row_key(row, resolve)
        if key not in seen:
            seen.add(key)
            kept.append(row)
    return kept


def apply_filters(rows, args):
    """Apply the selection options in their fixed order: kind, origin, contains, regex, domain, unique, sort."""
    if args.kind:
        wanted = _word_set(args.kind)
        rows = [row for row in rows if row["kind"] in wanted]
    if args.origin:
        wanted = _word_set(args.origin)
        rows = [row for row in rows if row["origin"].removesuffix("+decoded") in wanted]
    if args.contains:
        needle = args.contains.lower()
        rows = [row for row in rows if needle in row["link"].lower() or needle in row["resolved"].lower()]
    if args.regex:
        pattern = re.compile(args.regex, re.IGNORECASE)
        rows = [row for row in rows if pattern.search(row["link"]) or pattern.search(row["resolved"])]
    if args.domain:
        domains = {piece.strip().lower().lstrip(".") for piece in args.domain.split(",")} - {""}
        rows = [row for row in rows if _in_domains(_row_host(row), domains)]
    if args.unique:
        rows = _drop_repeats(rows, args.resolve)
    if args.sort:
        rows = sorted(rows, key=lambda row: (row["kind"], _row_key(row, args.resolve).lower()))
    return rows


# ---------------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------------


def infer_format(path, explicit):
    """The save format: the explicit choice, else decided by the file extension."""
    if explicit:
        return explicit
    suffix = str(path).lower()
    if suffix.endswith(".json"):
        return "json"
    if suffix.endswith(".csv"):
        return "csv"
    return "txt"


def save_rows(rows, path, fmt, resolve):
    """Write the rows to a file as txt (one link per line), json (array of objects) or csv."""
    if fmt == "csv":
        with open(path, "w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=ROW_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
    elif fmt == "json":
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, indent=2)
            handle.write("\n")
    else:
        with open(path, "w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(_row_key(row, resolve) + "\n")


def paint(text, code, enabled):
    return f"\x1b[{code}m{text}\x1b[0m" if enabled else text


def _color_enabled(args):
    if args.quiet or args.color == "never":
        return False
    if args.color == "always":
        return True
    if "NO_COLOR" in os.environ:
        return False
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _banner_lines(rows, color):
    tally = Counter(row["kind"] for row in rows)
    breakdown = ", ".join(f"{kind}={count}" for kind, count in sorted(tally.items(), key=lambda pair: -pair[1]))
    return [
        paint("flowcarve \u2500 link carver", CODE_TITLE, color),
        paint(f"{len(rows)} link(s)  \u2022  kinds: {breakdown}", CODE_DIM, color),
        paint("\u2500" * 52, CODE_DIM, color),
    ]


def _row_line(row, args, color):
    code = KIND_CODES.get(row["kind"], CODE_FALLBACK_KIND)
    shown = row["resolved"] if args.resolve else row["link"]
    line = (
        "  " + paint(f"{row['kind']:<18}", code, color)
        + " " + paint(f"{row['origin']:<14}", CODE_DIM, color)
        + " " + paint(shown, code, color)
    )
    if args.verbose:
        context = " \u00b7 ".join(str(part) for part in (row["flow_url"], row["status"]) if part not in ("", None))
        if context:
            line += "  " + paint(":: " + context, CODE_DIM, color)
    return line


def _print_grouped(rows, args, color):
    groups = {}
    for row in rows:
        groups.setdefault(row["kind"], []).append(row)
    for kind, members in groups.items():
        label = f"[{kind}] {len(members)}"
        print(paint(label, KIND_CODES.get(kind, CODE_FALLBACK_KIND), color))
        print(paint("\u2500" * max(24, len(label)), CODE_DIM, color))
        for row in members:
            print(_row_line(row, args, color))
        print()


def _print_report(rows, args, color):
    if not rows:
        print(paint("No links found.", CODE_WARNING, color))
        return
    for line in _banner_lines(rows, color):
        print(line)
    print()
    if args.group:
        _print_grouped(rows, args, color)
    else:
        for row in rows:
            print(_row_line(row, args, color))
    print()
    print(paint(f"Done. {len(rows)} link(s).", CODE_DONE, color))


# ---------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------

_DESCRIPTION = """\
Carve links and endpoints out of local captures and pages. flowcarve works offline: it reads
files (or standard input), extracts URLs and paths, labels each one, and lists or saves them.
"""

_EPILOG = """\
Supported inputs:
  HAR captures (.har, or any JSON file with a HAR log)
  raw HTTP messages (a file that starts with an HTTP/ status line)
  HTML, JavaScript, CSS, JSON and plain text
  native mitmproxy flow dumps (.mitm, .flow, .flows, .dump); these need the optional
  mitmproxy package: pip install mitmproxy
  '-' reads one input from standard input (not mitmproxy dumps)

Kinds:   https http ws wss protocol-relative absolute-path relative-path js-endpoint mailto
Origins: request header html css json regex (a '+decoded' suffix marks a percent-decoded twin)

Examples:
  flowcarve capture.har --unique --sort
  flowcarve app.js page.html --kind absolute-path,js-endpoint --save endpoints.txt
  flowcarve capture.har --include-requests --domain example.com --format csv -o hosts.csv
  cat bundle.js | flowcarve - --contains /api/
"""


def build_parser():
    parser = argparse.ArgumentParser(
        description=_DESCRIPTION,
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("inputs", nargs="+", metavar="INPUT", help="files to read; '-' means standard input")
    parser.add_argument("-o", "--save", "--output", metavar="FILE", help="write the resulting rows to FILE")
    parser.add_argument("--format", choices=("txt", "json", "csv"),
                        help="file format for --save (default: decided by the file extension, else txt)")
    parser.add_argument("--include-requests", action="store_true",
                        help="also keep each flow's own request URL (origin 'request')")
    parser.add_argument("--unique", action="store_true", help="drop repeated rows, keeping the first")
    parser.add_argument("--sort", action="store_true", help="sort rows by kind, then by link")
    parser.add_argument("--group", action="store_true", help="group the on-screen list by kind")
    parser.add_argument("--resolve", action="store_true",
                        help="show, save, de-duplicate and sort on the resolved URL instead of the raw link")
    parser.add_argument("-v", "--verbose", action="store_true", help="show the flow URL and status for each row")
    parser.add_argument("--kind", help="comma-separated kinds to keep")
    parser.add_argument("--origin", help="comma-separated origins to keep (compared without '+decoded')")
    parser.add_argument("--contains", help="keep rows whose link or resolved URL contains this text (any case)")
    parser.add_argument("--regex", help="keep rows whose link or resolved URL matches this regular expression")
    parser.add_argument("--domain", help="comma-separated domains; keep rows on them or their subdomains")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="colored output: auto uses color on a terminal unless NO_COLOR is set")
    parser.add_argument("-q", "--quiet", action="store_true", help="print nothing to standard output")
    return parser


def parse_args(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.regex:
        try:
            re.compile(args.regex, re.IGNORECASE)
        except re.error as problem:
            parser.exit(2, f"{parser.prog}: error: invalid --regex: {problem}\n")
    return args


def _complain(message, color):
    print(paint(message, CODE_ERROR, color), file=sys.stderr)


def _read_inputs(paths, color):
    records = []
    failures = 0
    for path in paths:
        if path != STDIN_NAME and not os.path.exists(path):
            _complain(f"Not found: {path}", color)
            failures += 1
            continue
        try:
            records.extend(load_input(path))
        except Exception as exc:
            _complain(f"Failed to read {path}: {exc}", color)
            failures += 1
    return records, failures


@contextmanager
def _legacy_output():
    previous = []
    try:
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                previous.append((stream, stream.errors))
                stream.reconfigure(errors="backslashreplace")
        yield
    finally:
        for stream, errors in reversed(previous):
            stream.reconfigure(errors=errors)


@_legacy_output()
def main(argv=None):
    args = parse_args(argv)
    color = _color_enabled(args)
    records, failures = _read_inputs(args.inputs, color)
    rows = apply_filters(flatten(records, args.include_requests), args)
    if not args.quiet:
        _print_report(rows, args, color)
    if args.save:
        fmt = infer_format(args.save, args.format)
        try:
            save_rows(rows, args.save, fmt, args.resolve)
        except OSError as problem:
            print(f"Could not write {args.save}: {problem}", file=sys.stderr)
            return 1
        if not args.quiet:
            print(f"Wrote {len(rows)} link(s) to {args.save} ({fmt})")
    return 1 if failures and not rows else 0


if __name__ == "__main__":
    sys.exit(main())
