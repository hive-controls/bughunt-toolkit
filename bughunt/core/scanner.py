"""Bughunt scan command: option handling, safety rails, the scan engine and the intel passes.

Every outbound action is routed through the policy-enforcing helpers of ``bughunt.core.egress``; the
functions that touch DNS, raw sockets and TLS are decorated with the egress guard so a missing or stale
policy stops them before any network call.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import ipaddress
import itertools
import json
import os
import random
import re
import socket
import ssl
import sys
import time
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlsplit

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from bughunt import VERSION
from bughunt.core import egress, fastmode, identity, route
from bughunt.core import workspace as engagement
from bughunt.core.ledger import redact, redact_bytes, redact_text
from bughunt.core.policy import target_parts
from bughunt.core.report import (  # noqa: F401  (re-exported: other modules and tests import these from here)
    Finding,
    HostReport,
    HttpHit,
    PortResult,
    TlsInfo,
    reports_to_json,
    speaking,
    write_csv,
    write_markdown,
)
from bughunt.core.scope import scope_route, scope_socket  # noqa: F401  (re-exported)

# --------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------

COMMON_PORTS = (
    80,
    81,
    443,
    591,
    2082,
    2083,
    2086,
    2087,
    2095,
    2096,
    3000,
    3001,
    3443,
    4000,
    4172,
    4443,
    4567,
    5000,
    5001,
    5443,
    5601,
    6000,
    6443,
    7000,
    7001,
    7443,
    8000,
    8001,
    8008,
    8010,
    8080,
    8081,
    8088,
    8181,
    8443,
    8484,
    8880,
    8888,
    9000,
    9001,
    9090,
    9091,
    9200,
    9443,
    10000,
    10443,
    12443,
    15672,
    18080,
    28080,
)
ARTIFACT_PATHS = (
    "/robots.txt",
    "/sitemap.xml",
    "/favicon.ico",
    "/.well-known/security.txt",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.hg/requires",
    "/.env",
    "/.env.local",
    "/.htpasswd",
    "/.htaccess",
    "/.DS_Store",
    "/web.config",
    "/crossdomain.xml",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/backup.zip",
    "/backup.tar.gz",
    "/dump.sql",
)
MUTATION_SUFFIXES = (
    ".bak",
    ".old",
    ".orig",
    ".tmp",
    ".temp",
    ".copy",
    ".bak1",
    ".zip",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".7z",
    ".rar",
    ".sql",
    ".sql.gz",
    ".log",
    ".swp",
    ".swo",
    "~",
)
PARAMETER_NAMES = (
    "debug",
    "test",
    "admin",
    "dev",
    "staging",
    "redirect",
    "url",
    "next",
    "return",
    "dest",
    "callback",
    "jsonp",
    "api_key",
    "key",
    "token",
    "id",
    "file",
    "path",
    "page",
    "format",
)
PARAMETER_NAMES_USED = 12

MAX_CIDR_HOSTS = 1024
SOFT_CIDR_HOSTS = 256
MAX_UNAUTHORIZED_PORTS = 4096
MAX_UNAUTHORIZED_SKIP_TCP_PORTS = 1024
MAX_UNAUTHORIZED_PATHS = 400

TITLE_LIMIT = 160
SNIPPET_LIMIT = 180
ERROR_TEXT_LIMIT = 160
BANNER_LIMIT = 200
RETRY_BACKOFF_SECONDS = 0.15

DEFAULT_USER_AGENT = "Bughunt/2.3 (+authorized surface mapping)"
ACCEPT_ANYTHING = "*/*"

SERVER_SCRIPT_EXTENSION = re.compile(
    r"\.(?:php|phtml|asp|aspx|jsp|do|action|cgi)(?:[/?]|$)", re.IGNORECASE
)
API_STYLE_SEGMENT = re.compile(r"/(?:api|graphql|rest|v\d+)(?:[/?]|$)", re.IGNORECASE)

INTERESTING_HEADERS = frozenset(
    {
        "server",
        "x-powered-by",
        "x-generator",
        "x-aspnet-version",
        "x-frame-options",
        "content-security-policy",
        "strict-transport-security",
        "www-authenticate",
        "location",
        "via",
        "x-backend-server",
        "x-drupal-cache",
        "x-served-by",
        "cdn-cache-control",
        "allow",
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    }
)
DEFAULT_PAGE_MARKERS = (
    "welcome to nginx",
    "apache2 ubuntu default",
    "iis windows server",
    "it works!",
)


def _signature(tag: str, *needles: str) -> tuple[str, tuple[str, ...]]:
    return tag, needles or (tag,)


PRODUCT_SIGNATURES = (
    _signature("grafana"),
    _signature("kibana"),
    _signature("jenkins"),
    _signature("phpmyadmin"),
    _signature("tomcat"),
    _signature("weblogic"),
    _signature("webmin"),
    _signature("prometheus"),
    _signature("portainer"),
    _signature("nginx"),
    _signature("apache"),
    _signature("iis", "iis ", "microsoft-iis", "iis windows"),
    _signature("caddy"),
    _signature("traefik"),
    _signature("minio"),
    _signature("rabbitmq"),
    _signature("couchdb"),
    _signature("elasticsearch"),
    _signature("sonarqube"),
    _signature("gitlab"),
    _signature("nextcloud"),
    _signature("wordpress"),
    _signature("drupal"),
)

# Shodan-style favicon hashes (mmh3 of the base64 body) of each project's published favicon file, computed
# directly from the files in the project repositories.
FAVICON_HINTS = {
    "81586312": "Jenkins",
    "-297069493": "Apache Tomcat",
    "-476231906": "phpMyAdmin",
    "892542951": "Zabbix",
    "-1754690812": "Roundcube",
    "-548802532": "Apache Solr",
    "-505044752": "Odoo",
    "1015329088": "Drupal",
    "167837543": "Nextcloud",
    "-1791109565": "Kibana",
    "-1015107330": "RabbitMQ",
    "712297537": "Portainer",
    "1752131761": "Traefik",
    "479413330": "Webmin",
    "-1711538164": "Pi-hole",
    "-513557430": "Mongo Express",
}

_AGENT_PLATFORMS = (
    "Windows NT 10.0; Win64; x64",
    "Macintosh; Intel Mac OS X 10_15_7",
    "X11; Linux x86_64",
)


def _build_agent_pool() -> tuple[str, ...]:
    pool = [DEFAULT_USER_AGENT]
    for build in ("131.0.6778.205", "133.0.6943.98", "135.0.7049.84", "137.0.7151.68"):
        pool += [
            f"Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{build} Safari/537.36"
            for platform in _AGENT_PLATFORMS
        ]
    for version in ("128.0", "132.0", "136.0"):
        pool += [
            f"Mozilla/5.0 ({platform}; rv:{version}) Gecko/20100101 Firefox/{version}"
            for platform in _AGENT_PLATFORMS
        ]
    pool += [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.89 Safari/537.36 Edg/134.0.3124.51",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.7204.50 Safari/537.36 Edg/138.0.3351.55",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 15; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.7151.89 Mobile Safari/537.36",
        "curl/8.7.1",
        "curl/8.11.0",
    ]
    return tuple(pool)


USER_AGENT_POOL = _build_agent_pool()

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
DOH_RECORD_LABELS = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
CT_ENDPOINT = "https://crt.sh/"
CT_NAME_LIMIT = 80
CORS_PROBE_ORIGINS = ("https://bughunt.invalid", "http://127.0.0.1")
SMTP_PORTS = (25, 587, 2525)
HSTS_MIN_SECONDS = 15552000
SECURITY_TXT_OPTIONAL_KEYS = (
    "encryption",
    "policy",
    "canonical",
    "hiring",
    "acknowledgments",
)
# Sensitive artifacts, matched as a real path segment at ANY depth (never a bare substring), so
# /data/backup.zip and /.git-credentials are caught while /old/backup.html and /.envrc are not.
SENSITIVE_EXACT_SEGMENTS = (
    ".git",
    ".svn",
    ".htpasswd",
    ".env",
    ".git-credentials",
    "dump.sql",
)
SENSITIVE_BACKUP_EXTENSIONS = (
    "zip",
    "tar",
    "tar.gz",
    "tgz",
    "gz",
    "bz2",
    "xz",
    "7z",
    "rar",
    "sql",
    "sql.gz",
    "bak",
    "dump",
    "db",
    "sqlite",
)
# Archive / database magic that confirms a real exposure even behind a misreported content-type.
SENSITIVE_ARTIFACT_MAGIC = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",  # zip (also jar / office)
    b"\x1f\x8b",  # gzip
    b"BZh",  # bzip2
    b"\xfd7zXZ\x00",  # xz
    b"7z\xbc\xaf\x27\x1c",  # 7-zip
    b"Rar!\x1a\x07",  # rar
    b"SQLite format 3\x00",  # sqlite database
)
# Leading response bytes retained for soft-404/artifact classification when full bodies are not
# kept (e.g. --discover-only): the magic above sits at offset 0 and the HTML-fallback check reads
# body[:512], so 512 bytes is the whole window _looks_like_exposed_artifact ever inspects.
CLASSIFY_PREFIX_BYTES = 512


# --------------------------------------------------------------------------------------
# Console output (the stream is looked up at print time, never bound at import)
# --------------------------------------------------------------------------------------


_messages: ContextVar[list[str] | None] = ContextVar("scan_messages", default=None)


@contextmanager
def collect_messages() -> Iterator[list[str]]:
    messages: list[str] = []
    token = _messages.set(messages)
    try:
        yield messages
    finally:
        _messages.reset(token)


def emit(message: str = "", style: str = "") -> None:
    messages = _messages.get()
    if messages is not None:
        messages.append(message)
        return
    Console(highlight=False).print(Text(message, style=style), soft_wrap=True)


def show(renderable) -> None:
    if _messages.get() is not None:
        return
    Console(highlight=False).print(renderable)


class InputRejected(ValueError):
    """A scan input or option that the safety rails refuse."""


class _AbortScan(Exception):
    """Raised once the reason has already been printed; scan_main turns it into exit code 2."""


# --------------------------------------------------------------------------------------
# Reading lists and values
# --------------------------------------------------------------------------------------


def read_list_lines(path) -> list[str]:
    location = Path(path).expanduser()
    if not location.is_file():
        raise FileNotFoundError(f"list file not found: {path}")
    text = location.read_bytes().decode("utf-8", errors="replace")
    stripped = (line.strip() for line in text.splitlines())
    return [line for line in stripped if line and not line.startswith("#")]


def lines_if_file(value: str | None) -> list[str] | None:
    """The lines of ``value`` when it names an existing regular file, otherwise None (use it literally)."""
    if not value or any(character in value for character in ",\r\n"):
        return None
    try:
        if Path(value).expanduser().is_file():
            return read_list_lines(value)
    except (OSError, ValueError):
        return None
    return None


def parse_port_spec(spec: str) -> list[int]:
    found: set[int] = set()
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        first_text, dash, last_text = item.partition("-")
        first = int(first_text)
        last = int(last_text) if dash else first
        first, last = min(first, last), max(first, last)
        if first < 1 or last > 65535:
            raise argparse.ArgumentTypeError("ports must be in 1-65535")
        found.update(range(first, last + 1))
    return sorted(found)


def parse_delay(spec: str | None) -> tuple[float, float]:
    text = (spec or "").strip()
    if not text:
        return 0.0, 0.0
    low_text, dash, high_text = text.partition("-")
    low = float(low_text)
    high = float(high_text) if dash else low
    if low < 0 or high < 0:
        raise ValueError("--delay must not be negative")
    return (low, high) if low <= high else (high, low)


def parse_status_set(spec: str | None) -> set[int] | None:
    if not spec:
        return None
    allowed: set[int] = set()
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        low_text, dash, high_text = item.partition("-")
        low = int(low_text)
        allowed.update(range(low, int(high_text) + 1) if dash else [low])
    return allowed


def parse_header_line(line: str) -> tuple[str, str]:
    name, separator, value = line.partition(":")
    name = name.strip()
    if not separator or not name:
        raise ValueError(f"header must look like 'Name: value' (got {line!r})")
    return name, value.strip()


def collect_custom_headers(
    header_args: list[str] | None, headers_file: str | None
) -> dict[str, str]:
    lines: list[str] = []
    for entry in header_args or []:
        from_file = lines_if_file(entry)
        lines.extend(from_file if from_file is not None else [entry])
    if headers_file:
        lines.extend(read_list_lines(headers_file))
    headers: dict[str, str] = {}
    for line in lines:
        name, value = parse_header_line(line)
        headers[name] = value
    return headers


def parse_basic_auth(spec: str | None):
    if not spec:
        return None
    user, separator, password = spec.partition(":")
    if not separator:
        raise InputRejected("--auth must be USER:PASS")
    return httpx.BasicAuth(user, password)


def build_agent_pool(
    user_agent: str | None, agents_file: str | None, randomize: bool
) -> list[str]:
    from_file = lines_if_file(user_agent)
    pool = (
        list(from_file)
        if from_file is not None
        else ([user_agent] if user_agent else [])
    )
    if agents_file:
        pool.extend(read_list_lines(agents_file))
    if pool == [DEFAULT_USER_AGENT] and randomize:
        return list(USER_AGENT_POOL)
    return pool


# --------------------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------------------


def normalize_host(token: str) -> str:
    token = token.strip()
    if not token:
        return ""
    if "://" in token:
        return urlparse(token).hostname or token
    head = token.split("/", 1)[0]
    if head.startswith("["):
        closing = head.find("]")
        return head[1:closing] if closing != -1 else head[1:]
    if is_ip_literal(head):
        return head
    return head.split(":", 1)[0]


def usable_host_count(network) -> int:
    total = network.num_addresses
    if total <= 2:
        return total
    return total - 2 if network.version == 4 else total - 1


def expand_network(token: str, network, authorized: bool) -> list[str]:
    count = usable_host_count(network)
    if count > MAX_CIDR_HOSTS:
        raise InputRejected(
            f"CIDR {token} expands to {count} hosts (hard cap {MAX_CIDR_HOSTS})."
        )
    if count > SOFT_CIDR_HOSTS and not authorized:
        raise InputRejected(
            f"CIDR {token} expands to {count} hosts. Re-run with --authorized only if you own the range."
        )
    return [str(address) for address in network.hosts()]


def expand_target_token(token: str, authorized: bool) -> list[str]:
    candidate = token.strip()
    if "/" in candidate and "://" not in candidate:
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            network = None
        if network is not None:
            return expand_network(candidate, network, authorized)
    return [normalize_host(candidate)]


def collect_targets(
    positional: list[str], targets_file: str | None, authorized: bool
) -> list[str]:
    raw_tokens = list(positional)
    if targets_file:
        raw_tokens.extend(read_list_lines(targets_file))
    if not raw_tokens:
        raise InputRejected("No targets given. Pass hosts or --targets-file.")
    ordered: list[str] = []
    for token in raw_tokens:
        for host in expand_target_token(token, authorized):
            if host and host not in ordered:
                ordered.append(host)
    return ordered


def positional_files(tokens: list[str]) -> list[str]:
    found = []
    for token in tokens:
        if not token.strip() or "://" in token or token.startswith("-"):
            continue
        with suppress(OSError, ValueError):
            if Path(token).expanduser().is_file():
                found.append(token)
    return found


def reject_out_of_scope(targets: list[str]) -> None:
    blocked = [target for target in targets if not engagement.allowed(target)]
    for target in blocked:
        emit(engagement.explain_block(target))
    if blocked:
        raise _AbortScan


# --------------------------------------------------------------------------------------
# Ports
# --------------------------------------------------------------------------------------


def select_ports(args) -> list[int]:
    if args.all:
        ports = list(range(1, 65536))
    elif args.ports:
        ports = parse_port_spec(args.ports)
    elif args.port_range:
        ports = parse_port_spec(args.port_range)
    else:
        ports = list(COMMON_PORTS)
    if args.ports_file:
        listed: set[int] = set()
        for line in read_list_lines(args.ports_file):
            listed.update(parse_port_spec(line))
        if args.all or args.ports or args.port_range:
            ports = sorted(set(ports) | listed)
        elif listed:
            ports = sorted(listed)
    if args.exclude_ports:
        excluded = set(parse_port_spec(args.exclude_ports))
        ports = [port for port in ports if port not in excluded]
    return ports


def enforce_breadth_rails(args, ports: list[int]) -> None:
    if args.authorized:
        return
    if args.all:
        raise InputRejected(
            f"--all would scan {len(ports)} ports. Re-run with --authorized only if you own the target."
        )
    if len(ports) > MAX_UNAUTHORIZED_PORTS:
        raise InputRejected(
            f"Refusing {len(ports)} ports (limit {MAX_UNAUTHORIZED_PORTS}). "
            "Re-run with --authorized only if you own the target."
        )
    if args.skip_tcp and len(ports) > MAX_UNAUTHORIZED_SKIP_TCP_PORTS:
        raise InputRejected(
            f"--skip-tcp on {len(ports)} ports sends HTTP(S) to every one of them. "
            "Re-run with --authorized only if you own the target."
        )


# --------------------------------------------------------------------------------------
# Request paths
# --------------------------------------------------------------------------------------


def normalize_request_path(raw: str) -> str:
    text = raw.strip()
    if not text:
        return "/"
    if text.lower().startswith(("http://", "https://")):
        parts = urlsplit(text)
        return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return text if text.startswith("/") else "/" + text


def unique_in_order(items) -> list:
    seen: set = set()
    ordered = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def assemble_base_paths(paths_arg: str | None, paths_file: str | None) -> list[str]:
    explicit = paths_arg is not None
    from_file = lines_if_file(paths_arg) if explicit else None
    if from_file is not None:
        raw_paths = from_file
    elif explicit:
        raw_paths = [part.strip() for part in paths_arg.split(",") if part.strip()]
    else:
        raw_paths = []
    if paths_file:
        raw_paths = raw_paths + read_list_lines(paths_file)
    paths = unique_in_order(normalize_request_path(item) for item in raw_paths)
    # A --paths-file without an explicit --paths maps exactly its own paths: never inject the host root.
    return paths or ([] if paths_file else ["/"])


def mutation_suffixes(extra_spec: str | None) -> list[str]:
    extras = []
    for item in (extra_spec or "").split(","):
        item = item.strip()
        if item:
            extras.append(item if item.startswith(".") or item == "~" else "." + item)
    return unique_in_order([*MUTATION_SUFFIXES, *extras])


def add_mutated_paths(paths: list[str], suffixes: list[str]) -> list[str]:
    variants = [
        path + suffix
        for path in paths
        if "?" not in path and not path.endswith("/")
        for suffix in suffixes
    ]
    return unique_in_order([*paths, *variants])


def is_endpoint_like(path: str) -> bool:
    return bool(SERVER_SCRIPT_EXTENSION.search(path) or API_STYLE_SEGMENT.search(path))


def with_query_parameter(path: str, name: str, value: str = "1") -> str:
    base, question, query = path.partition("?")
    pairs = dict(parse_qsl(query, keep_blank_values=True)) if question else {}
    pairs[name] = value
    return f"{base}?{urlencode(pairs)}"


def add_parameter_variants(paths: list[str], extra_names: list[str]) -> list[str]:
    names = unique_in_order([*PARAMETER_NAMES[:PARAMETER_NAMES_USED], *extra_names])
    variants = [
        with_query_parameter(path, name)
        for path in paths
        if path == "/" or is_endpoint_like(path)
        for name in names
    ]
    return unique_in_order([*paths, *variants])


def expand_request_paths(
    args, base_paths: list[str], extra_parameter_names: list[str]
) -> list[str]:
    paths = list(base_paths)
    if args.discover:
        paths += [path for path in ARTIFACT_PATHS if path not in paths]
    if args.favicon and "/favicon.ico" not in paths:
        paths.append("/favicon.ico")
    if args.mutate_paths:
        paths = add_mutated_paths(paths, mutation_suffixes(args.mutate_ext))
    if args.params:
        paths = add_parameter_variants(paths, extra_parameter_names)
    paths = unique_in_order(paths)
    if len(paths) > MAX_UNAUTHORIZED_PATHS and not args.authorized:
        raise InputRejected(
            f"Refusing {len(paths)} request paths (limit {MAX_UNAUTHORIZED_PATHS}). "
            "Re-run with --authorized only if you own the target."
        )
    return paths


# --------------------------------------------------------------------------------------
# Argument parser
# --------------------------------------------------------------------------------------


def _switch(parser, *flags: str, help_text: str, dest: str | None = None) -> None:
    kwargs = {"dest": dest} if dest else {}
    parser.add_argument(*flags, action="store_true", help=help_text, **kwargs)


def _value(
    parser,
    *flags: str,
    help_text: str,
    kind=None,
    default=None,
    metavar: str | None = None,
    dest: str | None = None,
) -> None:
    kwargs = {"dest": dest} if dest else {}
    if kind is not None:
        kwargs["type"] = kind
    parser.add_argument(
        *flags, default=default, metavar=metavar, help=help_text, **kwargs
    )


def _add_target_options(parser) -> None:
    parser.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="IPs, hostnames, URLs or CIDR ranges to scan",
    )
    _switch(
        parser,
        "--dry-run",
        help_text="print the policy decision for every planned request and stop",
    )
    _value(
        parser,
        "-l",
        "--targets-file",
        help_text="file with one target per line",
        metavar="FILE",
    )
    selectors = parser.add_mutually_exclusive_group()
    selectors.add_argument(
        "--common",
        action="store_true",
        help="built-in list of common web ports (the default)",
    )
    selectors.add_argument(
        "--ports", metavar="SPEC", help="ports and ranges, e.g. 80,443,8000-8010"
    )
    selectors.add_argument(
        "--range", dest="port_range", metavar="START-END", help="inclusive port range"
    )
    selectors.add_argument(
        "--all", action="store_true", help="every TCP port (needs --authorized)"
    )
    _value(
        parser,
        "--ports-file",
        help_text="file with port specs, one per line",
        metavar="FILE",
    )
    _value(
        parser,
        "--exclude-ports",
        help_text="ports to drop from the final selection",
        metavar="SPEC",
    )
    parser.add_argument(
        "--authorized",
        "--i-own-this",
        dest="authorized",
        action="store_true",
        help="acknowledge ownership to lift the oversize-sweep limits",
    )
    _switch(
        parser,
        "--fast",
        help_text="auto-generate a scoped, verified policy for the target(s) so the "
        "scan passes the egress gate without a manual policy import (requires --authorized)",
    )


def _add_path_options(parser) -> None:
    _value(
        parser,
        "--paths",
        help_text="comma-separated paths, or a file of paths",
        default=None,
    )
    _value(
        parser,
        "--paths-file",
        help_text="file with one path per line (added to --paths)",
        metavar="FILE",
    )
    _value(
        parser,
        "--concurrency",
        help_text="parallel TCP connects",
        kind=int,
        default=256,
    )
    _value(
        parser,
        "--connect-timeout",
        help_text="TCP/TLS connect timeout in seconds",
        kind=float,
        default=1.2,
    )
    _value(
        parser,
        "--http-timeout",
        help_text="HTTP request timeout in seconds",
        kind=float,
        default=4.0,
    )
    _value(
        parser,
        "--delay",
        help_text="wait before each request: seconds or a lo-hi range",
        default="0",
    )
    _switch(parser, "--discover", help_text="also request common artifact paths")
    _switch(
        parser,
        "--mutate-paths",
        help_text="also request backup-style variants of file paths",
    )
    _value(parser, "--mutate-ext", help_text="extra mutation suffixes, comma separated")
    _switch(
        parser,
        "--params",
        help_text="probe common query parameters on endpoint-like paths",
    )
    _value(
        parser,
        "--params-file",
        help_text="extra parameter names, one per line",
        metavar="FILE",
    )


def _add_intel_options(parser) -> None:
    _switch(
        parser,
        "--score-headers",
        help_text="score security headers (keeps response bodies)",
    )
    _switch(parser, "--cors", help_text="run a CORS preflight probe after the scan")
    _switch(
        parser, "--extract-js", help_text="extract URLs and secrets from page bodies"
    )
    _switch(parser, "--favicon", help_text="fetch /favicon.ico and compute its hash")
    _switch(parser, "--dns", help_text="DNS-over-HTTPS record enumeration")
    _switch(parser, "--ct", help_text="certificate-transparency name lookup")
    _switch(
        parser,
        "--banners",
        help_text="read banners from TCP-open ports that do not speak HTTP",
    )
    _value(parser, "--md", help_text="write a Markdown report", metavar="FILE")
    _value(
        parser,
        "--screenshots",
        help_text="capture screenshots of live pages",
        metavar="DIR",
    )
    _switch(
        parser,
        "--intel",
        help_text="shorthand for --discover --score-headers --extract-js --favicon --dns",
    )


def _add_request_options(parser) -> None:
    _value(
        parser, "--retries", help_text="retries per HTTP request", kind=int, default=0
    )
    _switch(parser, "--http-only", help_text="skip HTTPS")
    _switch(parser, "--https-only", help_text="skip HTTP")
    _switch(
        parser,
        "--follow-redirects",
        help_text="refused: unscoped redirects are disabled",
    )
    _switch(parser, "--insecure", help_text="do not verify TLS certificates")
    _switch(parser, "--no-cert", help_text="do not collect TLS metadata")
    _switch(
        parser,
        "--skip-tcp",
        help_text="skip the TCP phase and send HTTP(S) to every selected port",
    )
    parser.add_argument(
        "--method",
        choices=["GET", "HEAD", "OPTIONS", "POST"],
        default="GET",
        help="HTTP method",
    )
    _value(parser, "--host-header", help_text="force the Host header")
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="HEADER",
        help="'Name: value' request header, or a file of them (repeatable)",
    )
    _value(
        parser,
        "--headers-file",
        help_text="file of 'Name: value' lines",
        metavar="FILE",
    )
    _value(parser, "--auth", help_text="HTTP Basic credentials", metavar="USER:PASS")
    _value(
        parser,
        "--user-agent",
        help_text="User-Agent string, or a file of agents",
        default=DEFAULT_USER_AGENT,
    )
    _value(
        parser,
        "--user-agents-file",
        help_text="file with one User-Agent per line",
        metavar="FILE",
    )
    _switch(
        parser,
        "--random-agent",
        help_text="pick one agent from the pool for the whole scan",
    )
    _switch(parser, "--rotate-agent", help_text="pick a random agent for every request")
    _value(parser, "--proxy", help_text="HTTP proxy URL")


def _add_output_options(parser) -> None:
    _value(
        parser,
        "--status",
        help_text="only these status codes count as live (a-b ranges allowed)",
    )
    _value(
        parser,
        "--grep",
        help_text="case-insensitive regex a hit must match to count as live",
    )
    _switch(
        parser,
        "--only-live",
        help_text="hide open ports that did not speak HTTP(S) from the table",
    )
    _value(parser, "--save-urls", help_text="append live URLs to FILE", metavar="FILE")
    _value(
        parser,
        "--save-source",
        help_text="write live response bodies into DIR",
        metavar="DIR",
    )
    _value(
        parser,
        "--save-headers",
        help_text="write live response header summaries into DIR",
        metavar="DIR",
    )
    _value(
        parser,
        "--output-dir",
        help_text="fill every unset output option under DIR",
        metavar="DIR",
    )
    _value(
        parser,
        "--max-body",
        help_text="max body bytes kept per response",
        kind=int,
        default=262144,
    )
    _value(parser, "--json", help_text="write the JSON report", metavar="FILE")
    _value(parser, "--csv", help_text="write the CSV report", metavar="FILE")
    _switch(parser, "--quiet", help_text="skip the startup banner")


def build_parser(prog: str = "bughunt") -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=prog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Bughunt scan, map HTTP/HTTPS attack surface on authorized hosts",
        epilog=(
            f"examples:\n  {prog} 10.0.0.5 --ports 80,443,8080\n  {prog} app.example --intel --output-dir out\n"
            f"  {prog} -l hosts.txt --common --status 200,401 --csv scan.csv\n  {prog} app.example --dry-run --quiet"
        ),
    )
    parser.add_argument("--version", action="version", version=f"Bughunt {VERSION}")
    _add_target_options(parser)
    _add_path_options(parser)
    _add_intel_options(parser)
    _add_request_options(parser)
    _add_output_options(parser)
    return parser


# --------------------------------------------------------------------------------------
# Policy-gated network primitives
# --------------------------------------------------------------------------------------


def _host_grant(call) -> list[str]:
    return [egress.host_target(call["host"], "active_scan")]


def _host_port_grant(call) -> list[str]:
    return [egress.host_target(call["host"], "active_scan", call["port"])]


def _tls_endpoint_grant(call) -> list[str]:
    return [egress.endpoint(call["host"], call["port"])]


@egress.guarded("active_scan", _host_grant)
def resolve_host(host):
    addresses: list[str] = []
    for entry in socket.getaddrinfo(host, None):
        address = entry[4][0]
        if address not in addresses:
            addresses.append(address)
    return addresses


async def _close_writer(writer) -> None:
    writer.close()
    with suppress(Exception):
        await writer.wait_closed()


_LOOP_GRACE_ITERATIONS = (
    8  # loop iterations, not seconds — see the comment in tcp_probe
)


async def _reap(task) -> None:
    """Await a cancelled probe task so its socket is reaped; re-raise only an OUTER cancellation."""
    try:
        await task
    except asyncio.CancelledError:
        current = asyncio.current_task()
        if current is not None and current.cancelling():
            raise
    except Exception:
        pass


async def _settle_connect(task, timeout) -> bool:
    """Wait for a connect task up to `timeout`, then give it a bounded loop-iteration grace; True when it finished.

    On False the task has been cancelled and reaped (the caller reports a timeout).
    """
    await asyncio.wait({task}, timeout=timeout)
    # A due connect-timeout timer and the connect completion can land in the same event-loop ready
    # batch when the loop has been stalled (synchronous egress work under high --concurrency). After
    # its socket connects, open_connection still needs a few call_soon hops to build the transport
    # (measured 3 on the proactor loop, 4 on a selector loop, CPython 3.14); cancelling in that window
    # reports an open port as a timeout. Yield up to this many loop iterations before concluding a
    # timeout — on an idle loop each iteration costs microseconds.
    for _ in range(_LOOP_GRACE_ITERATIONS):
        if task.done():
            break
        await asyncio.sleep(0)
    if not task.done():
        task.cancel()
        await _reap(task)
        return False
    return True


@egress.guarded("active_scan", _host_port_grant)
async def tcp_probe(host, port, timeout):
    task = asyncio.ensure_future(asyncio.open_connection(host, port))
    try:
        if not await _settle_connect(task, timeout):
            return False, "timeout"
        _reader, writer = task.result()
    except ConnectionRefusedError:
        return False, "refused"
    except OSError as exc:
        return False, exc.strerror or str(exc)
    except Exception as exc:
        return False, str(exc)
    finally:
        if not task.done():
            task.cancel()
    await _close_writer(writer)
    return True, ""


def _banner_greeting(port: int) -> bytes:
    if port in SMTP_PORTS:
        return b"EHLO bughunt.local\r\n"
    if port == 6379:
        return b"PING\r\n"
    return b""


@egress.guarded("active_scan", _host_port_grant)
async def banner_grab(host, port, timeout):
    task = asyncio.ensure_future(asyncio.open_connection(host, port))
    try:
        if not await _settle_connect(task, timeout):
            return ""
        reader, writer = task.result()
    except Exception:
        return ""
    finally:
        if not task.done():
            task.cancel()
    data = b""
    try:
        greeting = _banner_greeting(port)
        if greeting:
            writer.write(greeting)
            await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout)
    except Exception:
        data = b""
    finally:
        await _close_writer(writer)
    flattened = (
        data.decode("utf-8", errors="replace").replace("\r", " ").replace("\n", " ")
    )
    return flattened.strip()[:BANNER_LIMIT]


def _describe_certificate(certificate: bytes) -> dict:
    from bughunt.modules.cert import parse_certificate

    if not certificate:
        return {}
    parsed = parse_certificate(certificate)
    expired = False
    with suppress(ValueError):
        expiry = datetime.fromisoformat(parsed.not_after)
        expired = expiry < datetime.now(timezone.utc)
    return {
        "subject": parsed.subject,
        "issuer": parsed.issuer,
        "not_before": parsed.not_before,
        "not_after": parsed.not_after,
        "san": parsed.names[:12],
        "expired": expired,
    }


@egress.guarded("active_scan", _tls_endpoint_grant)
def collect_tls_info(host, port, timeout):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as secured:
                cipher = secured.cipher()
                info = TlsInfo(
                    version=secured.version() or "", cipher=cipher[0] if cipher else ""
                )
                for name, value in _describe_certificate(
                    secured.getpeercert(binary_form=True)
                ).items():
                    setattr(info, name, value)
                return info
    except Exception as exc:
        return TlsInfo(error=str(exc)[:ERROR_TEXT_LIMIT])


async def gather_tls_info(host: str, port: int, timeout: float) -> TlsInfo:
    try:
        return await asyncio.to_thread(collect_tls_info, host, port, timeout)
    except Exception as exc:
        return TlsInfo(error=str(exc)[:ERROR_TEXT_LIMIT])


# --------------------------------------------------------------------------------------
# One HTTP probe
# --------------------------------------------------------------------------------------


def error_hit(scheme, url, started, error):
    return HttpHit(
        scheme=scheme,
        url=url,
        final_url=url,
        status=None,
        reason="",
        server="",
        powered_by="",
        content_type="",
        location="",
        title="",
        snippet="",
        bytes_read=0,
        sha256="",
        elapsed_ms=(time.perf_counter() - started) * 1000,
        error=error,
    )


_TITLE_ELEMENT = re.compile(
    r"<title(?:\s[^>]*)?>(.*?)</title>", re.IGNORECASE | re.DOTALL
)
_SCRIPT_OR_STYLE_BLOCK = re.compile(
    r"<(script|style)\b.*?</\1\s*>", re.IGNORECASE | re.DOTALL
)
_ANY_TAG = re.compile(r"<[^>]*>")


def collapse_whitespace(text: str) -> str:
    return " ".join(text.split())


def extract_title(body: bytes) -> str:
    found = _TITLE_ELEMENT.search(body.decode("utf-8", errors="ignore"))
    return collapse_whitespace(found.group(1))[:TITLE_LIMIT] if found else ""


def extract_snippet(body: bytes, content_type: str) -> str:
    if not body:
        return ""
    text = collapse_whitespace(body.decode("utf-8", errors="replace"))
    if "html" in content_type.lower() or text.startswith("<"):
        without_blocks = _SCRIPT_OR_STYLE_BLOCK.sub(" ", text)
        plain = collapse_whitespace(_ANY_TAG.sub(" ", without_blocks))
        if plain:
            text = plain
    return text[:SNIPPET_LIMIT]


def classify_response(
    status, title: str, server: str, snippet: str, body: bytes
) -> list[str]:
    tags = []
    if status == 401:
        tags.append("auth-required")
    if status == 403:
        tags.append("forbidden")
    if status is not None and 300 <= status < 400:
        tags.append("redirect")
    if status is not None and status >= 500:
        tags.append("server-error")
    blob = "\n".join(
        [title, server, snippet, body[:2000].decode("utf-8", errors="replace")]
    ).lower()
    if "index of /" in blob or "directory listing" in blob:
        tags.append("dir-listing")
    if any(marker in blob for marker in DEFAULT_PAGE_MARKERS):
        tags.append("default-page")
    for tag, needles in PRODUCT_SIGNATURES:
        if any(needle in blob for needle in needles):
            tags.append(tag)
            break
    return tags


def select_headers(headers) -> dict[str, str]:
    selected = {
        name: value
        for name, value in headers.items()
        if name in INTERESTING_HEADERS or name.startswith("x-")
    }
    cookies = headers.get_list("set-cookie")
    if cookies:
        selected["set-cookie"] = "\n".join(cookies)
    return selected


def build_hit(
    response,
    scheme: str,
    url: str,
    started: float,
    method: str,
    keep_body: bool,
    max_body: int,
    analyze: bool = False,
) -> HttpHit:
    full_body = response.content
    stored = full_body[:max_body]
    content_type = response.headers.get("content-type", "").split(";")[0].strip()
    server = response.headers.get("server", "")
    title = extract_title(stored)
    snippet = extract_snippet(stored, content_type)
    tags = classify_response(response.status_code, title, server, snippet, stored)
    allow = response.headers.get("allow")
    if method == "OPTIONS" and allow:
        tags.append("allow:" + allow.replace(" ", ""))
    return HttpHit(
        scheme=scheme,
        url=url,
        final_url=str(response.url),
        status=response.status_code,
        reason=response.reason_phrase or "",
        server=server,
        powered_by=response.headers.get("x-powered-by", ""),
        content_type=content_type,
        location=response.headers.get("location", ""),
        title=title,
        snippet=snippet,
        bytes_read=len(full_body),
        sha256=hashlib.sha256(full_body).hexdigest()[:16] if full_body else "",
        elapsed_ms=(time.perf_counter() - started) * 1000,
        tags=tags,
        headers=select_headers(response.headers),
        body=stored if keep_body else b"",
        body_prefix=stored[:CLASSIFY_PREFIX_BYTES]
        if analyze and not keep_body
        else b"",
    )


def _shorten_error(exc: Exception) -> str:
    text = str(exc)
    return (
        text[: ERROR_TEXT_LIMIT - 3] + "..." if len(text) > ERROR_TEXT_LIMIT else text
    )


async def fetch_once(
    client,
    method: str,
    scheme: str,
    host: str,
    port: int,
    path: str,
    keep_body: bool,
    max_body: int,
    retries: int,
    request_headers: dict | None,
    analyze: bool = False,
) -> HttpHit:
    url = egress.endpoint(host, port, scheme=scheme, path=path)
    started = time.perf_counter()
    attempts = max(1, retries + 1)
    last_error = ""
    free_connect_retry_left = (
        True  # a ConnectTimeout sent no bytes; a stalled event loop can fake one
    )
    attempt = 0
    while attempt < attempts:
        attempt += 1
        try:
            response = await client.request(method, url, headers=request_headers)
            return build_hit(
                response, scheme, url, started, method, keep_body, max_body, analyze
            )
        except egress.PolicyBlocked as exc:
            hit = error_hit(scheme, url, started, _shorten_error(exc))
            hit.tags.append("policy-blocked")
            return hit
        except httpx.ConnectTimeout:
            last_error = "timeout"
            if free_connect_retry_left:
                free_connect_retry_left = False
                attempt -= 1  # this attempt does not count against --retries
                continue
        except httpx.TimeoutException:
            last_error = "timeout"
        except ssl.SSLError as exc:
            return error_hit(scheme, url, started, f"ssl: {exc}")
        except httpx.ConnectError as exc:
            last_error = f"connect: {exc}"
        except Exception as exc:
            last_error = _shorten_error(exc)
        if attempt < attempts:
            await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)
    return error_hit(scheme, url, started, last_error)


# --------------------------------------------------------------------------------------
# Artifact files
# --------------------------------------------------------------------------------------


def _sanitize_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text)


def artifact_stem(host: str, port: int, scheme: str, url: str) -> str:
    path_part = urlsplit(url).path.strip("/") or "root"
    return (
        f"{_sanitize_name(host)[:80]}_{port}_{scheme}_{_sanitize_name(path_part)[:60]}"
    )


def body_extension(content_type: str, body: bytes) -> str:
    kind = content_type.lower()
    lead = body.lstrip()
    if "json" in kind or lead.startswith(b"{"):
        return ".json"
    if (
        "html" in kind
        or lead[:32].lower().startswith(b"<!doctype")
        or b"<html" in body[:400].lower()
    ):
        return ".html"
    for marker, extension in (
        ("xml", ".xml"),
        ("javascript", ".js"),
        ("css", ".css"),
        ("text/", ".txt"),
    ):
        if marker in kind:
            return extension
    return ".bin"


class ArtifactSink:
    """Writes live URLs, response bodies and header summaries, redacting secrets on the way out."""

    def __init__(self, urls_path, source_dir, header_dir):
        self.seen_urls: set[str] = set()
        self._source_dir = Path(source_dir) if source_dir else None
        self._header_dir = Path(header_dir) if header_dir else None
        self._url_handle = None
        if urls_path:
            location = Path(urls_path)
            location.parent.mkdir(parents=True, exist_ok=True)
            self._url_handle = location.open("a", encoding="utf-8")
        for directory in (self._source_dir, self._header_dir):
            if directory is not None:
                directory.mkdir(parents=True, exist_ok=True)

    def close(self) -> None:
        if self._url_handle is not None:
            self._url_handle.close()
            self._url_handle = None

    def capture(self, host, port, hit) -> None:
        if not speaking(hit):
            return
        live_url = hit.final_url or hit.url
        self._record_url(live_url)
        stem = artifact_stem(host, port, hit.scheme, hit.url)
        if self._source_dir is not None and hit.body:
            extension = body_extension(hit.content_type, hit.body)
            (self._source_dir / f"{stem}{extension}").write_bytes(
                redact_bytes(hit.body)
            )
        if self._header_dir is not None:
            (self._header_dir / f"{stem}.headers.txt").write_text(
                redact_text(self._header_summary(hit)), encoding="utf-8"
            )

    def _record_url(self, live_url: str) -> None:
        if self._url_handle is None or live_url in self.seen_urls:
            return
        self.seen_urls.add(live_url)
        self._url_handle.write(redact_text(live_url) + "\n")
        self._url_handle.flush()

    @staticmethod
    def _header_summary(hit) -> str:
        lines = [
            f"URL: {hit.url}",
            f"Final-URL: {hit.final_url}",
            f"Status: {hit.status} {hit.reason}".rstrip(),
            f"SHA256-16: {hit.sha256}",
            "",
        ]
        lines += [f"{name}: {value}" for name, value in hit.headers.items()]
        return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------
# The scan engine
# --------------------------------------------------------------------------------------


@dataclass
class HttpSettings:
    """Everything one host's HTTP phase needs besides the port results."""

    target: str
    schemes: list[str]
    paths: list[str]
    method: str
    keep_body: bool
    max_body: int
    retries: int
    rotate_agents: list[str]
    collect_certs: bool
    connect_timeout: float
    jitter: "Jitter"
    gate: asyncio.Semaphore
    analyze: bool = False


class Jitter:
    """Random pause drawn from [low, high] seconds; a zero ceiling means no pause."""

    def __init__(self, low: float, high: float):
        self.low, self.high = low, high

    async def pause(self) -> None:
        if self.high > 0:
            await asyncio.sleep(random.uniform(self.low, self.high))


@contextmanager
def progress_ticker(total: int, label: str):
    console = Console(highlight=False)
    if _messages.get() is not None or not console.is_terminal:
        yield lambda: None
        return
    columns = (
        TextColumn("{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
    )
    with Progress(*columns, console=console, transient=True) as progress:
        task = progress.add_task(label, total=total)
        yield lambda: progress.advance(task)


def _clamped_concurrency(requested: int) -> int:
    """Cap the fan-out at the workspace profile's concurrency; egress still enforces its own cap per call."""
    try:
        return max(1, min(requested, egress.current_profile().concurrency))
    except egress.PolicyBlocked:
        return requested


async def probe_ports(
    target: str,
    ports: list[int],
    timeout: float,
    concurrency: int,
    jitter: Jitter,
    skip_tcp: bool,
) -> list[PortResult]:
    if skip_tcp:
        emit(
            f"skip-tcp treating {len(ports)} port(s) as open for HTTP(S) only",
            style="yellow",
        )
        return [PortResult(port, True) for port in ports]
    gate = asyncio.Semaphore(concurrency)
    with progress_ticker(len(ports), "TCP connect") as tick:

        async def probe(port: int) -> PortResult:
            async with gate:
                await jitter.pause()
                opened, error = await tcp_probe(target, port, timeout)
            tick()
            return PortResult(port, opened, tcp_error=error)

        return list(await asyncio.gather(*(probe(port) for port in ports)))


def build_client_options(
    concurrency: int,
    http_timeout: float,
    connect_timeout: float,
    follow_redirects: bool,
    verify_tls: bool,
    user_agents: list[str],
    host_header,
    custom_headers: dict,
    proxy,
    auth,
) -> dict:
    headers = {
        "User-Agent": user_agents[0] if user_agents else DEFAULT_USER_AGENT,
        "Accept": ACCEPT_ANYTHING,
    }
    headers.update(custom_headers)
    if host_header:
        headers["Host"] = host_header
    options = {
        "follow_redirects": follow_redirects,
        "verify": verify_tls,
        "http2": False,
        "auth": auth,
        "timeout": httpx.Timeout(http_timeout, connect=connect_timeout),
        "limits": httpx.Limits(
            max_connections=max(8, concurrency // 2),
            max_keepalive_connections=max(4, concurrency // 4),
        ),
        "headers": headers,
    }
    if proxy:
        options["proxy"] = proxy
    return options


async def run_http_job(
    client, settings: HttpSettings, port_result: PortResult, scheme: str, path: str
) -> HttpHit:
    request_headers = (
        {"User-Agent": random.choice(settings.rotate_agents)}
        if settings.rotate_agents
        else None
    )
    async with settings.gate:
        await settings.jitter.pause()
        hit = await fetch_once(
            client,
            settings.method,
            scheme,
            settings.target,
            port_result.port,
            path,
            settings.keep_body,
            settings.max_body,
            settings.retries,
            request_headers,
            settings.analyze,
        )
    wants_tls = (
        settings.collect_certs
        and scheme == "https"
        and (hit.status is not None or "ssl" in hit.error.lower())
    )
    if wants_tls:
        hit.tls = await gather_tls_info(
            settings.target, port_result.port, settings.connect_timeout
        )
        if hit.tls.expired:
            hit.tags.append("expired-cert")
    return hit


def passes_filters(hit, status_allow, grep) -> bool:
    if not speaking(hit):
        return False
    if status_allow and hit.status not in status_allow:
        return False
    if grep is not None:
        searchable = " ".join(
            [hit.title, hit.snippet, hit.server, hit.powered_by, hit.error]
        )
        return grep.search(searchable) is not None
    return True


def apply_filters(port_results: list[PortResult], status_allow, grep) -> None:
    if not status_allow and grep is None:
        return
    for port_result in port_results:
        for hit in port_result.hits:
            if hit.status is not None and not passes_filters(hit, status_allow, grep):
                hit.tags.append("filtered")


async def scan_host(
    target,
    ports,
    connect_timeout,
    http_timeout,
    concurrency,
    paths,
    follow_redirects,
    try_http,
    try_https,
    verify_tls,
    user_agents,
    rotate_agent,
    host_header,
    custom_headers,
    collect_certs,
    keep_body,
    max_body,
    delay_lo,
    delay_hi,
    proxy,
    sink,
    status_allow,
    grep,
    skip_tcp,
    method,
    retries,
    auth,
    analyze=False,
):
    concurrency = _clamped_concurrency(concurrency)
    jitter = Jitter(delay_lo, delay_hi)
    results = await probe_ports(
        target, ports, connect_timeout, concurrency, jitter, skip_tcp
    )
    open_results = [entry for entry in results if entry.tcp_open]
    if not open_results:
        return results
    settings = HttpSettings(
        target=target,
        schemes=[
            name
            for name, wanted in (("http", try_http), ("https", try_https))
            if wanted
        ],
        paths=list(paths),
        method=method,
        keep_body=keep_body,
        max_body=max_body,
        retries=retries,
        rotate_agents=list(user_agents) if rotate_agent and user_agents else [],
        collect_certs=collect_certs,
        connect_timeout=connect_timeout,
        jitter=jitter,
        gate=asyncio.Semaphore(max(4, concurrency // 2)),
        analyze=analyze,
    )
    options = build_client_options(
        concurrency,
        http_timeout,
        connect_timeout,
        follow_redirects,
        verify_tls,
        user_agents,
        host_header,
        custom_headers,
        proxy,
        auth,
    )
    jobs = [
        (entry, scheme, path)
        for entry in open_results
        for scheme in settings.schemes
        for path in settings.paths
    ]
    async with egress.async_client(operation="active_scan", **options) as client:
        hits = await asyncio.gather(
            *(
                run_http_job(client, settings, entry, scheme, path)
                for entry, scheme, path in jobs
            )
        )
    for (entry, _scheme, _path), hit in zip(jobs, hits):
        entry.hits.append(hit)
    apply_filters(open_results, status_allow, grep)
    if sink is not None:
        for entry in open_results:
            for hit in entry.hits:
                if "filtered" not in hit.tags:
                    sink.capture(target, entry.port, hit)
    return results


# --------------------------------------------------------------------------------------
# Favicon hashing
# --------------------------------------------------------------------------------------

_UINT32 = 0xFFFFFFFF


def _rotate_left(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & _UINT32


def _scramble_block(block: int) -> int:
    block = (block * 0xCC9E2D51) & _UINT32
    return (_rotate_left(block, 15) * 0x1B873593) & _UINT32


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 (x86, 32-bit) returned as a signed integer."""
    state = seed & _UINT32
    body_length = len(data) & ~3
    for offset in range(0, body_length, 4):
        state ^= _scramble_block(int.from_bytes(data[offset : offset + 4], "little"))
        state = (_rotate_left(state, 13) * 5 + 0xE6546B64) & _UINT32
    remainder = data[body_length:]
    if remainder:
        state ^= _scramble_block(int.from_bytes(remainder, "little"))
    state ^= len(data)
    state = ((state ^ (state >> 16)) * 0x85EBCA6B) & _UINT32
    state = ((state ^ (state >> 13)) * 0xC2B2AE35) & _UINT32
    state ^= state >> 16
    return state - (1 << 32) if state & 0x80000000 else state


def favicon_hash(body: bytes) -> int:
    """The Shodan-style favicon fingerprint: murmur3 of the MIME-style base64 text of the file."""
    return murmur3_32(base64.encodebytes(body))


# --------------------------------------------------------------------------------------
# Analysis pass
# --------------------------------------------------------------------------------------

MISSING_HEADER_RULES = (
    (
        "strict-transport-security",
        "medium",
        "Missing HSTS",
        "Missing HSTS (HTTPS only)",
    ),
    (
        "content-security-policy",
        "medium",
        "Missing CSP",
        "Missing Content-Security-Policy",
    ),
    (
        "x-frame-options",
        "low",
        "Missing X-Frame-Options",
        "Missing X-Frame-Options (clickjacking)",
    ),
    (
        "x-content-type-options",
        "low",
        "Missing X-Content-Type-Options",
        "Missing X-Content-Type-Options",
    ),
    ("referrer-policy", "info", "Missing Referrer-Policy", "Missing Referrer-Policy"),
    (
        "permissions-policy",
        "info",
        "Missing Permissions-Policy",
        "Missing Permissions-Policy",
    ),
)
_HSTS_MAX_AGE = re.compile(r"max-age=(\d+)", re.IGNORECASE)
_SCRIPT_SRC = re.compile(
    r"""<script\b[^>]*?\bsrc\s*=\s*(["'])(.*?)\1""", re.IGNORECASE | re.DOTALL
)
_CALL_ARGUMENT = re.compile(
    r"""(?:fetch|axios|jQuery\.ajax|\.ajax|\.get|\.post|\.put|\.delete)\s*\(\s*["']([^"']+)["']"""
)
_QUOTED_URL = re.compile(r"""["']((?:https?:)?//[^"'\s]+)["']""")
_QUOTED_PATH = re.compile(r"""["'](/[A-Za-z0-9_\-./]{3,120})["']""")
_SECRET_ASSIGNMENT = re.compile(
    r"""(api[_-]?key|secret|token|password|auth)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{8,})["']""",
    re.IGNORECASE,
)
JS_URL_LIMIT = 80
JS_SECRET_LIMIT = 8
API_PATH_MARKERS = ("/api", "/v1", "/v2", "/graphql", "/rest", "/admin")
_JS_BASE_TEMPLATE = re.compile(
    r"\$\{[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\}(/[A-Za-z0-9_./-]{3,120})",
    re.ASCII,
)
JS_TEMPLATE_TEXT_LIMIT = 8 * 1024 * 1024
JS_TEMPLATE_LENGTH_LIMIT = 512


def hsts_findings(url: str, value: str) -> list[Finding]:
    findings = []
    max_age = _HSTS_MAX_AGE.search(value)
    if max_age and int(max_age.group(1)) < HSTS_MIN_SECONDS:
        findings.append(
            Finding(
                "low",
                "Short HSTS max-age",
                "max-age is under 180 days",
                url=url,
                evidence=value[:80],
            )
        )
    if "includesubdomains" not in value.lower():
        findings.append(
            Finding("info", "HSTS without includeSubDomains", value[:80], url=url)
        )
    return findings


def cookie_findings(hit, set_cookie_value: str) -> list[Finding]:
    findings = []
    for cookie in set_cookie_value.split("\n"):
        cookie = cookie.strip()
        if "=" not in cookie:
            continue
        name = cookie.split("=", 1)[0].strip()
        attributes = {
            part.strip().partition("=")[0].lower(): part.strip()
            .partition("=")[2]
            .strip()
            .lower()
            for part in cookie.split(";")[1:]
            if part.strip()
        }
        detail = cookie[:120]
        if hit.scheme == "https" and "secure" not in attributes:
            findings.append(
                Finding(
                    "medium",
                    f"Cookie '{name}' missing Secure",
                    detail,
                    url=hit.url,
                    evidence=name,
                )
            )
        if "httponly" not in attributes:
            findings.append(
                Finding(
                    "low",
                    f"Cookie '{name}' missing HttpOnly",
                    detail,
                    url=hit.url,
                    evidence=name,
                )
            )
        if "samesite" not in attributes:
            findings.append(
                Finding(
                    "low",
                    f"Cookie '{name}' missing SameSite",
                    detail,
                    url=hit.url,
                    evidence=name,
                )
            )
        elif attributes["samesite"] == "none" and "secure" not in attributes:
            findings.append(
                Finding(
                    "medium",
                    f"Cookie '{name}' SameSite=None without Secure",
                    detail,
                    url=hit.url,
                )
            )
    return findings


def header_findings(hit) -> list[Finding]:
    present = {name.lower(): value for name, value in hit.headers.items()}
    https = hit.scheme == "https"
    findings = [
        Finding(severity, title, detail, url=hit.url)
        for header, severity, title, detail in MISSING_HEADER_RULES
        if header not in present and (https or header != "strict-transport-security")
    ]
    if present.get("access-control-allow-origin") == "*":
        findings.append(
            Finding(
                "medium",
                "CORS allows any origin",
                "Access-Control-Allow-Origin: *",
                url=hit.url,
                evidence="*",
            )
        )
    if https and present.get("strict-transport-security"):
        findings += hsts_findings(hit.url, present["strict-transport-security"])
    if "set-cookie" in present:
        findings += cookie_findings(hit, present["set-cookie"])
    return findings


def parse_security_txt(body: bytes) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    for line in body.decode("utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, _, value = stripped.partition(":")
        fields.setdefault(key.strip().lower(), []).append(value.strip())
    return fields


def _expires_findings(url: str, values: list[str]) -> list[Finding]:
    if not values:
        return [
            Finding(
                "low",
                "security.txt missing Expires",
                "RFC 9116 recommends an Expires field",
                url=url,
            )
        ]
    raw = values[0]
    text = raw[:-1] + "+00:00" if raw.endswith(("Z", "z")) else raw
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return [Finding("low", "security.txt Expires not ISO-8601", raw, url=url)]
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    if moment < datetime.now(timezone.utc):
        return [
            Finding(
                "medium",
                "security.txt expired",
                f"Expires: {raw}",
                url=url,
                evidence=raw,
            )
        ]
    return [Finding("info", "security.txt Expires", raw, url=url)]


def security_txt_findings(hit) -> list[Finding]:
    fields = parse_security_txt(hit.body)
    contacts = fields.get("contact", [])
    if contacts:
        findings = [
            Finding(
                "info",
                "security.txt present",
                "Contact: " + ", ".join(contacts[:4]),
                url=hit.url,
                evidence="; ".join(contacts[:3]),
            )
        ]
    else:
        findings = [
            Finding(
                "low",
                "security.txt missing Contact",
                "RFC 9116 requires at least one Contact field",
                url=hit.url,
            )
        ]
    findings += _expires_findings(hit.url, fields.get("expires", []))
    for key in SECURITY_TXT_OPTIONAL_KEYS:
        if fields.get(key):
            findings.append(
                Finding(
                    "info",
                    f"security.txt {key}",
                    ", ".join(fields[key][:3]),
                    url=hit.url,
                )
            )
    return findings


def _script_template_literals(text: str):
    position = 0
    while position < len(text):
        if text.startswith("//", position) or text.startswith("/*", position):
            block_comment = text[position + 1] == "*"
            end = text.find("*/" if block_comment else "\n", position + 2)
            if end < 0:
                return
            position = end + (2 if block_comment else 1)
            continue
        delimiter = text[position]
        if delimiter not in "\"'`":
            position += 1
            continue
        start = position
        position += 1
        while position < len(text) and text[position] != delimiter:
            position += 2 if text[position] == "\\" else 1
        if position >= len(text):
            return
        position += 1
        if delimiter == "`":
            yield text[start:position]


def _template_script_intel(base_url: str, text: str) -> tuple[list[str], list[Finding]]:
    urls = []
    unresolved = {}
    for literal in _script_template_literals(text[:JS_TEMPLATE_TEXT_LIMIT]):
        if len(literal) > JS_TEMPLATE_LENGTH_LIMIT:
            continue
        reference = literal[1:-1]
        if "\\" in reference or any(character.isspace() for character in reference):
            continue
        template = _JS_BASE_TEMPLATE.fullmatch(reference)
        if template and not template.group(1).startswith("//"):
            suffix = template.group(1).lower()
            if "submissions" in suffix.split("/") or any(
                marker in suffix for marker in API_PATH_MARKERS
            ):
                unresolved.setdefault(reference, None)
        elif "$" not in reference:
            try:
                parsed = urlsplit(reference)
            except ValueError:
                continue
            if parsed.scheme in ("http", "https") and parsed.netloc:
                if not parsed.username and not parsed.password:
                    urls.append(reference)
            elif re.fullmatch(r"/[A-Za-z0-9_./-]{3,120}", reference):
                if not reference.startswith("//") and any(
                    marker in reference.lower() for marker in API_PATH_MARKERS
                ):
                    urls.append(urljoin(base_url, reference))
        if len(unresolved) >= JS_URL_LIMIT or len(urls) >= JS_URL_LIMIT:
            break
    findings = [
        Finding(
            "info",
            "Unresolved JavaScript route template",
            "Literal route suffix references an unresolved JavaScript base; no URL inferred",
            url=base_url,
            evidence=reference,
        )
        for reference in unresolved
    ]
    return urls, findings


def extract_script_intel(base_url: str, text: str) -> tuple[list[str], list[Finding]]:
    """URLs referenced by a page or script, plus findings for key-like assignments."""
    found = [urljoin(base_url, match.group(2)) for match in _SCRIPT_SRC.finditer(text)]
    found += [
        urljoin(base_url, match.group(1)) for match in _CALL_ARGUMENT.finditer(text)
    ]
    for match in _QUOTED_URL.finditer(text):
        reference = match.group(1)
        found.append("https:" + reference if reference.startswith("//") else reference)
    for match in _QUOTED_PATH.finditer(text):
        if any(marker in match.group(1).lower() for marker in API_PATH_MARKERS):
            found.append(urljoin(base_url, match.group(1)))
    findings = [
        Finding(
            "high",
            "Possible secret in JavaScript/HTML",
            f"Key-like assignment for '{match.group(1)}'",
            url=base_url,
            evidence=f"{match.group(1)}=***",
        )
        for match in itertools.islice(
            _SECRET_ASSIGNMENT.finditer(text), JS_SECRET_LIMIT
        )
    ]
    template_urls, template_findings = _template_script_intel(base_url, text)
    return unique_in_order(found + template_urls)[
        :JS_URL_LIMIT
    ], findings + template_findings


def _record_favicon(report: HostReport, hit) -> None:
    fingerprint = str(favicon_hash(hit.body))
    report.favicon_hash = fingerprint
    report.favicon_hint = FAVICON_HINTS.get(fingerprint, "")
    hit.tags.append(f"favicon:{fingerprint}")


def _hits_sensitive_path(path: str) -> bool:
    """A sensitive artifact reached as a path segment at any depth, not an incidental substring."""
    for segment in path.split("/"):
        if segment in SENSITIVE_EXACT_SEGMENTS or segment.startswith(".env."):
            return True
        stem, dot, extension = segment.partition(".")
        if stem == "backup" and dot and extension in SENSITIVE_BACKUP_EXTENSIONS:
            return True
    return False


def _looks_like_exposed_artifact(hit) -> bool:
    """A sensitive-path 200/206 is a real exposure unless the BODY itself is an HTML fallback (soft-404).

    The content-type header is server-controlled, so it never downgrades on its own: a plaintext secret
    labelled text/html stays HIGH, while a genuine HTML body is a soft-404 whatever its path depth.

    When full bodies are not kept (e.g. --discover-only), ``body_prefix`` holds the bounded leading
    bytes retained under analysis so this check still fires.
    """
    body = hit.body or hit.body_prefix or b""
    if body.startswith(SENSITIVE_ARTIFACT_MAGIC):
        return True
    if body[:512].lstrip().lower().startswith((b"<!doctype html", b"<html")):
        return False
    return bool(body.strip()) or bool(hit.content_type)


def analyze_hit(report: HostReport, hit) -> list[Finding]:
    path = urlparse(hit.url).path.lower()
    status = hit.status
    below_400 = status is not None and status < 400
    findings: list[Finding] = []
    if below_400 and (path in ("", "/") or "text/html" in hit.content_type.lower()):
        findings += header_findings(hit)
    elif "set-cookie" in hit.headers:
        findings += cookie_findings(hit, hit.headers["set-cookie"])
    if path.endswith("security.txt") and below_400 and hit.body:
        findings += security_txt_findings(hit)
        hit.tags.append("security-txt")
    if status in (200, 206) and _hits_sensitive_path(path):
        if _looks_like_exposed_artifact(hit):
            findings.append(
                Finding(
                    "high",
                    "Sensitive path responded",
                    "Artifact-style path returned a body",
                    url=hit.url,
                )
            )
        else:
            findings.append(
                Finding(
                    "info",
                    "Sensitive path HTML fallback",
                    "Matched a sensitive path but the response is an HTML fallback, not an exposed artifact",
                    url=hit.url,
                )
            )
    if hit.body:
        urls, secrets = extract_script_intel(
            hit.final_url or hit.url, hit.body.decode("utf-8", errors="replace")
        )
        report.js_urls.extend(urls)
        findings += secrets
    if path.endswith("favicon.ico") and hit.body and below_400:
        _record_favicon(report, hit)
    origin = hit.headers.get("access-control-allow-origin")
    if (
        origin
        and origin not in ("*", "null")
        and origin != hit.url
        and "bughunt" in origin.lower()
    ):
        findings.append(
            Finding(
                "high",
                "Reflected CORS origin",
                "Server echoed a foreign Origin",
                url=hit.url,
                evidence=origin,
            )
        )
    return findings


def analyze_host(report: HostReport) -> None:
    for port_result in report.results:
        for hit in port_result.hits:
            if speaking(hit) and "filtered" not in hit.tags:
                report.findings.extend(analyze_hit(report, hit))
        if port_result.banner:
            report.banners.append(f"{port_result.port}/tcp {port_result.banner}")
            report.findings.append(
                Finding(
                    "info", f"Banner on port {port_result.port}", port_result.banner
                )
            )
    report.js_urls = unique_in_order(report.js_urls)
    first_of_kind: dict[tuple[str, str, str], Finding] = {}
    for item in report.findings:
        first_of_kind.setdefault((item.severity, item.title, item.url), item)
    report.findings = list(first_of_kind.values())


# --------------------------------------------------------------------------------------
# Post-scan passes: banners, DNS, certificate transparency, CORS, screenshots
# --------------------------------------------------------------------------------------


async def collect_banners(
    host: str, results: list[PortResult], timeout: float, concurrency: int
) -> None:
    gate = asyncio.Semaphore(max(4, _clamped_concurrency(concurrency) // 4))

    async def grab(port_result: PortResult) -> None:
        async with gate:
            port_result.banner = await banner_grab(host, port_result.port, timeout)

    silent = [
        entry
        for entry in results
        if entry.tcp_open and not any(speaking(hit) for hit in entry.hits)
    ]
    await asyncio.gather(*(grab(entry) for entry in silent))


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def query_doh(name: str, record_type: str) -> list[str]:
    try:
        egress.authorize(egress.host_target(name, "dns"), "dns")
        with egress.client(operation="passive", timeout=6.0) as client:
            reply = client.get(
                DOH_ENDPOINT,
                params={"name": name, "type": record_type},
                headers={"Accept": "application/dns-json"},
            )
        records = [
            str(answer.get("data", "")).strip().strip('"')
            for answer in reply.json().get("Answer") or []
        ]
    except Exception:
        return []
    return [record for record in records if record]


def lookup_dns_records(host: str) -> dict[str, list[str]]:
    if is_ip_literal(host):
        return {}
    queries = [(label, host, label) for label in DOH_RECORD_LABELS] + [
        ("DMARC", f"_dmarc.{host}", "TXT")
    ]
    found = {}
    for label, name, record_type in queries:
        records = query_doh(name, record_type)
        if records:
            found[label] = records
    return found


def lookup_ct_names(host: str) -> list[str]:
    if is_ip_literal(host):
        return []
    needle = host.split(":")[0].lower()
    names: list[str] = []
    try:
        egress.authorize(CT_ENDPOINT, "passive")
        with egress.client(operation="passive", timeout=20.0) as client:
            rows = client.get(CT_ENDPOINT, params={"q": host, "output": "json"}).json()
        if not isinstance(rows, list):
            return []
        for row in rows:
            for raw_name in str(row["name_value"]).split("\n"):
                name = raw_name.strip().lower().lstrip("*.")
                if name and needle in name and name not in names:
                    names.append(name)
    except Exception:
        return []
    return names[:CT_NAME_LIMIT]


def cors_targets(report: HostReport) -> list:
    live = [hit for entry in report.results for hit in entry.hits if speaking(hit)]
    roots = [hit for hit in live if urlparse(hit.url).path in ("", "/")]
    return roots[:6] if roots else live[:4]


async def cors_probe(report, timeout, verify_tls, proxy):
    options = {"timeout": timeout, "verify": verify_tls, "follow_redirects": False}
    if proxy:
        options["proxy"] = proxy
    async with egress.async_client(operation="active_scan", **options) as client:
        for hit in cors_targets(report):
            for origin in CORS_PROBE_ORIGINS:
                try:
                    response = await client.request(
                        "OPTIONS",
                        hit.url,
                        headers={
                            "Origin": origin,
                            "Access-Control-Request-Method": "GET",
                        },
                    )
                except Exception:
                    continue
                allowed = response.headers.get("access-control-allow-origin")
                if allowed not in (origin, "*"):
                    continue
                report.findings.append(
                    Finding(
                        "high" if allowed == origin else "medium",
                        "Permissive CORS",
                        f"OPTIONS Origin {origin} → {allowed}",
                        url=hit.url,
                        evidence=allowed,
                    )
                )


def browser_settings(proxy):
    launch_options = {"headless": True, "args": ["--no-proxy-server"]}
    if proxy:
        launch_options["proxy"] = {"server": proxy}
    context_options = {
        "viewport": {"width": 1280, "height": 720},
        "service_workers": "block",
    }
    return launch_options, context_options


_COOKIE_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def actor_cookies(profile: dict, cookie_header: str) -> list[dict]:
    pairs = []
    for piece in cookie_header.split(";"):
        name, _, value = piece.strip().partition("=")
        if not piece.strip():
            continue
        if not _COOKIE_TOKEN.match(name):
            raise identity.IdentityError("Invalid browser actor cookie")
        pairs.append((name, value))
    origins = [target_parts(origin)[0] for origin in profile["origins"]]
    return [
        {"name": name, "value": value, "url": origin + "/"}
        for origin in origins
        for name, value in pairs
    ]


def open_scoped_context(browser, url: str, context_options: dict):
    signature = identity.selection_signature()
    context = browser.new_context(**context_options)
    try:
        actor, revision, credentials = identity.snapshot(url, signature)
        if actor != "default" and credentials.get("Cookie"):
            profile = identity.read_profile(actor)
            if profile["revision"] != revision:
                raise identity.IdentityError("Browser actor changed during setup")
            context.add_cookies(actor_cookies(profile, credentials["Cookie"]))
        context.route("**/*", lambda route: scope_route(route, signature))
        context.route_web_socket(
            "**/*", lambda socket_handle: scope_socket(socket_handle, signature)
        )
    except BaseException:
        context.close()
        raise
    return context


def shoot_page(browser, url: str, context_options: dict, directory: Path) -> None:
    context = open_scoped_context(browser, url, context_options)
    try:
        page = context.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=8000)
            page.screenshot(
                path=str(directory / f"{_sanitize_name(url)[:80]}.png"), full_page=False
            )
        finally:
            page.close()
    finally:
        context.close()


def capture_screenshots(report, directory, proxy=None):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        emit(
            "Screenshots need Playwright: pip install playwright && playwright install chromium",
            style="yellow",
        )
        return
    shootable = [
        hit.final_url or hit.url
        for entry in report.results
        for hit in entry.hits
        if speaking(hit) and hit.status is not None and hit.status < 400
    ][:20]
    if not shootable:
        return
    if proxy:
        egress.authorize_proxy(proxy, "active_scan")
    for url in shootable:
        egress.authorize(url, "active_scan")
        egress.authorize(url, "process")
    try:
        with sync_playwright() as playwright:
            launch_options, context_options = browser_settings(proxy)
            browser = playwright.chromium.launch(**launch_options)
            for url in shootable:
                if not engagement.allowed(url):
                    continue
                try:
                    shoot_page(browser, url, context_options, directory)
                except Exception as exc:
                    emit(f"screenshot of {url} failed: {exc}", style="yellow")
            browser.close()
        emit(f"Screenshots saved in {directory}")
    except Exception as exc:
        emit(f"screenshots failed: {exc}", style="yellow")


# --------------------------------------------------------------------------------------
# Console rendering
# --------------------------------------------------------------------------------------

SEVERITY_STYLES = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
FINDINGS_SHOWN = 30


def status_style(status) -> str:
    if status is None:
        return "dim"
    return {2: "green", 3: "cyan", 4: "yellow", 5: "red"}.get(status // 100, "dim")


def classify_address(text: str) -> str:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return "other"
    for label, matched in (
        ("loopback", address.is_loopback),
        ("link-local", address.is_link_local),
        ("multicast", address.is_multicast),
        ("private", address.is_private),
        ("public", address.is_global),
    ):
        if matched:
            return label
    return "other"


def live_hits(report: HostReport) -> list:
    return [
        hit
        for entry in report.results
        for hit in entry.hits
        if speaking(hit) and "filtered" not in hit.tags
    ]


def hit_label(hit) -> str:
    return hit.title or hit.location or hit.error or hit.snippet


def host_summary_panel(report: HostReport) -> Panel:
    open_count = sum(1 for entry in report.results if entry.tcp_open)
    lines = Text()
    lines.append(f"Target: {report.target}\n")
    lines.append(f"Resolved: {', '.join(report.resolved) or '-'}\n")
    lines.append(
        f"Ports tested: {len(report.results)}   TCP open: {open_count}   Live HTTP(S): {len(live_hits(report))}\n"
    )
    lines.append(f"Elapsed: {report.elapsed:.2f}s")
    return Panel(lines, title="Host summary", expand=False)


def host_table(report: HostReport, only_live: bool) -> Table:
    table = Table(show_lines=False)
    for column in ("Port", "Proto", "Status", "Server", "Title / error", "Tags", "ms"):
        table.add_column(column, overflow="fold")
    for entry in (item for item in report.results if item.tcp_open):
        spoken = [hit for hit in entry.hits if speaking(hit)]
        for hit in spoken:
            table.add_row(
                str(entry.port),
                hit.scheme,
                Text(str(hit.status), style=status_style(hit.status)),
                hit.server,
                Text(hit_label(hit)[:80]),
                ", ".join(hit.tags),
                f"{hit.elapsed_ms:.0f}",
            )
        if not spoken and not only_live:
            errors = "; ".join(
                unique_in_order(hit.error for hit in entry.hits if hit.error)
            )
            table.add_row(
                str(entry.port), "tcp", "open, no HTTP", "", Text(errors[:80]), "", ""
            )
    return table


def hit_panel(hit) -> Panel:
    body = Text()
    body.append(
        f"{hit.status} {hit.reason}".strip() + "\n", style=status_style(hit.status)
    )
    body.append(
        f"Final URL: {hit.final_url}\nServer: {hit.server or '-'}   Type: {hit.content_type or '-'}\n"
    )
    body.append(f"Bytes: {hit.bytes_read}   SHA-256: {hit.sha256 or '-'}\n")
    if hit.tags:
        body.append("Tags: " + ", ".join(hit.tags) + "\n")
    body.append(hit.snippet[:120])
    return Panel(body, title=hit.url, expand=False)


def show_findings(report: HostReport) -> None:
    if not report.findings:
        return
    table = Table(title="Findings")
    for column in ("Severity", "Title", "URL"):
        table.add_column(column, overflow="fold")
    for item in report.findings[:FINDINGS_SHOWN]:
        table.add_row(
            Text(item.severity, style=SEVERITY_STYLES.get(item.severity, "")),
            Text(item.title),
            Text(item.url),
        )
    show(table)


def show_intel_lines(report: HostReport) -> None:
    if report.dns:
        emit(
            "DNS records: "
            + ", ".join(f"{kind}={len(values)}" for kind, values in report.dns.items())
        )
    if report.ct_names:
        emit(f"CT names: {len(report.ct_names)}")
    if report.favicon_hash:
        emit(
            f"Favicon hash: {report.favicon_hash}"
            + (f" ({report.favicon_hint})" if report.favicon_hint else "")
        )


def render_host(report: HostReport, only_live: bool) -> None:
    show(host_summary_panel(report))
    if not any(entry.tcp_open for entry in report.results):
        emit("No TCP-open ports found.", style="yellow")
        return
    show(host_table(report, only_live))
    for hit in live_hits(report):
        show(hit_panel(hit))
    show_findings(report)
    show_intel_lines(report)


def render_run_summary(reports: list[HostReport], elapsed: float) -> None:
    total_live = sum(len(live_hits(report)) for report in reports)
    show(
        Panel(
            Text(
                f"Hosts: {len(reports)}   Live URLs: {total_live}   Elapsed: {elapsed:.2f}s"
            ),
            title="Scan complete",
            expand=False,
        )
    )


def show_banner() -> None:
    emit(f"Bughunt {VERSION}", style="bold cyan")
    emit("HTTP/HTTPS attack-surface mapper")
    emit(
        "Rules of engagement: scan only hosts you own or are explicitly authorized to test; scope and policy are enforced.",
        style="yellow",
    )


# --------------------------------------------------------------------------------------
# scan_main
# --------------------------------------------------------------------------------------


@dataclass
class ScanPlan:
    """Everything derived from the options before the first packet is sent."""

    targets: list[str]
    ports: list[int]
    paths: list[str]
    delay_low: float
    delay_high: float
    agents: list[str]
    headers: dict[str, str]
    auth: object
    concurrency: int
    keep_body: bool
    run_analysis: bool
    status_allow: set[int] | None = None
    grep: object = None


def apply_output_dir(args: argparse.Namespace, *, create: bool = True) -> None:
    root = Path(args.output_dir)
    if create:
        root.mkdir(parents=True, exist_ok=True)
    defaults = {
        "save_urls": root / "live.txt",
        "save_source": root / "pages",
        "save_headers": root / "headers",
        "json": root / "bughunt.json",
        "csv": root / "bughunt.csv",
        "md": root / "bughunt.md",
    }
    for option, location in defaults.items():
        if not getattr(args, option):
            setattr(args, option, str(location))


def apply_intel_shorthand(args) -> None:
    if args.intel:
        args.discover = args.score_headers = args.extract_js = args.favicon = (
            args.dns
        ) = True


def assemble_plan(
    args: argparse.Namespace, *, create_outputs: bool = True, check_scope: bool = True
) -> ScanPlan:
    targets = collect_targets(args.targets, args.targets_file, args.authorized)
    if check_scope:
        reject_out_of_scope(targets)
    if args.output_dir:
        apply_output_dir(args, create=create_outputs)
    ports = select_ports(args)
    base_paths = assemble_base_paths(args.paths, args.paths_file)
    delay_low, delay_high = parse_delay(args.delay)
    agents = build_agent_pool(
        args.user_agent, args.user_agents_file, args.random_agent or args.rotate_agent
    )
    headers = collect_custom_headers(args.header, args.headers_file)
    auth = parse_basic_auth(args.auth)
    parameter_names = read_list_lines(args.params_file) if args.params_file else []
    enforce_breadth_rails(args, ports)
    if args.http_only and args.https_only:
        raise InputRejected(
            "Nothing to do: --http-only and --https-only exclude every scheme."
        )
    apply_intel_shorthand(args)
    paths = expand_request_paths(args, base_paths, parameter_names)
    keep_body = bool(
        args.save_source
        or args.extract_js
        or args.favicon
        or args.score_headers
        or args.intel
        or args.md
        or args.screenshots
    )
    run_analysis = bool(
        args.score_headers
        or args.extract_js
        or args.favicon
        or args.md
        or args.intel
        or args.discover
    )
    return ScanPlan(
        targets=targets,
        ports=ports,
        paths=paths,
        delay_low=delay_low,
        delay_high=delay_high,
        agents=agents,
        headers=headers,
        auth=auth,
        concurrency=max(1, args.concurrency),
        keep_body=keep_body,
        run_analysis=run_analysis,
    )


def planned_urls(args, plan: ScanPlan) -> list[str]:
    schemes = [
        name
        for name, enabled in (
            ("http", not args.https_only),
            ("https", not args.http_only),
        )
        if enabled
    ]
    return [
        egress.endpoint(host, port, scheme=scheme, path=path)
        for host in plan.targets
        for port in plan.ports
        for path in plan.paths
        for scheme in schemes
    ]


def print_dry_run(urls: list[str], method: str) -> int:
    rows = [egress.dry_run(url, "active_scan", method) for url in urls]
    print(json.dumps(rows, indent=2))
    return 0 if all(row["permitted"] for row in rows) else 2


def _proxy_route_policy():
    """Return (policy, exit_code). (None, None) means the gate is not active for --proxy."""
    path = route.locate_config()
    if path is None:
        emit('route gate: not configured; see "bughunt route init"')
        return None, None
    try:
        policy = route.load_config(path)
    except route.ConfigError as exc:
        emit(f"Route config invalid; blocked: {exc}")
        return None, 2
    if "proxy_scan" not in policy.protect:
        return None, None
    return policy, None


def _deny_proxy(*lines: str) -> int:
    """Report why the proxy gate blocked; a failing output stream must never turn a denial into a crash-open."""
    for line in lines:
        with suppress(Exception):
            emit(line)
    return 2


def _warn_if_hostname_proxy(host: str) -> None:
    """The gate verifies the proxy host once; a hostname is re-resolved by the client at connect time."""
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    with suppress(Exception):
        emit(
            f"Route gate verified {host} once at start; the HTTP client re-resolves a hostname at connect time. "
            "Use an IP-literal --proxy to remove this DNS-change window.",
            style="yellow",
        )


def check_proxy_route(proxy: str, *, probe=None, resolver=None):
    """When a route config protects proxy_scan, prove the route to the proxy before any scan traffic.

    Fails closed: an invalid config, a probe error, or any unexpected exception from the route check blocks.
    """
    try:
        parsed = urlparse(proxy)
        host = parsed.hostname
    except ValueError:
        host = None
    if not host:
        return _deny_proxy("--proxy must contain a valid host.")
    egress.authorize("http://localhost/", "process")
    egress.authorize(
        egress.endpoint(host, parsed.port or 80, scheme=parsed.scheme), "manual"
    )
    if route.optout_requested():
        try:
            route.warn_optout("proxy_scan")
        except Exception:
            return _deny_proxy("Route opt-out audit could not be saved; scan blocked.")
        return None
    try:
        policy, blocked_code = _proxy_route_policy()
    except Exception as exc:  # noqa: BLE001 - fail closed on anything unexpected while locating the config
        return _deny_proxy(f"Route gate could not be evaluated; blocked: {exc}")
    if blocked_code is not None or policy is None:
        return blocked_code
    try:
        verdict = route.verify(
            policy,
            destination=host,
            kind="proxy",
            probe=probe,
            resolver=resolver or socket.getaddrinfo,
        )
    except Exception as exc:  # noqa: BLE001 - the route check must never escape as a pass or a crash
        _deny_proxy(f"Route could not be verified: {exc}")
        verdict = None
    if verdict is None or verdict.ok is not True:
        details = [str(line) for line in (verdict.details if verdict else ())]
        return _deny_proxy(
            *details, f"Proxy route check failed for {host}; scan blocked."
        )
    _warn_if_hostname_proxy(host)
    return None


def print_settings(args, plan: ScanPlan, method: str) -> None:
    schemes = "/".join(
        name
        for name, enabled in (
            ("http", not args.https_only),
            ("https", not args.http_only),
        )
        if enabled
    )
    emit(
        f"Targets: {len(plan.targets)}   Ports: {len(plan.ports)}   Paths: {len(plan.paths)}   "
        f"Concurrency: {plan.concurrency}"
    )
    emit(f"Schemes: {schemes}   Method: {method}")
    if plan.delay_high > 0:
        emit(f"Jitter: {plan.delay_low}-{plan.delay_high}s per request")
    if args.skip_tcp:
        emit(
            "TCP phase skipped: every selected port is treated as open", style="yellow"
        )
    if plan.headers:
        emit("Custom headers: " + ", ".join(plan.headers))
    emit(
        f"User-Agents in pool: {len(plan.agents)}"
        + ("   (rotating)" if args.rotate_agent else "")
    )
    outputs = [
        f"{label}={value}"
        for label, value in (
            ("urls", args.save_urls),
            ("source", args.save_source),
            ("headers", args.save_headers),
            ("json", args.json),
            ("csv", args.csv),
            ("md", args.md),
        )
        if value
    ]
    if outputs:
        emit("Outputs: " + "  ".join(outputs))


def resolve_or_report(target: str):
    emit(f"Target: {target}", style="bold")
    try:
        addresses = resolve_host(target)
    except socket.gaierror as exc:
        emit(f"DNS resolution failed for {target}: {exc}", style="red")
        return None
    for address in addresses:
        emit(f"  {address}  ({classify_address(address)})")
    return addresses


def run_target(
    target: str, addresses: list[str], args, plan: ScanPlan, sink: ArtifactSink
) -> HostReport:
    started = time.perf_counter()
    results = asyncio.run(
        scan_host(
            target=target,
            ports=plan.ports,
            connect_timeout=args.connect_timeout,
            http_timeout=args.http_timeout,
            concurrency=plan.concurrency,
            paths=plan.paths,
            follow_redirects=args.follow_redirects,
            try_http=not args.https_only,
            try_https=not args.http_only,
            verify_tls=not args.insecure,
            user_agents=plan.agents,
            rotate_agent=args.rotate_agent,
            host_header=args.host_header,
            custom_headers=plan.headers,
            collect_certs=(not args.http_only) and not args.no_cert,
            keep_body=plan.keep_body,
            max_body=max(1024, args.max_body),
            delay_lo=plan.delay_low,
            delay_hi=plan.delay_high,
            proxy=args.proxy,
            sink=sink,
            status_allow=plan.status_allow,
            grep=plan.grep,
            skip_tcp=args.skip_tcp,
            method=args.method.upper(),
            retries=max(0, args.retries),
            auth=plan.auth,
            analyze=plan.run_analysis,
        )
    )
    report = HostReport(target, addresses, results, time.perf_counter() - started)
    add_intel(report, args, plan)
    return report


def add_intel(report: HostReport, args, plan: ScanPlan) -> None:
    if args.dns:
        report.dns = lookup_dns_records(report.target)
    if args.ct:
        report.ct_names = lookup_ct_names(report.target)
    if args.banners:
        asyncio.run(
            collect_banners(
                report.target, report.results, args.connect_timeout, plan.concurrency
            )
        )
    if plan.run_analysis:
        analyze_host(report)
    elif args.banners:
        report.banners = [
            f"{result.port}/tcp {result.banner}"
            for result in report.results
            if result.banner
        ]
    if args.cors:
        asyncio.run(
            cors_probe(
                report,
                timeout=args.http_timeout,
                verify_tls=not args.insecure,
                proxy=args.proxy,
            )
        )
    if args.screenshots:
        capture_screenshots(report, Path(args.screenshots), args.proxy)


def write_outputs(args, reports: list[HostReport], elapsed: float) -> None:
    if args.json:
        document = redact(reports_to_json(reports, elapsed))
        target = Path(args.json)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(document, indent=2), encoding="utf-8")
        emit(f"wrote {args.json}")
    if args.csv:
        write_csv(Path(args.csv), reports)
        emit(f"wrote {args.csv}")
    if args.md:
        write_markdown(Path(args.md), reports, elapsed)
        emit(f"wrote {args.md}")


def collect_scan(
    args: argparse.Namespace,
    plan: ScanPlan,
    sink: ArtifactSink,
    *,
    report: bool = False,
) -> tuple[list[HostReport], float, int]:
    reports: list[HostReport] = []
    started = time.perf_counter()
    try:
        for target in plan.targets:
            addresses = resolve_or_report(target)
            if addresses is None:
                reports.append(HostReport(target, [], [], 0.0))
                continue
            host_report = run_target(target, addresses, args, plan, sink)
            reports.append(host_report)
            if report:
                render_host(host_report, args.only_live)
    except egress.PolicyBlocked as exc:
        emit(str(exc))
        return reports, time.perf_counter() - started, 2
    except KeyboardInterrupt:
        return reports, time.perf_counter() - started, 130
    finally:
        sink.close()
    elapsed = time.perf_counter() - started
    return reports, elapsed, 0


def run_scan(args, plan: ScanPlan, sink: ArtifactSink) -> int:
    reports, elapsed, code = collect_scan(args, plan, sink, report=True)
    if code == 0:
        render_run_summary(reports, elapsed)
        write_outputs(args, reports, elapsed)
    return code


def prepare_scan(
    args: argparse.Namespace, *, dry_run: bool = False
) -> tuple[ScanPlan, list[str]]:
    if positional_files(args.targets) and all(
        Path(token).is_file() for token in args.targets if token.strip()
    ):
        raise InputRejected("Use --targets-file for target lists")
    if args.follow_redirects:
        raise InputRejected("Unscoped redirects are disabled in this fork")
    status_allow = parse_status_set(args.status)
    grep = re.compile(args.grep, re.IGNORECASE) if args.grep else None
    if args.fast:
        if dry_run:
            if not args.authorized:
                raise InputRejected("Fast mode requires --authorized")
            fastmode._guard_existing_policy()
        else:
            fastmode.setup_scope(args)
    plan = assemble_plan(
        args, create_outputs=not dry_run, check_scope=not (args.fast and dry_run)
    )
    plan.status_allow, plan.grep = status_allow, grep
    urls = planned_urls(args, plan)
    if args.fast and not dry_run:
        fastmode.synthesize_policy(urls, args)
    return plan, urls


def scan_main(argv=None, prog="bughunt"):
    args = build_parser(prog).parse_args(argv)
    files = positional_files(args.targets)
    for token in files:
        emit(
            f"{token} is a file. Did you mean -l {token} to read targets from it?",
            style="yellow",
        )
    if files and len(files) == len([token for token in args.targets if token.strip()]):
        emit("No hosts were given.")
        return 2
    if args.follow_redirects:
        emit("Unscoped redirects are disabled in this fork.")
        return 2
    if not args.quiet:
        show_banner()
    try:
        plan, urls = prepare_scan(args)
    except _AbortScan:
        return 2
    except (ValueError, OSError, argparse.ArgumentTypeError, re.error) as exc:
        emit(str(exc))
        return 2
    method = args.method.upper()
    if args.dry_run:
        return print_dry_run(urls, method)
    try:
        for url in urls:
            egress.authorize(url, "active_scan", method)
        if args.proxy:
            route_code = check_proxy_route(args.proxy)
            if route_code is not None:
                return route_code
    except egress.PolicyBlocked as exc:
        emit(str(exc))
        return 2
    if args.random_agent and not args.rotate_agent and plan.agents:
        plan.agents = [random.choice(plan.agents)]
    sink = ArtifactSink(args.save_urls, args.save_source, args.save_headers)
    print_settings(args, plan, method)
    return run_scan(args, plan, sink)


def main(argv=None):
    from bughunt.console.cli import dispatch

    arguments = sys.argv[1:] if argv is None else argv
    return dispatch(
        arguments,
        scan_main=scan_main,
        build_parser=build_parser,
        tool_file=Path(__file__).resolve(),
    )


if __name__ == "__main__":
    raise SystemExit(main())
