"""tcurl: fetch one URL over Tor through Bughunt's scope and policy gate.

Every byte tcurl sends, the exit check, the fetch and each redirect hop, is a request made by the
guarded egress client, so scope.txt and the mission policy are consulted before anything leaves the
machine. The client is pointed at a Tor daemon you run yourself (SOCKS5, remote DNS). The SOCKS
listener must be granted in the policy as the endpoint identifier http://HOST:PORT; without that
grant nothing is sent. There is no direct-connection fallback: if Tor cannot be reached the run stops.

Run it as `bughunt tcurl example.com` or from the console (`use tcurl`, `set URL example.com`, `run`).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import pydoc
import re
import secrets
import shutil
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urldefrag, urlsplit

import httpx
from rich.console import Console
from rich.syntax import Syntax
from rich.text import Text

from bughunt.core import egress
from bughunt.core.http import redirect_target
from bughunt.core.workspace import allowed, split_host

SCHEMA_VERSION = 1
DEFAULT_SOCKS = "127.0.0.1:9050"
SOCKS_ENV_VAR = "BUGHUNT_TOR_SOCKS"
EXIT_CHECK_URL = "https://check.torproject.org/api/ip"
EXIT_CHECK_HOSTS = frozenset({"check.torproject.org"})
EXIT_CHECK_BODY_LIMIT = 64 * 1024
FETCH_OPERATION = "manual"
CHECK_OPERATION = "passive"
DEFAULT_MAX_BODY = 8 * 1024 * 1024
DEFAULT_MAX_TIME = 60.0
DEFAULT_CONNECT_TIMEOUT = 30.0
DEFAULT_MAX_REDIRS = 10
HIGHLIGHT_LIMIT = 1024 * 1024
PAGER_COMMAND = "less -FRXi"

EXIT_OK = 0
EXIT_TOR = 1
EXIT_USAGE = 2
EXIT_TRANSPORT = 3
EXIT_INTERRUPTED = 130

DISCLOSURE = (
    "Route: Tor (SOCKS5, remote DNS) via {endpoint}. The target sees a Tor exit relay address, "
    "not your VPN address. Bughunt's VPN route check does not cover this request, and Bughunt "
    "cannot verify how your Tor daemon itself connects. Scope and policy were enforced before sending."
)
CLEARNET_WARNING = "Plain http over Tor: the exit relay can read and alter this traffic."
VPN_ATTRIBUTION = "not applicable: target sees the Tor exit"
DNS_NOTE = "remote (resolved inside Tor)"
ISOLATION_NOTE = "socks-auth per run"
SOCKS_INSTALL_HINT = ("Tor routing needs the optional socksio package. Install it with: "
                      'pip install "bughunt[tor]"  (or: pip install socksio==1.0.0)')

HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
METHOD_TOKEN = re.compile(r"[A-Z]+")
ONION_V3_LABEL = re.compile(r"[a-z2-7]{56}")
SENSITIVE_HEADER = re.compile(r"(?i)authorization|cookie|token|api[-_]?key|secret|session|csrf")
CREDENTIAL_HEADERS = frozenset({"authorization", "cookie", "proxy-authorization"})
TEXT_TYPES = ("text/", "application/json", "application/xml", "application/javascript",
              "application/x-www-form-urlencoded", "application/xhtml")
TEXT_SUFFIXES = ("+json", "+xml")
LEXERS = (("html", "html"), ("json", "json"), ("javascript", "javascript"),
          ("ecmascript", "javascript"), ("css", "css"), ("xml", "xml"))

_CONTROL_CHARACTERS = {code: 0xFFFD for code in (*range(0, 9), 11, 12, *range(14, 32), 127, *range(128, 160))}


# ---------------------------------------------------------------------------------------------
# Errors: each maps to an outcome name and a process exit code
# ---------------------------------------------------------------------------------------------


class TcurlError(Exception):
    outcome = "invalid-input"
    exit_code = EXIT_USAGE

    def __init__(self, message: str, *, kind: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind or self.outcome


class UsageProblem(TcurlError):
    outcome = "invalid-input"
    exit_code = EXIT_USAGE


class BlockedByGate(TcurlError):
    outcome = "blocked"
    exit_code = EXIT_USAGE


class TorUnreachable(TcurlError):
    outcome = "tor-unreachable"
    exit_code = EXIT_TOR


class ExitNotTor(TcurlError):
    outcome = "exit-not-tor"
    exit_code = EXIT_TOR


class TransportFailure(TcurlError):
    outcome = "transport-error"
    exit_code = EXIT_TRANSPORT


# ---------------------------------------------------------------------------------------------
# Typed result (the --json document is built from these; schema_version 1)
# ---------------------------------------------------------------------------------------------


@dataclass
class DecisionInfo:
    permitted: bool
    reason: str


@dataclass
class ExitInfo:
    state: str = "skipped"
    ip: str | None = None
    is_tor: bool | None = None
    check_url: str = ""
    check_run_id: str | None = None


def new_exit_info(state: str = "skipped", run_id: str | None = None) -> ExitInfo:
    return ExitInfo(state=state, check_url=EXIT_CHECK_URL, check_run_id=run_id)


@dataclass
class RedirectInfo:
    source: str
    destination: str
    status: int
    followed: bool
    note: str = ""


@dataclass
class BodyInfo:
    size: int = 0
    truncated: bool = False
    sha256: str = hashlib.sha256(b"").hexdigest()
    saved_to: str | None = None
    text: str | None = None
    encoding: str | None = None


@dataclass
class ResponseInfo:
    status: int
    reason: str
    http_version: str
    final_url: str
    content_type: str
    headers: list[tuple[str, str]]
    elapsed_ms: int
    body: BodyInfo


@dataclass
class TcurlResult:
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    outcome: str = "ok"
    error: tuple[str, str] | None = None
    endpoint: str = DEFAULT_SOCKS
    exit_info: ExitInfo = field(default_factory=new_exit_info)
    method: str = "GET"
    url: str = ""
    onion: bool = False
    header_names: list[str] = field(default_factory=list)
    body_bytes: int = 0
    actor: str | None = None
    mission: str | None = None
    policy_version: str | None = None
    target_decision: DecisionInfo | None = None
    hop_decision: DecisionInfo | None = None
    check_decision: DecisionInfo | None = None
    run_id: str | None = None
    redirects: list[RedirectInfo] = field(default_factory=list)
    response: ResponseInfo | None = None
    exit_code: int = EXIT_OK
    notes: list[str] = field(default_factory=list)
    raw_body: bytes = b""

    def fail(self, problem: TcurlError) -> None:
        self.outcome, self.exit_code = problem.outcome, problem.exit_code
        self.error = (problem.kind, problem.message)

    def to_document(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": "tcurl",
            "generated_at": self.generated_at,
            "outcome": self.outcome,
            "error": None if self.error is None else {"kind": self.error[0], "message": self.error[1]},
            "route": route_document(self.endpoint),
            "exit": _plain_fields(self.exit_info),
            "request": {"method": self.method, "url": self.url, "onion": self.onion,
                        "header_names": list(self.header_names), "body_bytes": self.body_bytes,
                        "actor": self.actor},
            "policy": {"mission": self.mission, "policy_version": self.policy_version,
                       "operation": FETCH_OPERATION, "target_decision": _decision_document(self.target_decision),
                       "hop_decision": _decision_document(self.hop_decision),
                       "check_decision": _decision_document(self.check_decision), "run_id": self.run_id},
            "redirects": [{"from": hop.source, "to": hop.destination, "status": hop.status,
                           "followed": hop.followed, "note": hop.note} for hop in self.redirects],
            "response": None if self.response is None else _response_document(self.response),
            "exit_code": self.exit_code,
        }


def _plain_fields(info: ExitInfo) -> dict:
    return {"state": info.state, "ip": info.ip, "is_tor": info.is_tor,
            "check_url": info.check_url, "check_run_id": info.check_run_id}


def _decision_document(decision: DecisionInfo | None) -> dict | None:
    return None if decision is None else {"permitted": decision.permitted, "reason": decision.reason}


def _response_document(response: ResponseInfo) -> dict:
    body = response.body
    return {"status": response.status, "reason": response.reason, "http_version": response.http_version,
            "final_url": response.final_url, "content_type": response.content_type,
            "headers": [[name, value] for name, value in response.headers],
            "elapsed_ms": response.elapsed_ms,
            "body": {"bytes": body.size, "truncated": body.truncated, "sha256": body.sha256,
                     "saved_to": body.saved_to, "text": body.text, "encoding": body.encoding}}


def route_document(endpoint: str) -> dict:
    return {"class": "tor", "scheme": "socks5h", "endpoint": endpoint, "dns": DNS_NOTE,
            "isolation": ISOLATION_NOTE, "vpn_attribution": VPN_ATTRIBUTION,
            "disclosure": DISCLOSURE.format(endpoint=endpoint)}


# ---------------------------------------------------------------------------------------------
# Input: URL, method, headers, body, SOCKS endpoint
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Plan:
    url: str
    method: str
    headers: tuple[tuple[str, str], ...]
    body: bytes | None
    onion: bool
    socks_host: str
    socks_port: int
    isolation: str

    @property
    def authority(self) -> str:
        host = f"[{self.socks_host}]" if ":" in self.socks_host else self.socks_host
        return f"{host}:{self.socks_port}"

    @property
    def socks_url(self) -> str:
        return f"socks5h://{self.isolation}:{self.isolation}@{self.authority}"

    @property
    def hop_identifier(self) -> str:
        return egress.endpoint(self.socks_host, self.socks_port, "http")


def new_isolation_token() -> str:
    """A fresh SOCKS credential per run: Tor gives each distinct credential its own circuit."""
    return secrets.token_hex(8)


def scrub(text: str, isolation: str = "") -> str:
    return text.replace(isolation, "[isolation]") if isolation else text


def in_scope(url: str) -> bool:
    try:
        return allowed(url)
    except ValueError:
        return False


def onion_problem(host: str) -> str:
    """Why `host` (a .onion name) is not usable, or an empty string when it is a v3 address."""
    label = host[: -len(".onion")].rsplit(".", 1)[-1]
    if len(label) == 16:
        return "v2 onion addresses are not supported (they were retired from Tor)"
    if not ONION_V3_LABEL.fullmatch(label):
        return "not a valid v3 onion address (expected 56 characters from a-z and 2-7)"
    return ""


def normalize_url(raw: str) -> tuple[str, bool]:
    """Return (absolute http(s) URL without fragment, is_onion); raise UsageProblem when unusable."""
    text = raw.strip()
    if not text or "\\" in text or any(ord(character) < 33 or ord(character) == 127 for character in text):
        raise UsageProblem("The URL is empty or contains whitespace, backslashes or control characters.")
    if "://" not in text:
        bare_host = text.split("/", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]
        onion_host = split_host(bare_host)[0].lower().endswith(".onion")
        text = ("http://" if onion_host else "https://") + text
    parts = urlsplit(text)
    if parts.scheme.lower() not in {"http", "https"}:
        raise UsageProblem(f"Only http and https URLs are supported, not {parts.scheme}://")
    try:
        host, _port = (parts.hostname or ""), parts.port
    except ValueError as exc:
        raise UsageProblem("The URL has an invalid port.") from exc
    if not host:
        raise UsageProblem("The URL has no host.")
    if parts.username is not None or parts.password is not None:
        raise UsageProblem("Credentials inside the URL are not supported; use -H or a saved identity.")
    onion = host.lower().endswith(".onion")
    problem = onion_problem(host.lower()) if onion else ""
    if problem:
        raise UsageProblem(f"{host}: {problem}.", kind="onion-address")
    return urldefrag(text)[0], onion


def parse_header(raw: str) -> tuple[str, str]:
    name, separator, value = raw.partition(":")
    name, value = name.strip(), value.strip()
    if not separator or not HEADER_NAME.fullmatch(name):
        raise UsageProblem(f"Header {raw!r} must look like 'Name: value'.")
    if any(character in value for character in "\r\n\x00"):
        raise UsageProblem(f"Header {name} contains a line break or NUL byte.")
    return name, value


def choose_method(options: argparse.Namespace, has_body: bool) -> str:
    if options.head and has_body:
        raise UsageProblem("-I (HEAD) and -d (a request body) cannot be combined.")
    chosen = options.request.upper() if options.request else ("HEAD" if options.head else
                                                              "POST" if has_body else "GET")
    if not METHOD_TOKEN.fullmatch(chosen):
        raise UsageProblem(f"{options.request!r} is not a valid HTTP method token.")
    if chosen == "CONNECT":
        raise UsageProblem("CONNECT is not supported; tcurl sends ordinary requests only.")
    return chosen


def build_body(options: argparse.Namespace) -> bytes | None:
    pieces = options.data or []
    return "&".join(pieces).encode("utf-8") if pieces else None


def parse_socks_endpoint(text: str) -> tuple[str, int]:
    host, port_text = split_host(text.strip())
    if not host or any(character in host for character in "/\\@?# \t"):
        raise UsageProblem(f"{text!r} is not a SOCKS endpoint; use HOST:PORT.")
    try:
        port = int(port_text) if port_text else 9050
    except ValueError as exc:
        raise UsageProblem(f"{text!r} has a port that is not a number.") from exc
    if not 1 <= port <= 65535:
        raise UsageProblem(f"{text!r} has a port outside 1-65535.")
    return host, port


def socks_endpoint_text(options: argparse.Namespace) -> str:
    return options.socks or os.environ.get(SOCKS_ENV_VAR, "").strip() or DEFAULT_SOCKS


def validate_numbers(options: argparse.Namespace) -> None:
    if options.max_time <= 0 or options.connect_timeout <= 0:
        raise UsageProblem("--max-time and --connect-timeout must be greater than 0.")
    if options.max_redirs < 0 or options.max_body < 1:
        raise UsageProblem("--max-redirs cannot be negative and --max-body must be at least 1.")
    if options.json and options.output == "-":
        raise UsageProblem("--json already owns stdout; use -o PATH to save the body.")
    if options.output and options.output != "-":
        target = Path(options.output)
        if target.is_dir() or not target.parent.is_dir():
            raise UsageProblem(f"Cannot write the response to {options.output}.")


def build_plan(options: argparse.Namespace) -> Plan:
    validate_numbers(options)
    url, onion = normalize_url(options.url)
    body = build_body(options)
    headers = tuple(parse_header(raw) for raw in options.header or [])
    if body is not None and not any(name.lower() == "content-type" for name, _ in headers):
        headers += (("Content-Type", "application/x-www-form-urlencoded"),)
    if options.user_agent:
        headers += (("User-Agent", options.user_agent),)
    host, port = parse_socks_endpoint(socks_endpoint_text(options))
    return Plan(url, choose_method(options, body is not None), headers, body, onion,
                host, port, new_isolation_token())


# ---------------------------------------------------------------------------------------------
# Gate: scope and policy decisions made before any traffic
# ---------------------------------------------------------------------------------------------


def target_decision(plan: Plan) -> tuple[DecisionInfo, dict]:
    row = egress.dry_run(plan.url, FETCH_OPERATION, plan.method)
    if not in_scope(plan.url):
        return DecisionInfo(False, "outside-scope"), row
    return DecisionInfo(bool(row["permitted"]), str(row["reason"])), row


def hop_decision(plan: Plan, operations: tuple[str, ...]) -> DecisionInfo:
    for operation in operations:
        row = egress.dry_run(plan.hop_identifier, operation)
        if not row["permitted"]:
            return DecisionInfo(False, f"{row['reason']} for operation {operation}")
    return DecisionInfo(True, "permitted")


def check_decision(row: dict) -> DecisionInfo:
    return DecisionInfo(bool(row["permitted"]), str(row["reason"]))


def record_policy(result: TcurlResult, plan: Plan, check_enabled: bool) -> None:
    """Evaluate every grant tcurl needs and store the decisions; sends nothing."""
    result.target_decision, target_row = target_decision(plan)
    operations = (FETCH_OPERATION, CHECK_OPERATION) if check_enabled else (FETCH_OPERATION,)
    result.hop_decision = hop_decision(plan, operations)
    if check_enabled:
        result.check_decision = check_decision(egress.dry_run(EXIT_CHECK_URL, CHECK_OPERATION))
    result.actor, result.policy_version = target_row.get("actor"), target_row.get("policy_version")
    try:
        result.mission = egress.current_profile().mission
    except egress.PolicyBlocked:
        result.mission = None


def missing_grants(result: TcurlResult, plan: Plan) -> list[str]:
    missing = []
    if result.target_decision and not result.target_decision.permitted:
        reason = result.target_decision.reason
        advice = " (add it with: bughunt scope add HOST)" if reason == "outside-scope" else ""
        missing.append(f"target {plan.url} [{reason}]{advice}")
    if result.hop_decision and not result.hop_decision.permitted:
        missing.append(f"SOCKS hop {plan.hop_identifier} [{result.hop_decision.reason}]")
    if result.check_decision and not result.check_decision.permitted:
        missing.append(f"exit-check host {EXIT_CHECK_URL} [{result.check_decision.reason}]")
    return missing


def raise_if_blocked(result: TcurlResult, plan: Plan) -> None:
    missing = missing_grants(result, plan)
    if missing:
        raise BlockedByGate("Nothing was sent. Missing grants: " + "; ".join(missing), kind="grant-missing")


def require_socks_support() -> None:
    if importlib.util.find_spec("socksio") is None:
        raise UsageProblem(SOCKS_INSTALL_HINT, kind="socksio-missing")


# ---------------------------------------------------------------------------------------------
# Transport: one guarded client per phase, always through the SOCKS proxy
# ---------------------------------------------------------------------------------------------


def open_client(plan: Plan, operation: str, options: argparse.Namespace, *,
                insecure: bool = False, hooks: list | None = None) -> httpx.Client:
    """The only place a client is built. It always carries the proxy; there is no direct variant."""
    timeout = httpx.Timeout(options.max_time, connect=min(options.connect_timeout, options.max_time))
    return egress.client(operation=operation, proxy=plan.socks_url, timeout=timeout,
                         verify=not insecure, follow_redirects=False, trust_env=False,
                         event_hooks={"request": hooks or []})


def describe_failure(failure: BaseException, isolation: str) -> str:
    text = str(failure).strip() or type(failure).__name__
    return scrub(text, isolation)


def classify_failure(failure: Exception, events: list[str], isolation: str) -> TcurlError:
    """Turn a transport exception into a typed error, using the SOCKS stage httpcore reported."""
    detail = describe_failure(failure, isolation)
    stage_failed = {event.rsplit(".", 2)[-2] for event in events if event.endswith(".failed")}
    if "connect_tcp" in stage_failed:
        return TorUnreachable(f"Cannot reach the Tor SOCKS endpoint: {detail}", kind="tor-unreachable")
    if "setup_socks5_connection" in stage_failed:
        if isinstance(failure, httpx.ProxyError) and "could not connect" in str(failure):
            return TransportFailure(f"Tor refused or could not complete the connection: {detail}",
                                    kind="socks-reply")
        return TorUnreachable(f"The SOCKS endpoint did not complete a SOCKS5 handshake: {detail}",
                              kind="socks-handshake")
    if isinstance(failure, httpx.TimeoutException):
        return TransportFailure(f"Timed out: {detail}", kind="timeout")
    if "start_tls" in stage_failed or "CERTIFICATE" in detail.upper() or "SSL" in detail.upper():
        return TransportFailure(f"TLS failure: {detail}", kind="tls")
    return TransportFailure(detail, kind=type(failure).__name__)


@dataclass
class Reply:
    response: httpx.Response
    body: bytes
    truncated: bool
    run_id: str | None
    elapsed_ms: int


def read_capped(response: httpx.Response, limit: int, deadline: float) -> tuple[bytes, bool]:
    kept = bytearray()
    for chunk in response.iter_bytes():
        if time.monotonic() > deadline:
            raise httpx.ReadTimeout("the overall --max-time elapsed")
        room = limit - len(kept)
        if len(chunk) > room:
            kept.extend(chunk[:room])
            return bytes(kept), True
        kept.extend(chunk)
    return bytes(kept), False


def exchange(client: httpx.Client, plan: Plan, method: str, url: str, headers: Iterable[tuple[str, str]],
             body: bytes | None, *, limit: int, deadline: float) -> Reply:
    """Send one request and read at most `limit` bytes of the answer. Never retries, never reroutes."""
    events: list[str] = []
    request = client.build_request(method, url, headers=list(headers), content=body,
                                   extensions={"trace": lambda event, info: events.append(event)})
    started = time.perf_counter()
    try:
        response = client.send(request, stream=True)
        try:
            kept, truncated = read_capped(response, limit, deadline)
        finally:
            response.close()
    except TcurlError:
        raise
    except egress.PolicyBlocked as blocked:
        raise BlockedByGate(scrub(str(blocked), plan.isolation), kind="policy") from blocked
    except Exception as failure:
        raise classify_failure(failure, events, plan.isolation) from failure
    finally:
        client.cookies.clear()
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return Reply(response, kept, truncated, response.extensions.get("bughunt_run_id"), elapsed_ms)


# ---------------------------------------------------------------------------------------------
# Exit check (fixed host, passive) and the Tor decision
# ---------------------------------------------------------------------------------------------


def refuse_unlisted_check_host(request: httpx.Request) -> None:
    if request.url.host.lower() not in EXIT_CHECK_HOSTS:
        raise BlockedByGate(f"{request.url.host} is not the exit-check host; the request was not sent.",
                            kind="check-host")


def parse_exit_answer(reply: Reply) -> ExitInfo:
    """Read check.torproject.org's answer; anything unreadable is 'unverified', never 'confirmed'."""
    info = new_exit_info(run_id=reply.run_id)
    try:
        document = json.loads(reply.body.decode("utf-8")) if reply.response.status_code == 200 else None
    except ValueError:
        document = None
    if not isinstance(document, dict):
        info.state = "unverified"
        return info
    is_tor = document.get("IsTor")
    info.is_tor = is_tor if isinstance(is_tor, bool) else None
    try:
        info.ip = str(ipaddress.ip_address(str(document.get("IP", "")).strip()))
    except ValueError:
        info.ip = None
    info.state = "not-tor" if info.is_tor is False else (
        "confirmed" if info.is_tor and info.ip else "unverified")
    return info


def check_exit(plan: Plan, options: argparse.Namespace) -> ExitInfo:
    deadline = time.monotonic() + options.max_time
    with open_client(plan, CHECK_OPERATION, options, hooks=[refuse_unlisted_check_host]) as client:
        try:
            reply = exchange(client, plan, "GET", EXIT_CHECK_URL, (("Accept", "application/json"),), None,
                             limit=EXIT_CHECK_BODY_LIMIT, deadline=deadline)
        except TransportFailure:
            return new_exit_info("unverified")
    return parse_exit_answer(reply)


def enforce_exit_state(info: ExitInfo) -> None:
    if info.state == "not-tor":
        shown = f" ({info.ip})" if info.ip else ""
        raise ExitNotTor(f"The exit address{shown} is not a Tor exit; the request was not sent.",
                         kind="exit-not-tor")


# ---------------------------------------------------------------------------------------------
# Fetch: one request per hop, scope and policy re-checked before every redirect
# ---------------------------------------------------------------------------------------------


def next_method(status: int, method: str) -> tuple[str, bool]:
    """(method for the next hop, keep_body) following curl's redirect rewriting."""
    if (status == 303 and method != "HEAD") or (status in (301, 302) and method == "POST"):
        return "GET", False
    return method, True


def hop_headers(headers: Iterable[tuple[str, str]], current: str, following: str) -> list[tuple[str, str]]:
    if urlsplit(current)[:2] == urlsplit(following)[:2]:
        return list(headers)
    return [(name, value) for name, value in headers if name.lower() not in CREDENTIAL_HEADERS]


def hop_in_scope(url: str) -> bool:
    return in_scope(url)


def hop_refusal(url: str, method: str) -> str:
    """Empty when the redirect may be followed; otherwise the reason it must not be."""
    if urlsplit(url).scheme.lower() not in {"http", "https"}:
        return "redirect to a non-http(s) URL is not followed"
    if not hop_in_scope(url):
        host = urlsplit(url).hostname or url
        return f"redirect to {host} is outside scope, not followed"
    row = egress.dry_run(url, FETCH_OPERATION, method)
    if not row["permitted"]:
        return f"redirect to {url} is not permitted by policy ({row['reason']}), not followed"
    return ""


def follow_redirects(client: httpx.Client, plan: Plan, options: argparse.Namespace, first: Reply,
                     result: TcurlResult, deadline: float) -> Reply:
    reply, current = first, plan.url
    method, body, headers = plan.method, plan.body, plan.headers
    while options.location:
        target = redirect_target(current, reply.response)
        if not target:
            break
        status = reply.response.status_code
        method, keep_body = next_method(status, method)
        refusal = "" if len(result.redirects) < options.max_redirs else (
            f"stopped after {options.max_redirs} redirects")
        refusal = refusal or hop_refusal(target, method)
        result.redirects.append(RedirectInfo(current, target, status, not refusal, refusal))
        if refusal:
            break
        body = body if keep_body else None
        headers = hop_headers(headers, current, target)
        reply = exchange(client, plan, method, target, headers, body,
                         limit=options.max_body, deadline=deadline)
        current = target
    return reply


def fetch(plan: Plan, options: argparse.Namespace, result: TcurlResult) -> Reply:
    deadline = time.monotonic() + options.max_time
    with open_client(plan, FETCH_OPERATION, options, insecure=options.insecure) as client:
        first = exchange(client, plan, plan.method, plan.url, plan.headers, plan.body,
                         limit=options.max_body, deadline=deadline)
        return follow_redirects(client, plan, options, first, result, deadline)


# ---------------------------------------------------------------------------------------------
# Response handling
# ---------------------------------------------------------------------------------------------


def is_text_media(content_type: str, body: bytes) -> bool:
    media = content_type.split(";")[0].strip().lower()
    if b"\x00" in body[:4096]:
        return False
    if not media:
        return True
    return media.startswith(TEXT_TYPES) or media.endswith(TEXT_SUFFIXES)


def decode_body(body: bytes, content_type: str) -> tuple[str, str]:
    match = re.search(r"charset=([\w.-]+)", content_type, re.I)
    for name in (match.group(1) if match else "", "utf-8"):
        try:
            return body.decode(name or "utf-8", errors="replace"), (name or "utf-8").lower()
        except LookupError:
            continue
    return body.decode("utf-8", errors="replace"), "utf-8"


def neutralize(text: str) -> str:
    """Make hostile response text safe to print: no terminal escapes, no characters the stream cannot show."""
    plain = text.replace("\r\n", "\n").translate(_CONTROL_CHARACTERS).replace("\r", "\ufffd")
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    return plain.encode(encoding, errors="replace").decode(encoding, errors="replace")


def save_body(path: str, body: bytes) -> str:
    target = Path(path)
    try:
        target.write_bytes(body)
    except OSError as exc:
        raise UsageProblem(f"Could not write {path}: {exc.strerror or exc}", kind="output-unwritable") from exc
    return str(target)


def build_response(reply: Reply, final_url: str, options: argparse.Namespace) -> ResponseInfo:
    response, content_type = reply.response, reply.response.headers.get("content-type", "")
    body = BodyInfo(size=len(reply.body), truncated=reply.truncated, sha256=hashlib.sha256(reply.body).hexdigest())
    if options.output and options.output != "-":
        body.saved_to = save_body(options.output, reply.body)
    elif is_text_media(content_type, reply.body):
        body.text, body.encoding = decode_body(reply.body, content_type)
    return ResponseInfo(status=response.status_code, reason=response.reason_phrase or "",
                        http_version=response.http_version or "", final_url=final_url,
                        content_type=content_type.split(";")[0].strip(),
                        headers=[(name.decode("latin-1"), value.decode("latin-1"))
                                 for name, value in response.headers.raw],
                        elapsed_ms=reply.elapsed_ms, body=body)


# ---------------------------------------------------------------------------------------------
# One run, end to end
# ---------------------------------------------------------------------------------------------


def describe_request(result: TcurlResult, plan: Plan) -> None:
    result.method, result.url, result.onion = plan.method, plan.url, plan.onion
    result.header_names = [name for name, _ in plan.headers]
    result.body_bytes = len(plan.body or b"")
    result.endpoint = plan.authority


def finish_fetch(result: TcurlResult, plan: Plan, reply: Reply, options: argparse.Namespace) -> None:
    followed = [hop.destination for hop in result.redirects if hop.followed]
    result.response = build_response(reply, followed[-1] if followed else plan.url, options)
    result.raw_body, result.run_id = reply.body, reply.run_id
    if options.user_agent:
        result.notes.append("-A is replaced on the wire by the policy User-Agent.")


def execute(options: argparse.Namespace, result: TcurlResult) -> None:
    result.endpoint = socks_endpoint_text(options)
    check_enabled = not options.no_exit_check
    plan = build_plan(options)
    describe_request(result, plan)
    record_policy(result, plan, check_enabled)
    raise_if_blocked(result, plan)
    if options.dry_run:
        return
    require_socks_support()
    if check_enabled:
        result.exit_info = check_exit(plan, options)
        enforce_exit_state(result.exit_info)
    reply = fetch(plan, options, result)
    finish_fetch(result, plan, reply, options)


def run(options: argparse.Namespace) -> TcurlResult:
    """Run once and describe what happened; expected failures become a typed outcome, not a traceback."""
    result = TcurlResult()
    try:
        execute(options, result)
    except TcurlError as problem:
        result.fail(problem)
    except KeyboardInterrupt:
        result.outcome, result.exit_code = "interrupted", EXIT_INTERRUPTED
        result.error = ("interrupted", "Interrupted.")
    return result


# ---------------------------------------------------------------------------------------------
# Presentation (free-form text) and the --json document
# ---------------------------------------------------------------------------------------------


def human_size(count: int) -> str:
    if count < 1024:
        return f"{count} B"
    return f"{count / 1024:.1f} KB" if count < 1024 * 1024 else f"{count / (1024 * 1024):.1f} MB"


EXIT_WORDS = {"confirmed": ("Tor exit confirmed", "green"), "not-tor": ("NOT a Tor exit", "red"),
              "unverified": ("exit unverified (check inconclusive)", "yellow"),
              "skipped": ("exit unverified (check skipped)", "yellow")}

Row = tuple[str, str, str]


def exit_and_route_rows(result: TcurlResult) -> list[Row]:
    rows: list[Row] = []
    if result.exit_info.state != "skipped" or result.outcome == "ok":
        label, style = EXIT_WORDS[result.exit_info.state]
        rows.append(("exit", f"{result.exit_info.ip or '-'}  {label}", style))
    rows.append(("route", f"tor via {result.endpoint}, remote DNS - not your VPN exit", "cyan"))
    rows.append(("note", DISCLOSURE.format(endpoint=result.endpoint), "dim"))
    if result.url.startswith("http://") and not result.onion:
        rows.append(("warning", CLEARNET_WARNING, "yellow"))
    return rows


def response_rows(result: TcurlResult) -> list[Row]:
    response = result.response
    if response is None:
        return []
    detail = f"{response.status} {response.reason}  {response.elapsed_ms / 1000:.2f}s  {human_size(response.body.size)}"
    rows: list[Row] = [("status", f"{detail}  {response.content_type}".rstrip(), "bold")]
    if response.final_url != result.url:
        rows.append(("final", response.final_url, ""))
    if response.body.saved_to:
        rows.append(("saved", response.body.saved_to, "green"))
    if response.body.truncated:
        rows.append(("note", "body truncated at --max-body", "yellow"))
    return rows


def banner_rows(result: TcurlResult) -> list[Row]:
    rows = exit_and_route_rows(result)
    rows.append(("request", f"{result.method} {result.url}", ""))
    rows.extend(response_rows(result))
    rows.extend(("note", hop.note, "yellow") for hop in result.redirects if not hop.followed)
    rows.extend(("note", note, "dim") for note in result.notes)
    if result.error is not None:
        rows.append(("error", result.error[1], "red"))
    return rows


def stdout_is_terminal() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except (AttributeError, ValueError):
        return False


def color_enabled(options: argparse.Namespace, interactive: bool) -> bool:
    if options.json or options.no_color or os.environ.get("NO_COLOR"):
        return False
    return bool(options.color or interactive)


def make_console(options: argparse.Namespace, *, to_stderr: bool, interactive: bool) -> Console:
    color = color_enabled(options, interactive)
    return Console(stderr=to_stderr, highlight=False, markup=False, emoji=False,
                   color_system="auto" if color else None,
                   force_terminal=True if options.color and not options.no_color else None)


def print_rows(console: Console, rows: list[Row]) -> None:
    for label, text, style in rows:
        line = Text(f"{label:<8}", style="bold")
        line.append(neutralize(text), style=style or None)
        console.print(line, soft_wrap=True)


def lexer_for(content_type: str) -> str | None:
    media = content_type.lower()
    return next((lexer for marker, lexer in LEXERS if marker in media), None)


def header_block(result: TcurlResult) -> str:
    response = result.response
    lines = [f"{response.http_version} {response.status} {response.reason}".strip()]
    lines += [f"{name}: {value}" for name, value in response.headers]
    return neutralize("\n".join(lines)) + "\n\n"


def body_renderable(result: TcurlResult, color: bool) -> Syntax | Text:
    response = result.response
    text = neutralize(response.body.text or "")
    lexer = lexer_for(response.content_type) if color and len(text) <= HIGHLIGHT_LIMIT else None
    if lexer:
        return Syntax(text, lexer, theme="ansi_dark", word_wrap=True, background_color="default")
    return Text(text)


def should_page(options: argparse.Namespace, interactive: bool) -> bool:
    return bool(interactive and not options.no_pager and not options.json and shutil.which("less"))


def plain_write(text: str) -> None:
    """Write text to stdout, replacing anything the stream's encoding cannot show."""
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    sys.stdout.write(text.encode(encoding, errors="replace").decode(encoding, errors="replace"))
    sys.stdout.flush()


def write_stdout_bytes(data: bytes) -> None:
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        plain_write(data.decode("utf-8", errors="replace"))
        return
    buffer.write(data)
    buffer.flush()


def page_body(result: TcurlResult, options: argparse.Namespace, interactive: bool, include: bool) -> None:
    shown = make_console(options, to_stderr=False, interactive=interactive)
    pieces = ([Text(header_block(result))] if include else []) + [
        body_renderable(result, color_enabled(options, interactive))]
    if should_page(options, interactive):
        with shown.capture() as captured:
            for piece in pieces:
                shown.print(piece, soft_wrap=True, end="")
        pydoc.pipepager(captured.get(), PAGER_COMMAND)
        return
    for piece in pieces:
        shown.print(piece, soft_wrap=True, end="")
    shown.print()


def print_body(result: TcurlResult, options: argparse.Namespace, interactive: bool) -> None:
    response = result.response
    if response is None or response.body.saved_to:
        return
    if response.body.text is None:
        if options.output == "-":
            write_stdout_bytes(result.raw_body)
            return
        withheld = (f"{response.content_type or 'binary'} body ({human_size(response.body.size)}) "
                    "kept off the terminal; add -o FILE to save it.")
        print_rows(make_console(options, to_stderr=True, interactive=interactive), [("note", withheld, "yellow")])
        return
    include = options.include or result.method == "HEAD"
    if options.output == "-" or (not interactive and not options.color):
        plain_write((header_block(result) if include else "") + response.body.text)
        return
    page_body(result, options, interactive, include)


def print_verbose(result: TcurlResult) -> None:
    console = Console(stderr=True, highlight=False, markup=False, emoji=False)
    lines = [f"> {result.method} {result.url}"] + [f"> {name}" for name in result.header_names]
    if result.response is not None:
        lines.append(f"< {result.response.http_version} {result.response.status} {result.response.reason}")
        lines += [f"< {name}: {'[hidden]' if SENSITIVE_HEADER.search(name) else value}"
                  for name, value in result.response.headers]
    for line in lines:
        console.print(Text(neutralize(line)), soft_wrap=True)


def emit_text(result: TcurlResult, options: argparse.Namespace) -> None:
    interactive = stdout_is_terminal()
    print_rows(make_console(options, to_stderr=not interactive, interactive=interactive), banner_rows(result))
    if options.verbose:
        print_verbose(result)
    if result.outcome == "ok":
        print_body(result, options, interactive)


def emit_document(result: TcurlResult) -> None:
    sys.stdout.write(json.dumps(result.to_document(), indent=2) + "\n")
    sys.stdout.flush()


def emit(result: TcurlResult, options: argparse.Namespace) -> None:
    if options.json or options.dry_run:
        emit_document(result)
    else:
        emit_text(result, options)


# ---------------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch one URL over Tor and show the exit address. Scope and mission policy "
                    "apply to the target, to every redirect hop and to the Tor SOCKS endpoint.",
        epilog="examples:\n"
               "  bughunt tcurl example.com -I\n"
               "  bughunt tcurl example.com -L -H 'Accept: application/json'\n"
               "  bughunt tcurl http://<56-character-address>.onion/ --json\n"
               "  bughunt tcurl example.com --dry-run",
        formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    parser.add_argument("url", help="one URL; a bare host means https:// (http:// for .onion)")
    add_request_options(parser)
    add_transport_options(parser)
    add_output_options(parser)
    return parser


def add_request_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-X", "--request", metavar="METHOD", help="HTTP method (default GET)")
    parser.add_argument("-I", "--head", action="store_true", help="send HEAD and show the headers")
    parser.add_argument("-H", "--header", action="append", metavar="NAME: VALUE",
                        help="extra request header (repeatable)")
    parser.add_argument("-d", "--data", action="append", metavar="TEXT",
                        help="request body text (repeatable, joined with &); implies POST")
    parser.add_argument("-A", "--user-agent", metavar="TEXT",
                        help="accepted, but the policy User-Agent replaces it on the wire")


def add_transport_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-L", "--location", action="store_true",
                        help="follow redirects, checking scope and policy before each hop")
    parser.add_argument("--max-redirs", type=int, default=DEFAULT_MAX_REDIRS, metavar="N",
                        help=f"most redirects to follow (default {DEFAULT_MAX_REDIRS})")
    parser.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification for the fetch")
    parser.add_argument("-m", "--max-time", type=float, default=DEFAULT_MAX_TIME, metavar="SEC",
                        help=f"time limit per phase in seconds (default {DEFAULT_MAX_TIME:g})")
    parser.add_argument("--connect-timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT, metavar="SEC",
                        help=f"time limit for reaching the SOCKS port (default {DEFAULT_CONNECT_TIMEOUT:g})")
    parser.add_argument("--max-body", type=int, default=DEFAULT_MAX_BODY, metavar="BYTES",
                        help=f"most response bytes kept (default {DEFAULT_MAX_BODY})")
    parser.add_argument("--socks", metavar="HOST:PORT",
                        help=f"Tor SOCKS5 endpoint (default {DEFAULT_SOCKS}, or ${SOCKS_ENV_VAR}); "
                             "it must be granted in the policy as http://HOST:PORT")
    parser.add_argument("--no-exit-check", action="store_true", help="skip the Tor exit check")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the scope and policy decisions as JSON and send nothing")


def add_output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-i", "--include", action="store_true", help="show response headers above the body")
    parser.add_argument("-o", "--output", metavar="PATH", help="save the body to PATH (- for stdout)")
    parser.add_argument("-v", "--verbose", action="store_true", help="summarise request and response headers on stderr")
    parser.add_argument("--json", action="store_true", help="print only the JSON result on stdout")
    parser.add_argument("--no-pager", "--raw", dest="no_pager", action="store_true",
                        help="print the whole response instead of opening a pager")
    parser.add_argument("--no-color", action="store_true", help="plain text")
    parser.add_argument("--color", action="store_true", help="colour output even when stdout is piped")


def leftover_message(leftovers: list[str]) -> str:
    flags = [word for word in leftovers if word.startswith("-")]
    if flags:
        return f"tcurl no longer wraps curl; {flags[0].split('=', 1)[0]} is not supported."
    return "tcurl takes exactly one URL."


def parse_command_line(words: list[str]) -> argparse.Namespace | int:
    """The parsed options, or the exit code to return right away (help, or a usage error)."""
    parser = build_parser()
    try:
        options, leftovers = parser.parse_known_args(words)
    except SystemExit as exit_request:
        return exit_request.code if isinstance(exit_request.code, int) else EXIT_USAGE
    if leftovers:
        parser.print_usage(sys.stderr)
        sys.stderr.write(f"{parser.prog}: error: {leftover_message(leftovers)}\n")
        return EXIT_USAGE
    return options


def main(argv: list[str] | None = None) -> int:
    parsed = parse_command_line(list(sys.argv[1:] if argv is None else argv))
    if isinstance(parsed, int):
        return parsed
    result = run(parsed)
    try:
        emit(result, parsed)
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
