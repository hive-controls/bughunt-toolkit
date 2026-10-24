"""Shared harness for the chromahaus characterization oracle.

Used by test_chromahaus_contract.py, test_chromahaus_behavior.py and test_chromahaus_defects.py.
Not a test module itself (no test_ prefix); conftest.py puts tests/ on sys.path.

Design rules
  * The subject is loaded FRESH for every test under a private module name, so module globals
    (HTTP, the no-color flag) never leak between tests and the cached loader module used by
    test_addons.py is not disturbed. CHROMAHAUS_UNDER_TEST=<path> points the whole oracle at a
    different file (used for mutation proofs and for A/B runs against the rebuild).
  * Everything is mocked at the transport edge: bughunt.core.http.api_client is wrapped to add a MockTransport,
    and the subject builds its own client through _http(), so the real policy decision, host guard, pacing,
    header rewrite and evidence ledger all run. DNS, TCP and subprocess are tripwired (autouse).
  * Nothing here reads a private helper of the subject; only the contract surface in spec 2.1.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re
import socket
import subprocess
import sys
import time
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import httpx
import pytest

from bughunt.core import scanner as bughunt_scanner
from bughunt.modules.policy import example_document

REAL_POPEN = subprocess.Popen  # captured before the tripwire replaces it (standalone-entry test only)

REPO = Path(bughunt_scanner.__file__).resolve().parents[2]
ADDON_DIR = REPO / "addons" / "chromahaus"
SUBJECT = Path(os.environ.get("CHROMAHAUS_UNDER_TEST") or ADDON_DIR / "chromahaus.py").resolve()

KEY = "k3y-oracle"
SHA = "a" * 64
URLHAUS = "https://urlhaus-api.abuse.ch/v1"
BAZAAR = "https://mb-api.abuse.ch/api/v1/"
THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
SSLBL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
FORM = "application/x-www-form-urlencoded"
JSON_TYPE = "application/json"
JSON_HEADERS = {"content-type": JSON_TYPE}
TEXT_HEADERS = {"content-type": "text/plain"}

POLICY_DOCUMENT = example_document()
POLICY_UA = POLICY_DOCUMENT["user_agent"]
POLICY_REQUIRED_HEADERS = {name.lower(): value for name, value in POLICY_DOCUMENT["required_headers"].items()}

# The spec's five exact policy origins (section 5.1) and the methods each one is used with.
FULL_GRANTS = {
    "https://urlhaus-api.abuse.ch": ("GET", "POST"),
    "https://mb-api.abuse.ch": ("POST",),
    "https://threatfox-api.abuse.ch": ("POST",),
    "https://feodotracker.abuse.ch": ("GET",),
    "https://sslbl.abuse.ch": ("GET",),
}

ANSI = re.compile(r"\x1b\[[0-9;]*m")


M32, S40, H64 = "a" * 32, "b" * 40, "c" * 64


def plain_get(url):
    return ("GET", url, None, None)


def form_post(url, body):
    return ("POST", url, body, "form")


def json_post(url, body):
    return ("POST", url, body, "json")


class TtyBuffer(io.StringIO):
    """A stdout stand-in that claims to be a terminal, so color gating can be observed."""

    def isatty(self) -> bool:
        return True


def reply_json(payload, status: int = 200):
    return (status, JSON_HEADERS, json.dumps(payload).encode("utf-8"))


def reply_text(text: str, status: int = 200):
    return (status, TEXT_HEADERS, text.encode("utf-8"))


@dataclass
class Seen:
    method: str
    url: str
    headers: dict
    body: bytes
    timeout: object = None

    @property
    def host(self) -> str:
        return httpx.URL(self.url).host


def abuse_defaults(seen: Seen):
    """Quiet, valid answers: JSON no_results for the APIs, an empty-but-valid text list for the feeds."""
    if seen.url in (FEODO, SSLBL):
        return reply_text("# header\n")
    return reply_json({"query_status": "no_results"})


class Fake:
    """Scripted abuse.ch behind the mock transport.

    routes: {url or (METHOD, url): reply}. A reply is (status, headers, body) or a callable(seen) -> reply.
    handler: optional callable(seen, call_number) -> reply or None (None falls through to routes/default);
    it may raise (httpx.ConnectError, KeyboardInterrupt, ...) to script transport failures.
    Requests nothing answered are recorded in .unrouted and fail the test that caused them.
    """

    def __init__(self, routes=None, default=abuse_defaults, handler=None):
        self.routes = dict(routes or {})
        self.default = default
        self.handler = handler
        self.seen: list[Seen] = []
        self.unrouted: list[Seen] = []
        self.client_builds: list[tuple] = []  # (hosts, timeout) of every api_client(...) the subject asked for
        self.api_client = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        seen = Seen(request.method, str(request.url), dict(request.headers), request.content,
                    request.extensions.get("timeout"))
        self.seen.append(seen)
        reply = self.handler(seen, len(self.seen)) if self.handler is not None else None
        if reply is None:
            reply = self.routes.get((seen.method, seen.url), self.routes.get(seen.url, self.default))
        if callable(reply):
            reply = reply(seen)
        if reply is None:
            self.unrouted.append(seen)
            reply = (599, {}, b"unrouted")
        status, headers, body = reply
        return httpx.Response(status, headers=headers, content=body, request=request)

    def install(self, monkeypatch) -> "Fake":
        """Put this fake behind the subject's OWN client construction.

        bughunt.core.http.api_client is wrapped so that, when the subject asks for its client, the real
        api_client (host guard, egress policy decision, pacing, header rewrite, evidence ledger) is built over a
        MockTransport serving this fake. Call this BEFORE importing the subject so its `from ... import api_client`
        binds the wrapper; a subject that builds a client any other way hits the DNS/TCP tripwire instead.
        """
        from bughunt.core import http as core_http

        real = core_http.api_client

        def api_client_over_fake(hosts, *, timeout, headers=None, transport=None):
            self.client_builds.append((frozenset(hosts), timeout))
            return real(hosts, timeout=timeout, headers=headers, transport=transport or httpx.MockTransport(self))

        self.api_client = api_client_over_fake
        monkeypatch.setattr(core_http, "api_client", api_client_over_fake)
        return self

    @property
    def urls(self) -> list[str]:
        return [seen.url for seen in self.seen]


def write_policy(workspace: Path, grants=None, *, permissions=None) -> dict:
    """Write a verified policy.json. grants: {origin: methods}; permissions: full operation->bool map."""
    document = example_document()
    all_operations = list(document["permissions"])
    document["state"] = "verified"
    document["verified_at"] = datetime.now(timezone.utc).isoformat()
    document["permissions"] = dict(permissions) if permissions is not None else {op: True for op in all_operations}
    document["limits"] = {"requests_per_second": 1000000, "concurrency": 100}
    chosen = FULL_GRANTS if grants is None else grants
    document["assets"] = [
        {"id": f"asset-{index}", "origin": origin, "paths": ["/"], "operations": all_operations,
         "methods": list(methods)}
        for index, (origin, methods) in enumerate(chosen.items())
    ]
    document["exclusions"] = []
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    return document


def only_permitted(*operations: str) -> dict:
    return {op: op in operations for op in example_document()["permissions"]}


def grants_without(*origins: str) -> dict:
    return {origin: methods for origin, methods in FULL_GRANTS.items() if origin not in origins}


def load_fresh_subject():
    name = f"chromahaus_oracle_{uuid.uuid4().hex[:12]}"
    spec = importlib.util.spec_from_file_location(name, SUBJECT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


@dataclass
class Result:
    returned: object
    exited: bool
    exit_arg: object
    out: str
    err: str
    prompts: list = field(default_factory=list)

    @property
    def rc(self) -> int:
        """The exit code the console loader would report (SystemExit and return values mapped alike)."""
        if self.exited:
            code = self.exit_arg
            if code is None or code == 0:
                return 0
            return code if isinstance(code, int) else 1
        if self.returned is None or self.returned is True:
            return 0
        return self.returned if isinstance(self.returned, int) else 0


class Rig:
    """One fresh subject module + one scripted abuse.ch + one scratch policy workspace."""

    def __init__(self, module, fake: Fake, workspace: Path, home: Path, cwd: Path):
        self.module = module
        self.fake = fake
        self.workspace = workspace
        self.home = home
        self.cwd = cwd

    def cli(self, *argv: str, **options) -> Result:
        return self.run(["--key", KEY, *argv], **options)

    def run(self, argv, *, stdin=None, tty: bool = False, allow_unrouted: bool = False) -> Result:
        out = TtyBuffer() if tty else io.StringIO()
        err = io.StringIO()
        prompts: list = []
        lines = None if stdin is None else iter(stdin)

        def scripted_input(prompt=""):
            prompts.append(prompt)
            if lines is None:
                raise AssertionError("main() asked for interactive input")
            try:
                value = next(lines)
            except StopIteration:
                raise EOFError from None
            if isinstance(value, BaseException):
                raise value
            return value

        returned, exited, exit_arg = None, False, None
        saved_argv = sys.argv
        sys.argv = ["bughunt chroma", *argv]
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                    mock.patch("builtins.input", scripted_input):
                try:
                    returned = self.module.main(list(argv))
                except SystemExit as exc:
                    exited, exit_arg = True, exc.code
        finally:
            sys.argv = saved_argv
        if self.fake.unrouted and not allow_unrouted:
            raise AssertionError(f"unrouted requests: {[(s.method, s.url) for s in self.fake.unrouted]}")
        return Result(returned, exited, exit_arg, out.getvalue(), err.getvalue(), prompts)

    def policy(self, grants=None, permissions=None) -> dict:
        return write_policy(self.workspace, grants, permissions=permissions)

    def scope(self, text: str) -> None:
        (self.workspace / "scope.txt").write_text(text, encoding="utf-8")

    def manifests(self) -> list[dict]:
        runs = self.workspace / "runs"
        if not runs.is_dir():
            return []
        return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(runs.glob("*/manifest.json"))]

    def evidence_files(self) -> list[Path]:
        runs = self.workspace / "runs"
        return sorted(path for path in runs.rglob("*") if path.is_file()) if runs.is_dir() else []


def json_documents(text: str) -> list:
    """Every top-level JSON value that starts in column 0 of the text, in order (banner/heading lines are indented)."""
    decoder = json.JSONDecoder()
    documents, position = [], 0
    for match in re.finditer(r"^[\[{]", text, re.MULTILINE):
        if match.start() < position:
            continue
        try:
            document, position = decoder.raw_decode(text, match.start())
        except ValueError:
            continue
        documents.append(document)
    return documents


def machine_parse(text: str):
    """The JSON values in stdout if it is exactly one JSON document or JSON Lines, else None."""
    stripped = text.strip()
    try:
        return [json.loads(stripped)]
    except ValueError:
        pass
    values = []
    for line in stripped.splitlines():
        if not line.strip():
            continue
        try:
            values.append(json.loads(line))
        except ValueError:
            return None
    return values or None


def long_sleeps(calls) -> list:
    """Sleeps of a second or more (the egress layer's 10 ms lease polls are not the tool's pacing)."""
    return [call for call in calls if call >= 1]


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """DNS, TCP and subprocess tripwires. A trip fails the test even if the tool swallows the exception."""
    trips: list[str] = []

    def tripped(*args, **kwargs):
        trips.append(repr(args)[:120])
        raise AssertionError("real DNS/TCP/process boundary reached from a chromahaus test")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "create_connection"):
        monkeypatch.setattr(socket, name, tripped)
    monkeypatch.setattr(socket.socket, "connect", tripped)
    monkeypatch.setattr(socket.socket, "connect_ex", tripped)
    monkeypatch.setattr(subprocess, "Popen", tripped)
    yield trips
    assert not trips, f"network/process boundary tripped: {trips}"


@pytest.fixture
def rig(tmp_path, monkeypatch, no_real_network):
    home = tmp_path / "home"
    cwd = tmp_path / "cwd"
    workspace = tmp_path / "workspace"
    home.mkdir()
    cwd.mkdir()
    for name in ("ABUSECH_AUTH_KEY", "ABUSE_CH_KEY", "NO_COLOR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("BUGHUNT_SCOPE", str(workspace))
    monkeypatch.chdir(cwd)
    write_policy(workspace)
    fake = Fake().install(monkeypatch)
    module = load_fresh_subject()  # after install(): the subject must bind the wrapped api_client
    yield Rig(module, fake, workspace, home, cwd)
    client = getattr(module, "HTTP", None)
    if client is not None:
        client.close()
    sys.modules.pop(module.__name__, None)


@pytest.fixture
def sleeps(monkeypatch):
    """Record time.sleep instead of sleeping. Use long_sleeps() to read the tool's own pacing."""
    calls: list = []
    monkeypatch.setattr(time, "sleep", calls.append)
    return calls


ZIP = b"PK" + b"\0" * 64  # 66 bytes: over the 32-byte "too short" threshold of the downloader


def url_row(index, **extra):
    row = {"id": str(index), "url": f"http://r.example/{index}", "url_status": "online", "host": "r.example",
           "date_added": "2026-10-18T10:00:00", "threat": "malware_download", "tags": ["elf", "mozi"]}
    row.update(extra)
    return row


def feed(*ids_and_urls):
    """A URLhaus recent-URLs answer; an id of None yields an item without an id."""
    return {"query_status": "ok", "urls": [{"id": i, "url": u} if i else {"url": u} for i, u in ids_and_urls]}


def poll_script(payloads):
    """Fake.handler: one answer per poll, then Ctrl-C on the next poll (which ends a watch)."""
    def handler(seen, number):
        if number > len(payloads):
            raise KeyboardInterrupt
        return reply_json(payloads[number - 1])
    return handler


def shown_numbers(pattern, text):
    return {int(number) for number in re.findall(pattern, text)}


def repl(rig, *lines, tty=False):
    """Run the interactive shell with scripted input lines (a BaseException instance in the list is raised)."""
    return rig.run(["--key", KEY], stdin=list(lines), tty=tty)


def console_form_entry(monkeypatch):
    """The catalog's console-form export for `chroma`, with BUGHUNT_ADDONS pointing at the repo's addons folder."""
    from bughunt.console import catalog_export

    monkeypatch.setenv("BUGHUNT_ADDONS", str(REPO / "addons"))
    return catalog_export._module_dict(
        "chroma", tool_file=Path(bughunt_scanner.__file__).resolve(), build_parser=bughunt_scanner.build_parser)
