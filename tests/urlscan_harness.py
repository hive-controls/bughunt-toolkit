"""Harness for the addon-urlscan characterization oracle (M2 Wave 2). Not a test module.

Everything here sits at the network edge: requests go through httpx.MockTransport wrapped by the
real `api_client` (so the host guard and the egress policy still run), `socket` is booby-trapped,
and HOME / the workspace are scratch directories. No call to urlscan.io is ever made, so every
statement about the LIVE service stays UNVERIFIED (mock-only); only the addon's own behavior is
characterized.

Test-pinned contracts the harness relies on (a rebuild must keep them):
  * `main(argv)` resolves the module-global `Client` at CALL time;
  * `Client(api_key=..., timeout=...)` exposes a swappable `.http`;
  * `APIError`, `API_HOSTS` and `scan_gate` exist.

To run the oracle against another copy of the addon (a rebuild, or a mutant), set
BUGHUNT_URLSCAN_ADDON_ROOT to a directory that contains `urlscan/urlscan.py`.
"""

from __future__ import annotations

import io
import json
import os
import socket
import ssl
import sys
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest

from bughunt.console import loader
from bughunt.core import scanner as bughunt_scanner
from bughunt.core.http import api_client
from test_gate import seed_policy

REPO_ROOT = Path(bughunt_scanner.__file__).resolve().parents[2]
ADDON_ROOT = Path(os.environ.get("BUGHUNT_URLSCAN_ADDON_ROOT") or REPO_ROOT / "addons")
ADDON_SCRIPT = ADDON_ROOT / "urlscan" / "urlscan.py"

UUID = "0196d976-07f6-7aae-8a57-aa019145f31c"
JSON_HEADERS = {"content-type": "application/json"}
SCAN_URL = "https://urlscan.io/api/v1/scan/"
SEARCH_BASE = "https://urlscan.io/api/v1/search/"
RESULT_URL = f"https://urlscan.io/api/v1/result/{UUID}/"
SCREENSHOT_URL = f"https://urlscan.io/screenshots/{UUID}.png"
DOM_URL = f"https://urlscan.io/dom/{UUID}/"
QUOTAS_URL = "https://urlscan.io/api/v1/quotas"
QUOTAS_FALLBACK_URL = "https://urlscan.io/user/quotas/"
WHOAMI_URL = "https://urlscan.io/user/username"

_SSL_CONTEXTS: dict = {}
_REAL_CREATE_DEFAULT_CONTEXT = ssl.create_default_context


def _cached_default_context(*args, **kwargs):
    """Building a default SSL context loads the CA bundle (~150 ms) on every httpx.Client(); the oracle
    builds hundreds of clients whose real transport is swapped for a mock, so share one context."""
    key = (args, tuple(sorted(kwargs.items())))
    if key not in _SSL_CONTEXTS:
        _SSL_CONTEXTS[key] = _REAL_CREATE_DEFAULT_CONTEXT(*args, **kwargs)
    return _SSL_CONTEXTS[key]


def reply(status: int = 200, body=b"", headers: dict | None = None, **rate):
    """Build a canned response. dict/list bodies become JSON; `rate` kwargs become x-rate-limit-* headers."""
    merged = dict(headers or {})
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode("utf-8")
        merged.setdefault("content-type", "application/json")
    elif isinstance(body, str):
        body = body.encode("utf-8")
    for name, value in rate.items():
        merged["x-rate-limit-" + name.replace("_", "-")] = str(value)
    return (status, merged, body)


@dataclass
class Seen:
    method: str
    url: str
    headers: dict
    body: bytes
    tick: float = 0.0

    def json(self):
        return json.loads(self.body.decode("utf-8"))


@dataclass
class Outcome:
    code: object  # int return value, or the SystemExit code
    exited: bool  # True when main() raised SystemExit
    out: str
    err: str
    seen: list = field(default_factory=list)
    client_calls: list = field(default_factory=list)  # [{"api_key": ..., "timeout": ...}] per Client(...) built

    @property
    def urls(self) -> list[str]:
        return [item.url for item in self.seen]

    @property
    def gets(self) -> list[str]:
        return [item.url for item in self.seen if item.method == "GET"]


class TtyText(io.StringIO):
    """StringIO that claims to be a terminal (stdin answers, stderr spinner)."""

    def isatty(self) -> bool:
        return True


class Bench:
    def __init__(self, module, workspace: Path, home: Path, cwd: Path, monkeypatch, capsys):
        self.module = module
        self.workspace = workspace
        self.home = home
        self.cwd = cwd
        self.monkeypatch = monkeypatch
        self.capsys = capsys
        self.real_client = module.Client
        self.clock = None

    # -- policy / scope ------------------------------------------------------------------
    def policy(self) -> dict:
        return json.loads((self.workspace / "policy.json").read_text(encoding="utf-8"))

    def write_policy(self, document: dict) -> None:
        (self.workspace / "policy.json").write_text(json.dumps(document), encoding="utf-8")

    def edit_policy(self, mutate) -> None:
        document = self.policy()
        mutate(document)
        self.write_policy(document)

    def remove_urlscan_asset(self) -> None:
        self.edit_policy(lambda d: d.update(assets=[a for a in d["assets"] if "urlscan.io" not in a["origin"]]))

    def set_urlscan_methods(self, methods: list[str]) -> None:
        def mutate(document):
            for asset in document["assets"]:
                if asset["origin"] == "https://urlscan.io":
                    asset["methods"] = methods
        self.edit_policy(mutate)

    def grant_origin(self, origin: str) -> None:
        def mutate(document):
            template = next(a for a in document["assets"] if a["origin"] == "https://urlscan.io")
            document["assets"].append({**template, "id": "asset-extra", "origin": origin})
        self.edit_policy(mutate)

    # -- time ----------------------------------------------------------------------------
    def fake_clock(self, start: float = 1000.0):
        """Replace time.monotonic / time.perf_counter / time.sleep so sleeping advances a fake clock
        (no real waiting). perf_counter is the egress pacing seam (bughunt.core.clock.now, patched
        here via the shared stdlib time module); monotonic is the addon's own poll loop. Both read the
        one fake state, so a faked sleep advances every reader and egress never busy-spins for real."""
        import time as time_module

        state = {"now": start}
        self.monkeypatch.setattr(time_module, "monotonic", lambda: state["now"])
        self.monkeypatch.setattr(time_module, "perf_counter", lambda: state["now"])
        self.monkeypatch.setattr(time_module, "sleep", lambda seconds: state.__setitem__("now", state["now"] + max(0.0, seconds)))
        self.clock = state
        return state

    # -- running -------------------------------------------------------------------------
    def _handler(self, routes, responder, seen):
        counters: dict = {}
        clock = self.clock

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(Seen(request.method, str(request.url), dict(request.headers), request.content,
                             clock["now"] if clock else 0.0))
            key = (request.method, str(request.url))
            entry = (routes or {}).get(key)
            if entry is None:
                if responder is None:
                    raise AssertionError(f"unexpected request {key}")
                entry = responder(request, len(seen))
                if isinstance(entry, httpx.Response):
                    entry.request = request
                    return entry
            if isinstance(entry, list):
                index = counters.get(key, 0)
                counters[key] = index + 1
                entry = entry[min(index, len(entry) - 1)]
            status, headers, body = entry
            return httpx.Response(status, headers=headers, content=body, request=request)

        return handler

    def client(self, routes=None, responder=None, api_key="K", timeout=1.0):
        """A real Client whose `.http` is swapped for the mock edge. Returns (client, seen)."""
        seen: list[Seen] = []
        client = self.real_client(api_key=api_key, timeout=timeout)
        handler = self._handler(routes, responder, seen)
        client.http = api_client(self.module.API_HOSTS, timeout=1, transport=httpx.MockTransport(handler))
        return client, seen

    def run(self, argv, routes=None, responder=None, *, entry=None, stdin_text=None, stdin_tty=False,
            stdout_tty=False, stderr_tty=False, keep_client=False, stdout=None) -> Outcome:
        seen: list[Seen] = []
        module = self.module
        handler = self._handler(routes, responder, seen)
        real_client = self.real_client
        client_calls: list = []

        def client_with_mock(api_key=None, timeout=30.0):
            client_calls.append({"api_key": api_key, "timeout": timeout})
            client = real_client(api_key=api_key, timeout=timeout)
            client.http = api_client(module.API_HOSTS, timeout=1, transport=httpx.MockTransport(handler))
            return client

        if not keep_client:
            self.monkeypatch.setattr(module, "Client", client_with_mock)
        self._install_streams(stdin_text, stdin_tty, stdout_tty, stderr_tty)
        if stdout is not None:
            self.monkeypatch.setattr(sys, "stdout", stdout)
        call = entry or module.main
        try:
            code, exited = call(None if argv is None else list(argv)), False
        except SystemExit as exc:
            code, exited = (0 if exc.code is None else exc.code), True
        captured = self.capsys.readouterr()
        return Outcome(code, exited, captured.out, captured.err, seen, client_calls)

    def _install_streams(self, stdin_text, stdin_tty, stdout_tty, stderr_tty) -> None:
        patch = self.monkeypatch
        if stdin_text is not None or stdin_tty:
            stdin = TtyText(stdin_text or "") if stdin_tty else io.StringIO(stdin_text or "")
            patch.setattr(sys, "stdin", stdin)
        else:
            patch.setattr("sys.stdin.isatty", lambda: False, raising=False)
        if stdout_tty:
            patch.setattr("sys.stdout.isatty", lambda: True, raising=False)
        if stderr_tty:
            patch.setattr("sys.stderr.isatty", lambda: True, raising=False)


@pytest.fixture
def bench(monkeypatch, tmp_path, capsys):
    """A fresh copy of the addon module, a scratch workspace/policy/HOME, and a trapped network."""
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "scope.txt").write_text("allowed.example\n", encoding="utf-8")
    seed_policy(workspace)
    home = tmp_path / "home"
    home.mkdir()
    cwd = tmp_path / "cwd"
    cwd.mkdir()

    monkeypatch.setenv("BUGHUNT_SCOPE", str(workspace))
    monkeypatch.setenv("BUGHUNT_ADDONS", str(ADDON_ROOT))
    for name in ("URLSCAN_API_KEY", "NO_COLOR", "FORCE_COLOR", "HTTPS_PROXY", "https_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(ssl, "create_default_context", _cached_default_context)

    def forbidden(*args, **kwargs):
        raise AssertionError("network touched: the oracle must stay mock-only")

    for name in ("getaddrinfo", "gethostbyname", "create_connection"):
        monkeypatch.setattr(socket, name, forbidden)

    for key in [name for name in sys.modules if name.startswith("bughunt_tools.urlscan_")]:
        monkeypatch.delitem(sys.modules, key)
    module = loader.import_script(ADDON_SCRIPT)
    yield Bench(module, workspace, home, cwd, monkeypatch, capsys)
    for key in [name for name in sys.modules if name.startswith("bughunt_tools.urlscan_")]:
        sys.modules.pop(key, None)


def write_key_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
