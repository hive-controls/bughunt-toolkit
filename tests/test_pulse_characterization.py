"""Characterization oracle for addons/pulse, written BEFORE the clean-room rebuild.

Scope: everything `tests/test_addons.py` leaves unpinned for the `pulse` addon - the CLI surface,
the per-URL check (status families, `ok`, content type, timing, retries, error text), the manual
redirect walk (cap, scope per hop, explicit policy per request), the guarded client's construction,
input parsing, exit codes, JSON/CSV exports, the `--only` filter, the display contract, the optional
`h2` flag, and the `bughunt pulse` loader path.

Network posture: NO real network call is made. Every URL is served by `httpx.MockTransport` at the
egress edge, and an autouse tripwire makes DNS and TCP connects raise. Two subprocess tests (standalone
launch, cp1252 stdout) only ever see out-of-scope URLs or an injected mock transport. UNVERIFIED
(mock-only): real HTTP/2 against a live server with `h2` installed, real DNS/TLS failure text, real
latency, terminal rendering other than a non-TTY 250-column stream.

Tiers follow the spec (m2-pulse-spec.md). Tests whose name ends in `__pinned_current` pin today's
behavior that the rebuild must reproduce (spec decision: preserve). Tests whose name ends in
`__correct` assert the CORRECT behavior of a known defect and are marked xfail(strict=True) until
the rebuild fixes it. Everything else pins a contract the rebuild must keep.

Point the suite at another copy of the script (mutation proofs, or the rebuilt file in a scratch
location) with `BUGHUNT_PULSE_UNDER_TEST=<path to pulse.py>`; the default is the repo's addon.
"""

from __future__ import annotations

import asyncio
import csv
import inspect
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import types
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest
from rich.console import Console

from bughunt.console import catalog, loader, ui
from bughunt.console.catalog_export import export_catalog
from bughunt.core import egress, scanner
from test_gate import seed_policy

REPO = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT = REPO / "addons" / "pulse" / "pulse.py"
SCRIPT = Path(os.environ.get("BUGHUNT_PULSE_UNDER_TEST") or DEFAULT_SCRIPT).resolve()

REAL_ASYNC_CLIENT = egress.async_client
ANSI = re.compile(r"\x1b\[[0-9;]*m")
BASE = "https://allowed.example"
FIELDS = (
    "url",
    "ok",
    "status",
    "reason",
    "family",
    "elapsed_ms",
    "final_url",
    "content_type",
    "error",
    "redirects",
    "excluded",
)
FAMILY_WORD = {
    "2xx": "LIVE",
    "3xx": "REDIRECT",
    "4xx": "CLIENT ERROR",
    "5xx": "SERVER ERROR",
    "error": "UNREACHABLE",
}


def u(path: str = "/") -> str:
    return BASE + path


def plain(text: str) -> str:
    return ANSI.sub("", text)


def record(result) -> dict:
    return {name: getattr(result, name) for name in FIELDS}


# ---------------------------------------------------------------------------------------------
# Workspace (scope + policy) and the network-edge harness
# ---------------------------------------------------------------------------------------------


def build_workspace(
    path: Path,
    *,
    scope=("allowed.example",),
    policy=True,
    restrict=None,
    limits=None,
    deny=(),
) -> None:
    """Scope file plus a verified policy. `restrict` maps origin -> allowed operations; `deny` switches whole
    operations off; `limits` replaces the (effectively unlimited) default pacing profile."""
    path.mkdir(parents=True, exist_ok=True)
    for stale in ("scope.txt", "policy.json"):
        (path / stale).unlink(missing_ok=True)
    document = seed_policy(path)
    for row in document["assets"]:
        if row["origin"] in (restrict or {}):
            row["operations"] = list(restrict[row["origin"]])
    for operation in deny:
        document["permissions"][operation] = False
    if limits is not None:
        document["limits"] = limits
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    if not policy:
        (path / "policy.json").unlink()
    if scope is not None:
        (path / "scope.txt").write_text("\n".join(scope) + "\n", encoding="utf-8")


class Wire:
    """The mock network edge. `routes`: url -> (status, headers) | exception instance; unrouted URLs use
    `default` (a (status, headers) pair) or fail to connect. `handler(request)` may return the same kinds
    of outcome (or an awaitable of one) and takes precedence. Tracks peak in-flight requests."""

    def __init__(
        self, routes=None, *, default=None, handler=None, delay=0.0, events=None
    ):
        self.routes, self.default, self.handler = dict(routes or {}), default, handler
        self.delay, self.events = delay, events
        self.requests: list[httpx.Request] = []
        self.argv_seen: list[list[str]] = []
        self.in_flight = self.peak = 0

    @property
    def urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._respond)

    async def _respond(self, request):
        self.requests.append(request)
        self.argv_seen.append(list(sys.argv))
        if self.events is not None:
            self.events.append(("request", str(request.url)))
        self.in_flight += 1
        self.peak = max(self.peak, self.in_flight)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            if self.handler is not None:
                outcome = self.handler(request)
                if inspect.isawaitable(outcome):
                    outcome = await outcome
            else:
                outcome = self.routes.get(str(request.url), self.default)
        finally:
            self.in_flight -= 1
        if outcome is None:
            raise httpx.ConnectError("no route " + str(request.url), request=request)
        if isinstance(outcome, BaseException):
            raise outcome
        status, headers = outcome
        return httpx.Response(status, headers=headers, request=request)


@dataclass
class Run:
    code: int
    out: str
    err: str

    @property
    def plain_out(self) -> str:
        return plain(self.out)


class World:
    """One scope/policy workspace plus the guarded-path mock edge, and a `main()` runner."""

    def __init__(self, pulse, monkeypatch, tmp_path, capsys):
        self.pulse, self.mp, self.tmp, self.capsys = (
            pulse,
            monkeypatch,
            tmp_path,
            capsys,
        )
        self.scope_dir = tmp_path / "scope"
        self.client_kwargs: list[dict] = []
        self.wire = Wire()
        monkeypatch.setenv("BUGHUNT_SCOPE", str(self.scope_dir))
        monkeypatch.setenv("COLUMNS", "250")
        self.workspace()

    def workspace(self, **options) -> None:
        build_workspace(self.scope_dir, **options)

    def serve(self, routes=None, **wire_options) -> Wire:
        """Route the GUARDED egress client over a mock transport and record what pulse asked it for."""
        self.wire = wire = Wire(routes, **wire_options)

        def guarded_over_mock(**kwargs):
            self.client_kwargs.append(dict(kwargs))
            kwargs["transport"] = wire.transport()
            return REAL_ASYNC_CLIENT(**kwargs)

        self.mp.setattr(egress, "async_client", guarded_over_mock)
        return wire

    def urls_file(
        self, *lines: str, raw: bytes | None = None, name: str = "urls.txt"
    ) -> str:
        path = self.tmp / name
        path.write_bytes(
            raw if raw is not None else ("\n".join(lines) + "\n").encode("utf-8")
        )
        return str(path)

    def run(self, *argv: str, stdin: str | None = None) -> Run:
        self.mp.setattr(sys, "argv", ["bughunt pulse", *argv])
        if stdin is not None:
            self.mp.setattr(sys, "stdin", io.StringIO(stdin))
        code, exited = 0, False
        try:
            self.pulse.main()
        except SystemExit as exc:
            code, exited = (0 if exc.code is None else exc.code), True
        out, err = self.capsys.readouterr()
        assert exited, "main() returned instead of raising SystemExit"
        return Run(code, out, err)

    def run_checks(self, urls, **overrides):
        options = dict(
            follow=False,
            timeout=5,
            concurrency=5,
            retries=0,
            user_agent="UA/1",
            insecure=False,
            method_note="",
        )
        options.update(overrides)
        return asyncio.run(self.pulse.run_checks(list(urls), **options))

    def read_json(self, path) -> dict:
        return json.loads(Path(path).read_text(encoding="utf-8"))

    @property
    def ledger(self) -> list[dict]:
        return [
            json.loads(p.read_text(encoding="utf-8"))
            for p in sorted((self.scope_dir / "runs").glob("*/manifest.json"))
        ]


def check(pulse, wire: Wire, url: str, *, follow=False, retries=0):
    """check_one over an UNGUARDED client: any scope or policy decision seen is the addon's own."""

    async def go():
        async with httpx.AsyncClient(transport=wire.transport()) as client:
            return await pulse.check_one(client, url, follow=follow, retries=retries)

    return asyncio.run(go())


@pytest.fixture(scope="session")
def addons_root(tmp_path_factory):
    """A throwaway addons tree holding a byte copy of the script under test."""
    root = tmp_path_factory.mktemp("pulse-addons")
    (root / "pulse").mkdir()
    shutil.copyfile(SCRIPT, root / "pulse" / "pulse.py")
    return root


@pytest.fixture(scope="session")
def pulse(addons_root):
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("COLUMNS", "250")
        return loader.import_script(addons_root / "pulse" / "pulse.py")


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Tripwire: nothing in this module may resolve a name or open a socket."""

    def forbidden(*args, **kwargs):
        raise AssertionError("real network reached from a pulse characterization test")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture(autouse=True)
def scratch_scope(monkeypatch, tmp_path):
    """Default workspace for tests that do not build a World (check_one over an unguarded client)."""
    monkeypatch.setenv("COLUMNS", "250")
    monkeypatch.setenv("BUGHUNT_SCOPE", str(tmp_path / "default-scope"))
    build_workspace(tmp_path / "default-scope")


@pytest.fixture
def world(pulse, monkeypatch, tmp_path, capsys):
    return World(pulse, monkeypatch, tmp_path, capsys)


@pytest.fixture
def sleeps(monkeypatch):
    """Backoff gaps (>= 0.1 s) requested through asyncio.sleep; the sleeps themselves return at once."""
    recorded: list[float] = []
    real_sleep = asyncio.sleep

    async def fake(delay, result=None):
        if delay >= 0.1:
            recorded.append(delay)
        await real_sleep(0)
        return result

    monkeypatch.setattr(asyncio, "sleep", fake)
    return recorded


# ---------------------------------------------------------------------------------------------
# A. CLI surface (spec section 3), catalog and discovery
# ---------------------------------------------------------------------------------------------

EXPECTED_ACTIONS = [
    # dest, option strings, default, type, metavar
    ("file", [], None, None, None),
    ("urls", ["--urls"], None, None, None),
    ("follow_redirects", ["-f", "--follow-redirects"], False, None, None),
    ("show_redirects", ["--show-redirects"], False, None, None),
    ("concurrency", ["-c", "--concurrency"], 20, int, "N"),
    ("timeout", ["-t", "--timeout"], 10.0, float, "SEC"),
    ("retries", ["-r", "--retries"], 1, int, "N"),
    ("user_agent", ["-A", "--user-agent"], None, None, None),
    ("insecure", ["-k", "--insecure"], False, None, None),
    ("only", ["--only"], None, None, "FAMILIES"),
    ("json_out", ["--json"], None, None, "PATH"),
    ("csv_out", ["--csv"], None, None, "PATH"),
]


def test_parser_actions_dests_flags_defaults_types_and_metavars(pulse):
    parser = pulse.build_parser()
    assert len(parser._actions) == 13
    actions = [a for a in parser._actions if a.dest != "help"]
    assert [a.dest for a in actions] == [dest for dest, *_ in EXPECTED_ACTIONS]
    for dest, flags, default, kind, metavar in EXPECTED_ACTIONS:
        action = next(a for a in actions if a.dest == dest)
        assert action.option_strings == flags, dest
        assert action.type is kind, dest
        assert action.metavar == metavar, dest
        if dest != "user_agent":
            assert action.default == default and type(action.default) is type(
                default
            ), dest
    switches = {"follow_redirects", "show_redirects", "insecure"}
    for action in actions:
        assert (action.nargs == 0) is (action.dest in switches), action.dest
    assert next(a for a in actions if a.dest == "file").required is False
    assert next(a for a in parser._actions if a.dest == "help").option_strings == [
        "-h",
        "--help",
    ]
    default_agent = next(a for a in actions if a.dest == "user_agent").default
    assert isinstance(default_agent, str) and default_agent.strip()


def test_parser_reads_short_and_long_forms_into_the_same_destinations(pulse):
    short = [
        "urls.txt",
        "-f",
        "--show-redirects",
        "-c",
        "5",
        "-t",
        "2.5",
        "-r",
        "0",
        "-A",
        "UA/9",
        "-k",
        "--only",
        "2xx,error",
        "--json",
        "o.json",
        "--csv",
        "o.csv",
    ]
    long = [
        "urls.txt",
        "--follow-redirects",
        "--show-redirects",
        "--concurrency",
        "5",
        "--timeout",
        "2.5",
        "--retries",
        "0",
        "--user-agent",
        "UA/9",
        "--insecure",
        "--only",
        "2xx,error",
        "--json",
        "o.json",
        "--csv",
        "o.csv",
    ]
    expected = {
        "file": "urls.txt",
        "urls": None,
        "follow_redirects": True,
        "show_redirects": True,
        "concurrency": 5,
        "timeout": 2.5,
        "retries": 0,
        "user_agent": "UA/9",
        "insecure": True,
        "only": "2xx,error",
        "json_out": "o.json",
        "csv_out": "o.csv",
    }
    assert vars(pulse.build_parser().parse_args(short)) == expected
    assert vars(pulse.build_parser().parse_args(long)) == expected


def test_parser_defaults(pulse):
    args = pulse.build_parser().parse_args(["urls.txt"])
    assert (args.file, args.follow_redirects, args.show_redirects, args.insecure) == (
        "urls.txt",
        False,
        False,
        False,
    )
    assert (args.concurrency, args.timeout, args.retries) == (20, 10.0, 1)
    assert isinstance(args.timeout, float)
    assert (args.only, args.json_out, args.csv_out) == (None, None, None)


def test_there_is_no_http2_quiet_method_or_proxy_flag(pulse):
    flags = {
        flag
        for action in pulse.build_parser()._actions
        for flag in action.option_strings
    }
    assert not flags & {
        "--http2",
        "--h2",
        "--quiet",
        "-q",
        "--version",
        "--method",
        "--header",
        "--proxy",
    }


def test_catalog_registers_pulse_in_recon_without_aliases():
    tool = catalog.tool_by_command("pulse")
    assert (tool.command, tool.folder, tool.script, tool.aliases) == (
        "pulse",
        "pulse",
        "pulse.py",
        (),
    )
    assert (
        tool.summary
        == "Check a list of URLs and report which ones answer, grouped by status."
    )
    assert "pulse" not in catalog.DISABLED_REFERENCES
    assert dict(catalog.MODULE_GROUPS)["Recon"][-1] == "pulse"
    assert (
        catalog.MODULE_WHEN["pulse"]
        == "You have a URL list and want to know which entries are live."
    )
    assert catalog.reference_canonical("pulse") == "pulse"


def test_catalog_form_matches_the_parser_in_console_order(addons_root, monkeypatch):
    monkeypatch.setenv("BUGHUNT_ADDONS", str(addons_root))
    data = export_catalog(
        tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    entry = next(
        m for p in data["phases"] for m in p["modules"] if m["name"] == "pulse"
    )
    assert (
        entry["disabled"] is False
        and entry["aliases"] == []
        and entry["reference"] is True
    )
    options = [
        (o["name"], o["flags"], o["kind"], o["required"], o["default"])
        for o in entry["form"]["options"]
    ]
    agent = options[7]
    assert (
        agent[:4] == ("USER_AGENT", ["-A", "--user-agent"], "value", False)
        and agent[4].strip()
    )
    options[7] = agent[:4] + ("<ua>",)
    assert options == [
        ("FILE", [], "positional", False, ""),
        ("URLS", ["--urls"], "value", False, ""),
        ("FOLLOW_REDIRECTS", ["-f", "--follow-redirects"], "bool", False, ""),
        ("SHOW_REDIRECTS", ["--show-redirects"], "bool", False, ""),
        ("CONCURRENCY", ["-c", "--concurrency"], "value", False, "20"),
        ("TIMEOUT", ["-t", "--timeout"], "value", False, "10.0"),
        ("RETRIES", ["-r", "--retries"], "value", False, "1"),
        ("USER_AGENT", ["-A", "--user-agent"], "value", False, "<ua>"),
        ("INSECURE", ["-k", "--insecure"], "bool", False, ""),
        ("ONLY", ["--only"], "value", False, ""),
        ("JSON_OUT", ["--json"], "value", False, ""),
        ("CSV_OUT", ["--csv"], "value", False, ""),
    ]


def test_addon_lookup_finds_pulse_without_the_addons_env_var(monkeypatch):
    """Spec defect P4 was observed at 8e3cd26 (addon root derived one level too shallow). The M0 quick-win
    (2eb1935, this worktree's base) fixed it, so this is a regression pin, not an xfail."""
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    tool = catalog.tool_by_command("pulse")
    found = catalog.locate_script(tool, Path(scanner.__file__).resolve())
    assert (
        found is not None and found.name == "pulse.py" and found.parent.name == "pulse"
    )


# ---------------------------------------------------------------------------------------------
# B. check_one: the record, status families, `ok`, content type, timing (spec 4.4, 6.1)
# ---------------------------------------------------------------------------------------------


def test_check_result_has_the_eleven_export_fields_in_order_with_defaults(pulse):
    blank = pulse.CheckResult(url="u", ok=False)
    assert record(blank) == {
        "url": "u",
        "ok": False,
        "status": None,
        "reason": "",
        "family": "error",
        "elapsed_ms": 0,
        "final_url": "",
        "content_type": "",
        "error": "",
        "redirects": [],
        "excluded": False,
    }
    positional = pulse.CheckResult("u", True, 200, "OK", "2xx", 5, "f", "t", "e", ["r"])
    assert list(record(positional).values()) == [
        "u",
        True,
        200,
        "OK",
        "2xx",
        5,
        "f",
        "t",
        "e",
        ["r"],
        False,
    ]
    assert blank.redirects is not pulse.CheckResult(url="v", ok=False).redirects


def test_success_record_for_a_plain_200(pulse):
    wire = Wire({u(): (200, {"content-type": "text/html; charset=utf-8"})})
    row = record(check(pulse, wire, u()))
    elapsed = row.pop("elapsed_ms")
    assert row == {
        "url": u(),
        "ok": True,
        "status": 200,
        "reason": "OK",
        "family": "2xx",
        "final_url": u(),
        "content_type": "text/html",
        "error": "",
        "redirects": [],
        "excluded": False,
    }
    assert type(elapsed) is int and elapsed >= 0
    assert wire.urls == [u()] and wire.requests[0].method == "GET"


STATUS_MATRIX = [
    # status, family, ok when redirects are NOT followed
    (199, "error", False),
    (200, "2xx", True),
    (204, "2xx", True),
    (299, "2xx", True),
    (300, "3xx", True),
    (302, "3xx", True),
    (399, "3xx", True),
    (400, "4xx", False),
    (404, "4xx", False),
    (499, "4xx", False),
    (500, "5xx", False),
    (503, "5xx", False),
    (599, "5xx", False),
    (600, "error", False),
    (999, "error", False),
]


@pytest.mark.parametrize(
    "status, family, ok", STATUS_MATRIX, ids=[str(row[0]) for row in STATUS_MATRIX]
)
def test_status_family_and_ok_when_not_following(pulse, status, family, ok):
    result = check(pulse, Wire({u(): (status, {})}), u())
    assert (result.status, result.family, result.ok) == (status, family, ok)
    assert result.error == ""
    assert result.final_url == u() and result.redirects == []


@pytest.mark.parametrize("status", [199, 600, 999])
def test_unclassifiable_statuses_keep_their_code_with_an_empty_reason_and_error(
    pulse, status
):
    result = check(pulse, Wire({u(): (status, {})}), u())
    assert result.status == status and result.reason == "" and result.error == ""
    assert result.family == "error" and result.ok is False


@pytest.mark.parametrize(
    "status, reason", [(200, "OK"), (404, "Not Found"), (503, "Service Unavailable")]
)
def test_reason_phrase_is_carried(pulse, status, reason):
    assert check(pulse, Wire({u(): (status, {})}), u()).reason == reason


def test_unfollowed_redirect_is_ok_and_not_walked(pulse):
    wire = Wire({u(): (301, {"location": "/home"}), u("/home"): (200, {})})
    result = check(pulse, wire, u(), follow=False)
    assert wire.urls == [u()]
    assert (result.status, result.ok, result.family) == (301, True, "3xx")
    assert result.final_url == u() and result.redirects == [] and result.error == ""


def test_followed_redirect_that_lands_on_200_is_ok(pulse):
    wire = Wire({u(): (301, {"location": "/home"}), u("/home"): (200, {})})
    result = check(pulse, wire, u(), follow=True)
    assert (result.status, result.ok, result.family, result.final_url) == (
        200,
        True,
        "2xx",
        u("/home"),
    )


def test_followed_3xx_outcome_is_never_ok(pulse):
    stopped = check(
        pulse,
        Wire({u(): (302, {"location": "https://outside.example/x"})}),
        u(),
        follow=True,
    )
    assert (stopped.status, stopped.family, stopped.ok) == (302, "3xx", False)
    no_location = check(pulse, Wire({u(): (302, {})}), u(), follow=True)
    assert (
        no_location.status,
        no_location.family,
        no_location.ok,
        no_location.error,
    ) == (302, "3xx", False, "")


@pytest.mark.parametrize(
    "header, expected",
    [
        ("text/html; charset=utf-8", "text/html"),
        ("Application/JSON", "Application/JSON"),
        ("  text/plain ; q=1", "text/plain"),
        ("image/png;", "image/png"),
    ],
)
def test_content_type_has_parameters_stripped_and_case_kept(pulse, header, expected):
    assert (
        check(pulse, Wire({u(): (200, {"content-type": header})}), u()).content_type
        == expected
    )


def test_missing_content_type_is_empty(pulse):
    assert check(pulse, Wire({u(): (200, {})}), u()).content_type == ""


def test_elapsed_ms_is_an_int_of_the_whole_chain(pulse, monkeypatch):
    """pulse reads time.perf_counter() once before the walk (pulse.py:202) and once after
    (pulse.py:210), so elapsed_ms is exactly the virtual time the mock edge advances across the
    WHOLE chain. The earlier version fabricated the duration with a real asyncio.sleep(0.06), whose
    wake is scheduled off time.monotonic -- coarse (15.625 ms) on CPython<=3.12 Windows -- so a 60 ms
    sleep could return in ~44-49 ms and the absolute lower bounds (50 / 100) flaked. Injecting a
    scripted perf_counter removes the dependency on real sleep/scheduler timing entirely."""
    leg_seconds = (
        0.05  # each served hop advances the virtual clock by one exact 50 ms leg
    )
    virtual = [0.0]
    monkeypatch.setattr(time, "perf_counter", lambda: virtual[0])

    def advancing(routes):
        def handler(request):
            virtual[0] += leg_seconds
            return routes[str(request.url)]

        return handler

    virtual[0] = 0.0
    single = check(pulse, Wire(handler=advancing({u(): (200, {})})), u())
    assert type(single.elapsed_ms) is int
    assert single.elapsed_ms == 50

    virtual[0] = 0.0
    followed = check(
        pulse,
        Wire(
            handler=advancing(
                {u(): (301, {"location": "/home"}), u("/home"): (200, {})}
            )
        ),
        u(),
        follow=True,
    )
    assert type(followed.elapsed_ms) is int
    assert followed.elapsed_ms == 100
    # the whole-chain total is exactly the sum of its legs (two hops), not just the final hop
    assert followed.elapsed_ms == 2 * single.elapsed_ms


def test_elapsed_ms_reads_the_fine_clock_not_coarse_monotonic(pulse, monkeypatch):
    """Regression guard: green only while pulse times with the fine time.perf_counter. The clock is
    fully scripted (no real sleeping): time.monotonic is floored to GetTickCount64's 15.625 ms step
    (CPython<=3.12 Windows), while perf_counter advances by an exact sub-tick 7 ms on the served hop.
    pulse reports 7 ms. Were pulse to regress to a coarse clock (monotonic / time.time), two reads in
    one 15.625 ms tick would compare equal (0 ms) or jump a whole 15/31/... ms -- never 7 -- so this
    turns red."""
    import math

    real_monotonic = time.monotonic
    monkeypatch.setattr(
        time, "monotonic", lambda: math.floor(real_monotonic() / 0.015625) * 0.015625
    )
    virtual = [0.0]
    monkeypatch.setattr(time, "perf_counter", lambda: virtual[0])

    def seven_ms_hop(request):
        virtual[0] += 0.007
        return (200, {})

    result = check(pulse, Wire(handler=seven_ms_hop), u())
    assert result.elapsed_ms == 7


@pytest.mark.parametrize(
    "code, family",
    [
        (None, "error"),
        (0, "error"),
        (100, "error"),
        (199, "error"),
        (200, "2xx"),
        (299, "2xx"),
        (300, "3xx"),
        (399, "3xx"),
        (400, "4xx"),
        (499, "4xx"),
        (500, "5xx"),
        (599, "5xx"),
        (600, "error"),
    ],
)
def test_status_family_boundaries_via_the_internal_helper(pulse, code, family):
    """The helper's name is FREE in the spec (2.1); skipped if the rebuild renames it. The same boundaries are
    pinned through check_one above, which is the real contract (None is only reachable through the helper)."""
    helper = getattr(pulse, "status_family", None)
    if helper is None:
        pytest.skip("rebuild renamed the internal status_family helper")
    assert helper(code) == family


def test_error_rows_have_zero_elapsed_and_no_final_url(pulse):
    result = check(pulse, Wire({u(): httpx.ReadTimeout("slow")}), u())
    assert (
        result.elapsed_ms,
        result.final_url,
        result.content_type,
        result.redirects,
    ) == (0, "", "", [])
    assert (result.status, result.reason, result.family, result.ok) == (
        None,
        "",
        "error",
        False,
    )


# ---------------------------------------------------------------------------------------------
# C. Scope gate and the redirect walk (spec 4.4 step 1, 4.5)
# ---------------------------------------------------------------------------------------------


def test_out_of_scope_url_is_never_requested_and_never_retried(pulse, sleeps):
    wire = Wire({})
    result = check(pulse, wire, "https://outside.example/", retries=3)
    assert wire.requests == [] and sleeps == []
    assert record(result) == {
        "url": "https://outside.example/",
        "ok": False,
        "status": None,
        "reason": "",
        "family": "error",
        "elapsed_ms": 0,
        "final_url": "",
        "content_type": "",
        "error": result.error,
        "redirects": [],
        "excluded": False,
    }
    assert "scope" in result.error


def test_no_scope_file_means_nothing_is_contacted(pulse, world):
    world.workspace(scope=None)
    wire = Wire({u(): (200, {})})
    result = check(pulse, wire, u())
    assert wire.requests == [] and result.family == "error" and "scope" in result.error


def test_scope_includes_subdomains_but_not_look_alikes(pulse):
    sub = Wire({"https://cdn.allowed.example/": (200, {})})
    assert check(pulse, sub, "https://cdn.allowed.example/").status == 200
    lookalike = Wire({})
    result = check(pulse, lookalike, "https://allowed.example.evil.example/")
    assert lookalike.requests == [] and "scope" in result.error


def chain_routes(redirects: int, final=(200, {})) -> dict:
    """h0 -> h1 -> ... -> h<redirects>, where the last URL answers `final`."""
    routes = {u(f"/h{i}"): (301, {"location": f"/h{i + 1}"}) for i in range(redirects)}
    routes[u(f"/h{redirects}")] = final
    return routes


def test_redirect_loop_stops_after_exactly_eleven_requests_with_the_cap_note(pulse):
    wire = Wire(
        {u("/a"): (301, {"location": "/b"}), u("/b"): (301, {"location": "/a"})}
    )
    result = check(pulse, wire, u("/a"), follow=True)
    assert len(wire.requests) == 11
    assert result.error == "stopped after 10 redirects"
    assert (result.status, result.family, result.ok) == (301, "3xx", False)
    assert result.redirects == wire.urls and result.final_url == wire.urls[-1]


def test_exactly_ten_hops_then_a_final_answer_is_accepted(pulse):
    wire = Wire(chain_routes(10))
    result = check(pulse, wire, u("/h0"), follow=True)
    assert len(wire.requests) == 11
    assert (result.status, result.ok, result.error) == (200, True, "")
    assert result.redirects == wire.urls == [u(f"/h{i}") for i in range(11)]


def test_eleven_hops_stop_at_the_cap_and_never_request_the_twelfth_url(pulse):
    wire = Wire(chain_routes(11))
    result = check(pulse, wire, u("/h0"), follow=True)
    assert wire.urls == [u(f"/h{i}") for i in range(11)]
    assert (result.status, result.ok, result.error) == (
        301,
        False,
        "stopped after 10 redirects",
    )
    assert result.final_url == u("/h10") and len(result.redirects) == 11


def test_unfollowed_loop_is_a_single_request(pulse):
    wire = Wire(
        {u("/a"): (301, {"location": "/b"}), u("/b"): (301, {"location": "/a"})}
    )
    result = check(pulse, wire, u("/a"), follow=False)
    assert wire.urls == [u("/a")] and result.ok is True and result.redirects == []


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_every_redirect_status_with_a_location_is_followed(pulse, status):
    wire = Wire({u(): (status, {"location": "/next"}), u("/next"): (200, {})})
    result = check(pulse, wire, u(), follow=True)
    assert (
        wire.urls == [u(), u("/next")]
        and result.status == 200
        and result.redirects == wire.urls
    )


@pytest.mark.parametrize(
    "status, headers",
    [
        (302, {}),
        (301, {"location": ""}),
        (300, {"location": "/next"}),
        (304, {"location": "/next"}),
        (305, {"location": "/next"}),
        (200, {"location": "/next"}),
    ],
)
def test_non_redirects_are_returned_as_is_when_following(pulse, status, headers):
    wire = Wire({u(): (status, headers), u("/next"): (200, {})})
    result = check(pulse, wire, u(), follow=True)
    assert wire.urls == [u()] and result.status == status
    assert result.error == "" and result.redirects == [] and result.final_url == u()


def test_relative_location_resolves_against_the_current_url(pulse):
    wire = Wire(
        {
            u("/a/b"): (302, {"location": "c"}),
            u("/a/c"): (302, {"location": "../d"}),
            u("/d"): (200, {}),
        }
    )
    result = check(pulse, wire, u("/a/b"), follow=True)
    assert wire.urls == [u("/a/b"), u("/a/c"), u("/d")] and result.status == 200


def test_in_scope_hop_to_a_sibling_subdomain_is_followed(pulse):
    wire = Wire(
        {
            u(): (301, {"location": "https://www.allowed.example/"}),
            "https://www.allowed.example/": (200, {}),
        }
    )
    result = check(pulse, wire, u(), follow=True)
    assert result.status == 200 and result.final_url == "https://www.allowed.example/"


def test_scheme_downgrade_to_http_in_scope_is_followed(pulse):
    wire = Wire(
        {
            u(): (301, {"location": "http://allowed.example/"}),
            "http://allowed.example/": (200, {}),
        }
    )
    result = check(pulse, wire, u(), follow=True)
    assert (
        wire.urls == [u(), "http://allowed.example/"]
        and result.final_url == "http://allowed.example/"
    )


def test_hop_leaving_scope_after_an_in_scope_hop_keeps_the_chain_so_far(pulse):
    wire = Wire(
        {
            u("/a"): (301, {"location": "/b"}),
            u("/b"): (302, {"location": "https://outside.example/x"}),
        }
    )
    result = check(pulse, wire, u("/a"), follow=True)
    assert wire.urls == [u("/a"), u("/b")]
    assert (result.status, result.ok, result.final_url) == (302, False, u("/b"))
    assert result.redirects == [u("/a"), u("/b")]
    assert (
        "outside.example" in result.error
        and "scope" in result.error
        and "not followed" in result.error
    )


def test_hop_leaving_scope_at_once_records_no_chain(pulse):
    wire = Wire({u(): (302, {"location": "https://outside.example/x"})})
    result = check(pulse, wire, u(), follow=True)
    assert (result.status, result.final_url, result.redirects) == (302, u(), [])


def test_scope_edge_applies_to_look_alike_hosts_in_redirects(pulse):
    wire = Wire({u(): (302, {"location": "https://allowed.example.evil.example/x"})})
    result = check(pulse, wire, u(), follow=True)
    assert wire.urls == [u()] and "allowed.example.evil.example" in result.error


# ---------------------------------------------------------------------------------------------
# D. Explicit policy authorization with an UNGUARDED client (kills "authorize removed")
# ---------------------------------------------------------------------------------------------


def test_every_request_is_preceded_by_an_explicit_crawl_authorization(
    pulse, monkeypatch
):
    events: list[tuple] = []
    real_authorize = egress.authorize

    def spy(target, operation, method="GET"):
        events.append(("authorize", target, operation, method))
        return real_authorize(target, operation, method)

    monkeypatch.setattr(egress, "authorize", spy)
    wire = Wire(
        {u(): (301, {"location": "/home"}), u("/home"): (200, {})}, events=events
    )
    result = check(pulse, wire, u(), follow=True)
    assert result.status == 200
    assert events == [
        ("authorize", u(), "crawl", "GET"),
        ("request", u()),
        ("authorize", u("/home"), "crawl", "GET"),
        ("request", u("/home")),
    ]


def test_in_scope_url_without_a_policy_grant_is_not_requested(pulse, world):
    world.workspace(scope=("allowed.example", "notasset.example"))
    wire = Wire({"https://notasset.example/": (200, {})})
    result = check(pulse, wire, "https://notasset.example/")
    assert wire.requests == []
    assert (
        result.family == "excluded"
        and result.status is None
        and result.ok is False
        and result.excluded
    )
    assert (
        result.error.startswith("asset-unknown")
        and "no outbound action ran" in result.error
    )


@pytest.mark.parametrize(
    "hop",
    ["https://notasset.allowed.example/", "https://allowed.example:8443/"],
    ids=["ungranted-subdomain", "ungranted-port"],
)
def test_in_scope_hop_without_a_policy_grant_keeps_the_prior_response(pulse, hop):
    """Ports and schemes are part of the granted origin; denied hops preserve observed evidence."""
    wire = Wire({u(): (301, {"location": hop}), hop: (200, {})})
    result = check(pulse, wire, u(), follow=True)
    assert wire.urls == [u()]
    assert (result.status, result.family, result.ok, result.final_url) == (
        301,
        "3xx",
        False,
        u(),
    )
    assert result.excluded
    assert (
        result.error.startswith("asset-unknown")
        and "no outbound action ran" in result.error
    )


@pytest.mark.parametrize(
    "location",
    ["https://evil.example@allowed.example/", "https://user:pw@allowed.example/x"],
)
def test_userinfo_redirect_is_excluded_and_keeps_the_prior_response(pulse, location):
    wire = Wire({u(): (301, {"location": location})})
    result = check(pulse, wire, u(), follow=True)
    assert wire.urls == [u()]
    assert (
        result.family == "3xx"
        and result.excluded
        and result.error.startswith("invalid-target")
    )


def test_non_http_scheme_on_an_in_scope_host_is_an_invalid_target(pulse):
    wire = Wire({})
    result = check(pulse, wire, "ftp://allowed.example/x")
    assert wire.requests == [] and result.error.startswith("invalid-target")


def test_missing_policy_file_blocks_every_url_before_any_request(pulse, world):
    world.workspace(policy=False)
    wire = Wire({u(): (200, {})})
    result = check(pulse, wire, u())
    assert wire.requests == []
    assert (
        result.family == "excluded"
        and result.excluded
        and result.error.startswith("policy-missing-or-invalid")
    )


def policy_denial(url: str) -> str:
    """The reason the policy layer itself gives for refusing a crawl of `url` (computed, not hand-typed)."""
    verdict = egress.dry_run(url, "crawl")
    assert verdict["permitted"] is False
    return f"{verdict['reason']}; no outbound action ran"


@pytest.mark.parametrize(
    "options",
    [{"restrict": {"https://allowed.example": ["manual"]}}, {"deny": ("crawl",)}],
    ids=["origin-grant-excludes-crawl", "crawl-switched-off"],
)
def test_crawl_must_be_a_permitted_operation_on_the_origin(pulse, world, options):
    world.workspace(**options)
    wire = Wire({u(): (200, {})})
    result = check(pulse, wire, u())
    assert wire.requests == [] and result.error == policy_denial(u())


def test_crawl_grant_alone_is_enough(pulse, world):
    world.workspace(restrict={"https://allowed.example": ["crawl"]})
    assert check(pulse, Wire({u(): (200, {})}), u()).status == 200


def test_denied_third_hop_keeps_observed_chain_and_exclusion_reason(pulse, sleeps):
    wire = Wire(
        {
            u("/first"): (301, {"location": "/second"}),
            u("/second"): (307, {"location": "https://notasset.allowed.example/"}),
        }
    )
    result = check(pulse, wire, u("/first"), follow=True, retries=3)
    assert wire.urls == [u("/first"), u("/second")]
    assert sleeps == []
    assert (result.status, result.final_url, result.ok, result.excluded) == (
        307,
        u("/second"),
        False,
        True,
    )
    assert result.redirects == wire.urls
    assert "excluded" in pulse._info_cell(result, False)
    assert "asset-unknown" in pulse._info_cell(result, False)


@pytest.mark.parametrize("redirect", [False, True])
def test_transport_policy_block_is_terminal_and_retains_any_prior_response(
    pulse, sleeps, redirect
):
    denied = u("/denied")
    wire = Wire(
        {
            u(): (302, {"location": denied}),
            denied: egress.PolicyBlocked("policy-changed; no outbound action ran"),
        }
    )
    result = check(pulse, wire, u() if redirect else denied, follow=True, retries=3)
    assert wire.urls == ([u(), denied] if redirect else [denied])
    assert sleeps == []
    assert result.excluded and not result.ok
    assert result.status == (302 if redirect else None)
    assert result.final_url == (u() if redirect else "")
    assert result.error == "policy-changed; no outbound action ran"


def test_policy_exclusions_are_exported_and_counted_separately_from_down(world, sleeps):
    world.workspace(scope=("allowed.example", "notasset.example"))
    wire = world.serve(
        {
            u("/redirect"): (302, {"location": "https://notasset.allowed.example/"}),
            u("/down"): (500, {}),
        }
    )
    json_path, csv_path = world.tmp / "results.json", world.tmp / "results.csv"
    run = world.run(
        world.urls_file("https://notasset.example/", u("/redirect"), u("/down")),
        "-f",
        "-r",
        "3",
        "--json",
        str(json_path),
        "--csv",
        str(csv_path),
    )
    assert run.code == 2
    assert sorted(wire.urls) == sorted([u("/redirect"), u("/down")])
    assert sleeps == []
    rows = world.read_json(json_path)["results"]
    assert [row["excluded"] for row in rows] == [True, True, False]
    assert [(row["status"], row["family"]) for row in rows] == [
        (None, "excluded"),
        (302, "3xx"),
        (500, "5xx"),
    ]
    assert rows[1]["final_url"] == u("/redirect") and not rows[1]["ok"]
    with csv_path.open(encoding="utf-8", newline="") as handle:
        assert [row["excluded"] for row in csv.DictReader(handle)] == [
            "True",
            "True",
            "False",
        ]
    assert "0 live | 1 down | 2 excluded | 3 total" in run.plain_out
    assert "EXCLUDED (2)" in run.plain_out and "asset-unknown" in run.plain_out


# ---------------------------------------------------------------------------------------------
# E. Failures: error text table, retries, backoff (spec 4.4 item 5)
# ---------------------------------------------------------------------------------------------

ERROR_ROWS = [
    ("read-timeout", httpx.ReadTimeout("slow"), "timeout"),
    ("connect-timeout", httpx.ConnectTimeout("slow"), "timeout"),
    ("pool-timeout", httpx.PoolTimeout("slow"), "timeout"),
    (
        "tls-certificate",
        httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] bad"),
        "tls error: [SSL: CERTIFICATE_VERIFY_FAILED] bad",
    ),
    (
        "tls-lowercase-ssl",
        httpx.ConnectError("ssl handshake failed"),
        "tls error: ssl handshake failed",
    ),
    (
        "tls-lowercase-certificate",
        httpx.ConnectError("certificate has expired"),
        "tls error: certificate has expired",
    ),
    ("connect-refused", httpx.ConnectError("refused"), "connection failed: refused"),
    (
        "connect-empty-message",
        httpx.ConnectError(""),
        "connection failed: ConnectError",
    ),
    ("too-many-redirects", httpx.TooManyRedirects("x"), "too many redirects"),
    ("unsupported-protocol", httpx.UnsupportedProtocol("x"), "unsupported protocol"),
    ("other-httpx-error", httpx.ReadError("boom"), "boom"),
    ("other-httpx-error-empty", httpx.RemoteProtocolError(""), "RemoteProtocolError"),
    ("non-httpx-exception", RuntimeError("weird"), "RuntimeError: weird"),
    ("non-httpx-oserror", OSError("disk"), "OSError: disk"),
]


@pytest.mark.parametrize(
    "failure, text", [row[1:] for row in ERROR_ROWS], ids=[row[0] for row in ERROR_ROWS]
)
def test_failure_becomes_an_error_row_with_the_documented_text(pulse, failure, text):
    result = check(pulse, Wire({u(): failure}), u())
    assert record(result) == {
        "url": u(),
        "ok": False,
        "status": None,
        "reason": "",
        "family": "error",
        "elapsed_ms": 0,
        "final_url": "",
        "content_type": "",
        "error": text,
        "redirects": [],
        "excluded": False,
    }


@pytest.mark.parametrize(
    "retries, attempts, gaps",
    [
        (-1, 1, []),
        (0, 1, []),
        (1, 2, [0.4]),
        (2, 3, [0.4, 0.8]),
        (3, 4, [0.4, 0.8, 1.2]),
    ],
)
def test_network_failure_makes_retries_plus_one_attempts_with_linear_backoff(
    pulse, sleeps, retries, attempts, gaps
):
    wire = Wire({u(): httpx.ConnectError("down")})
    result = check(pulse, wire, u(), retries=retries)
    assert len(wire.requests) == attempts
    assert sleeps == pytest.approx(gaps)
    assert result.error == "connection failed: down" and result.family == "error"


def test_the_last_attempts_failure_is_the_one_reported(pulse, sleeps):
    outcomes = [httpx.ConnectError("first"), httpx.ReadTimeout("second")]
    wire = Wire(handler=lambda request: outcomes[len(wire.requests) - 1])
    assert check(pulse, wire, u(), retries=1).error == "timeout"


def test_a_flaky_first_attempt_is_retried_to_success(pulse, sleeps):
    wire = Wire(
        handler=lambda request: (
            httpx.ConnectError("flap") if len(wire.requests) == 1 else (200, {})
        )
    )
    result = check(pulse, wire, u(), retries=1)
    assert len(wire.requests) == 2 and sleeps == pytest.approx([0.4])
    assert (result.status, result.ok, result.error) == (200, True, "")


def test_backoff_really_waits_and_elapsed_covers_only_the_successful_attempt(pulse):
    wire = Wire(
        handler=lambda request: (
            httpx.ConnectError("flap") if len(wire.requests) == 1 else (200, {})
        )
    )
    started = time.monotonic()
    result = check(pulse, wire, u(), retries=1)
    assert time.monotonic() - started >= 0.38
    assert result.status == 200 and result.elapsed_ms < 300


@pytest.mark.parametrize("status", [404, 500, 503])
def test_http_statuses_are_never_retried(pulse, sleeps, status):
    wire = Wire({u(): (status, {})})
    result = check(pulse, wire, u(), retries=3)
    assert len(wire.requests) == 1 and sleeps == [] and result.status == status


def test_each_attempt_walks_the_whole_chain_again(pulse, sleeps):
    wire = Wire(
        {u(): (301, {"location": "/home"}), u("/home"): httpx.ConnectError("down")}
    )
    result = check(pulse, wire, u(), follow=True, retries=1)
    assert wire.urls == [u(), u("/home"), u(), u("/home")]
    assert result.error == "connection failed: down"


def test_initial_policy_denials_are_excluded_without_backoff(pulse, world, sleeps):
    world.workspace(scope=("allowed.example", "notasset.example"))
    result = check(pulse, Wire({}), "https://notasset.example/", retries=2)
    assert sleeps == [] and result.excluded
    assert result.error.startswith("asset-unknown")


# ---------------------------------------------------------------------------------------------
# F. The guarded client built by run_checks (spec 4.6, 5.1, 5.2)
# ---------------------------------------------------------------------------------------------


def test_one_guarded_client_is_built_for_the_whole_run_with_operation_crawl(world):
    world.serve({u("/a"): (200, {}), u("/b"): (200, {}), u("/c"): (200, {})})
    results = world.run_checks([u("/a"), u("/b"), u("/c")])
    assert [r.status for r in results] == [200, 200, 200]
    assert len(world.client_kwargs) == 1
    assert world.client_kwargs[0]["operation"] == "crawl"


def test_client_is_told_explicitly_to_ignore_env_proxies_and_never_auto_follow(world):
    world.serve({u(): (200, {})})
    world.run_checks([u()])
    kwargs = world.client_kwargs[0]
    assert kwargs.get("trust_env") is False
    assert kwargs.get("follow_redirects") is False


@pytest.mark.parametrize(
    "timeout, connect", [(3.5, 3.5), (30, 10), (10, 10), (0.5, 0.5)]
)
def test_client_timeout_is_total_with_a_connect_cap_of_ten(world, timeout, connect):
    world.serve({u(): (200, {})})
    world.run_checks([u()], timeout=timeout)
    budget = world.client_kwargs[0]["timeout"]
    assert isinstance(budget, httpx.Timeout)
    assert (budget.connect, budget.read, budget.write, budget.pool) == (
        connect,
        timeout,
        timeout,
        timeout,
    )


def test_client_headers_carry_the_requested_user_agent_and_accept_any(world):
    world.serve({u(): (200, {})})
    world.run_checks([u()], user_agent="UA-Test/1")
    headers = httpx.Headers(world.client_kwargs[0]["headers"])
    assert headers["user-agent"] == "UA-Test/1" and headers["accept"] == "*/*"


@pytest.mark.parametrize("concurrency", [1, 7])
def test_client_connection_limits_equal_the_concurrency(world, concurrency):
    world.serve({u(): (200, {})})
    world.run_checks([u()], concurrency=concurrency)
    limits = world.client_kwargs[0]["limits"]
    assert (limits.max_connections, limits.max_keepalive_connections) == (
        concurrency,
        concurrency,
    )


@pytest.mark.parametrize("insecure, verify", [(False, True), (True, False)])
def test_tls_verification_follows_the_insecure_flag(world, insecure, verify):
    world.serve({u(): (200, {})})
    world.run_checks([u()], insecure=insecure)
    assert world.client_kwargs[0]["verify"] is verify


def test_dash_k_reaches_the_client_from_the_command_line(world):
    world.serve({u(): (200, {})})
    world.run(world.urls_file(u()), "-r", "0", "-k")
    assert world.client_kwargs[0]["verify"] is False
    world.run(world.urls_file(u()), "-r", "0")
    assert world.client_kwargs[1]["verify"] is True


def test_command_line_flags_reach_the_client_and_the_result_rows(world):
    wire = world.serve({u(): (301, {"location": "/home"}), u("/home"): (200, {})})
    world.run(
        world.urls_file(u()), "-c", "7", "-t", "3.5", "-r", "0", "-A", "UA-Test/1", "-f"
    )
    kwargs = world.client_kwargs[0]
    assert (kwargs["limits"].max_connections, kwargs["timeout"].read) == (7, 3.5)
    assert httpx.Headers(kwargs["headers"])["user-agent"] == "UA-Test/1"
    assert wire.urls == [u(), u("/home")]


def test_wire_requests_are_gets_with_the_profile_user_agent_not_the_requested_one(
    world,
):
    wire = world.serve({u("/a"): (200, {}), u("/b"): (200, {})})
    world.run_checks([u("/a"), u("/b")], user_agent="UA-Test/1")
    profile = egress.current_profile()
    assert len(wire.requests) == 2
    for request in wire.requests:
        assert request.method == "GET"
        assert request.headers["user-agent"] == profile.user_agent != "UA-Test/1"
        assert request.headers["accept"] == "*/*"
        for name, value in profile.required_headers:
            assert request.headers[name] == value


def test_each_guarded_request_is_ledgered_under_the_crawl_operation(world):
    world.serve({u("/a"): (200, {}), u("/b"): (200, {})})
    world.run_checks([u("/a"), u("/b"), "https://outside.example/"])
    manifests = world.ledger
    assert sorted(m["target"] for m in manifests) == [u("/a"), u("/b")]
    assert {m["operation"] for m in manifests} == {"crawl"}


def test_guarded_client_runs_under_the_crawl_operation_and_nothing_else(world):
    """An origin that grants only `crawl` must answer through the guarded client (a client built for any other
    operation would be denied by the transport); an origin that grants only `manual` must be refused."""
    world.workspace(
        restrict={
            "https://allowed.example": ["crawl"],
            "https://www.allowed.example": ["manual"],
        }
    )
    wire = world.serve({u(): (200, {}), "https://www.allowed.example/": (200, {})})
    results = world.run_checks([u(), "https://www.allowed.example/"])
    assert wire.urls == [u()]
    assert [r.status for r in results] == [200, None]
    assert results[1].error == policy_denial("https://www.allowed.example/")


def test_out_of_scope_url_is_not_contacted_through_the_guarded_client(world):
    wire = world.serve({"https://outside.example/": (200, {})})
    results = world.run_checks(["https://outside.example/"])
    assert wire.requests == [] and "scope" in results[0].error


def test_missing_policy_excludes_every_in_scope_url_with_exit_two(world):
    world.workspace(policy=False)
    wire = world.serve({u("/a"): (200, {}), u("/b"): (200, {})})
    path = world.urls_file(u("/a"), u("/b"))
    run = world.run(path, "-r", "0", "--json", str(world.tmp / "o.json"))
    assert run.code == 2 and wire.requests == []
    rows = world.read_json(world.tmp / "o.json")["results"]
    assert [r["status"] for r in rows] == [None, None]
    assert all(r["excluded"] for r in rows)
    assert all(r["error"].startswith("policy-missing-or-invalid") for r in rows)


def test_the_policy_profile_paces_requests_regardless_of_the_concurrency_flag(world):
    world.workspace(limits={"requests_per_second": 4, "concurrency": 1})
    wire = world.serve({u(f"/p{i}"): (200, {}) for i in range(4)}, delay=0.02)
    started = time.monotonic()
    results = world.run_checks(
        [u(f"/p{i}") for i in range(4)], concurrency=4, timeout=0.3
    )
    assert time.monotonic() - started >= 0.6
    assert wire.peak == 1
    assert [r.status for r in results] == [200] * 4 and all(
        "timeout" not in r.error for r in results
    )


@pytest.mark.parametrize("concurrency, expected_peak", [(1, 1), (2, 2)])
def test_concurrency_flag_bounds_simultaneous_checks(world, concurrency, expected_peak):
    wire = world.serve(default=(200, {}), delay=0.05)
    results = world.run_checks([u(f"/c{i}") for i in range(6)], concurrency=concurrency)
    assert len(results) == 6 and wire.peak == expected_peak


def test_checks_run_in_parallel_up_to_the_concurrency(world):
    wire = world.serve(default=(200, {}), delay=0.08)
    world.run_checks([u(f"/c{i}") for i in range(6)], concurrency=6)
    assert wire.peak >= 3


def test_results_come_back_in_input_order_even_when_they_finish_out_of_order(world):
    delays = {u("/a"): 0.15, u("/b"): 0.07, u("/c"): 0.0}

    async def handler(request):
        await asyncio.sleep(delays[str(request.url)])
        return (200, {})

    world.serve(handler=handler)
    results = world.run_checks([u("/a"), u("/b"), u("/c")])
    assert [r.url for r in results] == [u("/a"), u("/b"), u("/c")]


# ---------------------------------------------------------------------------------------------
# G. Optional HTTP/2 (spec 4.7). Real h2 against a live server is UNVERIFIED (mock-only).
# ---------------------------------------------------------------------------------------------


def test_http2_is_off_when_h2_cannot_be_imported_and_the_run_still_works(
    world, monkeypatch
):
    monkeypatch.setitem(sys.modules, "h2", None)
    world.serve({u(): (200, {})})
    results = world.run_checks([u()])
    assert world.client_kwargs[0]["http2"] is False
    assert results[0].status == 200


def test_http2_is_on_when_h2_is_importable(world, monkeypatch):
    monkeypatch.setitem(sys.modules, "h2", types.ModuleType("h2"))
    world.serve({u(): (200, {})})
    results = world.run_checks([u()])
    assert world.client_kwargs[0]["http2"] is True
    assert results[0].status == 200


def test_http2_choice_is_made_afresh_on_every_run(world, monkeypatch):
    world.serve({u(): (200, {})})
    monkeypatch.setitem(sys.modules, "h2", types.ModuleType("h2"))
    world.run_checks([u()])
    monkeypatch.setitem(sys.modules, "h2", None)
    world.run_checks([u()])
    assert [k["http2"] for k in world.client_kwargs] == [True, False]


def test_real_httpx_refuses_http2_without_h2_which_is_why_pulse_probes_for_it(
    monkeypatch,
):
    monkeypatch.setitem(sys.modules, "h2", None)
    with pytest.raises(ImportError):
        httpx.AsyncClient(http2=True)


# ---------------------------------------------------------------------------------------------
# H. Input loading and URL normalization (spec 4.2, 4.3)
# ---------------------------------------------------------------------------------------------


def exported_urls(world, *argv_before, **file_options) -> list[str]:
    out = world.tmp / "rows.json"
    run = world.run(*argv_before, "-r", "0", "--json", str(out), **file_options)
    rows = world.read_json(out)["results"]
    assert run.code == 2 if any(row["excluded"] for row in rows) else run.code in (0, 1)
    return [row["url"] for row in rows]


def test_comments_blanks_and_duplicates_are_dropped_keeping_first_occurrence_order(
    world,
):
    wire = world.serve(default=(200, {}))
    path = world.urls_file(
        "# header",
        "",
        "allowed.example",
        "  https://allowed.example/a  ",
        "allowed.example",
        "https://allowed.example/a",
        "   # indented comment",
        "https://allowed.example/A",
        "https://allowed.example/a/",
        "   ",
    )
    urls = exported_urls(world, path)
    assert urls == [
        "https://allowed.example",
        "https://allowed.example/a",
        "https://allowed.example/A",
        "https://allowed.example/a/",
    ]
    assert len(wire.requests) == 4


def test_dash_reads_urls_from_stdin(world):
    wire = world.serve(default=(200, {}))
    urls = exported_urls(
        world,
        "-",
        stdin="# x\nallowed.example/z\n\nallowed.example/z\nhttps://allowed.example/y\n",
    )
    assert urls == ["https://allowed.example/z", "https://allowed.example/y"]
    assert len(wire.requests) == 2


def test_missing_input_file_exits_one_naming_the_file_before_building_a_client(world):
    world.serve(default=(200, {}))
    run = world.run(str(world.tmp / "nope.txt"))
    assert run.code == 1 and "nope.txt" in run.out and "not found" in run.out.lower()
    assert world.client_kwargs == [] and world.wire.requests == []


@pytest.mark.parametrize(
    "content",
    [b"", b"# only\n  # comments\n\n", b"   \n\t\n"],
    ids=["empty", "comments", "blank"],
)
def test_input_without_urls_exits_one(world, content):
    world.serve(default=(200, {}))
    path = world.urls_file(raw=content, name="empty.txt")
    run = world.run(path)
    assert run.code == 1 and "empty.txt" in run.out
    assert world.client_kwargs == []


def test_empty_stdin_exits_one_naming_stdin(world):
    world.serve(default=(200, {}))
    run = world.run("-", stdin="# nothing\n")
    assert run.code == 1 and "stdin" in run.out.lower()
    assert world.client_kwargs == []


NORMALIZATION = [
    ("example.com", "https://example.com"),
    ("192.168.0.1", "https://192.168.0.1"),
    ("example.com/path?q=1", "https://example.com/path?q=1"),
    ("HTTP://EXAMPLE.COM", "HTTP://EXAMPLE.COM"),
    ("ftp://a/x", "ftp://a/x"),
    ("file:///etc/passwd", "file:///etc/passwd"),
    ("mailto:x@y", "mailto:x@y"),
    ("//example.com", "https:////example.com"),
    ("allowed.example", "https://allowed.example"),
    ("http://allowed.example/x", "http://allowed.example/x"),
]


def test_url_normalization_table_through_the_exported_url_field(world):
    """Every row here is out of scope or unauthorized, so nothing is requested - the exported `url` is the evidence."""
    wire = world.serve(default=(200, {}))
    path = world.urls_file(*[raw for raw, _expected in NORMALIZATION])
    assert exported_urls(world, path) == [expected for _raw, expected in NORMALIZATION]
    assert all("example.com" not in url and "192.168" not in url for url in wire.urls)


def test_schemeless_host_with_port_is_prefixed_and_still_policy_checked(
    world,
):
    wire = world.serve(default=(200, {}))
    path = world.urls_file(
        "allowed.example:8080", "localhost:8080/x", "allowed.example:80"
    )
    out = world.tmp / "rows.json"
    world.run(path, "-r", "0", "--json", str(out))
    rows = world.read_json(out)["results"]
    assert [r["url"] for r in rows] == [
        "https://allowed.example:8080",
        "https://localhost:8080/x",
        "https://allowed.example:80",
    ]
    assert rows[0]["error"] and rows[0]["status"] is None
    assert [url.rstrip("/") for url in wire.urls] == ["https://allowed.example:80"]


def test_invalid_utf8_bytes_are_replaced_not_fatal(world):
    world.serve(default=(200, {}))
    path = world.urls_file(raw=b"\xff\xfebad\nallowed.example/ok\n")
    assert exported_urls(world, path) == [
        "https://\ufffd\ufffdbad",
        "https://allowed.example/ok",
    ]


def test_inline_hash_comment_is_removed_and_fragment_is_preserved(world):
    wire = world.serve(default=(200, {}))
    path = world.urls_file(
        "allowed.example/inline # trailing note",
        "allowed.example/fragment#part\t# note",
    )
    assert exported_urls(world, path) == [
        "https://allowed.example/inline",
        "https://allowed.example/fragment#part",
    ]
    assert "https://allowed.example/inline" in wire.urls


# ---------------------------------------------------------------------------------------------
# I. Exit codes (spec 4.1)
# ---------------------------------------------------------------------------------------------

EXIT_ROUTES = {
    u("/ok"): (200, {}),
    u("/also"): (200, {}),
    u("/missing"): (404, {}),
    u("/boom"): (500, {}),
    u("/moved"): (301, {"location": "/home"}),
    u("/home"): (200, {}),
    u("/leave"): (302, {"location": "https://outside.example/x"}),
    u("/odd"): (999, {}),
    u("/loop-a"): (301, {"location": "/loop-b"}),
    u("/loop-b"): (301, {"location": "/loop-a"}),
}
EXIT_CASES = [
    ("all-2xx", [u("/ok"), u("/also")], [], 0),
    ("2xx-and-404", [u("/ok"), u("/missing")], [], 0),
    ("only-404", [u("/missing")], [], 0),
    ("2xx-and-500", [u("/ok"), u("/boom")], [], 1),
    ("only-500", [u("/boom")], [], 1),
    ("2xx-and-unreachable", [u("/ok"), u("/dns-fail")], [], 1),
    ("2xx-and-out-of-scope", [u("/ok"), "https://outside.example/"], [], 1),
    ("2xx-and-policy-denied", [u("/ok"), "ftp://allowed.example/x"], [], 2),
    ("unfollowed-3xx", [u("/moved")], [], 0),
    ("followed-3xx-lands-on-200", [u("/moved")], ["-f"], 0),
    ("followed-3xx-stopped-at-scope-edge", [u("/leave")], ["-f"], 0),
    ("followed-3xx-stopped-by-cap", [u("/loop-a")], ["-f"], 0),
    ("unclassifiable-status", [u("/odd")], [], 1),
    ("only-filter-hides-the-failure", [u("/ok"), u("/boom")], ["--only", "2xx"], 1),
    ("only-filter-hides-a-4xx", [u("/ok"), u("/missing")], ["--only", "5xx"], 0),
]


@pytest.mark.parametrize(
    "lines, flags, code", [c[1:] for c in EXIT_CASES], ids=[c[0] for c in EXIT_CASES]
)
def test_exit_code_matrix(world, lines, flags, code):
    world.serve(EXIT_ROUTES)
    assert world.run(world.urls_file(*lines), "-r", "0", *flags).code == code


@pytest.mark.parametrize(
    "flags",
    [["-c", "0"], ["-c", "-1"], ["-t", "0"], ["-t", "-1"], ["-r", "-1"]],
    ids=lambda flags: " ".join(flags),
)
def test_invalid_numbers_exit_two_with_a_message_on_stdout_before_any_input_is_read(
    world, flags
):
    world.serve(EXIT_ROUTES)
    run = world.run(str(world.tmp / "does-not-exist.txt"), *flags)
    assert run.code == 2 and run.out.strip() and run.err == ""
    assert world.client_kwargs == []


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["urls.txt", "-c", "x"],
        ["urls.txt", "-t", "abc"],
        ["urls.txt", "-r", "1.5"],
        ["urls.txt", "--nope"],
        ["urls.txt", "--only"],
    ],
    ids=["no-file", "c-x", "t-abc", "r-1.5", "unknown-flag", "only-no-value"],
)
def test_argparse_errors_exit_two_with_usage_on_stderr(world, argv):
    world.serve(EXIT_ROUTES)
    run = world.run(*argv)
    assert run.code == 2 and run.out == "" and "usage:" in run.err
    assert world.client_kwargs == []


def test_help_exits_zero_on_stdout_and_lists_every_flag(world):
    run = world.run("-h")
    assert run.code == 0 and "usage:" in run.out
    for flag in (
        "--follow-redirects",
        "--show-redirects",
        "--concurrency",
        "--timeout",
        "--retries",
        "--user-agent",
        "--insecure",
        "--only",
        "--json",
        "--csv",
    ):
        assert flag in run.out


def interrupting(request):
    raise KeyboardInterrupt


def test_ctrl_c_prints_a_notice_exits_130_and_renders_and_exports_nothing(world):
    world.serve(handler=interrupting)
    path = world.urls_file(u("/a"), u("/b"))
    run = world.run(
        path,
        "-r",
        "0",
        "--json",
        str(world.tmp / "o.json"),
        "--csv",
        str(world.tmp / "o.csv"),
    )
    assert run.code == 130
    assert "interrupt" in run.out.lower()
    assert not (world.tmp / "o.json").exists() and not (world.tmp / "o.csv").exists()
    assert (
        not any(word in run.out for word in FAMILY_WORD.values())
        and "Summary" not in run.out
    )


# ---------------------------------------------------------------------------------------------
# J. Exports (spec 6.2, 6.3, 4.9)
# ---------------------------------------------------------------------------------------------

MIXED_ROUTES = {
    u("/ok"): (200, {"content-type": "text/html; charset=utf-8"}),
    "https://www.allowed.example/also": (200, {"content-type": "text/html"}),
    u("/missing"): (404, {}),
    u("/boom"): (500, {"content-type": "application/json"}),
    u("/moved"): (301, {"location": "/home"}),
    u("/home"): (200, {"content-type": "text/plain"}),
    u("/leave"): (302, {"location": "https://outside.example/x"}),
}
MIXED_LIST = [
    u("/ok"),
    u("/missing"),
    u("/boom"),
    u("/moved"),
    u("/leave"),
    "https://outside.example/",
    u("/dns-fail"),
    "# a note",
    "",
    "https://www.allowed.example/also",
]


def run_mixed(world, *flags, lines=MIXED_LIST, routes=MIXED_ROUTES, **options):
    world.serve(routes, **options)
    return world.run(world.urls_file(*lines), "-r", "0", *flags)


def test_json_export_envelope_rows_and_encoding(world):
    path = world.tmp / "out.json"
    unicode_url = "https://allowed.example/caf\u00e9"
    lines = [
        u("/ok"),
        u("/moved"),
        u("/leave"),
        "https://outside.example/",
        unicode_url,
    ]
    run = run_mixed(world, "-f", "--json", str(path), lines=lines)
    assert run.code == 2
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    document = json.loads(text)
    assert list(document) == ["generated_at", "count", "results"]
    assert document["count"] == len(document["results"]) == 5
    assert [r["url"] for r in document["results"]] == lines
    assert all(list(row) == list(FIELDS) for row in document["results"])
    assert document["results"][-1]["excluded"]
    stamp = datetime.fromisoformat(document["generated_at"])
    assert stamp.utcoffset() == timedelta(0) and document["generated_at"].endswith(
        "+00:00"
    )
    assert re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{6})?\+00:00", document["generated_at"]
    )
    assert abs(datetime.now(stamp.tzinfo) - stamp) < timedelta(minutes=5)
    assert text.replace("\r\n", "\n").startswith('{\n  "generated_at": ')
    assert not text.endswith("\n") and "\\u00e9" in text and "\u00e9" not in text


def test_json_rows_carry_nulls_booleans_and_the_flattened_redirect_chain(world):
    path = world.tmp / "out.json"
    run_mixed(world, "-f", "--json", str(path))
    rows = {row["url"]: row for row in world.read_json(path)["results"]}
    ok, moved, leave = rows[u("/ok")], rows[u("/moved")], rows[u("/leave")]
    assert (ok["ok"], ok["status"], ok["redirects"], ok["content_type"]) == (
        True,
        200,
        "",
        "text/html",
    )
    assert (moved["ok"], moved["status"], moved["final_url"]) == (True, 200, u("/home"))
    assert moved["redirects"] == f"{u('/moved')} -> {u('/home')}"
    assert (leave["ok"], leave["status"], leave["redirects"]) == (False, 302, "")
    assert "outside.example" in leave["error"]
    gone = rows["https://outside.example/"]
    assert (gone["ok"], gone["status"], gone["family"], gone["elapsed_ms"]) == (
        False,
        None,
        "error",
        0,
    )
    assert rows[u("/dns-fail")]["error"] == "connection failed: no route " + u(
        "/dns-fail"
    )


def test_json_without_follow_has_empty_redirect_cells(world):
    path = world.tmp / "out.json"
    run_mixed(world, "--json", str(path))
    rows = {row["url"]: row for row in world.read_json(path)["results"]}
    assert rows[u("/moved")]["status"] == 301 and rows[u("/moved")]["redirects"] == ""


def test_csv_export_header_cells_quoting_and_line_endings(world):
    path = world.tmp / "out.csv"
    comma_url = "https://outside.example/a,b"
    accent_url = "https://outside.example/caf\u00e9"
    lines = [u("/ok"), u("/moved"), comma_url, accent_url]
    run = run_mixed(world, "-f", "--csv", str(path), lines=lines)
    assert run.code == 1
    raw = path.read_bytes()
    assert raw.count(b"\r\n") == 5 and raw.count(b"\n") == 5
    assert accent_url.encode("utf-8") in raw and b'"' + comma_url.encode() + b'"' in raw
    rows = list(csv.reader(io.StringIO(raw.decode("utf-8"), newline="")))
    assert rows[0] == list(FIELDS)
    by_url = {row[0]: dict(zip(FIELDS, row)) for row in rows[1:]}
    assert list(by_url) == lines
    assert (by_url[u("/ok")]["ok"], by_url[u("/ok")]["status"]) == ("True", "200")
    assert by_url[comma_url]["ok"] == "False" and by_url[comma_url]["status"] == ""
    assert by_url[u("/moved")]["redirects"] == f"{u('/moved')} -> {u('/home')}"
    assert by_url[u("/ok")]["redirects"] == ""


def test_both_exports_hold_every_row_regardless_of_the_only_filter(world):
    json_path, csv_path = world.tmp / "out.json", world.tmp / "out.csv"
    run = run_mixed(
        world, "--only", "5xx", "--json", str(json_path), "--csv", str(csv_path)
    )
    assert run.code == 1
    document = world.read_json(json_path)
    assert document["count"] == 8 and len(document["results"]) == 8
    with csv_path.open(newline="", encoding="utf-8") as handle:
        assert len(list(csv.DictReader(handle))) == 8
    assert u("/ok") not in run.out


def test_exports_announce_themselves_on_stdout_json_before_csv(world):
    json_path, csv_path = world.tmp / "first.json", world.tmp / "second.csv"
    run = run_mixed(world, "--csv", str(csv_path), "--json", str(json_path))
    assert "wrote" in run.out.lower()
    assert 0 <= run.out.index("first.json") < run.out.index("second.csv")


def test_no_export_files_are_written_unless_asked(world):
    run_mixed(world)
    assert not list(world.tmp.glob("*.json")) and not list(world.tmp.glob("*.csv"))


# ---------------------------------------------------------------------------------------------
# K. The --only display filter (spec 4.8); P1 is a known defect
# ---------------------------------------------------------------------------------------------

ONLY_ROUTES = {
    u("/ok"): (200, {}),
    u("/moved"): (301, {"location": "/home"}),
    u("/missing"): (404, {}),
    u("/gone"): (410, {}),
    u("/boom"): (500, {}),
}
ONLY_LIST = [
    u("/ok"),
    u("/moved"),
    u("/missing"),
    u("/gone"),
    u("/boom"),
    "https://outside.example/",
]
ONLY_URL_FAMILY = {
    u("/ok"): "2xx",
    u("/moved"): "3xx",
    u("/missing"): "4xx",
    u("/gone"): "4xx",
    u("/boom"): "5xx",
    "https://outside.example/": "error",
}


def shown_tables(out: str) -> list[str]:
    return [
        family
        for family, word in FAMILY_WORD.items()
        if re.search(rf"{word}[^\n]*\(\d+\)", out)
    ]


def shown_urls(out: str) -> set[str]:
    return {url for url in ONLY_URL_FAMILY if url in out}


def only_run(world, only):
    world.serve(ONLY_ROUTES)
    return world.run(world.urls_file(*ONLY_LIST), "-r", "0", "--only", only)


def urls_of(*families: str, drop=()) -> set[str]:
    return {
        url
        for url, family in ONLY_URL_FAMILY.items()
        if family in families and url not in drop
    }


ONLY_TABLE = [
    ("2xx", ["2xx"], urls_of("2xx")),
    ("2xx,error", ["2xx", "error"], urls_of("2xx", "error")),
    ("4xx,5xx,error", ["4xx", "5xx", "error"], urls_of("4xx", "5xx", "error")),
    (" 2xx , 3xx ", ["2xx", "3xx"], urls_of("2xx", "3xx")),
    ("3xx,,2xx", ["2xx", "3xx"], urls_of("2xx", "3xx")),
    ("2xx,bogus", ["2xx"], urls_of("2xx")),
    ("4xx,404", ["4xx"], urls_of("4xx", drop={u("/gone")})),
]


@pytest.mark.parametrize(
    "only, tables, urls", ONLY_TABLE, ids=[row[0] for row in ONLY_TABLE]
)
def test_only_family_tokens_choose_the_tables_in_fixed_order(world, only, tables, urls):
    run = only_run(world, only)
    assert shown_tables(run.out) == tables
    assert shown_urls(run.out) == urls
    assert "no results matched" not in run.out.lower()


@pytest.mark.parametrize(
    "only", ["404,500,error", "bogus", ",", "ERROR", "2XX", "2xx,404"]
)
def test_only_filters_that_select_nothing_print_the_no_match_message__pinned_current(
    world, only
):
    """Explicit families constrain numeric filters; family matching is case-sensitive."""
    run = only_run(world, only)
    assert shown_tables(run.out) == [] and shown_urls(run.out) == set()
    assert "no results matched" in run.out.lower()
    assert run.code == 1


@pytest.mark.parametrize(
    "only, expected",
    [
        ("404", {u("/missing")}),
        ("404,500", {u("/missing"), u("/boom")}),
        ("200", {u("/ok")}),
    ],
)
def test_only_with_bare_status_codes_shows_exactly_those_rows__correct(
    world, only, expected
):
    run = only_run(world, only)
    assert shown_urls(run.out) == expected
    assert "no results matched" not in run.out.lower()


def test_only_changes_neither_the_summary_nor_the_exit_code(world):
    full = only_run(world, "2xx,3xx,4xx,5xx,error")
    narrow = only_run(world, "5xx")
    assert full.code == narrow.code == 1
    for pattern in (
        r"(\d+) live",
        r"(\d+) down",
        r"(\d+) total",
        r"2xx (\d+)",
        r"4xx (\d+)",
        r"err (\d+)",
    ):
        assert re.search(pattern, full.out).group(1) == re.search(
            pattern, narrow.out
        ).group(1)


# ---------------------------------------------------------------------------------------------
# L. Display contract (spec 4.8) - loose on wording, strict on required content
# ---------------------------------------------------------------------------------------------


def test_tables_appear_in_fixed_family_order_with_row_counts(world):
    run = run_mixed(world)
    assert shown_tables(run.out) == ["2xx", "3xx", "4xx", "5xx", "error"]
    positions = [
        re.search(rf"{word}[^\n]*\(\d+\)", run.out).start()
        for word in FAMILY_WORD.values()
    ]
    assert positions == sorted(positions)
    counts = {
        family: int(re.search(rf"{word}[^\n]*\((\d+)\)", run.out).group(1))
        for family, word in FAMILY_WORD.items()
    }
    assert counts == {"2xx": 2, "3xx": 2, "4xx": 1, "5xx": 1, "error": 2}


def test_families_without_rows_are_omitted(world):
    run = run_mixed(world, lines=[u("/ok"), u("/missing")])
    assert shown_tables(run.out) == ["2xx", "4xx"]


def test_rows_keep_input_order_within_a_family(world):
    lines = [u("/zeta"), u("/missing"), u("/alpha"), u("/mid")]
    routes = {
        u("/zeta"): (200, {}),
        u("/alpha"): (200, {}),
        u("/mid"): (200, {}),
        u("/missing"): (404, {}),
    }
    run = run_mixed(world, lines=lines, routes=routes)
    assert run.out.index("/zeta") < run.out.index("/alpha") < run.out.index("/mid")


def test_rows_show_code_or_a_placeholder_and_the_final_url_or_error_or_reason(world):
    run = run_mixed(world, "-f")
    out = run.plain_out
    line = lambda token: next(row for row in out.splitlines() if token in row)
    assert (
        "200" in line(u("/ok"))
        and "OK" in line(u("/ok"))
        and "text/html" in line(u("/ok"))
    )
    assert "Not Found" in line(u("/missing")) and "404" in line(u("/missing"))
    assert u("/home") in line(u("/moved"))
    scope_row = line("https://outside.example/")
    assert "----" in scope_row and "scope" in scope_row
    assert re.search(
        r"[\u2014\u2013-]",
        scope_row.replace("----", "").replace("https://outside.example/", ""),
    )
    assert "connection failed" in line(u("/dns-fail"))


def test_show_redirects_adds_the_chain_to_rows_that_have_one(world):
    plain_run = run_mixed(world, "-f")
    shown = run_mixed(world, "-f", "--show-redirects")
    assert plain_run.out.count(u("/moved")) == 1
    assert shown.out.count(u("/moved")) >= 2 and u("/home") in shown.out


def test_show_redirects_is_inert_without_a_followed_chain(world):
    plain_run = run_mixed(world)
    shown = run_mixed(world, "--show-redirects")
    assert plain_run.out.count(u("/moved")) == shown.out.count(u("/moved")) == 1


def test_summary_counts(world):
    run = run_mixed(world)
    out = run.plain_out
    grab = lambda pattern: int(re.search(pattern, out).group(1))
    assert (grab(r"(\d+) live"), grab(r"(\d+) down"), grab(r"(\d+) total")) == (4, 4, 8)
    assert [
        grab(rf"{label} (\d+)") for label in ("2xx", "3xx", "4xx", "5xx", "err")
    ] == [2, 2, 1, 1, 2]


def test_summary_counts_when_following(world):
    out = run_mixed(world, "-f").plain_out
    grab = lambda pattern: int(re.search(pattern, out).group(1))
    assert (grab(r"(\d+) live"), grab(r"(\d+) down"), grab(r"(\d+) total")) == (3, 5, 8)
    assert [
        grab(rf"{label} (\d+)") for label in ("2xx", "3xx", "4xx", "5xx", "err")
    ] == [3, 1, 1, 1, 2]


def test_summary_average_covers_only_timed_rows_and_wall_has_two_decimals(world):
    out = run_mixed(
        world,
        lines=[u("/ok"), "https://outside.example/", "https://outside.example/2"],
        delay=0.04,
    ).plain_out
    average = int(re.search(r"avg\D*(\d+)", out).group(1))
    assert 30 <= average < 1500
    assert re.search(r"wall\D*\d+\.\d{2}(?!\d)", out)


def test_summary_average_is_zero_when_no_row_was_timed(world):
    out = run_mixed(world, lines=["https://outside.example/"]).plain_out
    assert int(re.search(r"avg\D*(\d+)", out).group(1)) == 0


def test_header_panel_reports_the_run_parameters(world):
    world.serve(default=(200, {}))
    path = world.urls_file(u("/a"), u("/b"), u("/c"))
    header = lambda run: run.out.split(FAMILY_WORD["2xx"], 1)[0]
    following = header(world.run(path, "-c", "7", "-t", "3.5", "-r", "2", "-f"))
    plain_header = header(world.run(path, "-c", "7", "-t", "3.5", "-r", "2"))
    for token in ("3", "7", "3.5", "2"):
        assert token in following and token in plain_header
    assert following != plain_header


def test_no_results_message_when_the_filter_selects_nothing(world):
    run = only_run(world, "bogus")
    assert "no results matched" in run.out.lower()
    assert "total" in run.out


# ---------------------------------------------------------------------------------------------
# M. The loader path (`bughunt pulse`) (spec 2.3, section 8.3 item 15)
# ---------------------------------------------------------------------------------------------


def run_named(name: str, *argv: str) -> int:
    return loader.run_named(
        name,
        list(argv),
        tool_file=Path(scanner.__file__).resolve(),
        scan_main=scanner.scan_main,
    )


@pytest.fixture
def via_loader(world, addons_root, monkeypatch):
    """`bughunt pulse` through loader.run_named, with the loader's own console captured."""
    monkeypatch.setenv("BUGHUNT_ADDONS", str(addons_root))
    console_text = io.StringIO()
    monkeypatch.setattr(
        ui,
        "console",
        Console(theme=ui.THEME, highlight=False, file=console_text, width=200),
    )

    def call(*argv: str):
        code = run_named("pulse", *argv)
        out, err = world.capsys.readouterr()
        return Run(code, out, err), console_text.getvalue()

    return call


def test_loader_module_key_and_program_name(pulse, world, via_loader):
    assert re.fullmatch(r"bughunt_tools\.pulse_[0-9a-f]{12}", pulse.__name__)
    wire = world.serve({u(): (200, {})})
    run, _console = via_loader(world.urls_file(u()), "-r", "0")
    assert run.code == 0
    assert wire.argv_seen[0][0] == "bughunt pulse"


@pytest.mark.parametrize(
    "lines, flags, code",
    [
        ([u("/ok")], [], 0),
        ([u("/ok"), u("/missing")], [], 0),
        ([u("/ok"), u("/boom")], [], 1),
        ([u("/ok"), "https://outside.example/"], [], 1),
    ],
    ids=["all-ok", "with-404", "with-500", "out-of-scope"],
)
def test_loader_returns_the_exit_code(world, via_loader, lines, flags, code):
    world.serve(EXIT_ROUTES)
    run, _console = via_loader(world.urls_file(*lines), "-r", "0", *flags)
    assert run.code == code


@pytest.mark.parametrize(
    "argv", [["--bogus"], [], ["x.txt", "-c", "0"], ["x.txt", "-t", "-1"]]
)
def test_loader_maps_usage_and_validation_errors_to_two(world, via_loader, argv):
    world.serve(EXIT_ROUTES)
    run, _console = via_loader(*argv)
    assert run.code == 2


def test_loader_missing_file_is_one(world, via_loader):
    world.serve(EXIT_ROUTES)
    run, _console = via_loader(str(world.tmp / "nope.txt"))
    assert run.code == 1 and "nope.txt" in run.out


def test_loader_help_is_zero(world, via_loader):
    run, _console = via_loader("-h")
    assert run.code == 0 and "usage:" in run.out and "--follow-redirects" in run.out


def test_loader_maps_a_policy_block_at_client_construction_to_two_with_the_reason(
    world, via_loader, monkeypatch
):
    """ASSUMED path (spec 2.3, read from egress._wrap): a construction-time PolicyBlocked is not an error row;
    it escapes main and the loader prints the reason. Injected here by a stub - no real invalid actor is built."""

    def refuse(**kwargs):
        raise egress.PolicyBlocked("actor-missing-or-invalid; no outbound action ran")

    monkeypatch.setattr(egress, "async_client", refuse)
    run, console = via_loader(world.urls_file(u("/ok")), "-r", "0")
    assert run.code == 2
    assert "actor-missing-or-invalid" in console


def test_loader_returns_130_for_ctrl_c_because_pulse_converts_the_interrupt_itself(
    world, via_loader
):
    world.serve(handler=interrupting)
    run, _console = via_loader(world.urls_file(u("/a")), "-r", "0")
    assert run.code == 130 and "interrupt" in run.out.lower()


# ---------------------------------------------------------------------------------------------
# N. Known defects: assert the CORRECT behavior, xfail until the rebuild fixes it
# ---------------------------------------------------------------------------------------------


def test_policy_denied_hop_keeps_the_earlier_answer_with_a_stop_note(pulse):
    wire = Wire(
        {
            u(): (301, {"location": "https://notasset.allowed.example/"}),
            "https://notasset.allowed.example/": (200, {}),
        }
    )
    result = check(pulse, wire, u(), follow=True)
    assert wire.urls == [u()]
    assert result.status == 301 and result.family == "3xx" and result.final_url == u()
    assert result.error and result.excluded and not result.ok


def test_policy_denial_is_not_retried_or_slept_on(pulse, world, sleeps):
    world.workspace(scope=("allowed.example", "notasset.example"))
    result = check(pulse, Wire({}), "https://notasset.example/", retries=2)
    assert sleeps == []
    assert result.error.startswith("asset-unknown")


def test_schemeless_host_with_a_granted_port_gets_https_and_is_requested__correct(
    world,
):
    wire = world.serve(default=(200, {}))
    path = world.urls_file("allowed.example:80")
    assert exported_urls(world, path) == ["https://allowed.example:80"]
    assert [url.rstrip("/") for url in wire.urls] == ["https://allowed.example:80"]


def test_inline_hash_comment_is_stripped_from_the_url__correct(world):
    wire = world.serve(default=(200, {}))
    path = world.urls_file("allowed.example/inline # trailing note")
    assert exported_urls(world, path) == ["https://allowed.example/inline"]
    assert wire.urls == ["https://allowed.example/inline"]


def test_directory_as_input_is_a_clean_exit_one__correct(world, via_loader):
    world.serve(default=(200, {}))
    run, console = via_loader(str(world.tmp))
    assert run.code == 1
    assert "Traceback" not in run.err and "Traceback" not in console


@pytest.mark.parametrize(
    "through_loader, shared", [(False, False), (True, False), (False, True)]
)
@pytest.mark.parametrize(
    "mode, expected", [("ok", 0), ("input", 1), ("usage", 2), ("export", 1)]
)
def test_output_encoding_policy_is_restored(
    world, addons_root, monkeypatch, through_loader, shared, mode, expected
):
    world.serve(default=(200, {}))
    source = world.urls_file(u("/ok"))
    arguments = [source, "-r", "0"]
    if mode == "input":
        arguments[0] = str(world.tmp / "absent")
    elif mode == "usage":
        arguments += ["--concurrency", "0"]
    elif mode == "export":
        arguments += ["--json", str(world.tmp / "absent" / "out.json")]
    output = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict")
    error = (
        output
        if shared
        else io.TextIOWrapper(
            io.BytesIO(), encoding="cp1252", errors="xmlcharrefreplace"
        )
    )
    with monkeypatch.context() as patch:
        patch.setattr(sys, "stdout", output)
        patch.setattr(sys, "stderr", error)
        patch.setattr(sys, "argv", ["bughunt pulse", *arguments])
        patch.setenv("BUGHUNT_ADDONS", str(addons_root))
        try:
            code = (
                run_named("pulse", *arguments) if through_loader else world.pulse.main()
            )
        except SystemExit as stopped:
            code = stopped.code
        assert code == expected
        assert output.errors == "strict"
        assert error.errors == ("strict" if shared else "xmlcharrefreplace")
        print(json.dumps({"next": "🙂"}, ensure_ascii=True))
        output.flush()
        assert json.loads(
            output.buffer.getvalue().decode("cp1252").splitlines()[-1]
        ) == {"next": "🙂"}


def test_directory_as_input_exits_one__pinned_current(world, via_loader):
    """P7: today this is an uncaught PermissionError/IsADirectoryError that the loader turns into rc 1."""
    world.serve(default=(200, {}))
    run, _console = via_loader(str(world.tmp))
    assert run.code == 1 and world.client_kwargs == []


@pytest.mark.parametrize("export_flag", ["--json", "--csv"])
def test_unwritable_export_path_is_a_clean_exit_one_naming_the_path__correct(
    world, via_loader, export_flag
):
    world.serve(MIXED_ROUTES)
    target = world.tmp / "no-such-dir" / "out.json"
    run, console = via_loader(
        world.urls_file(u("/ok")), "-r", "0", export_flag, str(target)
    )
    assert run.code == 1
    assert "Traceback" not in run.err and "Traceback" not in console
    assert "no-such-dir" in run.out + console


def test_unwritable_export_path_exits_one_after_displaying_the_results__pinned_current(
    world, via_loader
):
    """P7: today the OSError is uncaught (loader rc 1); the tables and summary were already printed."""
    world.serve(MIXED_ROUTES)
    target = world.tmp / "no-such-dir" / "out.json"
    run, _console = via_loader(
        world.urls_file(u("/ok")), "-r", "0", "--json", str(target)
    )
    assert run.code == 1 and "total" in run.out and not target.exists()


def test_bracketed_file_names_are_printed_literally__correct(world, monkeypatch):
    """Relative name on purpose: a Windows path separator before `[` would escape the markup and mask the defect."""
    world.serve(default=(200, {}))
    monkeypatch.chdir(world.tmp)
    run = world.run("[bold]z.txt")
    assert run.code == 1 and "[bold]z.txt" in run.out.replace("\n", "")


# Subprocess defects: the child sees a real interpreter start (stdout encoding, sys.path).


def child_env(world, **extra) -> dict:
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "BUGHUNT_ADDONS", "PYTHONUTF8", "PYTHONIOENCODING"}
    }
    env.update(
        BUGHUNT_SCOPE=str(world.scope_dir), COLUMNS="250", PYTHONDONTWRITEBYTECODE="1"
    )
    env.update(extra)
    return env


def test_standalone_launch_works_from_a_directory_where_bughunt_is_not_importable__correct(
    world, standalone_python
):
    path = world.urls_file("https://outside.example/")
    done = subprocess.run(
        [*standalone_python, str(SCRIPT), path],
        cwd=str(world.tmp),
        env=child_env(world),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    assert "ModuleNotFoundError" not in done.stderr, done.stderr[-600:]
    assert done.returncode == 1 and "scope" in done.stdout


CP1252_DRIVER = """
import sys
sys.path.insert(0, {repo!r})
import httpx
from pathlib import Path
from bughunt.core import egress
from bughunt.console import loader

real = egress.async_client
routes = {{"https://allowed.example/moved": (301, {{"location": "/home"}}), "https://allowed.example/home": (200, {{}})}}

def respond(request):
    status, headers = routes[str(request.url)]
    return httpx.Response(status, headers=headers, request=request)

def guarded_over_mock(**kwargs):
    kwargs["transport"] = httpx.MockTransport(respond)
    return real(**kwargs)

egress.async_client = guarded_over_mock
module = loader.import_script(Path({script!r}))
sys.argv = ["bughunt pulse", {urls!r}, "-r", "0", "-f", "--show-redirects"]
module.main()
"""


def test_show_redirects_survives_a_cp1252_stdout__correct(world):
    urls = world.urls_file(u("/moved"))
    driver = world.tmp / "driver.py"
    driver.write_text(
        CP1252_DRIVER.format(repo=str(REPO), script=str(SCRIPT), urls=urls),
        encoding="utf-8",
    )
    done = subprocess.run(
        [sys.executable, str(driver)],
        cwd=str(world.tmp),
        env=child_env(world, PYTHONIOENCODING="cp1252"),
        capture_output=True,
        timeout=120,
    )
    stderr = done.stderr.decode("utf-8", "replace")
    assert "UnicodeEncodeError" not in stderr and "Traceback" not in stderr, stderr[
        -600:
    ]
    assert done.returncode == 0
    assert "total" in done.stdout.decode("cp1252", "replace")
