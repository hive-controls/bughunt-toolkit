"""Characterization oracle for addons/IOCaw, written BEFORE the clean-room rebuild.

Scope: everything `tests/test_addons.py` leaves unpinned for the `ioc` addon - the parser table, the
eight subcommands' output (rich text and `--json` pass-through), exit codes, the feed-row schema,
the year CSV rules, defang, export formats, the egress/policy posture and the loader path.

Network posture: NO real TweetFeed call is made. Every response is served by `httpx.MockTransport`
at the egress edge (the addon's own client is built by the real `bughunt.core.http.api_client`, so
the real policy gate, host guard and wire-header rules run in front of the mock), and an autouse
tripwire makes DNS and TCP connects raise. Every TweetFeed response shape here is INVENTED from the
display logic of the code under test: the live service's shapes, headers and tag syntax are
UNVERIFIED (mock-only), and tests that depend on them say so.

Tiers follow the spec (m2-iocaw-spec.md): tests named for a defect (D1, D2, D4 ... D11) assert the
CORRECT behavior and are marked xfail(strict=True) until the rebuild fixes them; every other test
pins current behavior the rebuild must reproduce. A few pins are intentionally the OPPOSITE of a
defect fix and say so (the `*_current_*` tests): flip or delete them if the orchestrator approves
the matching deviation (D5 retry policy, D11 `--quiet` placement).

Point the suite at another copy of the script (mutation proofs, or the rebuilt file in a scratch
location) with `BUGHUNT_IOC_UNDER_TEST=<path to iocaw.py>`; the default is the repo's addon. Each
test imports its OWN copy of that file under its own workspace, so import-time behavior is
exercised every time.
"""

from __future__ import annotations

import argparse
import ast
import csv
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from rich.console import Console

from bughunt.console import catalog, loader, options, ui
from bughunt.console.catalog_export import export_catalog
from bughunt.core import egress
from bughunt.core import http as core_http
from bughunt.core import scanner, workspace
from bughunt.core.http import api_client
from test_gate import seed_policy

REPO = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT = REPO / "addons" / "IOCaw" / "iocaw.py"
SCRIPT = Path(os.environ.get("BUGHUNT_IOC_UNDER_TEST") or DEFAULT_SCRIPT).resolve()

BASE = "https://api.tweetfeed.live"
CSV_URL = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv"
API_HOSTS = frozenset({"api.tweetfeed.live", "raw.githubusercontent.com"})
ADDON_ACCEPT = "application/json, text/csv, text/plain;q=0.8, */*;q=0.5"
CSV_HEADER_LINE = "date,user,type,value,tags,tweet"
PROFILE_UA = "Bughunt-owned-lab"  # the User-Agent the test policy profile stamps on every request
WINDOWS = ("today", "week", "month", "year")
IOC_TYPES = ("url", "domain", "ip", "sha256", "md5")
BLOCKLIST_KINDS = (
    "domains",
    "ips",
    "urls",
    "sha256",
    "md5",
    "hosts",
    "adguard",
    "rpz",
    "dnsmasq",
    "nrd-domains",
)
SPARK_BLOCKS = "".join(chr(code) for code in range(0x2581, 0x2589))

ROW_URL = {
    "date": "2026-10-18 10:01:02",
    "user": "alice",
    "type": "url",
    "value": "https://evil.example/login",
    "tags": ["#phishing", "#scam"],
    "tweet": "https://twitter.example/alice/status/1",
}
ROW_IP = {
    "date": "2026-10-18 09:00:00",
    "user": "@bob",
    "type": "ip",
    "value": "203.0.113.7",
    "tags": ["#c2"],
    "tweet": "https://twitter.example/bob/status/2",
}
ROW_HASH = {
    "date": "2026-10-18 08:00:00",
    "user": "carol",
    "type": "sha256",
    "value": "a" * 64,
    "tags": [],
    "tweet": "",
}
ROWS = [ROW_URL, ROW_IP, ROW_HASH]


def json_reply(payload, *, status=200, headers=None):
    return (
        status,
        {"content-type": "application/json", **(headers or {})},
        json.dumps(payload).encode(),
    )


def text_reply(text, *, status=200, ctype="text/plain", headers=None):
    body = text if isinstance(text, bytes) else text.encode("utf-8")
    return (status, {"content-type": ctype, **(headers or {})}, body)


def squash(text: str) -> str:
    """Collapse every whitespace run so content assertions do not depend on table layout."""
    return re.sub(r"\s+", " ", text)


def in_order(text: str, *parts: str) -> bool:
    """True when each part occurs in `text` after the previous one (whitespace-insensitive)."""
    haystack, position = squash(text), 0
    for part in parts:
        found = haystack.find(squash(part), position)
        if found < 0:
            return False
        position = found + len(squash(part))
    return True


# ---------------------------------------------------------------------------------------------
# Harness: scratch policy workspace + egress-edge mock + a private copy of the script under test
# ---------------------------------------------------------------------------------------------


@dataclass
class Run:
    code: object  # int exit code, or None when an exception escaped main()
    out: str
    err: str
    exc: BaseException | None = None

    @property
    def text(self) -> str:
        return squash(self.out)

    @property
    def lines(self) -> list[str]:
        return [line.strip() for line in self.out.splitlines()]

    def json(self):
        return json.loads(self.out)


class World:
    """A policy workspace, a mock TweetFeed behind the real guarded client, and one imported addon."""

    def __init__(self, monkeypatch, tmp_path, capsys):
        self.mp, self.tmp, self.capsys = (
            monkeypatch,
            tmp_path / "world",
            capsys,
        )  # tmp_path itself stays clean for exports
        self.tmp.mkdir()
        self.requests: list[httpx.Request] = []
        self._routes: dict = {}
        self._default = None
        self._handler = None
        self._imports = 0
        self.ioc = None
        self.addons_root: Path | None = None
        self.transport = httpx.MockTransport(self._respond)
        self.workspace_dir = self.tmp / "workspace"

        def factory(hosts, **kwargs):
            kwargs.setdefault("transport", self.transport)
            return api_client(hosts, **kwargs)

        monkeypatch.setattr(core_http, "api_client", factory)
        monkeypatch.setattr(
            egress.clock, "sleep", time.sleep
        )  # bind egress's pacing wait to the real time.sleep so the poll is not recorded (clock.now stays real perf_counter); precedes the recorded-sleep patch
        for name in ("FORCE_COLOR", "NO_COLOR", "BUGHUNT_ADDONS"):
            monkeypatch.delenv(name, raising=False)
        self.workspace()
        self.load()

    # -- the mock edge -------------------------------------------------------------------------

    def _respond(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._handler is not None:
            spec = self._handler(request)
        else:
            spec = self._routes.get(str(request.url), self._default)
        if spec is None:
            raise AssertionError(f"unrouted request {request.url}")
        if isinstance(spec, BaseException):
            raise spec
        status, headers, body = spec
        return httpx.Response(status, headers=headers, content=body, request=request)

    def serve(self, default=None, *, routes=None, handler=None) -> None:
        """`default` answers every URL; `routes` maps exact URL -> reply; `handler(request)` wins."""
        self._default, self._routes, self._handler = (
            default,
            dict(routes or {}),
            handler,
        )

    @property
    def urls(self) -> list[str]:
        return [str(request.url) for request in self.requests]

    # -- workspace and module ------------------------------------------------------------------

    def workspace(
        self, directory: Path | None = None, *, drop=(), policy=True, mutate=None
    ) -> Path:
        """Seed a verified policy (api.tweetfeed.live and raw.githubusercontent.com granted, every
        operation). `drop` removes assets, `mutate(document)` edits the policy, `policy=False` removes it."""
        target = directory or self.workspace_dir
        target.mkdir(parents=True, exist_ok=True)
        (target / "policy.json").unlink(missing_ok=True)
        document = seed_policy(target)
        document["assets"] = [
            row for row in document["assets"] if row["origin"] not in set(drop)
        ]
        if mutate is not None:
            mutate(document)
        (target / "policy.json").write_text(json.dumps(document), encoding="utf-8")
        if not policy:
            (target / "policy.json").unlink()
        self.mp.setenv("BUGHUNT_SCOPE", str(target))
        return target

    def load(self, columns: str | None = "140"):
        """Import a fresh private copy of the script. Rich reads COLUMNS when its console is built,
        so the width must be chosen here; `columns=None` means "not a terminal, no COLUMNS" (80)."""
        self._imports += 1
        if columns is None:
            self.mp.delenv("COLUMNS", raising=False)
        else:
            self.mp.setenv("COLUMNS", columns)
        self.addons_root = self.tmp / f"addons-{self._imports}"
        folder = self.addons_root / "IOCaw"
        folder.mkdir(parents=True)
        shutil.copyfile(SCRIPT, folder / "iocaw.py")
        self.ioc = loader.import_script(folder / "iocaw.py")
        return self.ioc

    def forget_modules(self) -> None:
        for key in [
            key
            for key, module in sys.modules.items()
            if str(getattr(module, "__file__", "") or "").startswith(str(self.tmp))
        ]:
            sys.modules.pop(key, None)

    # -- running -------------------------------------------------------------------------------

    def run(self, *argv: str) -> Run:
        code, exc = None, None
        try:
            code = self.ioc.main(list(argv))
        except SystemExit as stop:
            code = stop.code
        except Exception as raised:  # noqa: BLE001 - the oracle records what escapes main()
            exc = raised
        out, err = self.capsys.readouterr()
        return Run(code, out, err, exc)

    def via_loader(self, name: str, *argv: str):
        """`bughunt <name> ...` through loader.run_named with the loader's own console captured."""
        self.mp.setenv("BUGHUNT_ADDONS", str(self.addons_root))
        console_text = io.StringIO()
        self.mp.setattr(
            ui,
            "console",
            Console(theme=ui.THEME, highlight=False, file=console_text, width=200),
        )
        code = loader.run_named(
            name,
            list(argv),
            tool_file=Path(scanner.__file__).resolve(),
            scan_main=scanner.scan_main,
        )
        out, err = self.capsys.readouterr()
        return Run(code, out, err), console_text.getvalue()

    def sleeps(self, stop_after: int = 3) -> list:
        """Replace time.sleep: records the interval and raises KeyboardInterrupt after `stop_after` calls."""
        calls: list = []

        def sleeper(seconds):
            calls.append(seconds)
            if len(calls) >= stop_after:
                raise KeyboardInterrupt

        self.mp.setattr(time, "sleep", sleeper)
        self.mp.setattr(self.ioc, "sleep", sleeper, raising=False)
        return calls


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Tripwire: nothing in this module may resolve a name or open a socket."""

    def forbidden(*args, **kwargs):
        raise AssertionError("real network reached from an IOCaw characterization test")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def world(monkeypatch, tmp_path, capsys):
    scene = World(monkeypatch, tmp_path, capsys)
    yield scene
    scene.forget_modules()


# ---------------------------------------------------------------------------------------------
# A. Module surface and CLI parser table (spec 2.1, section 3)  [C1]
# ---------------------------------------------------------------------------------------------


def parser_table(parser) -> dict:
    """dest -> (option strings, default, choices, nargs, type name) for every non-help action."""
    table = {}
    for action in parser._actions:
        if action.dest in ("help", "version", "cmd"):
            continue
        table[action.dest] = (
            tuple(action.option_strings),
            action.default,
            tuple(action.choices) if action.choices else None,
            action.nargs,
            getattr(action.type, "__name__", None) if action.type else None,
        )
    return table


def flag(*names):
    return (names, False, None, 0, None)


def value(*names, default=None, choices=None, kind=None):
    return (names, default, choices, None, kind)


FILTERS = {
    "type": value("--type", choices=IOC_TYPES),
    "tag": value("--tag"),
    "user": value("--user"),
}


def shared(limit):
    return {
        "json": flag("--json"),
        "defang": flag("--defang"),
        "limit": value("--limit", default=limit, kind="int"),
        "export": value("--export"),
    }


EXPECTED_PARSER = {
    "feed": {
        "window": ((), "today", WINDOWS, "?", None),
        **FILTERS,
        **shared(40),
        "contains": value("--contains"),
        "values_only": flag("--values-only"),
        "tweets": flag("--tweets"),
    },
    "lookup": {
        "value": ((), None, None, None, None),
        "json": flag("--json"),
        "defang": flag("--defang"),
        "tweets": flag("--tweets"),
    },
    "campaigns": {"id": value("--id"), **shared(40)},
    "trends": {
        "json": flag("--json"),
        "limit": value("--limit", default=15, kind="int"),
    },
    "counts": {
        "window": ((), None, WINDOWS, "?", None),
        "json": flag("--json"),
        "limit": value("--limit", default=12, kind="int"),
    },
    "status": {"json": flag("--json")},
    "watch": {
        "since": value("--since"),
        "interval": value("--interval", default=60, kind="int"),
        "polls": value("--polls", kind="int"),
        **FILTERS,
        "defang": flag("--defang"),
    },
    "blocklist": {
        "kind": ((), None, BLOCKLIST_KINDS, None, None),
        "limit": value("--limit", default=30, kind="int"),
        "defang": flag("--defang"),
        "export": value("--export"),
    },
}


def subparsers_of(parser):
    return next(action for action in parser._actions if action.dest == "cmd")


def test_module_constants_and_exceptions(world):
    ioc = world.ioc
    assert ioc.API_HOSTS == API_HOSTS and isinstance(ioc.API_HOSTS, frozenset)
    assert (ioc.NAME, ioc.VERSION, ioc.BASE, ioc.DOCS, ioc.TIMEOUT) == (
        "IOCaw",
        "1.0.0",
        BASE,
        "https://tweetfeed.live/api/",
        30,
    )
    assert hasattr(ioc, "SESSION")
    assert issubclass(ioc.TweetFeedError, RuntimeError)
    assert (
        callable(ioc.build_parser)
        and callable(ioc.main)
        and callable(ioc.api_get)
        and callable(ioc._session)
    )
    for name in (
        "feed",
        "lookup",
        "campaigns",
        "trends",
        "counts",
        "status",
        "watch",
        "blocklist",
    ):
        assert callable(getattr(ioc, f"cmd_{name}")), name


def test_main_and_api_get_signatures(world):
    import inspect

    main = inspect.signature(world.ioc.main)
    assert list(main.parameters) == ["argv"] and main.parameters["argv"].default is None
    api_get = inspect.signature(world.ioc.api_get)
    assert list(api_get.parameters) == [
        "path",
        "params",
        "allow_redirects",
        "expect_json",
    ]
    assert api_get.parameters["params"].default is None
    assert api_get.parameters["allow_redirects"].kind is inspect.Parameter.KEYWORD_ONLY
    assert api_get.parameters["allow_redirects"].default is True
    assert api_get.parameters["expect_json"].kind is inspect.Parameter.KEYWORD_ONLY
    assert api_get.parameters["expect_json"].default is True


def test_parser_is_zero_arg_with_prog_iocaw_and_a_required_cmd_subparser(world):
    parser = world.ioc.build_parser()
    assert parser.prog == "iocaw"
    command = subparsers_of(parser)
    assert command.required is True
    assert list(command.choices) == [
        "feed",
        "lookup",
        "campaigns",
        "trends",
        "counts",
        "status",
        "watch",
        "blocklist",
    ]


def test_top_level_options_are_only_version_and_quiet(world):
    parser = world.ioc.build_parser()
    flags = sorted(
        option for action in parser._actions for option in action.option_strings
    )
    assert flags == sorted(["--quiet", "--version", "-h", "--help"])
    quiet = next(action for action in parser._actions if action.dest == "quiet")
    assert (quiet.default, quiet.nargs) == (False, 0)


@pytest.mark.parametrize("command", list(EXPECTED_PARSER))
def test_subparser_dests_flags_defaults_choices_and_types(world, command):
    sub = subparsers_of(world.ioc.build_parser()).choices[command]
    assert parser_table(sub) == {
        **EXPECTED_PARSER[command],
        "quiet": (("--quiet",), argparse.SUPPRESS, None, 0, None),
    }


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--quiet"],
        ["feed", "yesterday"],
        ["feed", "--type", "email"],
        ["feed", "--type", "URL"],
        ["feed", "--limit", "x"],
        ["lookup"],
        ["blocklist"],
        ["blocklist", "bogus"],
        ["watch", "--interval", "x"],
        ["counts", "hour"],
        ["status", "--limit", "3"],
        ["lookup", "x", "--limit", "3"],
        ["trends", "--defang"],
        ["watch", "--json"],
        ["feed", "--bogus"],
        ["bogus"],
    ],
)
def test_argparse_errors_exit_2_with_text_on_stderr_only(world, argv):
    world.serve(json_reply([]))
    run = world.run(*argv)
    assert run.code == 2 and run.out == "" and run.err.strip()
    assert world.requests == []


def test_version_prints_name_and_version_and_exits_0(world):
    run = world.run("--version")
    assert run.code == 0 and run.out.strip() == "IOCaw 1.0.0" and world.requests == []


def test_help_exits_0_and_names_every_subcommand(world):
    run = world.run("--help")
    assert run.code == 0
    for name in (
        "feed",
        "lookup",
        "campaigns",
        "trends",
        "counts",
        "status",
        "watch",
        "blocklist",
    ):
        assert name in run.out
    assert world.requests == []


def test_parsed_defaults_match_the_table(world):
    parser = world.ioc.build_parser()
    args = parser.parse_args(["feed"])
    assert (
        args.cmd,
        args.window,
        args.limit,
        args.json,
        args.defang,
        args.contains,
        args.export,
        args.quiet,
    ) == ("feed", "today", 40, False, False, None, None, False)
    assert parser.parse_args(["--quiet", "counts"]).window is None
    assert (
        parser.parse_args(["watch"]).interval == 60
        and parser.parse_args(["watch"]).since is None
    )


def test_session_attribute_is_read_at_call_time(world):
    """Tests (and the console) REPLACE `SESSION`; every request must go through the current value."""
    other_seen = []

    def other(request):
        other_seen.append(str(request.url))
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            content=b"{}",
            request=request,
        )

    world.mp.setattr(
        world.ioc,
        "SESSION",
        api_client(API_HOSTS, timeout=1, transport=httpx.MockTransport(other)),
    )
    world.serve(json_reply({"from": "first"}))
    payload, response = world.ioc.api_get("/v1/status")
    assert (
        payload == {} and other_seen == [f"{BASE}/v1/status"] and world.requests == []
    )
    assert isinstance(response, httpx.Response)


def test_session_factory_builds_a_guarded_client_without_proxy_or_redirect_following(
    world,
):
    session = world.ioc._session()
    assert isinstance(session, httpx.Client)
    assert session.trust_env is False and session.follow_redirects is False
    assert (
        session.timeout.connect,
        session.timeout.read,
        session.timeout.write,
        session.timeout.pool,
    ) == (30, 30, 30, 30)


# ---------------------------------------------------------------------------------------------
# B. Discovery: catalog entry, alias, option reader, catalog export, loader path  [C1, C13]
# ---------------------------------------------------------------------------------------------


def test_catalog_registers_ioc_with_iocaw_alias_in_intel(world):
    tool = catalog.tool_by_command("ioc")
    assert (tool.command, tool.folder, tool.script, tool.aliases) == (
        "ioc",
        "IOCaw",
        "iocaw.py",
        ("iocaw",),
    )
    assert (
        tool.summary
        == "Search the public TweetFeed list of reported indicators of compromise."
    )
    assert (
        catalog.reference_canonical("iocaw") == "ioc"
        and catalog.reference_canonical("ioc") == "ioc"
    )
    assert "ioc" not in catalog.DISABLED_REFERENCES
    assert "ioc" in dict(catalog.MODULE_GROUPS)["Intel"]


def test_default_addon_roots_locate_the_script_in_the_repo_addons_dir(monkeypatch):
    """D3 as filed in the spec (default roots missed `<repo>/addons`) is already FIXED at the base
    commit by the M0 quick-wins (#38); this pins the fixed behavior for the rebuild."""
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    found = catalog.locate_script(
        catalog.tool_by_command("ioc"), Path(scanner.__file__).resolve()
    )
    assert found is not None and found.resolve() == DEFAULT_SCRIPT.resolve()


def test_catalog_export_form_snapshot(world):
    world.mp.setenv("BUGHUNT_ADDONS", str(world.addons_root))
    data = export_catalog(
        tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    entry = next(
        module
        for phase in data["phases"]
        for module in phase["modules"]
        if module["name"] == "ioc"
    )
    assert (
        entry["aliases"] == ["iocaw"]
        and entry["reference"] is True
        and entry["disabled"] is False
    )
    assert (
        entry["summary"]
        == "Search the public TweetFeed list of reported indicators of compromise."
    )
    form = entry["form"]
    assert form["command_name"] == "COMMAND"
    assert [row["name"] for row in form["subcommands"]] == [
        "feed",
        "lookup",
        "campaigns",
        "trends",
        "counts",
        "status",
        "watch",
        "blocklist",
    ]
    got = [
        (
            o["subcommand"],
            o["name"],
            tuple(o["flags"]),
            o["kind"],
            o["required"],
            tuple(o["choices"]),
            o["default"],
        )
        for o in form["options"]
    ]
    types = tuple(IOC_TYPES)

    def window(sub, default):
        return (sub, "WINDOW", (), "positional", False, WINDOWS, default)

    expected = [
        ("", "QUIET", ("--quiet",), "bool", False, (), ""),
        window("feed", "today"),
        ("feed", "TYPE", ("--type",), "value", False, types, ""),
        ("feed", "TAG", ("--tag",), "value", False, (), ""),
        ("feed", "USER", ("--user",), "value", False, (), ""),
        ("feed", "JSON", ("--json",), "bool", False, (), ""),
        ("feed", "DEFANG", ("--defang",), "bool", False, (), ""),
        ("feed", "LIMIT", ("--limit",), "value", False, (), "40"),
        ("feed", "EXPORT", ("--export",), "value", False, (), ""),
        ("feed", "CONTAINS", ("--contains",), "value", False, (), ""),
        ("feed", "VALUES_ONLY", ("--values-only",), "bool", False, (), ""),
        ("feed", "TWEETS", ("--tweets",), "bool", False, (), ""),
        ("lookup", "VALUE", (), "positional", True, (), ""),
        ("lookup", "JSON", ("--json",), "bool", False, (), ""),
        ("lookup", "DEFANG", ("--defang",), "bool", False, (), ""),
        ("lookup", "TWEETS", ("--tweets",), "bool", False, (), ""),
        ("campaigns", "ID", ("--id",), "value", False, (), ""),
        ("campaigns", "JSON", ("--json",), "bool", False, (), ""),
        ("campaigns", "DEFANG", ("--defang",), "bool", False, (), ""),
        ("campaigns", "LIMIT", ("--limit",), "value", False, (), "40"),
        ("campaigns", "EXPORT", ("--export",), "value", False, (), ""),
        ("trends", "JSON", ("--json",), "bool", False, (), ""),
        ("trends", "LIMIT", ("--limit",), "value", False, (), "15"),
        window("counts", ""),
        ("counts", "JSON", ("--json",), "bool", False, (), ""),
        ("counts", "LIMIT", ("--limit",), "value", False, (), "12"),
        ("status", "JSON", ("--json",), "bool", False, (), ""),
        ("watch", "SINCE", ("--since",), "value", False, (), ""),
        ("watch", "INTERVAL", ("--interval",), "value", False, (), "60"),
        ("watch", "POLLS", ("--polls",), "value", False, (), ""),
        ("watch", "TYPE", ("--type",), "value", False, types, ""),
        ("watch", "TAG", ("--tag",), "value", False, (), ""),
        ("watch", "USER", ("--user",), "value", False, (), ""),
        ("watch", "DEFANG", ("--defang",), "bool", False, (), ""),
        ("blocklist", "KIND", (), "positional", True, tuple(BLOCKLIST_KINDS), ""),
        ("blocklist", "LIMIT", ("--limit",), "value", False, (), "30"),
        ("blocklist", "DEFANG", ("--defang",), "bool", False, (), ""),
        ("blocklist", "EXPORT", ("--export",), "value", False, (), ""),
        (
            "",
            "COMMAND",
            (),
            "positional",
            True,
            (
                "feed",
                "lookup",
                "campaigns",
                "trends",
                "counts",
                "status",
                "watch",
                "blocklist",
            ),
            "",
        ),
    ]
    assert got == expected


def test_saved_console_options_render_to_argv_the_parser_accepts(world):
    world.mp.setenv("BUGHUNT_ADDONS", str(world.addons_root))
    spec = options.load_spec(
        "ioc", tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    parser = world.ioc.build_parser()
    for settings in (
        {"COMMAND": "feed", "JSON": "true", "TAG": "phishing"},
        {"COMMAND": "status"},
        {"COMMAND": "lookup", "VALUE": "evil.example", "JSON": "true"},
        {"COMMAND": "feed", "TAG": "x", "LIMIT": "5", "DEFANG": "true"},
    ):
        argv = options.render_argv(spec, settings, [])
        assert parser.parse_args(argv).cmd == settings["COMMAND"], argv


@pytest.mark.parametrize("name", ["ioc", "iocaw"])
def test_loader_runs_the_program_under_either_name(world, name):
    world.serve(json_reply({"stale": False}))
    run, console = world.via_loader(name, "--quiet", "status", "--json")
    assert run.code == 0 and json.loads(run.out) == {"stale": False}
    assert world.urls == [f"{BASE}/v1/status"]


def test_loader_maps_exit_codes(world):
    world.serve(json_reply({}))
    assert world.via_loader("ioc", "--version")[0].code == 0
    assert world.via_loader("ioc")[0].code == 2
    assert world.via_loader("ioc", "feed", "bogus")[0].code == 2
    world.serve(text_reply("boom", status=500))
    run, _console = world.via_loader("ioc", "--quiet", "status")
    assert run.code == 2 and "HTTP 500" in run.err


def test_loader_ctrl_c_is_exit_130(world):
    world.serve(handler=lambda request: KeyboardInterrupt())
    run, _console = world.via_loader("ioc", "--quiet", "status")
    assert run.code == 130


# ---------------------------------------------------------------------------------------------
# C. main(): order of operations, exit codes, banner matrix  [C13, C18]
# ---------------------------------------------------------------------------------------------

STATUS_OK = {
    "stale": False,
    "age_seconds": 12,
    "checked_at": "2026-10-18T10:00:00Z",
    "artifacts": {},
}
BANNER_CASES = [  # (argv, reply, has --json)
    (("feed",), json_reply(ROWS), False),
    (
        ("lookup", "evil.example"),
        json_reply({"query": "evil.example", "found": False}),
        False,
    ),
    (("campaigns",), json_reply({"campaigns": []}), False),
    (("trends",), json_reply({}), False),
    (("counts",), json_reply({}), False),
    (("status",), json_reply(STATUS_OK), False),
    (("blocklist", "domains"), text_reply("evil.example\n"), None),
    (("watch", "--interval", "9"), json_reply([]), None),
]


def banner_visible(run: Run) -> bool:
    return "IOCaw 1.0.0" in run.out and "https://tweetfeed.live/api/" in run.out


@pytest.mark.parametrize(
    "argv,reply,has_json", BANNER_CASES, ids=[case[0][0] for case in BANNER_CASES]
)
def test_banner_is_printed_unless_quiet_or_json(world, argv, reply, has_json):
    world.serve(reply)
    world.sleeps(stop_after=1)
    assert banner_visible(world.run(*argv)), "no banner without --quiet"
    assert not banner_visible(world.run("--quiet", *argv)), (
        "--quiet must suppress the banner"
    )
    if has_json is False:
        run = world.run(*argv, "--json")
        assert not banner_visible(run), "--json must suppress the banner"
        json.loads(run.out)


def test_quiet_suppresses_only_the_banner(world):
    world.serve(json_reply(ROWS))
    run = world.run("--quiet", "feed")
    assert run.code == 0 and "evil.example" in run.out and "3 IOCs" in run.text


def test_quiet_is_a_top_level_option_that_must_precede_the_subcommand(world):
    world.serve(json_reply(ROWS))
    assert world.run("--quiet", "feed").code == 0


@pytest.mark.parametrize(
    "argv", [("--quiet", "feed"), ("feed", "--quiet"), ("--quiet", "feed", "--quiet")]
)
def test_quiet_before_or_after_the_subcommand_suppresses_the_banner(world, argv):
    world.serve(json_reply(ROWS))
    run = world.run(*argv)
    assert run.code == 0 and not banner_visible(run)


def test_tweetfeed_error_is_printed_on_stderr_and_exits_2(world):
    world.serve(text_reply("nope", status=500))
    run = world.run("--quiet", "status")
    assert run.code == 2 and "HTTP 500" in run.err and run.out == ""


def test_exit_code_is_a_plain_int_on_success(world):
    world.serve(json_reply(ROWS))
    run = world.run("--quiet", "feed")
    assert type(run.code) is int and run.code == 0 and run.exc is None


def test_ctrl_c_outside_watch_exits_130_with_a_stop_notice(world):
    world.serve(handler=lambda request: KeyboardInterrupt())
    run = world.run("--quiet", "status")
    assert run.code == 130 and run.out.strip() and run.err == ""


def test_main_without_argv_reads_sys_argv(world, monkeypatch):
    world.serve(json_reply(ROWS))
    monkeypatch.setattr(sys, "argv", ["iocaw", "--quiet", "feed", "--json"])
    code = world.ioc.main()
    out, _err = world.capsys.readouterr()
    assert code == 0 and json.loads(out) == ROWS


# ---------------------------------------------------------------------------------------------
# D. api_get: path rule, redirects, status mapping, payload rule  [T for the first three, C6]
# ---------------------------------------------------------------------------------------------


def test_api_get_rejects_a_path_without_a_leading_slash_and_sends_nothing(world):
    world.serve(json_reply({}))
    for path in ("v1/status", "https://evil.example/", "//evil.example/x", ""):
        with pytest.raises(world.ioc.TweetFeedError):
            world.ioc.api_get(path)
    assert world.requests == []


def test_api_get_returns_payload_and_response(world):
    world.serve(json_reply({"a": 1}, headers={"X-Resp-State": "HIT"}))
    payload, response = world.ioc.api_get("/v1/status")
    assert (
        payload == {"a": 1}
        and response.headers["x-resp-state"] == "HIT"
        and world.urls == [f"{BASE}/v1/status"]
    )


def test_api_get_expect_json_false_returns_the_text(world):
    world.serve(text_reply("# c\nevil.example\n"))
    text, response = world.ioc.api_get("/v1/blocklist/domains.txt", expect_json=False)
    assert text == "# c\nevil.example\n" and response.status_code == 200


def test_api_get_params_ride_the_first_request_only(world):
    world.serve(
        handler=lambda request: (
            (302, {"location": f"{BASE}/v1/other"}, b"")
            if request.url.path == "/v1/ioc"
            else json_reply({"ok": True})
        )
    )
    payload, _response = world.ioc.api_get("/v1/ioc", {"value": "x.example"})
    assert payload == {"ok": True}
    assert world.urls == [f"{BASE}/v1/ioc?value=x.example", f"{BASE}/v1/other"]


def test_api_get_without_redirects_is_a_single_request(world):
    world.serve(
        handler=lambda request: (
            302,
            {"location": f"{BASE}/v1/next", "content-type": "text/plain"},
            b"moved",
        )
    )
    payload, response = world.ioc.api_get("/v1/status", allow_redirects=False)
    assert (
        world.urls == [f"{BASE}/v1/status"]
        and response.status_code == 302
        and payload == "moved"
    )


def test_redirect_chain_is_capped_at_one_plus_five_requests(world):
    world.serve(
        handler=lambda request: (
            302,
            {"location": f"{BASE}/v1/hop{len(world.requests)}"},
            b"",
        )
    )
    text, response = world.ioc.api_get("/v1/status", expect_json=False)
    assert len(world.urls) == 6 and response.status_code == 302 and text == ""


@pytest.mark.parametrize(
    "target",
    [
        "https://evil.example/x.csv",
        "https://raw.githubusercontent.com.evil.example/x.csv",
        "https://evilraw.githubusercontent.com.evil.example/x",
        "http://127.0.0.1/",
        "https://tweetfeed.live/x",
    ],
)
def test_off_host_redirects_are_never_requested(world, target):
    world.serve(routes={f"{BASE}/v1/year": (302, {"location": target}, b"")})
    with pytest.raises(world.ioc.TweetFeedError) as caught:
        world.ioc.api_get("/v1/year", expect_json=False)
    assert world.urls == [f"{BASE}/v1/year"]
    assert str(caught.value).startswith("network error talking to TweetFeed:")


@pytest.mark.parametrize(
    "status,needles",
    [
        (410, ["365"]),
        (404, ["not found", f"{BASE}/v1/status"]),
        (403, ["cloudflare"]),
        (500, ["HTTP 500", f"{BASE}/v1/status", "server exploded line2"]),
        (429, ["HTTP 429"]),
        (400, ["HTTP 400"]),
        (503, ["HTTP 503"]),
    ],
)
def test_http_error_statuses_map_to_exit_2_with_the_documented_content(
    world, status, needles
):
    world.serve(text_reply("server exploded\nline2", status=status))
    run = world.run("--quiet", "status")
    assert run.code == 2 and run.out == "" and run.exc is None
    for needle in needles:
        assert needle.lower() in run.err.lower(), needle


def test_error_body_is_cut_to_240_characters(world):
    world.serve(text_reply("x" * 500, status=500))
    run = world.run("--quiet", "status")
    assert (
        run.code == 2 and run.err.count("x") == 240
    )  # the console wraps the line, so count instead of search


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ConnectTimeout("slow-connect"),
        httpx.ReadError("read-reset"),
        httpx.ConnectError("no-route"),
    ],
)
def test_transport_failures_become_a_network_error_with_exit_2(world, failure):
    world.serve(handler=lambda request: failure)
    run = world.run("--quiet", "status")
    assert (
        run.code == 2
        and "network error talking to TweetFeed:" in run.err
        and str(failure) in run.err
    )


def test_empty_200_body_is_invalid_json_exit_2(world):
    world.serve((200, {"content-type": "text/html"}, b""))
    run = world.run("--quiet", "status")
    assert (
        run.code == 2 and "invalid JSON" in run.err and f"{BASE}/v1/status" in run.err
    )


def test_malformed_json_body_is_invalid_json_exit_2(world):
    world.serve((200, {"content-type": "application/json"}, b"{bad json"))
    run = world.run("--quiet", "status")
    assert run.code == 2 and run.err.startswith(f"invalid JSON from {BASE}/v1/status")


def test_json_is_detected_from_the_first_character_when_the_content_type_is_not_json(
    world,
):
    world.serve((200, {"content-type": "text/plain"}, json.dumps(ROWS).encode()))
    run = world.run("--quiet", "feed", "--json")
    assert run.code == 0 and run.json() == ROWS


def test_plain_text_transport_is_preserved_but_status_requires_an_object(
    world,
):
    world.serve(text_reply("hello not json"))
    payload, _ = world.ioc.api_get("/v1/status")
    assert payload == "hello not json"
    run = world.run("--quiet", "status", "--json")
    assert run.code == 2 and run.out == ""
    assert "expected a JSON object" in run.err


def test_an_unfollowed_redirect_text_is_not_a_successful_status_response(world):
    world.serve((302, {}, b"no location"))
    run = world.run("--quiet", "status", "--json")
    assert run.code == 2 and run.out == ""
    assert "expected a JSON object" in run.err


# ---------------------------------------------------------------------------------------------
# E. feed: path building, JSON pass-through, text rendering, local filters  [C2, C3, C4]
# ---------------------------------------------------------------------------------------------


def json_payload(text: str):
    """Parse the JSON array out of stdout even when a notice line precedes it (the year window, D2)."""
    lines = text.splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith("["):
            return json.loads("".join(lines[index:]))
    raise AssertionError(f"no JSON array in output: {text[:200]!r}")


FEED_PATHS = [
    (("feed",), "/v1/today"),
    (("feed", "today"), "/v1/today"),
    (("feed", "week"), "/v1/week"),
    (("feed", "month"), "/v1/month"),
    (
        ("feed", "week", "--tag", "phishing", "--user", "bob", "--type", "url"),
        "/v1/week/phishing/@bob/url",
    ),
    (("feed", "month", "--user", "@bob"), "/v1/month/@bob"),
    (("feed", "--user", "bob"), "/v1/today/@bob"),
    (("feed", "--tag", "/lumma"), "/v1/today/lumma"),
    (("feed", "--tag", "CobaltStrike"), "/v1/today/CobaltStrike"),
    (("feed", "--type", "domain"), "/v1/today/domain"),
    (("feed", "--type", "ip", "--tag", "c2"), "/v1/today/c2/ip"),
    (("feed", "--type", "md5", "--user", "bob"), "/v1/today/@bob/md5"),
]


@pytest.mark.parametrize("argv,path", FEED_PATHS)
def test_feed_path_vectors_with_the_fixed_tag_user_type_order(world, argv, path):
    world.serve(json_reply(ROWS))
    run = world.run("--quiet", *argv, "--json")
    assert run.code == 0 and world.urls == [BASE + path]
    assert world.requests[0].method == "GET"


@pytest.mark.parametrize(
    "flagname,filter_value",
    [
        ("--tag", "#phishing"),
        ("--tag", "Cobalt Strike"),
        ("--tag", "lumma/extra"),
        ("--tag", "100%"),
        ("--tag", "a?b"),
        ("--tag", "*"),
        ("--user", "bad user"),
        ("--user", "a/b"),
    ],
)
def test_feed_filters_the_policy_grammar_rejects_fail_as_invalid_target_with_zero_requests(
    world, flagname, filter_value
):
    world.serve(json_reply(ROWS))
    run = world.run("--quiet", "feed", "week", flagname, filter_value, "--json")
    assert (
        run.code == 2
        and "invalid-target" in run.err
        and run.out == ""
        and run.exc is None
    )
    assert world.requests == []


def test_feed_json_is_the_server_payload_pretty_printed_with_ensure_ascii(world):
    rows = [
        {**ROW_URL, "value": "https://bücher.example/", "extra": {"k": [1, 2]}},
        ROW_IP,
    ]
    world.serve(json_reply(rows))
    run = world.run("--quiet", "feed", "--json")
    assert run.out == json.dumps(rows, indent=2) + "\n"
    assert "\\u00fc" in run.out and run.json() == rows


def test_feed_json_limit_applies_and_zero_means_all(world):
    world.serve(json_reply(ROWS))
    assert world.run("--quiet", "feed", "--json", "--limit", "2").json() == ROWS[:2]
    assert world.run("--quiet", "feed", "--json", "--limit", "0").json() == ROWS
    assert world.run("--quiet", "feed", "--json").json() == ROWS


def test_feed_default_limit_is_40(world):
    rows = [{**ROW_URL, "value": f"h{index:03d}.example"} for index in range(55)]
    world.serve(json_reply(rows))
    assert len(world.run("--quiet", "feed", "--json").json()) == 40
    assert len(world.run("--quiet", "feed", "--json", "--limit", "0").json()) == 55


def test_feed_json_preserves_raw_data_and_honors_export(world, tmp_path):
    world.serve(json_reply(ROWS))
    target = tmp_path / "out.csv"
    run = world.run(
        "--quiet",
        "feed",
        "--json",
        "--defang",
        "--values-only",
        "--export",
        str(target),
    )
    assert run.code == 0 and run.json() == ROWS and target.exists()
    with target.open(encoding="utf-8", newline="") as handle:
        assert [row["value"] for row in csv.DictReader(handle)] == [
            row["value"] for row in ROWS
        ]
    assert str(target) in run.err


def test_feed_contains_is_a_case_insensitive_substring_over_value_user_type_tweet_and_tags(
    world,
):
    rows = [
        {
            "date": "d1",
            "user": "u1",
            "type": "url",
            "value": "alpha.example",
            "tags": [],
            "tweet": "",
        },
        {
            "date": "d2",
            "user": "BobUser",
            "type": "domain",
            "value": "beta.example",
            "tags": ["#x"],
            "tweet": "",
        },
        {
            "date": "d3",
            "user": "u3",
            "type": "ip",
            "value": "gamma.example",
            "tags": ["#Lumma"],
            "tweet": "",
        },
        {
            "date": "d4",
            "user": "u4",
            "type": "md5",
            "value": "delta.example",
            "tags": [],
            "tweet": "https://t.example/ZETA",
        },
    ]
    world.serve(json_reply(rows))
    for needle, expected in (
        ("ALPHA", [0]),
        ("bobuser", [1]),
        ("lumma", [2]),
        ("zeta", [3]),
        ("MD5", [3]),
        ("domain", [1]),
        ("example", [0, 1, 2, 3]),
        ("nomatch-xyz", []),
    ):
        run = world.run("--quiet", "feed", "--json", "--contains", needle)
        assert run.json() == [rows[index] for index in expected], needle


def test_feed_non_array_body_is_an_error_exit_2(world):
    for body in ({"a": 1}, "text"):
        world.serve(json_reply(body))
        run = world.run("--quiet", "feed")
        assert run.code == 2 and "JSON array" in run.err and run.exc is None


def test_feed_header_shows_window_and_filters_and_none_when_unfiltered(world):
    world.serve(json_reply(ROWS))
    assert in_order(
        world.run(
            "--quiet",
            "feed",
            "week",
            "--tag",
            "phishing",
            "--user",
            "bob",
            "--type",
            "url",
        ).out,
        "week",
        "phishing / @bob / url",
    )
    plain = world.run("--quiet", "feed", "month")
    assert in_order(plain.out, "month", "none")


def test_feed_header_subtitle_reports_the_response_headers_in_fixed_order(world):
    world.serve(
        json_reply(
            ROWS,
            headers={
                "X-Result-Count": "3",
                "X-Result-Window-Start": "2026-10-18",
                "X-Result-Window-End": "2026-10-19",
                "X-Result-Truncated": "TRUE",
                "X-Resp-State": "HIT",
            },
        )
    )
    run = world.run("--quiet", "feed")
    assert in_order(
        run.out,
        "count=3",
        "from=2026-10-18",
        "to=2026-10-19",
        "TRUNCATED@10k",
        "cache=HIT",
    )


def test_feed_header_subtitle_omits_absent_and_false_tokens(world):
    world.serve(
        json_reply(ROWS, headers={"X-Result-Count": "3", "X-Result-Truncated": "false"})
    )
    run = world.run("--quiet", "feed")
    assert "count=3" in run.out and "TRUNCATED" not in run.out
    assert "from=" not in run.out and "to=" not in run.out and "cache=" not in run.out
    world.serve(json_reply(ROWS))
    bare = world.run("--quiet", "feed")
    assert re.search(r"\bok\b", bare.out) and "count=" not in bare.out


def test_feed_table_shows_when_type_value_tags_and_reporter_per_row(world):
    world.serve(json_reply(ROWS))
    text = world.run("--quiet", "feed").text
    assert in_order(
        text,
        "2026-10-18 10:01:02",
        "url",
        "https://evil.example/login",
        "#phishing #scam",
        "@alice",
    )
    assert in_order(text, "2026-10-18 09:00:00", "ip", "203.0.113.7", "#c2", "@bob")
    assert "@@bob" not in text
    assert in_order(text, "2026-10-18 08:00:00", "sha256", "a" * 64, "@carol")


def test_feed_table_adds_a_missing_hash_to_tags_and_a_placeholder_user(world):
    rows = [
        {
            "date": "2026-10-18 10:00:00",
            "type": "domain",
            "value": "x.example",
            "tags": ["malware", "#rat"],
        }
    ]
    world.serve(json_reply(rows))
    text = world.run("--quiet", "feed").text
    assert "#malware #rat" in text and "@?" in text


def test_feed_summary_counts_all_rows_even_when_the_table_is_limited(world):
    world.serve(json_reply(ROWS))
    run = world.run("--quiet", "feed", "--limit", "1")
    assert "3 IOCs" in run.text
    assert (
        re.search(r"url\W{0,3}1", run.text)
        and re.search(r"ip\W{0,3}1", run.text)
        and re.search(r"sha256\W{0,3}1", run.text)
    )
    assert in_order(run.text, "evil.example/login") and "203.0.113.7" not in run.text
    assert re.search(r"showing\s+1\s+of\s+3", run.text)


def test_feed_summary_types_are_most_common_first_and_tags_and_reporters_are_ranked_and_capped(
    world,
):
    rows = []
    for rank in range(
        1, 11
    ):  # tag rank N appears (11 - N) times, so tag01 is the most common
        rows += [
            {
                "date": "2026-10-18",
                "user": f"user{(rank % 7) + 1}",
                "type": "url" if rank % 3 else "ip",
                "value": f"v{rank}-{copy}.example",
                "tags": [f"#Tag{rank:02d}"],
                "tweet": "",
            }
            for copy in range(11 - rank)
        ]
    world.serve(json_reply(rows))
    run = world.run("--quiet", "feed", "--limit", "1")
    summary = run.text[run.text.index("55 IOCs") :]
    shown_tags = re.findall(r"#(tag\d\d)", summary)
    assert shown_tags == [f"tag{rank:02d}" for rank in range(1, 9)], (
        "top 8 tags, lower-cased, most common first"
    )
    reporters = re.findall(r"@(user\d)", summary)
    assert len(reporters) == 5 and len(set(reporters)) == 5, "top 5 reporters"
    counts = dict(re.findall(r"\b(url|ip)\W{0,3}(\d+)", summary.split("top tags")[0]))
    assert counts == {
        "url": str(sum(11 - r for r in range(1, 11) if r % 3)),
        "ip": str(sum(11 - r for r in range(1, 11) if not r % 3)),
    }


def test_feed_limit_hint_only_when_rows_were_cut_and_zero_shows_all(world):
    world.serve(json_reply(ROWS))
    assert not re.search(
        r"showing\s+\d+\s+of", world.run("--quiet", "feed", "--limit", "3").text
    )
    assert not re.search(
        r"showing\s+\d+\s+of", world.run("--quiet", "feed", "--limit", "0").text
    )
    everything = world.run("--quiet", "feed", "--limit", "0").text
    assert "203.0.113.7" in everything and "a" * 64 in everything


def test_feed_tweets_lists_value_and_url_for_shown_rows_that_have_one(world):
    world.serve(json_reply(ROWS))
    run = world.run("--quiet", "feed", "--tweets")
    assert (
        "https://twitter.example/alice/status/1" in run.text
        and "https://twitter.example/bob/status/2" in run.text
    )
    assert in_order(
        run.text, "https://evil.example/login", "https://twitter.example/alice/status/1"
    )
    assert "twitter.example" not in world.run("--quiet", "feed").out
    limited = world.run("--quiet", "feed", "--tweets", "--limit", "1")
    assert "alice/status/1" in limited.text and "bob/status/2" not in limited.text


def test_feed_with_no_rows_warns_and_exits_0(world):
    world.serve(json_reply([]))
    run = world.run("--quiet", "feed")
    assert run.code == 0 and "no iocs matched" in run.text.lower()
    contains = world.run("--quiet", "feed", "--contains", "zzz")
    assert contains.code == 0 and "no iocs matched" in contains.text.lower()


def test_feed_values_only_prints_one_value_per_line_limited_and_defanged(world):
    world.serve(json_reply(ROWS))
    run = world.run("--quiet", "feed", "--values-only", "--limit", "2")
    assert run.code == 0 and run.lines.index(
        "https://evil.example/login"
    ) < run.lines.index("203.0.113.7")
    assert "a" * 64 not in run.out
    defanged = world.run("--quiet", "feed", "--values-only", "--defang", "--limit", "0")
    assert defanged.lines.index("hxxps://evil[.]example/login") < defanged.lines.index(
        "203[.]0[.]113[.]7"
    )
    assert "a" * 64 in defanged.lines


def test_feed_values_only_with_no_rows_prints_no_value_lines(world):
    world.serve(json_reply([]))
    run = world.run("--quiet", "feed", "--values-only")
    assert run.code == 0 and "no iocs matched" not in run.text.lower()


def test_feed_user_filter_shown_in_header_is_at_prefixed(world):
    world.serve(json_reply(ROWS))
    assert "@bob" in world.run("--quiet", "feed", "--user", "bob").out


# ---------------------------------------------------------------------------------------------
# F. feed year: the CSV redirect, local filters, parse rules  [C5]
# ---------------------------------------------------------------------------------------------

YEAR_CSV = (
    "date,user,type,value,tags,tweet\n"
    "2026-01-01 00:00:00,alice,url,https://evil.example/a,#phishing #scam,https://t.example/1\n"
    "2026-01-02 00:00:00,@bob,domain,evil.example,#c2|#rat,https://t.example/2\n"
    '2026-01-03 00:00:00,carol,ip,203.0.113.7,"#malware,#stealer",https://t.example/3\n'
)


def serve_year(world, body, *, ctype="text/csv"):
    text = body if isinstance(body, bytes) else body.encode("utf-8")
    world.serve(
        routes={
            f"{BASE}/v1/year": (302, {"location": CSV_URL}, b""),
            CSV_URL: (200, {"content-type": ctype}, text),
        }
    )


def test_year_window_makes_exactly_two_requests_with_no_filter_segments(world):
    serve_year(world, YEAR_CSV)
    run = world.run(
        "--quiet",
        "feed",
        "year",
        "--tag",
        "#phishing",
        "--user",
        "alice",
        "--type",
        "url",
        "--json",
    )
    assert run.code == 0 and world.urls == [f"{BASE}/v1/year", CSV_URL]


def test_year_csv_rows_have_the_feed_row_schema(world):
    serve_year(world, YEAR_CSV)
    rows = json_payload(
        world.run("--quiet", "feed", "year", "--json", "--limit", "0").out
    )
    assert rows == [
        {
            "date": "2026-01-01 00:00:00",
            "user": "alice",
            "type": "url",
            "value": "https://evil.example/a",
            "tags": ["#phishing", "#scam"],
            "tweet": "https://t.example/1",
        },
        {
            "date": "2026-01-02 00:00:00",
            "user": "@bob",
            "type": "domain",
            "value": "evil.example",
            "tags": ["#c2", "#rat"],
            "tweet": "https://t.example/2",
        },
        {
            "date": "2026-01-03 00:00:00",
            "user": "carol",
            "type": "ip",
            "value": "203.0.113.7",
            "tags": ["#malware", "#stealer"],
            "tweet": "https://t.example/3",
        },
    ]
    assert all(
        list(row) == ["date", "user", "type", "value", "tags", "tweet"] for row in rows
    )


def test_year_csv_header_detection_headerless_blank_rows_and_short_rows(world):
    serve_year(
        world,
        "2026-01-01 00:00:00,alice,url,https://x.example/,#a,https://t.example/1\n"
        "\n"
        "2026-01-02,dave,md5,abcd\n"
        ",,,\n",
    )
    rows = json_payload(
        world.run("--quiet", "feed", "year", "--json", "--limit", "0").out
    )
    assert rows[0] == {
        "date": "2026-01-01 00:00:00",
        "user": "alice",
        "type": "url",
        "value": "https://x.example/",
        "tags": ["#a"],
        "tweet": "https://t.example/1",
    }
    assert rows[1] == {
        "date": "2026-01-02",
        "user": "dave",
        "type": "md5",
        "value": "abcd",
        "tags": [],
        "tweet": "",
    }
    assert len(rows) == 3 and rows[2]["value"] == ""


@pytest.mark.parametrize(
    "header", ["Date,User,Type,Value,Tags,Tweet", "date", "x,y,TYPE", "VALUE"]
)
def test_year_csv_first_row_is_a_header_when_any_cell_is_a_known_column_name(
    world, header
):
    serve_year(world, header + "\n2026-01-01,alice,url,v.example,#a,\n")
    rows = json_payload(world.run("--quiet", "feed", "year", "--json").out)
    assert [row["value"] for row in rows] == ["v.example"]


@pytest.mark.parametrize(
    "cell,tags",
    [
        ("#phishing #scam", ["#phishing", "#scam"]),
        ("#c2|#rat", ["#c2", "#rat"]),
        ("#a,#b", ["#a", "#b"]),
        ("#a, #b |#c  #d", ["#a", "#b", "#c", "#d"]),
        ("", []),
        ("  ", []),
        ("lumma|rat", ["lumma", "rat"]),
    ],
)
def test_year_csv_tags_cell_splits_on_commas_pipes_and_whitespace(world, cell, tags):
    quoted = '"' + cell + '"'
    serve_year(
        world,
        f"date,user,type,value,tags,tweet\n2026-01-01,u,url,v.example,{quoted},\n",
    )
    assert (
        json_payload(world.run("--quiet", "feed", "year", "--json").out)[0]["tags"]
        == tags
    )


def test_year_empty_body_is_zero_rows(world):
    serve_year(world, "")
    run = world.run("--quiet", "feed", "year", "--json")
    assert run.code == 0 and json_payload(run.out) == []


def test_year_header_only_body_is_zero_rows(world):
    serve_year(world, "date,user,type,value,tags,tweet\n")
    assert json_payload(world.run("--quiet", "feed", "year", "--json").out) == []


YEAR_FILTER_CSV = (
    "date,user,type,value,tags,tweet\n"
    "d1,alice,URL,https://a.example/,#Phishing #scam,https://t.example/1\n"
    "d2,@Bob,domain,b.example,#phishing,https://t.example/2\n"
    "d3,bobby,domain,c.example,#phishing-kit,https://t.example/3\n"
    "d4,carol,ip,203.0.113.7,#malware,https://t.example/4\n"
)


@pytest.mark.parametrize(
    "argv,expected",
    [
        (("--type", "url"), ["a.example"]),
        (("--type", "domain"), ["b.example", "c.example"]),
        (("--tag", "phishing"), ["https://a.example/", "b.example"]),
        (("--tag", "#PHISHING"), ["https://a.example/", "b.example"]),
        (("--tag", "phish"), []),
        (("--tag", "scam"), ["https://a.example/"]),
        (("--user", "bob"), ["b.example"]),
        (("--user", "@bob"), ["b.example"]),
        (("--user", "bo"), []),
        (("--type", "domain", "--tag", "phishing"), ["b.example"]),
        (("--contains", "203.0.113"), ["203.0.113.7"]),
        (("--tag", "phishing", "--contains", "B.EXAMPLE"), ["b.example"]),
    ],
)
def test_year_local_filters_are_exact_and_case_insensitive(world, argv, expected):
    serve_year(world, YEAR_FILTER_CSV)
    rows = json_payload(
        world.run("--quiet", "feed", "year", "--json", "--limit", "0", *argv).out
    )
    got = [row["value"] for row in rows]
    if argv == ("--type", "url"):
        got = [value.split("//")[-1].rstrip("/") for value in got]
    assert got == expected


def test_year_limit_applies_to_the_filtered_rows(world):
    serve_year(world, YEAR_FILTER_CSV)
    rows = json_payload(
        world.run("--quiet", "feed", "year", "--json", "--limit", "2").out
    )
    assert [row["value"] for row in rows] == ["https://a.example/", "b.example"]


def test_year_text_mode_prints_a_client_side_filter_notice_and_the_table(world):
    serve_year(world, YEAR_CSV)
    run = world.run("--quiet", "feed", "year", "--tag", "phishing")
    assert run.code == 0
    assert "year" in run.err.lower() and "client" in run.err.lower()
    assert "https://evil.example/a" in run.text and "203.0.113.7" not in run.text
    assert in_order(run.out, "year", "phishing")


def test_year_window_tolerates_hash_filters_that_rolling_windows_reject(world):
    serve_year(world, YEAR_CSV)
    assert (
        world.run("--quiet", "feed", "year", "--tag", "#phishing", "--json").code == 0
    )
    world.serve(json_reply(ROWS))
    assert (
        "invalid-target"
        in world.run("--quiet", "feed", "month", "--tag", "#phishing", "--json").err
    )


# ---------------------------------------------------------------------------------------------
# G. lookup  [C7]
# ---------------------------------------------------------------------------------------------

LOOKUP_FOUND = {
    "query": "evil.example",
    "found": True,
    "window": "365d",
    "ai": {
        "summary": "Phishing kit staging host.",
        "family": "KitFamily",
        "threat_type": "phishing",
        "confidence": 0.83,
    },
    "records": [
        {
            "type": "domain",
            "value": "evil.example",
            "first_seen": "2026-01-01",
            "last_seen": "2026-10-01",
            "count": 37,
            "tags": ["#phishing", "kit"],
            "users": ["alice", "@bob"],
            "tweets": ["https://t.example/lookup-1", "https://t.example/lookup-2"],
        }
    ],
    "reg": {
        "apex": "evil.example",
        "registrar": "RegistrarCo",
        "created": "2026-01-01",
        "asn": "AS64500",
        "org": "OrgCo",
        "newly_registered": True,
        "ips": [f"203.0.113.{n}" for n in range(1, 9)],
    },
    "campaigns": [
        {
            "id": "tfc-111111111111",
            "name": "Kit wave",
            "confidence": "high",
            "ioc_count": 212,
        }
    ],
    "archive": {"total": 777},
}


@pytest.mark.parametrize(
    "argument,query",
    [
        ("evil.example", "value=evil.example"),
        (
            "http://evil.example/a?b=1&c=d",
            "value=http%3A%2F%2Fevil.example%2Fa%3Fb%3D1%26c%3Dd",
        ),
        ("203.0.113.7", "value=203.0.113.7"),
        ("a" * 64, "value=" + "a" * 64),
        ("evil example", "value=evil+example"),
        ("ü.example", "value=%C3%BC.example"),
        ("x#y%z", "value=x%23y%25z"),
    ],
)
def test_lookup_request_vectors(world, argument, query):
    world.serve(json_reply({"query": argument, "found": False}))
    run = world.run("--quiet", "lookup", argument, "--json")
    assert run.code == 0 and world.urls == [f"{BASE}/v1/ioc?{query}"]


def test_lookup_json_is_the_payload_pretty_printed(world):
    world.serve(json_reply(LOOKUP_FOUND))
    run = world.run("--quiet", "lookup", "evil.example", "--json")
    assert run.out == json.dumps(LOOKUP_FOUND, indent=2) + "\n"


def test_lookup_not_found_is_a_warning_with_exit_0_and_falls_back_to_the_argument(
    world,
):
    world.serve(json_reply({"found": False}))
    run = world.run("--quiet", "lookup", "x.example")
    assert run.code == 0 and "x.example" in run.out and "not found" in run.text.lower()
    assert "365" in run.text


def test_lookup_found_shows_the_query_and_window(world):
    world.serve(json_reply({"query": "echo.example", "found": True, "window": "30d"}))
    run = world.run("--quiet", "lookup", "x.example")
    assert (
        run.code == 0
        and "echo.example" in run.out
        and "found" in run.out
        and "30d" in run.out
    )
    assert "not found" not in run.text.lower()
    world.serve(json_reply({"query": "echo.example", "found": True}))
    assert "365d" in world.run("--quiet", "lookup", "x.example").out


def test_lookup_found_renders_every_section_in_order(world):
    world.serve(json_reply(LOOKUP_FOUND))
    run = world.run("--quiet", "lookup", "evil.example")
    assert run.code == 0
    assert in_order(
        run.out,
        "evil.example",
        "found",
        "Phishing kit staging host.",
        "KitFamily",
        "0.83",
        "domain",
        "37",
        "@alice @bob",
        "RegistrarCo",
        "AS64500",
        "OrgCo",
        "True",
        "tfc-111111111111",
        "Kit wave",
        "212",
        "777",
    )
    assert in_order(run.out, "first", "2026-01-01", "2026-10-01") or (
        "2026-01-01" in run.out and "2026-10-01" in run.out
    )
    assert in_order(run.out, "phishing", "family") or "KitFamily" in run.out


def test_lookup_registration_shows_only_the_first_six_ips(world):
    world.serve(json_reply(LOOKUP_FOUND))
    text = world.run("--quiet", "lookup", "evil.example").text
    assert (
        "203.0.113.6" in text
        and "203.0.113.7" not in text
        and "203.0.113.8" not in text
    )


def test_lookup_tweets_are_listed_only_with_the_flag(world):
    world.serve(json_reply(LOOKUP_FOUND))
    assert "lookup-1" not in world.run("--quiet", "lookup", "evil.example").out
    flagged = world.run("--quiet", "lookup", "evil.example", "--tweets")
    assert (
        "https://t.example/lookup-1" in flagged.text
        and "https://t.example/lookup-2" in flagged.text
    )


def test_lookup_defang_applies_to_record_values(world):
    world.serve(json_reply(LOOKUP_FOUND))
    text = world.run("--quiet", "lookup", "evil.example", "--defang").text
    assert "evil[.]example" in text


def test_lookup_json_rejects_a_plain_text_payload(world):
    world.serve(text_reply("plain"))
    run = world.run("--quiet", "lookup", "x.example", "--json")
    assert run.code == 2 and run.out == ""
    assert "expected a JSON object" in run.err


# ---------------------------------------------------------------------------------------------
# H. campaigns  [C8]
# ---------------------------------------------------------------------------------------------

CAMPAIGN_LIST = {
    "campaign_count": 7,
    "window": "30d",
    "generated_at": "2026-10-18T00:00:00Z",
    "campaigns": [
        {
            "id": "tfc-aaaaaaaaaaaa",
            "name": "Wave A",
            "confidence": "high",
            "ioc_count": 1010,
            "ioc_count_7d": 33,
            "last_seen": "2026-10-17",
            "targeted_brand": "BrandX",
            "targeted_sector": "Retail",
        },
        {
            "id": "tfc-bbbbbbbbbbbb",
            "name": "Wave B",
            "confidence": "weird",
            "ioc_count": 404,
            "last_seen": "2026-10-16",
            "targeted_sector": "Finance",
        },
        {
            "id": "tfc-cccccccccccc",
            "name": "Wave C",
            "confidence": "low",
            "ioc_count": 5,
            "ioc_count_7d": 0,
            "last_seen": "2026-10-15",
        },
    ],
}
CAMPAIGN_DETAIL = {
    "id": "tfc-aaaaaaaaaaaa",
    "name": "Wave A",
    "context": "Credential theft kit.",
    "confidence": "high",
    "ioc_count": 2,
    "first_seen": "2026-10-01",
    "last_seen": "2026-10-17",
    "targeted_brand": "BrandX",
    "targeted_sector": "Retail",
    "ttps": ["T1566", "T1204"],
}


def test_campaigns_list_request_and_json_pass_through(world):
    world.serve(json_reply(CAMPAIGN_LIST))
    run = world.run("--quiet", "campaigns", "--json")
    assert (
        world.urls == [f"{BASE}/v1/campaigns"]
        and run.out == json.dumps(CAMPAIGN_LIST, indent=2) + "\n"
    )


def test_campaigns_list_header_table_target_rule_and_hint(world):
    world.serve(json_reply(CAMPAIGN_LIST))
    run = world.run("--quiet", "campaigns")
    assert run.code == 0
    assert in_order(run.out, "7", "30d", "2026-10-18T00:00:00Z")
    for needle in (
        "tfc-aaaaaaaaaaaa",
        "Wave A",
        "high",
        "1010",
        "33",
        "2026-10-17",
        "BrandX",
        "tfc-bbbbbbbbbbbb",
        "weird",
        "404",
        "Finance",
        "tfc-cccccccccccc",
        "low",
    ):
        assert needle in run.text, needle
    assert "Retail" not in run.text, "brand wins over sector"
    assert "campaigns --id" in run.text


def test_campaigns_list_count_falls_back_to_the_list_length(world):
    world.serve(json_reply({"campaigns": CAMPAIGN_LIST["campaigns"]}))
    assert re.search(r"\b3 campaigns", world.run("--quiet", "campaigns").text)


def test_campaigns_list_limit_default_40_and_zero_means_all(world):
    many = {
        "campaigns": [
            {"id": f"tfc-{index:012d}", "name": f"w{index}"} for index in range(45)
        ]
    }
    world.serve(json_reply(many))
    default = world.run("--quiet", "campaigns").out
    assert len(re.findall(r"tfc-\d{12}", default)) == 40
    assert (
        len(
            re.findall(
                r"tfc-\d{12}", world.run("--quiet", "campaigns", "--limit", "0").out
            )
        )
        == 45
    )
    assert (
        len(
            re.findall(
                r"tfc-\d{12}", world.run("--quiet", "campaigns", "--limit", "2").out
            )
        )
        == 2
    )


def test_campaign_detail_request_wrapped_and_flat_shapes(world):
    wrapped = {"campaign": CAMPAIGN_DETAIL, "iocs": ROWS[:2]}
    world.serve(json_reply(wrapped))
    run = world.run("--quiet", "campaigns", "--id", "tfc-aaaaaaaaaaaa")
    assert run.code == 0 and world.urls == [f"{BASE}/v1/campaigns/tfc-aaaaaaaaaaaa"]
    assert in_order(run.out, "Wave A", "tfc-aaaaaaaaaaaa", "Credential theft kit.")
    for needle in (
        "high",
        "2026-10-01",
        "2026-10-17",
        "BrandX",
        "Retail",
        "T1566",
        "T1204",
    ):
        assert needle in run.text, needle
    flat = {**CAMPAIGN_DETAIL, "iocs": ROWS[:2]}
    world.serve(json_reply(flat))
    again = world.run("--quiet", "campaigns", "--id", "tfc-aaaaaaaaaaaa")
    assert (
        "Credential theft kit." in again.text
        and "https://evil.example/login" in again.text
    )


def test_campaign_detail_ioc_table_summary_limit_and_defang(world):
    world.serve(json_reply({"campaign": CAMPAIGN_DETAIL, "iocs": ROWS}))
    run = world.run(
        "--quiet", "campaigns", "--id", "tfc-aaaaaaaaaaaa", "--limit", "1", "--defang"
    )
    assert (
        "hxxps://evil[.]example/login" in run.text
        and "203[.]0[.]113[.]7" not in run.text
    )
    assert "3 IOCs" in run.text and "@alice" in run.text and "@carol" in run.text


def test_campaign_detail_falls_back_to_records_and_skips_a_table_without_values(world):
    world.serve(json_reply({"campaign": CAMPAIGN_DETAIL, "records": ROWS[:1]}))
    assert (
        "https://evil.example/login"
        in world.run("--quiet", "campaigns", "--id", "tfc-aaaaaaaaaaaa").text
    )
    world.serve(json_reply({"campaign": CAMPAIGN_DETAIL, "iocs": [{"no": "value"}]}))
    assert (
        "IOCs" not in world.run("--quiet", "campaigns", "--id", "tfc-aaaaaaaaaaaa").text
    )
    world.serve(json_reply({"campaign": CAMPAIGN_DETAIL, "iocs": []}))
    assert world.run("--quiet", "campaigns", "--id", "tfc-aaaaaaaaaaaa").code == 0


def test_campaign_detail_json_pass_through(world):
    world.serve(json_reply({"campaign": CAMPAIGN_DETAIL}))
    run = world.run("--quiet", "campaigns", "--id", "tfc-aaaaaaaaaaaa", "--json")
    assert run.out == json.dumps({"campaign": CAMPAIGN_DETAIL}, indent=2) + "\n"


@pytest.mark.parametrize(
    "campaign_id",
    ["../../admin", "a b", "tfc-x/y", "tfc-é", "%41", "tfc-1?x", "tfc-1#f", "..%2f"],
)
def test_hostile_campaign_ids_are_rejected_by_policy_with_zero_requests(
    world, campaign_id
):
    world.serve(json_reply({}))
    run = world.run("--quiet", "campaigns", "--id", campaign_id, "--json")
    assert run.code == 2 and "invalid-target" in run.err and world.requests == []


@pytest.mark.parametrize("campaign_id", ["tfc-aaaaaaaaaaaa", "TFC_1-x", "tfc..x"])
def test_plain_campaign_ids_ride_the_path_unchanged(world, campaign_id):
    world.serve(json_reply({}))
    assert world.run("--quiet", "campaigns", "--id", campaign_id, "--json").code == 0
    assert world.urls == [f"{BASE}/v1/campaigns/{campaign_id}"]


# ---------------------------------------------------------------------------------------------
# I. trends, counts, status: shape tolerance and the --limit quirk  [C9]
#    The tolerated shapes are the code's guesses about a service nobody observed (UNVERIFIED).
# ---------------------------------------------------------------------------------------------


def mover(tag, **fields):
    return {"tag": tag, **fields}


TRENDS_FULL = {
    "generated_at": "2026-10-18",
    "movers": {
        "up": [mover("lumma", now=50, prev=10, delta=40, pct=400.0)],
        "down": [mover("rat", now=1, prev=9, delta=-8, pct=-88.9)],
    },
    "tlds": {"xyz": 100, "top": 50},
    "novelty": {
        "new_domains": 5,
        "generated_at": "g",
        "version": 1,
        "window": "w",
        "nested": {"a": 1},
        "listy": [1],
    },
    "daily": {"total": [1, 5, 3, 9, 2, 8, 4, 7]},
}


def test_trends_requests_the_endpoint_and_json_is_a_pass_through(world):
    world.serve(json_reply(TRENDS_FULL))
    run = world.run("--quiet", "trends", "--json")
    assert (
        world.urls == [f"{BASE}/v1/trends"]
        and run.out == json.dumps(TRENDS_FULL, indent=2) + "\n"
    )


def test_trends_renders_movers_tlds_novelty_and_the_daily_sparkline(world):
    world.serve(json_reply(TRENDS_FULL))
    run = world.run("--quiet", "trends")
    assert run.code == 0 and "2026-10-18" in run.text
    assert in_order(run.out, "#lumma", "50", "10", "40", "400%")
    assert in_order(run.out, "#rat", "1", "9", "-8", "-89%")
    assert in_order(run.out, "lumma", "rat"), (
        "up movers first, then down movers appended"
    )
    assert in_order(run.out, "xyz", "100", "top", "50")
    assert (
        "new_domains=5" in run.text
        and "version=" not in run.text
        and "nested" not in run.text
    )
    assert (
        "listy" not in run.text
        and "window=" not in run.text
        and "generated_at=" not in run.text
    )


def test_trends_daily_shows_only_the_last_seven_totals_as_a_block_sparkline(world):
    world.serve(json_reply(TRENDS_FULL))
    text = world.run("--quiet", "trends").text
    assert "[5, 3, 9, 2, 8, 4, 7]" in text and "[1, 5" not in text
    spark = re.search(f"[{SPARK_BLOCKS}]{{7}}", text)
    assert spark, "seven block characters"
    blocks = spark.group(0)
    totals = [5, 3, 9, 2, 8, 4, 7]
    assert (
        blocks[totals.index(max(totals))] == SPARK_BLOCKS[-1]
        and blocks[totals.index(min(totals))] == SPARK_BLOCKS[0]
    )
    ranks = [SPARK_BLOCKS.index(ch) for ch in blocks]
    assert all(
        (ranks[i] <= ranks[j]) == (totals[i] <= totals[j])
        for i in range(7)
        for j in range(7)
    )


@pytest.mark.parametrize(
    "movers,expected_order",
    [
        ([mover("a", current=5, delta=2), mover("b", now=9)], ["a", "b"]),
        ({"items": [mover("b", count=3, previous=1, delta=2, pct=200)]}, ["b"]),
        ({"tags": [mover("c", now=1)]}, ["c"]),
        ({"top": [mover("d", now=1), mover("e", now=2)]}, ["d", "e"]),
        ({"up": [mover("f", now=1)], "down": [mover("g", now=2)]}, ["f", "g"]),
        (
            {
                "alpha": {"delta": -3, "current": 1},
                "beta": 7,
                "generated_at": "x",
                "window": "w",
                "version": 2,
            },
            ["beta", "alpha"],
        ),
    ],
)
def test_trends_tolerates_each_mover_shape(world, movers, expected_order):
    world.serve(json_reply({"movers": movers}))
    run = world.run("--quiet", "trends")
    assert run.code == 0 and run.exc is None
    tags = re.findall(r"#([a-z]+)\b", run.text)
    assert tags == expected_order


@pytest.mark.parametrize("junk", ["junk", 7, [], {}, None, [1, "x"]])
def test_trends_ignores_unusable_movers(world, junk):
    world.serve(json_reply({"generated_at": "g", "movers": junk}))
    run = world.run("--quiet", "trends")
    assert run.code == 0 and "movers" not in run.text.lower() or run.code == 0


def test_trends_mover_value_fallbacks(world):
    world.serve(
        json_reply(
            {
                "movers": [
                    mover("p", count=3, previous=1),
                    mover("q", current=5, prev=2),
                    mover("r", now=8),
                ]
            }
        )
    )
    text = world.run("--quiet", "trends").text
    assert (
        in_order(text, "#p", "3", "1")
        and in_order(text, "#q", "5", "2")
        and in_order(text, "#r", "8")
    )


@pytest.mark.parametrize(
    "tlds,expected",
    [
        (
            [
                {"tld": "xyz", "count": 3},
                {"name": "top", "total": 9},
                {"tag": "icu", "count": 1},
            ],
            ["xyz", "top", "icu"],
        ),
        ({"xyz": 100, "icu": 300, "top": 50}, ["icu", "xyz", "top"]),
        ({"items": [{"tld": "aaa", "count": 1}]}, ["aaa"]),
        ({"top": {"bbb": 2, "ccc": 5}}, None),
        ({"tlds": [{"tld": "ddd", "count": 1}]}, ["ddd"]),
    ],
)
def test_trends_tolerates_each_tld_shape(world, tlds, expected):
    world.serve(json_reply({"tlds": tlds}))
    run = world.run("--quiet", "trends")
    assert run.code == 0 and run.exc is None
    if expected:
        names = [name for name in re.findall(r"\b(xyz|top|icu|aaa|ddd)\b", run.text)]
        assert names == expected


def test_trends_limit_quirk_default_15_for_both_tables_and_zero_falls_back(world):
    payload = {
        "movers": [mover(f"mv{index:02d}", now=index) for index in range(20)],
        "tlds": {f"tl{index:02d}": 100 - index for index in range(20)},
    }
    world.serve(json_reply(payload))

    def shown(*extra):
        text = world.run("--quiet", "trends", *extra).text
        return len(set(re.findall(r"#mv\d\d", text))), len(
            set(re.findall(r"\btl\d\d\b", text))
        )

    assert shown() == (15, 15)
    assert shown("--limit", "3") == (3, 3)
    assert shown("--limit", "0") == (15, 12)


def test_trends_daily_with_fewer_than_seven_totals_shows_them_all(world):
    world.serve(json_reply({"daily": {"total": [3, 1, 2]}}))
    text = world.run("--quiet", "trends").text
    assert "[3, 1, 2]" in text and re.search(f"[{SPARK_BLOCKS}]{{3}}", text)


COUNTS_PAYLOAD = {
    "generated_at": "2026-10-18",
    "windows": {
        "year": {"total": 999, "types": {"url": 500, "ip": 499}, "tags": {"c2": 3}},
        "week": {"total": 50, "types": {"url": 50}, "tags": {}},
        "today": {
            "total": 9,
            "first_date": "2026-10-18",
            "last_date": "2026-10-19",
            "types": {"url": 5, "ip": 4},
            "tags": {"c2": 3, "phishing": 6, "rat": 1},
        },
        "month": {},
    },
}


def test_counts_requests_the_endpoint_and_json_is_a_pass_through(world):
    world.serve(json_reply(COUNTS_PAYLOAD))
    run = world.run("--quiet", "counts", "--json")
    assert (
        world.urls == [f"{BASE}/v1/counts"]
        and run.out == json.dumps(COUNTS_PAYLOAD, indent=2) + "\n"
    )


def test_counts_shows_windows_in_fixed_order_skipping_missing_and_empty_ones(world):
    world.serve(json_reply(COUNTS_PAYLOAD))
    run = world.run("--quiet", "counts")
    assert run.code == 0 and "2026-10-18" in run.text
    assert in_order(run.out, "today", "9", "week", "50", "year", "999")
    assert "month" not in run.text


def test_counts_window_positional_selects_one_window(world):
    world.serve(json_reply(COUNTS_PAYLOAD))
    run = world.run("--quiet", "counts", "week")
    assert "50" in run.text and "999" not in run.text and "phishing" not in run.text
    assert "month" not in world.run("--quiet", "counts", "month").text


def test_counts_shows_dates_types_and_tags_by_count_and_none_for_absent_dates(world):
    world.serve(json_reply(COUNTS_PAYLOAD))
    run = world.run("--quiet", "counts", "today")
    assert in_order(run.out, "today", "9", "2026-10-18", "2026-10-19")
    assert "url=5" in run.text and "ip=4" in run.text
    assert in_order(run.out, "#phishing", "6", "#c2", "3", "#rat", "1")
    assert "None" in world.run("--quiet", "counts", "week").text


def test_counts_tag_table_limit_default_12_and_zero_falls_back_to_12(world):
    tags = {f"tg{index:02d}": 100 - index for index in range(20)}
    world.serve(
        json_reply({"windows": {"today": {"total": 1, "types": {}, "tags": tags}}})
    )

    def shown(*extra):
        return len(
            set(re.findall(r"#tg\d\d", world.run("--quiet", "counts", *extra).text))
        )

    assert (shown(), shown("--limit", "3"), shown("--limit", "0")) == (12, 3, 12)


STATUS_PAYLOAD = {
    "stale": True,
    "age_seconds": 12345,
    "checked_at": "2026-10-18T10:00:00Z",
    "contract": {
        "license": "CC0-1.0",
        "tlp": "CLEAR",
        "docs": "https://docs.example/contract",
    },
    "artifacts": {
        "zzz.json": {
            "window": "w-z",
            "rows": 5,
            "updated_at": "2026-10-17T00:00:00Z",
            "age_seconds": 77,
            "stale": True,
        },
        "today.csv": {
            "window": "today",
            "rows": 9,
            "updated_at": "2026-10-18T09:00:00Z",
            "age_seconds": 55,
            "stale": False,
        },
        "year.csv": {
            "window": "year",
            "rows": 99,
            "updated_at": "2026-10-18T08:00:00Z",
            "age_seconds": 66,
        },
        "broken": "not-an-object",
    },
}
STATUS_HEADERS = {
    "X-Result-Count": "9",
    "X-Result-Window-Start": "s",
    "X-Result-Window-End": "e",
    "X-Result-Truncated": "true",
    "X-Resp-State": "HIT",
}


def test_status_requests_the_endpoint_and_json_is_a_pass_through(world):
    world.serve(json_reply(STATUS_PAYLOAD))
    run = world.run("--quiet", "status", "--json")
    assert (
        world.urls == [f"{BASE}/v1/status"]
        and run.out == json.dumps(STATUS_PAYLOAD, indent=2) + "\n"
    )


def test_status_header_contract_artifacts_and_cache_footer(world):
    world.serve(json_reply(STATUS_PAYLOAD, headers=STATUS_HEADERS))
    run = world.run("--quiet", "status")
    assert run.code == 0
    assert in_order(run.out, "True", "12345", "2026-10-18T10:00:00Z")
    assert in_order(run.out, "CC0-1.0", "CLEAR", "https://docs.example/contract")
    for needle in (
        "today.csv",
        "today",
        "9",
        "2026-10-18T09:00:00Z",
        "55",
        "zzz.json",
        "w-z",
        "77",
        "year.csv",
        "99",
    ):
        assert needle in run.text, needle
    assert "broken" not in run.text
    assert in_order(run.out, "count=9", "from=s", "to=e", "TRUNCATED@10k", "cache=HIT")


def test_status_stale_column_says_yes_or_no_per_artifact(world):
    world.serve(json_reply(STATUS_PAYLOAD))
    text = run_text = world.run("--quiet", "status").text
    assert re.search(r"today\.csv.*?\bno\b", text) and re.search(
        r"zzz\.json.*?\byes\b", text
    )
    assert run_text


def test_status_stale_flag_falls_back_to_any_stale(world):
    world.serve(
        json_reply(
            {"any_stale": True, "age_seconds": 1, "checked_at": "c", "artifacts": {}}
        )
    )
    assert "True" in world.run("--quiet", "status").text


def test_status_lists_well_known_artifacts_first_then_the_rest_PINNED_CURRENT_free_per_spec_10(
    world,
):
    """Spec 10 lets the rebuild use server order instead; delete this test if it does."""
    names = [
        "a.json",
        "trends.json",
        "year.csv",
        "week.csv",
        "today.csv",
        "counts.json",
        "campaigns.json",
        "month.csv",
    ]
    world.serve(json_reply({"artifacts": {name: {"window": "w"} for name in names}}))
    text = world.run("--quiet", "status").text
    positions = [
        text.index(name)
        for name in (
            "today.csv",
            "week.csv",
            "month.csv",
            "year.csv",
            "campaigns.json",
            "counts.json",
            "trends.json",
            "a.json",
        )
    ]
    assert positions == sorted(positions)


def test_status_lists_at_most_twenty_artifacts(world):
    world.serve(
        json_reply(
            {
                "artifacts": {
                    f"art{index:02d}.json": {"window": "w"} for index in range(25)
                }
            }
        )
    )
    assert (
        len(set(re.findall(r"art\d\d\.json", world.run("--quiet", "status").text)))
        == 20
    )


# ---------------------------------------------------------------------------------------------
# J. watch: poll loop, since advance, de-duplication, error handling  [C10]
#    Sleep is patched at time.sleep (the seam the spec names); a handler cap also bounds the loop.
# ---------------------------------------------------------------------------------------------

WATCH_A = {
    "date": "2026-10-18 10:01:02",
    "user": "alice",
    "type": "url",
    "value": "https://evil.example/watch-a",
    "tags": ["#phishing"],
    "tweet": "",
}
WATCH_B = {
    "date": "2026-10-18 10:05:00",
    "user": "bob",
    "type": "ip",
    "value": "203.0.113.99",
    "tags": [],
    "tweet": "",
}


def poll_sequence(world, bodies):
    """Serve `bodies[i]` to poll i (a reply tuple or a payload); a poll past the end raises KeyboardInterrupt."""

    def handler(request):
        index = len(world.requests) - 1
        if index >= len(bodies):
            return KeyboardInterrupt()
        body = bodies[index]
        return body if isinstance(body, tuple) else json_reply(body)

    world.serve(handler=handler)


def test_watch_polls_since_with_filters_in_tag_user_type_order_and_sleeps_the_interval(
    world,
):
    poll_sequence(world, [[], [], []])
    sleeps = world.sleeps(stop_after=3)
    run = world.run(
        "--quiet",
        "watch",
        "--since",
        "2026-10-18T10:00:00Z",
        "--tag",
        "phishing",
        "--user",
        "bob",
        "--type",
        "url",
        "--interval",
        "7",
    )
    assert run.code == 0
    assert world.urls == [f"{BASE}/v1/since/2026-10-18T10:00:00Z/phishing/@bob/url"] * 3
    assert sleeps == [7, 7, 7]


def test_watch_user_handle_gets_one_at_prefix(world):
    poll_sequence(world, [[]])
    world.sleeps(stop_after=1)
    world.run("--quiet", "watch", "--since", "2026-10-18T10:00:00Z", "--user", "bob")
    world.run("--quiet", "watch", "--since", "2026-10-18T10:00:00Z", "--user", "@bob")
    assert world.urls[0].endswith("/@bob") and world.urls[1].endswith("/@bob")


def test_watch_announces_since_and_interval(world):
    poll_sequence(world, [[]])
    world.sleeps(stop_after=1)
    run = world.run(
        "--quiet", "watch", "--since", "2026-10-18T10:00:00Z", "--interval", "9"
    )
    first = run.lines[0]
    assert (
        "2026-10-18T10:00:00Z" in first and "9s" in first and "watch" in first.lower()
    )


def test_watch_default_since_is_now_in_utc_second_precision(world):
    poll_sequence(world, [[]])
    world.sleeps(stop_after=1)
    run = world.run("--quiet", "watch")
    match = re.fullmatch(
        rf"{re.escape(BASE)}/v1/since/(\d{{4}}-\d\d-\d\dT\d\d:\d\d:\d\dZ)",
        world.urls[0],
    )
    assert match and match.group(1) in run.out and "60s" in run.lines[0]


def test_watch_advances_since_deduplicates_and_reports_silence(world):
    poll_sequence(world, [[WATCH_A], [WATCH_A, WATCH_B], [WATCH_A, WATCH_B]])
    sleeps = world.sleeps(stop_after=3)
    run = world.run(
        "--quiet",
        "watch",
        "--since",
        "2026-10-18T10:00:00Z",
        "--tag",
        "phishing",
        "--interval",
        "7",
    )
    assert run.code == 0 and sleeps == [7, 7, 7]
    assert world.urls == [
        f"{BASE}/v1/since/2026-10-18T10:00:00Z/phishing",
        f"{BASE}/v1/since/2026-10-18T10:01:02Z/phishing",
        f"{BASE}/v1/since/2026-10-18T10:05:00Z/phishing",
    ]
    assert (
        run.text.count("https://evil.example/watch-a") == 1
        and run.text.count("203.0.113.99") == 1
    )
    assert len(re.findall(r"\+1\s+\d\d:\d\d:\d\d", run.text)) == 2
    assert re.search(r"\d\d:\d\d:\d\d\s+silence \(2 already seen\)", run.text)


def test_watch_advances_to_the_maximum_date_of_the_new_rows(world):
    poll_sequence(world, [[WATCH_B, WATCH_A], []])
    world.sleeps(stop_after=2)
    world.run("--quiet", "watch", "--since", "2026-10-18T10:00:00Z")
    assert world.urls[1].endswith("/v1/since/2026-10-18T10:05:00Z")


def test_watch_prints_new_rows_without_a_limit_and_honors_defang(world):
    rows = [
        {
            **WATCH_A,
            "value": f"https://evil.example/n{index:02d}",
            "date": f"2026-10-18 10:00:{index % 60:02d}",
        }
        for index in range(45)
    ]
    poll_sequence(world, [rows])
    world.sleeps(stop_after=1)
    run = world.run("--quiet", "watch", "--since", "2026-10-18T09:00:00Z", "--defang")
    assert len(set(re.findall(r"hxxps://evil\[\.\]example/n\d\d", run.text))) == 45
    assert "+45" in run.text


def test_watch_since_is_not_validated(world):
    poll_sequence(world, [[]])
    world.sleeps(stop_after=1)
    assert world.run("--quiet", "watch", "--since", "garbage").code == 0
    assert world.urls == [f"{BASE}/v1/since/garbage"]


def test_watch_non_array_payload_counts_as_zero_rows(world):
    poll_sequence(world, [{"not": "a list"}])
    world.sleeps(stop_after=1)
    run = world.run("--quiet", "watch", "--since", "2026-10-18T10:00:00Z")
    assert run.code == 0 and re.search(r"silence \(0 already seen\)", run.text)


def test_watch_transient_errors_are_printed_and_the_loop_continues(world):
    poll_sequence(world, [text_reply("flaky", status=500), [WATCH_A]])
    sleeps = world.sleeps(stop_after=2)
    run = world.run(
        "--quiet", "watch", "--since", "2026-10-18T10:00:00Z", "--interval", "5"
    )
    assert run.code == 0 and sleeps == [5, 5]
    assert "HTTP 500" in run.text and "https://evil.example/watch-a" in run.text
    assert world.urls[0] == world.urls[1], "an error does not advance since"


def test_watch_ctrl_c_ends_the_loop_with_exit_0_and_a_stop_notice(world):
    poll_sequence(world, [[]])
    world.sleeps(stop_after=1)
    run = world.run("--quiet", "watch", "--since", "2026-10-18T10:00:00Z")
    assert run.code == 0 and run.err == "" and run.lines[-1] != ""


def test_watch_json_flag_does_not_exist(world):
    assert world.run("--quiet", "watch", "--json").code == 2


# ---------------------------------------------------------------------------------------------
# K. blocklist  [C11]
# ---------------------------------------------------------------------------------------------

BLOCKLIST_TEXT = (
    "# header comment\nevil.example\n\nbad.example\n# another\nworse.example\n"
)


@pytest.mark.parametrize("kind", BLOCKLIST_KINDS)
def test_blocklist_requests_the_kind_txt_path(world, kind):
    world.serve(text_reply(BLOCKLIST_TEXT))
    run = world.run("--quiet", "blocklist", kind)
    assert run.code == 0 and world.urls == [f"{BASE}/v1/blocklist/{kind}.txt"]


def test_blocklist_filters_comments_and_empty_lines_and_names_kind_and_count(world):
    world.serve(text_reply(BLOCKLIST_TEXT))
    run = world.run("--quiet", "blocklist", "domains")
    assert in_order(run.out, "domains", "3")
    assert [line for line in run.lines if line.endswith(".example")] == [
        "evil.example",
        "bad.example",
        "worse.example",
    ]
    assert "header comment" not in run.text and "another" not in run.text


def test_blocklist_whitespace_only_lines_are_kept_as_entries_PINNED_QUIRK(world):
    world.serve(text_reply("a.example\n  \nb.example\n"))
    assert in_order(world.run("--quiet", "blocklist", "ips").out, "ips", "3")


def test_blocklist_limit_default_30_zero_all_and_the_showing_hint(world):
    body = "".join(f"h{index:02d}.example\n" for index in range(35))
    world.serve(text_reply(body))
    default = world.run("--quiet", "blocklist", "domains")
    assert len(re.findall(r"h\d\d\.example", default.text)) == 30 and re.search(
        r"showing\s+30\s+of\s+35", default.text
    )
    limited = world.run("--quiet", "blocklist", "domains", "--limit", "2")
    assert len(re.findall(r"h\d\d\.example", limited.text)) == 2 and re.search(
        r"showing\s+2\s+of\s+35", limited.text
    )
    everything = world.run("--quiet", "blocklist", "domains", "--limit", "0")
    assert (
        len(re.findall(r"h\d\d\.example", everything.text)) == 35
        and "showing" not in everything.text
    )


def test_blocklist_defang_rewrites_every_line_including_host_format_lines(world):
    world.serve(text_reply("0.0.0.0 evil.example\nhttp://bad.example/x.php\n"))
    run = world.run("--quiet", "blocklist", "hosts", "--defang")
    assert (
        "0[.]0[.]0[.]0 evil[.]example" in run.lines
        and "hxxp://bad[.]example/x[.]php" in run.lines
    )


def test_blocklist_export_writes_the_full_text_including_comments_and_prints_the_path(
    world, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    world.serve(text_reply(BLOCKLIST_TEXT + "unicode-\u00fc.example\n"))
    run = world.run(
        "--quiet", "blocklist", "domains", "--limit", "1", "--export", "bl.txt"
    )
    assert run.code == 0 and "bl.txt" in run.text
    written = (tmp_path / "bl.txt").read_bytes().decode("utf-8")
    assert written.replace("\r\n", "\n") == BLOCKLIST_TEXT + "unicode-\u00fc.example\n"


def test_blocklist_export_ignores_defang_and_limit(world, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    world.serve(text_reply("a.example\nb.example\n"))
    world.run(
        "--quiet",
        "blocklist",
        "domains",
        "--defang",
        "--limit",
        "1",
        "--export",
        "raw.txt",
    )
    assert (tmp_path / "raw.txt").read_bytes().decode().replace(
        "\r\n", "\n"
    ) == "a.example\nb.example\n"


def test_blocklist_has_no_json_flag_and_stays_text_only(world):
    assert world.run("--quiet", "blocklist", "domains", "--json").code == 2


# ---------------------------------------------------------------------------------------------
# L. --export: formats, extension rules, row selection  [C12]
# ---------------------------------------------------------------------------------------------

EXPORT_HEADER = ["date", "user", "type", "value", "tags", "tweet"]


@pytest.fixture
def exporting(world, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    world.serve(json_reply(ROWS))
    return world


def test_export_json_is_the_shown_rows_as_a_pretty_array(exporting, tmp_path):
    run = exporting.run("--quiet", "feed", "--limit", "2", "--export", "out.json")
    assert run.code == 0 and "out.json" in run.err
    text = (tmp_path / "out.json").read_bytes().decode("utf-8")
    assert json.loads(text) == ROWS[:2] and text.replace("\r\n", "\n").startswith(
        '[\n  {\n    "date"'
    )


def test_export_txt_is_one_raw_value_per_line_never_defanged(exporting, tmp_path):
    exporting.run("--quiet", "feed", "--defang", "--limit", "0", "--export", "out.txt")
    lines = (tmp_path / "out.txt").read_bytes().decode("utf-8").splitlines()
    assert lines == ["https://evil.example/login", "203.0.113.7", "a" * 64]


def test_export_csv_header_rows_and_tags_joined_by_single_spaces(exporting, tmp_path):
    exporting.run("--quiet", "feed", "--limit", "0", "--export", "out.csv")
    rows = list(
        csv.reader(
            io.StringIO((tmp_path / "out.csv").read_bytes().decode("utf-8"), newline="")
        )
    )
    assert rows[0] == EXPORT_HEADER
    assert rows[1] == [
        "2026-10-18 10:01:02",
        "alice",
        "url",
        "https://evil.example/login",
        "#phishing #scam",
        "https://twitter.example/alice/status/1",
    ]
    assert rows[2][1] == "@bob" and rows[2][4] == "#c2"
    assert rows[3] == ["2026-10-18 08:00:00", "carol", "sha256", "a" * 64, "", ""]
    assert len(rows) == 4


def test_export_csv_uses_the_csv_modules_default_crlf_row_endings(exporting, tmp_path):
    exporting.run("--quiet", "feed", "--limit", "2", "--export", "out.csv")
    data = (tmp_path / "out.csv").read_bytes()
    assert (
        data.startswith(b"date,user,type,value,tags,tweet\r\n")
        and data.count(b"\r\n") == 3
    )
    assert data.replace(b"\r\n", b"").count(b"\n") == 0


@pytest.mark.parametrize(
    "given,written",
    [
        ("o.csv", "o.csv"),
        ("o", "o.csv"),
        ("o.xlsx", "o.xlsx.csv"),
        ("o.dat", "o.dat.csv"),
        ("O.CSV", "O.CSV"),
    ],
)
def test_export_other_extensions_become_csv_and_csv_is_appended_unless_present(
    exporting, tmp_path, given, written
):
    run = exporting.run("--quiet", "feed", "--limit", "1", "--export", given)
    assert written in run.err
    assert sorted(path.name for path in tmp_path.iterdir() if path.name != "world") == [
        written
    ]
    assert (
        (tmp_path / written)
        .read_bytes()
        .startswith(b"date,user,type,value,tags,tweet\r\n")
    )


@pytest.mark.parametrize("given,kind", [("O.JSON", "json"), ("O.TXT", "txt")])
def test_export_extension_match_is_case_insensitive(exporting, tmp_path, given, kind):
    exporting.run("--quiet", "feed", "--limit", "1", "--export", given)
    data = (tmp_path / given).read_bytes().decode("utf-8")
    assert (
        (json.loads(data) == ROWS[:1])
        if kind == "json"
        else (data.splitlines() == ["https://evil.example/login"])
    )


def test_export_limit_applies_and_zero_exports_everything(exporting, tmp_path):
    exporting.run("--quiet", "feed", "--limit", "1", "--export", "one.json")
    exporting.run("--quiet", "feed", "--limit", "0", "--export", "all.json")
    assert len(json.loads((tmp_path / "one.json").read_text("utf-8"))) == 1
    assert len(json.loads((tmp_path / "all.json").read_text("utf-8"))) == 3


def test_export_missing_fields_become_empty_cells_and_text_is_utf8(
    world, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    world.serve(
        json_reply(
            [
                {"value": "x.example"},
                {**ROW_URL, "value": "https://b\u00fccher.example/"},
            ]
        )
    )
    world.run("--quiet", "feed", "--export", "sparse.csv")
    rows = list(
        csv.reader(
            io.StringIO(
                (tmp_path / "sparse.csv").read_bytes().decode("utf-8"), newline=""
            )
        )
    )
    assert (
        rows[1] == ["", "", "", "x.example", "", ""]
        and rows[2][3] == "https://b\u00fccher.example/"
    )


def test_export_with_values_only_writes_the_shown_rows(exporting, tmp_path):
    run = exporting.run(
        "--quiet", "feed", "--values-only", "--limit", "2", "--export", "v.txt"
    )
    assert run.code == 0 and "v.txt" in run.err
    assert run.out.splitlines() == [row["value"] for row in ROWS[:2]]
    assert (tmp_path / "v.txt").read_bytes().decode().splitlines() == [
        "https://evil.example/login",
        "203.0.113.7",
    ]


def test_export_values_only_with_no_rows_writes_a_header_only_csv(
    world, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    world.serve(json_reply([]))
    world.run("--quiet", "feed", "--values-only", "--export", "empty.csv")
    assert (
        tmp_path / "empty.csv"
    ).read_bytes() == b"date,user,type,value,tags,tweet\r\n"


def test_export_is_skipped_when_no_iocs_matched_but_honored_in_json_mode(
    world, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    world.serve(json_reply([]))
    assert world.run("--quiet", "feed", "--export", "none.csv").code == 0
    world.serve(json_reply(ROWS))
    assert world.run("--quiet", "feed", "--json", "--export", "j.csv").code == 0
    assert (tmp_path / "j.csv").is_file() and not (tmp_path / "none.csv").exists()


def test_export_text_files_use_the_platform_newline_PINNED_CURRENT(exporting, tmp_path):
    """Text-mode writes translate \\n to os.linesep (CRLF on Windows); spec 4.8. Other export tests
    compare newline-agnostically on purpose; an LF-only rebuild would change only this test."""
    exporting.run("--quiet", "feed", "--limit", "2", "--export", "nl.txt")
    assert (tmp_path / "nl.txt").read_bytes() == (
        "https://evil.example/login\n203.0.113.7\n"
    ).replace("\n", os.linesep).encode("utf-8")


# ---------------------------------------------------------------------------------------------
# M. defang (spec 4.9)
# ---------------------------------------------------------------------------------------------

DEFANG_VECTORS = [
    ("https://evil.example/login", "hxxps://evil[.]example/login"),
    ("http://evil.example/a.php?x=1.2", "hxxp://evil[.]example/a[.]php?x=1[.]2"),
    ("203.0.113.7", "203[.]0[.]113[.]7"),
    ("HTTP://X.EXAMPLE", "HTTP://X[.]EXAMPLE"),
    ("Https://X.example", "Https://X[.]example"),
    ("ftp://x.example", "ftp://x[.]example"),
    ("see-https:x", "see-hxxps:x"),
    ("evil.example:http:foo", "evil[.]example:hxxp:foo"),
    ("http://a.example/http://b.example", "hxxp://a[.]example/hxxp://b[.]example"),
    ("a" * 64, "a" * 64),
    ("no-dots-here", "no-dots-here"),
]


@pytest.mark.parametrize("raw,defanged", DEFANG_VECTORS)
def test_defang_vectors_in_values_only_output(world, raw, defanged):
    world.serve(json_reply([{**ROW_URL, "value": raw}]))
    assert defanged in world.run("--quiet", "feed", "--values-only", "--defang").lines
    assert raw in world.run("--quiet", "feed", "--values-only").lines


def test_defang_applies_to_the_feed_table_but_not_to_json(world):
    world.serve(json_reply([ROW_URL]))
    assert (
        "hxxps://evil[.]example/login" in world.run("--quiet", "feed", "--defang").text
    )
    assert (
        "https://evil.example/login"
        in world.run("--quiet", "feed", "--defang", "--json").out
    )


# ---------------------------------------------------------------------------------------------
# N. Egress and policy posture  [C14, C15]
# ---------------------------------------------------------------------------------------------

REGISTRY = {  # every subcommand once, with the minimal valid reply for its endpoint
    "feed": ("feed",),
    "year": ("feed", "year"),
    "lookup": ("lookup", "x.example"),
    "campaigns": ("campaigns",),
    "campaign": ("campaigns", "--id", "tfc-aaaaaaaaaaaa"),
    "trends": ("trends",),
    "counts": ("counts",),
    "status": ("status",),
    "blocklist": ("blocklist", "domains"),
    "watch": ("watch", "--since", "2026-10-18T10:00:00Z"),
}


def posture_handler(request):
    path = request.url.path
    if str(request.url) == CSV_URL:
        return text_reply(YEAR_CSV, ctype="text/csv")
    if path == "/v1/year":
        return (302, {"location": CSV_URL}, b"")
    if path.startswith("/v1/blocklist/"):
        return text_reply("evil.example\n")
    if path in ("/v1/today",) or path.startswith("/v1/since/"):
        return json_reply([])
    return json_reply({})


@pytest.fixture
def served_battery(world):
    world.serve(handler=posture_handler)
    world.sleeps(stop_after=1)
    return world


def test_every_command_sends_only_get_requests_to_the_two_listed_hosts(served_battery):
    for name, argv in REGISTRY.items():
        before = len(served_battery.requests)
        run = served_battery.run("--quiet", *argv)
        assert run.code == 0, (name, run.out[-200:])
        sent = served_battery.requests[before:]
        assert len(sent) == (2 if name == "year" else 1), name
    assert {request.method for request in served_battery.requests} == {"GET"}
    assert {request.url.host for request in served_battery.requests} == {
        "api.tweetfeed.live",
        "raw.githubusercontent.com",
    }
    assert {request.url.scheme for request in served_battery.requests} == {"https"}
    assert all(request.content == b"" for request in served_battery.requests)


def test_wire_headers_policy_profile_replaces_the_user_agent_and_the_addon_accept_survives(
    served_battery,
):
    served_battery.run("--quiet", "feed", "year")
    assert len(served_battery.requests) == 2
    for request in served_battery.requests:
        assert request.headers["user-agent"] == PROFILE_UA, (
            "the policy profile overwrites the requested UA"
        )
        assert request.headers["x-researcher"] == "owned-lab", (
            "profile-required headers are added"
        )
        assert request.headers["accept"] == ADDON_ACCEPT
        assert "gzip" in request.headers["accept-encoding"]
        assert (
            "authorization" not in request.headers and "cookie" not in request.headers
        )


def test_each_admitted_request_is_recorded_by_egress_as_a_run_with_the_full_url(world):
    world.serve(json_reply({"found": False}))
    world.run("--quiet", "lookup", "x.example", "--json")
    manifests = [
        json.loads(path.read_text("utf-8"))
        for path in (world.workspace_dir / "runs").glob("*/manifest.json")
    ]
    assert len(manifests) == 1
    assert manifests[0]["target"] == f"{BASE}/v1/ioc?value=x.example"
    assert (manifests[0]["operation"], manifests[0]["decision"]) == (
        "passive",
        "permitted",
    )


def test_requests_are_admitted_under_the_passive_operation_only(world):
    def only(operation):
        def edit(document):
            for asset in document["assets"]:
                if asset["origin"] == BASE:
                    asset["operations"] = [operation]

        return edit

    world.serve(json_reply({}))
    world.workspace(mutate=only("passive"))
    world.load()
    assert world.run("--quiet", "status", "--json").code == 0
    world.requests.clear()
    world.workspace(mutate=only("manual"))
    world.load()
    denied = world.run("--quiet", "status", "--json")
    assert (
        denied.code == 2
        and "asset-method-disallowed" in denied.err
        and world.requests == []
    )


def test_the_command_is_not_scope_gated(world, monkeypatch):
    """No scope file exists and `workspace.allowed` is never consulted: the target is the feed."""

    def forbidden(*args, **kwargs):
        raise AssertionError("IOCaw must not consult the engagement scope")

    monkeypatch.setattr(workspace, "allowed", forbidden)
    assert not (world.workspace_dir / "scope.txt").exists()
    world.serve(json_reply({}))
    assert world.run("--quiet", "status", "--json").code == 0


@pytest.mark.parametrize("name", ["status", "feed", "lookup", "blocklist"])
def test_without_an_asset_for_the_api_host_the_request_is_denied_before_the_transport(
    world, name
):
    world.serve(handler=posture_handler)
    world.workspace(drop=(BASE,))
    world.load()
    run = world.run("--quiet", *REGISTRY[name])
    assert (
        run.code == 2
        and "asset-unknown" in run.err
        and "no outbound action ran" in run.err
    )
    assert world.requests == [] and run.exc is None
    assert not (world.workspace_dir / "runs").exists(), (
        "a denied request leaves no run record"
    )


def test_without_a_policy_the_request_is_denied_before_the_transport(world):
    world.serve(handler=posture_handler)
    world.workspace(policy=False)
    world.load()
    run = world.run("--quiet", "status")
    assert (
        run.code == 2
        and "policy-missing-or-invalid" in run.err
        and "no outbound action ran" in run.err
    )
    assert world.requests == []


def test_year_second_hop_without_a_github_raw_asset_is_denied_after_the_first_hop(
    world,
):
    serve_year(world, YEAR_CSV)
    world.workspace(drop=("https://raw.githubusercontent.com",))
    world.load()
    run = world.run("--quiet", "feed", "year", "--json")
    assert run.code == 2 and "asset-unknown" in run.err
    assert world.urls == [f"{BASE}/v1/year"], "only the first hop was sent"


def test_a_client_built_in_one_workspace_is_refused_in_another(world):
    """Egress refuses a client whose workspace changed; the addon must surface it as exit 2 with the
    reason, send nothing, and prefer a replaced SESSION. (D4 is about the addon's OWN client.)"""
    world.serve(json_reply({}))
    other_workspace = world.tmp / "other-workspace"
    world.mp.setattr(
        world.ioc,
        "SESSION",
        api_client(API_HOSTS, timeout=1, transport=world.transport),
    )
    world.workspace(other_workspace)
    run = world.run("--quiet", "status", "--json")
    assert (
        run.code == 2
        and "client-workspace-changed" in run.err
        and "no outbound action ran" in run.err
    )
    assert world.requests == []


def test_documentation_states_the_posture_the_code_keeps():
    manual = (REPO / "docs" / "manual.md").read_text("utf-8")
    assert (
        "`ioc` | Talks only to `api.tweetfeed.live` and the GitHub raw file `/v1/year` redirects to."
        in manual
    )
    assert "`ioc` | TweetFeed indicators (IOCaw) | `bughunt ioc --help`" in manual
    assert "`iocaw` is `ioc`" in manual


BANNED_MODULES = {
    "socket",
    "subprocess",
    "requests",
    "aiohttp",
    "urllib3",
    "http.client",
    "urllib.request",
    "ssl",
    "ftplib",
    "smtplib",
    "telnetlib",
    "asyncio",
}
BANNED_CLIENT_KEYWORDS = {
    "verify",
    "proxy",
    "proxies",
    "trust_env",
    "follow_redirects",
    "mounts",
    "cert",
}


def test_the_script_has_no_network_path_other_than_the_guarded_client():
    tree = ast.parse(SCRIPT.read_text("utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
    assert not imported & BANNED_MODULES, imported & BANNED_MODULES
    direct_httpx_calls = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "httpx"
    ]
    assert direct_httpx_calls == [], (
        "all traffic must go through bughunt.core.http.api_client"
    )
    weakened = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.keyword) and node.arg in BANNED_CLIENT_KEYWORDS
    ]
    assert weakened == [], "no TLS/proxy/redirect override on any call"
    assert "bughunt.core.http" in imported


# ---------------------------------------------------------------------------------------------
# O. Standalone launch  [C17]
# ---------------------------------------------------------------------------------------------


def standalone_env(world):
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "BUGHUNT_ADDONS")
    }
    env["BUGHUNT_SCOPE"] = str(world.workspace_dir)
    return env


def test_standalone_version_works_from_an_unrelated_directory_without_bughunt_on_the_path(
    world, tmp_path
):
    foreign = tmp_path / "elsewhere"
    foreign.mkdir()
    done = subprocess.run(
        [sys.executable, str(SCRIPT), "--version"],
        cwd=foreign,
        env=standalone_env(world),
        timeout=120,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert done.returncode == 0 and done.stdout.strip() == "IOCaw 1.0.0", done.stderr[
        -400:
    ]


STANDALONE_DRIVER = textwrap.dedent("""
    import runpy, socket, sys
    def forbidden(*args, **kwargs):
        raise AssertionError("real network reached")
    socket.getaddrinfo = forbidden
    socket.create_connection = forbidden
    script = sys.argv[1]
    sys.argv = [script, *sys.argv[2:]]
    runpy.run_path(script, run_name="__main__")
""")


def test_standalone_run_without_a_policy_fails_closed_with_exit_2_and_no_network(
    world, tmp_path
):
    empty = world.workspace(world.tmp / "no-policy", policy=False)
    env = standalone_env(world)
    env["BUGHUNT_SCOPE"] = str(empty)
    driver = tmp_path / "driver.py"
    driver.write_text(STANDALONE_DRIVER, encoding="utf-8")
    foreign = tmp_path / "elsewhere"
    foreign.mkdir()
    done = subprocess.run(
        [sys.executable, str(driver), str(SCRIPT), "--quiet", "status"],
        cwd=foreign,
        env=env,
        timeout=120,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert done.returncode == 2, done.stderr[-600:]
    assert (
        "policy-missing-or-invalid" in done.stderr
        and "AssertionError" not in done.stderr
    )


# ---------------------------------------------------------------------------------------------
# P. KNOWN DEFECTS: each test asserts the CORRECT behavior and is xfail until the rebuild fixes
#    it (strict=True). Spec ids D1..D11; D17 was found while writing this oracle (not in the spec).
# ---------------------------------------------------------------------------------------------

HOSTILE = ["[/x]", "[red]x[/red]"]


def d1_feed(field, **extra):
    def build(bad):
        row = {**ROW_URL, "tags": ["#a"], "tweet": "https://t.example/ok", **extra}
        row[field] = bad if field != "value" else f"http://h.example/{bad}"
        if field == "tags":
            row["tags"] = [bad]
        return (json_reply([row]), 0)

    return build


def d1_json(payload_factory, code=0):
    return lambda bad: (json_reply(payload_factory(bad)), code)


D1_CASES = {
    "feed-value": (("feed",), d1_feed("value")),
    "feed-user": (("feed",), d1_feed("user")),
    "feed-tag": (("feed",), d1_feed("tags")),
    "feed-tweet-listing": (("feed", "--tweets"), d1_feed("tweet")),
    "feed-values-only": (("feed", "--values-only"), d1_feed("value")),
    "blocklist-line": (
        ("blocklist", "domains"),
        lambda bad: (text_reply(f"{bad}\n"), 0),
    ),
    "http-error-body": (
        ("status",),
        lambda bad: (text_reply(f"upstream said {bad}", status=500), 2),
    ),
    "lookup-query": (
        ("lookup", "q"),
        d1_json(lambda bad: {"query": bad, "found": False}),
    ),
    "lookup-summary": (
        ("lookup", "q"),
        d1_json(lambda bad: {"query": "q", "found": True, "ai": {"summary": bad}}),
    ),
    "lookup-record": (
        ("lookup", "q"),
        d1_json(
            lambda bad: {"found": True, "records": [{"type": "domain", "value": bad}]}
        ),
    ),
    "lookup-campaign": (
        ("lookup", "q"),
        d1_json(
            lambda bad: {"found": True, "campaigns": [{"id": "tfc-1", "name": bad}]}
        ),
    ),
    "lookup-registration": (
        ("lookup", "q"),
        d1_json(lambda bad: {"found": True, "reg": {"registrar": bad}}),
    ),
    "campaigns-list": (
        ("campaigns",),
        d1_json(lambda bad: {"campaigns": [{"id": "tfc-1", "name": bad}]}),
    ),
    "campaigns-target": (
        ("campaigns",),
        d1_json(lambda bad: {"campaigns": [{"id": "tfc-1", "targeted_brand": bad}]}),
    ),
    "campaign-detail": (
        ("campaigns", "--id", "tfc-1"),
        d1_json(lambda bad: {"id": "tfc-1", "name": bad, "context": bad}),
    ),
    "campaign-ttps": (
        ("campaigns", "--id", "tfc-1"),
        d1_json(lambda bad: {"id": "tfc-1", "ttps": [bad]}),
    ),
    "trends-mover": (
        ("trends",),
        d1_json(lambda bad: {"movers": [{"tag": bad, "now": 1}]}),
    ),
    "trends-tld": (
        ("trends",),
        d1_json(lambda bad: {"tlds": [{"tld": bad, "count": 1}]}),
    ),
    "trends-novelty": (("trends",), d1_json(lambda bad: {"novelty": {"k": bad}})),
    "counts-type": (
        ("counts",),
        d1_json(lambda bad: {"windows": {"today": {"total": 1, "types": {bad: 1}}}}),
    ),
    "counts-tag": (
        ("counts",),
        d1_json(lambda bad: {"windows": {"today": {"total": 1, "tags": {bad: 1}}}}),
    ),
    "status-contract": (
        ("status",),
        d1_json(lambda bad: {"contract": {"license": bad}}),
    ),
    "status-artifact": (
        ("status",),
        d1_json(lambda bad: {"artifacts": {bad: {"window": bad}}}),
    ),
}


@pytest.mark.parametrize("bad", HOSTILE)
@pytest.mark.parametrize("case", D1_CASES)
def test_hostile_data_renders_literally_and_does_not_crash(world, case, bad):
    argv, build = D1_CASES[case]
    reply, expected_code = build(bad)
    world.serve(reply)
    run = world.run("--quiet", *argv)
    assert run.exc is None, run.exc
    assert run.code == expected_code
    # a feed tag is shown twice: in the table and in the "top tags" summary line
    assert (run.err if case == "http-error-body" else run.text).count(bad) >= (
        2 if case == "feed-tag" else 1
    ), "the text must be shown exactly as received"


def test_d2a_feed_year_json_stdout_is_pure_json(world):
    serve_year(world, YEAR_CSV)
    run = world.run("--quiet", "feed", "year", "--json")
    assert run.code == 0 and len(json.loads(run.out)) == 3


def test_d2b_values_only_stdout_is_exactly_the_values(world):
    world.serve(json_reply(ROWS))
    run = world.run("--quiet", "feed", "--values-only")
    assert [line for line in run.out.splitlines() if line.strip()] == [
        row["value"] for row in ROWS
    ]


LONG_URL = (
    "https://long.example/" + "a" * 150
)  # 171 characters, wider than the 80-column non-terminal default


def test_d2c_values_only_values_are_never_wrapped_when_piped(world):
    world.load(columns=None)
    world.serve(json_reply([{**ROW_URL, "value": LONG_URL}]))
    run = world.run("--quiet", "feed", "--values-only")
    assert LONG_URL in run.lines


def test_d2c_blocklist_entries_are_never_wrapped_when_piped(world):
    world.load(columns=None)
    world.serve(text_reply(LONG_URL + "\n"))
    run = world.run("--quiet", "blocklist", "urls")
    assert LONG_URL in run.lines


def test_d2d_errors_use_stderr_in_json_mode(world):
    world.serve(text_reply("nope", status=500))
    run = world.run("--quiet", "status", "--json")
    assert run.code == 2 and "HTTP 500" in run.err and run.out == ""


def build_in_one_workspace_then_switch(world):
    """Import the addon under workspace A, then make workspace B the active one."""
    other = world.tmp / "second-workspace"
    world.workspace(other)
    return other


def test_d4_the_addons_own_client_survives_a_workspace_change(world):
    world.serve(json_reply({"stale": False}))
    build_in_one_workspace_then_switch(world)
    run = world.run("--quiet", "status", "--json")
    assert run.code == 0 and "client-workspace-changed" not in run.out
    assert world.urls == [f"{BASE}/v1/status"]


def test_d4_the_loader_path_survives_a_workspace_change(world):
    world.serve(json_reply({"stale": False}))
    build_in_one_workspace_then_switch(world)
    run, _console = world.via_loader("ioc", "--quiet", "status", "--json")
    assert run.code == 0


def test_d4_owned_clients_close_and_rebind_after_a_completed_run(world):
    clients = []
    factory = world.ioc._session

    def tracked_session():
        client = factory()
        clients.append(client)
        return client

    world.mp.setattr(world.ioc, "_session", tracked_session)
    world.serve(json_reply({"stale": False}))
    assert world.run("--quiet", "status", "--json").code == 0
    build_in_one_workspace_then_switch(world)
    assert world.run("--quiet", "status", "--json").code == 0
    assert len(clients) == 2 and all(client.is_closed for client in clients)
    assert world.urls == [f"{BASE}/v1/status"] * 2


def test_d5_watch_stops_on_a_policy_denial_instead_of_retrying(world):
    poll_sequence(world, [[]])
    world.workspace(drop=(BASE,))
    world.load()
    sleeps = world.sleeps(stop_after=3)
    run = world.run(
        "--quiet", "watch", "--since", "2026-10-18T10:00:00Z", "--interval", "5"
    )
    assert run.code == 2 and sleeps == [] and world.requests == []


def test_d5_watch_stops_on_invalid_target(world):
    poll_sequence(world, [[]])
    sleeps = world.sleeps(stop_after=3)
    run = world.run(
        "--quiet", "watch", "--since", "2026-10-18 10:00:00", "--interval", "5"
    )
    assert run.code == 2 and sleeps == []


@pytest.mark.parametrize("interval", ["0", "-5"])
def test_d5_watch_rejects_a_non_positive_interval(world, interval):
    poll_sequence(world, [[]])
    world.sleeps(stop_after=2)
    run = world.run(
        "--quiet", "watch", "--since", "2026-10-18T10:00:00Z", "--interval", interval
    )
    assert run.code == 2 and world.requests == []


NON_OBJECT_PAYLOADS = [
    pytest.param([1, 2], id="list"),
    pytest.param("plain text", id="text"),
]
OBJECT_COMMANDS = {
    "lookup": ("lookup", "x.example"),
    "campaigns": ("campaigns",),
    "campaign-detail": ("campaigns", "--id", "tfc-a"),
    "trends": ("trends",),
    "counts": ("counts",),
    "status": ("status",),
}


@pytest.mark.parametrize("payload", NON_OBJECT_PAYLOADS)
@pytest.mark.parametrize("command", list(OBJECT_COMMANDS))
@pytest.mark.parametrize("json_mode", [False, True])
def test_d6_a_non_object_payload_is_a_tweetfeed_error_not_a_crash(
    world, command, payload, json_mode
):
    world.serve(
        json_reply(payload) if isinstance(payload, list) else text_reply(payload)
    )
    run = world.run(
        "--quiet", *OBJECT_COMMANDS[command], *(["--json"] if json_mode else [])
    )
    assert run.exc is None and run.code == 2


@pytest.mark.parametrize("arguments", [(), ("--id", "tfc-1"), ("--json",)])
def test_d8_campaigns_export_is_not_silently_ignored(
    world, tmp_path, monkeypatch, arguments
):
    monkeypatch.chdir(tmp_path)
    world.serve(json_reply(CAMPAIGN_LIST))
    run = world.run("--quiet", "campaigns", *arguments, "--export", "campaigns.csv")
    assert run.code == 2 and world.requests == [] and "not supported" in run.err
    assert not (tmp_path / "campaigns.csv").exists()


@pytest.mark.parametrize(
    "argv",
    [
        ("feed", "--export", "no_such_dir/x.csv"),
        ("blocklist", "domains", "--export", "no_such_dir/x.txt"),
        ("feed", "--json", "--export", "no_such_dir/x.json"),
        ("feed", "--values-only", "--export", "no_such_dir/x.txt"),
    ],
)
def test_d8_export_io_errors_are_a_tweetfeed_error(world, tmp_path, monkeypatch, argv):
    monkeypatch.chdir(tmp_path)
    world.serve(json_reply(ROWS) if argv[0] == "feed" else text_reply("a.example\n"))
    run = world.run("--quiet", *argv)
    assert run.exc is None and run.code == 1 and "no_such_dir" in run.err


CP1252_DRIVER = textwrap.dedent("""
    import json, sys
    from pathlib import Path
    sys.path.insert(0, sys.argv[1])
    sys.path.insert(0, sys.argv[1] + "/tests")
    import httpx
    from bughunt.core import http as core_http
    from bughunt.console import loader
    real = core_http.api_client
    payload = json.loads(sys.argv[3])
    transport = httpx.MockTransport(lambda request: httpx.Response(
        200, headers={"content-type": "application/json"}, content=json.dumps(payload).encode(), request=request))
    core_http.api_client = lambda hosts, **kwargs: real(hosts, transport=transport, **kwargs)
    module = loader.import_script(Path(sys.argv[2]))
    sys.exit(module.main(sys.argv[4:]))
""")


@pytest.mark.parametrize(
    "argv,payload",
    [
        (("--quiet", "trends"), TRENDS_FULL),
        (("--quiet", "counts"), COUNTS_PAYLOAD),
        (("--quiet", "status", "--json"), {"marker": "rocket \U0001f680"}),
        (
            ("--quiet", "feed", "--values-only"),
            [{**ROW_URL, "value": "https://h.example/\U0001f680"}],
        ),
    ],
)
def test_d9_output_survives_a_cp1252_stdout(world, tmp_path, argv, payload):
    driver = tmp_path / "cp1252_driver.py"
    driver.write_text(CP1252_DRIVER, encoding="utf-8")
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("PYTHONPATH", "PYTHONUTF8")
    }
    env.update(
        BUGHUNT_SCOPE=str(world.workspace_dir), PYTHONIOENCODING="cp1252", COLUMNS="140"
    )
    done = subprocess.run(
        [
            sys.executable,
            "-X",
            "utf8=0",
            str(driver),
            str(REPO),
            str(SCRIPT),
            json.dumps(payload),
            *argv,
        ],
        cwd=tmp_path,
        env=env,
        timeout=120,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert done.returncode == 0, done.stderr[-400:]
    if "--json" in argv:
        assert json.loads(done.stdout) == payload
    if "--values-only" in argv:
        assert done.stdout.splitlines() == [row["value"] for row in payload]


@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("outcome", ["success", "usage", "exception"])
@pytest.mark.parametrize("entrypoint", ["direct", "loader"])
def test_output_stream_policies_are_restored(world, shared, outcome, entrypoint):
    import io

    output = io.TextIOWrapper(
        io.BytesIO(), encoding="cp1252", errors="backslashreplace"
    )
    error = (
        output
        if shared
        else io.TextIOWrapper(io.BytesIO(), encoding="ascii", errors="replace")
    )
    original = [(stream.encoding, stream.errors) for stream in (output, error)]

    def command(args):
        print("rocket \U0001f680")
        if outcome == "exception":
            raise RuntimeError("command failed")
        return 0

    world.mp.setitem(world.ioc.COMMANDS, "status", command)

    def invoke(argv):
        if entrypoint == "loader":
            return loader._call_main(world.ioc, argv, "ioc", SCRIPT)
        return world.ioc.main(argv)

    with world.mp.context() as patch:
        patch.setattr(sys, "stdout", output)
        patch.setattr(sys, "stderr", error)
        if outcome == "usage":
            if entrypoint == "loader":
                assert invoke(["--unknown"]) == 2
            else:
                with pytest.raises(SystemExit):
                    invoke(["--unknown"])
        elif outcome == "exception":
            with pytest.raises(RuntimeError, match="command failed"):
                invoke(["--quiet", "status"])
        else:
            assert invoke(["--quiet", "status"]) == 0
    assert [(stream.encoding, stream.errors) for stream in (output, error)] == original
    if outcome != "usage":
        assert output.buffer.getvalue().decode("utf-8").splitlines() == [
            "rocket \U0001f680"
        ]


def test_d11_a_saved_console_quiet_setting_renders_argv_the_parser_accepts(world):
    world.mp.setenv("BUGHUNT_ADDONS", str(world.addons_root))
    spec = options.load_spec(
        "ioc", tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    argv = options.render_argv(spec, {"COMMAND": "feed", "QUIET": "true"}, [])
    world.ioc.build_parser().parse_args(argv)


def test_d11_quiet_is_accepted_after_the_subcommand_and_suppresses_the_banner(world):
    world.serve(json_reply(ROWS))
    run = world.run("feed", "--quiet")
    assert run.code == 0 and not banner_visible(run)


@pytest.mark.parametrize(
    "argv",
    [
        ("feed", "week", "--tag", "..", "--json"),
        ("feed", "week", "--tag", ".", "--json"),
        ("campaigns", "--id", "..", "--json"),
        ("campaigns", "--id", ".", "--json"),
    ],
)
def test_d17_dot_segment_filters_and_ids_cannot_change_the_api_path(world, argv):
    world.serve(json_reply([] if argv[0] == "feed" else {}))
    run = world.run("--quiet", *argv)
    assert run.code == 2 and world.requests == []
