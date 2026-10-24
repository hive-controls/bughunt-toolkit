"""Characterization oracle for addons/crt-scout, written BEFORE the clean-room rebuild.

Scope: everything `tests/test_addons.py` leaves unpinned for the `ct` addon - stdout line
formats, `-o` / `-w` files, exit codes, the name filter, the wordlist, scope and policy gating
on every outbound path, and the `bughunt ct` loader path.

Network posture: NO real network call is made. crt.name and every probe target are served by
`httpx.MockTransport` at the egress edge, and an autouse tripwire makes DNS and TCP connects
raise. The live crt.name response format and the effect of `-d` are UNVERIFIED (mock-only):
fixtures use the plain "name [date]" line shape the current code tolerates.

Tiers follow the spec: tests named for a defect (D1, D2, D4, D5, D8, D10) assert the CORRECT
behavior and are marked xfail(strict=True) until the rebuild fixes them; every other test pins
current behavior that the rebuild must reproduce.

Point the suite at another copy of the script (mutation proofs, or the rebuilt file in a scratch
location) with `BUGHUNT_CT_UNDER_TEST=<path to crt-scout.py>`; the default is the repo's addon.
"""

from __future__ import annotations

import ast
import asyncio
import io
import json
import os
import re
import runpy
import shutil
import socket
import subprocess
import sys
import textwrap
import types
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from rich.console import Console

from bughunt.console import catalog, loader, ui
from bughunt.console.catalog_export import export_catalog
from bughunt.core import egress, scanner, workspace
from bughunt.core.http import HostNotAllowed, api_client
from test_gate import seed_policy

REPO = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT = REPO / "addons" / "crt-scout" / "crt-scout.py"
SCRIPT = Path(os.environ.get("BUGHUNT_CT_UNDER_TEST") or DEFAULT_SCRIPT).resolve()

ARROW = chr(
    0x2192
)  # the single arrow character in the contract, written as a code point on purpose
GREEN, RED, RESET = "\x1b[92m", "\x1b[91m", "\x1b[0m"
YELLOW, BLUE = "\x1b[93m", "\x1b[94m"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
API_URL = "https://crt.name/v1/search?apex=allowed.example"

# Hosts the default policy grants (https and http, every operation). `mail` is deliberately
# absent: it is in scope (a subdomain of allowed.example) but has no policy grant.
GRANTED_LABELS = ("www", "api", "app", "dev", "admin", "cdn", "host-a")
NUMBERED_LABELS = tuple(f"h{number:02d}" for number in range(1, 26))
STANDARD_GRANTS = tuple(
    f"{label}.allowed.example" for label in GRANTED_LABELS + NUMBERED_LABELS
)


def plain(text: str) -> str:
    return ANSI.sub("", text)


def live_line(url: str, status: int) -> str:
    return f"[LIVE] {url}  {ARROW}  HTTP {status}"


def names_body(*names: str) -> bytes:
    return ("\n".join(names) + "\n").encode()


# ---------------------------------------------------------------------------------------------
# Workspace (scope + policy) and the network-edge harness
# ---------------------------------------------------------------------------------------------


def build_workspace(
    path: Path,
    *,
    scope=("allowed.example",),
    grant=STANDARD_GRANTS,
    drop=(),
    restrict=None,
    policy=True,
) -> None:
    """Scope file plus a verified policy. `grant` adds https+http origins (all operations)."""
    path.mkdir(parents=True, exist_ok=True)
    for stale in ("scope.txt", "policy.json"):
        (path / stale).unlink(missing_ok=True)
    document = seed_policy(path)
    assets = [row for row in document["assets"] if row["origin"] not in set(drop)]
    known = {row["origin"] for row in assets}
    for host in grant:
        for scheme in ("https", "http"):
            origin = f"{scheme}://{host}"
            if origin not in known:
                known.add(origin)
                assets.append(
                    {
                        "id": f"extra-{len(assets)}",
                        "origin": origin,
                        "paths": ["/"],
                        "operations": list(document["permissions"]),
                        "methods": ["GET", "HEAD", "POST", "OPTIONS", "CONNECT"],
                    }
                )
    for row in assets:
        if row["origin"] in (restrict or {}):
            row["operations"] = list(restrict[row["origin"]])
    document["assets"] = assets
    (path / "policy.json").write_text(json.dumps(document), encoding="utf-8")
    if not policy:
        (path / "policy.json").unlink()
    if scope is not None:
        (path / "scope.txt").write_text("\n".join(scope) + "\n", encoding="utf-8")


@dataclass
class Run:
    code: int
    out: str
    err: str

    @property
    def plain_out(self) -> str:
        return plain(self.out)

    @property
    def plain_err(self) -> str:
        return plain(self.err)


class World:
    """One scope/policy workspace plus mock transports standing in for crt.name and the probes."""

    def __init__(self, ct, monkeypatch, tmp_path, capsys):
        self.ct, self.mp, self.tmp, self.capsys = ct, monkeypatch, tmp_path, capsys
        self.scope_dir = tmp_path / "scope"
        self.api_requests: list[httpx.Request] = []
        self.probe_requests: list[httpx.Request] = []
        monkeypatch.setenv("BUGHUNT_SCOPE", str(self.scope_dir))
        self.workspace()

    def workspace(self, **options) -> None:
        build_workspace(self.scope_dir, **options)

    @property
    def api_urls(self) -> list[str]:
        return [str(request.url) for request in self.api_requests]

    @property
    def probe_urls(self) -> list[str]:
        return [str(request.url) for request in self.probe_requests]

    def api(
        self,
        body: bytes = b"",
        *,
        status: int = 200,
        headers=None,
        failure=None,
        handler=None,
    ):
        """Serve crt.name through the guarded passive client, with a mock transport behind it."""

        def respond(request):
            self.api_requests.append(request)
            if handler is not None:
                return handler(request)
            if failure is not None:
                raise failure(request)
            return httpx.Response(
                status, headers=headers, content=body, request=request
            )

        transport = httpx.MockTransport(respond)
        ct = self.ct
        self.mp.setattr(
            ct.CrtScout,
            "_api",
            lambda scout: api_client(ct.API_HOSTS, timeout=1, transport=transport),
        )

    def probes(self, routes=None, *, handler=None):
        """Serve probe targets. `routes`: url -> (status, headers) or an exception instance.
        Unrouted URLs fail to connect. The client is UNGUARDED, so any policy denial seen in a
        test must come from the addon's own explicit authorization."""
        routes = routes or {}

        async def respond(request):
            self.probe_requests.append(request)
            if handler is not None:
                return await handler(request)
            outcome = routes.get(str(request.url))
            if outcome is None:
                raise httpx.ConnectError("no route", request=request)
            if isinstance(outcome, Exception):
                raise outcome
            status, headers = outcome
            return httpx.Response(status, headers=headers, request=request)

        transport = httpx.MockTransport(respond)
        self.mp.setattr(
            self.ct.CrtScout,
            "_probe_client",
            lambda scout: httpx.AsyncClient(transport=transport),
        )

    def run(self, *argv: str) -> Run:
        """`main()` as the loader drives it: sys.argv[0] is `bughunt ct`; exit via SystemExit."""
        self.mp.setattr(sys, "argv", ["bughunt ct", *argv])
        code = 0
        try:
            asyncio.run(self.ct.main())
        except SystemExit as exc:
            code = 0 if exc.code is None else exc.code
        out, err = self.capsys.readouterr()
        return Run(code, out, err)

    def scout(self, *extra: str, domain: str = "allowed.example"):
        args = self.ct.create_parser().parse_args([domain, "-q", *extra])
        return self.ct.CrtScout(args.domain, args)


@pytest.fixture(scope="session")
def addons_root(tmp_path_factory):
    """A throwaway addons tree holding a byte copy of the script under test."""
    root = tmp_path_factory.mktemp("ct-addons")
    (root / "crt-scout").mkdir()
    shutil.copyfile(SCRIPT, root / "crt-scout" / "crt-scout.py")
    return root


@pytest.fixture(scope="session")
def ct(addons_root):
    return loader.import_script(addons_root / "crt-scout" / "crt-scout.py")


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Tripwire: nothing in this module may resolve a name or open a socket."""

    def forbidden(*args, **kwargs):
        raise AssertionError(
            "real network reached from a crt-scout characterization test"
        )

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture(autouse=True)
def script_style_main(monkeypatch):
    """Python 3.14 argparse derives the default prog from `__main__.__spec__` (so `python -m pytest`
    wins over sys.argv[0]). A console-script or `python script.py` launch has no spec: emulate that."""
    monkeypatch.setitem(sys.modules, "__main__", types.SimpleNamespace(__spec__=None))


@pytest.fixture
def world(ct, monkeypatch, tmp_path, capsys, standalone_python):
    scene = World(ct, monkeypatch, tmp_path, capsys)
    scene.standalone_python = standalone_python
    return scene


# ---------------------------------------------------------------------------------------------
# A. CLI surface (section 3) and discovery
# ---------------------------------------------------------------------------------------------

EXPECTED_ACTIONS = [
    # dest, option strings, default
    ("domain", [], None),
    ("check", ["-c", "--check"], False),
    ("https_only", ["--https-only"], False),
    ("insecure", ["-k", "--insecure"], False),
    ("ua", ["--ua"], DEFAULT_UA),
    ("output", ["-o", "--output"], None),
    ("wordlist", ["-w", "--wordlist"], None),
    ("dates", ["-d", "--dates"], False),
    ("timeout", ["--timeout"], 5),
    ("workers", ["--workers"], 50),
    ("show_dead", ["--show-dead"], False),
    ("quiet", ["-q", "--quiet"], False),
]


def test_parser_actions_dests_flags_and_defaults(ct):
    actions = ct.create_parser()._actions
    assert len(actions) == 13
    assert [a.dest for a in actions if a.dest != "help"] == [
        name for name, _f, _d in EXPECTED_ACTIONS
    ]
    for name, flags, default in EXPECTED_ACTIONS:
        action = next(a for a in actions if a.dest == name)
        assert (action.option_strings, action.default) == (flags, default), name
    assert next(a for a in actions if a.dest == "domain").required is True
    assert next(a for a in actions if a.dest == "help").option_strings == [
        "-h",
        "--help",
    ]


def test_parser_value_types_and_combined_short_switches(ct):
    args = ct.create_parser().parse_args(
        ["x.example", "--timeout", "7", "--workers", "3", "-ckq"]
    )
    assert (args.timeout, args.workers) == (7, 3)
    assert isinstance(args.timeout, int) and isinstance(args.workers, int)
    assert (args.check, args.insecure, args.quiet) == (True, True, True)
    assert (args.https_only, args.dates, args.show_dead) == (False, False, False)


def test_parser_usage_line_shows_the_program_name_from_argv(ct, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["bughunt ct"])
    assert ct.create_parser().format_usage().startswith("usage: bughunt ct")


def test_api_hosts_constant_is_exactly_crt_name(ct):
    assert ct.API_HOSTS == frozenset({"crt.name"})


def test_catalog_form_matches_the_parser_in_console_order(addons_root, monkeypatch):
    monkeypatch.setenv("BUGHUNT_ADDONS", str(addons_root))
    data = export_catalog(
        tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    entry = next(m for p in data["phases"] for m in p["modules"] if m["name"] == "ct")
    assert (
        entry["disabled"] is False
        and entry["aliases"] == ["crt-scout"]
        and entry["reference"] is True
    )
    options = [
        (o["name"], o["flags"], o["kind"], o["required"], o["default"])
        for o in entry["form"]["options"]
    ]
    ua_default = options[4][4]
    assert ua_default.startswith("Mozilla/5.0 (Windows NT 10.0;")
    options[4] = options[4][:4] + ("<ua>",)
    assert options == [
        ("DOMAIN", [], "positional", True, ""),
        ("CHECK", ["-c", "--check"], "bool", False, ""),
        ("HTTPS_ONLY", ["--https-only"], "bool", False, ""),
        ("INSECURE", ["-k", "--insecure"], "bool", False, ""),
        ("UA", ["--ua"], "value", False, "<ua>"),
        ("OUTPUT", ["-o", "--output"], "value", False, ""),
        ("WORDLIST", ["-w", "--wordlist"], "value", False, ""),
        ("DATES", ["-d", "--dates"], "bool", False, ""),
        ("TIMEOUT", ["--timeout"], "value", False, "5"),
        ("WORKERS", ["--workers"], "value", False, "50"),
        ("SHOW_DEAD", ["--show-dead"], "bool", False, ""),
        ("QUIET", ["-q", "--quiet"], "bool", False, ""),
    ]


def test_catalog_registers_ct_with_crt_scout_alias_in_recon():
    tool = catalog.tool_by_command("ct")
    assert (tool.command, tool.folder, tool.script, tool.aliases) == (
        "ct",
        "crt-scout",
        "crt-scout.py",
        ("crt-scout",),
    )
    assert (
        tool.summary
        == "Find subdomains in certificate logs, then test which of them are live."
    )
    assert (
        catalog.reference_canonical("crt-scout") == "ct"
        and catalog.reference_canonical("ct") == "ct"
    )
    assert "ct" not in catalog.DISABLED_REFERENCES
    assert "ct" in dict(catalog.MODULE_GROUPS)["Recon"]


# ---------------------------------------------------------------------------------------------
# B. main(): order of operations and exit codes (4.1)
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "domain",
    [
        "not_a_domain",
        "localhost",
        "a..b.com",
        "a_b.allowed.example",
        "allowed.example.",
        ".allowed.example",
        "http://allowed.example",
        "allowed.example/path",
        "allowed.example:443",
        "b" + chr(0xFC) + "cher.example",
        "a b.example",
    ],
)
def test_invalid_domain_format_exits_1_before_any_request(world, domain):
    world.api(names_body("www.allowed.example"))
    world.probes()
    run = world.run("-c", "--", domain)
    assert run.code == 1
    assert domain in run.err
    assert run.out == ""
    assert world.api_requests == [] and world.probe_requests == []


def test_leading_hyphen_domain_is_an_argparse_error_unless_separated_and_then_a_format_error(
    world,
):
    world.api(names_body("www.allowed.example"))
    assert world.run("-a.example.com", "-c").code == 2
    assert world.run("-c", "--", "-a.example.com").code == 1
    assert world.api_requests == []


@pytest.mark.parametrize(
    "domain", ["1.2.3.4", "a.b", "xn--bcher-kva.example", "a-.example.com", "0.example"]
)
def test_well_formed_but_out_of_scope_domain_passes_the_format_gate_and_exits_2(
    world, domain
):
    world.api(names_body("www.allowed.example"))
    run = world.run(domain)
    assert run.code == 2
    assert run.out == "" and world.api_requests == []


def test_out_of_scope_domain_exits_2_with_plain_explanation_and_no_request(
    world, ct, monkeypatch
):
    monkeypatch.setattr(
        ct.CrtScout,
        "_api",
        lambda scout: (_ for _ in ()).throw(AssertionError("api built")),
    )
    monkeypatch.setattr(
        ct.CrtScout,
        "_probe_client",
        lambda scout: (_ for _ in ()).throw(AssertionError("probe built")),
    )
    run = world.run("outside.example", "-c")
    assert run.code == 2
    assert run.out == ""
    assert "\x1b[" not in run.err
    assert run.err.strip() == workspace.explain_block("outside.example").strip()


def test_domain_is_unusable_without_any_scope_file(world):
    world.workspace(scope=None)
    world.api(names_body("www.allowed.example"))
    run = world.run("allowed.example")
    assert run.code == 2 and run.out == "" and world.api_requests == []


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["allowed.example", "--timeout", "x"],
        ["allowed.example", "--workers", "1.5"],
        ["allowed.example", "--nope"],
        ["allowed.example", "--version"],
    ],
)
def test_argparse_errors_exit_2(world, argv):
    world.api(names_body("www.allowed.example"))
    run = world.run(*argv)
    assert run.code == 2
    assert run.out == "" and world.api_requests == []
    assert "usage:" in run.err


def test_help_exits_0_on_stdout_and_lists_every_flag(world):
    run = world.run("-h")
    assert run.code == 0
    assert run.out.startswith("usage: bughunt ct")
    for flag in (
        "--check",
        "--https-only",
        "--insecure",
        "--ua",
        "--output",
        "--wordlist",
        "--dates",
        "--timeout",
        "--workers",
        "--show-dead",
        "--quiet",
    ):
        assert flag in run.out


def test_domain_is_lowercased_before_scope_and_the_api_query(world):
    world.api(names_body("www.allowed.example"))
    run = world.run("ALLOWED.Example")
    assert run.code == 0
    assert world.api_urls == [API_URL]
    assert run.plain_out == "www.allowed.example\n"


def test_preflight_requires_a_policy_asset_for_the_apex_even_without_check(world):
    world.workspace(scope=("allowed.example", "noasset.example"))
    world.api(names_body("www.noasset.example"))
    with pytest.raises(egress.PolicyBlocked, match="exact origin/root grant required"):
        world.run("noasset.example")
    assert world.api_requests == []
    assert world.capsys.readouterr().out == ""


def test_preflight_requires_the_passive_operation_on_the_apex(world):
    world.workspace(
        restrict={
            origin: ["crawl"]
            for origin in (
                "https://allowed.example",
                "http://allowed.example",
                "https://allowed.example:80",
            )
        }
    )
    world.api(names_body("www.allowed.example"))
    with pytest.raises(egress.PolicyBlocked):
        world.run("allowed.example")
    assert world.api_requests == []


def test_preflight_with_no_policy_file_is_policy_blocked(world):
    world.workspace(policy=False)
    world.api(names_body("www.allowed.example"))
    with pytest.raises(egress.PolicyBlocked, match="policy-missing-or-invalid"):
        world.run("allowed.example")
    assert world.api_requests == []


@pytest.mark.parametrize("status", [204, 301, 403, 404, 429, 500, 503])
def test_api_non_200_is_a_soft_failure_with_the_status_in_the_notice(world, status):
    world.api(b"www.allowed.example\n", status=status)
    run = world.run("allowed.example", "-c")
    assert run.code == 0 and run.out == ""
    assert str(status) in run.err
    assert world.probe_requests == []


def test_api_timeout_is_a_soft_failure(world):
    world.api(failure=lambda request: httpx.ReadTimeout("slow", request=request))
    run = world.run("allowed.example")
    assert run.code == 0 and run.out == ""
    assert run.err.strip()


def test_api_transport_error_is_a_soft_failure_that_shows_the_error_text(world):
    world.api(
        failure=lambda request: httpx.ConnectError("kaboom-reason", request=request)
    )
    run = world.run("allowed.example")
    assert run.code == 0 and run.out == ""
    assert "kaboom-reason" in run.err


def test_policy_denied_crt_name_is_a_soft_failure_and_never_reaches_the_transport(
    world,
):
    world.workspace(drop=["https://crt.name"])
    world.api(names_body("www.allowed.example"))
    run = world.run("allowed.example", "-c")
    assert run.code == 0 and run.out == ""
    assert "no outbound action ran" in run.err
    assert world.api_requests == [] and world.probe_requests == []


def test_crt_name_grant_must_cover_the_passive_operation(world):
    world.workspace(restrict={"https://crt.name": ["crawl"]})
    world.api(names_body("www.allowed.example"))
    run = world.run("allowed.example")
    assert run.code == 0 and run.out == ""
    assert world.api_requests == []


@pytest.mark.parametrize("body", [b"", b"\n\n   \n\t\n"])
def test_empty_result_ends_the_run_with_exit_0_and_no_stdout(world, body, tmp_path):
    world.api(body)
    wordlist = tmp_path / "w.txt"
    run = world.run("allowed.example", "-c", "-w", str(wordlist))
    assert run.code == 0 and run.out == ""
    assert "no subdomains returned" in run.plain_err.lower()
    assert world.probe_requests == [] and not wordlist.exists()


def test_when_every_name_is_dropped_the_run_ends_without_wordlist_or_probes(
    world, tmp_path
):
    world.api(names_body("evil.example", "*.allowed.example", "169.254.169.254"))
    wordlist = tmp_path / "w.txt"
    run = world.run("allowed.example", "-c", "-w", str(wordlist))
    assert run.code == 0 and run.out == ""
    assert re.search(r"skipped\s+3\b", run.plain_err.lower())
    assert "no subdomains returned" in run.plain_err.lower()
    assert world.probe_requests == [] and not wordlist.exists()


def test_zero_live_hosts_is_exit_0_with_nothing_on_stdout(world):
    world.api(names_body("www.allowed.example", "api.allowed.example"))
    world.probes({})
    run = world.run("allowed.example", "-c", "-q")
    assert run.code == 0 and run.out == ""


def test_standalone_ctrl_c_exits_130_with_a_notice_on_stderr(
    world, monkeypatch, capsys
):
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(workspace, "allowed", interrupt)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "allowed.example"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    out, err = capsys.readouterr()
    assert exit_info.value.code == 130
    assert out == "" and err.strip()


# --- standalone subprocess runs (documented usage: `python crt-scout.py <domain>`) ------------


def standalone(world, *args, pythonpath=True):
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    env["BUGHUNT_SCOPE"] = str(world.scope_dir)
    if pythonpath:
        env["PYTHONPATH"] = str(REPO)
    command = [sys.executable] if pythonpath else world.standalone_python
    return subprocess.run(
        [*command, str(SCRIPT), *args],
        cwd=world.tmp,
        env=env,
        timeout=120,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def test_standalone_out_of_scope_exits_2(world):
    done = standalone(world, "outside.example")
    assert done.returncode == 2 and done.stdout == ""
    assert "outside.example" in done.stderr


def test_standalone_invalid_domain_exits_1(world):
    done = standalone(world, "not_a_domain")
    assert done.returncode == 1 and done.stdout == ""


def test_standalone_argparse_error_exits_2(world):
    done = standalone(world, "allowed.example", "--timeout", "x")
    assert done.returncode == 2 and done.stdout == ""


def test_standalone_policy_block_at_preflight_is_an_uncaught_traceback_exit_1(world):
    world.workspace(scope=("allowed.example", "noasset.example"))
    done = standalone(world, "noasset.example")
    assert done.returncode == 1 and done.stdout == ""
    assert "Traceback" in done.stderr and "PolicyBlocked" in done.stderr


def test_standalone_without_pythonpath_disables_editable_registration(
    world, monkeypatch
):
    probe = world.tmp / "import_probe.py"
    probe.write_text(
        "import importlib.util, sys\n"
        "import httpx, rich\n"
        "print(sys.flags.isolated, sys.flags.no_site, importlib.util.find_spec('bughunt') is None)\n",
        encoding="utf-8",
    )
    monkeypatch.setitem(globals(), "SCRIPT", probe)
    done = standalone(world, pythonpath=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "1 1 True"


def test_standalone_launch_works_without_bughunt_on_pythonpath(world):
    done = standalone(world, "outside.example", pythonpath=False)
    assert "ModuleNotFoundError" not in done.stderr
    assert done.returncode == 2


# ---------------------------------------------------------------------------------------------
# C. Fetch and name filter (4.2, 6.1)
# ---------------------------------------------------------------------------------------------


def test_api_request_has_only_the_apex_parameter_without_dates(world):
    world.api(names_body("www.allowed.example"))
    world.run("allowed.example")
    assert world.api_urls == [API_URL]
    assert world.api_requests[0].method == "GET"


def test_dates_flag_adds_dates_1_after_the_apex_parameter(world):
    world.api(names_body("www.allowed.example"))
    world.run("allowed.example", "-d")
    assert world.api_urls == [API_URL + "&dates=1"]


def test_dates_flag_shows_the_first_seen_dates(world):
    world.api(b"www.allowed.example 2021-05-01\napi.allowed.example 2022-07-09\n")
    run = world.run("allowed.example", "-d")
    assert "2021-05-01" in run.plain_out and "2022-07-09" in run.plain_out


@pytest.mark.parametrize("checked", [False, True])
def test_supplied_dates_survive_export_without_inventing_missing_dates(
    world, tmp_path, checked
):
    world.api(
        b"www.allowed.example 2021-05-01\nwww.allowed.example 2021-05-01\napi.allowed.example\n"
    )
    world.probes(
        {
            "https://www.allowed.example": (200, {}),
            "https://api.allowed.example": (200, {}),
        }
    )
    target = tmp_path / "dated.txt"
    arguments = ["allowed.example", "-d", "-o", str(target)]
    if checked:
        arguments += ["-c", "-q"]
    run = world.run(*arguments)
    lines = read_lines(target)
    assert run.code == 0 and run.out == ""
    assert len(lines) == 2
    assert next(line for line in lines if "www.allowed.example" in line).endswith(
        "[dates: 2021-05-01]"
    )
    assert "dates:" not in next(line for line in lines if "api.allowed.example" in line)


def test_names_are_lowercased_dot_stripped_first_token_and_deduplicated(world):
    body = (
        "WWW.Allowed.Example.\n"
        "api.allowed.example 2021-05-01 2022-01-01\n"
        "api.allowed.example\n"
        "\n   \n\t\n"
        "  dev.allowed.example..\r\n"
        "app.allowed.example\t2020-01-01\n"
        "ADMIN.allowed.example\r\n"
    ).encode()
    world.api(body)
    run = world.run("allowed.example")
    assert run.plain_out.splitlines() == [
        "admin.allowed.example",
        "api.allowed.example",
        "app.allowed.example",
        "dev.allowed.example",
        "www.allowed.example",
    ]


def test_pinned_filter_vector_through_main(world):
    world.api(
        names_body(
            "www.allowed.example",
            "allowed.example",
            "evil.example",
            "*.allowed.example",
            "x.allowed.example@evil.example",
            "169.254.169.254",
        )
    )
    run = world.run("allowed.example")
    assert run.plain_out.splitlines() == ["allowed.example", "www.allowed.example"]
    assert re.search(r"skipped\s+4\b", run.plain_err.lower())
    assert re.search(r"found\s+2\b", run.plain_err.lower())


LABEL_63 = "a" * 63
NAME_253 = "b" * 45 + f".{LABEL_63}" * 3 + ".allowed.example"
NAME_254 = "b" * 46 + f".{LABEL_63}" * 3 + ".allowed.example"

KEEP_CASES = [
    ("allowed.example", True),
    ("www.allowed.example", True),
    ("a.b.c.allowed.example", True),
    ("xn--bcher-kva.allowed.example", True),
    ("a-b.allowed.example", True),
    ("1.allowed.example", True),
    (f"{LABEL_63}.allowed.example", True),
    (NAME_253, True),
    ("notallowed.example", False),
    ("evilallowed.example", False),
    ("allowed.example.evil.example", False),
    ("x.allowed.example@evil.example", False),
    ("evil.example", False),
    ("*.allowed.example", False),
    ("_dmarc.allowed.example", False),
    ("-bad.allowed.example", False),
    ("bad-.allowed.example", False),
    ("a..allowed.example", False),
    (".allowed.example", False),
    ("www.allowed.example:443", False),
    ("www.allowed.example/", False),
    ("www allowed.example", False),
    ("169.254.169.254", False),
    ("", False),
    (f"{'a' * 64}.allowed.example", False),
    (NAME_254, False),
]


@pytest.mark.parametrize(
    "name,expected", KEEP_CASES, ids=[f"{n[:40]}|{e}" for n, e in KEEP_CASES]
)
def test_keep_name_only_hostnames_under_the_domain(world, name, expected):
    assert world.scout().keep_name(name) is expected


KEEP_GRAMMAR_CASES = [
    ("x.co", True),
    ("a.example", True),
    ("a.xn--p1ai", True),
    ("1.2.3.4", False),
    ("a.b", False),
    ("a.1b", False),
    ("a.bc-", False),
    (f"a.{'t' * 63}", True),
    (f"a.{'t' * 64}", False),
]


@pytest.mark.parametrize(
    "name,expected",
    KEEP_GRAMMAR_CASES,
    ids=[f"{n[:30]}|{e}" for n, e in KEEP_GRAMMAR_CASES],
)
def test_keep_name_final_label_grammar(world, name, expected):
    world.workspace(scope=("allowed.example", name))
    assert workspace.allowed(name) is True, (
        "precondition: only the hostname grammar may reject this name"
    )
    assert world.scout(domain=name).keep_name(name) is expected


def test_keep_name_also_requires_the_name_to_be_in_scope(world):
    world.workspace(scope=("*.allowed.example",))
    scout = world.scout()
    assert workspace.allowed("allowed.example") is False
    assert scout.keep_name("allowed.example") is False
    assert scout.keep_name("www.allowed.example") is True


OTHER_IN_SCOPE_NAMES = (
    "other.example",
    "www.other.example",
    "notallowed.example",
    "evilallowed.example",
    "allowed.example.other.example",
)


@pytest.mark.parametrize("name", OTHER_IN_SCOPE_NAMES)
def test_keep_name_requires_the_name_to_be_under_the_domain_even_when_it_is_in_scope(
    world, name
):
    world.workspace(
        scope=(
            "allowed.example",
            "other.example",
            "notallowed.example",
            "evilallowed.example",
        )
    )
    assert workspace.allowed(name) is True, (
        "precondition: scope alone must not be what rejects this name"
    )
    assert world.scout().keep_name(name) is False


def test_fetch_keeps_only_names_under_the_domain_when_scope_is_wider(world):
    world.workspace(
        scope=(
            "allowed.example",
            "other.example",
            "notallowed.example",
            "evilallowed.example",
        )
    )
    world.api(names_body("www.allowed.example", *OTHER_IN_SCOPE_NAMES))
    scout = world.scout()
    asyncio.run(scout.fetch_subdomains())
    assert scout.subdomains == {"www.allowed.example"}


def test_fetch_drops_in_domain_names_that_scope_does_not_cover(world):
    world.workspace(scope=("*.allowed.example",))
    world.api(names_body("allowed.example", "www.allowed.example"))
    scout = world.scout()
    asyncio.run(scout.fetch_subdomains())
    assert scout.subdomains == {"www.allowed.example"}


def test_notices_report_found_count_and_use_severity_colors(world):
    world.api(names_body("www.allowed.example", "api.allowed.example", "evil.example"))
    run = world.run("allowed.example")
    lines = run.err.splitlines()
    querying = next(
        line
        for line in lines
        if "allowed.example" in line
        and "found" not in line.lower()
        and "skipped" not in line.lower()
    )
    skipped = next(line for line in lines if "skipped" in line.lower())
    found = next(line for line in lines if "found" in line.lower())
    assert (
        querying.startswith(BLUE)
        and skipped.startswith(YELLOW)
        and found.startswith(GREEN)
    )
    assert re.search(r"skipped\s+1\b", plain(skipped).lower()) and re.search(
        r"found\s+2\b", plain(found).lower()
    )
    assert all(line.endswith(RESET) for line in (querying, skipped, found))

    world.api(b"")
    empty = world.run("allowed.example")
    assert next(
        line for line in empty.err.splitlines() if "no subdomains" in line.lower()
    ).startswith(RED)


# --- the API client: host allow-list, hop cap, wire facts ---------------------------------------


def test_api_redirect_within_crt_name_is_followed(world):
    def handler(request):
        if request.url.path == "/v1/search":
            return httpx.Response(
                302,
                headers={"location": "https://crt.name/v1/moved?apex=allowed.example"},
                request=request,
            )
        return httpx.Response(
            200, content=names_body("www.allowed.example"), request=request
        )

    world.api(handler=handler)
    run = world.run("allowed.example")
    assert run.plain_out == "www.allowed.example\n"
    assert world.api_urls == [API_URL, "https://crt.name/v1/moved?apex=allowed.example"]


def test_api_redirect_off_the_allow_list_is_never_requested(world):
    def handler(request):
        return httpx.Response(
            302,
            headers={"location": "https://evil.example/steal?apex=allowed.example"},
            request=request,
        )

    world.api(handler=handler)
    run = world.run("allowed.example")
    assert run.code == 0 and run.out == ""
    assert world.api_urls == [API_URL]
    assert "evil.example" in run.err


def test_api_redirect_chain_is_capped_at_five_hops(world):
    def handler(request):
        return httpx.Response(
            302, headers={"location": "https://crt.name/v1/loop"}, request=request
        )

    world.api(handler=handler)
    run = world.run("allowed.example")
    assert run.code == 0 and run.out == ""
    assert len(world.api_requests) == 6
    assert "302" in run.err


def test_real_api_client_is_a_guarded_passive_client_with_a_host_allow_list(world):
    # Swapping `_transport` after construction keeps the egress guard in front of the mock; the
    # guard itself relies on this httpx 0.28.1 seam (egress._wrap -> _transport_for_url).
    scout = world.scout()
    seen = []
    client = scout._api()
    client._transport = httpx.MockTransport(
        lambda request: seen.append(request) or httpx.Response(200, request=request)
    )
    with client:
        assert client.trust_env is False and client.follow_redirects is False
        with pytest.raises(HostNotAllowed):
            client.get("https://evil.example/")
        with pytest.raises(HostNotAllowed):
            client.get("https://crt.name.evil.example/")
        assert seen == []
        assert (
            client.get(
                "https://crt.name/v1/search", params={"apex": "allowed.example"}
            ).status_code
            == 200
        )
    assert [str(request.url) for request in seen] == [API_URL]


def test_wire_user_agent_is_the_policy_profile_for_api_and_probes_not_the_ua_flag(
    world,
):
    profile_agent = egress.current_profile().user_agent
    assert profile_agent != "CUSTOM-UA"
    scout = world.scout("--ua", "CUSTOM-UA")
    wire = []

    def record(request):
        wire.append(request.headers.get("user-agent"))
        return httpx.Response(200, request=request)

    api = scout._api()
    api._transport = httpx.MockTransport(record)
    with api:
        api.get("https://crt.name/v1/search", params={"apex": "allowed.example"})

    async def probe():
        client = scout._probe_client()
        client._transport = httpx.MockTransport(record)
        async with client:
            await client.get("https://www.allowed.example")

    asyncio.run(probe())
    assert wire == [profile_agent, profile_agent]


def test_real_probe_client_blocks_a_url_with_no_policy_grant_before_the_transport(
    world,
):
    scout = world.scout()
    seen = []

    async def probe():
        client = scout._probe_client()
        client._transport = httpx.MockTransport(
            lambda request: seen.append(request) or httpx.Response(200, request=request)
        )
        async with client:
            with pytest.raises(egress.PolicyBlocked):
                await client.get("https://mail.allowed.example")
            assert seen == []
            assert (await client.get("https://www.allowed.example")).status_code == 200

    asyncio.run(probe())
    assert [str(request.url) for request in seen] == ["https://www.allowed.example"]


def test_api_client_kwargs_ua_timeout_and_tls_always_verified(world, monkeypatch):
    captured = {}
    real = egress.client
    monkeypatch.setattr(
        egress, "client", lambda **kwargs: captured.update(kwargs) or real(**kwargs)
    )
    scout = world.scout("--ua", "UA-API", "-k")
    scout._api().close()
    assert captured["operation"] == "passive"
    assert captured["headers"]["User-Agent"] == "UA-API"
    assert captured["timeout"] == 30
    assert captured["trust_env"] is False and captured["follow_redirects"] is False
    assert captured.get("verify", True) is True, (
        "crt.name must be TLS-verified even with -k"
    )


@pytest.mark.parametrize(
    "flags,verify", [((), True), (("-k",), False), (("--insecure",), False)]
)
def test_probe_client_kwargs_ua_timeouts_limits_and_verify(
    world, monkeypatch, flags, verify
):
    captured = {}
    real = egress.async_client
    monkeypatch.setattr(
        egress,
        "async_client",
        lambda **kwargs: captured.update(kwargs) or real(**kwargs),
    )
    world.scout("--ua", "UA-PROBE", "--timeout", "7", *flags)._probe_client()
    assert captured["operation"] == "crawl"
    assert captured["headers"]["User-Agent"] == "UA-PROBE"
    assert captured["timeout"] == httpx.Timeout(10, connect=7)
    assert captured["limits"] == httpx.Limits(max_connections=100)
    assert captured["verify"] is verify
    assert captured["trust_env"] is False and captured["follow_redirects"] is False


def test_default_ua_reaches_both_clients(world, monkeypatch):
    captured = []
    real_sync, real_async = egress.client, egress.async_client
    monkeypatch.setattr(
        egress,
        "client",
        lambda **kw: captured.append(kw["headers"]["User-Agent"]) or real_sync(**kw),
    )
    monkeypatch.setattr(
        egress,
        "async_client",
        lambda **kw: captured.append(kw["headers"]["User-Agent"]) or real_async(**kw),
    )
    scout = world.scout()
    scout._api().close()
    scout._probe_client()
    assert captured == [DEFAULT_UA, DEFAULT_UA]


def test_addon_source_has_no_raw_network_primitives():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    banned_modules = {
        "socket",
        "subprocess",
        "requests",
        "aiohttp",
        "urllib3",
        "http.client",
        "urllib.request",
    }
    banned_calls = {
        "Client",
        "AsyncClient",
        "get",
        "post",
        "put",
        "delete",
        "head",
        "options",
        "patch",
        "request",
        "stream",
        "HTTPTransport",
        "AsyncHTTPTransport",
    }
    imported, called = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
            imported.update(f"{node.module}.{alias.name}" for alias in node.names)
            if node.module == "httpx":
                called.update(
                    alias.name for alias in node.names if alias.name in banned_calls
                )
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "httpx"
        ):
            if node.func.attr in banned_calls:
                called.add(node.func.attr)
    assert imported & banned_modules == set()
    assert called == set()


# ---------------------------------------------------------------------------------------------
# D. Wordlist (4.3)
# ---------------------------------------------------------------------------------------------


def read_lines(path: Path) -> list[str]:
    return path.read_bytes().decode("utf-8").splitlines()


def test_wordlist_pinned_vector_sorted_unique_prefixes_without_stoplisted_labels(
    world, tmp_path
):
    names = (
        "allowed.example",
        "api.v2.allowed.example",
        "evil.allowed.example",
        "mail.allowed.example",
        "www.allowed.example",
    )
    world.api(names_body(*names))
    target = tmp_path / "words.txt"
    run = world.run("allowed.example", "-w", str(target))
    assert run.code == 0
    assert read_lines(target) == ["api", "evil", "v2"]
    assert str(target) in run.err
    assert run.plain_out.splitlines() == sorted(names)


@pytest.mark.parametrize("stopword", ["www", "mail", "ftp", "blog", "shop"])
def test_wordlist_stoplist_applies_at_any_label_position(world, tmp_path, stopword):
    world.api(
        names_body(
            f"{stopword}.allowed.example",
            f"api.{stopword}.allowed.example",
            f"{stopword}.api2.allowed.example",
        )
    )
    target = tmp_path / "words.txt"
    world.run("allowed.example", "-w", str(target))
    assert read_lines(target) == ["api", "api2"]


def test_wordlist_keeps_near_miss_labels_and_sorts_lexicographically(world, tmp_path):
    world.api(
        names_body(
            "www2.allowed.example",
            "mailer.allowed.example",
            "shopping.allowed.example",
            "10.allowed.example",
            "2.allowed.example",
            "a-b.x.allowed.example",
            "x.allowed.example",
        )
    )
    target = tmp_path / "words.txt"
    world.run("allowed.example", "-w", str(target))
    assert read_lines(target) == ["10", "2", "a-b", "mailer", "shopping", "www2", "x"]


def test_wordlist_deduplicates_labels_across_names(world, tmp_path):
    world.api(
        names_body(
            "api.v2.allowed.example", "api.v3.allowed.example", "v2.api.allowed.example"
        )
    )
    target = tmp_path / "words.txt"
    world.run("allowed.example", "-w", str(target))
    assert read_lines(target) == ["api", "v2", "v3"]


def test_wordlist_is_an_empty_file_when_only_the_apex_and_stoplisted_names_exist(
    world, tmp_path
):
    world.api(names_body("allowed.example", "www.allowed.example"))
    target = tmp_path / "words.txt"
    run = world.run("allowed.example", "-w", str(target))
    assert target.read_bytes() == b""
    assert run.code == 0


def test_wordlist_truncates_an_existing_file(world, tmp_path):
    target = tmp_path / "words.txt"
    target.write_text("stale-1\nstale-2\nstale-3\nstale-4\n", encoding="utf-8")
    world.api(names_body("api.allowed.example"))
    world.run("allowed.example", "-w", str(target))
    assert read_lines(target) == ["api"]


def test_wordlist_is_built_from_all_kept_names_not_only_live_ones(world, tmp_path):
    world.api(
        names_body(
            "www.allowed.example", "dead-one.allowed.example", "dev.allowed.example"
        )
    )
    world.probes({"https://www.allowed.example": (200, {})})
    target = tmp_path / "words.txt"
    run = world.run("allowed.example", "-c", "-q", "-w", str(target))
    assert read_lines(target) == ["dead-one", "dev"]
    assert plain(run.out).splitlines() == [
        live_line("https://www.allowed.example", 200)
    ]


def test_wordlist_write_failure_exits_one_without_continuing(world, tmp_path):
    world.api(names_body("api.allowed.example"))
    run = world.run("allowed.example", "-w", str(tmp_path))
    assert run.code == 1
    assert run.plain_out == ""
    assert run.err.strip()


# ---------------------------------------------------------------------------------------------
# E. stdout and -o contracts (6.2)
# ---------------------------------------------------------------------------------------------


def test_without_check_stdout_is_the_sorted_bare_names_uncolored_and_nothing_else(
    world,
):
    names = (
        "www.allowed.example",
        "allowed.example",
        "api.allowed.example",
        "app.allowed.example",
    )
    world.api(names_body(*names))
    run = world.run("allowed.example", "--show-dead")
    assert run.out == "".join(f"{name}\n" for name in sorted(names))
    assert "\x1b" not in run.out
    assert world.probe_requests == []


def test_output_file_is_honored_without_check(world, tmp_path):
    names = ("www.allowed.example", "api.allowed.example")
    world.api(names_body(*names))
    target = tmp_path / "names.txt"
    world.run("allowed.example", "-o", str(target))
    assert target.exists()
    assert read_lines(target) == sorted(names)


def test_output_without_check_writes_names_instead_of_stdout(world, tmp_path):
    world.api(names_body("www.allowed.example"))
    target = tmp_path / "names.txt"
    run = world.run("allowed.example", "-o", str(target))
    assert run.code == 0
    assert run.plain_out == ""
    assert read_lines(target) == ["www.allowed.example"]


LIVE_ROUTES = {
    "https://www.allowed.example": (200, {}),
    "https://api.allowed.example": (404, {}),
    "https://app.allowed.example": (301, {"location": "https://evil.example/x"}),
    "http://admin.allowed.example": (200, {}),
}
LIVE_NAMES = (
    "www.allowed.example",
    "api.allowed.example",
    "app.allowed.example",
    "admin.allowed.example",
    "dev.allowed.example",
)
LIVE_EXPECTED = [
    live_line("http://admin.allowed.example", 200),
    live_line("https://www.allowed.example", 200),
    live_line("https://app.allowed.example", 301),
    live_line("https://api.allowed.example", 404),
]


def test_live_lines_use_the_exact_format_and_sort_by_scheme_then_status(world):
    world.api(names_body(*LIVE_NAMES))
    world.probes(LIVE_ROUTES)
    run = world.run("allowed.example", "-c", "-q")
    assert run.code == 0
    assert run.plain_out.splitlines() == LIVE_EXPECTED
    assert run.plain_out.count(f"  {ARROW}  HTTP ") == 4


def test_live_and_dead_lines_are_colored_even_when_stdout_is_not_a_terminal(world):
    world.api(names_body(*LIVE_NAMES))
    world.probes(LIVE_ROUTES)
    run = world.run("allowed.example", "-c", "-q", "--show-dead")
    expected = [f"{GREEN}{line}{RESET}" for line in LIVE_EXPECTED] + [
        f"{RED}[DEAD] dev.allowed.example{RESET}"
    ]
    assert run.out.splitlines() == expected


def test_show_dead_lists_dead_hosts_after_all_live_lines(world):
    world.api(
        names_body(
            "www.allowed.example",
            "dev.allowed.example",
            "admin.allowed.example",
            "api.allowed.example",
        )
    )
    world.probes({"https://www.allowed.example": (200, {})})
    run = world.run("allowed.example", "-c", "-q", "--show-dead")
    lines = run.plain_out.splitlines()
    assert lines[0] == live_line("https://www.allowed.example", 200)
    assert sorted(lines[1:]) == [
        "[DEAD] admin.allowed.example",
        "[DEAD] api.allowed.example",
        "[DEAD] dev.allowed.example",
    ]


def test_dead_hosts_are_hidden_without_show_dead(world):
    world.api(names_body("www.allowed.example", "dev.allowed.example"))
    world.probes({"https://www.allowed.example": (200, {})})
    run = world.run("allowed.example", "-c", "-q")
    assert run.plain_out == live_line("https://www.allowed.example", 200) + "\n"


def test_results_records_are_host_scheme_status_tuples_with_dead_as_none(world):
    world.api(names_body("www.allowed.example", "dev.allowed.example"))
    world.probes({"https://www.allowed.example": (200, {})})
    scout = world.scout("-c")
    asyncio.run(scout.run())
    assert sorted(scout.results) == [
        ("dev.allowed.example", "dead", None),
        ("www.allowed.example", "https", 200),
    ]
    assert all(
        isinstance(status, (int, type(None))) for _h, _s, status in scout.results
    )


def test_output_file_with_check_gets_uncolored_live_then_dead_lines_and_stdout_is_empty(
    world, tmp_path
):
    world.api(names_body(*LIVE_NAMES))
    world.probes(LIVE_ROUTES)
    target = tmp_path / "live.txt"
    run = world.run("allowed.example", "-c", "-q", "--show-dead", "-o", str(target))
    assert run.code == 0 and run.out == ""
    data = target.read_bytes().decode("utf-8")
    assert "\x1b" not in data
    assert data.splitlines() == LIVE_EXPECTED + ["[DEAD] dev.allowed.example"]
    assert str(target) in run.err
    assert re.search(r"live hosts:\s*4\b", run.plain_err.lower())
    assert "  https://www.allowed.example (200)" in run.plain_err.splitlines()
    assert "  http://admin.allowed.example (200)" in run.plain_err.splitlines()


def test_output_file_excludes_dead_hosts_without_show_dead(world, tmp_path):
    world.api(names_body("www.allowed.example", "dev.allowed.example"))
    world.probes({"https://www.allowed.example": (200, {})})
    target = tmp_path / "live.txt"
    world.run("allowed.example", "-c", "-q", "-o", str(target))
    assert read_lines(target) == [live_line("https://www.allowed.example", 200)]


def test_output_file_is_created_empty_when_nothing_is_live(world, tmp_path):
    world.api(names_body("www.allowed.example"))
    world.probes({})
    target = tmp_path / "live.txt"
    run = world.run("allowed.example", "-c", "-q", "-o", str(target))
    assert run.code == 0 and run.out == ""
    assert target.read_bytes() == b""
    assert re.search(r"live hosts:\s*0\b", run.plain_err.lower())


def test_output_summary_lists_twenty_live_urls_then_how_many_more(world, tmp_path):
    hosts = [f"h{number:02d}.allowed.example" for number in range(1, 23)]
    world.api(names_body(*hosts))
    world.probes(
        {f"https://{host}": (200 + index, {}) for index, host in enumerate(hosts)}
    )
    target = tmp_path / "live.txt"
    run = world.run("allowed.example", "-c", "-q", "-o", str(target))
    listed = [
        line for line in run.plain_err.splitlines() if line.startswith("  https://")
    ]
    assert listed == [
        f"  https://{host} ({200 + index})" for index, host in enumerate(hosts[:20])
    ]
    assert "  ... and 2 more" in run.plain_err.splitlines()
    assert len(read_lines(target)) == 22
    assert re.search(r"live hosts:\s*22\b", run.plain_err.lower())


def test_output_file_write_failure_is_an_error_notice_not_a_crash(world, tmp_path):
    world.api(names_body("www.allowed.example"))
    world.probes({"https://www.allowed.example": (200, {})})
    run = world.run("allowed.example", "-c", "-q", "-o", str(tmp_path))
    assert run.code == 1 and run.out == ""
    assert run.err.strip()


def test_output_file_is_utf8_regardless_of_the_default_locale(tmp_path, world):
    world.workspace()
    driver = tmp_path / "driver.py"
    driver.write_text(
        textwrap.dedent("""
        import asyncio, sys
        from pathlib import Path
        import httpx
        sys.path.insert(0, sys.argv[1])
        from bughunt.console import loader
        from bughunt.core.http import api_client
        ct = loader.import_script(Path(sys.argv[2]))
        body = b"www.allowed.example\\n"
        ct.CrtScout._api = lambda self: api_client(ct.API_HOSTS, timeout=1, transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=body, request=request)))
        ct.CrtScout._probe_client = lambda self: httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, request=request)))
        sys.argv = ["bughunt ct", *sys.argv[3:]]
        asyncio.run(ct.main())
    """),
        encoding="utf-8",
    )
    target = tmp_path / "live.txt"
    env = {key: value for key, value in os.environ.items() if key != "PYTHONPATH"}
    env.update(
        BUGHUNT_SCOPE=str(world.scope_dir),
        PYTHONUTF8="0",
        PYTHONIOENCODING="utf-8",
        LC_ALL="C",
        PYTHONCOERCECLOCALE="0",
    )
    done = subprocess.run(
        [
            sys.executable,
            "-X",
            "utf8=0",
            str(driver),
            str(REPO),
            str(SCRIPT),
            "allowed.example",
            "-c",
            "-q",
            "-o",
            str(target),
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
    assert target.read_bytes().decode("utf-8").splitlines() == [
        live_line("https://www.allowed.example", 200)
    ]


def test_output_file_uses_platform_line_endings(world, tmp_path):
    world.api(names_body("www.allowed.example", "api.allowed.example"))
    world.probes(
        {
            "https://www.allowed.example": (200, {}),
            "https://api.allowed.example": (200, {}),
        }
    )
    target = tmp_path / "live.txt"
    world.run("allowed.example", "-c", "-q", "-o", str(target))
    assert len(target.read_text(encoding="utf-8").splitlines()) == 2
    assert target.read_bytes().endswith(os.linesep.encode())


def test_progress_counter_is_rewritten_on_stderr_and_quiet_suppresses_only_it(world):
    names = ("www.allowed.example", "api.allowed.example", "app.allowed.example")
    world.api(names_body(*names))
    world.probes(
        {f"https://{name}": (200 + index, {}) for index, name in enumerate(names)}
    )
    loud = world.run("allowed.example", "-c")
    ordered = [loud.err.index(f"{count}/3") for count in (1, 2, 3)]
    assert ordered == sorted(ordered)
    assert "\r" in loud.err
    assert re.search(r"3/3\n", loud.err)

    quiet = world.run("allowed.example", "-c", "-q")
    assert "\r" not in quiet.err
    assert not re.search(r"\d/3", quiet.err)
    assert re.search(r"found\s+3\b", quiet.plain_err.lower())
    assert re.search(r"(?<!\d)5(?!\d)", quiet.plain_err) and re.search(
        r"(?<!\d)50(?!\d)", quiet.plain_err
    )


def test_check_notice_reports_name_count_timeout_and_workers(world):
    world.api(names_body("www.allowed.example", "api.allowed.example"))
    world.probes({})
    run = world.run("allowed.example", "-c", "-q", "--timeout", "7", "--workers", "9")
    notice = next(
        line for line in run.plain_err.splitlines() if "7" in line and "9" in line
    )
    assert re.search(r"\b2\b", notice)


# ---------------------------------------------------------------------------------------------
# F. Probes: schemes, redirects, scope and policy on every request (4.4, 5.1)
# ---------------------------------------------------------------------------------------------


def test_probe_urls_are_exactly_scheme_host_with_https_first_and_first_answer_wins(
    world,
):
    world.api(names_body("www.allowed.example"))
    world.probes(
        {
            "https://www.allowed.example": (503, {}),
            "http://www.allowed.example": (200, {}),
        }
    )
    run = world.run("allowed.example", "-c", "-q")
    assert world.probe_urls == ["https://www.allowed.example"]
    assert run.plain_out == live_line("https://www.allowed.example", 503) + "\n"


@pytest.mark.parametrize("status", [200, 204, 404, 418, 500, 503])
def test_any_http_status_counts_as_live(world, status):
    world.api(names_body("www.allowed.example"))
    world.probes({"https://www.allowed.example": (status, {})})
    run = world.run("allowed.example", "-c", "-q", "--https-only")
    assert run.plain_out == live_line("https://www.allowed.example", status) + "\n"


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ConnectError("refused"),
        httpx.ConnectTimeout("slow"),
        httpx.ReadTimeout("slow"),
        httpx.RemoteProtocolError("bad"),
        None,
    ],
)
def test_http_is_tried_after_https_fails_and_reported_with_its_scheme(world, failure):
    world.api(names_body("www.allowed.example"))
    routes = {"http://www.allowed.example": (200, {})}
    if failure is not None:
        routes["https://www.allowed.example"] = failure
    world.probes(routes)
    run = world.run("allowed.example", "-c", "-q")
    assert world.probe_urls == [
        "https://www.allowed.example",
        "http://www.allowed.example",
    ]
    assert run.plain_out == live_line("http://www.allowed.example", 200) + "\n"


def test_https_only_never_requests_http(world):
    world.api(names_body("www.allowed.example"))
    world.probes({"http://www.allowed.example": (200, {})})
    run = world.run("allowed.example", "-c", "-q", "--https-only", "--show-dead")
    assert world.probe_urls == ["https://www.allowed.example"]
    assert run.plain_out == "[DEAD] www.allowed.example\n"


def test_a_host_that_answers_on_neither_scheme_is_dead_after_both_attempts(world):
    world.api(names_body("www.allowed.example"))
    world.probes({})
    scout = world.scout("-c")
    asyncio.run(scout.run())
    assert world.probe_urls == [
        "https://www.allowed.example",
        "http://www.allowed.example",
    ]
    assert scout.results == [("www.allowed.example", "dead", None)]


def test_relative_location_is_resolved_against_the_current_url(world):
    world.api(names_body("cdn.allowed.example"))
    world.probes(
        {
            "https://cdn.allowed.example": (301, {"location": "/rel"}),
            "https://cdn.allowed.example/rel": (204, {}),
        }
    )
    run = world.run("allowed.example", "-c", "-q", "--https-only")
    assert world.probe_urls == [
        "https://cdn.allowed.example",
        "https://cdn.allowed.example/rel",
    ]
    assert run.plain_out == live_line("https://cdn.allowed.example", 204) + "\n"


def test_in_scope_redirect_across_granted_hosts_reports_the_final_status(world):
    world.api(names_body("www.allowed.example"))
    world.probes(
        {
            "https://www.allowed.example": (
                302,
                {"location": "https://cdn.allowed.example/landing"},
            ),
            "https://cdn.allowed.example/landing": (200, {}),
        }
    )
    run = world.run("allowed.example", "-c", "-q", "--https-only")
    assert run.plain_out == live_line("https://www.allowed.example", 200) + "\n"


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/x",
        "http://evil.example/",
        "//evil.example/x",
        "https://notallowed.example/",
        "https://allowed.example.evil.example/",
        "https://169.254.169.254/latest",
    ],
)
def test_out_of_scope_redirect_hops_are_never_requested(world, location):
    world.api(names_body("www.allowed.example"))
    world.probes({"https://www.allowed.example": (302, {"location": location})})
    run = world.run("allowed.example", "-c", "-q", "--https-only")
    assert world.probe_urls == ["https://www.allowed.example"]
    assert run.plain_out == live_line("https://www.allowed.example", 302) + "\n"


def test_in_scope_redirect_loop_stops_after_eleven_requests_and_reports_the_redirect_status(
    world,
):
    world.api(names_body("www.allowed.example"))
    world.probes(
        {
            "https://www.allowed.example": (301, {"location": "/a"}),
            "https://www.allowed.example/a": (301, {"location": "/"}),
            "https://www.allowed.example/": (301, {"location": "/a"}),
        }
    )
    run = world.run("allowed.example", "-c", "-q", "--https-only")
    assert len(world.probe_requests) == 11
    assert run.plain_out == live_line("https://www.allowed.example", 301) + "\n"


def test_in_scope_host_without_a_policy_grant_is_never_requested(world):
    world.api(names_body("mail.allowed.example", "www.allowed.example"))
    world.probes(
        {
            "https://www.allowed.example": (200, {}),
            "https://mail.allowed.example": (200, {}),
            "http://mail.allowed.example": (200, {}),
        }
    )
    run = world.run("allowed.example", "-c", "-q")
    assert world.probe_urls == ["https://www.allowed.example"]
    assert run.plain_out == live_line("https://www.allowed.example", 200) + "\n"


def test_in_scope_host_without_a_policy_grant_is_not_reported_dead(world):
    world.api(names_body("mail.allowed.example", "www.allowed.example"))
    world.probes({"https://www.allowed.example": (200, {})})
    scout = world.scout("-c", "--show-dead")
    asyncio.run(scout.run())
    assert ("mail.allowed.example", "dead", None) not in scout.results
    assert ("mail.allowed.example", "blocked", None) in scout.results
    output = plain(world.capsys.readouterr().out)
    assert "[DEAD] mail.allowed.example" not in output
    assert "[BLOCKED] mail.allowed.example" in output


@pytest.mark.parametrize("redirected", [False, True])
def test_policy_denial_never_falls_back_to_http_and_exports_blocked(
    world, tmp_path, redirected
):
    if not redirected:
        world.workspace(restrict={"https://www.allowed.example": ["passive"]})
    world.api(names_body("www.allowed.example"))
    world.probes(
        {
            "https://www.allowed.example": (
                302,
                {"location": "https://mail.allowed.example/"},
            ),
            "http://www.allowed.example": (200, {}),
        }
    )
    destination = tmp_path / "blocked.txt"
    world.run("allowed.example", "-c", "-q", "--show-dead", "-o", str(destination))
    assert world.probe_urls == (["https://www.allowed.example"] if redirected else [])
    assert destination.read_text(encoding="utf-8") == "[BLOCKED] www.allowed.example\n"


def test_redirect_into_an_ungranted_in_scope_host_never_requests_that_hop(world):
    world.api(names_body("allowed.example"))
    world.probes(
        {
            "https://allowed.example": (
                302,
                {"location": "https://cdn.allowed.example/hop2"},
            ),
            "https://cdn.allowed.example/hop2": (
                302,
                {"location": "https://mail.allowed.example/hop3"},
            ),
            "https://mail.allowed.example/hop3": (200, {}),
        }
    )
    world.run("allowed.example", "-c", "-q", "--https-only")
    assert world.probe_urls == [
        "https://allowed.example",
        "https://cdn.allowed.example/hop2",
    ]


def test_probe_needs_the_crawl_operation_not_just_a_grant(world):
    world.workspace(
        restrict={
            "https://www.allowed.example": ["passive"],
            "http://www.allowed.example": ["passive"],
        }
    )
    world.api(names_body("www.allowed.example", "api.allowed.example"))
    world.probes(
        {
            "https://www.allowed.example": (200, {}),
            "https://api.allowed.example": (200, {}),
        }
    )
    run = world.run("allowed.example", "-c", "-q", "--https-only")
    assert world.probe_urls == ["https://api.allowed.example"]
    assert run.plain_out == live_line("https://api.allowed.example", 200) + "\n"


def test_probe_stage_rechecks_scope_for_every_host_without_a_request(world):
    world.probes(
        {"https://outside.example": (200, {}), "https://www.allowed.example": (200, {})}
    )
    scout = world.scout("-c")
    scout.subdomains = {"outside.example", "www.allowed.example"}
    asyncio.run(scout.check_all_hosts())
    assert world.probe_urls == ["https://www.allowed.example"]
    assert sorted(scout.results) == [
        ("outside.example", "blocked", None),
        ("www.allowed.example", "https", 200),
    ]


@pytest.mark.parametrize("workers", [1, 2, 3, 50])
def test_workers_caps_concurrent_probes(world, workers):
    names = [
        f"{label}.allowed.example"
        for label in ("www", "api", "app", "dev", "admin", "cdn")
    ]
    world.api(names_body(*names))
    state = {"active": 0, "peak": 0}

    async def slow(request):
        state["active"] += 1
        state["peak"] = max(state["peak"], state["active"])
        await asyncio.sleep(0.03)
        state["active"] -= 1
        return httpx.Response(200, request=request)

    world.probes(handler=slow)
    run = world.run(
        "allowed.example", "-c", "-q", "--https-only", "--workers", str(workers)
    )
    assert run.code == 0 and len(plain(run.out).splitlines()) == 6
    assert state["peak"] == min(workers, 6)


@pytest.mark.parametrize("workers", ["0", "-1"])
def test_non_positive_workers_neither_hangs_nor_crashes(world, workers):
    world.api(names_body("www.allowed.example"))
    world.probes({"https://www.allowed.example": (200, {})})
    world.mp.setattr(
        sys, "argv", ["bughunt ct", "allowed.example", "-c", "-q", "--workers", workers]
    )

    async def bounded():
        await asyncio.wait_for(world.ct.main(), timeout=2)

    try:
        asyncio.run(bounded())
    except SystemExit as exc:
        assert exc.code == 2
    except asyncio.TimeoutError:
        pytest.fail("--workers %s hung" % workers)
    except ValueError as exc:
        pytest.fail("--workers %s raised ValueError: %s" % (workers, exc))


# ---------------------------------------------------------------------------------------------
# G. The loader path (`bughunt ct`, alias `crt-scout`)
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
    """`bughunt ct` through loader.run_named, with the loader's own console captured."""
    monkeypatch.setenv("BUGHUNT_ADDONS", str(addons_root))
    console_text = io.StringIO()
    monkeypatch.setattr(
        ui,
        "console",
        Console(theme=ui.THEME, highlight=False, file=console_text, width=200),
    )

    def call(name: str, *argv: str):
        code = run_named(name, *argv)
        out, err = world.capsys.readouterr()
        return Run(code, out, err), console_text.getvalue()

    return call


@pytest.mark.parametrize("name", ["ct", "crt-scout"])
def test_loader_resolves_ct_and_its_alias_to_the_same_program(world, via_loader, name):
    world.api(names_body("www.allowed.example"))
    run, _console = via_loader(name, "outside.example")
    assert run.code == 2 and run.out == ""
    assert run.err.strip() == workspace.explain_block("outside.example").strip()
    assert world.api_requests == []


def test_loader_full_run_returns_0_and_prints_the_names(world, via_loader):
    world.api(names_body("www.allowed.example", "api.allowed.example"))
    run, _console = via_loader("ct", "allowed.example")
    assert run.code == 0
    assert run.plain_out.splitlines() == ["api.allowed.example", "www.allowed.example"]
    assert world.api_urls == [API_URL]


def test_loader_check_run_prints_live_lines(world, via_loader):
    world.api(names_body("www.allowed.example"))
    world.probes({"https://www.allowed.example": (200, {})})
    run, _console = via_loader("ct", "allowed.example", "-c", "-q")
    assert run.code == 0
    assert run.plain_out == live_line("https://www.allowed.example", 200) + "\n"


def test_loader_gives_the_program_its_bughunt_ct_name_for_usage(world, via_loader):
    run, _console = via_loader("ct", "-h")
    assert run.code == 0
    assert run.out.startswith("usage: bughunt ct")


@pytest.mark.parametrize(
    "argv,code",
    [(["not_a_domain"], 1), (["allowed.example", "--timeout", "x"], 2), ([], 2)],
)
def test_loader_maps_exit_codes_through_system_exit(world, via_loader, argv, code):
    run, _console = via_loader("ct", *argv)
    assert run.code == code and run.out == ""


def test_loader_maps_a_preflight_policy_block_to_return_code_2_with_the_reason(
    world, via_loader
):
    world.workspace(scope=("allowed.example", "noasset.example"))
    world.api(names_body("www.noasset.example"))
    run, console = via_loader("ct", "noasset.example")
    assert run.code == 2 and run.out == ""
    assert "exact origin/root grant required" in console
    assert world.api_requests == []


def test_loader_reraises_keyboard_interrupt(world, via_loader, ct, monkeypatch):
    async def interrupted(scout):
        raise KeyboardInterrupt

    monkeypatch.setattr(ct.CrtScout, "run", interrupted)
    with pytest.raises(KeyboardInterrupt):
        via_loader("ct", "allowed.example")
