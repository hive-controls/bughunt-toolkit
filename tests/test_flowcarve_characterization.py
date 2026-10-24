"""Characterization oracle for addons/flowcarve (command `carve`), written BEFORE the clean-room rebuild.

Scope: everything `tests/test_addons.py` leaves unpinned for the `carve` addon (that file only asserts the
module is not in DISABLED_REFERENCES): argument surface, input sniffing and loading (HAR, raw HTTP, plain
text/HTML/JS/JSON, stdin, native `.mitm` dumps), the fixed link-extraction pass order, link normalization and
classification, filters, the txt/json/csv save files, the stdout list, exit codes and the `bughunt carve`
loader path.

Posture: flowcarve is an OFFLINE parser. No network is reached and none is mocked; an autouse tripwire turns
any in-process DNS/connect attempt into a failure. Nothing here needs a workspace, scope or policy fixture.

Labels (the spec in section 9 sets the default per defect):
  * every test whose name starts with `test_dN_pinned_` records a defect-adjacent behavior the spec says to
    PRESERVE (D4 for HAR integer statuses, D5, D7, D8, D9, D10, D11, D18). It must stay green on the rebuild.
  * every test whose name starts with `test_dN_` WITHOUT `pinned` asserts the CORRECT behavior for a defect the
    spec recommends to deviate on (D1, D2, D3, D4, D6, D12). It is marked xfail(strict=True) against the
    current program. An unexpected pass fails the suite until the fix is reviewed and its marker removed.
  * D16 (addon-root lookup, pyproject entry point) is already fixed on this post-M0 base, so those tests are
    ordinary VERIFY-the-fix tests, not xfails.
  * everything else pins current behavior the rebuild must reproduce (tiers [T]/[C]/[K] of the spec).

Point the suite at another copy of the script (a mutant for a mutation proof, or the rebuilt file in a scratch
location) with `BUGHUNT_FC_UNDER_TEST=<path to flowcarve.py>`; the default is the repo's addon.

Evidence limits (stated, not hidden): the native `.mitm` reader path needs mitmproxy, which is not installed in
the verification environment. The tests marked GATED call `pytest.importorskip("mitmproxy")` and generate their
flow file at test time with mitmproxy's own writer; they were WRITTEN against the documented mitmproxy API but
NEVER EXECUTED here (UNVERIFIED). Table-membership sweeps of the upstream data tables are deliberately absent
(spec section 10 decision): only table members the spec names appear in the vectors.

Seam names (keep_link, classify_link, extract_from_text, ...) are the spec's section 2.1 names. A rebuild that
renames them must either keep these names or the orchestrator edits the seam layer; the black-box CLI layer
(`bench.run` / `bench.cli`) does not depend on any internal name.
"""

from __future__ import annotations

import ast
import base64
import csv
import importlib.util
import inspect
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest
from rich.console import Console

from bughunt.console import catalog, loader, ui
from bughunt.console.catalog_export import export_catalog
from bughunt.core import scanner
from flowcarve_vectors import (
    CLASSIFY_VECTORS,
    EXTRACT_VECTORS,
    HEADER_VECTORS,
    KEEP_VECTORS,
    MIME_VECTORS,
    RESOLVE_VECTORS,
    SNIFF_VECTORS,
)

REPO = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT = REPO / "addons" / "flowcarve" / "flowcarve.py"
SCRIPT = Path(os.environ.get("BUGHUNT_FC_UNDER_TEST") or DEFAULT_SCRIPT).resolve()

TRUSTS = ("url", "quoted", "attribute", "lax")
KINDS = (
    "https",
    "http",
    "wss",
    "ws",
    "protocol-relative",
    "absolute-path",
    "relative-path",
    "js-endpoint",
    "mailto",
)
ROW_KEYS = [
    "link",
    "resolved",
    "kind",
    "origin",
    "flow_url",
    "status",
    "content_type",
    "source",
]
RECORD_KEYS = {"source", "url", "status", "content_type", "links"}
MIDDLE_DOT = chr(0xB7)  # separates flow url and status in --verbose rows
E_ACUTE = chr(0xE9)
ANSI = re.compile(r"\x1b\[[0-9;]*m")
SEGMENT = re.compile(r"((?:\x1b\[[0-9;]*m)+)([^\x1b]*)\x1b\[0m")


def defect(code: str, reason: str):
    """xfail-correct marker: the test asserts the CORRECT behavior for a known defect of the current program."""
    return pytest.mark.xfail(reason=f"{code}: {reason}", strict=True)


def plain(text: str) -> str:
    return ANSI.sub("", text)


def sgr_segments(text: str) -> list[tuple[frozenset, str]]:
    """(SGR code set, visible text) for every colored span in `text`."""
    found = []
    for match in SEGMENT.finditer(text):
        sequences = re.findall(r"\x1b\[([0-9;]*)m", match.group(1))
        codes = frozenset(
            int(code) for sequence in sequences for code in sequence.split(";") if code
        )
        found.append((codes, match.group(2)))
    return found


@dataclass
class Run:
    code: int
    out: str
    err: str

    @property
    def lines(self) -> list[str]:
        return self.out.splitlines()


def row_line(kind: str, origin: str, display: str, extra: str = "") -> str:
    line = f"  {kind:<18} {origin:<14} {display}"
    return f"{line}  :: {extra}" if extra else line


# ---------------------------------------------------------------------------------------------
# Fixtures and harness
# ---------------------------------------------------------------------------------------------

PAGE_HTML = """<!doctype html><html><head>
<link rel="stylesheet" href="/static/app.css"><script src="//cdn.example.com/lib.js"></script>
<meta http-equiv="refresh" content="0;url=https://example.com/next">
<style>@import "theme.css"; .a{background:url(img/bg.png)}</style></head>
<body><a href="page2.html">p2</a><a href="?tab=2">t</a><a href="mailto:ops@example.com">m</a>
<a href="javascript:void(0)">x</a><img srcset="a.png 1x, b.png 2x"><div data-url="/api/v1/data" data-foo="bar"></div>
<script>var u = "/api/v2/users"; fetch('/api/v1/items?x=1'); var re = /foo\\/bar/g; var abs = "https:\\/\\/api.example.com\\/v3\\/x";
// see http://intranet/status and https://www.w3.org/2000/svg
</script></body></html>"""

# (kind, origin, link) in output order for PAGE_HTML
PAGE_ROWS = [
    ("absolute-path", "html", "/static/app.css"),
    ("protocol-relative", "html", "//cdn.example.com/lib.js"),
    ("https", "html", "https://example.com/next"),
    ("relative-path", "html", "page2.html"),
    ("relative-path", "html", "?tab=2"),
    ("mailto", "html", "mailto:ops@example.com"),
    ("relative-path", "html", "a.png"),
    ("relative-path", "html", "b.png"),
    ("absolute-path", "html", "/api/v1/data"),
    ("relative-path", "css", "img/bg.png"),
    ("relative-path", "css", "theme.css"),
    ("http", "regex", "http://intranet/status"),
    ("absolute-path", "regex", "/api/v1/items?x=1"),
    ("absolute-path", "regex", "/api/v2/users"),
    ("https", "regex", "https://api.example.com/v3/x"),
]

RAW_HTTP = (
    "HTTP/1.1 302 Found\r\nLocation: /login?next=%2Fhome\r\n"
    "Link: </css/a.css>; rel=preload, <https://cdn.example.com/f.woff2>; rel=preload\r\n"
    "Refresh: 5; url=/wait\r\nContent-Type: text/html\r\nX-Request-URL: https://app.example.com/start\r\n\r\n"
    '<a href="/body/link">b</a>'
)
RAW_ROWS = [
    ("absolute-path", "header", "/login?next=%2Fhome"),
    ("absolute-path", "header", "/css/a.css"),
    ("https", "header", "https://cdn.example.com/f.woff2"),
    ("absolute-path", "header", "/wait"),
    ("absolute-path", "html", "/body/link"),
]

PLAIN_TEXT = (
    'Hello see https://example.com/a and "/api/plain/x" but not /api/unquoted/path'
)


def har_entry(url, *, status=200, mime="text/html", body="", headers=(), encoding=None):
    content = {"text": body}
    if mime is not None:
        content["mimeType"] = mime
    if encoding:
        content["encoding"] = encoding
    return {
        "request": {"url": url},
        "response": {
            "status": status,
            "headers": [{"name": n, "value": v} for n, v in headers],
            "content": content,
        },
    }


def har_doc(*entries) -> str:
    return json.dumps({"log": {"entries": list(entries)}})


CAPTURE_HAR = har_doc(
    har_entry(
        "https://app.example.com/index.html",
        headers=[("Content-Type", "text/html"), ("Location", "/loc")],
        body='<a href="/har/link">x</a> "/api/har/q"',
    ),
    har_entry(
        "https://app.example.com/img.png",
        mime="image/png",
        body='"/api/should/not/appear"',
    ),
    har_entry(
        "https://app.example.com/b64.js",
        mime="application/javascript",
        encoding="base64",
        body=base64.b64encode(b'var a = "/api/b64/path";').decode(),
    ),
    "not-a-dict",
)

# Three flows with relative links, mixed-case hosts, a look-alike domain and duplicates (resolved vs raw).
FILTER_HAR = har_doc(
    har_entry(
        "https://App.Example.com/d/p",
        headers=[("Location", "/Z/y")],
        body='<a href="/B/x">b</a><a href="mailto:o@example.com">m</a><a href="a/c%2Fd">r</a> '
        '"//cdn.Example.com/a" "https://notexample.com/z" "www.foo.com/q" "/B/x"',
    ),
    har_entry(
        "https://other.org/page",
        body='<a href="/other/path">o</a> "https://App.Example.com/d/a/c/d"',
    ),
    har_entry(
        "https://App.Example.com/d/q",
        body='<a href="/B/x">b</a><a href="https://App.Example.com/B/x">abs</a>',
    ),
)
# (kind, origin, link) of every row of FILTER_HAR with --include-requests, in output order (indexes used below)
FILTER_ROWS = [
    ("https", "request", "https://App.Example.com/d/p"),  # 0
    ("absolute-path", "header", "/Z/y"),  # 1
    ("absolute-path", "html", "/B/x"),  # 2
    ("mailto", "html", "mailto:o@example.com"),  # 3
    ("relative-path", "html+decoded", "a/c/d"),  # 4
    ("https", "regex", "https://notexample.com/z"),  # 5
    ("protocol-relative", "regex", "//cdn.Example.com/a"),  # 6
    ("https", "regex", "www.foo.com/q"),  # 7
    ("https", "request", "https://other.org/page"),  # 8
    ("absolute-path", "html", "/other/path"),  # 9
    ("https", "regex", "https://App.Example.com/d/a/c/d"),  # 10
    ("https", "request", "https://App.Example.com/d/q"),  # 11
    ("absolute-path", "html", "/B/x"),  # 12
    ("https", "html", "https://App.Example.com/B/x"),  # 13
]


@pytest.fixture(scope="session")
def fc():
    """The program under test, loaded by file path under its own module name."""
    spec = importlib.util.spec_from_file_location("flowcarve_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    yield module
    sys.modules.pop(spec.name, None)


@pytest.fixture(autouse=True)
def no_real_network(monkeypatch):
    """Tripwire: flowcarve is offline; nothing in this module may resolve a name or open a socket."""

    def forbidden(*args, **kwargs):
        raise AssertionError("network reached from a flowcarve characterization test")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


class Bench:
    """A scratch working directory plus in-process (`run`) and subprocess (`cli`) entry points."""

    def __init__(self, fc, capsys, root: Path):
        self.fc, self.capsys, self.root = fc, capsys, root

    def put(self, name: str, data) -> str:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return name

    def read(self, name: str) -> bytes:
        return (self.root / name).read_bytes()

    def run(self, *argv: str) -> Run:
        """`main(argv)` in-process; argparse's SystemExit becomes the exit code."""
        self.capsys.readouterr()
        try:
            code = self.fc.main(list(argv))
        except SystemExit as exc:
            code = (
                exc.code
                if isinstance(exc.code, int)
                else (0 if exc.code is None else 1)
            )
        out, err = self.capsys.readouterr()
        return Run(code, out, err)

    def rows(self, *argv: str, code: int = 0) -> list[dict]:
        """Run quietly with `-o _rows.json` and return the saved row objects."""
        result = self.run(*argv, "-q", "-o", "_rows.json")
        assert result.code == code, result
        return json.loads(self.read("_rows.json").decode("utf-8"))

    def cli(
        self,
        *argv: str,
        stdin: bytes | None = None,
        env: dict | None = None,
        utf8: bool = True,
        encoding: str = "utf-8",
    ) -> Run:
        """The script as a real child process (stdin, exit status, uncaught tracebacks, encodings)."""
        child_env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("NO_COLOR", "PYTHONUTF8", "PYTHONIOENCODING")
        }
        child_env["PYTHONDONTWRITEBYTECODE"] = "1"
        child_env.update(env or {})
        flags = ["-X", "utf8=1"] if utf8 else ["-X", "utf8=0"]
        done = subprocess.run(
            [sys.executable, *flags, str(SCRIPT), *argv],
            input=stdin if stdin is not None else b"",
            capture_output=True,
            cwd=self.root,
            env=child_env,
            timeout=120,
        )
        # text-mode newline translation on Windows is D3 (tested apart); everything else compares on LF
        out = done.stdout.decode(encoding, "replace").replace(
            chr(13) + chr(10), chr(10)
        )
        err = done.stderr.decode(encoding, "replace").replace(
            chr(13) + chr(10), chr(10)
        )
        return Run(done.returncode, out, err)


@pytest.fixture
def bench(fc, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NO_COLOR", raising=False)
    return Bench(fc, capsys, tmp_path)


def triples(found) -> list[tuple]:
    return [tuple(item) for item in found]


def kinds_origins(rows: list[dict]) -> list[tuple]:
    return [(row["kind"], row["origin"], row["link"]) for row in rows]


# =============================================================================================
# A. Module and argument surface (spec 2.1, 3)
# =============================================================================================

# (dest, option strings as a set, default); order is the console form order
EXPECTED_ACTIONS = [
    ("inputs", set(), None),
    ("save", {"-o", "--save", "--output"}, None),
    ("format", {"--format"}, None),
    ("include_requests", {"--include-requests"}, False),
    ("unique", {"--unique"}, False),
    ("sort", {"--sort"}, False),
    ("group", {"--group"}, False),
    ("resolve", {"--resolve"}, False),
    ("verbose", {"-v", "--verbose"}, False),
    ("kind", {"--kind"}, None),
    ("origin", {"--origin"}, None),
    ("contains", {"--contains"}, None),
    ("regex", {"--regex"}, None),
    ("domain", {"--domain"}, None),
    ("color", {"--color"}, "auto"),
    ("quiet", {"-q", "--quiet"}, False),
]


def test_build_parser_needs_no_arguments_and_returns_an_argparse_parser(fc):
    import argparse

    assert isinstance(fc.build_parser(), argparse.ArgumentParser)


def test_parser_dests_flags_defaults_and_order(fc):
    actions = [a for a in fc.build_parser()._actions if a.dest != "help"]
    assert [a.dest for a in actions] == [
        name for name, _flags, _default in EXPECTED_ACTIONS
    ]
    for action, (name, flags, default) in zip(actions, EXPECTED_ACTIONS):
        assert (set(action.option_strings), action.default) == (flags, default), name


def test_parser_help_action_and_input_cardinality(fc):
    parser = fc.build_parser()
    help_action = next(a for a in parser._actions if a.dest == "help")
    assert set(help_action.option_strings) == {"-h", "--help"}
    inputs = next(a for a in parser._actions if a.dest == "inputs")
    assert inputs.nargs == "+" and inputs.option_strings == []
    assert len([a for a in parser._actions]) == 17


def test_parser_choices_and_types(fc):
    actions = {a.dest: a for a in fc.build_parser()._actions}
    assert tuple(actions["format"].choices) == ("txt", "json", "csv")
    assert tuple(actions["color"].choices) == ("auto", "always", "never")
    for name in (
        "include_requests",
        "unique",
        "sort",
        "group",
        "resolve",
        "verbose",
        "quiet",
    ):
        assert actions[name].nargs == 0, name
    assert all(
        actions[name].type is None
        for name in ("kind", "origin", "contains", "regex", "domain", "save")
    )


def test_parse_args_accepts_every_alias_and_combined_short_switches(fc):
    for flag in ("-o", "--save", "--output"):
        assert fc.parse_args(["a", "b", flag, "out.json"]).save == "out.json"
    args = fc.parse_args(["a", "b", "-vq"])
    assert (args.inputs, args.verbose, args.quiet) == (["a", "b"], True, True)
    assert fc.parse_args(["-", "--color", "never"]).color == "never"


def test_main_is_synchronous_and_returns_an_int(bench):
    assert not inspect.iscoroutinefunction(bench.fc.main)
    bench.put("plain.txt", PLAIN_TEXT)
    outcome = bench.fc.main(["plain.txt", "-q"])
    assert outcome == 0 and type(outcome) is int


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--format", "xml", "x"],
        ["x", "--color", "bad"],
        ["x", "--save"],
        ["x", "--kind"],
        ["x", "--version"],
    ],
)
def test_argparse_errors_exit_2_without_touching_stdout(bench, argv):
    result = bench.run(*argv)
    assert result.code == 2 and result.out == ""
    assert result.err.strip() != ""


def test_help_exits_0_and_states_that_mitm_needs_mitmproxy(bench):
    result = bench.run("-h")
    assert result.code == 0
    assert "pip install mitmproxy" in result.out


def test_empty_string_option_values_are_ignored_not_rejected(bench):
    bench.put("page.html", PAGE_HTML)
    everything = bench.rows("page.html")
    assert (
        bench.rows(
            "page.html", "--kind", "", "--origin", "", "--contains", "", "--domain", ""
        )
        == everything
    )


# =============================================================================================
# B. Catalog, discovery and the loader contract (spec 2.3, D16)
# =============================================================================================


@pytest.fixture(scope="session")
def addons_root(tmp_path_factory):
    """An addons dir holding a copy of the script under test, for BUGHUNT_ADDONS."""
    root = tmp_path_factory.mktemp("addons")
    (root / "flowcarve").mkdir()
    shutil.copyfile(SCRIPT, root / "flowcarve" / "flowcarve.py")
    return root


def test_catalog_registers_carve_with_the_flowcarve_alias_in_capture():
    tool = catalog.tool_by_command("carve")
    assert (tool.command, tool.folder, tool.script, tool.aliases) == (
        "carve",
        "flowcarve",
        "flowcarve.py",
        ("flowcarve",),
    )
    assert (
        tool.summary
        == "Pull URLs and endpoints out of proxy dumps, HAR files and saved pages."
    )
    assert (
        catalog.reference_canonical("flowcarve") == "carve"
        and catalog.reference_canonical("carve") == "carve"
    )
    assert "carve" not in catalog.DISABLED_REFERENCES
    assert "carve" in dict(catalog.MODULE_GROUPS)["Capture"]


def test_catalog_form_lists_the_parser_options_in_console_order(
    addons_root, monkeypatch
):
    monkeypatch.setenv("BUGHUNT_ADDONS", str(addons_root))
    data = export_catalog(
        tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    entry = next(
        m for p in data["phases"] for m in p["modules"] if m["name"] == "carve"
    )
    assert (
        entry["disabled"] is False
        and entry["aliases"] == ["flowcarve"]
        and entry["reference"] is True
    )
    options = [
        (o["name"], o["kind"], o["required"], o["default"], o["choices"])
        for o in entry["form"]["options"]
    ]
    assert options == [
        ("INPUTS", "positional", True, "", []),
        ("SAVE", "value", False, "", []),
        ("FORMAT", "value", False, "", ["txt", "json", "csv"]),
        ("INCLUDE_REQUESTS", "bool", False, "", []),
        ("UNIQUE", "bool", False, "", []),
        ("SORT", "bool", False, "", []),
        ("GROUP", "bool", False, "", []),
        ("RESOLVE", "bool", False, "", []),
        ("VERBOSE", "bool", False, "", []),
        ("KIND", "value", False, "", []),
        ("ORIGIN", "value", False, "", []),
        ("CONTAINS", "value", False, "", []),
        ("REGEX", "value", False, "", []),
        ("DOMAIN", "value", False, "", []),
        ("COLOR", "value", False, "auto", ["auto", "always", "never"]),
        ("QUIET", "bool", False, "", []),
    ]
    by_name = {o["name"]: set(o["flags"]) for o in entry["form"]["options"]}
    assert by_name["SAVE"] == {"-o", "--save", "--output"} and by_name["VERBOSE"] == {
        "-v",
        "--verbose",
    }


def test_d16_verified_addon_root_resolves_without_bughunt_addons(monkeypatch):
    """D16 (fixed on this base): with BUGHUNT_ADDONS unset the repo's own addons folder is found."""
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    tool = catalog.tool_by_command("carve")
    found = catalog.locate_script(tool, Path(scanner.__file__))
    assert found is not None and Path(found).resolve() == DEFAULT_SCRIPT.resolve()
    data = export_catalog(
        tool_file=Path(scanner.__file__), build_parser=scanner.build_parser
    )
    entry = next(
        m for p in data["phases"] for m in p["modules"] if m["name"] == "carve"
    )
    assert entry["form"] is not None and not entry.get("unavailable")


def test_d16_verified_pyproject_entry_point_names_a_real_function():
    tomllib = pytest.importorskip("tomllib")
    scripts = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]["scripts"]
    module_name, _, function_name = scripts["bughunt"].partition(":")
    module = importlib.import_module(module_name)
    assert callable(getattr(module, function_name))


# =============================================================================================
# C. Offline, import-light and unvendored-mitmproxy posture (spec 2.2, 5, 6)
# =============================================================================================

NETWORK_MODULES = (
    "socket",
    "ssl",
    "http",
    "urllib.request",
    "urllib3",
    "httpx",
    "requests",
    "aiohttp",
    "ftplib",
    "smtplib",
    "telnetlib",
    "subprocess",
    "socketserver",
    "xmlrpc",
    "imaplib",
    "poplib",
    "bughunt",
)


def _imported_names(tree: ast.AST) -> list[tuple[str, ast.AST]]:
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend((alias.name, node) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append((node.module, node))
    return names


def test_source_imports_nothing_that_can_reach_a_network_or_another_process():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    offenders = [
        name
        for name, _node in _imported_names(tree)
        if any(name == bad or name.startswith(bad + ".") for bad in NETWORK_MODULES)
    ]
    assert offenders == []
    called = {
        f"{n.func.value.id}.{n.func.attr}"
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and isinstance(n.func.value, ast.Name)
    }
    assert not {"os.system", "os.popen", "os.execv", "os.spawnv"} & called


def test_mitmproxy_is_only_ever_imported_lazily_inside_a_function():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    inside_functions = {
        id(inner)
        for func in ast.walk(tree)
        if isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef))
        for inner in ast.walk(func)
    }
    mitm_imports = [
        node
        for name, node in _imported_names(tree)
        if name == "mitmproxy" or name.startswith("mitmproxy.")
    ]
    assert all(id(node) in inside_functions for node in mitm_imports)


def test_importing_and_helping_work_with_mitmproxy_unimportable(bench):
    """Nothing but the stdlib at import time: bughunt/httpx/mitmproxy stay unloaded, --help works."""
    probe = (
        "import importlib.util, sys\n"
        "sys.modules['mitmproxy'] = None\n"
        "spec = importlib.util.spec_from_file_location('fc_probe', sys.argv[1])\n"
        "mod = importlib.util.module_from_spec(spec); sys.modules['fc_probe'] = mod; spec.loader.exec_module(mod)\n"
        "print(sorted(n for n in ('bughunt', 'httpx', 'requests', 'aiohttp') if n in sys.modules), callable(mod.main), callable(mod.build_parser))\n"
        "try:\n    mod.main(['-h'])\nexcept SystemExit as exc:\n    print('help-exit', exc.code)\n"
    )
    done = subprocess.run(
        [sys.executable, "-I", "-X", "utf8=1", "-c", probe, str(SCRIPT)],
        capture_output=True,
        cwd=bench.root,
        timeout=120,
    )
    lines = done.stdout.decode("utf-8", "replace").splitlines()
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    assert lines[0] == "[] True True" and lines[-1] == "help-exit 0"


def test_standalone_launch_works_from_any_directory(bench):
    bench.put("plain.txt", PLAIN_TEXT)
    result = bench.cli("plain.txt", "--quiet", "-o", "out.txt")
    assert result.code == 0
    assert bench.read("out.txt").decode("utf-8").split() == [
        "https://example.com/a",
        "/api/plain/x",
    ]


def test_mitmproxy_is_declared_only_in_the_addon_requirements_never_vendored():
    requirements = (REPO / "addons" / "flowcarve" / "requirements.txt").read_text(
        encoding="utf-8"
    )
    functional = [
        ln.strip()
        for ln in requirements.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    assert functional == ["mitmproxy>=10.0.0"]
    assert (
        "mitmproxy" not in (REPO / "pyproject.toml").read_text(encoding="utf-8").lower()
    )
    for root_requirements in REPO.glob("requirements*.txt"):
        assert (
            "mitmproxy" not in root_requirements.read_text(encoding="utf-8").lower()
        ), root_requirements.name
    pruned = {".git", ".venv", "venv", "node_modules", "__pycache__"}
    vendored = []
    for current, dirs, files in os.walk(REPO):
        dirs[:] = [
            d
            for d in dirs
            if d not in pruned and not (Path(current) / d / "pyvenv.cfg").is_file()
        ]
        vendored += [os.path.join(current, d) for d in dirs if d.lower() == "mitmproxy"]
        vendored += [
            os.path.join(current, f)
            for f in files
            if f.lower().startswith("mitmproxy") and f.endswith((".whl", ".tar.gz"))
        ]
    assert vendored == []


def test_manual_keeps_the_documented_carve_facts():
    manual = (REPO / "docs" / "manual.md").read_text(encoding="utf-8")
    assert "`bughunt carve capture.har --unique`" in manual
    assert "`flowcarve` is `carve`" in manual


# =============================================================================================
# D. Pure helpers: classification, mime, sniffing, resolving (spec 4.2, 4.5, 4.6)
# =============================================================================================


@pytest.mark.parametrize(
    "link,kind", CLASSIFY_VECTORS, ids=[ascii(v[0]) for v in CLASSIFY_VECTORS]
)
def test_classify_link_vectors(fc, link, kind):
    assert fc.classify_link(link) == kind


@pytest.mark.parametrize(
    "content_type,scan", MIME_VECTORS, ids=[ascii(v[0]) for v in MIME_VECTORS]
)
def test_scannable_mime_vectors(fc, content_type, scan):
    assert fc.scannable_mime(content_type) is scan


@pytest.mark.parametrize(
    "path,head,kind",
    SNIFF_VECTORS,
    ids=[f"{v[0]}-{ascii(v[1])[:24]}" for v in SNIFF_VECTORS],
)
def test_sniff_kind_vectors(fc, path, head, kind):
    assert fc.sniff_kind(path, head) == kind


@pytest.mark.parametrize(
    "link,base,resolved",
    RESOLVE_VECTORS,
    ids=[f"{v[0]}@{v[1]}" for v in RESOLVE_VECTORS],
)
def test_try_resolve_vectors(fc, link, base, resolved):
    assert fc.try_resolve(link, base) == resolved


@pytest.mark.parametrize(
    "path,explicit,fmt",
    [
        ("o.json", None, "json"),
        ("o.JSON", None, "json"),
        ("o.csv", None, "csv"),
        ("O.CSV", None, "csv"),
        ("o.txt", None, "txt"),
        ("o.dat", None, "txt"),
        ("o", None, "txt"),
        ("o.json", "csv", "csv"),
        ("o.csv", "txt", "txt"),
        ("o.dat", "json", "json"),
    ],
)
def test_infer_format(fc, path, explicit, fmt):
    assert fc.infer_format(path, explicit) == fmt


# =============================================================================================
# E. keep_link: normalization then acceptance, per trust level (spec 4.4)
# =============================================================================================


@pytest.mark.parametrize(
    "raw,expected", KEEP_VECTORS, ids=[ascii(v[0])[:48] for v in KEEP_VECTORS]
)
def test_keep_link_vectors_at_every_trust_level(fc, raw, expected):
    assert tuple(fc.keep_link(raw, trust=trust) for trust in TRUSTS) == expected


def test_keep_link_default_trust_is_quoted(fc):
    assert fc.keep_link("/api/v1/users") == "/api/v1/users"
    assert (
        fc.keep_link("users") is None and fc.keep_link("users", trust="lax") == "users"
    )
    assert (
        fc.keep_link("?x=1") is None
        and fc.keep_link("?x=1", trust="attribute") == "?x=1"
    )


def test_keep_link_length_limits(fc):
    assert fc.keep_link("/" + "a" * 2047, trust="quoted") == "/" + "a" * 2047
    assert fc.keep_link("/" + "a" * 2048, trust="quoted") is None


def test_keep_link_never_returns_data_links_so_the_data_kind_is_unreachable(fc):
    assert fc.keep_link("data:text/html,x", trust="lax") is None
    assert fc.classify_link("data:text/html,x") == "data"


# =============================================================================================
# F. extract_from_text / extract_from_headers (spec 4.4, 4.5)
# =============================================================================================


@pytest.mark.parametrize(
    "case,body,expected", EXTRACT_VECTORS, ids=[v[0] for v in EXTRACT_VECTORS]
)
def test_extract_from_text_golden(fc, case, body, expected):
    assert triples(fc.extract_from_text(body)) == expected


@pytest.mark.parametrize(
    "headers,expected", HEADER_VECTORS, ids=[ascii(v[0])[:50] for v in HEADER_VECTORS]
)
def test_extract_from_headers_golden(fc, headers, expected):
    assert triples(fc.extract_from_headers(headers)) == expected


def test_vector_corpus_exercises_all_nine_kinds_and_the_body_origins():
    kinds = {
        kind
        for _case, _body, expected in EXTRACT_VECTORS
        for _link, kind, _origin in expected
    }
    origins = {
        origin
        for _case, _body, expected in EXTRACT_VECTORS
        for _link, _kind, origin in expected
    }
    assert kinds == set(KINDS)
    assert {"html", "css", "json", "regex", "html+decoded", "regex+decoded"} <= origins
    assert {
        origin for _headers, expected in HEADER_VECTORS for _l, _k, origin in expected
    } == {"header"}


def test_extract_dedupes_by_exact_string_and_the_first_pass_names_the_origin(fc):
    found = triples(fc.extract_from_text('<a href="/dup/x"></a> "/dup/x" url(/dup/x)'))
    assert found == [("/dup/x", "absolute-path", "html")]


def test_d11_pinned_absolute_urls_inside_comments_are_kept(fc):
    """The old README claims comments are skipped; the program keeps absolute URLs found in comments."""
    found = triples(
        fc.extract_from_text("// see http://intranet/status\n/* https://e.com/doc */")
    )
    assert [link for link, _k, _o in found] == [
        "http://intranet/status",
        "https://e.com/doc",
    ]


# =============================================================================================
# G. Input loading and record shapes (spec 4.2, 4.3, 6.1)
# =============================================================================================


def test_record_shape_is_the_five_key_dict_for_every_input_kind(fc, tmp_path):
    files = {
        "p.txt": PLAIN_TEXT.encode(),
        "r.txt": RAW_HTTP.encode(),
        "c.har": CAPTURE_HAR.encode(),
        "logo.png": b"\x89PNG",
        "empty.txt": b"",
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
        records = fc.load_input(str(tmp_path / name))
        assert records and all(set(record) == RECORD_KEYS for record in records), name
        assert all(len(item) == 3 for record in records for item in record["links"]), (
            name
        )


def test_text_file_record(fc, tmp_path):
    path = tmp_path / "p.txt"
    path.write_text(PLAIN_TEXT, encoding="utf-8")
    (record,) = fc.load_input(str(path))
    assert (
        record["source"],
        record["url"],
        record["status"],
        record["content_type"],
    ) == (str(path), str(path), None, "")
    assert triples(record["links"]) == [
        ("https://example.com/a", "https", "regex"),
        ("/api/plain/x", "absolute-path", "regex"),
    ]


def test_text_file_falls_back_to_latin_1_instead_of_failing(fc, tmp_path):
    path = tmp_path / "l.html"
    path.write_bytes(b'<p>"/api/lat1/x" caf\xe9</p>')
    (record,) = fc.load_input(str(path))
    assert [link for link, _k, _o in record["links"]] == ["/api/lat1/x"]


@pytest.mark.parametrize(
    "name",
    ["logo.png", "font.WOFF2", "doc.pdf", "bundle.gz", "clip.mp4", "lib.wasm", "a.zip"],
)
def test_binary_looking_suffixes_yield_one_record_without_links(fc, tmp_path, name):
    path = tmp_path / name
    path.write_bytes(b'<a href="/api/in/binary">')
    (record,) = fc.load_input(str(path))
    assert record["links"] == []


def test_svg_suffix_is_scanned(fc, tmp_path):
    path = tmp_path / "i.svg"
    path.write_bytes(b'<a href="/api/in/svg">')
    (record,) = fc.load_input(str(path))
    assert [link for link, _k, _o in record["links"]] == ["/api/in/svg"]


def test_empty_file_is_text_with_no_links(fc, tmp_path):
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")
    (record,) = fc.load_input(str(path))
    assert record["links"] == [] and record["status"] is None


def test_har_records_follow_entries_and_skip_non_dict_entries(fc, tmp_path):
    path = tmp_path / "cap.har"
    path.write_text(CAPTURE_HAR, encoding="utf-8")
    records = fc.load_input(str(path))
    assert [(r["url"], r["status"], r["content_type"]) for r in records] == [
        ("https://app.example.com/index.html", 200, "text/html"),
        ("https://app.example.com/img.png", 200, "image/png"),
        ("https://app.example.com/b64.js", 200, "application/javascript"),
    ]
    assert all(r["source"] == str(path) for r in records)
    assert [triples(r["links"]) for r in records] == [
        [
            ("https://app.example.com/index.html", "https", "request"),
            ("/loc", "absolute-path", "header"),
            ("/har/link", "absolute-path", "html"),
            ("/api/har/q", "absolute-path", "regex"),
        ],
        [("https://app.example.com/img.png", "https", "request")],
        [
            ("https://app.example.com/b64.js", "https", "request"),
            ("/api/b64/path", "absolute-path", "regex"),
        ],
    ]


def test_har_with_no_entries_gives_no_records_and_no_rows(bench):
    bench.put("e.har", har_doc())
    result = bench.run("e.har")
    assert (result.code, result.out) == (0, "No links found.\n")


def test_har_entry_without_a_response_still_yields_its_request_link(bench):
    bench.put(
        "noresp.har",
        json.dumps(
            {"log": {"entries": [{"request": {"url": "https://a.example.com/x"}}]}}
        ),
    )
    (row,) = bench.rows("noresp.har", "--include-requests")
    assert (row["kind"], row["origin"], row["status"], row["content_type"]) == (
        "https",
        "request",
        None,
        "",
    )
    assert bench.rows("noresp.har") == []


def test_har_content_type_falls_back_to_the_response_header(fc, tmp_path):
    path = tmp_path / "h.har"
    path.write_text(
        har_doc(
            har_entry(
                "https://a.example.com/x",
                mime=None,
                headers=[("Content-Type", "text/html")],
                body='<a href="/h/ref">r</a>',
            )
        ),
        encoding="utf-8",
    )
    (record,) = fc.load_input(str(path))
    assert record["content_type"] == "text/html"
    assert [link for link, _k, _o in record["links"] if _o == "html"] == ["/h/ref"]


@pytest.mark.parametrize(
    "document",
    [
        'not json "/api/text/fallback"',
        '{"log": {"entries": "nope"}}',
        '{"log": {"entries": [1, 2]}}',
        '{"no": "log"}',
    ],
)
def test_har_suffix_with_something_that_is_not_a_har_falls_back_to_text(
    fc, tmp_path, document
):
    path = tmp_path / "x.har"
    path.write_text(document, encoding="utf-8")
    (record,) = fc.load_input(str(path))
    assert (record["url"], record["status"]) == (str(path), None)


def test_har_sniffed_by_content_without_the_har_suffix(bench):
    bench.put("capture.json", CAPTURE_HAR)
    assert kinds_origins(bench.rows("capture.json", "--include-requests"))[0] == (
        "https",
        "request",
        "https://app.example.com/index.html",
    )


def test_json_file_with_a_log_key_is_just_json(fc, tmp_path):
    path = tmp_path / "data.json"
    path.write_text('{"log": "x", "u": "/api/json/file"}', encoding="utf-8")
    (record,) = fc.load_input(str(path))
    assert triples(record["links"]) == [("/api/json/file", "absolute-path", "json")]


def test_raw_http_file_record(fc, tmp_path):
    path = tmp_path / "raw.txt"
    path.write_bytes(RAW_HTTP.encode())
    (record,) = fc.load_input(str(path))
    assert (
        record["url"] == "https://app.example.com/start"
        and record["content_type"] == "text/html"
    )
    assert [(k, o, link) for link, k, o in record["links"]] == RAW_ROWS


def test_raw_http_url_is_the_path_when_there_is_no_x_request_url(fc, tmp_path):
    path = tmp_path / "raw2.txt"
    path.write_bytes(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<a href=/x/yz>z</a>"
    )
    (record,) = fc.load_input(str(path))
    assert record["url"] == str(path)


def test_raw_http_splits_on_a_bare_lf_blank_line_too(fc, tmp_path):
    path = tmp_path / "raw3.txt"
    path.write_bytes(
        b"HTTP/1.1 200 OK\nContent-Type: text/html\nLocation: /lf/loc\n\n<a href=/x/yz>z</a>"
    )
    (record,) = fc.load_input(str(path))
    assert [(k, o, link) for link, k, o in record["links"]] == [
        ("absolute-path", "header", "/lf/loc"),
        ("absolute-path", "html", "/x/yz"),
    ]


def test_raw_http_body_is_skipped_for_unscannable_content_types(fc, tmp_path):
    path = tmp_path / "raw4.txt"
    path.write_bytes(
        b'HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n"/api/skip/me"'
    )
    (record,) = fc.load_input(str(path))
    assert record["links"] == []


def test_raw_http_body_is_scanned_when_there_is_no_content_type(fc, tmp_path):
    path = tmp_path / "raw5.txt"
    path.write_bytes(b'HTTP/1.1 200 OK\r\nServer: x\r\n\r\n<a href="/no/ctype">a</a>')
    (record,) = fc.load_input(str(path))
    assert [link for link, _k, _o in record["links"]] == ["/no/ctype"]


def test_d4_pinned_har_status_is_the_integer_found_in_the_file(bench):
    bench.put("cap.har", CAPTURE_HAR)
    assert {row["status"] for row in bench.rows("cap.har", "--include-requests")} == {
        200
    }


def test_d5_pinned_stdin_raw_http_loses_url_and_status_that_a_file_keeps(bench):
    bench.put("raw.txt", RAW_HTTP)
    from_file = bench.rows("raw.txt")
    assert {row["flow_url"] for row in from_file} == {"https://app.example.com/start"}
    done = bench.cli("-", "-q", "-o", "stdin.json", stdin=RAW_HTTP.encode())
    assert done.code == 0
    from_stdin = json.loads(bench.read("stdin.json").decode("utf-8"))
    assert kinds_origins(from_stdin) == RAW_ROWS
    assert {row["flow_url"] for row in from_stdin} == {"-"} and {
        row["status"] for row in from_stdin
    } == {None}
    assert {row["source"] for row in from_stdin} == {"-"}


def test_d9_pinned_duplicate_response_header_names_collapse_last_one_wins_in_har(
    fc, tmp_path
):
    path = tmp_path / "dup.har"
    path.write_text(
        har_doc(
            har_entry(
                "https://a.example.com/x",
                headers=[
                    ("Link", "</first/link>; rel=x"),
                    ("link", "</second/link>; rel=y"),
                ],
            )
        ),
        encoding="utf-8",
    )
    (record,) = fc.load_input(str(path))
    assert [
        (link, origin) for link, _k, origin in record["links"] if origin == "header"
    ] == [("/second/link", "header")]


def test_d9_pinned_duplicate_response_header_names_collapse_last_one_wins_in_raw_http(
    fc, tmp_path
):
    path = tmp_path / "dup.txt"
    path.write_bytes(
        b"HTTP/1.1 200 OK\r\nLink: </first/link>; rel=x\r\nlink: </second/link>\r\n\r\n"
    )
    (record,) = fc.load_input(str(path))
    assert [link for link, _k, _o in record["links"]] == ["/second/link"]


def test_d10_pinned_lowercase_http_prefix_sniffs_as_raw_http_but_yields_no_status(
    bench,
):
    bench.put(
        "lower.txt",
        "http/1.1 200 OK\nContent-Type: text/html\nLocation: /lc/loc\n\n<a href=/x/yz>z</a>",
    )
    rows = bench.rows("lower.txt")
    assert kinds_origins(rows) == [
        ("absolute-path", "header", "/lc/loc"),
        ("absolute-path", "html", "/x/yz"),
    ]
    assert {row["status"] for row in rows} == {None} and {
        row["content_type"] for row in rows
    } == {"text/html"}


def test_d8_pinned_header_and_request_links_get_no_decoded_twin_but_body_links_do(
    bench,
):
    bench.put(
        "twin.har",
        har_doc(
            har_entry(
                "https://e.example.com/p%3Fq%3D1",
                headers=[("Location", "/loc%2Fa/b")],
                body='<a href="/body%2Fa/b">x</a>',
            )
        ),
    )
    rows = kinds_origins(bench.rows("twin.har", "--include-requests"))
    assert rows == [
        ("https", "request", "https://e.example.com/p%3Fq%3D1"),
        ("absolute-path", "header", "/loc%2Fa/b"),
        ("absolute-path", "html", "/body%2Fa/b"),
        ("absolute-path", "html+decoded", "/body/a/b"),
    ]


def test_request_urls_are_echoed_verbatim_with_no_redaction(bench):
    bench.put(
        "secret.har", har_doc(har_entry("https://e.example.com/cb?token=SECRET123&x=1"))
    )
    (row,) = bench.rows("secret.har", "--include-requests")
    assert row["link"] == "https://e.example.com/cb?token=SECRET123&x=1"


def test_d18_pinned_non_ascii_path_characters_make_a_path_a_non_link(bench):
    bench.put("na.txt", f'Hello "/caf{E_ACUTE}/xy/zed" "/caf%C3%A9/xy/zed"')
    assert kinds_origins(bench.rows("na.txt")) == [
        ("absolute-path", "regex", "/caf%C3%A9/xy/zed")
    ]


def test_all_six_origins_are_produced(bench):
    bench.put(
        "mix.har",
        har_doc(
            har_entry(
                "https://a.example.com/index",
                headers=[("Location", "/to/there")],
                body='<a href="/h/ref">h</a><style>a{background:url(c/d.png)}</style> "/api/q/r"',
            ),
            har_entry(
                "https://a.example.com/data.json",
                mime="application/json",
                body='{"u": "/api/j/k"}',
            ),
        ),
    )
    origins = {row["origin"] for row in bench.rows("mix.har", "--include-requests")}
    assert origins == {"request", "header", "html", "css", "json", "regex"}


# =============================================================================================
# H. flatten / resolve / filters (spec 4.6), black-box over a HAR with relative links
# =============================================================================================


@pytest.fixture
def filter_bench(bench):
    bench.put("f.har", FILTER_HAR)
    return bench


def picked(indexes) -> list[tuple]:
    return [FILTER_ROWS[i] for i in indexes]


def test_flatten_rows_have_the_eight_keys_and_resolved_is_always_computed(filter_bench):
    rows = filter_bench.rows("f.har", "--include-requests")
    assert kinds_origins(rows) == FILTER_ROWS
    assert all(list(row) == ROW_KEYS for row in rows)
    by_link = {(row["link"], row["origin"]): row for row in rows}
    assert by_link[("/Z/y", "header")]["resolved"] == "https://App.Example.com/Z/y"
    assert (
        by_link[("//cdn.Example.com/a", "regex")]["resolved"]
        == "https://cdn.Example.com/a"
    )
    assert by_link[("www.foo.com/q", "regex")]["resolved"] == "https://www.foo.com/q"
    assert (
        by_link[("mailto:o@example.com", "html")]["resolved"] == "mailto:o@example.com"
    )
    assert (
        by_link[("a/c/d", "html+decoded")]["resolved"]
        == "https://App.Example.com/d/a/c/d"
    )
    assert by_link[("/other/path", "html")]["flow_url"] == "https://other.org/page"
    assert {row["content_type"] for row in rows} == {"text/html"} and {
        row["source"] for row in rows
    } == {"f.har"}


def test_request_rows_are_dropped_unless_include_requests(filter_bench):
    rows = filter_bench.rows("f.har")
    assert kinds_origins(rows) == [r for r in FILTER_ROWS if r[1] != "request"]


def test_flatten_defaults_for_a_record_without_url_status_or_source(fc):
    rows = fc.flatten([{"links": [("/a/bc", "absolute-path", "html")]}], False)
    assert rows == [
        {
            "link": "/a/bc",
            "resolved": "/a/bc",
            "kind": "absolute-path",
            "origin": "html",
            "flow_url": "",
            "status": None,
            "content_type": "",
            "source": "",
        }
    ]


def test_flatten_include_requests_switch(fc):
    record = {
        "url": "https://h.com/d/p",
        "status": 200,
        "content_type": "t",
        "source": "s",
        "links": [
            ("/a/b", "absolute-path", "request"),
            ("x/y/z", "relative-path", "html"),
        ],
    }
    assert [r["origin"] for r in fc.flatten([record], False)] == ["html"]
    assert [r["origin"] for r in fc.flatten([record], True)] == ["request", "html"]
    assert fc.flatten([record], False)[0]["resolved"] == "https://h.com/d/x/y/z"


@pytest.mark.parametrize(
    "argv,indexes",
    [
        (["--kind", " HTTPS , Mailto"], [0, 3, 5, 7, 8, 10, 11, 13]),
        (["--kind", "ws"], []),
        (["--origin", "html"], [2, 3, 4, 9, 12, 13]),
        (["--origin", "request"], [0, 8, 11]),
        (["--origin", "HEADER, regex"], [1, 5, 6, 7, 10]),
        (["--contains", "EXAMPLE.COM"], [0, 1, 2, 3, 4, 5, 6, 10, 11, 12, 13]),
        (["--contains", "/other/"], [9]),
        (["--regex", "^HTTPS://OTHER"], [8, 9]),
        (["--regex", r"\.org/page$"], [8]),
        (["--domain", ".Example.com"], [0, 1, 2, 4, 6, 10, 11, 12, 13]),
        (["--domain", " ,example.com,, "], [0, 1, 2, 4, 6, 10, 11, 12, 13]),
        (["--domain", "example.com,other.org"], [0, 1, 2, 4, 6, 8, 9, 10, 11, 12, 13]),
        (["--domain", "notexample.com"], [5]),
        (["--domain", " , "], []),
        (["--kind", "https", "--domain", "example.com"], [0, 10, 11, 13]),
        (["--kind", "absolute-path", "--origin", "html", "--contains", "b/x"], [2, 12]),
    ],
)
def test_filters_keep_the_documented_rows(filter_bench, argv, indexes):
    rows = filter_bench.rows("f.har", "--include-requests", *argv)
    assert kinds_origins(rows) == picked(indexes)


def test_origin_request_matches_nothing_without_include_requests(filter_bench):
    assert filter_bench.rows("f.har", "--origin", "request") == []


def test_origin_filter_matches_the_origin_without_its_decoded_suffix(filter_bench):
    decoded = [
        r
        for r in filter_bench.rows("f.har", "--origin", "html")
        if r["origin"].endswith("+decoded")
    ]
    assert [r["link"] for r in decoded] == ["a/c/d"]


def test_domain_filter_uses_the_resolved_host_and_never_matches_look_alikes(
    filter_bench,
):
    links = [
        r["link"]
        for r in filter_bench.rows(
            "f.har", "--include-requests", "--domain", "example.com"
        )
    ]
    assert (
        "https://notexample.com/z" not in links
        and "/Z/y" in links
        and "//cdn.Example.com/a" in links
    )


def test_unique_keeps_the_first_row_per_link(filter_bench):
    rows = filter_bench.rows("f.har", "--include-requests", "--unique")
    assert kinds_origins(rows) == picked([i for i in range(14) if i != 12])


def test_unique_with_resolve_keys_on_the_resolved_url(filter_bench):
    rows = filter_bench.rows("f.har", "--include-requests", "--unique", "--resolve")
    assert kinds_origins(rows) == picked([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11])


def test_sort_is_stable_on_kind_then_lowercased_link(filter_bench):
    rows = filter_bench.rows("f.har", "--include-requests", "--sort")
    assert kinds_origins(rows) == picked([2, 12, 9, 1, 13, 10, 0, 11, 5, 8, 7, 3, 6, 4])


def test_sort_with_resolve_keys_on_the_resolved_url(filter_bench):
    rows = filter_bench.rows("f.har", "--include-requests", "--sort", "--resolve")
    assert kinds_origins(rows) == picked([2, 12, 1, 9, 13, 10, 0, 11, 5, 8, 7, 3, 6, 4])


def test_sort_runs_after_unique(filter_bench):
    rows = filter_bench.rows("f.har", "--include-requests", "--unique", "--sort")
    assert kinds_origins(rows) == picked([2, 9, 1, 13, 10, 0, 11, 5, 8, 7, 3, 6, 4])


def test_resolve_changes_nothing_for_inputs_whose_base_is_a_file_path(bench):
    bench.put("page.html", PAGE_HTML)
    assert bench.rows("page.html", "--resolve") == bench.rows("page.html")


# =============================================================================================
# I. Save files (spec 4.7)
# =============================================================================================


@pytest.fixture
def cap(bench):
    bench.put("cap.har", CAPTURE_HAR)
    return bench


def lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def test_json_save_is_an_indent_2_array_of_eight_key_objects(cap):
    result = cap.run("cap.har", "--include-requests", "--unique", "-o", "o.json")
    assert result.code == 0
    text = lf(cap.read("o.json")).decode("utf-8")
    rows = json.loads(text)
    assert [list(row) for row in rows] == [ROW_KEYS] * 7
    assert text == json.dumps(rows, indent=2) + "\n"
    assert rows[1] == {
        "link": "/loc",
        "resolved": "https://app.example.com/loc",
        "kind": "absolute-path",
        "origin": "header",
        "flow_url": "https://app.example.com/index.html",
        "status": 200,
        "content_type": "text/html",
        "source": "cap.har",
    }


def test_txt_save_is_one_link_per_line(cap):
    cap.run("cap.har", "--include-requests", "--unique", "-o", "o.txt")
    assert lf(cap.read("o.txt")).decode("utf-8").split("\n") == [
        "https://app.example.com/index.html",
        "/loc",
        "/har/link",
        "/api/har/q",
        "https://app.example.com/img.png",
        "https://app.example.com/b64.js",
        "/api/b64/path",
        "",
    ]


def test_txt_save_with_resolve_writes_the_resolved_urls(cap):
    cap.run("cap.har", "--resolve", "-o", "o.txt")
    assert lf(cap.read("o.txt")).decode("utf-8").split("\n") == [
        "https://app.example.com/loc",
        "https://app.example.com/har/link",
        "https://app.example.com/api/har/q",
        "https://app.example.com/api/b64/path",
        "",
    ]


def test_csv_save_has_the_header_then_one_row_each_and_always_crlf(cap):
    cap.run("cap.har", "--include-requests", "-o", "o.csv")
    raw = cap.read("o.csv")
    assert raw.startswith(
        b"link,resolved,kind,origin,flow_url,status,content_type,source\r\n"
    )
    assert raw.count(b"\r\n") == 8 and raw.count(b"\n") == 8
    rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8"), newline="")))
    assert [(r["kind"], r["origin"], r["link"]) for r in rows] == [
        ("https", "request", "https://app.example.com/index.html"),
        ("absolute-path", "header", "/loc"),
        ("absolute-path", "html", "/har/link"),
        ("absolute-path", "regex", "/api/har/q"),
        ("https", "request", "https://app.example.com/img.png"),
        ("https", "request", "https://app.example.com/b64.js"),
        ("absolute-path", "regex", "/api/b64/path"),
    ]
    assert rows[0]["status"] == "200" and rows[0]["source"] == "cap.har"


def test_csv_status_none_is_an_empty_cell(bench):
    bench.put("p.txt", PLAIN_TEXT)
    bench.run("p.txt", "-q", "-o", "p.csv")
    rows = list(
        csv.DictReader(io.StringIO(bench.read("p.csv").decode("utf-8"), newline=""))
    )
    assert [r["status"] for r in rows] == ["", ""] and [
        r["flow_url"] for r in rows
    ] == ["p.txt", "p.txt"]


@pytest.mark.parametrize(
    "name,explicit,expected_format",
    [
        ("o.json", [], "json"),
        ("o.JSON", [], "json"),
        ("o.csv", [], "csv"),
        ("o.CSV", [], "csv"),
        ("o.txt", [], "txt"),
        ("o.dat", [], "txt"),
        ("o", [], "txt"),
        ("o.dat", ["--format", "json"], "json"),
        ("o.csv", ["--format", "txt"], "txt"),
        ("o.json", ["--format", "csv"], "csv"),
    ],
)
def test_save_format_is_inferred_from_the_extension_unless_given(
    cap, name, explicit, expected_format
):
    result = cap.run("cap.har", "-o", name, *explicit)
    assert result.code == 0
    assert result.lines[-1] == f"Wrote 4 link(s) to {name} ({expected_format})"
    body = lf(cap.read(name))
    if expected_format == "json":
        assert json.loads(body.decode("utf-8"))[0]["link"] == "/loc"
    elif expected_format == "csv":
        assert body.startswith(b"link,resolved,kind,origin,")
    else:
        assert body.startswith(b"/loc\n")


def test_save_is_written_even_when_there_are_no_rows(bench):
    bench.put("nothing.txt", "Hello world no links here")
    for name, expected in (
        ("n.txt", b""),
        ("n.json", b"[]\n"),
        ("n.csv", b"link,resolved,kind,origin,flow_url,status,content_type,source\r\n"),
    ):
        result = bench.run("nothing.txt", "-o", name)
        assert result.code == 0 and result.lines == [
            "No links found.",
            f"Wrote 0 link(s) to {name} ({name[2:]})",
        ]
        assert lf(bench.read(name)) == lf(expected)


def test_save_holds_the_filtered_rows_and_overwrites_without_asking(cap):
    cap.put("o.txt", "stale content that must vanish\n")
    cap.run("cap.har", "--kind", "absolute-path", "--origin", "regex", "-o", "o.txt")
    assert lf(cap.read("o.txt")).decode("utf-8") == "/api/har/q\n/api/b64/path\n"


def test_quiet_with_save_prints_nothing_but_still_writes(cap):
    result = cap.run("cap.har", "-q", "-o", "q.txt")
    assert (result.code, result.out, result.err) == (0, "", "")
    assert lf(cap.read("q.txt")).count(b"\n") == 4


def test_non_ascii_survives_in_every_format(bench):
    accented = f"https://e.example.com/caf{E_ACUTE}"
    bench.put("u.txt", f"Hello https://e.example.com/caf%C3%A9 and {accented}")
    bench.run("u.txt", "-q", "-o", "u.json")
    bench.run("u.txt", "-q", "-o", "u.txt.out")
    bench.run("u.txt", "-q", "-o", "u.csv")
    as_json = lf(bench.read("u.json")).decode(
        "ascii"
    )  # ASCII-escaped: json.dump's default ensure_ascii
    assert "caf" + chr(92) + "u00e9" in as_json and "caf%C3%A9" in as_json
    assert accented in bench.read("u.txt.out").decode("utf-8")
    assert accented in bench.read("u.csv").decode("utf-8")


# =============================================================================================
# J. Stdout list and color (spec 4.7)
# =============================================================================================


def list_body(result: Run, count: int) -> list[str]:
    """Rows of the ungrouped list, after checking the banner/footer scaffolding around them."""
    lines = result.lines
    assert len(lines) == 3 + 1 + count + 1 + 1
    assert f"{count} link(s)" in lines[1] and "kinds: " in lines[1]
    assert lines[3] == "" and lines[-2] == ""
    assert "Done." in lines[-1] and f"{count} link(s)" in lines[-1]
    return lines[4:-2]


def test_default_list_layout_and_row_order(bench):
    bench.put("page.html", PAGE_HTML)
    result = bench.run("page.html")
    assert result.code == 0 and result.err == ""
    assert list_body(result, 15) == [
        row_line(kind, origin, link) for kind, origin, link in PAGE_ROWS
    ]


def test_banner_counts_kinds_by_count_descending_then_first_seen(bench):
    bench.put("page.html", PAGE_HTML)
    counts = bench.run("page.html").lines[1].split("kinds: ", 1)[1]
    assert (
        counts
        == "relative-path=6, absolute-path=4, https=2, protocol-relative=1, mailto=1, http=1"
    )


def test_page_links_by_pass(bench):
    bench.put("page.html", PAGE_HTML)
    assert kinds_origins(bench.rows("page.html")) == PAGE_ROWS


def test_verbose_appends_flow_url_and_status_with_a_middle_dot(bench):
    bench.put("raw.txt", RAW_HTTP)
    body = list_body(bench.run("raw.txt", "--verbose"), 5)
    context = f"https://app.example.com/start {MIDDLE_DOT} 302"
    assert body == [
        row_line(kind, origin, link, context) for kind, origin, link in RAW_ROWS
    ]


def test_verbose_omits_the_status_part_when_it_is_none(bench):
    bench.put("p.txt", PLAIN_TEXT)
    body = list_body(bench.run("p.txt", "-v"), 2)
    assert body[0] == row_line("https", "regex", "https://example.com/a", "p.txt")


def test_resolve_displays_the_resolved_url_in_the_list(bench):
    bench.put("raw.txt", RAW_HTTP)
    body = list_body(bench.run("raw.txt", "--resolve"), 5)
    assert body[0] == row_line(
        "absolute-path", "header", "https://app.example.com/login?next=%2Fhome"
    )
    assert body[2] == row_line("https", "header", "https://cdn.example.com/f.woff2")


GROUPED_PAGE = [
    "[absolute-path] 4",
    "-" * 24,
    row_line("absolute-path", "html", "/api/v1/data", "page.html"),
    row_line("absolute-path", "regex", "/api/v1/items?x=1", "page.html"),
    row_line("absolute-path", "regex", "/api/v2/users", "page.html"),
    row_line("absolute-path", "html", "/static/app.css", "page.html"),
    "",
    "[http] 1",
    "-" * 24,
    row_line("http", "regex", "http://intranet/status", "page.html"),
    "",
    "[https] 2",
    "-" * 24,
    row_line("https", "regex", "https://api.example.com/v3/x", "page.html"),
    row_line("https", "html", "https://example.com/next", "page.html"),
    "",
    "[mailto] 1",
    "-" * 24,
    row_line("mailto", "html", "mailto:ops@example.com", "page.html"),
    "",
    "[protocol-relative] 1",
    "-" * 24,
    row_line("protocol-relative", "html", "//cdn.example.com/lib.js", "page.html"),
    "",
    "[relative-path] 6",
    "-" * 24,
    row_line("relative-path", "html", "?tab=2", "page.html"),
    row_line("relative-path", "html", "a.png", "page.html"),
    row_line("relative-path", "html", "b.png", "page.html"),
    row_line("relative-path", "css", "img/bg.png", "page.html"),
    row_line("relative-path", "html", "page2.html", "page.html"),
    row_line("relative-path", "css", "theme.css", "page.html"),
    "",
]


def test_group_prints_a_labelled_section_per_kind_in_first_seen_order(bench):
    bench.put("page.html", PAGE_HTML)
    lines = bench.run("page.html", "--unique", "--sort", "--group", "-v").lines

    def as_dashes(line: str) -> str:
        # the rule glyph is presentation (FREE); its length is the contract
        return (
            "-" * len(line)
            if line
            and len(set(line)) == 1
            and not line[0].isalnum()
            and line[0] not in " ["
            else line
        )

    assert [as_dashes(line) for line in lines[4:-2]] == GROUPED_PAGE
    assert lines[-3:-1] == ["", ""] and "Done." in lines[-1]


def test_group_rule_is_at_least_24_wide_and_as_wide_as_a_longer_label(bench):
    bench.put("page.html", PAGE_HTML)
    lines = bench.run("page.html", "--group").lines
    index = lines.index("[protocol-relative] 1")
    assert len(lines[index + 1]) == max(24, len("[protocol-relative] 1"))
    assert len(lines[lines.index("[http] 1") + 1]) == 24


def test_no_rows_prints_one_line_even_after_input_errors(bench):
    bench.put("nothing.txt", "Hello world no links here")
    result = bench.run("nope.txt", "nothing.txt")
    assert (
        result.out == "No links found.\n"
        and result.err.strip() == "Not found: nope.txt"
    )


def test_quiet_prints_nothing_to_stdout_even_with_no_rows(bench):
    bench.put("nothing.txt", "Hello world no links here")
    assert bench.run("nothing.txt", "-q").out == ""


ALL_KINDS_TEXT = (
    'Hello https://e.com/a http://e.com/b wss://e.com/c ws://e.com/d //e.com/e.js "/api/f" '
    '"x/y/z" "api/g" "mailto:o@e.com"'
)
KIND_CODES = {
    "https": {1, 92},
    "http": {1, 33},
    "protocol-relative": {96},
    "absolute-path": {94},
    "relative-path": {34},
    "js-endpoint": {95},
    "ws": {1, 35},
    "wss": {1, 35},
    "mailto": {36},
}


def test_all_nine_kinds_are_produced_by_one_document(bench):
    bench.put("k.txt", ALL_KINDS_TEXT)
    assert {row["kind"] for row in bench.rows("k.txt")} == set(KINDS)


def test_color_always_paints_title_counts_kinds_origins_and_footer(bench):
    bench.put("k.txt", ALL_KINDS_TEXT)
    lines = bench.run("k.txt", "--color", "always").out.splitlines()
    assert sgr_segments(lines[0])[0][0] == {1, 96}
    assert sgr_segments(lines[1])[0][0] == {2}
    assert sgr_segments(lines[-1])[0][0] == {92}
    painted = {}
    for line in lines[4:-2]:
        segments = sgr_segments(line)
        kind = segments[0][1].strip()
        painted[kind] = (segments[0][0], segments[1][0], segments[2][0])
    assert set(painted) == set(KINDS)
    for kind, (kind_codes, origin_codes, link_codes) in painted.items():
        assert kind_codes == KIND_CODES[kind] == link_codes, kind
        assert origin_codes == {2}, kind


def test_color_never_and_piped_auto_emit_no_escape_sequences(bench):
    bench.put("page.html", PAGE_HTML)
    assert "\x1b" not in bench.run("page.html", "--color", "never").out
    assert "\x1b" not in bench.run("page.html").out


def test_color_auto_follows_the_terminal_and_no_color(bench, monkeypatch):
    bench.put("page.html", PAGE_HTML)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True, raising=False)
    assert "\x1b[" in bench.run("page.html").out
    monkeypatch.setenv("NO_COLOR", "1")
    assert "\x1b" not in bench.run("page.html").out
    assert "\x1b[" in bench.run("page.html", "--color", "always").out


def test_color_marks_warnings_yellow_and_errors_red_and_quiet_turns_it_off(bench):
    bench.put("nothing.txt", "Hello world no links here")
    warned = bench.run("nothing.txt", "--color", "always")
    assert sgr_segments(warned.out)[0] == (frozenset({93}), "No links found.")
    failed = bench.run("nope.txt", "--color", "always")
    assert sgr_segments(failed.err)[0] == (frozenset({31}), "Not found: nope.txt")
    quiet = bench.run("nope.txt", "--color", "always", "-q")
    assert (
        quiet.err.strip() == "Not found: nope.txt"
        and "\x1b" not in quiet.err
        and quiet.out == ""
    )


# =============================================================================================
# K. Exit codes and messages (spec 4.1)
# =============================================================================================


def test_exit_0_when_everything_is_fine_and_when_there_are_simply_no_links(bench):
    bench.put("page.html", PAGE_HTML)
    bench.put("nothing.txt", "Hello world no links here")
    assert bench.run("page.html", "-q").code == 0
    assert bench.run("nothing.txt").code == 0
    assert bench.run("page.html", "--kind", "ws").code == 0


def test_missing_file_is_reported_and_alone_gives_exit_1(bench):
    result = bench.run("nope.txt")
    assert (result.code, result.out, result.err) == (
        1,
        "No links found.\n",
        "Not found: nope.txt\n",
    )


def test_exit_1_when_errors_and_the_other_inputs_found_nothing(bench):
    bench.put("nothing.txt", "Hello world no links here")
    assert bench.run("nope.txt", "nothing.txt").code == 1


def test_d7_pinned_partial_failure_still_exits_0_with_the_error_on_stderr_only(bench):
    bench.put("page.html", PAGE_HTML)
    result = bench.run("nope.txt", "page.html", "-q")
    assert (result.code, result.out) == (0, "")
    assert result.err == "Not found: nope.txt\n"


def test_filters_that_remove_every_row_after_an_error_still_exit_1(bench):
    bench.put("page.html", PAGE_HTML)
    assert bench.run("nope.txt", "page.html", "--kind", "ws", "-q").code == 1


def test_a_directory_as_input_is_a_failed_read_not_a_crash(bench):
    (bench.root / "adir").mkdir()
    result = bench.run("adir")
    assert result.code == 1 and result.err.startswith("Failed to read adir: ")
    assert result.out == "No links found.\n"


def test_inputs_are_processed_in_order_and_each_failure_is_independent(
    bench, monkeypatch
):
    monkeypatch.setitem(sys.modules, "mitmproxy", None)
    bench.put("a.txt", "Hello https://a.example.com/one")
    bench.put("b.txt", "Hello https://b.example.com/two")
    bench.put("bad.mitm", b"this is not a flow dump")
    result = bench.run("a.txt", "nope.txt", "bad.mitm", "b.txt", "-q", "-o", "o.txt")
    assert result.code == 0
    assert lf(bench.read("o.txt")).decode("utf-8").split() == [
        "https://a.example.com/one",
        "https://b.example.com/two",
    ]
    assert (
        result.err.splitlines()[0] == "Not found: nope.txt"
        and "Failed to read bad.mitm: " in result.err
    )


def test_stdin_dash_can_be_mixed_with_files(bench):
    bench.put("p.txt", PLAIN_TEXT)
    done = bench.cli(
        "p.txt", "-", "-q", "-o", "o.txt", stdin=b'<p>"/api/from/stdin"</p>'
    )
    assert done.code == 0
    assert lf(bench.read("o.txt")).decode("utf-8").split() == [
        "https://example.com/a",
        "/api/plain/x",
        "/api/from/stdin",
    ]


def test_stdin_forms(bench):
    done = bench.cli("-", "-q", "-o", "h.json", stdin=PAGE_HTML.encode())
    assert done.code == 0
    assert kinds_origins(json.loads(bench.read("h.json").decode("utf-8"))) == PAGE_ROWS
    done = bench.cli("-", "-q", "-o", "g.json", stdin=CAPTURE_HAR.encode())
    har_rows = json.loads(bench.read("g.json").decode("utf-8"))
    assert [r["link"] for r in har_rows] == [
        "/loc",
        "/har/link",
        "/api/har/q",
        "/api/b64/path",
    ]
    assert {r["source"] for r in har_rows} == {"-"} and har_rows[0]["status"] == 200
    done = bench.cli("-", stdin=b"")
    assert (done.code, done.out) == (0, "No links found.\n")


def test_stdin_mitm_dump_is_refused_with_a_pointer_to_a_file_path(bench):
    done = bench.cli("-", stdin=b"\x00\x01\x02 binary flow dump")
    assert done.code == 1
    assert (
        "Failed to read -: Reading mitmproxy dumps from stdin is not supported; pass a file path."
        in done.err
    )
    assert done.out == "No links found.\n"


def test_standalone_exit_codes(bench):
    bench.put("page.html", PAGE_HTML)
    assert bench.cli("page.html", "-q").code == 0
    assert bench.cli("nope.txt").code == 1
    assert bench.cli().code == 2
    assert bench.cli("--format", "xml", "page.html").code == 2


# =============================================================================================
# L. Known defects: CORRECT behavior, xfail until the rebuild fixes them (spec 9)
# =============================================================================================

D1_TEXT_HEADS = [
    ("a.js", b"var x = 1;"),
    ("a.js", b"(function(){})()"),
    ("a.js", b"// c"),
    ("a.js", b"/* c */"),
    ("a.js", b'"use strict"'),
    ("a.js", b"function f(){}"),
    ("a.js", b"import x from 'y'"),
    ("a.js", b"const x = 1"),
    ("a.css", b"body{}"),
    ("a.css", b".a{}"),
    ("a.css", b"@import 'x'"),
    ("a.json", b'\xef\xbb\xbf{"u": "/api/bom"}'),
    ("a.txt", b"x"),
    ("a.txt", b"/api/x"),
    ("a.txt", b"-"),
    ("a.txt", b"1"),
    ("a.txt", b"ABC"),
]


@pytest.mark.parametrize(
    "path,head", D1_TEXT_HEADS, ids=[f"{p}-{ascii(h)[:20]}" for p, h in D1_TEXT_HEADS]
)
def test_d1_sniff_kind_calls_ordinary_text_text(fc, path, head):
    assert fc.sniff_kind(path, head) == "text"


def test_d1_a_plain_js_file_is_scanned_as_text(bench):
    bench.put("app.js", 'var u = "/api/js/users";')
    assert [r["link"] for r in bench.rows("app.js")] == ["/api/js/users"]


def test_d1_stdin_javascript_is_scanned_as_text(bench):
    done = bench.cli("-", "-q", "-o", "o.json", stdin=b'var u = "/api/js/users";')
    assert done.code == 0
    assert [r["link"] for r in json.loads(bench.read("o.json").decode("utf-8"))] == [
        "/api/js/users"
    ]


def test_d1_stdin_latin_1_text_is_scanned_with_replacement(bench):
    done = bench.cli("-", "-q", "-o", "o.json", stdin=b'caf\xe9 "/api/lat/x"')
    assert done.code == 0
    assert [r["link"] for r in json.loads(bench.read("o.json").decode("utf-8"))] == [
        "/api/lat/x"
    ]


def test_native_typed_netstring_signature_is_recognized_without_a_suffix(fc):
    assert fc.sniff_kind("capture", b"14:4:type,4:http,}") == "mitm"
    assert fc.sniff_kind("notes.txt", b"123: plain text") == "text"


def test_timestamped_text_is_not_a_native_flow_dump(bench, fc):
    text = '12:34:56 "/api/timestamped/link"'
    assert fc.sniff_kind("notes.txt", text.encode()) == "text"
    bench.put("notes.txt", text)
    assert [row["link"] for row in bench.rows("notes.txt")] == ["/api/timestamped/link"]


@pytest.mark.parametrize(
    "head",
    [
        b"14:4:type,4:http,]",
        b"99:4:type,4:http,}",
        b"14:4:type!4:http,}",
        b"12:34:56 foo}",
    ],
)
def test_inconsistent_typed_netstring_frames_are_text(fc, head):
    assert fc.sniff_kind("notes.txt", head) == "text"


def test_large_typed_dictionary_frame_is_recognized_beyond_the_sniff_buffer(bench, fc):
    payload = b"4:type,4:http,4:body,5000:" + b"x" * 5000 + b","
    framed = str(len(payload)).encode() + b":" + payload + b"}"
    bench.put("capture", framed)
    assert fc.sniff_kind(bench.root / "capture", framed[: fc.SNIFF_BYTES]) == "mitm"
    assert fc.sniff_kind("-", framed) == "mitm"


def test_d2_listing_survives_a_non_utf8_stdout(bench):
    bench.put("p.txt", PLAIN_TEXT)
    done = bench.cli(
        "p.txt", utf8=False, env={"PYTHONIOENCODING": "cp1252"}, encoding="cp1252"
    )
    assert (
        done.code == 0
        and "https://example.com/a" in done.out
        and "UnicodeEncodeError" not in done.err
    )


def test_quiet_save_does_not_depend_on_the_stdout_encoding(bench):
    bench.put("p.txt", PLAIN_TEXT)
    done = bench.cli(
        "p.txt", "-q", "-o", "cp.txt", utf8=False, env={"PYTHONIOENCODING": "cp1252"}
    )
    assert done.code == 0 and lf(bench.read("cp.txt")).decode("utf-8").split() == [
        "https://example.com/a",
        "/api/plain/x",
    ]


@pytest.mark.parametrize(
    "through_loader, shared", [(False, False), (True, False), (False, True)]
)
@pytest.mark.parametrize(
    "options, expected",
    [(["-q"], 0), (["--regex", "("], 2), (["-q", "-o", "missing/out.txt"], 1)],
)
def test_output_encoding_policy_is_restored(
    bench, addons_root, monkeypatch, through_loader, shared, options, expected
):
    bench.put("p.txt", PLAIN_TEXT)
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
        patch.setenv("BUGHUNT_ADDONS", str(addons_root))
        try:
            code = (
                loader.run_named(
                    "carve",
                    ["p.txt", *options],
                    tool_file=Path(scanner.__file__).resolve(),
                    scan_main=scanner.scan_main,
                )
                if through_loader
                else bench.fc.main(["p.txt", *options])
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


def test_txt_and_json_exports_round_trip_with_platform_newlines(bench):
    bench.put("p.txt", PLAIN_TEXT)
    bench.run("p.txt", "-q", "-o", "o.txt")
    bench.run("p.txt", "-q", "-o", "o.json")
    assert bench.read("o.txt").decode("utf-8").splitlines() == [
        "https://example.com/a",
        "/api/plain/x",
    ]
    assert [row["link"] for row in json.loads(bench.read("o.json"))] == [
        "https://example.com/a",
        "/api/plain/x",
    ]
    assert bench.read("o.txt").endswith(os.linesep.encode())


def test_d4_raw_http_status_is_an_integer_in_the_saved_rows(bench):
    bench.put("raw.txt", RAW_HTTP)
    assert {row["status"] for row in bench.rows("raw.txt")} == {302}


def test_d6_bad_regex_is_a_clean_one_line_error_with_exit_2(bench):
    bench.put("page.html", PAGE_HTML)
    done = bench.cli("page.html", "--regex", "(")
    assert done.code == 2 and "Traceback" not in done.err and done.err.strip() != ""
    assert len(done.err.strip().splitlines()) <= 2


def test_d6_unwritable_save_is_a_clean_error_with_exit_1(bench):
    bench.put("page.html", PAGE_HTML)
    done = bench.cli("page.html", "-q", "-o", "no_such_dir/x.txt")
    assert done.code == 1 and "Traceback" not in done.err and "no_such_dir" in done.err


def test_d6_bad_regex_through_the_loader_exits_2_without_a_traceback(
    bench, addons_root, monkeypatch
):
    monkeypatch.setenv("BUGHUNT_ADDONS", str(addons_root))
    console_text = io.StringIO()
    monkeypatch.setattr(
        ui,
        "console",
        Console(theme=ui.THEME, highlight=False, file=console_text, width=200),
    )
    bench.put("page.html", PAGE_HTML)
    bench.capsys.readouterr()
    code = loader.run_named(
        "carve",
        ["page.html", "--regex", "("],
        tool_file=Path(scanner.__file__).resolve(),
        scan_main=scanner.scan_main,
    )
    assert code == 2 and "Traceback" not in bench.capsys.readouterr().err


def test_d12_a_bad_ipv6_attribute_does_not_cost_the_good_links(bench):
    bench.put("x.html", '<a href="/api/good/one">g</a> <a href="https://[bad/x">b</a>')
    result = bench.run("x.html", "-q", "-o", "o.json")
    assert result.code == 0 and "Failed to read" not in result.err
    assert [r["link"] for r in json.loads(bench.read("o.json").decode("utf-8"))] == [
        "/api/good/one"
    ]


@pytest.mark.parametrize("raw", ["http://intranet:99999", "https://[bad/x", "//[bad/x"])
def test_d12_keep_link_never_raises_on_a_malformed_host(fc, raw):
    for trust in TRUSTS:
        assert fc.keep_link(raw, trust=trust) is None


def test_d12_status_line_without_a_status_code_is_status_none(bench):
    bench.put("odd.txt", "HTTP/1.1")
    result = bench.run("odd.txt")
    assert (result.code, result.out) == (0, "No links found.\n") and result.err == ""


# =============================================================================================
# M. mitmproxy: absent-library handling (runs everywhere) and the GATED native-flow path
# =============================================================================================


def test_missing_mitmproxy_is_a_per_input_install_hint_not_a_startup_failure(
    bench, monkeypatch
):
    monkeypatch.setitem(sys.modules, "mitmproxy", None)
    bench.put("capture.mitm", b"\x00\x01 pretend flow dump")
    result = bench.run("capture.mitm")
    assert result.code == 1 and result.out == "No links found.\n"
    assert result.err.startswith("Failed to read capture.mitm: ")
    assert "pip install mitmproxy" in result.err


@pytest.mark.parametrize("name", ["a.mitm", "a.flow", "a.flows", "a.dump", "A.MITM"])
def test_flow_dump_suffixes_route_to_the_native_reader(bench, monkeypatch, name):
    monkeypatch.setitem(sys.modules, "mitmproxy", None)
    bench.put(name, 'Hello "/api/looks/like/text"')
    result = bench.run(name)
    assert result.code == 1 and "pip install mitmproxy" in result.err


def test_har_text_and_raw_inputs_never_need_mitmproxy(bench, monkeypatch):
    monkeypatch.setitem(sys.modules, "mitmproxy", None)
    bench.put("cap.har", CAPTURE_HAR)
    bench.put("raw.txt", RAW_HTTP)
    bench.put("page.html", PAGE_HTML)
    for name in ("cap.har", "raw.txt", "page.html"):
        result = bench.run(name, "-q")
        assert (result.code, result.err) == (0, ""), name


def native_flow_file(path: Path, *flows) -> None:
    """GATED helper: write flows with mitmproxy's own writer (UNVERIFIED against any mitmproxy version)."""
    from mitmproxy import io as flow_io

    with open(path, "wb") as handle:
        writer = flow_io.FlowWriter(handle)
        for flow in flows:
            writer.add(flow)


def native_http_flow(
    url: str,
    *,
    status: int = 200,
    content_type: str = "text/html",
    body: bytes = b"",
    location: str | None = None,
):
    from mitmproxy.test import tflow

    flow = tflow.tflow(resp=True)
    flow.request.url = url
    flow.response.status_code = status
    flow.response.headers["content-type"] = content_type
    if location:
        flow.response.headers["location"] = location
    flow.response.content = body
    return flow


def test_gated_native_flow_dump_yields_request_header_and_body_links(bench):
    """GATED + UNVERIFIED: needs mitmproxy; never executed in the verification environment."""
    pytest.importorskip("mitmproxy")
    native_flow_file(
        bench.root / "capture.mitm",
        native_http_flow(
            "https://native.example.com/page",
            body=b'<a href="/native/link">x</a>',
            location="/native/loc",
        ),
    )
    rows = bench.rows("capture.mitm", "--include-requests")
    assert kinds_origins(rows) == [
        ("https", "request", "https://native.example.com/page"),
        ("absolute-path", "header", "/native/loc"),
        ("absolute-path", "html", "/native/link"),
    ]
    assert {row["status"] for row in rows} == {200} and {
        row["content_type"] for row in rows
    } == {"text/html"}
    assert {row["flow_url"] for row in rows} == {"https://native.example.com/page"}


def test_gated_native_flow_skips_non_http_flows_and_unscannable_bodies(bench):
    """GATED + UNVERIFIED."""
    pytest.importorskip("mitmproxy")
    from mitmproxy.test import tflow

    native_flow_file(
        bench.root / "mixed.mitm",
        tflow.ttcpflow(),
        native_http_flow(
            "https://native.example.com/img",
            content_type="image/png",
            body=b'"/api/skip/me"',
        ),
    )
    rows = bench.rows("mixed.mitm", "--include-requests")
    assert kinds_origins(rows) == [
        ("https", "request", "https://native.example.com/img")
    ]


def test_gated_real_flow_dump_is_still_recognized_without_a_dump_suffix(bench):
    """GATED + UNVERIFIED: guards the D1 fix, which must not stop real dumps from reaching the native reader."""
    pytest.importorskip("mitmproxy")
    native_flow_file(
        bench.root / "capture_no_suffix",
        native_http_flow(
            "https://native.example.com/page", body=b'<a href="/native/link">x</a>'
        ),
    )
    assert [r["link"] for r in bench.rows("capture_no_suffix")] == ["/native/link"]


def test_gated_corrupt_flow_dump_is_a_read_error_for_that_input(bench):
    """GATED + UNVERIFIED."""
    pytest.importorskip("mitmproxy")
    bench.put("bad.mitm", b"definitely not a tnetstring flow file")
    result = bench.run("bad.mitm")
    assert (
        result.code == 1
        and "Failed to read bad.mitm: " in result.err
        and "could not be read" in result.err
    )


# =============================================================================================
# N. `bughunt carve` through the loader (spec 2.1, 2.3)
# =============================================================================================


@pytest.fixture
def via_loader(bench, addons_root, monkeypatch):
    """`bughunt carve ...` through loader.run_named with the loader's own console captured."""
    monkeypatch.setenv("BUGHUNT_ADDONS", str(addons_root))
    console_text = io.StringIO()
    monkeypatch.setattr(
        ui,
        "console",
        Console(theme=ui.THEME, highlight=False, file=console_text, width=200),
    )

    def call(name: str, *argv: str):
        bench.capsys.readouterr()
        code = loader.run_named(
            name,
            list(argv),
            tool_file=Path(scanner.__file__).resolve(),
            scan_main=scanner.scan_main,
        )
        out, err = bench.capsys.readouterr()
        return Run(code, out, err), console_text.getvalue()

    return call


@pytest.mark.parametrize("name", ["carve", "flowcarve"])
def test_loader_resolves_carve_and_its_alias_to_the_same_program(
    bench, via_loader, name
):
    bench.put("page.html", PAGE_HTML)
    run, _console = via_loader(name, "page.html", "--unique")
    assert run.code == 0 and run.err == ""
    assert run.lines[4:-2] == [row_line(k, o, link) for k, o, link in PAGE_ROWS]


def test_loader_maps_return_codes_and_system_exit(bench, via_loader):
    bench.put("nothing.txt", "Hello world no links here")
    assert via_loader("carve", "nothing.txt")[0].code == 0
    missing, _console = via_loader("carve", "nope.txt")
    assert missing.code == 1 and missing.err == "Not found: nope.txt\n"
    assert via_loader("carve")[0].code == 2
    assert via_loader("carve", "-h")[0].code == 0
    assert via_loader("carve", "--format", "xml", "nothing.txt")[0].code == 2


def test_loader_save_goes_to_the_requested_file(bench, via_loader):
    bench.put("page.html", PAGE_HTML)
    run, _console = via_loader("carve", "page.html", "-q", "-o", "via.json")
    assert run.code == 0 and run.out == ""
    assert len(json.loads(bench.read("via.json").decode("utf-8"))) == 15


def test_d16_verified_carve_runs_through_the_loader_without_bughunt_addons(
    bench, monkeypatch
):
    """D16 (fixed on this base): the repo's own addons folder is found from the scanner module path."""
    monkeypatch.delenv("BUGHUNT_ADDONS", raising=False)
    monkeypatch.setattr(
        ui,
        "console",
        Console(theme=ui.THEME, highlight=False, file=io.StringIO(), width=200),
    )
    bench.put("page.html", PAGE_HTML)
    bench.capsys.readouterr()
    code = loader.run_named(
        "carve",
        ["page.html", "-q"],
        tool_file=Path(scanner.__file__).resolve(),
        scan_main=scanner.scan_main,
    )
    assert code == 0
